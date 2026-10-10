//! The non-secret record of which backend holds the vault's master key, shared
//! by the daemon and operator CLI. A file backend records its absolute path.

use super::{fsync_parent_dir, write_key_file, KeySource, MasterKeyError, ResolverConfig};
use std::path::{Path, PathBuf};

const VERSION: &str = "version:1";

fn file_source(path: &Path) -> Result<KeySource, MasterKeyError> {
    if path.as_os_str().is_empty() {
        return Err(MasterKeyError::KeyPathInvalid(
            "key path must not be empty".into(),
        ));
    }
    let absolute = std::path::absolute(path).map_err(MasterKeyError::Io)?;
    let parent = absolute
        .parent()
        .ok_or_else(|| MasterKeyError::KeyPathInvalid("key path has no parent directory".into()))?;
    let name = absolute
        .file_name()
        .ok_or_else(|| MasterKeyError::KeyPathInvalid("key path must name a file".into()))?;
    // Selection can name a conflicting override even when its directory is absent.
    // The file backend enforces directory existence before loading or provisioning.
    let path = parent
        .canonicalize()
        .unwrap_or_else(|_| parent.into())
        .join(name);
    Ok(KeySource::OperatorPath { path })
}

fn name(source: &KeySource) -> Result<String, MasterKeyError> {
    match source {
        KeySource::Keychain => Ok("keychain".into()),
        KeySource::OperatorPath { path } => {
            let normalized = file_source(path)?;
            let KeySource::OperatorPath { path } = normalized else {
                unreachable!()
            };
            let raw = path
                .to_str()
                .filter(|s| !s.contains(['\n', '\r']))
                .ok_or_else(|| {
                    MasterKeyError::KeySourceInvalid(
                        "file path must be UTF-8 without line breaks".into(),
                    )
                })?;
            Ok(format!("file:{raw}"))
        }
    }
}

/// Read the versioned custody choice, or `None` for a vault not yet migrated.
/// Unknown versions and backends are errors: they must never select a fallback.
pub fn read_key_source(data_dir: &Path) -> Result<Option<KeySource>, MasterKeyError> {
    let raw = match std::fs::read_to_string(data_dir.join("key-source")) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(MasterKeyError::Io(e)),
    };
    let mut lines = raw.lines();
    let version = lines.next().unwrap_or("<missing>");
    if version != VERSION {
        return Err(MasterKeyError::KeySourceInvalid(format!(
            "unknown version {version:?}"
        )));
    }
    let backend = lines.next().unwrap_or("<missing>");
    let source = if backend == "keychain" {
        KeySource::Keychain
    } else if let Some(raw_path) = backend.strip_prefix("file:") {
        let path = PathBuf::from(raw_path);
        if !path.is_absolute() {
            return Err(MasterKeyError::KeySourceInvalid(format!(
                "file path {raw_path:?} must be absolute"
            )));
        }
        KeySource::OperatorPath { path }
    } else {
        return Err(MasterKeyError::KeySourceInvalid(format!(
            "unknown backend {backend:?}"
        )));
    };
    if lines.next().is_some() {
        return Err(MasterKeyError::KeySourceInvalid(
            "unexpected extra lines".into(),
        ));
    }
    Ok(Some(source))
}

fn agree(recorded: &KeySource, requested: &KeySource) -> Result<(), MasterKeyError> {
    let recorded = name(recorded)?;
    let requested = name(requested)?;
    if recorded != requested {
        return Err(MasterKeyError::KeySourceConflict {
            recorded,
            requested,
        });
    }
    Ok(())
}

/// Select custody using the record and both override names. Different flag and
/// environment paths are refused too, rather than hiding one override's mistake.
pub fn key_source_with_overrides(
    data_dir: &Path,
    flag_path: Option<&Path>,
    env_path: Option<&Path>,
) -> Result<KeySource, MasterKeyError> {
    let flag = flag_path.map(file_source).transpose()?;
    let env = env_path.map(file_source).transpose()?;
    if let (Some(flag), Some(env)) = (&flag, &env) {
        let env_name = name(env)?;
        let flag_name = name(flag)?;
        if env_name != flag_name {
            return Err(MasterKeyError::KeySourceInvalid(format!(
                "CK_MASTER_KEY_PATH requests {env_name}, but --key-path requests {flag_name}; remove the conflicting override"
            )));
        }
    }
    let requested = flag.or(env);
    if let Some(recorded) = read_key_source(data_dir)? {
        if let Some(requested) = requested {
            agree(&recorded, &requested)?;
        }
        return Ok(recorded);
    }
    // Unrecorded legacy vaults used Keychain unless the operator supplied a path.
    // Fresh non-macOS provisioning is refused by bootstrap, never auto-fallback.
    Ok(requested.unwrap_or(KeySource::Keychain))
}

/// The entry points share environment handling as well as record parsing.
pub fn key_source(data_dir: &Path, flag_path: Option<&Path>) -> Result<KeySource, MasterKeyError> {
    let env_path = std::env::var_os("CK_MASTER_KEY_PATH").map(PathBuf::from);
    key_source_with_overrides(data_dir, flag_path, env_path.as_deref())
}

pub(super) fn check_record(config: &ResolverConfig) -> Result<(), MasterKeyError> {
    if let Some(recorded) = read_key_source(&config.data_dir)? {
        agree(&recorded, &config.source)?;
    }
    Ok(())
}

pub(super) fn record_migration(config: &ResolverConfig) -> Result<(), MasterKeyError> {
    if config.data_dir.join("store.db").exists() {
        record_source(&config.data_dir, &config.source)?;
    }
    Ok(())
}

/// Publish a complete record without replacing another resolver's choice. Normal
/// daemon/offline CLI writes hold the store lease, but routed CLI preflight loads
/// do not. A create-only hard link makes those concurrent migrations safe too.
pub(super) fn record_source(data_dir: &Path, source: &KeySource) -> Result<(), MasterKeyError> {
    let config = ResolverConfig {
        data_dir: data_dir.into(),
        source: source.clone(),
    };
    if let Some(recorded) = read_key_source(data_dir)? {
        agree(&recorded, source)?;
        return fsync_parent_dir(&data_dir.join("key-source")).map_err(MasterKeyError::Io);
    }
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| MasterKeyError::Csprng)?;
    let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let tmp = data_dir.join(format!(".key-source.{suffix}.tmp"));
    let record = format!("{VERSION}\n{}\n", name(source)?);
    write_key_file(&tmp, record.as_bytes())?;
    let path = data_dir.join("key-source");
    let published = std::fs::hard_link(&tmp, &path);
    let cleanup = std::fs::remove_file(&tmp);
    match published {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => check_record(&config)?,
        Err(e) => return Err(MasterKeyError::Io(e)),
    }
    cleanup.map_err(MasterKeyError::Io)?;
    fsync_parent_dir(&path).map_err(MasterKeyError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::MasterKey;
    use crate::resolver::{
        bootstrap, resolve, resolve_for_db, resolve_with_backend, KeySlot, MasterKeyStore,
    };
    use crate::test_support::TestTempDir;

    fn fixture(tag: &str) -> (TestTempDir, ResolverConfig) {
        let root = TestTempDir::new(format!("ck-cred-{tag}-{}", std::process::id()));
        let canonical_root = root.canonicalize().unwrap();
        let data_dir = canonical_root.join("vault");
        std::fs::create_dir_all(&data_dir).unwrap();
        let config = ResolverConfig {
            data_dir,
            source: KeySource::OperatorPath {
                path: canonical_root.join("master.key"),
            },
        };
        (root, config)
    }

    #[test]
    fn key_source_record_round_trips_file_and_keychain() {
        let (_root, config) = fixture("source-roundtrip");
        bootstrap(&config).unwrap();
        assert_eq!(
            read_key_source(&config.data_dir).unwrap(),
            Some(config.source.clone())
        );
        assert_eq!(
            std::fs::read_to_string(config.data_dir.join("key-source")).unwrap(),
            format!(
                "version:1\nfile:{}\n",
                match &config.source {
                    KeySource::OperatorPath { path } => path
                        .parent()
                        .unwrap()
                        .canonicalize()
                        .unwrap()
                        .join(path.file_name().unwrap())
                        .display()
                        .to_string(),
                    _ => unreachable!(),
                }
            )
        );
        let other = config.data_dir.join("other");
        std::fs::create_dir(&other).unwrap();
        record_source(&other, &KeySource::Keychain).unwrap();
        assert_eq!(read_key_source(&other).unwrap(), Some(KeySource::Keychain));
    }

    #[test]
    fn key_source_override_must_agree_with_record() {
        let (root, config) = fixture("source-conflict");
        bootstrap(&config).unwrap();
        let KeySource::OperatorPath { path } = &config.source else {
            unreachable!()
        };
        assert_eq!(
            key_source_with_overrides(&config.data_dir, Some(path), Some(path)).unwrap(),
            config.source
        );
        let different = root.join("different.key");
        let error = key_source_with_overrides(&config.data_dir, Some(&different), None)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&path.display().to_string())
                && error.contains(&different.display().to_string()),
            "{error}"
        );
        let other = root.join("keychain-vault");
        std::fs::create_dir(&other).unwrap();
        record_source(&other, &KeySource::Keychain).unwrap();
        let error = key_source_with_overrides(&other, None, Some(path))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("keychain") && error.contains(&path.display().to_string()),
            "{error}"
        );
        let error =
            key_source_with_overrides(&root.join("no-record"), Some(path), Some(&different))
                .unwrap_err()
                .to_string();
        assert!(
            error.contains("CK_MASTER_KEY_PATH")
                && error.contains("--key-path")
                && !error.contains("records"),
            "{error}"
        );
    }

    #[test]
    fn key_source_unknown_backend_and_version_are_named() {
        let (_root, config) = fixture("source-unknown");
        for (raw, expected) in [
            ("version:99\nkeychain\n", "version:99"),
            ("version:1\nsecret-service\n", "secret-service"),
        ] {
            std::fs::write(config.data_dir.join("key-source"), raw).unwrap();
            let error = key_source_with_overrides(&config.data_dir, None, None)
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn migration_records_file_only_after_successful_load() {
        let (_root, config) = fixture("source-migrate-file");
        std::fs::write(config.data_dir.join("store.db"), []).unwrap();
        assert!(resolve(&config, None).is_err());
        assert!(!config.data_dir.join("key-source").exists());
        let key = bootstrap(&config).unwrap();
        std::fs::remove_file(config.data_dir.join("key-source")).unwrap();
        let wrong_id = MasterKey::from_bytes([17; 32]).key_id();
        assert!(resolve_for_db(&config, wrong_id).is_err());
        assert!(!config.data_dir.join("key-source").exists());
        assert_eq!(
            resolve_for_db(&config, key.key_id()).unwrap().key_id(),
            key.key_id()
        );
        assert_eq!(
            read_key_source(&config.data_dir).unwrap(),
            Some(config.source.clone())
        );
        resolve(&config, None).unwrap();
    }

    struct TestKeychain {
        available: bool,
    }
    impl MasterKeyStore for TestKeychain {
        fn load_slot(&self, _: &Path, _: KeySlot) -> Result<Option<MasterKey>, MasterKeyError> {
            if self.available {
                Ok(Some(MasterKey::from_bytes([7; 32])))
            } else {
                Err(MasterKeyError::VaultLocked)
            }
        }
        fn store_slot(&self, _: &Path, _: KeySlot, _: &MasterKey) -> Result<(), MasterKeyError> {
            unreachable!()
        }
        fn clear_slot(&self, _: &Path, _: KeySlot) -> Result<(), MasterKeyError> {
            unreachable!()
        }
    }

    #[test]
    fn migration_records_keychain_only_after_successful_load() {
        let (_root, mut config) = fixture("source-migrate-keychain");
        config.source = KeySource::Keychain;
        std::fs::write(config.data_dir.join("store.db"), []).unwrap();
        assert!(resolve_with_backend(&config, None, &TestKeychain { available: false }).is_err());
        assert!(!config.data_dir.join("key-source").exists());
        resolve_with_backend(&config, None, &TestKeychain { available: true }).unwrap();
        assert_eq!(
            read_key_source(&config.data_dir).unwrap(),
            Some(KeySource::Keychain)
        );
    }

    #[test]
    fn concurrent_migrations_never_replace_a_record() {
        let (_root, config) = fixture("source-race");
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let config = config.clone();
                std::thread::spawn(move || record_source(&config.data_dir, &config.source))
            })
            .collect();
        for handle in handles {
            handle.join().unwrap().unwrap();
        }
        assert_eq!(
            read_key_source(&config.data_dir).unwrap(),
            Some(config.source.clone())
        );
        assert!(record_source(&config.data_dir, &KeySource::Keychain).is_err());
        assert_eq!(
            read_key_source(&config.data_dir).unwrap(),
            Some(config.source)
        );
        for iteration in 0..16 {
            let data_dir = config.data_dir.join(format!("conflict-{iteration}"));
            std::fs::create_dir(&data_dir).unwrap();
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let handles: Vec<_> = [
                KeySource::Keychain,
                KeySource::OperatorPath {
                    path: config.data_dir.parent().unwrap().join("other.key"),
                },
            ]
            .into_iter()
            .map(|source| {
                let data_dir = data_dir.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    let result = record_source(&data_dir, &source);
                    (source, result)
                })
            })
            .collect();
            let results: Vec<_> = handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect();
            assert_eq!(
                results.iter().filter(|(_, result)| result.is_ok()).count(),
                1
            );
            let (winner, _) = results.iter().find(|(_, result)| result.is_ok()).unwrap();
            assert_eq!(read_key_source(&data_dir).unwrap().as_ref(), Some(winner));
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn fresh_bootstrap_without_path_names_both_override_remedies() {
        let (_root, mut config) = fixture("source-platform-default");
        config.source = KeySource::Keychain;
        let error = bootstrap(&config).unwrap_err().to_string();
        assert!(
            error.contains("--key-path") && error.contains("CK_MASTER_KEY_PATH"),
            "{error}"
        );
        assert!(!config.data_dir.join("key-source").exists());
    }

    #[cfg(unix)]
    #[test]
    fn checked_key_file_refuses_mode_0644() {
        use std::os::unix::fs::PermissionsExt;
        let (_root, config) = fixture("source-mode");
        bootstrap(&config).unwrap();
        let KeySource::OperatorPath { path } = &config.source else {
            unreachable!()
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = resolve(&config, None).unwrap_err().to_string();
        assert!(
            error.contains("chmod 600") && error.contains(&path.display().to_string()),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn checked_key_file_refuses_symlink_and_nonregular_file() {
        let (root, mut config) = fixture("source-symlink");
        bootstrap(&config).unwrap();
        let KeySource::OperatorPath { path } = &config.source else {
            unreachable!()
        };
        let link = root.join("link.key");
        std::os::unix::fs::symlink(path, &link).unwrap();
        config.source = KeySource::OperatorPath { path: link };
        let error = resolve(&config, None).unwrap_err().to_string();
        assert!(
            error.contains("regular file") && error.contains("symlink"),
            "{error}"
        );
        config.source = KeySource::OperatorPath {
            path: root.to_path_buf(),
        };
        assert!(resolve(&config, None)
            .unwrap_err()
            .to_string()
            .contains("regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn checked_key_file_refuses_another_owner_when_chown_is_permitted() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        extern "C" {
            fn chown(path: *const std::ffi::c_char, owner: u32, group: u32) -> i32;
        }
        let (_root, config) = fixture("source-owner");
        bootstrap(&config).unwrap();
        let KeySource::OperatorPath { path } = &config.source else {
            unreachable!()
        };
        let uid = std::fs::metadata(path).unwrap().uid();
        let raw = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // The CString is live for the call; -1 leaves the group unchanged.
        if unsafe { chown(raw.as_ptr(), uid.wrapping_add(1), u32::MAX) } != 0 {
            eprintln!(
                "SKIPPING owner refusal: cannot chown {} to another uid",
                path.display()
            );
            return;
        }
        let error = resolve(&config, None).unwrap_err().to_string();
        assert!(
            error.contains("chown") && error.contains("effective uid"),
            "{error}"
        );
    }
}
