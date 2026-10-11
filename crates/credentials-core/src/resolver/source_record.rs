//! The non-secret record of which backend holds the vault's master key, shared
//! by the daemon and operator CLI. A file backend records its absolute path.

use super::{fsync_parent_dir, write_key_file, KeySource, MasterKeyError, ResolverConfig};
use std::path::{Path, PathBuf};

const VERSION: &str = "version:1";

fn file_source(path: &Path) -> Result<KeySource, MasterKeyError> {
    Ok(KeySource::OperatorPath {
        path: normalize_file_path(path)?,
    })
}

fn normalize_file_path(path: &Path) -> Result<PathBuf, MasterKeyError> {
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
    Ok(parent
        .canonicalize()
        .unwrap_or_else(|_| parent.into())
        .join(name))
}

fn name(source: &KeySource) -> Result<String, MasterKeyError> {
    match source {
        KeySource::Keychain => Ok("keychain".into()),
        KeySource::CredentialManager => Ok("credential-manager".into()),
        KeySource::SecretService => Ok("secret-service".into()),
        KeySource::OperatorPath { path } => {
            let path = normalize_file_path(path)?;
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
    } else if backend == "credential-manager" {
        KeySource::CredentialManager
    } else if backend == "secret-service" {
        KeySource::SecretService
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
    // Do not reinterpret an existing unrecorded database as a fresh native vault.
    // A fresh vault's OS default is only a choice of store, not a fallback on failure.
    Ok(requested.unwrap_or_else(|| {
        if data_dir.join("store.db").exists() {
            KeySource::Keychain
        } else {
            super::native_source_for(std::env::consts::OS)
        }
    }))
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
    #[cfg(windows)]
    subc_os::windows_acl::verify_private_dir(data_dir).map_err(MasterKeyError::Io)?;
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
    fn native_source_records_round_trip_and_refuse_file_overrides() {
        let (root, config) = fixture("native-records");
        let path = root.join("operator.key");
        for (source, name) in [
            (KeySource::CredentialManager, "credential-manager"),
            (KeySource::SecretService, "secret-service"),
        ] {
            let dir = config.data_dir.join(name);
            std::fs::create_dir(&dir).unwrap();
            record_source(&dir, &source).unwrap();
            assert_eq!(
                std::fs::read_to_string(dir.join("key-source")).unwrap(),
                format!("version:1\n{name}\n")
            );
            assert_eq!(key_source_with_overrides(&dir, None, None).unwrap(), source);
            for (flag, env) in [(Some(path.as_path()), None), (None, Some(path.as_path()))] {
                let error = key_source_with_overrides(&dir, flag, env).unwrap_err();
                assert!(matches!(error, MasterKeyError::KeySourceConflict { .. }));
                assert!(error.to_string().contains(name));
            }
        }
    }

    #[test]
    fn fresh_native_default_does_not_reinterpret_legacy_database() {
        let (_root, config) = fixture("native-default");
        assert_eq!(
            key_source_with_overrides(&config.data_dir, None, None).unwrap(),
            super::super::native_source_for(std::env::consts::OS)
        );
        std::fs::write(config.data_dir.join("store.db"), []).unwrap();
        assert_eq!(
            key_source_with_overrides(&config.data_dir, None, None).unwrap(),
            KeySource::Keychain
        );
    }

    #[test]
    fn unavailable_native_bootstrap_never_uses_existing_key_file() {
        struct Unavailable;
        impl MasterKeyStore for Unavailable {
            fn load_slot(&self, _: &Path, _: KeySlot) -> Result<Option<MasterKey>, MasterKeyError> {
                Err(MasterKeyError::NativeStoreUnavailable {
                    backend: "secret-service",
                    reason: "no session bus".into(),
                })
            }
            fn store_slot(
                &self,
                _: &Path,
                _: KeySlot,
                _: &MasterKey,
            ) -> Result<(), MasterKeyError> {
                panic!("must not write after native store refusal")
            }
            fn clear_slot(&self, _: &Path, _: KeySlot) -> Result<(), MasterKeyError> {
                panic!("must not clear after native store refusal")
            }
        }
        let (_root, mut config) = fixture("native-no-fallback");
        let file_key = bootstrap(&config).unwrap();
        let file_source = config.source.clone();
        std::fs::remove_file(config.data_dir.join("key-source")).unwrap();
        config.source = super::super::native_source_for(std::env::consts::OS);
        let error = super::super::bootstrap_with_backend(&config, &Unavailable).unwrap_err();
        assert!(matches!(
            error,
            MasterKeyError::NativeStoreUnavailable { .. }
        ));
        assert!(error.to_string().contains("--key-path"));
        assert!(!config.data_dir.join("key-source").exists());
        assert_eq!(
            file_source
                .backend()
                .load_slot(&config.data_dir, KeySlot::Current)
                .unwrap()
                .unwrap()
                .key_id(),
            file_key.key_id()
        );
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
        // Match on the file names: both paths are canonicalised, which on Windows adds
        // a `\\?\` verbatim prefix, so the full input paths don't appear verbatim.
        let names = |p: &Path| p.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            error.contains("key-source records file:")
                && error.contains(&names(path))
                && error.contains(&names(&different)),
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
            ("version:1\nunknown-native-store\n", "unknown-native-store"),
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

    /// Runs on every OS: checks each OS's default store (macOS keychain, Windows
    /// Credential Manager, Linux Secret Service) and that creating a key in another
    /// OS's store is refused.
    #[test]
    fn fresh_bootstrap_without_path_names_both_override_remedies() {
        use crate::resolver::refuse_unsupported_bootstrap;
        let error = refuse_unsupported_bootstrap(&KeySource::Keychain, false, "linux")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("--key-path") && error.contains("CK_MASTER_KEY_PATH"),
            "{error}"
        );
        for (platform, source) in [
            ("macos", KeySource::Keychain),
            ("windows", KeySource::CredentialManager),
            ("linux", KeySource::SecretService),
        ] {
            assert_eq!(super::super::native_source_for(platform), source);
            assert!(refuse_unsupported_bootstrap(&source, false, platform).is_ok());
            assert!(refuse_unsupported_bootstrap(&source, false, "unsupported-os").is_err());
            assert!(refuse_unsupported_bootstrap(&source, true, "unsupported-os").is_ok());
        }
        let (_root, config) = fixture("source-file-any-os");
        assert!(refuse_unsupported_bootstrap(&config.source, false, "unsupported-os").is_ok());
        #[cfg(not(target_os = "macos"))]
        {
            let (_root, mut config) = fixture("source-platform-default");
            config.source = KeySource::Keychain;
            assert!(bootstrap(&config).is_err());
            assert!(!config.data_dir.join("key-source").exists());
        }
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
        use std::os::unix::fs::MetadataExt;
        let (_root, config) = fixture("source-owner");
        bootstrap(&config).unwrap();
        let KeySource::OperatorPath { path } = &config.source else {
            unreachable!()
        };
        let uid = std::fs::metadata(path).unwrap().uid();
        // Only root can change a file's owner. When chown fails, the test prints a
        // skip line and returns instead of passing silently.
        if std::os::unix::fs::chown(path, Some(uid.wrapping_add(1)), None).is_err() {
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
