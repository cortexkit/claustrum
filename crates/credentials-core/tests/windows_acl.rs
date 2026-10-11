//! Real Windows filesystem custody checks; wrappers keep the test count portable.
#![forbid(unsafe_code)]

#[cfg(windows)]
mod native {
    use credentials_core::resolver::{self, KeySource, MasterKeyError, ResolverConfig};
    use std::path::PathBuf;
    use subc_os::windows_acl::{
        self,
        test_support::{assert_dacl_owner_only, grant_everyone, grant_everyone_read},
    };

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let mut nonce = [0u8; 16];
            getrandom::getrandom(&mut nonce).unwrap();
            let suffix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
            let root = std::env::temp_dir().join(format!("claustrum-acl-{suffix}"));
            windows_acl::create_private_dir(&root).unwrap();
            Self(root)
        }

        fn config(&self) -> ResolverConfig {
            ResolverConfig {
                data_dir: self.0.join("vault"),
                source: KeySource::OperatorPath {
                    path: self.0.join("master.key"),
                },
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    pub fn extra_key_grant_is_refused() {
        let fixture = Fixture::new();
        let config = fixture.config();
        let key = resolver::bootstrap(&config).unwrap();
        assert_eq!(
            resolver::resolve(&config, None).unwrap().key_id(),
            key.key_id()
        );
        let path = fixture.0.join("master.key");
        grant_everyone_read(&path);
        let error = resolver::resolve(&config, None).unwrap_err();
        assert!(matches!(error, MasterKeyError::KeyPathUnsafe(_)), "{error}");
        let refusal = error.to_string();
        assert!(refusal.contains(&path.display().to_string()), "{refusal}");
        assert!(
            refusal.contains("remove inherited and explicit grants"),
            "{refusal}"
        );
        assert!(refusal.contains("do not regenerate the key"), "{refusal}");
    }

    pub fn created_key_has_protected_dacl() {
        let fixture = Fixture::new();
        let config = fixture.config();
        let key = resolver::bootstrap(&config).unwrap();
        assert_dacl_owner_only(&fixture.0.join("master.key"), false, true);
        assert_dacl_owner_only(&config.data_dir, true, true);
        assert_dacl_owner_only(&config.data_dir.join("key-source"), false, true);
        resolver::stage_next(&config, &key).unwrap();
        resolver::stage_next(&config, &key).unwrap();
        assert_dacl_owner_only(&fixture.0.join("master.key.next"), false, true);
    }

    pub fn inherited_vault_grants_are_tightened() {
        let fixture = Fixture::new();
        grant_everyone(&fixture.0);
        let config = fixture.config();
        std::fs::create_dir(&config.data_dir).unwrap();
        let descendant = config.data_dir.join("existing-metadata");
        std::fs::write(&descendant, b"not secret").unwrap();
        assert!(windows_acl::verify_private_dir(&config.data_dir).is_err());
        assert!(matches!(
            resolver::resolve(&config, None),
            Err(MasterKeyError::NotBootstrapped)
        ));
        assert_dacl_owner_only(&config.data_dir, true, true);
        assert_dacl_owner_only(&descendant, false, false);
    }
}

#[test]
fn windows_key_file_with_everyone_read_is_refused() {
    #[cfg(windows)]
    native::extra_key_grant_is_refused();
    #[cfg(not(windows))]
    eprintln!("SKIPPING windows_key_file_with_everyone_read_is_refused: requires Windows DACLs");
}

#[test]
fn windows_created_key_file_has_protected_owner_only_dacl() {
    #[cfg(windows)]
    native::created_key_has_protected_dacl();
    #[cfg(not(windows))]
    eprintln!(
        "SKIPPING windows_created_key_file_has_protected_owner_only_dacl: requires Windows DACLs"
    );
}

#[test]
fn windows_existing_vault_directory_loses_broad_inherited_grants() {
    #[cfg(windows)]
    native::inherited_vault_grants_are_tightened();
    #[cfg(not(windows))]
    eprintln!("SKIPPING windows_existing_vault_directory_loses_broad_inherited_grants: requires Windows DACLs");
}
