//! Opt-in real OS custody tests. CI must set CK_NATIVE_STORE_TESTS=1: an unavailable
//! store is then a failure, not a successful skip. Linux lock testing additionally
//! requires a disposable bus/keyring so it cannot lock a developer's login keyring.
#![forbid(unsafe_code)]

#[cfg(any(target_os = "linux", windows))]
mod native {
    use credentials_core::{
        key::MasterKey,
        resolver::{self, KeySlot, KeySource, MasterKeyStore, ResolverConfig},
    };
    use std::path::{Path, PathBuf};

    fn require_enabled() {
        assert_eq!(
            std::env::var("CK_NATIVE_STORE_TESTS").as_deref(),
            Ok("1"),
            "native custody tests require CK_NATIVE_STORE_TESTS=1 and an available OS store"
        );
    }

    struct Fixture {
        dir: PathBuf,
        source: KeySource,
        clean_store: bool,
    }
    impl Fixture {
        fn new() -> Self {
            let mut random = [0u8; 16];
            getrandom::getrandom(&mut random).unwrap();
            let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let dir =
                std::env::temp_dir().join(format!("ck-native-{}-{suffix}", std::process::id()));
            std::fs::create_dir(&dir).unwrap();
            Self {
                dir,
                clean_store: true,
                #[cfg(target_os = "linux")]
                source: KeySource::SecretService,
                #[cfg(windows)]
                source: KeySource::CredentialManager,
            }
        }
        fn config(&self) -> ResolverConfig {
            ResolverConfig {
                data_dir: self.dir.clone(),
                source: self.source.clone(),
            }
        }
        fn cleanup(&self) -> Result<(), resolver::MasterKeyError> {
            let backend = self.source.backend();
            // Attempt both removals even if the first fails.
            let current = backend.clear_slot(&self.dir, KeySlot::Current);
            let next = backend.clear_slot(&self.dir, KeySlot::Next);
            current.and(next)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if self.clean_store {
                if let Err(error) = self.cleanup() {
                    eprintln!(
                        "native test cleanup failed for {}: {error}",
                        self.dir.display()
                    );
                }
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn id(
        store: &dyn MasterKeyStore,
        dir: &Path,
        slot: KeySlot,
    ) -> Option<credentials_core::key::KeyId> {
        store.load_slot(dir, slot).unwrap().map(|key| key.key_id())
    }

    pub fn round_trip() {
        require_enabled();
        let fixture = Fixture::new();
        let config = fixture.config();
        let store = fixture.source.backend();
        assert!(store
            .load_slot(&fixture.dir, KeySlot::Current)
            .unwrap()
            .is_none());
        assert!(store
            .load_slot(&fixture.dir, KeySlot::Next)
            .unwrap()
            .is_none());
        let missing = resolver::resolve(&config, None).unwrap_err();
        assert!(matches!(missing, resolver::MasterKeyError::NotBootstrapped));
        assert!(missing.to_string().contains("ck auth bootstrap"));
        assert!(missing.to_string().contains("restore the missing key"));
        let current = resolver::bootstrap(&config).unwrap();
        let next = MasterKey::from_bytes([42; 32]);
        resolver::stage_next(&config, &MasterKey::from_bytes([41; 32])).unwrap();
        resolver::stage_next(&config, &next).unwrap();
        assert_eq!(
            id(store.as_ref(), &fixture.dir, KeySlot::Current),
            Some(current.key_id())
        );
        assert_eq!(
            id(store.as_ref(), &fixture.dir, KeySlot::Next),
            Some(next.key_id())
        );
        assert_eq!(
            resolver::resolve_for_db(&config, next.key_id())
                .unwrap()
                .key_id(),
            next.key_id()
        );
        resolver::heal_pending_rotation(&config, next.key_id()).unwrap();
        assert_eq!(
            id(store.as_ref(), &fixture.dir, KeySlot::Current),
            Some(next.key_id())
        );
        assert_eq!(id(store.as_ref(), &fixture.dir, KeySlot::Next), None);
        for slot in [KeySlot::Current, KeySlot::Next] {
            store.clear_slot(&fixture.dir, slot).unwrap();
            store.clear_slot(&fixture.dir, slot).unwrap();
            assert_eq!(id(store.as_ref(), &fixture.dir, slot), None);
        }
        fixture.cleanup().unwrap();
    }

    #[cfg(target_os = "linux")]
    pub fn locked_refusal() {
        require_enabled();
        // Prove the service is reachable before locking the disposable collection,
        // so an unavailable service cannot be mistaken for a locked-store refusal.
        let mut fixture = Fixture::new();
        let backend = fixture.source.backend();
        backend.load_slot(&fixture.dir, KeySlot::Current).unwrap();
        fixture.cleanup().unwrap();
        assert_eq!(
            std::env::var("CK_NATIVE_STORE_DISPOSABLE_SESSION").as_deref(),
            Ok("1"),
            "lock test requires CK_NATIVE_STORE_DISPOSABLE_SESSION=1 on an isolated bus/keyring"
        );
        // No items were created. After locking, cleanup must not access the collection.
        fixture.clean_store = false;
        let connection = zbus::blocking::Connection::session().unwrap();
        let service = zbus::blocking::Proxy::new(
            &connection,
            "org.freedesktop.secrets",
            "/org/freedesktop/secrets",
            "org.freedesktop.Secret.Service",
        )
        .unwrap();
        let collection: zbus::zvariant::OwnedObjectPath =
            service.call("ReadAlias", &("default",)).unwrap();
        let (_, prompt): (
            Vec<zbus::zvariant::OwnedObjectPath>,
            zbus::zvariant::OwnedObjectPath,
        ) = service.call("Lock", &(vec![collection],)).unwrap();
        assert_eq!(prompt.as_str(), "/", "locking must not require a prompt");
        let start = std::time::Instant::now();
        for result in [
            backend
                .load_slot(&fixture.dir, KeySlot::Current)
                .map(|_| ()),
            backend.store_slot(&fixture.dir, KeySlot::Next, &MasterKey::from_bytes([7; 32])),
            backend.clear_slot(&fixture.dir, KeySlot::Current),
        ] {
            let error = result.unwrap_err();
            assert!(error.is_vault_locked());
            let message = error.to_string();
            assert!(
                message.contains("locked") && message.contains("unlock the keyring"),
                "{message}"
            );
            assert!(
                message.contains("--key-path") && message.contains("CK_MASTER_KEY_PATH"),
                "{message}"
            );
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "a locked collection must refuse without waiting on a prompt"
        );
    }
}

#[test]
#[cfg(any(target_os = "linux", windows))]
#[ignore = "requires CK_NATIVE_STORE_TESTS=1 and an available native custody service"]
fn native_store_round_trip_both_slots_and_rotation() {
    #[cfg(any(target_os = "linux", windows))]
    native::round_trip();
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "requires CK_NATIVE_STORE_TESTS=1 and CK_NATIVE_STORE_DISPOSABLE_SESSION=1 on an isolated bus/keyring"]
fn secret_service_locked_collection_refuses_without_prompt() {
    #[cfg(target_os = "linux")]
    native::locked_refusal();
}
