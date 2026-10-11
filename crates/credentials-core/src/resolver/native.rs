//! Native custody uses the existing vault service and slot accounts. Secret Service
//! calls are made below its prompting convenience APIs: prompt handles are refusals.

#[cfg(any(windows, target_os = "linux", test))]
use super::KeychainCli;
use super::{KeySlot, MasterKeyError, MasterKeyStore};
use crate::key::MasterKey;
use std::path::Path;

/// Windows per-user generic credentials, protected at rest by DPAPI.
pub struct CredentialManager;
/// Linux's default Secret Service collection on the user's session bus.
pub struct SecretService;

fn unavailable(backend: &'static str, reason: impl ToString) -> MasterKeyError {
    MasterKeyError::NativeStoreUnavailable {
        backend,
        reason: reason.to_string(),
    }
}

// Both native implementations use this write path so rotation cannot choose a
// different item identity from load/delete. Reuse the existing keychain service
// derivation unchanged so upgrades still address every provisioned macOS vault key.
#[cfg(any(windows, target_os = "linux", test))]
fn write_slot(
    data_dir: &Path,
    slot: KeySlot,
    key: &MasterKey,
    write: impl FnOnce(&str, &str, &str) -> Result<(), MasterKeyError>,
) -> Result<(), MasterKeyError> {
    let service = KeychainCli::service_for(data_dir)?;
    let account = KeychainCli::account_for(slot);
    let encoded = super::encode_hex_key(key);
    write(&service, &account, &encoded)
}

/// Secret Service answers `/` when an operation completed and a prompt path when it
/// needs one. A prompt path is refused, never executed: the vault runs unattended.
#[cfg(any(target_os = "linux", test))]
fn refuse_prompt_path(path: &str) -> Result<(), MasterKeyError> {
    if path == "/" {
        Ok(())
    } else {
        Err(unavailable(
            "secret-service",
            "operation requires an interactive prompt; unattended access refused",
        ))
    }
}

#[cfg(any(windows, target_os = "linux", test))]
fn decode_secret(raw: &[u8]) -> Result<MasterKey, MasterKeyError> {
    let bytes = super::decode_hex_key(raw)?;
    Ok(MasterKey::from_bytes(*bytes))
}

#[cfg(windows)]
mod windows {
    use super::*;
    use zeroize::Zeroizing;

    fn entry(service: &str, account: &str) -> Result<keyring::Entry, MasterKeyError> {
        // Explicit target keeps the two slot accounts distinct in the flat Windows store.
        keyring::Entry::new_with_target(&format!("{service}/{account}"), service, account)
            .map_err(|e| unavailable("credential-manager", e))
    }

    impl MasterKeyStore for CredentialManager {
        fn load_slot(
            &self,
            dir: &Path,
            slot: KeySlot,
        ) -> Result<Option<MasterKey>, MasterKeyError> {
            let service = KeychainCli::service_for(dir)?;
            match entry(&service, &KeychainCli::account_for(slot))?.get_password() {
                Ok(value) => decode_secret(Zeroizing::new(value).as_bytes()).map(Some),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(unavailable("credential-manager", e)),
            }
        }

        fn store_slot(
            &self,
            dir: &Path,
            slot: KeySlot,
            key: &MasterKey,
        ) -> Result<(), MasterKeyError> {
            write_slot(dir, slot, key, |service, account, encoded| {
                entry(service, account)?
                    .set_password(encoded)
                    .map_err(|e| unavailable("credential-manager", e))
            })
        }

        fn clear_slot(&self, dir: &Path, slot: KeySlot) -> Result<(), MasterKeyError> {
            let service = KeychainCli::service_for(dir)?;
            match entry(&service, &KeychainCli::account_for(slot))?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(unavailable("credential-manager", e)),
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod linux;

macro_rules! unsupported_store {
    ($store:ty, $backend:literal) => {
        impl MasterKeyStore for $store {
            fn load_slot(&self, _: &Path, _: KeySlot) -> Result<Option<MasterKey>, MasterKeyError> {
                Err(unavailable($backend, "this build is running on another OS"))
            }
            fn store_slot(
                &self,
                _: &Path,
                _: KeySlot,
                _: &MasterKey,
            ) -> Result<(), MasterKeyError> {
                Err(unavailable($backend, "this build is running on another OS"))
            }
            fn clear_slot(&self, _: &Path, _: KeySlot) -> Result<(), MasterKeyError> {
                Err(unavailable($backend, "this build is running on another OS"))
            }
        }
    };
}
#[cfg(not(windows))]
unsupported_store!(CredentialManager, "credential-manager");
#[cfg(not(target_os = "linux"))]
unsupported_store!(SecretService, "secret-service");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestTempDir;
    use std::collections::HashMap;

    #[test]
    fn native_write_preserves_both_slot_identities() {
        let dir = TestTempDir::new(format!("native-slot-{}", std::process::id()));
        let current = MasterKey::from_bytes([11; 32]);
        let next = MasterKey::from_bytes([22; 32]);
        let mut items = HashMap::new();
        for (slot, key) in [(KeySlot::Current, &current), (KeySlot::Next, &next)] {
            write_slot(&dir, slot, key, |service, account, value| {
                assert_eq!(
                    Some(service.to_owned()),
                    crate::contract::keychain_service_for(&dir)
                );
                items.insert(
                    account.to_owned(),
                    decode_secret(value.as_bytes())?.key_id(),
                );
                Ok(())
            })
            .unwrap();
        }
        let account = crate::contract::KEYCHAIN_ACCOUNT_CURRENT;
        assert_eq!(items.len(), 2);
        assert_eq!(items.get(account), Some(&current.key_id()));
        assert_eq!(items.get(&format!("{account}-next")), Some(&next.key_id()));
    }

    #[test]
    fn secret_service_prompt_handle_is_refused() {
        assert!(refuse_prompt_path("/").is_ok());
        let error = refuse_prompt_path("/org/freedesktop/secrets/prompt/1").unwrap_err();
        assert!(error.to_string().contains("unlock the keyring"));
        assert!(error.to_string().contains("interactive prompt"));
    }

    #[test]
    fn native_refusals_name_store_and_remedies() {
        let missing = MasterKeyError::NotBootstrapped.to_string();
        assert!(
            missing.contains("ck auth bootstrap") && missing.contains("restore the missing key")
        );
        for backend in ["credential-manager", "secret-service"] {
            let error = unavailable(backend, "access refused");
            assert!(error.is_vault_locked());
            let message = error.to_string();
            for expected in [
                backend,
                "--key-path",
                "CK_MASTER_KEY_PATH",
                "cannot be redirected",
                "access refused",
            ] {
                assert!(message.contains(expected), "{message}");
            }
            assert!(message.contains(if backend == "secret-service" {
                "unlock the keyring"
            } else {
                "sign in as the vault owner"
            }));
        }
    }
}
