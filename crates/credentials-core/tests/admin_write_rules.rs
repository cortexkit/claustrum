use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::{
    admin_ops::{apply, AdminOpBody},
    audit::AlarmReason,
    key::MasterKey,
    record::{CredentialKind, VaultRecord},
    store::EncryptedStore,
    test_support::TestTempDir,
};

/// A store in its own temp directory, returned with the directory so it outlives the store.
///
/// Not `:memory:`: the single-writer lease file lives beside the database path, and an
/// in-memory path has no directory, so the lease landed in the test's working directory
/// (the crate root) and was left there as an untracked file after every run.
fn store() -> (TestTempDir, EncryptedStore) {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let dir = TestTempDir::new(format!(
        "admin-write-rules-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let raw = open_sqlite(&StorageDescriptor {
        module_id: "admin-write-rules".into(),
        storage_namespace: "default".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: dir.join("store.db").to_string_lossy().into_owned(),
        },
    })
    .unwrap();
    EncryptedStore::migrate(&raw).unwrap();
    let store = EncryptedStore::open(raw, MasterKey::from_bytes([23; 32])).unwrap();
    (dir, store)
}

fn approval(id: &str, hash: &str) -> AdminOpBody {
    AdminOpBody::Approval {
        v: 1,
        credential_id: id.into(),
        artifact_sha256: hash.into(),
        approver: "vault".into(),
    }
}

#[test]
fn approval_preserves_admin_origin_without_actor_impersonation() {
    let (_dir, store) = store();
    store
        .create(
            "signing:root",
            &VaultRecord::new_static(
                CredentialKind::SigningKey,
                "operator",
                b"seed".to_vec(),
                None,
            ),
        )
        .unwrap();
    let hash = "a".repeat(64);
    for origin in ["route-admin/gen-7", "offline-cli"] {
        let reply = apply(&store, approval("signing:root", &hash), origin).unwrap();
        assert_eq!(reply["approver"], "vault");
        let entries = store.read_audit(None).unwrap();
        let entry = entries.last().unwrap();
        assert_eq!(entry.actor, format!("{origin}/approver:vault"));
        assert!(entry.alarm);
        assert_eq!(
            entry.alarm_reason.as_deref(),
            Some(AlarmReason::AdminWrite.as_str())
        );
        assert_eq!(entry.payload_hash.as_deref(), Some(hash.as_str()));
    }
}

#[test]
fn approval_rejects_invalid_artifact_hash_without_audit_write() {
    let (_dir, store) = store();
    store
        .create(
            "signing:root",
            &VaultRecord::new_static(
                CredentialKind::SigningKey,
                "operator",
                b"seed".to_vec(),
                None,
            ),
        )
        .unwrap();
    let before = store.read_audit(None).unwrap().len();
    for hash in [
        "A".repeat(64),
        "g".repeat(64),
        "a".repeat(63),
        "a".repeat(65),
        "é".repeat(32),
    ] {
        assert!(apply(&store, approval("signing:root", &hash), "route-admin").is_err());
        assert_eq!(store.read_audit(None).unwrap().len(), before);
    }
}

#[test]
fn approval_requires_an_existing_signing_key_without_audit_write() {
    let (_dir, store) = store();
    store
        .create(
            "apikey:root",
            &VaultRecord::new_static(CredentialKind::ApiKey, "operator", b"seed".to_vec(), None),
        )
        .unwrap();
    let before = store.read_audit(None).unwrap().len();
    for id in ["missing", "apikey:root"] {
        assert!(apply(&store, approval(id, &"a".repeat(64)), "route-admin").is_err());
        assert_eq!(store.read_audit(None).unwrap().len(), before);
    }
}

#[test]
fn legacy_prefix_grants_are_refused_with_migration_guidance() {
    let (_dir, store) = store();
    let before = store.read_audit(None).unwrap().len();
    for tag in ["admin.grant_create", "admin.grant_revoke"] {
        let op = serde_json::from_value(serde_json::json!({"op":tag,"v":1,"principal_id":"client","credential_prefix":"oauth:","operation":"read"})).unwrap();
        let error = apply(&store, op, "route-admin").unwrap_err().to_string();
        assert!(
            error.contains("prefix grants were removed")
                && error.contains("exact")
                && error.contains("category"),
            "{error}"
        );
        assert_eq!(store.read_audit(None).unwrap().len(), before);
    }
}
