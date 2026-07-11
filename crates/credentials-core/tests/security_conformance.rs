//! §13 security-conformance suite — store-layer matrix (a v1 ship-gate requirement).
//!
//! The adversarial store-level checks the contract's §13 gate enumerates, exercised
//! through the PUBLIC API: the fail-closed error matrix (every failure mode is a
//! typed error, never a panic, never plaintext), overwrite-CAS (create-only rejects
//! a blind overwrite; a CAS mismatch is rejected; an admin overwrite raises a
//! durable audit alarm row), invalidate-then-get read-visibility, and concurrent
//! import+get. The kill-9 mid-refresh, rotate crash-cut, lease-handover, envelope
//! fuzz, and the on-the-wire malicious-local-client harness live in their own files.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::audit::{AuditCtx, AuditOp};
use credentials_core::key::{MasterKey, MASTER_KEY_LEN};
use credentials_core::record::{CredentialKind, VaultRecord};
use credentials_core::store::{payload_hash, EncryptedStore, StoreOpError};

fn tmp_root(tag: &str) -> std::path::PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "ck-cred-conf-{}-{}-{}",
        tag,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn descriptor(root: &std::path::Path) -> StorageDescriptor {
    StorageDescriptor {
        module_id: "cortexkit-credentials".into(),
        storage_namespace: "vault".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: root.join("store.db").to_string_lossy().into_owned(),
        },
    }
}

fn open(root: &std::path::Path, seed: u8) -> EncryptedStore {
    let store = open_sqlite(&descriptor(root)).expect("open");
    EncryptedStore::migrate(&store).expect("migrate");
    EncryptedStore::open(store, MasterKey::from_bytes([seed; MASTER_KEY_LEN])).expect("open vault")
}

fn api_key_record(secret: &[u8]) -> VaultRecord {
    VaultRecord::new_static(CredentialKind::ApiKey, "operator", secret.to_vec(), None)
}

// ---- fail-closed matrix --------------------------------------------------
// Every failure mode is a typed StoreOpError, never a panic, and never returns the
// secret payload.

#[test]
fn fail_closed_absent_is_not_found() {
    let root = tmp_root("fc-absent");
    let store = open(&root, 1);
    assert!(matches!(store.get("nope"), Err(StoreOpError::NotFound)));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn fail_closed_needs_reauth_does_not_yield_payload() {
    let root = tmp_root("fc-reauth");
    let store = open(&root, 1);
    store.create("id", &api_key_record(b"top-secret")).unwrap();
    store.invalidate("id").unwrap();
    // A needs_reauth record is a typed error — the secret is never returned.
    match store.get("id") {
        Err(StoreOpError::NeedsReauth) => {}
        other => panic!("expected NeedsReauth, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn fail_closed_wrong_key_never_opens_and_never_plaintext() {
    // A vault opened under the wrong master key fails closed at open() (the sealed
    // audit-key decrypt fails) — the secret is never decryptable.
    let root = tmp_root("fc-wrongkey");
    {
        let store = open(&root, 1);
        store.create("id", &api_key_record(b"top-secret")).unwrap();
    }
    let reopened = open_sqlite(&descriptor(&root)).unwrap();
    EncryptedStore::migrate(&reopened).unwrap();
    match EncryptedStore::open(reopened, MasterKey::from_bytes([0xAB; MASTER_KEY_LEN])) {
        Err(StoreOpError::Decrypt(_)) => {}
        Err(other) => panic!("expected a Decrypt fail-closed, got {other:?}"),
        Ok(_) => panic!("wrong key must not open the vault"),
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn fail_closed_corrupt_envelope_quarantines_not_panics() {
    // A row whose ciphertext is corrupted on disk is QUARANTINED on read (typed
    // error), never panics, never yields plaintext — and other records still serve.
    let root = tmp_root("fc-corrupt");
    {
        let store = open(&root, 1);
        store
            .create("good", &api_key_record(b"good-secret"))
            .unwrap();
        store.create("bad", &api_key_record(b"bad-secret")).unwrap();
    } // drop releases the single-writer lease so we can tamper directly.

    // Corrupt the "bad" record's envelope bytes directly on disk (a key-less
    // attacker / bit-rot), then reopen and read.
    {
        let conn = rusqlite::Connection::open(root.join("store.db")).unwrap();
        conn.execute(
            "UPDATE credentials SET envelope = ?2 WHERE credential_id = ?1",
            rusqlite::params!["bad", vec![0u8; 64]],
        )
        .unwrap();
    }

    let store = open(&root, 1);
    match store.get("bad") {
        Err(StoreOpError::Decrypt(_)) | Err(StoreOpError::Corrupt(_)) => {}
        other => panic!("expected a fail-closed corrupt error, got {other:?}"),
    }
    // Fault isolation: the healthy record still serves.
    assert_eq!(store.get("good").unwrap().payload, b"good-secret");
    let _ = std::fs::remove_dir_all(&root);
}

// ---- overwrite-CAS -------------------------------------------------------

#[test]
fn create_only_rejects_blind_overwrite() {
    let root = tmp_root("cas-createonly");
    let store = open(&root, 1);
    store.create("id", &api_key_record(b"v1")).unwrap();
    // A second create is rejected (no blind overwrite via create).
    match store.create("id", &api_key_record(b"v2")) {
        Err(StoreOpError::AlreadyExists) => {}
        other => panic!("expected AlreadyExists, got {other:?}"),
    }
    // The original is unchanged.
    assert_eq!(store.get("id").unwrap().payload, b"v1");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn cas_mismatch_rejected_and_record_unchanged() {
    let root = tmp_root("cas-mismatch");
    let store = open(&root, 1);
    store.create("id", &api_key_record(b"v1")).unwrap();
    let wrong = payload_hash(b"not the current payload");
    match store.overwrite_cas("id", &api_key_record(b"v2"), &wrong) {
        Err(StoreOpError::CasMismatch) => {}
        other => panic!("expected CasMismatch, got {other:?}"),
    }
    assert_eq!(
        store.get("id").unwrap().record_version,
        1,
        "unchanged after rejected CAS"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn admin_overwrite_raises_audit_alarm_row() {
    // An admin overwrite goes through with an AdminWrite alarm; the durable audit
    // row must be flagged (alarm=true) and the chain must verify.
    let root = tmp_root("cas-alarm");
    let store = open(&root, 1);
    store.create("id", &api_key_record(b"v1")).unwrap();
    let cur = store.get("id").unwrap();
    let expect = payload_hash(&cur.payload);
    store
        .overwrite_cas_audited(
            "id",
            &api_key_record(b"v2"),
            &expect,
            AuditCtx::admin(AuditOp::Overwrite),
        )
        .expect("admin overwrite");

    let entries = store.read_audit(None).unwrap();
    let overwrite = entries
        .iter()
        .find(|e| e.op == "overwrite")
        .expect("an overwrite audit entry exists");
    assert!(overwrite.alarm, "admin overwrite is a flagged alarm row");
    assert_eq!(overwrite.alarm_reason.as_deref(), Some("admin_write"));
    assert_eq!(store.verify_audit_chain().unwrap(), None, "chain verifies");
    let _ = std::fs::remove_dir_all(&root);
}

// ---- invalidate-then-get + concurrent import+get -------------------------

#[test]
fn invalidate_then_get_is_needs_reauth_and_revokes_handles() {
    let root = tmp_root("inval-get");
    let store = open(&root, 1);
    store.create("id", &api_key_record(b"secret")).unwrap();
    let h = credentials_core::store::mint_handle().unwrap();
    store
        .put_handle_hash(&h.hash, "id", AuditCtx::admin(AuditOp::MintHandle))
        .unwrap();
    assert_eq!(store.resolve_handle(&h.raw).unwrap(), "id");

    // Authoritative invalidate, then revoke its handles (the admin invalidate flow).
    store.invalidate("id").unwrap();
    store
        .revoke_all_handles("id", AuditCtx::admin(AuditOp::RevokeHandle))
        .unwrap();

    // get fails closed; the handle no longer resolves.
    assert!(matches!(store.get("id"), Err(StoreOpError::NeedsReauth)));
    assert!(matches!(
        store.resolve_handle(&h.raw),
        Err(StoreOpError::NotFound)
    ));
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_create_and_get_read_visibility() {
    // Concurrent imports (creates) of distinct credentials interleaved with reads:
    // each create is atomic, so a get either sees NotFound (before) or the full
    // record (after) — never a torn/partial read. The single-writer fence serializes
    // the writes; reads are lock-free.
    let root = tmp_root("concurrent");
    let store = Arc::new(open(&root, 1));

    let mut writers = Vec::new();
    for i in 0..16u8 {
        let store = Arc::clone(&store);
        writers.push(tokio::spawn(async move {
            let id = format!("cred-{i}");
            store
                .create(&id, &api_key_record(format!("secret-{i}").as_bytes()))
                .expect("create");
        }));
    }
    // Concurrent readers polling ids that appear mid-flight.
    let mut readers = Vec::new();
    for i in 0..16u8 {
        let store = Arc::clone(&store);
        readers.push(tokio::spawn(async move {
            let id = format!("cred-{i}");
            for _ in 0..50 {
                match store.get(&id) {
                    Ok(rec) => {
                        // If visible, it must be the COMPLETE record (no torn read).
                        assert_eq!(rec.payload, format!("secret-{i}").into_bytes());
                        return;
                    }
                    Err(StoreOpError::NotFound) => {
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    }
                    Err(e) => panic!("unexpected read error: {e:?}"),
                }
            }
        }));
    }
    for w in writers {
        w.await.unwrap();
    }
    for r in readers {
        r.await.unwrap();
    }
    // All 16 are present and complete after the writers finish.
    for i in 0..16u8 {
        let rec = store.get(&format!("cred-{i}")).expect("present");
        assert_eq!(rec.payload, format!("secret-{i}").into_bytes());
    }
    let _ = std::fs::remove_dir_all(&root);
}
