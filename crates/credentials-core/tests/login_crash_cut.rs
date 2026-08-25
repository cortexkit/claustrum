//! The vault-native-login crash-cut conformance test (a ship-gate requirement for
//! first-party login, the login analogue of the rotate crash-cut test).
//!
//! Login is IMPORT-SHAPED, not refresh-shaped: it writes ZERO durable state before
//! the network exchange, and its only durable write is a SINGLE atomic fenced
//! transaction (`overwrite_unconditional_audited`). So there is no dangling-intent
//! window to reconcile — the crash-safety property that matters is that a crashed
//! `login --replace` NEVER strands the credential it replaces. Because the flow is
//! exchange(no durable write) -> single-atomic-txn, a crash leaves the credential in
//! EXACTLY ONE of two states, never a half-written third:
//!   before-write — crashed before the store commit: the OLD credential is fully
//!                  intact and still refreshable (original refresh token). This is
//!                  the non-vacuous never-strand guard: if login ever regressed to
//!                  invalidate-old-then-write, the old credential would be stranded
//!                  here and this test would fail.
//!   after-write  — crashed just after commit: the NEW credential is present at
//!                  version+1, the handle survived, and the audit chain verifies with
//!                  the distinct `Login` op.
//!
//! Only built under `login-test-seam` (the helper binary requires it). Unix-only:
//! relies on SIGKILL + the kernel releasing the advisory lease on process death.

#![cfg(all(unix, feature = "login-test-seam"))]

use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::resolver::{self, KeySource, ResolverConfig};
use credentials_core::store::EncryptedStore;

mod common;

const OLD_REFRESH: &str = "OLD-REFRESH-TOKEN-do-not-lose";
const NEW_REFRESH: &str = "NEW-INDEPENDENT-REFRESH-TOKEN";

/// Spawn the helper at one cut point, wait for it to park, SIGKILL it, and return the
/// rig dir so the caller can re-open the vault from the killed-at-cut state.
fn kill_at_cut(cut: &str) -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("ck-cred-login-cut-{}-{}", cut, std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&key_dir).unwrap();
    let db_path = data_dir.join("store.db");
    let marker = root.join("ready.marker");

    let helper = common::warmed(env!("CARGO_BIN_EXE_login_cut_helper"));
    let mut child = std::process::Command::new(helper)
        .arg(db_path.to_string_lossy().to_string())
        .arg(key_dir.to_string_lossy().to_string())
        .arg(marker.to_string_lossy().to_string())
        .arg(cut)
        .spawn()
        .expect("spawn login_cut_helper");

    let deadline = Instant::now() + Duration::from_secs(30);
    while !marker.exists() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("helper never reached cut '{cut}' within 30s");
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("helper exited early ({status:?}) before parking at '{cut}'");
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    child.kill().expect("SIGKILL helper");
    let status = child.wait().expect("reap helper");
    assert_eq!(
        status.signal(),
        Some(9),
        "helper died by SIGKILL, got {status:?}"
    );

    root
}

/// Re-open the vault a fresh CLI/daemon would open after the crash.
fn reopen(root: &Path) -> EncryptedStore {
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    let db_path = data_dir.join("store.db");
    let config = ResolverConfig {
        data_dir: data_dir.clone(),
        source: KeySource::OperatorPath {
            path: key_dir.join("master.key"),
        },
    };
    let descriptor = StorageDescriptor {
        module_id: "cortexkit-credentials".into(),
        storage_namespace: "vault".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: db_path.to_string_lossy().into_owned(),
        },
    };
    let store = open_sqlite(&descriptor).expect("reopen after kill");
    EncryptedStore::migrate(&store).expect("migrate");
    let db_key_id = EncryptedStore::read_db_key_id(&store)
        .expect("read db key id")
        .expect("vault has an audit-key row");
    let key = resolver::resolve_for_db(&config, db_key_id).expect("resolve key");
    EncryptedStore::open(store, key).expect("open vault")
}

/// The raw handle the helper minted for the old credential (persisted to the rig), so
/// the test can prove it still RESOLVES via the real public API after the crash.
fn seeded_handle(root: &Path) -> String {
    std::fs::read_to_string(root.join("data").join("handle.txt")).expect("read seeded handle")
}

/// Whether the audit chain contains an entry with the given op string.
fn audit_has_op(store: &EncryptedStore, op: &str) -> bool {
    store
        .read_audit(None)
        .expect("read audit")
        .iter()
        .any(|e| e.op == op)
}

#[test]
fn crash_before_login_write_leaves_old_credential_intact_and_refreshable() {
    let root = kill_at_cut("before-write");
    let store = reopen(&root);

    // The OLD credential is fully intact: readable, active, and carrying its ORIGINAL
    // refresh token — the replace never happened, so the working credential is not
    // stranded. This is the load-bearing never-strand guarantee for ALF.
    let record = store
        .get("oauth:anthropic")
        .expect("old credential readable after a pre-write crash");
    assert_eq!(record.record_version, 1, "still the original version");
    assert!(
        record.is_refreshable(),
        "the old credential is still refreshable (adapter + oauth intact)"
    );
    let oauth = record.oauth.as_ref().expect("oauth credential present");
    assert_eq!(
        oauth.refresh_token, OLD_REFRESH,
        "the ORIGINAL refresh token survived — the credential is not stranded"
    );
    // The handle minted for the old credential still resolves to it.
    let handle = seeded_handle(&root);
    assert_eq!(
        store.resolve_handle(&handle).expect("handle resolves"),
        "oauth:anthropic",
        "the old credential's handle survived"
    );
    // The audit chain verifies clean AND carries NO Login entry — proving the audit
    // append can never precede or escape the atomic login txn (forensics stay
    // trustworthy after a crash: no phantom Login for a login that never committed).
    assert_eq!(store.verify_audit_chain().expect("verify"), None);
    assert!(
        !audit_has_op(&store, "login"),
        "no dangling Login audit entry before the write committed"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn crash_after_login_write_commits_new_credential_and_keeps_handle() {
    let root = kill_at_cut("after-write");
    let store = reopen(&root);

    // The NEW credential committed atomically: present at version+1 with the new,
    // independent refresh token.
    let record = store
        .get("oauth:anthropic")
        .expect("new credential readable after a post-write crash");
    assert_eq!(record.record_version, 2, "bumped to version+1 by the login");
    let oauth = record.oauth.as_ref().expect("oauth credential present");
    assert_eq!(
        oauth.refresh_token, NEW_REFRESH,
        "the new independent refresh token is stored"
    );
    // The handle survived the replace (overwrite leaves the handles table untouched).
    let handle = seeded_handle(&root);
    assert_eq!(
        store.resolve_handle(&handle).expect("handle resolves"),
        "oauth:anthropic",
        "the handle survived the login --replace"
    );
    // The audit chain verifies and carries the distinct Login op.
    assert_eq!(store.verify_audit_chain().expect("verify"), None);
    assert!(
        audit_has_op(&store, "login"),
        "a distinct login audit op was recorded"
    );

    let _ = std::fs::remove_dir_all(&root);
}
