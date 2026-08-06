//! The master-key-rotation crash-cut conformance test (a §13 ship-gate
//! requirement, the rotate analogue of the kill-9 mid-refresh test).
//!
//! For EACH cut point in the two-slot key handover, spawns the `rotate_cut_helper`
//! process, lets it drive the handover and park right after that step, sends a REAL
//! SIGKILL, then re-opens the SAME vault as a fresh process would and asserts it
//! NEVER bricks: crash-safe resolve (`resolve_for_db`) finds the key-store slot
//! whose fingerprint matches the database, the seeded credential is still readable,
//! and the audit chain still verifies. Also asserts a genuinely wrong key still
//! fails closed (so "never bricks" did not become "opens under anything").
//!
//! The cut points (the on-disk states a crash leaves):
//!   stage   — `next` written, database still under the OLD key  -> resolves to current
//!   rewrap  — database rewrapped under the NEW key, not promoted -> resolves to next
//!   promote — promoted (current = new key, next cleared)         -> resolves to current
//!
//! Only built under `rotate-test-seam` (the helper binary requires it). Unix-only:
//! relies on SIGKILL + the kernel releasing the advisory lease on process death.

#![cfg(all(unix, feature = "rotate-test-seam"))]

use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::key::MasterKey;
use credentials_core::resolver::{self, KeySlot, KeySource, MasterKeyError, ResolverConfig};
use credentials_core::store::{EncryptedStore, StoreOpError};

/// Spawn the helper at one cut point, wait for it to park, SIGKILL it, and return
/// the rig dir so the caller can re-open the vault from the killed-at-cut state.
fn kill_at_cut(cut: &str) -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("ck-cred-rotate-cut-{}-{}", cut, std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&key_dir).unwrap();
    let db_path = data_dir.join("store.db");
    let marker = root.join("ready.marker");

    let helper = env!("CARGO_BIN_EXE_rotate_cut_helper");
    let mut child = std::process::Command::new(helper)
        .arg(db_path.to_string_lossy().to_string())
        .arg(key_dir.to_string_lossy().to_string())
        .arg(marker.to_string_lossy().to_string())
        .arg(cut)
        .spawn()
        .expect("spawn rotate_cut_helper");

    // Wait until the helper parks at the requested cut point.
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

    // SIGKILL at the cut: uncatchable, no destructors — a true crash at this point.
    child.kill().expect("SIGKILL helper");
    let status = child.wait().expect("reap helper");
    assert_eq!(
        status.signal(),
        Some(9),
        "helper died by SIGKILL, got {status:?}"
    );

    root
}

/// Re-open the vault crash-safely from a killed-at-cut rig and assert it never
/// bricks: resolve finds the matching slot, the credential is readable, the chain
/// verifies. Returns the resolved key's fingerprint (hex) for cross-cut assertions.
fn assert_reopens_clean(root: &Path) -> String {
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

    // The crash-safe open path a fresh daemon/CLI would run: open store, read the
    // database's plaintext key fingerprint, resolve the matching key-store slot.
    let store = open_sqlite(&descriptor).expect("reopen after kill");
    EncryptedStore::migrate(&store).expect("migrate");
    let db_key_id = EncryptedStore::read_db_key_id(&store)
        .expect("read db key id")
        .expect("vault has an audit-key row");
    let key = resolver::resolve_for_db(&config, db_key_id)
        .expect("crash-safe resolve must find a matching slot (no brick)");
    let key_hex = key.key_id().to_hex();

    let store = EncryptedStore::open(store, key).expect("open vault under resolved key");
    // The seeded credential survived the rotation crash and is readable.
    assert_eq!(
        store
            .get("cred")
            .expect("credential readable after crash")
            .payload,
        b"secret",
        "the credential is intact after a crash at this cut"
    );
    // The audit chain still verifies under the stable audit key.
    assert_eq!(
        store.verify_audit_chain().expect("verify"),
        None,
        "audit chain intact after a crash at this cut"
    );
    key_hex
}

/// A genuinely wrong key (matching neither slot) must still fail closed at the
/// crash-safe resolve — "never bricks" must not have become "opens under anything".
fn assert_wrong_key_fails_closed(root: &Path) {
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
    let store = open_sqlite(&descriptor).expect("reopen");
    let _ = EncryptedStore::migrate(&store);
    // Use a stranger key_id (not the database's): no slot matches -> fail closed.
    let stranger = MasterKey::generate().unwrap().key_id();
    match resolver::resolve_for_db(&config, stranger) {
        Err(MasterKeyError::KeyMismatch { .. }) => {}
        other => panic!("a wrong key_id must fail closed, got {other:?}"),
    }
    // And the store's own open under a wrong key still fails closed (audit-key
    // decrypt KeyMismatch), independent of the slot logic.
    let wrong = MasterKey::generate().unwrap();
    match EncryptedStore::open(store, wrong) {
        Err(StoreOpError::Decrypt(_)) => {}
        other => panic!(
            "open under a wrong key must fail closed, got a non-decrypt result: {}",
            match other {
                Ok(_) => "Ok".into(),
                Err(e) => format!("{e:?}"),
            }
        ),
    }
}

/// Read the fingerprints the helper published for this rig.
///
/// Every rig generates fresh random keys, so "it reopened cleanly" is true of a
/// vault that was never rotated at all. Naming the expected key per cut is what
/// makes each test about the ROTATION rather than about opening a vault.
fn rig_keys(root: &Path) -> std::collections::HashMap<String, String> {
    let text = std::fs::read_to_string(root.join("data").join("keys.txt"))
        .expect("helper published its key fingerprints");
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Read one key-store slot's fingerprint, or `None` when the slot is empty.
fn slot_fingerprint(root: &Path, slot: KeySlot) -> Option<String> {
    let source = KeySource::OperatorPath {
        path: root.join("secrets").join("master.key"),
    };
    source
        .backend()
        .load_slot(&root.join("data"), slot)
        .expect("read key slot")
        .map(|key| key.key_id().to_hex())
}

#[test]
fn crash_after_stage_resolves_to_current_and_never_bricks() {
    let root = kill_at_cut("stage");
    // database still under the OLD key (k1): resolve must pick `current`.
    let resolved = assert_reopens_clean(&root);
    let keys = rig_keys(&root);
    assert_eq!(
        resolved, keys["k1"],
        "a crash after staging leaves the database under the OLD key, so resolve must \
         pick current=k1 — not merely open something"
    );
    assert_ne!(
        resolved, keys["k2"],
        "the staged key is not yet the database's"
    );
    // Resolving to k1 is also what a vault that was NEVER rotated would do, so assert
    // the on-disk fact that distinguishes them: the staged key really is in `next`.
    assert_eq!(
        slot_fingerprint(&root, KeySlot::Next).as_deref(),
        Some(keys["k2"].as_str()),
        "the crash happened AFTER staging, so k2 must be sitting in the next slot"
    );
    assert_wrong_key_fails_closed(&root);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn crash_after_rewrap_resolves_to_next_and_never_bricks() {
    let root = kill_at_cut("rewrap");
    // database rewrapped under the NEW key (k2), not promoted: resolve picks `next`.
    let resolved = assert_reopens_clean(&root);
    let keys = rig_keys(&root);
    assert_eq!(
        resolved, keys["k2"],
        "after the rewrap commits, the database is under the NEW key and resolve must \
         reach it through the unpromoted `next` slot — this is the cut that proves the \
         two-slot layout earns its existence"
    );
    assert_ne!(
        resolved, keys["k1"],
        "resolving to the old key here would mean the rewrap never happened"
    );
    // The slots say "rewrapped, not yet promoted": the database's key is still only
    // reachable through `next`, which is exactly the state promotion exists to end.
    assert_eq!(
        slot_fingerprint(&root, KeySlot::Current).as_deref(),
        Some(keys["k1"].as_str()),
        "current still holds the old key before promotion"
    );
    assert_eq!(
        slot_fingerprint(&root, KeySlot::Next).as_deref(),
        Some(keys["k2"].as_str()),
        "the database's key is reachable only via next at this cut"
    );
    assert_wrong_key_fails_closed(&root);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn crash_after_promote_resolves_to_current_and_never_bricks() {
    let root = kill_at_cut("promote");
    // promoted: current = new key, next cleared. resolve picks `current`.
    let resolved = assert_reopens_clean(&root);
    let keys = rig_keys(&root);
    assert_eq!(
        resolved, keys["k2"],
        "promotion completed, so the resolved key is the NEW one"
    );
    assert_ne!(
        resolved, keys["k1"],
        "the old key is no longer the database's"
    );
    // Resolving to k2 is true after the rewrap alone, so it cannot show promotion
    // happened. The slot layout can: promotion moves k2 into current and CLEARS next,
    // which is what stops the following rotation from overwriting the key the
    // database depends on.
    assert_eq!(
        slot_fingerprint(&root, KeySlot::Current).as_deref(),
        Some(keys["k2"].as_str()),
        "promotion moves the new key into current"
    );
    assert_eq!(
        slot_fingerprint(&root, KeySlot::Next),
        None,
        "promotion clears next, freeing it for the next rotation"
    );
    assert_wrong_key_fails_closed(&root);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn crash_during_a_resumed_second_rotation_never_bricks() {
    // The scheme's one hazard window: a second rotation that begins while a first is
    // still crashed post-rewrap/pre-promote. The helper reaches current=k1, next=k2,
    // db-under-k2, then runs the CLI's heal-before-stage (promoting k2->current, freeing
    // next) and stages k3, parking before the second rewrap. Without the heal, staging k3
    // would have clobbered next=k2 and this crash would brick (db=k2 matches neither
    // slot); with the heal, current=k2 matches the db and resolve is clean.
    let root = kill_at_cut("double-heal-staged");
    let resolved = assert_reopens_clean(&root);
    let keys = rig_keys(&root);
    assert_eq!(
        resolved, keys["k2"],
        "the heal promoted k2 to current before staging k3, so the database's key is \
         reachable; resolving to anything else means the heal did not run"
    );
    assert_ne!(
        resolved, keys["k3"],
        "k3 is merely staged — the database was never rewrapped under it"
    );
    assert_ne!(
        resolved, keys["k1"],
        "k1 was superseded by the first rotation"
    );
    // The heal is visible in the slots: k2 (the database's key) was promoted to
    // current, which is what freed next for k3. Without it, next would still hold k2
    // and staging k3 would have destroyed the only copy of the database's key.
    assert_eq!(
        slot_fingerprint(&root, KeySlot::Current).as_deref(),
        Some(keys["k2"].as_str()),
        "the heal promoted the database's key to current before the second stage"
    );
    assert_eq!(
        slot_fingerprint(&root, KeySlot::Next).as_deref(),
        Some(keys["k3"].as_str()),
        "the second rotation's key occupies next"
    );
    assert_wrong_key_fails_closed(&root);
    let _ = std::fs::remove_dir_all(&root);
}
