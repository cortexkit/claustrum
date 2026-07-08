//! Test-only helper for the master-key-rotation crash-cut conformance test.
//!
//! Only built under the `rotate-test-seam` feature. Unlike the kill-9 helper, this
//! compiles NO seam into the library: the two-slot rotation handover's cut points
//! are the boundaries between discrete PUBLIC operations, each individually atomic
//! (stage the new key into `next` -> rewrap the database under the new key in one
//! fenced transaction -> promote `next` to `current`). This helper drives that
//! sequence and PARKS (writes a readiness marker, then blocks forever) right after
//! the step named by its cut argument, so the parent test can SIGKILL it and prove
//! the vault reopens from that exact on-disk state without ever bricking.
//!
//! Usage: `rotate_cut_helper <db_path> <key_dir> <marker_path> <cut>`
//!   cut ∈ { stage, rewrap, promote }
//!     stage   = crash after `next` written, database still under the old key
//!     rewrap  = crash after the database rewrap commits (both slots present, not
//!               yet promoted) — this is also the "before promote" state
//!     promote = crash after promotion (current = new key, next cleared)
//!
//! The helper uses the operator-path key store (two files: master.key /
//! master.key.next) so it runs in CI without a keychain.

use std::path::PathBuf;

use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::key::MasterKey;
use credentials_core::record::{CredentialKind, VaultRecord};
use credentials_core::resolver::{self, KeySource, ResolverConfig};
use credentials_core::store::EncryptedStore;

fn park(marker: &PathBuf) -> ! {
    std::fs::write(marker, b"ready").expect("write readiness marker");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let db_path = args.next().expect("usage: <db> <key_dir> <marker> <cut>");
    let key_dir = PathBuf::from(args.next().expect("missing key_dir"));
    let marker = PathBuf::from(args.next().expect("missing marker"));
    let cut = args.next().expect("missing cut point");

    let data_dir = PathBuf::from(&db_path)
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let config = ResolverConfig {
        data_dir: data_dir.clone(),
        source: KeySource::OperatorPath {
            path: key_dir.join("master.key"),
        },
    };

    // Bootstrap the current key (k1) and seed a credential so the rewrap has real
    // work to do (and the parent can prove the credential is still readable after).
    let k1 = resolver::bootstrap(&config).expect("bootstrap");
    let descriptor = StorageDescriptor {
        module_id: "cortexkit-credentials".into(),
        storage_namespace: "vault".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: db_path.clone(),
        },
    };
    let store = open_sqlite(&descriptor).expect("open store");
    EncryptedStore::migrate(&store).expect("migrate");
    let mut store = EncryptedStore::open(store, k1).expect("open vault under k1");
    let record =
        VaultRecord::new_static(CredentialKind::ApiKey, "operator", b"secret".to_vec(), None);
    store.create("cred", &record).expect("seed credential");

    // The new key.
    let k2 = MasterKey::generate().expect("csprng");

    // Step 1: stage k2 into `next` (database still under k1).
    resolver::stage_next(&config, &k2).expect("stage next");
    if cut == "stage" {
        park(&marker);
    }

    // Step 2: rewrap the database under k2 in one atomic fenced transaction.
    store.rotate_master_key(k2).expect("rewrap under k2");
    if cut == "rewrap" {
        park(&marker);
    }

    // The `double-heal-staged` cut models the SCHEME'S ONE HAZARD WINDOW under a real
    // crash: a SECOND rotation that begins while a FIRST rotation is still crashed
    // post-rewrap/pre-promote. We are exactly in that first-crashed state right now for
    // this cut (we did stage k2 + rewrap k2 above and did NOT promote), so:
    //   current = k1, next = k2, database under k2.
    // The CLI's second rotation heals first (promoting k2 -> current, freeing next), then
    // stages k3, then rewraps. We park RIGHT AFTER heal+stage, BEFORE the second rewrap —
    // the precise point where, WITHOUT the heal, staging k3 would have overwritten next=k2
    // (the key the database depends on) and a crash would brick (db=k2 matches neither
    // current=k1 nor next=k3). With the heal, current=k2 matches the database, so a crash
    // here resolves cleanly. SIGKILL at this park proves the resumed rotation never bricks.
    if cut == "double-heal-staged" {
        // `store` was rewrapped to k2 above, so its in-memory key_id IS the database's
        // current fingerprint (k2) — the heal anchor, with no second store open (which
        // would contend on the single-writer lease this process already holds).
        let db_key_id = store.key_id();
        // Heal promotes next=k2 -> current (matching the db) and frees next.
        resolver::heal_pending_rotation(&config, db_key_id).expect("heal before 2nd stage");
        // Stage the second rotation's new key into the freed next slot.
        let k3 = MasterKey::generate().expect("csprng k3");
        resolver::stage_next(&config, &k3).expect("stage k3");
        // Parked at: db under k2 = current (healed), next = k3, second rewrap NOT done.
        park(&marker);
    }

    // Step 3 (single rotation): promote `next` to `current`, clear `next`.
    resolver::promote_next(&config).expect("promote");
    if cut == "promote" {
        park(&marker);
    }

    eprintln!("rotate_cut_helper: completed without parking — unexpected cut '{cut}'");
    std::process::exit(2);
}
