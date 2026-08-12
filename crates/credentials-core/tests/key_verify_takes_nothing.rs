//! `ck_key_verify` must acquire NOTHING EXCLUSIVE, proven against a held lease.
//!
//! The tool's own doc records that an earlier version opened the store through
//! `open_sqlite`, which acquires the single-writer lease as a side effect. Run against a
//! live vault it claimed the database at a higher epoch and FENCED THE RUNNING DAEMON
//! OUT OF ITS OWN STORE: reads kept working while every write was refused, and the tool
//! reported success throughout, because taking a lease is not a write and nothing in its
//! output could show it.
//!
//! That property was documented and never tested. A comment describing a past regression
//! is exactly the shape that comes back -- a plausible later repair ("just open the store
//! the normal way") reintroduces it, and every existing check stays green because the
//! damage is invisible from inside the tool.
//!
//! THE ASSERTION THAT DISCRIMINATES, arrived at by discarding two wrong ones. Both
//! failures were mine and both are worth recording, because each looked like a working
//! test.
//!
//! FIRST WRONG SHAPE: run the tool while the lease is held, then assert the HOLDER can
//! still write. Measured: `open_sqlite` FAILS CLOSED on contention rather than stealing
//! a held lease, so a lease-taking tool simply errors and the holder is untouched. The
//! assertion can never fire.
//!
//! SECOND WRONG SHAPE: run the tool unheld, then assert a daemon-shaped open SUCCEEDS.
//! Measured: the lease is an `flock`, released by the OS when the holding process exits
//! (`cortexkit-lease` `try_lock_exclusive`), so a short-lived tool CANNOT leave one
//! behind whatever it does. That property is guaranteed by the lease mechanism, not by
//! this tool -- so the assertion holds for every possible version of it, including a
//! deliberately broken one. An unkillable test.
//!
//! WHAT IS ACTUALLY AT STAKE, and it is the opposite of what I first wrote: a
//! lease-taking tool does not corrupt the daemon, it REFUSES TO RUN while the daemon is
//! up. The regression's damage was to the diagnostic's availability -- the same class as
//! `verify-audit` being unrunnable for six weeks. So the test is: WITH THE LEASE HELD,
//! THE TOOL MUST STILL WORK. Mutation-verified by making it open the store the ordinary
//! way, which fails exactly there.
//!
//! Requires `--features migration-tools`, which is what builds the binary.

use std::path::PathBuf;

use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::audit::AuditOp;
use credentials_core::record::{CredentialKind, VaultRecord};
use credentials_core::store::EncryptedStore;

fn rig() -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let root = std::env::temp_dir().join(format!(
        "ck-key-verify-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("data")).unwrap();
    std::fs::create_dir_all(root.join("secrets")).unwrap();
    root
}

fn descriptor(data_dir: &std::path::Path) -> StorageDescriptor {
    StorageDescriptor {
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: data_dir.join("store.db").to_string_lossy().into_owned(),
        },
    }
}

#[test]
fn key_verify_still_works_while_the_daemon_holds_the_lease() {
    let root = rig();
    let data_dir = root.join("data");
    let key_path = root.join("secrets").join("master.key");

    // Provision an operator-path key and a store sealed under it, then keep the store
    // OPEN -- this handle holds the single-writer lease, exactly as the running daemon
    // does.
    let key = credentials_core::resolver::bootstrap(&credentials_core::resolver::ResolverConfig {
        data_dir: data_dir.clone(),
        source: credentials_core::resolver::KeySource::OperatorPath {
            path: key_path.clone(),
        },
    })
    .expect("bootstrap an operator-path key");

    // Seed the store, then keep the handle: this holds the single-writer lease for the
    // rest of the test, exactly as the running daemon does.
    let held = {
        let raw = open_sqlite(&descriptor(&data_dir)).expect("open store");
        EncryptedStore::migrate(&raw).expect("migrate");
        let store = EncryptedStore::open(raw, key).expect("open vault");
        store
            .create(
                "apikey:one",
                &VaultRecord::new_static(
                    CredentialKind::ApiKey,
                    "operator",
                    b"secret".to_vec(),
                    None,
                ),
            )
            .expect("seed a credential");
        store
            .append_audit(&credentials_core::audit::AuditRecord {
                op: AuditOp::MintHandle,
                credential_id: Some("apikey:one".into()),
                payload_hash: None,
                actor: "test-baseline".into(),
                alarm: None,
            })
            .expect("baseline write must succeed before the tool runs");
        store
    };

    // CK_MASTER_KEY_PATH is also the arm that found the original defect: the tool
    // hardcoded KeySource::Keychain, so an operator-path vault -- a headless or CI host,
    // much of who runs a migration -- could not be verified at all. Same defect as the
    // usable-audit's, fixed hours earlier without a sweep for siblings, which is how it
    // survived here.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ck_key_verify"))
        .arg(&data_dir)
        .env("CK_MASTER_KEY_PATH", &key_path)
        .output()
        .expect("run ck_key_verify");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        out.status.success(),
        "the tool must read a vault whose lease is HELD -- that is the whole point of \
         it acquiring nothing exclusive\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("MATCH"),
        "it must actually compare the anchor against the resolved key, not merely \
         exit zero: {stdout}"
    );

    // The lease holder is untouched -- it was never the thing at risk, but asserting it
    // keeps the rig honest: a test where the holder had silently died would pass the
    // tool assertions above for the wrong reason.
    held.append_audit(&credentials_core::audit::AuditRecord {
        op: AuditOp::RevokeHandle,
        credential_id: Some("apikey:one".into()),
        payload_hash: None,
        actor: "test-after".into(),
        alarm: None,
    })
    .expect("and it must be able to WRITE, not merely open");

    let entries = held.read_audit(None).expect("read audit");
    let actors: Vec<&str> = entries.iter().map(|e| e.actor.as_str()).collect();
    assert!(
        actors.contains(&"test-baseline") && actors.contains(&"test-after"),
        "both writes must be durable: {actors:?}"
    );

    drop(held);
    let _ = std::fs::remove_dir_all(&root);
}
