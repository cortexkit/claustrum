//! End-to-end tests of the offline admin CLI binary.
//!
//! Drives the real `ck-creds` process against a temp vault dir with an
//! operator key path (so no keychain is touched), exercising the structural
//! master-key proof and the audit chain end-to-end: bootstrap a key, put a
//! credential, mint a handle, list + verify the audit chain. Also proves the
//! single-writer lease makes admin writes mutually exclusive with a held lease.

use std::path::PathBuf;
use std::process::Command;

use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ck-creds"))
}

fn tmp_root(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "ck-cred-cli-{}-{}-{}",
        std::process::id(),
        tag,
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn bootstrap_put_mint_audit_end_to_end() {
    let root = tmp_root("e2e");
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    std::fs::create_dir_all(&key_dir).unwrap();
    let key_path = key_dir.join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();

    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    // bootstrap a master key.
    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    let out = c.output().expect("run bootstrap");
    assert!(
        out.status.success(),
        "bootstrap: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // put an api_key credential.
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("operator:db")
        .arg("--payload")
        .arg("sk-secret");
    global(&mut c);
    let out = c.output().expect("run put");
    assert!(
        out.status.success(),
        "put: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // mint a handle for it: stdout is the raw handle.
    let mut c = cli();
    c.arg("mint-handle").arg("--id").arg("operator:db");
    global(&mut c);
    let out = c.output().expect("run mint-handle");
    assert!(
        out.status.success(),
        "mint: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let handle = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(handle.starts_with("ckh_"), "raw handle on stdout: {handle}");

    // verify-audit: the chain (put + mint_handle entries) must be intact.
    let mut c = cli();
    c.arg("verify-audit");
    global(&mut c);
    let out = c.output().expect("run verify-audit");
    assert!(
        out.status.success(),
        "verify-audit: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("intact"));

    // audit list shows the operations with the offline-cli actor.
    let mut c = cli();
    c.arg("audit");
    global(&mut c);
    let out = c.output().expect("run audit");
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(listing.contains("put"), "audit lists the put: {listing}");
    assert!(
        listing.contains("mint_handle"),
        "audit lists the mint: {listing}"
    );
    assert!(listing.contains("offline-cli"), "actor recorded: {listing}");

    // list shows the credential id + its active state (no secrets, no decrypt).
    let mut c = cli();
    c.arg("list");
    global(&mut c);
    let out = c.output().expect("run list");
    assert!(
        out.status.success(),
        "list: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows = String::from_utf8_lossy(&out.stdout);
    assert!(rows.contains("operator:db"), "list names the id: {rows}");
    assert!(rows.contains("active"), "list shows state: {rows}");
    assert!(
        !rows.contains("sk-secret"),
        "list must never print the payload: {rows}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// `logout` stops serving reversibly (invalidate + revoke handles, row + audit
/// kept), and `status` reports the resulting degraded state with the affected id.
#[test]
fn logout_is_reversible_stop_serving_and_status_reports_it() {
    let root = tmp_root("logout");
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    std::fs::create_dir_all(&key_dir).unwrap();
    let key_path = key_dir.join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();

    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    // bootstrap + put + mint a handle.
    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    assert!(c.output().unwrap().status.success());
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:x")
        .arg("--payload")
        .arg("sk-x");
    global(&mut c);
    assert!(c.output().unwrap().status.success());
    let mut c = cli();
    c.arg("mint-handle").arg("--id").arg("apikey:x");
    global(&mut c);
    assert!(c.output().unwrap().status.success());

    // status before: ok, 1/1 serving.
    let mut c = cli();
    c.arg("status");
    global(&mut c);
    let out = c.output().expect("run status");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("vault: ok (1/1 serving)"), "pre-logout: {s}");

    // logout by --id (apikey:x is not a login provider).
    let mut c = cli();
    c.arg("logout").arg("--id").arg("apikey:x");
    global(&mut c);
    let out = c.output().expect("run logout");
    assert!(
        out.status.success(),
        "logout: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("revoked 1 handle(s)"),
        "logout revokes the handle: {s}"
    );

    // status after: degraded, the id is named as needing re-login, and the ROW
    // SURVIVES (needs_reauth, not deleted) — logout is reversible by design.
    let mut c = cli();
    c.arg("status");
    global(&mut c);
    let out = c.output().expect("run status after");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("vault: degraded (0/1 serving)"),
        "post-logout: {s}"
    );
    assert!(
        s.contains("needs_reauth") && s.contains("apikey:x"),
        "the logged-out row survives as needs_reauth: {s}"
    );
    assert!(
        s.contains("needs re-login: apikey:x"),
        "status names the actionable id: {s}"
    );

    // The audit chain survives and stays intact (logout appended, destroyed nothing).
    let mut c = cli();
    c.arg("verify-audit");
    global(&mut c);
    let out = c.output().expect("run verify-audit");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("intact"));

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn admin_write_refused_while_lease_held() {
    // The structural "while stopped" proof: hold the single-writer lease (as the
    // daemon would) and confirm an admin CLI write is refused with the
    // daemon-running exit code (3), not applied.
    let root = tmp_root("lease");
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    std::fs::create_dir_all(&key_dir).unwrap();
    let key_path = key_dir.join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();

    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    // bootstrap first (no lease held yet).
    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    assert!(c.output().unwrap().status.success());

    // Now hold the lease (simulating the running daemon). The namespace MUST match
    // the CLI's ("default", what subc delivers) — the lease key is
    // (module_id, backend, namespace), so a mismatched namespace would take a
    // DIFFERENT lock and the admin write would (wrongly) not be refused.
    let descriptor = StorageDescriptor {
        module_id: "cortexkit-credentials".into(),
        storage_namespace: "default".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: data_dir.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let _held = open_sqlite(&descriptor).expect("hold the lease");

    // An admin put must now be refused with exit code 3 (daemon running).
    let mut c = cli();
    c.arg("put").arg("--id").arg("x").arg("--payload").arg("y");
    global(&mut c);
    let out = c.output().expect("run put while leased");
    assert!(
        !out.status.success(),
        "put must fail while the lease is held"
    );
    assert_eq!(out.status.code(), Some(3), "daemon-running exit code");

    drop(_held);
    let _ = std::fs::remove_dir_all(&root);
}
