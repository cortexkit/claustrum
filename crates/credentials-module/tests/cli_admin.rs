//! End-to-end tests of the offline admin CLI binary.
//!
//! Drives the real `ck-auth` process against a temp vault dir with an
//! operator key path (so no keychain is touched), exercising the structural
//! master-key proof and the audit chain end-to-end: bootstrap a key, put a
//! credential, mint a handle, list + verify the audit chain. Also proves the
//! single-writer lease makes admin writes mutually exclusive with a held lease.

use std::path::PathBuf;
use std::process::Command;

use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ck-auth"))
}

/// Both documented orders of a global flag must reach the same vault.
///
/// The verb is positional and is read before the flags, so a flag written BEFORE it
/// would be taken as the verb itself and produce "unexpected argument '<path>' for
/// '--data-dir'" -- a message naming the flag as a verb, from an invocation the help
/// text presents as correct. Nothing about the parser is visible to a caller, so the
/// two orders have to be equivalent rather than one of them being a rule to learn.
///
/// Driven through the real binary, because the ordering fix lives in argv handling
/// before dispatch: a unit test calling the helper directly passes whether or not
/// anything invokes it.
#[test]
fn a_global_flag_before_the_verb_reaches_the_same_vault_as_one_after_it() {
    let root = tmp_root("flag-order");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();

    let mut boot = cli();
    boot.arg("bootstrap")
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("--key-path")
        .arg(&key_path);
    assert!(boot.output().expect("bootstrap").status.success());

    // Flags AFTER the verb: the form that has always worked.
    let mut after = cli();
    after
        .arg("list")
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("--key-path")
        .arg(&key_path);
    let after = after.output().expect("list, flags after verb");

    // Flags BEFORE the verb: the form the help text documents.
    let mut before = cli();
    before
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("--key-path")
        .arg(&key_path)
        .arg("list");
    let before = before.output().expect("list, flags before verb");

    assert!(
        before.status.success(),
        "a global flag before the verb must not be read as the verb; got: {}",
        String::from_utf8_lossy(&before.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&before.stdout),
        String::from_utf8_lossy(&after.stdout),
        "both orders must address the same vault and print the same inventory"
    );

    let _ = std::fs::remove_dir_all(&root);
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

#[test]
fn version_reports_the_built_cli_without_configuration() {
    let out = cli()
        .arg("--version")
        .output()
        .expect("run ck-auth --version");
    assert!(
        out.status.success(),
        "version: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The package version alone was the WHOLE assertion here, which is what let the
    // flag ship answering "is this ck-auth" rather than "which ck-auth": the constant
    // it pinned has not moved in the project's lifetime, so the test passed no matter
    // what code was inside. Now it must also carry the revision field.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.trim(),
        format!(
            "ck-auth {} ({})",
            env!("CARGO_PKG_VERSION"),
            credentials_core::contract::BUILD_REV
        )
    );
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

/// An antigravity import stores an identity a consumer can actually resolve.
///
/// The importer parses the account's email out of the plugin store and, before this
/// was fixed, dropped it. That is invisible from inside the vault: the record stores
/// and serves normally, and the only symptom is downstream, where a consumer joining
/// on `account_id` cannot distinguish two antigravity accounts and collapses them
/// into one unlabelled entry.
///
/// So the assertion is on `account_id`, not `email`. Populating `email` alone would
/// look like a fix, render a value, and leave the symptom exactly as it was --
/// antigravity access tokens are opaque, so there is no live claim to fall back on.
///
/// Driven through the real binary, because the capture happens at the CLI call site:
/// a core-level test of the parser passes whether or not anything stores what it
/// returns.
#[test]
fn an_antigravity_import_stores_a_resolvable_account_identity() {
    use credentials_core::resolver::{KeySource, ResolverConfig};
    use credentials_core::store::EncryptedStore;

    let root = tmp_root("ag-import");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();

    // The plugin's on-disk shape, with two accounts so the selected one is not also
    // the first -- a capture that always took accounts[0] would otherwise pass.
    let store_json = root.join("antigravity-accounts.json");
    std::fs::write(
        &store_json,
        br#"{"version":4,"activeIndex":1,"accounts":[
              {"email":"first@x.com","refreshToken":"1//0-aaa","projectId":"proj-a"},
              {"email":"active@x.com","refreshToken":"1//0-bbb","projectId":"proj-b"}
            ]}"#,
    )
    .unwrap();

    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };
    let mut boot = cli();
    boot.arg("bootstrap");
    global(&mut boot);
    assert!(boot.output().unwrap().status.success(), "bootstrap");

    let mut imp = cli();
    imp.arg("import")
        .arg("--source")
        .arg("antigravity")
        .arg("--id")
        .arg("antigravity:google")
        .arg("--json")
        .arg(&store_json);
    global(&mut imp);
    let out = imp.output().expect("run import");
    assert!(
        out.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Read the stored record back through the real decrypt path.
    let config = ResolverConfig {
        data_dir: data_dir.clone(),
        source: KeySource::OperatorPath {
            path: key_path.clone(),
        },
    };
    let key = credentials_core::resolver::resolve(&config, None).expect("resolve key");
    let sqlite = open_sqlite(&StorageDescriptor {
        // Same shape the other tests in this file use: the module id is imported
        // rather than spelled so a rename cannot silently point this at a different
        // store than the CLI just wrote to.
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: data_dir.join("store.db").to_string_lossy().into_owned(),
        },
    })
    .expect("open store");
    EncryptedStore::migrate(&sqlite).expect("migrate");
    let store = EncryptedStore::open(sqlite, key).expect("open vault");
    let record = store.get("antigravity:google").expect("read the record");

    assert_eq!(
        record.identity.account_id.as_deref(),
        Some("active@x.com"),
        "account_id is the field a consumer resolves identity from; without it the \
         record renders an email and still labels nothing"
    );
    assert_eq!(
        record.identity.email.as_deref(),
        Some("active@x.com"),
        "and the display field agrees with it"
    );
    assert!(
        record.identity.is_servable(),
        "the stored identity must satisfy the servable predicate"
    );
    // The identity must track the SELECTED account, not the store's first.
    assert!(
        record
            .oauth
            .as_ref()
            .unwrap()
            .refresh_token
            .starts_with("1//0-bbb"),
        "sanity: the active account's credential was the one imported"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// `events` separates three outcomes an operator must not confuse.
///
/// "no events" and "this store cannot record events" would otherwise render the same,
/// and they call for different responses: the first means nothing has gone wrong, the
/// second means the recorder is not installed yet and an incident would leave no trace.
///
/// Also pins that the verb takes NO LEASE. The rows exist to explain a credential that
/// just failed, so requiring the daemon stopped would make the diagnostic unavailable
/// exactly when it is wanted.
#[test]
fn events_distinguishes_no_events_from_no_table_and_takes_no_lease() {
    let root = tmp_root("events");
    let data_dir = root.join("data");
    let key_path = root.join("secrets").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    assert!(c.output().unwrap().status.success());
    // A write, so the schema (and with it the events table) is actually created.
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:e")
        .arg("--payload")
        .arg("k");
    global(&mut c);
    assert!(c.output().unwrap().status.success());

    let mut c = cli();
    c.arg("events");
    global(&mut c);
    let out = c.output().expect("run events");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "events on a migrated vault must succeed"
    );
    assert!(
        text.contains("no authentication events recorded"),
        "an empty table must say so plainly; got: {text}"
    );

    // A store WITHOUT the table: the same command must say something different, because
    // "nothing recorded" and "nothing can be recorded" are different facts.
    let old = root.join("old");
    std::fs::create_dir_all(&old).unwrap();
    let conn = open_sqlite(&StorageDescriptor {
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: "default".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: old.join("store.db").to_string_lossy().into_owned(),
        },
    })
    .expect("open a bare store");
    drop(conn);

    let mut c = cli();
    c.arg("events").arg("--data-dir").arg(&old);
    let out = c.output().expect("run events on a pre-migration store");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "an absent table is a reportable state, not a failure"
    );
    assert!(
        text.contains("no authentication-event table yet"),
        "an absent table must be distinguishable from an empty one; got: {text}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// `invalidate` reports what it actually did, and reaches the state it claims.
///
/// The verb exits 0 for a credential that does not exist -- measured -- printing
/// "invalidated <id>; revoked 0 handle(s)". So an exit status says nothing here, and
/// the observable that separates a real invalidation from a no-op is the reported
/// handle count together with the resulting lifecycle state.
///
/// The store layer's own test covers `invalidate_audited`. This covers the verb: that
/// the CLI reaches that path, that its count comes from the transaction rather than
/// being printed unconditionally, and that a consumer's handle stops resolving.
#[test]
fn invalidate_reports_the_handles_it_revoked_and_leaves_the_row_needing_reauth() {
    let root = tmp_root("invalidate");
    let data_dir = root.join("data");
    let key_path = root.join("secrets").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    assert!(c.output().unwrap().status.success());

    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:inv")
        .arg("--payload")
        .arg("k");
    global(&mut c);
    assert!(c.output().unwrap().status.success());

    for _ in 0..2 {
        let mut c = cli();
        c.arg("mint-handle").arg("--id").arg("apikey:inv");
        global(&mut c);
        assert!(c.output().unwrap().status.success());
    }

    let mut c = cli();
    c.arg("invalidate").arg("--id").arg("apikey:inv");
    global(&mut c);
    let out = c.output().expect("run invalidate");
    let report = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "invalidate: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        report.contains("revoked 2 handle(s)"),
        "the count must come from the transaction, not be printed regardless; got: {report}"
    );

    let mut c = cli();
    c.arg("list");
    global(&mut c);
    let rows = String::from_utf8_lossy(&c.output().unwrap().stdout).into_owned();
    assert!(
        rows.contains("needs_reauth") && rows.contains("apikey:inv"),
        "the row must be left needing reauth: {rows}"
    );

    // The negative arm, and the reason the count above is the assertion rather than
    // the exit status: the same verb on an absent credential also succeeds.
    let mut c = cli();
    c.arg("invalidate").arg("--id").arg("apikey:never-existed");
    global(&mut c);
    let out = c.output().expect("run invalidate on an absent id");
    let report = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "an absent id still exits 0");
    assert!(
        report.contains("revoked 0 handle(s)"),
        "a no-op must report zero, which is what makes the positive count meaningful; \
         got: {report}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// `put --replace` is the routine static-key rotation path: it bumps
/// `record_version` (the consumer cache-invalidation signal) and keeps the
/// existing handle, exactly like `login --replace` does for an OAuth record.
///
/// Note the property under test belongs to the REPLACE APPLIER, not to `put`.
///
/// `put --replace` and `login --replace` both build an `AdminOpBody::Store` carrying
/// `StoreMode::ReplaceUnconditional`, which dispatches to
/// `overwrite_unconditional_audited` — that updates the credential row and never
/// touches the handles table. So a consumer's handle surviving an operator's re-login
/// is this same guarantee, reached through the same code.
///
/// Worth saying because the name says `put`, so someone asking "does a re-login keep
/// my handle?" would not find it here. The OAuth login arm is not driven instead
/// because it needs a real provider exchange; this arm reaches the shared applier
/// offline.
#[test]
fn put_replace_rotates_a_static_key_bumping_version_and_keeping_the_handle() {
    let root = tmp_root("put-replace");
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

    // bootstrap + create the key + mint a handle for it.
    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    assert!(c.output().unwrap().status.success());
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:vast")
        .arg("--payload")
        .arg("old-key");
    global(&mut c);
    assert!(c.output().unwrap().status.success());
    let mut c = cli();
    c.arg("mint-handle").arg("--id").arg("apikey:vast");
    global(&mut c);
    let handle = String::from_utf8_lossy(&c.output().unwrap().stdout)
        .trim()
        .to_string();
    assert!(handle.starts_with("ckh_"));

    // The created record is at v1.
    let mut c = cli();
    c.arg("list");
    global(&mut c);
    let rows = String::from_utf8_lossy(&c.output().unwrap().stdout).into_owned();
    assert!(
        rows.contains("v1") && rows.contains("apikey:vast"),
        "created at v1: {rows}"
    );

    // A create-mode put on the SAME id must be refused (create-only default) — this
    // is why a dedicated rotation verb is needed at all.
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:vast")
        .arg("--payload")
        .arg("new-key");
    global(&mut c);
    assert!(
        !c.output().unwrap().status.success(),
        "a plain put on an existing id must fail (create-only)"
    );

    // put --replace rotates it: new payload, version bumps to v2, id stays active.
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:vast")
        .arg("--payload")
        .arg("new-key")
        .arg("--replace");
    global(&mut c);
    let out = c.output().expect("run put --replace");
    assert!(
        out.status.success(),
        "put --replace: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut c = cli();
    c.arg("list");
    global(&mut c);
    let rows = String::from_utf8_lossy(&c.output().unwrap().stdout).into_owned();
    assert!(
        rows.contains("active         v2    apikey:vast"),
        "replace bumped the version and kept it active: {rows}"
    );

    // The handle SURVIVES the rotation, asserted on a COUNT rather than on an exit
    // status.
    //
    // `revoke-handle` succeeds for an unknown handle too -- measured: revoking a
    // never-minted string prints "revoked handle" and exits 0, deliberately, since
    // revocation is idempotent and must not confirm whether a handle exists. So
    // asserting that it succeeds proves nothing about the row surviving; it passes
    // just as well against a replace that orphaned every handle.
    //
    // `revoke-all-handles` reports the number it revoked, which is the signal that
    // distinguishes those cases: 1 if the replace kept the row, 0 if it did not.
    let mut c = cli();
    c.arg("revoke-all-handles").arg("--id").arg("apikey:vast");
    global(&mut c);
    let out = c.output().expect("run revoke-all-handles");
    let report = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "revoke-all-handles: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        report.contains("revoked 1 handle"),
        "the pre-rotation handle must still be live after the replace, so exactly one \
         is revoked here; got: {report}"
    );

    // --replace and --expected-hash are mutually exclusive.
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:vast")
        .arg("--payload")
        .arg("z")
        .arg("--replace")
        .arg("--expected-hash")
        .arg("00");
    global(&mut c);
    assert!(
        !c.output().unwrap().status.success(),
        "--replace and --expected-hash cannot be combined"
    );

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
        // Imported rather than spelled: this store must take the SAME lease lock the
        // CLI takes, and the lease key is (module_id, backend, namespace). A literal
        // here drifts silently on a module rename — the two sides then take DIFFERENT
        // locks, the admin write is no longer refused, and this test stops proving
        // mutual exclusion while still passing on its other assertions.
        module_id: credentials_core::contract::MODULE_ID.into(),
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

    // AND THE REFUSAL NAMES THE NO-DOWNTIME FIX. A caller hitting this has no reason
    // to know --subc exists: it lives under `help overrides`, which is exactly where
    // someone who does not know the flag's name will not look. A refusal that names
    // only "stop the daemon" pushes every routine repair through an outage, so the
    // remedy has to travel with the refusal rather than be findable from it.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--subc"),
        "the refusal must name the flag that makes the write succeed; got: {stderr}"
    );
    assert!(
        stderr.contains("stop the daemon"),
        "and must still offer the offline path; got: {stderr}"
    );

    drop(_held);
    let _ = std::fs::remove_dir_all(&root);
}

/// The validation bypass must not exist in a shipped binary.
///
/// `validate_key` has a test-only short circuit so this file's `login --provider zai`
/// test can run without a provider to talk to. On the operator's path an `Invalid`
/// result is the ONLY thing that stops a bad key being stored, so an env var that
/// turns that refusal into a store -- while printing "API key is valid." -- must be
/// compiled out. It is gated on `debug_assertions`.
///
/// Asserted against a real release build rather than by reading the `#[cfg]`, because
/// the claim is about the artifact: a later edit could move the gate, widen it, or add
/// a second read of the same var, and every one of those still reads correctly at the
/// source while shipping the hole.
///
/// The positive control is what makes the absence a measurement: a string known to be
/// present must be found by the identical pipeline, so a scan that silently finds
/// nothing (wrong path, unreadable file, broken pipe) fails here rather than passing as
/// a clean result.
#[test]
#[ignore = "builds the release profile; run explicitly or in the release gate"]
fn validation_bypass_is_absent_from_a_release_build() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let built = Command::new(env!("CARGO"))
        .args([
            "build",
            "--locked",
            "--release",
            "-p",
            "credentials-module",
            "--bin",
            "ck-auth",
        ])
        .current_dir(&manifest)
        .output()
        .expect("run cargo build");
    assert!(
        built.status.success(),
        "release build failed: {}",
        String::from_utf8_lossy(&built.stderr)
    );

    let exe = manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("target/release/ck-auth");
    let bytes = std::fs::read(&exe).expect("read the release ck-auth");

    let find = |needle: &str| bytes.windows(needle.len()).any(|w| w == needle.as_bytes());

    // Positive control first: if this fails the scan is broken, not the binary clean.
    assert!(
        find("API key validation failed"),
        "positive control absent -- the scan cannot see strings it should find, so the \
         bypass check below would pass vacuously"
    );

    assert!(
        !find("CORTEXKIT_TEST_BYPASS_VALIDATION"),
        "the validation bypass env var is present in the release ck-auth binary"
    );
}

#[test]
fn api_key_login_flow_integration() {
    let root = tmp_root("api-key-login");
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    std::fs::create_dir_all(&key_dir).unwrap();
    let key_path = key_dir.join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();

    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path)
            .env("CORTEXKIT_TEST_BYPASS_VALIDATION", "1");
    };

    // bootstrap first.
    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    assert!(c.output().unwrap().status.success());

    // Create a temp file with a dummy key.
    let key_file = root.join("dummy.key");
    std::fs::write(&key_file, "sk-dummy-key\n").unwrap();

    // Run login --provider zai --payload-file <key_file>
    let mut c = cli();
    c.arg("login")
        .arg("--provider")
        .arg("zai")
        .arg("--payload-file")
        .arg(&key_file);
    global(&mut c);
    let out = c.output().expect("run login");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "login failed: stdout: {}, stderr: {}",
        stdout,
        stderr
    );
    assert!(stdout.contains("logged in and stored apikey:zai"));

    // Verify it is stored by listing.
    let mut c = cli();
    c.arg("list");
    global(&mut c);
    let out = c.output().expect("run list");
    let rows = String::from_utf8_lossy(&out.stdout);
    assert!(rows.contains("apikey:zai"));

    // Test that login --id apikey:zai:work passes the id rail
    let key_file2 = root.join("dummy2.key");
    std::fs::write(&key_file2, "sk-dummy-key-2\n").unwrap();
    let mut c = cli();
    c.arg("login")
        .arg("--provider")
        .arg("zai")
        .arg("--id")
        .arg("apikey:zai:work")
        .arg("--payload-file")
        .arg(&key_file2);
    global(&mut c);
    let out = c.output().expect("run login with labeled id");
    assert!(
        out.status.success(),
        "labeled id login failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Test that login --id zai fails the id rail
    let mut c = cli();
    c.arg("login")
        .arg("--provider")
        .arg("zai")
        .arg("--id")
        .arg("zai")
        .arg("--payload-file")
        .arg(&key_file2);
    global(&mut c);
    let out = c.output().expect("run login with invalid id");
    assert!(!out.status.success(), "invalid id login should have failed");
    assert!(String::from_utf8_lossy(&out.stderr).contains("login --id must be"));

    let _ = std::fs::remove_dir_all(&root);
}

/// The rotate verb's HAPPY PATH, end to end through the real binary.
///
/// The crash-cut suite proves the two-slot handover survives a SIGKILL at each cut,
/// but it drives a helper that re-implements the sequence -- parking between steps
/// requires them separated. So the sequence the CLI actually runs (heal, stage,
/// rewrap, promote, in that order) had no test at all: a verb nobody runs casually,
/// because it needs the daemon stopped, and whose first real exercise would be during
/// a key-compromise incident.
///
/// Asserts the four things an operator is relying on when they type it, each of which
/// can fail independently of the printed "rotated master key to ..." line:
///   1. records still decrypt (a rewrap that half-failed prints success too),
///   2. the audit chain still verifies ACROSS the re-seal,
///   3. handles survive, so consumers are not silently cut off,
///   4. a SECOND rotation works on the slot state the first one left behind.
///
/// WHAT PASS 2 DOES NOT PROVE, measured rather than assumed: it does not exercise the
/// heal. Deleting `heal_pending_rotation` leaves this test green, because after a
/// SUCCESSFUL rotation `promote` has already cleared `next`, so the heal is a no-op --
/// it only does work when a PRIOR rotation crashed between rewrap and promote. That
/// state needs a real SIGKILL to produce, and the crash-cut suite's
/// `double-heal-staged` cut is where it is proven. Deleting `promote` also leaves this
/// green, and correctly so: the next rotation's heal recovers exactly that state, which
/// is why the code calls promote hygiene rather than a safety step.
///
/// Recorded because the obvious reading of a two-pass loop is that it covers the
/// second-rotation guards, and it does not.
#[test]
fn the_rotate_verb_leaves_the_vault_usable_and_can_run_twice() {
    let root = tmp_root("rotate-happy");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();

    let run = |args: &[&str]| -> std::process::Output {
        let mut c = cli();
        c.args(args)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
        c.output().expect("run ck-auth")
    };

    assert!(run(&["bootstrap"]).status.success());
    assert!(
        run(&["put", "--id", "apikey:one", "--payload", "secret-one"])
            .status
            .success()
    );
    let minted = run(&["mint-handle", "--id", "apikey:one"]);
    assert!(minted.status.success());
    let handle = String::from_utf8_lossy(&minted.stdout).trim().to_string();
    assert!(handle.starts_with("ckh_"), "minted: {handle}");

    for pass in 1..=2 {
        let out = run(&["rotate-master-key"]);
        assert!(
            out.status.success(),
            "rotation {pass} failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("rotated master key to key_id"),
            "rotation {pass} printed no new fingerprint"
        );

        // The record must still decrypt UNDER THE NEW KEY. `usable` is the only verb
        // that opens an envelope, so it is the one that can tell a real rewrap from a
        // rotation that reported success and left rows sealed under a key nobody holds.
        let scan = run(&["usable"]);
        let scan_out = String::from_utf8_lossy(&scan.stdout);
        assert!(scan.status.success(), "usable failed after rotation {pass}");
        assert!(
            scan_out.contains("serviceable: 1")
                && scan_out.contains("stranded: 0")
                && scan_out.contains("unreadable: 0"),
            "rotation {pass} left the record unreadable:\n{scan_out}"
        );

        // The chain spans the re-seal: the audit key is stored sealed and re-wrapped
        // with everything else, so a rotation that dropped it would break verification
        // of entries written before it.
        let verified = run(&["verify-audit"]);
        assert!(
            String::from_utf8_lossy(&verified.stdout).contains("intact"),
            "rotation {pass} broke the audit chain"
        );

        // Consumers hold handles and cannot distinguish a revoked one from an unknown
        // one, so a rotation that dropped them would read as an unexplained outage.
        // `revoke-all-handles` reports its count, which is the available proof the row
        // is still there without a live daemon to resolve against.
        let count = run(&["revoke-all-handles", "--id", "apikey:one"]);
        let count_out = String::from_utf8_lossy(&count.stdout);
        assert!(
            count_out.contains("revoked 1 handle"),
            "rotation {pass} lost the pre-rotation handle: {count_out}"
        );
        // Re-mint for the next pass, so pass 2 tests a handle that has itself crossed
        // a rotation.
        assert!(run(&["mint-handle", "--id", "apikey:one"]).status.success());
    }

    let _ = std::fs::remove_dir_all(&root);
}

/// Both binaries report their source revision, and the daemon does it WITHOUT a
/// supervisor.
///
/// `--version` used to print only the package version -- a constant that has not moved
/// in the project's lifetime, so it answered "is this ck-auth" and never "which one".
/// The daemon had no `--version` at all: asking it what it was required starting it,
/// which needs a connection file and a live supervisor, so the identity check depended
/// on the thing being identified already running correctly.
///
/// The daemon arm is the load-bearing one. Its flag is handled before the `--subc`
/// gate, and that ordering is invisible from the code below it: moving argument parsing
/// earlier, or making the gate stricter, would restore the old behaviour with nothing
/// else failing.
#[test]
fn both_binaries_report_a_build_revision_without_a_supervisor() {
    for (bin, label) in [
        (env!("CARGO_BIN_EXE_ck-auth"), "ck-auth"),
        (env!("CARGO_BIN_EXE_ck-claustrum"), "ck-claustrum"),
    ] {
        let out = std::process::Command::new(bin)
            .arg("--version")
            .output()
            .unwrap_or_else(|e| panic!("run {label} --version: {e}"));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{label} --version failed: {}{stdout}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.starts_with(label),
            "{label} --version must name the binary: {stdout}"
        );
        // The revision is present as its own field. An unstamped build says `unknown`,
        // which is the honest answer and still proves the field is wired -- the release
        // script is what fills it, and a missing field would read as a stamped build
        // whose revision happened not to print.
        assert!(
            stdout.contains('(') && stdout.contains(')'),
            "{label} --version must carry a revision field: {stdout}"
        );
    }
}
