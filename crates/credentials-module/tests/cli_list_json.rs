//! `ck auth list --json`: the stable machine-readable inventory for scripts.
//!
//! The human `ck auth list` table is not a parseable contract, so operator
//! operator scripts need a JSON document with a
//! pinned row shape. These tests drive the real `ck-auth` binary against a temp
//! vault and assert the wire shape, the `auth_method` agreement with
//! `credential.list_scoped`'s derivation, and that no secret ever reaches the
//! output.

#[path = "support/payload_file.rs"]
mod payload_file;
use payload_file::payload_file;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use cortexkit_test_support::{ckdev_binary, dev_command};
use credentials_core::store::EncryptedStore;

mod common;
use common::tmp_root;

#[path = "support/isolated_cli.rs"]
mod isolated_cli;

/// Point this suite at a specific `ck-auth` instead of the one cargo just built.
const CLI_BIN_ENV: &str = "CRED_CLI_BIN";

fn cli() -> Command {
    let mut command = cli_binary();
    isolated_cli::isolate(&mut command);
    command
}

fn cli_binary() -> Command {
    match std::env::var_os(CLI_BIN_ENV) {
        Some(raw) => {
            let path = PathBuf::from(raw);
            assert!(
                path.is_file(),
                "{CLI_BIN_ENV} points at {} which is not a file",
                path.display()
            );
            dev_command(ckdev_binary(path))
        }
        None => dev_command(ckdev_binary(env!("CARGO_BIN_EXE_ck-auth"))),
    }
}

fn assert_failed_write_leaves_vault_missing(verb: &[&str]) {
    let root = tmp_root(verb[0]);
    let data_dir = root.join("vault");
    let key_path = root.join("master.key");
    #[cfg(unix)]
    let mut key_file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)
            .expect("create the private key fixture")
    };
    #[cfg(windows)]
    let mut key_file = subc_os::windows_acl::create_private_file(&key_path)
        .expect("create the private key fixture");
    key_file.write_all(&[0; 32]).expect("write a malformed key");
    drop(key_file);
    let run = |args: &[&str]| {
        cli()
            .args(args)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path)
            .output()
            .expect("run ck-auth")
    };
    let assert_no_vault = |list: std::process::Output| {
        let stderr = String::from_utf8_lossy(&list.stderr);
        assert_eq!(list.status.code(), Some(1), "list --json: {stderr}");
        assert!(stderr.contains("no vault at"), "list --json: {stderr}");
        assert!(list.stdout.is_empty(), "no inventory exists to print");
    };
    assert_no_vault(run(&["list", "--json"]));

    let write = run(verb);
    let stderr = String::from_utf8_lossy(&write.stderr);
    assert_eq!(write.status.code(), Some(4), "{}: {stderr}", verb[0]);
    assert!(
        stderr.contains("expected 64 hex chars, got 32"),
        "{}: {stderr}",
        verb[0]
    );

    let list = run(&["list", "--json"]);
    assert!(
        !data_dir.exists(),
        "{} created the vault directory; list --json exited {:?}: {}{}",
        verb[0],
        list.status.code(),
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr),
    );
    assert_no_vault(list);
}

#[test]
fn malformed_key_before_bootstrap_put_leaves_no_vault() {
    assert_failed_write_leaves_vault_missing(&[
        "put",
        "--id",
        "opaque:x:1",
        "--kind",
        "opaque",
        "--generate-hex",
        "32",
    ]);
}

#[test]
fn malformed_key_before_bootstrap_grant_leaves_no_vault() {
    assert_failed_write_leaves_vault_missing(&[
        "grant",
        "--principal",
        "reserved:json-probe",
        "--selector-kind",
        "exact",
        "--selector",
        "opaque:x:1",
        "--operation",
        "list",
    ]);
}

#[test]
fn offline_put_reopens_an_existing_vault_and_keeps_its_records() {
    let vault = JsonVault::new("offline-reopen");
    vault.bootstrap();

    for id in ["opaque:x:1", "opaque:x:2"] {
        let put = vault.run(&[
            "put",
            "--id",
            id,
            "--kind",
            "opaque",
            "--generate-hex",
            "32",
        ]);
        let stderr = String::from_utf8_lossy(&put.stderr);
        assert_eq!(put.status.code(), Some(0), "put {id}: {stderr}");
    }
    let rows = vault.list_json();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["id"], "opaque:x:1");
    assert_eq!(rows[1]["id"], "opaque:x:2");
}

struct JsonVault {
    root: credentials_core::test_support::TestTempDir,
    data_dir: PathBuf,
    key_path: PathBuf,
}

impl JsonVault {
    fn new(tag: &str) -> Self {
        let root = tmp_root(tag);
        let data_dir = root.join("vault");
        let key_path = root.join("master.key");
        std::fs::create_dir_all(&data_dir).expect("vault directory");
        Self {
            root,
            data_dir,
            key_path,
        }
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        let out = cli()
            .args(args)
            .arg("--data-dir")
            .arg(&self.data_dir)
            .arg("--key-path")
            .arg(&self.key_path)
            .output()
            .expect("run ck-auth");
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(signal) = out.status.signal() {
                panic!("ck-auth {args:?} was killed by signal {signal}, not refused");
            }
        }
        out
    }

    fn bootstrap(&self) {
        let out = self.run(&["bootstrap"]);
        assert!(
            out.status.success(),
            "bootstrap failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Import a minimal opencode OAuth record for `id` (a Claude-style
    /// subscription login when `id` is `oauth:anthropic`).
    fn import_oauth(&self, id: &str, account_id: &str) {
        let source = self.root.join(format!("auth-{account_id}.json"));
        std::fs::write(
            &source,
            serde_json::to_vec(&serde_json::json!({
                "refresh": format!("refresh-for-{account_id}"),
                "access": format!("access-for-{account_id}"),
                "expires": 4102444800000_i64,
            }))
            .unwrap(),
        )
        .unwrap();
        let out = self.run(&[
            "import",
            "--source",
            "opencode",
            "--id",
            id,
            "--json",
            source.to_str().expect("utf8 path"),
            "--account-id",
            account_id,
        ]);
        assert!(
            out.status.success(),
            "import {id} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Parse `list --json` stdout into its credential rows.
    fn list_json(&self) -> Vec<serde_json::Value> {
        let out = self.run(&["list", "--json"]);
        assert!(
            out.status.success(),
            "list --json failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8(out.stdout).expect("stdout is UTF-8");
        let doc: serde_json::Value =
            serde_json::from_str(&stdout).expect("list --json prints one JSON document");
        assert_eq!(doc["v"], serde_json::json!(1), "top-level version");
        doc["credentials"]
            .as_array()
            .cloned()
            .expect("credentials is an array")
    }

    fn store(&self) -> EncryptedStore {
        let descriptor = StorageDescriptor {
            module_id: credentials_core::contract::MODULE_ID.into(),
            storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: self
                    .data_dir
                    .join("store.db")
                    .to_string_lossy()
                    .into_owned(),
            },
        };
        let key = credentials_core::resolver::resolve(
            &credentials_core::resolver::ResolverConfig {
                data_dir: self.data_dir.clone(),
                source: credentials_core::resolver::KeySource::OperatorPath {
                    path: self.key_path.clone(),
                },
            },
            None,
        )
        .unwrap();
        let store = open_sqlite(&descriptor).unwrap();
        EncryptedStore::migrate(&store).unwrap();
        EncryptedStore::open(store, key).unwrap()
    }
}

/// Dropping the isolation from `cli()` would let a test that omits `--data-dir`
/// open the developer's real vault and read its master key.
#[test]
fn every_cli_command_runs_in_the_isolated_home() {
    isolated_cli::assert_isolated(&cli());
}

/// The keys every `--json` row carries. Pinned
/// literally so a later field (a handle, a token, an email) cannot slip into
/// the script surface without reddening here first. A marked login adds one
/// more, `condition`, which unmarked rows omit so their bytes stay unchanged.
const JSON_ROW_KEYS: [&str; 13] = [
    "id",
    "state",
    "record_version",
    "categories",
    "provider_ids",
    "auth_method",
    "plan_tier",
    "plan_tier_source",
    "creator",
    "provider",
    "incarnation",
    "plan_tier_observed_at_ms",
    "plan_tier_since_ms",
];

#[test]
fn login_condition_inventory_and_clear_condition_work_without_daemon() {
    use credentials_core::{
        audit::{AuditCtx, AuditOp},
        federation::NewRemoteRecord,
        record::RecordIdentity,
        store::{AuthEventPrincipal, ConditionReport},
        OAuthCredential, VaultRecord,
    };
    use serde_json::json;

    const LOCAL: &str = "oauth:antigravity:cli";
    const COPY: &str = "oauth:antigravity:cli-copy";
    const LINK: &str = "https://accounts.google.com/check?mark=cli";
    let vault = JsonVault::new("login-condition-inventory");
    vault.bootstrap();
    let store = vault.store();
    let record = VaultRecord::new_oauth(
        "fixture",
        "antigravity",
        OAuthCredential {
            access_token: "test-access".to_owned().into(),
            refresh_token: "test-refresh".to_owned().into(),
            expires_at_ms: Some(4_102_444_800_000),
            token_url: "https://accounts.google.com/token".into(),
            client_id: None,
            client_secret: None,
            scopes: vec![],
        },
        b"test-access".to_vec(),
    );
    store.create(LOCAL, &record).unwrap();
    let local_incarnation = store.credential_incarnation(LOCAL).unwrap();
    assert!(store
        .report_condition_in_incarnation(
            LOCAL,
            1,
            &local_incarnation,
            ConditionReport {
                reason: "provider_verification_required",
                provider_status: 403,
                action_url: Some(LINK)
            },
            AuditCtx::route_admin(AuditOp::ReportCondition, "cli-reader"),
            AuthEventPrincipal::Reserved("cli-reader"),
        )
        .unwrap());
    let since = store
        .credential_condition(LOCAL, &local_incarnation)
        .unwrap()
        .unwrap()
        .since_ms;
    let copy = store
        .remote_add_audited(&NewRemoteRecord {
            provider_ids: Vec::new(),
            credential_id: COPY.into(),
            home_member: "fed-computer:22222222222222222222222222222222".into(),
            refresh_adapter: Some("antigravity".into()),
            detected_plan: None,
            identity: RecordIdentity::default(),
            home_version: 1,
            categories: vec![],
        })
        .unwrap();
    drop(store);
    let db = rusqlite::Connection::open(vault.data_dir.join("store.db")).unwrap();
    db.execute("INSERT INTO remote_record_conditions (credential_id, incarnation, reason, since_ms, action_url) VALUES (?1, ?2, 'provider_verification_required', 19, ?3)", (COPY, copy.incarnation, LINK)).unwrap();
    for cmd in ["status", "list"] {
        let out = vault.run(&[cmd]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(text.lines().any(|line| line.contains(LOCAL)
            && line.contains(&format!(
                "condition=provider_verification_required since_ms={since}"
            ))
            && line.contains(LINK)));
        assert!(text.lines().any(|line| line.contains(COPY)
            && line.contains("condition=provider_verification_required since_ms=19")
            && line.contains(LINK)
            && line.contains("clear at the home vault")));
    }
    let rows = vault.list_json();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["id"], LOCAL);
    assert_eq!(
        rows[0]["condition"],
        json!({"reason":"provider_verification_required", "since_ms":since, "action_url":LINK})
    );
    db.execute(
        "UPDATE credential_conditions SET action_url = NULL WHERE credential_id = ?1",
        [LOCAL],
    )
    .unwrap();
    assert_eq!(
        vault.list_json()[0]["condition"],
        json!({"reason":"provider_verification_required", "since_ms":since})
    );

    for (id, error) in [
        (COPY, "condition_home_owned/permanent"),
        ("unknown", "credential not found"),
    ] {
        let out = vault.run(&["clear-condition", "--id", id]);
        assert!(!out.status.success());
        assert!(String::from_utf8(out.stderr).unwrap().contains(error));
    }
    for expected in ["cleared=true\n", "cleared=false\n"] {
        let out = vault.run(&["clear-condition", "--id", LOCAL]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(String::from_utf8(out.stdout).unwrap(), expected);
    }
    assert_eq!(vault.list_json()[0].get("condition"), None);
}

#[test]
fn login_condition_inventory_reads_schema_before_condition_tables_without_migrating() {
    use credentials_core::store::CONDITION_SCHEMA_VERSION;

    let vault = JsonVault::new("inventory-before-login-conditions");
    vault.bootstrap();
    vault.import_oauth("oauth:anthropic", "before-conditions");
    let db = rusqlite::Connection::open(vault.data_dir.join("store.db")).unwrap();
    db.execute_batch("DROP TABLE credential_conditions; DROP TABLE remote_record_conditions;")
        .unwrap();
    // Simulate a store from before the condition step: remove that step's marker and
    // every later one, so the newest recorded step is the one before conditions.
    assert!(
        db.execute(
            "DELETE FROM cortexkit_schema_version WHERE namespace = 'credentials' AND version >= ?1",
            [CONDITION_SCHEMA_VERSION]
        )
        .unwrap()
            >= 1
    );
    let rows = vault.list_json();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["id"], "oauth:anthropic");
    assert_eq!(rows[0].get("condition"), None);
    assert_eq!(
        db.query_row(
            "SELECT MAX(version) FROM cortexkit_schema_version WHERE namespace = 'credentials'",
            [],
            |row| row.get::<_, u32>(0)
        )
        .unwrap(),
        CONDITION_SCHEMA_VERSION - 1
    );
    assert_eq!(db.query_row("SELECT COUNT(*) FROM sqlite_master WHERE name IN ('credential_conditions','remote_record_conditions')", [], |row| row.get::<_, u32>(0)).unwrap(), 0);
}

fn seed_three_credentials(vault: &JsonVault) {
    vault.bootstrap();
    assert!(vault
        .run(&[
            "put",
            "--id",
            "apikey:deepseek",
            "--payload-file",
            &payload_file("deepseek-key")
        ])
        .status
        .success());
    vault.import_oauth("oauth:anthropic", "claude-test");
    assert!(vault
        .run(&[
            "put",
            "--id",
            "opaque:notes",
            "--kind",
            "opaque",
            "--payload-file",
            &payload_file("operator-notes")
        ])
        .status
        .success());
}
/// Every row carries exactly the thirteen documented keys, rows arrive sorted by
/// id, and the top-level version is 1. The exact-set assertion is the secret
/// guard: a new field lands here first, and anything secret (a token, handle,
/// or email) fails this test before it can reach a script.
#[test]
fn list_json_reports_the_exact_key_set_sorted_by_id() {
    let vault = JsonVault::new("list-json-keys");
    seed_three_credentials(&vault);

    let rows = vault.list_json();
    assert_eq!(rows.len(), 3, "three seeded credentials");

    let mut ids: Vec<&str> = rows
        .iter()
        .map(|row| row["id"].as_str().expect("id is a string"))
        .collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "rows are sorted by id: {ids:?}");
    ids.clone_from(&sorted);
    assert_eq!(ids, ["apikey:deepseek", "oauth:anthropic", "opaque:notes"]);

    for row in &rows {
        let keys: BTreeSet<&str> = row
            .as_object()
            .expect("row is an object")
            .keys()
            .map(String::as_str)
            .collect();
        let expected: BTreeSet<&str> = JSON_ROW_KEYS.into_iter().collect();
        assert_eq!(
            keys, expected,
            "row {} carries exactly the documented keys",
            row["id"]
        );
        assert!(
            row["record_version"].as_u64().is_some_and(|v| v > 0),
            "record_version is a positive integer: {row}"
        );
        assert!(
            matches!(
                row["state"].as_str(),
                Some("active" | "needs_reauth" | "retired" | "corrupt")
            ),
            "state is a known lifecycle value: {row}"
        );
        assert!(
            row["categories"].is_array(),
            "categories is an array: {row}"
        );
        assert!(
            row["provider_ids"].is_array(),
            "provider_ids is an array: {row}"
        );
    }

    // A CLI-written row records `operator` as its creator; a row from a store
    // without creator tracking renders null instead.
    let by_id: BTreeMap<&str, &serde_json::Value> = rows
        .iter()
        .map(|row| (row["id"].as_str().unwrap(), row))
        .collect();
    assert_eq!(
        by_id["apikey:deepseek"]["creator"],
        serde_json::json!("operator")
    );
    assert_eq!(by_id["apikey:deepseek"]["provider"], "deepseek");
    assert_eq!(by_id["oauth:anthropic"]["provider"], "anthropic");
    assert!(by_id["opaque:notes"]["provider"].is_null());
    for row in &rows {
        assert_eq!(row["incarnation"].as_str().unwrap().len(), 32);
        assert!(row["plan_tier_observed_at_ms"].is_null());
        assert!(row["plan_tier_since_ms"].is_null());
    }
    let db = vault.data_dir.join("store.db");
    let conn = rusqlite::Connection::open(&db).expect("open store for creator probe");
    conn.execute(
        "UPDATE credentials SET created_by = NULL WHERE credential_id = 'opaque:notes'",
        [],
    )
    .expect("clear one creator");
    drop(conn);
    let nulled = vault.list_json();
    let notes = nulled
        .iter()
        .find(|row| row["id"] == "opaque:notes")
        .expect("opaque row survives a creator clear");
    assert!(
        notes["creator"].is_null(),
        "a row with no known creator renders null: {notes}"
    );
}

/// `auth_method` agrees with `credential.list_scoped`'s derivation for an API
/// key, a Claude subscription login, and a non-LLM credential.
///
/// The comparison runs against the store's own `list_scoped_snapshot` rows
/// (which use `list_auth_method` over the unsealed kind and adapter), not
/// against literals alone, so a `--json` implementation that re-derives the
/// value from the id string instead of reusing the shared table fails here.
#[test]
fn list_json_auth_method_agrees_with_list_scoped_derivation() {
    let vault = JsonVault::new("list-json-auth-method");
    seed_three_credentials(&vault);

    for id in ["apikey:deepseek", "oauth:anthropic", "opaque:notes"] {
        let out = vault.run(&[
            "grant",
            "--principal",
            "reserved:json-probe",
            "--selector-kind",
            "exact",
            "--selector",
            id,
            "--operation",
            "list",
        ]);
        assert!(
            out.status.success(),
            "grant list on {id} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let rows = vault.list_json();
    let json_methods: BTreeMap<String, Option<String>> = rows
        .iter()
        .map(|row| {
            (
                row["id"].as_str().unwrap().to_string(),
                row["auth_method"].as_str().map(str::to_string),
            )
        })
        .collect();

    // The pinned literals: an API key, a Claude subscription login, and a
    // static non-LLM credential with no `auth_method`.
    assert_eq!(
        json_methods["apikey:deepseek"].as_deref(),
        Some("apikey"),
        "a static API key lists as apikey"
    );
    assert_eq!(
        json_methods["oauth:anthropic"].as_deref(),
        Some("oauth"),
        "a Claude subscription login lists as oauth"
    );
    assert_eq!(
        json_methods["opaque:notes"], None,
        "a non-LLM credential carries a null auth_method"
    );

    // The same values `credential.list_scoped` reports for the same rows.
    let descriptor = StorageDescriptor {
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: vault
                .data_dir
                .join("store.db")
                .to_string_lossy()
                .into_owned(),
        },
    };
    let key = credentials_core::resolver::resolve(
        &credentials_core::resolver::ResolverConfig {
            data_dir: vault.data_dir.clone(),
            source: credentials_core::resolver::KeySource::OperatorPath {
                path: vault.key_path.clone(),
            },
        },
        None,
    )
    .expect("resolve operator key");
    let store =
        EncryptedStore::open(open_sqlite(&descriptor).expect("open store"), key).expect("key");
    let snapshot = store
        .list_scoped_snapshot(
            "reserved",
            "json-probe",
            &credentials_core::store::DeclaredGrantSet::empty(),
        )
        .expect("scoped snapshot");
    for row in &snapshot.rows {
        let expected = row.auth_method.map(|method| method.as_str().to_string());
        assert_eq!(
            json_methods.get(&row.id),
            Some(&expected),
            "{}: --json disagrees with list_scoped",
            row.id
        );
    }
}

/// `provider_ids` and `plan_tier` appear when set, and render empty/null when
/// not. This supports the pre-restart check: a credential that served a run
/// must show the metadata a deploy gates on.
#[test]
fn list_json_carries_provider_ids_and_plan_tier_when_set() {
    let vault = JsonVault::new("list-json-providers-plan");
    vault.bootstrap();
    assert!(vault
        .run(&[
            "put",
            "--id",
            "apikey:zai",
            "--payload-file",
            &payload_file("zai-key")
        ])
        .status
        .success());
    assert!(vault
        .run(&[
            "put",
            "--id",
            "apikey:plain",
            "--payload-file",
            &payload_file("plain-key")
        ])
        .status
        .success());
    assert!(vault
        .run(&[
            "set-providers",
            "--id",
            "apikey:zai",
            "--set",
            "zai-coding-plan"
        ])
        .status
        .success());
    assert!(vault
        .run(&["set-plan", "--id", "apikey:zai", "--tier", "pro_200"])
        .status
        .success());

    let rows = vault.list_json();
    let by_id: BTreeMap<&str, &serde_json::Value> = rows
        .iter()
        .map(|row| (row["id"].as_str().unwrap(), row))
        .collect();

    let zai = by_id["apikey:zai"];
    assert_eq!(
        zai["provider_ids"],
        serde_json::json!(["zai-coding-plan"]),
        "the assigned provider id is listed"
    );
    assert_eq!(zai["plan_tier"], serde_json::json!("pro_200"));
    assert_eq!(zai["plan_tier_source"], serde_json::json!("operator"));
    assert!(zai["plan_tier_observed_at_ms"].as_i64().is_some());
    let conn = rusqlite::Connection::open(vault.data_dir.join("store.db")).unwrap();
    let committed: i64 = conn
        .query_row(
            "SELECT observed_at_ms FROM credential_plan_tiers WHERE credential_id='apikey:zai'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(zai["plan_tier_observed_at_ms"], committed);

    let plain = by_id["apikey:plain"];
    assert_eq!(
        plain["provider_ids"],
        serde_json::json!([]),
        "no provider ids is an empty array, not null"
    );
    assert!(
        plain["plan_tier"].is_null() && plain["plan_tier_source"].is_null(),
        "an unset tier renders null for both fields: {plain}"
    );
}

/// Nothing secret reaches the document: a payload carrying a recognisable
/// marker string must not appear anywhere in stdout (or stderr), in either
/// rendering.
/// A shell that cannot reach the master key must not print a listing whose every
/// `auth_method` is null: a script would read that as "these credentials have no
/// auth method", a statement about the credentials, when the fact is about the shell.
#[test]
fn list_json_refuses_when_the_master_key_cannot_be_read() {
    let vault = JsonVault::new("list-json-keyless");
    seed_three_credentials(&vault);
    let moved = vault.root.join("master.key.moved");
    std::fs::rename(&vault.key_path, &moved).expect("move the key file aside");
    let out = vault.run(&["list", "--json"]);
    assert!(
        !out.status.success(),
        "--json must refuse without the key: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("\"credentials\""),
        "no listing may be printed: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn list_json_never_prints_secret_material() {
    let vault = JsonVault::new("list-json-no-secrets");
    vault.bootstrap();
    let marker = "sk-canary-9f3a-json-never-print";
    let payload = format!("prefix-{marker}-suffix");
    assert!(vault
        .run(&[
            "put",
            "--id",
            "apikey:deepseek",
            "--payload-file",
            &payload_file(&payload)
        ])
        .status
        .success());
    let source = vault.root.join("auth-marker.json");
    std::fs::write(
        &source,
        serde_json::to_vec(&serde_json::json!({
            "refresh": format!("refresh-{marker}"),
            "access": format!("access-{marker}"),
            "expires": 4102444800000_i64,
        }))
        .unwrap(),
    )
    .unwrap();
    let out = vault.run(&[
        "import",
        "--source",
        "opencode",
        "--id",
        "oauth:anthropic",
        "--json",
        source.to_str().expect("utf8 path"),
        "--account-id",
        "marker-test",
    ]);
    assert!(
        out.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    for args in [vec!["list", "--json"], vec!["list"]] {
        let out = vault.run(&args);
        assert!(
            out.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stdout.contains(marker),
            "{args:?} stdout leaks the payload marker"
        );
        assert!(
            !stderr.contains(marker),
            "{args:?} stderr leaks the payload marker"
        );
    }
    // The marker is genuinely stored (the assertion above is not vacuous): the
    // human table names both credentials while carrying no marker bytes.
    let out = vault.run(&["list"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("apikey:deepseek"));
    assert!(stdout.contains("oauth:anthropic"));
}

#[test]
fn set_plan_since_roundtrips_dates_timestamps_and_epoch_ms_and_clears_old_date() {
    let vault = JsonVault::new("list-json-plan-since");
    seed_three_credentials(&vault);
    let run = |args: &[&str]| {
        let out = vault.run(args);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    for since in ["2025-01-01", "2025-01-01T01:00:00+01:00", "1735689600000"] {
        run(&[
            "set-plan",
            "--id",
            "apikey:deepseek",
            "--tier",
            "plus",
            "--since",
            since,
        ]);
        let rows = vault.list_json();
        let row = rows
            .iter()
            .find(|row| row["id"] == "apikey:deepseek")
            .unwrap();
        assert_eq!(row["plan_tier_since_ms"], 1_735_689_600_000i64);
        assert_eq!(row["plan_tier_source"], "operator");
        assert!(run(&["list"]).contains("plus since=2025-01-01T00:00:00.000Z"));
    }
    assert!(!vault
        .run(&[
            "set-plan",
            "--id",
            "apikey:deepseek",
            "--clear",
            "--since",
            "2025-01-01"
        ])
        .status
        .success());
    run(&["set-plan", "--id", "apikey:deepseek", "--tier", "pro_200"]);
    let rows = vault.list_json();
    assert!(rows
        .iter()
        .find(|row| row["id"] == "apikey:deepseek")
        .unwrap()["plan_tier_since_ms"]
        .is_null());
    run(&["set-plan", "--id", "apikey:deepseek", "--clear"]);
    assert!(run(&["verify-audit"]).contains("intact"));
}
