use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use cortexkit_test_support::ckdev_binary;
use credentials_core::admin_ops::{apply, AdminOpBody, ADMIN_OP_SCHEMA_V2};
use credentials_core::audit::{AlarmReason, AuditOp};
use credentials_core::resolver::{resolve, KeySource, ResolverConfig};
use credentials_core::store::module_secrets::{ModuleSecretError, ModuleSecretOwner};
use credentials_core::store::{EncryptedStore, StoreOpError};
use credentials_core::test_support::TestTempDir;

#[path = "support/isolated_cli.rs"]
mod isolated_cli;
#[cfg(unix)]
#[path = "support/terminal_cli.rs"]
mod terminal_cli;

const CANARY: &[u8] = b"module-secret-canary-never-print";

struct Vault {
    _root: TestTempDir,
    data: PathBuf,
    key: PathBuf,
}

struct TestStore {
    store: EncryptedStore,
    path: PathBuf,
}

impl std::ops::Deref for TestStore {
    type Target = EncryptedStore;
    fn deref(&self) -> &Self::Target {
        &self.store
    }
}

impl TestStore {
    fn with_raw_conn<T>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        f(&rusqlite::Connection::open(&self.path)?)
    }
}

impl Vault {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = TestTempDir::new(format!(
            "module-secret-cli-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let data = root.join("vault");
        let key = root.join("master.key");
        std::fs::create_dir_all(&data).unwrap();
        Self {
            _root: root,
            data,
            key,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(ckdev_binary(env!("CARGO_BIN_EXE_ck-auth")));
        isolated_cli::isolate(&mut command);
        isolated_cli::assert_isolated(&command);
        command
            .arg("--data-dir")
            .arg(&self.data)
            .arg("--key-path")
            .arg(&self.key);
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        use base64::Engine;
        let output = self
            .command()
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(output.status.code().is_some(), "CLI terminated by signal");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!combined.contains(std::str::from_utf8(CANARY).unwrap()));
        assert!(!combined.contains(&base64::engine::general_purpose::STANDARD.encode(CANARY)));
        output
    }

    fn bootstrap(&self) {
        success(self.run(&["bootstrap"]));
    }

    fn store(&self) -> TestStore {
        let key = resolve(
            &ResolverConfig {
                data_dir: self.data.clone(),
                source: KeySource::OperatorPath {
                    path: self.key.clone(),
                },
            },
            None,
        )
        .unwrap();
        let sqlite = open_sqlite(&StorageDescriptor {
            module_id: credentials_core::contract::MODULE_ID.into(),
            storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: self.data.join("store.db").to_string_lossy().into_owned(),
            },
        })
        .unwrap();
        EncryptedStore::migrate_with_key(&sqlite, &key).unwrap();
        TestStore {
            store: EncryptedStore::open(sqlite, key).unwrap(),
            path: self.data.join("store.db"),
        }
    }

    fn seed(&self, module: &str, name: &str, protected: bool) {
        self.store()
            .put_module_secret(&owner(module), name, CANARY, None, Some(protected))
            .unwrap();
    }
}

fn owner(module: &str) -> ModuleSecretOwner {
    ModuleSecretOwner::new(module).unwrap()
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn refused(output: Output, code: &str) {
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "a refusal must not print a success body"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn module_secret_list_is_sorted_metadata_only_and_filterable() {
    let vault = Vault::new();
    vault.bootstrap();
    vault.seed("zeta", "a", false);
    vault.seed("alpha", "z", false);
    vault.seed("alpha", "a", true);
    vault
        .store()
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE module_secrets SET state='corrupt' WHERE module_id='alpha' AND name='z'",
                [],
            )
        })
        .unwrap();
    let before = vault.store().read_audit(None).unwrap().len();
    let listed = success(vault.run(&["module-secret", "list"]));
    let lines: Vec<_> = listed.lines().collect();
    assert_eq!(lines[0], "MODULE\tNAME\tVERSION\tPROTECTED\tSTATE\tUPDATED");
    assert_eq!(lines.len(), 4);
    for (line, expected) in lines[1..].iter().zip([
        ["alpha", "a", "1", "true", "active"],
        ["alpha", "z", "1", "false", "corrupt"],
        ["zeta", "a", "1", "false", "active"],
    ]) {
        let cells: Vec<_> = line.split('\t').collect();
        assert_eq!(&cells[..5], expected);
        assert!(cells[5].parse::<i64>().unwrap() > 0);
        assert_eq!(cells.len(), 6);
    }
    let filtered = success(vault.run(&["module-secret", "list", "--module", "zeta"]));
    assert_eq!(filtered.lines().count(), 2);
    assert!(filtered.lines().nth(1).unwrap().starts_with("zeta\ta\t"));
    assert_eq!(vault.store().read_audit(None).unwrap().len(), before);
}

#[test]
fn module_secret_delete_requires_exact_confirmation_and_deletes_protected() {
    let vault = Vault::new();
    vault.bootstrap();
    vault.seed("alpha", "key", true);
    let before = vault.store().read_audit(None).unwrap().len();
    refused(
        vault.run(&[
            "module-secret",
            "delete",
            "--module",
            "alpha",
            "--name",
            "key",
        ]),
        "non-terminal",
    );
    refused(
        vault.run(&[
            "module-secret",
            "delete",
            "--module",
            "alpha",
            "--name",
            "key",
            "--confirm",
            "alpha:other",
        ]),
        "confirmation",
    );
    assert_eq!(vault.store().read_audit(None).unwrap().len(), before);
    success(vault.run(&[
        "module-secret",
        "delete",
        "--module",
        "alpha",
        "--name",
        "key",
        "--confirm",
        "alpha:key",
    ]));
    let store = vault.store();
    assert!(store
        .list_module_secrets(&owner("alpha"))
        .unwrap()
        .is_empty());
    let audit = store.read_audit(None).unwrap();
    assert_eq!(audit.len(), before + 1);
    let deletion = audit
        .iter()
        .find(|row| row.op == AuditOp::ModuleSecretDelete.as_str())
        .unwrap();
    assert_eq!(deletion.actor, "offline-cli");
    assert_eq!(
        deletion.alarm_reason.as_deref(),
        Some(AlarmReason::AdminWrite.as_str())
    );
    drop(store);
    refused(
        vault.run(&[
            "module-secret",
            "delete",
            "--module",
            "alpha",
            "--name",
            "key",
            "--confirm",
            "alpha:key",
        ]),
        "not_found",
    );
}

#[cfg(unix)]
#[test]
fn module_secret_delete_terminal_prompt_requires_the_exact_item() {
    let vault = Vault::new();
    vault.bootstrap();
    vault.seed("alpha", "key", true);
    let mut command = vault.command();
    command.args([
        "module-secret",
        "delete",
        "--module",
        "alpha",
        "--name",
        "key",
    ]);
    let (status, screen) = terminal_cli::run(command, &[("Type alpha:key: ", b"wrong\r", false)]);
    assert!(!status.success(), "{screen}");
    assert!(screen.contains("confirmation does not match"));
    assert_eq!(
        vault
            .store()
            .list_module_secrets(&owner("alpha"))
            .unwrap()
            .len(),
        1
    );
    let mut command = vault.command();
    command.args([
        "module-secret",
        "delete",
        "--module",
        "alpha",
        "--name",
        "key",
    ]);
    let (status, screen) =
        terminal_cli::run(command, &[("Type alpha:key: ", b"alpha:key\r", false)]);
    assert!(status.success(), "{screen}");
    assert!(!screen.contains(std::str::from_utf8(CANARY).unwrap()));
    assert!(vault
        .store()
        .list_module_secrets(&owner("alpha"))
        .unwrap()
        .is_empty());
}

#[test]
fn module_secret_move_reseals_all_items_and_preserves_metadata() {
    let vault = Vault::new();
    vault.bootstrap();
    vault.seed("old", "z", false);
    vault.seed("old", "a", true);
    let store = vault.store();
    store
        .put_module_secret(&owner("old"), "z", CANARY, Some(1), None)
        .unwrap();
    let before = store.list_module_secrets(&owner("old")).unwrap();
    let created: Vec<(String, i64)> = store
        .with_raw_conn(|conn| {
            conn.prepare("SELECT name, created_at_ms FROM module_secrets ORDER BY name")?
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect()
        })
        .unwrap();
    let count = store.read_audit(None).unwrap().len();
    drop(store);
    assert!(
        success(vault.run(&["module-secret", "move", "--from", "old", "--to", "new"]))
            .contains("moved 2")
    );
    let store = vault.store();
    assert!(store.list_module_secrets(&owner("old")).unwrap().is_empty());
    let after = store.list_module_secrets(&owner("new")).unwrap();
    for (old, new) in before.iter().zip(&after) {
        assert_eq!(
            (&old.name, old.version, old.protected, old.state),
            (&new.name, new.version, new.protected, new.state)
        );
        assert!(new.updated_at_ms >= old.updated_at_ms);
        assert_eq!(
            store
                .get_module_secret(&owner("new"), &new.name)
                .unwrap()
                .value
                .expose(),
            CANARY
        );
    }
    let created_after: Vec<(String, i64)> = store
        .with_raw_conn(|conn| {
            conn.prepare("SELECT name, created_at_ms FROM module_secrets ORDER BY name")?
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect()
        })
        .unwrap();
    assert_eq!(created_after, created);
    let audit = store.read_audit(None).unwrap();
    assert_eq!(audit.len(), count + 2);
    let mut moves: Vec<_> = audit
        .iter()
        .filter(|row| row.op == AuditOp::ModuleSecretMove.as_str())
        .collect();
    moves.sort_by_key(|row| row.seq);
    assert_eq!(
        moves
            .iter()
            .map(|row| row.credential_id.as_deref())
            .collect::<Vec<_>>(),
        [Some("module-secret|new|a"), Some("module-secret|new|z")]
    );
    assert!(moves.iter().all(|row| row.actor == "offline-cli"
        && row.alarm_reason.as_deref() == Some(AlarmReason::AdminWrite.as_str())));
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

fn snapshot(store: &TestStore) -> (Vec<String>, Vec<credentials_core::audit::AuditEntry>) {
    let rows = store.with_raw_conn(|conn| {
        conn.prepare("SELECT json_array(module_id,name,version,protected,state,key_id,hex(envelope),created_at_ms,updated_at_ms) FROM module_secrets ORDER BY module_id,name")?
            .query_map([], |row| row.get(0))?.collect()
    }).unwrap();
    (rows, store.read_audit(None).unwrap())
}

#[test]
fn module_secret_move_refusals_and_late_audit_failure_move_nothing() {
    use credentials_core::envelope::{seal, RecordBinding};
    use credentials_core::key::MasterKey;
    for (case, expected) in [
        ("same", "invalid_params"),
        ("empty", "not_found"),
        ("occupied", "invalid_params"),
        ("corrupt", "corrupt"),
        ("bad-envelope", "corrupt"),
        ("wrong-key", "vault_locked"),
        ("late-audit", "store_error"),
    ] {
        let vault = Vault::new();
        vault.bootstrap();
        vault.seed("old", "a", false);
        vault.seed("old", "z", true);
        if case == "occupied" {
            vault.seed("new", "other", false);
        }
        let store = vault.store();
        match case {
            "corrupt" => {
                store
                    .with_raw_conn(|conn| {
                        conn.execute(
                            "UPDATE module_secrets SET state='corrupt' WHERE name='z'",
                            [],
                        )
                    })
                    .unwrap();
            }
            "bad-envelope" => {
                store
                    .with_raw_conn(|conn| {
                        conn.execute(
                            "UPDATE module_secrets SET envelope=x'00' WHERE name='z'",
                            [],
                        )
                    })
                    .unwrap();
            }
            "wrong-key" => {
                let key = MasterKey::from_bytes([0x79; 32]);
                let sealed = seal(
                    &key,
                    CANARY,
                    &RecordBinding {
                        credential_id: "module-secret|old|z",
                        record_version: 1,
                    },
                )
                .unwrap();
                store
                    .with_raw_conn(|conn| {
                        conn.execute(
                            "UPDATE module_secrets SET envelope=?1 WHERE name='z'",
                            [sealed],
                        )
                    })
                    .unwrap();
            }
            "late-audit" => {
                store.with_raw_conn(|conn| conn.execute_batch(
                "CREATE TRIGGER refuse_second_move BEFORE INSERT ON audit_log WHEN NEW.op='module_secret_move' AND NEW.credential_id='module-secret|new|z' BEGIN SELECT RAISE(ABORT,'injected audit failure'); END;"
            )).unwrap();
            }
            _ => {}
        }
        let before = snapshot(&store);
        drop(store);
        let (from, to) = match case {
            "same" => ("old", "old"),
            "empty" => ("absent", "new"),
            _ => ("old", "new"),
        };
        refused(
            vault.run(&["module-secret", "move", "--from", from, "--to", to]),
            expected,
        );
        assert_eq!(
            snapshot(&vault.store()),
            before,
            "{case} changed rows or the audit chain"
        );
    }
}

#[test]
fn module_secret_cli_grammar_and_flag_errors_happen_before_store_access() {
    let vault = Vault::new();
    for args in [
        vec!["list", "--module", "Bad"],
        vec![
            "delete",
            "--module",
            "ok",
            "--name",
            "bad|name",
            "--confirm",
            "ok:bad|name",
        ],
        vec!["move", "--from", "old|bad", "--to", "new"],
        vec!["move", "--from", "old", "--to", "New"],
        vec!["list", "--name", "key"],
        vec!["move", "--from", "old", "--to", "new", "--to", "other"],
    ] {
        let mut invocation = vec!["module-secret"];
        invocation.extend(args);
        let output = vault.run(&invocation);
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("master key"));
        assert!(!vault.key.exists());
        assert!(!vault.data.join("store.db").exists());
    }
}

#[test]
fn module_secret_apply_revalidates_every_selector_before_store_access() {
    let vault = Vault::new();
    vault.bootstrap();
    let store = vault.store();
    // A missing table makes any accidental query return Store, not InvalidParams.
    store
        .with_raw_conn(|conn| conn.execute_batch("DROP TABLE module_secrets"))
        .unwrap();
    for op in [
        AdminOpBody::ModuleSecretList {
            v: 2,
            module: Some("Bad".into()),
        },
        AdminOpBody::ModuleSecretDelete {
            v: 2,
            module: "Bad".into(),
            name: "ok".into(),
        },
        AdminOpBody::ModuleSecretDelete {
            v: 2,
            module: "ok".into(),
            name: "Bad".into(),
        },
        AdminOpBody::ModuleSecretMove {
            v: 2,
            from: "Bad".into(),
            to: "ok".into(),
        },
        AdminOpBody::ModuleSecretMove {
            v: 2,
            from: "ok".into(),
            to: "Bad".into(),
        },
    ] {
        assert!(matches!(
            apply(&store, op, "operator"),
            Err(StoreOpError::ModuleSecret(ModuleSecretError::InvalidParams))
        ));
    }
}

#[test]
fn module_secret_admin_bodies_round_trip_and_keep_schema_pairing() {
    for (op, name) in [
        (
            AdminOpBody::ModuleSecretList {
                v: ADMIN_OP_SCHEMA_V2,
                module: None,
            },
            "admin.module_secret_list",
        ),
        (
            AdminOpBody::ModuleSecretDelete {
                v: ADMIN_OP_SCHEMA_V2,
                module: "alpha".into(),
                name: "key".into(),
            },
            "admin.module_secret_delete",
        ),
        (
            AdminOpBody::ModuleSecretMove {
                v: ADMIN_OP_SCHEMA_V2,
                from: "alpha".into(),
                to: "beta".into(),
            },
            "admin.module_secret_move",
        ),
    ] {
        assert!(op.has_valid_schema_version());
        assert_eq!(op.schema_version(), 2);
        assert_eq!(op.required_schema_version(), 2);
        assert_eq!(op.lock_id(), None);
        assert!(!op.requires_daemon());
        assert_eq!(op.op_name(), name);
        let bytes = op.to_bytes().unwrap();
        let decoded: AdminOpBody = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.to_bytes().unwrap(), bytes);
        let mut invalid: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        invalid["v"] = 1.into();
        assert!(!serde_json::from_value::<AdminOpBody>(invalid)
            .unwrap()
            .has_valid_schema_version());
    }
}

#[test]
fn module_secret_help_has_each_verb_and_stays_within_eighty_columns() {
    let vault = Vault::new();
    let top = success(vault.run(&["help"]));
    assert!(top
        .lines()
        .any(|line| line.trim_start().starts_with("module-secret ")));
    let table = success(vault.run(&["help", "module-secret"]));
    for verb in ["list", "delete", "move"] {
        assert!(table
            .lines()
            .any(|line| line.trim_start().starts_with(&format!("{verb} "))));
        let help = success(vault.run(&["help", "module-secret", verb]));
        assert_eq!(help, success(vault.run(&["module-secret", verb, "--help"])));
        assert!(help.contains(&format!("ck auth module-secret {verb}")));
        assert!(
            help.lines().all(|line| line.chars().count() <= 80),
            "{help}"
        );
    }
}
