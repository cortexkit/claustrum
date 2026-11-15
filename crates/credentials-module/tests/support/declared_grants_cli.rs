use super::*;

const INCOMPLETE: &str = "declared grants could not be read completely\n";
const SUMMARY: &str =
    "3 declared grant(s) from first-party modules; see ck auth grants --declared\n";

fn migrated_vault(tag: &str) -> GrantCliVault {
    let vault = GrantCliVault::new(tag);
    vault.bootstrap();
    let key = credentials_core::resolver::resolve(
        &credentials_core::resolver::ResolverConfig {
            data_dir: vault.data_dir.clone(),
            source: credentials_core::resolver::KeySource::OperatorPath {
                path: vault.key_path.clone(),
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
            path: vault
                .data_dir
                .join("store.db")
                .to_string_lossy()
                .into_owned(),
        },
    })
    .unwrap();
    EncryptedStore::migrate_with_key(&sqlite, &key).unwrap();
    drop(EncryptedStore::open(sqlite, key).unwrap());
    vault
}

fn seed_declared(vault: &GrantCliVault) {
    let conn = rusqlite::Connection::open(vault.data_dir.join("store.db")).unwrap();
    for (module, grants) in [
        (
            "z-module",
            r#"[{"selector_kind":"category","selector":"llm-provider","operation":"read"}]"#,
        ),
        (
            "a-long-module-name",
            r#"[{"selector_kind":"category","selector":"llm-provider","operation":"list"},{"selector_kind":"audience","selector":"cortexkit-account","operation":"account_token"}]"#,
        ),
    ] {
        conn.execute("INSERT INTO declared_grant_sets (module_id, declaration_digest, grants_json, skipped_count, first_seen_ms) VALUES (?1, 'digest', ?2, 0, 1700000000000)", rusqlite::params![module, grants]).unwrap();
    }
}

fn assert_ok(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn online(vault: &GrantCliVault, peer: &ProviderRoutePeer, args: &[&str]) -> std::process::Output {
    let mut command = cli();
    command
        .args(args)
        .arg("--data-dir")
        .arg(&vault.data_dir)
        .arg("--key-path")
        .arg(&vault.key_path)
        .arg("--subc")
        .arg(&peer.connection);
    command.output().unwrap()
}

// cortexkit-account's relay parser accepts only this header and grant rows with eight fields.
// A declared section on stdout would make the entire grant inventory unrecognizable.
fn account_accepts_grants(stdout: &[u8]) -> bool {
    let text = std::str::from_utf8(stdout).unwrap();
    if text.trim() == "no grants" {
        return true;
    }
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    if lines
        .next()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        != Some(vec![
            "KIND",
            "PRINCIPAL",
            "SELECTOR",
            "KIND",
            "SELECTOR",
            "OP",
            "REACHES",
            "GRANTED",
        ])
    {
        return false;
    }
    lines.all(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        fields.len() == 8
            && (fields[5].parse::<u64>().is_ok() || fields[5] == "token")
            && chrono::NaiveDate::parse_from_str(fields[6], "%Y-%m-%d").is_ok()
            && chrono::NaiveTime::parse_from_str(fields[7], "%H:%M:%S").is_ok()
    })
}

#[test]
fn declared_inventory_is_opt_in_and_plain_grants_stays_account_compatible() {
    let vault = migrated_vault("declared-cli-opt-in");
    assert_ok(&vault.run(&[
        "grant",
        "--principal",
        "agent",
        "--selector-kind",
        "category",
        "--selector",
        "llm-provider",
        "--operation",
        "read",
    ]));
    let before = vault.run(&["grants"]);
    let inventories: Vec<_> = [vec!["list"], vec!["list", "--json"], vec!["status"]]
        .into_iter()
        .map(|args| {
            let out = vault.run(&args);
            assert_ok(&out);
            (args, out)
        })
        .collect();
    seed_declared(&vault);
    let plain = vault.run(&["grants"]);
    assert_ok(&plain);
    assert_eq!(plain.stdout, before.stdout);
    assert_eq!(plain.stderr, SUMMARY.as_bytes());
    assert!(account_accepts_grants(&plain.stdout));
    let mut broken = plain.stdout.clone();
    broken.extend_from_slice(b"\ndeclared grants (last declaration each module presented):\n");
    assert!(
        !account_accepts_grants(&broken),
        "the compatibility check must reject an appended section"
    );
    for (args, expected) in inventories {
        let actual = vault.run(&args);
        assert_ok(&actual);
        assert_eq!(actual.stdout, expected.stdout, "{args:?}");
        assert_eq!(actual.stderr, expected.stderr, "{args:?}");
    }
    let declared = vault.run(&["grants", "--declared"]);
    assert_ok(&declared);
    assert!(declared.stderr.is_empty());
    assert_eq!(String::from_utf8(declared.stdout).unwrap(), concat!(
        "declared grants (last declaration each module presented):\n",
        "MODULE              SELECTOR KIND  SELECTOR           OP             REACHES  FIRST SEEN\n",
        "a-long-module-name  audience       cortexkit-account  account_token    token  2023-11-14 22:13:20\n",
        "a-long-module-name  category       llm-provider       list                 0  2023-11-14 22:13:20\n",
        "z-module            category       llm-provider       read                 0  2023-11-14 22:13:20\n",
    ));
}

#[test]
fn declared_corruption_only_and_mixed_rows_preserve_other_offline_outputs() {
    let vault = migrated_vault("declared-cli-corrupt");
    let before = vault.run(&["grants"]);
    assert_eq!(before.stdout, b"no grants\n");
    let inventories: Vec<_> = [vec!["list"], vec!["list", "--json"], vec!["status"]]
        .into_iter()
        .map(|args| (args.clone(), vault.run(&args)))
        .collect();
    seed_declared(&vault);
    let conn = rusqlite::Connection::open(vault.data_dir.join("store.db")).unwrap();
    conn.execute("UPDATE declared_grant_sets SET grants_json = 'corrupt-canary' WHERE module_id = 'z-module'", []).unwrap();
    let mixed = vault.run(&["grants", "--declared"]);
    assert_ok(&mixed);
    assert_eq!(mixed.stderr, INCOMPLETE.as_bytes());
    assert!(String::from_utf8_lossy(&mixed.stdout).contains("a-long-module-name"));
    assert!(!String::from_utf8_lossy(&mixed.stdout).contains("z-module"));
    let mixed_plain = vault.run(&["grants"]);
    assert_ok(&mixed_plain);
    assert_eq!(mixed_plain.stdout, before.stdout);
    assert_eq!(mixed_plain.stderr, format!("2 declared grant(s) from first-party modules; see ck auth grants --declared\n{INCOMPLETE}").as_bytes());
    conn.execute(
        "DELETE FROM declared_grant_sets WHERE module_id != 'z-module'",
        [],
    )
    .unwrap();
    for args in [vec!["grants"], vec!["grants", "--declared"]] {
        let output = vault.run(&args);
        assert_ok(&output);
        assert_eq!(output.stderr, INCOMPLETE.as_bytes());
        assert_eq!(
            output.stdout,
            if args.len() == 1 {
                before.stdout.clone()
            } else {
                Vec::new()
            }
        );
    }
    for (args, expected) in inventories {
        let actual = vault.run(&args);
        assert_ok(&actual);
        assert_eq!(actual.stdout, expected.stdout);
        assert_eq!(actual.stderr, expected.stderr);
    }
    let revoked = vault.run(&[
        "revoke-grant",
        "--principal",
        "z-module",
        "--selector-kind",
        "category",
        "--selector",
        "llm-provider",
        "--operation",
        "read",
    ]);
    assert!(!revoked.status.success());
    assert!(!String::from_utf8_lossy(&revoked.stderr).contains("declared_grant"));
    conn.execute("DROP TABLE declared_grant_sets", []).unwrap();
    let unreadable = vault.run(&["grants", "--declared"]);
    assert_ok(&unreadable);
    assert!(unreadable.stdout.is_empty());
    assert_eq!(unreadable.stderr, INCOMPLETE.as_bytes());
}

#[test]
fn declared_inventory_empty_and_step_44_print_no_extra_output() {
    let vault = migrated_vault("declared-cli-old");
    for old in [false, true] {
        if old {
            let conn = rusqlite::Connection::open(vault.data_dir.join("store.db")).unwrap();
            conn.execute_batch("DROP TABLE declared_grant_sets; DELETE FROM cortexkit_schema_version WHERE version = 45;").unwrap();
        }
        let plain = vault.run(&["grants"]);
        assert_ok(&plain);
        assert_eq!(plain.stdout, b"no grants\n");
        assert!(plain.stderr.is_empty());
        let declared = vault.run(&["grants", "--declared"]);
        assert_ok(&declared);
        assert!(declared.stdout.is_empty());
        assert!(declared.stderr.is_empty());
    }
}

#[test]
fn declared_grant_create_and_revoke_explain_the_last_seen_inventory() {
    let vault = migrated_vault("declared-cli-revoke");
    seed_declared(&vault);
    let args = |verb| {
        [
            verb,
            "--principal",
            "z-module",
            "--selector-kind",
            "category",
            "--selector",
            "llm-provider",
            "--operation",
            "read",
        ]
    };
    let refused = vault.run(&args("revoke-grant"));
    assert!(!refused.status.success());
    let remedy = String::from_utf8_lossy(&refused.stderr);
    for text in [
        "declared_grant/permanent",
        "z-module",
        "approved declaration",
        "daemon's configuration",
        "re-binds",
        "restart the module",
        "stored row is replaced",
    ] {
        assert!(remedy.contains(text), "{remedy}");
    }
    for verb in ["grant", "grant"] {
        let created = vault.run(&args(verb));
        assert_ok(&created);
        assert!(String::from_utf8_lossy(&created.stdout)
            .contains("the last-seen declaration also lists this tuple"));
    }
    let revoked = vault.run(&args("revoke-grant"));
    assert_ok(&revoked);
    assert!(String::from_utf8_lossy(&revoked.stdout)
        .contains("the last-seen declaration still lists this tuple"));
    assert_eq!(vault.run(&["grants"]).stdout, b"no grants\n");
}

#[test]
fn declared_flag_is_in_the_verb_table_and_wrapped_help_page() {
    for args in [
        vec!["help"],
        vec!["help", "grants"],
        vec!["grants", "--help"],
    ] {
        let output = cli().args(&args).output().unwrap();
        assert_ok(&output);
        let page = String::from_utf8(output.stdout).unwrap();
        assert!(page.contains("grants [--declared]"));
        if args.len() > 1 {
            assert!(page.contains("last-seen"));
            assert!(page.contains("restart the module"));
        }
        assert!(
            page.lines().all(|line| line.chars().count() <= 80),
            "{page}"
        );
    }
}

#[test]
fn declared_online_inventory_matches_offline_and_corruption_is_advisory() {
    let vault = migrated_vault("declared-cli-online");
    assert_ok(&vault.run(&[
        "put",
        "--id",
        "apikey:declared-test",
        "--payload-file",
        &payload_file("test-key"),
    ]));
    assert_ok(&vault.run(&[
        "set-category",
        "apikey:declared-test",
        "--set",
        "llm-provider",
    ]));
    assert_ok(&vault.run(&[
        "grant",
        "--principal",
        "agent",
        "--selector-kind",
        "category",
        "--selector",
        "llm-provider",
        "--operation",
        "read",
    ]));
    let baseline: Vec<_> = [
        vec!["list"],
        vec!["list", "--json"],
        vec!["status"],
        vec!["grants"],
    ]
    .into_iter()
    .map(|args| (args.clone(), vault.run(&args)))
    .collect();
    let peer = ProviderRoutePeer::start(&vault);
    seed_declared(&vault);
    for (args, before) in &baseline {
        let output = online(&vault, &peer, args);
        assert_ok(&output);
        assert_eq!(output.stdout, before.stdout, "{args:?}");
        assert_eq!(
            output.stderr,
            if args[0] == "grants" {
                SUMMARY.as_bytes()
            } else {
                &before.stderr
            }
        );
    }
    let declared = online(&vault, &peer, &["grants", "--declared"]);
    assert_ok(&declared);
    let offline = vault.run(&["grants", "--declared"]);
    assert_ok(&offline);
    assert_eq!(declared.stdout, offline.stdout);
    assert_eq!(declared.stderr, offline.stderr);
    let text = String::from_utf8(declared.stdout).unwrap();
    let rows: Vec<_> = text
        .lines()
        .skip(2)
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .collect();
    assert_eq!(
        rows.iter().map(|row| row[4]).collect::<Vec<_>>(),
        ["token", "1", "1"]
    );
    assert!(account_accepts_grants(
        &online(&vault, &peer, &["grants"]).stdout
    ));
    let conn = rusqlite::Connection::open(vault.data_dir.join("store.db")).unwrap();
    for corrupt_only in [false, true] {
        conn.execute("UPDATE declared_grant_sets SET grants_json = 'raw-json-canary' WHERE module_id = 'z-module'", []).unwrap();
        if corrupt_only {
            conn.execute(
                "DELETE FROM declared_grant_sets WHERE module_id != 'z-module'",
                [],
            )
            .unwrap();
        }
        for args in [vec!["grants"], vec!["grants", "--declared"]] {
            let online = online(&vault, &peer, &args);
            let offline = vault.run(&args);
            assert_ok(&online);
            assert_ok(&offline);
            assert_eq!(online.stdout, offline.stdout);
            assert_eq!(online.stderr, offline.stderr);
            let stderr = String::from_utf8(online.stderr).unwrap();
            assert_eq!(stderr.matches(INCOMPLETE).count(), 1);
            if corrupt_only {
                assert_eq!(stderr, INCOMPLETE);
                assert_eq!(
                    online.stdout,
                    if args.len() == 1 {
                        baseline[3].1.stdout.clone()
                    } else {
                        Vec::new()
                    }
                );
            }
        }
        for (args, expected) in &baseline[..3] {
            let actual = online(&vault, &peer, args);
            assert_ok(&actual);
            assert_eq!(actual.stdout, expected.stdout);
            assert_eq!(actual.stderr, expected.stderr);
        }
    }
    let revoked = online(
        &vault,
        &peer,
        &[
            "revoke-grant",
            "--principal",
            "z-module",
            "--selector-kind",
            "category",
            "--selector",
            "llm-provider",
            "--operation",
            "read",
        ],
    );
    assert!(!revoked.status.success());
    assert!(!String::from_utf8_lossy(&revoked.stderr).contains("declared_grant"));
    conn.execute("DROP TABLE declared_grant_sets", []).unwrap();
    let missing = online(&vault, &peer, &["grants", "--declared"]);
    assert_ok(&missing);
    assert!(missing.stdout.is_empty());
    assert_eq!(missing.stderr, INCOMPLETE.as_bytes());
    assert!(
        peer.observed.lock().unwrap().len() >= 10,
        "the online reads must actually traverse admin.op"
    );
}

#[test]
fn declared_online_grant_and_revoke_keep_the_remedy_and_success_fields() {
    let vault = migrated_vault("declared-cli-online-revoke");
    seed_declared(&vault);
    let peer = ProviderRoutePeer::start(&vault);
    let args = |verb| {
        [
            verb,
            "--principal",
            "z-module",
            "--selector-kind",
            "category",
            "--selector",
            "llm-provider",
            "--operation",
            "read",
        ]
    };
    let refused = online(&vault, &peer, &args("revoke-grant"));
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("declared_grant/permanent"));
    let created = online(&vault, &peer, &args("grant"));
    assert_ok(&created);
    assert!(String::from_utf8_lossy(&created.stdout)
        .contains("the last-seen declaration also lists this tuple"));
    let revoked = online(&vault, &peer, &args("revoke-grant"));
    assert_ok(&revoked);
    assert!(String::from_utf8_lossy(&revoked.stdout)
        .contains("the last-seen declaration still lists this tuple"));
}
