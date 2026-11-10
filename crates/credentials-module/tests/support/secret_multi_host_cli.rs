use super::*;

fn stdout_ok(out: std::process::Output) -> String {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(!text.contains(MATERIAL_CANARY));
    text
}

#[test]
fn secret_multi_host_setting_offline_online_and_lease_free_status() {
    let vault = GrantCliVault::new("multi-host-setting");
    let status = || stdout_ok(vault.run(&["secret", "multi-host", "status"]));
    assert_eq!(status(), "multi-host setting off\n");
    let path = vault.data_dir.join("store.db");
    drop(rusqlite::Connection::open(&path).unwrap());
    assert_eq!(status(), "multi-host setting off\n");
    std::fs::remove_file(&path).unwrap();
    vault.bootstrap();
    assert_eq!(status(), "multi-host setting off\n");
    for action in ["on", "off"] {
        assert_eq!(
            stdout_ok(vault.run(&["secret", "multi-host", action])),
            format!("multi-host setting {action}\n")
        );
        assert_eq!(status(), format!("multi-host setting {action}\n"));
    }
    if std::env::var_os(CLI_BIN_ENV).is_none() {
        let peer = ProviderRoutePeer::start(&vault);
        let out = cli()
            .args(["secret", "multi-host", "on", "--data-dir"])
            .arg(&vault.data_dir)
            .arg("--key-path")
            .arg(&vault.key_path)
            .arg("--subc")
            .arg(&peer.connection)
            .env("CORTEXKIT_TEST_BYPASS_VALIDATION", "1")
            .output()
            .unwrap();
        assert_eq!(stdout_ok(out), "multi-host setting on\n");
        assert_eq!(status(), "multi-host setting on\n");
        assert_eq!(
            peer.observed
                .lock()
                .unwrap()
                .iter()
                .filter(|v| v["op"] == "admin.secret_multi_host_set")
                .count(),
            1
        );
        drop(peer);
    }
    let held = open_sqlite(&StorageDescriptor {
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    })
    .unwrap();
    assert_eq!(
        status(),
        if std::env::var_os(CLI_BIN_ENV).is_none() {
            "multi-host setting on\n"
        } else {
            "multi-host setting off\n"
        }
    );
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE settings SET value='broken' WHERE name='secret.multi_host'",
        [],
    )
    .unwrap();
    assert_eq!(status(), "multi-host setting unreadable\n");
    for args in [
        vec!["secret", "multi-host"],
        vec!["secret", "multi-host", "bogus"],
        vec!["secret", "multi-host", "on", "off"],
    ] {
        assert!(!vault.run(&args).status.success());
    }
    drop(held);
}

#[test]
fn secret_multi_host_put_maps_legacy_and_extended_and_surfaces_disabled() {
    let vault = GrantCliVault::new("multi-host-put");
    vault.bootstrap();
    let file = material_file(&vault.root, 0o600, MATERIAL_CANARY);
    let put = |name: &str, kind: &str, flags: &[&str]| {
        let mut args = vec![
            "secret",
            "put",
            name,
            "--kind",
            kind,
            "--material-file",
            file.to_str().unwrap(),
        ];
        args.extend_from_slice(flags);
        vault.run(&args)
    };
    stdout_ok(put("legacy-rule", "api-key", &["--rule", "x.test/repos/a"]));
    stdout_ok(put(
        "legacy-literal-prefix",
        "api-key",
        &["--rule", "x.test/v1/*"],
    ));
    let refused = put("wildcard", "api-key", &["--rule", "*.x.test"]);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("secret_multi_host_disabled"),
        "{refused:?}"
    );
    assert_eq!(agent_secret_listing(&vault.data_dir).secrets.len(), 2);
    stdout_ok(vault.run(&["secret", "multi-host", "on"]));
    stdout_ok(put("wildcard", "api-key", &["--rule", "*.x.test"]));
    stdout_ok(put(
        "many-rules",
        "api-key",
        &["--rule", "z.test/v1", "--rule", "a.test"],
    ));
    std::fs::write(&file, "fixture-user\nfixture-password").unwrap();
    stdout_ok(put(
        "legacy-origin",
        "site-login",
        &["--origin", "https://x.test:443"],
    ));
    stdout_ok(put(
        "many-origins",
        "site-login",
        &["--origin", "https://z.test", "--origin", "https://a.test"],
    ));
    let listing = agent_secret_listing(&vault.data_dir);
    let row = |name: &str| listing.secrets.iter().find(|r| r.name == name).unwrap();
    assert_eq!(row("legacy-rule").host.as_deref(), Some("x.test"));
    assert_eq!(row("legacy-rule").path_prefix.as_deref(), Some("/repos/a"));
    assert_eq!(row("legacy-rule").scope_json, None);
    assert_eq!(row("legacy-literal-prefix").scope_json, None);
    assert_eq!(
        row("legacy-literal-prefix").path_prefix.as_deref(),
        Some("/v1/*")
    );
    assert_eq!(
        row("legacy-origin").origin.as_deref(),
        Some("https://x.test:443")
    );
    assert_eq!(row("legacy-origin").scope_json, None);
    for name in ["wildcard", "many-rules", "many-origins"] {
        assert_eq!(row(name).host, None);
        assert_eq!(row(name).origin, None);
        assert!(row(name).scope_json.is_some());
    }
    let text = stdout_ok(vault.run(&["secret", "list"]));
    for expected in [
        "legacy-rule agent_api_key active host=x.test prefix=/repos/a location=authorization_bearer",
        "legacy-literal-prefix agent_api_key active host=x.test prefix=/v1/* location=authorization_bearer",
        "legacy-origin site_login active origin=https://x.test:443",
        "wildcard agent_api_key active rule=*.x.test location=authorization_bearer",
        "many-rules agent_api_key active rule=a.test rule=z.test/v1 location=authorization_bearer",
        "many-origins site_login active origin=https://a.test origin=https://z.test",
    ] {
        assert!(text.lines().any(|line| line == expected), "missing {expected}: {text}");
    }
}

#[test]
fn secret_multi_host_invalid_fields_precede_material_daemon_and_lease() {
    let vault = GrantCliVault::new("multi-host-preflight");
    let cases: &[(&str, &[&str], &str)] = &[
        (
            "api-key",
            &["--rule", "x.test", "--host", "x.test"],
            "--rule",
        ),
        (
            "api-key",
            &["--rule", "x.test", "--path-prefix", "/v1"],
            "--rule",
        ),
        ("api-key", &["--rule", "*.com"], "--rule"),
        ("api-key", &["--rule", "*.github.io"], "--rule"),
        ("api-key", &["--rule", "UPPER.test"], "--rule"),
        ("api-key", &["--rule", "x.test/"], "--rule"),
        (
            "api-key",
            &["--rule", "x.test", "--rule", "x.test"],
            "--rule",
        ),
        ("api-key", &["--rule", "a.*.test"], "--rule"),
        (
            "api-key",
            &["--rule", "x.test", "--origin", "https://x.test"],
            "--origin",
        ),
        (
            "api-key",
            &["--rule", "*.x.test", "--location", "header:Host"],
            "--location",
        ),
        (
            "site-login",
            &["--rule", "x.test", "--origin", "https://x.test"],
            "--rule",
        ),
        (
            "site-login",
            &[
                "--origin",
                "https://x.test",
                "--origin",
                "https://x.test:443",
            ],
            "--origin",
        ),
        (
            "site-login",
            &["--origin", "https://x.test", "--origin", "http://y.test"],
            "--origin",
        ),
    ];
    for (kind, flags, field) in cases {
        let out = cli()
            .args(["secret", "put", "invalid", "--kind", kind])
            .args(*flags)
            .args([
                "--material-file",
                "missing-material",
                "--subc",
                "missing-daemon",
                "--data-dir",
            ])
            .arg(&vault.data_dir)
            .arg("--key-path")
            .arg(&vault.key_path)
            .output()
            .unwrap();
        assert!(!out.status.success());
        let error = String::from_utf8_lossy(&out.stderr);
        assert!(error.contains(field), "{flags:?}: {error}");
        assert!(
            !error.contains("cannot read material") && !error.contains("missing-daemon"),
            "{error}"
        );
        assert!(!vault.data_dir.join("store.db").exists());
    }
}

#[test]
fn secret_multi_host_cli_count_boundaries() {
    let vault = GrantCliVault::new("multi-host-counts");
    vault.bootstrap();
    stdout_ok(vault.run(&["secret", "multi-host", "on"]));
    let file = material_file(&vault.root, 0o600, MATERIAL_CANARY);
    for (kind, flag, accepted) in [("api-key", "--rule", 8), ("site-login", "--origin", 4)] {
        if kind == "site-login" {
            std::fs::write(&file, "fixture-user\nfixture-password").unwrap();
        }
        for count in [accepted, accepted + 1] {
            let name = format!("{kind}-{count}");
            let mut args: Vec<String> = [
                "secret",
                "put",
                &name,
                "--kind",
                kind,
                "--material-file",
                file.to_str().unwrap(),
            ]
            .into_iter()
            .map(str::to_owned)
            .collect();
            for i in 0..count {
                args.push(flag.into());
                args.push(if kind == "api-key" {
                    format!("h{i}.test")
                } else {
                    format!("https://h{i}.test")
                });
            }
            let refs: Vec<_> = args.iter().map(String::as_str).collect();
            let out = vault.run(&refs);
            if count == accepted {
                stdout_ok(out);
            } else {
                assert!(!out.status.success());
                assert!(
                    String::from_utf8_lossy(&out.stderr).contains(flag),
                    "{out:?}"
                );
                assert!(!agent_secret_listing(&vault.data_dir)
                    .secrets
                    .iter()
                    .any(|r| r.name == name));
            }
        }
    }
}

#[test]
fn secret_multi_host_help_lists_switch_and_repeatable_flags() {
    let help = stdout_ok(cli().args(["help", "secret"]).output().unwrap());
    assert!(help.contains("multi-host on|off|status"), "{help}");
    for flag in ["--rule", "--origin"] {
        assert!(
            help.lines()
                .any(|line| line.contains(flag) && line.contains("repeat")),
            "{help}"
        );
    }
    assert!(help.lines().all(|line| line.chars().count() <= 80));
    let table = stdout_ok(cli().arg("help").output().unwrap());
    assert!(
        table
            .lines()
            .any(|line| line.contains("secret") && line.contains("multi-host")),
        "{table}"
    );
}

#[test]
fn secret_multi_host_corrupt_scope_lists_grants_and_can_be_deleted() {
    let vault = GrantCliVault::new("multi-host-corrupt");
    vault.bootstrap();
    stdout_ok(vault.run(&["secret", "multi-host", "on"]));
    let file = material_file(&vault.root, 0o600, MATERIAL_CANARY);
    for (name, kind, flags) in [
        ("key", "api-key", vec!["--rule", "*.x.test"]),
        (
            "login",
            "site-login",
            vec!["--origin", "https://x.test", "--origin", "https://y.test"],
        ),
    ] {
        if kind == "site-login" {
            std::fs::write(&file, "fixture-user\nfixture-password").unwrap();
        }
        let mut args = vec![
            "secret",
            "put",
            name,
            "--kind",
            kind,
            "--material-file",
            file.to_str().unwrap(),
        ];
        args.extend_from_slice(&flags);
        stdout_ok(vault.run(&args));
        let grant_id = format!("flow-{name}");
        add_flow_grant(&vault.data_dir, &grant_id, name, "install-A");
        let conn = rusqlite::Connection::open(vault.data_dir.join("store.db")).unwrap();
        conn.execute(
            "INSERT INTO secret_grants (grant_id,secret_name,incarnation,scope_owner,scope_kind,scope_ref,coverage,duration,expires_at_ms,granted_at_ms,envelope_sha256) SELECT ?1,name,incarnation,'owner','head','H','scope','permanent',0,10,'digest' FROM agent_secrets WHERE name=?2",
            rusqlite::params![format!("agent-{name}"), name],
        ).unwrap();
        let invalid = if kind == "api-key" {
            vec![
                "not json",
                r#"[{"host":"x.test","path_prefix":""}]"#,
                r#"[ {"host":"*.x.test","path_prefix":""} ]"#,
                r#"[{"host":"*.x.test","path_prefix":""},{"host":"*.x.test","path_prefix":""}]"#,
            ]
        } else {
            vec![
                "not json",
                r#"["https://x.test"]"#,
                r#"[ "https://x.test", "https://y.test" ]"#,
                r#"["https://x.test","https://x.test:443"]"#,
            ]
        };
        for raw in invalid {
            conn.execute(
                "UPDATE agent_secrets SET scope_json=?1 WHERE name=?2",
                [raw, name],
            )
            .unwrap();
            let list = stdout_ok(vault.run(&["secret", "list"]));
            let stored_kind = if kind == "api-key" {
                "agent_api_key"
            } else {
                "site_login"
            };
            assert!(
                list.lines()
                    .any(|line| line == format!("{name} {stored_kind} active scope=unreadable")),
                "{list}"
            );
            let grants = stdout_ok(vault.run(&["secret", "grants"]));
            assert!(
                grants.contains(&format!("{grant_id} secret|{name}")),
                "{grants}"
            );
            assert!(
                grants.contains(&format!("agent-{name} secret|{name}")),
                "{grants}"
            );
        }
        drop(conn);
        assert_eq!(
            stdout_ok(vault.run(&["secret", "delete", name])),
            format!("deleted secret {name}\n")
        );
        assert!(!agent_secret_listing(&vault.data_dir)
            .secrets
            .iter()
            .any(|row| row.name == name));
        let grants = stdout_ok(vault.run(&["secret", "grants"]));
        assert!(!grants.contains(&format!("secret|{name}")), "{grants}");
    }
}

#[test]
fn secret_multi_host_list_reads_step_34_and_mixed_migrated_scopes_without_lease() {
    let vault = GrantCliVault::new("multi-host-old-list");
    let path = vault.data_dir.join("store.db");
    let sqlite = open_sqlite(&StorageDescriptor {
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    })
    .unwrap();
    credentials_core::store::migrate_through_for_test(&sqlite, 34).unwrap();
    sqlite.with_conn(|conn| conn.execute_batch(
        "INSERT INTO agent_secrets (name,kind,incarnation,state,host,path_prefix,location,origin,record_version,key_id,envelope,created_at_ms) VALUES ('legacy-key','agent_api_key','00000000000000000000000000000001','active','x.test','/v1','authorization_bearer',NULL,1,'key',x'00',10),('legacy-login','site_login','00000000000000000000000000000002','corrupt',NULL,NULL,NULL,'https://x.test',1,'key',x'00',10);"
    )).unwrap();
    let legacy = "legacy-key agent_api_key active host=x.test prefix=/v1 location=authorization_bearer\nlegacy-login site_login corrupt origin=https://x.test\n";
    assert_eq!(stdout_ok(vault.run(&["secret", "list"])), legacy);
    credentials_core::store::migrate_through_for_test(&sqlite, 35).unwrap();
    sqlite.with_conn(|conn| conn.execute_batch(
        "INSERT INTO agent_secrets (name,kind,incarnation,state,location,record_version,key_id,envelope,created_at_ms,scope_json) VALUES ('extended-key','agent_api_key','00000000000000000000000000000003','active','authorization_bearer',1,'key',x'00',10,'[{\"host\":\"*.github.io\",\"path_prefix\":\"\"}]');
         INSERT INTO agent_secrets (name,kind,incarnation,state,record_version,key_id,envelope,created_at_ms,scope_json) VALUES ('extended-login','site_login','00000000000000000000000000000004','active',1,'key',x'00',10,'[\"https://a.test\",\"https://z.test:443\"]');"
    )).unwrap();
    assert_eq!(stdout_ok(vault.run(&["secret", "list"])), format!(
        "extended-key agent_api_key active rule=*.github.io location=authorization_bearer\nextended-login site_login active origin=https://a.test origin=https://z.test:443\n{legacy}"
    ));
    assert!(!vault.key_path.exists());
}

#[test]
fn secret_multi_host_operator_list_vectors_use_the_real_renderer() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../credentials-core/tests/vectors/multi-host/secret-list-v2.json"
    ))
    .unwrap();
    let mut checked = 0;
    for case in corpus["cases"].as_array().unwrap() {
        if case["operation"] != "ck auth secret list" {
            continue;
        }
        let label = case["case"].as_str().unwrap();
        let vault = GrantCliVault::new(label);
        vault.bootstrap();
        stdout_ok(vault.run(&["secret", "multi-host", "on"]));
        let setup = &case["setup"];
        let kind = setup["kind"].as_str().unwrap();
        let scope = &setup["stored_scope"];
        let raw = setup["scope_json"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| {
                scope[if kind == "agent_api_key" {
                    "rules"
                } else {
                    "origins"
                }]
                .to_string()
            });
        let conn = rusqlite::Connection::open(vault.data_dir.join("store.db")).unwrap();
        conn.execute(
            "INSERT INTO agent_secrets (name,kind,incarnation,state,location,record_version,key_id,envelope,created_at_ms,scope_json) VALUES (?1,?2,'00000000000000000000000000000149','active',?3,1,'test-key',x'00',10,?4)",
            rusqlite::params![setup["name"].as_str().unwrap(),kind,
                (kind == "agent_api_key").then(||scope["location"].as_str().unwrap_or("header:X-Api-Key")),raw],
        ).unwrap();
        drop(conn);
        let expected = case["expect"]["line"].as_str().unwrap();
        assert_eq!(
            stdout_ok(vault.run(&["secret", "list"])),
            format!("{expected}\n"),
            "{label}"
        );
        checked += 1;
    }
    assert_eq!(checked, 3, "every operator-list vector must reach the CLI");
}
