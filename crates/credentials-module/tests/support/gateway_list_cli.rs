use super::*;

fn run(
    vault: &GrantCliVault,
    peer: Option<&ProviderRoutePeer>,
    args: &[&str],
) -> std::process::Output {
    let mut command = cli();
    isolated_cli::assert_isolated(&command);
    command
        .args(args)
        .arg("--data-dir")
        .arg(&vault.data_dir)
        .arg("--key-path")
        .arg(&vault.key_path);
    if let Some(peer) = peer {
        command.arg("--subc").arg(&peer.connection);
    }
    let out = command.output().unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

#[test]
fn gateway_list_online_and_offline_show_names_only_and_json_keeps_values() {
    let vault = GrantCliVault::new("gateway-list");
    vault.bootstrap();
    run(
        &vault,
        None,
        &[
            "put",
            "--id",
            "apikey:custom",
            "--payload-file",
            &payload_file("ordinary-key-canary"),
        ],
    );
    run(
        &vault,
        None,
        &["set-category", "apikey:custom", "--set", "llm-gateway"],
    );
    let ordinary = run(&vault, None, &["list", "--json"]);
    let ordinary: serde_json::Value = serde_json::from_slice(&ordinary.stdout).unwrap();
    let ordinary_bytes = serde_json::to_string(&ordinary["credentials"][0]).unwrap();

    for (id, extra_headers) in [
        (
            "apikey:anthropic-gw-acme",
            vec![
                "--gateway-header",
                "x-z=last-value-canary",
                "--gateway-header",
                "x-a=first-value-canary",
            ],
        ),
        ("apikey:anthropic-gw-acme:empty", vec![]),
    ] {
        let file = payload_file("gateway-key-canary");
        let mut args = vec![
            "put",
            "--id",
            id,
            "--payload-file",
            &file,
            "--gateway-base-url",
            "http://[::1]:4000/v1",
            "--gateway-auth-header",
            "authorization",
            "--gateway-auth-scheme",
            "bearer",
            "--provider-id",
            "anthropic-gw-acme",
        ];
        args.extend(extra_headers);
        run(&vault, None, &args);
    }

    let peer = ProviderRoutePeer::start(&vault);
    let mut offline = None;
    for route in [None, Some(&peer)] {
        let text = run(&vault, route, &["list"]);
        let stdout = String::from_utf8(text.stdout).unwrap();
        for (id, names) in [
            ("apikey:anthropic-gw-acme", "x-a,x-z"),
            ("apikey:anthropic-gw-acme:empty", "-"),
        ] {
            let row = stdout
                .lines()
                .find(|line| line.split_whitespace().any(|word| word == id))
                .unwrap();
            assert!(
                row.ends_with(&format!(
                    "method=gateway  base_url=http://[::1]:4000/v1  headers={names}"
                )),
                "{row}"
            );
        }
        let custom = stdout
            .lines()
            .find(|line| line.contains("apikey:custom"))
            .unwrap();
        assert!(!custom.contains("gateway  base_url="));
        for marker in [
            "first-value-canary",
            "last-value-canary",
            "gateway-key-canary",
            "ordinary-key-canary",
        ] {
            assert!(!stdout.contains(marker), "text listing exposed a value");
            assert!(!String::from_utf8_lossy(&text.stderr).contains(marker));
        }

        let json = run(&vault, route, &["list", "--json"]);
        let raw = String::from_utf8(json.stdout).unwrap();
        assert!(raw.contains(&ordinary_bytes), "ordinary row bytes changed");
        assert!(!raw.contains("gateway-key-canary"));
        assert!(!raw.contains("ordinary-key-canary"));
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let rows = doc["credentials"].as_array().unwrap();
        assert_eq!(rows.len(), 3);
        for row in rows {
            if row["id"] == "apikey:custom" {
                assert!(row.get("base_url").is_none());
                assert!(row.get("headers").is_none());
                assert_eq!(row["auth_method"], "apikey");
            } else {
                assert_eq!(row["auth_method"], "gateway");
                assert_eq!(row["base_url"], "http://[::1]:4000/v1");
                assert_eq!(
                    row["headers"],
                    if row["id"] == "apikey:anthropic-gw-acme" {
                        serde_json::json!({"x-a": "first-value-canary", "x-z": "last-value-canary"})
                    } else {
                        serde_json::json!({})
                    }
                );
                let old_keys: Vec<_> = ordinary["credentials"][0]
                    .as_object()
                    .unwrap()
                    .keys()
                    .collect();
                let gateway_old_keys: Vec<_> = row
                    .as_object()
                    .unwrap()
                    .keys()
                    .filter(|key| !matches!(key.as_str(), "base_url" | "headers"))
                    .collect();
                assert_eq!(gateway_old_keys, old_keys);
                assert_eq!(row.as_object().unwrap().len(), old_keys.len() + 2);
            }
        }
        if let Some((prior_text, prior_json)) = &offline {
            assert_eq!(&stdout, prior_text);
            assert_eq!(&raw, prior_json);
        } else {
            offline = Some((stdout, raw));
        }
    }
    assert_eq!(
        peer.observed.lock().unwrap().len(),
        2,
        "both reads used admin.status"
    );
}

#[test]
fn gateway_list_and_status_below_migration_keep_output_and_schema_unchanged() {
    let vault = GrantCliVault::new("gateway-list-behind");
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
    let version = credentials_core::store::GATEWAY_SETTINGS_SCHEMA_VERSION - 1;
    credentials_core::store::migrate_through_for_test(&sqlite, version).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([241; 32])).unwrap();
    store
        .create(
            "apikey:custom",
            &credentials_core::VaultRecord::new_static(
                CredentialKind::ApiKey,
                "test",
                b"fixture-key".to_vec(),
                None,
            ),
        )
        .unwrap();
    drop(store);

    let schema = || {
        let conn = rusqlite::Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let version: u32 = conn
            .query_row(
                "SELECT MAX(version) FROM cortexkit_schema_version",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut stmt = conn
            .prepare("SELECT name, sql FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap();
        let tables = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        (version, tables)
    };
    let before = schema();
    assert_eq!(before.0, version);
    assert!(!before
        .1
        .iter()
        .any(|(name, _)| name == "credential_gateway_settings"));

    // Pin the pre-gateway human output, not a second rendering of the new metadata.
    let expected_list = concat!(
        "STATE          VER   CREDENTIAL  CATEGORIES  PROVIDERS\n",
        "active         v1    apikey:custom  -  -\n",
        "\n(`active` = nothing has reported it dead. Not a check that the provider still accepts it;\n",
        " that costs a real call. `ck auth usable` opens the envelopes; only a get proves service.)\n",
    );
    for (args, expected) in [
        (vec!["list"], expected_list.to_string()),
        (
            vec!["status"],
            format!("vault: ok (1/1 serving)\n\n{expected_list}\nread grants: none\n"),
        ),
    ] {
        let out = run(&vault, None, &args);
        assert_eq!(String::from_utf8(out.stdout).unwrap(), expected);
        assert!(
            out.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            schema(),
            before,
            "{args:?} changed the schema or table list"
        );
    }
}
