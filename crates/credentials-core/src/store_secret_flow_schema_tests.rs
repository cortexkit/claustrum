use super::*;
use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use rusqlite::types::Value as SqlValue;

const INC: &str = "00000000000000000000000000000001";
const CODE_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn migration_35_preserves_legacy_secrets_and_all_related_rows() {
    use crate::agent_secret::{self, SecretMaterial, SecretScope};
    use crate::secret::Secret;

    let (_root, sqlite) = crate::store::taxonomy_tests::sqlite("secret-scope-migration", 155);
    migrate_through_for_test(&sqlite, 34).unwrap();
    let key = MasterKey::from_bytes([155; 32]);
    let fixtures = [
        (
            "ops-key",
            INC,
            "active",
            SecretScope::ApiKey {
                host: "x.test".into(),
                path_prefix: Some("/repos/a".into()),
                location: "authorization_bearer".into(),
            },
            SecretMaterial::ApiKey(Secret::new(b"migration-test-key".to_vec())),
        ),
        (
            "login",
            "00000000000000000000000000000002",
            "corrupt",
            SecretScope::SiteLogin {
                origin: "https://x.test".into(),
            },
            SecretMaterial::SiteLogin {
                username: Secret::new("migration-user".into()),
                password: Secret::new("migration-test-password".into()),
                otpauth: None,
            },
        ),
    ];
    for (name, incarnation, state, scope, material) in &fixtures {
        let blob = agent_secret::seal(&key, incarnation, name, scope, material).unwrap();
        let (host, prefix, location, origin) = if let SecretScope::ApiKey {
            host,
            path_prefix,
            location,
        } = scope
        {
            (
                Some(host.as_str()),
                path_prefix.as_deref(),
                Some(location.as_str()),
                None,
            )
        } else if let SecretScope::SiteLogin { origin } = scope {
            (None, None, None, Some(origin.as_str()))
        } else {
            panic!("migration fixtures must use legacy scopes")
        };
        sqlite.with_conn(|conn| {
            conn.execute(
                "INSERT INTO agent_secrets (name,kind,incarnation,state,host,path_prefix,location,origin,record_version,key_id,envelope,created_at_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,1,'legacy-key-id',?9,10)",
                rusqlite::params![name, scope.kind(), incarnation, state, host, prefix, location, origin, blob],
            )?;
            Ok(())
        }).unwrap();
    }
    seed_flow(
        &sqlite,
        "flow-grant",
        "ops-key",
        INC,
        Some(r#"["GET","POST"]"#),
    );
    sqlite.with_conn(|conn| conn.execute_batch(&format!(
        "INSERT INTO secret_grants (grant_id,secret_name,incarnation,scope_owner,scope_kind,scope_ref,coverage,duration,expires_at_ms,granted_at_ms,envelope_sha256,agent_id,card_ref,first_released,last_use_ms,asking_member_id) VALUES ('agent-grant','ops-key','{INC}','owner','head','H','scope','hour',500,11,'envelope-hash','agent-A','card',1,12,'asking-vault');
         UPDATE secret_flow_grants SET asking_member_id='asking-vault';
         INSERT INTO secret_pending_requests (request_id,request_kind,secret_name,incarnation,member_id,mapped_owner,mapped_kind,mapped_ref,mapped_epoch,coverage,agent_id,statement_bytes,statement_sha256,request_expires_at_ms,consumed,flow_id,flow_version,flow_code_hash,flow_install_id,methods,asking_member_id) VALUES ('flow-request','approve','ops-key','{INC}','member','owner','head','H',7,'scope','agent-A',x'1234','digest',999,0,'daily-fetch',7,'{CODE_HASH}','flow-grant','[\"GET\"]','asking-vault');
         INSERT INTO secret_pending_requests (request_id,request_kind,secret_name,incarnation,member_id,statement_bytes,statement_sha256,request_expires_at_ms,consumed) VALUES ('delete-request','delete','login','00000000000000000000000000000002','member',x'5678','digest2',1000,1);
         INSERT INTO secret_deposit_tombstones VALUES ('deposit','digest','member','{INC}');
         INSERT INTO secret_release_receipts VALUES ('asking-vault','nonce','aad-hash','{INC}','flow','flow-grant',x'001122',x'334455',1000);"
    ))).unwrap();
    let tables = [
        "agent_secrets",
        "secret_grants",
        "secret_flow_grants",
        "secret_pending_requests",
        "secret_deposit_tombstones",
        "secret_release_receipts",
    ];
    let before: Vec<_> = tables.iter().map(|table| rows(&sqlite, table)).collect();
    migrate_through_for_test(&sqlite, SECRET_SCOPE_SCHEMA_VERSION).unwrap();
    assert_eq!(sqlite.with_conn(read_schema_version).unwrap(), 35);
    for (table, before) in tables.into_iter().zip(before) {
        let after = rows(&sqlite, table);
        assert_eq!(after.len(), before.len(), "{table}");
        for (old, new) in before.iter().zip(after) {
            if table == "agent_secrets" {
                assert_eq!(&new[..old.len()], old, "{table}");
                assert_eq!(&new[old.len()..], &[SqlValue::Null]);
            } else {
                assert_eq!(&new, old, "{table}");
            }
        }
    }
    sqlite.with_conn(|conn| {
        let columns = conn.prepare("PRAGMA table_info(agent_secrets)")?
            .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, bool>(3)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(columns.len(), 13);
        assert_eq!(columns.last().unwrap(), &("scope_json".into(), "TEXT".into(), false));
        let indexes = conn.prepare("SELECT il.origin, il.\"unique\", ii.name FROM pragma_index_list('agent_secrets') AS il JOIN pragma_index_info(il.name) AS ii ORDER BY il.origin")?
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?, r.get::<_, String>(2)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(indexes, [("pk".into(), true, "name".into()), ("u".into(), true, "incarnation".into())]);
        for (name, incarnation, _, scope, material) in &fixtures {
            let blob: Vec<u8> = conn.query_row("SELECT envelope FROM agent_secrets WHERE name=?1", [name], |r| r.get(0))?;
            assert_eq!(&agent_secret::open(&key, incarnation, name, scope, &blob).unwrap(), material);
        }
        Ok(())
    }).unwrap();
}

#[test]
fn migration_35_check_requires_exactly_one_scope_form_for_each_kind() {
    let (_root, sqlite) = crate::store::taxonomy_tests::sqlite("secret-scope-check", 156);
    migrate_through_for_test(&sqlite, SECRET_SCOPE_SCHEMA_VERSION).unwrap();
    let api = "agent_api_key";
    let login = "site_login";
    let host = Some("x.test");
    let prefix = Some("/repos/a");
    let location = Some("authorization_bearer");
    let origin = Some("https://x.test");
    // The table CHECK selects the scope form; stored decoding validates JSON contents.
    let scope = Some("[]");
    let accepted = [
        (api, host, prefix, location, None, None),
        (api, None, None, location, None, scope),
        (login, None, None, None, origin, None),
        (login, None, None, None, None, scope),
    ];
    let refused = [
        ("api both forms", (api, host, None, location, None, scope)),
        ("api neither form", (api, None, None, location, None, None)),
        (
            "api extended prefix",
            (api, None, prefix, location, None, scope),
        ),
        ("api missing location", (api, None, None, None, None, scope)),
        (
            "api empty location",
            (api, None, None, Some(""), None, scope),
        ),
        (
            "api with origin",
            (api, None, None, location, origin, scope),
        ),
        ("login both forms", (login, None, None, None, origin, scope)),
        ("login neither form", (login, None, None, None, None, None)),
        ("login with host", (login, host, None, None, None, scope)),
        (
            "login with prefix",
            (login, None, prefix, None, None, scope),
        ),
        (
            "login with location",
            (login, None, None, location, None, scope),
        ),
    ];
    sqlite.with_conn(|conn| {
        let insert = |name, incarnation, (kind, host, prefix, location, origin, scope)| conn.execute(
            "INSERT INTO agent_secrets (name,kind,incarnation,state,host,path_prefix,location,origin,record_version,key_id,envelope,created_at_ms,scope_json) VALUES (?1,?2,?3,'active',?4,?5,?6,?7,1,'key',x'1234',10,?8)",
            rusqlite::params![name, kind, incarnation, host, prefix, location, origin, scope],
        );
        for (i, fields) in accepted.into_iter().enumerate() {
            assert_eq!(insert(format!("valid-{i}"), format!("{i:032x}"), fields)?, 1);
        }
        for (i, (case, fields)) in refused.into_iter().enumerate() {
            let error = insert(format!("invalid-{i}"), format!("{:032x}", i + 100), fields).unwrap_err();
            assert_eq!(error.sqlite_error().unwrap().extended_code, rusqlite::ffi::SQLITE_CONSTRAINT_CHECK, "{case}: {error}");
        }
        let duplicate_name = insert("valid-0".into(), format!("{:032x}", 200), accepted[0]).unwrap_err();
        assert_eq!(duplicate_name.sqlite_error().unwrap().extended_code, rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY);
        let duplicate_incarnation = insert("duplicate-incarnation".into(), format!("{:032x}", 0), accepted[0]).unwrap_err();
        assert_eq!(duplicate_incarnation.sqlite_error().unwrap().extended_code, rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE);
        Ok(())
    }).unwrap();
}

#[test]
fn read_only_scope_listing_reads_steps_27_34_and_35_without_decoding_or_migrating() {
    let (root, sqlite) = crate::store::taxonomy_tests::sqlite("secret-scope-listing", 157);
    migrate_through_for_test(&sqlite, 27).unwrap();
    seed_agent_rows(&sqlite);
    let path = store_file(&root);
    let legacy = list_agent_secrets_read_only(&path).unwrap().unwrap();
    assert_eq!(legacy.secrets.len(), 1);
    assert_eq!(legacy.secrets[0].scope_json, None);
    assert_eq!(sqlite.with_conn(read_schema_version).unwrap(), 27);

    migrate_through_for_test(&sqlite, 34).unwrap();
    assert_eq!(
        list_agent_secrets_read_only(&path).unwrap().unwrap(),
        legacy
    );
    assert_eq!(sqlite.with_conn(read_schema_version).unwrap(), 34);

    migrate_through_for_test(&sqlite, SECRET_SCOPE_SCHEMA_VERSION).unwrap();
    assert_eq!(
        list_agent_secrets_read_only(&path).unwrap().unwrap(),
        legacy
    );
    let rules = r#"[{"host":"*.x.test","path_prefix":""}]"#;
    let unreadable = " not-json [ ";
    sqlite.with_conn(|conn| {
        conn.execute(
            "INSERT INTO agent_secrets (name,kind,incarnation,state,location,record_version,key_id,envelope,created_at_ms,scope_json) VALUES ('extended-key','agent_api_key',?1,'active','authorization_bearer',1,'key',x'00',10,?2)",
            rusqlite::params!["00000000000000000000000000000003", rules],
        )?;
        conn.execute(
            "INSERT INTO agent_secrets (name,kind,incarnation,state,record_version,key_id,envelope,created_at_ms,scope_json) VALUES ('unreadable-login','site_login',?1,'corrupt',1,'key',x'00',10,?2)",
            rusqlite::params!["00000000000000000000000000000004", unreadable],
        )?;
        Ok(())
    }).unwrap();
    let listing = list_agent_secrets_read_only(&path).unwrap().unwrap();
    assert_eq!(listing.secrets.len(), 3);
    assert_eq!(listing.secrets[0].scope_json.as_deref(), Some(rules));
    assert_eq!(listing.secrets[1], legacy.secrets[0]);
    assert_eq!(listing.secrets[2].scope_json.as_deref(), Some(unreadable));
    assert_eq!(list_agent_secret_grants_read_only(&path).unwrap().len(), 1);
    assert_eq!(sqlite.with_conn(read_schema_version).unwrap(), 35);
}

fn old_store(version: u32) -> (crate::test_support::TestTempDir, SqliteStore) {
    // Each caller migrates to a different version, so the version keeps tests that run in
    // parallel out of each other's directory; the pid keeps separate runs apart.
    let root = crate::test_support::TestTempDir::new(format!(
        "flow-schema-{version}-{}",
        std::process::id()
    ));
    let sqlite = open_sqlite(&StorageDescriptor {
        module_id: "claustrum".into(),
        storage_namespace: "flow-schema".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: store_file(&root).to_string_lossy().into_owned(),
        },
    })
    .unwrap();
    migrate_through_for_test(&sqlite, version).unwrap();
    (root, sqlite)
}

fn seed_agent_rows(sqlite: &SqliteStore) {
    sqlite.with_conn(|conn| conn.execute_batch(&format!(
        "INSERT INTO agent_secrets VALUES ('ops-key','agent_api_key','{INC}','active','x.test','/repos/a','authorization_bearer',NULL,1,'key',x'1234',10);
         INSERT INTO secret_grants VALUES ('agent-grant','ops-key','{INC}','owner','head','H','scope','permanent',0,11,'envelope-hash','agent-A','card',1,12);
         INSERT INTO secret_pending_requests VALUES ('agent-request','approve','ops-key','{INC}','member','owner','head','H',1,'scope','agent-A',x'1234','digest',999,0);
         INSERT INTO secret_pending_requests VALUES ('delete-request','delete','ops-key','{INC}','member',NULL,NULL,NULL,NULL,NULL,NULL,x'5678','digest2',1000,1);
         INSERT INTO secret_deposit_tombstones VALUES ('deposit','digest','member','{INC}');
         INSERT INTO secret_phone_keys VALUES ('fp','pair',zeroblob(32),zeroblob(65),10);
         INSERT INTO secret_phone_observations VALUES ('fp','pair',10);"
    ))).unwrap();
}

fn rows(sqlite: &SqliteStore, table: &str) -> Vec<Vec<SqlValue>> {
    sqlite
        .with_conn(|conn| {
            let mut stmt = conn.prepare(&format!("SELECT * FROM {table} ORDER BY 1"))?;
            let columns = stmt.column_count();
            let rows = stmt.query_map([], |r| {
                (0..columns)
                    .map(|i| r.get(i))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })?;
            rows.collect()
        })
        .unwrap()
}

fn seed_flow(sqlite: &SqliteStore, id: &str, name: &str, incarnation: &str, methods: Option<&str>) {
    sqlite.with_conn(|conn| {
        conn.execute(
            "INSERT INTO secret_flow_grants (grant_id,secret_name,incarnation,flow_id,flow_version,flow_code_hash,flow_install_id,methods,granted_at_ms,envelope_sha256,card_ref,last_use_ms) VALUES (?1,?2,?3,'daily-fetch',7,?4,?1,?5,10,'envelope-hash','flow-card',12)",
            rusqlite::params![id, name, incarnation, CODE_HASH, methods],
        )?;
        Ok(())
    }).unwrap();
}

#[test]
fn migration_28_conserves_every_agent_row_and_only_appends_nullable_pending_columns() {
    let (_root, sqlite) = old_store(AGENT_SECRET_SCHEMA_VERSION);
    seed_agent_rows(&sqlite);
    let tables = [
        "agent_secrets",
        "secret_grants",
        "secret_pending_requests",
        "secret_deposit_tombstones",
        "secret_phone_keys",
        "secret_phone_observations",
    ];
    let before: Vec<_> = tables.iter().map(|table| rows(&sqlite, table)).collect();
    migrate_through_for_test(&sqlite, FLOW_SECRET_SCHEMA_VERSION).unwrap();
    assert_eq!(
        sqlite.with_conn(read_schema_version).unwrap(),
        FLOW_SECRET_SCHEMA_VERSION
    );
    for (table, before) in tables.into_iter().zip(before) {
        let after = rows(&sqlite, table);
        assert_eq!(after.len(), before.len(), "{table}");
        for (old, new) in before.iter().zip(after) {
            assert_eq!(&new[..old.len()], old, "{table}");
            if table == "secret_pending_requests" {
                assert_eq!(&new[old.len()..], &vec![SqlValue::Null; 5]);
            } else {
                assert_eq!(&new, old, "{table}");
            }
        }
    }
    assert!(rows(&sqlite, "secret_flow_grants").is_empty());
}

#[test]
fn read_only_listing_works_at_all_three_schema_generations_without_migrating() {
    let (root, sqlite) = old_store(AGENT_SECRET_SCHEMA_VERSION - 1);
    let path = store_file(&root);
    assert_eq!(list_agent_secrets_read_only(&path).unwrap(), None);
    assert_eq!(sqlite.with_conn(read_schema_version).unwrap(), 26);

    migrate_through_for_test(&sqlite, AGENT_SECRET_SCHEMA_VERSION).unwrap();
    seed_agent_rows(&sqlite);
    let before = list_agent_secrets_read_only(&path).unwrap().unwrap();
    assert_eq!(sqlite.with_conn(read_schema_version).unwrap(), 27);
    assert_eq!(before.secrets.len(), 1);
    assert_eq!(before.secrets[0].name, "ops-key");
    assert!(before.secrets[0].flow_grants.is_empty());
    assert_eq!(
        before.secrets[0].grants,
        vec![OperatorGrantRow {
            grant_id: "agent-grant".into(),
            scope_owner: "owner".into(),
            scope_kind: "head".into(),
            scope_ref: "H".into(),
            coverage: "scope".into(),
            duration: "permanent".into(),
            expires_at_ms: None,
            last_use_ms: Some(12),
            asking_member_id: None,
        }]
    );

    EncryptedStore::migrate(&sqlite).unwrap();
    seed_flow(&sqlite, "flow-A", "ops-key", INC, Some(r#"["GET","POST"]"#));
    seed_flow(&sqlite, "flow-B", "ops-key", INC, Some(r#"["GET"]"#));
    sqlite.with_conn(|conn| conn.execute_batch(
        "INSERT INTO agent_secrets (name, kind, incarnation, state, host, path_prefix, location, origin, record_version, key_id, envelope, created_at_ms) VALUES ('login','site_login','00000000000000000000000000000002','active',NULL,NULL,NULL,'https://x.test',1,'key',x'00',10);"
    )).unwrap();
    seed_flow(
        &sqlite,
        "flow-login",
        "login",
        "00000000000000000000000000000002",
        None,
    );
    let after = list_agent_secrets_read_only(&path).unwrap().unwrap();
    assert_eq!(
        sqlite.with_conn(read_schema_version).unwrap(),
        newest_migration_version()
    );
    assert_eq!(after.phones, before.phones);
    let key = after.secrets.iter().find(|s| s.name == "ops-key").unwrap();
    assert_eq!(key.grants, before.secrets[0].grants);
    assert_eq!(key.flow_grants.len(), 2);
    let flow = &key.flow_grants[0];
    assert_eq!(flow.grant_id, "flow-A");
    assert_eq!(flow.flow_id, "daily-fetch");
    assert_eq!(flow.flow_version, 7);
    assert_eq!(flow.flow_code_hash, CODE_HASH);
    assert_eq!(flow.flow_install_id, "flow-A");
    assert_eq!(flow.methods, Some(vec!["GET".into(), "POST".into()]));
    assert_eq!(flow.granted_at_ms, 10);
    assert_eq!(flow.last_use_ms, Some(12));
    assert_eq!(flow.card_ref.as_deref(), Some("flow-card"));
    assert_eq!(key.flow_grants[1].flow_install_id, "flow-B");
    assert_eq!(
        after
            .secrets
            .iter()
            .find(|s| s.name == "login")
            .unwrap()
            .flow_grants[0]
            .methods,
        None
    );
    let mut ids: Vec<_> = list_agent_secret_grants_read_only(&path)
        .unwrap()
        .into_iter()
        .map(|(id, _, expiry)| {
            assert_eq!(expiry, 0);
            id
        })
        .collect();
    ids.sort();
    assert_eq!(ids, ["agent-grant", "flow-A", "flow-B", "flow-login"]);
    assert_eq!(
        sqlite.with_conn(read_schema_version).unwrap(),
        newest_migration_version()
    );
}

#[test]
fn migration_30_keeps_every_secret_row_and_marks_it_local() {
    let (root, sqlite) = old_store(SECRET_ASKING_MEMBER_SCHEMA_VERSION - 1);
    sqlite.with_conn(|conn| conn.execute_batch(&format!(
        "INSERT INTO agent_secrets VALUES ('ops-key','agent_api_key','{INC}','active','x.test','/repos/a','authorization_bearer',NULL,1,'key',x'1234',10);
         INSERT INTO secret_grants (grant_id,secret_name,incarnation,scope_owner,scope_kind,scope_ref,coverage,duration,expires_at_ms,granted_at_ms,envelope_sha256) VALUES ('agent-grant','ops-key','{INC}','owner','head','H','scope','permanent',0,11,'envelope-hash');
         INSERT INTO secret_pending_requests (request_id,request_kind,secret_name,incarnation,member_id,statement_bytes,statement_sha256,request_expires_at_ms,flow_id,flow_version,flow_code_hash,flow_install_id) VALUES ('flow-request','approve','ops-key','{INC}','member',x'00','hash',1000,'daily-fetch',7,'{CODE_HASH}','flow-A');"
    ))).unwrap();
    seed_flow(&sqlite, "flow-A", "ops-key", INC, Some(r#"["GET"]"#));
    let tables = [
        "secret_grants",
        "secret_flow_grants",
        "secret_pending_requests",
    ];
    let before: Vec<_> = tables.iter().map(|table| rows(&sqlite, table)).collect();
    EncryptedStore::migrate(&sqlite).unwrap();
    assert_eq!(
        sqlite.with_conn(read_schema_version).unwrap(),
        newest_migration_version()
    );
    for (table, before) in tables.into_iter().zip(before) {
        let after = rows(&sqlite, table);
        assert_eq!(after.len(), 1, "{table}");
        assert_eq!(before.len(), 1, "{table}");
        // Every old column keeps its value and the one appended column reads '' (local).
        let mut expected = before[0].clone();
        expected.push(SqlValue::Text(String::new()));
        assert_eq!(after[0], expected, "{table}");
    }
    let listing = list_agent_secrets_read_only(&store_file(&root))
        .unwrap()
        .unwrap();
    assert_eq!(listing.secrets[0].grants[0].asking_member_id, None);
    assert_eq!(listing.secrets[0].flow_grants[0].asking_member_id, None);
}

#[test]
fn flow_versions_keep_the_protocol_integer_range_in_grants_and_pending_requests() {
    let (_root, sqlite) = old_store(FLOW_SECRET_SCHEMA_VERSION);
    seed_flow(&sqlite, "flow-A", "ops-key", INC, None);
    sqlite.with_conn(|conn| {
        conn.execute("INSERT INTO secret_pending_requests (request_id,request_kind,secret_name,incarnation,member_id,statement_bytes,statement_sha256,request_expires_at_ms) VALUES ('flow-request','approve','ops-key',?1,'member',x'00','hash',1000)", [INC])?;
        for table in ["secret_flow_grants", "secret_pending_requests"] {
            for version in ["1", "9007199254740991"] {
                conn.execute_batch(&format!("UPDATE {table} SET flow_version={version}"))?;
                let stored: u64 = conn.query_row(&format!("SELECT flow_version FROM {table}"), [], |r| r.get(0))?;
                assert_eq!(stored.to_string(), version);
            }
            for invalid in ["0", "-1", "9007199254740992", "1.5", "'v1'"] {
                assert!(conn.execute_batch(&format!("UPDATE {table} SET flow_version={invalid}")).is_err(), "{table}: {invalid}");
            }
        }
        Ok(())
    }).unwrap();
}

fn delete_fixture(tag: &str) -> (crate::test_support::TestTempDir, Arc<EncryptedStore>) {
    let (root, store) = setup(tag);
    store
        .secret_put_audited(&api_key_put("ops-key", None), "offline-cli")
        .unwrap();
    store
        .secret_put_audited(&api_key_put("other-key", None), "offline-cli")
        .unwrap();
    approve(&store, NOW);
    for name in ["ops-key", "other-key"] {
        let incarnation: String = store
            .store
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT incarnation FROM agent_secrets WHERE name=?1",
                    [name],
                    |r| r.get(0),
                )
            })
            .unwrap();
        seed_flow(&store.store, name, name, &incarnation, Some(r#"["GET"]"#));
        store.store.with_conn(|conn| {
            conn.execute("INSERT INTO secret_pending_requests (request_id,request_kind,secret_name,incarnation,member_id,statement_bytes,statement_sha256,request_expires_at_ms,flow_id,flow_version,flow_code_hash,flow_install_id,methods) VALUES (?1,'approve',?1,?2,?3,x'00','hash',?4,'daily-fetch',7,?5,?1,'[\"GET\"]')", rusqlite::params![name, incarnation, MEMBER, NOW + 600_000, CODE_HASH])?;
            Ok(())
        }).unwrap();
    }
    (root, store)
}

fn signed_delete(store: &EncryptedStore) -> PhoneOperation {
    let request = phone(
        store,
        &PhoneOperation::DeleteRequest {
            name: "ops-key".into(),
        },
        NOW,
    );
    let statement = URL_SAFE_NO_PAD
        .decode(request["statement_b64url"].as_str().unwrap())
        .unwrap();
    let envelope = serde_json::to_vec(&json!({
        "v":"ck-secret-use-envelope/v1",
        "items":[{"request_id":request["request_id"],"statement_sha256":sha256_hex(&statement)}],
        "decision":"delete","duration":"none","grant_expires_at_ms":request["expires_at_ms"],
        "device_fingerprint":FP,"issued_at_ms":NOW,
    }))
    .unwrap();
    let signature: Signature = signer().sign(&envelope);
    PhoneOperation::DeleteCommit {
        envelope,
        signature: signature.to_der().as_bytes().to_vec(),
    }
}

#[test]
fn both_secret_delete_paths_remove_the_incarnations_flow_grants_and_pending_requests() {
    for phone_delete in [false, true] {
        let (root, store) = delete_fixture("flow-delete");
        if phone_delete {
            let operation = signed_delete(&store);
            let answer = phone(&store, &operation, NOW);
            assert_eq!(answer["results"][0]["outcome"], "granted");
        } else {
            assert_eq!(
                store
                    .secret_operator_delete_audited("ops-key", "offline-cli")
                    .unwrap(),
                json!({"status":"deleted"})
            );
        }
        assert_eq!(rows(&store.store, "secret_flow_grants").len(), 1);
        assert_eq!(
            rows(&store.store, "secret_flow_grants")[0][0],
            SqlValue::Text("other-key".into())
        );
        assert!(rows(&store.store, "secret_grants").is_empty());
        let pending = rows(&store.store, "secret_pending_requests");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0][0], SqlValue::Text("other-key".into()));
        let listing = list_agent_secrets_read_only(&store_file(&root))
            .unwrap()
            .unwrap();
        assert_eq!(listing.secrets.len(), 1);
        assert_eq!(listing.secrets[0].name, "other-key");
        assert_eq!(
            store
                .secret_permissions_revoke("ops-key", "provider", NOW)
                .unwrap(),
            json!({"outcome":"not_found"})
        );
        assert_eq!(store.verify_audit_chain().unwrap(), None);
    }
}

#[test]
fn both_secret_delete_paths_roll_back_if_flow_grants_cannot_be_deleted() {
    for phone_delete in [false, true] {
        let (_root, store) = delete_fixture("flow-delete-rollback");
        let operation = phone_delete.then(|| signed_delete(&store));
        store.store.with_conn(|conn| conn.execute_batch(
            "CREATE TRIGGER refuse_flow_delete BEFORE DELETE ON secret_flow_grants BEGIN SELECT RAISE(ABORT,'flow delete refused'); END;"
        )).unwrap();
        let tables = [
            "agent_secrets",
            "secret_grants",
            "secret_flow_grants",
            "secret_pending_requests",
            "audit_log",
        ];
        let before: Vec<_> = tables.iter().map(|t| rows(&store.store, t)).collect();
        if let Some(operation) = operation {
            assert_eq!(
                store.secret_phone_operation(FP, Some("pair-A"), NOW, &operation, || true, || NOW),
                Err(crate::agent_secret::SecretError::StoreError)
            );
        } else {
            assert!(store
                .secret_operator_delete_audited("ops-key", "offline-cli")
                .is_err());
        }
        for (table, before) in tables.into_iter().zip(before) {
            assert_eq!(rows(&store.store, table), before, "{table}");
        }
        assert_eq!(store.verify_audit_chain().unwrap(), None);
    }
}

#[test]
fn every_single_grant_revoke_caller_deletes_a_flow_grant_and_audits_its_identity() {
    for caller in ["operator", "provider", "phone"] {
        let (_root, store) = setup("flow-revoke");
        let stored = store
            .secret_put_audited(&api_key_put("ops-key", None), "offline-cli")
            .unwrap();
        let incarnation = stored["incarnation"].as_str().unwrap();
        approve(&store, NOW);
        seed_flow(
            &store.store,
            "flow-A",
            "ops-key",
            incarnation,
            Some(r#"["GET"]"#),
        );
        seed_flow(
            &store.store,
            "flow-B",
            "ops-key",
            incarnation,
            Some(r#"["GET"]"#),
        );
        let revoke = || match caller {
            "operator" => store
                .secret_operator_revoke_audited("flow-A", "offline-cli")
                .unwrap(),
            "provider" => store
                .secret_permissions_revoke("flow-A", "provider", NOW)
                .unwrap(),
            _ => phone(
                &store,
                &PhoneOperation::Revoke {
                    grant_id: "flow-A".into(),
                },
                NOW,
            ),
        };
        assert_eq!(revoke(), json!({"outcome":"revoked"}));
        assert_eq!(revoke(), json!({"outcome":"not_found"}));
        let remaining = rows(&store.store, "secret_flow_grants");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0][0], SqlValue::Text("flow-B".into()));
        assert_eq!(rows(&store.store, "secret_grants").len(), 1);

        // Encode lengths here rather than using the audit helper, so a missing field
        // or a framing change in the implementation cannot change the expected hash.
        let mut payload = Vec::new();
        for field in ["flow-A", incarnation, "daily-fetch", "7"] {
            payload.extend_from_slice(&(field.len() as u64).to_le_bytes());
            payload.extend_from_slice(field.as_bytes());
        }
        let expected_actor = match caller {
            "operator" => "offline-cli".to_owned(),
            "provider" => "provider".to_owned(),
            _ => format!("fed-phone:{FP}"),
        };
        let audits = store.store.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT credential_id,actor,payload_hash FROM audit_log WHERE op='secret_grant_revoke'")?;
            let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        }).unwrap();
        assert_eq!(
            audits,
            vec![(
                "secret|ops-key".into(),
                expected_actor,
                sha256_hex(&payload)
            )]
        );
        assert_eq!(store.verify_audit_chain().unwrap(), None);
    }
}

#[test]
fn single_flow_grant_revoke_rolls_back_when_auditing_fails() {
    let (_root, store) = setup("flow-revoke-rollback");
    let stored = store
        .secret_put_audited(&api_key_put("ops-key", None), "offline-cli")
        .unwrap();
    seed_flow(
        &store.store,
        "flow-A",
        "ops-key",
        stored["incarnation"].as_str().unwrap(),
        Some(r#"["GET"]"#),
    );
    store.store.with_conn(|conn| conn.execute_batch(
        "CREATE TRIGGER refuse_flow_audit BEFORE INSERT ON audit_log WHEN NEW.op='secret_grant_revoke' BEGIN SELECT RAISE(ABORT,'audit refused'); END;"
    )).unwrap();
    let before = rows(&store.store, "secret_flow_grants");
    let audit_before = rows(&store.store, "audit_log");
    assert_eq!(
        store.secret_permissions_revoke("flow-A", "provider", NOW),
        Err(crate::agent_secret::SecretError::StoreError)
    );
    assert_eq!(rows(&store.store, "secret_flow_grants"), before);
    assert_eq!(rows(&store.store, "audit_log"), audit_before);
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}
