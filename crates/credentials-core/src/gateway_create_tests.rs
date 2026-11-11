use super::taxonomy_tests::{api_record, rig, sqlite};
use super::*;
use crate::admin_ops::{apply, AdminAuditOp, AdminOpBody, ADMIN_OP_SCHEMA_V2};
use crate::gateway::{GatewayAuth, GatewayHeader, GatewaySettings, GatewaySettingsRule};

const ID: &str = "apikey:anthropic-gw-acme:eu";
const PROVIDER: &str = "anthropic-gw-acme";

fn settings() -> GatewaySettings {
    GatewaySettings {
        base_url: "http://localhost:4000/v1".into(),
        auth: GatewayAuth {
            header: "authorization".into(),
            scheme: "bearer".into(),
        },
        headers: vec![
            GatewayHeader {
                name: "x-a".into(),
                value: "a\"b\\c".into(),
            },
            GatewayHeader {
                name: "x-z".into(),
                value: "2".into(),
            },
        ],
    }
}

fn op(
    id: &str,
    record: VaultRecord,
    settings: GatewaySettings,
    provider_ids: Vec<String>,
) -> AdminOpBody {
    AdminOpBody::GatewayCreate {
        v: ADMIN_OP_SCHEMA_V2,
        id: id.into(),
        record: Box::new(record),
        audit_op: AdminAuditOp::Login,
        base_url: settings.base_url,
        auth_header: settings.auth.header,
        auth_scheme: settings.auth.scheme,
        headers: settings.headers,
        provider_ids,
    }
}

fn valid_op() -> AdminOpBody {
    op(ID, api_record(), settings(), vec![PROVIDER.into()])
}

fn rows(store: &EncryptedStore, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
    store
        .with_raw_conn(|conn| {
            let mut statement = conn.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))?;
            let columns = statement.column_count();
            let result = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| row.get(column))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })?
                .collect();
            result
        })
        .unwrap()
}

fn state(store: &EncryptedStore) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    [
        "credentials",
        "credential_gateway_settings",
        "credential_categories",
        "credential_provider_ids",
        "audit_log",
        "refresh_intent",
        "grants_generation",
    ]
    .into_iter()
    .map(|table| rows(store, table))
    .collect()
}

fn assert_refused(store: &EncryptedStore, op: AdminOpBody, rule: GatewaySettingsRule) {
    let before = state(store);
    let error = apply(store, op, "operator:test").unwrap_err();
    assert_eq!(error.wire_code(), Some("invalid_gateway_settings"));
    assert!(
        error.to_string().contains(&format!("rule={rule}")),
        "{error}"
    );
    assert_eq!(
        state(store),
        before,
        "refused creation changed durable state"
    );
}

#[test]
fn gateway_create_wire_discriminator_fields_round_trip_and_lock_are_pinned() {
    let op = valid_op();
    let bytes = op.to_bytes().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["op"], "admin.gateway_create");
    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        [
            "audit_op",
            "auth_header",
            "auth_scheme",
            "base_url",
            "headers",
            "id",
            "op",
            "provider_ids",
            "record",
            "v"
        ]
    );
    assert_eq!(
        value["headers"][0],
        serde_json::json!({"name":"x-a", "value":"a\"b\\c"})
    );
    let decoded: AdminOpBody = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded.to_bytes().unwrap(), bytes);
    assert_eq!(decoded.op_name(), "admin.gateway_create");
    assert_eq!(decoded.lock_id(), Some(ID));
    assert_eq!(decoded.required_schema_version(), ADMIN_OP_SCHEMA_V2);
    assert!(decoded.has_valid_schema_version());
    assert!(!decoded.requires_daemon());
    assert!(!format!("{decoded:?}").contains("a\"b\\c"));
}

#[test]
fn gateway_create_commits_version_one_fixed_metadata_generation_intent_and_two_audits() {
    let (_root, store) = rig("gateway-create", 201);
    // Legacy registry defaults must not turn a gateway into an llm-provider key.
    store.with_raw_conn(|conn| conn.execute(
        "INSERT INTO registered_providers (service, categories_json, provider_ids_json, created_at_ms) \
         VALUES (?1, '[\"llm-provider\"]', '[\"anthropic\"]', 0)",
        [PROVIDER],
    )).unwrap();
    store.open_intent(ID, 7, "old-refresh-hash").unwrap();
    let generation = store.grants_generation().unwrap();
    let mut record = api_record();
    record.record_version = 99;
    assert_eq!(
        apply(
            &store,
            op(ID, record, settings(), vec![PROVIDER.into()]),
            "operator:test"
        )
        .unwrap(),
        serde_json::json!({"stored":true})
    );
    let record = store.get(ID).unwrap();
    assert_eq!(record.record_version, 1);
    assert_eq!(record.kind, CredentialKind::ApiKey);
    assert_eq!(record.payload.expose(), b"key");
    assert_eq!(store.categories(ID).unwrap(), ["llm-gateway"]);
    assert_eq!(store.provider_ids(ID).unwrap(), [PROVIDER]);
    assert_eq!(store.grants_generation().unwrap(), generation + 1);
    assert!(store.read_intent(ID).unwrap().is_none());
    let stored = rows(&store, "credential_gateway_settings");
    use rusqlite::types::Value::Text;
    assert_eq!(
        stored,
        vec![vec![
            Text(ID.into()),
            Text(store.credential_incarnation(ID).unwrap()),
            Text("http://localhost:4000/v1".into()),
            Text("authorization".into()),
            Text("bearer".into()),
            Text(serde_json::to_string(&settings().headers).unwrap()),
        ]]
    );
    let audit = store.read_audit(None).unwrap();
    assert_eq!(audit.len(), 2);
    assert_eq!(audit[0].op, "login");
    assert_eq!(audit[0].credential_id.as_deref(), Some(ID));
    assert_eq!(
        audit[0].payload_hash,
        Some(hex32(&audit::payload_fingerprint(&store.audit_key, b"key")))
    );
    assert_eq!(audit[0].actor, "operator:test");
    assert_eq!(audit[1].op, "gateway_create");
    // Hash fixed JSON bytes rather than reusing the settings serializer under test.
    let digest = sha256_hex_of_bytes(br#"{"base_url":"http://localhost:4000/v1","auth":{"header":"authorization","scheme":"bearer"},"headers":{"x-a":"a\"b\\c","x-z":"2"}}"#);
    assert_eq!(
        audit[1].credential_id,
        Some(format!("gateway:{ID}|{digest}"))
    );
    assert_eq!(audit[1].payload_hash, None);
    assert_eq!(audit[1].actor, "operator:test");
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn gateway_create_credential_id_refusals_leave_every_creation_table_unchanged() {
    let (_root, store) = rig("gateway-id", 202);
    for id in [
        "anthropic-gw-acme",
        "oauth:anthropic-gw-acme",
        "apikey:anthropic-gw-acme:",
        "apikey:anthropic-gw-acme:eu:extra",
        "apikey:anthropic-gw-acme:bad|label",
        "apikey:anthropic-gw-acme:bad label",
    ] {
        assert_refused(
            &store,
            op(id, api_record(), settings(), vec![PROVIDER.into()]),
            GatewaySettingsRule::CredentialId,
        );
    }
    assert!(state(&store)[..5].iter().all(Vec::is_empty));
}

#[test]
fn gateway_create_kind_refusals_cover_non_api_keys_and_refresh_adapters() {
    let (_root, store) = rig("gateway-kind", 203);
    for kind in [
        CredentialKind::Dsn,
        CredentialKind::Opaque,
        CredentialKind::Oauth,
    ] {
        let mut record = api_record();
        record.kind = kind;
        assert_refused(
            &store,
            op(ID, record, settings(), vec![PROVIDER.into()]),
            GatewaySettingsRule::Kind,
        );
    }
    let mut record = api_record();
    record.refresh_adapter = Some("anthropic".into());
    assert_refused(
        &store,
        op(ID, record, settings(), vec![PROVIDER.into()]),
        GatewaySettingsRule::Kind,
    );
    assert!(state(&store)[..5].iter().all(Vec::is_empty));
}

#[test]
fn gateway_create_provider_id_refusals_cover_count_shape_mapping_slug_and_service_equality() {
    let (_root, store) = rig("gateway-provider", 204);
    for providers in [
        vec![],
        vec![PROVIDER, PROVIDER],
        vec!["anthropic"],
        vec!["openrouter-gw-acme"],
        vec!["anthropic-gw-1bad"],
        vec!["anthropic-gw-other"],
        vec!["Anthropic-gw-acme"],
    ] {
        assert_refused(
            &store,
            op(
                ID,
                api_record(),
                settings(),
                providers.into_iter().map(str::to_owned).collect(),
            ),
            GatewaySettingsRule::ProviderId,
        );
    }
    assert!(state(&store)[..5].iter().all(Vec::is_empty));
}

#[test]
fn gateway_create_direct_wire_op_refuses_misordered_and_repeated_header_names() {
    let (_root, store) = rig("gateway-header-order", 205);
    for names in [["x-z", "x-a"], ["x-a", "x-a"]] {
        let mut value = serde_json::to_value(valid_op()).unwrap();
        value["headers"] = serde_json::json!([
            {"name": names[0], "value": "first"}, {"name": names[1], "value": "second"}
        ]);
        let op = serde_json::from_value(value).unwrap();
        assert_refused(&store, op, GatewaySettingsRule::HeaderName);
    }
    assert!(state(&store)[..5].iter().all(Vec::is_empty));
}

#[test]
fn gateway_create_conflicts_with_plain_and_gateway_records_without_changing_any_state() {
    for plain in [true, false] {
        let (_root, store) = rig("gateway-conflict", 206);
        if plain {
            store
                .create_audited(ID, &api_record(), AuditCtx::admin(AuditOp::Put))
                .unwrap();
        } else {
            apply(&store, valid_op(), "operator:test").unwrap();
        }
        store.open_intent(ID, 1, "retained-intent").unwrap();
        let before = state(&store);
        assert!(matches!(
            apply(&store, valid_op(), "operator:test"),
            Err(StoreOpError::AlreadyExists)
        ));
        assert_eq!(state(&store), before);
    }
}

#[test]
fn gateway_create_keeps_deposit_identity_and_sealing_checks() {
    let (_root, store) = rig("gateway-record-checks", 207);
    for payload in [Vec::new(), CUSTODY_TOMBSTONE_PREFIX.as_bytes().to_vec()] {
        let record = VaultRecord::new_static(CredentialKind::ApiKey, "test", payload, None);
        let before = state(&store);
        assert!(matches!(
            apply(
                &store,
                op(ID, record, settings(), vec![PROVIDER.into()]),
                "operator:test"
            ),
            Err(StoreOpError::Encode(_))
        ));
        assert_eq!(state(&store), before);
    }
    let mut record = api_record();
    record.identity.account_id = Some("bad\nidentity".into());
    let before = state(&store);
    assert!(apply(
        &store,
        op(ID, record, settings(), vec![PROVIDER.into()]),
        "operator:test"
    )
    .is_err());
    assert_eq!(state(&store), before);
}

#[test]
fn gateway_create_second_audit_failure_rolls_back_record_metadata_generation_and_intent() {
    let (_root, store) = rig("gateway-rollback", 208);
    store.open_intent(ID, 7, "retained-intent").unwrap();
    store
        .with_raw_conn(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER refuse_gateway_audit BEFORE INSERT ON audit_log \
         WHEN NEW.op = 'gateway_create' BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;",
            )
        })
        .unwrap();
    let before = state(&store);
    assert!(apply(&store, valid_op(), "operator:test").is_err());
    assert_eq!(state(&store), before);
    assert!(state(&store)[..5].iter().all(Vec::is_empty));
}

#[test]
fn gateway_create_remove_cleans_settings_even_without_foreign_keys_and_reuse_gets_new_incarnation()
{
    let (_root, store) = rig("gateway-remove", 209);
    apply(&store, valid_op(), "operator:test").unwrap();
    let original = store.credential_incarnation(ID).unwrap();
    store
        .with_raw_conn(|conn| conn.execute_batch("PRAGMA foreign_keys = OFF;"))
        .unwrap();
    store
        .remove_audited(ID, AuditCtx::admin(AuditOp::Remove))
        .unwrap();
    assert!(rows(&store, "credential_gateway_settings").is_empty());
    assert!(rows(&store, "credential_categories").is_empty());
    assert!(rows(&store, "credential_provider_ids").is_empty());
    store
        .create_audited(ID, &api_record(), AuditCtx::admin(AuditOp::Put))
        .unwrap();
    assert_ne!(store.credential_incarnation(ID).unwrap(), original);
    assert!(rows(&store, "credential_gateway_settings").is_empty());
    store
        .remove_audited(ID, AuditCtx::admin(AuditOp::Remove))
        .unwrap();
    let mut replacement = settings();
    replacement.base_url = "http://localhost:5000".into();
    replacement.headers.clear();
    apply(
        &store,
        op(ID, api_record(), replacement, vec![PROVIDER.into()]),
        "operator:test",
    )
    .unwrap();
    let incarnation = store.credential_incarnation(ID).unwrap();
    assert_ne!(incarnation, original);
    let stored = rows(&store, "credential_gateway_settings");
    use rusqlite::types::Value::Text;
    assert_eq!(stored[0][1], Text(incarnation));
    assert_eq!(stored[0][2], Text("http://localhost:5000".into()));
    assert_eq!(stored[0][5], Text("[]".into()));
}

#[test]
fn gateway_migration_adds_only_settings_and_leaves_old_readers_and_rows_unchanged() {
    assert_eq!(GATEWAY_SETTINGS_SCHEMA_VERSION, 41);
    let (root, sqlite) = sqlite("gateway-migration", 210);
    migrate_through_for_test(&sqlite, GATEWAY_SETTINGS_SCHEMA_VERSION - 1).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([210; 32])).unwrap();
    store
        .create_audited(ID, &api_record(), AuditCtx::admin(AuditOp::Put))
        .unwrap();
    let table_names = || {
        store
            .with_raw_conn(|conn| {
                let mut stmt = conn
                    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")?;
                let result = stmt
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>();
                result
            })
            .unwrap()
    };
    let before_tables = table_names();
    let before_rows: Vec<_> = before_tables
        .iter()
        .filter(|name| name.as_str() != "cortexkit_schema_version")
        .map(|name| (name.clone(), rows(&store, name)))
        .collect();
    let (_, version) = list_meta_read_only_with_schema(&root.join("store.db")).unwrap();
    assert_eq!(version, 40);
    count_refresh_intents_read_only(&root.join("store.db")).unwrap();
    assert_eq!(table_names(), before_tables);
    assert_eq!(store.with_raw_conn(read_schema_version).unwrap(), 40);
    migrate_through_for_test(&store.store, GATEWAY_SETTINGS_SCHEMA_VERSION).unwrap();
    let added: Vec<_> = table_names()
        .into_iter()
        .filter(|name| !before_tables.contains(name))
        .collect();
    assert_eq!(added, ["credential_gateway_settings"]);
    assert_eq!(store.with_raw_conn(read_schema_version).unwrap(), 41);
    assert!(rows(&store, "credential_gateway_settings").is_empty());
    for (table, before) in before_rows {
        assert_eq!(rows(&store, &table), before, "migration changed {table}");
    }
    apply(&store, valid_op(), "operator:test").unwrap_err();
    store
        .remove_audited(ID, AuditCtx::admin(AuditOp::Remove))
        .unwrap();
    apply(&store, valid_op(), "operator:test").unwrap();
    let before = rows(&store, "credential_gateway_settings");
    let error = store.with_raw_conn(|conn| {
        conn.execute(
            "INSERT INTO credential_gateway_settings SELECT * FROM credential_gateway_settings",
            [],
        )
    });
    assert!(
        error.is_err(),
        "the table must have at most one settings row per credential"
    );
    assert_eq!(rows(&store, "credential_gateway_settings"), before);
}
