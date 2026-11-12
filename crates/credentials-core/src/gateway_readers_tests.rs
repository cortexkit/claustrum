use super::gateway_create_tests::settings;
use super::taxonomy_tests::{api_record, rig, sqlite};
use super::*;
use crate::admin_ops::{AdminAuditOp, AdminOpBody, ADMIN_OP_SCHEMA_V2};
use crate::{GatewayHeader, ListAuthMethod, ModelVendor};

const ID: &str = "apikey:moonshotai-gw-acme:eu";
const PROVIDER: &str = "moonshotai-gw-acme";

fn create_gateway(store: &EncryptedStore) {
    let mut settings = settings();
    settings.base_url = "http://[::1]:4000/v1".into();
    store
        .gateway_create_audited(
            ID,
            &api_record(),
            &settings,
            &[PROVIDER.into()],
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
}

fn grant(store: &EncryptedStore, principal: &str, selector: &str, operation: GrantOperation) {
    store
        .create_read_grant_audited(
            "reserved",
            principal,
            SelectorKind::Category,
            selector,
            operation,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
}

fn schema(store: &EncryptedStore) -> (u32, Vec<(String, String, Option<String>)>) {
    store
        .with_raw_conn(|conn| {
            let mut stmt =
                conn.prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")?;
            let entries = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok((read_schema_version(conn)?, entries))
        })
        .unwrap()
}

#[test]
fn gateway_readers_use_settings_not_category_or_service_spelling_for_auth_method() {
    let (root, store) = rig("gateway-readers-method", 224);
    create_gateway(&store);
    let ordinary = "apikey:anthropic-gw-legacy";
    store.create(ordinary, &api_record()).unwrap();
    store
        .set_categories_audited(
            ordinary,
            SetCategoryMode::Set,
            &["llm-gateway".into()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
    for operation in [GrantOperation::List, GrantOperation::Read] {
        grant(&store, "consumer", "llm-gateway", operation);
    }
    let snapshot = store.list_scoped_snapshot("reserved", "consumer").unwrap();
    assert_eq!(snapshot.rows.len(), 2);
    let gateway = snapshot.rows.iter().find(|row| row.id == ID).unwrap();
    assert_eq!(
        gateway.auth_method.map(ListAuthMethod::as_str),
        Some("gateway")
    );
    assert_eq!(gateway.provider_ids, [PROVIDER]);
    let ordinary_row = snapshot.rows.iter().find(|row| row.id == ordinary).unwrap();
    assert_eq!(ordinary_row.categories, ["llm-gateway"]);
    assert_eq!(ordinary_row.auth_method, Some(ListAuthMethod::Apikey));
    assert_eq!(store.meta(ordinary).unwrap().gateway, None);
    let methods =
        auth_methods_read_only(&root.join("store.db"), &MasterKey::from_bytes([224; 32])).unwrap();
    assert_eq!(methods[ID], Some(ListAuthMethod::Gateway));
    assert_eq!(methods[ordinary], Some(ListAuthMethod::Apikey));
    grant(
        &store,
        "provider-only",
        "llm-provider",
        GrantOperation::List,
    );
    assert!(store
        .list_scoped_snapshot("reserved", "provider-only")
        .unwrap()
        .rows
        .is_empty());
}

#[test]
fn gateway_readers_preserve_sign_and_open_only_method_omission_but_identify_quarantined_gateways() {
    let (root, store) = rig("gateway-readers-disclosure", 225);
    create_gateway(&store);
    for (principal, operation) in [
        ("signer", GrantOperation::Sign),
        ("opener", GrantOperation::Open),
    ] {
        grant(&store, principal, "llm-gateway", operation);
        let snapshot = store.list_scoped_snapshot("reserved", principal).unwrap();
        assert_eq!(snapshot.rows.len(), 1);
        assert_eq!(snapshot.rows[0].auth_method, None);
        assert_eq!(snapshot.rows[0].identity, None);
    }
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE credentials SET state = 'corrupt', envelope = x'00' WHERE credential_id = ?1",
                [ID],
            )
        })
        .unwrap();
    grant(&store, "lister", "llm-gateway", GrantOperation::List);
    let snapshot = store.list_scoped_snapshot("reserved", "lister").unwrap();
    assert_eq!(snapshot.rows.len(), 1);
    assert_eq!(snapshot.rows[0].state, RecordState::Corrupt);
    assert_eq!(snapshot.rows[0].auth_method, Some(ListAuthMethod::Gateway));
    assert_eq!(snapshot.rows[0].identity, None);
    let methods =
        auth_methods_read_only(&root.join("store.db"), &MasterKey::from_bytes([225; 32])).unwrap();
    assert_eq!(methods[ID], Some(ListAuthMethod::Gateway));
}

#[test]
fn gateway_readers_below_migration_keep_existing_output_and_never_change_schema() {
    let (root, sqlite) = sqlite("gateway-readers-behind", 226);
    migrate_through_for_test(&sqlite, GATEWAY_SETTINGS_SCHEMA_VERSION - 1).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([226; 32])).unwrap();
    store.create(ID, &api_record()).unwrap();
    store
        .set_categories_audited(
            ID,
            SetCategoryMode::Set,
            &["llm-gateway".into()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
    grant(&store, "consumer", "llm-gateway", GrantOperation::List);
    let before = schema(&store);
    assert_eq!(before.0, GATEWAY_SETTINGS_SCHEMA_VERSION - 1);
    assert!(!before
        .1
        .iter()
        .any(|(_, name, _)| name == "credential_gateway_settings"));
    let expected = vec![(
        ID.into(),
        RecordMeta {
            incarnation: Some(store.credential_incarnation(ID).unwrap()),
            plan_tier_observed_at_ms: None,
            plan_tier_since_ms: None,
            record_version: 1,
            key_id_hex: store.key_id().to_hex(),
            state: RecordState::Active,
            stale_pending: false,
            categories: vec!["llm-gateway".into()],
            created_by: Some("operator".into()),
            provider_ids: vec![],
            plan_tier: None,
            gateway: None,
        },
    )];
    assert_eq!(store.gateway_settings(ID).unwrap(), None);
    assert_eq!(store.meta(ID).unwrap(), expected[0].1);
    assert_eq!(store.list_meta().unwrap(), expected);
    assert_eq!(
        list_meta_read_only(&root.join("store.db")).unwrap(),
        expected
    );
    assert_eq!(
        list_meta_read_only_with_schema(&root.join("store.db")).unwrap(),
        (expected, GATEWAY_SETTINGS_SCHEMA_VERSION - 1)
    );
    let methods =
        auth_methods_read_only(&root.join("store.db"), &MasterKey::from_bytes([226; 32])).unwrap();
    assert_eq!(
        methods.into_iter().collect::<Vec<_>>(),
        [(ID.into(), Some(ListAuthMethod::Apikey))]
    );
    assert_eq!(
        count_refresh_intents_read_only(&root.join("store.db")).unwrap(),
        0
    );
    let snapshot = store.list_scoped_snapshot("reserved", "consumer").unwrap();
    assert_eq!(snapshot.rows.len(), 1);
    assert_eq!(snapshot.rows[0].auth_method, Some(ListAuthMethod::Apikey));
    assert_eq!(schema(&store), before);
}

#[test]
fn gateway_readers_expose_exact_settings_incarnation_host_and_derived_vendor() {
    let (root, store) = rig("gateway-readers-settings", 221);
    create_gateway(&store);
    let mut expected_settings = settings();
    expected_settings.base_url = "http://[::1]:4000/v1".into();
    let expected = StoredGatewaySettings {
        incarnation: store.credential_incarnation(ID).unwrap(),
        settings: expected_settings,
        host: "[::1]".into(),
        vendor: ModelVendor::Moonshot,
    };
    assert_eq!(store.gateway_settings(ID).unwrap(), Some(expected.clone()));
    assert_eq!(store.meta(ID).unwrap().gateway, Some(expected.clone()));
    let live = store.list_meta().unwrap();
    assert_eq!(live[0].1.gateway, Some(expected.clone()));
    let (readonly, version) = list_meta_read_only_with_schema(&root.join("store.db")).unwrap();
    assert_eq!(version, newest_migration_version());
    assert_eq!(readonly, live);
    assert_eq!(list_meta_read_only(&root.join("store.db")).unwrap(), live);
    assert_eq!(store.gateway_settings("apikey:missing").unwrap(), None);
}

#[test]
fn gateway_readers_return_the_settings_rows_incarnation_without_rebinding_it() {
    let (_root, store) = rig("gateway-readers-incarnation", 222);
    create_gateway(&store);
    let original = store.gateway_settings(ID).unwrap().unwrap();
    store
        .remove_audited(ID, AuditCtx::admin(AuditOp::Remove))
        .unwrap();
    assert_eq!(store.gateway_settings(ID).unwrap(), None);
    create_gateway(&store);
    let current = store.credential_incarnation(ID).unwrap();
    assert_ne!(current, original.incarnation);
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE credential_gateway_settings SET incarnation = ?1 WHERE credential_id = ?2",
                rusqlite::params![original.incarnation, ID],
            )
        })
        .unwrap();
    let stored = store.gateway_settings(ID).unwrap().unwrap();
    assert_eq!(stored.incarnation, original.incarnation);
    assert_ne!(stored.incarnation, current);
    let meta = store.meta(ID).unwrap();
    assert_eq!(meta.incarnation.as_deref(), Some(current.as_str()));
    assert_eq!(meta.gateway, Some(stored));
}

#[test]
fn gateway_header_debug_redacts_values_in_settings_admin_ops_and_metadata() {
    let mut settings = settings();
    let header_value = "test-only-header-value-not-for-debug";
    settings.headers = vec![GatewayHeader {
        name: "x-routing".into(),
        value: header_value.into(),
    }];
    let operation = AdminOpBody::GatewayCreate {
        v: ADMIN_OP_SCHEMA_V2,
        id: ID.into(),
        record: Box::new(api_record()),
        audit_op: AdminAuditOp::Put,
        base_url: settings.base_url.clone(),
        auth_header: settings.auth.header.clone(),
        auth_scheme: settings.auth.scheme.clone(),
        headers: settings.headers.clone(),
        provider_ids: vec![PROVIDER.into()],
    };
    let (_root, store) = rig("gateway-readers-debug", 223);
    store
        .gateway_create_audited(
            ID,
            &api_record(),
            &settings,
            &[PROVIDER.into()],
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
    for debug in [
        format!("{settings:?}"),
        format!("{operation:?}"),
        format!("{:?}", store.meta(ID).unwrap()),
    ] {
        assert!(debug.contains("x-routing"));
        assert!(
            !debug.contains(header_value),
            "header value leaked through Debug"
        );
    }
    assert!(format!("{settings:?}").contains("value: \"<redacted>\""));
}
