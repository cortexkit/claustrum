use super::gateway_create_tests::settings;
use super::taxonomy_tests::{api_record, rig};
use super::*;
use crate::secret::SecretBytes;

const ID: &str = "apikey:anthropic-gw-acme:eu";
const PROVIDER: &str = "anthropic-gw-acme";

fn gateway(store: &EncryptedStore) {
    store
        .gateway_create_audited(
            ID,
            &api_record(),
            &settings(),
            &[PROVIDER.into()],
            AuditCtx::admin(AuditOp::Login),
        )
        .unwrap();
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
        "registered_providers",
    ]
    .into_iter()
    .map(|table| rows(store, table))
    .collect()
}

fn assert_refused<T: std::fmt::Debug>(
    store: &EncryptedStore,
    code: &str,
    rule: &str,
    change: impl FnOnce() -> Result<T, StoreOpError>,
) {
    let before = state(store);
    let error = change().unwrap_err();
    assert_eq!(error.wire_code(), Some(code), "{error}");
    assert!(
        error.to_string().contains(&format!("rule={rule}")),
        "{error}"
    );
    assert_eq!(state(store), before);
}

fn invalid_records() -> Vec<VaultRecord> {
    let mut dsn = api_record();
    dsn.kind = CredentialKind::Dsn;
    let mut refreshable = api_record();
    refreshable.refresh_adapter = Some("test-adapter".into());
    vec![dsn, refreshable]
}

#[test]
fn gateway_fixed_unconditional_overwrite_refuses_kind_and_refresh_adapter_atomically() {
    let (_root, store) = rig("gateway-fixed-unconditional", 221);
    gateway(&store);
    store.open_intent(ID, 1, "pending-refresh").unwrap();
    for record in invalid_records() {
        assert_refused(&store, "gateway_fixed", "kind", || {
            store.overwrite_unconditional_audited(ID, &record, AuditCtx::admin(AuditOp::Login))
        });
    }
}

#[test]
fn gateway_fixed_cas_overwrite_refuses_kind_and_refresh_adapter_atomically() {
    let (_root, store) = rig("gateway-fixed-cas", 222);
    gateway(&store);
    store.open_intent(ID, 1, "pending-refresh").unwrap();
    let hash = payload_hash(store.get(ID).unwrap().payload.expose());
    for record in invalid_records() {
        assert_refused(&store, "gateway_fixed", "kind", || {
            store.overwrite_cas_audited(ID, &record, &hash, AuditCtx::admin(AuditOp::Login))
        });
    }
}

#[test]
fn gateway_fixed_identity_policy_overwrite_refuses_kind_and_refresh_adapter_atomically() {
    let (_root, store) = rig("gateway-fixed-identity-policy", 223);
    gateway(&store);
    store.open_intent(ID, 1, "pending-refresh").unwrap();
    for preserve in [false, true] {
        for record in invalid_records() {
            assert_refused(&store, "gateway_fixed", "kind", || {
                store.overwrite_unconditional_with_identity_policy_audited(
                    ID,
                    &record,
                    preserve,
                    AuditCtx::admin(AuditOp::Login),
                )
            });
        }
    }
}

#[test]
fn gateway_fixed_key_only_replacements_keep_settings_categories_provider_and_incarnation() {
    let (_root, store) = rig("gateway-fixed-key-only", 224);
    gateway(&store);
    let settings = rows(&store, "credential_gateway_settings");
    let categories = rows(&store, "credential_categories");
    let providers = rows(&store, "credential_provider_ids");
    let incarnation = store.credential_incarnation(ID).unwrap();
    for path in 0..3 {
        let current = store.get(ID).unwrap();
        let mut replacement = api_record();
        replacement.payload = SecretBytes::new(format!("rotated-{path}").into_bytes());
        let ctx = AuditCtx::admin(AuditOp::Put);
        match path {
            0 => store.overwrite_unconditional_audited(ID, &replacement, ctx),
            1 => store.overwrite_cas_audited(
                ID,
                &replacement,
                &payload_hash(current.payload.expose()),
                ctx,
            ),
            _ => store.overwrite_unconditional_with_identity_policy_audited(
                ID,
                &replacement,
                false,
                ctx,
            ),
        }
        .unwrap();
        let updated = store.get(ID).unwrap();
        assert_eq!(updated.payload.expose(), replacement.payload.expose());
        assert_eq!(updated.record_version, current.record_version + 1);
        assert_eq!(store.credential_incarnation(ID).unwrap(), incarnation);
        assert_eq!(rows(&store, "credential_gateway_settings"), settings);
        assert_eq!(rows(&store, "credential_categories"), categories);
        assert_eq!(rows(&store, "credential_provider_ids"), providers);
        assert_eq!(store.read_audit(None).unwrap().len(), 3 + path);
    }
}

fn ids(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

#[test]
fn gateway_fixed_categories_refuse_changes_and_accept_silent_noops_in_every_mode() {
    let (_root, store) = rig("gateway-fixed-categories", 225);
    gateway(&store);
    for (mode, request) in [
        (SetCategoryMode::Set, ids(&[])),
        (SetCategoryMode::Set, ids(&["llm-provider"])),
        (SetCategoryMode::Add, ids(&["llm-provider"])),
        (SetCategoryMode::Remove, ids(&["llm-gateway"])),
    ] {
        assert_refused(&store, "gateway_fixed", "category", || {
            store.set_categories_audited(ID, mode, &request, AuditCtx::admin(AuditOp::SetCategory))
        });
    }
    for (mode, request) in [
        (SetCategoryMode::Set, ids(&["llm-gateway", "llm-gateway"])),
        (SetCategoryMode::Add, ids(&["llm-gateway"])),
        (SetCategoryMode::Add, ids(&[])),
        (SetCategoryMode::Remove, ids(&["llm-provider"])),
        (SetCategoryMode::Remove, ids(&[])),
    ] {
        let before = state(&store);
        assert!(!store
            .set_categories_audited(ID, mode, &request, AuditCtx::admin(AuditOp::SetCategory))
            .unwrap());
        assert_eq!(state(&store), before);
    }
}

#[test]
fn gateway_fixed_reclassification_skips_settings_rows_with_or_without_force() {
    let (_root, store) = rig("gateway-fixed-reclassify", 226);
    gateway(&store);
    for force in [false, true] {
        let before = state(&store);
        assert_eq!(
            store
                .reclassify_audited(force, AuditCtx::admin(AuditOp::CategoryMigrate))
                .unwrap(),
            0
        );
        assert_eq!(state(&store), before);
    }

    // A catalog-matching fixture makes the settings-row skip observable: ordinary
    // gateway ids have no catalog defaults, which already makes reclassification a no-op.
    let catalog_id = "apikey:anthropic";
    store.create(catalog_id, &api_record()).unwrap();
    assert!(!crate::catalog::category_defaults(catalog_id).is_empty());
    store.with_raw_conn(|conn| conn.execute(
        "INSERT INTO credential_gateway_settings \
         SELECT c.credential_id, c.incarnation, g.base_url, g.auth_header, g.auth_scheme, g.headers_json \
         FROM credentials c CROSS JOIN credential_gateway_settings g \
         WHERE c.credential_id = ?1 AND g.credential_id = ?2",
        rusqlite::params![catalog_id, ID],
    )).unwrap();
    for force in [false, true] {
        store.with_raw_conn(|conn| {
            conn.execute("DELETE FROM credential_categories WHERE credential_id = ?1", [catalog_id])?;
            if force {
                conn.execute(
                    "INSERT INTO credential_categories (credential_id, category) VALUES (?1, 'llm-gateway')",
                    [catalog_id],
                )?;
            }
            Ok(())
        }).unwrap();
        let before = state(&store);
        assert_eq!(
            store
                .reclassify_audited(force, AuditCtx::admin(AuditOp::CategoryMigrate))
                .unwrap(),
            0
        );
        assert_eq!(state(&store), before);
    }
}

#[test]
fn gateway_fixed_providers_refuse_changes_and_accept_silent_noops_in_every_mode() {
    let (_root, store) = rig("gateway-fixed-providers", 227);
    gateway(&store);
    for (mode, request) in [
        (SetProvidersMode::Set, ids(&[])),
        (SetProvidersMode::Set, ids(&["openai"])),
        (SetProvidersMode::Add, ids(&["openai"])),
        (SetProvidersMode::Remove, ids(&[PROVIDER])),
    ] {
        assert_refused(&store, "gateway_fixed", "provider_id", || {
            store.set_providers_audited(ID, mode, &request, AuditCtx::admin(AuditOp::SetProviders))
        });
    }
    for (mode, request) in [
        (SetProvidersMode::Set, ids(&[PROVIDER])),
        (SetProvidersMode::Add, ids(&[PROVIDER])),
        (SetProvidersMode::Add, ids(&[])),
        (SetProvidersMode::Remove, ids(&["openai"])),
        (SetProvidersMode::Remove, ids(&[])),
    ] {
        let before = state(&store);
        assert_eq!(
            store
                .set_providers_audited(ID, mode, &request, AuditCtx::admin(AuditOp::SetProviders))
                .unwrap(),
            [PROVIDER]
        );
        assert_eq!(state(&store), before);
    }
}

fn assert_provider_refused(
    store: &EncryptedStore,
    credential_id: &str,
    mode: SetProvidersMode,
    request: &[String],
    rule: &str,
    value: &str,
) {
    assert_refused(store, "invalid_provider_id", rule, || {
        let result = store.set_providers_audited(
            credential_id,
            mode,
            request,
            AuditCtx::admin(AuditOp::SetProviders),
        );
        if let Err(StoreOpError::InvalidProviderId { value: actual, .. }) = &result {
            assert_eq!(actual, value);
        }
        result
    });
}

#[test]
fn gateway_fixed_reserved_ids_refuse_first_requested_even_if_held_but_allow_removal() {
    let (_root, store) = rig("gateway-fixed-reserved", 228);
    let ordinary_id = "apikey:ordinary-gw-service";
    store.create(ordinary_id, &api_record()).unwrap();
    store
        .set_categories_audited(
            ordinary_id,
            SetCategoryMode::Set,
            &ids(&["llm-gateway"]),
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "INSERT INTO credential_provider_ids (credential_id, provider_id) VALUES (?1, ?2)",
                rusqlite::params![ordinary_id, "openai-gw-held"],
            )
        })
        .unwrap();
    for mode in [SetProvidersMode::Set, SetProvidersMode::Add] {
        for (requested, first) in [
            (
                ids(&["plain", "openai-gw-z-first", "anthropic-gw-a-second"]),
                "openai-gw-z-first",
            ),
            (ids(&["openai-gw-held"]), "openai-gw-held"),
        ] {
            assert_provider_refused(&store, ordinary_id, mode, &requested, "reserved", first);
        }
    }
    let before = state(&store);
    assert_eq!(
        store
            .set_providers_audited(
                ordinary_id,
                SetProvidersMode::Remove,
                &ids(&["openai-gw-not-held"]),
                AuditCtx::admin(AuditOp::SetProviders),
            )
            .unwrap(),
        ["openai-gw-held"]
    );
    assert_eq!(state(&store), before);
    assert!(store
        .set_providers_audited(
            ordinary_id,
            SetProvidersMode::Remove,
            &ids(&["openai-gw-held"]),
            AuditCtx::admin(AuditOp::SetProviders),
        )
        .unwrap()
        .is_empty());
    assert_eq!(
        store
            .read_audit(None)
            .unwrap()
            .last()
            .unwrap()
            .credential_id
            .as_deref(),
        Some("providers:apikey:ordinary-gw-service|")
    );
    assert!(rows(&store, "credential_gateway_settings").is_empty());
    assert_eq!(
        store
            .set_providers_audited(
                ordinary_id,
                SetProvidersMode::Add,
                &ids(&["openai"]),
                AuditCtx::admin(AuditOp::SetProviders)
            )
            .unwrap(),
        ["openai"]
    );
}

#[test]
fn gateway_fixed_provider_check_order_is_shape_duplicate_existence_gateway_then_count() {
    let (_root, store) = rig("gateway-fixed-provider-order", 229);
    gateway(&store);
    let ordinary_id = "apikey:ordinary";
    store.create(ordinary_id, &api_record()).unwrap();
    for credential_id in [ID, ordinary_id, "apikey:missing"] {
        for mode in [SetProvidersMode::Set, SetProvidersMode::Add] {
            let invalid = format!("A{}", "x".repeat(64));
            assert_provider_refused(
                &store,
                credential_id,
                mode,
                &ids(&["openai-gw-x", &invalid]),
                "charset",
                &invalid,
            );
            let long = "x".repeat(65);
            assert_provider_refused(
                &store,
                credential_id,
                mode,
                &ids(&["openai-gw-x", &long]),
                "length",
                &long,
            );
            assert_provider_refused(
                &store,
                credential_id,
                mode,
                &ids(&["openai-gw-x", "openai-gw-x"]),
                "duplicate",
                "openai-gw-x",
            );
        }
    }
    let full: Vec<_> = (0..33).map(|i| format!("p{i:02}")).collect();
    let mut reserved_overflow = full.clone();
    reserved_overflow.extend(ids(&["openai-gw-z-first", "anthropic-gw-a-second"]));
    for mode in [SetProvidersMode::Set, SetProvidersMode::Add] {
        let before = state(&store);
        assert!(matches!(
            store.set_providers_audited(
                "apikey:missing",
                mode,
                &reserved_overflow,
                AuditCtx::admin(AuditOp::SetProviders)
            ),
            Err(StoreOpError::NotFound)
        ));
        assert_eq!(state(&store), before);
        assert_refused(&store, "gateway_fixed", "provider_id", || {
            store.set_providers_audited(
                ID,
                mode,
                &reserved_overflow,
                AuditCtx::admin(AuditOp::SetProviders),
            )
        });
        assert_provider_refused(
            &store,
            ordinary_id,
            mode,
            &reserved_overflow,
            "reserved",
            "openai-gw-z-first",
        );
        assert_provider_refused(&store, ordinary_id, mode, &full, "count", "p32");
    }
}

#[test]
fn gateway_fixed_provider_registration_refuses_reserved_defaults_and_services_atomically() {
    let (_root, store) = rig("gateway-fixed-registration", 230);
    gateway(&store);
    for service in ["custom-gw-acme", "-gw-", "custom-gw-"] {
        let before = state(&store);
        assert!(matches!(
            validate_registered_provider_service(service),
            Err(StoreOpError::InvalidServiceName { .. })
        ));
        assert!(matches!(
            store.set_registered_provider_audited(
                service,
                &ids(&["llm-provider"]),
                &[],
                AuditCtx::admin(AuditOp::ProviderSet)
            ),
            Err(StoreOpError::InvalidServiceName { .. })
        ));
        assert_eq!(state(&store), before);
    }
    let service = "custom-provider";
    for existing in [false, true] {
        if existing {
            store
                .set_registered_provider_audited(
                    service,
                    &ids(&["llm-provider"]),
                    &ids(&["openai"]),
                    AuditCtx::admin(AuditOp::ProviderSet),
                )
                .unwrap();
        }
        assert_refused(&store, "invalid_provider_id", "reserved", || {
            store.set_registered_provider_settings_audited(
                service,
                &ids(&["llm-provider"]),
                &ids(&["openai", "openai-gw-acme"]),
                None,
                AuditCtx::admin(AuditOp::ProviderSet),
            )
        });
    }
    store.with_raw_conn(|conn| conn.execute(
        "UPDATE registered_providers SET provider_ids_json = '[\"openai-gw-legacy\"]' WHERE service = ?1",
        [service],
    )).unwrap();
    assert_refused(&store, "invalid_provider_id", "reserved", || {
        store.set_registered_provider_audited(
            service,
            &ids(&["llm-provider"]),
            &ids(&["openai-gw-legacy"]),
            AuditCtx::admin(AuditOp::ProviderSet),
        )
    });
    assert!(store
        .set_registered_provider_audited(
            service,
            &ids(&["llm-provider"]),
            &ids(&["openai"]),
            AuditCtx::admin(AuditOp::ProviderSet)
        )
        .unwrap());
    assert_eq!(
        store
            .registered_providers()
            .unwrap()
            .iter()
            .find(|row| row.service == service)
            .unwrap()
            .provider_ids,
        ["openai"]
    );
}
