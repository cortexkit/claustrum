//! Tests for the vault release-2 (home-vault federation) schema and store APIs.

use super::*;
use crate::admin_ops::{
    apply, AdminAuditOp, AdminOpBody, StoreMode, ADMIN_OP_SCHEMA_V1, ADMIN_OP_SCHEMA_V2,
};
use crate::federation::{
    federation_gate_payload_hash, federation_self_payload_hash, member_grant_payload_hash,
    remote_membership_payload_hash, MemberGrantOperation, MemberGrantSelector, NewRemoteRecord,
    RemoteHomeState,
};
use crate::secret::Secret;
use crate::store::taxonomy_tests::{api_record, rig, sqlite};

const HOME: &str = "fed-computer:0123456789abcdef0123456789abcdef";
const OTHER: &str = "fed-computer:fedcba9876543210fedcba9876543210";
const ACTOR: &str = "route-admin";

fn new_remote(id: &str) -> NewRemoteRecord {
    NewRemoteRecord {
        credential_id: id.to_string(),
        home_member: HOME.to_string(),
        refresh_adapter: Some("anthropic".to_string()),
        detected_plan: Some(crate::plan_detection::DetectedPlan {
            tier: Some("max_20x".to_string()),
            raw: Some("default_claude_max_20x".to_string()),
            observed_at_ms: 1_700_000_000_000,
        }),
        identity: RecordIdentity {
            account_id: Some("acct-1".to_string()),
            email: Some("me@example.com".to_string()),
            org_name: None,
        },
        home_version: 4,
        categories: vec!["llm-provider".to_string()],
    }
}

fn add_remote(store: &EncryptedStore, id: &str) -> crate::federation::RemoteRecord {
    store
        .remote_add_audited(&new_remote(id))
        .expect("remote add")
}

fn local_rows(store: &EncryptedStore, id: &str) -> i64 {
    store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM credentials WHERE credential_id = ?1",
                [id],
                |row| row.get(0),
            )
        })
        .unwrap()
}

fn audit_rows(store: &EncryptedStore, op: AuditOp) -> Vec<AuditEntry> {
    store
        .read_audit(None)
        .unwrap()
        .into_iter()
        .filter(|entry| entry.op == op.as_str())
        .collect()
}

fn store_body(
    id: &str,
    record: VaultRecord,
    audit_op: AdminAuditOp,
    mode: StoreMode,
) -> AdminOpBody {
    AdminOpBody::Store {
        v: ADMIN_OP_SCHEMA_V1,
        id: id.to_string(),
        record: Box::new(record),
        audit_op,
        mode,
    }
}

fn oauth_record() -> VaultRecord {
    VaultRecord::new_oauth(
        "opencode",
        "anthropic",
        crate::oauth::OAuthCredential {
            access_token: "access".to_string().into(),
            refresh_token: "refresh".to_string().into(),
            expires_at_ms: Some(9_999),
            token_url: "https://t.test/token".into(),
            client_id: Some("c".into()),
            client_secret: None,
            scopes: vec![],
        },
        b"access".to_vec(),
    )
}

/// Every creator below must refuse the id while it is a remote record, and leave no
/// `credentials` row behind. Each test names the creator it stands for.
fn assert_refused_as_remote(
    store: &EncryptedStore,
    id: &str,
    result: Result<serde_json::Value, StoreOpError>,
) {
    assert!(
        matches!(result, Err(StoreOpError::CredentialIdIsRemote)),
        "creating a local record under a remote id must be refused by name: {result:?}"
    );
    assert_eq!(local_rows(store, id), 0, "no local row may be left behind");
    assert!(
        store.remote_record(id).unwrap().is_some(),
        "the remote record stays"
    );
}

#[test]
fn release_2_migrations_follow_release_1_and_keep_existing_rows_and_grants() {
    assert_eq!(VAULT_RELEASE_1_SCHEMA_VERSION, 18);
    assert_eq!(
        FEDERATION_SCHEMA_VERSION,
        VAULT_RELEASE_1_SCHEMA_VERSION + 1
    );
    let versions: Vec<u32> = MIGRATIONS.iter().map(|m| m.version).collect();
    let release_2: Vec<u32> = versions
        .iter()
        .copied()
        .filter(|version| *version > VAULT_RELEASE_1_SCHEMA_VERSION)
        .collect();
    assert_eq!(release_2, (19..=26).collect::<Vec<_>>());
    assert_eq!(*versions.last().unwrap(), newest_migration_version());

    let (_root, sqlite) = sqlite("federation-migrate", 190);
    migrate_through_for_test(&sqlite, VAULT_RELEASE_1_SCHEMA_VERSION).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([190; 32])).unwrap();
    store
        .create_audited("apikey:zai", &api_record(), AuditCtx::admin(AuditOp::Put))
        .unwrap();
    store
        .create_read_grant_audited(
            "reserved",
            "broca",
            SelectorKind::Exact,
            "apikey:zai",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let grants_before = store.list_read_grants().unwrap();
    let metas_before = store.list_meta().unwrap();
    let audit_before = store.read_audit(None).unwrap();

    EncryptedStore::migrate(&store.store).unwrap();

    assert_eq!(
        store.store.with_conn(read_schema_version).unwrap(),
        newest_migration_version()
    );
    for table in [
        "remote_records",
        "remote_record_categories",
        "remote_record_provider_ids",
        "remote_record_plan_tiers",
        "member_grants",
        "remote_issue_seen",
        "pending_transfers",
        "outgoing_transfers",
        "settings",
    ] {
        assert!(
            store
                .with_raw_conn(|conn| table_exists(conn, table))
                .unwrap(),
            "{table} must exist after the release-2 migrations"
        );
    }
    assert_eq!(store.list_read_grants().unwrap(), grants_before);
    assert_eq!(store.list_meta().unwrap(), metas_before);
    assert_eq!(store.read_audit(None).unwrap(), audit_before);
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

/// Custody on B: the remote-record table cannot hold a token, because it has no column
/// that could. A column added later for one would redden this.
#[test]
fn remote_records_has_no_payload_or_oauth_column() {
    let (_root, store) = rig("federation-columns", 191);
    let columns: Vec<String> = store
        .with_raw_conn(|conn| {
            let mut stmt = conn.prepare("SELECT name FROM pragma_table_info('remote_records')")?;
            let names = stmt
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(names)
        })
        .unwrap();
    assert!(columns.contains(&"incarnation".to_string()), "{columns:?}");
    for column in &columns {
        for forbidden in [
            "payload",
            "oauth",
            "token",
            "envelope",
            "secret",
            "refresh_token",
        ] {
            assert!(
                !column.contains(forbidden) || column == "refresh_adapter",
                "remote_records must not have a {forbidden} column, found {column}"
            );
        }
    }
}

#[test]
fn a_release_1_binary_refuses_a_release_2_store_naming_both_versions() {
    let (_root, store) = rig("federation-release-1", 192);
    let recorded = store.store.with_conn(read_schema_version).unwrap();
    assert!(recorded >= FEDERATION_SCHEMA_VERSION);
    // The same check a release-1 binary runs, with release 1's own newest version.
    let error = refuse_store_ahead_of_binary(recorded, VAULT_RELEASE_1_SCHEMA_VERSION)
        .expect_err("a release-1 binary must refuse a release-2 store");
    let rendered = error.to_string();
    assert!(
        rendered.contains(&format!("store schema {recorded}"))
            && rendered.contains(&format!("this binary's {VAULT_RELEASE_1_SCHEMA_VERSION}")),
        "the refusal must name both versions: {rendered}"
    );
    // And this binary opens its own store.
    refuse_store_ahead_of_binary(recorded, newest_migration_version()).unwrap();
    EncryptedStore::migrate(&store.store).unwrap();
}

#[test]
fn put_refuses_an_id_held_by_a_remote_record() {
    let (_root, store) = rig("federation-put", 193);
    add_remote(&store, "apikey:zai");
    let result = apply(
        &store,
        store_body(
            "apikey:zai",
            api_record(),
            AdminAuditOp::Put,
            StoreMode::Create,
        ),
        ACTOR,
    );
    assert_refused_as_remote(&store, "apikey:zai", result);
    // `put --replace` on an id with no local row must not create one either.
    let replaced = apply(
        &store,
        store_body(
            "apikey:zai",
            api_record(),
            AdminAuditOp::Overwrite,
            StoreMode::ReplaceUnconditional,
        ),
        ACTOR,
    );
    assert!(replaced.is_err(), "{replaced:?}");
    assert_eq!(local_rows(&store, "apikey:zai"), 0);
}

#[test]
fn import_refuses_an_id_held_by_a_remote_record() {
    let (_root, store) = rig("federation-import", 194);
    add_remote(&store, "oauth:anthropic");
    let result = apply(
        &store,
        store_body(
            "oauth:anthropic",
            oauth_record(),
            AdminAuditOp::Import,
            StoreMode::Create,
        ),
        ACTOR,
    );
    assert_refused_as_remote(&store, "oauth:anthropic", result);
    let replaced = apply(
        &store,
        AdminOpBody::StoreWithIdentityPolicy {
            v: ADMIN_OP_SCHEMA_V1,
            id: "oauth:anthropic".into(),
            record: Box::new(oauth_record()),
            audit_op: AdminAuditOp::Import,
            clear_identity: false,
        },
        ACTOR,
    );
    assert!(replaced.is_err(), "{replaced:?}");
    assert_eq!(local_rows(&store, "oauth:anthropic"), 0);
}

#[test]
fn login_refuses_an_id_held_by_a_remote_record() {
    let (_root, store) = rig("federation-login", 195);
    add_remote(&store, "oauth:anthropic");
    let result = apply(
        &store,
        store_body(
            "oauth:anthropic",
            oauth_record(),
            AdminAuditOp::Login,
            StoreMode::Create,
        ),
        ACTOR,
    );
    assert_refused_as_remote(&store, "oauth:anthropic", result);
    let replaced = apply(
        &store,
        store_body(
            "oauth:anthropic",
            oauth_record(),
            AdminAuditOp::Login,
            StoreMode::ReplaceUnconditional,
        ),
        ACTOR,
    );
    assert!(replaced.is_err(), "{replaced:?}");
    assert_eq!(local_rows(&store, "oauth:anthropic"), 0);
}

#[test]
fn mint_signing_key_refuses_an_id_held_by_a_remote_record() {
    let (_root, store) = rig("federation-signing", 196);
    add_remote(&store, "signing:agent-assertion:1");
    let der =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, der.as_ref())
    );
    let record = VaultRecord::new_static(
        CredentialKind::SigningKey,
        "operator",
        pem.into_bytes(),
        None,
    );
    let result = apply(
        &store,
        store_body(
            "signing:agent-assertion:1",
            record,
            AdminAuditOp::Put,
            StoreMode::Create,
        ),
        ACTOR,
    );
    assert_refused_as_remote(&store, "signing:agent-assertion:1", result);
}

#[test]
fn mint_kem_key_refuses_an_id_held_by_a_remote_record() {
    let (_root, store) = rig("federation-kem", 197);
    add_remote(&store, "kem:push");
    let pem = crate::kem::generate_key().unwrap();
    let record =
        VaultRecord::new_static(CredentialKind::KemKey, "operator", pem.into_bytes(), None);
    let result = apply(
        &store,
        store_body("kem:push", record, AdminAuditOp::Put, StoreMode::Create),
        ACTOR,
    );
    assert_refused_as_remote(&store, "kem:push", result);
}

/// `transfer init` creates the vault's transfer key as a new KEM record.
#[test]
fn transfer_init_refuses_an_id_held_by_a_remote_record() {
    let (_root, store) = rig("federation-transfer-init", 198);
    add_remote(&store, "kem:vault-transfer:1");
    let pem = crate::kem::generate_key().unwrap();
    let record =
        VaultRecord::new_static(CredentialKind::KemKey, "operator", pem.into_bytes(), None);
    let result = store
        .create_audited(
            "kem:vault-transfer:1",
            &record,
            AuditCtx::route_admin(AuditOp::Put, ACTOR),
        )
        .map(|_| serde_json::Value::Null);
    assert_refused_as_remote(&store, "kem:vault-transfer:1", result);
}

/// Accepting a transfer creates a new static record under the body's id.
#[test]
fn transfer_accept_refuses_an_id_held_by_a_remote_record() {
    let (_root, store) = rig("federation-transfer-accept", 199);
    add_remote(&store, "apikey:openai");
    let result = store
        .create_audited(
            "apikey:openai",
            &api_record(),
            AuditCtx::route_admin(AuditOp::TransferIn, OTHER),
        )
        .map(|_| serde_json::Value::Null);
    assert_refused_as_remote(&store, "apikey:openai", result);
    assert!(audit_rows(&store, AuditOp::TransferIn).is_empty());
}

#[test]
fn deposit_cookie_refuses_an_id_held_by_a_remote_record() {
    let (_root, store) = rig("federation-cookie", 200);
    add_remote(&store, "cookie:ollama.com:ufuk");
    let result = store
        .deposit_cookie(
            "cookie:ollama.com:ufuk",
            &Secret::new("session=abc".to_owned()),
            "consent-123",
            None,
            "reserved:cerebellum",
        )
        .map(|_| serde_json::Value::Null);
    assert_refused_as_remote(&store, "cookie:ollama.com:ufuk", result);
}

#[test]
fn remote_add_refuses_an_id_held_by_a_local_record() {
    let (_root, store) = rig("federation-remote-add", 201);
    store
        .create_audited(
            "oauth:anthropic",
            &api_record(),
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
    let result = store.remote_add_audited(&new_remote("oauth:anthropic"));
    assert!(
        matches!(result, Err(StoreOpError::CredentialIdIsLocal)),
        "{result:?}"
    );
    assert!(store.remote_record("oauth:anthropic").unwrap().is_none());
    assert!(audit_rows(&store, AuditOp::RemoteAdd).is_empty());
    // A second add of an existing remote id is refused too: re-homing is remove, add.
    add_remote(&store, "oauth:openai");
    assert!(matches!(
        store.remote_add_audited(&new_remote("oauth:openai")),
        Err(StoreOpError::AlreadyExists)
    ));
}

/// The trigger is what refuses the remote insert, not a check in `remote_add_audited`:
/// a raw insert into `remote_records` for a local id is refused the same way.
#[test]
fn the_id_triggers_refuse_raw_inserts_in_both_directions() {
    let (_root, store) = rig("federation-triggers", 202);
    store
        .create_audited("apikey:zai", &api_record(), AuditCtx::admin(AuditOp::Put))
        .unwrap();
    add_remote(&store, "oauth:anthropic");
    let into_remote = store.with_raw_conn(|conn| {
        conn.execute(
            "INSERT INTO remote_records (credential_id, home_member, incarnation, kind, \
             last_home_version, last_home_state, created_at_ms, updated_at_ms) \
             VALUES ('apikey:zai', ?1, ?2, 'oauth', 1, 'active', 0, 0)",
            rusqlite::params![HOME, "0".repeat(32)],
        )
    });
    assert!(
        matches!(into_remote, Err(StoreOpError::CredentialIdIsLocal)),
        "{into_remote:?}"
    );
    let into_local = store.with_raw_conn(|conn| {
        conn.execute(
            "INSERT INTO credentials (credential_id, record_version, key_id, state, envelope, updated_at_ms) \
             VALUES ('oauth:anthropic', 1, '00', 'active', X'00', 0)",
            [],
        )
    });
    assert!(
        matches!(into_local, Err(StoreOpError::CredentialIdIsRemote)),
        "{into_local:?}"
    );
    let renamed = store.with_raw_conn(|conn| {
        conn.execute(
            "UPDATE credentials SET credential_id = 'oauth:anthropic' WHERE credential_id = 'apikey:zai'",
            [],
        )
    });
    assert!(
        matches!(renamed, Err(StoreOpError::CredentialIdIsRemote)),
        "{renamed:?}"
    );
}

#[test]
fn remote_add_and_remove_are_audited_with_the_home_member_and_incarnation() {
    let (_root, store) = rig("federation-remote-audit", 203);
    let first = add_remote(&store, "oauth:anthropic");
    assert_eq!(first.home_member, HOME);
    assert!(crate::federation::is_lower_hex_16_bytes(&first.incarnation));
    assert_eq!(first.last_home_version, 4);
    assert_eq!(first.last_home_state, RemoteHomeState::Active);
    assert_eq!(first.identity.account_id.as_deref(), Some("acct-1"));
    assert_eq!(
        first.detected_plan,
        new_remote("oauth:anthropic").detected_plan
    );
    assert_eq!(
        store.categories("oauth:anthropic").unwrap(),
        ["llm-provider"]
    );
    let added = audit_rows(&store, AuditOp::RemoteAdd);
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].credential_id.as_deref(), Some("oauth:anthropic"));
    assert_eq!(added[0].actor, HOME);
    assert_eq!(
        added[0].payload_hash.as_deref(),
        Some(
            remote_membership_payload_hash(&first.incarnation)
                .unwrap()
                .as_str()
        )
    );

    let removed = store.remote_remove_audited("oauth:anthropic").unwrap();
    assert_eq!(removed.incarnation, first.incarnation);
    let removals = audit_rows(&store, AuditOp::RemoteRemove);
    assert_eq!(removals.len(), 1);
    assert_eq!(
        removals[0].credential_id.as_deref(),
        Some("oauth:anthropic")
    );
    assert_eq!(removals[0].actor, HOME);
    assert_eq!(added[0].payload_hash, removals[0].payload_hash);
    assert!(matches!(
        store.remote_remove_audited("oauth:anthropic"),
        Err(StoreOpError::NotFound)
    ));

    let again = add_remote(&store, "oauth:anthropic");
    assert_ne!(
        again.incarnation, first.incarnation,
        "re-adding mints a new incarnation"
    );
    assert_eq!(store.list_remote_records().unwrap(), vec![again]);
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn remote_remove_deletes_every_remote_row_with_foreign_keys_off() {
    let (_root, store) = rig("federation-remote-remove", 204);
    add_remote(&store, "oauth:anthropic");
    let ctx = || AuditCtx::route_admin(AuditOp::SetCategory, ACTOR);
    store
        .set_categories_audited(
            "oauth:anthropic",
            SetCategoryMode::Add,
            &["custom-team".into()],
            ctx(),
        )
        .unwrap();
    store
        .set_providers_audited(
            "oauth:anthropic",
            SetProvidersMode::Set,
            &["anthropic".into()],
            AuditCtx::route_admin(AuditOp::SetProviders, ACTOR),
        )
        .unwrap();
    store
        .set_plan_audited(
            "oauth:anthropic",
            Some("max_5x"),
            AuditCtx::route_admin(AuditOp::SetPlan, ACTOR),
        )
        .unwrap();
    let count = |store: &EncryptedStore| -> i64 {
        store
            .with_raw_conn(|conn| {
                conn.query_row(
                    "SELECT (SELECT COUNT(*) FROM remote_records) \
                          + (SELECT COUNT(*) FROM remote_record_categories) \
                          + (SELECT COUNT(*) FROM remote_record_provider_ids) \
                          + (SELECT COUNT(*) FROM remote_record_plan_tiers)",
                    [],
                    |row| row.get(0),
                )
            })
            .unwrap()
    };
    assert_eq!(count(&store), 1 + 2 + 1 + 1);
    store
        .with_raw_conn(|conn| conn.pragma_update(None, "foreign_keys", "OFF"))
        .unwrap();
    store.remote_remove_audited("oauth:anthropic").unwrap();
    assert_eq!(count(&store), 0, "no remote_* row may survive a remove");
}

#[test]
fn set_category_providers_and_plan_write_the_remote_tables_for_a_remote_id() {
    let (_root, store) = rig("federation-remote-metadata", 205);
    add_remote(&store, "oauth:anthropic");
    let generation = store.grants_generation().unwrap();
    assert!(store
        .set_categories_audited(
            "oauth:anthropic",
            SetCategoryMode::Set,
            &["custom-team".into()],
            AuditCtx::route_admin(AuditOp::SetCategory, ACTOR),
        )
        .unwrap());
    assert_eq!(store.grants_generation().unwrap(), generation + 1);
    assert_eq!(
        store
            .set_providers_audited(
                "oauth:anthropic",
                SetProvidersMode::Add,
                &["anthropic".into()],
                AuditCtx::route_admin(AuditOp::SetProviders, ACTOR),
            )
            .unwrap(),
        ["anthropic"]
    );
    assert_eq!(
        store
            .set_plan_audited(
                "oauth:anthropic",
                Some("max_5x"),
                AuditCtx::route_admin(AuditOp::SetPlan, ACTOR),
            )
            .unwrap()
            .as_deref(),
        Some("max_5x")
    );
    assert_eq!(
        store.categories("oauth:anthropic").unwrap(),
        ["custom-team"]
    );
    assert_eq!(
        store.provider_ids("oauth:anthropic").unwrap(),
        ["anthropic"]
    );
    let (remote, local): ((i64, i64, String), i64) = store
        .with_raw_conn(|conn| {
            let remote = conn.query_row(
                "SELECT (SELECT COUNT(*) FROM remote_record_categories), \
                        (SELECT COUNT(*) FROM remote_record_provider_ids), \
                        (SELECT plan_tier FROM remote_record_plan_tiers WHERE credential_id = 'oauth:anthropic')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            let local = conn.query_row(
                "SELECT (SELECT COUNT(*) FROM credential_categories) \
                      + (SELECT COUNT(*) FROM credential_provider_ids) \
                      + (SELECT COUNT(*) FROM credential_plan_tiers)",
                [],
                |row| row.get(0),
            )?;
            Ok((remote, local))
        })
        .unwrap();
    assert_eq!(remote, (1, 1, "max_5x".to_string()));
    assert_eq!(
        local, 0,
        "a remote id never reaches the local metadata tables"
    );
    // The audit rows are the same shape a local id gets.
    let targets: Vec<String> = store
        .read_audit(None)
        .unwrap()
        .into_iter()
        .filter_map(|entry| entry.credential_id)
        .collect();
    for expected in [
        "category:oauth:anthropic|custom-team",
        "providers:oauth:anthropic|anthropic",
        "plan:oauth:anthropic||max_5x",
    ] {
        assert!(
            targets.iter().any(|target| target == expected),
            "{expected} in {targets:?}"
        );
    }
    // An id that is neither local nor remote is still not found.
    assert!(matches!(
        store.set_plan_audited("oauth:none", None, AuditCtx::admin(AuditOp::SetPlan)),
        Err(StoreOpError::NotFound)
    ));
    assert!(matches!(
        store.set_categories_audited(
            "oauth:none",
            SetCategoryMode::Set,
            &[],
            AuditCtx::admin(AuditOp::SetCategory)
        ),
        Err(StoreOpError::NotFound)
    ));
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn scoped_coverage_treats_a_remote_id_and_its_categories_as_existing() {
    let (_root, store) = rig("federation-coverage", 206);
    add_remote(&store, "oauth:anthropic");
    let grant = |kind: SelectorKind, selector: &str| {
        store
            .create_read_grant_audited(
                "reserved",
                "broca",
                kind,
                selector,
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap()
    };
    grant(SelectorKind::Category, "custom-team");
    let before = store
        .evaluate_scoped_coverage("reserved", "broca", "oauth:anthropic", GrantOperation::Read)
        .unwrap();
    assert!(before.id_exists);
    assert!(!before.covered);
    assert_eq!(before.id_category_count, Some(1));

    store
        .set_categories_audited(
            "oauth:anthropic",
            SetCategoryMode::Add,
            &["custom-team".into()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
    let by_category = store
        .evaluate_scoped_coverage("reserved", "broca", "oauth:anthropic", GrantOperation::Read)
        .unwrap();
    assert!(by_category.covered && by_category.id_exists);
    assert_eq!(by_category.id_category_count, Some(2));

    grant(SelectorKind::Exact, "oauth:openai");
    add_remote(&store, "oauth:openai");
    store
        .set_categories_audited(
            "oauth:openai",
            SetCategoryMode::Set,
            &[],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
    assert!(store
        .read_grant_covers("reserved", "broca", "oauth:openai", GrantOperation::Read)
        .unwrap());

    let unknown = store
        .evaluate_scoped_coverage("reserved", "broca", "oauth:none", GrantOperation::Read)
        .unwrap();
    assert!(!unknown.covered && !unknown.id_exists);
}

#[test]
fn reclassify_force_refuses_to_strip_a_category_a_member_grant_reaches() {
    let (_root, store) = rig("federation-reclassify", 207);
    store
        .create_audited(
            "oauth:snowflake",
            &api_record(),
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
    store
        .set_categories_audited(
            "oauth:snowflake",
            SetCategoryMode::Set,
            &["custom-team".into()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
    store
        .create_member_grant_audited(
            OTHER,
            MemberGrantOperation::RemoteRead,
            &MemberGrantSelector::Category("custom-team".into()),
            "pair-1",
        )
        .unwrap();
    let refused = store
        .reclassify_audited(true, AuditCtx::admin(AuditOp::SetCategory))
        .expect_err("a member grant's category must not be stripped");
    assert!(refused.to_string().contains("custom-team"), "{refused}");
    assert_eq!(
        store.categories("oauth:snowflake").unwrap(),
        ["custom-team"]
    );

    // Control: without the member grant the same call goes through.
    store
        .revoke_member_grant_audited(
            OTHER,
            MemberGrantOperation::RemoteRead,
            &MemberGrantSelector::Category("custom-team".into()),
        )
        .unwrap();
    assert_eq!(
        store
            .reclassify_audited(true, AuditCtx::admin(AuditOp::SetCategory))
            .unwrap(),
        1
    );
}

#[test]
fn pairing_ids_accept_128_bytes_and_refuse_one_byte_over_without_writes() {
    let (_root, store) = rig("federation-pairing-id-boundary", 237);
    let selector = MemberGrantSelector::Exact("oauth:anthropic".into());
    let at_cap = "p".repeat(128);
    assert!(store
        .create_member_grant_audited(OTHER, MemberGrantOperation::RemoteRead, &selector, &at_cap)
        .unwrap());
    let grants = store.list_member_grants().unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].pairing_id, at_cap);
    let audit = audit_rows(&store, AuditOp::MemberGrantCreate);
    assert_eq!(audit.len(), 1);

    let refused = store.create_member_grant_audited(
        OTHER,
        MemberGrantOperation::RemoteRead,
        &selector,
        &format!("{at_cap}p"),
    );
    assert!(
        matches!(refused, Err(StoreOpError::Encode(_))),
        "{refused:?}"
    );
    assert_eq!(store.list_member_grants().unwrap(), grants);
    assert_eq!(
        audit_rows(&store, AuditOp::MemberGrantCreate).len(),
        audit.len()
    );
}

#[test]
fn member_grants_are_audited_with_the_member_and_the_stored_pairing_id() {
    let (_root, store) = rig("federation-member-grants", 208);
    let exact = MemberGrantSelector::Exact("oauth:anthropic".into());
    assert!(store
        .create_member_grant_audited(OTHER, MemberGrantOperation::RemoteRead, &exact, "pair-1")
        .unwrap());
    assert!(
        !store
            .create_member_grant_audited(OTHER, MemberGrantOperation::RemoteRead, &exact, "pair-1")
            .unwrap(),
        "re-granting unchanged writes nothing"
    );
    assert!(store
        .create_member_grant_audited(OTHER, MemberGrantOperation::RemoteRead, &exact, "pair-2")
        .unwrap());
    assert!(store
        .create_member_grant_audited(
            OTHER,
            MemberGrantOperation::TransferDeliver,
            &MemberGrantSelector::None,
            "pair-2",
        )
        .unwrap());
    let grants = store.list_member_grants().unwrap();
    assert_eq!(grants.len(), 2);
    assert_eq!(grants[0].selector, exact);
    assert_eq!(
        grants[0].pairing_id, "pair-2",
        "a re-grant replaces the pairing id"
    );

    let created = audit_rows(&store, AuditOp::MemberGrantCreate);
    assert_eq!(created.len(), 3);
    assert_eq!(created[0].actor, OTHER);
    assert_eq!(created[0].credential_id.as_deref(), Some("oauth:anthropic"));
    assert_eq!(
        created[1].payload_hash.as_deref(),
        Some(
            member_grant_payload_hash(MemberGrantOperation::RemoteRead, &exact, "pair-2").as_str()
        )
    );
    assert_eq!(created[2].credential_id, None);

    store
        .revoke_member_grant_audited(OTHER, MemberGrantOperation::RemoteRead, &exact)
        .unwrap();
    let revoked = audit_rows(&store, AuditOp::MemberGrantRevoke);
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].actor, OTHER);
    assert_eq!(revoked[0].payload_hash, created[1].payload_hash);
    assert!(matches!(
        store.revoke_member_grant_audited(OTHER, MemberGrantOperation::RemoteRead, &exact),
        Err(StoreOpError::NotFound)
    ));

    // Shapes the table cannot hold are refused before any write.
    for (member, operation, selector, pairing) in [
        (
            "fed-phone:x",
            MemberGrantOperation::RemoteRead,
            exact.clone(),
            "p",
        ),
        (
            OTHER,
            MemberGrantOperation::RemoteRead,
            MemberGrantSelector::None,
            "p",
        ),
        (
            OTHER,
            MemberGrantOperation::TransferDeliver,
            exact.clone(),
            "p",
        ),
        (
            OTHER,
            MemberGrantOperation::RemoteRead,
            MemberGrantSelector::Category("Bad!".into()),
            "p",
        ),
        (OTHER, MemberGrantOperation::RemoteRead, exact.clone(), ""),
    ] {
        assert!(
            store
                .create_member_grant_audited(member, operation, &selector, pairing)
                .is_err(),
            "{member} {operation:?} {selector:?} {pairing:?}"
        );
    }
    assert_eq!(audit_rows(&store, AuditOp::MemberGrantCreate).len(), 3);
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

/// The gate and the self id are read from the store on every call, so the admin op's
/// write is visible at once; each change writes exactly one audit row.
#[test]
fn gate_and_self_id_are_read_live_and_written_only_through_audited_admin_ops() {
    let (_root, store) = rig("federation-settings", 209);
    assert!(
        !store.federation_member_mapping().unwrap(),
        "the gate defaults off"
    );
    assert_eq!(store.federation_self_member().unwrap(), None);

    let gate = |enabled| {
        apply(
            &store,
            AdminOpBody::FederationGateSet {
                v: ADMIN_OP_SCHEMA_V2,
                enabled,
            },
            ACTOR,
        )
        .unwrap()
    };
    assert_eq!(gate(true)["changed"], true);
    assert!(store.federation_member_mapping().unwrap());
    assert_eq!(gate(true)["changed"], false);
    assert_eq!(gate(false)["changed"], true);
    assert!(!store.federation_member_mapping().unwrap());
    let gate_rows = audit_rows(&store, AuditOp::FederationGateSet);
    assert_eq!(gate_rows.len(), 2);
    assert_eq!(gate_rows[0].credential_id, None);
    assert_eq!(gate_rows[0].actor, ACTOR);
    assert!(gate_rows[0].alarm);
    assert_eq!(
        gate_rows[0].payload_hash.as_deref(),
        Some(federation_gate_payload_hash(true).as_str())
    );
    assert_eq!(
        gate_rows[1].payload_hash.as_deref(),
        Some(federation_gate_payload_hash(false).as_str())
    );

    // The self id is set only on the live daemon, which first checks it against the id
    // callosum computes for this computer. `apply` (the offline lease path) refuses the
    // op before writing anything, valid id or not.
    for member in ["fed-computer:NOTHEX", HOME] {
        let refused = apply(
            &store,
            AdminOpBody::FederationSelfSet {
                v: ADMIN_OP_SCHEMA_V2,
                member: member.into(),
            },
            ACTOR,
        );
        assert!(
            matches!(&refused, Err(StoreOpError::Encode(message))
                if message.starts_with(crate::admin_ops::FEDERATION_REQUIRES_DAEMON)),
            "{refused:?}"
        );
    }
    assert_eq!(store.federation_self_member().unwrap(), None);
    assert!(audit_rows(&store, AuditOp::FederationSelfSet).is_empty());

    // The store write the daemon makes after that check validates and audits.
    let refused = store.set_federation_self_member_audited(
        "fed-computer:NOTHEX",
        AuditCtx::route_admin(AuditOp::FederationSelfSet, ACTOR),
    );
    assert!(
        matches!(refused, Err(StoreOpError::InvalidMemberId)),
        "{refused:?}"
    );
    assert_eq!(store.federation_self_member().unwrap(), None);
    assert!(audit_rows(&store, AuditOp::FederationSelfSet).is_empty());

    for member in [HOME, OTHER] {
        store
            .set_federation_self_member_audited(
                member,
                AuditCtx::route_admin(AuditOp::FederationSelfSet, ACTOR),
            )
            .unwrap();
        assert_eq!(
            store.federation_self_member().unwrap().as_deref(),
            Some(member)
        );
    }
    let self_rows = audit_rows(&store, AuditOp::FederationSelfSet);
    assert_eq!(self_rows.len(), 2);
    assert_eq!(self_rows[1].credential_id, None);
    assert_eq!(self_rows[1].actor, ACTOR);
    assert_eq!(
        self_rows[1].payload_hash.as_deref(),
        Some(federation_self_payload_hash(OTHER).as_str())
    );
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

/// A damaged gate row reads as off, never on.
#[test]
fn an_unrecognised_gate_value_reads_as_off() {
    let (_root, store) = rig("federation-gate-damage", 210);
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "INSERT INTO settings (name, value, updated_at_ms) VALUES (?1, 'yes', 0)",
                [crate::federation::MEMBER_MAPPING_SETTING],
            )
        })
        .unwrap();
    assert!(!store.federation_member_mapping().unwrap());
}

/// A store from before federation reads every federation fact as unset, so a newer
/// CLI reading it without the lease does not fail.
#[test]
fn a_release_1_store_reads_federation_state_as_empty() {
    let (_root, sqlite) = sqlite("federation-behind", 211);
    migrate_through_for_test(&sqlite, VAULT_RELEASE_1_SCHEMA_VERSION).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([211; 32])).unwrap();
    assert!(!store.federation_member_mapping().unwrap());
    assert_eq!(store.federation_self_member().unwrap(), None);
    assert!(store.list_remote_records().unwrap().is_empty());
    assert!(store.remote_record("oauth:anthropic").unwrap().is_none());
    assert!(store.list_member_grants().unwrap().is_empty());
    assert!(store.categories("oauth:anthropic").unwrap().is_empty());
    assert!(store.provider_ids("oauth:anthropic").unwrap().is_empty());
}

#[test]
fn first_use_names_a_member_principal_by_its_member_id() {
    let (_root, store) = rig("federation-first-use", 212);
    store
        .record_scoped_first_use_by(
            "oauth:anthropic",
            AuthEventPrincipal::Member(OTHER),
            GrantOperation::Read,
        )
        .unwrap();
    let principal: (String, String) = store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT principal_kind, principal_id FROM auth_events WHERE credential_id = 'oauth:anthropic'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })
        .unwrap();
    assert_eq!(principal, ("member".to_string(), OTHER.to_string()));
}

// ---------------------------------------------------------------------------------
// remote_issue: one audit row per (member, credential, version, material)
// ---------------------------------------------------------------------------------

const ISSUED_ID: &str = "oauth:anthropic:issued";

fn seen_rows(store: &EncryptedStore, id: &str) -> i64 {
    store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM remote_issue_seen WHERE credential_id = ?1",
                [id],
                |row| row.get(0),
            )
        })
        .unwrap()
}

/// The version and stored-bytes digest a serving read would hand the issuer.
fn served(store: &EncryptedStore, id: &str) -> (u64, String) {
    let read = store.get_with_stale_pending_and_digest(id).expect("read");
    (read.record.record_version, read.stored_digest_hex)
}

#[test]
fn a_remote_issue_whose_version_or_material_changed_writes_nothing() {
    let (_root, store) = rig("federation-issue-mismatch", 213);
    store.create(ISSUED_ID, &oauth_record()).expect("create");
    let (version, digest) = served(&store, ISSUED_ID);

    // The version moved on since the serving read.
    let wrong_version = store.record_remote_issue_audited(OTHER, ISSUED_ID, version + 1, &digest);
    assert!(
        matches!(wrong_version, Err(StoreOpError::CasMismatch)),
        "a version mismatch releases nothing: {wrong_version:?}"
    );
    // Same version number, different stored bytes: the shape of a delete and re-create.
    let other_digest = "0".repeat(64);
    let wrong_material =
        store.record_remote_issue_audited(OTHER, ISSUED_ID, version, &other_digest);
    assert!(
        matches!(wrong_material, Err(StoreOpError::CasMismatch)),
        "a digest mismatch releases nothing: {wrong_material:?}"
    );
    // A record that no longer exists.
    let gone = store.record_remote_issue_audited(OTHER, "oauth:anthropic:gone", 1, &digest);
    assert!(matches!(gone, Err(StoreOpError::CasMismatch)), "{gone:?}");

    assert_eq!(seen_rows(&store, ISSUED_ID), 0, "no seen row on a mismatch");
    assert!(
        audit_rows(&store, AuditOp::RemoteIssue).is_empty(),
        "no audit row on a mismatch"
    );

    // The control: the matching tuple does record, so the refusals above were the
    // check and not a broken writer.
    assert!(store
        .record_remote_issue_audited(OTHER, ISSUED_ID, version, &digest)
        .unwrap());
    assert_eq!(seen_rows(&store, ISSUED_ID), 1);
}

#[test]
fn a_remote_issue_is_audited_once_per_material_across_a_reopen() {
    let (root, store) = rig("federation-issue-once", 214);
    store.create(ISSUED_ID, &oauth_record()).expect("create");
    let (version, digest) = served(&store, ISSUED_ID);

    assert!(store
        .record_remote_issue_audited(OTHER, ISSUED_ID, version, &digest)
        .unwrap());
    assert!(
        !store
            .record_remote_issue_audited(OTHER, ISSUED_ID, version, &digest)
            .unwrap(),
        "a repeat of the same tuple writes nothing"
    );
    let rows = audit_rows(&store, AuditOp::RemoteIssue);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].credential_id.as_deref(), Some(ISSUED_ID));
    assert_eq!(rows[0].actor, OTHER);
    assert_eq!(
        rows[0].payload_hash.as_deref(),
        Some(crate::federation::remote_issue_payload_hash(ISSUED_ID, version).as_str())
    );
    // Another member is a separate tuple.
    assert!(store
        .record_remote_issue_audited(HOME, ISSUED_ID, version, &digest)
        .unwrap());
    drop(store);

    let descriptor = cortexkit_store::StorageDescriptor {
        module_id: "claustrum".into(),
        storage_namespace: "taxonomy-federation-issue-once".into(),
        isolation: cortexkit_store::Isolation::Module,
        backend: cortexkit_store::StorageBackend::Sqlite {
            path: root.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let sqlite = cortexkit_store::open_sqlite(&descriptor).expect("reopen sqlite");
    let store =
        EncryptedStore::open(sqlite, MasterKey::from_bytes([214; 32])).expect("reopen store");
    assert!(
        !store
            .record_remote_issue_audited(OTHER, ISSUED_ID, version, &digest)
            .unwrap(),
        "a restart appends nothing"
    );
    assert_eq!(audit_rows(&store, AuditOp::RemoteIssue).len(), 2);
    assert!(store.verify_audit_chain().is_ok());
}

#[test]
fn removing_a_credential_deletes_its_remote_issue_seen_rows() {
    let (_root, store) = rig("federation-issue-remove", 215);
    store.create(ISSUED_ID, &oauth_record()).expect("create");
    store
        .create("oauth:anthropic:kept", &oauth_record())
        .expect("create");
    for id in [ISSUED_ID, "oauth:anthropic:kept"] {
        let (version, digest) = served(&store, id);
        store
            .record_remote_issue_audited(OTHER, id, version, &digest)
            .unwrap();
    }
    assert_eq!(seen_rows(&store, ISSUED_ID), 1);

    store
        .remove_audited(ISSUED_ID, AuditCtx::admin(AuditOp::Remove))
        .expect("remove");
    assert_eq!(seen_rows(&store, ISSUED_ID), 0, "the removed id's rows go");
    assert_eq!(
        seen_rows(&store, "oauth:anthropic:kept"),
        1,
        "another credential's rows stay"
    );

    // A re-created record restarts at version 1 and is audited afresh.
    store.create(ISSUED_ID, &oauth_record()).expect("re-create");
    let (version, digest) = served(&store, ISSUED_ID);
    assert!(store
        .record_remote_issue_audited(OTHER, ISSUED_ID, version, &digest)
        .unwrap());
}

// ---------------------------------------------------------------------------------
// Writes a requester makes after a fetch
// ---------------------------------------------------------------------------------

#[test]
fn fetch_outcomes_accept_64_bytes_and_refuse_one_byte_over_without_writes() {
    use crate::federation::RemoteRecordWrite;
    let (_root, store) = rig("federation-fetch-outcome-boundary", 238);
    let record = add_remote(&store, "oauth:anthropic");
    let (id, inc) = ("oauth:anthropic", record.incarnation.as_str());
    let at_cap = "a".repeat(64);
    assert_eq!(
        store
            .remote_record_note_fetch_outcome(id, inc, &at_cap)
            .unwrap(),
        RemoteRecordWrite::Changed
    );
    assert_eq!(
        store
            .remote_record_apply_home_state(id, inc, RemoteHomeState::NeedsReauth, &at_cap)
            .unwrap(),
        RemoteRecordWrite::Changed
    );
    let kept = store.remote_record(id).unwrap().unwrap();
    assert_eq!(kept.last_fetch_outcome.as_deref(), Some(at_cap.as_str()));
    assert_eq!(kept.last_home_error.as_deref(), Some(at_cap.as_str()));

    let over_cap = format!("{at_cap}a");
    let refused = store.remote_record_note_fetch_outcome(id, inc, &over_cap);
    assert!(
        matches!(refused, Err(StoreOpError::Encode(_))),
        "{refused:?}"
    );
    let refused =
        store.remote_record_apply_home_state(id, inc, RemoteHomeState::Corrupt, &over_cap);
    assert!(
        matches!(refused, Err(StoreOpError::Encode(_))),
        "{refused:?}"
    );
    assert_eq!(store.remote_record(id).unwrap().unwrap(), kept);
}

fn success_at(version: u64, recheck_pending: bool) -> crate::federation::RemoteHomeSuccess {
    crate::federation::RemoteHomeSuccess {
        home_version: version,
        refresh_adapter: Some("anthropic".to_string()),
        detected_plan: None,
        identity: RecordIdentity {
            account_id: Some(format!("acct-v{version}")),
            email: None,
            org_name: None,
        },
        recheck_pending,
    }
}

/// A reply fetched for an earlier `remote add` of the same id must never land on the
/// record that replaced it: every post-fetch write names the incarnation it was
/// fetched under, and a write under an old one changes nothing.
#[test]
fn a_write_under_an_old_incarnation_changes_nothing() {
    use crate::federation::RemoteRecordWrite;
    let (_root, store) = rig("federation-remote-stale-incarnation", 216);
    let old = add_remote(&store, "oauth:anthropic");
    store.remote_remove_audited("oauth:anthropic").unwrap();
    let new = add_remote(&store, "oauth:anthropic");
    assert_ne!(old.incarnation, new.incarnation);

    let id = "oauth:anthropic";
    let stale = old.incarnation.as_str();
    assert_eq!(
        store
            .remote_record_note_fetch_outcome(id, stale, "home_unreachable")
            .unwrap(),
        RemoteRecordWrite::StaleIncarnation
    );
    assert_eq!(
        store
            .remote_record_apply_success(id, stale, &success_at(9, false))
            .unwrap(),
        RemoteRecordWrite::StaleIncarnation
    );
    assert_eq!(
        store
            .remote_record_apply_home_state(id, stale, RemoteHomeState::NeedsReauth, "not_found")
            .unwrap(),
        RemoteRecordWrite::StaleIncarnation
    );
    assert_eq!(
        store
            .remote_record_raise_reported_version(id, stale, 9)
            .unwrap(),
        RemoteRecordWrite::StaleIncarnation
    );
    assert_eq!(
        store.remote_record(id).unwrap().unwrap(),
        new,
        "the re-added record is untouched by writes under the old incarnation"
    );

    // A removed id has no incarnation at all.
    store.remote_remove_audited(id).unwrap();
    assert_eq!(
        store
            .remote_record_note_fetch_outcome(id, &new.incarnation, "ok")
            .unwrap(),
        RemoteRecordWrite::StaleIncarnation
    );
}

#[test]
fn a_transport_failure_outcome_leaves_the_authoritative_state_and_error() {
    use crate::federation::RemoteRecordWrite;
    let (_root, store) = rig("federation-remote-outcome-only", 217);
    let record = add_remote(&store, "oauth:anthropic");
    let (id, inc) = ("oauth:anthropic", record.incarnation.as_str());
    assert_eq!(
        store
            .remote_record_apply_home_state(id, inc, RemoteHomeState::NeedsReauth, "not_found")
            .unwrap(),
        RemoteRecordWrite::Changed
    );
    assert_eq!(
        store
            .remote_record_note_fetch_outcome(id, inc, "home_unreachable")
            .unwrap(),
        RemoteRecordWrite::Changed
    );
    let after = store.remote_record(id).unwrap().unwrap();
    assert_eq!(after.last_home_state, RemoteHomeState::NeedsReauth);
    assert_eq!(after.last_home_error.as_deref(), Some("not_found"));
    assert_eq!(
        after.last_fetch_outcome.as_deref(),
        Some("home_unreachable")
    );
    assert_eq!(after.last_home_version, record.last_home_version);
    assert_eq!(after.identity, record.identity);

    // The same outcome again writes nothing.
    assert_eq!(
        store
            .remote_record_note_fetch_outcome(id, inc, "home_unreachable")
            .unwrap(),
        RemoteRecordWrite::Unchanged
    );
    // An outcome is a code, never a peer's text.
    assert!(store
        .remote_record_note_fetch_outcome(id, inc, "Home said: no")
        .is_err());
    // Only a served token makes a record active.
    assert!(store
        .remote_record_apply_home_state(id, inc, RemoteHomeState::Active, "ok")
        .is_err());
}

#[test]
fn reported_version_never_moves_backwards() {
    use crate::federation::RemoteRecordWrite;
    let (_root, store) = rig("federation-remote-reported", 218);
    let record = add_remote(&store, "oauth:anthropic");
    let (id, inc) = ("oauth:anthropic", record.incarnation.as_str());
    let reported =
        |store: &EncryptedStore| store.remote_record(id).unwrap().unwrap().reported_version;

    assert_eq!(
        store
            .remote_record_raise_reported_version(id, inc, 5)
            .unwrap(),
        RemoteRecordWrite::Changed
    );
    assert_eq!(
        store
            .remote_record_raise_reported_version(id, inc, 3)
            .unwrap(),
        RemoteRecordWrite::Unchanged,
        "a delayed older report does not lower it"
    );
    assert_eq!(reported(&store), Some(5));
    assert_eq!(
        store
            .remote_record_raise_reported_version(id, inc, 5)
            .unwrap(),
        RemoteRecordWrite::Unchanged
    );
    assert_eq!(
        store
            .remote_record_raise_reported_version(id, inc, 7)
            .unwrap(),
        RemoteRecordWrite::Changed
    );
    assert_eq!(reported(&store), Some(7));
}

/// A success clears an unresolved report unless the home is still holding that report
/// back (same or lower version, with `recheck_in_ms`); a re-create always clears it.
#[test]
fn a_success_resolves_a_report_unless_the_home_is_still_holding_it_back() {
    use crate::federation::RemoteRecordWrite;
    let (_root, store) = rig("federation-remote-success", 219);
    let record = add_remote(&store, "oauth:anthropic");
    let (id, inc) = ("oauth:anthropic", record.incarnation.as_str());
    let now = |store: &EncryptedStore| store.remote_record(id).unwrap().unwrap();
    assert_eq!(record.last_home_version, 4);

    store
        .remote_record_raise_reported_version(id, inc, 4)
        .unwrap();
    assert_eq!(
        store
            .remote_record_apply_success(id, inc, &success_at(4, true))
            .unwrap(),
        RemoteRecordWrite::Changed
    );
    let held = now(&store);
    assert_eq!(
        held.reported_version,
        Some(4),
        "same version with recheck keeps it"
    );
    assert_eq!(held.identity.account_id.as_deref(), Some("acct-v4"));
    assert_eq!(
        held.detected_plan, None,
        "home-owned fields follow the reply"
    );
    assert_eq!(
        store
            .remote_record_apply_success(id, inc, &success_at(4, true))
            .unwrap(),
        RemoteRecordWrite::Unchanged,
        "an identical reply writes nothing"
    );

    store
        .remote_record_apply_success(id, inc, &success_at(4, false))
        .unwrap();
    assert_eq!(now(&store).reported_version, None, "no recheck resolves it");

    store
        .remote_record_raise_reported_version(id, inc, 4)
        .unwrap();
    store
        .remote_record_apply_success(id, inc, &success_at(5, true))
        .unwrap();
    assert_eq!(
        now(&store).reported_version,
        None,
        "a newer version resolves it"
    );
    assert_eq!(now(&store).last_home_version, 5);

    store
        .remote_record_raise_reported_version(id, inc, 5)
        .unwrap();
    store
        .remote_record_apply_success(id, inc, &success_at(1, true))
        .unwrap();
    let recreated = now(&store);
    assert_eq!(
        recreated.reported_version, None,
        "a home re-create resolves it"
    );
    assert_eq!(
        recreated.last_home_version, 1,
        "a re-create replaces the version"
    );

    store
        .remote_record_apply_home_state(id, inc, RemoteHomeState::NeedsReauth, "needs_reauth")
        .unwrap();
    store
        .remote_record_raise_reported_version(id, inc, 1)
        .unwrap();
    store
        .remote_record_apply_home_state(id, inc, RemoteHomeState::Corrupt, "corrupt")
        .unwrap();
    assert_eq!(
        now(&store).reported_version,
        None,
        "an authoritative non-success resolves it"
    );
    store
        .remote_record_apply_success(id, inc, &success_at(2, false))
        .unwrap();
    let restored = now(&store);
    assert_eq!(restored.last_home_state, RemoteHomeState::Active);
    assert_eq!(restored.last_home_error, None);
}

#[test]
fn the_remote_inventory_carries_this_vaults_own_metadata() {
    let (_root, store) = rig("federation-remote-inventory", 220);
    add_remote(&store, "oauth:anthropic");
    store
        .set_providers_audited(
            "oauth:anthropic",
            SetProvidersMode::Set,
            &["anthropic".into()],
            AuditCtx::route_admin(AuditOp::SetProviders, ACTOR),
        )
        .unwrap();
    store
        .set_plan_audited(
            "oauth:anthropic",
            Some("max_5x"),
            AuditCtx::route_admin(AuditOp::SetPlan, ACTOR),
        )
        .unwrap();
    let rows = store.remote_inventory().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].record.credential_id, "oauth:anthropic");
    assert_eq!(rows[0].categories, vec!["llm-provider".to_string()]);
    assert_eq!(rows[0].provider_ids, vec!["anthropic".to_string()]);
    assert_eq!(rows[0].plan_tier.as_deref(), Some("max_5x"));
}

// ---------------------------------------------------------------------------------
// Sealed static-key transfers
// ---------------------------------------------------------------------------------

const TRANSFER_ID: &str = "0123456789abcdef0123456789abcdef";
const TRANSFER_ID_2: &str = "fedcba9876543210fedcba9876543210";

fn sealed(tag: u8) -> crate::federation::SealedTransfer {
    crate::federation::SealedTransfer {
        enc: vec![tag; 32],
        ciphertext: vec![tag.wrapping_add(1); 48],
        aad: format!("{{\"tag\":{tag}}}").into_bytes(),
    }
}

fn reopen(root: &crate::test_support::TestTempDir, label: &str, seed: u8) -> EncryptedStore {
    let descriptor = cortexkit_store::StorageDescriptor {
        module_id: "claustrum".into(),
        storage_namespace: format!("taxonomy-{label}"),
        isolation: cortexkit_store::Isolation::Module,
        backend: cortexkit_store::StorageBackend::Sqlite {
            path: root.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let sqlite = cortexkit_store::open_sqlite(&descriptor).expect("reopen sqlite");
    EncryptedStore::open(sqlite, MasterKey::from_bytes([seed; 32])).expect("reopen store")
}

fn new_outgoing(transfer_id: &str, tag: u8) -> crate::federation::NewOutgoingTransfer {
    crate::federation::NewOutgoingTransfer {
        transfer_id: transfer_id.to_string(),
        receiver_member: OTHER.to_string(),
        credential_id: "apikey:openai".to_string(),
        sealed: sealed(tag),
        created_at_ms: 1_000,
    }
}

fn new_incoming(
    sender: &str,
    transfer_id: &str,
    tag: u8,
) -> crate::federation::NewIncomingTransfer {
    crate::federation::NewIncomingTransfer {
        sender_member: sender.to_string(),
        transfer_id: transfer_id.to_string(),
        credential_id: "apikey:openai".to_string(),
        kind: "api_key".to_string(),
        categories: vec!["llm-provider".to_string()],
        size_bytes: 100,
        sealed: sealed(tag),
        received_at_ms: 1_000,
    }
}

/// A distinct 32-hex transfer id per index.
fn transfer_id(index: u8) -> String {
    format!("{:032x}", 0x1000 + u32::from(index))
}

fn acceptance(
    transfer_id: &str,
    tag: u8,
    provider_ids: Vec<String>,
) -> crate::federation::TransferAcceptance {
    let mut record = api_record();
    record.source = "transfer".to_string();
    crate::federation::TransferAcceptance {
        sender_member: HOME.to_string(),
        transfer_id: transfer_id.to_string(),
        body_hash: sealed(tag).body_hash(),
        credential_id: "apikey:openai".to_string(),
        record,
        categories: vec!["ops-secrets".to_string()],
        provider_ids,
        replace: false,
    }
}

/// A crash between the outgoing commit and the delivery: the reopened store still holds
/// the row with exactly the sealed bytes committed, so `--resume` re-sends them, and
/// exactly one `transfer_out` row records the send.
#[test]
fn a_crash_after_the_outgoing_commit_leaves_the_identical_bytes_for_resume() {
    let label = "federation-outgoing-crash";
    let (root, store) = rig(label, 231);
    let committed = store
        .commit_outgoing_transfer_audited(&new_outgoing(TRANSFER_ID, 5))
        .expect("commit");
    drop(store);

    let store = reopen(&root, label, 231);
    let row = store
        .outgoing_transfer(TRANSFER_ID)
        .unwrap()
        .expect("the committed row survives the crash");
    assert_eq!(
        row.sealed,
        sealed(5),
        "resume must find the exact sealed bytes"
    );
    assert_eq!(row.body_hash, sealed(5).body_hash());
    assert_eq!(row, committed);
    assert_eq!(row.state, crate::federation::OutgoingTransferState::Pending);
    assert_eq!(
        row.expires_at_ms,
        1_000 + crate::federation::TRANSFER_RETENTION_MS
    );
    let out = audit_rows(&store, AuditOp::TransferOut);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].credential_id.as_deref(), Some("apikey:openai"));
    assert_eq!(out[0].actor, OTHER, "transfer_out names the receiver");
    assert_eq!(
        out[0].payload_hash.as_deref(),
        Some(
            crate::federation::transfer_payload_hash(TRANSFER_ID, &sealed(5).body_hash())
                .unwrap()
                .as_str()
        )
    );
    assert!(store.verify_audit_chain().is_ok());
}

/// Send commits before delivery: the outgoing row and `transfer_out` commit together or
/// not at all. A fault between the two leaves neither, so nothing is ever sent for it.
#[test]
fn a_fault_between_the_outgoing_row_and_transfer_out_leaves_neither() {
    let (_root, store) = rig("federation-outgoing-fault", 232);
    let fault = || true;
    let result =
        store.commit_outgoing_transfer_with_fault(&new_outgoing(TRANSFER_ID, 6), Some(&fault));
    assert!(
        result.is_err(),
        "the injected fault fails the commit: {result:?}"
    );
    assert!(store.outgoing_transfer(TRANSFER_ID).unwrap().is_none());
    assert!(store.list_outgoing_transfers().unwrap().is_empty());
    assert!(audit_rows(&store, AuditOp::TransferOut).is_empty());
}

/// Accept writes the record, categories, provider ids, the accepted marker and
/// `transfer_in` in one transaction: a refusal part-way (here a provider id the rules
/// refuse, checked after the record is written) leaves no record, no categories, no
/// provider ids, the transfer still pending with its sealed bytes, and no audit row.
#[test]
fn an_accept_that_fails_part_way_writes_nothing() {
    let (_root, store) = rig("federation-accept-partway", 233);
    assert_eq!(
        store
            .insert_incoming_transfer(&new_incoming(HOME, TRANSFER_ID, 7))
            .unwrap(),
        crate::federation::IncomingInsert::Inserted
    );
    let result =
        store.accept_incoming_transfer_audited(&acceptance(TRANSFER_ID, 7, vec!["Bad Id".into()]));
    assert!(
        matches!(result, Err(StoreOpError::InvalidProviderId { .. })),
        "{result:?}"
    );
    assert_eq!(local_rows(&store, "apikey:openai"), 0, "no record survives");
    assert!(store.categories("apikey:openai").unwrap().is_empty());
    assert!(store.provider_ids("apikey:openai").unwrap().is_empty());
    let row = store.incoming_transfer(HOME, TRANSFER_ID).unwrap().unwrap();
    assert_eq!(row.state, crate::federation::IncomingTransferState::Pending);
    assert_eq!(row.sealed, Some(sealed(7)));
    assert!(audit_rows(&store, AuditOp::TransferIn).is_empty());

    // The same accept with valid provider ids writes all of it at once.
    let outcome = store
        .accept_incoming_transfer_audited(&acceptance(TRANSFER_ID, 7, vec!["openai".into()]))
        .unwrap();
    assert_eq!(
        outcome,
        crate::federation::TransferAcceptOutcome::Accepted { record_version: 1 }
    );
    assert_eq!(local_rows(&store, "apikey:openai"), 1);
    assert_eq!(
        store.categories("apikey:openai").unwrap(),
        vec!["ops-secrets".to_string()],
        "the body's categories replace the catalog defaults"
    );
    assert_eq!(store.provider_ids("apikey:openai").unwrap(), vec!["openai"]);
    let row = store.incoming_transfer(HOME, TRANSFER_ID).unwrap().unwrap();
    assert_eq!(
        row.state,
        crate::federation::IncomingTransferState::Accepted
    );
    assert!(
        row.sealed.is_none(),
        "an accepted row keeps no sealed bytes"
    );
    let record = store.get("apikey:openai").unwrap();
    assert_eq!(record.source, "transfer");
    let created_by: String = store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT created_by FROM credentials WHERE credential_id = 'apikey:openai'",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(created_by, "operator");
    let rows = audit_rows(&store, AuditOp::TransferIn);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor, HOME, "transfer_in names the sender");
    // A second accept of the same transfer writes nothing more.
    assert_eq!(
        store
            .accept_incoming_transfer_audited(&acceptance(TRANSFER_ID, 7, vec!["openai".into()]))
            .unwrap(),
        crate::federation::TransferAcceptOutcome::AlreadyDecided(
            crate::federation::IncomingTransferState::Accepted
        )
    );
    assert_eq!(audit_rows(&store, AuditOp::TransferIn).len(), 1);
    assert!(store.verify_audit_chain().is_ok());
}

/// The dedup recheck runs before the queue bounds: with the sender's queue full, the
/// same bytes again answer their stored state and write nothing, while a different
/// transfer is refused as queue-full.
#[test]
fn a_duplicate_is_answered_before_the_queue_full_check() {
    let (_root, store) = rig("federation-dedup-before-queue", 234);
    for index in 0..crate::federation::TRANSFER_PENDING_PER_SENDER_CAP as u8 {
        assert_eq!(
            store
                .insert_incoming_transfer(&new_incoming(HOME, &transfer_id(index), 10 + index))
                .unwrap(),
            crate::federation::IncomingInsert::Inserted
        );
    }
    let counts = store.pending_transfer_counts(HOME).unwrap();
    assert_eq!(counts.from_sender, 8);
    assert!(counts.full());

    let duplicate = store
        .insert_incoming_transfer(&new_incoming(HOME, &transfer_id(0), 10))
        .unwrap();
    assert_eq!(
        duplicate,
        crate::federation::IncomingInsert::Known(crate::federation::IncomingTransferState::Pending)
    );
    let fresh = store
        .insert_incoming_transfer(&new_incoming(HOME, &transfer_id(50), 90))
        .unwrap();
    assert_eq!(fresh, crate::federation::IncomingInsert::QueueFull);
    assert_eq!(store.list_incoming_transfers().unwrap().len(), 8);

    // Another sender has its own queue; an id reused with other bytes is a conflict.
    assert_eq!(
        store
            .insert_incoming_transfer(&new_incoming(OTHER, &transfer_id(0), 10))
            .unwrap(),
        crate::federation::IncomingInsert::Inserted
    );
    assert_eq!(
        store
            .insert_incoming_transfer(&new_incoming(OTHER, &transfer_id(0), 99))
            .unwrap(),
        crate::federation::IncomingInsert::Conflict
    );
}

#[test]
fn the_total_queue_keeps_64_transfers_and_refuses_the_65th_without_eviction() {
    let (_root, store) = rig("federation-total-queue-boundary", 239);
    // One transfer per sender keeps the per-sender cap from masking the total cap.
    for index in 0..64u8 {
        let sender = format!("fed-computer:{index:032x}");
        assert_eq!(
            store
                .insert_incoming_transfer(&new_incoming(&sender, &transfer_id(index), index))
                .unwrap(),
            crate::federation::IncomingInsert::Inserted,
            "transfer {} is admitted",
            index + 1
        );
    }
    let kept = store.list_incoming_transfers().unwrap();
    assert_eq!(kept.len(), 64);
    let counts = store.pending_transfer_counts(HOME).unwrap();
    assert_eq!(counts.total, 64);
    assert_eq!(counts.from_sender, 0);
    assert!(counts.full());
    assert_eq!(
        store
            .insert_incoming_transfer(&new_incoming(HOME, &transfer_id(64), 64))
            .unwrap(),
        crate::federation::IncomingInsert::QueueFull
    );
    assert_eq!(store.list_incoming_transfers().unwrap(), kept);
}

/// Expiry drops the sealed bytes and keeps the id and hash as expired; a decided row
/// is untouched.
#[test]
fn expiry_keeps_the_id_and_hash_but_drops_the_envelope() {
    let (_root, store) = rig("federation-expiry", 235);
    store
        .insert_incoming_transfer(&new_incoming(HOME, TRANSFER_ID, 20))
        .unwrap();
    store
        .insert_incoming_transfer(&new_incoming(HOME, TRANSFER_ID_2, 21))
        .unwrap();
    store
        .reject_incoming_transfer_audited(HOME, TRANSFER_ID_2, "rejected_by_operator")
        .unwrap();
    let later = 1_000 + crate::federation::TRANSFER_RETENTION_MS;
    assert_eq!(store.expire_incoming_transfers(later - 1).unwrap(), 0);
    assert_eq!(store.expire_incoming_transfers(later).unwrap(), 1);
    let row = store
        .incoming_transfer_by_hash(HOME, &sealed(20).body_hash())
        .unwrap()
        .unwrap();
    assert_eq!(row.state, crate::federation::IncomingTransferState::Expired);
    assert!(row.sealed.is_none());
    let rejected = store
        .incoming_transfer(HOME, TRANSFER_ID_2)
        .unwrap()
        .unwrap();
    assert_eq!(
        rejected.state,
        crate::federation::IncomingTransferState::Rejected
    );
    assert_eq!(
        rejected.reject_reason.as_deref(),
        Some("rejected_by_operator")
    );
    assert_eq!(audit_rows(&store, AuditOp::TransferReject).len(), 1);
}

/// Recovery is refused while the transfer key is `Active`; once it is found off
/// `Active`, one transaction replaces it, rejects every pending transfer and abandons
/// every outgoing one, with one `transfer_reject` row each.
#[test]
fn transfer_key_recovery_rejects_pending_and_abandons_outgoing_in_one_transaction() {
    let (_root, store) = rig("federation-key-recovery", 236);
    let old_pem = crate::kem::generate_key().unwrap();
    store
        .create_audited(
            crate::federation::VAULT_TRANSFER_ID,
            &VaultRecord::new_static(
                CredentialKind::KemKey,
                "operator",
                old_pem.into_bytes(),
                None,
            ),
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
    store
        .insert_incoming_transfer(&new_incoming(HOME, TRANSFER_ID, 30))
        .unwrap();
    store
        .insert_incoming_transfer(&new_incoming(OTHER, TRANSFER_ID, 31))
        .unwrap();
    store
        .commit_outgoing_transfer_audited(&new_outgoing(TRANSFER_ID_2, 32))
        .unwrap();
    let new_key = VaultRecord::new_static(
        CredentialKind::KemKey,
        "operator",
        crate::kem::generate_key().unwrap().into_bytes(),
        None,
    );

    let refused =
        store.recover_vault_transfer_key_audited(&new_key, AuditCtx::admin(AuditOp::Overwrite));
    assert!(
        matches!(refused, Err(StoreOpError::TransferKeyProtected)),
        "{refused:?}"
    );
    assert!(audit_rows(&store, AuditOp::TransferReject).is_empty());

    assert!(store
        .force_vault_transfer_key_state_for_test(RecordState::NeedsReauth)
        .unwrap());
    let recovery = store
        .recover_vault_transfer_key_audited(&new_key, AuditCtx::admin(AuditOp::Overwrite))
        .expect("recovery is admitted off Active");
    assert_eq!(recovery.rejected_incoming.len(), 2);
    assert_eq!(
        recovery.abandoned_outgoing,
        vec![crate::federation::RecoveredOutgoing {
            transfer_id: TRANSFER_ID_2.to_string(),
            credential_id: "apikey:openai".to_string(),
            receiver_member: OTHER.to_string(),
        }]
    );
    assert_eq!(
        store.vault_transfer_key_state().unwrap(),
        Some(RecordState::Active)
    );
    let key = store.get(crate::federation::VAULT_TRANSFER_ID).unwrap();
    assert_eq!(key.payload.expose(), new_key.payload.expose());
    for sender in [HOME, OTHER] {
        let row = store
            .incoming_transfer(sender, TRANSFER_ID)
            .unwrap()
            .unwrap();
        assert_eq!(
            row.state,
            crate::federation::IncomingTransferState::Rejected
        );
        assert_eq!(row.reject_reason.as_deref(), Some("remote_seal_invalid"));
    }
    let outgoing = store.outgoing_transfer(TRANSFER_ID_2).unwrap().unwrap();
    assert_eq!(
        outgoing.state,
        crate::federation::OutgoingTransferState::Abandoned
    );
    let rejects = audit_rows(&store, AuditOp::TransferReject);
    assert_eq!(rejects.len(), 3);
    let mut actors: Vec<&str> = rejects.iter().map(|row| row.actor.as_str()).collect();
    actors.sort();
    assert_eq!(actors, vec![HOME, OTHER, OTHER]);
    assert!(store.verify_audit_chain().is_ok());
}
