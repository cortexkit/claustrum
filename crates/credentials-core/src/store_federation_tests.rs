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

    let refused = apply(
        &store,
        AdminOpBody::FederationSelfSet {
            v: ADMIN_OP_SCHEMA_V2,
            member: "fed-computer:NOTHEX".into(),
        },
        ACTOR,
    );
    assert!(
        matches!(refused, Err(StoreOpError::InvalidMemberId)),
        "{refused:?}"
    );
    assert_eq!(store.federation_self_member().unwrap(), None);
    assert!(audit_rows(&store, AuditOp::FederationSelfSet).is_empty());

    for member in [HOME, OTHER] {
        apply(
            &store,
            AdminOpBody::FederationSelfSet {
                v: ADMIN_OP_SCHEMA_V2,
                member: member.into(),
            },
            ACTOR,
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
    store.create("oauth:anthropic:kept", &oauth_record()).expect("create");
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
