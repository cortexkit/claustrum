//! Operator tiers are separate from sealed material, but must not survive a
//! replacement that changes the account the assertion described.

use super::*;
use crate::admin_ops::{
    apply, AdminAuditOp, AdminOpBody, StoreMode, ADMIN_OP_SCHEMA_V1, ADMIN_OP_SCHEMA_V2,
};
use crate::store::taxonomy_tests::{api_record, rig, sqlite};

const ID: &str = "apikey:plan";

fn record(account: Option<&str>) -> VaultRecord {
    let mut record = api_record();
    record.identity.account_id = account.map(str::to_owned);
    record
}

fn set(store: &EncryptedStore, id: &str, tier: Option<&str>) {
    store
        .set_plan_audited(id, tier, AuditCtx::admin(AuditOp::SetPlan))
        .unwrap();
}

fn plan_audit(store: &EncryptedStore) -> Vec<AuditEntry> {
    store
        .read_audit(None)
        .unwrap()
        .into_iter()
        .filter(|entry| entry.op == "set_plan")
        .collect()
}

#[test]
fn migration_16_adds_only_an_empty_tier_table_and_behind_readers_tolerate_absence() {
    let (root, sqlite) = sqlite("plan-migration", 180);
    migrate_through_for_test(&sqlite, 15).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([180; 32])).unwrap();
    store.create(ID, &record(Some("account"))).unwrap();
    let before = store.list_meta().unwrap();
    let audit = store.read_audit(None).unwrap();
    let objects = || {
        store.with_raw_conn(|conn| {
        let mut stmt = conn.prepare("SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>();
        rows
    }).unwrap()
    };
    let ddl = objects();
    assert_eq!(before[0].1.plan_tier, None);
    let (offline, version) = list_meta_read_only_with_schema(&root.join("store.db")).unwrap();
    assert_eq!(version, 15);
    assert_eq!(offline, before);
    store
        .create_read_grant_audited(
            "reserved",
            "reader",
            SelectorKind::Exact,
            ID,
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    assert_eq!(
        store
            .list_scoped_snapshot("reserved", "reader")
            .unwrap()
            .rows[0]
            .plan_tier,
        None
    );
    let audit_before = store.read_audit(None).unwrap();
    migrate_through_for_test(&store.store, 16).unwrap();
    let after = objects();
    assert_eq!(after.len(), ddl.len() + 1);
    for object in ddl {
        assert!(after.contains(&object), "{} changed", object.0);
    }
    assert!(after.contains(&("credential_plan_tiers".into(), "CREATE TABLE credential_plan_tiers (credential_id TEXT NOT NULL PRIMARY KEY, plan_tier TEXT NOT NULL, FOREIGN KEY (credential_id) REFERENCES credentials(credential_id) ON DELETE CASCADE)".into())));
    assert_eq!(store.list_meta().unwrap(), before);
    assert_eq!(store.read_audit(None).unwrap(), audit_before);
    assert_eq!(audit.len(), 1);
    assert_eq!(newest_migration_version(), 16);
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn set_plan_validates_syntax_refuses_unknown_and_audits_only_old_to_new_transitions() {
    let (root, store) = rig("plan-set", 181);
    store.create(ID, &record(None)).unwrap();
    let raw = || {
        store
            .with_raw_conn(|conn| {
                conn.query_row(
                    "SELECT record_version, envelope FROM credentials WHERE credential_id = ?1",
                    [ID],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
            })
            .unwrap()
    };
    let before = raw();
    let op = |id: &str, tier: Option<&str>| AdminOpBody::SetPlan {
        v: ADMIN_OP_SCHEMA_V2,
        credential_id: id.into(),
        plan_tier: tier.map(str::to_owned),
    };
    assert_eq!(
        apply(&store, op(ID, Some("pro_200")), "operator").unwrap(),
        serde_json::json!({"plan_tier":"pro_200"})
    );
    for tier in [
        "",
        "1a",
        "_a",
        "A",
        "max-5x",
        "max 5x",
        "é",
        "a\n",
        &"a".repeat(33),
    ] {
        assert!(
            matches!(
                apply(&store, op(ID, Some(tier)), "operator"),
                Err(StoreOpError::InvalidPlanTier)
            ),
            "{tier:?}"
        );
    }
    for tier in [None, Some("max_20x")] {
        assert!(matches!(
            apply(&store, op("missing", tier), "operator"),
            Err(StoreOpError::NotFound)
        ));
    }
    apply(&store, op(ID, Some("pro_200")), "operator").unwrap();
    apply(&store, op(ID, Some("unrecognised_tier")), "operator").unwrap();
    assert_eq!(
        apply(&store, op(ID, None), "operator").unwrap(),
        serde_json::json!({"plan_tier":null})
    );
    apply(&store, op(ID, None), "operator").unwrap();
    assert_eq!(
        plan_audit(&store)
            .iter()
            .map(|row| row.credential_id.as_deref().unwrap())
            .collect::<Vec<_>>(),
        [
            "plan:apikey:plan||pro_200",
            "plan:apikey:plan|pro_200|unrecognised_tier",
            "plan:apikey:plan|unrecognised_tier|"
        ]
    );
    assert_eq!(raw(), before, "metadata writes must not re-seal the record");
    set(&store, ID, Some("max_5x"));
    assert_eq!(
        store.list_meta().unwrap()[0].1.plan_tier.as_deref(),
        Some("max_5x")
    );
    assert_eq!(
        list_meta_read_only_with_schema(&root.join("store.db"))
            .unwrap()
            .0,
        store.list_meta().unwrap()
    );
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn plan_replacement_paths_clear_only_when_the_effective_account_changes() {
    let (_root, store) = rig("plan-replacements", 182);
    // Each deposit path that can replace a credential's payload: `put` (a plain store,
    // compare-and-swap on the payload hash), `import` and `login` (a store that always
    // takes the incoming identity, even when it is empty), and the legacy import (an
    // unconditional plain store, which keeps the stored identity when the incoming
    // record carries none). The tier must be cleared exactly when the account_id
    // stored after the write differs from the one before it.
    for (path, identity_policy, cas) in [
        ("put", false, true),
        ("import", true, false),
        ("login", true, false),
        ("legacy-import", false, false),
    ] {
        let id = format!("apikey:{path}");
        let mut current = record(Some("old"));
        store.create(&id, &current).unwrap();
        for (step, (new_account, clear)) in [
            (Some("old"), false),
            (Some("new"), true),
            (None, true),
            (None, false),
            (Some("new"), true),
        ]
        .into_iter()
        .enumerate()
        {
            set(&store, &id, Some("max_20x"));
            let audit_before = plan_audit(&store).len();
            let incoming = record(new_account);
            let mode = if cas {
                StoreMode::ReplaceCas {
                    expected_hash_hex: hex32(&payload_hash(current.payload.expose())),
                }
            } else {
                StoreMode::ReplaceUnconditional
            };
            let op = if identity_policy {
                AdminOpBody::StoreWithIdentityPolicy {
                    v: ADMIN_OP_SCHEMA_V1,
                    id: id.clone(),
                    record: Box::new(incoming.clone()),
                    audit_op: if path == "login" {
                        AdminAuditOp::Login
                    } else {
                        AdminAuditOp::Import
                    },
                    clear_identity: true,
                }
            } else {
                AdminOpBody::Store {
                    v: ADMIN_OP_SCHEMA_V1,
                    id: id.clone(),
                    record: Box::new(incoming.clone()),
                    mode,
                    audit_op: AdminAuditOp::Put,
                }
            };
            apply(&store, op, "operator").unwrap();
            // Only the legacy import keeps the stored account_id when the incoming record
            // has none, so after step 1 it stays "new" and the tier is never cleared again.
            let effective = store.get(&id).unwrap();
            let (expected_account, changed) = if path == "legacy-import" {
                [
                    (Some("old"), false),
                    (Some("new"), true),
                    (Some("new"), false),
                    (Some("new"), false),
                    (Some("new"), false),
                ][step]
            } else {
                (new_account, clear)
            };
            assert_eq!(
                effective.identity.account_id.as_deref(),
                expected_account,
                "{path}: effective account"
            );
            assert_eq!(
                store.meta(&id).unwrap().plan_tier.as_deref(),
                if changed { None } else { Some("max_20x") },
                "{path}: {:?} -> {:?}",
                current.identity.account_id,
                effective.identity.account_id
            );
            assert_eq!(
                plan_audit(&store).len(),
                audit_before + usize::from(changed),
                "{path} audit"
            );
            if changed {
                assert_eq!(
                    plan_audit(&store).last().unwrap().credential_id.as_deref(),
                    Some(format!("plan:{id}|max_20x|").as_str())
                );
            }
            current = effective;
        }
    }
    let cookie_id = "cookie:example.test:account";
    let cookie = crate::secret::Secret::from("a=b".to_owned());
    store
        .deposit_cookie(
            cookie_id,
            &cookie,
            "consent",
            Some("old@example.test"),
            "reserved:browser",
        )
        .unwrap();
    set(&store, cookie_id, Some("pro_200"));
    store
        .deposit_cookie(cookie_id, &cookie, "consent", None, "reserved:browser")
        .unwrap();
    assert_eq!(
        store.meta(cookie_id).unwrap().plan_tier.as_deref(),
        Some("pro_200")
    );
    store
        .deposit_cookie(
            cookie_id,
            &cookie,
            "consent",
            Some("new@example.test"),
            "reserved:browser",
        )
        .unwrap();
    assert_eq!(
        store.meta(cookie_id).unwrap().plan_tier,
        None,
        "cookie replacement changed accounts"
    );
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn account_change_rolls_back_material_tier_and_audit_when_the_tier_audit_fails() {
    let (_root, store) = rig("plan-rollback", 183);
    store.create(ID, &record(Some("old"))).unwrap();
    set(&store, ID, Some("max_5x"));
    let before = store.get(ID).unwrap();
    let audit_before = store.read_audit(None).unwrap().len();
    store.with_raw_conn(|conn| conn.execute_batch("CREATE TRIGGER refuse_plan_audit BEFORE INSERT ON audit_log WHEN NEW.op = 'set_plan' BEGIN SELECT RAISE(ABORT, 'audit failure'); END;")).unwrap();
    assert!(store
        .overwrite_unconditional_audited(ID, &record(Some("new")), AuditCtx::admin(AuditOp::Import))
        .is_err());
    assert_eq!(store.get(ID).unwrap().record_version, before.record_version);
    assert_eq!(
        store.get(ID).unwrap().identity.account_id,
        before.identity.account_id
    );
    assert_eq!(store.meta(ID).unwrap().plan_tier.as_deref(), Some("max_5x"));
    assert_eq!(store.read_audit(None).unwrap().len(), audit_before);
}

#[test]
fn tiers_follow_identity_authority_while_providers_also_reach_sign_only_rows() {
    let (_root, store) = rig("plan-authority", 184);
    for (id, operation) in [
        ("apikey:read", GrantOperation::Read),
        ("apikey:list", GrantOperation::List),
        ("apikey:sign", GrantOperation::Sign),
        ("apikey:open", GrantOperation::Open),
    ] {
        store.create(id, &record(Some("account"))).unwrap();
        set(&store, id, Some("pro_200"));
        store
            .set_providers_audited(
                id,
                SetProvidersMode::Set,
                &["openai".into()],
                AuditCtx::admin(AuditOp::SetProviders),
            )
            .unwrap();
        store
            .create_read_grant_audited(
                "reserved",
                "consumer",
                SelectorKind::Exact,
                id,
                operation,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
    }
    let snapshot = store.list_scoped_snapshot("reserved", "consumer").unwrap();
    assert_eq!(snapshot.rows.len(), 4);
    for row in snapshot.rows {
        assert_eq!(
            row.provider_ids,
            ["openai"],
            "{} keeps provider metadata",
            row.id
        );
        assert_eq!(
            row.plan_tier.as_deref(),
            if row.id == "apikey:read" || row.id == "apikey:list" {
                Some("pro_200")
            } else {
                None
            },
            "{} tier disclosure",
            row.id
        );
    }
}

#[test]
fn tier_lifecycle_preserves_refresh_and_removes_without_foreign_key_enforcement() {
    use crate::oauth::OAuthCredential;
    let (_root, store) = rig("plan-lifecycle", 185);
    let id = "oauth:anthropic";
    let mut oauth = VaultRecord::new_oauth(
        "test",
        "anthropic",
        OAuthCredential {
            access_token: "a".to_owned().into(),
            refresh_token: "r".to_owned().into(),
            expires_at_ms: Some(99_999),
            token_url: "".into(),
            client_id: None,
            client_secret: None,
            scopes: Vec::new(),
        },
        b"payload".to_vec(),
    );
    oauth.identity.account_id = Some("account".into());
    store.create(id, &oauth).unwrap();
    set(&store, id, Some("max_5x"));
    store.commit_refresh(id, 1, &oauth).unwrap();
    assert_eq!(store.meta(id).unwrap().plan_tier.as_deref(), Some("max_5x"));
    store
        .retire_and_revoke_all_audited(id, AuditCtx::admin(AuditOp::Invalidate))
        .unwrap();
    assert_eq!(store.meta(id).unwrap().plan_tier.as_deref(), Some("max_5x"));
    set(&store, id, Some("max_20x"));
    store
        .with_raw_conn(|conn| conn.pragma_update(None, "foreign_keys", "OFF"))
        .unwrap();
    store
        .remove_audited(id, AuditCtx::admin(AuditOp::Remove))
        .unwrap();
    store.create(id, &oauth).unwrap();
    assert_eq!(store.meta(id).unwrap().plan_tier, None);
    assert_eq!(
        plan_audit(&store).len(),
        2,
        "remove records removal, not an asserted tier change"
    );
    // When the stored envelope can't be decrypted, a replacement can't show that the
    // account behind the credential stayed the same, so the tier is cleared.
    set(&store, id, Some("max_5x"));
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE credentials SET envelope = X'00' WHERE credential_id = ?1",
                [id],
            )
            .map(|_| ())
        })
        .unwrap();
    store
        .overwrite_unconditional_audited(id, &oauth, AuditCtx::admin(AuditOp::Import))
        .unwrap();
    assert_eq!(store.meta(id).unwrap().plan_tier, None);
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}
