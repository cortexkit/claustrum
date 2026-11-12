//! Operator tiers are separate from sealed material, but must not survive a
//! replacement that changes the account the assertion described.

use super::*;
use crate::admin_ops::{
    apply, AdminAuditOp, AdminOpBody, StoreMode, ADMIN_OP_SCHEMA_V1, ADMIN_OP_SCHEMA_V2,
};
use crate::store::taxonomy_tests::{api_record, rig, sqlite};

const ID: &str = "apikey:plan";

#[test]
fn plan_since_is_cleared_on_tier_change_and_repeats_are_unaudited() {
    let (_root, store) = rig("plan-since", 192);
    store.create(ID, &record(Some("account"))).unwrap();
    let op = |tier: Option<&str>, since_ms: Option<u64>| AdminOpBody::SetPlan {
        v: ADMIN_OP_SCHEMA_V2,
        credential_id: ID.into(),
        plan_tier: tier.map(str::to_owned),
        since_ms: since_ms.map(serde_json::Value::from),
    };
    apply(&store, op(Some("plus"), Some(1)), "operator").unwrap();
    assert_eq!(store.meta(ID).unwrap().plan_tier_since_ms, Some(1));
    let observed = store.meta(ID).unwrap().plan_tier_observed_at_ms;
    let audit = plan_audit(&store);
    apply(&store, op(Some("plus"), Some(1)), "operator").unwrap();
    assert_eq!(plan_audit(&store), audit);
    apply(&store, op(Some("plus"), Some(2)), "operator").unwrap();
    assert_eq!(store.meta(ID).unwrap().plan_tier_observed_at_ms, observed);
    assert_eq!(plan_audit(&store).len(), audit.len() + 1);
    assert_eq!(store.meta(ID).unwrap().plan_tier_since_ms, Some(2));
    apply(&store, op(Some("pro_200"), None), "operator").unwrap();
    assert_eq!(
        store.meta(ID).unwrap().plan_tier_since_ms,
        None,
        "a changed tier must not inherit the previous tier's effective start"
    );
    apply(&store, op(Some("pro_200"), Some(3)), "operator").unwrap();
    apply(&store, op(Some("pro_200"), None), "operator").unwrap();
    assert_eq!(store.meta(ID).unwrap().plan_tier_since_ms, None);
    apply(&store, op(Some("plus"), Some(4)), "operator").unwrap();
    apply(&store, op(None, None), "operator").unwrap();
    assert_eq!(store.meta(ID).unwrap().plan_tier_since_ms, None);
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn plan_since_admin_refuses_wrong_types_ranges_future_and_clear_with_date() {
    let (_root, store) = rig("plan-since-invalid", 193);
    store.create(ID, &record(None)).unwrap();
    let before = store.read_audit(None).unwrap();
    for since_ms in [
        serde_json::json!(null),
        serde_json::json!("1"),
        serde_json::json!(true),
        serde_json::json!([]),
        serde_json::json!({}),
        serde_json::json!(1.5),
        serde_json::json!(0),
        serde_json::json!(-1),
        serde_json::json!(u64::MAX),
        serde_json::json!(crate::plan_tier::MAX_PLAN_TIER_SINCE_MS + 1),
        serde_json::json!(now_ms() + 60_000),
    ] {
        let op: AdminOpBody = serde_json::from_value(serde_json::json!({
            "op":"admin.set_plan", "v":2, "credential_id":ID, "plan_tier":"plus", "since_ms": since_ms
        })).unwrap();
        assert!(
            matches!(
                apply(&store, op, "operator"),
                Err(StoreOpError::InvalidPlanTier)
            ),
            "{since_ms}"
        );
    }
    for tier in [serde_json::json!(null), serde_json::json!("plus")] {
        let mut value =
            serde_json::json!({"op":"admin.set_plan", "v":2, "credential_id":ID, "since_ms":1});
        if tier.is_null() {
            value["plan_tier"] = tier;
        }
        assert!(matches!(
            apply(&store, serde_json::from_value(value).unwrap(), "operator"),
            Err(StoreOpError::InvalidPlanTier)
        ));
    }
    assert_eq!(store.read_audit(None).unwrap(), before);
    assert_eq!(store.meta(ID).unwrap().plan_tier, None);
}

#[test]
fn plan_since_follows_operator_identity_visibility_and_survives_token_refresh() {
    let (_root, store) = rig("plan-since-visibility", 194);
    let mut incoming = record(Some("account"));
    incoming.detected_plan = Some(crate::plan_detection::DetectedPlan {
        tier: Some("plus".into()),
        raw: None,
        observed_at_ms: 100,
    });
    store.create(ID, &incoming).unwrap();
    for (principal, operation) in [
        ("reader", GrantOperation::List),
        ("signer", GrantOperation::Sign),
        ("opener", GrantOperation::Open),
    ] {
        store
            .create_read_grant_audited(
                "reserved",
                principal,
                SelectorKind::Exact,
                ID,
                operation,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
    }
    let row = |principal| {
        store
            .list_scoped_snapshot("reserved", principal)
            .unwrap()
            .rows
            .remove(0)
    };
    assert_eq!(row("reader").plan_tier_source.as_deref(), Some("detected"));
    assert_eq!(row("reader").plan_tier_since_ms, None);
    store
        .set_plan_since_audited(
            ID,
            Some("pro_200"),
            Some(50),
            AuditCtx::admin(AuditOp::SetPlan),
        )
        .unwrap();
    assert_eq!(row("reader").plan_tier_since_ms, Some(50));
    for principal in ["signer", "opener"] {
        assert_eq!(row(principal).plan_tier, None);
        assert_eq!(row(principal).plan_tier_since_ms, None);
    }
    store.commit_refresh(ID, 1, &incoming).unwrap();
    assert_eq!(row("reader").plan_tier_since_ms, Some(50));
    set(&store, ID, None);
    assert_eq!(row("reader").plan_tier_since_ms, None);
    assert_eq!(row("reader").plan_tier_source.as_deref(), Some("detected"));
}

#[test]
fn plan_observed_time_tracks_value_changes_not_refreshes_and_clear_restores_detection_time() {
    let (_root, store) = rig("plan-value-time", 189);
    let mut incoming = record(Some("account"));
    let detect = |tier: &str, at| crate::plan_detection::DetectedPlan {
        tier: Some(tier.into()),
        raw: Some(tier.into()),
        observed_at_ms: at,
    };
    incoming.detected_plan = Some(detect("plus", 100));
    store.create(ID, &incoming).unwrap();
    store
        .create_read_grant_audited(
            "reserved",
            "reader",
            SelectorKind::Exact,
            ID,
            GrantOperation::List,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let row = || {
        store
            .list_scoped_snapshot("reserved", "reader")
            .unwrap()
            .rows
            .remove(0)
    };
    assert_eq!(row().plan_tier_observed_at_ms, Some(100));
    let incarnation = row().incarnation;
    incoming.detected_plan = Some(detect("plus", 200));
    store.commit_refresh(ID, 1, &incoming).unwrap();
    assert_eq!(row().plan_tier_observed_at_ms, Some(100));
    incoming.detected_plan = Some(detect("pro_200", 300));
    store.commit_refresh(ID, 2, &incoming).unwrap();
    assert_eq!(row().plan_tier_observed_at_ms, Some(300));
    set(&store, ID, Some("max_20x"));
    let operator_time = store.meta(ID).unwrap().plan_tier_observed_at_ms.unwrap();
    assert_eq!(row().plan_tier_observed_at_ms, Some(operator_time));
    set(&store, ID, Some("max_20x"));
    assert_eq!(row().plan_tier_observed_at_ms, Some(operator_time));
    set(&store, ID, None);
    assert_eq!(row().plan_tier_observed_at_ms, Some(300));
    assert_eq!(row().incarnation, incarnation);

    // Simulate an existing envelope written before current-value times existed.
    let mut legacy = store.get(ID).unwrap();
    legacy.detected_plan_tier_observed_at_ms = None;
    let blob = store.seal_record(ID, &legacy).unwrap();
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE credentials SET envelope=?1 WHERE credential_id=?2",
                rusqlite::params![blob, ID],
            )
        })
        .unwrap();
    incoming.detected_plan = Some(detect("pro_200", 400));
    store.commit_refresh(ID, 3, &incoming).unwrap();
    assert_eq!(row().plan_tier_observed_at_ms, None);
    incoming.detected_plan = Some(detect("plus", 500));
    store.commit_refresh(ID, 4, &incoming).unwrap();
    assert_eq!(row().plan_tier_observed_at_ms, Some(500));
    store
        .overwrite_unconditional_audited(ID, &incoming, AuditCtx::admin(AuditOp::Overwrite))
        .unwrap();
    assert_eq!(row().incarnation, incarnation);
    store
        .remove_audited(ID, AuditCtx::admin(AuditOp::Remove))
        .unwrap();
    store.create(ID, &record(None)).unwrap();
    assert_ne!(row().incarnation, incarnation);
    assert_eq!(row().plan_tier_observed_at_ms, None);
}

#[test]
fn migration_36_does_not_invent_operator_observation_times() {
    let (_root, sqlite) = sqlite("plan-time-migration", 190);
    migrate_through_for_test(&sqlite, crate::store::SECRET_SCOPE_SCHEMA_VERSION).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([190; 32])).unwrap();
    store.create(ID, &record(None)).unwrap();
    set(&store, ID, Some("plus"));
    let before = store.get(ID).unwrap();
    let audit = store.read_audit(None).unwrap();
    migrate_through_for_test(
        &store.store,
        crate::store::PLAN_TIER_OBSERVED_SCHEMA_VERSION,
    )
    .unwrap();
    assert_eq!(store.meta(ID).unwrap().plan_tier_observed_at_ms, None);
    assert_eq!(
        store.get(ID).unwrap().encode().unwrap(),
        before.encode().unwrap()
    );
    assert_eq!(store.read_audit(None).unwrap(), audit);
    set(&store, ID, Some("plus"));
    assert_eq!(store.meta(ID).unwrap().plan_tier_observed_at_ms, None);
    set(&store, ID, Some("pro_200"));
    assert!(store.meta(ID).unwrap().plan_tier_observed_at_ms.is_some());
}

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
    assert_eq!(newest_migration_version(), 44);
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
        since_ms: None,
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

#[test]
fn detected_plan_override_precedence_and_clear_reveal_the_observation() {
    let (_root, store) = rig("detected-plan-override", 192);
    let mut incoming = record(Some("account"));
    incoming.detected_plan = Some(crate::plan_detection::DetectedPlan {
        tier: Some("max_20x".into()),
        raw: Some("default_claude_max_20x".into()),
        observed_at_ms: 123,
    });
    store.create(ID, &incoming).unwrap();
    for (principal, operation) in [
        ("reader", GrantOperation::Read),
        ("lister", GrantOperation::List),
        ("signer", GrantOperation::Sign),
    ] {
        store
            .create_read_grant_audited(
                "reserved",
                principal,
                SelectorKind::Exact,
                ID,
                operation,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
    }
    for (override_tier, expected, source) in [
        (None, "max_20x", "detected"),
        (Some("max_5x"), "max_5x", "operator"),
        (None, "max_20x", "detected"),
    ] {
        set(&store, ID, override_tier);
        for principal in ["reader", "lister"] {
            let row = store
                .list_scoped_snapshot("reserved", principal)
                .unwrap()
                .rows
                .remove(0);
            assert_eq!(row.plan_tier.as_deref(), Some(expected));
            assert_eq!(row.plan_tier_source.as_deref(), Some(source));
        }
        let hidden = store
            .list_scoped_snapshot("reserved", "signer")
            .unwrap()
            .rows
            .remove(0);
        assert_eq!(hidden.plan_tier, None);
        assert_eq!(hidden.plan_tier_source, None);
        assert_eq!(
            store.get(ID).unwrap().record_version,
            1,
            "override and clear must not write the record"
        );
    }
    let mut copied = store.get(ID).unwrap();
    copied.identity.account_id = Some("new-account".into());
    store
        .overwrite_unconditional_audited(ID, &copied, AuditCtx::admin(AuditOp::Login))
        .unwrap();
    assert_eq!(store.get(ID).unwrap().detected_plan, None);
    for cas in [true, false] {
        store
            .overwrite_unconditional_audited(ID, &incoming, AuditCtx::admin(AuditOp::Login))
            .unwrap();
        set(&store, ID, Some("max_5x"));
        let mut changed = store.get(ID).unwrap();
        changed.identity.account_id = Some("other".into());
        if cas {
            store
                .overwrite_cas_audited(
                    ID,
                    &changed,
                    &payload_hash(changed.payload.expose()),
                    AuditCtx::admin(AuditOp::Login),
                )
                .unwrap();
        } else {
            store
                .set_identity_audited(ID, changed.identity, AuditCtx::admin(AuditOp::SetIdentity))
                .unwrap();
        }
        assert_eq!(store.get(ID).unwrap().detected_plan, None);
        assert_eq!(store.meta(ID).unwrap().plan_tier, None);
    }
}
