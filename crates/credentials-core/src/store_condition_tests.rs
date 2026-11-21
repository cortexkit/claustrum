use super::taxonomy_tests::{api_record, rig, sqlite};
use super::*;
use crate::federation::{NewRemoteRecord, RemoteWatchApplyMode, RemoteWatchRow};
use crate::oauth::OAuthCredential;

const ID: &str = "antigravity:google";
const COPY: &str = "antigravity:google:copy";
const HOME: &str = "fed-computer:0123456789abcdef0123456789abcdef";
const VERIFY: &str = "provider_verification_required";
const INELIGIBLE: &str = "provider_ineligible";
const ADAPTER: Option<&str> = Some("antigravity");
const LINK: &str = "https://accounts.google.com/verify?session=fixture-private-query";
const ACTOR: &str = "reader-fixture";
const PRINCIPAL: AuthEventPrincipal<'_> = AuthEventPrincipal::Enrolled(ACTOR);

fn login(adapter: &str) -> VaultRecord {
    VaultRecord::new_oauth(
        "test",
        adapter,
        OAuthCredential {
            access_token: "access".to_owned().into(),
            refresh_token: "refresh".to_owned().into(),
            expires_at_ms: None,
            token_url: String::new(),
            client_id: None,
            client_secret: None,
            scopes: Vec::new(),
        },
        b"access".to_vec(),
    )
}

fn deposit(store: &EncryptedStore, record: &VaultRecord) -> String {
    store
        .create_audited(ID, record, AuditCtx::admin(AuditOp::Login))
        .unwrap();
    store.credential_incarnation(ID).unwrap()
}

fn report(
    store: &EncryptedStore,
    incarnation: &str,
    version: u64,
    reason: &str,
    link: Option<&str>,
) -> Result<bool, StoreOpError> {
    store.report_condition_in_incarnation(
        ID,
        version,
        incarnation,
        ConditionReport {
            reason,
            provider_status: 403,
            action_url: link,
        },
        AuditCtx {
            op: AuditOp::ReportCondition,
            actor: ACTOR,
            alarm: None,
        },
        PRINCIPAL,
    )
}

fn clear(store: &EncryptedStore, incarnation: &str, version: u64) -> Result<bool, StoreOpError> {
    store.clear_condition_in_incarnation(
        ID,
        version,
        incarnation,
        AuditCtx {
            op: AuditOp::ClearCondition,
            actor: ACTOR,
            alarm: None,
        },
        PRINCIPAL,
    )
}

fn current(store: &EncryptedStore, incarnation: &str) -> Condition {
    store
        .credential_condition(ID, incarnation)
        .unwrap()
        .unwrap()
}

#[test]
fn condition_action_url_accepts_2048_bytes_and_refuses_2049() {
    let prefix = "https://ACCOUNTS.GOOGLE.COM/";
    let mut link = format!("{prefix}{}", "x".repeat(2048 - prefix.len()));
    check_condition_link(ADAPTER, VERIFY, &link).unwrap();
    link.push('x');
    assert!(matches!(
        check_condition_link(ADAPTER, VERIFY, &link),
        Err(StoreOpError::ConditionLinkRefused)
    ));
}

#[test]
fn condition_report_checks_catalog_then_status_then_link_without_echoing_input() {
    for adapter in [None, Some("google"), Some("anthropic")] {
        assert!(matches!(
            check_condition_report(adapter, VERIFY, 401, Some(LINK)),
            Err(StoreOpError::ConditionNotAdmitted)
        ));
    }
    assert!(matches!(
        check_condition_report(ADAPTER, "future_reason", 401, Some(LINK)),
        Err(StoreOpError::ConditionNotAdmitted)
    ));
    assert!(matches!(
        check_condition_report(ADAPTER, INELIGIBLE, 401, Some(LINK)),
        Err(StoreOpError::ConditionStatusRefused)
    ));
    assert!(matches!(
        check_condition_report(ADAPTER, INELIGIBLE, 403, Some(LINK)),
        Err(StoreOpError::ConditionLinkRefused)
    ));
    check_condition_report(ADAPTER, INELIGIBLE, 403, None).unwrap();
    check_condition_report(ADAPTER, VERIFY, 403, Some(LINK)).unwrap();

    for prefix in [
        "http://accounts.google.com/",
        "HTTPS://accounts.google.com/",
        "https://accounts.google.com.evil.test/",
        "https://a.accounts.google.com/",
        "https://x@accounts.google.com/",
        "https://@accounts.google.com/",
        "https://accounts.google.com:443/",
        "https://accounts.google.com:8443/",
        "https://accounts.google.com/#",
        "https://accounts.google.com/ ",
        "https://accounts.google.com/\t",
        "https://accounts.google.com/é",
        "not a URL",
    ] {
        let link = format!("{prefix}?fixture-private-query");
        let error = check_condition_report(ADAPTER, VERIFY, 403, Some(&link)).unwrap_err();
        assert!(matches!(error, StoreOpError::ConditionLinkRefused));
        assert!(!format!("{error:?} {error}").contains("fixture-private-query"));
    }
}

#[test]
fn condition_reports_replace_only_the_changed_fields_and_emit_outcomes() {
    let (root, store) = rig("condition-outcomes", 201);
    let incarnation = deposit(&store, &login("antigravity"));
    let initial = store.meta(ID).unwrap();
    assert!(report(&store, &incarnation, 1, VERIFY, Some(LINK)).unwrap());
    let set = current(&store, &incarnation);
    assert_eq!(set.reason, VERIFY);
    assert_eq!(set.action_url.as_deref(), Some(LINK));
    assert!(set.since_ms > 0);
    assert!(!format!("{set:?}").contains("fixture-private-query"));
    assert_eq!(
        condition_read_only(&root.join("store.db"), ID, &incarnation).unwrap(),
        Some(set.clone())
    );
    assert!(!report(&store, &incarnation, 1, VERIFY, Some(LINK)).unwrap());
    assert_eq!(current(&store, &incarnation), set);

    // Use a known earlier timestamp so the assertions do not depend on elapsed time.
    store
        .with_raw_conn(|conn| conn.execute("UPDATE credential_conditions SET since_ms = 7", []))
        .unwrap();
    let changed_link = format!("{LINK}-changed");
    assert!(report(&store, &incarnation, 1, VERIFY, Some(&changed_link)).unwrap());
    let changed = current(&store, &incarnation);
    assert_eq!(changed.since_ms, 7);
    assert_eq!(changed.action_url.as_deref(), Some(changed_link.as_str()));
    assert!(!report(&store, &incarnation, 0, INELIGIBLE, None).unwrap());
    assert!(!report(&store, &incarnation, 2, INELIGIBLE, None).unwrap());
    assert_eq!(current(&store, &incarnation), changed);
    assert!(report(&store, &incarnation, 1, INELIGIBLE, None).unwrap());
    let replaced = current(&store, &incarnation);
    assert_eq!(replaced.reason, INELIGIBLE);
    assert_eq!(replaced.action_url, None);
    assert_ne!(replaced.since_ms, 7);
    assert_eq!(store.meta(ID).unwrap(), initial);
    assert_eq!(store.get(ID).unwrap().record_version, 1);
    assert_eq!(
        store
            .with_raw_conn(|conn| conn.query_row(
                "SELECT reporter FROM credential_conditions",
                [],
                |row| row.get::<_, String>(0)
            ))
            .unwrap(),
        ACTOR
    );

    assert!(!clear(&store, &incarnation, 2).unwrap());
    assert_eq!(current(&store, &incarnation), replaced);
    assert!(clear(&store, &incarnation, 1).unwrap());
    assert!(!clear(&store, &incarnation, 1).unwrap());
    assert_eq!(store.credential_condition(ID, &incarnation).unwrap(), None);
    assert_eq!(store.connector_auth_reason(ID).unwrap(), None);

    let audit = store.read_audit(None).unwrap();
    let ops: Vec<_> = audit
        .iter()
        .skip(1)
        .map(|row| {
            (
                row.op.as_str(),
                row.actor.as_str(),
                row.payload_hash.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        ops,
        [
            ("report_condition", ACTOR, None),
            ("report_condition", ACTOR, None),
            ("report_condition", ACTOR, None),
            ("clear_condition", ACTOR, None),
        ]
    );
    assert_eq!(store.verify_audit_chain().unwrap(), None);
    let events = store.recent_auth_events(50).unwrap();
    let outcomes: Vec<_> = events
        .iter()
        .rev()
        .map(|event| {
            assert_eq!(event.detail, None);
            assert_eq!(event.principal_kind.as_deref(), Some("enrolled"));
            assert_eq!(event.principal_id.as_deref(), Some(ACTOR));
            (
                event.kind.as_str(),
                event.record_version.unwrap(),
                event.applied,
                event.provider_status,
            )
        })
        .collect();
    let r = "consumer_report_condition";
    let c = "consumer_clear_condition";
    assert_eq!(
        outcomes,
        [
            (r, 1, true, Some(403)),
            (r, 1, false, Some(403)),
            (r, 1, true, Some(403)),
            (r, 0, false, Some(403)),
            (r, 2, false, Some(403)),
            (r, 1, true, Some(403)),
            (c, 2, false, None),
            (c, 1, true, None),
            (c, 1, false, None),
        ]
    );
}

#[test]
fn condition_report_uses_the_transaction_row_and_refuses_corruption_without_quarantine() {
    let (_root, store) = rig("condition-admission", 202);
    let incarnation = deposit(&store, &login("antigravity"));
    store
        .overwrite_unconditional_audited(ID, &login("google"), AuditCtx::admin(AuditOp::Import))
        .unwrap();
    let audit = store.read_audit(None).unwrap();
    let writes = store.subscribe_writes();
    assert!(matches!(
        report(&store, &incarnation, 2, VERIFY, Some(LINK)),
        Err(StoreOpError::ConditionNotAdmitted)
    ));
    assert!(!writes.has_changed().unwrap());
    assert_eq!(store.read_audit(None).unwrap(), audit);
    assert!(store.recent_auth_events(10).unwrap().is_empty());
    assert_eq!(store.credential_condition(ID, &incarnation).unwrap(), None);
    assert!(
        !clear(&store, &incarnation, 2).unwrap(),
        "clear does not check the adapter"
    );

    store
        .overwrite_unconditional_audited(ID, &api_record(), AuditCtx::admin(AuditOp::Import))
        .unwrap();
    assert!(matches!(
        report(&store, &incarnation, 3, VERIFY, None),
        Err(StoreOpError::ConditionNotAdmitted)
    ));
    store
        .overwrite_unconditional_audited(ID, &login("antigravity"), AuditCtx::admin(AuditOp::Login))
        .unwrap();
    let audit = store.read_audit(None).unwrap();
    let writes = store.subscribe_writes();
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE credentials SET state = 'corrupt' WHERE credential_id = ?1",
                [ID],
            )
        })
        .unwrap();
    assert!(matches!(
        report(&store, &incarnation, 4, VERIFY, None),
        Err(StoreOpError::ConditionNotAdmitted)
    ));
    store.with_raw_conn(|conn| conn.execute("UPDATE credentials SET state = 'active', envelope = X'00' WHERE credential_id = ?1", [ID])).unwrap();
    assert!(matches!(
        report(&store, &incarnation, 4, VERIFY, None),
        Err(StoreOpError::ConditionNotAdmitted)
    ));
    assert_eq!(store.meta(ID).unwrap().state, RecordState::Active);
    assert_eq!(store.credential_condition(ID, &incarnation).unwrap(), None);
    assert_eq!(store.recent_auth_events(10).unwrap().len(), 1);
    assert_eq!(store.read_audit(None).unwrap(), audit);
    assert!(!writes.has_changed().unwrap());
}

#[test]
fn condition_reports_also_apply_on_needs_reauth_and_retired_logins() {
    let (_root, store) = rig("condition-state", 203);
    let incarnation = deposit(&store, &login("antigravity"));
    for (state, reason) in [
        (RecordState::NeedsReauth, VERIFY),
        (RecordState::Retired, INELIGIBLE),
    ] {
        store
            .with_raw_conn(|conn| {
                conn.execute(
                    "UPDATE credentials SET state = ?2 WHERE credential_id = ?1",
                    [ID, state.as_str()],
                )
            })
            .unwrap();
        assert!(report(&store, &incarnation, 1, reason, None).unwrap());
        assert_eq!(store.meta(ID).unwrap().state, state);
        assert!(store.get(ID).is_err());
    }
}

#[test]
fn condition_report_refusals_precede_the_version_fence_and_write_nothing() {
    let (_root, store) = rig("condition-check-order", 211);
    let incarnation = deposit(&store, &login("antigravity"));
    let audit = store.read_audit(None).unwrap();
    let writes = store.subscribe_writes();
    let report = |reason, provider_status, action_url| {
        store.report_condition_in_incarnation(
            ID,
            2,
            &incarnation,
            ConditionReport {
                reason,
                provider_status,
                action_url,
            },
            AuditCtx::vault(AuditOp::ReportCondition),
            PRINCIPAL,
        )
    };
    assert!(matches!(
        report("future_reason", 401, Some(LINK)),
        Err(StoreOpError::ConditionNotAdmitted)
    ));
    assert!(matches!(
        report(INELIGIBLE, 401, Some(LINK)),
        Err(StoreOpError::ConditionStatusRefused)
    ));
    assert!(matches!(
        report(INELIGIBLE, 403, Some(LINK)),
        Err(StoreOpError::ConditionLinkRefused)
    ));
    assert_eq!(store.credential_condition(ID, &incarnation).unwrap(), None);
    assert_eq!(store.read_audit(None).unwrap(), audit);
    assert!(store.recent_auth_events(10).unwrap().is_empty());
    assert!(!writes.has_changed().unwrap());
}

#[test]
fn condition_report_refuses_an_openable_envelope_that_cannot_decode() {
    let (_root, store) = rig("condition-decode", 212);
    let incarnation = deposit(&store, &login("antigravity"));
    let bad_record = envelope::seal(
        &store.key,
        b"not a record",
        &RecordBinding {
            credential_id: ID,
            record_version: 1,
        },
    )
    .unwrap();
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE credentials SET envelope = ?2 WHERE credential_id = ?1",
                rusqlite::params![ID, bad_record],
            )
        })
        .unwrap();
    let audit = store.read_audit(None).unwrap();
    assert!(matches!(
        report(&store, &incarnation, 1, VERIFY, None),
        Err(StoreOpError::ConditionNotAdmitted)
    ));
    assert_eq!(store.meta(ID).unwrap().state, RecordState::Active);
    assert_eq!(store.credential_condition(ID, &incarnation).unwrap(), None);
    assert_eq!(store.read_audit(None).unwrap(), audit);
    assert!(store.recent_auth_events(10).unwrap().is_empty());
}

fn remote() -> NewRemoteRecord {
    NewRemoteRecord {
        credential_id: COPY.into(),
        home_member: HOME.into(),
        refresh_adapter: ADAPTER.map(str::to_owned),
        detected_plan: None,
        identity: RecordIdentity::default(),
        home_version: 1,
        categories: Vec::new(),
    }
}

fn seed_remote_condition(store: &EncryptedStore, incarnation: &str) {
    store.with_raw_conn(|conn| conn.execute(
        "INSERT INTO remote_record_conditions (credential_id, incarnation, reason, since_ms, action_url) VALUES (?1, ?2, ?3, 7, ?4)",
        rusqlite::params![COPY, incarnation, VERIFY, LINK],
    )).unwrap();
}

fn disable_foreign_keys(store: &EncryptedStore) {
    store
        .with_raw_conn(|conn| {
            conn.pragma_update(None, "foreign_keys", "OFF")?;
            assert_eq!(
                conn.pragma_query_value(None, "foreign_keys", |row| row.get::<_, u32>(0))?,
                0
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn condition_lifetime_guard_and_local_removal_ignore_disabled_foreign_keys() {
    let (root, store) = rig("condition-lifetime", 204);
    disable_foreign_keys(&store);
    let original = deposit(&store, &login("antigravity"));
    assert!(report(&store, &original, 1, VERIFY, Some(LINK)).unwrap());
    store
        .remove_audited(ID, AuditCtx::admin(AuditOp::Remove))
        .unwrap();
    assert_eq!(
        store
            .with_raw_conn(|conn| conn.query_row(
                "SELECT COUNT(*) FROM credential_conditions",
                [],
                |r| r.get::<_, u32>(0)
            ))
            .unwrap(),
        0
    );
    let next = deposit(&store, &login("antigravity"));
    assert_ne!(original, next);
    assert_eq!(store.credential_condition(ID, &next).unwrap(), None);
    assert!(report(&store, &next, 1, INELIGIBLE, None).unwrap());
    let before = current(&store, &next);
    let audit = store.read_audit(None).unwrap();
    assert!(matches!(
        report(&store, &original, 1, VERIFY, Some(LINK)),
        Err(StoreOpError::NotFound)
    ));
    assert!(matches!(
        clear(&store, &original, 1),
        Err(StoreOpError::NotFound)
    ));
    assert_eq!(current(&store, &next), before);
    assert_eq!(store.credential_condition(ID, &original).unwrap(), None);
    assert_eq!(store.read_audit(None).unwrap(), audit);
    assert_eq!(store.recent_auth_events(10).unwrap().len(), 1);

    // A side row left by a different incarnation must not appear in either reader.
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE credential_conditions SET incarnation = ?1",
                [&original],
            )
        })
        .unwrap();
    for incarnation in [&original, &next] {
        assert_eq!(store.credential_condition(ID, incarnation).unwrap(), None);
        assert_eq!(
            condition_read_only(&root.join("store.db"), ID, incarnation).unwrap(),
            None
        );
    }
    assert!(!clear(&store, &next, 1).unwrap());
    // A new report replaces the stale child; it does not inherit its earlier date.
    store
        .with_raw_conn(|conn| conn.execute("UPDATE credential_conditions SET since_ms = 7", []))
        .unwrap();
    assert!(report(&store, &next, 1, INELIGIBLE, None).unwrap());
    assert_ne!(current(&store, &next).since_ms, 7);
}

#[test]
fn condition_removed_from_operator_and_watch_copies_with_foreign_keys_off() {
    let (root, store) = rig("condition-copy-removal", 205);
    disable_foreign_keys(&store);
    let copy = store.remote_add_audited(&remote()).unwrap();
    seed_remote_condition(&store, &copy.incarnation);
    let condition = store
        .remote_record_condition(COPY, &copy.incarnation)
        .unwrap()
        .unwrap();
    assert_eq!(condition.action_url.as_deref(), Some(LINK));
    assert_eq!(
        condition_read_only(&root.join("store.db"), COPY, &copy.incarnation).unwrap(),
        Some(condition)
    );
    assert_eq!(
        store
            .remote_record_condition(COPY, "wrong lifetime")
            .unwrap(),
        None
    );
    store.remote_remove_audited(COPY).unwrap();
    let count = || {
        store
            .with_raw_conn(|conn| {
                conn.query_row("SELECT COUNT(*) FROM remote_record_conditions", [], |r| {
                    r.get::<_, u32>(0)
                })
            })
            .unwrap()
    };
    assert_eq!(count(), 0);

    let row = RemoteWatchRow {
        credential_id: COPY.into(),
        state: crate::federation::RemoteHomeState::Active,
        refresh_adapter: ADAPTER.map(str::to_owned),
        identity: RecordIdentity::default(),
        categories: Vec::new(),
        provider_ids: None,
        detected_plan: None,
        home_version: 1,
        condition: None,
    };
    store
        .remote_watch_apply_audited(HOME, "pair", &[row], RemoteWatchApplyMode::Full, &[])
        .unwrap();
    let watched = store.remote_record(COPY).unwrap().unwrap();
    assert_ne!(copy.incarnation, watched.incarnation);
    assert_eq!(
        store
            .remote_record_condition(COPY, &watched.incarnation)
            .unwrap(),
        None
    );
    seed_remote_condition(&store, &watched.incarnation);
    store
        .remote_watch_apply_audited(HOME, "pair", &[], RemoteWatchApplyMode::Full, &[])
        .unwrap();
    assert_eq!(count(), 0);
    assert!(!store
        .read_audit(None)
        .unwrap()
        .iter()
        .any(|row| row.op == "clear_condition"));
}

#[test]
fn condition_readers_and_removals_work_before_the_condition_migration() {
    let (root, sqlite) = sqlite("condition-old-schema", 206);
    migrate_through_for_test(&sqlite, 48).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([206; 32])).unwrap();
    disable_foreign_keys(&store);
    let local = deposit(&store, &login("antigravity"));
    let copy = store.remote_add_audited(&remote()).unwrap();
    assert_eq!(store.credential_condition(ID, &local).unwrap(), None);
    assert_eq!(
        store
            .remote_record_condition(COPY, &copy.incarnation)
            .unwrap(),
        None
    );
    assert_eq!(
        condition_read_only(&root.join("store.db"), ID, &local).unwrap(),
        None
    );
    assert_eq!(
        condition_read_only(&root.join("store.db"), COPY, &copy.incarnation).unwrap(),
        None
    );
    store
        .remove_audited(ID, AuditCtx::admin(AuditOp::Remove))
        .unwrap();
    store.remote_remove_audited(COPY).unwrap();
    assert_eq!(store.with_raw_conn(read_schema_version).unwrap(), 48);
}

#[test]
fn condition_since_ms_storage_accepts_the_largest_safe_integer_and_refuses_the_next() {
    let (_root, store) = rig("condition-time-bounds", 207);
    let incarnation = deposit(&store, &login("antigravity"));
    assert!(report(&store, &incarnation, 1, INELIGIBLE, None).unwrap());
    let copy = store.remote_add_audited(&remote()).unwrap();
    seed_remote_condition(&store, &copy.incarnation);
    store
        .with_raw_conn(|conn| {
            for table in ["credential_conditions", "remote_record_conditions"] {
                let sql = format!("UPDATE {table} SET since_ms = ?1");
                assert_eq!(conn.execute(&sql, [9_007_199_254_740_991_i64])?, 1);
                assert!(conn.execute(&sql, [9_007_199_254_740_992_i64]).is_err());
                assert!(conn.execute(&sql, [-1_i64]).is_err());
                assert!(conn.execute(&sql, [1.5_f64]).is_err());
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(
        current(&store, &incarnation).since_ms,
        MAX_CONDITION_SINCE_MS
    );
    assert_eq!(
        store
            .remote_record_condition(COPY, &copy.incarnation)
            .unwrap()
            .unwrap()
            .since_ms,
        MAX_CONDITION_SINCE_MS
    );
}

#[test]
fn condition_migration_installs_both_cascades() {
    let (_root, store) = rig("condition-cascades", 213);
    let incarnation = deposit(&store, &login("antigravity"));
    assert!(report(&store, &incarnation, 1, INELIGIBLE, None).unwrap());
    let copy = store.remote_add_audited(&remote()).unwrap();
    seed_remote_condition(&store, &copy.incarnation);
    store
        .with_raw_conn(|conn| {
            conn.pragma_update(None, "foreign_keys", "ON")?;
            assert_eq!(
                conn.pragma_query_value(None, "foreign_keys", |row| row.get::<_, u32>(0))?,
                1
            );
            for (parent, child, id) in [
                ("credentials", "credential_conditions", ID),
                ("remote_records", "remote_record_conditions", COPY),
            ] {
                assert_eq!(
                    conn.execute(
                        &format!("DELETE FROM {parent} WHERE credential_id = ?1"),
                        [id]
                    )?,
                    1
                );
                assert_eq!(
                    conn.query_row(&format!("SELECT COUNT(*) FROM {child}"), [], |row| row
                        .get::<_, u32>(0))?,
                    0
                );
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn condition_operator_clear_only_changes_a_local_condition_and_names_the_operator() {
    let (_root, store) = rig("condition-operator", 208);
    let ctx = AuditCtx::route_admin(AuditOp::ClearCondition, "operator-fixture");
    let unknown = store.clear_condition_audited(ID, ctx).unwrap_err();
    assert!(matches!(unknown, StoreOpError::NotFound));
    assert_eq!(unknown.to_string(), "credential not found");
    let copy = store.remote_add_audited(&remote()).unwrap();
    seed_remote_condition(&store, &copy.incarnation);
    let home_owned = store.clear_condition_audited(COPY, ctx).unwrap_err();
    assert_eq!(home_owned.wire_code(), Some("condition_home_owned"));
    assert_eq!(home_owned.wire_class(), Some("permanent"));
    assert!(store
        .remote_record_condition(COPY, &copy.incarnation)
        .unwrap()
        .is_some());

    let local = deposit(&store, &login("antigravity"));
    assert!(!store.clear_condition_audited(ID, ctx).unwrap());
    assert!(report(&store, &local, 1, INELIGIBLE, None).unwrap());
    let before = store.read_audit(None).unwrap();
    assert!(store.clear_condition_audited(ID, ctx).unwrap());
    assert!(!store.clear_condition_audited(ID, ctx).unwrap());
    assert_eq!(store.credential_condition(ID, &local).unwrap(), None);
    let after = store.read_audit(None).unwrap();
    let [entry] = &after[before.len()..] else {
        panic!("expected one operator audit row")
    };
    assert_eq!(entry.op, "clear_condition");
    assert_eq!(entry.actor, "operator-fixture");
    assert_eq!(entry.payload_hash, None);
    assert_eq!(store.recent_auth_events(10).unwrap().len(), 1);
}

#[test]
fn condition_person_material_clears_atomically_but_refresh_and_failed_replace_keep_it() {
    let (_root, store) = rig("condition-material", 209);
    let record = login("antigravity");
    let incarnation = deposit(&store, &record);
    assert!(report(&store, &incarnation, 1, INELIGIBLE, None).unwrap());
    let before = current(&store, &incarnation);
    store
        .open_intent(ID, 1, &refresh_token_hash("refresh"))
        .unwrap();
    assert_eq!(
        store
            .commit_refresh(
                ID,
                1,
                &store.credential_incarnation(ID).unwrap(),
                &record,
                None
            )
            .unwrap(),
        2
    );
    assert_eq!(current(&store, &incarnation), before);

    store.with_raw_conn(|conn| conn.execute_batch("CREATE TRIGGER reject_login BEFORE INSERT ON audit_log WHEN NEW.op = 'login' BEGIN SELECT RAISE(ABORT, 'login audit failed'); END")).unwrap();
    let audit = store.read_audit(None).unwrap();
    let login_ctx = AuditCtx::admin(AuditOp::Login);
    assert!(store
        .overwrite_unconditional_audited(ID, &record, login_ctx)
        .is_err());
    assert_eq!(current(&store, &incarnation), before);
    assert_eq!(store.meta(ID).unwrap().record_version, 2);
    assert_eq!(store.read_audit(None).unwrap(), audit);
    store
        .with_raw_conn(|conn| conn.execute_batch("DROP TRIGGER reject_login"))
        .unwrap();

    store
        .overwrite_unconditional_audited(ID, &record, login_ctx)
        .unwrap();
    assert_eq!(store.credential_condition(ID, &incarnation).unwrap(), None);
    assert!(report(&store, &incarnation, 3, INELIGIBLE, None).unwrap());
    store
        .overwrite_unconditional_audited(ID, &record, AuditCtx::admin(AuditOp::Import))
        .unwrap();
    assert_eq!(store.credential_condition(ID, &incarnation).unwrap(), None);

    assert!(report(&store, &incarnation, 4, INELIGIBLE, None).unwrap());
    assert!(matches!(
        store.overwrite_cas_audited(ID, &record, &[0; 32], AuditCtx::admin(AuditOp::Overwrite)),
        Err(StoreOpError::CasMismatch)
    ));
    assert_eq!(current(&store, &incarnation).reason, INELIGIBLE);
    store
        .overwrite_cas_audited(
            ID,
            &record,
            &payload_hash(record.payload.expose()),
            AuditCtx::admin(AuditOp::Overwrite),
        )
        .unwrap();
    assert_eq!(store.credential_condition(ID, &incarnation).unwrap(), None);
    let after = store.read_audit(None).unwrap();
    assert_eq!(
        after[audit.len()..]
            .iter()
            .map(|row| row.op.as_str())
            .collect::<Vec<_>>(),
        [
            "login",
            "report_condition",
            "import",
            "report_condition",
            "overwrite"
        ]
    );
}

#[test]
fn condition_transactions_roll_back_when_their_diagnostic_fails() {
    let (_root, store) = rig("condition-rollback", 210);
    let incarnation = deposit(&store, &login("antigravity"));
    let audit = store.read_audit(None).unwrap();
    store.with_raw_conn(|conn| conn.execute_batch("CREATE TRIGGER reject_event BEFORE INSERT ON auth_events BEGIN SELECT RAISE(ABORT, 'diagnostic failed'); END")).unwrap();
    assert!(report(&store, &incarnation, 1, INELIGIBLE, None).is_err());
    assert_eq!(store.credential_condition(ID, &incarnation).unwrap(), None);
    assert_eq!(store.read_audit(None).unwrap(), audit);
    store
        .with_raw_conn(|conn| conn.execute_batch("DROP TRIGGER reject_event"))
        .unwrap();
    assert!(report(&store, &incarnation, 1, INELIGIBLE, None).unwrap());

    let before = current(&store, &incarnation);
    let audit = store.read_audit(None).unwrap();
    store.with_raw_conn(|conn| conn.execute_batch("CREATE TRIGGER reject_event BEFORE INSERT ON auth_events BEGIN SELECT RAISE(ABORT, 'diagnostic failed'); END")).unwrap();
    assert!(clear(&store, &incarnation, 1).is_err());
    assert_eq!(current(&store, &incarnation), before);
    assert_eq!(store.read_audit(None).unwrap(), audit);
    assert_eq!(store.recent_auth_events(10).unwrap().len(), 1);
}
