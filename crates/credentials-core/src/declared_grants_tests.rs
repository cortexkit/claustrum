use super::*;
use crate::store::taxonomy_tests::{api_record, rig, sqlite};
use serde_json::json;

fn parse(entries: serde_json::Value) -> (DeclaredGrantSet, DeclarationDiagnostics) {
    parse_declared_grants("striatum", &json!({"v": 1, "grants": entries}))
}

#[test]
fn declaration_skips_whole_entries_before_hand_grant_validation() {
    let (set, diagnostics) = parse(json!([
        {"category":"llm-provider","operation":"read","only":"x"},
        {"category":"llm-provider","operation":"unknown"},
        {"category":"llm-provider","operation":"sign"},
        {"category":"llm-provider","operation":"open"},
        {"category":"llm-provider","operation":"seal"},
        {"exact":"apikey:anthropic","operation":"read"},
        {"category":"llm-provider","operation":"deposit"},
        {"category":"llm-provider","operation":"account_token"},
        {"audience":"unrecognized","operation":"account_token"},
        {"audience":"cortexkit-account","operation":"read"},
        {"category":7,"operation":"read"},
        {"category":"llm-provider","operation":7},
        {"category":"Not Valid","operation":"read"},
        {"category":"llm-provider","audience":"cortexkit-account","operation":"read"},
        null,
        {"category":"llm-provider","operation":"read"},
        {"category":"browser-session","operation":"deposit"},
        {"audience":"cortexkit-account","operation":"account_token"}
    ]));
    assert_eq!(set.grants().len(), 3);
    assert_eq!(diagnostics.whole_reason, None);
    assert_eq!(diagnostics.skipped_count, 15);
    assert_eq!(
        diagnostics
            .skipped
            .iter()
            .map(|skip| (skip.index, skip.reason))
            .collect::<Vec<_>>(),
        vec![
            (0, "field"),
            (1, "operation"),
            (2, "operation"),
            (3, "operation"),
            (4, "operation"),
            (5, "selector"),
            (6, "tuple"),
            (7, "operation"),
            (8, "audience"),
            (9, "operation"),
            (10, "selector"),
            (11, "operation"),
            (12, "tuple"),
            (13, "field"),
            (14, "entry")
        ]
    );
    for audience in ACCOUNT_TOKEN_AUDIENCES {
        let (grants, diagnostics) =
            parse(json!([{"audience":audience,"operation":"account_token"}]));
        assert_eq!(grants.grants().len(), 1);
        assert_eq!(diagnostics, DeclarationDiagnostics::default());
    }
    let (_, invalid_module) = parse_declared_grants(
        "bad|module",
        &json!({"v":1,"grants":[
            {"category":"llm-provider","operation":"read"}
        ]}),
    );
    assert_eq!(invalid_module.skipped[0].reason, "tuple");
}

#[test]
fn declaration_json_is_compact_text_sorted_and_deduplicated() {
    let (set, diagnostics) = parse_declared_grants(
        "striatum",
        &json!({
            "v":1,"future_top_level":true,"grants":[
                {"category":"llm-provider","operation":"read"},
                {"category":"llm-provider","operation":"list"},
                {"category":"browser-session","operation":"deposit"},
                {"category":"llm-provider","operation":"read"},
                {"audience":"cortexkit-runners","operation":"account_token"}
            ]
        }),
    );
    assert_eq!(diagnostics, DeclarationDiagnostics::default());
    assert_eq!(set.grants_json(), concat!(
        "[{\"selector_kind\":\"audience\",\"selector\":\"cortexkit-runners\",\"operation\":\"account_token\"},",
        "{\"selector_kind\":\"category\",\"selector\":\"browser-session\",\"operation\":\"deposit\"},",
        "{\"selector_kind\":\"category\",\"selector\":\"llm-provider\",\"operation\":\"list\"},",
        "{\"selector_kind\":\"category\",\"selector\":\"llm-provider\",\"operation\":\"read\"}]"
    ));
    assert_eq!(
        DeclaredGrantSet::from_grants_json("striatum", &set.grants_json()).unwrap(),
        set
    );
}

#[test]
fn declaration_accepts_32_raw_entries_and_rejects_33_before_deduplication() {
    let entry = json!({"category":"llm-provider","operation":"read"});
    let (accepted, diagnostics) = parse(json!(vec![entry.clone(); 32]));
    assert_eq!(accepted.grants().len(), 1);
    assert_eq!(diagnostics, DeclarationDiagnostics::default());
    let (refused, diagnostics) = parse(json!(vec![entry; 33]));
    assert_eq!(refused.grants_json(), "[]");
    assert_eq!(diagnostics.whole_reason, Some("entry_count"));
    assert_eq!(diagnostics.skipped_count, 33);
    assert!(diagnostics.skipped.is_empty());
}

#[test]
fn declaration_rejects_unknown_version_and_non_array_grants_without_partial_authority() {
    for (value, reason, count) in [
        (
            json!({"v":2,"grants":[{"category":"llm-provider","operation":"read"}]}),
            "version",
            1,
        ),
        (json!({"v":1,"grants":{}}), "grants", 0),
        (json!({"v":1}), "grants", 0),
        (json!({"v":"1","grants":[]}), "version", 0),
        (json!({"grants":[]}), "version", 0),
    ] {
        let (set, diagnostics) = parse_declared_grants("striatum", &value);
        assert_eq!(set.grants_json(), "[]");
        assert_eq!(diagnostics.whole_reason, Some(reason));
        assert_eq!(diagnostics.skipped_count, count);
    }
    assert_eq!(parse(json!([])).1, DeclarationDiagnostics::default());
}

fn seen_count(store: &EncryptedStore) -> i64 {
    store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT count(*) FROM audit_log WHERE op='declaration_seen'",
                [],
                |row| row.get(0),
            )
        })
        .unwrap()
}

#[test]
fn declaration_change_key_and_clear_are_atomic_audited_and_restart_stable() {
    let (root, store) = rig("declaration-seen", 221);
    let (grants, _) = parse(json!([{"category":"llm-provider","operation":"read"}]));
    let write = |digest, approval, origin| {
        store
            .record_declared_grants_seen("striatum", digest, approval, origin, &grants, 0)
            .unwrap()
    };
    assert!(!write(None, None, None));
    assert!(write(Some("digest-a"), Some("approval-a"), Some("release")));
    assert_eq!(seen_count(&store), 1);
    store
        .with_raw_conn(|conn| {
            conn.execute("UPDATE declared_grant_sets SET first_seen_ms=123", [])
                .map(|_| ())
        })
        .unwrap();
    assert!(!write(
        Some("digest-a"),
        Some("approval-b"),
        Some("development")
    ));
    let record = store.list_declared_grant_sets().unwrap().rows.remove(0);
    assert_eq!(record.first_seen_ms, 123);
    assert_eq!(
        record.approved_declarations_digest.as_deref(),
        Some("approval-a")
    );
    assert_eq!(record.origin.as_deref(), Some("release"));
    assert_eq!(seen_count(&store), 1);
    let audit: (String, String, String) = store
        .with_raw_conn(|conn| {
            conn.query_row(
        "SELECT actor,credential_id,payload_hash FROM audit_log WHERE op='declaration_seen'",
        [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    )
        })
        .unwrap();
    assert_eq!(audit.0, "reserved:striatum");
    assert_eq!(audit.1, "declaration|digest-a");
    assert_eq!(
        audit.2,
        format!(
            "{:x}",
            Sha256::digest(record.grants.grants_json().as_bytes())
        )
    );
    assert!(write(Some("digest-b"), None, None));
    assert_eq!(seen_count(&store), 2);
    let (other, _) = parse(json!([{"category":"llm-provider","operation":"list"}]));
    assert!(store
        .record_declared_grants_seen("striatum", Some("digest-b"), None, None, &other, 0)
        .unwrap());
    assert_eq!(seen_count(&store), 3);
    assert!(store.list_read_grants().unwrap().is_empty());
    assert_eq!(store.verify_audit_chain().unwrap(), None);
    drop(store);

    use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
    let sqlite = open_sqlite(&StorageDescriptor {
        module_id: "claustrum".into(),
        storage_namespace: "taxonomy-declaration-seen".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: root.join("store.db").to_string_lossy().into_owned(),
        },
    })
    .unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([221; 32])).unwrap();
    assert!(!store
        .record_declared_grants_seen("striatum", Some("digest-b"), None, None, &other, 0)
        .unwrap());
    assert_eq!(seen_count(&store), 3);
    assert!(store
        .record_declared_grants_seen("striatum", None, Some("approval-c"), None, &grants, 9)
        .unwrap());
    let cleared = store.list_declared_grant_sets().unwrap().rows.remove(0);
    assert_eq!(cleared.declaration_digest, None);
    assert_eq!(cleared.grants.grants_json(), "[]");
    assert_eq!(cleared.skipped_count, 0);
    assert_eq!(seen_count(&store), 4);
    assert!(!store
        .record_declared_grants_seen("striatum", None, None, None, &grants, 0)
        .unwrap());
    let hash: String = store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT payload_hash FROM audit_log WHERE credential_id='declaration|none'",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(
        hash,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
    );
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn declaration_rejections_persist_empty_sets_and_inventory_skips_corruption() {
    let (root, store) = rig("declaration-inventory", 222);
    let (set, diagnostics) = parse_declared_grants("striatum", &json!({"v":2,"grants":[{},{}]}));
    store
        .record_declared_grants_seen(
            "striatum",
            Some("bad-version"),
            None,
            None,
            &set,
            diagnostics.skipped_count,
        )
        .unwrap();
    let listing = declared_grant_sets_read_only(&root.join("store.db")).unwrap();
    assert!(!listing.incomplete);
    assert_eq!(listing.rows[0].grants.grants_json(), "[]");
    assert_eq!(listing.rows[0].skipped_count, 2);
    for invalid in [
        "not-json",
        r#"[{"selector_kind":"category","selector":"llm-provider","operation":"sign"}]"#,
        r#"[{"selector_kind":"audience","selector":"unknown","operation":"account_token"}]"#,
        r#"[{"selector_kind":"category","selector":"llm-provider","operation":"read","only":"x"}]"#,
    ] {
        store
            .with_raw_conn(|conn| {
                conn.execute("UPDATE declared_grant_sets SET grants_json=?1", [invalid])
                    .map(|_| ())
            })
            .unwrap();
        let listing = store.list_declared_grant_sets().unwrap();
        assert!(listing.incomplete);
        assert!(listing.rows.is_empty());
        assert_eq!(
            declared_grant_sets_read_only(&root.join("store.db")).unwrap(),
            listing
        );
    }
    assert!(store.list_read_grants().unwrap().is_empty());
    let (root, sqlite) = sqlite("declaration-old-inventory", 223);
    migrate_through_for_test(&sqlite, 44).unwrap();
    assert_eq!(
        declared_grant_sets_read_only(&root.join("store.db")).unwrap(),
        DeclaredGrantListing::default()
    );
}

#[test]
fn declaration_seen_rolls_back_the_row_when_audit_fails_and_retries() {
    let (_root, store) = rig("declaration-rollback", 224);
    let (grants, _) = parse(json!([{"category":"llm-provider","operation":"read"}]));
    store
        .with_raw_conn(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER refuse_declaration_audit BEFORE INSERT ON audit_log \
         WHEN NEW.op='declaration_seen' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;",
            )
        })
        .unwrap();
    assert!(store
        .record_declared_grants_seen("striatum", Some("a"), None, None, &grants, 0)
        .is_err());
    assert!(store.list_declared_grant_sets().unwrap().rows.is_empty());
    assert_eq!(seen_count(&store), 0);
    store
        .with_raw_conn(|conn| conn.execute_batch("DROP TRIGGER refuse_declaration_audit;"))
        .unwrap();
    assert!(store
        .record_declared_grants_seen("striatum", Some("a"), None, None, &grants, 0)
        .unwrap());
    store
        .with_raw_conn(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER refuse_declaration_write BEFORE UPDATE ON declared_grant_sets \
         BEGIN SELECT RAISE(ABORT,'inventory unavailable'); END;",
            )
        })
        .unwrap();
    assert!(store
        .record_declared_grants_seen("striatum", Some("b"), None, None, &grants, 0)
        .is_err());
    assert_eq!(seen_count(&store), 1);
    assert_eq!(
        store.list_declared_grant_sets().unwrap().rows[0]
            .declaration_digest
            .as_deref(),
        Some("a")
    );
    store
        .with_raw_conn(|conn| conn.execute_batch("DROP TABLE declared_grant_sets;"))
        .unwrap();
    assert!(store
        .record_declared_grants_seen("striatum", Some("b"), None, None, &grants, 0)
        .is_err());
    assert_eq!(seen_count(&store), 1);
}

#[test]
fn declaration_union_covers_local_remote_audience_and_only_the_bound_reserved_principal() {
    let (_root, store) = rig("declaration-union", 225);
    let id = "apikey:anthropic";
    store
        .create_audited(id, &api_record(), AuditCtx::admin(AuditOp::Put))
        .unwrap();
    let remote = "oauth:anthropic:declaration";
    store
        .remote_add_audited(&crate::federation::NewRemoteRecord {
            credential_id: remote.into(),
            home_member: "fed-computer:0123456789abcdef0123456789abcdef".into(),
            refresh_adapter: Some("anthropic".into()),
            detected_plan: None,
            identity: crate::record::RecordIdentity::default(),
            home_version: 1,
            categories: vec!["llm-provider".into()],
        })
        .unwrap();
    let (grants, _) = parse(json!([
        {"category":"llm-provider","operation":"read"},
        {"audience":"cortexkit-runners","operation":"account_token"}
    ]));
    let empty = DeclaredGrantSet::empty();
    for target in [id, remote] {
        assert!(
            !store
                .evaluate_scoped_coverage(
                    "reserved",
                    "striatum",
                    target,
                    GrantOperation::Read,
                    &empty
                )
                .unwrap()
                .covered
        );
        let covered = store
            .evaluate_scoped_coverage(
                "reserved",
                "striatum",
                target,
                GrantOperation::Read,
                &grants,
            )
            .unwrap();
        assert!(covered.covered);
        assert_eq!(covered.caller_active_grants, 1);
        assert!(covered.id_exists);
        for (kind, principal) in [("reserved", "other"), ("enrolled", "striatum")] {
            assert!(
                !store
                    .evaluate_scoped_coverage(
                        kind,
                        principal,
                        target,
                        GrantOperation::Read,
                        &grants
                    )
                    .unwrap()
                    .covered
            );
            assert!(store
                .list_scoped_snapshot(kind, principal, &grants)
                .unwrap()
                .grants
                .is_empty());
        }
        for operation in [
            GrantOperation::Sign,
            GrantOperation::Open,
            GrantOperation::Seal,
        ] {
            assert!(
                !store
                    .evaluate_scoped_coverage("reserved", "striatum", target, operation, &grants)
                    .unwrap()
                    .covered
            );
        }
    }
    assert!(
        store
            .evaluate_scoped_coverage(
                "reserved",
                "striatum",
                "cortexkit-runners",
                GrantOperation::AccountToken,
                &grants
            )
            .unwrap()
            .covered
    );
    assert!(
        !store
            .evaluate_scoped_coverage(
                "reserved",
                "striatum",
                "cortexkit-account",
                GrantOperation::AccountToken,
                &grants
            )
            .unwrap()
            .covered
    );
    let declared = store
        .list_scoped_snapshot("reserved", "striatum", &grants)
        .unwrap();
    assert_eq!(
        declared
            .rows
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        vec![id]
    );
    assert!(declared
        .rows
        .iter()
        .all(|row| row.operations == [GrantOperation::Read]));
    assert!(store.list_read_grants().unwrap().is_empty());
    store
        .create_read_grant_audited(
            "reserved",
            "striatum",
            SelectorKind::Category,
            "llm-provider",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let union = store
        .list_scoped_snapshot("reserved", "striatum", &grants)
        .unwrap();
    assert_eq!(union.rows, declared.rows);
    assert_eq!(union.grants.len(), 2);
    assert_eq!(
        store
            .evaluate_scoped_coverage("reserved", "striatum", id, GrantOperation::Read, &grants)
            .unwrap()
            .caller_active_grants,
        1
    );
    assert_eq!(
        store
            .watch_scoped_snapshot("reserved", "striatum", &grants)
            .unwrap()
            .0,
        union
    );
}

#[test]
fn declaration_deposit_union_keeps_the_existing_row_projection() {
    let (_root, store) = rig("declaration-deposit", 226);
    let (grants, _) = parse(json!([{"category":"browser-session","operation":"deposit"}]));
    let id = "cookie:ollama.com:declaration";
    store
        .create_audited(
            id,
            &VaultRecord::new_cookie("session", b"cookie".to_vec()),
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
    let declared = store
        .list_scoped_snapshot("reserved", "striatum", &grants)
        .unwrap();
    assert!(declared.rows.is_empty());
    assert_eq!(declared.grants.len(), 1);
    assert!(
        store
            .evaluate_scoped_coverage("reserved", "striatum", id, GrantOperation::Deposit, &grants)
            .unwrap()
            .covered
    );
    assert!(
        !store
            .evaluate_scoped_coverage(
                "reserved",
                "striatum",
                "apikey:anthropic",
                GrantOperation::Deposit,
                &grants
            )
            .unwrap()
            .covered
    );
    store
        .create_read_grant_audited(
            "reserved",
            "striatum",
            SelectorKind::Category,
            "browser-session",
            GrantOperation::Deposit,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let hand = store
        .list_scoped_snapshot("reserved", "striatum", &DeclaredGrantSet::empty())
        .unwrap();
    let union = store
        .list_scoped_snapshot("reserved", "striatum", &grants)
        .unwrap();
    assert_eq!(union, hand);
    assert_eq!(union.rows, declared.rows);
    assert_eq!(union.grants.len(), declared.grants.len());
}
