use super::*;
use crate::store::taxonomy_tests::{api_record, rig, sqlite};
use serde_json::json;

fn parse(entries: serde_json::Value) -> (DeclaredGrantSet, DeclarationDiagnostics) {
    parse_declared_grants("striatum", &json!({"v": 1, "grants": entries}))
}

#[test]
fn declared_grant_approval_wording_formats_admitted_grants_and_unknown_categories() {
    let (set, diagnostics) = parse(json!([
        {"category":"llm-provider","operation":"read"},
        {"category":"llm-provider","operation":"list"},
        {"category":"browser-session","operation":"deposit"},
        {"audience":"cortexkit-runners","operation":"account_token"},
        {"category":"custom-native","operation":"read"},
        {"category":"embedding-provider","operation":"read"},
        {"category":"embedding-provider","operation":"list"}
    ]));
    assert_eq!(diagnostics, DeclarationDiagnostics::default());
    assert_eq!(
        set.grants()
            .iter()
            .map(|grant| declared_grant_approval_sentence(grant).unwrap())
            .collect::<Vec<_>>(),
        vec![
            "Get short-lived CortexKit account tokens for cortexkit-runners",
            "Save browser sign-ins into the vault (browser sign-in)",
            "Read your custom-native logins and keys",
            "See which embedding models logins and keys exist (no secrets)",
            "Read your embedding models logins and keys",
            "See which model provider logins and keys exist (no secrets)",
            "Read your model provider logins and keys",
        ]
    );
    for (selector_kind, operation) in [
        (SelectorKind::Exact, GrantOperation::Read),
        (SelectorKind::Category, GrantOperation::Sign),
        (SelectorKind::Category, GrantOperation::Open),
        (SelectorKind::Category, GrantOperation::Seal),
        (SelectorKind::Category, GrantOperation::AccountToken),
        (SelectorKind::Audience, GrantOperation::Read),
    ] {
        assert_eq!(
            declared_grant_approval_sentence(&DeclaredGrant {
                selector_kind,
                selector: "llm-provider".into(),
                operation,
            }),
            None,
        );
    }
}

#[test]
fn declared_grant_approval_wording_matches_wire_contract_tables() {
    fn table(section: &str, header: &str) -> Vec<(String, String)> {
        let mut lines = section.lines().skip_while(|line| *line != header);
        assert_eq!(lines.next(), Some(header), "missing approval table");
        assert_eq!(lines.next(), Some("|---|---|"));
        lines
            .take_while(|line| line.starts_with('|'))
            .map(|line| {
                let cells: Vec<_> = line
                    .strip_prefix('|')
                    .unwrap()
                    .strip_suffix('|')
                    .unwrap()
                    .split('|')
                    .map(|cell| cell.trim().replace("&lt;", "<").replace("&gt;", ">"))
                    .collect();
                assert_eq!(cells.len(), 2, "approval tables have exactly two columns");
                (cells[0].clone(), cells[1].clone())
            })
            .collect()
    }

    let contract = include_str!("../../../docs/wire-contract-v1.md");
    let section: String = contract
        .split_once("#### Approval wording\n")
        .expect("approval wording heading")
        .1
        .lines()
        .take_while(|line| !line.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let templates = table(&section, "| Declarable shape | Vault text |");
    assert_eq!(
        templates,
        DECLARED_GRANT_APPROVAL_TEMPLATES
            .iter()
            .map(|(shape, template)| (shape.to_string(), template.to_string()))
            .collect::<Vec<_>>(),
        "approval templates differ between code and the wire contract",
    );
    let names: Vec<_> = table(&section, "| Category | Plain name |")
        .into_iter()
        .map(|(category, name)| {
            let category = category
                .strip_prefix('`')
                .and_then(|category| category.strip_suffix('`'))
                .expect("category name in backticks")
                .to_string();
            (category, name)
        })
        .collect();
    assert_eq!(
        names,
        DECLARED_GRANT_CATEGORY_NAMES
            .iter()
            .map(|(category, name)| (category.to_string(), name.to_string()))
            .collect::<Vec<_>>(),
        "category names differ between code and the wire contract",
    );
}

#[test]
fn declared_grant_catalog_categories_have_plain_names() {
    for category in crate::catalog::CredentialCategory::ALL {
        let names: Vec<_> = DECLARED_GRANT_CATEGORY_NAMES
            .iter()
            .filter(|(name, _)| *name == category.as_str())
            .collect();
        assert_eq!(
            names.len(),
            1,
            "{} needs exactly one plain name",
            category.as_str()
        );
        assert!(
            !names[0].1.is_empty(),
            "{} needs a plain name",
            category.as_str()
        );
    }
}

fn declared_grants_vectors() -> serde_json::Value {
    let declarations = [
        (
            "valid-mixed",
            json!({"v":1,"grants":[
                {"category":"llm-provider","operation":"read"},
                {"category":"llm-provider","operation":"list"},
                {"category":"browser-session","operation":"deposit"},
                {"audience":"cortexkit-runners","operation":"account_token"}
            ]}),
        ),
        (
            "unknown-entry-field",
            json!({"v":1,"grants":[
                {"category":"llm-provider","operation":"read","only":"x"}
            ]}),
        ),
        (
            "unknown-operation",
            json!({"v":1,"grants":[
                {"category":"llm-provider","operation":"unknown"}
            ]}),
        ),
        (
            "category-sign",
            json!({"v":1,"grants":[
                {"category":"llm-provider","operation":"sign"}
            ]}),
        ),
        (
            "exact-selector",
            json!({"v":1,"grants":[
                {"exact":"apikey:anthropic","operation":"read"}
            ]}),
        ),
        (
            "non-browser-deposit",
            json!({"v":1,"grants":[
                {"category":"llm-provider","operation":"deposit"}
            ]}),
        ),
        (
            "unknown-audience",
            json!({"v":1,"grants":[
                {"audience":"unrecognized","operation":"account_token"}
            ]}),
        ),
        (
            "duplicates",
            json!({"v":1,"grants":[
                {"category":"llm-provider","operation":"read"},
                {"category":"llm-provider","operation":"list"},
                {"category":"llm-provider","operation":"read"}
            ]}),
        ),
        (
            "unsupported-version",
            json!({"v":2,"grants":[
                {"category":"llm-provider","operation":"read"}
            ]}),
        ),
        (
            "too-many-entries",
            json!({"v":1,"grants":vec![
                json!({"category":"llm-provider","operation":"read"}); 33
            ]}),
        ),
        ("missing-grants", json!({"v":1})),
        (
            "ignored-top-level-field",
            json!({"v":1,"future_top_level":true,"grants":[
                {"category":"llm-provider","operation":"read"}
            ]}),
        ),
        ("empty-grants", json!({"v":1,"grants":[]})),
        (
            "raw-category-name",
            json!({"v":1,"grants":[
                {"category":"custom-native","operation":"read"}
            ]}),
        ),
    ];
    let module_id = "striatum";
    let cases: Vec<_> = declarations
        .into_iter()
        .map(|(case, declaration)| {
            let (set, diagnostics) = parse_declared_grants(module_id, &declaration);
            let skipped: Vec<_> = diagnostics
                .skipped
                .iter()
                .map(|skip| json!({"index":skip.index,"reason":skip.reason}))
                .collect();
            // Sentences zip with the admitted grants, not the original declaration entries.
            let approval_sentences: Vec<_> = set
                .grants()
                .iter()
                .map(|grant| {
                    declared_grant_approval_sentence(grant).expect("admitted grant wording")
                })
                .collect();
            json!({
                "case":case,
                "declaration":declaration,
                "module_id":module_id,
                "grants_json":set.grants_json(),
                "skipped":skipped,
                "whole_reason":diagnostics.whole_reason,
                "skipped_count":diagnostics.skipped_count,
                "approval_sentences":approval_sentences,
            })
        })
        .collect();
    let templates: Vec<_> = DECLARED_GRANT_APPROVAL_TEMPLATES
        .iter()
        .map(|(shape, template)| json!({"shape":shape,"template":template}))
        .collect();
    let category_names: Vec<_> = DECLARED_GRANT_CATEGORY_NAMES
        .iter()
        .map(|(category, plain_name)| json!({"category":category,"plain_name":plain_name}))
        .collect();
    json!({"version":2,"templates":templates,"category_names":category_names,"cases":cases})
}

#[test]
fn declared_grants_v1_vectors_still_render_from_live_parser_and_wording() {
    let emitted = declared_grants_vectors();
    let expected: serde_json::Value =
        serde_json::from_slice(include_bytes!("../tests/vectors/declared-grants-v1.json")).unwrap();
    assert_eq!(expected["version"], 1);
    // The published v1 category table is historical; its cases and wording remain live checks.
    assert_eq!(emitted["templates"], expected["templates"]);
    assert_eq!(emitted["cases"], expected["cases"]);
}

#[test]
fn declared_grants_v2_vectors_are_emitted_by_parser_and_wording_code_and_pinned() {
    use sha2::{Digest, Sha256};

    let emitted = declared_grants_vectors();
    let bytes = serde_json::to_vec_pretty(&emitted).unwrap();
    let pinned = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/declared-grants-v2.json");
    let sums_path = pinned.with_file_name("declared-grants-v2.SHA256SUMS");
    let sums = format!("{:x}  declared-grants-v2.json\n", Sha256::digest(&bytes));
    if std::env::var_os("CK_EMIT_SECRET_VECTORS").is_some() {
        std::fs::create_dir_all(pinned.parent().unwrap()).unwrap();
        std::fs::write(&pinned, bytes).unwrap();
        std::fs::write(&sums_path, &sums).unwrap();
        println!("emitted 14 declared-grant parser and approval wording cases with the live category table");
    } else {
        let expected = std::fs::read(&pinned).expect("pinned declared-grant vectors");
        assert_eq!(
            bytes, expected,
            "vault-emitted declared-grant vectors changed"
        );
        assert_eq!(std::fs::read_to_string(&sums_path).unwrap(), sums);
    }
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
    for audience in [
        "cortexkit-runners",
        "cortexkit-account",
        "cortexkit-webhook-relay",
    ] {
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
fn hub_audience_declarations_admit_only_ckbus_and_skip_without_losing_other_grants() {
    let (_root, store) = rig("hub-audience-declarations", 228);
    let declaration = json!({"v":1,"grants":[
        {"audience":"cortexkit-hub","operation":"account_token"},
        {"audience":"cortexkit-account","operation":"account_token"}
    ]});
    let (bus, diagnostics) = parse_declared_grants("ckbus", &declaration);
    assert_eq!(bus.grants().len(), 2);
    assert_eq!(diagnostics, DeclarationDiagnostics::default());
    assert!(store
        .read_grant_covers(
            "reserved",
            "ckbus",
            "cortexkit-hub",
            GrantOperation::AccountToken,
            &bus,
        )
        .unwrap());
    assert_eq!(
        DeclaredGrantSet::from_grants_json("ckbus", &bus.grants_json()).unwrap(),
        bus
    );
    for module in ["motor", "striatum", "CKBUS"] {
        let (other, diagnostics) = parse_declared_grants(module, &declaration);
        assert_eq!(diagnostics.whole_reason, None);
        assert_eq!(diagnostics.skipped_count, 1);
        assert_eq!(
            diagnostics.skipped,
            vec![SkippedDeclaredGrant {
                index: 0,
                reason: "cortexkit-hub audience is reserved for reserved:ckbus",
            }]
        );
        assert_eq!(other.grants().len(), 1);
        assert_eq!(other.grants()[0].selector, "cortexkit-account");
        assert!(!store
            .read_grant_covers(
                "reserved",
                module,
                "cortexkit-hub",
                GrantOperation::AccountToken,
                &other,
            )
            .unwrap());
        assert!(store
            .read_grant_covers(
                "reserved",
                module,
                "cortexkit-account",
                GrantOperation::AccountToken,
                &other,
            )
            .unwrap());
        assert!(DeclaredGrantSet::from_grants_json(module, &bus.grants_json()).is_err());
    }
}

#[test]
fn hub_audience_grants_admit_only_reserved_ckbus_without_refused_writes() {
    let (_root, store) = rig("hub-audience-grants", 227);
    store
        .create_read_grant_audited(
            "reserved",
            "ckbus",
            SelectorKind::Audience,
            "cortexkit-hub",
            GrantOperation::AccountToken,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let grants = store.list_read_grants().unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].principal_id, "ckbus");
    assert_eq!(grants[0].selector, "cortexkit-hub");
    for (kind, id) in [
        ("reserved", "motor"),
        ("reserved", "CKBUS"),
        ("enrolled", "x"),
        ("enrolled", "ckbus"),
        ("direct", ""),
        ("direct", "ckbus"),
    ] {
        let tip = store.audit_tip().unwrap();
        let refused = store
            .create_read_grant_audited(
                kind,
                id,
                SelectorKind::Audience,
                "cortexkit-hub",
                GrantOperation::AccountToken,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap_err();
        assert_eq!(refused.wire_code(), Some("hub_audience_reserved"));
        assert_eq!(refused.wire_class(), Some("permanent"));
        assert!(matches!(refused, StoreOpError::HubAudienceReserved));
        assert!(refused.to_string().contains("reserved:ckbus"));
        assert_eq!(store.list_read_grants().unwrap(), grants);
        assert_eq!(store.audit_tip().unwrap(), tip);
    }
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
