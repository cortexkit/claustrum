//! Taxonomy tests for the encrypted store.

use super::*;
use crate::record::CredentialKind;
use crate::test_support::TestTempDir;
use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};

pub(super) fn sqlite(label: &str, seed: u8) -> (TestTempDir, SqliteStore) {
    let root = TestTempDir::new(format!("taxonomy-{label}-{}-{seed}", std::process::id()));
    let descriptor = StorageDescriptor {
        module_id: "claustrum".into(),
        storage_namespace: format!("taxonomy-{label}"),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: root.join("store.db").to_string_lossy().into_owned(),
        },
    };
    (root, open_sqlite(&descriptor).expect("open sqlite"))
}

pub(super) fn rig(label: &str, seed: u8) -> (TestTempDir, EncryptedStore) {
    let (root, sqlite) = sqlite(label, seed);
    EncryptedStore::migrate(&sqlite).expect("migrate");
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([seed; 32])).expect("store");
    (root, store)
}

pub(super) fn api_record() -> VaultRecord {
    VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None)
}

#[test]
fn migration_n_guard_is_byte_exact_and_leaves_the_previous_schema_untouched() {
    let (_root, sqlite) = sqlite("guard", 81);
    sqlite
        .migrate(SCHEMA_NAMESPACE, &MIGRATIONS[..8])
        .expect("migrate through version 8");
    sqlite
            .with_conn(|conn| {
                for (seq, id) in ["Category:example", "category:example"].iter().enumerate() {
                    conn.execute(
                        "INSERT INTO credentials \
                         (credential_id, record_version, key_id, state, envelope, updated_at_ms) \
                         VALUES (?1, 1, '00', 'active', X'00', 0)",
                        rusqlite::params![id],
                    )?;
                    // A deposit row, because a real store never holds a credential the
                    // chain cannot date and the migration that adds `created_at_ms`
                    // refuses one that it cannot. The MACs are placeholders: nothing
                    // here verifies the chain.
                    conn.execute(
                        "INSERT INTO audit_log \
                         (seq, ts_ms, op, credential_id, payload_hash, actor, alarm, alarm_reason, prev_mac, entry_mac) \
                         VALUES (?1, ?2, 'put', ?3, NULL, 'test', 0, NULL, 'previous', 'entry')",
                        rusqlite::params![seq as i64 + 1, seq as i64 + 1, id],
                    )?;
                }
                Ok(())
            })
            .expect("seed ids");

    let error = EncryptedStore::migrate(&sqlite).expect_err("lowercase reservation must block");
    let message = error.to_string();
    assert!(message.contains("category:example"));
    assert!(!message.contains("Category:example"));
    sqlite
        .with_conn(|conn| {
            let version: i64 = conn.query_row(
                "SELECT MAX(version) FROM cortexkit_schema_version WHERE namespace = ?1",
                rusqlite::params![SCHEMA_NAMESPACE],
                |row| row.get(0),
            )?;
            assert_eq!(version, 8);
            let table: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'credential_categories')",
                [],
                |row| row.get(0),
            )?;
            assert!(!table);
            conn.execute(
                "DELETE FROM credentials WHERE credential_id = 'category:example'",
                [],
            )?;
            Ok(())
        })
        .expect("inspect blocked store");
    EncryptedStore::migrate(&sqlite).expect("mixed-case id survives migration");
    sqlite
        .with_conn(|conn| {
            let survives: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM credentials WHERE credential_id = 'Category:example')",
                [],
                |row| row.get(0),
            )?;
            assert!(survives);
            let category_rows: i64 =
                conn.query_row("SELECT COUNT(*) FROM credential_categories", [], |row| {
                    row.get(0)
                })?;
            assert_eq!(category_rows, 0, "migration never classifies");
            Ok(())
        })
        .expect("inspect migrated store");
}

#[test]
fn lease_free_readers_tolerate_a_store_one_migration_behind() {
    // *** THE PLACEMENT WINDOW, REPRODUCED. *** A CLI-only change is placed first
    // and the daemon, which migrates on boot, is restarted later. Between the two
    // every offline read meets a store exactly one migration behind, and these
    // readers must read it truthfully rather than fail on a table and a column that
    // do not exist yet.
    let (root, sqlite) = sqlite("behind-readers", 83);
    migrate_through_for_test(&sqlite, 8).expect("migrate through version 8");
    let path = root.join("store.db");
    sqlite
        .with_conn(|conn| {
            for id in ["apikey:one", "apikey:two"] {
                conn.execute(
                    "INSERT INTO credentials \
                         (credential_id, record_version, key_id, state, envelope, updated_at_ms) \
                         VALUES (?1, 1, '00', 'active', X'00', 0)",
                    rusqlite::params![id],
                )?;
            }
            conn.execute(
                "INSERT INTO read_grants \
                     (principal_kind, principal_id, credential_prefix, operation, created_at_ms) \
                     VALUES ('reserved', 'agent', 'apikey:', 'read', 7)",
                [],
            )?;
            Ok(())
        })
        .expect("seed schema-8 rows");

    let (metas, meta_schema) =
        list_meta_read_only_with_schema(&path).expect("metadata read on a schema-8 store");
    assert_eq!(
        meta_schema, 8,
        "the reader must report the store's own version"
    );
    assert_eq!(
        metas.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(),
        ["apikey:one", "apikey:two"],
        "every credential must be listed, not just the ones a new column happens to fit"
    );
    assert!(
        metas.iter().all(|(_, meta)| meta.categories.is_empty()),
        "a schema-8 store has no categories, so an empty list is the true reading"
    );

    let error = list_read_grants_read_only_with_schema(&path)
        .expect_err("legacy prefix grants cannot be represented truthfully");
    let message = error.to_string();
    assert!(message.contains("store schema 8"));
    assert!(message.contains("selector kinds arrive with migration 10"));
    assert!(message.contains("restart the daemon on this build"));
    assert!(message.contains("ck-auth that matches the store"));

    // POSITIVE CONTROL FOR EVERY ABSENT ASSERTION ABOVE. The same reads against a
    // migrated store must find the thing present, or the assertions above would pass
    // just as well against a reader that never returns anything.
    let (migrated_root, store) = rig("behind-readers-migrated", 84);
    store
        .create_audited("apikey:zai", &api_record(), AuditCtx::admin(AuditOp::Put))
        .expect("seed a classified credential");
    store
        .create_read_grant_audited(
            "reserved",
            "agent",
            SelectorKind::Category,
            "llm-provider",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .expect("seed a category grant");
    let migrated_path = migrated_root.join("store.db");

    let (metas, meta_schema) =
        list_meta_read_only_with_schema(&migrated_path).expect("metadata read on a migrated store");
    assert_eq!(
        meta_schema,
        newest_migration_version(),
        "a migrated store reports the binary's own version (the literal is pinned by \
             the_newest_migration_version_is_pinned_because_the_manifest_declares_it)"
    );
    assert!(meta_schema >= CATEGORY_SCHEMA_VERSION);
    assert_eq!(
        metas[0].1.categories,
        ["llm-provider", "web-search"],
        "the migrated arm must read REAL categories, or the empty list above proves nothing"
    );

    let (grants, grant_schema) = list_read_grants_read_only_with_schema(&migrated_path)
        .expect("grant read on a migrated store");
    assert_eq!(grant_schema, newest_migration_version());
    assert_eq!(
        grants[0].selector_kind,
        SelectorKind::Category,
        "the migrated arm must read the stored selector kind, or the Prefix assertion \
             above would hold for a reader that hardcodes it"
    );
}

#[test]
fn creation_defaults_and_set_category_transitions_have_exact_audit_targets() {
    let (_root, store) = rig("set-category", 82);
    store
        .create_audited("apikey:zai", &api_record(), AuditCtx::admin(AuditOp::Put))
        .expect("create classified credential");
    assert_eq!(
        store.categories("apikey:zai").unwrap(),
        ["llm-provider", "web-search"]
    );
    let audit = store.read_audit(None).unwrap();
    assert_eq!(audit.len(), 1, "creation has exactly its deposit audit row");
    assert!(audit.iter().all(|entry| entry.op != "set_category"));

    assert!(store
        .set_categories_audited(
            "apikey:zai",
            SetCategoryMode::Set,
            &[
                "monitoring".into(),
                "llm-provider".into(),
                "monitoring".into()
            ],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap());
    assert_eq!(
        store.categories("apikey:zai").unwrap(),
        ["llm-provider", "monitoring"]
    );
    let audit = store.read_audit(None).unwrap();
    assert_eq!(
        audit.last().unwrap().credential_id.as_deref(),
        Some("category:apikey:zai|llm-provider,monitoring")
    );
    assert!(store
        .set_categories_audited(
            "apikey:zai",
            SetCategoryMode::Remove,
            &["monitoring".into()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap());
    assert_eq!(store.categories("apikey:zai").unwrap(), ["llm-provider"]);
    assert!(store
        .set_categories_audited(
            "apikey:zai",
            SetCategoryMode::Add,
            &["monitoring".into()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap());
    let count = store.read_audit(None).unwrap().len();
    assert!(!store
        .set_categories_audited(
            "apikey:zai",
            SetCategoryMode::Add,
            &["monitoring".into()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap());
    assert_eq!(
        store.read_audit(None).unwrap().len(),
        count,
        "no-op is silent"
    );

    assert!(store
        .set_categories_audited(
            "apikey:zai",
            SetCategoryMode::Set,
            &[],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap());
    assert_eq!(
        store
            .read_audit(None)
            .unwrap()
            .last()
            .unwrap()
            .credential_id
            .as_deref(),
        Some("category:apikey:zai|")
    );
    for invalid in [
        "a",
        "Upper",
        "under_score",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        assert!(matches!(
            store.set_categories_audited(
                "apikey:zai",
                SetCategoryMode::Add,
                &[invalid.into()],
                AuditCtx::admin(AuditOp::SetCategory),
            ),
            Err(StoreOpError::InvalidCategoryName)
        ));
    }
    assert!(matches!(
        store.set_categories_audited(
            "missing",
            SetCategoryMode::Set,
            &["monitoring".into()],
            AuditCtx::admin(AuditOp::SetCategory),
        ),
        Err(StoreOpError::NotFound)
    ));
    assert!(matches!(
        store.set_categories_audited(
            "legacy|id",
            SetCategoryMode::Set,
            &["monitoring".into()],
            AuditCtx::admin(AuditOp::SetCategory),
        ),
        Err(StoreOpError::InvalidCredentialId)
    ));
}

/// `--force` MUST NOT STRIP A CATEGORY AN ACTIVE GRANT SELECTS ON.
///
/// The case this guards: `forge-identity`, a category only migration 10 assigns and the
/// registry does not list, is what a grant reaching 22 GitHub App credentials selects
/// on, for a consumer that mints tokens hourly. `--force` deletes each set and
/// reinserts the registry's, so it would have taken that grant to zero reach, with the
/// symptom arriving as `not_found` on credentials that plainly exist.
///
/// The refusal fires BEFORE the first write, so a refused call leaves every credential
/// exactly as it was rather than half reclassified.
#[test]
fn force_refuses_to_strip_a_category_an_active_grant_selects_on() {
    let (_root, store) = rig("reclassify-grant-guard", 211);
    let id = "oauth:anthropic";
    let record = VaultRecord::new_static(CredentialKind::ApiKey, "test", b"m".to_vec(), None);
    store
        .create_audited(id, &record, AuditCtx::admin(AuditOp::Put))
        .expect("seed");
    // A category the registry does not know, like `forge-identity`, which only
    // migration 10 assigns.
    store
        .set_categories_audited(
            id,
            SetCategoryMode::Add,
            &["hand-assigned".to_owned()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .expect("assign");
    store
        .create_read_grant_audited(
            "reserved",
            "some-consumer",
            SelectorKind::Category,
            "hand-assigned",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .expect("grant");

    let before = store.categories(id).expect("before");
    let refusal = store
        .reclassify_audited(true, AuditCtx::admin(AuditOp::SetCategory))
        .expect_err("force must refuse while a grant selects on a stripped category");
    let text = refusal.to_string();
    assert!(
        text.contains("hand-assigned") && text.contains("set-category"),
        "the refusal must name the category AND the repair, got: {text}"
    );
    assert_eq!(
        store.categories(id).expect("after"),
        before,
        "a refused reclassify must leave every category exactly as it was"
    );

    // CONTROL: with the grant gone, the same call proceeds. Without this the test
    // passes against a `--force` that refuses unconditionally.
    store
        .revoke_read_grant_audited(
            "reserved",
            "some-consumer",
            SelectorKind::Category,
            "hand-assigned",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantRevoke),
        )
        .expect("revoke");
    store
        .reclassify_audited(true, AuditCtx::admin(AuditOp::SetCategory))
        .expect("with no grant selecting it, force proceeds");
}

#[test]
fn reclassify_refills_empty_sets_is_idempotent_and_force_changes_only_differences() {
    let (_root, store) = rig("reclassify", 83);
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
            &[],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
    let before = store.read_audit(None).unwrap().len();
    assert_eq!(
        store
            .reclassify_audited(false, AuditCtx::admin(AuditOp::SetCategory))
            .unwrap(),
        1
    );
    assert_eq!(
        store.categories("oauth:snowflake").unwrap(),
        ["data-warehouse", "snowflake-native"]
    );
    assert_eq!(store.read_audit(None).unwrap().len(), before + 1);
    assert_eq!(
        store
            .reclassify_audited(false, AuditCtx::admin(AuditOp::SetCategory))
            .unwrap(),
        0
    );
    store
        .set_categories_audited(
            "oauth:snowflake",
            SetCategoryMode::Set,
            &["monitoring".into()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
    assert_eq!(
        store
            .reclassify_audited(true, AuditCtx::admin(AuditOp::SetCategory))
            .unwrap(),
        1
    );
    assert_eq!(
        store.categories("oauth:snowflake").unwrap(),
        ["data-warehouse", "snowflake-native"]
    );
}

#[test]
fn seal_grants_are_exact_only_and_imply_nothing_in_either_direction() {
    let (_root, store) = rig("seal-grants", 86);
    store
        .create_audited("kem:push", &api_record(), AuditCtx::admin(AuditOp::Put))
        .unwrap();
    store
        .set_categories_audited(
            "kem:push",
            SetCategoryMode::Set,
            &["push-keys".to_string()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
    for kind in [SelectorKind::Category, SelectorKind::Audience] {
        assert!(
            kind.validate_operation(GrantOperation::Seal).is_err(),
            "{kind:?}"
        );
        let refused = store.create_read_grant_audited(
            "reserved",
            "pusher",
            kind,
            "push-keys",
            GrantOperation::Seal,
            AuditCtx::admin(AuditOp::GrantCreate),
        );
        assert!(refused.is_err(), "{kind:?} seal grant must be refused");
    }
    assert!(store.list_read_grants().unwrap().is_empty());
    assert_eq!(
        SelectorKind::Exact.validate_operation(GrantOperation::Seal),
        Ok(())
    );

    // A seal grant covers seal only.
    store
        .create_read_grant_audited(
            "reserved",
            "pusher",
            SelectorKind::Exact,
            "kem:push",
            GrantOperation::Seal,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let covers = |principal: &str, operation| {
        store
            .evaluate_scoped_coverage(
                "reserved",
                principal,
                "kem:push",
                operation,
                &crate::store::DeclaredGrantSet::empty(),
            )
            .unwrap()
            .covered
    };
    assert!(covers("pusher", GrantOperation::Seal));
    for operation in [
        GrantOperation::Read,
        GrantOperation::Sign,
        GrantOperation::Open,
        GrantOperation::List,
    ] {
        assert!(
            !covers("pusher", operation),
            "seal must not imply {operation:?}"
        );
    }
    // And no other operation covers seal, by exact or by category selector.
    for operation in [
        GrantOperation::Read,
        GrantOperation::Sign,
        GrantOperation::Open,
        GrantOperation::List,
    ] {
        for (kind, selector) in [
            (SelectorKind::Exact, "kem:push"),
            (SelectorKind::Category, "push-keys"),
        ] {
            store
                .create_read_grant_audited(
                    "reserved",
                    "other",
                    kind,
                    selector,
                    operation,
                    AuditCtx::admin(AuditOp::GrantCreate),
                )
                .unwrap();
        }
    }
    assert!(
        !covers("other", GrantOperation::Seal),
        "nothing implies seal"
    );
    assert!(covers("other", GrantOperation::Open));
}

#[test]
fn selector_kinds_coexist_revoke_independently_and_coverage_is_operation_scoped() {
    let (_root, store) = rig("coverage", 84);
    store
        .create_audited(
            "apikey:deepseek",
            &api_record(),
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
    store
        .create_read_grant_audited(
            "reserved",
            "consumer",
            SelectorKind::Exact,
            "llm-provider",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    store
        .create_read_grant_audited(
            "reserved",
            "consumer",
            SelectorKind::Category,
            "llm-provider",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    store
        .create_read_grant_audited(
            "reserved",
            "consumer",
            SelectorKind::Category,
            "llm-provider",
            GrantOperation::Sign,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();

    let read = store
        .evaluate_scoped_coverage(
            "reserved",
            "consumer",
            "apikey:deepseek",
            GrantOperation::Read,
            &crate::store::DeclaredGrantSet::empty(),
        )
        .unwrap();
    assert!(read.covered);
    assert_eq!(read.caller_active_grants, 2);
    assert!(read.holds_category_selector);
    let unrelated = store
        .evaluate_scoped_coverage(
            "reserved",
            "consumer",
            "missing",
            GrantOperation::Read,
            &crate::store::DeclaredGrantSet::empty(),
        )
        .unwrap();
    assert!(!unrelated.covered);
    assert!(!unrelated.id_exists);
    assert_eq!(unrelated.id_category_count, Some(0));

    let snapshot = store
        .list_scoped_snapshot(
            "reserved",
            "consumer",
            &crate::store::DeclaredGrantSet::empty(),
        )
        .expect("one snapshot");
    assert_eq!(snapshot.grants.len(), 3);
    assert_eq!(snapshot.rows.len(), 1);
    assert_eq!(
        snapshot.rows[0].operations,
        [GrantOperation::Read, GrantOperation::Sign]
    );

    store
        .revoke_read_grant_audited(
            "reserved",
            "consumer",
            SelectorKind::Category,
            "llm-provider",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantRevoke),
        )
        .unwrap();
    let remaining = store.list_read_grants().unwrap();
    assert!(remaining.iter().any(|grant| {
        grant.selector_kind == SelectorKind::Exact && grant.selector == "llm-provider"
    }));
    assert!(store
        .read_grant_covers(
            "reserved",
            "consumer",
            "apikey:deepseek",
            GrantOperation::Sign,
            &DeclaredGrantSet::empty(),
        )
        .unwrap());
    assert!(!store
        .read_grant_covers(
            "reserved",
            "consumer",
            "apikey:deepseek",
            GrantOperation::Read,
            &DeclaredGrantSet::empty(),
        )
        .unwrap());
    let targets: Vec<_> = store
        .read_audit(None)
        .unwrap()
        .into_iter()
        .filter_map(|entry| entry.credential_id)
        .filter(|target| target.starts_with("grant:"))
        .collect();
    assert!(targets
        .iter()
        .all(|target| target.split_once('|').is_some()));
    assert!(targets.iter().any(|target| target.contains(":exact|")));
    assert!(targets.iter().any(|target| target.contains(":category|")));
}

#[test]
fn remove_explicitly_deletes_categories_with_foreign_keys_disabled() {
    let (_root, store) = rig("remove-category", 85);
    store
        .create_audited("apikey:zai", &api_record(), AuditCtx::admin(AuditOp::Put))
        .unwrap();
    store
        .with_raw_conn(|conn| conn.pragma_update(None, "foreign_keys", "OFF"))
        .unwrap();
    store
        .remove_audited("apikey:zai", AuditCtx::admin(AuditOp::Remove))
        .unwrap();
    assert!(store.categories("apikey:zai").unwrap().is_empty());
}
