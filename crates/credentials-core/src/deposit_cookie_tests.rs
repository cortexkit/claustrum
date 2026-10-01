use super::*;
use crate::secret::Secret;
use crate::store::taxonomy_tests::{rig, sqlite};

const ID: &str = "cookie:ollama.com:ufuk";
const CALLER: &str = "reserved:cerebellum";
const HASH: &str = "d523e692e03fc04a7700e325960047a0283a062980239e5ea7ad03b4eac9bcb7";

fn deposit(store: &EncryptedStore) -> Result<DepositCookieOutcome, StoreOpError> {
    store.deposit_cookie(
        ID,
        &Secret::new("session=abc".to_owned()),
        "consent-123",
        None,
        CALLER,
    )
}

fn raw_row(store: &EncryptedStore) -> (i64, Vec<u8>) {
    store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT record_version, envelope FROM credentials WHERE credential_id = ?1",
                [ID],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })
        .unwrap()
}

fn counts(store: &EncryptedStore) -> (i64, i64, i64) {
    store.with_raw_conn(|conn| conn.query_row("SELECT (SELECT count(*) FROM credentials), (SELECT count(*) FROM credential_categories), (SELECT count(*) FROM audit_log)", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))).unwrap()
}

#[test]
fn deposit_cookie_create_replace_preserves_creator_categories_birth_and_identity() {
    let (_root, store) = rig("cookie-create", 151);
    assert_eq!(
        store
            .deposit_cookie(
                ID,
                &Secret::new("session=abc".to_owned()),
                "consent-123",
                Some("me@example.com"),
                CALLER
            )
            .unwrap(),
        DepositCookieOutcome::Created { record_version: 1 }
    );
    let meta = store.meta(ID).unwrap();
    assert_eq!(meta.created_by.as_deref(), Some(CALLER));
    assert_eq!(meta.categories, ["browser-session"]);
    let birth: (i64, i64) = store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT created_at_ms, updated_at_ms FROM credentials WHERE credential_id = ?1",
                [ID],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
        })
        .unwrap();
    assert_eq!(birth.0, birth.1);
    let record = store.get(ID).unwrap();
    assert_eq!(record.kind, CredentialKind::Cookie);
    assert_eq!(record.source, CALLER);
    assert_eq!(record.payload.expose(), b"session=abc");
    assert_eq!(record.identity.email.as_deref(), Some("me@example.com"));
    assert_eq!(
        deposit(&store).unwrap(),
        DepositCookieOutcome::Replaced { record_version: 2 }
    );
    assert_eq!(store.get(ID).unwrap().identity, record.identity);
    assert_eq!(store.meta(ID).unwrap().created_by, meta.created_by);
    assert_eq!(store.meta(ID).unwrap().categories, meta.categories);
    let after_birth: i64 = store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT created_at_ms FROM credentials WHERE credential_id = ?1",
                [ID],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(after_birth, birth.0);
    let audit = store.read_audit(None).unwrap();
    assert_eq!(audit.len(), 2);
    for entry in audit {
        assert_eq!(entry.actor, CALLER);
        assert_eq!(entry.payload_hash.as_deref(), Some(HASH));
        assert!(!entry.alarm);
    }
    assert_eq!(store.verify_audit_chain().unwrap(), None);
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "DELETE FROM credential_categories WHERE credential_id = ?1",
                [ID],
            )
        })
        .unwrap();
    assert_eq!(
        deposit(&store).unwrap(),
        DepositCookieOutcome::Replaced { record_version: 3 }
    );
    assert!(store.meta(ID).unwrap().categories.is_empty());
    store
        .overwrite_unconditional_audited(
            ID,
            &VaultRecord::new_cookie("operator", b"operator replacement".to_vec()),
            AuditCtx::vault(AuditOp::Overwrite),
        )
        .unwrap();
    assert_eq!(store.meta(ID).unwrap().created_by.as_deref(), Some(CALLER));
    assert_eq!(
        deposit(&store).unwrap(),
        DepositCookieOutcome::Replaced { record_version: 5 }
    );
}

#[test]
fn deposit_cookie_refuses_operator_and_other_creator_without_opening_or_mutating() {
    let (_root, store) = rig("cookie-creator", 152);
    store
        .create(ID, &VaultRecord::new_cookie("operator", b"old".to_vec()))
        .unwrap();
    assert_eq!(
        store.meta(ID).unwrap().created_by.as_deref(),
        Some("operator")
    );
    let before = raw_row(&store);
    let before_counts = counts(&store);
    assert!(matches!(
        deposit(&store),
        Err(StoreOpError::DepositCookieNotPermitted)
    ));
    assert_eq!(raw_row(&store), before);
    assert_eq!(counts(&store), before_counts);
    let other = "cookie:other.com:me";
    store
        .deposit_cookie(
            other,
            &Secret::new("other".into()),
            "consent",
            None,
            "reserved:other",
        )
        .unwrap();
    let other_before: (i64, Vec<u8>) = store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT record_version, envelope FROM credentials WHERE credential_id = ?1",
                [other],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })
        .unwrap();
    let before_counts = counts(&store);
    assert!(matches!(
        store.deposit_cookie(other, &Secret::new("new".into()), "consent", None, CALLER),
        Err(StoreOpError::DepositCookieNotPermitted)
    ));
    let other_after: (i64, Vec<u8>) = store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT record_version, envelope FROM credentials WHERE credential_id = ?1",
                [other],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })
        .unwrap();
    assert_eq!(other_before, other_after);
    assert_eq!(counts(&store), before_counts);
}

#[test]
fn deposit_cookie_audit_append_failure_rolls_back_create_and_replace() {
    let (_root, store) = rig("cookie-audit-fault", 153);
    store.force_deposit_cookie_audit_append_error_for_test(true);
    assert!(deposit(&store).is_err());
    assert_eq!(counts(&store), (0, 0, 0));
    store.force_deposit_cookie_audit_append_error_for_test(false);
    deposit(&store).unwrap();
    let before = raw_row(&store);
    let before_counts = counts(&store);
    store.force_deposit_cookie_audit_append_error_for_test(true);
    assert!(deposit(&store).is_err());
    assert_eq!(raw_row(&store), before);
    assert_eq!(counts(&store), before_counts);
    store.force_deposit_cookie_audit_append_error_for_test(false);
}

#[test]
fn deposit_grants_are_narrow_and_cover_defaults_not_stored_categories() {
    let (_root, store) = rig("cookie-grant", 154);
    for (principal, kind, selector) in [
        ("reserved", SelectorKind::Exact, ID),
        ("reserved", SelectorKind::Category, "llm-provider"),
        ("enrolled", SelectorKind::Category, "browser-session"),
    ] {
        let error = store
            .create_read_grant_audited(
                principal,
                "agent",
                kind,
                selector,
                GrantOperation::Deposit,
                AuditCtx::vault(AuditOp::GrantCreate),
            )
            .unwrap_err();
        assert!(matches!(error, StoreOpError::InvalidDepositGrant));
        assert_eq!(
            error.to_string(),
            "deposit requires a reserved principal and category browser-session selector"
        );
    }
    store
        .create_read_grant_audited(
            "reserved",
            "cerebellum",
            SelectorKind::Category,
            "browser-session",
            GrantOperation::Deposit,
            AuditCtx::vault(AuditOp::GrantCreate),
        )
        .unwrap();
    assert!(
        store
            .evaluate_scoped_coverage("reserved", "cerebellum", ID, GrantOperation::Deposit)
            .unwrap()
            .covered
    );
    deposit(&store).unwrap();
    assert!(store
        .list_scoped_snapshot("reserved", "cerebellum")
        .unwrap()
        .rows
        .is_empty());
    store
        .create_read_grant_audited(
            "reserved",
            "cerebellum",
            SelectorKind::Category,
            "browser-session",
            GrantOperation::Read,
            AuditCtx::vault(AuditOp::GrantCreate),
        )
        .unwrap();
    assert_eq!(
        store
            .list_scoped_snapshot("reserved", "cerebellum")
            .unwrap()
            .rows[0]
            .operations,
        [GrantOperation::Read]
    );
    store
        .revoke_read_grant_audited(
            "reserved",
            "cerebellum",
            SelectorKind::Category,
            "browser-session",
            GrantOperation::Read,
            AuditCtx::vault(AuditOp::GrantRevoke),
        )
        .unwrap();
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "DELETE FROM credential_categories WHERE credential_id = ?1",
                [ID],
            )
        })
        .unwrap();
    assert!(
        store
            .evaluate_scoped_coverage("reserved", "cerebellum", ID, GrantOperation::Deposit)
            .unwrap()
            .covered
    );
    for op in [
        GrantOperation::Read,
        GrantOperation::Sign,
        GrantOperation::Open,
        GrantOperation::List,
    ] {
        assert!(
            !store
                .evaluate_scoped_coverage("reserved", "cerebellum", ID, op)
                .unwrap()
                .covered
        );
    }
    assert!(
        !store
            .evaluate_scoped_coverage(
                "reserved",
                "cerebellum",
                "apikey:x",
                GrantOperation::Deposit
            )
            .unwrap()
            .covered
    );
}

#[test]
fn migration_14_conserves_every_table_changes_only_two_ddl_objects_and_refuses_null_creator() {
    let (_root, sqlite) = sqlite("cookie-migration", 155);
    migrate_through_for_test(&sqlite, 13).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([155; 32])).unwrap();
    let record = VaultRecord::new_cookie("old", b"legacy".to_vec());
    let blob = store.seal_record(ID, &record).unwrap();
    store.with_raw_conn(|conn| {
        conn.execute("INSERT INTO credentials (credential_id, record_version, key_id, state, envelope, updated_at_ms, created_at_ms) VALUES (?1, 1, ?2, 'active', ?3, 7, 7)", rusqlite::params![ID, store.key_id.to_hex(), blob])?;
        for operation in ["read", "sign", "open", "list"] {
            conn.execute("INSERT INTO read_grants VALUES ('reserved','agent','category','browser-session',?1,9)", [operation])?;
        }
        conn.execute("INSERT INTO credential_categories VALUES (?1, 'browser-session')", [ID])?;
        conn.execute("UPDATE grants_generation SET value = 57", [])?;
        Ok(())
    }).unwrap();
    assert!(store.with_raw_conn(|conn| conn.execute("INSERT INTO read_grants VALUES ('reserved','new','category','browser-session','deposit',9)", [])).is_err());
    let objects = |store: &EncryptedStore| {
        store.with_raw_conn(|conn| {
        let mut stmt = conn.prepare("SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>();
        rows
    }).unwrap()
    };
    let tables = |store: &EncryptedStore, ddl: &[(String, String, String)]| {
        store
            .with_raw_conn(|conn| {
                let mut result = BTreeMap::new();
                for (kind, name, _) in ddl {
                    if kind != "table" || name == "cortexkit_schema_version" {
                        continue;
                    }
                    let mut columns_stmt =
                        conn.prepare(&format!("PRAGMA table_info(\"{name}\")"))?;
                    let columns = columns_stmt
                        .query_map([], |r| r.get::<_, String>(1))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    let columns: Vec<_> = columns
                        .into_iter()
                        .filter(|c| c != "created_by")
                        .map(|c| format!("\"{c}\""))
                        .collect();
                    let mut stmt = conn.prepare(&format!(
                        "SELECT {} FROM \"{name}\" ORDER BY rowid",
                        columns.join(",")
                    ))?;
                    let n = stmt.column_count();
                    let rows = stmt
                        .query_map([], |r| {
                            (0..n)
                                .map(|i| r.get::<_, rusqlite::types::Value>(i))
                                .collect::<rusqlite::Result<Vec<_>>>()
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    result.insert(name.clone(), rows);
                }
                Ok(result)
            })
            .unwrap()
    };
    let (behind_meta, version) = list_meta_read_only_with_schema(&_root.join("store.db")).unwrap();
    assert_eq!(version, 13);
    assert_eq!(behind_meta[0].1.created_by, None);
    let before_ddl = objects(&store);
    let before_tables = tables(&store, &before_ddl);
    let before = raw_row(&store);
    migrate_through_for_test(&store.store, 14).unwrap();
    let after_ddl = objects(&store);
    assert_eq!(tables(&store, &after_ddl), before_tables);
    for ((old_kind, old_name, old_sql), (kind, name, sql)) in before_ddl.iter().zip(&after_ddl) {
        assert_eq!((kind, name), (old_kind, old_name));
        match name.as_str() {
            "credentials" => assert_eq!(sql, &old_sql.replacen(')', ", created_by TEXT)", 1)),
            "read_grants" => assert_eq!(
                sql,
                &old_sql.replace("'open', 'list'", "'open', 'list', 'deposit'")
            ),
            _ => assert_eq!(sql, old_sql),
        }
    }
    assert_eq!(before_ddl.len(), after_ddl.len());
    assert_eq!(store.meta(ID).unwrap().created_by, None);
    assert!(matches!(
        deposit(&store),
        Err(StoreOpError::DepositCookieNotPermitted)
    ));
    assert_eq!(raw_row(&store), before);
    store.with_raw_conn(|conn| conn.execute("INSERT INTO read_grants VALUES ('reserved','new','category','browser-session','deposit',9)", [])).unwrap();
}
