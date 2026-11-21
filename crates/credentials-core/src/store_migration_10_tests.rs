//! Migration 10: the enrollment tables, the selector column, the dated credential rows
//! and the grant generation.

use super::*;
use crate::store::taxonomy_tests::{api_record, rig, sqlite};
use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};

/// Exact selectors are byte equality, so adding another id with the same leading
/// bytes cannot widen an existing grant.
#[test]
fn an_exact_selector_matches_only_the_byte_equal_credential_id() {
    let (_root, store) = rig("exact-is-byte-equality", 97);
    for credential_id in ["apikey:opencode", "apikey:opencode-zed"] {
        store
            .create_audited(credential_id, &api_record(), AuditCtx::admin(AuditOp::Put))
            .unwrap();
    }
    store
        .create_read_grant_audited(
            "reserved",
            "broca",
            SelectorKind::Exact,
            "apikey:opencode",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();

    assert!(store
        .read_grant_covers(
            "reserved",
            "broca",
            "apikey:opencode",
            GrantOperation::Read,
            &DeclaredGrantSet::empty()
        )
        .unwrap());
    assert!(
        !store
            .read_grant_covers(
                "reserved",
                "broca",
                "apikey:opencode-zed",
                GrantOperation::Read,
                &DeclaredGrantSet::empty(),
            )
            .unwrap(),
        "a longer id with the same leading bytes must not inherit exact authority"
    );
}

#[test]
fn migration_10_converts_every_non_table_prefix_or_refuses_atomically() {
    for (label, ids, should_migrate) in [
        ("total-zero", Vec::<&str>::new(), false),
        ("total-one", vec!["service:only"], true),
        (
            "total-three",
            vec!["service:one", "service:three", "service:two"],
            false,
        ),
    ] {
        let (_root, store) = sqlite(label, 120);
        migrate_through_for_test(&store, 9).expect("migrate through schema 9");
        seed_schema_9_ids(&store, &ids);
        store
                .with_conn(|conn| {
                    conn.execute(
                        "INSERT INTO read_grants \
                         (principal_kind, principal_id, selector_kind, credential_prefix, operation, created_at_ms) \
                         VALUES ('reserved', 'synthetic', 'prefix', 'service:', 'read', 7)",
                        [],
                    )?;
                    Ok(())
                })
                .expect("insert synthetic prefix grant");
        let before = schema_9_grants(&store);

        if should_migrate {
            EncryptedStore::migrate(&store).expect("one match converts to exact");
            assert_eq!(
                schema_10_grants(&store),
                vec![(
                    "reserved".to_string(),
                    "synthetic".to_string(),
                    "exact".to_string(),
                    "service:only".to_string(),
                    "read".to_string(),
                )]
            );
        } else {
            let error = EncryptedStore::migrate(&store)
                .expect_err("zero and multiple prefix matches must refuse")
                .to_string();
            assert!(
                error.contains("principal_id=synthetic")
                    && error.contains("selector=service:")
                    && error.contains("match set"),
                "the refusal must name the row and its match set: {error}"
            );
            for id in &ids {
                assert!(
                    error.contains(id),
                    "the refusal must name every computed match {id}: {error}"
                );
            }
            assert_eq!(schema_version_of(&store), 9);
            assert_eq!(schema_9_grants(&store), before);
        }
    }
}

#[test]
fn conversion_table_rows_refuse_every_computed_reach_change() {
    let family = category_conversion();
    let (category, listed_ids) = category_conversion_parts();

    // An additional family member enlarges the old prefix set but is absent from
    // the approved category assignment set.
    let (_root, extra_family) = sqlite("conversion-extra-family", 121);
    migrate_through_for_test(&extra_family, 9).unwrap();
    let mut family_ids = listed_ids.to_vec();
    family_ids.push("github_app:twenty-third");
    seed_schema_9_ids(&extra_family, &family_ids);
    extra_family
        .with_conn(|conn| {
            insert_schema_9_grant(conn, family);
            Ok(())
        })
        .unwrap();
    let before = schema_9_grants(&extra_family);
    let error = EncryptedStore::migrate(&extra_family)
        .expect_err("an extra family member changes reach")
        .to_string();
    assert!(
        error.contains("before covered set")
            && error.contains("after covered set")
            && error.contains("difference")
            && error.contains("github_app:twenty-third"),
        "the refusal must show both sets and their difference: {error}"
    );
    assert_eq!(schema_version_of(&extra_family), 9);
    assert_eq!(schema_9_grants(&extra_family), before);

    // A pre-existing assignment outside the approved list enlarges the replacement
    // category even though the old family prefix does not reach it.
    let (_root, outside_category) = sqlite("conversion-outside-category", 122);
    migrate_through_for_test(&outside_category, 9).unwrap();
    let mut category_ids = listed_ids.to_vec();
    category_ids.push("gitlab:outside");
    seed_schema_9_ids(&outside_category, &category_ids);
    outside_category
            .with_conn(|conn| {
                insert_schema_9_grant(conn, family);
                conn.execute(
                    "INSERT INTO credential_categories (credential_id, category) VALUES ('gitlab:outside', ?1)",
                    rusqlite::params![category],
                )?;
                Ok(())
            })
            .unwrap();
    let before_grants = schema_9_grants(&outside_category);
    let before_categories = category_assignments(&outside_category);
    let error = EncryptedStore::migrate(&outside_category)
        .expect_err("an outside category member changes reach")
        .to_string();
    assert!(
        error.contains("before covered set")
            && error.contains("after covered set")
            && error.contains("difference")
            && error.contains("gitlab:outside"),
        "the refusal must show the unexpected category member: {error}"
    );
    assert_eq!(schema_version_of(&outside_category), 9);
    assert_eq!(schema_9_grants(&outside_category), before_grants);
    assert_eq!(category_assignments(&outside_category), before_categories);

    // A listed exact conversion is also checked against this store's actual prefix
    // set rather than trusted merely because its row key is listed.
    let exact = MIGRATION_10_CONVERSION_TABLE
        .iter()
        .find(|entry| entry.old_selector.ends_with('-'))
        .expect("the ruling table has a strict-prefix exact conversion");
    let exact_target = match exact.replacement {
        Migration10Replacement::Exact { selector } => selector,
        Migration10Replacement::Category { .. } => unreachable!(),
    };
    let (_root, widened_exact) = sqlite("conversion-widened-exact", 123);
    migrate_through_for_test(&widened_exact, 9).unwrap();
    seed_schema_9_ids(&widened_exact, &[exact_target, "apikey:opencode-second"]);
    widened_exact
        .with_conn(|conn| {
            insert_schema_9_grant(conn, exact);
            Ok(())
        })
        .unwrap();
    let before = schema_9_grants(&widened_exact);
    let error = EncryptedStore::migrate(&widened_exact)
        .expect_err("a listed exact prefix that reaches twice must refuse")
        .to_string();
    assert!(
        error.contains("before covered set")
            && error.contains("after covered set")
            && error.contains("difference")
            && error.contains("apikey:opencode-second"),
        "the listed row must still prove reach preservation: {error}"
    );
    assert_eq!(schema_version_of(&widened_exact), 9);
    assert_eq!(schema_9_grants(&widened_exact), before);
}

#[test]
fn category_backfill_reach_guard_checks_every_grant_row() {
    let family = category_conversion();
    let (category, listed_ids) = category_conversion_parts();
    let (_root, store) = sqlite("all-row-reach-guard", 124);
    migrate_through_for_test(&store, 9).unwrap();
    seed_schema_9_ids(&store, listed_ids);
    store
            .with_conn(|conn| {
                insert_schema_9_grant(conn, family);
                conn.execute(
                    "INSERT INTO read_grants \
                     (principal_kind, principal_id, selector_kind, credential_prefix, operation, created_at_ms) \
                     VALUES ('reserved', 'different-principal', 'category', ?1, 'read', 8)",
                    rusqlite::params![format!("category:{category}")],
                )?;
                Ok(())
            })
            .unwrap();

    let before = schema_9_grants(&store);
    let error = EncryptedStore::migrate(&store)
        .expect_err("the unrelated empty category row would widen")
        .to_string();
    assert!(
        error.contains("principal_id=different-principal")
            && error.contains("before covered set []")
            && error.contains("after covered set")
            && listed_ids.iter().all(|id| error.contains(id)),
        "the refusal must name the unrelated row and its 22 new matches: {error}"
    );
    assert_eq!(schema_version_of(&store), 9);
    assert_eq!(schema_9_grants(&store), before);
    assert!(category_assignments(&store).is_empty());
}

#[test]
fn existing_category_rows_strip_the_marker_without_changing_reach() {
    let (_root, store) = sqlite("category-marker-strip", 125);
    migrate_through_for_test(&store, 9).unwrap();
    seed_schema_9_ids(&store, &["service:member", "service:other"]);
    store
            .with_conn(|conn| {
                conn.execute(
                    "INSERT INTO credential_categories (credential_id, category) \
                     VALUES ('service:member', 'shared-category')",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO read_grants \
                     (principal_kind, principal_id, selector_kind, credential_prefix, operation, created_at_ms) \
                     VALUES ('reserved', 'category-holder', 'category', 'category:shared-category', 'read', 9)",
                    [],
                )?;
                Ok(())
            })
            .unwrap();

    EncryptedStore::migrate(&store).expect("reach-neutral category row migrates");
    assert_eq!(
        schema_10_grants(&store),
        vec![(
            "reserved".to_string(),
            "category-holder".to_string(),
            "category".to_string(),
            "shared-category".to_string(),
            "read".to_string(),
        )]
    );
    let covered: Vec<String> = store
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT cc.credential_id FROM credential_categories cc \
                     JOIN read_grants rg ON rg.selector_kind = 'category' AND rg.selector = cc.category \
                     ORDER BY cc.credential_id",
                )?;
                let rows = stmt
                    .query_map([], |row| row.get(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .unwrap();
    assert_eq!(covered, ["service:member"]);
}

#[test]
fn live_conversion_table_lands_cell_for_cell_and_audits_the_22_assignments() {
    let (_root, store) = sqlite("live-conversion", 126);
    migrate_through_for_test(&store, 9).unwrap();
    let key = MasterKey::from_bytes([126; 32]);
    let credential_ids = live_conversion_credential_ids();
    seed_verified_schema_9_ids(&store, &key, &credential_ids);
    store
        .with_conn(|conn| {
            for conversion in MIGRATION_10_CONVERSION_TABLE {
                insert_schema_9_grant(conn, conversion);
            }
            Ok(())
        })
        .unwrap();

    EncryptedStore::migrate_with_key(&store, &key).expect("the live fixture migrates");

    let mut expected_rows: Vec<(String, String, String, String, String)> =
        MIGRATION_10_CONVERSION_TABLE
            .iter()
            .map(|entry| {
                let (kind, selector) = match entry.replacement {
                    Migration10Replacement::Exact { selector } => ("exact", selector),
                    Migration10Replacement::Category { selector, .. } => ("category", selector),
                };
                (
                    entry.principal_kind.to_string(),
                    entry.principal_id.to_string(),
                    kind.to_string(),
                    selector.to_string(),
                    entry.operation.as_str().to_string(),
                )
            })
            .collect();
    expected_rows.sort();
    assert_eq!(
        schema_10_grants(&store),
        expected_rows,
        "the migrated rows must match the ruling-9 table cell for cell"
    );
    for entry in MIGRATION_10_CONVERSION_TABLE {
        let (selector_kind, selector, expected_reach) = match entry.replacement {
            Migration10Replacement::Exact { selector } => ("exact", selector, 1),
            Migration10Replacement::Category {
                selector,
                assignments,
            } => ("category", selector, assignments.len() as i64),
        };
        let reach: i64 = store
            .with_conn(|conn| match selector_kind {
                "exact" => conn.query_row(
                    "SELECT COUNT(*) FROM credentials WHERE credential_id = ?1",
                    rusqlite::params![selector],
                    |row| row.get(0),
                ),
                "category" => conn.query_row(
                    "SELECT COUNT(*) FROM credential_categories WHERE category = ?1",
                    rusqlite::params![selector],
                    |row| row.get(0),
                ),
                _ => unreachable!(),
            })
            .unwrap();
        assert_eq!(
            reach, expected_reach,
            "{} {} must retain the ruling-9 reach",
            entry.principal_id, entry.old_selector
        );
    }

    let (category, listed_ids) = category_conversion_parts();
    assert_eq!(
        category_assignments(&store),
        listed_ids
            .iter()
            .map(|credential_id| ((*credential_id).to_string(), category.to_string()))
            .collect::<Vec<_>>()
    );

    let migration_audit: Vec<AuditEntry> = store
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT seq, ts_ms, op, credential_id, payload_hash, actor, alarm, alarm_reason, prev_mac, entry_mac \
                     FROM audit_log WHERE op = 'category.migrate' ORDER BY seq",
                )?;
                let rows = stmt
                    .query_map([], row_to_audit)?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .unwrap();
    assert_eq!(migration_audit.len(), 1);
    assert_eq!(migration_audit[0].op, "category.migrate");
    assert_eq!(migration_audit[0].actor, "migration:10");
    let target = migration_audit[0]
        .credential_id
        .as_deref()
        .expect("the category migration names its assignments");
    assert!(
        listed_ids
            .iter()
            .all(|credential_id| target.contains(credential_id)),
        "the one audit row must name all assigned credentials: {target}"
    );

    let encrypted = EncryptedStore::open(store, key).expect("open the migrated fixture");
    assert_eq!(
        encrypted.verify_audit_chain().expect("verify the chain"),
        None,
        "the category migration append must preserve the HMAC chain"
    );
}

#[test]
fn missing_chain_key_refuses_before_any_category_or_grant_write() {
    let family = category_conversion();
    let (_, listed_ids) = category_conversion_parts();
    let (_root, store) = sqlite("missing-migration-chain-key", 127);
    migrate_through_for_test(&store, 9).unwrap();
    seed_schema_9_ids(&store, listed_ids);
    store
        .with_conn(|conn| {
            insert_schema_9_grant(conn, family);
            Ok(())
        })
        .unwrap();
    let before = schema_9_grants(&store);

    let error = EncryptedStore::migrate(&store)
        .expect_err("the backfill cannot be unaudited")
        .to_string();
    assert!(
        error.contains("audit chain key unavailable"),
        "the refusal must name the unavailable chain key: {error}"
    );
    assert_eq!(schema_version_of(&store), 9);
    assert_eq!(schema_9_grants(&store), before);
    assert!(category_assignments(&store).is_empty());
    let migration_rows: i64 = store
        .with_conn(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM audit_log WHERE op = 'category.migrate'",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(migration_rows, 0);
}

#[test]
fn migrated_and_fresh_stores_hold_identical_grant_keys() {
    let (_root, migrated) = sqlite("grant-parity-migrated", 128);
    migrate_through_for_test(&migrated, 9).unwrap();
    let key = MasterKey::from_bytes([128; 32]);
    let credential_ids = live_conversion_credential_ids();
    seed_verified_schema_9_ids(&migrated, &key, &credential_ids);
    migrated
        .with_conn(|conn| {
            for conversion in MIGRATION_10_CONVERSION_TABLE {
                insert_schema_9_grant(conn, conversion);
            }
            Ok(())
        })
        .unwrap();
    EncryptedStore::migrate_with_key(&migrated, &key).unwrap();

    let (_root, fresh) = sqlite("grant-parity-fresh", 129);
    EncryptedStore::migrate(&fresh).unwrap();
    fresh
            .with_conn(|conn| {
                for credential_id in &credential_ids {
                    conn.execute(
                        "INSERT INTO credentials \
                         (credential_id, record_version, key_id, state, envelope, updated_at_ms, created_at_ms) \
                         VALUES (?1, 1, '00', 'active', X'00', 9, 10)",
                        rusqlite::params![credential_id],
                    )?;
                }
                for entry in MIGRATION_10_CONVERSION_TABLE {
                    let (kind, selector) = match entry.replacement {
                        Migration10Replacement::Exact { selector } => ("exact", selector),
                        Migration10Replacement::Category { selector, .. } => {
                            ("category", selector)
                        }
                    };
                    conn.execute(
                        "INSERT INTO read_grants \
                         (principal_kind, principal_id, selector_kind, selector, operation, created_at_ms) \
                         VALUES (?1, ?2, ?3, ?4, ?5, 99)",
                        rusqlite::params![
                            entry.principal_kind,
                            entry.principal_id,
                            kind,
                            selector,
                            entry.operation.as_str()
                        ],
                    )?;
                }
                Ok(())
            })
            .unwrap();

    assert_eq!(
        schema_10_grants(&migrated),
        schema_10_grants(&fresh),
        "created_at_ms is excluded by name because migrated rows retain their schema-9 timestamp"
    );
}

/// One credential the way a real store carries it: a row whose `updated_at_ms` is a
/// LATER write time than its deposit, a chain deposit entry that dates it, an
/// earlier non-deposit entry and a later one.
///
/// Each decoy is a different wrong answer. Reading the row's own write time gives
/// `birth_ms + 500_000`; taking the minimum over every op in the chain gives
/// `birth_ms - 1_000`; only the earliest DEPOSIT entry gives `birth_ms`.
fn seed_credential_at_schema_9(
    conn: &rusqlite::Connection,
    credential_id: &str,
    birth_ms: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO credentials \
             (credential_id, record_version, key_id, state, envelope, updated_at_ms) \
             VALUES (?1, 1, '00', 'active', X'00', ?2)",
        rusqlite::params![credential_id, birth_ms + 500_000],
    )?;
    for (ts_ms, op) in [
        (birth_ms - 1_000, "fetch_anomaly"),
        (birth_ms, "put"),
        (birth_ms + 500_000, "overwrite"),
    ] {
        append_unverified_chain_row(conn, ts_ms, op, credential_id)?;
    }
    Ok(())
}

/// Append a chain row with placeholder MACs. Every test using this one asks what the
/// migration DERIVES from the chain, never whether the chain verifies, and the real
/// append path needs an unsealed audit key this fixture has no use for.
fn append_unverified_chain_row(
    conn: &rusqlite::Connection,
    ts_ms: i64,
    op: &str,
    credential_id: &str,
) -> rusqlite::Result<()> {
    conn.execute(
            "INSERT INTO audit_log \
             (ts_ms, op, credential_id, payload_hash, actor, alarm, alarm_reason, prev_mac, entry_mac) \
             VALUES (?1, ?2, ?3, NULL, 'test', 0, NULL, 'previous', 'entry')",
            rusqlite::params![ts_ms, op, credential_id],
        )?;
    Ok(())
}

fn seed_schema_9_ids(store: &SqliteStore, credential_ids: &[&str]) {
    store
        .with_conn(|conn| {
            for (index, credential_id) in credential_ids.iter().enumerate() {
                seed_credential_at_schema_9(conn, credential_id, 1_700_000_000_000 + index as i64)?;
            }
            Ok(())
        })
        .expect("seed schema-9 credentials");
}

fn insert_schema_9_grant(conn: &rusqlite::Connection, row: &Migration10Conversion) {
    conn.execute(
            "INSERT INTO read_grants \
             (principal_kind, principal_id, selector_kind, credential_prefix, operation, created_at_ms) \
             VALUES (?1, ?2, 'prefix', ?3, ?4, 7)",
            rusqlite::params![
                row.principal_kind,
                row.principal_id,
                row.old_selector,
                row.operation.as_str()
            ],
        )
        .expect("insert schema-9 conversion-table grant");
}

fn schema_9_grants(store: &SqliteStore) -> Vec<(String, String, String, String, String)> {
    store
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT principal_kind, principal_id, selector_kind, credential_prefix, operation \
                     FROM read_grants ORDER BY principal_kind, principal_id, selector_kind, credential_prefix, operation",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .expect("read schema-9 grants")
}

fn schema_10_grants(store: &SqliteStore) -> Vec<(String, String, String, String, String)> {
    store
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT principal_kind, principal_id, selector_kind, selector, operation \
                     FROM read_grants ORDER BY principal_kind, principal_id, selector_kind, selector, operation",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .expect("read schema-10 grants")
}

fn category_assignments(store: &SqliteStore) -> Vec<(String, String)> {
    store
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT credential_id, category FROM credential_categories ORDER BY credential_id, category",
                )?;
                let rows = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .expect("read category assignments")
}

fn category_conversion() -> &'static Migration10Conversion {
    MIGRATION_10_CONVERSION_TABLE
        .iter()
        .find(|entry| matches!(entry.replacement, Migration10Replacement::Category { .. }))
        .expect("the ruling-9 table has one category conversion")
}

fn category_conversion_parts() -> (&'static str, &'static [&'static str]) {
    match category_conversion().replacement {
        Migration10Replacement::Category {
            selector,
            assignments,
        } => (selector, assignments),
        Migration10Replacement::Exact { .. } => unreachable!(),
    }
}

fn seed_verified_schema_9_ids(
    store: &SqliteStore,
    key: &MasterKey,
    credential_ids: &BTreeSet<&'static str>,
) {
    let audit_key = load_or_create_audit_key(store, key).expect("create the fixture audit key");
    store
        .with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            for credential_id in credential_ids {
                tx.execute(
                    "INSERT INTO credentials \
                         (credential_id, record_version, key_id, state, envelope, updated_at_ms) \
                         VALUES (?1, 1, '00', 'active', X'00', 9)",
                    rusqlite::params![credential_id],
                )?;
                append_audit_tx(
                    &tx,
                    &audit_key,
                    &AuditRecord {
                        op: AuditOp::Put,
                        credential_id: Some((*credential_id).to_string()),
                        payload_hash: None,
                        actor: "fixture".to_string(),
                        alarm: None,
                    },
                )?;
            }
            tx.commit()
        })
        .expect("seed credentials with a verifiable birth chain");
}

fn live_conversion_credential_ids() -> BTreeSet<&'static str> {
    let mut ids = BTreeSet::new();
    for entry in MIGRATION_10_CONVERSION_TABLE {
        match entry.replacement {
            Migration10Replacement::Exact { selector } => {
                ids.insert(selector);
            }
            Migration10Replacement::Category { assignments, .. } => {
                ids.extend(assignments.iter().copied());
            }
        }
    }
    ids
}

/// Every schema object this vault owns, as (type, name, sql), name-ordered.
///
/// `cortexkit`-prefixed objects are excluded because they belong to the storage
/// crate rather than to this schema: the version table it writes, and the fence
/// table it creates lazily on the first fenced write, so its presence says which
/// paths a store has exercised rather than which migrations it carries.
fn vault_schema_objects(store: &SqliteStore) -> Vec<(String, String, String)> {
    store
        .with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT type, name, COALESCE(sql, '') FROM sqlite_master \
                      WHERE name NOT LIKE 'cortexkit%' ORDER BY name",
            )?;
            let objects = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(objects)
        })
        .expect("read sqlite_master")
}

fn object_sql(objects: &[(String, String, String)], name: &str) -> String {
    objects
        .iter()
        .find(|(_, object, _)| object == name)
        .unwrap_or_else(|| {
            let names: Vec<&str> = objects.iter().map(|(_, n, _)| n.as_str()).collect();
            panic!("{name} is absent from the schema; it holds {names:?}")
        })
        .2
        .clone()
}

/// (name, declared type, NOT NULL, default, part of the primary key) per column.
fn columns_of(
    store: &SqliteStore,
    table: &str,
) -> Vec<(String, String, bool, Option<String>, bool)> {
    store
        .with_conn(|conn| {
            let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
            let columns = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)? != 0,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, i64>(5)? != 0,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(columns)
        })
        .expect("read table_info")
}

fn generation_of(store: &SqliteStore) -> i64 {
    store
        .with_conn(|conn| conn.query_row("SELECT value FROM grants_generation", [], |r| r.get(0)))
        .expect("read the grant generation")
}

fn schema_version_of(store: &SqliteStore) -> u32 {
    store
        .with_conn(read_schema_version)
        .expect("read the schema version")
}

#[test]
fn migration_11_preserves_all_grants_generation_and_every_other_schema_object() {
    let (root, store) = sqlite("migration-11", 117);
    migrate_through_for_test(&store, 10).expect("schema 10");
    store.with_conn(|conn| {
            for (kind, id, selector_kind, selector, operation, timestamp) in [
                ("reserved", "agent", "exact", "apikey:one", "read", 7),
                ("enrolled", "consumer", "category", "llm-provider", "sign", 9),
                ("reserved", "agent", "category", "github", "read", 11),
                ("enrolled", "consumer", "exact", "apikey:two", "sign", 13),
            ] {
                conn.execute(
                    "INSERT INTO read_grants (principal_kind, principal_id, selector_kind, selector, operation, created_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![kind, id, selector_kind, selector, operation, timestamp],
                )?;
            }
            conn.execute("UPDATE grants_generation SET value = 42 WHERE id = 1", [])?;
            Ok(())
        }).expect("seed both selectors and operations");
    let rows = |store: &SqliteStore| {
        store.with_conn(|conn| {
                let mut stmt = conn.prepare("SELECT principal_kind, principal_id, selector_kind, selector, operation, created_at_ms FROM read_grants ORDER BY principal_kind, principal_id, selector_kind, selector, operation")?;
                let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, i64>(5)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            }).expect("read all six grant columns")
    };
    let before_rows = rows(&store);
    let before_objects = vault_schema_objects(&store);
    let old_ddl = object_sql(&before_objects, "read_grants");
    assert!(old_ddl.contains("CHECK(operation IN ('read', 'sign'))"));
    assert_eq!(generation_of(&store), 42);
    // Through 11 only: this pins what migration 11 alone changes, and a later
    // migration's DDL would otherwise show up in the object comparison below.
    migrate_through_for_test(&store, 11).expect("schema 11");
    assert_eq!(schema_version_of(&store), 11);
    assert_eq!(
        rows(&store),
        before_rows,
        "every column of every grant survives"
    );
    assert_eq!(
        generation_of(&store),
        42,
        "a DDL-only migration is not a grant mutation"
    );
    let after_objects = vault_schema_objects(&store);
    let expected: Vec<_> = before_objects
        .into_iter()
        .map(|(kind, name, ddl)| {
            if name == "read_grants" {
                (
                    kind,
                    name,
                    ddl.replace(
                        "CHECK(operation IN ('read', 'sign'))",
                        "CHECK(operation IN ('read', 'sign', 'open'))",
                    ),
                )
            } else {
                (kind, name, ddl)
            }
        })
        .collect();
    assert_eq!(
        after_objects, expected,
        "only the operation CHECK may change"
    );
    let (grants, version) =
        list_read_grants_read_only_with_schema(&root.join("store.db")).expect("schema 11 read");
    assert_eq!(version, 11);
    assert_eq!(grants.len(), 4);
}

#[test]
fn migration_17_conserves_every_grant_and_enforces_audience_pairs() {
    let (_root, store) = sqlite("migration-17", 173);
    migrate_through_for_test(&store, 16).unwrap();
    store
        .with_conn(|conn| {
            let mut timestamp = 100;
            for principal in ["reserved", "enrolled"] {
                for selector_kind in ["exact", "category"] {
                    for operation in ["read", "sign", "open", "list", "deposit"] {
                        timestamp += 1;
                        conn.execute(
                            "INSERT INTO read_grants VALUES (?1,'agent',?2,?3,?4,?5)",
                            rusqlite::params![
                                principal,
                                selector_kind,
                                format!("selector-{timestamp}"),
                                operation,
                                timestamp
                            ],
                        )?;
                    }
                }
            }
            conn.execute("UPDATE grants_generation SET value=57 WHERE id=1", [])?;
            Ok(())
        })
        .unwrap();
    let rows = |store: &SqliteStore| {
        store.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT principal_kind,principal_id,selector_kind,selector,operation,created_at_ms FROM read_grants ORDER BY 1,2,3,4,5")?;
            let rows = stmt.query_map([], |r| Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,String>(2)?, r.get::<_,String>(3)?, r.get::<_,String>(4)?, r.get::<_,i64>(5)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        }).unwrap()
    };
    let before = rows(&store);
    assert_eq!(before.len(), 20);
    migrate_through_for_test(&store, 17).unwrap();
    assert_eq!(rows(&store), before, "all six columns survive unchanged");
    assert_eq!(generation_of(&store), 57);
    store.with_conn(|conn| {
            conn.execute("INSERT INTO read_grants VALUES ('reserved','ck-motor','audience','cortexkit-runners','account_token',999)",[])?;
            for (kind, operation) in [("exact","account_token"),("category","account_token"),("audience","read"),("audience","sign"),("audience","open"),("audience","list"),("audience","deposit")] {
                assert!(conn.execute("INSERT INTO read_grants VALUES ('reserved','bad',?1,'cortexkit-runners',?2,1000)", rusqlite::params![kind,operation]).is_err(),"{kind}/{operation}");
            }
            Ok(())
        }).unwrap();
}

#[test]
fn migration_44_preserves_every_step_43_row_and_leaves_plan_starts_unknown() {
    let (_root, sqlite) = sqlite("plan-since-upgrade", 212);
    migrate_through_for_test(&sqlite, 43).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([212; 32])).unwrap();
    let id = "apikey:plan-upgrade";
    store
        .create_audited(id, &api_record(), AuditCtx::admin(AuditOp::Put))
        .unwrap();
    store
        .set_plan_audited(id, Some("plus"), AuditCtx::admin(AuditOp::SetPlan))
        .unwrap();
    store
        .create_read_grant_audited(
            "reserved",
            "upgrade-reader",
            SelectorKind::Exact,
            id,
            GrantOperation::List,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let gateway = super::gateway_create_tests::settings();
    crate::admin_ops::apply(
        &store,
        crate::admin_ops::AdminOpBody::GatewayCreate {
            v: crate::admin_ops::ADMIN_OP_SCHEMA_V2,
            id: "apikey:anthropic-gw-upgrade".into(),
            record: Box::new(api_record()),
            audit_op: crate::admin_ops::AdminAuditOp::Put,
            base_url: gateway.base_url,
            auth_header: gateway.auth.header,
            auth_scheme: gateway.auth.scheme,
            headers: gateway.headers,
            provider_ids: vec!["anthropic-gw-upgrade".into()],
        },
        "operator",
    )
    .unwrap();
    let remote = "oauth:anthropic:upgrade";
    store
        .remote_add_audited(&crate::federation::NewRemoteRecord {
            credential_id: remote.into(),
            home_member: "fed-computer:0123456789abcdef0123456789abcdef".into(),
            refresh_adapter: Some("anthropic".into()),
            detected_plan: None,
            identity: crate::record::RecordIdentity::default(),
            home_version: 7,
            categories: vec![],
        })
        .unwrap();
    store
        .set_plan_audited(remote, Some("pro"), AuditCtx::admin(AuditOp::SetPlan))
        .unwrap();
    let before = every_table_row(&store.store);
    assert_eq!(before["credentials"].len(), 2);
    assert_eq!(before["credential_plan_tiers"].len(), 1);
    assert_eq!(before["remote_record_plan_tiers"].len(), 1);
    assert_eq!(before["credential_gateway_settings"].len(), 1);
    assert_eq!(before["read_grants"].len(), 1);
    migrate_through_for_test(&store.store, 44).unwrap();
    assert_eq!(store.with_raw_conn(read_schema_version).unwrap(), 44);
    let mut after = every_table_row(&store.store);
    for table in ["credential_plan_tiers", "remote_record_plan_tiers"] {
        for row in after.get_mut(table).unwrap() {
            assert_eq!(
                row.pop(),
                Some(rusqlite::types::Value::Null),
                "{table} must not invent a start"
            );
        }
    }
    assert_eq!(
        after, before,
        "every pre-existing column in every table is byte-identical"
    );
    assert_eq!(store.meta(id).unwrap().plan_tier_since_ms, None);
    assert_eq!(
        store.remote_inventory().unwrap()[0].plan_tier_since_ms,
        None
    );
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn migration_45_adds_only_an_empty_declaration_inventory_and_preserves_every_row() {
    let (_root, sqlite) = sqlite("declarations-upgrade", 227);
    migrate_through_for_test(&sqlite, 44).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([227; 32])).unwrap();
    store
        .create_audited(
            "apikey:anthropic",
            &api_record(),
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
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
    let before = every_table_row(&store.store);
    EncryptedStore::migrate(&store.store).unwrap();
    assert_eq!(store.with_raw_conn(read_schema_version).unwrap(), 53);
    let mut after = every_table_row(&store.store);
    assert_eq!(after.remove("declared_grant_sets"), Some(vec![]));
    for table in [
        "agent_policies",
        "broker_action_requests",
        "credential_conditions",
        "fleet_discards",
        "fleet_epochs",
        "fleet_removals",
        "hub_login_homes",
        "hub_login_targets",
        "hub_manifest_high_water",
        "hub_own_report",
        "hub_report_task",
        "module_secrets",
        "remote_record_conditions",
    ] {
        assert_eq!(after.remove(table), Some(vec![]));
    }
    for row in after.get_mut("credentials").unwrap() {
        for _ in [
            "github_app_id",
            "github_app_slug",
            "github_app_created_at_ms",
            "github_app_agent",
            "github_app_relay_slot",
        ] {
            assert_eq!(row.pop(), Some(rusqlite::types::Value::Null));
        }
    }
    assert_eq!(after, before);
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn policy_root_init_refuses_a_step_51_vault_with_a_lost_root() {
    let (_root, sqlite) = sqlite("policy-root-lost", 226);
    migrate_through_for_test(&sqlite, 51).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([226; 32])).unwrap();
    store.with_raw_conn(|conn| {
        conn.execute(
            "INSERT INTO gh_manifests VALUES (1, X'01', ?1, '0123456789abcdef', zeroblob(64), 1, 'import', NULL)",
            ["a".repeat(64)],
        )
    }).unwrap();
    migrate_through_for_test(&store.store, 52).unwrap();
    let before = every_table_row(&store.store);
    assert!(before["credentials"].is_empty());
    let refused = store.init_policy_root_admin("operator").unwrap_err();
    assert_eq!(refused.wire_code(), Some("policy_root_established"));
    assert_eq!(refused.wire_class(), Some("permanent"));
    assert_eq!(every_table_row(&store.store), before);
}

#[test]
fn migration_52_seeds_an_active_legacy_root_and_preserves_step_51_rows_on_a_copy() {
    use base64::Engine as _;
    use rusqlite::{params, types::Value};

    let (root, sqlite) = sqlite("root-setting-upgrade", 229);
    migrate_through_for_test(&sqlite, 51).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([229; 32])).unwrap();
    let der =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(der.as_ref())
    );
    store
        .create(
            GH_MANIFEST_ROOT_KEY_ID,
            &VaultRecord::new_static(CredentialKind::SigningKey, "test", pem.into_bytes(), None),
        )
        .unwrap();
    store.create("github_app:sample", &api_record()).unwrap();
    store
        .create_read_grant_audited(
            "reserved",
            "migration-fixture",
            SelectorKind::Exact,
            "github_app:sample",
            GrantOperation::PolicyToken,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    store.with_raw_conn(|conn| {
        let hash = "a".repeat(64);
        let signature = [7_u8; 64];
        conn.execute_batch("UPDATE credentials SET github_app_id='123', github_app_slug='sample' WHERE credential_id='github_app:sample';")?;
        conn.execute(
            "INSERT INTO gh_manifests VALUES (1, X'01', ?1, '0123456789abcdef', ?2, 1, 'import', NULL)",
            params![hash, signature.as_slice()],
        )?;
        conn.execute(
            "INSERT INTO agent_policies VALUES (1, X'02', ?1, '0123456789abcdef', ?2, 1, 'ceremony', 1, 1)",
            params![hash, signature.as_slice()],
        )?;
        Ok(())
    }).unwrap();
    let original = every_table_row(&store.store);
    let legacy_timestamp = store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT updated_at_ms FROM credentials WHERE credential_id=?1",
                [GH_MANIFEST_ROOT_KEY_ID],
                |r| r.get::<_, i64>(0),
            )
        })
        .unwrap();
    assert_eq!(original["credentials"].len(), 2);
    for table in ["agent_policies", "read_grants", "gh_manifests"] {
        assert_eq!(original[table].len(), 1);
    }
    let seed = vec![
        Value::Text("policy_root_credential".into()),
        Value::Text(GH_MANIFEST_ROOT_KEY_ID.into()),
        Value::Integer(legacy_timestamp),
    ];

    for (label, legacy_state, with_key) in [
        ("keyless", Some("active"), false),
        ("keyed", Some("active"), true),
        ("retired", Some("retired"), false),
        ("absent", None, false),
    ] {
        let path = root
            .join(format!("{label}.db"))
            .to_string_lossy()
            .into_owned();
        store
            .with_raw_conn(|conn| conn.execute("VACUUM INTO ?1", [&path]))
            .unwrap();
        let copy = open_sqlite(&StorageDescriptor {
            module_id: "claustrum".into(),
            storage_namespace: format!("root-setting-{label}"),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite { path },
        })
        .unwrap();
        copy.with_conn(|conn| {
            assert_eq!(read_schema_version(conn)?, 51);
            match legacy_state {
                Some("active") => (),
                Some(state) => {
                    conn.execute(
                        "UPDATE credentials SET state=?1 WHERE credential_id=?2",
                        params![state, GH_MANIFEST_ROOT_KEY_ID],
                    )?;
                }
                None => {
                    conn.execute(
                        "DELETE FROM credentials WHERE credential_id=?1",
                        [GH_MANIFEST_ROOT_KEY_ID],
                    )?;
                }
            }
            Ok(())
        })
        .unwrap();
        let before = every_table_row(&copy);
        if with_key {
            EncryptedStore::migrate_with_key(&copy, &MasterKey::from_bytes([229; 32])).unwrap();
        } else {
            EncryptedStore::migrate(&copy).unwrap();
        }
        assert_eq!(copy.with_conn(read_schema_version).unwrap(), 53);
        let mut after = every_table_row(&copy);
        assert_eq!(after.remove("broker_action_requests"), Some(vec![]));
        let settings = after.get_mut("settings").unwrap();
        let seeded = settings.iter().position(|row| row[0] == seed[0]);
        assert_eq!(
            seeded.map(|index| settings.remove(index)).as_ref(),
            (legacy_state == Some("active")).then_some(&seed),
            "{label}"
        );
        for row in after.get_mut("credentials").unwrap() {
            for _ in 0..3 {
                assert_eq!(row.pop(), Some(Value::Null), "{label}");
            }
        }
        assert_eq!(after, before, "{label}");
    }
    assert_eq!(every_table_row(&store.store), original);
}

#[test]
fn migration_53_broker_action_adds_only_its_table_to_a_step_52_copy() {
    let (root, sqlite) = sqlite("broker-action-upgrade", 229);
    migrate_through_for_test(&sqlite, 52).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([229; 32])).unwrap();
    store
        .create_audited(
            "github_app:sample",
            &api_record(),
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
    store
        .create_read_grant_audited(
            "reserved",
            "aft",
            SelectorKind::Exact,
            "github_app:sample",
            GrantOperation::PolicyToken,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    store.with_raw_conn(|conn| {
        let hash = "a".repeat(64);
        conn.execute(
            "INSERT INTO gh_manifests VALUES (1, X'01', ?1, '0123456789abcdef', zeroblob(64), 1, 'import', NULL)",
            [&hash],
        )?;
        conn.execute(
            "INSERT INTO agent_policies VALUES (1, X'02', ?1, '0123456789abcdef', zeroblob(64), 1, 'ceremony', 1, 1)",
            [&hash],
        )?;
        Ok(())
    }).unwrap();

    let path = root
        .join("broker-action-copy.db")
        .to_string_lossy()
        .into_owned();
    store
        .with_raw_conn(|conn| conn.execute("VACUUM INTO ?1", [&path]))
        .unwrap();
    let copy = open_sqlite(&StorageDescriptor {
        module_id: "claustrum".into(),
        storage_namespace: "broker-action-copy".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite { path },
    })
    .unwrap();
    assert_eq!(schema_version_of(&copy), 52);
    let before = table_rows(&copy, |_| true);
    for table in [
        "agent_policies",
        "audit_log",
        "credentials",
        "gh_manifests",
        "read_grants",
    ] {
        assert!(
            !before[table].is_empty(),
            "the copy must carry {table} rows"
        );
    }
    let existing_schema = |db: &SqliteStore| {
        db.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT type, name, tbl_name, sql FROM sqlite_schema
                 WHERE tbl_name <> 'broker_action_requests' ORDER BY type, name",
            )?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<String>>(3)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .unwrap()
    };
    let before_schema = existing_schema(&copy);

    migrate_through_for_test(&copy, 53).unwrap();

    assert_eq!(schema_version_of(&copy), 53);
    assert_eq!(existing_schema(&copy), before_schema);
    let mut after = table_rows(&copy, |_| true);
    assert_eq!(after.remove("broker_action_requests"), Some(vec![]));
    // Only the migration runner's new version row may differ in an existing table.
    let versions = after.get_mut("cortexkit_schema_version").unwrap();
    let before_versions = &before["cortexkit_schema_version"];
    assert_eq!(versions.len(), before_versions.len() + 1);
    versions.retain(|row| before_versions.contains(row));
    assert_eq!(after, before);
    assert_eq!(schema_version_of(&store.store), 52);
}

#[test]
fn migration_46_preserves_secret_rows_and_adds_only_nullable_local_use() {
    let (_root, sqlite) = sqlite("local-program-upgrade", 228);
    migrate_through_for_test(&sqlite, 45).unwrap();
    sqlite.with_conn(|conn| {
            conn.execute_batch("INSERT INTO agent_secrets VALUES ('legacy','agent_api_key','00000000000000000000000000000001','active','x.test',NULL,'authorization_bearer',NULL,1,'key',X'0102',1,NULL);
                INSERT INTO agent_secrets VALUES ('extended','site_login','00000000000000000000000000000002','active',NULL,NULL,NULL,NULL,1,'key',X'0304',2,'[\"https://a.test\",\"https://b.test\"]');
                INSERT INTO secret_grants (grant_id,secret_name,incarnation,scope_owner,scope_kind,scope_ref,coverage,duration,expires_at_ms,granted_at_ms,envelope_sha256) VALUES ('g','legacy','00000000000000000000000000000001','owner','head','H','scope','hour',100,1,'digest');
                INSERT INTO secret_pending_requests (request_id,request_kind,secret_name,incarnation,member_id,statement_bytes,statement_sha256,request_expires_at_ms) VALUES ('r','approve','legacy','00000000000000000000000000000001','member',X'0506','digest',100);")
        }).unwrap();
    let before = every_table_row(&sqlite);
    EncryptedStore::migrate(&sqlite).unwrap();
    let mut after = every_table_row(&sqlite);
    for table in [
        "agent_policies",
        "broker_action_requests",
        "credential_conditions",
        "fleet_discards",
        "fleet_epochs",
        "fleet_removals",
        "hub_login_homes",
        "hub_login_targets",
        "hub_manifest_high_water",
        "hub_own_report",
        "hub_report_task",
        "module_secrets",
        "remote_record_conditions",
    ] {
        assert_eq!(after.remove(table), Some(vec![]));
    }
    for table in ["secret_grants", "secret_pending_requests"] {
        assert_eq!(after[table].len(), 1);
        assert_eq!(
            after.get_mut(table).unwrap()[0].pop(),
            Some(rusqlite::types::Value::Null)
        );
    }
    assert_eq!(
        after, before,
        "migration must preserve every pre-existing byte"
    );
    sqlite.with_conn(|conn| {
            let insert = "INSERT INTO agent_secrets (name,kind,incarnation,state,host,path_prefix,location,origin,record_version,key_id,envelope,created_at_ms,scope_json) VALUES ('local','local_program','00000000000000000000000000000003','active',?1,?2,?3,?4,1,'key',X'0708',3,?5)";
            for (host, prefix, location, origin, scope) in [
                (None, None, None, None, None),
                (Some("x.test"), None, None, None, Some("{}")),
                (None, Some("/"), None, None, Some("{}")),
                (None, None, Some("header:X"), None, Some("{}")),
                (None, None, None, Some("https://x.test"), Some("{}")),
            ] {
                assert!(conn.execute(insert, rusqlite::params![host,prefix,location,origin,scope]).is_err());
            }
            conn.execute(insert, rusqlite::params![None::<String>,None::<String>,None::<String>,None::<String>,"{}"])?;
            Ok(())
        }).unwrap();
}

/// Every row of every vault table, sorted by all of its columns, keyed by table name.
/// Used to show a DDL-only migration copied every row of every table unchanged. Sorted
/// rather than in rowid order because a rebuilt table assigns fresh rowids, and the
/// migration runner's own version table is left out because it is meant to change.
fn every_table_row(store: &SqliteStore) -> TableRows {
    table_rows(store, |name| {
        !name.starts_with("sqlite_") && !name.starts_with("cortexkit")
    })
}

type TableRows = BTreeMap<String, Vec<Vec<rusqlite::types::Value>>>;

fn table_rows(store: &SqliteStore, include: impl Fn(&str) -> bool) -> TableRows {
    store
        .with_conn(|conn| {
            let mut names =
                conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")?;
            let names = names
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut tables = BTreeMap::new();
            for name in names.into_iter().filter(|name| include(name)) {
                let width = conn
                    .prepare(&format!("SELECT * FROM \"{name}\" LIMIT 0"))?
                    .column_count();
                let order = (1..=width)
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                let mut stmt =
                    conn.prepare(&format!("SELECT * FROM \"{name}\" ORDER BY {order}"))?;
                let rows = stmt
                    .query_map([], |row| {
                        (0..width)
                            .map(|i| row.get::<_, rusqlite::types::Value>(i))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                tables.insert(name, rows);
            }
            Ok(tables)
        })
        .expect("dump every table")
}

#[test]
fn migration_18_admits_exact_seal_grants_and_conserves_every_row_counter_and_object() {
    let (_root, store) = sqlite("migration-18", 183);
    migrate_through_for_test(&store, 17).unwrap();
    let insert_grant = |conn: &rusqlite::Connection,
                        principal: &str,
                        selector_kind: &str,
                        selector: &str,
                        operation: &str,
                        timestamp: i64| {
        conn.execute(
            "INSERT INTO read_grants VALUES (?1,'agent',?2,?3,?4,?5)",
            rusqlite::params![principal, selector_kind, selector, operation, timestamp],
        )
    };
    store
            .with_conn(|conn| {
                // Every schema-17 operation over every selector kind it may carry, for
                // both principal kinds.
                let mut timestamp = 100;
                for principal in ["reserved", "enrolled"] {
                    for (selector_kind, operation) in [
                        ("exact", "read"),
                        ("exact", "sign"),
                        ("exact", "open"),
                        ("exact", "list"),
                        ("exact", "deposit"),
                        ("category", "read"),
                        ("category", "sign"),
                        ("category", "open"),
                        ("category", "list"),
                        ("category", "deposit"),
                        ("audience", "account_token"),
                    ] {
                        timestamp += 1;
                        insert_grant(
                            conn,
                            principal,
                            selector_kind,
                            &format!("selector-{timestamp}"),
                            operation,
                            timestamp,
                        )?;
                    }
                }
                // Companion tables a grant rebuild must not touch.
                conn.execute(
                    "INSERT INTO credentials (credential_id, record_version, key_id, state, envelope, updated_at_ms, created_at_ms) \
                     VALUES ('kem:push', 3, '00', 'active', X'00', 7, 7)",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO credential_categories VALUES ('kem:push', 'push-keys')",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO credential_provider_ids VALUES ('kem:push', 'apns')",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO credential_plan_tiers VALUES ('kem:push', 'pro')",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO audit_log \
                     (seq, ts_ms, op, credential_id, payload_hash, actor, alarm, alarm_reason, prev_mac, entry_mac) \
                     VALUES (1, 1, 'put', 'kem:push', NULL, 'test', 0, NULL, 'previous', 'entry')",
                    [],
                )?;
                conn.execute("UPDATE grants_generation SET value = 57 WHERE id = 1", [])?;
                Ok(())
            })
            .unwrap();
    // Schema 17 must refuse `seal`, or the migration below proves nothing about it.
    assert!(store
        .with_conn(|conn| insert_grant(conn, "reserved", "exact", "kem:push", "seal", 1))
        .is_err());
    let before_rows = every_table_row(&store);
    assert_eq!(before_rows["read_grants"].len(), 22);
    let before_objects = vault_schema_objects(&store);
    let old_ddl = object_sql(&before_objects, "read_grants");

    migrate_through_for_test(&store, 18).unwrap();
    assert_eq!(schema_version_of(&store), 18);
    assert_eq!(
        every_table_row(&store),
        before_rows,
        "every row of every table, grants included, survives byte for byte"
    );
    assert_eq!(
        generation_of(&store),
        57,
        "a DDL-only migration is not a grant mutation"
    );
    let after_objects = vault_schema_objects(&store);
    let new_ddl = object_sql(&after_objects, "read_grants");
    assert_ne!(new_ddl, old_ddl);
    assert!(new_ddl.contains("'account_token','seal')"));
    assert!(new_ddl.contains("CHECK (operation <> 'seal' OR selector_kind = 'exact')"));
    assert!(
        new_ddl.contains("CHECK ((operation = 'account_token') = (selector_kind = 'audience'))")
    );
    let others = |objects: &[(String, String, String)]| {
        objects
            .iter()
            .filter(|(_, name, _)| name != "read_grants")
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(
        others(&after_objects),
        others(&before_objects),
        "only the grant table's DDL may change"
    );

    store
        .with_conn(|conn| {
            insert_grant(conn, "reserved", "exact", "kem:push", "seal", 900)?;
            for selector_kind in ["category", "audience"] {
                assert!(
                    insert_grant(conn, "reserved", selector_kind, "push-keys", "seal", 901)
                        .is_err(),
                    "{selector_kind} seal"
                );
            }
            // The account_token pairing survives the rebuild.
            assert!(insert_grant(conn, "reserved", "exact", "x", "account_token", 902).is_err());
            Ok(())
        })
        .unwrap();
}

#[test]
fn migration_13_admits_list_and_copies_every_grant_without_touching_the_generation() {
    let (root, store) = sqlite("migration-13", 124);
    migrate_through_for_test(&store, 12).expect("schema 12");
    store.with_conn(|conn| {
            for (kind, id, selector_kind, selector, operation, timestamp) in [
                ("reserved", "agent", "exact", "apikey:one", "read", 7),
                ("enrolled", "consumer", "category", "llm-provider", "sign", 9),
                ("reserved", "agent", "category", "github", "open", 11),
                ("enrolled", "consumer", "exact", "kem:two", "open", 13),
            ] {
                conn.execute(
                    "INSERT INTO read_grants (principal_kind, principal_id, selector_kind, selector, operation, created_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![kind, id, selector_kind, selector, operation, timestamp],
                )?;
            }
            conn.execute("UPDATE grants_generation SET value = 57 WHERE id = 1", [])?;
            Ok(())
        }).expect("seed every schema-12 operation over both selectors");
    // Schema 12 must refuse `list`, or the migration below proves nothing about it.
    let refused = store.with_conn(|conn| {
            conn.execute(
                "INSERT INTO read_grants (principal_kind, principal_id, selector_kind, selector, operation, created_at_ms) VALUES ('reserved', 'router', 'category', 'llm-provider', 'list', 1)",
                [],
            )
        });
    assert!(refused.is_err(), "schema 12 has no `list` operation");
    let rows = |store: &SqliteStore| {
        store.with_conn(|conn| {
                let mut stmt = conn.prepare("SELECT principal_kind, principal_id, selector_kind, selector, operation, created_at_ms FROM read_grants ORDER BY principal_kind, principal_id, selector_kind, selector, operation")?;
                let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, i64>(5)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            }).expect("read all six grant columns")
    };
    let before_rows = rows(&store);
    assert_eq!(before_rows.len(), 4);
    let before_objects = vault_schema_objects(&store);
    let old_ddl = object_sql(&before_objects, "read_grants");
    assert!(old_ddl.contains("CHECK(operation IN ('read', 'sign', 'open'))"));

    migrate_through_for_test(&store, 13).expect("schema 13");
    assert_eq!(schema_version_of(&store), 13);
    assert_eq!(
        rows(&store),
        before_rows,
        "every column of every grant survives byte for byte"
    );
    assert_eq!(
        generation_of(&store),
        57,
        "a DDL-only migration is not a grant mutation"
    );
    let after_objects = vault_schema_objects(&store);
    let expected: Vec<_> = before_objects
        .into_iter()
        .map(|(kind, name, ddl)| {
            if name == "read_grants" {
                (
                    kind,
                    name,
                    ddl.replace(
                        "CHECK(operation IN ('read', 'sign', 'open'))",
                        "CHECK(operation IN ('read', 'sign', 'open', 'list'))",
                    ),
                )
            } else {
                (kind, name, ddl)
            }
        })
        .collect();
    assert_eq!(
        after_objects, expected,
        "only the operation CHECK may change"
    );

    store.with_conn(|conn| {
            conn.execute(
                "INSERT INTO read_grants (principal_kind, principal_id, selector_kind, selector, operation, created_at_ms) VALUES ('reserved', 'router', 'category', 'llm-provider', 'list', 15)",
                [],
            )
        }).expect("schema 13 stores a list grant");
    let (grants, version) =
        list_read_grants_read_only_with_schema(&root.join("store.db")).expect("schema 13 read");
    assert_eq!(version, 13);
    assert_eq!(grants.len(), 5);
    assert!(grants
        .iter()
        .any(|grant| grant.operation == GrantOperation::List && grant.principal_id == "router"));
}

fn pending_proposer(store: &EncryptedStore, request_id: &str) -> (Option<String>, Option<String>) {
    store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT proposer_kind, proposer_id FROM pending_enrollments WHERE request_id = ?1",
                [request_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })
        .expect("read the stored proposer")
}

#[test]
fn a_proposal_stores_its_proposer_on_the_pending_row() {
    let (root, store) = rig("proposer-stored", 121);
    let reserved = store
        .propose_enrollment_by(
            Some(AuthEventPrincipal::Reserved("insula")),
            "module-consumer",
            &"a".repeat(64),
        )
        .expect("reserved propose");
    let direct = store
        .propose_enrollment_by(
            Some(AuthEventPrincipal::Direct),
            "host-consumer",
            &"b".repeat(64),
        )
        .expect("direct propose");
    assert_eq!(
        pending_proposer(&store, &reserved.request_id),
        (Some("reserved".to_string()), Some("insula".to_string()))
    );
    assert_eq!(
        pending_proposer(&store, &direct.request_id),
        (Some("direct".to_string()), None),
        "a direct principal carries no id"
    );

    // The lease-free reader carries the same two fields out to the CLI.
    let (rows, version) = list_enrollments_read_only_with_schema(&root.join("store.db"))
        .expect("lease-free enrollment read");
    assert_eq!(version, newest_migration_version());
    let row = rows
        .iter()
        .find(|row| row.key == reserved.request_id)
        .expect("reserved row listed");
    assert_eq!(row.proposer_kind.as_deref(), Some("reserved"));
    assert_eq!(row.proposer_id.as_deref(), Some("insula"));
}

#[test]
fn resuming_a_proposal_as_another_principal_keeps_the_original_proposer() {
    let (_root, store) = rig("proposer-resume", 122);
    let secret = "c".repeat(64);
    let first = store
        .propose_enrollment_by(
            Some(AuthEventPrincipal::Reserved("insula")),
            "resumed-consumer",
            &secret,
        )
        .expect("first propose");
    let resumed = store
        .propose_enrollment_by(
            Some(AuthEventPrincipal::Direct),
            "resumed-consumer",
            &secret,
        )
        .expect("same name and secret resumes");
    assert_eq!(
        resumed.request_id, first.request_id,
        "a resume, not a new row"
    );
    assert_eq!(
        pending_proposer(&store, &first.request_id),
        (Some("reserved".to_string()), Some("insula".to_string())),
        "a resume must not rewrite who the operator sees as the proposer"
    );
}

#[test]
fn migration_12_leaves_existing_pending_rows_without_a_proposer_and_a_behind_read_works() {
    let (root, store) = sqlite("migration-12", 123);
    migrate_through_for_test(&store, 11).expect("schema 11");
    store
            .with_conn(|conn| {
                conn.execute(
                    "INSERT INTO pending_enrollments \
                     (request_id, proposed_name, request_secret_hash, state, created_at_ms, expires_at_ms) \
                     VALUES ('req-before-12', 'older-consumer', ?1, 'pending', 1, 9999999999999)",
                    ["d".repeat(64)],
                )
            })
            .expect("seed a schema-11 pending row");
    let path = root.join("store.db");

    // A newer CLI reading a store the daemon has not migrated yet: the listing must
    // still work while the proposer columns do not exist.
    let (behind_rows, behind_version) =
        list_enrollments_read_only_with_schema(&path).expect("schema-11 enrollment read");
    assert_eq!(behind_version, 11);
    assert_eq!(behind_rows.len(), 1);
    assert_eq!(behind_rows[0].key, "req-before-12");
    assert_eq!(behind_rows[0].proposer_kind, None);
    assert_eq!(behind_rows[0].proposer_id, None);

    // Run the chain through 12 only, so the schema version asserted below is the one
    // migration 12 records; a later migration would advance it.
    migrate_through_for_test(&store, 12).expect("schema 12");
    assert_eq!(
        schema_version_of(&store),
        ENROLLMENT_PROPOSER_SCHEMA_VERSION
    );
    let (rows, version) =
        list_enrollments_read_only_with_schema(&path).expect("schema-12 enrollment read");
    assert_eq!(version, ENROLLMENT_PROPOSER_SCHEMA_VERSION);
    assert_eq!(rows.len(), 1, "the existing request survives the migration");
    assert_eq!(
        (rows[0].proposer_kind.clone(), rows[0].proposer_id.clone()),
        (None, None),
        "no backfill: a pre-12 row has no reliable proposer to copy"
    );
}

#[test]
fn migration_34_preserves_enrollments_and_pending_requests_without_labels() {
    let (root, store) = sqlite("migration-34", 124);
    migrate_through_for_test(&store, 33).unwrap();
    store.with_conn(|conn| {
            conn.execute_batch(
                "INSERT INTO enrolled_consumers VALUES ('live-id','older-consumer','hash',7,12,'operator',NULL); \
                 INSERT INTO enrolled_consumers VALUES ('revoked-id','revoked-consumer',NULL,0,13,'operator',14);"
            )?;
            for state in ["pending", "approved", "consumed", "denied", "expired"] {
                conn.execute(
                    "INSERT INTO pending_enrollments (request_id,proposed_name,request_secret_hash,state,created_at_ms,expires_at_ms,proposer_kind,proposer_id) VALUES (?1,?1,?2,?1,15,9999999999999,'reserved','broca')",
                    rusqlite::params![state, "d".repeat(64)],
                )?;
            }
            Ok(())
        }).unwrap();
    let path = root.join("store.db");
    let before = list_enrollments_read_only(&path).unwrap();
    assert_eq!(before.len(), 2);
    assert!(before.iter().all(|row| row.display_name.is_none()));
    EncryptedStore::migrate(&store).unwrap();
    assert_eq!(list_enrollments_read_only(&path).unwrap(), before);
    store.with_conn(|conn| {
            assert_eq!(conn.query_row("SELECT COUNT(*) FROM pending_enrollments WHERE display_name IS NULL AND created_at_ms=15 AND proposer_id='broca'", [], |r| r.get::<_, i64>(0))?, 5);
            assert_eq!(conn.query_row("SELECT COUNT(*) FROM enrolled_consumers WHERE display_name IS NULL", [], |r| r.get::<_, i64>(0))?, 2);
            assert_eq!(conn.query_row("SELECT token_generation FROM enrolled_consumers WHERE enrollment_id='live-id' AND token_hash='hash'", [], |r| r.get::<_, i64>(0))?, 7);
            assert_eq!(conn.query_row("SELECT revoked_at_ms FROM enrolled_consumers WHERE enrollment_id='revoked-id'", [], |r| r.get::<_, i64>(0))?, 14);
            Ok(())
        }).unwrap();
}

#[test]
fn enrollment_label_admin_op_changes_only_label_and_audits_real_changes() {
    use crate::admin_ops::{apply, AdminOpBody, ADMIN_OP_SCHEMA_V2};
    let (root, store) = rig("enrollment-label-admin", 126);
    let secret = "ab".repeat(32);
    let proposal = store
        .propose_enrollment("consumer", &enrollment_secret_hash(&secret).unwrap())
        .unwrap();
    let id = store
        .approve_enrollment(&proposal.request_id, "consumer", "approver")
        .unwrap();
    store
        .poll_enrollment(&proposal.request_id, &secret)
        .unwrap();
    store
        .create_read_grant_audited(
            "enrolled",
            "consumer",
            SelectorKind::Exact,
            "apikey:label",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let snapshot = || {
        store.with_raw_conn(|conn| conn.query_row(
            "SELECT enrollment_id, name, token_hash, token_generation, approved_at_ms, approved_by, revoked_at_ms \
             FROM enrolled_consumers WHERE enrollment_id=?1", [&id], |row| Ok((
                row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)?, row.get::<_, i64>(4)?, row.get::<_, String>(5)?, row.get::<_, Option<i64>>(6)?,
            )))).unwrap()
    };
    let original = snapshot();
    assert!(
        original.2.is_some(),
        "exercise an enrollment with a minted token"
    );
    assert_eq!(original.3, 1);
    let grants = store.list_read_grants().unwrap();
    let generation = store.grants_generation().unwrap();
    let pending = store.with_raw_conn(|conn| conn.query_row(
            "SELECT state, final_name, approved_by, approved_at_ms FROM pending_enrollments WHERE request_id=?1",
            [&proposal.request_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, i64>(3)?)))).unwrap();
    let label = |value: Option<&str>| {
        apply(
            &store,
            AdminOpBody::EnrollLabel {
                v: ADMIN_OP_SCHEMA_V2,
                name: "consumer".into(),
                display_name: value.map(str::to_owned),
            },
            "offline-cli",
        )
        .unwrap()
    };
    let mut tip = store.audit_tip().unwrap().unwrap();
    for value in [Some("  Person's plugin  "), Some("New label"), None] {
        let reply = label(value);
        assert_eq!(
            reply,
            serde_json::json!({"name":"consumer", "display_name":value.map(str::trim), "changed":true})
        );
        let rows = list_enrollments_read_only(&root.join("store.db")).unwrap();
        assert_eq!(rows[0].display_name.as_deref(), value.map(str::trim));
        let after = store.audit_tip().unwrap().unwrap();
        assert_eq!(after.0, tip.0 + 1);
        store.with_raw_conn(|conn| {
                let audit = conn.query_row("SELECT op, credential_id, payload_hash, actor, alarm FROM audit_log WHERE seq=?1", [after.0], |row| Ok((
                    row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?, row.get::<_, String>(3)?, row.get::<_, bool>(4)?,
                )))?;
                assert_eq!(audit, ("enroll.label".into(), id.clone(), None, "offline-cli".into(), false));
                Ok(())
            }).unwrap();
        assert_eq!(label(value)["changed"], false);
        assert_eq!(store.audit_tip().unwrap(), Some(after.clone()));
        assert_eq!(snapshot(), original);
        assert_eq!(store.list_read_grants().unwrap(), grants);
        assert_eq!(store.grants_generation().unwrap(), generation);
        tip = after;
    }
    let after_pending = store.with_raw_conn(|conn| conn.query_row(
            "SELECT state, final_name, approved_by, approved_at_ms FROM pending_enrollments WHERE request_id=?1",
            [&proposal.request_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, i64>(3)?)))).unwrap();
    assert_eq!(pending, after_pending);
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn enrollment_label_refusals_and_audit_failure_write_nothing() {
    use crate::admin_ops::{apply, AdminOpBody, ADMIN_OP_SCHEMA_V2};
    let (root, store) = rig("enrollment-label-refusals", 127);
    let request = store
        .propose_enrollment("consumer", &"a".repeat(64))
        .unwrap();
    store
        .approve_enrollment(&request.request_id, "consumer", "approver")
        .unwrap();
    let label = |name: &str, value: Option<&str>| {
        apply(
            &store,
            AdminOpBody::EnrollLabel {
                v: ADMIN_OP_SCHEMA_V2,
                name: name.into(),
                display_name: value.map(str::to_owned),
            },
            "route-admin",
        )
    };
    let before = list_enrollments_read_only(&root.join("store.db")).unwrap();
    let tip = store.audit_tip().unwrap();
    for invalid in ["".to_string(), "a\u{202e}b".into(), "x".repeat(41)] {
        assert!(matches!(
            label("consumer", Some(&invalid)),
            Err(StoreOpError::InvalidDisplayName)
        ));
        assert_eq!(
            list_enrollments_read_only(&root.join("store.db")).unwrap(),
            before
        );
        assert_eq!(store.audit_tip().unwrap(), tip);
    }
    assert!(matches!(
        label("unknown", Some("Name")),
        Err(StoreOpError::NotFound)
    ));
    assert_eq!(store.audit_tip().unwrap(), tip);
    store.with_raw_conn(|conn| conn.execute_batch(
            "CREATE TRIGGER refuse_label_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;"
        )).unwrap();
    assert!(label("consumer", Some("Name")).is_err());
    assert_eq!(
        list_enrollments_read_only(&root.join("store.db")).unwrap(),
        before
    );
    assert_eq!(store.audit_tip().unwrap(), tip);
    store
        .with_raw_conn(|conn| conn.execute_batch("DROP TRIGGER refuse_label_audit"))
        .unwrap();
    store.revoke_enrollment("consumer", "operator").unwrap();
    let tip = store.audit_tip().unwrap();
    for value in [Some("Name"), None] {
        assert!(matches!(
            label("consumer", value),
            Err(StoreOpError::NotFound)
        ));
        assert_eq!(store.audit_tip().unwrap(), tip);
    }
    store
        .with_raw_conn(|conn| {
            let value: Option<String> = conn.query_row(
                "SELECT display_name FROM enrolled_consumers WHERE name='consumer'",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(value, None);
            Ok(())
        })
        .unwrap();
}

#[test]
fn enrollment_display_names_survive_rotation_but_not_revocation_or_reuse() {
    let (root, store) = rig("enrollment-labels", 125);
    let secret = "ab".repeat(32);
    let hash = enrollment_secret_hash(&secret).unwrap();
    let proposal = store
        .propose_enrollment_with_display_name_by(
            None,
            "consumer",
            &hash,
            Some("  Claude sign-in for Pi  "),
        )
        .unwrap();
    let path = root.join("store.db");
    assert_eq!(
        list_enrollments_read_only(&path).unwrap()[0]
            .display_name
            .as_deref(),
        Some("Claude sign-in for Pi")
    );
    let resumed = store
        .propose_enrollment_with_display_name_by(None, "consumer", &hash, Some("Replacement claim"))
        .unwrap();
    assert_eq!(resumed, proposal);
    assert_eq!(
        list_enrollments_read_only(&path).unwrap()[0]
            .display_name
            .as_deref(),
        Some("Claude sign-in for Pi")
    );
    store
        .create_read_grant_audited(
            "enrolled",
            "consumer",
            SelectorKind::Exact,
            "apikey:label",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let permission_holder =
        || store.secret_permissions_list(None, now_ms()).unwrap()["grants"][0]["holder"].clone();
    assert!(
        permission_holder().get("label").is_none(),
        "a proposal is not an approved label"
    );
    let before = store.audit_tip().unwrap();
    for invalid in ["", "a\nb", "a\u{202e}b", "a\u{200d}b"] {
        assert!(matches!(
            store.approve_enrollment_with_display_name(
                &proposal.request_id,
                "consumer",
                false,
                Some(invalid),
                "operator"
            ),
            Err(StoreOpError::InvalidDisplayName)
        ));
        assert_eq!(store.audit_tip().unwrap(), before);
        let rows = list_enrollments_read_only(&path).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, "pending");
        assert_eq!(
            rows[0].display_name.as_deref(),
            Some("Claude sign-in for Pi")
        );
    }
    let (id, label) = store
        .approve_enrollment_with_display_name(
            &proposal.request_id,
            "consumer",
            true,
            None,
            "operator",
        )
        .unwrap();
    assert_eq!(label.as_deref(), Some("Claude sign-in for Pi"));
    assert_eq!(permission_holder()["label"], "Claude sign-in for Pi");
    let EnrollmentPoll::Approved { token, .. } = store
        .poll_enrollment(&proposal.request_id, &secret)
        .unwrap()
    else {
        panic!("approved")
    };
    store.rotate_enrollment(&token, 1).unwrap();
    assert_eq!(permission_holder()["label"], "Claude sign-in for Pi");
    assert_eq!(
        list_enrollments_read_only(&path).unwrap()[0].display_name,
        label
    );
    store.revoke_enrollment("consumer", "operator").unwrap();
    assert!(list_enrollments_read_only(&path).unwrap().is_empty());
    assert_eq!(
        store.secret_permissions_list(None, now_ms()).unwrap()["grants"],
        serde_json::json!([])
    );
    store
        .with_raw_conn(|conn| {
            let stored: Option<String> = conn.query_row(
                "SELECT display_name FROM enrolled_consumers WHERE enrollment_id=?1",
                [&id],
                |r| r.get(0),
            )?;
            assert_eq!(stored, None);
            Ok(())
        })
        .unwrap();
    let replacement = store.propose_enrollment("consumer", &hash).unwrap();
    assert_eq!(
        store
            .approve_enrollment_with_display_name(
                &replacement.request_id,
                "consumer",
                false,
                None,
                "operator"
            )
            .unwrap()
            .1,
        None
    );
    store
        .create_read_grant_audited(
            "enrolled",
            "consumer",
            SelectorKind::Exact,
            "apikey:label",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    assert!(
        permission_holder().get("label").is_none(),
        "a new enrollment must not inherit a label"
    );
    let override_request = store
        .propose_enrollment_with_display_name_by(None, "other-consumer", &hash, Some("Proposal"))
        .unwrap();
    assert_eq!(
        store
            .approve_enrollment_with_display_name(
                &override_request.request_id,
                "other-consumer",
                false,
                Some("  Person's choice  "),
                "operator"
            )
            .unwrap()
            .1
            .as_deref(),
        Some("Person's choice")
    );
}

#[test]
fn open_grants_round_trip_and_unknown_operations_are_refused_by_the_reader() {
    let (root, store) = sqlite("open-grant", 118);
    EncryptedStore::migrate(&store).expect("migrate");
    assert!(GrantOperation::Read < GrantOperation::Sign);
    assert!(GrantOperation::Sign < GrantOperation::Open);
    assert!(GrantOperation::Open < GrantOperation::List);
    for (text, operation) in [
        ("read", GrantOperation::Read),
        ("sign", GrantOperation::Sign),
        ("open", GrantOperation::Open),
        ("list", GrantOperation::List),
    ] {
        assert_eq!(text.parse::<GrantOperation>(), Ok(operation));
        assert_eq!(operation.as_str(), text);
    }
    assert_eq!(
            "other".parse::<GrantOperation>(),
            Err(
                "unknown grant operation 'other' (expected read, sign, open, list, deposit, account_token, seal, or policy_token)"
                    .to_string()
            )
        );
    store.with_conn(|conn| {
            for operation in ["open", "sign", "read", "list"] {
                conn.execute("INSERT INTO read_grants (principal_kind, principal_id, selector_kind, selector, operation, created_at_ms) VALUES ('reserved', 'agent', 'exact', 'apikey:one', ?1, 1)", [operation])?;
            }
            Ok(())
        }).expect("seed all operations");
    let path = root.join("store.db");
    assert_eq!(
        list_read_grants_read_only_with_schema(&path)
            .expect("read open")
            .0
            .iter()
            .map(|grant| grant.operation)
            .collect::<Vec<_>>(),
        [
            GrantOperation::List,
            GrantOperation::Open,
            GrantOperation::Read,
            GrantOperation::Sign
        ],
        "the stored TEXT orders each selector's operations: the SQL sorts by text and \
             `ck auth grants` checks text order, so any other order refuses the whole listing"
    );
    store.with_conn(|conn| {
            conn.execute_batch("PRAGMA ignore_check_constraints = ON")?;
            conn.execute("INSERT INTO read_grants (principal_kind, principal_id, selector_kind, selector, operation, created_at_ms) VALUES ('reserved', 'agent', 'exact', 'apikey:two', 'other', 2)", [])?;
            Ok(())
        }).expect("simulate corrupt operation");
    let error = list_read_grants_read_only_with_schema(&path)
        .expect_err("unknown operation refuses the entire inventory")
        .to_string();
    assert!(
            error.contains(
                "unknown grant operation 'other' (expected read, sign, open, list, deposit, account_token, seal, or policy_token)"
            ),
            "{error}"
        );
}

#[test]
fn schema_10_lease_free_readers_and_schema_13_shared_runner_remain_compatible() {
    let (root, store) = sqlite("migration-compat", 119);
    migrate_through_for_test(&store, 10).expect("schema 10");
    store.with_conn(|conn| conn.execute("INSERT INTO read_grants (principal_kind, principal_id, selector_kind, selector, operation, created_at_ms) VALUES ('reserved', 'agent', 'exact', 'apikey:one', 'read', 1)", [])).expect("seed schema-10 grant");
    let path = root.join("store.db");
    assert_eq!(
        list_meta_read_only_with_schema(&path)
            .expect("behind metadata")
            .1,
        10
    );
    let (behind_grants, behind_version) =
        list_read_grants_read_only_with_schema(&path).expect("behind grants");
    assert_eq!(behind_version, 10);
    assert_eq!(behind_grants[0].operation, GrantOperation::Read);
    // Migrate through 12 only. The version-13 row inserted below then simulates an
    // already-applied migration 13, which the shared runner must skip.
    migrate_through_for_test(&store, 12).expect("schema 12");
    store.with_conn(|conn| conn.execute("INSERT INTO cortexkit_schema_version (namespace, version, applied_at_unix) VALUES (?1, 13, 0)", [SCHEMA_NAMESPACE])).expect("schema 13 fixture");
    let through_13: Vec<_> = MIGRATIONS
        .iter()
        .copied()
        .filter(|m| m.version <= 13)
        .collect();
    store
        .migrate(SCHEMA_NAMESPACE, &through_13)
        .expect("shared runner skips already-applied migrations");
    assert_eq!(
        list_meta_read_only_with_schema(&path)
            .expect("ahead metadata")
            .1,
        13
    );
    let (ahead_grants, ahead_version) =
        list_read_grants_read_only_with_schema(&path).expect("ahead grants");
    assert_eq!(ahead_version, 13);
    assert_eq!(ahead_grants[0].operation, GrantOperation::Read);
}

#[test]
fn migration_10_applies_to_a_schema_9_store_and_lands_the_ddl_a_fresh_store_carries() {
    let (_migrated_root, migrated) = sqlite("ddl-migrated", 101);
    migrate_through_for_test(&migrated, 9).expect("migrate through version 9");
    migrated
            .with_conn(|conn| {
                seed_credential_at_schema_9(conn, "apikey:one", 1_700_000_000_000)?;
                conn.execute(
                    "INSERT INTO read_grants \
                     (principal_kind, principal_id, selector_kind, credential_prefix, operation, created_at_ms) \
                     VALUES ('reserved', 'agent', 'prefix', 'apikey:one', 'read', 7)",
                    [],
                )?;
                Ok(())
            })
            .expect("seed a schema-9 store");

    migrate_through_for_test(&migrated, 10).expect("migration 10 applies to a schema-9 store");
    assert_eq!(schema_version_of(&migrated), 10);

    let (_fresh_root, fresh) = sqlite("ddl-fresh", 102);
    migrate_through_for_test(&fresh, 10).expect("a store created fresh at schema 10");

    let objects = vault_schema_objects(&migrated);
    assert_eq!(
        objects,
        vault_schema_objects(&fresh),
        "a store that upgraded and a store created today serve the same binary, so \
             their schema must be identical object for object"
    );

    let read_grants = object_sql(&objects, "read_grants");
    assert!(
        read_grants.contains("CHECK (selector_kind IN ('exact','category'))"),
        "the selector vocabulary must be closed in the table itself: {read_grants}"
    );
    assert!(
        read_grants.contains("CHECK (principal_kind IN ('reserved','enrolled'))"),
        "the principal vocabulary must be closed in the table itself: {read_grants}"
    );
    assert!(
        !read_grants.contains("credential_prefix"),
        "the selector column must not keep its historical name: {read_grants}"
    );

    for (index, target, predicate) in [
        (
            "enrolled_consumers_live_name",
            "enrolled_consumers(name)",
            "WHERE revoked_at_ms IS NULL",
        ),
        (
            "pending_enrollments_live_name",
            "pending_enrollments(proposed_name)",
            "WHERE state IN ('pending','approved')",
        ),
    ] {
        let sql = object_sql(&objects, index);
        // A separate statement, because SQLite accepts no WHERE clause on an
        // in-table UNIQUE and would therefore make the uniqueness total.
        assert!(
            sql.starts_with("CREATE UNIQUE INDEX")
                && sql.contains(target)
                && sql.contains(predicate),
            "{index} must be a partial unique index over live rows: {sql}"
        );
    }
}

#[test]
fn the_new_tables_carry_the_columns_defaults_and_nullability_the_schema_declares() {
    let (_root, store) = sqlite("shape", 103);
    EncryptedStore::migrate(&store).expect("migrate");

    let column = |name: &str, kind: &str, not_null: bool, default: Option<&str>, pk: bool| {
        (
            name.to_string(),
            kind.to_string(),
            not_null,
            default.map(str::to_string),
            pk,
        )
    };

    for (table, expected) in [
        (
            "credential_conditions",
            vec![
                column("credential_id", "TEXT", true, None, true),
                column("incarnation", "TEXT", true, None, false),
                column("reason", "TEXT", true, None, false),
                column("since_ms", "INTEGER", true, None, false),
                column("reporter", "TEXT", true, None, false),
                column("action_url", "TEXT", false, None, false),
            ],
        ),
        (
            "remote_record_conditions",
            vec![
                column("credential_id", "TEXT", true, None, true),
                column("incarnation", "TEXT", true, None, false),
                column("reason", "TEXT", true, None, false),
                column("since_ms", "INTEGER", true, None, false),
                column("action_url", "TEXT", false, None, false),
            ],
        ),
        (
            "module_secrets",
            vec![
                column("module_id", "TEXT", true, None, true),
                column("name", "TEXT", true, None, true),
                column("version", "INTEGER", true, None, false),
                column("protected", "INTEGER", true, None, false),
                column("state", "TEXT", true, None, false),
                column("key_id", "TEXT", true, None, false),
                column("envelope", "BLOB", true, None, false),
                column("created_at_ms", "INTEGER", true, None, false),
                column("updated_at_ms", "INTEGER", true, None, false),
            ],
        ),
        (
            "fleet_epochs",
            vec![
                column("epoch", "INTEGER", false, None, true),
                column("key", "BLOB", true, None, false),
                column("minter", "TEXT", true, None, false),
                column("members_json", "TEXT", true, None, false),
                column("mint_id", "TEXT", false, None, false),
                column("state", "TEXT", true, None, false),
                column("created_at_ms", "INTEGER", true, None, false),
            ],
        ),
        (
            "fleet_removals",
            vec![
                column("member_id", "TEXT", true, None, true),
                column("removal_id", "TEXT", true, None, true),
                column("observed_at_ms", "INTEGER", true, None, false),
            ],
        ),
        (
            "fleet_discards",
            vec![
                column("mint_id", "TEXT", false, None, true),
                column("epoch", "INTEGER", true, None, false),
            ],
        ),
        (
            "secret_grants",
            vec![
                column("grant_id", "TEXT", false, None, true),
                column("secret_name", "TEXT", true, None, false),
                column("incarnation", "TEXT", true, None, false),
                column("scope_owner", "TEXT", true, None, false),
                column("scope_kind", "TEXT", true, None, false),
                column("scope_ref", "TEXT", true, None, false),
                column("coverage", "TEXT", true, None, false),
                column("duration", "TEXT", true, None, false),
                column("expires_at_ms", "INTEGER", true, None, false),
                column("granted_at_ms", "INTEGER", true, None, false),
                column("envelope_sha256", "TEXT", true, None, false),
                column("agent_id", "TEXT", false, None, false),
                column("card_ref", "TEXT", false, None, false),
                column("first_released", "INTEGER", true, Some("0"), false),
                column("last_use_ms", "INTEGER", false, None, false),
                column("asking_member_id", "TEXT", true, Some("''"), false),
                column("local_use", "TEXT", false, None, false),
            ],
        ),
        (
            "secret_pending_requests",
            vec![
                column("request_id", "TEXT", false, None, true),
                column("request_kind", "TEXT", true, None, false),
                column("secret_name", "TEXT", true, None, false),
                column("incarnation", "TEXT", true, None, false),
                column("member_id", "TEXT", true, None, false),
                column("mapped_owner", "TEXT", false, None, false),
                column("mapped_kind", "TEXT", false, None, false),
                column("mapped_ref", "TEXT", false, None, false),
                column("mapped_epoch", "INTEGER", false, None, false),
                column("coverage", "TEXT", false, None, false),
                column("agent_id", "TEXT", false, None, false),
                column("statement_bytes", "BLOB", true, None, false),
                column("statement_sha256", "TEXT", true, None, false),
                column("request_expires_at_ms", "INTEGER", true, None, false),
                column("consumed", "INTEGER", true, Some("0"), false),
                column("flow_id", "TEXT", false, None, false),
                column("flow_version", "INTEGER", false, None, false),
                column("flow_code_hash", "TEXT", false, None, false),
                column("flow_install_id", "TEXT", false, None, false),
                column("methods", "TEXT", false, None, false),
                column("asking_member_id", "TEXT", true, Some("''"), false),
                column("local_use", "TEXT", false, None, false),
            ],
        ),
        (
            "declared_grant_sets",
            vec![
                column("module_id", "TEXT", false, None, true),
                column("declaration_digest", "TEXT", false, None, false),
                column("approved_declarations_digest", "TEXT", false, None, false),
                column("origin", "TEXT", false, None, false),
                column("grants_json", "TEXT", true, None, false),
                column("skipped_count", "INTEGER", true, None, false),
                column("first_seen_ms", "INTEGER", true, None, false),
            ],
        ),
        (
            "credential_plan_tiers",
            vec![
                column("credential_id", "TEXT", true, None, true),
                column("plan_tier", "TEXT", true, None, false),
                column("observed_at_ms", "INTEGER", false, None, false),
                column("since_ms", "INTEGER", false, None, false),
            ],
        ),
        (
            "remote_record_plan_tiers",
            vec![
                column("credential_id", "TEXT", true, None, true),
                column("plan_tier", "TEXT", true, None, false),
                column("observed_at_ms", "INTEGER", false, None, false),
                column("since_ms", "INTEGER", false, None, false),
            ],
        ),
        (
            "gh_manifests",
            vec![
                column("version", "INTEGER", false, None, true),
                column("manifest_bytes", "BLOB", true, None, false),
                column("manifest_sha256", "TEXT", true, None, false),
                column("key_id", "TEXT", true, None, false),
                column("signature", "BLOB", true, None, false),
                column("signed_at_ms", "INTEGER", true, None, false),
                column("source", "TEXT", true, None, false),
                column("approval_audit_seq", "INTEGER", false, None, false),
            ],
        ),
        (
            "agent_policies",
            vec![
                column("version", "INTEGER", true, None, true),
                column("policy_bytes", "BLOB", true, None, false),
                column("policy_sha256", "TEXT", true, None, false),
                column("key_id", "TEXT", true, None, false),
                column("signature", "BLOB", true, None, false),
                column("signed_at_ms", "INTEGER", true, None, false),
                column("source", "TEXT", true, None, false),
                column("approval_seq", "INTEGER", true, None, false),
                column("manifest_version", "INTEGER", true, None, false),
            ],
        ),
        (
            "broker_action_requests",
            vec![
                column("request_id", "TEXT", true, None, true),
                column("principal", "TEXT", true, None, false),
                column("agent_id", "TEXT", true, None, false),
                column("scope_json", "TEXT", true, None, false),
                column("statement_bytes", "BLOB", true, None, false),
                column("statement_sha256", "TEXT", true, None, false),
                column("policy_version", "INTEGER", true, None, false),
                column("identity", "TEXT", true, None, false),
                column("legs_json", "TEXT", true, None, false),
                column("created_at_ms", "INTEGER", true, None, false),
                column("expires_at_ms", "INTEGER", true, None, false),
                column("approved_at_ms", "INTEGER", false, None, false),
                column("device_fingerprint", "TEXT", false, None, false),
                column("envelope_sha256", "TEXT", false, None, false),
                column("issued_legs", "INTEGER", true, Some("0"), false),
            ],
        ),
        (
            "gh_manifest_proposals",
            vec![
                column("proposal_id", "TEXT", true, None, true),
                column("agent_id", "TEXT", true, None, false),
                column("app_id", "INTEGER", true, None, false),
                column("app_slug", "TEXT", true, None, false),
                column("repo", "TEXT", true, None, false),
                column("installation_permissions", "BLOB", true, None, false),
                column("base_version", "INTEGER", true, None, false),
                column("manifest_bytes", "BLOB", true, None, false),
                column("manifest_sha256", "TEXT", true, None, false),
                column("statement_bytes", "BLOB", true, None, false),
                column("statement_sha256", "TEXT", true, None, false),
                column("created_at_ms", "INTEGER", true, None, false),
                column("expires_at_ms", "INTEGER", true, None, false),
                column("state", "TEXT", true, None, false),
                column("approved_envelope_sha256", "TEXT", false, None, false),
                column("approved_fingerprint", "TEXT", false, None, false),
            ],
        ),
        (
            "gh_manifest_activations",
            vec![
                column("member_id", "TEXT", true, None, true),
                column("version", "INTEGER", false, None, false),
                column("payload_sha256", "TEXT", false, None, false),
                column("verdict", "TEXT", false, None, false),
                column("reason", "TEXT", false, None, false),
                column("reported_at_ms", "INTEGER", false, None, false),
                column("retired_at_ms", "INTEGER", false, None, false),
                column("report_box_id", "TEXT", false, None, false),
            ],
        ),
        (
            "gh_manifest_activation_audits",
            vec![
                column("member_id", "TEXT", true, None, true),
                column("version", "INTEGER", true, None, true),
                column("verdict", "TEXT", true, None, true),
            ],
        ),
        (
            "hub_login_targets",
            vec![
                column("member_id", "TEXT", true, None, true),
                column("box_id", "TEXT", true, None, false),
                column("transfer_public_key", "BLOB", true, None, false),
                column("pairing_id", "TEXT", true, None, false),
                column("generation", "INTEGER", true, None, false),
                column("kind", "TEXT", true, None, false),
                column("sealed_bytes", "BLOB", false, None, false),
                column("stale", "INTEGER", true, None, false),
                column("delivered", "INTEGER", true, None, false),
            ],
        ),
        (
            "hub_login_homes",
            vec![
                column("home_member", "TEXT", true, None, true),
                column("generation", "INTEGER", true, None, false),
                column("pairing_id", "TEXT", false, None, false),
                column("skipped_ids_json", "TEXT", true, None, false),
                column("reapply", "INTEGER", true, None, false),
            ],
        ),
        (
            "hub_own_report",
            vec![
                column("singleton", "INTEGER", true, None, true),
                column("version", "INTEGER", true, None, false),
                column("payload_sha256", "TEXT", true, None, false),
                column("verdict", "TEXT", true, None, false),
                column("reason", "TEXT", false, None, false),
            ],
        ),
        (
            "hub_report_task",
            vec![
                column("singleton", "INTEGER", true, None, true),
                column("seq", "INTEGER", true, None, false),
                column("signed_bytes", "BLOB", true, None, false),
                column("sent", "INTEGER", true, None, false),
            ],
        ),
        (
            "hub_manifest_high_water",
            vec![
                column("member_id", "TEXT", true, None, true),
                column("box_id", "TEXT", true, None, true),
                column("pairing_id", "TEXT", true, None, false),
                column("seq", "INTEGER", true, None, false),
            ],
        ),
    ] {
        assert_eq!(columns_of(&store, table), expected, "{table}");
    }

    assert_eq!(
        columns_of(&store, "enrolled_consumers"),
        vec![
            column("enrollment_id", "TEXT", false, None, true),
            column("name", "TEXT", true, None, false),
            column("token_hash", "TEXT", false, None, false),
            column("token_generation", "INTEGER", true, Some("0"), false),
            column("approved_at_ms", "INTEGER", true, None, false),
            column("approved_by", "TEXT", true, None, false),
            column("revoked_at_ms", "INTEGER", false, None, false),
            column("display_name", "TEXT", false, None, false),
        ],
        "an incarnation carries no token until one is minted, so token_hash is \
             nullable and the generation starts at 0"
    );

    assert_eq!(
        columns_of(&store, "pending_enrollments"),
        vec![
            column("request_id", "TEXT", false, None, true),
            column("proposed_name", "TEXT", true, None, false),
            column("final_name", "TEXT", false, None, false),
            column("enrollment_id", "TEXT", false, None, false),
            column("request_secret_hash", "TEXT", true, None, false),
            column("state", "TEXT", true, None, false),
            column("approved_by", "TEXT", false, None, false),
            column("approved_at_ms", "INTEGER", false, None, false),
            column("created_at_ms", "INTEGER", true, None, false),
            column("expires_at_ms", "INTEGER", true, None, false),
            // Migration 12: nullable, because rows proposed before it carry none.
            column("proposer_kind", "TEXT", false, None, false),
            column("proposer_id", "TEXT", false, None, false),
            column("display_name", "TEXT", false, None, false),
            // Migration 40: nullable, because a proposal that names no grants
            // stores none.
            column("requested_grants_json", "TEXT", false, None, false),
        ],
        "everything an approval fills in is nullable at proposal time"
    );

    assert_eq!(
        columns_of(&store, "grants_generation"),
        vec![
            column("id", "INTEGER", false, None, true),
            column("value", "INTEGER", true, None, false),
        ]
    );

    assert!(
        columns_of(&store, "credentials").contains(&column(
            "created_at_ms",
            "INTEGER",
            false,
            None,
            false
        )),
        "credentials must carry a nullable creation time"
    );
    assert!(columns_of(&store, "credentials").ends_with(&[
        column("github_app_id", "TEXT", false, None, false),
        column("github_app_slug", "TEXT", false, None, false),
        column("github_app_created_at_ms", "INTEGER", false, None, false),
        column("github_app_agent", "TEXT", false, None, false),
        column("github_app_relay_slot", "TEXT", false, None, false),
    ]));

    // The state vocabulary is DRIVEN rather than read off the DDL text: a CHECK
    // that names five states and rejects a sixth is the observable.
    for state in ["pending", "approved", "denied", "consumed", "expired"] {
        store
                .with_conn(|conn| {
                    conn.execute(
                        "INSERT INTO pending_enrollments \
                         (request_id, proposed_name, request_secret_hash, state, created_at_ms, expires_at_ms) \
                         VALUES (?1, ?1, 'ff', ?2, 1, 2)",
                        rusqlite::params![format!("request-{state}"), state],
                    )
                })
                .unwrap_or_else(|error| panic!("state {state} must be accepted: {error}"));
    }
    let rejected = store.with_conn(|conn| {
            conn.execute(
                "INSERT INTO pending_enrollments \
                 (request_id, proposed_name, request_secret_hash, state, created_at_ms, expires_at_ms) \
                 VALUES ('request-bogus', 'bogus', 'ff', 'bogus', 1, 2)",
                [],
            )
        });
    assert!(
        rejected.is_err(),
        "a state outside the five must be refused by the table"
    );
}

#[test]
fn the_migration_seeds_the_grant_generation_last_and_reads_nothing_it_must_not() {
    let statements = MIGRATIONS
        .iter()
        .find(|migration| migration.version == 10)
        .expect("migration 10")
        .statements;

    assert!(
        !statements.contains("updated_at_ms"),
        "a write time is not a creation time, so no statement here may reach for one"
    );
    for op in CHAIN_BIRTH_OPS {
        assert!(
            statements.contains(&format!("'{op}'")),
            "the backfill must date rows from the same deposit vocabulary the guard \
                 checks, and {op} is missing from it"
        );
    }
    assert!(
        statements
            .trim_end()
            .ends_with("INSERT INTO grants_generation (id, value) VALUES (1, 1);"),
        "the seed must be the LAST statement, so this migration's own writes cannot \
             be mistaken for the first mutation after it"
    );
}

#[test]
fn the_grant_generation_reads_one_on_a_fresh_store_and_on_a_migrated_one() {
    let (_fresh_root, fresh) = sqlite("generation-fresh", 104);
    migrate_through_for_test(&fresh, 10).expect("fresh store at schema 10");
    assert_eq!(generation_of(&fresh), 1);

    // A store with rows for this migration to convert and date: its writes must not
    // move the counter either.
    let (_migrated_root, migrated) = sqlite("generation-migrated", 105);
    migrate_through_for_test(&migrated, 9).expect("migrate through version 9");
    migrated
            .with_conn(|conn| {
                for (index, id) in ["apikey:one", "apikey:two", "github_app:one"]
                    .iter()
                    .enumerate()
                {
                    seed_credential_at_schema_9(conn, id, 1_700_000_000_000 + index as i64)?;
                    conn.execute(
                        "INSERT INTO read_grants \
                         (principal_kind, principal_id, selector_kind, credential_prefix, operation, created_at_ms) \
                         VALUES ('reserved', 'agent', 'prefix', ?1, 'read', 7)",
                        rusqlite::params![id],
                    )?;
                }
                Ok(())
            })
            .expect("seed a schema-9 store");
    migrate_through_for_test(&migrated, 10).expect("migrate to 10");
    assert_eq!(
        generation_of(&migrated),
        1,
        "the conversion and the backfill are this migration's own writes, so a \
             consumer cannot tell a migrated store from a fresh one by this value"
    );
}

#[test]
fn declared_operator_inventory_is_additive_sorted_and_incomplete_on_corruption() {
    use crate::admin_ops::{apply, AdminOpBody, ADMIN_OP_SCHEMA_V1};
    let (_root, store) = rig("declared-operator-status", 109);
    let status = || {
        apply(
            &store,
            AdminOpBody::Status {
                v: ADMIN_OP_SCHEMA_V1,
            },
            "test",
        )
        .unwrap()
    };
    let baseline = status();
    assert!(baseline.get("declared_grants").is_none());
    assert!(baseline.get("declared_grants_incomplete").is_none());
    for module in ["z-module", "a-module"] {
        let grants = DeclaredGrantSet::from_grants_json(module, r#"[{"selector_kind":"category","selector":"llm-provider","operation":"read"},{"selector_kind":"category","selector":"llm-provider","operation":"list"},{"selector_kind":"audience","selector":"cortexkit-account","operation":"account_token"}]"#).unwrap();
        store
            .record_declared_grants_seen(module, Some("digest"), None, None, &grants, 0)
            .unwrap();
    }
    let listed = status();
    let rows = listed["declared_grants"].as_array().unwrap();
    let keys: Vec<_> = rows
        .iter()
        .map(|row| {
            (
                row["module_id"].as_str().unwrap(),
                row["selector_kind"].as_str().unwrap(),
                row["operation"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        keys,
        vec![
            ("a-module", "audience", "account_token"),
            ("a-module", "category", "list"),
            ("a-module", "category", "read"),
            ("z-module", "audience", "account_token"),
            ("z-module", "category", "list"),
            ("z-module", "category", "read")
        ]
    );
    for row in rows {
        assert_eq!(row.as_object().unwrap().len(), 5);
        assert!(row["first_seen_ms"].as_i64().unwrap() > 0);
    }
    let mut unchanged = listed;
    unchanged.as_object_mut().unwrap().remove("declared_grants");
    assert_eq!(unchanged, baseline);
    store.store.with_conn(|conn| conn.execute("UPDATE declared_grant_sets SET grants_json = 'not-json' WHERE module_id = 'a-module'", [])).unwrap();
    let mut partial = status();
    assert_eq!(partial["declared_grants"].as_array().unwrap().len(), 3);
    assert_eq!(
        partial
            .as_object_mut()
            .unwrap()
            .remove("declared_grants_incomplete"),
        Some(serde_json::json!(true))
    );
    partial.as_object_mut().unwrap().remove("declared_grants");
    assert_eq!(partial, baseline);
    store
        .store
        .with_conn(|conn| {
            conn.execute(
                "UPDATE declared_grant_sets SET grants_json = 'not-json'",
                [],
            )
        })
        .unwrap();
    let mut corrupt_only = status();
    assert!(corrupt_only.get("declared_grants").is_none());
    assert_eq!(
        corrupt_only
            .as_object_mut()
            .unwrap()
            .remove("declared_grants_incomplete"),
        Some(serde_json::json!(true))
    );
    assert_eq!(corrupt_only, baseline);
    store
        .store
        .with_conn(|conn| conn.execute("DROP TABLE declared_grant_sets", []))
        .unwrap();
    let mut unavailable = status();
    assert_eq!(
        unavailable
            .as_object_mut()
            .unwrap()
            .remove("declared_grants_incomplete"),
        Some(serde_json::json!(true))
    );
    assert_eq!(unavailable, baseline);
}

#[test]
fn declared_operator_revoke_refuses_inventory_only_and_revokes_hand_duplicates() {
    use crate::admin_ops::{apply, AdminOpBody, ADMIN_OP_SCHEMA_V2};
    let (_root, store) = rig("declared-operator-revoke", 110);
    let grants = DeclaredGrantSet::from_grants_json(
        "agent",
        r#"[{"selector_kind":"category","selector":"llm-provider","operation":"read"}]"#,
    )
    .unwrap();
    store
        .record_declared_grants_seen("agent", Some("digest"), None, None, &grants, 0)
        .unwrap();
    let revoke = |kind: &str| AdminOpBody::GrantRevokeV2 {
        v: ADMIN_OP_SCHEMA_V2,
        principal_kind: kind.into(),
        principal_id: "agent".into(),
        selector_kind: SelectorKind::Category,
        selector: "llm-provider".into(),
        operation: GrantOperation::Read,
    };
    let create = || AdminOpBody::GrantCreateV2 {
        v: ADMIN_OP_SCHEMA_V2,
        principal_kind: "reserved".into(),
        principal_id: "agent".into(),
        selector_kind: SelectorKind::Category,
        selector: "llm-provider".into(),
        operation: GrantOperation::Read,
    };
    let tip = store.audit_tip().unwrap();
    let error = apply(&store, revoke("reserved"), "test").unwrap_err();
    assert_eq!(error.wire_code(), Some("declared_grant"));
    assert_eq!(error.wire_class(), Some("permanent"));
    let message = error.to_string();
    for remedy in [
        "agent",
        "approved declaration",
        "daemon's configuration",
        "re-binds",
        "restart the module",
        "stored row is replaced",
    ] {
        assert!(message.contains(remedy), "{message}");
    }
    assert_eq!(store.audit_tip().unwrap(), tip);
    assert!(matches!(
        apply(&store, revoke("enrolled"), "test"),
        Err(StoreOpError::NotFound)
    ));
    for _ in 0..2 {
        assert_eq!(
            apply(&store, create(), "test").unwrap()["declared_covers"],
            true
        );
    }
    let revoked = apply(&store, revoke("reserved"), "test").unwrap();
    assert_eq!(
        revoked,
        serde_json::json!({"grant_revoked":true,"declared_still_listed":true})
    );
    assert!(store.list_read_grants().unwrap().is_empty());
    store
        .store
        .with_conn(|conn| {
            conn.execute(
                "UPDATE declared_grant_sets SET grants_json = 'not-json'",
                [],
            )
        })
        .unwrap();
    assert!(matches!(
        apply(&store, revoke("reserved"), "test"),
        Err(StoreOpError::NotFound)
    ));
    assert!(apply(&store, create(), "test")
        .unwrap()
        .get("declared_covers")
        .is_none());
    assert_eq!(
        apply(&store, revoke("reserved"), "test").unwrap(),
        serde_json::json!({"grant_revoked":true})
    );
    store
        .store
        .with_conn(|conn| conn.execute("DROP TABLE declared_grant_sets", []))
        .unwrap();
    assert!(matches!(
        apply(&store, revoke("reserved"), "test"),
        Err(StoreOpError::NotFound)
    ));
    assert!(apply(&store, create(), "test")
        .unwrap()
        .get("declared_covers")
        .is_none());
}

/// A repeated identical grant reports `already_granted` and writes nothing: no audit
/// row, no generation bump. That is what lets `ck auth grant` report "no change" and
/// exit 0 when a setup script re-runs it.
#[test]
fn a_repeated_identical_grant_is_reported_and_changes_nothing_durable() {
    let (root, store) = rig("grant-repeat", 108);
    let op = || crate::admin_ops::AdminOpBody::GrantCreateV2 {
        v: crate::admin_ops::ADMIN_OP_SCHEMA_V2,
        principal_kind: "reserved".into(),
        principal_id: "agent".into(),
        selector_kind: SelectorKind::Category,
        selector: "llm-provider".into(),
        operation: GrantOperation::Read,
    };
    let first = crate::admin_ops::apply(&store, op(), "test").expect("first grant");
    assert_eq!(first["grant_created"], true);
    let tip = store.audit_tip().expect("tip");
    let generation = store.grants_generation().expect("generation");

    let second = crate::admin_ops::apply(&store, op(), "test").expect("repeat grant");
    assert_eq!(second["grant_created"], false);
    assert_eq!(second["already_granted"], true);
    assert_eq!(
        store.audit_tip().expect("tip"),
        tip,
        "a no-op grant must not append to the audit chain"
    );
    assert_eq!(
        store.grants_generation().expect("generation"),
        generation,
        "a no-op grant must not bump the grants generation"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_first_mutation_after_the_migration_bumps_the_generation_through_the_fenced_path() {
    let (root, store) = rig("generation-bump", 106);
    assert_eq!(store.grants_generation().expect("read generation"), 1);

    store
        .create_audited("apikey:one", &api_record(), AuditCtx::admin(AuditOp::Put))
        .expect("deposit");
    assert_eq!(
        store.grants_generation().expect("read generation"),
        1,
        "a deposit changes no grant and no category"
    );

    store
        .create_read_grant_audited(
            "reserved",
            "agent",
            SelectorKind::Exact,
            "apikey:one",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .expect("create grant");
    assert_eq!(store.grants_generation().expect("read generation"), 2);

    store
        .set_categories_audited(
            "apikey:one",
            SetCategoryMode::Set,
            &["llm-provider".to_string()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .expect("assign a category");
    assert_eq!(
        store.grants_generation().expect("read generation"),
        3,
        "an assignment changes what a category grant reaches"
    );

    store
        .revoke_read_grant_audited(
            "reserved",
            "agent",
            SelectorKind::Exact,
            "apikey:one",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantRevoke),
        )
        .expect("revoke grant");
    assert_eq!(store.grants_generation().expect("read generation"), 4);

    // The bump rides the fenced write rather than sitting beside it: a superseded
    // writer moves neither the rows nor the counter.
    store
        .with_raw_conn(|conn| {
            conn.execute("UPDATE cortexkit_fence SET epoch = 999 WHERE id = 0", [])
        })
        .expect("simulate a newer writer");
    match store.create_read_grant_audited(
        "reserved",
        "agent",
        SelectorKind::Exact,
        "apikey:one",
        GrantOperation::Read,
        AuditCtx::admin(AuditOp::GrantCreate),
    ) {
        Err(StoreOpError::Fenced { .. }) => {}
        other => panic!("a superseded writer must be fenced, got {other:?}"),
    }
    assert_eq!(
        store.grants_generation().expect("read generation"),
        4,
        "a rejected write must leave the counter where it was"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn every_credential_is_dated_from_its_own_chain_deposit_entry() {
    let (_root, store) = sqlite("backfill", 107);
    migrate_through_for_test(&store, 9).expect("migrate through version 9");
    // Sixty rows, a realistic store size, each with a distinct deposit instant except
    // for one deliberate same-millisecond pair.
    let expected: Vec<(String, i64)> = (0..60)
        .map(|index: i64| {
            let birth = if index == 59 {
                1_700_000_000_000 + 58
            } else {
                1_700_000_000_000 + index
            };
            (format!("apikey:{index:02}"), birth)
        })
        .collect();
    store
        .with_conn(|conn| {
            for (id, birth) in &expected {
                seed_credential_at_schema_9(conn, id, *birth)?;
            }
            Ok(())
        })
        .expect("seed sixty credentials");

    EncryptedStore::migrate(&store).expect("migrate to 10");

    let dated: Vec<(String, Option<i64>)> = store
        .with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT credential_id, created_at_ms FROM credentials ORDER BY credential_id",
            )?;
            let dated = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(dated)
        })
        .expect("read the dated rows");
    assert_eq!(dated.len(), 60);
    for (id, birth) in &expected {
        let actual = dated
            .iter()
            .find(|(dated_id, _)| dated_id == id)
            .map(|(_, value)| *value)
            .expect("every credential keeps its row");
        assert_eq!(
            actual,
            Some(*birth),
            "{id} must be dated from its own deposit entry"
        );
    }
    let distinct: BTreeSet<Option<i64>> = dated.iter().map(|(_, value)| *value).collect();
    assert_eq!(
        distinct.len(),
        59,
        "the values must be as distinct as the deposits are -- 59 instants over 60 \
             rows, because two were deposited in the same millisecond"
    );
}

#[test]
fn a_credential_the_chain_cannot_date_stops_the_migration_and_changes_nothing() {
    let (_root, store) = sqlite("undatable", 108);
    migrate_through_for_test(&store, 9).expect("migrate through version 9");
    store
            .with_conn(|conn| {
                seed_credential_at_schema_9(conn, "apikey:dated", 1_700_000_000_000)?;
                // A row whose only chain entries are writes, never a deposit.
                conn.execute(
                    "INSERT INTO credentials \
                     (credential_id, record_version, key_id, state, envelope, updated_at_ms) \
                     VALUES ('apikey:undated', 1, '00', 'active', X'00', 9)",
                    [],
                )?;
                append_unverified_chain_row(conn, 5, "overwrite", "apikey:undated")?;
                conn.execute(
                    "INSERT INTO read_grants \
                     (principal_kind, principal_id, selector_kind, credential_prefix, operation, created_at_ms) \
                     VALUES ('reserved', 'agent', 'prefix', 'apikey:', 'read', 7)",
                    [],
                )?;
                Ok(())
            })
            .expect("seed a schema-9 store");
    let before = table_dump(&store);

    let error = EncryptedStore::migrate(&store)
        .expect_err("a credential the chain cannot date must stop the migration");
    let message = error.to_string();
    assert!(
        message.contains("apikey:undated"),
        "the refusal must name the offending id: {message}"
    );
    assert!(
        !message.contains("apikey:dated"),
        "the refusal must name only the rows it cannot date: {message}"
    );

    assert_eq!(schema_version_of(&store), 9, "the store stays where it was");
    assert_eq!(
        table_dump(&store),
        before,
        "a refused migration leaves the credentials and the grants untouched"
    );
    let objects = vault_schema_objects(&store);
    for absent in [
        "enrolled_consumers",
        "pending_enrollments",
        "grants_generation",
    ] {
        assert!(
            !objects.iter().any(|(_, name, _)| name == absent),
            "{absent} must not exist after a refused migration"
        );
    }
}

/// The credential and grant rows, as text, so a refused migration can be compared
/// against the store it started from.
fn table_dump(store: &SqliteStore) -> Vec<String> {
    store
            .with_conn(|conn| {
                let mut rows = Vec::new();
                let mut credentials = conn.prepare(
                    "SELECT credential_id, record_version, state, updated_at_ms \
                      FROM credentials ORDER BY credential_id",
                )?;
                for row in credentials.query_map([], |row| {
                    Ok(format!(
                        "credential {} {} {} {}",
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?
                    ))
                })? {
                    rows.push(row?);
                }
                drop(credentials);
                let mut grants = conn.prepare(
                    "SELECT principal_kind, principal_id, selector_kind, credential_prefix, operation \
                      FROM read_grants ORDER BY principal_kind, principal_id, credential_prefix, operation",
                )?;
                for row in grants.query_map([], |row| {
                    Ok(format!(
                        "grant {} {} {} {} {}",
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?
                    ))
                })? {
                    rows.push(row?);
                }
                Ok(rows)
            })
            .expect("dump the credential and grant rows")
}

#[test]
fn a_name_is_unique_among_live_rows_and_free_among_terminal_ones() {
    let (_root, store) = sqlite("live-names", 109);
    EncryptedStore::migrate(&store).expect("migrate");

    let enrollment = |id: &str, name: &str, revoked: Option<i64>| {
        store.with_conn(|conn| {
            conn.execute(
                "INSERT INTO enrolled_consumers \
                     (enrollment_id, name, approved_at_ms, approved_by, revoked_at_ms) \
                     VALUES (?1, ?2, 1, 'operator', ?3)",
                rusqlite::params![id, name, revoked],
            )
        })
    };
    enrollment("one", "broca", None).expect("the first live incarnation");
    assert!(
        enrollment("two", "broca", None).is_err(),
        "two live incarnations of one name would let a grant reach two consumers"
    );
    enrollment("three", "broca", Some(2)).expect("a revoked incarnation keeps the name");
    enrollment("four", "broca", Some(3)).expect("revoked incarnations do not collide");
    assert_eq!(
        store
            .with_conn(|conn| conn.query_row(
                "SELECT COUNT(*) FROM enrolled_consumers WHERE name = 'broca'",
                [],
                |row| row.get::<_, i64>(0)
            ))
            .expect("count incarnations"),
        3,
        "a revoked row and the live one share the name"
    );

    let pending = |request: &str, name: &str, state: &str| {
        store.with_conn(|conn| {
                conn.execute(
                    "INSERT INTO pending_enrollments \
                     (request_id, proposed_name, request_secret_hash, state, created_at_ms, expires_at_ms) \
                     VALUES (?1, ?2, 'ff', ?3, 1, 2)",
                    rusqlite::params![request, name, state],
                )
            })
    };
    pending("r1", "broca", "pending").expect("the first request");
    assert!(
        pending("r2", "broca", "pending").is_err(),
        "one live request per proposed name"
    );
    assert!(
        pending("r3", "broca", "approved").is_err(),
        "an approved request holds the name until it is consumed"
    );
    for (request, state) in [("r4", "denied"), ("r5", "consumed"), ("r6", "expired")] {
        pending(request, "broca", state)
            .unwrap_or_else(|error| panic!("a {state} row must not block the name: {error}"));
    }
}

#[test]
fn opening_a_migrated_store_without_the_write_lease_writes_nothing() {
    let (root, store) = rig("unleased", 110);
    store
        .create_audited("apikey:one", &api_record(), AuditCtx::admin(AuditOp::Put))
        .expect("deposit");
    store
        .create_read_grant_audited(
            "reserved",
            "agent",
            SelectorKind::Exact,
            "apikey:one",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .expect("create grant");
    let path = root.join("store.db");
    let key = MasterKey::from_bytes([110; 32]);

    let counts_before = row_counts(&store.store);
    let mtime_before = std::fs::metadata(&path)
        .expect("stat store")
        .modified()
        .expect("store mtime");

    // The lease-free readers, on the same file, with no write lease held.
    let (metas, schema) = list_meta_read_only_with_schema(&path).expect("lease-free metadata read");
    assert_eq!(schema, newest_migration_version());
    assert_eq!(metas.len(), 1);
    let (grants, _) = list_read_grants_read_only_with_schema(&path).expect("lease-free grants");
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].selector, "apikey:one");
    assert_eq!(grants[0].selector_kind, SelectorKind::Exact);
    assert_eq!(
        verify_audit_chain_read_only(&path, &key).expect("lease-free chain verification"),
        None,
        "the chain must verify after a lease-free open, with no repair and no append"
    );

    assert_eq!(
        row_counts(&store.store),
        counts_before,
        "a lease-free open must write no row"
    );
    assert_eq!(
        std::fs::metadata(&path)
            .expect("stat store")
            .modified()
            .expect("store mtime"),
        mtime_before,
        "a lease-free open must not touch the store file"
    );
    let _ = std::fs::remove_dir_all(&root);
}

fn enrollment_secret(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

#[test]
fn grant_to_an_enrolled_name_approve_cannot_accept_is_refused_at_creation_only() {
    let (_root, store) = rig("grant-unapprovable-enrolled-name", 162);
    // 33 bytes: one past the approval grammar's 32-byte limit.
    let too_long = "a".repeat(33);
    assert!(!crate::enrollment::valid_enrollment_name(&too_long));
    let before = store.audit_tip().unwrap();
    let created = store.create_read_grant_audited(
        "enrolled",
        &too_long,
        SelectorKind::Category,
        "llm-provider",
        GrantOperation::Read,
        AuditCtx::admin(AuditOp::GrantCreate),
    );
    assert!(
        matches!(created, Err(StoreOpError::InvalidPrincipal)),
        "{created:?}"
    );
    assert_eq!(store.audit_tip().unwrap(), before);

    // 32 bytes is the largest name approval accepts, so it must still be grantable.
    let longest = "a".repeat(32);
    store
        .create_read_grant_audited(
            "enrolled",
            &longest,
            SelectorKind::Category,
            "llm-provider",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();

    // Revocation keeps the wider rule: a grant an older build created under an
    // unapprovable name must stay removable, so the principal is not what refuses.
    let revoked = store.revoke_read_grant_audited(
        "enrolled",
        &too_long,
        SelectorKind::Category,
        "llm-provider",
        GrantOperation::Read,
        AuditCtx::admin(AuditOp::GrantRevoke),
    );
    assert!(
        !matches!(revoked, Err(StoreOpError::InvalidPrincipal)),
        "revocation must not apply the approval grammar: {revoked:?}"
    );
}

#[test]
fn missing_enrollment_approve_returns_not_found_without_audit() {
    let (_root, store) = rig("missing-enrollment-approve", 158);
    let before = store.audit_tip().unwrap();
    let result = store.approve_enrollment(&enrollment_secret(40), "consumer", "operator");
    assert_eq!(store.audit_tip().unwrap(), before);
    assert!(matches!(result, Err(StoreOpError::NotFound)), "{result:?}");
}

#[test]
fn missing_enrollment_deny_returns_not_found_without_audit() {
    let (_root, store) = rig("missing-enrollment-deny", 159);
    let before = store.audit_tip().unwrap();
    let result = store.deny_enrollment(&enrollment_secret(40), "operator");
    assert_eq!(store.audit_tip().unwrap(), before);
    assert!(matches!(result, Err(StoreOpError::NotFound)), "{result:?}");
}

#[test]
fn missing_enrollment_revoke_returns_not_found_without_audit() {
    let (_root, store) = rig("missing-enrollment-revoke", 160);
    let before = store.audit_tip().unwrap();
    let result = store.revoke_enrollment("consumer", "operator");
    assert_eq!(store.audit_tip().unwrap(), before);
    assert!(matches!(result, Err(StoreOpError::NotFound)), "{result:?}");
}

#[test]
fn missing_enrollment_reissue_returns_not_found_without_audit() {
    let (_root, store) = rig("missing-enrollment-reissue", 161);
    let before = store.audit_tip().unwrap();
    let result = store.reissue_enrollment("consumer", "operator").map(|_| ());
    assert_eq!(store.audit_tip().unwrap(), before);
    assert!(matches!(result, Err(StoreOpError::NotFound)), "{result:?}");
}

#[test]
fn approval_and_denial_persist_expiry_without_denial_audits() {
    let (_root, store) = rig("expired-decisions", 157);
    let hash = enrollment_secret_hash(&enrollment_secret(7)).unwrap();
    for approve in [true, false] {
        let proposal = store.propose_enrollment("consumer", &hash).unwrap();
        store
            .with_raw_conn(|conn| {
                conn.execute(
                    "UPDATE pending_enrollments SET expires_at_ms = 0 WHERE request_id = ?1",
                    [&proposal.request_id],
                )
            })
            .unwrap();
        let before = store.read_audit(None).unwrap().len();
        let result = if approve {
            store
                .approve_enrollment(&proposal.request_id, "consumer", "operator")
                .map(|_| ())
        } else {
            store.deny_enrollment(&proposal.request_id, "operator")
        };
        assert!(
            matches!(result, Err(StoreOpError::NotFound)),
            "an expired request must answer NotFound, not a storage error: {result:?}"
        );
        let state: String = store
            .with_raw_conn(|conn| {
                conn.query_row(
                    "SELECT state FROM pending_enrollments WHERE request_id = ?1",
                    [&proposal.request_id],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert_eq!(state, "expired");
        assert_eq!(store.read_audit(None).unwrap().len(), before);
        let expires: i64 = store.with_raw_conn(|conn| conn.query_row("SELECT COUNT(*) FROM auth_events WHERE credential_id = ?1 AND detail = 'expired'", [ENROLL_EXPIRE_SUBJECT], |row| row.get(0))).unwrap();
        assert_eq!(expires, if approve { 1 } else { 2 });
    }
}

#[test]
fn default_category_assignments_and_removal_advance_generation() {
    let (_root, store) = rig("default-generation", 158);
    let before = store.grants_generation().unwrap();
    store.create("apikey:zai", &api_record()).unwrap();
    let created = store.grants_generation().unwrap();
    assert!(created > before);
    store
        .remove_audited("apikey:zai", AuditCtx::admin(AuditOp::Remove))
        .unwrap();
    let removed = store.grants_generation().unwrap();
    assert!(removed > created);
    store
        .deposit_cookie(
            "cookie:example.com:agent",
            &crate::secret::SecretString::from("session=x".to_string()),
            "consent",
            None,
            "reserved:agent",
        )
        .unwrap();
    let deposited = store.grants_generation().unwrap();
    assert!(deposited > removed);
    store
        .deposit_cookie(
            "cookie:example.com:agent",
            &crate::secret::SecretString::from("session=y".to_string()),
            "consent",
            None,
            "reserved:agent",
        )
        .unwrap();
    assert_eq!(store.grants_generation().unwrap(), deposited);
}

#[test]
fn migration_targets_attribute_each_id_to_its_category() {
    let assignments = vec![
        ("one".into(), "alpha".into()),
        ("two".into(), "beta".into()),
        ("three".into(), "alpha".into()),
    ];
    assert_eq!(
        migration_category_targets(&assignments),
        ["category:alpha|one,three", "category:beta|two"]
    );
}

#[test]
fn schema_nine_grant_listing_explains_required_migration() {
    let (root, sqlite) = sqlite("schema-nine-listing", 159);
    migrate_through_for_test(&sqlite, 9).unwrap();
    sqlite.with_conn(|conn| conn.execute("INSERT INTO read_grants (principal_kind, principal_id, selector_kind, credential_prefix, operation, created_at_ms) VALUES ('reserved', 'agent', 'prefix', 'apikey:', 'read', 0)", [])).unwrap();
    let error = list_read_grants_read_only_with_schema(&root.join("store.db"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("store schema 9"), "{error}");
    assert!(
        error.contains("selector kinds arrive with migration 10"),
        "{error}"
    );
    assert!(
        error.contains("restart the daemon on this build"),
        "{error}"
    );
}

#[test]
fn malformed_hashes_secrets_and_tokens_refuse_before_any_store_lookup() {
    let (_root, store) = rig("enrollment-grammar", 116);
    let invalid_values = [
        "a".repeat(63),
        "a".repeat(65),
        "AB".repeat(32),
        format!("{}g", "a".repeat(63)),
    ];
    for invalid in &invalid_values {
        assert!(matches!(
            store.propose_enrollment("consumer", invalid),
            Err(EnrollmentError::Refused(EnrollmentRefusal::InvalidParams))
        ));
    }
    let pending_count: i64 = store
        .with_raw_conn(|conn| {
            conn.query_row("SELECT COUNT(*) FROM pending_enrollments", [], |row| {
                row.get(0)
            })
        })
        .expect("count pending rows");
    assert_eq!(pending_count, 0, "malformed hashes write no pending row");

    store
        .with_raw_conn(|conn| {
            conn.execute_batch("DROP TABLE pending_enrollments; DROP TABLE enrolled_consumers;")
        })
        .expect("remove lookup tables");
    for invalid in &invalid_values {
        assert!(matches!(
            store.poll_enrollment("request", invalid),
            Err(EnrollmentError::Refused(EnrollmentRefusal::InvalidParams))
        ));
        assert!(matches!(
            store.rotate_enrollment(invalid, 1),
            Err(EnrollmentError::Refused(EnrollmentRefusal::InvalidParams))
        ));
    }
}

#[test]
fn pending_queue_is_bounded_without_eviction_and_ttl_reclaims_approved_capacity() {
    let (_root, store) = rig("enrollment-queue", 111);
    let base = now_ms();
    let secret = enrollment_secret(7);
    let secret_hash = enrollment_secret_hash(&secret).expect("hash secret");
    let oldest = store
        .propose_enrollment_at("oldest", &secret_hash, base)
        .expect("oldest proposal");
    for index in 0..14 {
        store
            .propose_enrollment_at(&format!("n{index}"), &secret_hash, base + index)
            .expect("fill queue below the limit");
    }
    let below_limit: i64 = store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM pending_enrollments WHERE state IN ('pending','approved')",
                [],
                |row| row.get(0),
            )
        })
        .expect("count queue below the limit");
    assert_eq!(below_limit, ENROLLMENT_LIVE_LIMIT - 1);
    store
        .propose_enrollment_at("n14", &secret_hash, base + 14)
        .expect("the sixteenth live row is accepted");
    store
        .approve_enrollment(&oldest.request_id, "oldest", "operator")
        .expect("approve oldest without consuming it");

    for index in 0..32 {
        assert!(matches!(
            store.propose_enrollment_at(&format!("f{index}"), &secret_hash, base + 100 + index),
            Err(EnrollmentError::Refused(
                EnrollmentRefusal::PendingQueueFull
            ))
        ));
    }
    let full_count: i64 = store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM pending_enrollments WHERE state IN ('pending','approved')",
                [],
                |row| row.get(0),
            )
        })
        .expect("count full queue after refused floods");
    assert_eq!(full_count, ENROLLMENT_LIVE_LIMIT);
    assert!(matches!(
        store.poll_enrollment_at(&oldest.request_id, &secret, base + 200),
        Ok(EnrollmentPoll::Approved { .. })
    ));
    let live: i64 = store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM pending_enrollments WHERE state IN ('pending','approved')",
                [],
                |row| row.get(0),
            )
        })
        .expect("count live queue");
    assert_eq!(
        live, 15,
        "consumption frees exactly the approved row's slot"
    );

    // Refill that slot with an approved-but-unconsumed row, which must occupy it.
    let held = store
        .propose_enrollment_at("held", &secret_hash, base + 300)
        .expect("refill queue");
    store
        .approve_enrollment(&held.request_id, "held", "operator")
        .expect("approve held request");
    assert!(matches!(
        store.propose_enrollment_at("blocked", &secret_hash, base + 400),
        Err(EnrollmentError::Refused(
            EnrollmentRefusal::PendingQueueFull
        ))
    ));

    let after_ttl = base + ENROLLMENT_PENDING_TTL_MS + 401;
    store
        .propose_enrollment_at("reclaimed", &secret_hash, after_ttl)
        .expect("TTL sweep reclaims every stale live slot");
    assert!(matches!(
        store.poll_enrollment_at(&held.request_id, &secret, after_ttl),
        Err(EnrollmentError::Refused(EnrollmentRefusal::Superseded))
    ));
}

#[test]
fn approved_restart_poll_rotation_and_total_poll_transitions_hold() {
    let (root, store) = rig("enrollment-restart", 112);
    let secret = enrollment_secret(8);
    let secret_hash = enrollment_secret_hash(&secret).expect("hash secret");
    let proposal = store
        .propose_enrollment("consumer", &secret_hash)
        .expect("propose");
    let enrollment_id = store
        .approve_enrollment(&proposal.request_id, "consumer", "operator")
        .expect("approve");
    let pending_secret = enrollment_secret(14);
    let pending = store
        .propose_enrollment(
            "pending-restart",
            &enrollment_secret_hash(&pending_secret).expect("hash pending secret"),
        )
        .expect("pending proposal before restart");
    let before_restart: (Option<String>, i64) = store
            .with_raw_conn(|conn| {
                conn.query_row(
                    "SELECT token_hash, token_generation FROM enrolled_consumers WHERE enrollment_id = ?1",
                    [&enrollment_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
            })
            .expect("read approval row");
    assert_eq!(before_restart, (None, 0));
    drop(store);

    let descriptor = StorageDescriptor {
        module_id: "cortexkit-credentials".into(),
        storage_namespace: "vault".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: root.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let sqlite = open_sqlite(&descriptor).expect("reopen sqlite");
    let store = std::sync::Arc::new(
        EncryptedStore::open(sqlite, MasterKey::from_bytes([112; 32])).expect("reopen vault"),
    );
    let chain_before_poll = store.read_audit(None).expect("audit").len();
    assert!(matches!(
        store.poll_enrollment(&pending.request_id, &pending_secret),
        Ok(EnrollmentPoll::Pending)
    ));

    let wrong = enrollment_secret(9);
    assert!(matches!(
        store.poll_enrollment(&proposal.request_id, &wrong),
        Err(EnrollmentError::Refused(EnrollmentRefusal::NotFound))
    ));
    assert!(matches!(
        store.poll_enrollment(&enrollment_secret(10), &secret),
        Err(EnrollmentError::Refused(EnrollmentRefusal::NotFound))
    ));

    let left = std::sync::Arc::clone(&store);
    let right = std::sync::Arc::clone(&store);
    let left_id = proposal.request_id.clone();
    let right_id = proposal.request_id.clone();
    let left_secret = secret.clone();
    let right_secret = secret.clone();
    let first = std::thread::spawn(move || left.poll_enrollment(&left_id, &left_secret));
    let second = std::thread::spawn(move || right.poll_enrollment(&right_id, &right_secret));
    let outcomes = [
        first.join().expect("first poll"),
        second.join().expect("second poll"),
    ];
    let approved = outcomes
        .iter()
        .find_map(|outcome| match outcome {
            Ok(EnrollmentPoll::Approved {
                token,
                token_generation,
                ..
            }) => Some((token.clone(), *token_generation)),
            _ => None,
        })
        .expect("exactly one poll delivers");
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                Err(EnrollmentError::Refused(EnrollmentRefusal::AlreadyConsumed))
            ))
            .count(),
        1
    );
    assert_eq!(approved.1, 1);
    assert!(is_lower_hex_32(&approved.0));
    assert_eq!(
        store.read_audit(None).expect("audit").len(),
        chain_before_poll
    );

    let stored_hash: String = store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT token_hash FROM enrolled_consumers WHERE enrollment_id = ?1",
                [&enrollment_id],
                |row| row.get(0),
            )
        })
        .expect("stored token hash");
    assert_eq!(stored_hash, enrollment_secret_hash(&approved.0).unwrap());
    store
            .with_raw_conn(|conn| {
                conn.execute(
                    "INSERT INTO read_grants \
                     (principal_kind, principal_id, selector_kind, selector, operation, created_at_ms) \
                     VALUES ('enrolled', 'consumer', 'exact', 'apikey:one', 'read', 123)",
                    [],
                )
            })
            .expect("seed enrolled grant");
    let grants_before: Vec<(String, String, String, String, String, i64)> = store
            .with_raw_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT principal_kind, principal_id, selector_kind, selector, operation, created_at_ms \
                     FROM read_grants ORDER BY principal_kind, principal_id, selector_kind, selector, operation",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    })?
                    .collect();
                rows
            })
            .expect("dump grants before rotation");

    let chain_before_rotate = store.read_audit(None).expect("audit").len();
    let rotated = store
        .rotate_enrollment(&approved.0, 1)
        .expect("rotate to two");
    assert_eq!(rotated.token_generation, 2);
    assert_eq!(
        store.read_audit(None).expect("audit").len(),
        chain_before_rotate + 1
    );
    assert!(matches!(
        store.rotate_enrollment(&rotated.token, 1),
        Err(EnrollmentError::Refused(EnrollmentRefusal::StaleGeneration))
    ));
    assert_eq!(
        store.read_audit(None).expect("audit").len(),
        chain_before_rotate + 1
    );
    assert!(matches!(
        store.rotate_enrollment(&approved.0, 1),
        Err(EnrollmentError::Refused(EnrollmentRefusal::NotFound))
    ));
    let rotated_again = store
        .rotate_enrollment(&rotated.token, 2)
        .expect("rotate to three");
    assert_eq!(rotated_again.token_generation, 3);
    assert_eq!(
        store.read_audit(None).expect("audit").len(),
        chain_before_rotate + 2
    );
    let grants_after: Vec<(String, String, String, String, String, i64)> = store
            .with_raw_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT principal_kind, principal_id, selector_kind, selector, operation, created_at_ms \
                     FROM read_grants ORDER BY principal_kind, principal_id, selector_kind, selector, operation",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    })?
                    .collect();
                rows
            })
            .expect("dump grants after rotation");
    assert_eq!(
        grants_after, grants_before,
        "rotation must not touch grants"
    );
}

#[test]
fn revoked_reissued_expired_and_reenrolled_requests_are_superseded_without_hash_changes() {
    let (_root, store) = rig("enrollment-superseded", 115);
    let base = now_ms();

    let old_secret = enrollment_secret(20);
    let old = store
        .propose_enrollment(
            "old-proposal",
            &enrollment_secret_hash(&old_secret).unwrap(),
        )
        .expect("old proposal");
    let old_enrollment = store
        .approve_enrollment(&old.request_id, "reused-name", "operator")
        .expect("approve old incarnation");
    store
        .revoke_enrollment("reused-name", "operator")
        .expect("revoke old incarnation");
    assert!(matches!(
        store.poll_enrollment(&old.request_id, &old_secret),
        Err(EnrollmentError::Refused(EnrollmentRefusal::Superseded))
    ));
    let old_hash: Option<String> = store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT token_hash FROM enrolled_consumers WHERE enrollment_id = ?1",
                [&old_enrollment],
                |row| row.get(0),
            )
        })
        .expect("old token hash");
    assert_eq!(old_hash, None);

    let new_secret = enrollment_secret(21);
    let new = store
        .propose_enrollment("reused-name", &enrollment_secret_hash(&new_secret).unwrap())
        .expect("new proposal");
    store
        .approve_enrollment(&new.request_id, "reused-name", "operator")
        .expect("approve new incarnation");
    assert!(matches!(
        store.poll_enrollment(&old.request_id, &old_secret),
        Err(EnrollmentError::Refused(EnrollmentRefusal::Superseded))
    ));
    assert!(matches!(
        store.poll_enrollment(&new.request_id, &new_secret),
        Ok(EnrollmentPoll::Approved { name, .. }) if name == "reused-name"
    ));

    let reissue_secret = enrollment_secret(22);
    let reissue_request = store
        .propose_enrollment(
            "repair-proposal",
            &enrollment_secret_hash(&reissue_secret).unwrap(),
        )
        .expect("repair proposal");
    let reissue_id = store
        .approve_enrollment(&reissue_request.request_id, "repair-name", "operator")
        .expect("approve repair");
    let reissued = store
        .reissue_enrollment("repair-name", "operator")
        .expect("operator reissue");
    assert_eq!(reissued.token_generation, 1);
    let reissued_hash = enrollment_secret_hash(&reissued.token).unwrap();
    assert!(matches!(
        store.poll_enrollment(&reissue_request.request_id, &reissue_secret),
        Err(EnrollmentError::Refused(EnrollmentRefusal::Superseded))
    ));
    let hash_after_poll: String = store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT token_hash FROM enrolled_consumers WHERE enrollment_id = ?1",
                [&reissue_id],
                |row| row.get(0),
            )
        })
        .expect("hash after superseded poll");
    assert_eq!(hash_after_poll, reissued_hash);

    let expiring_secret = enrollment_secret(23);
    let expiring = store
        .propose_enrollment_at(
            "expiring",
            &enrollment_secret_hash(&expiring_secret).unwrap(),
            base,
        )
        .expect("expiring proposal");
    let expiring_id = store
        .approve_enrollment(&expiring.request_id, "expiring", "operator")
        .expect("approve expiring request");
    assert!(matches!(
        store.poll_enrollment_at(
            &expiring.request_id,
            &expiring_secret,
            base + ENROLLMENT_PENDING_TTL_MS + 1
        ),
        Err(EnrollmentError::Refused(EnrollmentRefusal::Superseded))
    ));
    let expired_hash: Option<String> = store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT token_hash FROM enrolled_consumers WHERE enrollment_id = ?1",
                [&expiring_id],
                |row| row.get(0),
            )
        })
        .expect("expired approval token hash");
    assert_eq!(expired_hash, None);
}

#[test]
fn terminal_rows_and_enrollment_events_stay_bounded_without_chain_growth() {
    let (_root, store) = rig("enrollment-bounds", 113);
    let secret = enrollment_secret(11);
    let secret_hash = enrollment_secret_hash(&secret).expect("hash secret");
    let base = now_ms();
    let terminal_cycles = ENROLLMENT_TERMINAL_MAX_ROWS + 8;
    let chain_before_expiry = store.read_audit(None).expect("audit").len();
    for index in 0..terminal_cycles {
        store
            .propose_enrollment_at(
                "expiry-cycle",
                &secret_hash,
                base + index * (ENROLLMENT_PENDING_TTL_MS + 1),
            )
            .expect("expire then repropose same name");
    }
    assert_eq!(
        store.read_audit(None).expect("audit").len(),
        chain_before_expiry,
        "propose and expiry never enter the HMAC chain"
    );

    let denial_base = base + (terminal_cycles + 1) * (ENROLLMENT_PENDING_TTL_MS + 1);
    let mut saw_below_terminal_cap = false;
    let mut saw_terminal_cap = false;
    for index in 0..terminal_cycles {
        let proposal = store
            .propose_enrollment_at("denial-cycle", &secret_hash, denial_base + index)
            .expect("terminal rows neither block a name nor consume queue capacity");
        store
            .deny_enrollment(&proposal.request_id, "operator")
            .expect("deny");
        if !saw_terminal_cap {
            let boundary_count: i64 = store
                .with_raw_conn(|conn| {
                    conn.query_row("SELECT COUNT(*) FROM pending_enrollments", [], |row| {
                        row.get(0)
                    })
                })
                .expect("count terminal boundary");
            if boundary_count == ENROLLMENT_TERMINAL_MAX_ROWS - 1 {
                saw_below_terminal_cap = true;
            }
            if boundary_count == ENROLLMENT_TERMINAL_MAX_ROWS {
                assert!(
                    saw_below_terminal_cap,
                    "the terminal-row boundary skipped its just-below control"
                );
                saw_terminal_cap = true;
            }
        }
    }
    assert!(
        saw_terminal_cap,
        "the cycle must reach the terminal-row cap"
    );
    let count: i64 = store
        .with_raw_conn(|conn| {
            conn.query_row("SELECT COUNT(*) FROM pending_enrollments", [], |row| {
                row.get(0)
            })
        })
        .expect("count bounded table");
    assert_eq!(count, ENROLLMENT_TERMINAL_MAX_ROWS);
    let old_terminal: i64 = store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM pending_enrollments \
                     WHERE state IN ('denied','consumed','expired') AND created_at_ms < ?1",
                [denial_base - ENROLLMENT_TERMINAL_RETENTION_MS],
                |row| row.get(0),
            )
        })
        .expect("count old terminal rows");
    assert_eq!(old_terminal, 0);

    let legitimate = store
        .propose_enrollment_at("legitimate", &secret_hash, denial_base + 2_000)
        .expect("legitimate pending row");
    let chain_before_wrong_secrets = store.read_audit(None).expect("audit").len();
    let wrong = enrollment_secret(12);
    for _ in 0..(AUTH_EVENTS_PER_CREDENTIAL + 8) {
        assert!(matches!(
            store.poll_enrollment_at(&legitimate.request_id, &wrong, denial_base + 2_001),
            Err(EnrollmentError::Refused(EnrollmentRefusal::NotFound))
        ));
    }
    assert_eq!(
        store.read_audit(None).expect("audit").len(),
        chain_before_wrong_secrets,
        "wrong-secret polls never enter the HMAC chain"
    );

    let events: Vec<(String, String, Option<String>)> = store
        .with_raw_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT credential_id, kind, detail FROM auth_events \
                     WHERE kind = 'enrollment' ORDER BY seq",
            )?;
            let rows = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                .collect();
            rows
        })
        .expect("read enrollment events");
    for subject in [
        ENROLL_PROPOSE_SUBJECT,
        ENROLL_POLL_SUBJECT,
        ENROLL_EXPIRE_SUBJECT,
    ] {
        assert!(events.iter().filter(|event| event.0 == subject).count() <= 64);
    }
    let rendered = serde_json::to_string(&events).expect("render events");
    for forbidden in [
        "expiry-cycle",
        "denial-cycle",
        legitimate.request_id.as_str(),
        secret.as_str(),
        wrong.as_str(),
        secret_hash.as_str(),
    ] {
        assert!(!rendered.contains(forbidden), "event leaked {forbidden}");
    }
}

/// A CONSUMER WAITING FOR APPROVAL MUST NOT ERASE THE EVIDENCE OF AN ATTACK ON ITS REQUEST.
///
/// A real consumer polled `auth.enroll_poll` about twice a second while it waited. When
/// every pending poll appended a row, the per-subject ring held only "pending" within
/// half a minute, and a wrong-secret `not_found` -- the one row that says someone else
/// is trying this request id -- was gone before anyone looked.
///
/// Drives more pending polls than the ring holds, then asserts the refusal recorded
/// before them is still there and that no "pending" row was written at all.
#[test]
fn pending_polls_record_nothing_and_cannot_evict_a_wrong_secret_refusal() {
    let (_root, store) = rig("enrollment-pending-silent", 116);
    let secret = enrollment_secret(21);
    let secret_hash = enrollment_secret_hash(&secret).expect("hash secret");
    let base = now_ms();
    let request = store
        .propose_enrollment_at("patient-consumer", &secret_hash, base)
        .expect("propose");

    let wrong = enrollment_secret(22);
    assert!(matches!(
        store.poll_enrollment_at(&request.request_id, &wrong, base + 1),
        Err(EnrollmentError::Refused(EnrollmentRefusal::NotFound))
    ));

    let polls = (AUTH_EVENTS_PER_CREDENTIAL as i64) * 2;
    for index in 0..polls {
        assert!(matches!(
            store.poll_enrollment_at(&request.request_id, &secret, base + 2 + index),
            Ok(EnrollmentPoll::Pending)
        ));
    }

    let details: Vec<String> = store
        .with_raw_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT detail FROM auth_events WHERE credential_id = ?1 ORDER BY seq")?;
            let rows = stmt
                .query_map([ENROLL_POLL_SUBJECT], |row| row.get(0))?
                .collect();
            rows
        })
        .expect("read poll events");
    assert_eq!(
        details,
        vec!["not_found".to_owned()],
        "after {polls} pending polls the poll ring must hold exactly the wrong-secret \
             refusal; a 'pending' row here means routine waiting is evicting diagnosis"
    );
}

#[test]
fn lease_free_readers_leave_expired_pending_rows_untouched_until_writer_reopens() {
    let (root, store) = rig("enrollment-read-only", 114);
    let secret_hash = enrollment_secret_hash(&enrollment_secret(13)).unwrap();
    store
        .propose_enrollment_at("expired-reader", &secret_hash, 1)
        .expect("seed old pending row");
    let path = root.join("store.db");
    let key = MasterKey::from_bytes([114; 32]);
    drop(store);

    assert!(read_auth_events_read_only(&path, 100).is_ok());
    assert!(verify_audit_chain_read_only(&path, &key).is_ok());
    let read_only =
        rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open lease-free read-only connection");
    let state: String = read_only
        .query_row(
            "SELECT state FROM pending_enrollments WHERE proposed_name = 'expired-reader'",
            [],
            |row| row.get(0),
        )
        .expect("read untouched row");
    assert_eq!(state, "pending");
    drop(read_only);

    let descriptor = StorageDescriptor {
        module_id: "cortexkit-credentials".into(),
        storage_namespace: "vault".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    };
    let sqlite = open_sqlite(&descriptor).expect("reopen writer");
    let reopened = EncryptedStore::open(sqlite, key).expect("writer sweeps on open");
    let remaining: i64 = reopened
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM pending_enrollments WHERE proposed_name = 'expired-reader'",
                [],
                |row| row.get(0),
            )
        })
        .expect("read swept row count");
    assert_eq!(
        remaining, 0,
        "the writer expires then retention-deletes the old row"
    );
}

/// Every row count a read path could plausibly move, so a write that lands anywhere
/// shows up rather than only one that lands where the test looked.
fn row_counts(store: &SqliteStore) -> Vec<(String, i64)> {
    store
        .with_conn(|conn| {
            let mut names_stmt =
                conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")?;
            let names = names_stmt
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(names_stmt);
            let mut counts = Vec::new();
            for name in names {
                let count: i64 =
                    conn.query_row(&format!("SELECT COUNT(*) FROM \"{name}\""), [], |row| {
                        row.get(0)
                    })?;
                counts.push((name, count));
            }
            Ok(counts)
        })
        .expect("count every table")
}
