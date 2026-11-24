//! Credential metadata, plan tiers, and read-only inventory.

use super::*;

impl EncryptedStore {
    /// Count lifecycle states and refresh intents without opening any envelope.
    pub fn health_snapshot(&self) -> crate::health::VaultHealth {
        self.health_snapshot_at(now_ms())
    }

    pub(super) fn health_snapshot_at(&self, now: i64) -> crate::health::VaultHealth {
        use crate::health::{
            HealthAccumulator, VaultHealth, MAX_LISTED_ID_BYTES, MAX_REFRESH_INTENT_AGE_MS,
        };
        let cutoff = now.saturating_sub(MAX_REFRESH_INTENT_AGE_MS);
        let snapshot = self.store.with_conn(|conn| {
            let mut summary = HealthAccumulator::new();
            // Intent diagnostics are optional. Keep state counts even if the intent
            // table cannot be read, as the credential table may still be serviceable.
            if let Ok((open, overdue)) = conn.query_row(
                "SELECT COUNT(*), COUNT(CASE WHEN started_at_ms < ?1 THEN 1 END) FROM refresh_intent",
                [cutoff], |row| Ok((row.get(0)?, row.get(1)?)),
            ) {
                summary.health.open_intents = open;
                summary.health.overdue_intents = overdue;
                if overdue > 0 {
                    let _ = sample_overdue_intents(conn, cutoff, &mut summary);
                }
            }
            let mut stmt = conn.prepare(
                "SELECT CASE WHEN state <> 'active' AND length(CAST(credential_id AS BLOB)) <= ?1 \
                  THEN credential_id END, state FROM credentials ORDER BY credential_id",
            )?;
            let mut rows = stmt.query([MAX_LISTED_ID_BYTES])?;
            while let Some(row) = rows.next()? {
                let id: Option<String> = row.get(0)?;
                let state: String = row.get(1)?;
                summary.add_record(id.as_deref(), RecordState::from_str(&state));
            }
            Ok(summary.finish(self.is_fenced_out()))
        });
        let Ok(mut health) = snapshot else {
            return VaultHealth::unreadable();
        };
        // An unreadable audit tip must not be replaced with a stale witness value.
        if let Ok(Some((seq, entry_mac))) = self.audit_tip() {
            health.audit_seq = Some(seq);
            health.audit_tip_mac = Some(entry_mac);
        }
        health
    }
}

fn sample_overdue_intents(
    conn: &rusqlite::Connection,
    cutoff: i64,
    summary: &mut crate::health::HealthAccumulator,
) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare(
        "SELECT credential_id FROM refresh_intent WHERE started_at_ms < ?1 \
          AND length(CAST(credential_id AS BLOB)) <= ?2 ORDER BY credential_id",
    )?;
    let mut rows = stmt.query(rusqlite::params![
        cutoff,
        crate::health::MAX_LISTED_ID_BYTES
    ])?;
    while summary.wants_overdue_sample() {
        let Some(row) = rows.next()? else {
            break;
        };
        summary.sample_overdue_intent(&row.get::<_, String>(0)?);
    }
    Ok(())
}

pub(super) fn split_categories(categories: String) -> Vec<String> {
    if categories.is_empty() {
        Vec::new()
    } else {
        categories.split(',').map(str::to_string).collect()
    }
}

/// Split a comma-joined provider-id list read with `group_concat`, and sort it.
///
/// SQLite does not promise that `group_concat` keeps the order of its source rows, and
/// the wire promises ascending byte order, so the order is established here rather than
/// trusted. Provider ids cannot contain a comma, so the split is exact.
pub(super) fn split_provider_ids(joined: String) -> Vec<String> {
    let mut ids = split_categories(joined);
    ids.sort_unstable();
    ids
}

/// The SQL expression for one credential's comma-joined provider ids, correlated to
/// the `credentials` row of the enclosing query, or an empty string on a store below
/// [`PROVIDER_ID_SCHEMA_VERSION`], where the table does not exist and a credential
/// truly has none.
pub(super) fn provider_ids_column(schema_version: u32) -> &'static str {
    if schema_version >= PROVIDER_ID_SCHEMA_VERSION {
        "COALESCE((SELECT group_concat(provider_id, ',') FROM credential_provider_ids \
         WHERE credential_id = credentials.credential_id), '')"
    } else {
        "''"
    }
}

/// One credential's provider ids in ascending byte order, or none on a store below
/// [`PROVIDER_ID_SCHEMA_VERSION`].
pub(super) fn provider_ids_from_conn(
    conn: &rusqlite::Connection,
    credential_id: &str,
    schema_version: u32,
) -> rusqlite::Result<Vec<String>> {
    if schema_version < PROVIDER_ID_SCHEMA_VERSION {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        "SELECT provider_id FROM credential_provider_ids WHERE credential_id = ?1 ORDER BY provider_id",
    )?;
    let ids = stmt
        .query_map(rusqlite::params![credential_id], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(ids)
}

pub(super) fn plan_tier_column(schema_version: u32) -> &'static str {
    if schema_version >= 16 {
        "(SELECT plan_tier FROM credential_plan_tiers WHERE credential_id = credentials.credential_id)"
    } else {
        "NULL"
    }
}

pub(super) fn plan_tier_observed_column(schema_version: u32) -> &'static str {
    if schema_version >= PLAN_TIER_OBSERVED_SCHEMA_VERSION {
        "(SELECT observed_at_ms FROM credential_plan_tiers WHERE credential_id = credentials.credential_id)"
    } else {
        "NULL"
    }
}

pub(super) fn plan_tier_since_column(schema_version: u32) -> &'static str {
    if schema_version >= PLAN_TIER_SINCE_SCHEMA_VERSION {
        "(SELECT since_ms FROM credential_plan_tiers WHERE credential_id = credentials.credential_id)"
    } else {
        "NULL"
    }
}

fn plan_tier_from_conn(
    conn: &rusqlite::Connection,
    id: &str,
    schema_version: u32,
) -> rusqlite::Result<Option<String>> {
    if schema_version < 16 {
        return Ok(None);
    }
    conn.query_row(
        "SELECT plan_tier FROM credential_plan_tiers WHERE credential_id = ?1",
        [id],
        |row| row.get(0),
    )
    .optional()
}

pub(super) fn write_plan_tier_tx(
    tx: &rusqlite::Transaction,
    audit_key: &[u8; 32],
    id: &str,
    tier: Option<&str>,
    ctx: AuditCtx<'_>,
) -> rusqlite::Result<()> {
    write_plan_tier_in_tx(tx, audit_key, MetadataTables::Local, id, tier, None, ctx)
}

/// Set or clear one id's plan tier in the given table family, auditing only a change.
pub(super) fn write_plan_tier_in_tx(
    tx: &rusqlite::Transaction,
    audit_key: &[u8; 32],
    tables: MetadataTables,
    id: &str,
    tier: Option<&str>,
    since_ms: Option<i64>,
    ctx: AuditCtx<'_>,
) -> rusqlite::Result<()> {
    let old = match tables {
        MetadataTables::Local => plan_tier_from_conn(tx, id, read_schema_version(tx)?)?,
        MetadataTables::Remote => tx
            .query_row(
                "SELECT plan_tier FROM remote_record_plan_tiers WHERE credential_id = ?1",
                [id],
                |row| row.get(0),
            )
            .optional()?,
    };
    let schema_version = read_schema_version(tx)?;
    let old_since: Option<i64> = if schema_version >= PLAN_TIER_SINCE_SCHEMA_VERSION {
        tx.query_row(
            &format!(
                "SELECT since_ms FROM {} WHERE credential_id = ?1",
                tables.plan_tiers()
            ),
            [id],
            |row| row.get(0),
        )
        .optional()?
        .flatten()
    } else {
        None
    };
    if old.as_deref() == tier && old_since == since_ms {
        return Ok(());
    }
    if old.as_deref() == tier {
        // A date edit changes the assertion, not when the vault first saw its tier.
        tx.execute(
            &format!(
                "UPDATE {} SET since_ms = ?2 WHERE credential_id = ?1",
                tables.plan_tiers()
            ),
            rusqlite::params![id, since_ms],
        )?;
    } else {
        tx.execute(
            &format!(
                "DELETE FROM {} WHERE credential_id = ?1",
                tables.plan_tiers()
            ),
            [id],
        )?;
        if let Some(tier) = tier {
            if schema_version >= PLAN_TIER_SINCE_SCHEMA_VERSION {
                tx.execute(
                &format!("INSERT INTO {} (credential_id, plan_tier, observed_at_ms, since_ms) VALUES (?1, ?2, ?3, ?4)", tables.plan_tiers()),
                rusqlite::params![id, tier, now_ms(), since_ms],
            )?;
            } else if schema_version >= PLAN_TIER_OBSERVED_SCHEMA_VERSION {
                tx.execute(
                    &format!(
                    "INSERT INTO {} (credential_id, plan_tier, observed_at_ms) VALUES (?1, ?2, ?3)",
                    tables.plan_tiers()
                ),
                    rusqlite::params![id, tier, now_ms()],
                )?;
            } else {
                tx.execute(
                    &format!(
                        "INSERT INTO {} (credential_id, plan_tier) VALUES (?1, ?2)",
                        tables.plan_tiers()
                    ),
                    rusqlite::params![id, tier],
                )?;
            }
        }
    }
    append_audit_tx(
        tx,
        audit_key,
        &AuditRecord {
            op: AuditOp::SetPlan,
            credential_id: Some(format!(
                "plan:{id}|{}|{}",
                old.as_deref().unwrap_or(""),
                tier.unwrap_or("")
            )),
            payload_hash: None,
            actor: ctx.actor.to_owned(),
            alarm: ctx.alarm,
        },
    )?;
    Ok(())
}

/// Read sealed observations without a lease, mutations, or quarantine side effects.
/// Inventory remains available if a key is missing or an individual envelope is bad.
pub fn detected_plans_read_only(
    path: &std::path::Path,
    key: &MasterKey,
) -> Result<DetectedPlanListing, StoreOpError> {
    let map = |e: rusqlite::Error| StoreOpError::from(StoreError::Backend(e.to_string()));
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(map)?;
    detected_plans_from_conn(&conn, key).map_err(map)
}

pub(super) fn detected_plans_from_conn(
    conn: &rusqlite::Connection,
    key: &MasterKey,
) -> rusqlite::Result<DetectedPlanListing> {
    let mut stmt =
        conn.prepare("SELECT credential_id, record_version, envelope FROM credentials")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)? as u64,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let mut plans = std::collections::BTreeMap::new();
    for row in rows {
        let (id, version, envelope) = row?;
        if let Some(plan) = envelope::open(
            key,
            &envelope,
            &RecordBinding {
                credential_id: &id,
                record_version: version,
            },
        )
        .ok()
        .and_then(|plain| VaultRecord::decode(&plain).ok())
        .and_then(|record| {
            record
                .detected_plan
                .map(|plan| (plan, record.detected_plan_tier_observed_at_ms))
        }) {
            plans.insert(id, (version, plan.0, plan.1));
        }
    }
    Ok(plans)
}

pub(super) fn home_watch_candidates_from_conn(
    conn: &rusqlite::Connection,
    key: &MasterKey,
) -> rusqlite::Result<Vec<HomeWatchCandidate>> {
    let mut stmt = conn.prepare(
        "SELECT credential_id, state, record_version, envelope, incarnation FROM credentials \
         WHERE state IN ('active', 'needs_reauth') ORDER BY credential_id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)? as u64,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;
    let mut candidates = Vec::new();
    for row in rows {
        let (id, state, version, envelope, incarnation) = row?;
        let Some(record) = envelope::open(
            key,
            &envelope,
            &RecordBinding {
                credential_id: &id,
                record_version: version,
            },
        )
        .ok()
        .and_then(|plain| VaultRecord::decode(&plain).ok()) else {
            continue;
        };
        let is_refreshable = record.is_refreshable();
        let condition = super::conditions::local_condition_conn(conn, &id, &incarnation)?;
        candidates.push(HomeWatchCandidate {
            credential_id: id,
            state: RecordState::from_str(&state),
            record_version: version,
            kind: record.kind,
            refresh_adapter: record.refresh_adapter,
            identity: record.identity,
            detected_plan: record.detected_plan,
            condition,
            is_refreshable,
        });
    }
    Ok(candidates)
}

/// Read one credential's `auth_method` without a lease, for `ck auth list --json`.
///
/// The value comes from the same closed table `credential.list_scoped` reports
/// (gateway settings first, then [`crate::list_auth_method::list_auth_method`] over
/// the unsealed record's kind and stored refresh adapter), never from the credential
/// id, so `ck auth list --json` and `credential.list_scoped` cannot disagree.
/// A non-gateway row that fails to open or decode maps to `None` (its JSON row carries
/// null) rather than failing the whole listing: one unreadable envelope must not hide
/// the other credentials, the same way `detected_plans_read_only` skips rather than refuses.
///
/// Lease-free and read-only, like the other inventory readers `ck auth list` uses:
/// safe beside a running daemon and against a stopped one.
#[allow(clippy::type_complexity)]
pub fn auth_methods_read_only(
    path: &std::path::Path,
    key: &MasterKey,
) -> Result<
    std::collections::BTreeMap<String, Option<crate::list_auth_method::ListAuthMethod>>,
    StoreOpError,
> {
    let map = |e: rusqlite::Error| StoreOpError::from(StoreError::Backend(e.to_string()));
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(map)?;
    auth_methods_from_conn(&conn, key).map_err(map)
}

fn auth_methods_from_conn(
    conn: &rusqlite::Connection,
    key: &MasterKey,
) -> rusqlite::Result<
    std::collections::BTreeMap<String, Option<crate::list_auth_method::ListAuthMethod>>,
> {
    let mut stmt =
        conn.prepare("SELECT credential_id, record_version, envelope FROM credentials")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)? as u64,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let mut methods = std::collections::BTreeMap::new();
    for row in rows {
        let (id, version, envelope) = row?;
        if gateway::has_settings(conn, &id)? {
            methods.insert(id, Some(crate::ListAuthMethod::Gateway));
            continue;
        }
        let method = envelope::open(
            key,
            &envelope,
            &RecordBinding {
                credential_id: &id,
                record_version: version,
            },
        )
        .ok()
        .and_then(|plain| VaultRecord::decode(&plain).ok())
        .map(|record| {
            crate::list_auth_method::list_auth_method(
                record.kind,
                record.refresh_adapter.as_deref(),
            )
        });
        // `open`/`decode` failing yields `None` inside `Some` flattening: keep the
        // row present with a null method rather than dropping it, so the caller
        // renders every inventory id exactly once.
        methods.insert(id, method.flatten());
    }
    Ok(methods)
}

/// Which family of tables holds an id's operator metadata (categories, provider ids
/// and plan tier). A local record's live beside `credentials`; a remote record's live
/// beside `remote_records`, because the local tables' foreign keys point at
/// `credentials`, which never holds a remote id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MetadataTables {
    Local,
    Remote,
}

impl MetadataTables {
    pub(super) const fn categories(self) -> &'static str {
        match self {
            Self::Local => "credential_categories",
            Self::Remote => "remote_record_categories",
        }
    }

    pub(super) const fn provider_ids(self) -> &'static str {
        match self {
            Self::Local => "credential_provider_ids",
            Self::Remote => "remote_record_provider_ids",
        }
    }

    const fn plan_tiers(self) -> &'static str {
        match self {
            Self::Local => "credential_plan_tiers",
            Self::Remote => "remote_record_plan_tiers",
        }
    }
}

/// Which record table holds `credential_id`, or `None` when neither does. The remote
/// tables are consulted only on a store that has them, so a reader meeting a store
/// from before federation sees local records exactly as before.
pub(super) fn metadata_tables_for(
    conn: &rusqlite::Connection,
    credential_id: &str,
) -> rusqlite::Result<Option<MetadataTables>> {
    let local: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM credentials WHERE credential_id = ?1)",
        [credential_id],
        |row| row.get(0),
    )?;
    if local {
        return Ok(Some(MetadataTables::Local));
    }
    if read_schema_version(conn)? < REMOTE_METADATA_SCHEMA_VERSION {
        return Ok(None);
    }
    let remote: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM remote_records WHERE credential_id = ?1)",
        [credential_id],
        |row| row.get(0),
    )?;
    Ok(remote.then_some(MetadataTables::Remote))
}

/// Whether a table of this name exists, so a guard that runs BEFORE the migration
/// chain can query a store whose shape it does not yet know.
pub(super) fn table_exists(conn: &rusqlite::Connection, name: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        rusqlite::params![name],
        |row| row.get(0),
    )
}

fn list_meta_from_conn(
    conn: &rusqlite::Connection,
    schema_version: u32,
) -> rusqlite::Result<Vec<(String, RecordMeta)>> {
    // Below migration 9 there is no `credential_categories` table, so the category
    // subquery would fail the whole read. Reading the pre-9 shape and reporting an
    // empty category list is the TRUE reading of that store: no categories exist yet.
    let sql = if schema_version >= CATEGORY_SCHEMA_VERSION {
        "SELECT credential_id, record_version, key_id, state, stale_pending, \
         COALESCE((SELECT group_concat(category, ',') FROM (\
             SELECT category FROM credential_categories WHERE credential_id = credentials.credential_id ORDER BY category\
         )), '') \
         FROM credentials ORDER BY credential_id"
    } else {
        "SELECT credential_id, record_version, key_id, state, stale_pending, '' \
         FROM credentials ORDER BY credential_id"
    };
    // CLI inventory reads can run before migration, without a writer lease.
    // Report no known creator when the store has no created_by column yet.
    let creator = if schema_version >= 14 {
        "created_by"
    } else {
        "NULL"
    };
    // The same holds one migration later for provider ids: below
    // PROVIDER_ID_SCHEMA_VERSION the table is absent and every credential has none.
    let providers = provider_ids_column(schema_version);
    let sql = sql.replace(
        "FROM credentials ORDER BY",
        &format!(
            ", {creator}, {providers}, {}, {}, {}, {} FROM credentials ORDER BY",
            plan_tier_column(schema_version),
            if schema_version >= 33 {
                "incarnation"
            } else {
                "NULL"
            },
            plan_tier_observed_column(schema_version),
            plan_tier_since_column(schema_version)
        ),
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows: Vec<(String, RecordMeta)> = stmt
        .query_map([], |row| {
            let categories: String = row.get(5)?;
            Ok((
                row.get(0)?,
                RecordMeta {
                    record_version: row.get::<_, i64>(1)? as u64,
                    key_id_hex: row.get(2)?,
                    state: RecordState::from_str(&row.get::<_, String>(3)?),
                    stale_pending: row.get::<_, i64>(4)? != 0,
                    categories: split_categories(categories),
                    created_by: row.get(6)?,
                    provider_ids: split_provider_ids(row.get(7)?),
                    plan_tier: row.get(8)?,
                    incarnation: row.get(9)?,
                    plan_tier_observed_at_ms: row.get(10)?,
                    plan_tier_since_ms: row.get(11)?,
                    gateway: None,
                },
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.retain(|(id, _)| !is_github_app_companion_id(id));
    for (id, meta) in &mut rows {
        meta.gateway = gateway::from_conn(conn, id, schema_version)?;
    }
    Ok(rows)
}

/// List credential metadata from a store file WITHOUT a lease or a master key, with
/// the store's recorded schema version.
///
/// The version rides along so a caller can say what the store is MISSING rather than
/// silently rendering a reduced view: a store one migration behind has no categories
/// yet, and an empty category column there is a fact about the store, not about the
/// credentials.
pub fn list_meta_read_only_with_schema(
    store_path: &std::path::Path,
) -> Result<(Vec<(String, RecordMeta)>, u32), StoreOpError> {
    let map = |e: rusqlite::Error| StoreOpError::from(StoreError::Backend(e.to_string()));
    let conn = rusqlite::Connection::open_with_flags(
        store_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(map)?;
    let schema_version = read_schema_version(&conn).map_err(map)?;
    #[cfg(all(windows, debug_assertions, feature = "test-support"))]
    crate::test_support::windows_runtime_pause("reader")
        .map_err(|e| StoreOpError::from(StoreError::Io(e)))?;
    list_meta_from_conn(&conn, schema_version)
        .map(|rows| (rows, schema_version))
        .map_err(map)
        .map_err(|error| match error {
            StoreOpError::Store(message) if message.contains("no such table: credentials") => {
                StoreOpError::NotFound
            }
            other => other,
        })
}

/// List credential metadata from a store file WITHOUT a lease or a master key.
///
/// A thin wrapper over [`list_meta_read_only_with_schema`] for callers that want only
/// the rows. Reach for the version-aware reader when the caller has to say anything
/// about what the store is missing; do not add a third reader beside these two.
pub fn list_meta_read_only(
    store_path: &std::path::Path,
) -> Result<Vec<(String, RecordMeta)>, StoreOpError> {
    list_meta_read_only_with_schema(store_path).map(|(rows, _)| rows)
}

/// Count open refresh intents from a store file WITHOUT a lease or a master key.
pub fn count_refresh_intents_read_only(
    store_path: &std::path::Path,
) -> Result<usize, StoreOpError> {
    let map = |e: rusqlite::Error| StoreOpError::from(StoreError::Backend(e.to_string()));
    let conn = rusqlite::Connection::open_with_flags(
        store_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(map)?;

    conn.query_row("SELECT COUNT(*) FROM refresh_intent", [], |row| {
        row.get::<_, i64>(0)
    })
    .map(|count| count as usize)
    .map_err(|e| match e {
        rusqlite::Error::SqliteFailure(_, Some(ref m)) if m.contains("no such table") => {
            StoreOpError::NotFound
        }
        other => map(other),
    })
}

/// Count what a whole-file placement of `store_path` would resurrect.
///
/// WHY THIS EXISTS AS CODE RATHER THAN AS A DOCUMENTED RULE: backup restores depend on
/// the scrub list it reports on, and as a written rule alone that list would have no
/// implementation and nothing that would notice if the reasoning were wrong.
///
/// Drilled against a real captured generation it found ZERO re-armed handles -- not
/// because the hazard is absent, but because that 24-hour window happened to contain no
/// mint-then-later-revoke pair straddling the capture. A null from a window that did not
/// contain the case is not evidence, and a zero reported without that sentence reads as
/// "hazard refuted", after which the remedy quietly gets dropped. Making the number
/// visible on any copy is what stops that.
pub fn restore_resurrection_read_only(
    store_path: &std::path::Path,
) -> Result<RestoreResurrection, StoreOpError> {
    let map = |e: rusqlite::Error| StoreOpError::from(StoreError::Backend(e.to_string()));
    // A restored file can have a WAL-mode header but no accompanying WAL files.
    // It needs the immutable URI option; a live store must read its uncheckpointed WAL.
    // Encode the path before adding the option so SQLite treats path bytes literally.
    use std::fmt::Write as _;
    let path = store_path.as_os_str().as_encoded_bytes();
    let mut uri = String::from("file:");
    for (index, &byte) in path.iter().enumerate() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~' | b':')
            // A leading double slash is a path, not a URI authority.
            || (byte == b'/' && (index != 0 || !path.starts_with(b"//")))
        {
            uri.push(char::from(byte));
        } else {
            write!(uri, "%{byte:02X}").expect("writing to a String cannot fail");
        }
    }
    uri.push_str("?immutable=1");
    let conn = rusqlite::Connection::open_with_flags(
        uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(map)?;

    let count = |sql: &str| -> Result<usize, StoreOpError> {
        conn.query_row(sql, [], |row| row.get::<_, i64>(0))
            .map(|n| n as usize)
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(_, Some(ref m)) if m.contains("no such table") => {
                    StoreOpError::NotFound
                }
                other => map(other),
            })
    };

    let live_handles = count("SELECT COUNT(*) FROM handles WHERE revoked = 0")?;
    let open_intents = count("SELECT COUNT(*) FROM refresh_intent")?;
    let read_grants = count("SELECT COUNT(*) FROM read_grants")?;
    // ABSENT rather than zero when the table is missing. A store predating the fence table
    // has no epoch, which is a different fact from an epoch of 0 -- and reporting 0 would
    // tell an operator the placement is fence-safe when nothing was read.
    let fence_epoch = conn
        .query_row("SELECT MAX(epoch) FROM cortexkit_fence", [], |row| {
            row.get::<_, Option<i64>>(0)
        })
        .unwrap_or(None);

    Ok(RestoreResurrection {
        live_handles,
        open_intents,
        fence_epoch,
        read_grants,
    })
}

impl EncryptedStore {
    /// Read non-secret metadata for an id WITHOUT decrypting.
    pub fn meta(&self, credential_id: &str) -> Result<RecordMeta, StoreOpError> {
        self.store
            .with_conn(|conn| {
                let meta = conn.query_row(
                    &format!("SELECT record_version, key_id, state, stale_pending, \
                     COALESCE((SELECT group_concat(category, ',') FROM (\
                         SELECT category FROM credential_categories WHERE credential_id = ?1 ORDER BY category\
                     )), ''), created_by, {}, {}, {} \
                     FROM credentials WHERE credential_id = ?1",
                     if read_schema_version(conn)? >= 33 { "incarnation" } else { "NULL" },
                     plan_tier_observed_column(read_schema_version(conn)?),
                     plan_tier_since_column(read_schema_version(conn)?)),
                    rusqlite::params![credential_id],
                    |row| {
                        let categories: String = row.get(4)?;
                        Ok(RecordMeta {
                            incarnation: row.get(6)?,
                            plan_tier_observed_at_ms: row.get(7)?,
                            plan_tier_since_ms: row.get(8)?,
                            record_version: row.get::<_, i64>(0)? as u64,
                            key_id_hex: row.get(1)?,
                            state: RecordState::from_str(&row.get::<_, String>(2)?),
                            stale_pending: row.get::<_, i64>(3)? != 0,
                            categories: split_categories(categories),
                            created_by: row.get(5)?,
                            provider_ids: Vec::new(),
                            plan_tier: None,
                            gateway: None,
                        })
                    },
                )
                .optional()?;
                match meta {
                    Some(mut meta) => {
                        meta.provider_ids = provider_ids_from_conn(
                            conn,
                            credential_id,
                            read_schema_version(conn)?,
                        )?;
                        meta.plan_tier = plan_tier_from_conn(conn, credential_id, read_schema_version(conn)?)?;
                        meta.gateway = gateway::from_conn(conn, credential_id, read_schema_version(conn)?)?;
                        Ok(Some(meta))
                    }
                    None => Ok(None),
                }
            })
            .map_err(StoreOpError::from)?
            .ok_or(StoreOpError::NotFound)
    }

    /// List every record's id and non-secret metadata without decrypting.
    pub fn list_meta(&self) -> Result<Vec<(String, RecordMeta)>, StoreOpError> {
        self.store
            .with_conn(|conn| list_meta_from_conn(conn, read_schema_version(conn)?))
            .map_err(StoreOpError::from)
    }
}
