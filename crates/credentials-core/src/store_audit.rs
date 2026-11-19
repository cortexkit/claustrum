//! Audit-chain persistence and authentication observations.

use super::*;

/// Load the vault's sealed audit key, or create it on a brand-new vault.
///
/// The audit key lives in `vault_secrets` under [`AUDIT_KEY_SECRET_NAME`], sealed
/// with the master key; that fixed name stands in for a credential id and, with
/// version 0, is the additional authenticated data (AAD) the seal is bound to. On an
/// existing row: decrypt it (a wrong master key fails closed here). On no row: only
/// create a fresh key from the operating system's secure random generator if the vault
/// is genuinely EMPTY (no credentials, no audit entries); otherwise the row's absence
/// is corruption and we fail closed rather than regenerate (which would orphan every
/// existing audit entry).
pub(super) fn load_or_create_audit_key(
    store: &SqliteStore,
    key: &MasterKey,
) -> Result<Zeroizing<[u8; 32]>, StoreOpError> {
    let binding = RecordBinding {
        credential_id: AUDIT_KEY_SECRET_NAME,
        record_version: AUDIT_KEY_RECORD_VERSION,
    };

    // Read the existing sealed audit-key envelope, if any.
    let existing: Option<Vec<u8>> = store
        .with_conn(|c| {
            c.query_row(
                "SELECT envelope FROM vault_secrets WHERE name = ?1",
                rusqlite::params![AUDIT_KEY_SECRET_NAME],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })
        })
        .map_err(StoreOpError::from)?;

    if let Some(blob) = existing {
        // Decrypt with the master key — fail-closed on a wrong key (KeyMismatch) or
        // tampering, never a panic.
        let plaintext = envelope::open(key, &blob, &binding).map_err(StoreOpError::Decrypt)?;
        let bytes: [u8; 32] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| StoreOpError::CorruptVault("audit key is not 32 bytes".to_string()))?;
        return Ok(Zeroizing::new(bytes));
    }

    // No audit-key row. Only a brand-new (empty) vault may create one.
    let non_empty: bool = store
        .with_conn(|c| {
            // Before the agent-secret migration, only the legacy tables can hold data.
            let schema_version = read_schema_version(c)?;
            let flow_non_empty = schema_version >= FLOW_SECRET_SCHEMA_VERSION
                && c.query_row("SELECT EXISTS(SELECT 1 FROM secret_flow_grants)", [], |r| {
                    r.get::<_, bool>(0)
                })?;
            let module_non_empty = schema_version >= MODULE_SECRET_SCHEMA_VERSION
                && c.query_row("SELECT EXISTS(SELECT 1 FROM module_secrets)", [], |r| {
                    r.get::<_, bool>(0)
                })?;
            let query = if schema_version >= AGENT_SECRET_SCHEMA_VERSION {
                "SELECT EXISTS(SELECT 1 FROM credentials) OR EXISTS(SELECT 1 FROM audit_log) \
                 OR EXISTS(SELECT 1 FROM agent_secrets) \
                 OR EXISTS(SELECT 1 FROM secret_phone_keys) \
                 OR EXISTS(SELECT 1 FROM secret_phone_observations) \
                 OR EXISTS(SELECT 1 FROM secret_pending_requests) \
                 OR EXISTS(SELECT 1 FROM secret_grants) \
                 OR EXISTS(SELECT 1 FROM secret_deposit_tombstones)"
            } else {
                "SELECT EXISTS(SELECT 1 FROM credentials) OR EXISTS(SELECT 1 FROM audit_log)"
            };
            c.query_row(query, [], |r| r.get::<_, i64>(0))
                .map(|v| v != 0 || flow_non_empty || module_non_empty)
        })
        .map_err(StoreOpError::from)?;
    if non_empty {
        return Err(StoreOpError::CorruptVault(
            "audit key missing on a non-empty vault (refusing to regenerate)".to_string(),
        ));
    }

    // Brand-new vault: mint a fresh audit key and seal it under the master key.
    let audit_key = Zeroizing::new(
        crate::audit::generate_audit_key()
            .map_err(|_| StoreOpError::Store("csprng".to_string()))?,
    );
    let blob = envelope::seal(key, &*audit_key, &binding).map_err(StoreOpError::Decrypt)?;
    let key_id_hex = key.key_id().to_hex();
    store
        .with_conn_fenced(|tx| {
            tx.execute(
                "INSERT INTO vault_secrets (name, key_id, envelope) VALUES (?1, ?2, ?3)",
                rusqlite::params![AUDIT_KEY_SECRET_NAME, key_id_hex, blob],
            )?;
            Ok(())
        })
        .map_err(StoreOpError::from)?;
    Ok(audit_key)
}

/// Append an audit entry within an open transaction: read the current tip mac,
/// compute this entry's mac over it, insert it. Used both standalone and folded
/// into a mutation's own transaction so the audit entry and the mutation commit
/// together. The single-writer lease guarantees no concurrent appender, so reading
/// the tip and inserting the next seq is race-free.
/// Verify the audit chain from a store file WITHOUT taking the single-writer lease.
///
/// Separate from [`EncryptedStore::verify_audit_chain`] for the reason that method
/// could never be used in production: opening an `EncryptedStore` acquires the lease,
/// so the tamper-evidence check required stopping the daemon. Nobody stops a vault to
/// run an integrity check, which means THE CHECK THAT JUSTIFIES THE HMAC CHAIN HAD
/// NEVER RUN ON THE LIVE STORE -- and a tamper-evidence mechanism nobody can afford to
/// invoke provides evidence of nothing.
///
/// The verification itself is a pure read: fetch the entries, recompute each MAC over
/// its predecessor. It needs the master key only to unseal the stored audit key, never
/// to write. Open read-only, not immutable, so the newest entries -- still in the
/// WAL on a live store, and the ones an operator is usually asking about -- are seen.
///
/// Returns the seq of the first broken entry, or `None` when the chain verifies.
pub fn verify_audit_chain_read_only(
    store_path: &std::path::Path,
    key: &MasterKey,
) -> Result<Option<i64>, StoreOpError> {
    let map = |e: rusqlite::Error| StoreOpError::from(StoreError::Backend(e.to_string()));
    let conn = rusqlite::Connection::open_with_flags(
        store_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(map)?;

    // Unseal the audit key. Its absence is NOT an empty chain: it means this store was
    // never opened by a build that provisions one, and reporting "verified" for a store
    // whose key cannot be found would be the exact false green the chain exists to
    // prevent.
    let sealed: Vec<u8> = conn
        .query_row(
            "SELECT envelope FROM vault_secrets WHERE name = ?1",
            rusqlite::params![AUDIT_KEY_SECRET_NAME],
            |r| r.get(0),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StoreOpError::NotFound,
            other => map(other),
        })?;
    let binding = RecordBinding {
        credential_id: AUDIT_KEY_SECRET_NAME,
        record_version: AUDIT_KEY_RECORD_VERSION,
    };
    // A decrypt failure here is the WRONG KEY, not a broken chain: say so, because
    // "verification failed" would send an operator hunting tampering when the real
    // answer is that the vault is sealed under a different master key.
    let plain = envelope::open(key, &sealed, &binding).map_err(|e| {
        StoreOpError::from(StoreError::Backend(format!(
            "the audit key does not open under this master key ({e:?}) -- wrong key, \
             not a broken chain"
        )))
    })?;
    let audit_key: [u8; 32] = plain
        .as_slice()
        .try_into()
        .map_err(|_| StoreOpError::from(StoreError::Backend("audit key length".into())))?;
    let audit_key = Zeroizing::new(audit_key);

    let mut stmt = conn
        .prepare(
            "SELECT seq, ts_ms, op, credential_id, payload_hash, actor, alarm, \
                    alarm_reason, prev_mac, entry_mac \
             FROM audit_log ORDER BY seq ASC",
        )
        .map_err(map)?;
    let entries = stmt
        .query_map([], row_to_audit)
        .map_err(map)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map)?;

    Ok(audit::verify_chain(&audit_key, &entries))
}

/// Credential ids whose diagnostic history is AT the retention cap, and has therefore
/// almost certainly been trimmed.
///
/// `auth_events` is capped per credential and the trim is a silent DELETE. That is the
/// right behaviour -- an unbounded diagnostic table on a path a hostile consumer can
/// drive is a disk-exhaustion lever -- but it leaves a reader unable to tell "this is
/// everything that happened" from "this is what survived". Those need different
/// responses: the first closes an investigation, the second says the evidence is gone
/// and the window has to be reconstructed another way.
///
/// At-cap is a heuristic and deliberately so: a credential sitting at exactly the cap
/// might never have been trimmed. Reporting a possible loss that did not happen costs
/// an operator one sentence; concealing one that did costs them the wrong conclusion.
pub fn auth_events_at_cap_read_only(
    store_path: &std::path::Path,
) -> Result<Vec<String>, StoreOpError> {
    let map = |e: rusqlite::Error| StoreOpError::from(StoreError::Backend(e.to_string()));
    let conn = rusqlite::Connection::open_with_flags(
        store_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(map)?;

    let mut stmt = conn
        .prepare(
            "SELECT credential_id FROM auth_events \
             GROUP BY credential_id HAVING COUNT(*) >= ?1 ORDER BY credential_id",
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(_, Some(ref m)) if m.contains("no such table") => {
                StoreOpError::NotFound
            }
            other => map(other),
        })?;
    let ids = stmt
        .query_map(rusqlite::params![AUTH_EVENTS_PER_CREDENTIAL as i64], |r| {
            r.get::<_, String>(0)
        })
        .map_err(map)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map)?;
    Ok(ids)
}

/// Read the audit chain from a store file WITHOUT a lease or a master key.
///
/// Every column here is plaintext -- seq, op, credential id, actor, alarm -- so unlike
/// [`verify_audit_chain_read_only`] this needs no key at all, only a read-only
/// connection.
///
/// Separate from [`EncryptedStore::read_audit`] for the same reason as the other
/// lease-free readers: the moment an operator asks what happened is the moment the
/// vault is running, and a forensic log that requires an outage to read is unavailable
/// exactly when it is wanted.
///
/// `limit` caps to the most recent N entries; `None` reads the whole chain. Returned
/// oldest-first, matching chain order.
pub fn read_audit_read_only(
    store_path: &std::path::Path,
    limit: Option<usize>,
) -> Result<Vec<AuditEntry>, StoreOpError> {
    let map = |e: rusqlite::Error| StoreOpError::from(StoreError::Backend(e.to_string()));
    let conn = rusqlite::Connection::open_with_flags(
        store_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(map)?;

    // Newest-first with the cap, then reversed into chain order -- the same shape as
    // the leased reader, so a capped read returns the RECENT entries rather than the
    // oldest ones.
    let cap: i64 = limit.map(|n| n as i64).unwrap_or(-1);
    let mut stmt = conn
        .prepare(
            "SELECT seq, ts_ms, op, credential_id, payload_hash, actor, alarm, \
                    alarm_reason, prev_mac, entry_mac \
             FROM audit_log ORDER BY seq DESC LIMIT ?1",
        )
        .map_err(map)?;
    let mut entries = stmt
        .query_map(rusqlite::params![cap], row_to_audit)
        .map_err(map)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map)?;
    entries.reverse();
    Ok(entries)
}

/// Read recent authentication events from a store file WITHOUT a lease or a key.
///
/// Separate from [`EncryptedStore::recent_auth_events`] because opening an
/// `EncryptedStore` acquires the single-writer lease, which requires the daemon
/// stopped. The moment an operator wants these rows is the moment a credential just
/// failed, i.e. while the vault is running -- a diagnostic that needs an outage to
/// read is useless exactly when it is needed.
///
/// Safe against a live vault: every column is plaintext (no envelope, so no master
/// key), and the connection is read-only, which also leaves the WAL untouched -- a
/// read-write open would checkpoint on close and rewrite the file being inspected.
///
/// Open read-only, not immutable: immutable skips the write-ahead log, and
/// against a live store the newest events -- the ones being asked about -- are exactly
/// what is still in the WAL.
pub fn read_auth_events_read_only(
    store_path: &std::path::Path,
    limit: u32,
) -> Result<Vec<AuthEvent>, StoreOpError> {
    let map = |e: rusqlite::Error| StoreOpError::from(StoreError::Backend(e.to_string()));
    let conn = rusqlite::Connection::open_with_flags(
        store_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(map)?;

    // A MISSING TABLE IS NOT AN EMPTY ONE, and the caller has to be able to tell them
    // apart. The table arrived in a later migration, so a store written by an older
    // build has no `auth_events` at all -- and a running daemon does not migrate until
    // it restarts. Reported as its own outcome, because the raw sqlite "no such table"
    // reads like a broken install, and "no events" would be a lie: this vault cannot
    // record one yet.
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'auth_events'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map_err(map)?
        != 0;
    if !table_exists {
        return Err(StoreOpError::NotFound);
    }

    let mut stmt = conn
        .prepare(auth_events_select(&conn).map_err(map)?)
        .map_err(map)?;
    let rows = stmt
        .query_map(rusqlite::params![limit], auth_event_from_row)
        .map_err(map)?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(map)
}

/// The `auth_events` read, shared by both readers.
///
/// Kept beside [`auth_event_from_row`] because the two must agree on COLUMN ORDER:
/// the mapper addresses columns positionally, so reordering this list without
/// reordering the mapper compiles cleanly and returns wrong values silently. There
/// are two readers (leased and lease-free), and duplicating the pair would mean two
/// places that have to be changed together with nothing to catch a miss.
const AUTH_EVENTS_SELECT: &str =
    "SELECT ts_ms, credential_id, kind, provider_status, detail, reporter_source, record_version, applied, \
            principal_kind, principal_id \
     FROM auth_events ORDER BY seq DESC LIMIT ?1";

// A read-only CLI can run before the daemon has restarted to apply migration 4. Keep
// its existing diagnostics readable by projecting absent principal fields as NULL.
const AUTH_EVENTS_SELECT_PRE_PRINCIPAL: &str =
    "SELECT ts_ms, credential_id, kind, provider_status, detail, NULL AS reporter_source, record_version, applied, \
            NULL AS principal_kind, NULL AS principal_id \
     FROM auth_events ORDER BY seq DESC LIMIT ?1";

const AUTH_EVENTS_SELECT_PRE_REPORTER_SOURCE: &str =
    "SELECT ts_ms, credential_id, kind, provider_status, detail, NULL AS reporter_source, record_version, applied, \
            principal_kind, principal_id \
     FROM auth_events ORDER BY seq DESC LIMIT ?1";

fn auth_events_select(conn: &rusqlite::Connection) -> rusqlite::Result<&'static str> {
    let mut stmt = conn.prepare("PRAGMA table_info(auth_events)")?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let has_principal = columns.iter().any(|column| column == "principal_kind")
        && columns.iter().any(|column| column == "principal_id");
    let has_reporter_source = columns.iter().any(|column| column == "reporter_source");
    if has_principal && has_reporter_source {
        Ok(AUTH_EVENTS_SELECT)
    } else if has_principal {
        Ok(AUTH_EVENTS_SELECT_PRE_REPORTER_SOURCE)
    } else {
        Ok(AUTH_EVENTS_SELECT_PRE_PRINCIPAL)
    }
}

/// Decode one `auth_events` row. Positional, so it is bound to the column order in
/// [`AUTH_EVENTS_SELECT`] and [`AUTH_EVENTS_SELECT_PRE_PRINCIPAL`].
fn auth_event_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AuthEvent> {
    Ok(AuthEvent {
        ts_ms: r.get(0)?,
        credential_id: r.get(1)?,
        kind: r.get(2)?,
        provider_status: r.get::<_, Option<i64>>(3)?.map(|s| s as u16),
        detail: r.get(4)?,
        reporter_source: r.get(5)?,
        record_version: r.get::<_, Option<i64>>(6)?.map(|v| v as u64),
        applied: r.get::<_, i64>(7)? != 0,
        principal_kind: r.get(8)?,
        principal_id: r.get(9)?,
    })
}

/// Append one `auth_events` row. Diagnostics only: not MAC-chained, prunable, and
/// nothing may depend on it being complete.
///
/// `applied` records whether the observation actually changed the credential, which is
/// what separates "a consumer reported a dead token and we marked it" from "a consumer
/// reported against a version we had already replaced".
pub(crate) fn append_auth_event_tx(
    tx: &rusqlite::Transaction,
    credential_id: &str,
    obs: &AuthObservation<'_>,
    record_version: Option<u64>,
    applied: bool,
) -> rusqlite::Result<()> {
    append_secret_auth_event_tx(
        tx,
        credential_auth_subject(credential_id),
        obs,
        record_version,
        applied,
    )
}

fn credential_auth_subject(id: &str) -> &str {
    if id.contains('|') {
        "credential.invalid_id"
    } else {
        id
    }
}

// Secret diagnostics use disjoint subjects; generic credential writers must never enter them.
pub(super) fn append_secret_auth_event_tx(
    tx: &rusqlite::Transaction,
    credential_id: &str,
    obs: &AuthObservation<'_>,
    record_version: Option<u64>,
    applied: bool,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO auth_events \
             (ts_ms, credential_id, kind, provider_status, detail, reporter_source, record_version, applied, principal_kind, principal_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        rusqlite::params![
            now_ms(),
            credential_id,
            obs.kind,
            obs.provider_status.map(|s| s as i64),
            obs.detail,
            obs.reporter_source.map(ReporterSource::as_str),
            record_version.map(|v| v as i64),
            applied as i64,
            obs.principal.map(AuthEventPrincipal::kind),
            obs.principal.and_then(AuthEventPrincipal::id),
        ],
    )?;
    trim_auth_events_tx(tx, credential_id)
}

// Every auth-event writer calls this in the insert transaction, so a repeated scoped
// read refusal cannot turn diagnostics into an unbounded durable write path.
pub(super) fn trim_auth_events_tx(
    tx: &rusqlite::Transaction,
    credential_id: &str,
) -> rusqlite::Result<()> {
    tx.execute(
        "DELETE FROM auth_events \
         WHERE credential_id = ?1 AND seq NOT IN (\
             SELECT seq FROM auth_events WHERE credential_id = ?1 \
             ORDER BY seq DESC LIMIT ?2\
         )",
        rusqlite::params![credential_id, AUTH_EVENTS_PER_CREDENTIAL as i64],
    )?;
    Ok(())
}

pub(crate) fn append_audit_tx(
    tx: &rusqlite::Transaction,
    audit_key: &[u8; 32],
    record: &AuditRecord,
) -> rusqlite::Result<AuditEntry> {
    // An EMPTY audit table is the only reason to start from genesis (QueryReturnedNoRows
    // on the tip read). ANY OTHER query error (a broken/locked/damaged audit_log) must
    // propagate and fail the whole mutation's transaction — silently substituting genesis
    // would let a mutation commit against an unreadable chain, forking it. The
    // COALESCE(MAX(seq),0)+1 query returns a row even on an empty table, so it never hits
    // NoRows; only a real error surfaces there, and that too must propagate.
    let prev_mac: String = match tx.query_row(
        "SELECT entry_mac FROM audit_log ORDER BY seq DESC LIMIT 1",
        [],
        |r| r.get::<_, String>(0),
    ) {
        Ok(mac) => mac,
        Err(rusqlite::Error::QueryReturnedNoRows) => audit::GENESIS_MAC.to_string(),
        Err(e) => return Err(e),
    };

    let next_seq: i64 =
        tx.query_row("SELECT COALESCE(MAX(seq), 0) + 1 FROM audit_log", [], |r| {
            r.get(0)
        })?;

    let ts_ms = now_ms();
    let op = record.op.as_str();
    let alarm = record.alarm.is_some();
    let alarm_reason = record.alarm.map(AlarmReason::as_str);
    let entry_mac = audit::compute_entry_mac(
        audit_key,
        &prev_mac,
        &audit::MacFields {
            seq: next_seq,
            ts_ms,
            op,
            credential_id: record.credential_id.as_deref(),
            payload_hash: record.payload_hash.as_deref(),
            actor: &record.actor,
            alarm,
            alarm_reason,
        },
    );

    tx.execute(
        "INSERT INTO audit_log \
         (seq, ts_ms, op, credential_id, payload_hash, actor, alarm, alarm_reason, prev_mac, entry_mac) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        rusqlite::params![
            next_seq,
            ts_ms,
            op,
            record.credential_id,
            record.payload_hash,
            record.actor,
            alarm as i64,
            alarm_reason,
            prev_mac,
            entry_mac,
        ],
    )?;

    Ok(AuditEntry {
        seq: next_seq,
        ts_ms,
        op: op.to_string(),
        credential_id: record.credential_id.clone(),
        payload_hash: record.payload_hash.clone(),
        actor: record.actor.clone(),
        alarm,
        alarm_reason: alarm_reason.map(String::from),
        prev_mac,
        entry_mac,
    })
}

pub(super) fn row_to_audit(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEntry> {
    Ok(AuditEntry {
        seq: row.get(0)?,
        ts_ms: row.get(1)?,
        op: row.get(2)?,
        credential_id: row.get(3)?,
        payload_hash: row.get(4)?,
        actor: row.get(5)?,
        alarm: row.get::<_, i64>(6)? != 0,
        alarm_reason: row.get(7)?,
        prev_mac: row.get(8)?,
        entry_mac: row.get(9)?,
    })
}

impl EncryptedStore {
    /// Record an authentication observation WITHOUT changing the credential.
    ///
    /// For events that explain a credential's health but authorise no state change --
    /// chiefly a refresh that failed transiently, which clears its intent and leaves
    /// the record active. Nothing durable said the provider had been called and
    /// refused, so a credential could fail repeatedly and look untouched.
    ///
    /// Diagnostics only, and this write deliberately skips the fence that guards every
    /// credential mutation. That fence rejects a write from an instance whose lease has
    /// been taken over, which is right for anything carrying authority and wrong here:
    /// an explanatory row would then fail exactly when a handover is making the system
    /// hardest to explain.
    pub fn record_auth_event(
        &self,
        credential_id: &str,
        observation: AuthObservation<'_>,
        record_version: Option<u64>,
    ) -> Result<(), StoreOpError> {
        self.store
            .with_conn(|c| {
                let tx = c.unchecked_transaction()?;
                append_auth_event_tx(&tx, credential_id, &observation, record_version, false)?;
                tx.commit()
            })
            .map_err(StoreOpError::from)
    }

    /// Record why a principal-scoped read was refused. This is a trimmable diagnostic
    /// observation, not an authority transition, so it deliberately does not take the
    /// writer fence or append to the untrimmable audit chain.
    pub fn record_scoped_read_refusal(
        &self,
        credential_id: &str,
        principal_kind: &str,
        principal_id: Option<&str>,
        refusal: ScopedReadRefusal,
    ) -> Result<(), StoreOpError> {
        let credential_id = credential_auth_subject(credential_id);
        self.store
            .with_conn(|c| {
                let tx = c.unchecked_transaction()?;
                tx.execute(
                    "INSERT INTO auth_events \
                     (ts_ms, credential_id, kind, provider_status, detail, record_version, applied, principal_kind, principal_id) \
                     VALUES (?1, ?2, ?3, NULL, ?4, NULL, 0, ?5, ?6)",
                     rusqlite::params![
                         now_ms(),
                         credential_id,
                         AuthEventKind::ScopedReadRefusal.as_str(),
                         refusal.as_str(),
                        principal_kind,
                        principal_id,
                    ],
                )?;
                trim_auth_events_tx(&tx, credential_id)?;
                tx.commit()
            })
            .map_err(StoreOpError::from)
    }

    /// Record the FIRST successful scoped use of a credential by a principal.
    ///
    /// Idempotent by construction: the INSERT is conditioned on no prior row for the
    /// same (credential, principal, operation), so a consumer calling ten thousand times
    /// writes exactly one row. That is the whole design, and the reason is EVICTION
    /// rather than growth -- `auth_events` trims to the newest 64 rows per credential, so
    /// a per-call success would push out the refusal rows that answer why something
    /// stopped working. The least interesting row would evict the most interesting.
    ///
    /// WHY IT EXISTS: the audit recorded only refusals, which leaves two states
    /// indistinguishable -- a consumer whose scoped calls work, and one that never makes
    /// any. Measured 2026-09-19: `prefrontal-core` held three grants over 22 credentials
    /// with 467 refreshes in 24h, and 23 live capability handles on those same
    /// credentials explained every refresh equally well. Nothing in the store could say
    /// whether one scoped call had ever succeeded.
    ///
    /// Best-effort at the call site, like the refusal path: a diagnostic that could fail
    /// a read would be worse than the blindness it cures.
    pub fn record_scoped_first_use(
        &self,
        credential_id: &str,
        principal_kind: &str,
        principal_id: Option<&str>,
        operation: GrantOperation,
    ) -> Result<(), StoreOpError> {
        let credential_id = credential_auth_subject(credential_id);
        self.store
            .with_conn(|c| {
                let kind = AuthEventKind::ScopedFirstUse.as_str();
                let operation = operation.as_str();
                // The credential index bounds this probe to one credential's events.
                // A hit needs no writer lock; on a miss the insert rechecks for races.
                let already_recorded: bool = c.query_row(
                    "SELECT EXISTS(SELECT 1 FROM auth_events \
                     WHERE credential_id = ?1 AND kind = ?2 AND detail = ?3 \
                       AND principal_kind = ?4 AND principal_id IS ?5)",
                    rusqlite::params![credential_id, kind, operation, principal_kind, principal_id],
                    |row| row.get(0),
                )?;
                if already_recorded {
                    return Ok(());
                }

                let tx = c.unchecked_transaction()?;
                // The operation rides in `detail` rather than a new column: it is the
                // same shape the refusal path uses for its reason, and a migration for a
                // diagnostic field would cost more than it buys.
                let inserted = tx.execute(
                    "INSERT INTO auth_events \
                     (ts_ms, credential_id, kind, provider_status, detail, record_version, applied, principal_kind, principal_id) \
                     SELECT ?1, ?2, ?3, NULL, ?4, NULL, 1, ?5, ?6 \
                     WHERE NOT EXISTS ( \
                       SELECT 1 FROM auth_events \
                       WHERE credential_id = ?2 AND kind = ?3 AND detail = ?4 \
                         AND principal_kind = ?5 \
                         AND (principal_id IS ?6) \
                     )",
                    rusqlite::params![
                        now_ms(),
                        credential_id,
                        kind,
                        operation,
                        principal_kind,
                        principal_id,
                    ],
                )?;
                if inserted != 0 {
                    trim_auth_events_tx(&tx, credential_id)?;
                }
                tx.commit()
            })
            .map_err(StoreOpError::from)
    }

    /// [`Self::record_scoped_first_use`] for a typed principal, so a caller cannot
    /// misspell the stored kind. A member (another vault on a federation channel) is
    /// recorded under its own member id rather than the channel's module.
    pub fn record_scoped_first_use_by(
        &self,
        credential_id: &str,
        principal: AuthEventPrincipal<'_>,
        operation: GrantOperation,
    ) -> Result<(), StoreOpError> {
        self.record_scoped_first_use(credential_id, principal.kind(), principal.id(), operation)
    }

    /// Record that a read served a reported-stale token because the credential's
    /// current version was written inside the engine's report cooldown.
    ///
    /// At most ONE row per (credential, record_version), whatever the number of reads.
    /// A version's cooldown opens when that version is written, so each window maps to
    /// one version and "once per version" is "once per window". A row per read would
    /// be wrong twice over: a consumer in a report loop reads in a loop too, and
    /// `auth_events` keeps only the newest [`AUTH_EVENTS_PER_CREDENTIAL`] rows per
    /// credential, so deferral rows would evict the refusal rows that explain the loop.
    ///
    /// Unfenced and best-effort at the call site, like the other diagnostic writers: an
    /// explanatory row must never fail the read it describes. Returns whether a row was
    /// written.
    pub fn record_stale_refresh_deferred(
        &self,
        credential_id: &str,
        record_version: u64,
    ) -> Result<bool, StoreOpError> {
        let credential_id = credential_auth_subject(credential_id);
        self.store
            .with_conn(|c| {
                let tx = c.unchecked_transaction()?;
                let written = tx.execute(
                    "INSERT INTO auth_events \
                     (ts_ms, credential_id, kind, provider_status, detail, record_version, applied) \
                     SELECT ?1, ?2, ?3, NULL, NULL, ?4, 0 \
                     WHERE NOT EXISTS ( \
                       SELECT 1 FROM auth_events \
                       WHERE credential_id = ?2 AND kind = ?3 AND record_version = ?4 \
                     )",
                    rusqlite::params![
                        now_ms(),
                        credential_id,
                        AuthEventKind::StaleRefreshDeferred.as_str(),
                        record_version as i64,
                    ],
                )?;
                trim_auth_events_tx(&tx, credential_id)?;
                tx.commit()?;
                Ok(written > 0)
            })
            .map_err(StoreOpError::from)
    }

    /// Read recent authentication events, newest first. Diagnostics for an operator
    /// asking why a credential stopped working; never an authority for what happened.
    pub fn recent_auth_events(&self, limit: u32) -> Result<Vec<AuthEvent>, StoreOpError> {
        self.store
            .with_conn(|c| {
                let mut stmt = c.prepare(auth_events_select(c)?)?;
                let rows = stmt.query_map(rusqlite::params![limit], auth_event_from_row)?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
            })
            .map_err(StoreOpError::from)
    }

    // ---- audit chain ----------------------------------------------------

    /// Append one entry to the tamper-evident audit chain, computing its HMAC over
    /// the previous entry's mac, in a fenced write. Standalone variant; mutation
    /// paths that must audit atomically use [`append_audit_tx`] inside their own
    /// transaction.
    pub fn append_audit(&self, record: &AuditRecord) -> Result<AuditEntry, StoreOpError> {
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| append_audit_tx(tx, &audit_key, record))
            .map_err(StoreOpError::from)
    }

    /// Record a signature only while the decoded key's generation is still current.
    /// `identity` is the version and incarnation read with the key. Checking both in
    /// the append transaction prevents replacement or removal/recreation from placing
    /// an old-key signature after the new key's audit row. Signed bytes are published
    /// with the signature, so their plain SHA-256 lets readers compare the published
    /// payload with its audit row without a vault key.
    pub fn append_signature_audit(
        &self,
        credential_id: &str,
        identity: (u64, &str),
        signed_payload: &[u8],
        actor: &str,
    ) -> Result<AuditEntry, StoreOpError> {
        self.append_key_use_audit(
            AuditOp::Sign,
            credential_id,
            identity,
            &payload_hash(signed_payload),
            actor,
        )
    }

    /// Record one `credential.seal` before its ciphertext is returned, under the same
    /// fence as a signature row: the row is written only while the key generation the
    /// daemon sealed with is still the stored one. Only a keyed fingerprint of
    /// `sealed_plaintext` is recorded, so database readers cannot test plaintext guesses.
    pub fn append_seal_audit(
        &self,
        credential_id: &str,
        identity: (u64, &str),
        sealed_plaintext: &[u8],
        actor: &str,
    ) -> Result<AuditEntry, StoreOpError> {
        self.append_key_use_audit(
            AuditOp::Seal,
            credential_id,
            identity,
            &audit::payload_fingerprint(&self.audit_key, sealed_plaintext),
            actor,
        )
    }

    fn append_key_use_audit(
        &self,
        op: AuditOp,
        credential_id: &str,
        identity: (u64, &str),
        payload_hash: &[u8; 32],
        actor: &str,
    ) -> Result<AuditEntry, StoreOpError> {
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            let current: Option<(i64, String)> = tx
                .query_row(
                    "SELECT record_version, incarnation FROM credentials WHERE credential_id = ?1",
                    [credential_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            match current {
                Some((version, incarnation)) if incarnation == identity.1 => {
                    if version != identity.0 as i64 {
                        return Ok(Err(StoreOpError::CasMismatch));
                    }
                }
                _ => return Ok(Err(StoreOpError::NotFound)),
            }
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op,
                    credential_id: Some(credential_id.to_string()),
                    payload_hash: Some(hex32(payload_hash)),
                    actor: actor.to_string(),
                    alarm: None,
                },
            )
            .map(Ok)
        })
        .map_err(StoreOpError::from)?
    }

    /// Read the current audit-chain tip without scanning the chain.
    ///
    /// The sequence and entry MAC are returned together because the MAC binds the row at
    /// that sequence. A witness that records only the sequence cannot detect a truncated
    /// tail followed by fresh legitimate appends that reuse the same sequence number.
    /// Returns `None` when the audit chain is empty.
    pub fn audit_tip(&self) -> Result<Option<(i64, String)>, StoreOpError> {
        self.store
            .with_conn(|c| {
                c.query_row(
                    "SELECT seq, entry_mac FROM audit_log ORDER BY seq DESC LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
            })
            .map_err(StoreOpError::from)
    }

    /// Read the audit chain (oldest first), capped at `limit` most-recent entries
    /// when `limit` is `Some`. Used by status/monitoring to surface alarms and by
    /// the integrity check.
    pub fn read_audit(&self, limit: Option<usize>) -> Result<Vec<AuditEntry>, StoreOpError> {
        self.store
            .with_conn(|c| {
                // Fetch newest-first with the cap, then reverse to chain order.
                let cap: i64 = limit.map(|n| n as i64).unwrap_or(-1); // -1 = no limit
                let mut stmt = c.prepare(
                    "SELECT seq, ts_ms, op, credential_id, payload_hash, actor, alarm, \
                            alarm_reason, prev_mac, entry_mac \
                     FROM audit_log ORDER BY seq DESC LIMIT ?1",
                )?;
                let rows = stmt.query_map(rusqlite::params![cap], row_to_audit)?;
                let mut v = rows.collect::<rusqlite::Result<Vec<_>>>()?;
                v.reverse();
                Ok(v)
            })
            .map_err(StoreOpError::from)
    }

    /// Verify the full audit chain against the persisted audit key, sealed under the master key.
    /// Returns the seq of the first broken entry, or `None` if it verifies.
    pub fn verify_audit_chain(&self) -> Result<Option<i64>, StoreOpError> {
        let entries = self.read_audit(None)?;
        Ok(audit::verify_chain(&self.audit_key, &entries))
    }
}
