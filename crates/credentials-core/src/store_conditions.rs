//! Provider login conditions are lifetime-bound metadata, not serving state.

use super::*;

pub const MAX_CONDITION_ACTION_URL_BYTES: usize = 2048;
pub const MAX_CONDITION_SINCE_MS: u64 = (1 << 53) - 1;

/// The projection shared by a local login and a watched copy. The local reporter
/// is retained separately and does not travel with the condition.
#[derive(Clone, PartialEq, Eq)]
pub struct Condition {
    pub reason: String,
    pub since_ms: u64,
    pub action_url: Option<String>,
}

impl std::fmt::Debug for Condition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Condition")
            .field("reason", &self.reason)
            .field("since_ms", &self.since_ms)
            .finish_non_exhaustive()
    }
}

/// Reporter-supplied inputs. The action URL may contain account-identifying data.
#[derive(Clone, Copy)]
pub struct ConditionReport<'a> {
    pub reason: &'a str,
    pub provider_status: u16,
    pub action_url: Option<&'a str>,
}

/// Check the report against one adapter, in admission order. The forwarding vault can
/// use this on its copy; the home vault checks again against its own row in the write.
pub fn check_condition_report(
    adapter: Option<&str>,
    reason: &str,
    provider_status: u16,
    action_url: Option<&str>,
) -> Result<(), StoreOpError> {
    if adapter
        .and_then(|adapter| crate::catalog::condition_link_hosts(adapter, reason))
        .is_none()
    {
        return Err(StoreOpError::ConditionNotAdmitted);
    }
    if provider_status != 403 {
        return Err(StoreOpError::ConditionStatusRefused);
    }
    if let Some(link) = action_url {
        check_condition_link(adapter, reason, link)?;
    }
    Ok(())
}

/// Check a present link, without requiring that a received linkless reason is known.
pub fn check_condition_link(
    adapter: Option<&str>,
    reason: &str,
    link: &str,
) -> Result<(), StoreOpError> {
    let hosts = adapter
        .and_then(|adapter| crate::catalog::condition_link_hosts(adapter, reason))
        .ok_or(StoreOpError::ConditionLinkRefused)?;
    if link.len() > MAX_CONDITION_ACTION_URL_BYTES
        || !link.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(StoreOpError::ConditionLinkRefused);
    }
    // The URL parser normalizes away an explicit default port and empty userinfo.
    // Match the authority as sent before consulting the parsed URL.
    let authority = link
        .strip_prefix("https://")
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        .ok_or(StoreOpError::ConditionLinkRefused)?;
    if !hosts
        .iter()
        .any(|host| authority.eq_ignore_ascii_case(host))
    {
        return Err(StoreOpError::ConditionLinkRefused);
    }
    let parsed = url::Url::parse(link).map_err(|_| StoreOpError::ConditionLinkRefused)?;
    if parsed.fragment().is_some() || !parsed.host_str().is_some_and(|host| hosts.contains(&host)) {
        return Err(StoreOpError::ConditionLinkRefused);
    }
    Ok(())
}

fn condition_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Condition> {
    Ok(Condition {
        reason: row.get(0)?,
        since_ms: row.get(1)?,
        action_url: row.get(2)?,
    })
}

#[derive(Clone, Copy)]
enum Location {
    Local,
    Remote,
}

fn condition_in_incarnation(
    conn: &rusqlite::Connection,
    id: &str,
    incarnation: &str,
    location: Location,
) -> rusqlite::Result<Option<Condition>> {
    if read_schema_version(conn)? < CONDITION_SCHEMA_VERSION {
        return Ok(None);
    }
    let sql = match location {
        Location::Local => {
            "SELECT c.reason, c.since_ms, c.action_url FROM credential_conditions c \
             JOIN credentials r USING (credential_id, incarnation) \
             WHERE c.credential_id = ?1 AND c.incarnation = ?2"
        }
        Location::Remote => {
            "SELECT c.reason, c.since_ms, c.action_url FROM remote_record_conditions c \
             JOIN remote_records r USING (credential_id, incarnation) \
             WHERE c.credential_id = ?1 AND c.incarnation = ?2"
        }
    };
    conn.query_row(sql, rusqlite::params![id, incarnation], condition_from_row)
        .optional()
}

pub(super) fn remote_condition_conn(
    conn: &rusqlite::Connection,
    id: &str,
    incarnation: &str,
) -> rusqlite::Result<Option<Condition>> {
    condition_in_incarnation(conn, id, incarnation, Location::Remote)
}

pub(super) fn local_condition_conn(
    conn: &rusqlite::Connection,
    id: &str,
    incarnation: &str,
) -> rusqlite::Result<Option<Condition>> {
    condition_in_incarnation(conn, id, incarnation, Location::Local)
}

pub(super) fn write_remote_condition_tx(
    tx: &rusqlite::Transaction<'_>,
    id: &str,
    incarnation: &str,
    condition: Option<&Condition>,
) -> rusqlite::Result<()> {
    if let Some(condition) = condition {
        tx.execute(
            "INSERT INTO remote_record_conditions \
             (credential_id, incarnation, reason, since_ms, action_url) VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT(credential_id) DO UPDATE SET incarnation = excluded.incarnation, \
             reason = excluded.reason, since_ms = excluded.since_ms, action_url = excluded.action_url",
            rusqlite::params![id, incarnation, condition.reason, condition.since_ms, condition.action_url],
        )?;
    } else if read_schema_version(tx)? >= CONDITION_SCHEMA_VERSION {
        tx.execute(
            "DELETE FROM remote_record_conditions WHERE credential_id = ?1",
            [id],
        )?;
    }
    Ok(())
}

/// Read the condition for a row already identified by inventory, without a write
/// lease or migration. Both record tables may be absent on an older store.
pub fn condition_read_only(
    store_path: &std::path::Path,
    id: &str,
    incarnation: &str,
) -> Result<Option<Condition>, StoreOpError> {
    let map = |e: rusqlite::Error| StoreOpError::from(StoreError::Backend(e.to_string()));
    let conn =
        rusqlite::Connection::open_with_flags(store_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(map)?;
    match condition_in_incarnation(&conn, id, incarnation, Location::Local).map_err(map)? {
        Some(condition) => Ok(Some(condition)),
        None => condition_in_incarnation(&conn, id, incarnation, Location::Remote).map_err(map),
    }
}

pub(super) fn delete_local_condition_tx(
    tx: &rusqlite::Transaction<'_>,
    id: &str,
) -> rusqlite::Result<()> {
    if read_schema_version(tx)? >= CONDITION_SCHEMA_VERSION {
        tx.execute(
            "DELETE FROM credential_conditions WHERE credential_id = ?1",
            [id],
        )?;
    }
    Ok(())
}

impl EncryptedStore {
    pub fn credential_condition(
        &self,
        id: &str,
        incarnation: &str,
    ) -> Result<Option<Condition>, StoreOpError> {
        self.store
            .with_conn(|conn| local_condition_conn(conn, id, incarnation))
            .map_err(StoreOpError::from)
    }

    pub fn remote_record_condition(
        &self,
        id: &str,
        incarnation: &str,
    ) -> Result<Option<Condition>, StoreOpError> {
        self.store
            .with_conn(|conn| remote_condition_conn(conn, id, incarnation))
            .map_err(StoreOpError::from)
    }

    /// Apply a report to the lifetime admitted by the caller. `Ok(false)` means the
    /// report passed admission but the version did not match or nothing changed.
    pub fn report_condition_in_incarnation(
        &self,
        id: &str,
        expected_version: u64,
        incarnation: &str,
        report: ConditionReport<'_>,
        ctx: AuditCtx<'_>,
        principal: AuthEventPrincipal<'_>,
    ) -> Result<bool, StoreOpError> {
        self.fenced_write_or_refuse(|tx| {
            let row: Option<(u64, String, Vec<u8>)> = tx
                .query_row(
                    "SELECT record_version, state, envelope FROM credentials \
                     WHERE credential_id = ?1 AND incarnation = ?2",
                    rusqlite::params![id, incarnation],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((version, state, blob)) = row else {
                return Ok(Err(StoreOpError::NotFound));
            };
            // Do not use the serving path: a retired login can have a condition,
            // and an unopenable envelope is a refusal, not a quarantine request.
            let record = matches!(state.as_str(), "active" | "needs_reauth" | "retired")
                .then(|| envelope::open(&self.key, &blob, &RecordBinding {
                    credential_id: id,
                    record_version: version,
                }).ok())
                .flatten()
                .and_then(|plain| VaultRecord::decode(&plain).ok());
            let adapter = record.as_ref()
                .filter(|record| record.kind == CredentialKind::Oauth)
                .and_then(|record| record.refresh_adapter.as_deref());
            if let Err(refusal) = check_condition_report(adapter, report.reason, report.provider_status, report.action_url) {
                return Ok(Err(refusal));
            }

            let mut applied = false;
            if version == expected_version {
                // The parent was read once above. Ignore any child from a different lifetime.
                let previous = tx.query_row(
                    "SELECT reason, since_ms, action_url FROM credential_conditions \
                     WHERE credential_id = ?1 AND incarnation = ?2",
                    rusqlite::params![id, incarnation], condition_from_row,
                ).optional()?;
                let same_reason = previous.filter(|condition| condition.reason == report.reason);
                if !same_reason.as_ref().is_some_and(|condition| condition.action_url.as_deref() == report.action_url) {
                    let since = same_reason.map_or_else(|| now_ms() as u64, |condition| condition.since_ms);
                    tx.execute(
                        "INSERT INTO credential_conditions (credential_id, incarnation, reason, since_ms, reporter, action_url) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(credential_id) DO UPDATE SET \
                         incarnation = excluded.incarnation, reason = excluded.reason, since_ms = excluded.since_ms, \
                         reporter = excluded.reporter, action_url = excluded.action_url",
                        rusqlite::params![id, incarnation, report.reason, since, ctx.actor, report.action_url],
                    )?;
                    applied = true;
                    self.audit_condition(tx, id, AuditOp::ReportCondition, ctx)?;
                }
            }
            condition_event_tx(tx, id, AuthEventKind::ConsumerReportCondition, expected_version, applied, Some(report.provider_status), principal)?;
            Ok(Ok(applied))
        })
    }

    /// Clear a condition only on the admitted local row and reported version.
    pub fn clear_condition_in_incarnation(
        &self,
        id: &str,
        expected_version: u64,
        incarnation: &str,
        ctx: AuditCtx<'_>,
        principal: AuthEventPrincipal<'_>,
    ) -> Result<bool, StoreOpError> {
        self.fenced_write_or_refuse(|tx| {
            let version: Option<u64> = tx.query_row(
                "SELECT record_version FROM credentials WHERE credential_id = ?1 AND incarnation = ?2",
                rusqlite::params![id, incarnation], |row| row.get(0),
            ).optional()?;
            let Some(version) = version else {
                return Ok(Err(StoreOpError::NotFound));
            };
            let applied = version == expected_version && self.clear_current_condition_tx(tx, id, incarnation, ctx)?;
            condition_event_tx(tx, id, AuthEventKind::ConsumerClearCondition, expected_version, applied, None, principal)?;
            Ok(Ok(applied))
        })
    }

    /// Clear a local condition on the operator's behalf, without a consumer diagnostic.
    pub fn clear_condition_audited(
        &self,
        id: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<bool, StoreOpError> {
        self.fenced_write_or_refuse(|tx| {
            let incarnation: Option<String> = tx
                .query_row(
                    "SELECT incarnation FROM credentials WHERE credential_id = ?1",
                    [id],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(incarnation) = incarnation else {
                let remote = read_schema_version(tx)? >= FEDERATION_SCHEMA_VERSION
                    && tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM remote_records WHERE credential_id = ?1)",
                        [id],
                        |row| row.get(0),
                    )?;
                return Ok(Err(if remote {
                    StoreOpError::ConditionHomeOwned
                } else {
                    StoreOpError::NotFound
                }));
            };
            Ok(Ok(self.clear_current_condition_tx(
                tx,
                id,
                &incarnation,
                ctx,
            )?))
        })
    }

    fn clear_current_condition_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        id: &str,
        incarnation: &str,
        ctx: AuditCtx<'_>,
    ) -> rusqlite::Result<bool> {
        let applied = read_schema_version(tx)? >= CONDITION_SCHEMA_VERSION
            && tx.execute(
                "DELETE FROM credential_conditions WHERE credential_id = ?1 AND incarnation = ?2",
                rusqlite::params![id, incarnation],
            )? > 0;
        if applied {
            self.audit_condition(tx, id, AuditOp::ClearCondition, ctx)?;
        }
        Ok(applied)
    }

    fn audit_condition(
        &self,
        tx: &rusqlite::Transaction<'_>,
        id: &str,
        op: AuditOp,
        ctx: AuditCtx<'_>,
    ) -> rusqlite::Result<()> {
        append_audit_tx(
            tx,
            &self.audit_key,
            &AuditRecord {
                op,
                credential_id: Some(id.to_owned()),
                actor: ctx.actor.to_owned(),
                payload_hash: None,
                alarm: ctx.alarm,
            },
        )?;
        Ok(())
    }
}

fn condition_event_tx(
    tx: &rusqlite::Transaction<'_>,
    id: &str,
    kind: AuthEventKind,
    expected_version: u64,
    applied: bool,
    provider_status: Option<u16>,
    principal: AuthEventPrincipal<'_>,
) -> rusqlite::Result<()> {
    append_auth_event_tx(
        tx,
        id,
        &AuthObservation {
            kind: kind.as_str(),
            provider_status,
            detail: None,
            reporter_source: None,
            principal: Some(principal),
        },
        Some(expected_version),
        applied,
    )
}
