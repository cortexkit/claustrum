//! The durable side of hub login publication, member application and report ordering.
use super::{
    EncryptedStore, GhManifestActivationOutcome, GhManifestActivationReport, GhManifestVerdict,
    StoreOpError,
};
use crate::audit::AuditCtx;
use crate::federation::{check_member_id, is_lower_hex_16_bytes, SELF_MEMBER_SETTING};
use crate::hub_counters::{HubGeneration, HubReportSeq};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubLoginKind {
    Snapshot,
    Ended,
}

impl HubLoginKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Ended => "ended",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct HubLoginTarget {
    pub member_id: String,
    pub box_id: String,
    pub transfer_public_key: [u8; 32],
    pub pairing_id: String,
    pub generation: HubGeneration,
    pub kind: HubLoginKind,
    pub sealed_bytes: Option<Vec<u8>>,
    pub stale: bool,
    pub delivered: bool,
}

pub struct HubLoginRecipient<'a> {
    pub member_id: &'a str,
    pub box_id: &'a str,
    pub transfer_public_key: &'a [u8; 32],
    pub pairing_id: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubLoginHomeState {
    pub home_member: String,
    pub generation: HubGeneration,
    /// None after unpair or re-pair; the generation is still authoritative.
    pub pairing_id: Option<String>,
    pub skipped_ids: Vec<String>,
    pub reapply: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct HubOwnReport {
    pub version: i64,
    pub payload_sha256: String,
    pub verdict: GhManifestVerdict,
    pub reason: Option<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct HubReportTaskState {
    pub seq: HubReportSeq,
    pub signed_bytes: Vec<u8>,
    pub sent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubManifestHighWater {
    pub member_id: String,
    pub box_id: String,
    pub pairing_id: String,
    pub seq: HubReportSeq,
}

fn generation(row: &Row<'_>, column: usize) -> rusqlite::Result<HubGeneration> {
    let value = row.get(column)?;
    HubGeneration::new(value).ok_or(rusqlite::Error::IntegralValueOutOfRange(column, value))
}

fn report_seq(row: &Row<'_>, column: usize) -> rusqlite::Result<HubReportSeq> {
    let value = row.get(column)?;
    HubReportSeq::new(value).ok_or(rusqlite::Error::IntegralValueOutOfRange(column, value))
}

const HOME_STATE_SELECT: &str =
    "SELECT home_member, generation, pairing_id, skipped_ids_json, reapply FROM hub_login_homes";

fn home_state_from_row(row: &Row<'_>) -> rusqlite::Result<HubLoginHomeState> {
    let skipped: String = row.get(3)?;
    let skipped_ids = serde_json::from_str(&skipped).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(HubLoginHomeState {
        home_member: row.get(0)?,
        generation: generation(row, 1)?,
        pairing_id: row.get(2)?,
        skipped_ids,
        reapply: row.get(4)?,
    })
}

pub(super) fn hub_login_home_state_conn(
    conn: &Connection,
    home_member: &str,
) -> rusqlite::Result<Option<HubLoginHomeState>> {
    conn.query_row(
        &format!("{HOME_STATE_SELECT} WHERE home_member = ?1"),
        [home_member],
        home_state_from_row,
    )
    .optional()
}

fn own_report_conn(conn: &Connection) -> rusqlite::Result<Option<HubOwnReport>> {
    conn.query_row(
        "SELECT version, payload_sha256, verdict, reason FROM hub_own_report WHERE singleton = 1",
        [],
        |row| {
            let verdict = match row.get::<_, String>(2)?.as_str() {
                "valid" => GhManifestVerdict::Valid,
                "invalid" => GhManifestVerdict::Invalid,
                _ => return Err(rusqlite::Error::InvalidQuery),
            };
            Ok(HubOwnReport {
                version: row.get(0)?,
                payload_sha256: row.get(1)?,
                verdict,
                reason: row.get(3)?,
            })
        },
    )
    .optional()
}

const CLEAR_MANIFEST_FIELDS: &str = "UPDATE gh_manifest_activations SET version = NULL, \
    payload_sha256 = NULL, verdict = NULL, reason = NULL, reported_at_ms = NULL, report_box_id = NULL";

fn collector_is_home(conn: &Connection) -> rusqlite::Result<bool> {
    let setting = super::federation_store::read_setting(conn, super::SECRET_HOME_SETTING)?;
    // Home is the symbolic `self` setting, whether or not the self ID is set.
    match super::resolve_secret_home_role(setting.as_deref(), None) {
        super::SecretHomeRole::Home { .. } => Ok(true),
        super::SecretHomeRole::StoreError => Err(rusqlite::Error::InvalidQuery),
        _ => Ok(false),
    }
}

pub(super) fn clear_hub_manifest_report_tx(
    tx: &Transaction<'_>,
    member_id: &str,
) -> rusqlite::Result<bool> {
    Ok(tx.execute(
        &format!(
            "{CLEAR_MANIFEST_FIELDS} WHERE member_id = ?1 AND version IS NOT NULL \
        AND NOT EXISTS (SELECT 1 FROM settings WHERE name = ?2 AND value = ?1)"
        ),
        params![member_id, SELF_MEMBER_SETTING],
    )? != 0)
}

pub(super) fn end_hub_manifest_membership_tx(
    tx: &Transaction<'_>,
    member_id: &str,
) -> rusqlite::Result<bool> {
    let cleared = clear_hub_manifest_report_tx(tx, member_id)?;
    let forgotten = tx.execute(
        "DELETE FROM hub_manifest_high_water WHERE member_id = ?1",
        [member_id],
    )? != 0;
    Ok(cleared || forgotten)
}

pub(super) fn reset_hub_manifest_pairing_tx(
    tx: &Transaction<'_>,
    member_id: &str,
    current_pairing: &str,
) -> rusqlite::Result<bool> {
    let changed = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM hub_manifest_high_water WHERE member_id = ?1 AND pairing_id != ?2)",
        params![member_id, current_pairing], |row| row.get::<_, bool>(0),
    )?;
    if changed {
        end_hub_manifest_membership_tx(tx, member_id)?;
    }
    Ok(changed)
}

impl EncryptedStore {
    pub fn list_hub_login_targets(&self) -> Result<Vec<HubLoginTarget>, StoreOpError> {
        Ok(self.store.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT member_id, box_id, transfer_public_key, pairing_id, \
                generation, kind, sealed_bytes, stale, delivered FROM hub_login_targets ORDER BY member_id")?;
            let rows = stmt.query_map([], |row| {
                let kind = match row.get::<_, String>(5)?.as_str() {
                    "snapshot" => HubLoginKind::Snapshot,
                    "ended" => HubLoginKind::Ended,
                    _ => return Err(rusqlite::Error::InvalidQuery),
                };
                Ok(HubLoginTarget {
                    member_id: row.get(0)?, box_id: row.get(1)?, transfer_public_key: row.get(2)?,
                    pairing_id: row.get(3)?, generation: generation(row, 4)?, kind,
                    sealed_bytes: row.get(6)?, stale: row.get(7)?, delivered: row.get(8)?,
                })
            })?.collect();
            rows
        })?)
    }

    /// Build bytes for the next generation and commit them together. `seal` must
    /// not access the store or the network; it runs inside the write transaction.
    pub fn commit_hub_login_target(
        &self,
        recipient: &HubLoginRecipient<'_>,
        kind: HubLoginKind,
        seal: impl FnOnce(HubGeneration) -> Result<Vec<u8>, StoreOpError>,
    ) -> Result<HubGeneration, StoreOpError> {
        self.commit_hub_login_target_above(recipient, kind, None, seal)
    }

    /// As [`Self::commit_hub_login_target`], with the next generation also above
    /// `floor`: the highest generation this home is known to have published, for
    /// example one found on the hub after the local row was restored from a backup.
    pub fn commit_hub_login_target_above(
        &self,
        recipient: &HubLoginRecipient<'_>,
        kind: HubLoginKind,
        floor: Option<HubGeneration>,
        seal: impl FnOnce(HubGeneration) -> Result<Vec<u8>, StoreOpError>,
    ) -> Result<HubGeneration, StoreOpError> {
        check_member_id(recipient.member_id)?;
        super::federation_store::check_pairing_id(recipient.pairing_id)?;
        if !is_lower_hex_16_bytes(recipient.box_id) {
            return Err(StoreOpError::Encode("invalid hub box id".into()));
        }
        self.fenced_write_or_refuse(|tx| {
            let current = tx.query_row("SELECT generation FROM hub_login_targets WHERE member_id = ?1",
                [recipient.member_id], |row| generation(row, 0)).optional()?;
            let current = current.max(floor);
            let Some(next) = current.map_or(Some(HubGeneration::FIRST), HubGeneration::checked_next) else {
                return Ok(Err(StoreOpError::Encode("hub login generation exhausted".into())));
            };
            let bytes = match seal(next) {
                Ok(bytes) => bytes,
                Err(error) => return Ok(Err(error)),
            };
            tx.execute("INSERT INTO hub_login_targets \
                (member_id, box_id, transfer_public_key, pairing_id, generation, kind, sealed_bytes, stale, delivered) \
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 0) ON CONFLICT(member_id) DO UPDATE SET \
                box_id = excluded.box_id, transfer_public_key = excluded.transfer_public_key, \
                pairing_id = excluded.pairing_id, generation = excluded.generation, kind = excluded.kind, \
                sealed_bytes = excluded.sealed_bytes, stale = 0, delivered = 0",
                params![recipient.member_id, recipient.box_id, recipient.transfer_public_key, recipient.pairing_id,
                    next.get(), kind.as_str(), bytes])?;
            Ok(Ok(next))
        })
    }

    pub fn mark_hub_login_target_stale(
        &self,
        member_id: &str,
        generation: HubGeneration,
    ) -> Result<bool, StoreOpError> {
        Ok(self.fenced_write(|tx| {
            Ok(tx.execute(
                "UPDATE hub_login_targets SET stale = 1 \
            WHERE member_id = ?1 AND generation = ?2 AND stale = 0",
                params![member_id, generation.get()],
            )? != 0)
        })?)
    }

    /// Losing ownership of a box discards its bytes but never resets the counter.
    pub fn discard_hub_login_target_bytes(
        &self,
        member_id: &str,
        generation: HubGeneration,
    ) -> Result<bool, StoreOpError> {
        Ok(self.fenced_write(|tx| {
            Ok(tx.execute(
                "UPDATE hub_login_targets SET sealed_bytes = NULL, stale = 1, delivered = 0 \
            WHERE member_id = ?1 AND generation = ?2 AND sealed_bytes IS NOT NULL",
                params![member_id, generation.get()],
            )? != 0)
        })?)
    }

    pub fn mark_hub_login_target_delivered(
        &self,
        member_id: &str,
        generation: HubGeneration,
        bytes: &[u8],
    ) -> Result<bool, StoreOpError> {
        Ok(self.fenced_write(|tx| {
            Ok(tx.execute(
                "UPDATE hub_login_targets SET delivered = 1 WHERE member_id = ?1 \
            AND generation = ?2 AND sealed_bytes = ?3 AND stale = 0 AND delivered = 0",
                params![member_id, generation.get(), bytes],
            )? != 0)
        })?)
    }

    pub fn hub_login_home_state(
        &self,
        home_member: &str,
    ) -> Result<Option<HubLoginHomeState>, StoreOpError> {
        Ok(self
            .store
            .with_conn(|conn| hub_login_home_state_conn(conn, home_member))?)
    }

    pub fn list_hub_login_homes(&self) -> Result<Vec<HubLoginHomeState>, StoreOpError> {
        Ok(self.store.with_conn(|conn| {
            let mut stmt = conn.prepare(&format!("{HOME_STATE_SELECT} ORDER BY home_member"))?;
            let rows = stmt.query_map([], home_state_from_row)?.collect();
            rows
        })?)
    }

    /// Record a local report and its activation slot together. The setting is
    /// checked in the same transaction so the local path can never set a peer slot.
    pub fn record_hub_own_report(
        &self,
        report: &GhManifestActivationReport<'_>,
        ctx: AuditCtx<'_>,
    ) -> Result<GhManifestActivationOutcome, StoreOpError> {
        self.fenced_write_or_refuse(|tx| {
            if report.member_id.is_empty() || super::federation_store::read_setting(tx, SELF_MEMBER_SETTING)?.as_deref() != Some(report.member_id) {
                return Ok(Err(StoreOpError::NotFound));
            }
            let outcome = self.report_gh_manifest_active_tx(tx, report, ctx)?;
            // Counted before the commit wakes the reporter. An explicit report, even
            // one identical to the last, asks it for a fresh signed value with a higher
            // sequence: a Home that cleared its copy (a revoked and restored grant)
            // accepts only a newer one. A rolled-back commit only costs a spare signature.
            self.own_report_records.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tx.execute("UPDATE gh_manifest_activations SET report_box_id = NULL WHERE member_id = ?1", [report.member_id])?;
            tx.execute("INSERT INTO hub_own_report (singleton, version, payload_sha256, verdict, reason) \
                VALUES (1, ?1, ?2, ?3, ?4) ON CONFLICT(singleton) DO UPDATE SET version = excluded.version, \
                payload_sha256 = excluded.payload_sha256, verdict = excluded.verdict, reason = excluded.reason",
                params![report.version, report.payload_sha256, report.verdict.as_str(), report.reason])?;
            Ok(Ok(outcome))
        })
    }

    /// How many local reports this process has recorded, identical ones included.
    pub fn hub_own_report_records(&self) -> u64 {
        self.own_report_records.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn hub_own_report(&self) -> Result<Option<HubOwnReport>, StoreOpError> {
        Ok(self.store.with_conn(own_report_conn)?)
    }

    pub fn hub_report_task_state(&self) -> Result<Option<HubReportTaskState>, StoreOpError> {
        Ok(self.store.with_conn(|conn| {
            conn.query_row(
                "SELECT seq, signed_bytes, sent FROM hub_report_task WHERE singleton = 1",
                [],
                |row| {
                    Ok(HubReportTaskState {
                        seq: report_seq(row, 0)?,
                        signed_bytes: row.get(1)?,
                        sent: row.get(2)?,
                    })
                },
            )
            .optional()
        })?)
    }

    /// Sign only if the publisher's report is still current. `sign` must not access
    /// the store or network; it runs inside the transaction that persists the bytes.
    pub fn commit_hub_report_bytes(
        &self,
        expected: &HubOwnReport,
        sign: impl FnOnce(HubReportSeq) -> Result<Vec<u8>, StoreOpError>,
    ) -> Result<Option<HubReportSeq>, StoreOpError> {
        self.commit_hub_report_bytes_above(expected, None, sign)
    }

    /// As [`Self::commit_hub_report_bytes`], with the next sequence also above
    /// `floor`: the highest sequence this vault is known to have published, for
    /// example one found on the hub after the local row was restored from a backup.
    pub fn commit_hub_report_bytes_above(
        &self,
        expected: &HubOwnReport,
        floor: Option<HubReportSeq>,
        sign: impl FnOnce(HubReportSeq) -> Result<Vec<u8>, StoreOpError>,
    ) -> Result<Option<HubReportSeq>, StoreOpError> {
        self.fenced_write_or_refuse(|tx| {
            if own_report_conn(tx)?.as_ref() != Some(expected) {
                return Ok(Ok(None));
            }
            let current = tx.query_row("SELECT seq FROM hub_report_task WHERE singleton = 1", [], |row| report_seq(row, 0)).optional()?;
            let current = current.max(floor);
            let Some(next) = current.map_or(Some(HubReportSeq::FIRST), HubReportSeq::checked_next) else {
                return Ok(Err(StoreOpError::Encode("hub manifest report seq exhausted".into())));
            };
            let bytes = match sign(next) {
                Ok(bytes) => bytes,
                Err(error) => return Ok(Err(error)),
            };
            tx.execute("INSERT INTO hub_report_task (singleton, seq, signed_bytes, sent) VALUES (1, ?1, ?2, 0) \
                ON CONFLICT(singleton) DO UPDATE SET seq = excluded.seq, signed_bytes = excluded.signed_bytes, sent = 0",
                params![next.get(), bytes])?;
            Ok(Ok(Some(next)))
        })
    }

    /// Mark the exact version about to be sent, unless a newer local report has
    /// committed. True also allows a retry after a lost acknowledgement.
    pub fn mark_hub_report_sent(
        &self,
        expected: &HubOwnReport,
        seq: HubReportSeq,
        bytes: &[u8],
    ) -> Result<bool, StoreOpError> {
        Ok(self.fenced_write(|tx| {
            if own_report_conn(tx)?.as_ref() != Some(expected) {
                return Ok(false);
            }
            Ok(tx.execute(
                "UPDATE hub_report_task SET sent = 1 \
            WHERE singleton = 1 AND seq = ?1 AND signed_bytes = ?2",
                params![seq.get(), bytes],
            )? != 0)
        })?)
    }

    /// The collector holds its paired-device binding stable across this transaction.
    /// `still_current` rechecks the binding and that the same Home collector is still
    /// running after the store fence is acquired. It must not access the store or network.
    pub fn record_hub_manifest_report(
        &self,
        report: &GhManifestActivationReport<'_>,
        box_id: &str,
        pairing_id: &str,
        seq: HubReportSeq,
        still_current: impl FnOnce() -> bool,
        ctx: AuditCtx<'_>,
    ) -> Result<Option<GhManifestActivationOutcome>, StoreOpError> {
        check_member_id(report.member_id)?;
        super::federation_store::check_pairing_id(pairing_id)?;
        if !is_lower_hex_16_bytes(box_id) {
            return Err(StoreOpError::Encode("invalid hub box id".into()));
        }
        Ok(self.fenced_write(|tx| {
            if !collector_is_home(tx)? || !still_current() {
                return Ok(None);
            }
            let admitted = tx.query_row("SELECT EXISTS (SELECT 1 FROM member_grants \
                WHERE member_id = ?1 AND operation = 'secret_use' AND pairing_id = ?2) \
                AND NOT EXISTS (SELECT 1 FROM gh_manifest_activations WHERE member_id = ?1 AND retired_at_ms IS NOT NULL) \
                AND NOT EXISTS (SELECT 1 FROM settings WHERE name = ?3 AND value = ?1)",
                params![report.member_id, pairing_id, SELF_MEMBER_SETTING], |row| row.get::<_, bool>(0))?;
            reset_hub_manifest_pairing_tx(tx, report.member_id, pairing_id)?;
            if !admitted {
                return Ok(None);
            }
            let advanced = tx.execute("INSERT INTO hub_manifest_high_water (member_id, box_id, pairing_id, seq) \
                VALUES (?1, ?2, ?3, ?4) ON CONFLICT(member_id, box_id) DO UPDATE SET seq = excluded.seq \
                WHERE hub_manifest_high_water.seq < excluded.seq", params![report.member_id, box_id, pairing_id, seq.get()])? != 0;
            if !advanced {
                return Ok(None);
            }
            let outcome = self.report_gh_manifest_active_tx(tx, report, ctx)?;
            tx.execute("UPDATE gh_manifest_activations SET report_box_id = ?1 WHERE member_id = ?2",
                params![box_id, report.member_id])?;
            Ok(Some(outcome))
        })?)
    }

    pub fn list_hub_manifest_high_waters(&self) -> Result<Vec<HubManifestHighWater>, StoreOpError> {
        Ok(self.store.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT member_id, box_id, pairing_id, seq \
                FROM hub_manifest_high_water ORDER BY member_id, box_id",
            )?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(HubManifestHighWater {
                        member_id: row.get(0)?,
                        box_id: row.get(1)?,
                        pairing_id: row.get(2)?,
                        seq: report_seq(row, 3)?,
                    })
                })?
                .collect();
            rows
        })?)
    }

    pub fn clear_hub_manifest_report(&self, member_id: &str) -> Result<bool, StoreOpError> {
        Ok(self.fenced_write(|tx| clear_hub_manifest_report_tx(tx, member_id))?)
    }

    /// Clear a hub-derived slot only if the collector's binding is still current.
    /// If `keep_box` is set, a report already accepted from that box stays recorded.
    pub fn reconcile_hub_manifest_box(
        &self,
        member_id: &str,
        keep_box: Option<&str>,
        still_current: impl FnOnce() -> bool,
    ) -> Result<(), StoreOpError> {
        self.fenced_write(|tx| {
            if !collector_is_home(tx)? || !still_current() {
                return Ok(());
            }
            tx.execute(
                &format!(
                    "{CLEAR_MANIFEST_FIELDS} WHERE member_id = ?1 AND version IS NOT NULL
                    AND (?2 IS NULL OR report_box_id IS NOT ?2)
                    AND NOT EXISTS (SELECT 1 FROM settings WHERE name = ?3 AND value = ?1)"
                ),
                params![member_id, keep_box, SELF_MEMBER_SETTING],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    /// When the hub recreates the report bucket, clear peer fields before reading the
    /// new contents. Keep the expected members and their last accepted sequences.
    pub fn clear_peer_hub_manifest_reports(&self) -> Result<usize, StoreOpError> {
        Ok(self.fenced_write(|tx| {
            if !collector_is_home(tx)? {
                return Ok(0);
            }
            tx.execute(
                &format!(
                    "{CLEAR_MANIFEST_FIELDS} WHERE version IS NOT NULL \
            AND NOT EXISTS (SELECT 1 FROM settings WHERE name = ?1 AND value = member_id)"
                ),
                [SELF_MEMBER_SETTING],
            )
        })?)
    }

    /// Clear fields that local facts alone rule out, even before Callosum is ready.
    pub fn clear_ungranted_hub_manifest_reports(&self) -> Result<usize, StoreOpError> {
        Ok(self.fenced_write(|tx| {
            if !collector_is_home(tx)? {
                return Ok(0);
            }
            tx.execute(&format!("{CLEAR_MANIFEST_FIELDS} WHERE version IS NOT NULL \
            AND NOT EXISTS (SELECT 1 FROM settings WHERE name = ?1 AND value = member_id) \
            AND (retired_at_ms IS NOT NULL OR NOT EXISTS (SELECT 1 FROM member_grants AS g \
                WHERE g.member_id = gh_manifest_activations.member_id AND g.operation = 'secret_use'))"), [SELF_MEMBER_SETTING])
        })?)
    }

    /// On unpair, drop all high-waters; on re-pair, do so only if they belonged to
    /// a different pairing. Losing a grant or changing boxes does not call this.
    pub fn reconcile_hub_manifest_pairing(
        &self,
        member_id: &str,
        pairing_id: Option<&str>,
        still_current: impl FnOnce() -> bool,
    ) -> Result<bool, StoreOpError> {
        Ok(self.fenced_write(|tx| {
            if !collector_is_home(tx)? || !still_current() {
                return Ok(false);
            }
            match pairing_id {
                Some(current) => reset_hub_manifest_pairing_tx(tx, member_id, current),
                None => end_hub_manifest_membership_tx(tx, member_id),
            }
        })?)
    }
}

#[cfg(test)]
#[path = "store_hub_entry_tests.rs"]
mod tests;
