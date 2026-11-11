use super::{append_audit_tx, EncryptedStore, StoreOpError};
use crate::audit::{AuditCtx, GhManifestAudit};
use base64::Engine;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GhManifestVerdict {
    Valid,
    Invalid,
}

impl GhManifestVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
        }
    }
}

/// The caller derives member_id from the authenticated route, never from params.
/// Report grammar is validated by the transport before reaching the store.
pub struct GhManifestActivationReport<'a> {
    pub member_id: &'a str,
    pub version: i64,
    pub payload_sha256: &'a str,
    pub verdict: GhManifestVerdict,
    pub reason: Option<&'a str>,
    pub reported_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GhManifestLowerVersionReported {
    pub reported: i64,
    pub active: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GhManifestActivationOutcome {
    /// The module logs a warning from these versions after the report commits.
    /// Logging stays in the module, where output sites are checked for secrets.
    pub lower_version_reported: Option<GhManifestLowerVersionReported>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GhManifestComputerStatus {
    pub member_id: String,
    pub version: Option<i64>,
    pub payload_sha256: Option<String>,
    pub verdict: Option<GhManifestVerdict>,
    pub reason: Option<String>,
    pub reported_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GhManifestActiveStatus {
    pub version: i64,
    pub manifest_sha256: String,
    pub ready: bool,
    pub computers: Vec<GhManifestComputerStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GhManifestHandoffEnvelope {
    pub key_id: String,
    pub manifest_bytes: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GhManifestLatest {
    pub version: i64,
    pub envelope: GhManifestHandoffEnvelope,
}

impl EncryptedStore {
    /// Replace the last report even for retired members. Only the first report of
    /// each stored (member, version, verdict) tuple appends an activation audit.
    pub fn report_gh_manifest_active(
        &self,
        report: &GhManifestActivationReport<'_>,
        ctx: AuditCtx<'_>,
    ) -> Result<GhManifestActivationOutcome, StoreOpError> {
        Ok(self.fenced_write(|tx| {
            let active: Option<i64> = tx
                .query_row(
                    "SELECT version FROM gh_manifest_activations WHERE member_id = ?1",
                    [report.member_id],
                    |row| row.get(0),
                )
                .optional()?
                .flatten();
            let lower_version_reported =
                active
                    .filter(|active| report.version < *active)
                    .map(|active| GhManifestLowerVersionReported {
                        reported: report.version,
                        active,
                    });
            tx.execute(
                "INSERT INTO gh_manifest_activations \
                 (member_id, version, payload_sha256, verdict, reason, reported_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(member_id) DO UPDATE SET version = excluded.version, \
                 payload_sha256 = excluded.payload_sha256, verdict = excluded.verdict, \
                 reason = excluded.reason, reported_at_ms = excluded.reported_at_ms",
                params![
                    report.member_id,
                    report.version,
                    report.payload_sha256,
                    report.verdict.as_str(),
                    report.reason,
                    report.reported_at_ms
                ],
            )?;
            let inserted = tx.execute(
                "INSERT INTO gh_manifest_activation_audits (member_id, version, verdict) \
                 SELECT ?1, ?2, ?3 WHERE EXISTS (SELECT 1 FROM gh_manifests WHERE version = ?2) \
                 ON CONFLICT(member_id, version, verdict) DO NOTHING",
                params![report.member_id, report.version, report.verdict.as_str()],
            )?;
            if inserted != 0 {
                append_audit_tx(
                    tx,
                    &self.audit_key,
                    &GhManifestAudit::Activation {
                        member_id: report.member_id,
                        version: report.version,
                        verdict: report.verdict.as_str(),
                    }
                    .record(ctx.actor, ctx.alarm),
                )?;
            }
            Ok(GhManifestActivationOutcome {
                lower_version_reported,
            })
        })?)
    }

    /// Retirement removes a member from readiness, not delivery. Reports leave
    /// this timestamp untouched, including when retirement preceded any report.
    pub fn retire_gh_manifest_member(
        &self,
        member_id: &str,
        retired_at_ms: i64,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        self.fenced_write(|tx| {
            tx.execute(
                "INSERT INTO gh_manifest_activations (member_id, retired_at_ms) VALUES (?1, ?2) \
                 ON CONFLICT(member_id) DO UPDATE SET retired_at_ms = excluded.retired_at_ms",
                params![member_id, retired_at_ms],
            )?;
            append_audit_tx(
                tx,
                &self.audit_key,
                &GhManifestAudit::Retire {
                    member_id,
                    retired_at_ms,
                }
                .record(ctx.actor, ctx.alarm),
            )?;
            Ok(())
        })?;
        Ok(())
    }

    /// None means unknown_version. Read the stored hash and population in one
    /// snapshot so a concurrent report, grant or retirement cannot split the view.
    pub fn gh_manifest_active_status(
        &self,
        version: i64,
    ) -> Result<Option<GhManifestActiveStatus>, StoreOpError> {
        self.store.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            let manifest_sha256: Option<String> = tx.query_row(
                "SELECT manifest_sha256 FROM gh_manifests WHERE version = ?1",
                [version], |row| row.get(0),
            ).optional()?;
            let Some(manifest_sha256) = manifest_sha256 else { return Ok(None); };
            let computers = tx.prepare(
                "SELECT expected.member_id, a.version, a.payload_sha256, a.verdict, a.reason, a.reported_at_ms \
                 FROM (SELECT value AS member_id FROM settings WHERE name = ?1 AND value != '' \
                       UNION SELECT member_id FROM member_grants WHERE operation = 'secret_use' \
                       UNION SELECT member_id FROM gh_manifest_activations) AS expected \
                 LEFT JOIN gh_manifest_activations AS a ON a.member_id = expected.member_id \
                 WHERE a.retired_at_ms IS NULL ORDER BY expected.member_id COLLATE BINARY",
            )?.query_map([crate::federation::SELF_MEMBER_SETTING], |row| {
                let verdict: Option<String> = row.get(3)?;
                let verdict = match verdict.as_deref() {
                    None => None,
                    Some("valid") => Some(GhManifestVerdict::Valid),
                    Some("invalid") => Some(GhManifestVerdict::Invalid),
                    Some(other) => return Err(rusqlite::Error::InvalidColumnType(
                        3, format!("unknown manifest verdict {other}"), rusqlite::types::Type::Text,
                    )),
                };
                Ok(GhManifestComputerStatus {
                    member_id: row.get(0)?, version: row.get(1)?, payload_sha256: row.get(2)?,
                    verdict, reason: row.get(4)?, reported_at_ms: row.get(5)?,
                })
            })?.collect::<rusqlite::Result<Vec<_>>>()?;
            let ready = !computers.is_empty() && computers.iter().all(|computer| {
                computer.version == Some(version)
                    && computer.payload_sha256.as_deref() == Some(manifest_sha256.as_str())
                    && computer.verdict == Some(GhManifestVerdict::Valid)
            });
            tx.commit()?;
            Ok(Some(GhManifestActiveStatus { version, manifest_sha256, ready, computers }))
        }).map_err(StoreOpError::from)
    }

    /// Return the retained bytes without reserializing the manifest. None means
    /// nothing has been stored; signatures use standard, padded base64.
    pub fn latest_gh_manifest(&self) -> Result<Option<GhManifestLatest>, StoreOpError> {
        let row = self.store.with_conn(|conn| conn.query_row(
            "SELECT version, key_id, manifest_bytes, signature FROM gh_manifests ORDER BY version DESC LIMIT 1",
            [], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?, row.get::<_, Vec<u8>>(3)?)),
        ).optional())?;
        row.map(|(version, key_id, bytes, signature)| {
            let manifest_bytes = String::from_utf8(bytes)
                .map_err(|_| StoreOpError::Corrupt("manifest is not UTF-8".into()))?;
            Ok(GhManifestLatest {
                version,
                envelope: GhManifestHandoffEnvelope {
                    key_id,
                    manifest_bytes,
                    signature: base64::engine::general_purpose::STANDARD.encode(signature),
                },
            })
        })
        .transpose()
    }
}

#[cfg(test)]
#[path = "store_gh_activation_tests.rs"]
mod tests;
