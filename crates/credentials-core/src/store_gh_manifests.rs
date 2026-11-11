use super::{append_audit_tx, EncryptedStore, StoreOpError};
use crate::audit::{AuditCtx, GhManifestAudit};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GhManifestSource {
    Import,
    Ceremony,
    OneTap,
}

impl GhManifestSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Ceremony => "ceremony",
            Self::OneTap => "one_tap",
        }
    }
}

/// A verified signed version. Callers verify the signature, manifest version and
/// reproducibility before storing; this layer enforces monotonic, atomic storage.
pub struct GhManifestVersion<'a> {
    pub version: i64,
    pub manifest_bytes: &'a [u8],
    pub manifest_sha256: &'a str,
    pub key_id: &'a str,
    pub signature: &'a [u8; 64],
    pub signed_at_ms: i64,
    pub source: GhManifestSource,
    pub approval_audit_seq: Option<i64>,
}

impl EncryptedStore {
    /// Store an already verified version, its audit row and all older pending
    /// proposals' supersede transitions in one transaction under the writer lease.
    pub fn store_gh_manifest(
        &self,
        version: &GhManifestVersion<'_>,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        self.fenced_write(|tx| self.store_gh_manifest_in_tx(tx, version, ctx))?;
        Ok(())
    }

    /// Phone approval and operator signing use their existing write transaction so a
    /// signature, approval and stored version can never commit independently.
    pub(crate) fn store_gh_manifest_in_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        version: &GhManifestVersion<'_>,
        ctx: AuditCtx<'_>,
    ) -> rusqlite::Result<()> {
        tx.execute(
            "INSERT INTO gh_manifests \
             (version, manifest_bytes, manifest_sha256, key_id, signature, signed_at_ms, source, approval_audit_seq) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                version.version,
                version.manifest_bytes,
                version.manifest_sha256,
                version.key_id,
                version.signature.as_slice(),
                version.signed_at_ms,
                version.source.as_str(),
                version.approval_audit_seq,
            ],
        )?;
        append_audit_tx(
            tx,
            &self.audit_key,
            &GhManifestAudit::Store {
                version: version.version,
                source: version.source.as_str(),
                manifest_sha256: version.manifest_sha256,
            }
            .record(ctx.actor, ctx.alarm),
        )?;

        let proposals = tx
            .prepare(
                "SELECT proposal_id FROM gh_manifest_proposals \
                 WHERE state = 'pending' AND base_version < ?1 ORDER BY proposal_id",
            )?
            .query_map([version.version], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for proposal_id in proposals {
            tx.execute(
                "UPDATE gh_manifest_proposals SET state = 'superseded' WHERE proposal_id = ?1",
                [&proposal_id],
            )?;
            append_audit_tx(
                tx,
                &self.audit_key,
                &GhManifestAudit::ProposalState {
                    proposal_id: &proposal_id,
                    from: "pending",
                    to: "superseded",
                }
                .record(ctx.actor, ctx.alarm),
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "store_gh_manifest_tests.rs"]
mod tests;
