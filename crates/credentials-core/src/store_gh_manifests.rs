use super::{
    append_audit_tx, envelope, hex32, payload_hash, CredentialKind, EncryptedStore, RecordBinding,
    RecordState, StoreOpError, VaultRecord,
};
use crate::audit::{AuditCtx, GhManifestAudit};
use rusqlite::OptionalExtension;

/// The fleet's legacy root credential. Admin operations also use this id to take
/// the same lock before opening a transaction, regardless of the configured root.
pub const GH_MANIFEST_ROOT_KEY_ID: &str = "signing:gh-manifest-root:1";
pub(super) const POLICY_ROOT_CREDENTIAL_SETTING: &str = "policy_root_credential";

pub(super) fn is_policy_root_id(id: &str) -> bool {
    id == GH_MANIFEST_ROOT_KEY_ID || id.starts_with("signing:policy-root:")
}

pub(super) struct ManifestRoot {
    pub credential_id: String,
    pub record: VaultRecord,
}

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

pub(super) enum ManifestRootReadError {
    Sql(rusqlite::Error),
    Unusable(StoreOpError),
}

impl From<ManifestRootReadError> for StoreOpError {
    fn from(error: ManifestRootReadError) -> Self {
        match error {
            ManifestRootReadError::Sql(error) => Self::Store(error.to_string()),
            ManifestRootReadError::Unusable(error) => error,
        }
    }
}

impl EncryptedStore {
    /// Sign exact manifest bytes and append their plain SHA-256 commitment in the
    /// caller's fenced write transaction. Read the key here, not before taking the
    /// writer, so replacement cannot commit between key selection and the audit row.
    /// Callers must abort on error and publish the signature only after commit.
    pub fn sign_gh_manifest(
        &self,
        tx: &rusqlite::Transaction<'_>,
        manifest_bytes: &[u8],
        ctx: AuditCtx<'_>,
    ) -> Result<crate::signing::Signature, StoreOpError> {
        let sql_error = |e: rusqlite::Error| StoreOpError::Store(e.to_string());
        let root = self.gh_manifest_root_in_tx(tx)?;
        crate::signing::validate_signing_input(&root.credential_id, manifest_bytes)
            .map_err(|reason| StoreOpError::Encode(format!("invalid_params: {reason}")))?;
        let corrupt = || StoreOpError::Corrupt("unusable manifest signing key".into());
        let pem = std::str::from_utf8(root.record.payload.expose()).map_err(|_| corrupt())?;
        let prepared =
            crate::signing::prepare_ed25519(pem, manifest_bytes).map_err(|e| match e {
                crate::signing::SignError::TooLarge { .. } => StoreOpError::Encode(e.to_string()),
                crate::signing::SignError::UnusableKey(_) => corrupt(),
            })?;
        append_audit_tx(
            tx,
            &self.audit_key,
            &GhManifestAudit::Sign {
                credential_id: &root.credential_id,
                manifest_sha256: &hex32(&payload_hash(manifest_bytes)),
            }
            .record(ctx.actor, ctx.alarm),
        )
        .map_err(sql_error)?;
        Ok(prepared.sign())
    }

    // Import checks the same active root inside its writer transaction, but uses
    // only the public half and never calls the signer.
    pub(super) fn gh_manifest_root_in_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
    ) -> Result<ManifestRoot, StoreOpError> {
        self.read_gh_manifest_root_in_tx(tx).map_err(Into::into)
    }

    pub(super) fn read_gh_manifest_root_in_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
    ) -> Result<ManifestRoot, ManifestRootReadError> {
        use ManifestRootReadError::{Sql, Unusable};
        let not_found = || Unusable(StoreOpError::NotFound);
        let credential_id: String = tx
            .query_row(
                "SELECT value FROM settings WHERE name = ?1 AND typeof(value) = 'text'",
                [POLICY_ROOT_CREDENTIAL_SETTING],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(Sql)?
            .filter(|id| is_policy_root_id(id))
            .ok_or_else(not_found)?;
        let (version, state, blob): (i64, String, Vec<u8>) = tx
            .query_row(
                "SELECT record_version, state, envelope FROM credentials WHERE credential_id = ?1",
                [&credential_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(Sql)?
            .ok_or_else(not_found)?;
        if RecordState::from_str(&state) != RecordState::Active {
            return Err(not_found());
        }
        // Ordinary reads can quarantine a broken record through another write. This
        // transaction must instead fail without attempting a nested store mutation.
        let plaintext = envelope::open(
            &self.key,
            &blob,
            &RecordBinding {
                credential_id: &credential_id,
                record_version: version as u64,
            },
        )
        .map_err(|error| Unusable(StoreOpError::Decrypt(error)))?;
        let record = VaultRecord::decode(&plaintext)
            .map_err(|error| Unusable(StoreOpError::Corrupt(error.to_string())))?;
        if record.kind != CredentialKind::SigningKey {
            return Err(not_found());
        }
        Ok(ManifestRoot {
            credential_id,
            record,
        })
    }

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
