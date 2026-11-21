use rusqlite::{params, OptionalExtension, Transaction};

use super::{EncryptedStore, StoreOpError, GH_MANIFEST_ROOT_KEY_ID};
use crate::agent_policy::{
    policy_sha256, signed_input, validate_signer_rule_sets, AgentPolicy, PolicyError,
};
use crate::enrollment::decode_lower_hex_32;
use crate::signing::public_key_ed25519;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AgentPolicySource {
    Ceremony,
    OneTap,
}

impl AgentPolicySource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ceremony => "ceremony",
            Self::OneTap => "one_tap",
        }
    }
}

pub(crate) struct AgentPolicyVersion<'a> {
    pub version: i64,
    pub policy_bytes: &'a [u8],
    pub policy_sha256: &'a str,
    pub key_id: &'a str,
    pub signature: &'a [u8; 64],
    pub signed_at_ms: i64,
    pub source: AgentPolicySource,
    pub approval_seq: i64,
    pub manifest_version: i64,
}

#[derive(Debug)]
pub(crate) enum StoreAgentPolicyError {
    Policy(PolicyError),
    VersionMismatch,
    DigestMismatch,
    Root(StoreOpError),
    UnusableRoot,
    KeyIdMismatch,
    RootKeyIdMismatch,
    InvalidSignature,
    MissingManifest,
    ManifestSourceMismatch,
    ApprovalMismatch,
    Sql(rusqlite::Error),
}

impl From<PolicyError> for StoreAgentPolicyError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<rusqlite::Error> for StoreAgentPolicyError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sql(error)
    }
}

impl EncryptedStore {
    /// Verify the exact bytes and approval against the current root and paired manifest
    /// in the caller's writer transaction. No policy row is written before every check passes.
    pub(crate) fn store_agent_policy_in_tx(
        &self,
        tx: &Transaction<'_>,
        row: &AgentPolicyVersion<'_>,
    ) -> Result<(), StoreAgentPolicyError> {
        use StoreAgentPolicyError::*;

        let input = signed_input(row.policy_bytes)?;
        let policy = AgentPolicy::parse_canonical(row.policy_bytes)?;
        validate_signer_rule_sets(&policy)?;
        if policy.version != row.version {
            return Err(VersionMismatch);
        }
        if policy_sha256(row.policy_bytes) != row.policy_sha256 {
            return Err(DigestMismatch);
        }

        let root = self.gh_manifest_root_in_tx(tx).map_err(Root)?;
        let pem = std::str::from_utf8(root.payload.expose()).map_err(|_| UnusableRoot)?;
        let public = public_key_ed25519(pem).map_err(|_| UnusableRoot)?;
        if row.key_id != public.key_id {
            return Err(KeyIdMismatch);
        }
        if policy.root_key_id != public.key_id {
            return Err(RootKeyIdMismatch);
        }
        let public_bytes = decode_lower_hex_32(&public.public_key_hex).ok_or(UnusableRoot)?;
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_bytes)
            .verify(&input, row.signature)
            .map_err(|_| InvalidSignature)?;

        let (manifest_source, manifest_digest, manifest_approval): (String, String, Option<i64>) = tx
            .query_row(
                "SELECT source, manifest_sha256, approval_audit_seq FROM gh_manifests WHERE version = ?1",
                [row.manifest_version],
                |record| Ok((record.get(0)?, record.get(1)?, record.get(2)?)),
            )
            .optional()?
            .ok_or(MissingManifest)?;
        let approved_digest = match row.source {
            AgentPolicySource::Ceremony => row.policy_sha256,
            AgentPolicySource::OneTap => {
                if manifest_source != AgentPolicySource::OneTap.as_str() {
                    return Err(ManifestSourceMismatch);
                }
                if manifest_approval != Some(row.approval_seq) {
                    return Err(ApprovalMismatch);
                }
                &manifest_digest
            }
        };
        let approved: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM audit_log \
             WHERE seq = ?1 AND op = 'approval' AND credential_id = ?2 AND payload_hash = ?3)",
            params![row.approval_seq, GH_MANIFEST_ROOT_KEY_ID, approved_digest],
            |record| record.get(0),
        )?;
        if !approved {
            return Err(ApprovalMismatch);
        }

        tx.execute(
            "INSERT INTO agent_policies \
             (version, policy_bytes, policy_sha256, key_id, signature, signed_at_ms, source, approval_seq, manifest_version) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                row.version,
                row.policy_bytes,
                row.policy_sha256,
                row.key_id,
                row.signature.as_slice(),
                row.signed_at_ms,
                row.source.as_str(),
                row.approval_seq,
                row.manifest_version,
            ],
        )?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "store_agent_policy_tests.rs"]
mod tests;
