use super::agent_policy::{head_agent_policy_conn, AgentPolicySource};
use super::agent_policy_admin::{AgentPolicyApproval, PrepareAgentPolicyError};
use super::gh_manifests::ManifestRootReadError;
use super::{
    append_audit_tx, gh_proposals, hex32, payload_hash, EncryptedStore, GhManifestProposal,
    GhManifestSource, GhManifestVersion, GH_MANIFEST_ROOT_KEY_ID,
};
use crate::agent_policy::{manifest_projection, signed_input, AgentPolicy, Binding, PolicyError};
use crate::agent_secret::{SecretError, SECRET_ISSUE_SKEW_LIMIT_MS};
use crate::audit::{AuditCtx, AuditOp, AuditRecord, GhManifestAudit};
#[cfg(test)]
use crate::gh_manifest::ManifestBindingEnvelope;
use crate::gh_manifest::{GhManifest, ManifestBindingStatement};
use base64::Engine as _;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};

/// Rebuild both commitments from the immutable base. Hash agreement alone would
/// allow a rewritten proposal to smuggle unrelated manifest edits past the phone.
fn committed_manifest(
    tx: &rusqlite::Transaction<'_>,
    p: &GhManifestProposal,
) -> rusqlite::Result<Option<GhManifest>> {
    let base: Option<(Vec<u8>, String)> = tx
        .query_row(
            "SELECT manifest_bytes,manifest_sha256 FROM gh_manifests WHERE version=?1",
            [p.base_version],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((base_bytes, base_hash)) = base else {
        return Ok(None);
    };
    let (Ok(prior), Ok(manifest), Ok(permissions)) = (
        GhManifest::parse_reproducible(&base_bytes),
        GhManifest::parse_reproducible(&p.manifest_bytes),
        serde_json::from_slice(&p.installation_permissions),
    ) else {
        return Ok(None);
    };
    if prior.version() != p.base_version
        || prior.manifest_sha256() != base_hash
        || manifest.manifest_sha256() != p.manifest_sha256
        || hex32(&payload_hash(&p.statement_bytes)) != p.statement_sha256
    {
        return Ok(None);
    }
    let Ok(expected_manifest) =
        prior.build_next(&p.repo, &p.agent_id, manifest.issued_at_unix_secs())
    else {
        return Ok(None);
    };
    if expected_manifest.to_bytes() != p.manifest_bytes {
        return Ok(None);
    }
    let Ok(statement) = ManifestBindingStatement::new(
        p.proposal_id.clone(),
        p.agent_id.clone(),
        p.app_slug.clone(),
        p.repo.clone(),
        permissions,
        &expected_manifest,
        &prior,
        p.expires_at_ms,
    ) else {
        return Ok(None);
    };
    Ok(statement
        .canonical_bytes()
        .is_ok_and(|bytes| bytes == p.statement_bytes)
        .then_some(expected_manifest))
}

fn one_tap_policy(
    mut head: AgentPolicy,
    p: &GhManifestProposal,
    manifest: &GhManifest,
) -> Result<(AgentPolicy, Vec<u8>, Vec<u8>), SecretError> {
    use SecretError::{PolicyBindingConflict, PolicyTooLarge};

    // A parsed head's version fits within the JSON safe integer range, below i64::MAX.
    head.version += 1;
    let identity = format!("github_app:{}", p.app_slug);
    let repo = p.repo.to_ascii_lowercase();
    let key = ("github", p.agent_id.as_str());
    let identity_conflict = match head
        .bindings
        .binary_search_by(|binding| (binding.service.as_str(), binding.agent.as_str()).cmp(&key))
    {
        Ok(index) => {
            let binding = &mut head.bindings[index];
            let index = binding
                .resources
                .partition_point(|resource| resource < &repo);
            binding.resources.insert(index, repo);
            binding.identity != identity
        }
        Err(index) => {
            head.bindings.insert(
                index,
                Binding {
                    service: "github".into(),
                    agent: p.agent_id.clone(),
                    identity,
                    resources: vec![repo],
                },
            );
            false
        }
    };
    let bytes = head
        .canonical_signing_bytes()
        .map_err(|error| match error {
            PolicyError::TooLarge => PolicyTooLarge,
            _ => PolicyBindingConflict,
        })?;
    let policy = AgentPolicy::parse_canonical(&bytes).map_err(|_| PolicyBindingConflict)?;
    if identity_conflict
        || policy.github_projection()
            != manifest_projection(manifest).map_err(|_| PolicyBindingConflict)?
    {
        return Err(PolicyBindingConflict);
    }
    let input = signed_input(&bytes).map_err(|_| PolicyTooLarge)?;
    Ok((policy, bytes, input))
}

fn reply(p: &GhManifestProposal) -> Value {
    json!({"status":"approved", "proposal_id":p.proposal_id,
        "version":p.base_version + 1, "manifest_sha256":p.manifest_sha256})
}

impl EncryptedStore {
    /// Runs under the serializing writer after the caller's approval admission.
    /// Both approval modes use the same proposal and commitment checks.
    pub(super) fn gh_manifest_approval_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        fingerprint: &str,
        authority: super::store_agent_secrets::desktop::ApprovalAuthority<'_>,
        bytes: &[u8],
        now: i64,
    ) -> rusqlite::Result<Result<Value, SecretError>> {
        if !gh_proposals::setup_complete(tx)? {
            return Ok(Err(SecretError::ManifestSetupIncomplete));
        }
        let envelope = match authority.manifest(bytes, fingerprint, now) {
            Ok(envelope) => envelope,
            Err(error) => return Ok(Err(error)),
        };
        let stored = tx.query_row(
            "SELECT proposal_id,agent_id,app_id,app_slug,repo,installation_permissions,base_version, \
             manifest_bytes,manifest_sha256,statement_bytes,statement_sha256,created_at_ms,expires_at_ms, \
             state,approved_envelope_sha256,approved_fingerprint FROM gh_manifest_proposals WHERE proposal_id=?1",
            [&envelope.proposal_id], |row| Ok((gh_proposals::proposal_row(row)?,
                row.get::<_, String>(13)?, row.get::<_, Option<String>>(14)?, row.get::<_, Option<String>>(15)?)),
        ).optional()?;
        let Some((p, state, approved_hash, approved_fingerprint)) = stored else {
            return Ok(Err(SecretError::ApprovalInvalid));
        };
        let issued = envelope.issued_at_ms as i64;
        if envelope.statement_sha256 != p.statement_sha256 || issued < p.created_at_ms {
            return Ok(Err(SecretError::ApprovalInvalid));
        }
        let Some(manifest) = committed_manifest(tx, &p)? else {
            return Ok(Err(SecretError::ApprovalInvalid));
        };
        let envelope_hash = hex32(&payload_hash(bytes));
        if state == "approved" {
            return Ok(
                if approved_hash.as_deref() == Some(envelope_hash.as_str())
                    && approved_fingerprint.as_deref() == Some(fingerprint)
                    && now <= issued.saturating_add(SECRET_ISSUE_SKEW_LIMIT_MS)
                {
                    Ok(reply(&p))
                } else {
                    Err(SecretError::ApprovalInvalid)
                },
            );
        }
        let newest: i64 = tx.query_row("SELECT MAX(version) FROM gh_manifests", [], |row| {
            row.get(0)
        })?;
        if state == "superseded" || p.base_version != newest {
            return Ok(Err(SecretError::Superseded));
        }
        if state == "expired" || now >= p.expires_at_ms || issued >= p.expires_at_ms {
            return Ok(Err(SecretError::Expired));
        }
        // Returning Ok(Err(SecretError)) commits the transaction, so validate the
        // successor before any write.
        let policy = match head_agent_policy_conn(tx).map_err(|_| rusqlite::Error::InvalidQuery)? {
            Some(head) => match one_tap_policy(head, &p, &manifest) {
                Ok(policy) => Some(policy),
                Err(err) => return Ok(Err(err)),
            },
            None => None,
        };
        let prepared_policy = if let Some((policy, bytes, input)) = &policy {
            use PrepareAgentPolicyError::{Root, RootKeyIdMismatch, TooLarge, UnusableKey};
            match self.prepare_agent_policy_in_tx(tx, policy, bytes, input) {
                Ok(prepared) => Some(prepared),
                Err(TooLarge) => return Ok(Err(SecretError::PolicyTooLarge)),
                Err(Root(ManifestRootReadError::Sql(error))) => return Err(error),
                Err(Root(ManifestRootReadError::Unusable(_)) | UnusableKey | RootKeyIdMismatch) => {
                    return Ok(Err(SecretError::ManifestSetupIncomplete));
                }
            }
        } else {
            None
        };

        let actor = authority.actor(fingerprint, true);
        let approval = append_audit_tx(
            tx,
            &self.audit_key,
            &AuditRecord {
                op: AuditOp::Approval,
                credential_id: Some(GH_MANIFEST_ROOT_KEY_ID.into()),
                payload_hash: Some(p.manifest_sha256.clone()),
                actor: actor.clone(),
                alarm: None,
            },
        )?;
        let ctx = AuditCtx {
            op: AuditOp::GhManifestSign,
            actor: &actor,
            alarm: None,
        };
        let signed = self
            .sign_gh_manifest(tx, &p.manifest_bytes, ctx)
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let raw: [u8; 64] = base64::engine::general_purpose::STANDARD
            .decode(&signed.signature_b64)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(rusqlite::Error::InvalidQuery)?;
        // Exclude this proposal from the store helper's pending-sibling sweep.
        tx.execute("UPDATE gh_manifest_proposals SET state='approved',approved_envelope_sha256=?2,approved_fingerprint=?3 WHERE proposal_id=?1",
            params![p.proposal_id, envelope_hash, fingerprint])?;
        append_audit_tx(
            tx,
            &self.audit_key,
            &GhManifestAudit::ProposalState {
                proposal_id: &p.proposal_id,
                from: "pending",
                to: "approved",
            }
            .record(&actor, None),
        )?;
        self.store_gh_manifest_in_tx(
            tx,
            &GhManifestVersion {
                version: p.base_version + 1,
                manifest_bytes: &p.manifest_bytes,
                manifest_sha256: &p.manifest_sha256,
                key_id: &signed.key_id,
                signature: &raw,
                signed_at_ms: now,
                source: GhManifestSource::OneTap,
                approval_audit_seq: Some(approval.seq),
            },
            AuditCtx {
                op: AuditOp::GhManifestStore,
                actor: &actor,
                alarm: None,
            },
        )?;
        if let Some(prepared) = prepared_policy {
            self.sign_and_store_agent_policy_in_tx(
                tx,
                prepared,
                AgentPolicyApproval {
                    seq: approval.seq,
                    source: AgentPolicySource::OneTap,
                    manifest_version: manifest.version(),
                    actor: &actor,
                },
                || now,
            )
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        }
        Ok(Ok(reply(&p)))
    }
}

#[cfg(test)]
#[path = "store_gh_approval_tests.rs"]
mod tests;
