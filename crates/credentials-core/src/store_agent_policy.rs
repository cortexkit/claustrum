use std::collections::BTreeMap;

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::Serialize;

use super::{
    store_agent_secrets::secret_home_role_conn, EncryptedStore, SecretHomeRole, StoreOpError,
};
use crate::agent_policy::{
    github_default_rule_set, policy_sha256, signed_input, valid_github_app_agent,
    validate_signer_rule_sets, AgentPolicy, PolicyError, RuleSet,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentPolicySummary {
    pub version: i64,
    pub policy_sha256: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct ActiveAgentPolicy {
    pub version: i64,
    pub policy_sha256: String,
    pub manifest_version: i64,
    pub policy_text: String,
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

impl From<StoreAgentPolicyError> for StoreOpError {
    fn from(error: StoreAgentPolicyError) -> Self {
        use StoreAgentPolicyError::*;
        match error {
            Policy(error) => Self::Encode(error.to_string()),
            Root(error) => error,
            Sql(error) => super::gh_admin::sql(error),
            invariant => Self::Corrupt(format!("policy storage validation failed: {invariant:?}")),
        }
    }
}

pub(super) fn has_agent_policy_conn(conn: &rusqlite::Connection) -> rusqlite::Result<bool> {
    conn.query_row("SELECT EXISTS(SELECT 1 FROM agent_policies)", [], |row| {
        row.get(0)
    })
}

pub(super) fn paired_agent_policy_conn(
    conn: &Connection,
    manifest_version: i64,
) -> rusqlite::Result<Option<AgentPolicySummary>> {
    conn.query_row(
        "SELECT version, policy_sha256 FROM agent_policies WHERE manifest_version = ?1",
        [manifest_version],
        |row| {
            Ok(AgentPolicySummary {
                version: row.get(0)?,
                policy_sha256: row.get(1)?,
            })
        },
    )
    .optional()
}

pub(super) fn head_agent_policy_conn(
    conn: &rusqlite::Connection,
) -> Result<Option<AgentPolicy>, StoreOpError> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT policy_bytes FROM agent_policies ORDER BY version DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(super::gh_admin::sql)?;
    bytes
        .map(|bytes| {
            AgentPolicy::parse_canonical(&bytes).map_err(|error| {
                StoreOpError::Corrupt(format!("stored policy is invalid: {error}"))
            })
        })
        .transpose()
}

/// A ready manifest needs unanimous reports, so the first expected computer's
/// reported version is the only candidate. Use the caller's read snapshot.
pub(super) fn active_agent_policy_version_conn(
    conn: &rusqlite::Connection,
) -> rusqlite::Result<Option<i64>> {
    use super::gh_activations::{gh_manifest_expected_computers_conn, gh_manifest_reports_ready};

    let computers = gh_manifest_expected_computers_conn(conn)?;
    let Some(manifest_version) = computers.first().and_then(|computer| computer.version) else {
        return Ok(None);
    };
    let candidate: Option<(i64, String)> = conn
        .query_row(
            "SELECT p.version, m.manifest_sha256 FROM agent_policies p \
         JOIN gh_manifests m ON m.version = p.manifest_version WHERE m.version = ?1",
            [manifest_version],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    Ok(candidate.and_then(|(version, digest)| {
        gh_manifest_reports_ready(&computers, manifest_version, &digest).then_some(version)
    }))
}

impl EncryptedStore {
    /// Resolve the serving role and the ready pair from the same read snapshot.
    /// Non-serving vaults return their role without reading any policy row.
    pub fn active_agent_policy(
        &self,
    ) -> Result<(SecretHomeRole, Option<ActiveAgentPolicy>), StoreOpError> {
        self.store
            .with_conn(|conn| active_agent_policy_read(conn, || {}))
            .map_err(StoreOpError::from)
    }

    pub(crate) fn prepare_github_app_manifest(
        &self,
        agent: &str,
    ) -> Result<serde_json::Value, StoreOpError> {
        if !valid_github_app_agent(agent) {
            return Err(StoreOpError::Encode(
                "agent_invalid: expected agent_ followed by 16 lowercase hex digits".into(),
            ));
        }
        let (role, exists, policy) = self
            .store
            .with_conn(|conn| {
                let tx = conn.unchecked_transaction()?;
                let role = secret_home_role_conn(&tx);
                if !matches!(role, SecretHomeRole::Single | SecretHomeRole::Home { .. }) {
                    return Ok((role, false, None));
                }
                let exists = super::github_app_store::github_app_agent_exists_conn(&tx, agent)?;
                let policy = if exists {
                    None
                } else {
                    active_agent_policy_conn(&tx)?
                };
                tx.commit()?;
                Ok((role, exists, policy))
            })
            .map_err(|_| manifest_policy_unavailable())?;
        if !matches!(role, SecretHomeRole::Single | SecretHomeRole::Home { .. }) {
            return Err(manifest_policy_unavailable());
        }
        if exists {
            return Err(StoreOpError::Encode(
                super::github_app_store::AGENT_EXISTS.into(),
            ));
        }
        let rules = match policy {
            Some(policy) => AgentPolicy::parse_canonical(policy.policy_text.as_bytes())
                .map_err(|_| manifest_policy_unavailable())?
                .rule_sets
                .remove("github"),
            None => Some(github_default_rule_set().map_err(|_| manifest_policy_unavailable())?),
        };

        let mut suffix = [0u8; 3];
        getrandom::getrandom(&mut suffix)
            .map_err(|_| StoreOpError::Store("could not generate a GitHub App name".into()))?;
        let [a, b, c] = suffix;
        Ok(serde_json::json!({
            "name": format!("ck-{agent}-{a:02x}{b:02x}{c:02x}"),
            "default_permissions": github_app_manifest_permissions(rules.as_ref()),
            "default_events": ["issues", "issue_comment", "pull_request", "pull_request_review",
                "pull_request_review_comment", "release", "workflow_job", "workflow_run"],
        }))
    }

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
        let pem = std::str::from_utf8(root.record.payload.expose()).map_err(|_| UnusableRoot)?;
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
            params![row.approval_seq, root.credential_id, approved_digest],
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

fn active_agent_policy_read(
    conn: &Connection,
    after_role: impl FnOnce(),
) -> rusqlite::Result<(SecretHomeRole, Option<ActiveAgentPolicy>)> {
    let tx = conn.unchecked_transaction()?;
    let role = secret_home_role_conn(&tx);
    if !matches!(role, SecretHomeRole::Single | SecretHomeRole::Home { .. }) {
        return Ok((role, None));
    }
    after_role();
    let row = active_agent_policy_conn(&tx)?;
    tx.commit()?;
    Ok((role, row))
}

fn active_agent_policy_conn(conn: &Connection) -> rusqlite::Result<Option<ActiveAgentPolicy>> {
    active_agent_policy_version_conn(conn)?
        .map(|version| {
            conn.query_row(
                "SELECT version, policy_sha256, manifest_version, policy_bytes \
                 FROM agent_policies WHERE version = ?1",
                [version],
                |row| {
                    let bytes = row.get::<_, Vec<u8>>(3)?;
                    let policy_text = String::from_utf8(bytes).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            3,
                            rusqlite::types::Type::Blob,
                            Box::new(error),
                        )
                    })?;
                    Ok(ActiveAgentPolicy {
                        version: row.get(0)?,
                        policy_sha256: row.get(1)?,
                        manifest_version: row.get(2)?,
                        policy_text,
                    })
                },
            )
        })
        .transpose()
}

fn manifest_policy_unavailable() -> StoreOpError {
    StoreOpError::Encode("policy_unavailable: could not read the serving GitHub policy".into())
}

fn github_app_manifest_permissions(rules: Option<&RuleSet>) -> BTreeMap<&str, &str> {
    let mut permissions = BTreeMap::from([
        ("actions", "read"),
        ("contents", "read"),
        ("issues", "read"),
        ("pull_requests", "read"),
    ]);
    for credential in rules
        .into_iter()
        .flat_map(|rules| &rules.kinds)
        .filter_map(|kind| kind.credential.as_ref())
    {
        for (name, level) in &credential.github_permissions {
            let existing = permissions.entry(name.as_str()).or_insert(level.as_str());
            if level == "admin" || (level == "write" && *existing == "read") {
                *existing = level.as_str();
            }
        }
    }
    permissions
}

#[cfg(test)]
#[path = "store_agent_policy_tests.rs"]
mod tests;
