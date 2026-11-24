//! Local authorization and release checks for policy-narrowed GitHub App tokens.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use crate::{
    agent_policy::{AgentPolicy, Approval, Class, Identity},
    audit::{AuditOp, AuditRecord},
    broker_action::{valid_ulid, BrokerActionLeg},
    envelope::EnvelopeError,
    federation::is_lower_hex_sha256,
    oauth::OAuthCredential,
    record::RecordState,
};

use super::{
    agent_policy::{active_agent_policy_summary_conn, AgentPolicySummary},
    append_audit_tx,
    audit_store::record_scoped_first_use_tx,
    sha256_hex_of_bytes,
    store_agent_secrets::secret_home_role_conn,
    EncryptedStore, GrantOperation, SecretHomeRole, StoreOpError,
};

const MAX_POLICY_TOKEN_REPOSITORIES: usize = 500;

// Only one policy is active in a snapshot. Keep its parsed document, not any
// caller's binding, grants or approval result.
#[derive(Default)]
pub(super) struct ParsedPolicyMemo(Mutex<Option<ParsedPolicy>>);

struct ParsedPolicy {
    version: i64,
    sha256: String,
    policy: Arc<AgentPolicy>,
}

#[cfg(test)]
thread_local! {
    pub(super) static POLICY_TOKEN_POLICY_PARSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTokenRequest {
    pub identity: String,
    pub service: String,
    pub kind: String,
    pub resource: String,
    pub policy_version: i64,
    #[serde(default, deserialize_with = "present_value")]
    pub approval_request_id: Option<Value>,
    #[serde(default, deserialize_with = "present_value")]
    pub request_sha256: Option<Value>,
}

fn present_value<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Value>, D::Error> {
    // Preserve explicit null and other malformed values until after grant and service checks.
    Value::deserialize(deserializer).map(Some)
}

struct ApprovalProof<'a> {
    request_id: &'a str,
    request_sha256: &'a str,
}

impl PolicyTokenRequest {
    fn approval_proof(&self) -> Result<Option<ApprovalProof<'_>>, PolicyTokenError> {
        match (&self.approval_request_id, &self.request_sha256) {
            (None, None) => Ok(None),
            (Some(Value::String(request_id)), Some(Value::String(request_sha256)))
                if valid_ulid(request_id) && is_lower_hex_sha256(request_sha256) =>
            {
                Ok(Some(ApprovalProof {
                    request_id,
                    request_sha256,
                }))
            }
            _ => Err(PolicyTokenError::InvalidParams),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyTokenError {
    NotFound,
    StoreError,
    InvalidParams,
    VersionNotActive,
    ApprovalRequired,
    ApprovalInvalid,
    ApprovalPolicyChanged,
    ScopeUnavailable,
    NotInstalled,
    NeedsReauth,
    Corrupt,
    VaultLocked,
    InstallationUnusable,
    Expired,
}

/// The plaintext row identity and a fingerprint of the exact sealed bytes it held.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PolicyTokenRecordKey {
    incarnation: String,
    record_version: u64,
    envelope_digest: String,
}

pub struct PolicyTokenRecord {
    pub key: PolicyTokenRecordKey,
    envelope: Vec<u8>,
    attested_agent: Option<String>,
}

pub struct PolicyTokenPlan {
    pub record: PolicyTokenRecord,
    pub repositories: Vec<String>,
    pub permissions: BTreeMap<String, String>,
    pub approval_leg: Option<i64>,
}

pub enum PolicyTokenHandoff {
    Released,
    RecordChanged(PolicyTokenRecord),
}

impl EncryptedStore {
    /// Check every local gate in one read snapshot before a caller may use the cache
    /// or contact GitHub. The route has already admitted this reserved principal.
    pub fn prepare_policy_token(
        &self,
        module_id: &str,
        request: Option<&PolicyTokenRequest>,
        clock: impl FnOnce() -> i64,
    ) -> Result<PolicyTokenPlan, PolicyTokenError> {
        self.store
            .with_conn(|conn| {
                let tx = conn.unchecked_transaction()?;
                let result = prepare(&tx, &self.policy_token_memo, module_id, request, clock)?;
                tx.commit()?;
                Ok(result)
            })
            .map_err(|_| PolicyTokenError::StoreError)?
    }

    /// Open the bytes already read by the gates. The ordinary credential read can
    /// quarantine the row; a token request must never change its state.
    pub fn open_policy_token_material(
        &self,
        identity: &str,
        record: PolicyTokenRecord,
    ) -> Result<OAuthCredential, PolicyTokenError> {
        self.open_github_app_material(identity, record.key.record_version, &record.envelope)
            .map_err(|error| match error {
                StoreOpError::Decrypt(EnvelopeError::KeyMismatch { .. }) => {
                    PolicyTokenError::VaultLocked
                }
                _ => PolicyTokenError::Corrupt,
            })?
            .ok_or(PolicyTokenError::InstallationUnusable)
    }

    /// Authorize release and commit first use together. No provider request is made
    /// while holding this writer transaction.
    pub fn handoff_policy_token(
        &self,
        module_id: &str,
        request: &PolicyTokenRequest,
        key: &PolicyTokenRecordKey,
        expires_at_ms: i64,
        approval_leg: Option<i64>,
        clock: impl Fn() -> i64,
    ) -> Result<PolicyTokenHandoff, PolicyTokenError> {
        self.handoff_policy_token_with_probe(
            module_id,
            request,
            (key, expires_at_ms, approval_leg),
            clock,
            || {},
        )
    }

    pub(super) fn handoff_policy_token_with_probe(
        &self,
        module_id: &str,
        request: &PolicyTokenRequest,
        candidate: (&PolicyTokenRecordKey, i64, Option<i64>),
        clock: impl Fn() -> i64,
        after_grant: impl FnOnce(),
    ) -> Result<PolicyTokenHandoff, PolicyTokenError> {
        self.fenced_write(|tx| handoff(tx, self, module_id, request, candidate, clock, after_grant))
            .map_err(|_| PolicyTokenError::StoreError)?
    }
}

#[cfg(test)]
#[test]
fn policy_token_binding_accepts_500_and_refuses_501() {
    let request = PolicyTokenRequest {
        identity: "github_app:agent".into(),
        service: "github".into(),
        kind: "node_repository".into(),
        resource: "binding".into(),
        policy_version: 1,
        approval_request_id: None,
        request_sha256: None,
    };
    let resources: Vec<_> = (0..501).map(|i| format!("org/r{i:03}")).collect();
    assert_eq!(
        select_repositories(&request, &resources[..500]).unwrap(),
        resources[..500]
    );
    assert_eq!(
        select_repositories(&request, &resources),
        Err(PolicyTokenError::ScopeUnavailable)
    );
}

pub(super) fn serving_role(conn: &Connection) -> Result<(), PolicyTokenError> {
    match secret_home_role_conn(conn) {
        SecretHomeRole::Single | SecretHomeRole::Home { .. } => Ok(()),
        SecretHomeRole::Remote { .. } | SecretHomeRole::RemoteSetupIncomplete { .. } => {
            Err(PolicyTokenError::NotFound)
        }
        SecretHomeRole::StoreError => Err(PolicyTokenError::StoreError),
    }
}

pub(super) fn has_exact_grant(
    conn: &Connection,
    module_id: &str,
    identity: &str,
) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM read_grants \
         WHERE principal_kind = 'reserved' AND principal_id = ?1 \
           AND selector_kind = 'exact' AND selector = ?2 AND operation = ?3)",
        params![module_id, identity, GrantOperation::PolicyToken.as_str()],
        |row| row.get(0),
    )
}

fn prepare(
    conn: &Connection,
    memo: &ParsedPolicyMemo,
    module_id: &str,
    request: Option<&PolicyTokenRequest>,
    clock: impl FnOnce() -> i64,
) -> rusqlite::Result<Result<PolicyTokenPlan, PolicyTokenError>> {
    use PolicyTokenError as Error;
    if let Err(error) = serving_role(conn) {
        return Ok(Err(error));
    }
    let Some(request) = request else {
        return Ok(Err(Error::InvalidParams));
    };
    if !has_exact_grant(conn, module_id, &request.identity)? || request.service != "github" {
        return Ok(Err(Error::NotFound));
    }
    let proof = match request.approval_proof() {
        Ok(proof) => proof,
        Err(error) => return Ok(Err(error)),
    };
    let active = active_agent_policy_summary_conn(conn)?;
    let active_version = active.as_ref().map(|policy| policy.version);
    let policy =
        if let Some(summary) = active.filter(|policy| policy.version == request.policy_version) {
            let Some(policy) = read_policy(conn, memo, summary)? else {
                return Ok(Err(Error::StoreError));
            };
            Some(policy)
        } else {
            None
        };
    let kind = policy.as_ref().and_then(|policy| {
        policy
            .rule_sets
            .get(&request.service)?
            .kinds
            .iter()
            .find(|kind| kind.kind == request.kind)
    });
    let approval_leg = if let Some(proof) = proof {
        if kind.is_some_and(|kind| kind.approval != Approval::Once) {
            return Ok(Err(Error::InvalidParams));
        }
        match check_approval(conn, module_id, request, &proof, active_version, clock())? {
            Ok(leg) => Some(leg),
            Err(error) => return Ok(Err(error)),
        }
    } else {
        None
    };
    let Some(policy) = policy.as_ref() else {
        return Ok(Err(Error::VersionNotActive));
    };
    let Some(binding) = policy
        .bindings
        .iter()
        .find(|binding| binding.service == request.service && binding.identity == request.identity)
    else {
        return Ok(Err(Error::NotFound));
    };
    let Some((kind, credential)) = kind
        .filter(|kind| kind.class != Class::Denied && kind.identity == Identity::Agent)
        .and_then(|kind| Some((kind, kind.credential.as_ref()?)))
    else {
        return Ok(Err(Error::NotFound));
    };
    let repositories = match select_repositories(request, &binding.resources) {
        Ok(repositories) => repositories,
        Err(error) => return Ok(Err(error)),
    };
    let record = match read_record(conn, &request.identity)? {
        Ok(record) => record,
        Err(error) => return Ok(Err(error)),
    };
    if record
        .attested_agent
        .as_ref()
        .is_some_and(|agent| agent != &binding.agent)
    {
        return Ok(Err(Error::NotFound));
    }
    if kind.approval == Approval::Once && approval_leg.is_none() {
        return Ok(Err(Error::ApprovalRequired));
    }
    Ok(Ok(PolicyTokenPlan {
        record,
        repositories,
        permissions: credential.github_permissions.clone(),
        approval_leg,
    }))
}

fn read_policy(
    conn: &Connection,
    memo: &ParsedPolicyMemo,
    summary: AgentPolicySummary,
) -> rusqlite::Result<Option<Arc<AgentPolicy>>> {
    let AgentPolicySummary {
        version,
        policy_sha256: sha256,
    } = summary;
    if let Some(cached) = memo
        .0
        .lock()
        .unwrap()
        .as_ref()
        .filter(|cached| cached.version == version && cached.sha256 == sha256)
    {
        return Ok(Some(Arc::clone(&cached.policy)));
    }
    let bytes: Vec<u8> = conn.query_row(
        "SELECT policy_bytes FROM agent_policies WHERE version = ?1",
        [version],
        |row| row.get(0),
    )?;
    #[cfg(test)]
    POLICY_TOKEN_POLICY_PARSES.with(|count| count.set(count.get() + 1));
    let Ok(policy) = AgentPolicy::parse_canonical(&bytes) else {
        return Ok(None);
    };
    let policy = Arc::new(policy);
    *memo.0.lock().unwrap() = Some(ParsedPolicy {
        version,
        sha256,
        policy: Arc::clone(&policy),
    });
    Ok(Some(policy))
}

fn select_repositories(
    request: &PolicyTokenRequest,
    resources: &[String],
) -> Result<Vec<String>, PolicyTokenError> {
    if request.resource == "binding" && request.kind == "node_repository" {
        if resources.len() > MAX_POLICY_TOKEN_REPOSITORIES {
            return Err(PolicyTokenError::ScopeUnavailable);
        }
        // The canonical policy already orders the binding's repositories.
        Ok(resources.to_vec())
    } else if resources.binary_search(&request.resource).is_ok() {
        Ok(vec![request.resource.clone()])
    } else {
        Err(PolicyTokenError::NotFound)
    }
}

fn read_record(
    conn: &Connection,
    identity: &str,
) -> rusqlite::Result<Result<PolicyTokenRecord, PolicyTokenError>> {
    use PolicyTokenError as Error;
    let row = conn
        .query_row(
            "SELECT state, incarnation, record_version, envelope, github_app_agent FROM credentials WHERE credential_id = ?1",
            [identity],
            |r| Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?, r.get::<_, Vec<u8>>(3)?, r.get(4)?)),
        )
        .optional()?;
    let Some((state, incarnation, record_version, envelope, attested_agent)) = row else {
        return Ok(Err(Error::NotInstalled));
    };
    let result = match RecordState::from_str(&state) {
        RecordState::Active => Ok(PolicyTokenRecord {
            key: PolicyTokenRecordKey {
                incarnation,
                record_version,
                envelope_digest: sha256_hex_of_bytes(&envelope),
            },
            envelope,
            attested_agent,
        }),
        RecordState::NeedsReauth | RecordState::Retired => Err(Error::NeedsReauth),
        RecordState::Corrupt => Err(Error::Corrupt),
    };
    Ok(result)
}

fn check_approval(
    conn: &Connection,
    module_id: &str,
    request: &PolicyTokenRequest,
    proof: &ApprovalProof<'_>,
    active_version: Option<i64>,
    now: i64,
) -> rusqlite::Result<Result<i64, PolicyTokenError>> {
    use PolicyTokenError as Error;
    let actor = format!("reserved:{module_id}");
    let row = conn
        .query_row(
            "SELECT policy_version, identity, legs_json, issued_legs
             FROM broker_action_requests
             WHERE request_id = ?1 AND approved_at_ms IS NOT NULL
               AND expires_at_ms > ?2 AND principal = ?3",
            params![proof.request_id, now, actor],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((version, identity, legs, issued_legs)) = row else {
        return Ok(Err(Error::ApprovalInvalid));
    };
    if active_version != Some(version) {
        return Ok(Err(Error::ApprovalPolicyChanged));
    }
    let matches_leg = serde_json::from_str::<Vec<BrokerActionLeg>>(&legs)
        .ok()
        .zip(usize::try_from(issued_legs).ok())
        .is_some_and(|(legs, index)| {
            legs.get(index).is_some_and(|leg| {
                leg.kind == request.kind
                    && leg.resource == request.resource
                    && leg.request_sha256 == proof.request_sha256
            })
        });
    if identity != request.identity || !matches_leg {
        return Ok(Err(Error::ApprovalInvalid));
    }
    Ok(Ok(issued_legs))
}

fn handoff(
    tx: &rusqlite::Transaction<'_>,
    store: &EncryptedStore,
    module_id: &str,
    request: &PolicyTokenRequest,
    (key, expires_at_ms, prepared_leg): (&PolicyTokenRecordKey, i64, Option<i64>),
    clock: impl Fn() -> i64,
    after_grant: impl FnOnce(),
) -> rusqlite::Result<Result<PolicyTokenHandoff, PolicyTokenError>> {
    use PolicyTokenError as Error;
    if let Err(error) = serving_role(tx) {
        return Ok(Err(error));
    }
    if !has_exact_grant(tx, module_id, &request.identity)? {
        return Ok(Err(Error::NotFound));
    }
    after_grant();
    let active = active_agent_policy_summary_conn(tx)?;
    let active_version = active.as_ref().map(|policy| policy.version);
    let proof = match request.approval_proof() {
        Ok(proof) => proof,
        Err(error) => return Ok(Err(error)),
    };
    if let Some(proof) = &proof {
        match check_approval(tx, module_id, request, proof, active_version, clock())? {
            // A second waiter cannot spend the next leg just because it has identical facts.
            Ok(leg) if Some(leg) == prepared_leg => {}
            Ok(_) => return Ok(Err(Error::ApprovalInvalid)),
            Err(error) => return Ok(Err(error)),
        }
    }
    let Some(active) = active.filter(|policy| policy.version == request.policy_version) else {
        return Ok(Err(Error::VersionNotActive));
    };
    let record = match read_record(tx, &request.identity)? {
        Ok(record) => record,
        Err(error) => return Ok(Err(error)),
    };
    let same_record = record.key == *key;
    if same_record && expires_at_ms <= clock() {
        return Ok(Err(Error::Expired));
    }
    if let Some(agent) = &record.attested_agent {
        // A changed record is a candidate for a second mint. Never pass it back
        // to the route without checking that it still belongs to this binding.
        let Some(policy) = read_policy(tx, &store.policy_token_memo, active)? else {
            return Ok(Err(Error::StoreError));
        };
        if !policy.bindings.iter().any(|binding| {
            binding.service == request.service
                && binding.identity == request.identity
                && &binding.agent == agent
        }) {
            return Ok(Err(Error::NotFound));
        }
    }
    if !same_record {
        return Ok(Ok(PolicyTokenHandoff::RecordChanged(record)));
    }
    if let (Some(proof), Some(leg)) = (proof, prepared_leg) {
        let advanced = tx.execute(
            "UPDATE broker_action_requests SET issued_legs = issued_legs + 1
             WHERE request_id = ?1 AND issued_legs = ?2",
            params![proof.request_id, leg],
        )?;
        if advanced != 1 {
            return Ok(Err(Error::ApprovalInvalid));
        }
        append_audit_tx(
            tx,
            &store.audit_key,
            &AuditRecord {
                op: AuditOp::BrokerActionIssue,
                credential_id: Some(request.identity.clone()),
                payload_hash: Some(proof.request_sha256.to_owned()),
                actor: format!("reserved:{module_id}"),
                alarm: None,
            },
        )?;
    }
    record_scoped_first_use_tx(
        tx,
        &request.identity,
        "reserved",
        Some(module_id),
        GrantOperation::PolicyToken.as_str(),
    )?;
    Ok(Ok(PolicyTokenHandoff::Released))
}
