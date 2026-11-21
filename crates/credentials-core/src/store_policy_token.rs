//! Local authorization and release checks for policy-narrowed GitHub App tokens.

use std::collections::BTreeMap;

use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;

use crate::{
    agent_policy::{AgentPolicy, Class, Identity},
    envelope::{self, EnvelopeError, RecordBinding},
    oauth::OAuthCredential,
    record::{CredentialKind, RecordState, VaultRecord},
};

use super::{
    agent_policy::active_agent_policy_version_conn, audit_store::record_scoped_first_use_tx,
    sha256_hex_of_bytes, store_agent_secrets::secret_home_role_conn, EncryptedStore,
    GrantOperation, SecretHomeRole,
};

const MAX_POLICY_TOKEN_REPOSITORIES: usize = 500;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTokenRequest {
    pub identity: String,
    pub service: String,
    pub kind: String,
    pub resource: String,
    pub policy_version: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyTokenError {
    NotFound,
    StoreError,
    InvalidParams,
    VersionNotActive,
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
}

pub struct PolicyTokenPlan {
    pub record: PolicyTokenRecord,
    pub repositories: Vec<String>,
    pub permissions: BTreeMap<String, String>,
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
    ) -> Result<PolicyTokenPlan, PolicyTokenError> {
        self.store
            .with_conn(|conn| {
                let tx = conn.unchecked_transaction()?;
                let result = prepare(&tx, module_id, request)?;
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
        let plaintext = envelope::open(
            &self.key,
            &record.envelope,
            &RecordBinding {
                credential_id: identity,
                record_version: record.key.record_version,
            },
        )
        .map_err(|error| match error {
            EnvelopeError::KeyMismatch { .. } => PolicyTokenError::VaultLocked,
            _ => PolicyTokenError::Corrupt,
        })?;
        let record = VaultRecord::decode(&plaintext).map_err(|_| PolicyTokenError::Corrupt)?;
        if record.payload.expose().is_empty() {
            return Err(PolicyTokenError::Corrupt);
        }
        if record.kind != CredentialKind::Oauth
            || record.refresh_adapter.as_deref() != Some("github_app")
        {
            return Err(PolicyTokenError::InstallationUnusable);
        }
        record.oauth.ok_or(PolicyTokenError::InstallationUnusable)
    }

    /// Authorize release and commit first use together. No provider request is made
    /// while holding this writer transaction.
    pub fn handoff_policy_token(
        &self,
        module_id: &str,
        request: &PolicyTokenRequest,
        key: &PolicyTokenRecordKey,
        expires_at_ms: i64,
        clock: impl FnOnce() -> i64,
    ) -> Result<PolicyTokenHandoff, PolicyTokenError> {
        self.handoff_policy_token_with_probe(module_id, request, (key, expires_at_ms), clock, || {})
    }

    pub(super) fn handoff_policy_token_with_probe(
        &self,
        module_id: &str,
        request: &PolicyTokenRequest,
        candidate: (&PolicyTokenRecordKey, i64),
        clock: impl FnOnce() -> i64,
        after_grant: impl FnOnce(),
    ) -> Result<PolicyTokenHandoff, PolicyTokenError> {
        self.fenced_write(|tx| handoff(tx, module_id, request, candidate, clock, after_grant))
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
    };
    let resources: Vec<_> = (0..501).map(|i| format!("org/r{i:03}")).collect();
    assert_eq!(
        select_repositories(&request, resources[..500].to_vec()).unwrap(),
        resources[..500]
    );
    assert_eq!(
        select_repositories(&request, resources),
        Err(PolicyTokenError::ScopeUnavailable)
    );
}

fn serving_role(conn: &Connection) -> Result<(), PolicyTokenError> {
    match secret_home_role_conn(conn) {
        SecretHomeRole::Single | SecretHomeRole::Home { .. } => Ok(()),
        SecretHomeRole::Remote { .. } | SecretHomeRole::RemoteSetupIncomplete { .. } => {
            Err(PolicyTokenError::NotFound)
        }
        SecretHomeRole::StoreError => Err(PolicyTokenError::StoreError),
    }
}

fn has_exact_grant(conn: &Connection, module_id: &str, identity: &str) -> rusqlite::Result<bool> {
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
    module_id: &str,
    request: Option<&PolicyTokenRequest>,
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
    if active_agent_policy_version_conn(conn)? != Some(request.policy_version) {
        return Ok(Err(Error::VersionNotActive));
    }
    let policy_bytes: Vec<u8> = conn.query_row(
        "SELECT policy_bytes FROM agent_policies WHERE version = ?1",
        [request.policy_version],
        |row| row.get(0),
    )?;
    let Ok(policy) = AgentPolicy::parse_canonical(&policy_bytes) else {
        return Ok(Err(Error::StoreError));
    };
    let Some(binding) = policy
        .bindings
        .into_iter()
        .find(|binding| binding.service == request.service && binding.identity == request.identity)
    else {
        return Ok(Err(Error::NotFound));
    };
    let Some(credential) = policy
        .rule_sets
        .get(&request.service)
        .and_then(|rules| rules.kinds.iter().find(|kind| kind.kind == request.kind))
        .filter(|kind| kind.class != Class::Denied && kind.identity == Identity::Agent)
        .and_then(|kind| kind.credential.as_ref())
    else {
        return Ok(Err(Error::NotFound));
    };
    let repositories = match select_repositories(request, binding.resources) {
        Ok(repositories) => repositories,
        Err(error) => return Ok(Err(error)),
    };
    Ok(
        read_record(conn, &request.identity)?.map(|record| PolicyTokenPlan {
            record,
            repositories,
            permissions: credential.github_permissions.clone(),
        }),
    )
}

fn select_repositories(
    request: &PolicyTokenRequest,
    resources: Vec<String>,
) -> Result<Vec<String>, PolicyTokenError> {
    if request.resource == "binding" && request.kind == "node_repository" {
        if resources.len() > MAX_POLICY_TOKEN_REPOSITORIES {
            return Err(PolicyTokenError::ScopeUnavailable);
        }
        // The canonical policy already orders the binding's repositories.
        Ok(resources)
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
            "SELECT state, incarnation, record_version, envelope FROM credentials WHERE credential_id = ?1",
            [identity],
            |r| Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?, r.get::<_, Vec<u8>>(3)?)),
        )
        .optional()?;
    let Some((state, incarnation, record_version, envelope)) = row else {
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
        }),
        RecordState::NeedsReauth | RecordState::Retired => Err(Error::NeedsReauth),
        RecordState::Corrupt => Err(Error::Corrupt),
    };
    Ok(result)
}

fn handoff(
    tx: &rusqlite::Transaction<'_>,
    module_id: &str,
    request: &PolicyTokenRequest,
    (key, expires_at_ms): (&PolicyTokenRecordKey, i64),
    clock: impl FnOnce() -> i64,
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
    if active_agent_policy_version_conn(tx)? != Some(request.policy_version) {
        return Ok(Err(Error::VersionNotActive));
    }
    let record = match read_record(tx, &request.identity)? {
        Ok(record) => record,
        Err(error) => return Ok(Err(error)),
    };
    if record.key != *key {
        return Ok(Ok(PolicyTokenHandoff::RecordChanged(record)));
    }
    if expires_at_ms <= clock() {
        return Ok(Err(Error::Expired));
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
