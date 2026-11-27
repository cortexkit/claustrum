use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rusqlite::{Connection, OptionalExtension, Transaction};
use serde_json::{json, Value};

use super::agent_policy::{
    active_agent_policy_version_conn, head_agent_policy_conn, AgentPolicySource, AgentPolicyVersion,
};
use super::gh_admin::{manifest_root_error, sql};
use super::gh_manifests::ManifestRootReadError;
use super::github_app_store::github_app_attested_agent;
use super::{
    append_audit_tx, now_ms, AuditOp, AuditRecord, EncryptedStore, RecordState, StoreOpError,
};
use crate::agent_policy::{
    github_default_rule_set, github_release_names, github_rule_set_for_named_release,
    manifest_projection, policy_sha256, signed_input, validate_signer_rule_sets, AgentPolicy,
    AgentPolicyEnvelope, Binding, PolicyError, RuleSet, AGENT_POLICY_SCHEMA_V1,
};
use crate::audit::AgentPolicyAudit;
use crate::gh_manifest::GhManifest;
use crate::signing::{prepare_ed25519, public_key_ed25519, PreparedEd25519Signature, SignError};

pub(super) struct PreparedAgentPolicy<'a> {
    credential_id: String,
    version: i64,
    bytes: &'a [u8],
    hash: String,
    signature: PreparedEd25519Signature<'a>,
}

pub(super) enum PrepareAgentPolicyError {
    Root(ManifestRootReadError),
    UnusableKey,
    RootKeyIdMismatch,
    TooLarge,
    AttestationRead(rusqlite::Error),
    IdentityAgentMismatch,
}

impl From<PrepareAgentPolicyError> for StoreOpError {
    fn from(error: PrepareAgentPolicyError) -> Self {
        match error {
            PrepareAgentPolicyError::Root(error) => manifest_root_error(error.into()),
            PrepareAgentPolicyError::UnusableKey => unusable_root(),
            PrepareAgentPolicyError::RootKeyIdMismatch => refusal("policy_root_key_id_mismatch"),
            PrepareAgentPolicyError::TooLarge => policy_error(PolicyError::TooLarge),
            PrepareAgentPolicyError::AttestationRead(error) => sql(error),
            PrepareAgentPolicyError::IdentityAgentMismatch => identity_agent_mismatch(),
        }
    }
}

pub(super) struct AgentPolicyApproval<'a> {
    pub seq: i64,
    pub source: AgentPolicySource,
    pub manifest_version: i64,
    pub actor: &'a str,
}

fn refusal(reason: &str) -> StoreOpError {
    StoreOpError::Encode(reason.into())
}

fn policy_error(error: PolicyError) -> StoreOpError {
    StoreOpError::Encode(error.to_string())
}

fn github_rules_for_derivation(release: Option<&str>) -> Result<RuleSet, StoreOpError> {
    let Some(release) = release else {
        return github_default_rule_set().map_err(policy_error);
    };
    github_rule_set_for_named_release(release).map_err(|error| match error {
        PolicyError::UnknownDefaultRelease => {
            let known = github_release_names().collect::<Vec<_>>().join(", ");
            refusal(&format!(
                "rules_release_unknown: unknown GitHub rules release; known releases: {known}"
            ))
        }
        other => policy_error(other),
    })
}

fn identity_agent_mismatch() -> StoreOpError {
    refusal("policy_identity_agent_mismatch: a GitHub App is attested for a different agent")
}

fn identity_agrees_with_attestation(
    conn: &Connection,
    binding: &Binding,
) -> rusqlite::Result<bool> {
    Ok(github_app_attested_agent(conn, &binding.identity)?
        .is_none_or(|agent| agent == binding.agent))
}

fn unusable_root() -> StoreOpError {
    StoreOpError::Corrupt("unusable manifest signing key".into())
}

fn pairing_candidate(conn: &Connection, manifest_version: i64) -> Result<GhManifest, StoreOpError> {
    let (latest, bytes): (i64, Vec<u8>) = conn
        .query_row(
            "SELECT version, manifest_bytes FROM gh_manifests ORDER BY version DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sql)?
        .ok_or(StoreOpError::NotFound)?;
    if latest != manifest_version {
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM gh_manifests WHERE version = ?1)",
                [manifest_version],
                |row| row.get(0),
            )
            .map_err(sql)?;
        return Err(if exists {
            refusal("policy_manifest_not_newest")
        } else {
            StoreOpError::NotFound
        });
    }
    let paired: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM agent_policies WHERE manifest_version = ?1)",
            [manifest_version],
            |row| row.get(0),
        )
        .map_err(sql)?;
    if paired {
        return Err(refusal("policy_manifest_already_paired"));
    }
    GhManifest::parse_reproducible(&bytes)
        .map_err(|error| StoreOpError::Corrupt(format!("stored manifest is invalid: {error}")))
}

fn next_version(head: Option<&AgentPolicy>) -> i64 {
    // The model bounds versions to 2^53−1, so adding one cannot overflow i64.
    head.map_or(1, |policy| policy.version + 1)
}

fn require_head_bindings(
    bindings: &[Binding],
    head: Option<&AgentPolicy>,
) -> Result<(), StoreOpError> {
    if head.is_some_and(|head| bindings != head.bindings) {
        return Err(refusal("policy_binding_conflict"));
    }
    Ok(())
}

pub(super) fn validate_binding_owners(bindings: &[Binding]) -> Result<(), StoreOpError> {
    for binding in bindings
        .iter()
        .filter(|binding| binding.service == "github")
    {
        let mut owners = binding
            .resources
            .iter()
            .filter_map(|resource| resource.split_once('/').map(|(owner, _)| owner));
        if let Some(first) = owners.next() {
            if owners.any(|owner| owner != first) {
                return Err(refusal("policy_binding_conflict"));
            }
        }
    }
    Ok(())
}

fn policy_text(bytes: Vec<u8>) -> Result<String, StoreOpError> {
    String::from_utf8(bytes).map_err(|_| StoreOpError::Corrupt("policy is not UTF-8".into()))
}

impl EncryptedStore {
    pub(super) fn prepare_agent_policy_in_tx<'a>(
        &self,
        tx: &Transaction<'_>,
        policy: &AgentPolicy,
        bytes: &'a [u8],
        input: &'a [u8],
    ) -> Result<PreparedAgentPolicy<'a>, PrepareAgentPolicyError> {
        use PrepareAgentPolicyError::{Root, RootKeyIdMismatch, TooLarge, UnusableKey};
        let root = self.read_gh_manifest_root_in_tx(tx).map_err(Root)?;
        let pem = std::str::from_utf8(root.record.payload.expose()).map_err(|_| UnusableKey)?;
        let signature = prepare_ed25519(pem, input).map_err(|error| match error {
            SignError::TooLarge { .. } => TooLarge,
            SignError::UnusableKey(_) => UnusableKey,
        })?;
        if signature.key_id() != policy.root_key_id {
            return Err(RootKeyIdMismatch);
        }
        for binding in &policy.bindings {
            if !identity_agrees_with_attestation(tx, binding)
                .map_err(PrepareAgentPolicyError::AttestationRead)?
            {
                return Err(PrepareAgentPolicyError::IdentityAgentMismatch);
            }
        }
        Ok(PreparedAgentPolicy {
            credential_id: root.credential_id,
            version: policy.version,
            bytes,
            hash: policy_sha256(bytes),
            signature,
        })
    }

    pub(super) fn sign_and_store_agent_policy_in_tx(
        &self,
        tx: &Transaction<'_>,
        prepared: PreparedAgentPolicy<'_>,
        approval: AgentPolicyApproval<'_>,
        clock: impl FnOnce() -> i64,
    ) -> Result<(String, [u8; 64]), StoreOpError> {
        append_audit_tx(
            tx,
            &self.audit_key,
            &AgentPolicyAudit::Sign {
                credential_id: &prepared.credential_id,
                policy_sha256: &prepared.hash,
            }
            .record(approval.actor, None),
        )
        .map_err(sql)?;
        let signed = prepared.signature.sign();
        let signature: [u8; 64] = STANDARD
            .decode(&signed.signature_b64)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| StoreOpError::Corrupt("unusable policy signature".into()))?;
        self.store_agent_policy_in_tx(
            tx,
            &AgentPolicyVersion {
                version: prepared.version,
                policy_bytes: prepared.bytes,
                policy_sha256: &prepared.hash,
                key_id: &signed.key_id,
                signature: &signature,
                signed_at_ms: clock(),
                source: approval.source,
                approval_seq: approval.seq,
                manifest_version: approval.manifest_version,
            },
        )?;
        append_audit_tx(
            tx,
            &self.audit_key,
            &AgentPolicyAudit::Store {
                version: prepared.version,
                manifest_version: approval.manifest_version,
                source: approval.source.as_str(),
                policy_sha256: &prepared.hash,
            }
            .record(approval.actor, None),
        )
        .map_err(sql)?;
        Ok((signed.key_id, signature))
    }

    pub(crate) fn sign_agent_policy_admin(
        &self,
        policy_bytes: &str,
        manifest_version: i64,
        approver: &str,
        actor: &str,
    ) -> Result<Value, StoreOpError> {
        let input = signed_input(policy_bytes.as_bytes()).map_err(policy_error)?;
        let policy = AgentPolicy::parse_canonical(policy_bytes.as_bytes()).map_err(policy_error)?;
        validate_signer_rule_sets(&policy).map_err(policy_error)?;
        validate_binding_owners(&policy.bindings)?;
        self.manifest_admin_transaction(|tx| {
            let manifest = pairing_candidate(tx, manifest_version)?;
            let head = head_agent_policy_conn(tx)?;
            if policy.version != next_version(head.as_ref()) {
                return Err(refusal("invalid_policy_version"));
            }
            if policy.github_projection() != manifest_projection(&manifest).map_err(policy_error)? {
                return Err(refusal("policy_binding_conflict"));
            }
            require_head_bindings(&policy.bindings, head.as_ref())?;

            self.sign_agent_policy_ceremony_in_tx(
                tx,
                &policy,
                policy_bytes,
                &input,
                manifest_version,
                &format!("{actor}/approver:{approver}"),
            )
        })
    }

    pub(super) fn sign_agent_policy_ceremony_in_tx(
        &self,
        tx: &Transaction<'_>,
        policy: &AgentPolicy,
        policy_bytes: &str,
        input: &[u8],
        manifest_version: i64,
        actor: &str,
    ) -> Result<Value, StoreOpError> {
        let prepared =
            self.prepare_agent_policy_in_tx(tx, policy, policy_bytes.as_bytes(), input)?;
        let hash = prepared.hash.clone();
        let approval = append_audit_tx(
            tx,
            &self.audit_key,
            &AuditRecord {
                op: AuditOp::Approval,
                credential_id: Some(prepared.credential_id.clone()),
                payload_hash: Some(hash.clone()),
                actor: actor.to_owned(),
                alarm: None,
            },
        )
        .map_err(sql)?;
        let (key_id, signature) = self.sign_and_store_agent_policy_in_tx(
            tx,
            prepared,
            AgentPolicyApproval {
                seq: approval.seq,
                source: AgentPolicySource::Ceremony,
                manifest_version,
                actor,
            },
            now_ms,
        )?;
        Ok(json!({
            "version": policy.version,
            "policy_sha256": hash,
            "envelope": AgentPolicyEnvelope::new(policy_bytes.into(), key_id, &signature),
        }))
    }

    pub(crate) fn list_agent_policies_admin(&self) -> Result<Value, StoreOpError> {
        self.store.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            let policies = tx.prepare(
                "SELECT version, policy_sha256, key_id, signed_at_ms, source, approval_seq, manifest_version \
                 FROM agent_policies ORDER BY version",
            )?.query_map([], |row| Ok(json!({
                "version": row.get::<_, i64>(0)?,
                "policy_sha256": row.get::<_, String>(1)?,
                "key_id": row.get::<_, String>(2)?,
                "signed_at_ms": row.get::<_, i64>(3)?,
                "source": row.get::<_, String>(4)?,
                "approval_seq": row.get::<_, i64>(5)?,
                "manifest_version": row.get::<_, i64>(6)?,
            })))?.collect::<rusqlite::Result<Vec<_>>>()?;
            let head = policies.last().map(|row| &row["version"]);
            let active = if head.is_some() { active_agent_policy_version_conn(&tx)? } else { None };
            tx.commit()?;
            Ok(json!({"policies": policies, "head": head, "active": active}))
        }).map_err(StoreOpError::from)
    }

    pub(crate) fn export_agent_policy_admin(
        &self,
        version: i64,
    ) -> Result<AgentPolicyEnvelope, StoreOpError> {
        let (bytes, key_id, signature) =
            self.store
                .with_conn(|conn| {
                    conn.query_row(
                "SELECT policy_bytes, key_id, signature FROM agent_policies WHERE version = ?1",
                [version],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get(1)?, row.get::<_, [u8; 64]>(2)?)),
            ).optional()
                })?
                .ok_or(StoreOpError::NotFound)?;
        Ok(AgentPolicyEnvelope::new(
            policy_text(bytes)?,
            key_id,
            &signature,
        ))
    }

    pub(crate) fn derive_agent_policy_admin(
        &self,
        manifest_version: i64,
        identities: &BTreeMap<String, String>,
        rules_release: Option<&str>,
    ) -> Result<String, StoreOpError> {
        self.store.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            let derived = (|| {
                let manifest = pairing_candidate(&tx, manifest_version)?;
                let head = head_agent_policy_conn(&tx)?;
                let mut by_agent = BTreeMap::<_, Vec<_>>::new();
                for (repo, agent) in manifest_projection(&manifest).map_err(policy_error)? {
                    by_agent.entry(agent).or_default().push(repo);
                }
                if !by_agent.keys().eq(identities.keys()) {
                    return Err(refusal("policy_identities_do_not_match_manifest_agents"));
                }

                let mut used = BTreeSet::new();
                let mut bindings = Vec::new();
                for (agent, resources) in by_agent {
                    let identity = &identities[&agent];
                    if !used.insert(identity) {
                        return Err(policy_error(PolicyError::SharedIdentity));
                    }
                    self.require_active_github_app(&tx, identity)?;
                    let binding = Binding {
                        service: "github".into(),
                        agent,
                        identity: identity.clone(),
                        resources,
                    };
                    if !identity_agrees_with_attestation(&tx, &binding).map_err(sql)? {
                        return Err(identity_agent_mismatch());
                    }
                    bindings.push(binding);
                }
                require_head_bindings(&bindings, head.as_ref())?;
                validate_binding_owners(&bindings)?;

                let root = self
                    .gh_manifest_root_in_tx(&tx)
                    .map_err(manifest_root_error)?;
                let pem = std::str::from_utf8(root.record.payload.expose())
                    .map_err(|_| unusable_root())?;
                let public = public_key_ed25519(pem).map_err(|_| unusable_root())?;
                let policy = AgentPolicy {
                    schema: AGENT_POLICY_SCHEMA_V1.into(),
                    version: next_version(head.as_ref()),
                    issued_at_unix_secs: now_ms() / 1000,
                    root_key_id: public.key_id,
                    rule_sets: match (head, rules_release) {
                        (Some(head), None) => head.rule_sets,
                        (_, release) => BTreeMap::from([(
                            "github".into(),
                            github_rules_for_derivation(release)?,
                        )]),
                    },
                    bindings,
                };
                policy_text(policy.canonical_signing_bytes().map_err(policy_error)?)
            })();
            tx.commit()?;
            Ok(derived)
        })?
    }

    pub(super) fn require_active_github_app(
        &self,
        conn: &Connection,
        id: &str,
    ) -> Result<(), StoreOpError> {
        let invalid = || refusal("policy_identity_not_active_github_app");
        if !id
            .strip_prefix("github_app:")
            .is_some_and(crate::agent_policy::valid_app_slug)
        {
            return Err(invalid());
        }
        let (version, blob) = conn.query_row(
            "SELECT record_version, envelope FROM credentials WHERE credential_id = ?1 AND state = ?2",
            rusqlite::params![id, RecordState::Active.as_str()],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        ).optional().map_err(sql)?.ok_or_else(invalid)?;
        self.open_github_app_material(id, version, &blob)?
            .map(|_| ())
            .ok_or_else(invalid)
    }
}
