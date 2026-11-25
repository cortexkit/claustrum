use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Value};

use super::{
    agent_policy::{head_agent_policy_conn, paired_agent_policy_conn},
    agent_policy_admin::validate_binding_owners,
    append_audit_tx,
    gh_admin::sql,
    sha256_hex_of_bytes, EncryptedStore, StoreOpError,
};
use crate::{
    admin_ops::{GitHubBindingBase, GitHubBindingChange, GitHubBindingPreview},
    agent_policy::{
        manifest_projection, signed_input, validate_signer_rule_sets, AgentPolicy, Binding,
    },
    audit::{AuditOp, AuditRecord},
    gh_manifest::{GhManifest, RepositoryBindingEdit},
};

struct PreparedChange {
    preview: GitHubBindingPreview,
    manifest: GhManifest,
    policy: AgentPolicy,
    policy_bytes: String,
    policy_input: Vec<u8>,
    subject: String,
}

fn refusal(code: &str, detail: &str) -> StoreOpError {
    StoreOpError::Encode(format!("{code}: {detail}"))
}

fn conflict(detail: &str) -> StoreOpError {
    refusal("policy_binding_conflict", detail)
}

impl EncryptedStore {
    pub(crate) fn preview_github_binding_admin(
        &self,
        change: &GitHubBindingChange,
    ) -> Result<Value, StoreOpError> {
        self.store
            .with_conn(|conn| {
                let tx = conn.unchecked_transaction()?;
                let result = self
                    .prepare_github_binding(&tx, change, None)
                    .and_then(|prepared| {
                        serde_json::to_value(prepared.preview)
                            .map_err(|error| StoreOpError::Encode(error.to_string()))
                    });
                tx.commit()?;
                Ok(result)
            })
            .map_err(StoreOpError::from)?
    }

    pub(crate) fn commit_github_binding_admin(
        &self,
        change: &GitHubBindingChange,
        base: GitHubBindingBase,
        actor: &str,
    ) -> Result<Value, StoreOpError> {
        self.manifest_admin_transaction(|tx| {
            let PreparedChange {
                preview,
                manifest,
                policy,
                policy_bytes,
                policy_input,
                subject,
            } = self.prepare_github_binding(tx, change, Some(base))?;
            let manifest_bytes =
                String::from_utf8(manifest.to_bytes()).expect("manifest serialization is UTF-8");
            let actor = format!("{actor}/approver:operator");
            let signed_manifest =
                self.sign_gh_manifest_ceremony_in_tx(tx, &manifest, &manifest_bytes, &actor)?;
            let signed_policy = self.sign_agent_policy_ceremony_in_tx(
                tx,
                &policy,
                &policy_bytes,
                &policy_input,
                manifest.version(),
                &actor,
            )?;
            let preview_bytes = serde_json::to_vec(&preview)
                .map_err(|error| StoreOpError::Encode(error.to_string()))?;
            append_audit_tx(
                tx,
                &self.audit_key,
                &AuditRecord {
                    op: AuditOp::GhBindingChange,
                    credential_id: Some(subject),
                    payload_hash: Some(sha256_hex_of_bytes(&preview_bytes)),
                    actor,
                    alarm: None,
                },
            )
            .map_err(sql)?;
            Ok(json!({"manifest": signed_manifest, "policy": signed_policy, "change": preview}))
        })
    }

    fn prepare_github_binding(
        &self,
        conn: &Connection,
        change: &GitHubBindingChange,
        expected: Option<GitHubBindingBase>,
    ) -> Result<PreparedChange, StoreOpError> {
        let manifest_row: Option<(i64, Vec<u8>)> = conn
            .query_row(
                "SELECT version, manifest_bytes FROM gh_manifests ORDER BY version DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sql)?;
        let head = head_agent_policy_conn(conn)?;
        if expected.is_some_and(|base| {
            manifest_row.as_ref().map(|row| row.0) != Some(base.manifest_version)
                || head.as_ref().map(|policy| policy.version) != Some(base.policy_version)
        }) {
            return Err(refusal(
                "stale_base",
                "the signed pair changed; preview the binding change again",
            ));
        }
        let Some((manifest_version, manifest_bytes)) = manifest_row else {
            return Err(refusal("not_found", "no signed manifest and policy pair"));
        };
        let unpaired = || {
            conflict("the newest manifest is unpaired; finish it with ck auth policy sign first")
        };
        let mut policy = head.ok_or_else(unpaired)?;
        let base = GitHubBindingBase {
            manifest_version,
            policy_version: policy.version,
        };
        if paired_agent_policy_conn(conn, manifest_version)
            .map_err(sql)?
            .is_none_or(|paired| paired.version != policy.version)
        {
            return Err(unpaired());
        }
        let manifest = GhManifest::parse_reproducible(&manifest_bytes).map_err(|error| {
            StoreOpError::Corrupt(format!("stored manifest is invalid: {error}"))
        })?;
        if manifest.version() != manifest_version
            || manifest_projection(&manifest).map_err(|error| conflict(&error.to_string()))?
                != policy.github_projection()
        {
            return Err(conflict("the stored manifest and policy bindings disagree"));
        }
        let now = super::now_ms() / 1000;
        let before = policy.bindings.clone();
        let successor;
        let subject;
        match change {
            GitHubBindingChange::Remove { repo } | GitHubBindingChange::Move { repo, .. } => {
                let repo = repo.to_ascii_lowercase();
                let (source, resource) = policy
                    .bindings
                    .iter()
                    .enumerate()
                    .find_map(|(index, binding)| {
                        binding
                            .resources
                            .binary_search(&repo)
                            .ok()
                            .map(|resource| (index, resource))
                    })
                    .ok_or_else(|| refusal("not_found", "repository has no GitHub binding"))?;
                if let GitHubBindingChange::Move { to, .. } = change {
                    let destination = policy.bindings.iter().position(|binding| binding.agent == *to)
                        .ok_or_else(|| refusal("not_found", "destination agent has no GitHub binding; give it its first repository through one-tap approval, then move"))?;
                    if source == destination {
                        return Err(conflict(
                            "repository is already bound to the destination agent",
                        ));
                    }
                    policy.bindings[destination].resources.push(repo.clone());
                    policy.bindings[destination].resources.sort_unstable();
                    successor = manifest.operator_successor(
                        RepositoryBindingEdit::Move {
                            repo: &repo,
                            agent: to,
                        },
                        now,
                    );
                    subject = format!("gh-binding|move|{repo}");
                } else {
                    successor =
                        manifest.operator_successor(RepositoryBindingEdit::Remove(&repo), now);
                    subject = format!("gh-binding|remove|{repo}");
                }
                policy.bindings[source].resources.remove(resource);
                if policy.bindings[source].resources.is_empty() {
                    policy.bindings.remove(source);
                }
            }
            GitHubBindingChange::App { agent, slug } => {
                let index = policy
                    .bindings
                    .iter()
                    .position(|binding| binding.agent == *agent)
                    .ok_or_else(|| refusal("not_found", "agent has no GitHub binding"))?;
                let identity = format!("github_app:{slug}");
                if policy
                    .bindings
                    .iter()
                    .any(|binding| binding.identity == identity)
                {
                    return Err(conflict("App is already bound in the policy"));
                }
                self.require_active_github_app(conn, &identity)
                    .map_err(|error| match &error {
                        StoreOpError::Encode(code)
                            if code == "policy_identity_not_active_github_app" =>
                        {
                            refusal(
                                "policy_identity_not_active_github_app",
                                "expected the slug of an active GitHub App record",
                            )
                        }
                        _ => error,
                    })?;
                if super::github_app_store::github_app_attested_agent(conn, &identity)
                    .map_err(sql)?
                    .is_some_and(|attested| attested != *agent)
                {
                    return Err(refusal(
                        "policy_identity_agent_mismatch",
                        "App is attested to a different agent",
                    ));
                }
                policy.bindings[index].identity = identity;
                successor = manifest.operator_successor(RepositoryBindingEdit::Keep, now);
                subject = format!("gh-binding|app|{agent}");
            }
        }
        let manifest = successor.map_err(|error| conflict(&error.to_string()))?;
        policy.version += 1;
        policy.issued_at_unix_secs = now;
        validate_binding_owners(&policy.bindings)
            .map_err(|_| conflict("an agent's repositories must share one GitHub owner"))?;
        validate_signer_rule_sets(&policy)
            .map_err(|error| StoreOpError::Encode(error.to_string()))?;
        if manifest_projection(&manifest).map_err(|error| conflict(&error.to_string()))?
            != policy.github_projection()
        {
            return Err(conflict("successor manifest and policy bindings disagree"));
        }
        let preview = GitHubBindingPreview {
            base,
            old: changed_bindings(&before, &policy.bindings),
            new: changed_bindings(&policy.bindings, &before),
        };
        let policy_bytes = String::from_utf8(
            policy
                .canonical_signing_bytes()
                .map_err(|error| StoreOpError::Encode(error.to_string()))?,
        )
        .expect("policy serialization is UTF-8");
        let policy_input = signed_input(policy_bytes.as_bytes())
            .map_err(|error| StoreOpError::Encode(error.to_string()))?;
        Ok(PreparedChange {
            preview,
            manifest,
            policy,
            policy_bytes,
            policy_input,
            subject,
        })
    }
}

fn changed_bindings(from: &[Binding], other: &[Binding]) -> Vec<Binding> {
    from.iter()
        .filter(|binding| {
            other
                .binary_search_by_key(&binding.agent.as_str(), |row| row.agent.as_str())
                .ok()
                .is_none_or(|index| other[index] != **binding)
        })
        .cloned()
        .collect()
}
