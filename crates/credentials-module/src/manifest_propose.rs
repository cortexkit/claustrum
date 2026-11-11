//! Read-only proposal checks followed by one deadline-admitted store transaction.

use std::{sync::Arc, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use credentials_core::{
    http::ReqwestTransport,
    refresh_adapters::{
        github_app::{check_github_repository, GithubRepositoryCheck},
        HttpTransport,
    },
    store::{EncryptedStore, GhManifestProposalError, GhManifestProposalInput, SecretHomeRole},
};
use serde::Deserialize;
use serde_json::{json, Value};
use subc_protocol::Principal;
use tokio::time::Instant;

use crate::{
    federation::OutboundClient,
    manifest_identity::{check_identity, EntorhinalIdentity, GithubIdentitySource},
};

pub const OP_PROPOSE_BINDING: &str = "manifest.propose_binding";
pub const PROPOSE_DEADLINE: Duration = Duration::from_secs(60);
const APP_SLUG_LENGTH_LIMIT: usize = 100;
const AGENT_ID_LENGTH_LIMIT: usize = 128;
const REPO_PART_LENGTH_LIMIT: usize = 100;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    agent_id: String,
    app_id: i64,
    app_slug: String,
    repo: String,
}

impl Params {
    fn valid(&self) -> bool {
        let part = |s: &str| {
            (1..=REPO_PART_LENGTH_LIMIT).contains(&s.len())
                && s != "."
                && s != ".."
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        };
        (1..=AGENT_ID_LENGTH_LIMIT).contains(&self.agent_id.len())
            && self
                .agent_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            && self.app_id > 0
            && valid_app_slug(&self.app_slug)
            && self
                .repo
                .split_once('/')
                .is_some_and(|(owner, name)| part(owner) && part(name))
    }
}

fn valid_app_slug(slug: &str) -> bool {
    // GitHub App slugs use lowercase ASCII letters, digits and hyphens.
    (1..=APP_SLUG_LENGTH_LIMIT).contains(&slug.len())
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub enum ProposeAnswer {
    Reply(Value),
    InvalidParams,
}

fn refusal(code: &str, class: &str) -> ProposeAnswer {
    ProposeAnswer::Reply(json!({"error":{"code":code,"class":class}}))
}

fn store_refusal(error: GhManifestProposalError) -> ProposeAnswer {
    use GhManifestProposalError as Error;
    match error {
        Error::AlreadyBound {
            version,
            manifest_sha256,
        } => ProposeAnswer::Reply(json!({
            "error":{"code":"already_bound","class":"permanent","version":version,"manifest_sha256":manifest_sha256}
        })),
        Error::ManifestSetupIncomplete => refusal("manifest_setup_incomplete", "permanent"),
        Error::BoundToOtherAgent => refusal("bound_to_other_agent", "permanent"),
        Error::StaleBase => refusal("stale_base", "transient"),
        Error::NotReproducible => refusal("not_reproducible", "permanent"),
        Error::GithubUnavailable => refusal("github_unavailable", "transient"),
        Error::StoreError => refusal("store_error", "transient"),
    }
}

fn preflight(
    store: &EncryptedStore,
    principal: Option<&Principal>,
    params: &Value,
) -> Result<Params, ProposeAnswer> {
    if !matches!(principal, Some(Principal::Reserved { module_id }) if module_id == "plexus") {
        return Err(refusal("not_found", "permanent"));
    }
    let params: Params =
        serde_json::from_value(params.clone()).map_err(|_| ProposeAnswer::InvalidParams)?;
    if !params.valid() {
        return Err(ProposeAnswer::InvalidParams);
    }
    match store.secret_home_role() {
        SecretHomeRole::Remote { .. } | SecretHomeRole::RemoteSetupIncomplete { .. } => {
            return Err(refusal("not_found", "permanent"))
        }
        SecretHomeRole::StoreError => return Err(refusal("store_error", "transient")),
        SecretHomeRole::Single | SecretHomeRole::Home { .. } => {}
    }
    if !store.manifest_one_tap_enabled() {
        return Err(refusal("one_tap_disabled", "transient"));
    }
    store.check_gh_manifest_setup().map_err(store_refusal)?;
    Ok(params)
}

pub async fn serve(
    store: Arc<EncryptedStore>,
    outbound: Option<&OutboundClient>,
    principal: Option<&Principal>,
    params: &Value,
) -> ProposeAnswer {
    let deadline = Instant::now() + PROPOSE_DEADLINE;
    let params = match preflight(&store, principal, params) {
        Ok(params) => params,
        Err(answer) => return answer,
    };
    let Some(outbound) = outbound else {
        return refusal("identity_unavailable", "transient");
    };
    let identity = EntorhinalIdentity::new(outbound.clone());
    let http = ReqwestTransport::new();
    checked_proposal(
        store,
        params,
        &identity,
        http.as_ref()
            .map(|http| http as &dyn HttpTransport)
            .map_err(|_| ()),
        deadline,
        wall_now_ms,
    )
    .await
}

async fn checked_proposal(
    store: Arc<EncryptedStore>,
    params: Params,
    identity: &dyn GithubIdentitySource,
    http: Result<&dyn HttpTransport, ()>,
    deadline: Instant,
    clock: impl FnOnce() -> i64 + Send + 'static,
) -> ProposeAnswer {
    if Instant::now() >= deadline {
        return refusal("identity_unavailable", "transient");
    }
    let identity_result = tokio::time::timeout_at(
        deadline,
        check_identity(
            identity,
            &params.agent_id,
            params.app_id,
            &params.app_slug,
            deadline.saturating_duration_since(Instant::now()),
        ),
    )
    .await;
    // A ready future can win timeout_at's poll at the deadline itself. The stage
    // that used the remaining budget still determines the refusal code.
    if Instant::now() >= deadline {
        return refusal("identity_unavailable", "transient");
    }
    match identity_result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            return refusal(
                error.code(),
                if error.code() == "identity_mismatch" {
                    "permanent"
                } else {
                    "transient"
                },
            )
        }
        Err(_) => return refusal("identity_unavailable", "transient"),
    }
    if Instant::now() >= deadline {
        return refusal("github_unavailable", "transient");
    }
    let http = match http {
        Ok(http) => http,
        Err(()) => return refusal("github_unavailable", "transient"),
    };
    let record_id = format!("github_app:{}", params.app_slug);
    let credential = match store.github_app_oauth_for_manifest_proposal(&record_id) {
        Ok(Some(credential)) => credential,
        Ok(None) => return refusal("not_installed", "permanent"),
        Err(_) => return refusal("store_error", "transient"),
    };
    let installation_result = tokio::time::timeout_at(
        deadline,
        check_github_repository(&record_id, &credential, &params.repo, http),
    )
    .await;
    if Instant::now() >= deadline {
        return refusal("github_unavailable", "transient");
    }
    let (repo, permissions) = match installation_result {
        Ok(GithubRepositoryCheck::Found {
            full_name,
            installation_permissions,
        }) => (full_name, installation_permissions),
        Ok(GithubRepositoryCheck::NotInstalled) => return refusal("not_installed", "permanent"),
        Ok(GithubRepositoryCheck::InstallationAll) => {
            return refusal("installation_all", "permanent")
        }
        Ok(GithubRepositoryCheck::InstallationUnusable) => {
            return refusal("installation_unusable", "permanent")
        }
        Ok(GithubRepositoryCheck::InstallationTooLarge) => {
            return refusal("installation_too_large", "permanent")
        }
        Ok(GithubRepositoryCheck::GithubUnavailable) | Err(_) => {
            return refusal("github_unavailable", "transient")
        }
    };
    let prepared = store.prepare_gh_manifest_proposal(GhManifestProposalInput {
        agent_id: params.agent_id,
        app_id: params.app_id,
        app_slug: params.app_slug,
        repo,
        installation_permissions: permissions,
    });
    if Instant::now() >= deadline {
        return refusal("github_unavailable", "transient");
    }
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(error) => return store_refusal(error),
    };
    // The store checks the deadline with the writer held. Do not cancel this job:
    // an admitted transaction must commit and return its reply even after expiry.
    match tokio::task::spawn_blocking(move || {
        store.propose_gh_manifest_binding(
            &prepared,
            "reserved:plexus",
            || Instant::now() < deadline,
            clock,
        )
    })
    .await
    .unwrap_or(Err(GhManifestProposalError::StoreError))
    {
        Ok(proposal) => ProposeAnswer::Reply(json!({
            "status":"approval_required", "proposal_id":proposal.proposal_id,
            "statement_b64url":URL_SAFE_NO_PAD.encode(&proposal.statement_bytes),
            "manifest_version":proposal.base_version + 1,
            "manifest_sha256":proposal.manifest_sha256, "expires_at_ms":proposal.expires_at_ms,
        })),
        Err(error) => store_refusal(error),
    }
}

fn wall_now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[cfg(test)]
#[path = "manifest_propose_tests.rs"]
mod tests;
