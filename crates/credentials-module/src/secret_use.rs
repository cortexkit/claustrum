//! The trusted sender boundary for secret release. Scope authority comes only from ScopeStamp.
use credentials_core::{agent_secret::*, store::EncryptedStore};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use subc_protocol::{
    scope::{ParentState, ScopeKind, ScopeStamp},
    Principal,
};

pub enum UseAnswer {
    Reply(Value),
    InvalidParams,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    name: String,
    #[serde(default = "default_coverage")]
    coverage: String,
    stamp: Value,
    display_name: String,
    target: Target,
}
fn default_coverage() -> String {
    "scope".to_owned()
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Target {
    Api(ApiTarget),
    Login(LoginTarget),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiTarget {
    scheme: String,
    host: String,
    #[serde(default = "default_port")]
    port: u16,
    path: String,
}
fn default_port() -> u16 {
    443
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginTarget {
    origin: String,
}

fn owner(principal: &Principal) -> String {
    match principal {
        Principal::Reserved { module_id } => format!("reserved:{module_id}"),
        Principal::Direct => "direct".into(),
        Principal::Unverified => "unverified".into(),
    }
}

fn asking(stamp: &ScopeStamp) -> Option<(AskingScope, Option<AskingScope>)> {
    if stamp.attributes.flow_id.is_some() {
        return None;
    }
    let scope = AskingScope {
        owner: owner(&stamp.owner),
        kind: match stamp.kind {
            ScopeKind::Head => "head",
            ScopeKind::Worker => "worker",
            ScopeKind::Ephemeral => "ephemeral",
        }
        .into(),
        scope_ref: stamp.scope_ref.clone(),
        epoch: stamp.scope_epoch,
    };
    let parent = stamp
        .parent
        .as_ref()
        .filter(|parent| {
            stamp.parent_state == Some(ParentState::Linked)
                && parent.scope_epoch == stamp.scope_epoch
        })
        .map(|parent| AskingScope {
            owner: owner(&parent.owner),
            kind: "head".into(),
            scope_ref: parent.scope_ref.clone(),
            epoch: parent.scope_epoch,
        });
    match stamp.kind {
        ScopeKind::Head => Some((scope, None)),
        ScopeKind::Worker => Some((scope, parent)),
        ScopeKind::Ephemeral => parent
            .filter(|p| p.owner == "reserved:prefrontal-core")
            .map(|p| (p, None)),
    }
}

/// Caller admission precedes all parsing and all diagnostics, including malformed params.
pub fn serve(
    store: &Arc<EncryptedStore>,
    principal: Option<&Principal>,
    params: &Value,
    clock: impl Fn() -> i64,
) -> UseAnswer {
    let sender = match principal {
        Some(Principal::Reserved { module_id }) if module_id == "aft" => SecretSender::Aft,
        Some(Principal::Reserved { module_id }) if module_id == "cerebellum" => {
            SecretSender::Cerebellum
        }
        _ => return UseAnswer::Reply(SecretError::NotFound.body()),
    };
    let invalid = |error: ValidationError| {
        store.record_secret_use_refusal(
            sender,
            None,
            if error == ValidationError::LimitExceeded {
                "limit"
            } else {
                "grammar"
            },
        );
        match error {
            ValidationError::InvalidParams => UseAnswer::InvalidParams,
            ValidationError::LimitExceeded => UseAnswer::Reply(SecretError::LimitExceeded.body()),
        }
    };
    let params: Params = match serde_json::from_value(params.clone()) {
        Ok(p) => p,
        Err(_) => return invalid(ValidationError::InvalidParams),
    };
    if let Err(e) =
        validate_name(&params.name).and_then(|_| validate_display_name(&params.display_name))
    {
        return invalid(e);
    }
    if !matches!(params.coverage.as_str(), "scope" | "agent_and_workers") {
        return invalid(ValidationError::InvalidParams);
    }
    let target = match params.target {
        Target::Api(t) => UseTarget::ApiKey {
            scheme: t.scheme,
            host: t.host,
            port: t.port,
            path: t.path,
        },
        Target::Login(t) => UseTarget::SiteLogin { origin: t.origin },
    };
    if let Err(e) = target.validate() {
        return invalid(e);
    }
    // Decode the dependency's ScopeStamp, including its required scope_epoch.
    // Missing required fields are unmapped, not an invitation to infer authority.
    let stamp: ScopeStamp = match serde_json::from_value(params.stamp) {
        Ok(s) => s,
        Err(e) if e.to_string().starts_with("missing field ") => {
            store.record_secret_use_refusal(sender, None, "unmapped");
            return UseAnswer::Reply(SecretError::NotFound.body());
        }
        Err(_) => return invalid(ValidationError::InvalidParams),
    };
    // The store encodes pending approval statements as RFC 8785 canonical JSON;
    // its epoch must fit the exact JSON integer range, ending at 2^53 - 1.
    if stamp.scope_epoch > 9_007_199_254_740_991
        || stamp
            .parent
            .as_ref()
            .is_some_and(|p| p.scope_epoch > 9_007_199_254_740_991)
    {
        return invalid(ValidationError::InvalidParams);
    }
    let Some((scope, worker_parent)) = asking(&stamp) else {
        store.record_secret_use_refusal(sender, None, "unmapped");
        return UseAnswer::Reply(SecretError::NotFound.body());
    };
    if params.coverage == "agent_and_workers" && scope.kind != "head" {
        store.record_secret_use_refusal(sender, None, "coverage");
        return UseAnswer::InvalidParams;
    }
    let call = SecretUse {
        name: params.name,
        sender,
        scope,
        worker_parent,
        coverage: params.coverage,
        agent_id: stamp.attributes.agent_id,
        display_name: params.display_name,
        target,
    };
    match store.secret_use(&call, clock) {
        Ok(outcome) => {
            if let Some((id, now)) = outcome.last_use {
                let store = Arc::clone(store);
                tokio::task::spawn_blocking(move || store.secret_use_last_use(&id, now));
            }
            UseAnswer::Reply(outcome.reply)
        }
        Err(error) => UseAnswer::Reply(error.body()),
    }
}

#[cfg(test)]
#[path = "secret_use_tests.rs"]
mod tests;
