//! The trusted sender boundary for secret release. Scope authority comes only from ScopeStamp.
use credentials_core::{
    agent_secret::*,
    store::{EncryptedStore, ForwardedUse, ReleaseRequest, SealedRelease},
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use subc_protocol::{
    scope::{ParentState, ScopeKind, ScopeStamp},
    Principal,
};

#[path = "secret_flow.rs"]
mod flow;
pub use flow::{
    serve_approval as serve_flow_approval,
    serve_approval_forwarded as serve_flow_approval_forwarded,
    serve_revoke as serve_revoke_flow_grants,
    serve_revoke_forwarded as serve_revoke_flow_grants_forwarded,
};

pub enum UseAnswer {
    Reply(Value),
    InvalidParams,
}

/// The closed `secret.use` key set. There is deliberately no caller-supplied agent name:
/// a sender has no trusted human name for an agent, and the approval statement is
/// signed, so the statement names the agent only by the stamp's `agent_id`. The
/// approval card (Cingulate) is what shows a person-readable name. A sender that still
/// passes `display_name` is refused as an unknown field.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    name: String,
    #[serde(default = "default_coverage")]
    coverage: String,
    stamp: Value,
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
impl Target {
    fn into_use_target(self) -> UseTarget {
        match self {
            Self::Api(t) => UseTarget::ApiKey {
                scheme: t.scheme,
                host: t.host,
                port: t.port,
                path: t.path,
            },
            Self::Login(t) => UseTarget::SiteLogin { origin: t.origin },
        }
    }
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
        Some(Principal::Reserved { module_id }) if module_id == "basal" => {
            return flow::serve_use(store, params, clock);
        }
        Some(Principal::Reserved { module_id }) if module_id == "aft" => SecretSender::Aft,
        Some(Principal::Reserved { module_id }) if module_id == "cerebellum" => {
            SecretSender::Cerebellum
        }
        _ => return UseAnswer::Reply(SecretError::NotFound.body()),
    };
    let call = match parse_use(store, sender, params) {
        Ok(call) => call,
        Err(answer) => return answer,
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

/// Parse and validate `secret.use` params from an agent sender (AFT or Cerebellum) into
/// the call the store authorizes, or the answer that ends the request. Every refusal
/// here writes its diagnostic under `sender`.
fn parse_use(
    store: &EncryptedStore,
    sender: SecretSender,
    params: &Value,
) -> Result<SecretUse, UseAnswer> {
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
        Err(_) => return Err(invalid(ValidationError::InvalidParams)),
    };
    if let Err(e) = validate_name(&params.name) {
        return Err(invalid(e));
    }
    if !matches!(params.coverage.as_str(), "scope" | "agent_and_workers") {
        return Err(invalid(ValidationError::InvalidParams));
    }
    let target = params.target.into_use_target();
    if let Err(e) = target.validate() {
        return Err(invalid(e));
    }
    // Decode the dependency's ScopeStamp, including its required scope_epoch.
    // Missing required fields are unmapped, not an invitation to infer authority.
    let stamp: ScopeStamp = match serde_json::from_value(params.stamp) {
        Ok(s) => s,
        Err(e) if e.to_string().starts_with("missing field ") => {
            store.record_secret_use_refusal(sender, None, "unmapped");
            return Err(UseAnswer::Reply(SecretError::NotFound.body()));
        }
        Err(_) => return Err(invalid(ValidationError::InvalidParams)),
    };
    // The store encodes pending approval statements as RFC 8785 canonical JSON;
    // its epoch must fit the exact JSON integer range, ending at 2^53 - 1.
    if stamp.scope_epoch > 9_007_199_254_740_991
        || stamp
            .parent
            .as_ref()
            .is_some_and(|p| p.scope_epoch > 9_007_199_254_740_991)
    {
        return Err(invalid(ValidationError::InvalidParams));
    }
    let Some((scope, worker_parent)) = asking(&stamp) else {
        store.record_secret_use_refusal(sender, None, "unmapped");
        return Err(UseAnswer::Reply(SecretError::NotFound.body()));
    };
    if params.coverage == "agent_and_workers" && scope.kind != "head" {
        store.record_secret_use_refusal(sender, None, "coverage");
        return Err(UseAnswer::InvalidParams);
    }
    Ok(SecretUse {
        name: params.name,
        sender,
        scope,
        worker_parent,
        coverage: params.coverage,
        agent_id: stamp.attributes.agent_id,
        target,
    })
}

/// The home's answer to a `secret.use` that a paired computer forwarded, before the
/// federation layer renders it.
#[derive(Debug)]
pub enum ForwardedUseAnswer<E> {
    /// The secret was released, sealed to the asking computer: sealed just now, or the
    /// stored bytes answering a retry of the same request.
    Sealed(SealedRelease),
    /// `approval_required` or a refusal body. It never holds secret material.
    Reply(Value),
    /// The call params are malformed.
    InvalidParams,
    /// Sealing failed. Nothing was consumed, audited or stored.
    SealFailed(E),
}

/// Serve a `secret.use` that `request.requester`, a paired computer, forwarded on
/// behalf of its local `sender`, parsed from `call` exactly as a local call from that
/// sender is. AFT and Cerebellum take the agent path with a required `ScopeStamp`;
/// basal takes the flow path, whose stamp must carry the flow attributes. Only grants
/// made for the asking computer release, and a release crosses only through `seal`.
///
/// The caller must already have authenticated the requester and checked its pairing,
/// its `secret_use` member grant and its announced key, on every request.
pub fn serve_forwarded<E>(
    store: &Arc<EncryptedStore>,
    sender: SecretSender,
    call: &Value,
    request: &ReleaseRequest<'_>,
    seal: impl FnOnce(&Value) -> Result<SealedRelease, E>,
    clock: impl Fn() -> i64,
) -> ForwardedUseAnswer<E> {
    if sender == SecretSender::Basal {
        return flow::serve_use_forwarded(store, call, request, seal, clock);
    }
    let call = match parse_use(store, sender, call) {
        Ok(call) => call,
        Err(answer) => return answer.into(),
    };
    forwarded_answer(store.secret_use_sealed(&call, request, seal, clock))
}

impl<E> From<UseAnswer> for ForwardedUseAnswer<E> {
    fn from(answer: UseAnswer) -> Self {
        match answer {
            UseAnswer::Reply(reply) => Self::Reply(reply),
            UseAnswer::InvalidParams => Self::InvalidParams,
        }
    }
}

fn forwarded_answer<E>(
    result: Result<Result<ForwardedUse, E>, SecretError>,
) -> ForwardedUseAnswer<E> {
    match result {
        Ok(Ok(ForwardedUse::Sealed(sealed))) => ForwardedUseAnswer::Sealed(sealed),
        Ok(Ok(ForwardedUse::Reply(reply))) => ForwardedUseAnswer::Reply(reply),
        Ok(Err(error)) => ForwardedUseAnswer::SealFailed(error),
        Err(error) => ForwardedUseAnswer::Reply(error.body()),
    }
}

#[cfg(test)]
#[path = "secret_use_tests.rs"]
mod tests;
