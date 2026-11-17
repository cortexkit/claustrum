//! The trusted sender boundary for secret release. Scope authority comes only from ScopeStamp.
use base64::Engine as _;
use credentials_core::{
    agent_secret::*,
    store::{EncryptedStore, ForwardedUse, ReleaseRequest, SealedRelease},
};
use serde::{Deserialize, Serialize};
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

enum ParsedUse {
    Named(SecretUse),
    ByTarget(SecretUseByTarget),
}

fn is_target_only(params: &Value) -> bool {
    params.get("name").is_none() && params.get("target").is_some()
}

/// The closed `secret.use` key set. There is deliberately no caller-supplied agent name:
/// a sender has no trusted human name for an agent, and the approval statement is
/// signed, so the statement names the agent only by the stamp's attribution: a worker's
/// `on_behalf_of_agent`, otherwise `agent_id`. The approval card shows a person-readable
/// name. A sender that still passes `display_name` is refused as an unknown field.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    name: Option<String>,
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
    Local(LocalTarget),
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
            Self::Local(_) => unreachable!("local targets are parsed before legacy targets"),
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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LocalTarget {
    program: String,
    r#use: String,
    target: Value,
    command: String,
    workdir: String,
    purpose: String,
    expects: String,
    undoable: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SshParams {
    key: String,
    stamp: Value,
    #[serde(default = "default_coverage")]
    coverage: String,
    target: Value,
    command: String,
    workdir: String,
    data: String,
}

pub(crate) fn is_local_use(params: &Value) -> bool {
    params
        .get("target")
        .and_then(Value::as_object)
        .is_some_and(|t| {
            t.contains_key("program")
                || t.contains_key("use")
                || (!t.contains_key("scheme")
                    && !t.contains_key("origin")
                    && [
                        "target", "command", "workdir", "purpose", "expects", "undoable",
                    ]
                    .iter()
                    .any(|key| t.contains_key(*key)))
        })
}

fn aft(principal: Option<&Principal>) -> bool {
    matches!(principal, Some(Principal::Reserved { module_id }) if module_id == "aft")
}

fn local_body(error: SecretError) -> Value {
    let mut body = error.body();
    if error == SecretError::LimitExceeded {
        body["error"]["class"] = "permanent".into();
    }
    body
}

fn local_error(store: &EncryptedStore, name: &str, error: SecretError) -> UseAnswer {
    store.record_secret_use_refusal(
        SecretSender::Aft,
        Some(name),
        if error == SecretError::LimitExceeded {
            "limit"
        } else {
            "grammar"
        },
    );
    match error {
        SecretError::InvalidParams => UseAnswer::InvalidParams,
        _ => UseAnswer::Reply(local_body(error)),
    }
}

fn local_enabled(store: &EncryptedStore) -> Result<(), UseAnswer> {
    // This early refusal avoids parsing or forwarding while off. The store's
    // in-transaction check remains authoritative if the switch changes meanwhile.
    match store.secret_local_programs_enabled() {
        Ok(true) => Ok(()),
        Ok(false) => Err(UseAnswer::Reply(
            SecretError::SecretLocalProgramsDisabled.body(),
        )),
        Err(error) => Err(UseAnswer::Reply(error.body())),
    }
}

fn local_scope(
    store: &EncryptedStore,
    name: &str,
    stamp: Value,
    coverage: &str,
) -> Result<(AskingScope, Option<AskingScope>, Option<String>), UseAnswer> {
    if coverage != "scope" {
        return Err(local_error(store, name, SecretError::InvalidParams));
    }
    let stamp: ScopeStamp = match serde_json::from_value(stamp) {
        Ok(s) => s,
        Err(e) if e.to_string().starts_with("missing field ") => {
            store.record_secret_use_refusal(SecretSender::Aft, Some(name), "unmapped");
            return Err(UseAnswer::Reply(SecretError::NotFound.body()));
        }
        Err(_) => return Err(local_error(store, name, SecretError::InvalidParams)),
    };
    if stamp.scope_epoch > MAX_SECRET_JSON_INTEGER
        || stamp
            .parent
            .as_ref()
            .is_some_and(|p| p.scope_epoch > MAX_SECRET_JSON_INTEGER)
    {
        return Err(local_error(store, name, SecretError::InvalidParams));
    }
    let Some((scope, parent)) = asking(&stamp) else {
        store.record_secret_use_refusal(SecretSender::Aft, Some(name), "unmapped");
        return Err(UseAnswer::Reply(SecretError::NotFound.body()));
    };
    let agent = if stamp.kind == ScopeKind::Worker {
        stamp.attributes.on_behalf_of_agent
    } else {
        stamp.attributes.agent_id
    };
    Ok((scope, parent, agent))
}

fn parse_local_use(
    store: &EncryptedStore,
    sender: SecretSender,
    params: &Value,
) -> Result<SecretUse, UseAnswer> {
    if sender != SecretSender::Aft {
        return Err(UseAnswer::Reply(SecretError::NotFound.body()));
    }
    let params: Params =
        serde_json::from_value(params.clone()).map_err(|_| UseAnswer::InvalidParams)?;
    let name = params.name.ok_or(UseAnswer::InvalidParams)?;
    validate_name(&name).map_err(|_| UseAnswer::InvalidParams)?;
    let Target::Local(target) = params.target else {
        return Err(UseAnswer::InvalidParams);
    };
    local_enabled(store)?;
    let (scope, worker_parent, agent_id) =
        local_scope(store, &name, params.stamp, &params.coverage)?;
    let local =
        LocalUse::from_value(&serde_json::to_value(target).expect("local target serializes"))
            .map_err(|e| local_error(store, &name, e))?;
    if local.is_ssh() {
        return Err(local_error(store, &name, SecretError::InvalidParams));
    }
    Ok(SecretUse {
        name,
        sender,
        scope,
        worker_parent,
        coverage: params.coverage,
        agent_id,
        target: UseTarget::LocalProgram(local),
    })
}

pub(crate) fn parse_ssh_sign(
    store: &EncryptedStore,
    params: &Value,
) -> Result<SecretSshSign, UseAnswer> {
    let params: SshParams =
        serde_json::from_value(params.clone()).map_err(|_| UseAnswer::InvalidParams)?;
    credentials_core::agent_secret::validate_ssh_card_key_id(&params.key)
        .map_err(|_| UseAnswer::InvalidParams)?;
    local_enabled(store)?;
    let (scope, worker_parent, agent_id) =
        local_scope(store, &params.key, params.stamp, &params.coverage)?;
    let local_use = LocalUse::from_value(&serde_json::json!({"program":"ssh","use":"ssh_sign","target":params.target,"command":params.command,"workdir":params.workdir}))
        .map_err(|e| local_error(store, &params.key, e))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&params.data)
        .map_err(|_| local_error(store, &params.key, SecretError::InvalidParams))?;
    let data = SshUserauth::parse(bytes).map_err(|e| local_error(store, &params.key, e))?;
    if data.user() != local_use.user() {
        return Err(local_error(store, &params.key, SecretError::InvalidParams));
    }
    Ok(SecretSshSign {
        key: params.key,
        sender: SecretSender::Aft,
        scope,
        worker_parent,
        coverage: params.coverage,
        agent_id,
        local_use,
        data,
    })
}

pub fn serve_ssh_sign(
    store: &Arc<EncryptedStore>,
    principal: Option<&Principal>,
    params: &Value,
    clock: impl Fn() -> i64,
) -> UseAnswer {
    if !aft(principal) {
        return UseAnswer::Reply(SecretError::NotFound.body());
    }
    let call = match parse_ssh_sign(store, params) {
        Ok(call) => call,
        Err(answer) => return answer,
    };
    match store.secret_ssh_sign(&call, clock) {
        Ok(outcome) => UseAnswer::Reply(outcome.reply),
        Err(error) => match error {
            SecretError::InvalidParams => UseAnswer::InvalidParams,
            _ => UseAnswer::Reply(local_body(error)),
        },
    }
}

pub fn serve_ssh_sign_forwarded<E>(
    store: &Arc<EncryptedStore>,
    sender: SecretSender,
    params: &Value,
    request: &ReleaseRequest<'_>,
    seal: impl FnOnce(&Value) -> Result<SealedRelease, E>,
    clock: impl Fn() -> i64,
) -> ForwardedUseAnswer<E> {
    if sender != SecretSender::Aft {
        return ForwardedUseAnswer::Reply(SecretError::NotFound.body());
    }
    let call = match parse_ssh_sign(store, params) {
        Ok(call) => call,
        Err(answer) => return answer.into(),
    };
    local_forwarded_answer(store.secret_ssh_sign_sealed(&call, request, seal, clock))
}

pub(crate) fn preflight_forward(
    store: &EncryptedStore,
    sender: SecretSender,
    params: &Value,
    ssh: bool,
) -> Result<(), UseAnswer> {
    if ssh {
        let p: SshParams =
            serde_json::from_value(params.clone()).map_err(|_| UseAnswer::InvalidParams)?;
        if !p.key.starts_with("signing:")
            || credentials_core::store::validate_deposit_credential_id(&p.key).is_err()
        {
            return Err(UseAnswer::InvalidParams);
        }
    } else if is_local_use(params) {
        if sender != SecretSender::Aft {
            return Err(UseAnswer::Reply(SecretError::NotFound.body()));
        }
        let p: Params =
            serde_json::from_value(params.clone()).map_err(|_| UseAnswer::InvalidParams)?;
        let name = p.name.ok_or(UseAnswer::InvalidParams)?;
        validate_name(&name).map_err(|_| UseAnswer::InvalidParams)?;
        if !matches!(p.target, Target::Local(_)) {
            return Err(UseAnswer::InvalidParams);
        }
    } else {
        return Ok(());
    }
    // The asking computer performs only admission, closed params and its switch.
    // Stamp, target and data checks belong to the home after its own switch check.
    local_enabled(store)
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
    // Approvals bind to a head, worker or ephemeral scope on this computer. Any other
    // kind, such as a federated agent identity from another computer, has no approval
    // shape yet, so it maps to nothing and the use is refused as unmapped.
    let kind = match stamp.kind {
        ScopeKind::Head => "head",
        ScopeKind::Worker => "worker",
        ScopeKind::Ephemeral => "ephemeral",
        _ => return None,
    };
    let scope = AskingScope {
        owner: owner(&stamp.owner),
        kind: kind.into(),
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
            .filter(|p| PREFRONTAL_OWNERS.contains(&p.owner.as_str()))
            .map(|p| (p, None)),
        _ => None,
    }
}

/// The module that owns agent heads, under its current id and its id before the rename to
/// `prefrontal`. Both are accepted so the rename needs no vault restart at the cut; the
/// old id goes in the build after the cut.
const PREFRONTAL_OWNERS: [&str; 2] = ["reserved:prefrontal", "reserved:prefrontal-core"];

/// Caller admission precedes all parsing and all diagnostics, including malformed params.
pub fn serve(
    store: &Arc<EncryptedStore>,
    principal: Option<&Principal>,
    params: &Value,
    clock: impl Fn() -> i64,
) -> UseAnswer {
    if (is_local_use(params) || is_target_only(params)) && !aft(principal) {
        return UseAnswer::Reply(SecretError::NotFound.body());
    }
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
    let result = match call {
        ParsedUse::Named(call) => store.secret_use(&call, clock),
        ParsedUse::ByTarget(call) => store.secret_use_by_target(&call, clock),
    };
    match result {
        Ok(outcome) => {
            if let Some((id, now)) = outcome.last_use {
                let store = Arc::clone(store);
                tokio::task::spawn_blocking(move || store.secret_use_last_use(&id, now));
            }
            UseAnswer::Reply(outcome.reply)
        }
        Err(error) if is_local_use(params) => match error {
            SecretError::InvalidParams => UseAnswer::InvalidParams,
            _ => UseAnswer::Reply(local_body(error)),
        },
        Err(error) => UseAnswer::Reply(error.body()),
    }
}

/// The forwardable form of a secret call from `principal`, or `None` when the caller is
/// not admitted to `method` (the local serve functions then refuse it with `not_found`,
/// before anything is looked up). Admission is the local one: `secret.use` from AFT,
/// Cerebellum or basal, `secret.ssh_sign` from AFT only, and the two flow ops from basal only.
pub fn sender_call<'a>(
    method: &str,
    principal: Option<&Principal>,
    params: &'a Value,
) -> Option<crate::federation::remote_read::SecretCall<'a>> {
    use crate::federation::remote_read::SecretCall;
    let Some(Principal::Reserved { module_id }) = principal else {
        return None;
    };
    if method == "secret.use"
        && (is_local_use(params) || is_target_only(params))
        && module_id != "aft"
    {
        return None;
    }
    match (method, module_id.as_str()) {
        ("secret.ssh_sign", "aft") => Some(SecretCall::SshSign(params)),
        ("secret.use", "aft") => Some(SecretCall::Use {
            sender: SecretSender::Aft,
            call: params,
        }),
        ("secret.use", "cerebellum") => Some(SecretCall::Use {
            sender: SecretSender::Cerebellum,
            call: params,
        }),
        ("secret.use", "basal") => Some(SecretCall::Use {
            sender: SecretSender::Basal,
            call: params,
        }),
        ("secret.request_flow_approval", "basal") => Some(SecretCall::RequestFlowApproval(params)),
        ("secret.revoke_flow_grants", "basal") => Some(SecretCall::RevokeFlowGrants(params)),
        _ => None,
    }
}

/// Parse and validate `secret.use` params from an agent sender (AFT or Cerebellum) into
/// the call the store authorizes, or the answer that ends the request. Every refusal
/// on the legacy path writes its diagnostic under `sender`. Local targets have silent
/// admission, closed-params and feature-switch checks before scope diagnostics.
fn parse_use(
    store: &EncryptedStore,
    sender: SecretSender,
    params: &Value,
) -> Result<ParsedUse, UseAnswer> {
    if is_local_use(params) {
        return parse_local_use(store, sender, params).map(ParsedUse::Named);
    }
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
    if params.get("name").is_some_and(|name| !name.is_string()) {
        return Err(invalid(ValidationError::InvalidParams));
    }
    let params: Params = match serde_json::from_value(params.clone()) {
        Ok(p) => p,
        Err(_) => return Err(invalid(ValidationError::InvalidParams)),
    };
    if let Some(name) = &params.name {
        if let Err(e) = validate_name(name) {
            return Err(invalid(e));
        }
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
    let call = SecretUseByTarget {
        sender,
        scope,
        worker_parent,
        coverage: params.coverage,
        // Worker attribution names its head for display, without inheriting the
        // head's identity or changing the scope to which approval is bound.
        agent_id: if stamp.kind == ScopeKind::Worker {
            stamp.attributes.on_behalf_of_agent
        } else {
            stamp.attributes.agent_id
        },
        target,
    };
    match params.name {
        Some(name) => Ok(ParsedUse::Named(call.with_name(name))),
        None if sender == SecretSender::Aft && matches!(call.target, UseTarget::ApiKey { .. }) => {
            Ok(ParsedUse::ByTarget(call))
        }
        None => Err(UseAnswer::Reply(SecretError::NotFound.body())),
    }
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
    if is_target_only(call) && sender != SecretSender::Aft {
        return ForwardedUseAnswer::Reply(SecretError::NotFound.body());
    }
    if is_local_use(call) {
        let call = match parse_local_use(store, sender, call) {
            Ok(call) => call,
            Err(answer) => return answer.into(),
        };
        return local_forwarded_answer(store.secret_use_sealed(&call, request, seal, clock));
    }
    if sender == SecretSender::Basal {
        return flow::serve_use_forwarded(store, call, request, seal, clock);
    }
    let call = match parse_use(store, sender, call) {
        Ok(call) => call,
        Err(answer) => return answer.into(),
    };
    forwarded_answer(match call {
        ParsedUse::Named(call) => store.secret_use_sealed(&call, request, seal, clock),
        ParsedUse::ByTarget(call) => store.secret_use_by_target_sealed(&call, request, seal, clock),
    })
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

fn local_forwarded_answer<E>(
    result: Result<Result<ForwardedUse, E>, SecretError>,
) -> ForwardedUseAnswer<E> {
    match result {
        Err(SecretError::InvalidParams) => ForwardedUseAnswer::InvalidParams,
        Err(error) => ForwardedUseAnswer::Reply(local_body(error)),
        result => forwarded_answer(result),
    }
}

#[cfg(test)]
#[path = "secret_use_tests.rs"]
mod tests;
