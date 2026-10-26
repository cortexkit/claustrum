//! Basal's install-time consent and flow-only release boundary.
use super::*;
use credentials_core::store::SecretUseOutcome;
use serde_json::json;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalParams {
    name: String,
    flow: FlowIdentity,
    target: Target,
    methods: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UseParams {
    name: String,
    stamp: Value,
    target: Target,
    method: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeParams {
    flow_install_id: String,
    flow_version: Option<u64>,
}

fn admitted(principal: Option<&Principal>) -> bool {
    matches!(principal, Some(Principal::Reserved { module_id }) if module_id == "basal")
}

fn invalid(store: &EncryptedStore, error: ValidationError) -> UseAnswer {
    store.record_secret_use_refusal(
        SecretSender::Basal,
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
}

fn outcome(
    store: &Arc<EncryptedStore>,
    result: Result<SecretUseOutcome, SecretError>,
) -> UseAnswer {
    match result {
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

pub fn serve_approval(
    store: &Arc<EncryptedStore>,
    principal: Option<&Principal>,
    params: &Value,
    clock: impl Fn() -> i64,
) -> UseAnswer {
    if !admitted(principal) {
        return UseAnswer::Reply(SecretError::NotFound.body());
    }
    let parsed: ApprovalParams = match serde_json::from_value(params.clone()) {
        Ok(p) => p,
        Err(_) => return invalid(store, ValidationError::InvalidParams),
    };
    let target = parsed.target.into_use_target();
    let validation = (|| {
        validate_name(&parsed.name)?;
        parsed.flow.validate()?;
        target.validate()?;
        // Even a null methods key is forbidden for a login target.
        if matches!(target, UseTarget::SiteLogin { .. }) && params.get("methods").is_some() {
            return Err(ValidationError::InvalidParams);
        }
        validate_flow_methods(&target, parsed.methods.as_deref())
    })();
    let methods = match validation {
        Ok(methods) => methods,
        Err(error) => return invalid(store, error),
    };
    outcome(
        store,
        store.secret_request_flow_approval(
            &SecretFlowApproval {
                name: parsed.name,
                flow: parsed.flow,
                target,
                methods,
            },
            clock,
        ),
    )
}

// Admission is performed by secret_use::serve before entering the flow parser.
pub(super) fn serve_use(
    store: &Arc<EncryptedStore>,
    params: &Value,
    clock: impl Fn() -> i64,
) -> UseAnswer {
    let parsed: UseParams = match serde_json::from_value(params.clone()) {
        Ok(p) => p,
        Err(_) => return invalid(store, ValidationError::InvalidParams),
    };
    let target = parsed.target.into_use_target();
    let validation = (|| {
        validate_name(&parsed.name)?;
        target.validate()?;
        if matches!(target, UseTarget::SiteLogin { .. }) && params.get("method").is_some() {
            return Err(ValidationError::InvalidParams);
        }
        let methods = parsed.method.as_ref().map(std::slice::from_ref);
        validate_flow_methods(&target, methods)?;
        Ok(())
    })();
    if let Err(error) = validation {
        return invalid(store, error);
    }
    let stamp: ScopeStamp = match serde_json::from_value(parsed.stamp) {
        Ok(stamp) => stamp,
        Err(error) if error.to_string().starts_with("missing field ") => {
            store.record_secret_use_refusal(SecretSender::Basal, None, "unmapped");
            return UseAnswer::Reply(SecretError::NotFound.body());
        }
        Err(_) => return invalid(store, ValidationError::InvalidParams),
    };
    if stamp.scope_epoch > MAX_SECRET_JSON_INTEGER
        || stamp
            .parent
            .as_ref()
            .is_some_and(|p| p.scope_epoch > MAX_SECRET_JSON_INTEGER)
        || stamp
            .attributes
            .flow_version
            .is_some_and(|v| v > MAX_SECRET_JSON_INTEGER)
    {
        return invalid(store, ValidationError::InvalidParams);
    }
    let attributes = stamp.attributes;
    let (Some(flow_id), Some(version), Some(code_hash), Some(install_id)) = (
        attributes.flow_id,
        attributes.flow_version,
        attributes.flow_code_hash,
        attributes.flow_install_id,
    ) else {
        store.record_secret_use_refusal(SecretSender::Basal, None, "flow_identity");
        return UseAnswer::Reply(SecretError::NotFound.body());
    };
    outcome(
        store,
        store.secret_flow_use(
            &SecretFlowUse {
                name: parsed.name,
                flow: FlowIdentity {
                    flow_id,
                    version,
                    code_hash,
                    install_id,
                },
                target,
                method: parsed.method,
            },
            clock,
        ),
    )
}

pub fn serve_revoke(
    store: &Arc<EncryptedStore>,
    principal: Option<&Principal>,
    params: &Value,
) -> UseAnswer {
    if !admitted(principal) {
        return UseAnswer::Reply(SecretError::NotFound.body());
    }
    let parsed: RevokeParams = match serde_json::from_value(params.clone()) {
        Ok(p) => p,
        Err(_) => return invalid(store, ValidationError::InvalidParams),
    };
    if !(1..=256).contains(&parsed.flow_install_id.len())
        || !parsed
            .flow_install_id
            .bytes()
            .all(|b| (0x20..=0x7e).contains(&b))
        || parsed
            .flow_version
            .is_some_and(|v| !(1..=MAX_SECRET_JSON_INTEGER).contains(&v))
        || (params.get("flow_version").is_some() && parsed.flow_version.is_none())
    {
        return invalid(store, ValidationError::InvalidParams);
    }
    UseAnswer::Reply(
        match store.revoke_flow_grants(&parsed.flow_install_id, parsed.flow_version) {
            Ok(grants) => json!({"status":"revoked", "grants":grants}),
            Err(error) => error.body(),
        },
    )
}
