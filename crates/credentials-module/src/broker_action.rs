//! Route adapter for minting a broker action approval statement.

use std::sync::Arc;

use credentials_core::{
    broker_action::BrokerActionScope,
    store::{BrokerActionRequestError as Error, EncryptedStore},
};
use serde_json::{json, Value};
use subc_protocol::{scope::ScopeKind, EnvelopeHeader, Frame, Principal};
use tokio::sync::mpsc;

use crate::{secret_use, ModuleError};

pub(crate) const OP_REQUEST_ACTION: &str = "policy.request_action";

pub(crate) fn request_scope(value: Value) -> Result<(String, BrokerActionScope), Error> {
    if !value.is_object() {
        return Err(Error::InvalidParams);
    }
    let stamp = secret_use::decode_stamp(value).map_err(|error| match error {
        secret_use::StampError::Unmapped => Error::NotFound,
        secret_use::StampError::Invalid => Error::InvalidParams,
    })?;
    let kind = match stamp.kind {
        ScopeKind::Head => "head",
        ScopeKind::Worker => "worker",
        ScopeKind::Ephemeral => "ephemeral",
        _ => return Err(Error::InvalidParams),
    };
    // A flow or ephemeral run keeps its own scope rather than the secret-use
    // mapping to an agent head. A worker's attributed agent still comes from the stamp.
    let scope = BrokerActionScope {
        owner: secret_use::owner(&stamp.owner),
        kind: kind.into(),
        scope_ref: stamp.scope_ref.clone(),
        epoch: stamp.scope_epoch,
    };
    let agent = secret_use::stamp_agent(stamp)
        .filter(|agent| !agent.is_empty())
        .ok_or(Error::NotFound)?;
    Ok((agent, scope))
}

pub(crate) async fn serve(
    header: EnvelopeHeader,
    writer: &mpsc::Sender<Frame>,
    store: &Arc<EncryptedStore>,
    principal: Option<&Principal>,
    params: &Value,
) -> Result<(), ModuleError> {
    let module_id = match principal {
        Some(Principal::Reserved { module_id }) => Some(module_id.clone()),
        _ => None,
    };
    let store = Arc::clone(store);
    let params = params.clone();
    let clock = crate::secret_phone::broker_action_clock();
    let answer = tokio::task::spawn_blocking(move || {
        store.request_broker_action(module_id.as_deref(), params, request_scope, clock)
    })
    .await
    .unwrap_or(Err(Error::StoreError));
    let reply = match answer {
        Ok(reply) => json!(reply),
        Err(Error::InvalidParams) => {
            return crate::invalid_params(
                writer,
                header.ver,
                header.channel,
                header.epoch,
                header.corr,
                "invalid policy.request_action parameters",
            )
            .await;
        }
        Err(error) => {
            let (code, class) = match error {
                Error::NotFound => ("not_found", "permanent"),
                Error::PolicyAbsent => ("policy_absent", "permanent"),
                Error::ApprovalNotRequired => ("approval_not_required", "permanent"),
                Error::ConsentFieldsInvalid => ("consent_fields_invalid", "permanent"),
                Error::PendingLimit => ("approval_pending_limit", "transient"),
                Error::StoreError => ("store_error", "transient"),
                Error::InvalidParams => unreachable!(),
            };
            json!({"error":{"code":code,"class":class}})
        }
    };
    crate::send_route_result(writer, header, crate::wrap_result(reply)).await
}
