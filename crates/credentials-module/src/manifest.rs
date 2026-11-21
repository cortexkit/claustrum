//! Manifest delivery from the secret home and local activation reporting.

use std::sync::Arc;

use credentials_core::store::{ActiveAgentPolicy, EncryptedStore, SecretHomeRole};
use serde::Deserialize;
use serde_json::{json, Value};
use subc_protocol::{EnvelopeHeader, Frame, FrameType, Principal};
use tokio::sync::mpsc;

use crate::{
    manifest_active_report::{parse_active_report, record_own_manifest_active_report},
    policy_token::{self, OP_POLICY_TOKEN},
    read_surface::ReadSurface,
    ModuleError,
};

pub(crate) const OP_LATEST: &str = "manifest.latest";
pub(crate) const OP_WATCH: &str = "manifest.watch";
pub(crate) const OP_REPORT_ACTIVE: &str = "manifest.report_active";
pub(crate) const OP_ACTIVE_STATUS: &str = "manifest.active_status";
pub(crate) const OP_POLICY_ACTIVE: &str = "policy.active";
pub(crate) const OP_POLICY_WATCH: &str = "policy.watch";

pub(crate) fn is_op(method: &str) -> bool {
    matches!(
        method,
        OP_LATEST
            | OP_WATCH
            | OP_REPORT_ACTIVE
            | OP_ACTIVE_STATUS
            | OP_POLICY_ACTIVE
            | OP_POLICY_WATCH
            | OP_POLICY_TOKEN
    )
}

pub(crate) fn admitted(method: &str, principal: Option<&Principal>) -> bool {
    matches!(principal, Some(Principal::Reserved { module_id }) if match method {
        OP_LATEST | OP_REPORT_ACTIVE => module_id == "aft",
        OP_WATCH | OP_POLICY_ACTIVE | OP_POLICY_WATCH | OP_POLICY_TOKEN => module_id == "aft" || module_id == "plexus",
        OP_ACTIVE_STATUS => module_id == "plexus",
        _ => false,
    })
}

fn refusal(code: &str, class: &str) -> Value {
    json!({"error":{"code":code,"class":class}})
}

fn role_refusal(role: SecretHomeRole, method: &str) -> Option<Value> {
    match role {
        SecretHomeRole::Single | SecretHomeRole::Home { .. } => None,
        SecretHomeRole::StoreError => Some(refusal("store_error", "transient")),
        SecretHomeRole::Remote { .. } if method == OP_REPORT_ACTIVE => None,
        SecretHomeRole::Remote { .. } | SecretHomeRole::RemoteSetupIncomplete { .. }
            if matches!(
                method,
                OP_ACTIVE_STATUS | OP_POLICY_ACTIVE | OP_POLICY_WATCH
            ) =>
        {
            Some(refusal("not_found", "permanent"))
        }
        SecretHomeRole::Remote { .. } => Some(refusal("home_unavailable", "transient")),
        SecretHomeRole::RemoteSetupIncomplete { self_member } => {
            let mut reply = refusal("remote_setup_incomplete", "permanent");
            if let Some(member) = self_member {
                reply["error"]["remedy_member"] = json!(member);
            }
            Some(reply)
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionParams {
    version: i64,
}

pub(crate) fn watch_snapshot(store: &EncryptedStore) -> Value {
    if let Some(reply) = role_refusal(store.secret_home_role(), OP_WATCH) {
        return reply;
    }
    match store.latest_gh_manifest_metadata() {
        Ok(None) => json!({"version":null, "manifest_sha256":null}),
        Ok(Some((version, manifest_sha256))) => {
            json!({"version":version, "manifest_sha256":manifest_sha256})
        }
        Err(_) => refusal("store_error", "transient"),
    }
}

fn read_policy(store: &EncryptedStore, method: &str) -> Result<Option<ActiveAgentPolicy>, Value> {
    let (role, policy) = store
        .active_agent_policy()
        .map_err(|_| refusal("store_error", "transient"))?;
    if let Some(reply) = role_refusal(role, method) {
        return Err(reply);
    }
    Ok(policy)
}

pub(crate) fn policy_watch_snapshot(store: &EncryptedStore) -> Value {
    match read_policy(store, OP_POLICY_WATCH) {
        Ok(Some(policy)) => {
            json!({"version": policy.version, "policy_sha256": policy.policy_sha256})
        }
        Ok(None) => json!({"version": null, "policy_sha256": null}),
        Err(reply) => reply,
    }
}

pub(crate) async fn serve(
    header: EnvelopeHeader,
    writer: &mpsc::Sender<Frame>,
    surface: &Arc<ReadSurface>,
    principal: Option<&Principal>,
    method: &str,
    params: &Value,
) -> Result<(), ModuleError> {
    if !admitted(method, principal) {
        return crate::send_route_result(writer, header, crate::uniform_not_found()).await;
    }
    if let (OP_POLICY_TOKEN, Some(Principal::Reserved { module_id })) = (method, principal) {
        return policy_token::serve(
            header,
            writer,
            surface.store(),
            &surface.policy_tokens,
            module_id,
            params,
        )
        .await;
    }
    let report = if method == OP_REPORT_ACTIVE {
        parse_active_report(params)
    } else {
        None
    };
    let version = if method == OP_ACTIVE_STATUS {
        serde_json::from_value::<VersionParams>(params.clone())
            .ok()
            .filter(|p| p.version > 0)
    } else {
        None
    };
    let valid = match method {
        OP_REPORT_ACTIVE => report.is_some(),
        OP_ACTIVE_STATUS => version.is_some(),
        _ => params.as_object().is_some_and(|p| p.is_empty()),
    };
    if !valid {
        return crate::invalid_params(
            writer,
            header.ver,
            header.channel,
            header.epoch,
            header.corr,
            "invalid manifest parameters",
        )
        .await;
    }
    if matches!(method, OP_WATCH | OP_POLICY_WATCH) {
        let opened = if method == OP_POLICY_WATCH {
            surface
                .watches
                .open_policy(Arc::clone(surface), writer.clone(), header)
        } else {
            surface
                .watches
                .open_manifest(Arc::clone(surface), writer.clone(), header)
        };
        if !opened {
            let writer = writer.clone();
            tokio::spawn(async move {
                let _ = crate::watch_scoped::refusal(
                    &writer,
                    header,
                    FrameType::Response,
                    crate::read_surface::ReadError::NotFound,
                )
                .await;
            });
        }
        return Ok(());
    }
    if method == OP_LATEST {
        if let Some(answer) = surface
            .remote()
            .route_manifest_call(crate::federation::ingress::OP_MANIFEST_LATEST, params)
            .await
        {
            return match answer {
                crate::federation::remote_read::SecretForwardAnswer::Reply(reply) => {
                    crate::send_route_result(writer, header, crate::wrap_result(reply)).await
                }
                crate::federation::remote_read::SecretForwardAnswer::InvalidParams => {
                    crate::invalid_params(
                        writer,
                        header.ver,
                        header.channel,
                        header.epoch,
                        header.corr,
                        "invalid manifest parameters",
                    )
                    .await
                }
            };
        }
    }
    let store = Arc::clone(surface.store());
    let method = method.to_owned();
    let reply = tokio::task::spawn_blocking(move || {
        if method == OP_POLICY_ACTIVE {
            return match read_policy(&store, OP_POLICY_ACTIVE) {
                Ok(Some(policy)) => json!(policy),
                Ok(None) => json!({"version": null, "policy_sha256": null, "manifest_version": null, "policy_text": null}),
                Err(reply) => reply,
            };
        }
        if let Some(reply) = role_refusal(store.secret_home_role(), &method) {
            return reply;
        }
        match method.as_str() {
            OP_LATEST => match store.latest_gh_manifest() {
                Ok(Some(latest)) => json!(latest),
                Ok(None) => refusal("not_found", "permanent"),
                Err(_) => refusal("store_error", "transient"),
            },
            OP_ACTIVE_STATUS => match store.gh_manifest_active_status(version.unwrap().version) {
                Ok(Some(status)) => json!(status),
                Ok(None) => refusal("unknown_version", "transient"),
                Err(_) => refusal("store_error", "transient"),
            },
            OP_REPORT_ACTIVE => match store.federation_self_member() {
                Ok(Some(member)) => {
                    record_own_manifest_active_report(&store, &member, &report.unwrap())
                }
                Ok(None) => refusal("secret_setup_incomplete", "permanent"),
                Err(_) => refusal("store_error", "transient"),
            },
            _ => unreachable!(),
        }
    })
    .await
    .unwrap_or_else(|_| refusal("store_error", "transient"));
    crate::send_route_result(writer, header, crate::wrap_result(reply)).await
}

#[cfg(test)]
#[path = "manifest_tests.rs"]
mod tests;
