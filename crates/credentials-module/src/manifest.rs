//! Local manifest delivery and activation reporting for the vault's own computer.

use std::sync::Arc;

use credentials_core::store::{EncryptedStore, SecretHomeRole};
use serde::Deserialize;
use serde_json::{json, Value};
use subc_protocol::{EnvelopeHeader, Frame, FrameType, Principal};
use tokio::sync::mpsc;

use crate::{
    manifest_active_report::{parse_active_report, record_manifest_active_report},
    read_surface::ReadSurface,
    ModuleError,
};

pub(crate) const OP_LATEST: &str = "manifest.latest";
pub(crate) const OP_WATCH: &str = "manifest.watch";
pub(crate) const OP_REPORT_ACTIVE: &str = "manifest.report_active";
pub(crate) const OP_ACTIVE_STATUS: &str = "manifest.active_status";

pub(crate) fn is_op(method: &str) -> bool {
    matches!(
        method,
        OP_LATEST | OP_WATCH | OP_REPORT_ACTIVE | OP_ACTIVE_STATUS
    )
}

pub(crate) fn admitted(method: &str, principal: Option<&Principal>) -> bool {
    matches!(principal, Some(Principal::Reserved { module_id }) if match method {
        OP_LATEST | OP_REPORT_ACTIVE => module_id == "aft",
        OP_WATCH => module_id == "aft" || module_id == "plexus",
        OP_ACTIVE_STATUS => module_id == "plexus",
        _ => false,
    })
}

fn refusal(code: &str, class: &str) -> Value {
    json!({"error":{"code":code,"class":class}})
}

fn role_refusal(store: &EncryptedStore, status: bool) -> Option<Value> {
    match store.secret_home_role() {
        SecretHomeRole::Single | SecretHomeRole::Home { .. } => None,
        SecretHomeRole::StoreError => Some(refusal("store_error", "transient")),
        SecretHomeRole::Remote { .. } | SecretHomeRole::RemoteSetupIncomplete { .. } if status => {
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
    if let Some(reply) = role_refusal(store, false) {
        return reply;
    }
    match store.latest_gh_manifest() {
        Ok(None) => json!({"version":null, "manifest_sha256":null}),
        Ok(Some(latest)) => {
            // Versions are immutable, so the hash cannot change between these reads.
            match store.gh_manifest_active_status(latest.version) {
                Ok(Some(status)) => {
                    json!({"version":latest.version, "manifest_sha256":status.manifest_sha256})
                }
                _ => refusal("store_error", "transient"),
            }
        }
        Err(_) => refusal("store_error", "transient"),
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
    if method == OP_WATCH {
        if !surface
            .watches
            .open_manifest(Arc::clone(surface), writer.clone(), header)
        {
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
    let store = Arc::clone(surface.store());
    let method = method.to_owned();
    let reply = tokio::task::spawn_blocking(move || {
        if let Some(reply) = role_refusal(&store, method == OP_ACTIVE_STATUS) {
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
                    record_manifest_active_report(&store, &member, &report.unwrap())
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
