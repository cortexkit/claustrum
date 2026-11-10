//! The vault's non-secret account and static-key connector inventory.

use std::sync::Arc;

use credentials_core::{
    catalog::connector_metadata,
    plan_detection::{effective_plan, DetectedPlan},
    record::{RecordIdentity, RecordState},
    store::EncryptedStore,
    CredentialKind,
};
use serde_json::{json, Value};
use subc_protocol::{EnvelopeHeader, Frame, FrameType};
use tokio::sync::mpsc;

use crate::{
    admin_surface::{AdminSurface, ConnectorAdmission as Admission},
    read_surface::{ReadError, ReadSurface},
    ModuleError,
};

const MAX_CONNECTOR_NAME_CHARS: usize = 80;
const MAX_CONNECTOR_IDENTITY_BYTES: usize = 254;

pub(crate) fn is_op(method: &str) -> bool {
    matches!(method, "connectors.list" | "connectors.watch")
}

pub(crate) async fn serve(
    header: EnvelopeHeader,
    writer: &mpsc::Sender<Frame>,
    surface: &Arc<ReadSurface>,
    admin: &Arc<AdminSurface>,
    method: &str,
    params: &Value,
) -> Result<(), ModuleError> {
    if method == "connectors.watch" {
        open_watch(
            header,
            writer.clone(),
            Arc::clone(surface),
            Arc::clone(admin),
            params.clone(),
        );
        return Ok(());
    }
    if !admit(header, writer, admin, true).await? {
        return Ok(());
    }
    if !params.as_object().is_some_and(|params| params.is_empty()) {
        return crate::invalid_params(
            writer,
            header.ver,
            header.channel,
            header.epoch,
            header.corr,
            "connectors parameters must be an empty object",
        )
        .await;
    }
    let store = Arc::clone(surface.store());
    let reply = tokio::task::spawn_blocking(move || list(&store))
        .await
        .unwrap_or(Err(ReadError::StoreError));
    let body = match reply {
        Ok(reply) => reply,
        Err(code) => json!({"error":{"code":code,"class":code.class()}}),
    };
    crate::send_route_result(writer, header, crate::wrap_result(body)).await
}

fn log_admission(admission: &Admission, log_development: bool) {
    if log_development && matches!(admission, Admission::Development) {
        tracing::info!(target: "connectors", "unsigned_desktop_development_admission admitted connectors read");
    }
}

fn open_watch(
    header: EnvelopeHeader,
    writer: mpsc::Sender<Frame>,
    surface: Arc<ReadSurface>,
    admin: Arc<AdminSurface>,
    params: Value,
) {
    let admission = admin.connector_admission(header.channel, header.epoch);
    log_admission(&admission, true);
    if matches!(admission, Admission::Allowed | Admission::Development)
        && params.as_object().is_some_and(|params| params.is_empty())
    {
        if !surface
            .watches
            .open_connectors(Arc::clone(&surface), writer.clone(), header, admin)
        {
            tokio::spawn(async move {
                let _ = crate::watch_scoped::refusal(
                    &writer,
                    header,
                    FrameType::Response,
                    ReadError::NotFound,
                )
                .await;
            });
        }
        return;
    }
    // Refusal output must not block ingress: a following cancellation, route close,
    // or drain still needs to run while the route's response lane is backpressured.
    tokio::spawn(async move {
        if matches!(
            answer_admission(header, &writer, admission, false).await,
            Ok(true)
        ) {
            let _ = crate::invalid_params(
                &writer,
                header.ver,
                header.channel,
                header.epoch,
                header.corr,
                "connectors parameters must be an empty object",
            )
            .await;
        }
    });
}

pub(crate) async fn admit(
    header: EnvelopeHeader,
    writer: &mpsc::Sender<Frame>,
    admin: &AdminSurface,
    log_development: bool,
) -> Result<bool, ModuleError> {
    answer_admission(
        header,
        writer,
        admin.connector_admission(header.channel, header.epoch),
        log_development,
    )
    .await
}

async fn answer_admission(
    header: EnvelopeHeader,
    writer: &mpsc::Sender<Frame>,
    admission: Admission,
    log_development: bool,
) -> Result<bool, ModuleError> {
    log_admission(&admission, log_development);
    match admission {
        Admission::Allowed | Admission::Development => {}
        Admission::PhoneOff => {
            crate::send_route_result(
                writer,
                header,
                crate::wrap_result(
                    json!({"error":{"code":"phone_access_off","class":"permanent"}}),
                ),
            )
            .await?;
            return Ok(false);
        }
        Admission::PhoneRefused => {
            crate::send_route_result(writer, header, crate::uniform_not_found()).await?;
            return Ok(false);
        }
        Admission::Denied => {
            crate::send_route_error(writer, header.ver, header.channel, header.epoch, header.corr, "permissions_operator_required", "permissions operations need reserved:cingulate or the local operator's direct route").await?;
            return Ok(false);
        }
    }
    Ok(true)
}

fn category(groups: &[String], catalog: Option<&str>) -> Option<String> {
    for (names, category) in [
        (&["llm-provider", "media-provider"][..], "ai_models"),
        (&["web-search"][..], "search"),
        (&["cloud-infrastructure"][..], "infrastructure"),
    ] {
        if groups.iter().any(|group| names.contains(&group.as_str())) {
            return Some(category.to_owned());
        }
    }
    catalog.map(str::to_owned)
}

fn row(
    id: &str,
    kind: &str,
    incarnation: &str,
    groups: &[String],
    state: &str,
    reason: Option<String>,
    permissions: Vec<String>,
) -> Value {
    let (name, catalog_category) = connector_metadata(id);
    let status = match state {
        "active" => "ok",
        "needs_reauth" if kind == "api_key" => "key_refused",
        "needs_reauth" => "needs_sign_in",
        "retired" => "signed_out",
        _ => "damaged",
    };
    let mut value = json!({
        "id":id, "kind":kind, "incarnation":incarnation,
        "name":name.unwrap_or(id).chars().take(MAX_CONNECTOR_NAME_CHARS).collect::<String>(),
        "status":{"state":status}, "permissions":permissions,
        "setup":[{"step":if kind == "api_key" {"key"} else {"sign_in"}, "state":if status == "ok" {"done"} else {"needed"}, "where":"computer"}],
    });
    if let Some(category) = category(groups, catalog_category) {
        value["category"] = json!(category);
    }
    if status != "ok" {
        if let Some(reason) = reason {
            value["status"]["reason"] = json!(reason);
        }
        value["setup"][0]["remedy"] = json!(if kind == "api_key" {
            "replace_key"
        } else {
            "sign_in_again"
        });
    }
    value
}

fn labels(
    row: &mut Value,
    identity: &RecordIdentity,
    operator_plan: Option<String>,
    detected: Option<&DetectedPlan>,
) {
    if let Some(identity) = identity
        .email
        .as_ref()
        .or(identity.org_name.as_ref())
        .filter(|identity| identity.len() <= MAX_CONNECTOR_IDENTITY_BYTES)
    {
        row["identity"] = json!(identity);
    }
    if let (Some(tier), Some(source)) = effective_plan(operator_plan, detected) {
        row["plan"] = json!({"tier":tier,"source":source});
    }
}

pub(crate) fn list(store: &EncryptedStore) -> Result<Value, ReadError> {
    let error = |_| ReadError::StoreError;
    let runtime = store.connector_runtime_ids().map_err(error)?;
    let mut rows = Vec::new();
    for (id, record) in store.connector_records().map_err(error)? {
        let kind = match record.kind {
            CredentialKind::Oauth
                if record.refresh_adapter.as_deref().is_some_and(|adapter| {
                    adapter != credentials_core::refresh_adapters::github_app::ADAPTER_NAME
                }) =>
            {
                "account"
            }
            CredentialKind::Cookie => "account",
            CredentialKind::ApiKey if record.refresh_adapter.is_none() => "api_key",
            _ => continue,
        };
        if record.kind.is_vault_held_key() || runtime.contains(&id) {
            continue;
        }
        let meta = store.meta(&id).map_err(error)?;
        let permissions = store
            .connector_permission_ids(&id, &meta.categories)
            .map_err(error)?;
        let reason = if meta.state == RecordState::Active {
            None
        } else {
            store.connector_auth_reason(&id).map_err(error)?
        };
        let mut value = row(
            &id,
            kind,
            meta.incarnation.as_deref().ok_or(ReadError::StoreError)?,
            &meta.categories,
            meta.state.as_str(),
            reason,
            permissions,
        );
        labels(
            &mut value,
            &record.identity,
            meta.plan_tier,
            record.detected_plan.as_ref(),
        );
        rows.push(value);
    }
    for entry in store.remote_inventory().map_err(error)? {
        let record = entry.record;
        if runtime.contains(&record.credential_id) {
            continue;
        }
        let permissions = store
            .connector_permission_ids(&record.credential_id, &entry.categories)
            .map_err(error)?;
        let reason = store
            .connector_auth_reason(&record.credential_id)
            .map_err(error)?;
        let mut value = row(
            &record.credential_id,
            "account",
            &record.incarnation,
            &entry.categories,
            record.last_home_state.as_str(),
            reason,
            permissions,
        );
        labels(
            &mut value,
            &record.identity,
            entry.plan_tier,
            record.detected_plan.as_ref(),
        );
        value["setup"].as_array_mut().expect("setup").push(json!({"step":"home", "state":match record.last_fetch_outcome.as_deref() {None => "unknown", Some("ok") => "done", Some(_) => "needed"}, "where":"computer"}));
        rows.push(value);
    }
    rows.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let version: String = ring::digest::digest(
        &ring::digest::SHA256,
        &serde_json::to_vec(&rows).map_err(|_| ReadError::StoreError)?,
    )
    .as_ref()
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect();
    let mut reply = json!({"version":version,"watch":true,"rows":rows});
    if let Some(computer) = store.federation_self_member().map_err(error)? {
        reply["computer"] = json!(computer);
    }
    Ok(reply)
}
