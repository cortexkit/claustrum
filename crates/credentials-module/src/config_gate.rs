//! Config delivery over the module's channel-0 transport, never a file fallback.

use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use credentials_core::login_sharing::{self, Input};
use subc_config::{ApplyKind, FieldChange, Layer, RecordedValue};
use subc_protocol::{config::*, Frame, FrameType};
use tokio::sync::{mpsc, oneshot, Notify};

use crate::{
    federation::{login_sharing::ConfigPoll, ADMIN_OP_BUDGET},
    ModuleError,
};

type ReplySlot = Option<(u64, oneshot::Sender<Frame>)>;

pub struct Gate {
    writer: mpsc::Sender<Frame>,
    reply: Arc<Mutex<ReplySlot>>,
    changed: Arc<Notify>,
}

impl Gate {
    pub fn start(
        poll: ConfigPoll,
        path: std::path::PathBuf,
        writer: mpsc::Sender<Frame>,
    ) -> (Self, oneshot::Receiver<()>, tokio::task::JoinHandle<()>) {
        let gate = Self {
            writer,
            reply: Arc::new(Mutex::new(None)),
            changed: Arc::new(Notify::new()),
        };
        let (ready, initialized) = oneshot::channel();
        let mut delivery = Delivery {
            writer: gate.writer.clone(),
            reply: Arc::clone(&gate.reply),
            changed: Arc::clone(&gate.changed),
            poll,
            corr: 1,
            report: None,
            has_view: false,
            warned: HashSet::new(),
        };
        let task = tokio::spawn(async move {
            let declaration =
                ConfigDeclareRequest::new(login_sharing::schema(), path.to_string_lossy(), vec![]);
            // A refused declaration still consumes this connection's one declaration.
            match delivery.call(&declaration, CONFIG_DECLARE_OP).await {
                Ok(_) => delivery.refresh().await,
                Err(code) => delivery.warn(code),
            }
            let _ = ready.send(());
            loop {
                delivery.changed.notified().await;
                delivery.refresh().await;
            }
        });
        (gate, initialized, task)
    }

    pub async fn dispatch(&self, frame: &Frame) -> Result<bool, ModuleError> {
        if frame.header.channel != 0 {
            return Ok(false);
        }
        if matches!(frame.header.ty, FrameType::Response | FrameType::Error) {
            let mut slot = self.reply.lock().unwrap();
            if slot
                .as_ref()
                .is_some_and(|(corr, _)| *corr == frame.header.corr)
            {
                let (_, reply) = slot.take().unwrap();
                let _ = reply.send(frame.clone());
                return Ok(true);
            }
        }
        let op = serde_json::from_slice::<serde_json::Value>(&frame.body)
            .ok()
            .and_then(|v| v["op"].as_str().map(str::to_owned));
        if frame.header.ty == FrameType::Push && op.as_deref() == Some(CONFIG_CHANGED_OP) {
            if let Ok(hint) = serde_json::from_slice::<ConfigChanged>(&frame.body) {
                // This declaration has only a user layer, never project views.
                if hint.project_id.is_none() {
                    self.changed.notify_one();
                }
            }
            return Ok(true);
        }
        if frame.header.ty == FrameType::Request && op.as_deref() == Some(CONFIG_REVIEW_OP) {
            let (ty, body) = match serde_json::from_slice::<ConfigReviewRequest>(&frame.body) {
                Ok(request) => (FrameType::Response, serde_json::to_vec(&review(request))),
                Err(_) => (
                    FrameType::Error,
                    serde_json::to_vec(&subc_protocol::ErrorBody::new(
                        "invalid_request",
                        "invalid config.review snapshots",
                    )),
                ),
            };
            let response = Frame::build_with_version(
                frame.header.ver,
                ty,
                crate::control_flags(),
                0,
                0,
                frame.header.corr,
                body.map_err(ModuleError::Json)?,
            )
            .map_err(|e| ModuleError::Message(e.to_string()))?;
            crate::send(&self.writer, response).await?;
            return Ok(true);
        }
        Ok(false)
    }
}

/// Review uses the supplied immutable base, not a newly resolved old configuration.
fn review(request: ConfigReviewRequest) -> ConfigReviewReply {
    let candidate = user_input(&request.layers);
    let tuple =
        match candidate.and_then(|input| login_sharing::review_input(&input).map_err(|_| ())) {
            Ok(tuple) => tuple,
            Err(()) => {
                return ConfigReviewReply::new(
                    vec![],
                    vec![ConfigReviewRefusal::new(
                        "value_invalid",
                        vec!["/login_sharing".into()],
                        vec!["invalid value at /login_sharing".into()],
                    )],
                )
            }
        };
    let old = request
        .base
        .as_ref()
        .map(|v| v.effective["login_sharing"].clone())
        .unwrap_or(serde_json::Value::Null);
    let old_source = request
        .base
        .as_ref()
        .and_then(|v| v.sources.get("/login_sharing"))
        .copied()
        .unwrap_or(Layer::Default);
    let new = tuple.effective["login_sharing"].clone();
    let new_source = tuple.sources["/login_sharing"];
    if old == new && old_source == new_source {
        return ConfigReviewReply::new(vec![], vec![]);
    }
    let mut field = FieldChange::new(
        credentials_core::MODULE_ID,
        "/login_sharing",
        RecordedValue::new(old),
        RecordedValue::new(new),
        ApplyKind::Live,
    );
    field.old_source = old_source;
    field.new_source = new_source;
    ConfigReviewReply::new(vec![field], vec![])
}

fn user_input(layers: &[ConfigLayerSnapshot]) -> Result<Input, ()> {
    if layers.len() > 1
        || layers.iter().any(|l| {
            l.layer != ConfigLayer::User
                || l.module_id != credentials_core::MODULE_ID
                || l.project_id.is_some()
                || l.workspace_id.is_some()
        })
    {
        return Err(());
    }
    Ok(layers
        .first()
        .and_then(|l| l.bytes.clone())
        .map(Input::Bytes)
        .unwrap_or(Input::Missing))
}

struct Delivery {
    writer: mpsc::Sender<Frame>,
    reply: Arc<Mutex<ReplySlot>>,
    changed: Arc<Notify>,
    poll: ConfigPoll,
    corr: u64,
    report: Option<ConfigAppliedRequest>,
    has_view: bool,
    warned: HashSet<String>,
}

impl Delivery {
    fn warn(&mut self, code: String) {
        warn_once(&mut self.warned, code);
    }

    async fn call(
        &mut self,
        request: &impl serde::Serialize,
        op: &str,
    ) -> Result<serde_json::Value, String> {
        self.corr += 1;
        let (tx, rx) = oneshot::channel();
        *self.reply.lock().unwrap() = Some((self.corr, tx));
        let frame = Frame::build(
            FrameType::Request,
            crate::control_flags(),
            0,
            0,
            self.corr,
            serde_json::to_vec(request).map_err(|_| "invalid_request")?,
        )
        .map_err(|_| "invalid_request")?;
        let result = tokio::time::timeout(ADMIN_OP_BUDGET, async {
            self.writer
                .send(frame)
                .await
                .map_err(|_| "connection_closed".to_owned())?;
            let frame = rx.await.map_err(|_| "connection_closed".to_owned())?;
            if frame.header.ty == FrameType::Error {
                return Err(
                    serde_json::from_slice::<subc_protocol::ErrorBody>(&frame.body)
                        .map(|error| error.code)
                        .unwrap_or_else(|_| "invalid_reply".into()),
                );
            }
            let body: serde_json::Value =
                serde_json::from_slice(&frame.body).map_err(|_| "invalid_reply")?;
            if body["op"].as_str() != Some(op) {
                return Err("invalid_reply".into());
            }
            Ok(body)
        })
        .await
        .unwrap_or_else(|_| Err("timeout".into()));
        self.reply.lock().unwrap().take();
        result
    }

    async fn report(&mut self) -> bool {
        let Some(report) = self.report.clone() else {
            return true;
        };
        match self.call(&report, CONFIG_APPLIED_OP).await {
            Ok(_) => {
                self.report = None;
                true
            }
            Err(code) => {
                // Only anchor_pending authorizes replay of the same delivery attempt.
                if code != "anchor_pending" {
                    self.report = None;
                }
                self.warn(code);
                false
            }
        }
    }

    async fn apply(&mut self, view: &ConfigView) -> Result<(), Vec<String>> {
        if view.project_id.is_some()
            || !matches!(
                view.status,
                ConfigStatus::Active | ConfigStatus::Pending | ConfigStatus::Unstamped
            )
        {
            return Err(vec!["invalid config view".into()]);
        }
        let input = user_input(&view.layers).map_err(|_| vec!["invalid config layers".into()])?;
        match self.poll.apply_input(input).await {
            Ok(true) => {
                self.has_view = true;
                Ok(())
            }
            Ok(false) => Err(vec!["invalid value at /login_sharing".into()]),
            Err(_) => Err(vec!["config apply failed".into()]),
        }
    }

    async fn refresh(&mut self) {
        if !self.report().await {
            return;
        }
        let reply = match self
            .call(&ConfigGetRequest::new(), CONFIG_GET_OP)
            .await
            .and_then(|body| {
                serde_json::from_value::<ConfigGetReply>(body).map_err(|_| "invalid_reply".into())
            }) {
            Ok(reply) => reply,
            Err(code) => {
                self.warn(code);
                return;
            }
        };
        let Some(view) = reply.pending.as_ref().or(reply.active.as_ref()) else {
            self.warn("invalid_reply".into());
            return;
        };
        if view.project_id.is_some()
            || reply
                .active
                .as_ref()
                .is_some_and(|v| v.project_id.is_some())
        {
            self.warn("invalid_reply".into());
            return;
        }
        // Establish the approved recovery view before trying a first pending delivery.
        if !self.has_view && reply.pending.is_some() {
            if let Some(active) = &reply.active {
                if active.status != ConfigStatus::Active || self.apply(active).await.is_err() {
                    self.warn("invalid_recovery".into());
                    return;
                }
            }
        }
        let pending = reply.pending.is_some();
        if pending && (view.status != ConfigStatus::Pending || view.attempt.is_none()) {
            self.warn("invalid_reply".into());
            return;
        }
        let outcome = self.apply(view).await;
        if pending {
            let (result, reasons) = match outcome {
                Ok(()) => (ConfigApplyResult::Ack, vec![]),
                Err(reasons) => (ConfigApplyResult::Nack, reasons),
            };
            self.report = Some(ConfigAppliedRequest::new(
                view.generation,
                view.attempt.unwrap(),
                result,
                reasons,
            ));
            self.report().await;
        } else if outcome.is_err() {
            self.warn("value_invalid".into());
        }
    }
}

fn warn_once(warned: &mut HashSet<String>, code: String) {
    if warned.insert(code.clone()) {
        tracing::warn!(target: "federation", %code, "config gate refused delivery; applied login sharing value retained");
    }
}

#[cfg(test)]
#[path = "config_gate_tests.rs"]
mod tests;
