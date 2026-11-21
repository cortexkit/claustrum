//! Daemon-only GitHub App operations. The admin surface authenticates the exact
//! request before reaching any code here.

use std::{path::PathBuf, sync::Arc, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use credentials_core::{
    agent_policy::{valid_app_slug, valid_github_app_agent},
    engine::RefreshEngine,
    http::ReqwestTransport,
    refresh_adapters::{github_app::GithubAppAdapter, HttpResponse, HttpTransport},
    secret::{SecretBytes, SecretString},
    store::{GitHubAppCreation, SecretHomeRole, StoreOpError},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::time::{timeout_at, Instant};

use super::{store_err, AdminOutcome, ROUTE_ADMIN_ACTOR};
use crate::account_token_mint::{canonical_id, mint_relay_token, RelayTokenError};

const RELAY_OPEN_URL: &str = "https://hooks.cortexkit.io/v1/relay/github-apps/slots";
const RELAY_WEBHOOK_BASE: &str = "https://hooks.cortexkit.io/v1/github/apps";
const MAX_RELAY_REPLY_BYTES: usize = 8 * 1024;
const GITHUB_MANIFEST_BASE: &str = "https://api.github.com/app-manifests";
const GITHUB_APPS_BASE: &str = "https://github.com/apps";
const MAX_MANIFEST_CODE_BYTES: usize = 128;
const MAX_CONVERSION_REPLY_BYTES: usize = 64 * 1024;

pub(super) struct GitHubAppAdmin {
    budget: Duration,
    transport: Option<Arc<dyn HttpTransport>>,
    machine_path: Option<PathBuf>,
    clock: Option<i64>,
}

impl Default for GitHubAppAdmin {
    fn default() -> Self {
        Self {
            budget: crate::federation::ADMIN_OP_BUDGET,
            transport: None,
            machine_path: None,
            clock: None,
        }
    }
}

impl GitHubAppAdmin {
    fn http(&self) -> Result<Arc<dyn HttpTransport>, RelayFailure> {
        match &self.transport {
            Some(transport) => Ok(Arc::clone(transport)),
            // The shared transport does not follow redirects or forward the code,
            // bearer or secret to another destination.
            None => Ok(Arc::new(
                ReqwestTransport::new().map_err(|_| RelayFailure::Unavailable)?,
            )),
        }
    }

    /// Check serving admission within the same deadline as the operation's
    /// lock waits, token mint and HTTP work.
    async fn admit(&self, engine: &RefreshEngine) -> Result<Instant, AdminOutcome> {
        let deadline = Instant::now() + self.budget;
        let store = Arc::clone(engine.store());
        let role = timeout_at(
            deadline,
            tokio::task::spawn_blocking(move || store.secret_home_role()),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or_else(|| RelayFailure::Unavailable.refusal())?;
        match role {
            SecretHomeRole::Single | SecretHomeRole::Home { .. } => Ok(deadline),
            SecretHomeRole::Remote { home_member } => {
                Err(store_err(StoreOpError::SecretHomeElsewhere { home_member }))
            }
            SecretHomeRole::RemoteSetupIncomplete { self_member } => {
                Err(store_err(StoreOpError::SecretRemoteSetupIncomplete {
                    remedy_member: self_member,
                }))
            }
            SecretHomeRole::StoreError => Err(RelayFailure::Unavailable.refusal()),
        }
    }

    pub(super) async fn relay_slot_open(&self, engine: &Arc<RefreshEngine>) -> AdminOutcome {
        let deadline = match self.admit(engine).await {
            Ok(deadline) => deadline,
            Err(refusal) => return refusal,
        };
        let reply = match timeout_at(deadline, self.request_slot(engine, deadline)).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(failure)) => return failure.refusal(),
            Err(_) => return RelayFailure::Unavailable.refusal(),
        };

        // There is no local slot record to roll back. If audit fails, don't hand
        // out the URL; the pending slot will expire at the relay.
        if engine
            .store()
            .audit_github_app_relay_slot_open(&reply.slot, ROUTE_ADMIN_ACTOR)
            .is_err()
        {
            return AdminOutcome::Refused(
                "audit_write_failed/permanent: could not record the confirmed relay slot".into(),
            );
        }
        AdminOutcome::Ok(serde_json::json!(reply))
    }

    async fn request_slot(
        &self,
        engine: &Arc<RefreshEngine>,
        deadline: Instant,
    ) -> Result<SlotOpenReply, RelayFailure> {
        let http = self.http()?;
        let authorization = self
            .relay_authorization(engine, http.as_ref(), deadline)
            .await?;
        let reply = http
            .post(
                RELAY_OPEN_URL,
                &[("Authorization", authorization.expose().as_str())],
                "application/json",
                Vec::new(),
            )
            .await
            .map_err(|_| RelayFailure::Unavailable)?;
        confirmed_slot(reply)
    }

    async fn relay_authorization(
        &self,
        engine: &Arc<RefreshEngine>,
        http: &dyn HttpTransport,
        deadline: Instant,
    ) -> Result<SecretString, RelayFailure> {
        if Instant::now() >= deadline {
            return Err(RelayFailure::Unavailable);
        }
        let token = mint_relay_token(engine, http, self.machine_path.clone(), self.clock)
            .await
            .map_err(|error| match error {
                RelayTokenError::NoMachineKey => RelayFailure::UnavailableForAccount,
                RelayTokenError::MintFailed => RelayFailure::Unavailable,
            })?;
        if Instant::now() >= deadline {
            return Err(RelayFailure::Unavailable);
        }
        Ok(SecretString::new(format!("Bearer {}", token.jwt.expose())))
    }

    pub(super) async fn create_complete(
        &self,
        engine: &Arc<RefreshEngine>,
        code: SecretString,
        agent: &str,
        slot: Option<&str>,
    ) -> AdminOutcome {
        if !valid_github_app_agent(agent) {
            return refusal(
                "agent_invalid/permanent: expected agent_ followed by 16 lowercase hex digits",
            );
        }
        if !valid_manifest_code(code.expose()) || slot.is_some_and(|slot| !valid_relay_slot(slot)) {
            return refusal("invalid_params/permanent: invalid GitHub manifest code or relay slot");
        }
        let deadline = match self.admit(engine).await {
            Ok(deadline) => deadline,
            Err(refusal) => return refusal,
        };
        let store = Arc::clone(engine.store());
        let agent_owned = agent.to_owned();
        match timeout_at(
            deadline,
            tokio::task::spawn_blocking(move || store.github_app_agent_exists(&agent_owned)),
        )
        .await
        {
            Ok(Ok(Ok(true))) => {
                return refusal(
                    "github_app_agent_exists/permanent: an App already holds this agent",
                )
            }
            Ok(Ok(Ok(false))) => {}
            _ => return refusal(
                "relay_unavailable/transient: could not check agent ownership before conversion",
            ),
        }
        let Ok(http) = self.http() else {
            return refusal(CONVERSION_UNKNOWN);
        };
        if Instant::now() >= deadline {
            return refusal(CONVERSION_UNKNOWN);
        }
        // The grammar allows only ASCII unreserved characters, so the code is
        // already encoded as one URL segment.
        let url = SecretString::new(format!(
            "{GITHUB_MANIFEST_BASE}/{}/conversions",
            code.expose()
        ));
        let response = timeout_at(
            deadline,
            http.post(
                url.expose(),
                &[
                    ("Accept", "application/vnd.github+json"),
                    ("User-Agent", "cortexkit-claustrum"),
                ],
                "application/json",
                Vec::new(),
            ),
        )
        .await;
        drop(url);
        drop(code);
        let Ok(Ok(response)) = response else {
            return refusal(CONVERSION_UNKNOWN);
        };
        let body = SecretBytes::new(response.body);
        match response.status {
            200..=299 => {}
            400..=499 => {
                return refusal(
                    "github_app_code_invalid/permanent: GitHub refused the manifest code",
                )
            }
            _ => return refusal(CONVERSION_UNKNOWN),
        }
        let app = match read_conversion(body.expose(), slot.is_some()) {
            Ok(app) => app,
            Err(outcome) => return outcome,
        };
        drop(body);
        self.commit_conversion(engine, http.as_ref(), deadline, agent, slot, app)
            .await
    }

    async fn commit_conversion(
        &self,
        engine: &Arc<RefreshEngine>,
        http: &dyn HttpTransport,
        deadline: Instant,
        agent: &str,
        slot: Option<&str>,
        app: Conversion,
    ) -> AdminOutcome {
        let id = format!("github_app:{}", app.slug);
        let unsaved = |cause| unsaved(Some(&app.slug), Some(app.id), cause);
        if Instant::now() >= deadline {
            return unsaved("busy");
        }
        let Ok(_lock) = timeout_at(deadline, engine.acquire_admin_lock(&id)).await else {
            return unsaved("busy");
        };
        if Instant::now() >= deadline {
            return unsaved("busy");
        }
        let relay = slot.zip(app.webhook_secret.as_ref());
        let material = GitHubAppCreation {
            slug: &app.slug,
            app_id: app.id,
            agent,
            pem: &app.pem,
            client_id: &app.client_id,
            relay,
        };
        if let Err(error) = engine
            .store()
            .create_github_app_audited(material, ROUTE_ADMIN_ACTOR)
        {
            return unsaved(match error {
                StoreOpError::AlreadyExists => "github_app_exists",
                StoreOpError::Encode(message)
                    if message.starts_with("github_app_agent_exists:") =>
                {
                    "github_app_agent_exists"
                }
                _ => "store_failed",
            });
        }

        let app_id = app.id.to_string();
        let mut result = json!({
            "outcome": "created",
            "slug": app.slug,
            "app_id": app_id,
            "install_url": format!("{GITHUB_APPS_BASE}/{}/installations/new", app.slug),
        });
        if let Some((slot, secret)) = relay {
            let put = self.put_relay_slot(engine, http, deadline, slot, &app_id, secret);
            if let Err(failure) = timeout_at(deadline, put)
                .await
                .unwrap_or(Err(RelayFailure::Unavailable))
            {
                result["outcome"] = json!("relay_registration_failed");
                result["cause"] = json!(failure.code());
            }
        }
        AdminOutcome::Ok(result)
    }

    async fn put_relay_slot(
        &self,
        engine: &Arc<RefreshEngine>,
        http: &dyn HttpTransport,
        deadline: Instant,
        slot: &str,
        app_id: &str,
        secret: &SecretString,
    ) -> Result<(), RelayFailure> {
        let authorization = self.relay_authorization(engine, http, deadline).await?;
        // The validated slot consists only of URL-unreserved characters.
        let url = format!("{RELAY_OPEN_URL}/{slot}");
        let body = serde_json::to_vec(&RelayPut {
            app_id,
            webhook_secret: secret.expose(),
        })
        .expect("string fields always serialize");
        let reply = http
            .put(
                &url,
                &[("Authorization", authorization.expose().as_str())],
                "application/json",
                body,
            )
            .await
            .map_err(|_| RelayFailure::Unavailable)?;
        confirmed_put(reply)
    }
}

const CONVERSION_UNKNOWN: &str =
    "github_app_conversion_unknown/permanent: GitHub App conversion could not be confirmed";

fn refusal(message: &str) -> AdminOutcome {
    AdminOutcome::Refused(message.into())
}

fn valid_manifest_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= MAX_MANIFEST_CODE_BYTES
        && code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct ConversionFields {
    id: Option<Value>,
    slug: Option<Value>,
    pem: Option<Value>,
    client_id: Option<Value>,
    webhook_secret: Option<Value>,
}

struct Conversion {
    id: u64,
    slug: String,
    pem: SecretString,
    client_id: String,
    webhook_secret: Option<SecretString>,
}

fn read_conversion(body: &[u8], needs_relay: bool) -> Result<Conversion, AdminOutcome> {
    if body.len() > MAX_CONVERSION_REPLY_BYTES
        || body
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace())
            != Some(b'{')
    {
        return Err(unsaved(None, None, "reply_invalid"));
    }
    let fields: ConversionFields =
        serde_json::from_slice(body).map_err(|_| unsaved(None, None, "reply_invalid"))?;
    let id = fields.id.and_then(|id| id.as_u64()).filter(|id| *id > 0);
    let slug = nonempty_string(fields.slug).filter(|slug| valid_app_slug(slug));
    let pem = nonempty_string(fields.pem).map(SecretString::new);
    let client_id = nonempty_string(fields.client_id);
    let webhook_secret = nonempty_string(fields.webhook_secret)
        .map(SecretString::new)
        .filter(|_| needs_relay);
    match (id, slug, pem, client_id) {
        (Some(id), Some(slug), Some(pem), Some(client_id))
            if (!needs_relay || webhook_secret.is_some())
                && GithubAppAdapter::valid_private_key_pem(pem.expose()) =>
        {
            Ok(Conversion {
                id,
                slug,
                pem,
                client_id,
                webhook_secret,
            })
        }
        (id, slug, _, _) => Err(unsaved(slug.as_deref(), id, "reply_invalid")),
    }
}

fn nonempty_string(value: Option<Value>) -> Option<String> {
    match value {
        Some(Value::String(value)) if !value.is_empty() => Some(value),
        _ => None,
    }
}

fn unsaved(slug: Option<&str>, id: Option<u64>, cause: &str) -> AdminOutcome {
    let mut result = json!({"outcome": "github_app_unsaved", "cause": cause});
    if let Some(slug) = slug {
        result["slug"] = json!(slug);
    }
    if let Some(id) = id {
        result["app_id"] = json!(id.to_string());
    }
    AdminOutcome::Ok(result)
}

#[derive(Serialize)]
struct RelayPut<'a> {
    app_id: &'a str,
    webhook_secret: &'a str,
}

fn confirmed_put(response: HttpResponse) -> Result<(), RelayFailure> {
    let body = SecretBytes::new(response.body);
    match response.status {
        200 if body.expose().len() <= MAX_RELAY_REPLY_BYTES => Ok(()),
        200..=299 => Err(RelayFailure::ReplyInvalid),
        401 | 403 => Err(RelayFailure::UnavailableForAccount),
        404 => Err(RelayFailure::SlotExpired),
        409 => Err(RelayFailure::AppMismatch),
        300..=399 | 429 | 500..=599 => Err(RelayFailure::Unavailable),
        400..=499 => Err(RelayFailure::RequestRefused),
        _ => Err(RelayFailure::ReplyInvalid),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelayFailure {
    UnavailableForAccount,
    SlotLimit,
    Unavailable,
    RequestRefused,
    ReplyInvalid,
    SlotExpired,
    AppMismatch,
}

impl RelayFailure {
    fn code(self) -> &'static str {
        match self {
            Self::UnavailableForAccount => "relay_unavailable_for_account",
            Self::SlotLimit => "relay_slot_limit",
            Self::Unavailable => "relay_unavailable",
            Self::RequestRefused => "relay_request_refused",
            Self::ReplyInvalid => "relay_reply_invalid",
            Self::SlotExpired => "relay_slot_expired",
            Self::AppMismatch => "relay_app_mismatch",
        }
    }

    fn refusal(self) -> AdminOutcome {
        let message = match self {
            Self::UnavailableForAccount => {
                "relay_unavailable_for_account/permanent: the relay is unavailable for this account"
            }
            Self::SlotLimit => "relay_slot_limit/permanent: the account's relay slots are full",
            Self::Unavailable => "relay_unavailable/transient: could not open a relay slot",
            Self::RequestRefused => {
                "relay_request_refused/permanent: the relay refused the request"
            }
            Self::ReplyInvalid => {
                "relay_reply_invalid/permanent: the relay did not return a valid slot"
            }
            Self::SlotExpired => "relay_slot_expired/permanent: the relay slot expired",
            Self::AppMismatch => {
                "relay_app_mismatch/permanent: the relay slot belongs to another App"
            }
        };
        AdminOutcome::Refused(message.into())
    }
}

#[derive(Deserialize, Serialize)]
struct SlotOpenReply {
    slot: String,
    webhook_url: String,
    expires_at: String,
}

fn confirmed_slot(reply: HttpResponse) -> Result<SlotOpenReply, RelayFailure> {
    match reply.status {
        201 => {}
        401 | 403 | 404 => return Err(RelayFailure::UnavailableForAccount),
        409 => return Err(RelayFailure::SlotLimit),
        300..=399 | 429 | 500..=599 => return Err(RelayFailure::Unavailable),
        400..=499 => return Err(RelayFailure::RequestRefused),
        _ => return Err(RelayFailure::ReplyInvalid),
    }
    if reply.body.len() > MAX_RELAY_REPLY_BYTES {
        return Err(RelayFailure::ReplyInvalid);
    }
    let slot: SlotOpenReply =
        serde_json::from_slice(&reply.body).map_err(|_| RelayFailure::ReplyInvalid)?;
    if !valid_relay_slot(&slot.slot)
        || slot.webhook_url != format!("{RELAY_WEBHOOK_BASE}/{}/webhook", slot.slot)
        || chrono::DateTime::parse_from_rfc3339(&slot.expires_at).is_err()
    {
        return Err(RelayFailure::ReplyInvalid);
    }
    Ok(slot)
}

pub(super) fn valid_relay_slot(slot: &str) -> bool {
    slot.split_once('.').is_some_and(|(id, tag)| {
        canonical_id(id) && tag.len() == 22 && URL_SAFE_NO_PAD.decode(tag).is_ok()
    })
}

#[cfg(test)]
#[path = "github_app_admin_tests.rs"]
mod tests;
