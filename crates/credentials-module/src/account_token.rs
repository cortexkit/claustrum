//! Audience-scoped account exchange. Private machine material stays inside the vault;
//! callers can select only an audience covered by their operation-specific grant.
use super::{ErrorClass, ReadSurface};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use credentials_core::{
    audit::AuthEventKind,
    engine::RefreshEngine,
    refresh_adapters::HttpTransport,
    store::{AuthEventPrincipal, AuthObservation, GrantOperation},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use subc_protocol::Principal;
use tokio::sync::{watch, Mutex};

const CHALLENGE_URL: &str = "https://account.cortexkit.io/v1/machine/token/challenge";
const TOKEN_URL: &str = "https://account.cortexkit.io/v1/machine/token";
const AUDIENCES: [&str; 3] = [
    "cortexkit-runners",
    "cortexkit-account",
    "cortexkit-webhook-relay",
];

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountTokenParams {
    pub audience: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_ttl_ms: Option<u64>,
}

// No Debug: a cached or returned JWT must never become a diagnostic argument.
#[derive(Clone, Serialize)]
pub struct AccountTokenResult {
    pub jwt: credentials_core::secret::Secret<String>,
    pub expires_at_ms: i64,
    pub audience: String,
    pub account: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AccountTokenError {
    pub code: &'static str,
    pub class: ErrorClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

impl AccountTokenError {
    fn new(code: &'static str, class: ErrorClass) -> Self {
        Self {
            code,
            class,
            retry_after_ms: None,
        }
    }
    fn login() -> Self {
        Self::new("account_login_required", ErrorClass::AuthRequired)
    }
    fn invalid() -> Self {
        Self::new("account_exchange_invalid", ErrorClass::Permanent)
    }
    fn network() -> Self {
        Self::new("account_exchange_unavailable", ErrorClass::Transient)
    }
}

type Mint = Result<AccountTokenResult, AccountTokenError>;
type Flight = watch::Receiver<Option<Mint>>;
#[derive(Default)]
struct Entry {
    identity: String,
    cached: Option<AccountTokenResult>,
    flight: Option<Flight>,
}

pub(super) struct AccountTokens {
    entries: Arc<Mutex<HashMap<String, Entry>>>,
    machine_path: Option<PathBuf>,
    transport: Option<Arc<dyn HttpTransport>>,
    clock: Option<i64>,
}

impl AccountTokens {
    pub(super) fn new() -> Self {
        Self {
            entries: Arc::default(),
            machine_path: None,
            transport: None,
            clock: None,
        }
    }
    fn now(&self) -> i64 {
        if let Some(now) = self.clock {
            return now;
        }
        super::now_ms()
    }
    fn path(&self) -> Result<PathBuf, AccountTokenError> {
        if let Some(path) = &self.machine_path {
            return Ok(path.clone());
        }
        machine_state_path(std::env::var_os("XDG_STATE_HOME"), std::env::var_os("HOME"))
            .ok_or_else(AccountTokenError::login)
    }
}

/// Where `ck account login` records this Mac's enrollment. It must resolve exactly as
/// the account CLI's state path does (a non-empty `XDG_STATE_HOME` first, then
/// `HOME`), or the vault would look in a different place and refuse a machine that
/// is enrolled.
fn machine_state_path(
    xdg_state_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    if let Some(state) = xdg_state_home.filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(state).join("cortexkit/account/machine.json"));
    }
    home.map(|home| PathBuf::from(home).join(".local/state/cortexkit/account/machine.json"))
}

// This is the account CLI's enrollment pointer, not signing authority. Its public
// half and optional vault id must agree with the newest live vault machine key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Machine {
    account: String,
    key_id: Option<String>,
    public_key_hex: String,
    label: String,
    vault_key_id: Option<String>,
    enrollment_jti: Option<String>,
}
struct Signer {
    machine: Machine,
    key_id: String,
    pem: credentials_core::secret::Secret<Vec<u8>>,
    identity: String,
}

fn canonical_id(s: &str) -> bool {
    s.len() == 26
        && (b'0'..=b'7').contains(&s.as_bytes()[0])
        && s.bytes()
            .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
}
fn machine_number(id: &str) -> Option<u64> {
    let text = id.strip_prefix("signing:ck-account-machine:")?;
    let n: u64 = text.parse().ok()?;
    (n > 0 && n.to_string() == text).then_some(n)
}
fn signer(engine: &RefreshEngine, path: &std::path::Path) -> Result<Signer, AccountTokenError> {
    let bytes = credentials_core::resolver::read_owner_only_file(path, 8192)
        .map_err(|_| AccountTokenError::login())?;
    let machine: Machine =
        serde_json::from_slice(&bytes).map_err(|_| AccountTokenError::login())?;
    let key_id = machine
        .key_id
        .clone()
        .filter(|id| canonical_id(id))
        .ok_or_else(AccountTokenError::login)?;
    if !canonical_id(&machine.account)
        || machine.label.is_empty()
        || machine.label.len() > 64
        || machine.label.chars().any(|c| c.is_control() || c == '|')
        || machine
            .enrollment_jti
            .as_ref()
            .is_some_and(|id| !canonical_id(id))
    {
        return Err(AccountTokenError::login());
    }
    let id = engine
        .store()
        .list_meta()
        .map_err(|_| AccountTokenError::login())?
        .into_iter()
        .filter(|(_, meta)| meta.state == credentials_core::record::RecordState::Active)
        .filter_map(|(id, _)| machine_number(&id).map(|n| (n, id)))
        .max_by_key(|(n, _)| *n)
        .map(|(_, id)| id)
        .ok_or_else(AccountTokenError::login)?;
    let record = engine
        .store()
        .get(&id)
        .map_err(|_| AccountTokenError::login())?;
    if record.kind != credentials_core::record::CredentialKind::SigningKey {
        return Err(AccountTokenError::login());
    }
    let pem =
        std::str::from_utf8(record.payload.expose()).map_err(|_| AccountTokenError::login())?;
    let public = credentials_core::signing::public_key_ed25519(pem)
        .map_err(|_| AccountTokenError::login())?;
    if public.public_key_hex != machine.public_key_hex
        || machine.vault_key_id.as_ref().is_some_and(|v| v != &id)
    {
        return Err(AccountTokenError::login());
    }
    let identity = format!(
        "{}|{key_id}|{}|{}",
        machine.account, public.public_key_hex, record.record_version
    );
    Ok(Signer {
        machine,
        key_id,
        pem: record.payload,
        identity,
    })
}

fn decode(s: &str) -> Result<Vec<u8>, AccountTokenError> {
    if s.len() > 16384 {
        return Err(AccountTokenError::invalid());
    }
    let b = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| AccountTokenError::invalid())?;
    if URL_SAFE_NO_PAD.encode(&b) != s {
        return Err(AccountTokenError::invalid());
    }
    Ok(b)
}
fn worker_transcript(
    account: &str,
    key_id: &str,
    challenge: &str,
    audience: &str,
) -> Result<String, AccountTokenError> {
    let (payload, mac) = challenge
        .split_once('.')
        .ok_or_else(AccountTokenError::invalid)?;
    if decode(mac)?.len() != 32 {
        return Err(AccountTokenError::invalid());
    }
    let p: Value =
        serde_json::from_slice(&decode(payload)?).map_err(|_| AccountTokenError::invalid())?;
    // Check before preparing a signature; the full sealed string, not the decoded
    // payload, is embedded verbatim in the proof the account service verifies.
    if p["purpose"] != "worker_token"
        || p["account"] != account
        || p["key_id"] != key_id
        || p["aud"] != audience
    {
        return Err(AccountTokenError::invalid());
    }
    Ok(format!(
        "cortexkit-device-auth|v1|account.cortexkit.io|{account}|{key_id}|{challenge}|{audience}"
    ))
}

fn refusal(status: u16, body: &Value) -> AccountTokenError {
    let code = match body["error"].as_str().unwrap_or("") {
        "invalid_request" => "invalid_request",
        "auth_failed" => "auth_failed",
        "signature_invalid" => "signature_invalid",
        "machine_revoked" => "machine_revoked",
        "machine_not_found" => "machine_not_found",
        "account_not_active" => "account_not_active",
        "challenge_expired" => "challenge_expired",
        "challenge_spent" => "challenge_spent",
        "issuance_expired" => "issuance_expired",
        "rate_limited" => "rate_limited",
        "exchange_disabled" => "exchange_disabled",
        "account_check_unavailable" => "account_check_unavailable",
        _ => "account_exchange_unavailable",
    };
    let class = match status {
        400 => ErrorClass::Permanent,
        401 if matches!(code, "machine_revoked" | "machine_not_found") => ErrorClass::AuthRequired,
        401 if matches!(code, "auth_failed" | "signature_invalid") => ErrorClass::Permanent,
        403 => ErrorClass::AuthRequired,
        _ => ErrorClass::Transient,
    };
    AccountTokenError {
        code,
        class,
        retry_after_ms: matches!(status, 429 | 503)
            .then(|| {
                body["retry_after_s"]
                    .as_u64()
                    .and_then(|s| s.checked_mul(1000))
            })
            .flatten(),
    }
}
async fn post(
    http: &dyn HttpTransport,
    url: &str,
    body: Value,
) -> Result<Value, (u16, AccountTokenError)> {
    let reply = http
        .post(
            url,
            &[],
            "application/json",
            serde_json::to_vec(&body).expect("JSON value"),
        )
        .await
        .map_err(|_| (0, AccountTokenError::network()))?;
    let body: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
    if reply.status != 200 {
        return Err((reply.status, refusal(reply.status, &body)));
    }
    Ok(body)
}

async fn mint(
    http: &dyn HttpTransport,
    signer: &Signer,
    audience: &str,
    engine: &RefreshEngine,
    principal: AuthEventPrincipal<'_>,
    clock: Option<i64>,
) -> Mint {
    for attempt in 0..2 {
        let exchange = async {
            let body = json!({"key_id":signer.key_id,"aud":audience});
            let reply = post(http, CHALLENGE_URL, body).await?;
            let challenge = reply["challenge"].as_str().ok_or_else(|| (0, AccountTokenError::invalid()))?;
            let transcript = worker_transcript(&signer.machine.account, &signer.key_id, challenge, audience)
                .map_err(|e| (0, e))?;
            let pem = std::str::from_utf8(signer.pem.expose()).map_err(|_| (0, AccountTokenError::login()))?;
            let sig = credentials_core::signing::prepare_ed25519(pem, transcript.as_bytes())
                .map_err(|_| (0, AccountTokenError::invalid()))?.sign();
            let raw = base64::engine::general_purpose::STANDARD.decode(sig.signature_b64)
                .map_err(|_| (0, AccountTokenError::invalid()))?;
            let sig_hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            let token = post(http, TOKEN_URL, json!({"key_id":signer.key_id,"aud":audience,"challenge":challenge,"sig_hex":sig_hex})).await?;
            let jwt = token["jwt"].as_str().ok_or_else(|| (0, AccountTokenError::invalid()))?;
            let parts: Vec<_> = jwt.split('.').collect();
            if parts.len() != 3 { return Err((0, AccountTokenError::invalid())); }
            let claims: Value = serde_json::from_slice(&decode(parts[1]).map_err(|e| (0,e))?).map_err(|_| (0, AccountTokenError::invalid()))?;
            let iat = claims["iat"].as_i64().ok_or_else(|| (0, AccountTokenError::invalid()))?;
            let exp = claims["exp"].as_i64().ok_or_else(|| (0, AccountTokenError::invalid()))?;
            if iat.checked_add(900) != Some(exp) || claims["account"] != signer.machine.account || claims["device"] != signer.key_id || claims["aud"] != audience {
                return Err((0, AccountTokenError::invalid()));
            }
            let expires_at_ms = exp.checked_mul(1000).ok_or_else(|| (0, AccountTokenError::invalid()))?;
            if expires_at_ms <= clock.unwrap_or_else(super::now_ms) { return Err((0, AccountTokenError::network())); }
            Ok(AccountTokenResult { jwt: credentials_core::secret::Secret::new(jwt.into()), expires_at_ms, audience: audience.into(), account: signer.machine.account.clone() })
        }.await;
        if let Err((status, error)) = &exchange {
            if error.class == ErrorClass::Permanent {
                tracing::warn!("account worker exchange refused permanently; signer or contract vector may be wrong");
            }
            let _ = engine.store().record_auth_event(
                audience,
                AuthObservation {
                    kind: AuthEventKind::ScopedReadRefusal.as_str(),
                    provider_status: (*status != 0).then_some(*status),
                    detail: Some(error.code),
                    reporter_source: None,
                    principal: Some(principal),
                },
                None,
            );
        }
        match exchange {
            Err((409, _)) if attempt == 0 => continue,
            Err((_, error)) => return Err(error),
            Ok(token) => return Ok(token),
        }
    }
    unreachable!()
}

impl ReadSurface {
    pub async fn account_token(
        &self,
        principal: Option<&Principal>,
        params: &AccountTokenParams,
    ) -> Mint {
        let (kind, id) = self
            .authorize_scoped_as(
                principal,
                params.enrollment_token.as_deref(),
                &params.audience,
                GrantOperation::AccountToken,
            )
            .map_err(|_| AccountTokenError::new("not_found", ErrorClass::Permanent))?;
        if !AUDIENCES.contains(&params.audience.as_str()) {
            return Err(AccountTokenError::new("not_found", ErrorClass::Permanent));
        }
        let config = &self.account_tokens;
        let signer = signer(&self.engine, &config.path()?)?;
        let mut entries = config.entries.lock().await;
        let entry = entries.entry(params.audience.clone()).or_default();
        if entry.identity != signer.identity {
            *entry = Entry {
                identity: signer.identity.clone(),
                ..Entry::default()
            };
        }
        let minimum = params.min_ttl_ms.unwrap_or(0).max(60_000);
        if let Some(token) = &entry.cached {
            if token.expires_at_ms.saturating_sub(config.now()) as i128 > minimum as i128 {
                return Ok(token.clone());
            }
        }
        let mut flight = if let Some(flight) = &entry.flight {
            flight.clone()
        } else {
            let (sender, receiver) = watch::channel(None);
            entry.flight = Some(receiver.clone());
            let audience = params.audience.clone();
            let engine = Arc::clone(&self.engine);
            let entries = Arc::clone(&config.entries);
            let transport = config.transport.clone();
            let clock = config.clock;
            // Detached from the request so cancellation cannot strand waiters or
            // start a second mint while the first is still spending its challenge.
            tokio::spawn(async move {
                let principal = if kind == "reserved" {
                    AuthEventPrincipal::Reserved(&id)
                } else {
                    AuthEventPrincipal::Enrolled(&id)
                };
                let outcome = match transport {
                    Some(http) => {
                        mint(http.as_ref(), &signer, &audience, &engine, principal, clock).await
                    }
                    None => match credentials_core::http::ReqwestTransport::new() {
                        Ok(http) => {
                            mint(&http, &signer, &audience, &engine, principal, clock).await
                        }
                        Err(_) => {
                            let error = AccountTokenError::network();
                            let _ = engine.store().record_auth_event(
                                &audience,
                                AuthObservation {
                                    kind: AuthEventKind::ScopedReadRefusal.as_str(),
                                    provider_status: None,
                                    detail: Some(error.code),
                                    reporter_source: None,
                                    principal: Some(principal),
                                },
                                None,
                            );
                            Err(error)
                        }
                    },
                };
                let mut entries = entries.lock().await;
                if let Some(entry) = entries.get_mut(&audience) {
                    // A re-login can replace the identity while an older exchange is
                    // in flight; its result belongs only to the original waiters.
                    if entry.identity == signer.identity {
                        if let Ok(token) = &outcome {
                            entry.cached = Some(token.clone());
                        }
                        entry.flight = None;
                    }
                }
                sender.send_replace(Some(outcome));
            });
            receiver
        };
        drop(entries);
        loop {
            if let Some(outcome) = flight.borrow().clone() {
                return outcome;
            }
            flight
                .changed()
                .await
                .map_err(|_| AccountTokenError::network())?;
        }
    }
}

#[cfg(test)]
#[path = "account_token_tests.rs"]
mod tests;
