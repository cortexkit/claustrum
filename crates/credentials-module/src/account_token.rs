//! Audience-scoped account exchange. Private machine material stays inside the vault;
//! callers can select only an audience covered by their operation-specific grant.
use super::{ErrorClass, ReadSurface};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use credentials_core::{
    audit::AuthEventKind,
    engine::RefreshEngine,
    refresh_adapters::HttpTransport,
    store::{AccountMachineKey, AuthEventPrincipal, AuthObservation, GrantOperation},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
#[cfg(test)]
use subc_protocol::Principal;
use tokio::sync::{watch, Mutex};

const CHALLENGE_URL: &str = "https://account.cortexkit.io/v1/machine/token/challenge";
const TOKEN_URL: &str = "https://account.cortexkit.io/v1/machine/token";
use credentials_core::store::ACCOUNT_TOKEN_AUDIENCES as AUDIENCES;

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

impl Entry {
    fn token(&self, now: i64, minimum: u64) -> Option<AccountTokenResult> {
        self.cached
            .as_ref()
            .filter(|token| token.expires_at_ms.saturating_sub(now) as i128 > minimum as i128)
            .cloned()
    }
}

pub(super) struct AccountTokens {
    entries: Arc<Mutex<HashMap<String, Entry>>>,
    machine_path: Option<PathBuf>,
    transport: Option<Arc<dyn HttpTransport>>,
    clock: Option<i64>,
    #[cfg(test)]
    signer_opens: std::sync::atomic::AtomicUsize,
}

impl AccountTokens {
    pub(super) fn new() -> Self {
        Self {
            entries: Arc::default(),
            machine_path: None,
            transport: None,
            clock: None,
            #[cfg(test)]
            signer_opens: 0.into(),
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
        machine_state_path(cfg!(windows), |name| std::env::var_os(name))
            .ok_or_else(AccountTokenError::login)
    }
}

/// Where `ck account login` records this machine's enrollment. It must resolve exactly as
/// the account CLI's state path does, or the vault would look in a different place and
/// refuse a machine that is enrolled.
///
/// On Windows that is `%LOCALAPPDATA%\cortexkit\account`, ignoring the XDG variables, the
/// same way the supervisor places its own data on Windows. Elsewhere a non-empty
/// `XDG_STATE_HOME` wins, then `HOME/.local/state`. Empty variables count as unset.
fn machine_state_path(
    windows: bool,
    var: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    let set = |name: &str| {
        var(name)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    };
    let state = if windows {
        set("LOCALAPPDATA")?
    } else if let Some(state) = set("XDG_STATE_HOME") {
        state
    } else {
        set("HOME")?.join(".local").join("state")
    };
    Some(state.join("cortexkit").join("account").join("machine.json"))
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
    credential_id: String,
    key_id: String,
    pem: credentials_core::secret::Secret<Vec<u8>>,
}
struct Candidate {
    machine: Machine,
    key_id: String,
    row: AccountMachineKey,
    identity: String,
}

fn canonical_id(s: &str) -> bool {
    s.len() == 26
        && (b'0'..=b'7').contains(&s.as_bytes()[0])
        && s.bytes()
            .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
}
fn candidate(
    engine: &RefreshEngine,
    path: &std::path::Path,
) -> Result<Candidate, AccountTokenError> {
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
    let row = engine
        .store()
        .active_account_machine_key()
        .map_err(|_| AccountTokenError::login())?;
    let (id, incarnation, version, digest) = row.identity();
    if machine.vault_key_id.as_deref().is_some_and(|v| v != id) {
        return Err(AccountTokenError::login());
    }
    // Match the machine file's account and public key to the selected vault row.
    // Include its incarnation and version, and digest the envelope to catch damage
    // that did not bump the version.
    let identity = format!(
        "{}|{key_id}|{id}|{incarnation}|{version}|{digest}|{}",
        machine.account, machine.public_key_hex
    );
    Ok(Candidate {
        machine,
        key_id,
        row,
        identity,
    })
}

fn signer(surface: &ReadSurface, candidate: Candidate) -> Result<Signer, AccountTokenError> {
    #[cfg(test)]
    surface
        .account_tokens
        .signer_opens
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let Candidate {
        machine,
        key_id,
        row,
        ..
    } = candidate;
    let record = surface
        .engine
        .store()
        .open_account_machine_key(&row)
        .map_err(|_| AccountTokenError::login())?;
    if record.kind != credentials_core::record::CredentialKind::SigningKey {
        return Err(AccountTokenError::login());
    }
    let pem =
        std::str::from_utf8(record.payload.expose()).map_err(|_| AccountTokenError::login())?;
    let public = credentials_core::signing::public_key_ed25519(pem)
        .map_err(|_| AccountTokenError::login())?;
    if public.public_key_hex != machine.public_key_hex {
        return Err(AccountTokenError::login());
    }
    Ok(Signer {
        machine,
        credential_id: row.identity().0.to_owned(),
        key_id,
        pem: record.payload,
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
        _ => return AccountTokenError::network(),
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
    let body = serde_json::from_slice(&reply.body);
    if reply.status != 200 {
        return Err((
            reply.status,
            refusal(reply.status, &body.unwrap_or(Value::Null)),
        ));
    }
    body.map_err(|_| (reply.status, AccountTokenError::network()))
}

async fn mint(
    http: &dyn HttpTransport,
    signer: &Signer,
    audience: &str,
    engine: &RefreshEngine,
    principal: (&'static str, &str),
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
            credentials_core::signing::validate_signing_input(&signer.credential_id, transcript.as_bytes())
                .map_err(|_| (0, AccountTokenError::new("invalid_params", ErrorClass::Permanent)))?;
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
            observe_refusal(engine, audience, principal, *status, error.code).await;
        }
        match exchange {
            Err((409, _)) if attempt == 0 => continue,
            Err((_, error)) => return Err(error),
            Ok(token) => return Ok(token),
        }
    }
    unreachable!()
}

async fn observe_refusal(
    engine: &RefreshEngine,
    audience: &str,
    (kind, id): (&'static str, &str),
    status: u16,
    code: &'static str,
) {
    let store = Arc::clone(engine.store());
    let audience = audience.to_owned();
    let id = id.to_owned();
    let _ = tokio::task::spawn_blocking(move || {
        let principal = if kind == "reserved" {
            AuthEventPrincipal::Reserved(&id)
        } else {
            AuthEventPrincipal::Enrolled(&id)
        };
        store.record_auth_event(
            &audience,
            AuthObservation {
                kind: AuthEventKind::ScopedReadRefusal.as_str(),
                provider_status: (status != 0).then_some(status),
                detail: Some(code),
                reporter_source: None,
                principal: Some(principal),
            },
            None,
        )
    })
    .await;
}

async fn wait_for_flight(mut flight: Flight) -> Mint {
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

impl ReadSurface {
    pub async fn account_token(
        self: &Arc<Self>,
        caller: &crate::federation::ingress::ScopedCaller,
        params: &AccountTokenParams,
    ) -> Mint {
        let config = &self.account_tokens;
        // Queue preflights ahead of exchange completion, so requests already
        // checking the same key can share even a failed exchange. Release the
        // guard before waiting on HTTP or on another request's result.
        let mut entries = config.entries.lock().await;
        let surface = Arc::clone(self);
        let caller = caller.clone();
        let audience = params.audience.clone();
        let enrollment_token = params.enrollment_token.clone();
        let (kind, id, candidate) = tokio::task::spawn_blocking(move || {
            let (kind, id) = surface
                .authorize_scoped_as(
                    &caller,
                    enrollment_token.as_deref(),
                    &audience,
                    GrantOperation::AccountToken,
                )
                .map_err(|_| AccountTokenError::new("not_found", ErrorClass::Permanent))?;
            if !AUDIENCES.contains(&audience.as_str())
                || (audience == "cortexkit-hub" && (kind != "reserved" || id != "ckbus"))
            {
                return Err(AccountTokenError::new("not_found", ErrorClass::Permanent));
            }
            let key = candidate(&surface.engine, &surface.account_tokens.path()?)?;
            Ok((kind, id, key))
        })
        .await
        .map_err(|_| AccountTokenError::network())??;
        let minimum = params.min_ttl_ms.unwrap_or(0).max(60_000);
        if let Some(entry) = entries
            .get(&params.audience)
            .filter(|entry| entry.identity == candidate.identity)
        {
            if let Some(token) = entry.token(config.now(), minimum) {
                return Ok(token);
            }
            if let Some(flight) = entry.flight.clone() {
                drop(entries);
                return wait_for_flight(flight).await;
            }
        }
        let identity = candidate.identity.clone();
        let surface = Arc::clone(self);
        let signer = tokio::task::spawn_blocking(move || signer(&surface, candidate))
            .await
            .map_err(|_| AccountTokenError::network())??;

        let flight = {
            let (sender, receiver) = watch::channel(None);
            let entry = entries.entry(params.audience.clone()).or_default();
            if entry.identity != identity {
                *entry = Entry {
                    identity: identity.clone(),
                    ..Entry::default()
                };
            }
            entry.flight = Some(receiver.clone());
            let audience = params.audience.clone();
            let engine = Arc::clone(&self.engine);
            let entries = Arc::clone(&config.entries);
            let transport = config.transport.clone();
            let clock = config.clock;
            // Detached from the request so cancellation cannot strand waiters or
            // start a second mint while the first is still spending its challenge.
            tokio::spawn(async move {
                let principal = (kind, id.as_str());
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
                            observe_refusal(&engine, &audience, principal, 0, error.code).await;
                            Err(error)
                        }
                    },
                };
                let mut entries = entries.lock().await;
                if let Some(entry) = entries.get_mut(&audience) {
                    // A re-login can replace the identity while an older exchange is
                    // in flight; its result belongs only to the original waiters.
                    if entry.identity == identity {
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
        wait_for_flight(flight).await
    }
}

#[cfg(test)]
#[path = "account_token_tests.rs"]
mod tests;
