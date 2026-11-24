//! Machine-key exchange shared by the scoped account-token route and the admin relay.

use crate::error_class::ErrorClass;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use credentials_core::{
    audit::AuthEventKind,
    engine::RefreshEngine,
    refresh_adapters::HttpTransport,
    store::{AccountMachineKey, AuthEventPrincipal, AuthObservation, StoreOpError},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc};

const CHALLENGE_URL: &str = "https://account.cortexkit.io/v1/machine/token/challenge";
const TOKEN_URL: &str = "https://account.cortexkit.io/v1/machine/token";
pub(crate) const RELAY_TOKEN_AUDIENCE: &str = "cortexkit-webhook-relay";

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
    pub(crate) fn new(code: &'static str, class: ErrorClass) -> Self {
        Self {
            code,
            class,
            retry_after_ms: None,
        }
    }
    pub(crate) fn login() -> Self {
        Self::new("account_login_required", ErrorClass::AuthRequired)
    }
    fn invalid() -> Self {
        Self::new("account_exchange_invalid", ErrorClass::Permanent)
    }
    pub(crate) fn network() -> Self {
        Self::new("account_exchange_unavailable", ErrorClass::Transient)
    }
}

pub(crate) type Mint = Result<AccountTokenResult, AccountTokenError>;

/// Where `ck account login` records this machine's enrollment. It must resolve exactly as
/// the account CLI's state path does, or the vault would look in a different place and
/// refuse a machine that is enrolled.
///
/// On Windows that is `%LOCALAPPDATA%\cortexkit\account`, ignoring the XDG variables, the
/// same way the supervisor places its own data on Windows. Elsewhere a non-empty
/// `XDG_STATE_HOME` wins, then `HOME/.local/state`. Empty variables count as unset.
pub(crate) fn machine_state_path(
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
pub(crate) struct Machine {
    account: String,
    key_id: Option<String>,
    public_key_hex: String,
    label: String,
    vault_key_id: Option<String>,
    enrollment_jti: Option<String>,
}
pub(crate) struct Signer {
    machine: Machine,
    credential_id: String,
    key_id: String,
    pem: credentials_core::secret::Secret<Vec<u8>>,
}
pub(crate) struct Candidate {
    machine: Machine,
    key_id: String,
    row: AccountMachineKey,
    // The federation probe has no scoped cache.
    #[allow(dead_code)]
    pub(crate) identity: String,
}

pub(crate) fn canonical_id(s: &str) -> bool {
    s.len() == 26
        && (b'0'..=b'7').contains(&s.as_bytes()[0])
        && s.bytes()
            .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
}

pub(crate) enum CandidateError {
    NoMachineKey,
    Unusable,
}

pub(crate) fn candidate(
    engine: &RefreshEngine,
    path: &std::path::Path,
) -> Result<Candidate, CandidateError> {
    let bytes =
        credentials_core::resolver::read_owner_only_file(path, 8192).map_err(|e| match e {
            credentials_core::resolver::MasterKeyError::Io(error)
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                CandidateError::NoMachineKey
            }
            _ => CandidateError::Unusable,
        })?;
    let machine: Machine = serde_json::from_slice(&bytes).map_err(|_| CandidateError::Unusable)?;
    let key_id = machine
        .key_id
        .clone()
        .filter(|id| canonical_id(id))
        .ok_or(CandidateError::Unusable)?;
    if !canonical_id(&machine.account)
        || machine.label.is_empty()
        || machine.label.len() > 64
        || machine.label.chars().any(|c| c.is_control() || c == '|')
        || machine
            .enrollment_jti
            .as_ref()
            .is_some_and(|id| !canonical_id(id))
    {
        return Err(CandidateError::Unusable);
    }
    let row = engine
        .store()
        .active_account_machine_key()
        .map_err(|error| match error {
            StoreOpError::NotFound => CandidateError::NoMachineKey,
            _ => CandidateError::Unusable,
        })?;
    let (id, incarnation, version, digest) = row.identity();
    if machine.vault_key_id.as_deref().is_some_and(|v| v != id) {
        return Err(CandidateError::Unusable);
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

pub(crate) fn signer(
    engine: &RefreshEngine,
    candidate: Candidate,
) -> Result<Signer, AccountTokenError> {
    let Candidate {
        machine,
        key_id,
        row,
        ..
    } = candidate;
    let record = engine
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

pub(crate) fn decode(s: &str) -> Result<Vec<u8>, AccountTokenError> {
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
pub(crate) fn worker_transcript(
    account: &str,
    key_id: &str,
    challenge: &str,
    audience: &str,
) -> Result<String, AccountTokenError> {
    let (payload, mac) = challenge
        .split_once('.')
        .ok_or_else(AccountTokenError::network)?;
    let decode_reply = |part| decode(part).map_err(|_| AccountTokenError::network());
    if decode_reply(mac)?.len() != 32 {
        return Err(AccountTokenError::network());
    }
    let p: Value = serde_json::from_slice(&decode_reply(payload)?)
        .map_err(|_| AccountTokenError::network())?;
    let fields = ["purpose", "account", "key_id", "aud"].map(|field| p[field].as_str());
    let [Some(purpose), Some(bound_account), Some(bound_key), Some(bound_audience)] = fields else {
        return Err(AccountTokenError::network());
    };
    // Check before preparing a signature; the full sealed string, not the decoded
    // payload, is embedded verbatim in the proof the account service verifies.
    if purpose != "worker_token"
        || bound_account != account
        || bound_key != key_id
        || bound_audience != audience
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
    success_field: &str,
) -> Result<String, (u16, AccountTokenError)> {
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
    body.get(success_field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| (reply.status, AccountTokenError::network()))
}

pub(crate) async fn mint(
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
            let challenge = post(http, CHALLENGE_URL, body, "challenge").await?;
            let transcript = worker_transcript(&signer.machine.account, &signer.key_id, &challenge, audience)
                .map_err(|e| (200, e))?;
            let pem = std::str::from_utf8(signer.pem.expose()).map_err(|_| (0, AccountTokenError::login()))?;
            credentials_core::signing::validate_signing_input(&signer.credential_id, transcript.as_bytes())
                .map_err(|_| (0, AccountTokenError::new("invalid_params", ErrorClass::Permanent)))?;
            let sig = credentials_core::signing::prepare_ed25519(pem, transcript.as_bytes())
                .map_err(|_| (0, AccountTokenError::invalid()))?.sign();
            let raw = base64::engine::general_purpose::STANDARD.decode(sig.signature_b64)
                .map_err(|_| (0, AccountTokenError::invalid()))?;
            let sig_hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            let jwt = post(http, TOKEN_URL, json!({"key_id":signer.key_id,"aud":audience,"challenge":challenge,"sig_hex":sig_hex}), "jwt").await?;
            let malformed = || (200, AccountTokenError::network());
            let parts: Vec<_> = jwt.split('.').collect();
            if parts.len() != 3 { return Err(malformed()); }
            let claims: Value = serde_json::from_slice(&decode(parts[1]).map_err(|_| malformed())?).map_err(|_| malformed())?;
            let iat = claims["iat"].as_i64().ok_or_else(malformed)?;
            let exp = claims["exp"].as_i64().ok_or_else(malformed)?;
            let [Some(account), Some(device), Some(bound_audience)] = ["account", "device", "aud"].map(|field| claims[field].as_str()) else {
                return Err(malformed());
            };
            if iat.checked_add(900) != Some(exp) || account != signer.machine.account || device != signer.key_id || bound_audience != audience {
                return Err((200, AccountTokenError::invalid()));
            }
            let expires_at_ms = exp.checked_mul(1000).ok_or_else(|| (0, AccountTokenError::invalid()))?;
            if expires_at_ms <= clock.unwrap_or_else(wall_now_ms) { return Err((0, AccountTokenError::network())); }
            Ok(AccountTokenResult { jwt: credentials_core::secret::Secret::new(jwt), expires_at_ms, audience: audience.into(), account: signer.machine.account.clone() })
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

pub(crate) async fn observe_refusal(
    engine: &RefreshEngine,
    audience: &str,
    principal: AuthEventPrincipal<'_>,
    status: u16,
    code: &'static str,
) {
    let store = Arc::clone(engine.store());
    let audience = audience.to_owned();
    let (kind, id) = match principal {
        AuthEventPrincipal::Reserved(id) => ("reserved", id.to_owned()),
        AuthEventPrincipal::Enrolled(id) => ("enrolled", id.to_owned()),
        _ => ("direct", String::new()),
    };
    let _ = tokio::task::spawn_blocking(move || {
        let principal = match kind {
            "reserved" => AuthEventPrincipal::Reserved(&id),
            "enrolled" => AuthEventPrincipal::Enrolled(&id),
            _ => AuthEventPrincipal::Direct,
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

pub(crate) enum RelayTokenError {
    NoMachineKey,
    MintFailed,
}

/// The caller must already have passed admin admission. This exchange is not
/// detached or cached: the admin operation's deadline can cancel its HTTP work.
pub(crate) async fn mint_relay_token(
    engine: &Arc<RefreshEngine>,
    http: &dyn HttpTransport,
    machine_path: Option<PathBuf>,
    clock: Option<i64>,
) -> Result<AccountTokenResult, RelayTokenError> {
    let engine_for_preflight = Arc::clone(engine);
    let signer = tokio::task::spawn_blocking(move || {
        let path = machine_path
            .or_else(|| machine_state_path(cfg!(windows), |name| std::env::var_os(name)))
            .ok_or(RelayTokenError::NoMachineKey)?;
        let key = candidate(&engine_for_preflight, &path).map_err(|error| match error {
            CandidateError::NoMachineKey => RelayTokenError::NoMachineKey,
            CandidateError::Unusable => RelayTokenError::MintFailed,
        })?;
        signer(&engine_for_preflight, key).map_err(|_| RelayTokenError::MintFailed)
    })
    .await
    .map_err(|_| RelayTokenError::MintFailed)??;
    mint(
        http,
        &signer,
        RELAY_TOKEN_AUDIENCE,
        engine,
        AuthEventPrincipal::Direct,
        clock,
    )
    .await
    .map_err(|_| RelayTokenError::MintFailed)
}

fn wall_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
