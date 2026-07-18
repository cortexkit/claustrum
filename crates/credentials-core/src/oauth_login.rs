//! Vault-native first-party OAuth login (the authorization-code half of OAuth).
//!
//! The refresh adapters ([`crate::refresh_adapters`]) own the `grant_type=refresh_token`
//! exchange for a credential the vault ALREADY holds. This module owns the OTHER
//! half: minting a brand-new credential by driving an interactive authorization-code
//! login with PKCE, so the vault becomes the SOLE custodian of an INDEPENDENT refresh
//! token (its own rotation chain) rather than sharing a chain imported from another
//! custodian. That independence is what structurally eliminates the dual-custody
//! refresh-rotation race: two independently-minted grants for the same account are
//! separate chains and do not invalidate each other.
//!
//! ## The custody boundary
//!
//! This is PURE MECHANISM: PKCE generation, authorize-URL construction, callback
//! parsing, and the code-for-token exchange over the shared [`HttpTransport`]. It
//! opens NO browser and runs NO inbound redirect listener — the interactive half
//! (opening the URL, capturing the pasted code) belongs to the offline CLI driver,
//! and later the CK app. The vault daemon stays headless. The chosen redirect shape
//! is MANUAL CODE-PASTE (the provider hosts a page that displays the code), so there
//! is zero inbound network surface on either the CLI or the daemon.
//!
//! ## Fidelity
//!
//! The wire shape (authorize params, PKCE method, the exact token-exchange body incl.
//! the non-standard `state` field the provider expects) is pinned against the
//! first-party CortexKit `anthropic-auth` plugin — the working Claude Pro/Max login —
//! not invented here. Provider-specific constants (authorize URL, callback URL,
//! scopes) live with that provider's adapter; this module is provider-agnostic.

use serde::Deserialize;

use crate::refresh_adapters::{HttpTransport, RefreshError};
use crate::store::base64url;

/// A PKCE verifier/challenge pair (RFC 7636, method S256).
#[derive(Debug, Clone)]
pub struct Pkce {
    /// The high-entropy secret sent ONLY in the final token exchange. Never leaves
    /// the process before then; never logged.
    pub verifier: String,
    /// `base64url(sha256(verifier))` — the public value placed in the authorize URL.
    pub challenge: String,
}

/// The PKCE challenge method. The provider (Anthropic Claude Code client) requires
/// S256; the plain method is never used.
pub const CODE_CHALLENGE_METHOD: &str = "S256";

/// Generate a PKCE pair: a 256-bit CSPRNG verifier (base64url, 43 chars, within the
/// RFC 7636 43-128 unreserved-char range) and its SHA-256 challenge.
pub fn generate_pkce() -> Result<Pkce, getrandom::Error> {
    use sha2::{Digest, Sha256};
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)?;
    let verifier = base64url(&bytes);
    let challenge = base64url(&Sha256::digest(verifier.as_bytes()));
    Ok(Pkce {
        verifier,
        challenge,
    })
}

/// Generate the CSPRNG `state` (256 bits, base64url) that binds the authorize
/// request to its callback. Generated INDEPENDENTLY of the verifier (never derived
/// from it) so a leaked state reveals nothing about the verifier.
pub fn generate_state() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)?;
    Ok(base64url(&bytes))
}

/// Build the provider authorize URL the operator opens in a browser: the RFC param
/// set (`client_id`, `response_type=code`, `redirect_uri`, space-joined `scope`,
/// `code_challenge`, `code_challenge_method=S256`, `state`) plus whatever
/// provider-specific `extra_params` the provider's wire requires (Anthropic's
/// non-standard `code=true`; OpenAI's `id_token_add_organizations` etc. — each
/// pinned in that provider's adapter constants).
pub fn build_authorize_url(
    authorize_url: &str,
    client_id: &str,
    redirect_uri: &str,
    scopes: &[&str],
    challenge: &str,
    state: &str,
    extra_params: &[(&str, &str)],
) -> Result<String, url::ParseError> {
    let mut url = url::Url::parse(authorize_url)?;
    {
        let mut pairs = url.query_pairs_mut();
        for (k, v) in extra_params {
            pairs.append_pair(k, v);
        }
        pairs
            .append_pair("client_id", client_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &scopes.join(" "))
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", CODE_CHALLENGE_METHOD)
            .append_pair("state", state);
    }
    Ok(url.to_string())
}

/// A parsed authorization callback: the code and the returned state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Callback {
    pub code: String,
    pub state: String,
}

/// Parse whatever the operator pastes back. Accepts three shapes (mirroring the
/// first-party plugin so any form the provider's callback page presents works):
/// a full callback URL (`?code=..&state=..`), the bare `code#state` fragment the
/// manual page renders, or a raw `code=..&state=..` querystring. Returns `None` if
/// neither a code nor a state can be recovered.
pub fn parse_callback(input: &str) -> Option<Callback> {
    let trimmed = input.trim();

    // 1. A full URL with query params.
    if let Ok(url) = url::Url::parse(trimmed) {
        let mut code = None;
        let mut state = None;
        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "code" => code = Some(v.into_owned()),
                "state" => state = Some(v.into_owned()),
                _ => {}
            }
        }
        if let (Some(code), Some(state)) = (code, state) {
            return Some(Callback { code, state });
        }
    }

    // 2. The manual `code#state` form.
    if let Some((code, state)) = trimmed.split_once('#') {
        if !code.is_empty() && !state.is_empty() && !code.contains('&') {
            return Some(Callback {
                code: code.to_string(),
                state: state.to_string(),
            });
        }
    }

    // 3. A bare querystring `code=..&state=..`.
    let mut code = None;
    let mut state = None;
    for pair in trimmed.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            match k {
                "code" => code = Some(v.to_string()),
                "state" => state = Some(v.to_string()),
                _ => {}
            }
        }
    }
    match (code, state) {
        (Some(code), Some(state)) => Some(Callback { code, state }),
        _ => None,
    }
}

/// The tokens minted by a successful login. Same shape as a refresh result, so the
/// caller stores them through the existing `OAuthCredential`/`VaultRecord` path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at_ms: Option<i64>,
    /// The OIDC id_token, when the provider issues one (OpenAI does; Anthropic does
    /// not). Carried so the caller can read identity claims (e.g. the ChatGPT account
    /// id) — never stored in the credential record.
    pub id_token: Option<String>,
    /// Non-secret account identity disclosed by the exchange response itself
    /// (Anthropic inlines `account`/`organization` blocks; form-wire providers leave
    /// this empty and identity comes from id_token claims instead).
    pub account: Option<ExchangeAccount>,
    pub organization: Option<ExchangeOrganization>,
}

/// The `account` block of Anthropic's token exchange response: the provider-stable
/// account uuid and the login email. Non-secret display/routing metadata.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ExchangeAccount {
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub email_address: Option<String>,
}

/// The `organization` block of Anthropic's token exchange response: the workspace
/// the token draws subscription limits from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ExchangeOrganization {
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// A login failure.
#[derive(Debug)]
pub enum LoginError {
    /// The pasted callback could not be parsed into a code+state pair.
    Unparseable,
    /// The returned state did not match the state we generated — a forged or
    /// stale callback; the exchange is refused BEFORE any network call.
    StateMismatch,
    /// A transport/HTTP error reaching the token endpoint.
    Transport(String),
    /// The token endpoint returned a non-success status (the body is included for
    /// the operator, but never the pasted code).
    Status(u16, String),
    /// A success status with an undecodable body.
    Decode(String),
    /// A terminal device-flow error that is safe to show without echoing a response body.
    Device(String),
}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoginError::Unparseable => {
                write!(f, "could not parse the pasted authorization callback")
            }
            LoginError::StateMismatch => {
                write!(f, "authorization state mismatch (forged or stale callback)")
            }
            LoginError::Transport(m) => write!(f, "login transport error: {m}"),
            LoginError::Status(code, m) => write!(f, "login token exchange failed ({code}): {m}"),
            LoginError::Decode(m) => write!(f, "login response decode error: {m}"),
            LoginError::Device(m) => write!(f, "device login failed: {m}"),
        }
    }
}

impl std::error::Error for LoginError {}

impl From<RefreshError> for LoginError {
    fn from(e: RefreshError) -> Self {
        LoginError::Transport(e.to_string())
    }
}

/// The success response body of the authorization-code exchange. `refresh_token` is
/// REQUIRED here (unlike a refresh response, where it is optional) — a login that
/// returns no refresh token cannot become a custodied credential. The optional
/// `account`/`organization` identity blocks are Anthropic's (uuid + email, org name);
/// they ride the same response and are captured as non-secret metadata.
#[derive(Debug, Deserialize)]
struct ExchangeResponseBody {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    #[serde(default)]
    account: Option<ExchangeAccount>,
    #[serde(default)]
    organization: Option<ExchangeOrganization>,
}

/// The success response body of the STANDARD (RFC 6749/7636) form-encoded exchange
/// (OpenAI Codex). `id_token` is present for OIDC providers; `expires_in` is not
/// guaranteed by the official Codex browser flow, so it is optional.
#[derive(Debug, Deserialize)]
struct FormExchangeResponseBody {
    access_token: String,
    refresh_token: String,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    id_token: Option<String>,
}

/// Validate the callback's state against the expected state, then exchange the code
/// for tokens at the provider's token endpoint. State is checked BEFORE the network
/// call so a mismatched callback never reaches the provider.
///
/// The request body mirrors the first-party plugin verbatim (incl. the non-standard
/// `state` field the provider expects): JSON `{code, state, grant_type, client_id,
/// redirect_uri, code_verifier}`. `now_ms` is injected so the conformance test can
/// assert a deterministic `expires_at_ms`.
#[allow(clippy::too_many_arguments)]
pub async fn exchange_authorization_code(
    http: &dyn HttpTransport,
    token_url: &str,
    client_id: &str,
    redirect_uri: &str,
    callback: &Callback,
    expected_state: &str,
    verifier: &str,
    now_ms: i64,
) -> Result<LoginTokens, LoginError> {
    if callback.state != expected_state {
        return Err(LoginError::StateMismatch);
    }

    let body = serde_json::json!({
        "code": callback.code,
        "state": callback.state,
        "grant_type": "authorization_code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
    });
    let body = serde_json::to_vec(&body).expect("serializing a fixed-shape json body never fails");

    let resp = http.post(token_url, &[], "application/json", body).await?;

    if resp.status != 200 {
        return Err(LoginError::Status(
            resp.status,
            String::from_utf8_lossy(&resp.body).into_owned(),
        ));
    }

    let parsed: ExchangeResponseBody =
        serde_json::from_slice(&resp.body).map_err(|e| LoginError::Decode(e.to_string()))?;

    Ok(LoginTokens {
        access_token: parsed.access_token,
        refresh_token: parsed.refresh_token,
        expires_at_ms: Some(now_ms + parsed.expires_in.saturating_mul(1000)),
        // Anthropic's exchange issues no id_token; its identity rides the response's
        // account/organization blocks instead.
        id_token: None,
        account: parsed.account,
        organization: parsed.organization,
    })
}

/// The STANDARD authorization-code exchange (RFC 6749 + 7636): form-encoded body
/// `grant_type=authorization_code&code&redirect_uri&client_id&code_verifier`, NO
/// non-standard `state` field in the body (state is still validated here, before the
/// network call). This is the wire the official OpenAI Codex CLI uses; providers that
/// deviate (Anthropic's JSON body with an embedded `state`) use
/// [`exchange_authorization_code`] instead.
///
/// `extra_body` appends provider-specific form fields after the standard set. OpenAI
/// passes none (byte-identical to the RFC body); xAI passes `code_challenge` +
/// `code_challenge_method` because its public-client token endpoint expects the
/// challenge echoed alongside the verifier (matching the Grok CLI / Hermes flow).
#[allow(clippy::too_many_arguments)]
pub async fn exchange_authorization_code_form(
    http: &dyn HttpTransport,
    token_url: &str,
    client_id: &str,
    redirect_uri: &str,
    callback: &Callback,
    expected_state: &str,
    verifier: &str,
    extra_body: &[(&str, &str)],
    now_ms: i64,
) -> Result<LoginTokens, LoginError> {
    if callback.state != expected_state {
        return Err(LoginError::StateMismatch);
    }

    let mut fields: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", callback.code.as_str()),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", verifier),
    ];
    fields.extend_from_slice(extra_body);
    let body = crate::refresh_adapters::form_urlencode(&fields);

    let resp = http
        .post(
            token_url,
            &[],
            "application/x-www-form-urlencoded",
            body.into_bytes(),
        )
        .await?;

    if resp.status != 200 {
        return Err(LoginError::Status(
            resp.status,
            String::from_utf8_lossy(&resp.body).into_owned(),
        ));
    }

    let parsed: FormExchangeResponseBody =
        serde_json::from_slice(&resp.body).map_err(|e| LoginError::Decode(e.to_string()))?;

    Ok(LoginTokens {
        access_token: parsed.access_token,
        refresh_token: parsed.refresh_token,
        expires_at_ms: parsed.expires_in.map(|s| now_ms + s.saturating_mul(1000)),
        id_token: parsed.id_token,
        account: None,
        organization: None,
    })
}

/// Decode the payload claims of a JWT WITHOUT signature verification. Used only to
/// read non-secret identity metadata (the ChatGPT account id) out of a token that was
/// just received directly from the provider's token endpoint over TLS — the transport
/// is the trust anchor, exactly as the official Codex CLI treats it. Never used to
/// make an authorization decision.
pub fn decode_jwt_claims(token: &str) -> Option<serde_json::Value> {
    let payload_b64 = token.split('.').nth(1)?;
    let bytes = base64url_decode(payload_b64)?;
    serde_json::from_slice(&bytes).ok()
}

/// Read the ChatGPT account id out of one JWT's claims: the claim path is
/// `"https://api.openai.com/auth"."chatgpt_account_id"` (verified against the official
/// Codex CLI's token_data.rs). `None` when the token does not carry it.
fn chatgpt_account_id_from_jwt(jwt: &str) -> Option<String> {
    decode_jwt_claims(jwt)?
        .get("https://api.openai.com/auth")?
        .get("chatgpt_account_id")?
        .as_str()
        .map(str::to_string)
}

/// Extract the ChatGPT account id from a freshly-minted OpenAI token set. Tries the
/// id_token first (the official browser-flow source), then the access token — the same
/// fallback order the ecosystem uses. Used at login time to sanity-warn the operator.
pub fn extract_chatgpt_account_id(tokens: &LoginTokens) -> Option<String> {
    tokens
        .id_token
        .as_deref()
        .and_then(chatgpt_account_id_from_jwt)
        .or_else(|| chatgpt_account_id_from_jwt(&tokens.access_token))
}

/// The per-provider account-identity claim table: given a credential's stored refresh
/// adapter and the access token being served, return the NON-SECRET provider account id
/// (the identity the token executes under), or `None` when the adapter has no known
/// account claim or the token does not carry one.
///
/// This is the single home for provider claim-path knowledge, so a consumer never
/// re-implements JWT extraction. Parse-live (from the exact token being served) rather
/// than persisted, so the returned id always matches the served token with no migration
/// or drift between a stored column and a refreshed token. Like [`decode_jwt_claims`] it
/// only reads non-secret metadata from a TLS-delivered token; never an authz decision.
///
/// Providers are keyed by the adapter name [`crate::credential_id::default_refresh_adapter`]
/// stores on the record. `openai` covers both `chatgpt:openai` and `oauth:openai` (a
/// plain oauth:openai token simply carries no chatgpt_account_id claim → `None`). Add a
/// provider row here when a consumer needs its account id.
pub fn account_id_for_adapter(adapter: &str, access_token: &str) -> Option<String> {
    match adapter {
        "openai" => chatgpt_account_id_from_jwt(access_token),
        _ => None,
    }
}

/// Base64url-decode (no padding) — JWT segments use the unpadded alphabet.
fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    // Reverse of `base64url`: restore padding, translate the URL-safe alphabet, and
    // decode manually (no external base64 dependency in this crate).
    let translated: String = s
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let padded = match translated.len() % 4 {
        0 => translated,
        2 => format!("{translated}=="),
        3 => format!("{translated}="),
        _ => return None,
    };
    // Minimal base64 decoder over the standard alphabet.
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(padded.len() / 4 * 3);
    let mut buf = 0u32;
    let mut bits = 0u8;
    for ch in padded.bytes() {
        if ch == b'=' {
            break;
        }
        let val = ALPHABET.iter().position(|&a| a == ch)? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refresh_adapters::fixture::FixtureTransport;

    // The Anthropic (Claude Pro/Max) constants, pinned against the first-party
    // anthropic-auth plugin, used to exercise the real wire shape.
    const AUTHORIZE_URL: &str = "https://claude.com/cai/oauth/authorize";
    const TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";
    const CALLBACK_URL: &str = "https://platform.claude.com/oauth/code/callback";
    const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
    const SCOPES: &[&str] = &[
        "org:create_api_key",
        "user:profile",
        "user:inference",
        "user:sessions:claude_code",
        "user:mcp_servers",
        "user:file_upload",
    ];

    #[test]
    fn pkce_challenge_is_sha256_of_verifier() {
        use sha2::{Digest, Sha256};
        let pkce = generate_pkce().unwrap();
        // The challenge is base64url(sha256(verifier)) — recompute and compare.
        let expected = base64url(&Sha256::digest(pkce.verifier.as_bytes()));
        assert_eq!(pkce.challenge, expected);
        // A 256-bit value base64url-encodes to 43 chars (no padding), within the
        // RFC 7636 43-128 range.
        assert_eq!(pkce.verifier.len(), 43);
    }

    #[test]
    fn state_is_independent_of_verifier() {
        // Two fresh generations differ (CSPRNG), and state is not derived from the
        // verifier: generate a pkce and a state and confirm no relationship.
        let pkce = generate_pkce().unwrap();
        let state = generate_state().unwrap();
        assert_ne!(state, pkce.verifier);
        assert_ne!(state, pkce.challenge);
        assert_eq!(state.len(), 43);
        // Distinct calls yield distinct states.
        assert_ne!(generate_state().unwrap(), generate_state().unwrap());
    }

    #[test]
    fn authorize_url_carries_the_pinned_params() {
        let url = build_authorize_url(
            AUTHORIZE_URL,
            CLIENT_ID,
            CALLBACK_URL,
            SCOPES,
            "CHALLENGE",
            "STATE123",
            &[("code", "true")],
        )
        .unwrap();
        let parsed = url::Url::parse(&url).unwrap();
        let pairs: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(pairs["code"], "true");
        assert_eq!(pairs["client_id"], CLIENT_ID);
        assert_eq!(pairs["response_type"], "code");
        assert_eq!(pairs["redirect_uri"], CALLBACK_URL);
        assert_eq!(
            pairs["scope"],
            "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
        );
        assert_eq!(pairs["code_challenge"], "CHALLENGE");
        assert_eq!(pairs["code_challenge_method"], "S256");
        assert_eq!(pairs["state"], "STATE123");
        assert!(parsed.host_str().unwrap().contains("claude.com"));
    }

    #[test]
    fn xai_authorize_url_carries_the_grok_flow_params_and_nonce() {
        use crate::refresh_adapters::xai;
        // Reproduce how the login driver composes xAI's authorize params: the pinned
        // extras (plan + referrer) plus a per-flow nonce appended for the openid scope.
        let mut params: Vec<(&str, &str)> = xai::LOGIN_EXTRA_AUTHORIZE_PARAMS.to_vec();
        params.push(("nonce", "NONCE-xyz"));
        let url = build_authorize_url(
            xai::AUTHORIZE_URL,
            xai::GROK_CLI_CLIENT_ID,
            xai::LOGIN_REDIRECT_URI,
            xai::LOGIN_SCOPES,
            "CHALLENGE",
            "STATE123",
            &params,
        )
        .unwrap();
        let parsed = url::Url::parse(&url).unwrap();
        let pairs: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(parsed.host_str().unwrap(), "auth.x.ai");
        assert_eq!(pairs["client_id"], xai::GROK_CLI_CLIENT_ID);
        assert_eq!(pairs["response_type"], "code");
        assert_eq!(pairs["redirect_uri"], "http://127.0.0.1:56121/callback");
        assert_eq!(pairs["code_challenge_method"], "S256");
        // Load-bearing xAI-specific params for this public client.
        assert_eq!(pairs["plan"], "generic");
        assert_eq!(pairs["referrer"], "hermes-agent");
        assert_eq!(pairs["nonce"], "NONCE-xyz");
        // offline_access is what grants the refresh token; openid drives the nonce.
        let scope = &pairs["scope"];
        assert!(scope.contains("offline_access"), "scope: {scope}");
        assert!(scope.contains("openid"), "scope: {scope}");
        assert!(scope.contains("api:access"), "scope: {scope}");
    }

    #[test]
    fn parse_callback_accepts_hash_form() {
        let cb = parse_callback("  abc123#STATE456  ").unwrap();
        assert_eq!(cb.code, "abc123");
        assert_eq!(cb.state, "STATE456");
    }

    #[test]
    fn parse_callback_accepts_full_url() {
        let cb = parse_callback(
            "https://platform.claude.com/oauth/code/callback?code=abc123&state=STATE456",
        )
        .unwrap();
        assert_eq!(cb.code, "abc123");
        assert_eq!(cb.state, "STATE456");
    }

    #[test]
    fn parse_callback_accepts_bare_querystring() {
        let cb = parse_callback("code=abc123&state=STATE456").unwrap();
        assert_eq!(cb.code, "abc123");
        assert_eq!(cb.state, "STATE456");
    }

    #[test]
    fn parse_callback_rejects_garbage() {
        assert!(parse_callback("not-a-callback").is_none());
        assert!(parse_callback("").is_none());
    }

    #[tokio::test]
    async fn exchange_rejects_state_mismatch_before_network() {
        // A forged callback (wrong state) must be refused WITHOUT any HTTP call.
        let http = FixtureTransport::new(vec![]); // empty queue: any post() would panic
        let cb = Callback {
            code: "code".into(),
            state: "FORGED".into(),
        };
        let err = exchange_authorization_code(
            &http,
            TOKEN_URL,
            CLIENT_ID,
            CALLBACK_URL,
            &cb,
            "EXPECTED",
            "verifier",
            1000,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, LoginError::StateMismatch));
        // Proof no network happened: the fixture recorded zero requests.
        assert_eq!(http.requests().len(), 0);
    }

    #[tokio::test]
    async fn exchange_sends_the_pinned_body_and_parses_tokens() {
        // A recorded-shape success response (fidelity: same shape as the refresh
        // response — access_token, refresh_token, expires_in).
        let body = br#"{"access_token":"acc-NEW","refresh_token":"ref-NEW","expires_in":28800}"#;
        let http = FixtureTransport::ok(200, body.to_vec());
        let cb = Callback {
            code: "the-code".into(),
            state: "STATE".into(),
        };
        let tokens = exchange_authorization_code(
            &http,
            TOKEN_URL,
            CLIENT_ID,
            CALLBACK_URL,
            &cb,
            "STATE",
            "the-verifier",
            1_000_000,
        )
        .await
        .unwrap();

        assert_eq!(tokens.access_token, "acc-NEW");
        assert_eq!(tokens.refresh_token, "ref-NEW");
        assert_eq!(tokens.expires_at_ms, Some(1_000_000 + 28_800 * 1000));
        // No identity blocks in the response ⇒ none captured (no fabrication).
        assert!(tokens.account.is_none());
        assert!(tokens.organization.is_none());

        // Assert the EXACT bytes sent: JSON to the token endpoint with the pinned
        // field set (incl. the non-standard `state` field the provider expects).
        let reqs = http.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].url, TOKEN_URL);
        assert_eq!(reqs[0].content_type, "application/json");
        let sent: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(sent["grant_type"], "authorization_code");
        assert_eq!(sent["code"], "the-code");
        assert_eq!(sent["state"], "STATE");
        assert_eq!(sent["client_id"], CLIENT_ID);
        assert_eq!(sent["redirect_uri"], CALLBACK_URL);
        assert_eq!(sent["code_verifier"], "the-verifier");
    }

    #[tokio::test]
    async fn exchange_captures_account_and_organization_identity() {
        // The recorded-shape response WITH Anthropic's inline identity blocks (the
        // shape the claude.ai exchange returns; field names verified against the
        // oh-my-pi reference client). Unknown sub-fields are ignored.
        let body = br#"{"access_token":"acc","refresh_token":"ref","expires_in":3600,
            "account":{"uuid":"acct-uuid-1","email_address":"op@example.com"},
            "organization":{"uuid":"org-uuid-1","name":"op@example.com's Organization"}}"#;
        let http = FixtureTransport::ok(200, body.to_vec());
        let cb = Callback {
            code: "c".into(),
            state: "STATE".into(),
        };
        let tokens = exchange_authorization_code(
            &http,
            TOKEN_URL,
            CLIENT_ID,
            CALLBACK_URL,
            &cb,
            "STATE",
            "v",
            0,
        )
        .await
        .unwrap();
        let account = tokens.account.expect("account captured");
        assert_eq!(account.uuid.as_deref(), Some("acct-uuid-1"));
        assert_eq!(account.email_address.as_deref(), Some("op@example.com"));
        let org = tokens.organization.expect("organization captured");
        assert_eq!(org.name.as_deref(), Some("op@example.com's Organization"));
    }

    #[tokio::test]
    async fn exchange_surfaces_provider_error_status() {
        let http = FixtureTransport::ok(400, br#"{"error":"invalid_grant"}"#.to_vec());
        let cb = Callback {
            code: "code".into(),
            state: "STATE".into(),
        };
        let err = exchange_authorization_code(
            &http,
            TOKEN_URL,
            CLIENT_ID,
            CALLBACK_URL,
            &cb,
            "STATE",
            "verifier",
            0,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, LoginError::Status(400, _)));
    }

    // ── The STANDARD form-encoded exchange (OpenAI Codex wire) ────────────────

    // The OpenAI Codex login constants, pinned against the first-party openai-auth
    // plugin (same wire as the official codex CLI browser flow).
    const OPENAI_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
    const OPENAI_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
    const OPENAI_REDIRECT: &str = "http://localhost:1455/auth/callback";

    /// Build an unsigned JWT with the given JSON payload (alg is irrelevant — claims
    /// decoding never validates the signature; transport is the trust anchor).
    fn fake_jwt(payload: &serde_json::Value) -> String {
        let header = base64url(br#"{"alg":"none","typ":"JWT"}"#);
        let body = base64url(payload.to_string().as_bytes());
        format!("{header}.{body}.sig")
    }

    #[tokio::test]
    async fn form_exchange_sends_the_rfc_body_and_parses_id_token() {
        let id_token = fake_jwt(&serde_json::json!({
            "https://api.openai.com/auth": { "chatgpt_account_id": "acct-uuid-1" },
            "email": "u@example.com",
        }));
        let body = serde_json::json!({
            "access_token": "acc-OAI",
            "refresh_token": "ref-OAI",
            "id_token": id_token,
        });
        let http = FixtureTransport::ok(200, serde_json::to_vec(&body).unwrap());
        let cb = Callback {
            code: "the-code".into(),
            state: "STATE".into(),
        };
        let tokens = exchange_authorization_code_form(
            &http,
            OPENAI_TOKEN_URL,
            OPENAI_CLIENT_ID,
            OPENAI_REDIRECT,
            &cb,
            "STATE",
            "the-verifier",
            &[],
            1_000_000,
        )
        .await
        .unwrap();

        assert_eq!(tokens.access_token, "acc-OAI");
        assert_eq!(tokens.refresh_token, "ref-OAI");
        // No expires_in in the official browser-flow response: no stored expiry
        // (the refresh path treats an empty/absent expiry as refresh-on-first-use).
        assert_eq!(tokens.expires_at_ms, None);

        // The EXACT bytes sent: FORM-encoded RFC body, NO non-standard state field.
        let reqs = http.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].url, OPENAI_TOKEN_URL);
        assert_eq!(reqs[0].content_type, "application/x-www-form-urlencoded");
        let sent = String::from_utf8(reqs[0].body.clone()).unwrap();
        assert!(sent.contains("grant_type=authorization_code"));
        assert!(sent.contains("code=the-code"));
        assert!(sent.contains("client_id=app_EMoamEEZ73f0CkXaXp7hrann"));
        assert!(sent.contains("code_verifier=the-verifier"));
        assert!(sent.contains("redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback"));
        assert!(
            !sent.contains("state="),
            "RFC body must not carry state: {sent}"
        );

        // The account id extracts from the id_token's nested claim path.
        assert_eq!(
            extract_chatgpt_account_id(&tokens).as_deref(),
            Some("acct-uuid-1")
        );
    }

    const XAI_TOKEN_URL: &str = "https://auth.x.ai/oauth2/token";
    const XAI_CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";
    const XAI_REDIRECT: &str = "http://127.0.0.1:56121/callback";

    #[tokio::test]
    async fn xai_form_exchange_echoes_the_pkce_challenge_and_parses_the_bare_refresh() {
        // xAI's public-client token endpoint expects the PKCE challenge echoed in the
        // exchange body (verified against the opencode-grok-auth plugin, which mirrors
        // Hermes Agent's live flow). The refresh token comes back BARE (no packing) and
        // is stored verbatim — the same shape the xAI refresh adapter already sends.
        let body = serde_json::json!({
            "access_token": "acc-XAI",
            "refresh_token": "ref-XAI-bare",
            "expires_in": 3600,
            "token_type": "Bearer",
        });
        let http = FixtureTransport::ok(200, serde_json::to_vec(&body).unwrap());
        let cb = Callback {
            code: "xai-code".into(),
            state: "XSTATE".into(),
        };
        let tokens = exchange_authorization_code_form(
            &http,
            XAI_TOKEN_URL,
            XAI_CLIENT_ID,
            XAI_REDIRECT,
            &cb,
            "XSTATE",
            "xai-verifier",
            &[
                ("code_challenge", "xai-challenge"),
                ("code_challenge_method", "S256"),
            ],
            2_000_000,
        )
        .await
        .unwrap();

        assert_eq!(tokens.access_token, "acc-XAI");
        assert_eq!(tokens.refresh_token, "ref-XAI-bare");
        assert_eq!(tokens.expires_at_ms, Some(2_000_000 + 3600 * 1000));

        // The EXACT bytes: the standard fields PLUS the echoed challenge, form-encoded,
        // and no non-standard state field.
        let reqs = http.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].url, XAI_TOKEN_URL);
        assert_eq!(reqs[0].content_type, "application/x-www-form-urlencoded");
        let sent = String::from_utf8(reqs[0].body.clone()).unwrap();
        assert!(sent.contains("grant_type=authorization_code"));
        assert!(sent.contains("code=xai-code"));
        assert!(sent.contains("client_id=b1a00492-073a-47ea-816f-4c329264a828"));
        assert!(sent.contains("code_verifier=xai-verifier"));
        assert!(
            sent.contains("code_challenge=xai-challenge"),
            "xAI exchange must echo the PKCE challenge: {sent}"
        );
        assert!(
            sent.contains("code_challenge_method=S256"),
            "xAI exchange must echo the challenge method: {sent}"
        );
        assert!(
            sent.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A56121%2Fcallback"),
            "redirect must be the loopback callback: {sent}"
        );
        assert!(
            !sent.contains("state="),
            "RFC body must not carry state: {sent}"
        );
    }

    #[tokio::test]
    async fn xai_form_exchange_rejects_state_mismatch_before_network() {
        let http = FixtureTransport::new(vec![]);
        let cb = Callback {
            code: "code".into(),
            state: "FORGED".into(),
        };
        let err = exchange_authorization_code_form(
            &http,
            XAI_TOKEN_URL,
            XAI_CLIENT_ID,
            XAI_REDIRECT,
            &cb,
            "EXPECTED",
            "verifier",
            &[("code_challenge", "c"), ("code_challenge_method", "S256")],
            0,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, LoginError::StateMismatch));
        assert_eq!(http.requests().len(), 0);
    }

    #[test]
    fn account_id_for_adapter_reads_openai_claim_from_the_served_access_token() {
        // The vault serves the ACCESS token (it persists no id_token), so the account
        // id must resolve from the access token itself — not only the login-time id_token.
        let access = fake_jwt(&serde_json::json!({
            "https://api.openai.com/auth": { "chatgpt_account_id": "acct-served-42" },
            "exp": 4_102_444_800i64,
        }));
        assert_eq!(
            account_id_for_adapter("openai", &access).as_deref(),
            Some("acct-served-42")
        );
    }

    #[test]
    fn account_id_for_adapter_is_none_when_the_openai_token_lacks_the_claim() {
        // A plain oauth:openai token (or any OpenAI token without the ChatGPT claim)
        // yields None rather than a fabricated id.
        let access = fake_jwt(&serde_json::json!({ "sub": "user-1", "exp": 4_102_444_800i64 }));
        assert_eq!(account_id_for_adapter("openai", &access), None);
    }

    #[test]
    fn account_id_for_adapter_gates_by_provider_and_does_not_leak_across_adapters() {
        // The per-provider table is the guard: a token that DOES carry the OpenAI claim
        // must NOT surface an account id under a different adapter — the claim path is
        // openai-specific, and another provider's account identity lives elsewhere. This
        // proves the match arm is load-bearing, not incidental.
        let access = fake_jwt(&serde_json::json!({
            "https://api.openai.com/auth": { "chatgpt_account_id": "acct-openai-only" },
        }));
        assert_eq!(account_id_for_adapter("anthropic", &access), None);
        assert_eq!(account_id_for_adapter("xai", &access), None);
        assert_eq!(account_id_for_adapter("antigravity", &access), None);
    }

    #[test]
    fn account_id_for_adapter_returns_none_on_a_malformed_token_without_panicking() {
        // A non-JWT / truncated payload must fail closed to None, never panic on the
        // serve path.
        assert_eq!(account_id_for_adapter("openai", "not-a-jwt"), None);
        assert_eq!(account_id_for_adapter("openai", "only.two"), None);
        assert_eq!(account_id_for_adapter("openai", ""), None);
    }

    #[tokio::test]
    async fn form_exchange_rejects_state_mismatch_before_network() {
        let http = FixtureTransport::new(vec![]);
        let cb = Callback {
            code: "code".into(),
            state: "FORGED".into(),
        };
        let err = exchange_authorization_code_form(
            &http,
            OPENAI_TOKEN_URL,
            OPENAI_CLIENT_ID,
            OPENAI_REDIRECT,
            &cb,
            "EXPECTED",
            "verifier",
            &[],
            0,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, LoginError::StateMismatch));
        assert_eq!(http.requests().len(), 0);
    }

    #[test]
    fn account_id_falls_back_to_the_access_token_claims() {
        // No id_token: the nested claim on the ACCESS token is used (the ecosystem
        // fallback order; llm-runner's transport reads the same access-token claim).
        let access = fake_jwt(&serde_json::json!({
            "https://api.openai.com/auth": { "chatgpt_account_id": "acct-from-access" },
        }));
        let tokens = LoginTokens {
            access_token: access,
            refresh_token: "r".into(),
            expires_at_ms: None,
            id_token: None,
            account: None,
            organization: None,
        };
        assert_eq!(
            extract_chatgpt_account_id(&tokens).as_deref(),
            Some("acct-from-access")
        );

        // No claim anywhere: None (the CLI warns; the consumer fails loud on read).
        let bare = LoginTokens {
            access_token: fake_jwt(&serde_json::json!({"email":"x@y.z"})),
            refresh_token: "r".into(),
            expires_at_ms: None,
            id_token: None,
            account: None,
            organization: None,
        };
        assert_eq!(extract_chatgpt_account_id(&bare), None);
    }

    #[test]
    fn jwt_claims_decode_handles_base64url_payloads() {
        // A payload whose base64url form contains '-'/'_' and needs padding
        // restoration — exercises the manual decoder.
        let payload = serde_json::json!({"k": "value~with?special>chars", "n": 7});
        let jwt = fake_jwt(&payload);
        let decoded = decode_jwt_claims(&jwt).unwrap();
        assert_eq!(decoded["k"], "value~with?special>chars");
        assert_eq!(decoded["n"], 7);
        // Garbage is None, never a panic.
        assert!(decode_jwt_claims("not-a-jwt").is_none());
        assert!(decode_jwt_claims("a.!!!.c").is_none());
    }
}
