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

/// Build the provider authorize URL the operator opens in a browser. Mirrors the
/// first-party plugin's param set exactly: `code=true`, `client_id`,
/// `response_type=code`, `redirect_uri`, space-joined `scope`, `code_challenge`,
/// `code_challenge_method=S256`, `state`.
pub fn build_authorize_url(
    authorize_url: &str,
    client_id: &str,
    redirect_uri: &str,
    scopes: &[&str],
    challenge: &str,
    state: &str,
) -> Result<String, url::ParseError> {
    let mut url = url::Url::parse(authorize_url)?;
    url.query_pairs_mut()
        .append_pair("code", "true")
        .append_pair("client_id", client_id)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", &scopes.join(" "))
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", CODE_CHALLENGE_METHOD)
        .append_pair("state", state);
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
/// returns no refresh token cannot become a custodied credential.
#[derive(Debug, Deserialize)]
struct ExchangeResponseBody {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
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
    })
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
}
