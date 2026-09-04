//! The OpenAI / ChatGPT (Codex) OAuth refresh adapter.
//!
//! Refreshes the OAuth tokens minted by the Codex / ChatGPT-subscription login flow
//! (the `~/.codex/auth.json` `{ tokens: { access_token, refresh_token, ... } }`
//! entry). The refresh exchange is a JSON `refresh_token` grant to OpenAI's token
//! endpoint with the public Codex client id.
//!
//! Two provider-specific shapes the wire-format research pinned down (verified
//! against the official `openai/codex` CLI source, not invented):
//! - A dead/revoked refresh token is reported as a NESTED error code
//!   (`{"error":{"code":"refresh_token_expired" | "refresh_token_reused" |
//!   "refresh_token_invalidated"}}`) on a 400 OR 401 — NOT a flat `invalid_grant`.
//! - The official refresh path does not consume `expires_in` (the CLI reads the
//!   access token's own JWT expiry), so it is parsed optionally here and absence
//!   yields no stored expiry rather than a decode failure.
//!
//! The refresh token rotates (single-use), so a response that omits `refresh_token`
//! reuses the existing one. OpenAI exposes a revocation endpoint but no
//! non-mutating introspection, so [`RefreshAdapter::non_mutating_check`] stays
//! `None`.

use async_trait::async_trait;
use serde::Deserialize;

use super::{HttpTransport, RefreshAdapter, RefreshError, RefreshedTokens};
use crate::oauth::OAuthCredential;

/// OpenAI's OAuth token endpoint for the refresh-token grant (the endpoint the
/// official Codex CLI uses).
pub const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";

/// The public Codex OAuth client id (the same id the official Codex CLI uses).
pub const CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";

/// The adapter name, matching `VaultRecord::refresh_adapter` for OpenAI records.
pub const ADAPTER_NAME: &str = "openai";

// ── First-party login (authorization-code) constants ──────────────────────────
// Pinned against the first-party CortexKit `openai-auth` plugin (the proven working
// ChatGPT-subscription login; same wire as the official Codex CLI's browser flow),
// used by `ck-auth login --provider openai`.

/// OpenAI's OAuth authorization endpoint (the Codex browser-flow authorize URL).
pub const AUTHORIZE_URL: &str = "https://auth.openai.com/oauth/authorize";

/// The redirect target registered for the Codex client. OpenAI matches this string
/// EXACTLY against the client's registered redirect URI, so it MUST be `localhost`
/// (not `127.0.0.1`) and MUST use port 1455 — a mismatch fails authorize with
/// `authorize_hydra_invalid_request`. The vault CLI runs NO listener on this port:
/// the browser's navigation to it fails (connection refused) and the operator pastes
/// the full URL from the address bar back into the CLI. The code in that URL is
/// useless to any local interceptor without the PKCE verifier, which never leaves
/// the CLI process.
pub const LOGIN_REDIRECT_URI: &str = "http://localhost:1455/auth/callback";

/// The OAuth scopes requested at login (the first-party plugin's proven set —
/// identity + offline_access for the rotating refresh token; the official CLI's
/// extra `api.connectors.*` scopes are for features the vault does not consume).
pub const LOGIN_SCOPES: &[&str] = &["openid", "profile", "email", "offline_access"];

/// Extra authorize-URL parameters the Codex flow expects beyond the RFC set,
/// mirrored from the first-party plugin: organizations embedded into the id_token
/// (account-id extraction), the simplified confirmation flow, and the client
/// originator label.
pub const LOGIN_EXTRA_AUTHORIZE_PARAMS: &[(&str, &str)] = &[
    ("id_token_add_organizations", "true"),
    ("codex_cli_simplified_flow", "true"),
    ("originator", "opencode"),
];

/// The success response of the refresh exchange. Only `access_token` is reliably
/// present; `refresh_token` is rotated (optional — reuse the old when absent), and
/// `expires_in` is not part of the official refresh contract (optional).
#[derive(Debug, Deserialize)]
struct RefreshResponseBody {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
}

/// An OpenAI error envelope: `{"error":{"code":"..."}}`. Used to recognize the
/// dead-refresh-token codes.
#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    error: Option<ErrorBody>,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    code: Option<String>,
}

/// The OpenAI refresh adapter.
#[derive(Debug, Default)]
pub struct OpenAiAdapter;

impl OpenAiAdapter {
    pub fn new() -> Self {
        OpenAiAdapter
    }

    fn request_body(cred: &OAuthCredential) -> Vec<u8> {
        let client_id = cred.client_id.as_deref().unwrap_or(CODEX_CLIENT_ID);
        let body = serde_json::json!({
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": cred.refresh_token.expose(),
        });
        serde_json::to_vec(&body).expect("serializing a fixed-shape json body never fails")
    }

    fn endpoint(cred: &OAuthCredential) -> &str {
        if cred.token_url.is_empty() {
            TOKEN_URL
        } else {
            cred.token_url.as_str()
        }
    }

    /// Whether a body carries one of OpenAI's dead-refresh-token error codes.
    fn is_dead_refresh_token(body: &[u8]) -> bool {
        serde_json::from_slice::<ErrorEnvelope>(body)
            .ok()
            .and_then(|e| e.error)
            .and_then(|e| e.code)
            .map(|code| {
                matches!(
                    code.as_str(),
                    "refresh_token_expired" | "refresh_token_reused" | "refresh_token_invalidated"
                )
            })
            .unwrap_or(false)
    }
}

#[async_trait]
impl RefreshAdapter for OpenAiAdapter {
    fn name(&self) -> &str {
        ADAPTER_NAME
    }

    async fn refresh(
        &self,
        cred: &OAuthCredential,
        http: &dyn HttpTransport,
    ) -> Result<RefreshedTokens, RefreshError> {
        let body = Self::request_body(cred);
        let resp = http
            .post(Self::endpoint(cred), &[], "application/json", body)
            .await?;

        // A dead refresh token arrives as a nested error code on 400 or 401.
        if resp.status == 400 || resp.status == 401 {
            let text = String::from_utf8_lossy(&resp.body);
            if Self::is_dead_refresh_token(&resp.body) {
                return Err(RefreshError::InvalidGrant(text.into_owned()));
            }
            return Err(RefreshError::Status(resp.status, text.into_owned()));
        }
        if resp.status != 200 {
            return Err(RefreshError::Status(
                resp.status,
                String::from_utf8_lossy(&resp.body).into_owned(),
            ));
        }

        let parsed: RefreshResponseBody =
            serde_json::from_slice(&resp.body).map_err(|e| RefreshError::Decode(e.to_string()))?;
        let expires_at_ms = parsed
            .expires_in
            .map(|secs| now_ms() + secs.saturating_mul(1000));
        let refresh_token = parsed
            .refresh_token
            .unwrap_or_else(|| cred.refresh_token.expose().to_string());
        Ok(RefreshedTokens {
            access_token: parsed.access_token.into(),
            refresh_token: refresh_token.into(),
            expires_at_ms,
            github_app_permissions: None,
        })
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refresh_adapters::fixture::FixtureTransport;

    fn cred() -> OAuthCredential {
        OAuthCredential {
            access_token: "old-access".to_string().into(),
            refresh_token: "old-refresh".to_string().into(),
            expires_at_ms: Some(0),
            token_url: TOKEN_URL.into(),
            client_id: Some(CODEX_CLIENT_ID.into()),
            scopes: vec![],
        }
    }

    // The official Codex refresh parser reads access_token + refresh_token (rotated).
    const RECORDED_SUCCESS: &str =
        r#"{"access_token":"new-access","refresh_token":"new-refresh","id_token":"jwt..."}"#;

    #[tokio::test]
    async fn refresh_parses_rotated_tokens_absent_expiry_is_none() {
        let http = FixtureTransport::ok(200, RECORDED_SUCCESS.as_bytes().to_vec());
        let tokens = OpenAiAdapter::new().refresh(&cred(), &http).await.unwrap();
        assert_eq!(tokens.access_token.expose(), "new-access");
        assert_eq!(
            tokens.refresh_token.expose(),
            "new-refresh",
            "refresh token rotated"
        );
        assert_eq!(
            tokens.expires_at_ms, None,
            "no expires_in in the official refresh response => no stored expiry"
        );
    }

    #[tokio::test]
    async fn refresh_without_rotation_reuses_existing() {
        let http = FixtureTransport::ok(200, br#"{"access_token":"a"}"#.to_vec());
        let tokens = OpenAiAdapter::new().refresh(&cred(), &http).await.unwrap();
        assert_eq!(
            tokens.refresh_token.expose(),
            "old-refresh",
            "reuse existing when absent"
        );
    }

    #[tokio::test]
    async fn request_posts_json_refresh_grant() {
        let http = FixtureTransport::ok(200, RECORDED_SUCCESS.as_bytes().to_vec());
        OpenAiAdapter::new().refresh(&cred(), &http).await.unwrap();
        let reqs = http.requests();
        assert_eq!(reqs[0].url, TOKEN_URL);
        assert_eq!(reqs[0].content_type, "application/json");
        let sent: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(sent["grant_type"], "refresh_token");
        assert_eq!(sent["client_id"], CODEX_CLIENT_ID);
        assert_eq!(sent["refresh_token"], "old-refresh");
    }

    #[tokio::test]
    async fn nested_dead_token_codes_map_to_invalid_grant() {
        // Each of OpenAI's dead-refresh codes, on both 400 and 401, must be a dead
        // token (not a generic status error).
        for (status, code) in [
            (401, "refresh_token_expired"),
            (400, "refresh_token_reused"),
            (401, "refresh_token_invalidated"),
        ] {
            let body = format!(r#"{{"error":{{"code":"{code}"}}}}"#);
            let http = FixtureTransport::ok(status, body.into_bytes());
            match OpenAiAdapter::new().refresh(&cred(), &http).await {
                Err(RefreshError::InvalidGrant(_)) => {}
                other => panic!("expected InvalidGrant for {code}@{status}, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn unrelated_400_is_status_not_dead_token() {
        // A 400 that is NOT a dead-refresh code must not be branded a dead token.
        let http = FixtureTransport::ok(400, br#"{"error":{"code":"invalid_request"}}"#.to_vec());
        match OpenAiAdapter::new().refresh(&cred(), &http).await {
            Err(RefreshError::Status(400, _)) => {}
            other => panic!("expected Status(400), got {other:?}"),
        }
    }
}
