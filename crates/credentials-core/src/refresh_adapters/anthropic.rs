//! The Anthropic (Claude Pro/Max) OAuth refresh adapter.
//!
//! Refreshes the OAuth tokens minted by the Claude Code / opencode login flow (the
//! `auth.json` `{refresh, access, expires}` entry). The refresh exchange POSTs a
//! JSON `refresh_token` grant to Anthropic's OAuth token endpoint with the public
//! Claude Code client id. Anthropic ROTATES the refresh token (returns a new one),
//! which is exactly why this vault's crash-safe rotation matters — though it is not
//! guaranteed on every response, so a response that omits `refresh_token` reuses the
//! existing one (the same defensive behavior the Claude Code client uses).
//!
//! Anthropic exposes no non-mutating refresh-token introspection endpoint, so
//! [`RefreshAdapter::non_mutating_check`] is left at its `None` default: a refresh
//! interrupted by a crash resolves to `needs_reauth` (a rare re-login) rather than
//! a probe.
//!
//! The wire constants and request/response shape are pinned in the conformance
//! tests against a RECORDED response (the fidelity rule); they are not invented
//! here.

use async_trait::async_trait;
use serde::Deserialize;

use super::{HttpTransport, RefreshAdapter, RefreshError, RefreshedTokens};
use crate::oauth::OAuthCredential;

/// Anthropic's current OAuth token endpoint for the refresh-token grant (the
/// endpoint the current Claude Code client uses; the older `console.anthropic.com`
/// host is legacy). A credential's canonical `token_url`, when set at import,
/// overrides this.
pub const TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";

/// The public Claude Code OAuth client id (the same id the Claude Code / opencode
/// login flow uses; not a secret — it identifies the public client). The SAME id is
/// used for the authorization-code login flow, so a vault-native login mints tokens
/// the existing refresh adapter can refresh with no per-record client override.
pub const CLAUDE_CODE_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";

/// The adapter name, matching `VaultRecord::refresh_adapter` for Anthropic records.
pub const ADAPTER_NAME: &str = "anthropic";

// ── First-party login (authorization-code) constants ──────────────────────────
// Pinned against the Claude Code loopback flow (verified in the oh-my-pi reference
// implementation and live on-box): authorize at claude.ai, redirect to the fixed
// loopback callback the CLI listens on, exchange at api.anthropic.com. Used by
// `ck-auth login --provider anthropic`.

/// The Claude Pro/Max authorization endpoint the operator's browser is opened to
/// (distinct from the token endpoint).
pub const AUTHORIZE_URL: &str = "https://claude.ai/oauth/authorize";

/// The token endpoint the LOGIN exchange posts to, and the `token_url` stored on
/// records minted by login (refresh follows it; the same endpoint serves the
/// refresh grant). Distinct from the legacy [`TOKEN_URL`] default that pre-login
/// imported records carry.
pub const LOGIN_TOKEN_URL: &str = "https://api.anthropic.com/v1/oauth/token";

/// Anthropic's non-standard extra authorize param, sent on this flow by the
/// first-party clients.
pub const LOGIN_EXTRA_AUTHORIZE_PARAMS: &[(&str, &str)] = &[("code", "true")];

/// The registered loopback redirect for the Claude Code authorization flow. The CLI
/// binds it one-shot to capture the code redirect; if the bind fails the browser
/// lands on connection-refused and the operator pastes the address-bar URL instead
/// (same posture as the OpenAI/xAI loopback redirects).
pub const LOGIN_REDIRECT_URI: &str = "http://localhost:54545/callback";

/// The OAuth scopes requested at login (the Claude Pro/Max + Claude Code scope set).
pub const LOGIN_SCOPES: &[&str] = &[
    "org:create_api_key",
    "user:profile",
    "user:inference",
    "user:sessions:claude_code",
    "user:mcp_servers",
    "user:file_upload",
];

/// The success response body shape of the refresh exchange. Anthropic returns the
/// new access token and a relative `expires_in` (seconds). The rotated
/// `refresh_token` is OPTIONAL: when the response omits it, the existing refresh
/// token is reused (the Claude Code client does the same), so a non-rotating
/// refresh never drops the credential's ability to refresh again. Extra fields
/// (`scope`, `token_type`, `account`, `organization`) are ignored.
#[derive(Debug, Deserialize)]
struct RefreshResponseBody {
    access_token: String,
    /// The new refresh token, when the provider rotated it. Absent ⇒ reuse the old.
    #[serde(default)]
    refresh_token: Option<String>,
    /// Access-token lifetime in seconds from now.
    expires_in: i64,
}

/// The Anthropic refresh adapter.
#[derive(Debug, Default)]
pub struct AnthropicAdapter;

impl AnthropicAdapter {
    pub fn new() -> Self {
        AnthropicAdapter
    }

    /// Build the JSON refresh request body for a credential. Separated so the
    /// conformance test can assert the exact bytes sent.
    fn request_body(cred: &OAuthCredential) -> Vec<u8> {
        // The client id is taken from the credential when present (canonicalized at
        // import), falling back to the public Claude Code id.
        let client_id = cred.client_id.as_deref().unwrap_or(CLAUDE_CODE_CLIENT_ID);
        let body = serde_json::json!({
            "grant_type": "refresh_token",
            "refresh_token": cred.refresh_token.expose(),
            "client_id": client_id,
        });
        serde_json::to_vec(&body).expect("serializing a fixed-shape json body never fails")
    }

    /// The endpoint to POST to: the credential's canonical `token_url` when set,
    /// else Anthropic's known endpoint.
    fn endpoint(cred: &OAuthCredential) -> &str {
        if cred.token_url.is_empty() {
            TOKEN_URL
        } else {
            cred.token_url.as_str()
        }
    }
}

#[async_trait]
impl RefreshAdapter for AnthropicAdapter {
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

        // A 400 invalid_grant is a definitively dead refresh token (revoked /
        // already rotated away) → the credential needs re-auth.
        if resp.status == 400 {
            let text = String::from_utf8_lossy(&resp.body);
            if text.contains("invalid_grant") {
                return Err(RefreshError::InvalidGrant(text.into_owned()));
            }
            return Err(RefreshError::Status(400, text.into_owned()));
        }
        if resp.status != 200 {
            return Err(RefreshError::Status(
                resp.status,
                String::from_utf8_lossy(&resp.body).into_owned(),
            ));
        }

        let parsed: RefreshResponseBody =
            serde_json::from_slice(&resp.body).map_err(|e| RefreshError::Decode(e.to_string()))?;

        // Anthropic returns a relative expires_in (seconds); convert to an absolute
        // Unix-ms expiry so the stored credential carries a wall-clock deadline.
        let expires_at_ms = Some(now_ms() + parsed.expires_in.saturating_mul(1000));
        // Reuse the existing refresh token if the provider did not rotate it (the
        // field is optional on the wire).
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
            client_id: Some(CLAUDE_CODE_CLIENT_ID.into()),
            scopes: vec![],
        }
    }

    // A RECORDED-shape Anthropic success body (rotated refresh token + expires_in),
    // matching the current Claude Code wire format: Bearer token_type, a rotated
    // refresh token, relative expires_in seconds, and the Claude Code scope string.
    const RECORDED_SUCCESS: &str = r#"{"token_type":"Bearer","access_token":"sk-ant-oat01-new-access","refresh_token":"sk-ant-ort01-new-refresh","expires_in":28800,"scope":"user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"}"#;

    // A success body that OMITS refresh_token (a non-rotating refresh): the adapter
    // must reuse the existing refresh token rather than fail to decode.
    const RECORDED_SUCCESS_NO_ROTATION: &str =
        r#"{"token_type":"Bearer","access_token":"sk-ant-oat01-new","expires_in":28800}"#;

    #[tokio::test]
    async fn refresh_parses_rotated_tokens_and_absolute_expiry() {
        let http = FixtureTransport::ok(200, RECORDED_SUCCESS.as_bytes().to_vec());
        let before = now_ms();
        let tokens = AnthropicAdapter::new()
            .refresh(&cred(), &http)
            .await
            .unwrap();
        assert_eq!(tokens.access_token.expose(), "sk-ant-oat01-new-access");
        assert_eq!(
            tokens.refresh_token.expose(),
            "sk-ant-ort01-new-refresh",
            "refresh token rotated"
        );
        let exp = tokens.expires_at_ms.unwrap();
        assert!(
            exp >= before + 28_800_000 && exp <= now_ms() + 28_800_000,
            "expires_in converted to an absolute ms deadline"
        );
    }

    #[tokio::test]
    async fn refresh_without_rotation_reuses_existing_refresh_token() {
        let http = FixtureTransport::ok(200, RECORDED_SUCCESS_NO_ROTATION.as_bytes().to_vec());
        let tokens = AnthropicAdapter::new()
            .refresh(&cred(), &http)
            .await
            .unwrap();
        assert_eq!(tokens.access_token.expose(), "sk-ant-oat01-new");
        assert_eq!(
            tokens.refresh_token.expose(),
            "old-refresh",
            "no rotation in response => existing refresh token reused, not dropped"
        );
    }

    #[tokio::test]
    async fn request_posts_json_refresh_grant_to_token_url() {
        let http = FixtureTransport::ok(200, RECORDED_SUCCESS.as_bytes().to_vec());
        AnthropicAdapter::new()
            .refresh(&cred(), &http)
            .await
            .unwrap();
        let reqs = http.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].url, TOKEN_URL);
        assert_eq!(reqs[0].content_type, "application/json");
        assert!(
            reqs[0].headers.is_empty(),
            "no extra headers on the refresh POST"
        );
        let sent: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(sent["grant_type"], "refresh_token");
        assert_eq!(sent["refresh_token"], "old-refresh");
        assert_eq!(sent["client_id"], CLAUDE_CODE_CLIENT_ID);
    }

    #[tokio::test]
    async fn invalid_grant_maps_to_dead_refresh_token() {
        let http = FixtureTransport::ok(
            400,
            br#"{"error":"invalid_grant","error_description":"refresh token is invalid"}"#.to_vec(),
        );
        match AnthropicAdapter::new().refresh(&cred(), &http).await {
            Err(RefreshError::InvalidGrant(_)) => {}
            other => panic!("expected InvalidGrant, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn no_non_mutating_check() {
        // Anthropic exposes no introspection endpoint: recovery falls to needs_reauth.
        let http = FixtureTransport::new(vec![]);
        let out = AnthropicAdapter::new()
            .non_mutating_check(&cred(), &http)
            .await;
        assert!(
            out.is_none(),
            "no non-mutating validity check for anthropic"
        );
    }
}
