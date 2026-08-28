//! The xAI / Grok (SuperGrok) OAuth refresh adapter.
//!
//! Refreshes the OAuth tokens minted by the Grok CLI / SuperGrok subscription login
//! flow. The refresh exchange is a FORM-ENCODED `refresh_token` grant to xAI's
//! token endpoint with the public Grok CLI client id.
//!
//! Two provider-specific shapes the wire-format research pinned down (endpoint +
//! form shape verified against the xAI OIDC discovery and multiple independent
//! clients; the client id is reverse-engineered, consistent across those clients,
//! but not xAI-doc-published — see the `CLIENT_ID` note):
//! - A dead/revoked refresh token is signalled by HTTP STATUS (400 or 401), not a
//!   reliable canonical body, so this adapter keys the dead-token decision on the
//!   status code rather than matching a body string we could not verify.
//! - HTTP 403 is an ENTITLEMENT/tier denial (the subscription lapsed), which is
//!   DISTINCT from a dead refresh token: it is surfaced as a status error, not
//!   `invalid_grant`, so the credential is not branded `needs_reauth` for what is
//!   actually a billing/tier problem.
//!
//! The refresh token rotates optionally, so a response that omits `refresh_token`
//! reuses the existing one. xAI exposes a revocation endpoint but no non-mutating
//! introspection, so [`RefreshAdapter::non_mutating_check`] stays `None`.

use async_trait::async_trait;
use serde::Deserialize;

use super::{form_urlencode, HttpTransport, RefreshAdapter, RefreshError, RefreshedTokens};
use crate::oauth::OAuthCredential;

/// xAI's OAuth2 token endpoint for the refresh-token grant.
pub const TOKEN_URL: &str = "https://auth.x.ai/oauth2/token";
/// xAI's headless device authorization endpoint.
pub const DEVICE_CODE_URL: &str = "https://auth.x.ai/oauth2/device/code";
/// xAI's headless device token endpoint (the same endpoint serves refresh grants).
pub const DEVICE_TOKEN_URL: &str = "https://auth.x.ai/oauth2/token";
/// The scope set accepted by xAI's device grant.
pub const DEVICE_SCOPE: &str = "openid profile email offline_access grok-cli:access api:access";

/// The public Grok CLI OAuth client id. NOTE: this is reverse-engineered — it is
/// consistent across multiple independent open-source clients (Hermes, OpenClaw,
/// Warp) but is not published in xAI's own documentation. A credential's
/// `client_id` (set at import) overrides it.
pub const GROK_CLI_CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";

/// The adapter name, matching `VaultRecord::refresh_adapter` for xAI records.
pub const ADAPTER_NAME: &str = "xai";

// --- Vault-native login (authorization-code + PKCE) constants ---
//
// Pinned against the `opencode-grok-auth` plugin, which explicitly mirrors Hermes
// Agent's live xAI loopback flow for this same public client id. The refresh half
// (endpoint, client id, bare-refresh-token shape) is unchanged, so a vault-minted
// token refreshes through this adapter with no per-record override.

/// xAI's authorization endpoint (the interactive half). Distinct from [`TOKEN_URL`].
pub const AUTHORIZE_URL: &str = "https://auth.x.ai/oauth2/authorize";

/// The registered loopback redirect. The vault runs NO listener (zero inbound
/// surface): the browser lands on a connection-refused page whose address bar carries
/// `?code=..&state=..`, which the operator pastes back — the same posture as the
/// OpenAI login. The plugin's local listener is a convenience we deliberately omit.
pub const LOGIN_REDIRECT_URI: &str = "http://127.0.0.1:56121/callback";

/// The login scope set. `offline_access` is what grants the refresh token; `openid`
/// (with a per-flow nonce) and `profile`/`email` are the OIDC identity scopes;
/// `grok-cli:access`/`api:access` are the API entitlements. Matches the plugin.
pub const LOGIN_SCOPES: &[&str] = &[
    "openid",
    "profile",
    "email",
    "offline_access",
    "grok-cli:access",
    "api:access",
];

/// Non-standard authorize params `auth.x.ai` expects for this public client (the
/// plugin comment marks `referrer` as load-bearing). A fresh per-flow `nonce` is
/// appended by the login driver, not here (it must be CSPRNG per request).
pub const LOGIN_EXTRA_AUTHORIZE_PARAMS: &[(&str, &str)] =
    &[("plan", "generic"), ("referrer", "hermes-agent")];

/// The success response of the refresh exchange. Only `access_token` is reliably
/// present; `refresh_token` is rotated optionally (reuse the old when absent) and
/// `expires_in` is optional.
#[derive(Debug, Deserialize)]
struct RefreshResponseBody {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
}

/// The xAI refresh adapter.
#[derive(Debug, Default)]
pub struct XaiAdapter;

impl XaiAdapter {
    pub fn new() -> Self {
        XaiAdapter
    }

    fn request_body(cred: &OAuthCredential) -> Vec<u8> {
        let client_id = cred.client_id.as_deref().unwrap_or(GROK_CLI_CLIENT_ID);
        form_urlencode(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &cred.refresh_token),
            ("client_id", client_id),
        ])
        .into_bytes()
    }

    fn endpoint(cred: &OAuthCredential) -> &str {
        if cred.token_url.is_empty() {
            TOKEN_URL
        } else {
            cred.token_url.as_str()
        }
    }
}

#[async_trait]
impl RefreshAdapter for XaiAdapter {
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
            .post(
                Self::endpoint(cred),
                &[("Accept", "application/json")],
                "application/x-www-form-urlencoded",
                body,
            )
            .await?;

        match resp.status {
            200 => {
                let parsed: RefreshResponseBody = serde_json::from_slice(&resp.body)
                    .map_err(|e| RefreshError::Decode(e.to_string()))?;
                let expires_at_ms = parsed
                    .expires_in
                    .map(|secs| now_ms() + secs.saturating_mul(1000));
                let refresh_token = parsed
                    .refresh_token
                    .unwrap_or_else(|| cred.refresh_token.clone());
                Ok(RefreshedTokens {
                    access_token: parsed.access_token,
                    refresh_token,
                    expires_at_ms,
                    github_app_permissions: None,
                })
            }
            // A dead/revoked refresh token is signalled by status (no reliable body
            // to match), so 400/401 ⇒ the token needs re-auth.
            400 | 401 => Err(RefreshError::InvalidGrant(format!(
                "xai refresh rejected with status {}",
                resp.status
            ))),
            // 403 is an entitlement/tier denial (subscription lapsed), NOT a dead
            // refresh token — do not brand the credential needs_reauth for a billing
            // problem; surface it as a status error the operator can act on.
            403 => Err(RefreshError::Status(
                403,
                "xai entitlement denied (subscription/tier) — not a dead refresh token".to_string(),
            )),
            other => Err(RefreshError::Status(
                other,
                String::from_utf8_lossy(&resp.body).into_owned(),
            )),
        }
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
            access_token: "old-access".into(),
            refresh_token: "old-refresh".into(),
            expires_at_ms: Some(0),
            token_url: TOKEN_URL.into(),
            client_id: None, // exercise the default client id
            scopes: vec![],
        }
    }

    const RECORDED_SUCCESS: &str = r#"{"access_token":"xai-new-access","refresh_token":"xai-new-refresh","expires_in":3600,"token_type":"Bearer"}"#;

    #[tokio::test]
    async fn refresh_parses_rotated_tokens() {
        let http = FixtureTransport::ok(200, RECORDED_SUCCESS.as_bytes().to_vec());
        let tokens = XaiAdapter::new().refresh(&cred(), &http).await.unwrap();
        assert_eq!(tokens.access_token, "xai-new-access");
        assert_eq!(tokens.refresh_token, "xai-new-refresh");
        assert!(tokens.expires_at_ms.unwrap() > now_ms());
    }

    #[tokio::test]
    async fn refresh_without_rotation_reuses_existing() {
        let http = FixtureTransport::ok(200, br#"{"access_token":"a","expires_in":60}"#.to_vec());
        let tokens = XaiAdapter::new().refresh(&cred(), &http).await.unwrap();
        assert_eq!(tokens.refresh_token, "old-refresh");
    }

    #[tokio::test]
    async fn request_is_form_encoded_with_default_client_id() {
        let http = FixtureTransport::ok(200, RECORDED_SUCCESS.as_bytes().to_vec());
        XaiAdapter::new().refresh(&cred(), &http).await.unwrap();
        let reqs = http.requests();
        assert_eq!(reqs[0].url, TOKEN_URL);
        assert_eq!(reqs[0].content_type, "application/x-www-form-urlencoded");
        assert!(reqs[0]
            .headers
            .iter()
            .any(|(k, v)| k == "Accept" && v == "application/json"));
        let body = String::from_utf8(reqs[0].body.clone()).unwrap();
        assert!(body.contains("grant_type=refresh_token"), "{body}");
        assert!(
            body.contains(&format!("client_id={GROK_CLI_CLIENT_ID}")),
            "{body}"
        );
    }

    #[tokio::test]
    async fn status_400_and_401_are_dead_token() {
        for status in [400u16, 401] {
            let http = FixtureTransport::ok(status, b"whatever".to_vec());
            match XaiAdapter::new().refresh(&cred(), &http).await {
                Err(RefreshError::InvalidGrant(_)) => {}
                other => panic!("expected InvalidGrant for {status}, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn status_403_is_entitlement_not_dead_token() {
        // The important distinction: a tier/billing denial must NOT brand the
        // credential needs_reauth.
        let http = FixtureTransport::ok(403, b"forbidden".to_vec());
        match XaiAdapter::new().refresh(&cred(), &http).await {
            Err(RefreshError::Status(403, _)) => {}
            other => panic!("expected Status(403), got {other:?}"),
        }
    }
}
