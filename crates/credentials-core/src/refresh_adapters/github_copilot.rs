//! GitHub Copilot's bearer exchange adapter.
//!
//! The device grant produces a durable GitHub OAuth token. Copilot consumers receive
//! a separate short-lived bearer minted by `copilot_internal/v2/token`; the durable
//! GitHub token therefore stays in the vault's refresh slot and is never rotated.

use async_trait::async_trait;
use serde::Deserialize;

use super::{HttpTransport, RefreshAdapter, RefreshError, RefreshedTokens};
use crate::oauth::OAuthCredential;

/// GitHub's Copilot bearer exchange endpoint.
pub const TOKEN_URL: &str = "https://api.github.com/copilot_internal/v2/token";
/// The public GitHub device-flow client id used by Copilot clients.
pub const CLIENT_ID: &str = "Ov23li8tweQw6odWQebz";
/// GitHub device authorization endpoint.
pub const DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
/// GitHub device token endpoint.
pub const DEVICE_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
/// The adapter name stored on Copilot records.
pub const ADAPTER_NAME: &str = "github-copilot";

#[derive(Debug, Deserialize)]
struct CopilotTokenResponse {
    token: String,
    expires_at: i64,
}

/// Refreshes a Copilot bearer from the durable GitHub OAuth token.
#[derive(Debug, Default)]
pub struct GithubCopilotAdapter;

impl GithubCopilotAdapter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RefreshAdapter for GithubCopilotAdapter {
    fn name(&self) -> &str {
        ADAPTER_NAME
    }

    async fn refresh(
        &self,
        cred: &OAuthCredential,
        http: &dyn HttpTransport,
    ) -> Result<RefreshedTokens, RefreshError> {
        let authorization = format!("token {}", cred.refresh_token.expose());
        let response = http
            .get(
                TOKEN_URL,
                &[
                    ("Authorization", authorization.as_str()),
                    ("User-Agent", "cortexkit-credentials"),
                ],
            )
            .await?;
        match response.status {
            200 => {
                let parsed: CopilotTokenResponse = serde_json::from_slice(&response.body)
                    .map_err(|error| RefreshError::Decode(error.to_string()))?;
                Ok(RefreshedTokens {
                    access_token: parsed.token.into(),
                    refresh_token: cred.refresh_token.clone(),
                    expires_at_ms: Some(parsed.expires_at.saturating_mul(1000)),
                    github_app_permissions: None,
                })
            }
            401 | 403 => Err(RefreshError::InvalidGrant(
                "GitHub OAuth token was rejected by Copilot".into(),
            )),
            status => Err(RefreshError::Status(
                status,
                "Copilot bearer exchange failed".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refresh_adapters::fixture::FixtureTransport;

    fn cred() -> OAuthCredential {
        OAuthCredential {
            access_token: "old-copilot-token".to_string().into(),
            refresh_token: "github-oauth-token".to_string().into(),
            expires_at_ms: Some(0),
            token_url: TOKEN_URL.into(),
            client_id: Some(CLIENT_ID.into()),
            scopes: vec!["read:user".into()],
        }
    }

    #[tokio::test]
    async fn exchange_parses_token_and_absolute_expiry() {
        let http = FixtureTransport::ok(
            200,
            br#"{"token":"copilot-bearer","expires_at":1730000123}"#.to_vec(),
        );
        let tokens = GithubCopilotAdapter::new()
            .refresh(&cred(), &http)
            .await
            .unwrap();
        assert_eq!(tokens.access_token.expose(), "copilot-bearer");
        assert_eq!(tokens.refresh_token.expose(), "github-oauth-token");
        assert_eq!(tokens.expires_at_ms, Some(1_730_000_123_000));

        let requests = http.requests();
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].url, TOKEN_URL);
        assert!(requests[0]
            .headers
            .iter()
            .any(|(name, value)| name == "Authorization" && value == "token github-oauth-token"));
        assert!(requests[0]
            .headers
            .iter()
            .any(|(name, value)| name == "User-Agent" && value == "cortexkit-credentials"));
    }

    #[tokio::test]
    async fn revoked_github_token_maps_401_and_403_to_invalid_grant() {
        for status in [401, 403] {
            let http = FixtureTransport::ok(status, b"forbidden".to_vec());
            let error = GithubCopilotAdapter::new()
                .refresh(&cred(), &http)
                .await
                .unwrap_err();
            assert!(matches!(error, RefreshError::InvalidGrant(_)));
        }
    }
}
