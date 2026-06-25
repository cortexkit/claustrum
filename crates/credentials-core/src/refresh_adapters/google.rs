//! The Google (Gemini Code Assist) OAuth refresh adapter.
//!
//! Refreshes the OAuth tokens minted by the gemini-cli login flow (the
//! `~/.gemini/oauth_creds.json` `{access_token, refresh_token, expiry_date}` entry).
//! Unlike Anthropic, Google uses the standard Google OAuth2 token endpoint with a
//! FORM-ENCODED body that includes a `client_secret`, and Google does NOT rotate
//! the refresh token on refresh (long-lived refresh tokens), so the response omits
//! `refresh_token` and the existing one is carried forward.
//!
//! The wire format mirrors the proven gemini usage provider in the sibling
//! ai-provider-quota crate (form POST to `oauth2.googleapis.com/token`); it is not
//! invented here. Google exposes no non-mutating refresh-token introspection that
//! avoids rotation, so [`RefreshAdapter::non_mutating_check`] stays at its `None`
//! default (an interrupted refresh resolves to `needs_reauth`).

use async_trait::async_trait;
use serde::Deserialize;

use super::{form_urlencode, HttpTransport, RefreshAdapter, RefreshError, RefreshedTokens};
use crate::oauth::OAuthCredential;

/// Google's OAuth2 token endpoint for the refresh-token grant.
pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// The adapter name, matching `VaultRecord::refresh_adapter` for Google records.
pub const ADAPTER_NAME: &str = "google";

/// The success response of the refresh exchange: a new access token and a relative
/// `expires_in` (seconds). Google does not rotate the refresh token, so the
/// response carries no `refresh_token` and the existing one is reused.
#[derive(Debug, Deserialize)]
struct RefreshResponseBody {
    access_token: String,
    /// Access-token lifetime in seconds from now.
    expires_in: i64,
}

/// The Google refresh adapter. `client_secret` is required by Google's token
/// endpoint; it is provided at construction (the same public gemini-cli client
/// secret the sibling quota provider uses), since it is not a per-credential field.
pub struct GoogleAdapter {
    client_secret: String,
}

impl GoogleAdapter {
    /// Build the adapter with the OAuth client secret Google's token endpoint
    /// requires for the refresh grant.
    pub fn new(client_secret: impl Into<String>) -> Self {
        GoogleAdapter {
            client_secret: client_secret.into(),
        }
    }

    /// The form-encoded refresh request body. Separated so the conformance test can
    /// assert the exact bytes sent.
    fn request_body(&self, cred: &OAuthCredential) -> Vec<u8> {
        let client_id = cred.client_id.as_deref().unwrap_or_default();
        form_urlencode(&[
            ("client_id", client_id),
            ("client_secret", &self.client_secret),
            ("refresh_token", &cred.refresh_token),
            ("grant_type", "refresh_token"),
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
impl RefreshAdapter for GoogleAdapter {
    fn name(&self) -> &str {
        ADAPTER_NAME
    }

    async fn refresh(
        &self,
        cred: &OAuthCredential,
        http: &dyn HttpTransport,
    ) -> Result<RefreshedTokens, RefreshError> {
        let body = self.request_body(cred);
        let resp = http
            .post(
                Self::endpoint(cred),
                &[],
                "application/x-www-form-urlencoded",
                body,
            )
            .await?;

        // A dead refresh token comes back as 400 invalid_grant.
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
        let expires_at_ms = Some(now_ms() + parsed.expires_in.saturating_mul(1000));
        Ok(RefreshedTokens {
            access_token: parsed.access_token,
            // Google does not rotate; carry the existing refresh token forward.
            refresh_token: cred.refresh_token.clone(),
            expires_at_ms,
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
            access_token: "old-access".into(),
            refresh_token: "1//0refresh-token".into(),
            expires_at_ms: Some(0),
            token_url: TOKEN_URL.into(),
            client_id: Some("client.apps.googleusercontent.com".into()),
            scopes: vec![],
        }
    }

    // A recorded-shape Google token refresh response (access_token + expires_in,
    // no refresh_token — Google does not rotate).
    const RECORDED_SUCCESS: &str = r#"{"access_token":"ya29.new-access","expires_in":3599,"scope":"https://www.googleapis.com/auth/cloud-platform","token_type":"Bearer"}"#;

    #[tokio::test]
    async fn refresh_parses_access_token_and_reuses_refresh() {
        let http = FixtureTransport::ok(200, RECORDED_SUCCESS.as_bytes().to_vec());
        let tokens = GoogleAdapter::new("secret")
            .refresh(&cred(), &http)
            .await
            .unwrap();
        assert_eq!(tokens.access_token, "ya29.new-access");
        assert_eq!(
            tokens.refresh_token, "1//0refresh-token",
            "google does not rotate; existing refresh token reused"
        );
        assert!(tokens.expires_at_ms.unwrap() > now_ms());
    }

    #[tokio::test]
    async fn request_is_form_encoded_refresh_grant() {
        let http = FixtureTransport::ok(200, RECORDED_SUCCESS.as_bytes().to_vec());
        GoogleAdapter::new("the-secret")
            .refresh(&cred(), &http)
            .await
            .unwrap();
        let reqs = http.requests();
        assert_eq!(reqs[0].url, TOKEN_URL);
        assert_eq!(reqs[0].content_type, "application/x-www-form-urlencoded");
        let body = String::from_utf8(reqs[0].body.clone()).unwrap();
        assert!(body.contains("grant_type=refresh_token"), "{body}");
        assert!(body.contains("client_secret=the-secret"), "{body}");
        assert!(
            body.contains("refresh_token=1%2F%2F0refresh-token"),
            "url-encoded: {body}"
        );
    }

    #[tokio::test]
    async fn invalid_grant_is_dead_token() {
        let http = FixtureTransport::ok(
            400,
            br#"{"error":"invalid_grant","error_description":"Token has been expired or revoked."}"#
                .to_vec(),
        );
        match GoogleAdapter::new("s").refresh(&cred(), &http).await {
            Err(RefreshError::InvalidGrant(_)) => {}
            other => panic!("expected InvalidGrant, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn no_non_mutating_check() {
        let http = FixtureTransport::new(vec![]);
        let out = GoogleAdapter::new("s")
            .non_mutating_check(&cred(), &http)
            .await;
        assert!(out.is_none());
    }
}
