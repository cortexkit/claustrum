//! Devin CLI login and long-lived token support.
//!
//! Devin issues one opaque token from its CLI callback exchange. That token is both
//! access and refresh state; there is no refresh endpoint. A refresh request
//! therefore requires re-login rather than extending the rejected token's deadline.

use async_trait::async_trait;
use serde::Deserialize;
use url::Url;

use super::{HttpTransport, RefreshAdapter, RefreshError, RefreshedTokens};
use crate::oauth::OAuthCredential;
use crate::oauth_login::{Callback, LoginError, LoginTokens};

pub const ADAPTER_NAME: &str = "devin";
pub const DEFAULT_ID: &str = "oauth:devin";
pub const AUTHORIZE_URL: &str = "https://app.devin.ai/auth/cli/continue";
pub const TOKEN_URL: &str = "https://api.devin.ai/auth/cli/token";
pub const LOGIN_REDIRECT_URI: &str = "http://127.0.0.1:59653/callback";
pub const TOKEN_TTL_MS: i64 = 365 * 24 * 60 * 60 * 1000;

/// Build Devin's CLI authorize URL. Unlike a normal OAuth authorization request,
/// Devin's public CLI contract has no client_id, scope, or response_type parameter.
pub fn authorize_url(
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
) -> Result<String, url::ParseError> {
    let mut url = Url::parse(AUTHORIZE_URL)?;
    url.query_pairs_mut()
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("state", state)
        .append_pair("prompt", "select_account")
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(url.to_string())
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
}

/// Exchange Devin's callback code using the exact JSON body from the public CLI.
pub async fn exchange_authorization_code(
    http: &dyn HttpTransport,
    callback: &Callback,
    expected_state: &str,
    verifier: &str,
    now_ms: i64,
) -> Result<LoginTokens, LoginError> {
    if !crate::oauth_login::states_equal(&callback.state, expected_state) {
        return Err(LoginError::StateMismatch);
    }
    let body = serde_json::to_vec(&serde_json::json!({
        "code": callback.code,
        "code_verifier": verifier,
    }))
    .expect("fixed Devin login body is serializable");
    let response = http
        .post(TOKEN_URL, &[], "application/json", body)
        .await
        .map_err(|e| LoginError::Transport(e.to_string()))?;
    if response.status != 200 {
        return Err(LoginError::Status(
            response.status,
            "Devin token exchange was rejected".to_string(),
        ));
    }
    let parsed: TokenResponse =
        serde_json::from_slice(&response.body).map_err(|e| LoginError::Decode(e.to_string()))?;
    Ok(LoginTokens {
        access_token: parsed.token.clone(),
        refresh_token: parsed.token,
        expires_at_ms: Some(now_ms.saturating_add(TOKEN_TTL_MS)),
        id_token: None,
        account: None,
        organization: None,
    })
}

#[derive(Debug, Default)]
pub struct DevinAdapter;

impl DevinAdapter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RefreshAdapter for DevinAdapter {
    fn name(&self) -> &str {
        ADAPTER_NAME
    }

    async fn refresh(
        &self,
        _cred: &OAuthCredential,
        _http: &dyn HttpTransport,
    ) -> Result<RefreshedTokens, RefreshError> {
        // There is no refresh endpoint: a rejected token requires a new login.
        Err(RefreshError::InvalidGrant(
            "Devin access tokens are re-login-only".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refresh_adapters::fixture::FixtureTransport;

    fn cred() -> OAuthCredential {
        OAuthCredential {
            access_token: "opaque-token".to_string().into(),
            refresh_token: "opaque-token".to_string().into(),
            expires_at_ms: Some(0),
            token_url: TOKEN_URL.into(),
            client_id: None,
            scopes: vec![],
        }
    }

    #[test]
    fn authorize_url_has_exact_cli_parameters() {
        let url = authorize_url("http://127.0.0.1:59653/callback", "state", "challenge").unwrap();
        let parsed = Url::parse(&url).unwrap();
        assert_eq!(parsed.path(), "/auth/cli/continue");
        let params: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(
            params.get("redirect_uri").unwrap(),
            "http://127.0.0.1:59653/callback"
        );
        assert_eq!(params.get("state").unwrap(), "state");
        assert_eq!(params.get("prompt").unwrap(), "select_account");
        assert_eq!(params.get("code_challenge").unwrap(), "challenge");
        assert_eq!(params.get("code_challenge_method").unwrap(), "S256");
        assert!(!params.contains_key("client_id"));
    }

    #[tokio::test]
    async fn exchange_sends_exact_json_and_parses_opaque_token() {
        let http = FixtureTransport::ok(200, br#"{"token":"devin-token"}"#.to_vec());
        let callback = Callback {
            code: "code-value".into(),
            state: "state-value".into(),
        };
        let tokens = exchange_authorization_code(&http, &callback, "state-value", "verifier", 1000)
            .await
            .unwrap();
        assert_eq!(tokens.access_token, "devin-token");
        assert_eq!(tokens.refresh_token, "devin-token");
        assert_eq!(tokens.expires_at_ms, Some(1000 + TOKEN_TTL_MS));
        let request = &http.requests()[0];
        assert_eq!(request.url, TOKEN_URL);
        assert_eq!(request.content_type, "application/json");
        assert_eq!(
            String::from_utf8(request.body.clone()).unwrap(),
            r#"{"code":"code-value","code_verifier":"verifier"}"#
        );
    }

    #[tokio::test]
    async fn exchange_rejects_state_before_network() {
        let http = FixtureTransport::new(Vec::new());
        let callback = Callback {
            code: "code".into(),
            state: "wrong".into(),
        };
        assert!(matches!(
            exchange_authorization_code(&http, &callback, "expected", "verifier", 0).await,
            Err(LoginError::StateMismatch)
        ));
        assert!(http.requests().is_empty());
    }

    #[tokio::test]
    async fn refresh_requires_relogin_instead_of_renewing_a_rejected_token() {
        let http = FixtureTransport::new(Vec::new());
        assert!(matches!(
            DevinAdapter::new().refresh(&cred(), &http).await,
            Err(RefreshError::InvalidGrant(_))
        ));
        assert!(http.requests().is_empty(), "Devin has no refresh endpoint");
    }

    #[tokio::test]
    async fn exchange_error_shape_is_not_secret_bearing() {
        let http = FixtureTransport::ok(401, br#"{"error":"invalid"}"#.to_vec());
        let callback = Callback {
            code: "code".into(),
            state: "state".into(),
        };
        assert!(matches!(
            exchange_authorization_code(&http, &callback, "state", "verifier", 0).await,
            Err(LoginError::Status(401, _))
        ));
    }
}
