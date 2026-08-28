//! Snowflake Cortex per-account OAuth login and refresh support.
//!
//! Snowflake's token host is derived from the operator's account identifier and is
//! persisted in the canonical credential's `token_url`. That URL is the account
//! metadata the adapter reads during refresh; the same account is also required in
//! the credential id (`oauth:snowflake:<account>`).

use async_trait::async_trait;
use serde::Deserialize;
use url::Url;

use super::{form_urlencode, HttpTransport, RefreshAdapter, RefreshError, RefreshedTokens};
use crate::oauth::OAuthCredential;
use crate::oauth_login::{Callback, LoginError, LoginTokens};

pub const ADAPTER_NAME: &str = "snowflake";
pub const CLIENT_ID: &str = "LOCAL_APPLICATION";
pub const AUTHORIZE_PATH: &str = "/oauth/authorize";
pub const TOKEN_PATH: &str = "/oauth/token-request";
pub const TOKEN_URL_BASE: &str = "https://{account}.snowflakecomputing.com/oauth/token-request";
pub const LOGIN_REDIRECT_PREFIX: &str = "http://127.0.0.1:";
pub const DEFAULT_ID_PREFIX: &str = "oauth:snowflake:";
const BASIC_AUTH: &str = "Basic TE9DQUxfQVBQTElDQVRJT046TE9DQUxfQVBQTElDQVRJT04=";

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    expires_in: i64,
}

/// Validate the account spelling before interpolating it into a hostname and id.
pub fn validate_account(account: &str) -> Result<(), String> {
    if account.is_empty()
        || !account
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err("Snowflake account must contain only letters, digits, '-', '_' or '.'".into());
    }
    Ok(())
}

pub fn token_url(account: &str) -> Result<String, String> {
    validate_account(account)?;
    Ok(format!(
        "https://{account}.snowflakecomputing.com{TOKEN_PATH}"
    ))
}

pub fn default_id(account: &str) -> Result<String, String> {
    validate_account(account)?;
    Ok(format!("{DEFAULT_ID_PREFIX}{account}"))
}

/// Require the account-bearing id before a login can mint a Snowflake record.
pub fn validate_credential_id(account: &str, id: &str) -> Result<(), String> {
    let default = default_id(account)?;
    let valid = id == default
        || id
            .strip_prefix(&default)
            .and_then(|rest| rest.strip_prefix(':'))
            .is_some_and(|label| !label.is_empty() && !label.contains(':'));
    if valid {
        Ok(())
    } else {
        Err(format!(
            "Snowflake credential id must start with '{default}'"
        ))
    }
}

/// Build the per-account authorization URL with the dynamic loopback redirect.
pub fn authorize_url(
    account: &str,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
) -> Result<String, String> {
    validate_account(account)?;
    let host = format!("https://{account}.snowflakecomputing.com{AUTHORIZE_PATH}");
    let mut url = Url::parse(&host).map_err(|e| e.to_string())?;
    url.query_pairs_mut()
        .append_pair("client_id", CLIENT_ID)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("state", state)
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(url.to_string())
}

/// Parse and exchange the authorization code using Snowflake's Basic-auth form wire.
pub async fn exchange_authorization_code(
    http: &dyn HttpTransport,
    token_url: &str,
    redirect_uri: &str,
    callback: &Callback,
    expected_state: &str,
    verifier: &str,
    now_ms: i64,
) -> Result<LoginTokens, LoginError> {
    if callback.state != expected_state {
        return Err(LoginError::StateMismatch);
    }
    let body = form_urlencode(&[
        ("grant_type", "authorization_code"),
        ("code", &callback.code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", verifier),
    ]);
    let response = http
        .post(
            token_url,
            &[("Authorization", BASIC_AUTH)],
            "application/x-www-form-urlencoded",
            body.into_bytes(),
        )
        .await
        .map_err(|e| LoginError::Transport(e.to_string()))?;
    if response.status != 200 {
        return Err(LoginError::Status(
            response.status,
            "Snowflake token exchange was rejected".to_string(),
        ));
    }
    let parsed: TokenResponse =
        serde_json::from_slice(&response.body).map_err(|e| LoginError::Decode(e.to_string()))?;
    let refresh_token = parsed
        .refresh_token
        .ok_or_else(|| LoginError::Decode("Snowflake response omitted refresh_token".into()))?;
    Ok(LoginTokens {
        access_token: parsed.access_token,
        refresh_token,
        expires_at_ms: Some(now_ms.saturating_add(parsed.expires_in.saturating_mul(1000))),
        id_token: None,
        account: None,
        organization: None,
    })
}

#[derive(Debug, Deserialize)]
struct RefreshResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    expires_in: i64,
}

#[derive(Debug, Default)]
pub struct SnowflakeAdapter;

impl SnowflakeAdapter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RefreshAdapter for SnowflakeAdapter {
    fn name(&self) -> &str {
        ADAPTER_NAME
    }

    async fn refresh(
        &self,
        cred: &OAuthCredential,
        http: &dyn HttpTransport,
    ) -> Result<RefreshedTokens, RefreshError> {
        if cred.token_url.is_empty() {
            return Err(RefreshError::Decode(
                "Snowflake credential has no account-specific token URL".into(),
            ));
        }
        let body = form_urlencode(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &cred.refresh_token),
        ]);
        let response = http
            .post(
                &cred.token_url,
                &[("Authorization", BASIC_AUTH)],
                "application/x-www-form-urlencoded",
                body.into_bytes(),
            )
            .await?;
        match response.status {
            200 => {
                let parsed: RefreshResponse = serde_json::from_slice(&response.body)
                    .map_err(|e| RefreshError::Decode(e.to_string()))?;
                Ok(RefreshedTokens {
                    access_token: parsed.access_token,
                    refresh_token: parsed
                        .refresh_token
                        .unwrap_or_else(|| cred.refresh_token.clone()),
                    expires_at_ms: Some(
                        now_ms().saturating_add(parsed.expires_in.saturating_mul(1000)),
                    ),
                    github_app_permissions: None,
                })
            }
            400 | 401 => Err(RefreshError::InvalidGrant(
                "Snowflake refresh token was rejected".into(),
            )),
            status => Err(RefreshError::Status(
                status,
                "Snowflake refresh failed".into(),
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
            token_url: token_url("acme").unwrap(),
            client_id: Some(CLIENT_ID.into()),
            scopes: vec![],
        }
    }

    const SUCCESS: &str =
        r#"{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}"#;

    #[test]
    fn account_is_required_in_the_id() {
        assert!(default_id("").is_err());
        assert_eq!(
            default_id("org-account").unwrap(),
            "oauth:snowflake:org-account"
        );
        assert!(validate_account("org/account").is_err());
        assert!(validate_credential_id("org-account", "oauth:snowflake").is_err());
        assert!(validate_credential_id("org-account", "oauth:snowflake:org-account").is_ok());
        assert!(validate_credential_id("org-account", "oauth:snowflake:org-account:work").is_ok());
    }

    #[test]
    fn authorize_url_uses_account_host_and_pkce() {
        let url = authorize_url(
            "org-account",
            "http://127.0.0.1:41723/",
            "state",
            "challenge",
        )
        .unwrap();
        assert!(url.starts_with("https://org-account.snowflakecomputing.com/oauth/authorize?"));
        let parsed = Url::parse(&url).unwrap();
        let params: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(params.get("client_id").unwrap(), CLIENT_ID);
        assert_eq!(params.get("response_type").unwrap(), "code");
        assert_eq!(
            params.get("redirect_uri").unwrap(),
            "http://127.0.0.1:41723/"
        );
        assert_eq!(params.get("state").unwrap(), "state");
        assert_eq!(params.get("code_challenge").unwrap(), "challenge");
        assert_eq!(params.get("code_challenge_method").unwrap(), "S256");
    }

    #[tokio::test]
    async fn exchange_has_basic_header_and_exact_form_body() {
        let http = FixtureTransport::ok(200, SUCCESS.as_bytes().to_vec());
        let callback = Callback {
            code: "code/with space".into(),
            state: "state".into(),
        };
        let tokens = exchange_authorization_code(
            &http,
            "https://acme.snowflakecomputing.com/oauth/token-request",
            "http://127.0.0.1:41723/",
            &callback,
            "state",
            "verifier/value",
            10,
        )
        .await
        .unwrap();
        assert_eq!(tokens.access_token, "new-access");
        let request = &http.requests()[0];
        assert_eq!(
            request.headers,
            vec![("Authorization".into(), BASIC_AUTH.into())]
        );
        assert_eq!(request.content_type, "application/x-www-form-urlencoded");
        assert_eq!(
            String::from_utf8(request.body.clone()).unwrap(),
            "grant_type=authorization_code&code=code%2Fwith+space&redirect_uri=http%3A%2F%2F127.0.0.1%3A41723%2F&code_verifier=verifier%2Fvalue"
        );
    }

    #[tokio::test]
    async fn refresh_reuses_absent_rotated_token() {
        let http = FixtureTransport::ok(200, br#"{"access_token":"new","expires_in":60}"#.to_vec());
        let result = SnowflakeAdapter::new()
            .refresh(&cred(), &http)
            .await
            .unwrap();
        assert_eq!(result.refresh_token, "old-refresh");
        let request = &http.requests()[0];
        assert_eq!(request.url, token_url("acme").unwrap());
        assert_eq!(
            request.headers,
            vec![("Authorization".into(), BASIC_AUTH.into())]
        );
        assert_eq!(
            String::from_utf8(request.body.clone()).unwrap(),
            "grant_type=refresh_token&refresh_token=old-refresh"
        );
    }

    #[tokio::test]
    async fn refresh_invalid_grant_status_is_terminal() {
        let http = FixtureTransport::ok(401, br#"{"error":"invalid_grant"}"#.to_vec());
        assert!(matches!(
            SnowflakeAdapter::new().refresh(&cred(), &http).await,
            Err(RefreshError::InvalidGrant(_))
        ));
    }
}
