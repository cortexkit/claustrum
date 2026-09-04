//! Cursor browser-poll login and refresh support.
//!
//! Cursor's CLI login is deliberately not a localhost callback: the browser is
//! sent to a deep-control page and the CLI polls a short-lived challenge. The
//! refresh endpoint uses the returned refresh token as a bearer credential and
//! may rotate it.

use async_trait::async_trait;
use serde::Deserialize;
use url::Url;

use super::{HttpTransport, RefreshAdapter, RefreshError, RefreshedTokens};
use crate::oauth::OAuthCredential;
use crate::oauth_login::{decode_jwt_claims, LoginTokens, Pkce};

pub const ADAPTER_NAME: &str = "cursor";
pub const DEFAULT_ID: &str = "oauth:cursor";
pub const LOGIN_URL: &str = "https://cursor.com/loginDeepControl";
pub const POLL_URL: &str = "https://api2.cursor.sh/auth/poll";
pub const TOKEN_URL: &str = "https://api2.cursor.sh/auth/exchange_user_api_key";
pub const LOGIN_MODE: &str = "login";
pub const REDIRECT_TARGET: &str = "cli";
const MAX_ATTEMPTS: usize = 150;
const MAX_BACKOFF_MS: u64 = 10_000;
const INITIAL_BACKOFF_MS: u64 = 1_000;
/// Cursor's response normally carries a JWT expiry; this keeps a malformed token
/// from being treated as permanently fresh while still allowing a short retry window.
pub const FALLBACK_ACCESS_TTL_MS: i64 = 5 * 60 * 1000;

/// The data needed to present a Cursor browser-poll login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorLoginStart {
    pub uuid: String,
    pub authorize_url: String,
    pub verifier: String,
}

/// Start a Cursor login from a generated PKCE pair.
pub fn start_login(pkce: &Pkce) -> Result<CursorLoginStart, url::ParseError> {
    let uuid = generate_uuid_v4().map_err(|_| url::ParseError::EmptyHost)?;
    let authorize_url = authorize_url(pkce, &uuid)?;
    Ok(CursorLoginStart {
        uuid,
        authorize_url,
        verifier: pkce.verifier.clone(),
    })
}

/// Build Cursor's exact deep-control URL. The verifier is never placed in this URL.
pub fn authorize_url(pkce: &Pkce, uuid: &str) -> Result<String, url::ParseError> {
    let mut url = Url::parse(LOGIN_URL)?;
    url.query_pairs_mut()
        .append_pair("challenge", &pkce.challenge)
        .append_pair("uuid", uuid)
        .append_pair("mode", LOGIN_MODE)
        .append_pair("redirectTarget", REDIRECT_TARGET);
    Ok(url.to_string())
}

fn generate_uuid_v4() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorPollResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub enum CursorPollError {
    Transport(String),
    Decode(String),
    TerminalStatus(u16),
    TerminalTransport,
    AttemptLimit,
}

impl std::fmt::Display for CursorPollError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(_) => f.write_str("Cursor login poll transport failed"),
            Self::Decode(_) => f.write_str("Cursor login poll response was invalid"),
            Self::TerminalStatus(status) => write!(f, "Cursor login poll returned status {status}"),
            Self::TerminalTransport => f.write_str("Cursor login poll transport failed repeatedly"),
            Self::AttemptLimit => f.write_str("Cursor login poll timed out"),
        }
    }
}

impl std::error::Error for CursorPollError {}

/// The small GET seam keeps the browser-poll logic deterministic in conformance tests.
#[async_trait]
pub trait CursorPollTransport: Send + Sync {
    async fn get(&self, url: &str) -> Result<CursorPollResponse, CursorPollError>;
}

/// A production GET transport for Cursor's poll endpoint.
pub struct ReqwestCursorPollTransport {
    client: reqwest::Client,
}

impl ReqwestCursorPollTransport {
    pub fn new() -> Result<Self, CursorPollError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| CursorPollError::Transport(e.to_string()))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl CursorPollTransport for ReqwestCursorPollTransport {
    async fn get(&self, url: &str) -> Result<CursorPollResponse, CursorPollError> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| CursorPollError::Transport(e.to_string()))?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|e| CursorPollError::Transport(e.to_string()))?
            .to_vec();
        Ok(CursorPollResponse { status, body })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PollBody {
    access_token: String,
    refresh_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorTokens {
    pub access_token: String,
    pub refresh_token: String,
}

/// Run the bounded browser-poll flow. A 404 means that the browser has not finished;
/// every other non-200 response counts toward the three-error terminal threshold.
pub async fn run_cursor_login<T: CursorPollTransport + ?Sized>(
    transport: &T,
    uuid: &str,
    verifier: &str,
) -> Result<LoginTokens, CursorPollError> {
    let tokens = poll_for_tokens(transport, uuid, verifier).await?;
    let now = now_ms();
    Ok(LoginTokens {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token,
        expires_at_ms: Some(access_token_expiry_ms(&tokens.access_token, now)),
        id_token: None,
        account: None,
        organization: None,
    })
}

pub async fn poll_for_tokens<T: CursorPollTransport + ?Sized>(
    transport: &T,
    uuid: &str,
    verifier: &str,
) -> Result<CursorTokens, CursorPollError> {
    let mut delay_ms = INITIAL_BACKOFF_MS;
    let mut consecutive_errors = 0usize;
    for attempt in 0..MAX_ATTEMPTS {
        let url = poll_url(uuid, verifier).map_err(|e| CursorPollError::Decode(e.to_string()))?;
        let response = match transport.get(&url).await {
            Ok(response) => response,
            Err(error) => {
                consecutive_errors += 1;
                if consecutive_errors >= 3 {
                    return Err(CursorPollError::TerminalTransport);
                }
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                delay_ms = ((delay_ms as f64) * 1.2).ceil() as u64;
                delay_ms = delay_ms.min(MAX_BACKOFF_MS);
                let _ = error;
                continue;
            }
        };
        match response.status {
            200 => {
                return serde_json::from_slice::<PollBody>(&response.body)
                    .map(|body| CursorTokens {
                        access_token: body.access_token,
                        refresh_token: body.refresh_token,
                    })
                    .map_err(|e| CursorPollError::Decode(e.to_string()));
            }
            404 => {
                consecutive_errors = 0;
                if attempt + 1 == MAX_ATTEMPTS {
                    return Err(CursorPollError::AttemptLimit);
                }
            }
            status => {
                consecutive_errors += 1;
                if consecutive_errors >= 3 {
                    return Err(CursorPollError::TerminalStatus(status));
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        delay_ms = ((delay_ms as f64) * 1.2).ceil() as u64;
        delay_ms = delay_ms.min(MAX_BACKOFF_MS);
    }
    Err(CursorPollError::AttemptLimit)
}

pub fn poll_url(uuid: &str, verifier: &str) -> Result<String, url::ParseError> {
    let mut url = Url::parse(POLL_URL)?;
    url.query_pairs_mut()
        .append_pair("uuid", uuid)
        .append_pair("verifier", verifier);
    Ok(url.to_string())
}

/// Decode Cursor's JWT expiry, falling back to a short fixed lifetime for opaque or
/// malformed access tokens.
pub fn access_token_expiry_ms(token: &str, now_ms: i64) -> i64 {
    decode_jwt_claims(token)
        .and_then(|claims| claims.get("exp")?.as_i64())
        .map(|seconds| seconds.saturating_mul(1000))
        .unwrap_or_else(|| now_ms.saturating_add(FALLBACK_ACCESS_TTL_MS))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RefreshResponseBody {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
}

#[derive(Debug, Default)]
pub struct CursorAdapter;

impl CursorAdapter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RefreshAdapter for CursorAdapter {
    fn name(&self) -> &str {
        ADAPTER_NAME
    }

    async fn refresh(
        &self,
        cred: &OAuthCredential,
        http: &dyn HttpTransport,
    ) -> Result<RefreshedTokens, RefreshError> {
        let authorization = format!("Bearer {}", cred.refresh_token.expose());
        let response = http
            .post(
                if cred.token_url.is_empty() {
                    TOKEN_URL
                } else {
                    &cred.token_url
                },
                &[("Authorization", authorization.as_str())],
                "application/json",
                b"{}".to_vec(),
            )
            .await?;
        match response.status {
            200 => {
                let parsed: RefreshResponseBody = serde_json::from_slice(&response.body)
                    .map_err(|e| RefreshError::Decode(e.to_string()))?;
                Ok(RefreshedTokens {
                    expires_at_ms: Some(access_token_expiry_ms(&parsed.access_token, now_ms())),
                    refresh_token: parsed
                        .refresh_token
                        .map(Into::into)
                        .unwrap_or_else(|| cred.refresh_token.clone()),
                    access_token: parsed.access_token.into(),
                    github_app_permissions: None,
                })
            }
            401 | 403 => Err(RefreshError::InvalidGrant(
                "Cursor refresh token was rejected".to_string(),
            )),
            status => Err(RefreshError::Status(
                status,
                "Cursor refresh failed".to_string(),
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
    use std::sync::Mutex;

    struct PollFixture {
        responses: Mutex<Vec<CursorPollResponse>>,
        urls: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl CursorPollTransport for PollFixture {
        async fn get(&self, url: &str) -> Result<CursorPollResponse, CursorPollError> {
            self.urls.lock().unwrap().push(url.to_string());
            Ok(self.responses.lock().unwrap().remove(0))
        }
    }

    fn cred() -> OAuthCredential {
        OAuthCredential {
            access_token: "old".to_string().into(),
            refresh_token: "old-refresh".to_string().into(),
            expires_at_ms: Some(0),
            token_url: TOKEN_URL.into(),
            client_id: None,
            scopes: vec![],
        }
    }

    #[test]
    fn authorize_url_has_cursor_deep_control_parameters() {
        let pkce = Pkce {
            verifier: "verifier".into(),
            challenge: "challenge".into(),
        };
        let parsed = Url::parse(&authorize_url(&pkce, "uuid-123").unwrap()).unwrap();
        let params: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(params.get("challenge").unwrap(), "challenge");
        assert_eq!(params.get("uuid").unwrap(), "uuid-123");
        assert_eq!(params.get("mode").unwrap(), LOGIN_MODE);
        assert_eq!(params.get("redirectTarget").unwrap(), REDIRECT_TARGET);
    }

    #[tokio::test]
    async fn poll_shape_and_response_are_conformant() {
        let fixture = PollFixture {
            responses: Mutex::new(vec![CursorPollResponse {
                status: 200,
                body: br#"{"accessToken":"new-access","refreshToken":"new-refresh"}"#.to_vec(),
            }]),
            urls: Mutex::new(Vec::new()),
        };
        let tokens = poll_for_tokens(&fixture, "uuid-123", "verifier-xyz")
            .await
            .unwrap();
        assert_eq!(tokens.access_token, "new-access");
        assert_eq!(tokens.refresh_token, "new-refresh");
        assert_eq!(
            fixture.urls.lock().unwrap()[0],
            format!("{POLL_URL}?uuid=uuid-123&verifier=verifier-xyz")
        );
    }

    #[tokio::test]
    async fn poll_404_then_success_resets_pending_state() {
        let fixture = PollFixture {
            responses: Mutex::new(vec![
                CursorPollResponse {
                    status: 404,
                    body: Vec::new(),
                },
                CursorPollResponse {
                    status: 200,
                    body: br#"{"accessToken":"a","refreshToken":"r"}"#.to_vec(),
                },
            ]),
            urls: Mutex::new(Vec::new()),
        };
        let tokens = poll_for_tokens(&fixture, "u", "v").await.unwrap();
        assert_eq!(tokens.access_token, "a");
    }

    #[tokio::test]
    async fn refresh_posts_bearer_and_empty_json() {
        let http = FixtureTransport::ok(
            200,
            br#"{"accessToken":"new-access","refreshToken":"new-refresh"}"#.to_vec(),
        );
        let tokens = CursorAdapter::new().refresh(&cred(), &http).await.unwrap();
        assert_eq!(tokens.refresh_token.expose(), "new-refresh");
        let request = &http.requests()[0];
        assert_eq!(request.url, TOKEN_URL);
        assert_eq!(request.content_type, "application/json");
        assert_eq!(request.body, b"{}");
        assert_eq!(
            request.headers,
            vec![("Authorization".into(), "Bearer old-refresh".into())]
        );
    }

    #[tokio::test]
    async fn refresh_without_rotation_reuses_refresh_token() {
        let http = FixtureTransport::ok(200, br#"{"accessToken":"new-access"}"#.to_vec());
        let tokens = CursorAdapter::new().refresh(&cred(), &http).await.unwrap();
        assert_eq!(tokens.refresh_token.expose(), "old-refresh");
    }

    #[tokio::test]
    async fn refresh_401_and_403_are_invalid_grant() {
        for status in [401, 403] {
            let http = FixtureTransport::ok(status, b"rejected".to_vec());
            assert!(matches!(
                CursorAdapter::new().refresh(&cred(), &http).await,
                Err(RefreshError::InvalidGrant(_))
            ));
        }
    }

    #[test]
    fn jwt_expiry_is_read_in_milliseconds() {
        let payload = crate::store::base64url(br#"{"exp":1234}"#);
        assert_eq!(
            access_token_expiry_ms(&format!("header.{payload}.sig"), 0),
            1_234_000
        );
    }

    #[test]
    fn malformed_jwt_uses_short_expiry() {
        let now = 10_000;
        assert_eq!(
            access_token_expiry_ms("opaque", now),
            now + FALLBACK_ACCESS_TTL_MS
        );
    }
}
