//! Kimi Code OAuth device and refresh adapter.
//!
//! Kimi binds its OAuth requests to a stable CLI device id. The id is local metadata,
//! not a token; the CLI creates it once and the daemon reads the same file when it
//! constructs this adapter.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::Deserialize;

use super::{form_urlencode, HttpTransport, RefreshAdapter, RefreshError, RefreshedTokens};
use crate::oauth::OAuthCredential;

/// Kimi's public OAuth client id.
pub const CLIENT_ID: &str = "17e5f671-d194-4dfb-9706-5516cb48c098";
/// Kimi's OAuth host.
pub const HOST: &str = "https://auth.kimi.com";
/// Kimi device authorization endpoint.
pub const DEVICE_AUTH_URL: &str = "https://auth.kimi.com/api/oauth/device_authorization";
/// Kimi token endpoint, used for both polling and refresh.
pub const TOKEN_URL: &str = "https://auth.kimi.com/api/oauth/token";
/// The adapter name stored on Kimi records.
pub const ADAPTER_NAME: &str = "kimi";
/// The stable user agent required by the Kimi CLI wire.
pub const USER_AGENT: &str = concat!("cortexkit-credentials/", env!("CARGO_PKG_VERSION"));
pub const PLATFORM: &str = "kimi_cli";

/// Return the per-vault device-id path.
pub fn device_id_path(data_dir: &Path) -> PathBuf {
    data_dir.join("kimi-device-id")
}

/// Read a valid existing device id, or the fixed fallback used by the daemon when
/// the CLI-created file is unavailable.
pub fn read_device_id_or_unknown(path: &Path) -> String {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| is_device_id(value))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Create the device id on first CLI use and keep it mode 0600 on Unix.
pub fn ensure_device_id(path: &Path) -> Result<String, std::io::Error> {
    if let Ok(value) = std::fs::read_to_string(path) {
        let value = value.trim().to_string();
        if is_device_id(&value) {
            return Ok(value);
        }
    }
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| std::io::Error::other(format!("generating Kimi device id: {error}")))?;
    let mut id = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(id, "{byte:02x}");
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            use std::io::Write;
            file.write_all(id.as_bytes())?;
            file.write_all(b"\n")?;
            Ok(id)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let value = std::fs::read_to_string(path)
                .map_err(|read_error| std::io::Error::other(read_error.to_string()))?;
            let value = value.trim().to_string();
            if is_device_id(&value) {
                Ok(value)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Kimi device-id file is not a 32-hex identifier",
                ))
            }
        }
        Err(error) => Err(error),
    }
}

fn is_device_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    #[serde(default)]
    error: Option<String>,
}

/// Refreshes Kimi access tokens and preserves a refresh token when the provider
/// omits a rotated value.
#[derive(Debug, Clone)]
pub struct KimiAdapter {
    device_id: String,
}

impl KimiAdapter {
    pub fn new(device_id: impl Into<String>) -> Self {
        Self {
            device_id: device_id.into(),
        }
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    fn headers(&self) -> [(&str, &str); 3] {
        [
            ("User-Agent", USER_AGENT),
            ("X-Msh-Platform", PLATFORM),
            ("X-Msh-Device-Id", self.device_id.as_str()),
        ]
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
impl RefreshAdapter for KimiAdapter {
    fn name(&self) -> &str {
        ADAPTER_NAME
    }

    async fn refresh(
        &self,
        cred: &OAuthCredential,
        http: &dyn HttpTransport,
    ) -> Result<RefreshedTokens, RefreshError> {
        let client_id = cred.client_id.as_deref().unwrap_or(CLIENT_ID);
        let body = form_urlencode(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", cred.refresh_token.expose()),
            ("client_id", client_id),
        ])
        .into_bytes();
        let headers = self.headers();
        let response = http
            .post(
                Self::endpoint(cred),
                &headers,
                "application/x-www-form-urlencoded",
                body,
            )
            .await?;
        if response.status == 400 || response.status == 401 {
            if let Ok(error) = serde_json::from_slice::<ErrorResponse>(&response.body) {
                if matches!(
                    error.error.as_deref(),
                    Some("invalid_grant" | "expired_token")
                ) {
                    return Err(RefreshError::InvalidGrant(
                        "Kimi refresh token was rejected".into(),
                    ));
                }
            }
        }
        if !(200..300).contains(&response.status) {
            return Err(RefreshError::Status(
                response.status,
                "Kimi token endpoint rejected the refresh".into(),
            ));
        }
        let parsed: TokenResponse = serde_json::from_slice(&response.body)
            .map_err(|error| RefreshError::Decode(error.to_string()))?;
        let expires_at_ms = parsed
            .expires_in
            .filter(|seconds| *seconds >= 0)
            .map(|seconds| now_ms().saturating_add(seconds.saturating_mul(1000)));
        Ok(RefreshedTokens {
            access_token: parsed.access_token.into(),
            refresh_token: parsed
                .refresh_token
                .map(Into::into)
                .unwrap_or_else(|| cred.refresh_token.clone()),
            expires_at_ms,
            github_app_permissions: None,
        })
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
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
            client_id: Some(CLIENT_ID.into()),
            scopes: Vec::new(),
        }
    }

    #[tokio::test]
    async fn refresh_request_has_exact_form_and_device_headers() {
        let http = FixtureTransport::ok(
            200,
            br#"{"access_token":"new-access","expires_in":60}"#.to_vec(),
        );
        KimiAdapter::new("0123456789abcdef0123456789abcdef")
            .refresh(&cred(), &http)
            .await
            .unwrap();
        let request = &http.requests()[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.url, TOKEN_URL);
        assert_eq!(request.content_type, "application/x-www-form-urlencoded");
        assert_eq!(
            String::from_utf8(request.body.clone()).unwrap(),
            "grant_type=refresh_token&refresh_token=old-refresh&client_id=17e5f671-d194-4dfb-9706-5516cb48c098"
        );
        assert!(request
            .headers
            .iter()
            .any(|(name, value)| name == "User-Agent" && value == USER_AGENT));
        assert!(request
            .headers
            .iter()
            .any(|(name, value)| name == "X-Msh-Platform" && value == PLATFORM));
        assert!(request.headers.iter().any(|(name, value)| {
            name == "X-Msh-Device-Id" && value == "0123456789abcdef0123456789abcdef"
        }));
    }

    #[tokio::test]
    async fn absent_rotated_refresh_token_reuses_existing() {
        let http = FixtureTransport::ok(
            200,
            br#"{"access_token":"new-access","expires_in":60}"#.to_vec(),
        );
        let tokens = KimiAdapter::new("unknown")
            .refresh(&cred(), &http)
            .await
            .unwrap();
        assert_eq!(tokens.refresh_token.expose(), "old-refresh");
    }

    #[tokio::test]
    async fn known_dead_token_errors_map_to_invalid_grant() {
        for error in ["invalid_grant", "expired_token"] {
            let body = format!(r#"{{"error":"{error}"}}"#);
            for status in [400, 401] {
                let http = FixtureTransport::ok(status, body.as_bytes().to_vec());
                let result = KimiAdapter::new("unknown").refresh(&cred(), &http).await;
                assert!(matches!(result, Err(RefreshError::InvalidGrant(_))));
            }
        }
    }

    #[test]
    fn device_id_file_is_mode_0600_and_stable() {
        let root = std::env::temp_dir().join(format!("ck-kimi-device-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let path = device_id_path(&root);
        let first = ensure_device_id(&path).unwrap();
        let second = ensure_device_id(&path).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }
}
