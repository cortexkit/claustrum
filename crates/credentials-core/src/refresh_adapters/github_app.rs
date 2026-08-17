//! GitHub App installation-token refresh adapter.
//!
//! The vault keeps the App's PKCS#8 private key in `OAuthCredential::refresh_token`.
//! Each refresh signs a short-lived App JWT, discovers the current installation lazily,
//! and exchanges that assertion for the installation token a consumer may use. The PEM
//! is never copied into an HTTP request or returned as the credential payload.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine as _;
use ring::{rand::SystemRandom, signature};
use serde::{Deserialize, Serialize};

use super::{HttpTransport, RefreshAdapter, RefreshError, RefreshedTokens};
use crate::oauth::OAuthCredential;

/// GitHub REST API endpoint used to discover an App's current installations.
pub const INSTALLATIONS_URL: &str = "https://api.github.com/app/installations";
/// Prefix of the endpoint that exchanges an App JWT for an installation token.
pub const ACCESS_TOKENS_URL_PREFIX: &str = "https://api.github.com/app/installations/";
/// The adapter name stored on GitHub App records.
pub const ADAPTER_NAME: &str = "github_app";

const GITHUB_ACCEPT: &str = "application/vnd.github+json";
const GITHUB_API_VERSION: &str = "2022-11-28";
const USER_AGENT: &str = "cortexkit-credentials";
const JWT_BACKDATE_SECS: i64 = 60;
const JWT_LIFETIME_SECS: i64 = 9 * 60;

#[derive(Serialize)]
struct AppJwtClaims<'a> {
    iss: &'a str,
    iat: i64,
    exp: i64,
}

#[derive(Deserialize)]
struct Installation {
    id: u64,
    client_id: String,
}

#[derive(Deserialize)]
struct InstallationTokenResponse {
    token: String,
    expires_at: String,
}

/// Mints GitHub App installation tokens from vaulted PKCS#8 RSA private keys.
///
/// Installation ids are intentionally process-local. GitHub can issue a new id after
/// an uninstall and reinstall, so persisting one in the credential record would turn a
/// healthy key into a permanently stale 404 until an operator repaired the record.
#[derive(Debug, Default)]
pub struct GithubAppAdapter {
    installation_ids: Mutex<HashMap<String, u64>>,
}

impl GithubAppAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    fn mint_app_jwt(cred: &OAuthCredential, now_secs: i64) -> Result<String, RefreshError> {
        let client_id = cred
            .client_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| RefreshError::Decode("GitHub App record has no client_id".into()))?;
        let pem_der = pkcs8_der_from_pem(&cred.refresh_token)?;
        let key_pair = signature::RsaKeyPair::from_pkcs8(&pem_der).map_err(|error| {
            RefreshError::Decode(format!("invalid GitHub App PKCS#8 key: {error}"))
        })?;

        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = AppJwtClaims {
            // GitHub recommends the client id here. The numeric App id remains accepted
            // by GitHub but would leave new Apps on legacy behavior.
            iss: client_id,
            iat: now_secs.saturating_sub(JWT_BACKDATE_SECS),
            exp: now_secs.saturating_add(JWT_LIFETIME_SECS),
        };
        let claims = serde_json::to_vec(&claims).map_err(|error| {
            RefreshError::Decode(format!("encode GitHub App JWT claims: {error}"))
        })?;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims);
        let signing_input = format!("{header}.{payload}");

        let mut signature_bytes = vec![0; key_pair.public().modulus_len()];
        key_pair
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signing_input.as_bytes(),
                &mut signature_bytes,
            )
            .map_err(|error| RefreshError::Decode(format!("sign GitHub App JWT: {error}")))?;
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature_bytes);
        Ok(format!("{signing_input}.{signature}"))
    }

    fn cached_installation_id(&self, client_id: &str) -> Option<u64> {
        self.installation_ids.lock().ok()?.get(client_id).copied()
    }

    fn cache_installation_id(&self, client_id: &str, installation_id: u64) {
        if let Ok(mut ids) = self.installation_ids.lock() {
            ids.insert(client_id.to_string(), installation_id);
        }
    }

    fn forget_installation_id(&self, client_id: &str) {
        if let Ok(mut ids) = self.installation_ids.lock() {
            ids.remove(client_id);
        }
    }

    async fn discover_installation_id(
        &self,
        client_id: &str,
        headers: &[(&str, &str)],
        http: &dyn HttpTransport,
    ) -> Result<u64, RefreshError> {
        let response = http.get(INSTALLATIONS_URL, headers).await?;
        if response.status == 401 {
            return Err(RefreshError::InvalidGrant(
                "GitHub rejected the App JWT while discovering installations".into(),
            ));
        }
        if response.status != 200 {
            return Err(RefreshError::Status(
                response.status,
                String::from_utf8_lossy(&response.body).into_owned(),
            ));
        }

        let installations: Vec<Installation> = serde_json::from_slice(&response.body)
            .map_err(|error| RefreshError::Decode(error.to_string()))?;
        installations
            .into_iter()
            .find(|installation| installation.client_id == client_id)
            .map(|installation| installation.id)
            .ok_or_else(|| {
                RefreshError::Decode(
                    "GitHub returned no installation for this App client_id".into(),
                )
            })
    }

    fn auth_headers(authorization: &str) -> [(&str, &str); 4] {
        [
            ("Accept", GITHUB_ACCEPT),
            ("Authorization", authorization),
            ("X-GitHub-Api-Version", GITHUB_API_VERSION),
            ("User-Agent", USER_AGENT),
        ]
    }
}

#[async_trait]
impl RefreshAdapter for GithubAppAdapter {
    fn name(&self) -> &str {
        ADAPTER_NAME
    }

    async fn refresh(
        &self,
        cred: &OAuthCredential,
        http: &dyn HttpTransport,
    ) -> Result<RefreshedTokens, RefreshError> {
        let client_id = cred
            .client_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| RefreshError::Decode("GitHub App record has no client_id".into()))?;
        let jwt = Self::mint_app_jwt(cred, now_secs())?;
        let authorization = format!("Bearer {jwt}");
        let headers = Self::auth_headers(&authorization);

        let installation_id = match self.cached_installation_id(client_id) {
            Some(id) => id,
            None => {
                let id = self
                    .discover_installation_id(client_id, &headers, http)
                    .await?;
                self.cache_installation_id(client_id, id);
                id
            }
        };
        let url = format!("{ACCESS_TOKENS_URL_PREFIX}{installation_id}/access_tokens");
        let response = http
            .post(&url, &headers, "application/json", b"{}".to_vec())
            .await?;
        if response.status == 401 {
            return Err(RefreshError::InvalidGrant(
                "GitHub rejected the App JWT while minting an installation token".into(),
            ));
        }
        if response.status == 404 {
            // The App may have been uninstalled and reinstalled while this process was
            // alive. Forget only the process-local value so the next refresh discovers
            // GitHub's new id instead of preserving a stale id on the credential record.
            self.forget_installation_id(client_id);
            return Err(RefreshError::Status(
                response.status,
                String::from_utf8_lossy(&response.body).into_owned(),
            ));
        }
        if response.status != 201 {
            return Err(RefreshError::Status(
                response.status,
                String::from_utf8_lossy(&response.body).into_owned(),
            ));
        }

        let parsed: InstallationTokenResponse = serde_json::from_slice(&response.body)
            .map_err(|error| RefreshError::Decode(error.to_string()))?;
        let expires_at_ms = chrono::DateTime::parse_from_rfc3339(&parsed.expires_at)
            .map_err(|error| RefreshError::Decode(format!("invalid GitHub token expiry: {error}")))?
            .timestamp_millis();
        Ok(RefreshedTokens {
            access_token: parsed.token,
            // An installation-token exchange never rotates the App private key.
            refresh_token: cred.refresh_token.clone(),
            expires_at_ms: Some(expires_at_ms),
        })
    }
}

fn pkcs8_der_from_pem(pem: &str) -> Result<Vec<u8>, RefreshError> {
    if !pem.contains("-----BEGIN PRIVATE KEY-----") || !pem.contains("-----END PRIVATE KEY-----") {
        return Err(RefreshError::Decode(
            "GitHub App private key must be a PKCS#8 PEM".into(),
        ));
    }
    let encoded: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| RefreshError::Decode(format!("decode GitHub App PKCS#8 PEM: {error}")))
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ring::signature;
    use serde_json::Value;

    use super::*;
    use crate::refresh_adapters::fixture::FixtureTransport;

    const JWT_NOW_SECS: i64 = 1_700_000_000;
    const RECORDED_INSTALLATION_ID: u64 = 154_356_189;
    const RECORDED_EXPIRY_MS: i64 = 1_786_961_937_000;
    const TEST_PRIVATE_KEY: &str =
        include_str!("../../tests/fixtures/github_app/test_private_key.pem");
    const TEST_PUBLIC_KEY: &[u8] =
        include_bytes!("../../tests/fixtures/github_app/test_public_key.der");
    const RECORDED_APP: &[u8] = include_bytes!("../../tests/fixtures/github_app/app.json");
    const RECORDED_INSTALLATIONS: &[u8] =
        include_bytes!("../../tests/fixtures/github_app/installations.json");
    const RECORDED_ACCESS_TOKENS: &[u8] =
        include_bytes!("../../tests/fixtures/github_app/access_tokens.json");

    fn recorded_client_id() -> String {
        serde_json::from_slice::<Value>(RECORDED_APP).unwrap()["client_id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn credential() -> OAuthCredential {
        OAuthCredential {
            access_token: String::new(),
            refresh_token: TEST_PRIVATE_KEY.into(),
            expires_at_ms: Some(0),
            token_url: String::new(),
            client_id: Some(recorded_client_id()),
            scopes: vec![],
        }
    }

    fn jwt_parts(jwt: &str) -> (Value, Value, Vec<u8>, String) {
        let mut parts = jwt.split('.');
        let header = parts.next().unwrap();
        let claims = parts.next().unwrap();
        let signature = parts.next().unwrap();
        assert!(parts.next().is_none(), "JWT has exactly three segments");
        let decode = |value: &str| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(value)
                .unwrap()
        };
        (
            serde_json::from_slice(&decode(header)).unwrap(),
            serde_json::from_slice(&decode(claims)).unwrap(),
            decode(signature),
            format!("{header}.{claims}"),
        )
    }

    fn fixture_transport(responses: Vec<(u16, &[u8])>) -> FixtureTransport {
        FixtureTransport::new(
            responses
                .into_iter()
                .map(|(status, body)| {
                    Ok(super::super::HttpResponse {
                        status,
                        body: body.to_vec(),
                    })
                })
                .collect(),
        )
    }

    /// GitHub's JWT issuer is the App client id, not its still-accepted numeric app id.
    #[test]
    fn an_app_jwt_issuer_is_the_client_id_not_the_numeric_app_id() {
        let cred = credential();
        let jwt = GithubAppAdapter::mint_app_jwt(&cred, JWT_NOW_SECS).unwrap();
        let (_, claims, _, _) = jwt_parts(&jwt);

        assert_eq!(claims["iss"], recorded_client_id());
        assert_ne!(
            claims["iss"], 4_617_236,
            "the issuer is not the numeric app id"
        );
    }

    /// GitHub rejects App JWTs with clock-skewed issuance times or a lifetime over ten minutes.
    #[test]
    fn an_app_jwt_is_backdated_and_expires_within_ten_minutes() {
        let jwt = GithubAppAdapter::mint_app_jwt(&credential(), JWT_NOW_SECS).unwrap();
        let (_, claims, _, _) = jwt_parts(&jwt);

        assert_eq!(claims["iat"], JWT_NOW_SECS - JWT_BACKDATE_SECS);
        assert!(claims["exp"].as_i64().unwrap() > JWT_NOW_SECS);
        assert!(
            claims["exp"].as_i64().unwrap() <= JWT_NOW_SECS + 10 * 60,
            "GitHub refuses App JWTs whose expiry is more than ten minutes ahead"
        );
    }

    /// The JWT advertises and actually carries the RS256 signature GitHub verifies.
    #[test]
    fn an_app_jwt_has_an_rs256_signature_over_its_header_and_claims() {
        let jwt = GithubAppAdapter::mint_app_jwt(&credential(), JWT_NOW_SECS).unwrap();
        let (header, _, signature_bytes, signing_input) = jwt_parts(&jwt);

        assert_eq!(header["alg"], "RS256");
        signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, TEST_PUBLIC_KEY)
            .verify(signing_input.as_bytes(), &signature_bytes)
            .expect("the JWT signature must verify over its compact-JWS signing input");
    }

    /// Discovery chooses the recorded installation and keeps its id out of the durable credential.
    #[tokio::test]
    async fn installation_discovery_is_cached_in_memory_without_replacing_the_private_key() {
        let cred = credential();
        let http = fixture_transport(vec![
            (200, RECORDED_INSTALLATIONS),
            (201, RECORDED_ACCESS_TOKENS),
            (201, RECORDED_ACCESS_TOKENS),
        ]);
        let adapter = GithubAppAdapter::new();

        let first = adapter.refresh(&cred, &http).await.unwrap();
        let second = adapter.refresh(&cred, &http).await.unwrap();

        assert_eq!(first.refresh_token, TEST_PRIVATE_KEY);
        assert_eq!(second.refresh_token, TEST_PRIVATE_KEY);
        let requests = http.requests();
        assert_eq!(
            requests.len(),
            3,
            "the second mint reuses only in-memory discovery"
        );
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].url, INSTALLATIONS_URL);
        assert_eq!(
            requests[1].url,
            format!("{ACCESS_TOKENS_URL_PREFIX}{RECORDED_INSTALLATION_ID}/access_tokens")
        );
        assert_eq!(requests[2].method, "POST");
        for request in requests {
            let authorization = request
                .headers
                .iter()
                .find(|(name, _)| name == "Authorization")
                .map(|(_, value)| value)
                .expect("every GitHub request is authenticated by the App JWT");
            assert!(authorization.starts_with("Bearer "));
            assert!(
                !authorization.contains("BEGIN PRIVATE KEY"),
                "only the derived JWT may leave the vault"
            );
        }
    }

    /// The captured 201 body supplies the opaque installation token and absolute expiry.
    #[tokio::test]
    async fn a_recorded_installation_token_response_sets_token_and_expiry() {
        let http = fixture_transport(vec![
            (200, RECORDED_INSTALLATIONS),
            (201, RECORDED_ACCESS_TOKENS),
        ]);
        let tokens = GithubAppAdapter::new()
            .refresh(&credential(), &http)
            .await
            .unwrap();

        assert_eq!(tokens.access_token, "ghs_4617...MASKED_LIVE_TOKEN");
        assert!(
            tokens.access_token.is_ascii(),
            "installation tokens are header-safe ASCII"
        );
        assert_eq!(tokens.expires_at_ms, Some(RECORDED_EXPIRY_MS));
    }

    /// The recorded mint body has no inline repository list, so parsing must not require one.
    #[test]
    fn a_recorded_installation_token_without_inline_repositories_is_accepted() {
        let response: InstallationTokenResponse = serde_json::from_slice(RECORDED_ACCESS_TOKENS)
            .expect("an empty or absent repositories list is not a token-mint failure");

        assert_eq!(response.token, "ghs_4617...MASKED_LIVE_TOKEN");
        assert_eq!(response.expires_at, "2026-08-17T10:18:57Z");
    }
}
