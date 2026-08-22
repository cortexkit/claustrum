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
/// Sent on every GitHub call because the REST API REFUSES a request without one, with
/// `403 "Request forbidden by administrative rules..."` -- a status indistinguishable
/// from a permission refusal, which is how it cost a sibling module hours on
/// 2026-08-17. `reqwest` sends none unless configured.
///
/// Enforcement VARIES BY ENDPOINT on this vendor (GitHub's MCP surface does not require
/// it), so "our calls work today" is not evidence that a new endpoint will accept them.
/// The test asserts it on the captured request rather than reading this constant.
///
/// Value is a plain module identifier: GitHub asks for a name it can contact an operator
/// about, and any non-empty string satisfies the check. Safe to rename -- unlike the
/// keychain-service and AAD domain strings, nothing is derived from it.
const USER_AGENT: &str = "claustrum";
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
        let (encoding, der) = private_key_der_from_pem(&cred.refresh_token)?;
        let key_pair = match encoding {
            KeyEncoding::Pkcs8 => signature::RsaKeyPair::from_pkcs8(&der),
            KeyEncoding::Pkcs1 => signature::RsaKeyPair::from_der(&der),
        }
        .map_err(|error| {
            RefreshError::Decode(format!("invalid GitHub App {encoding:?} key: {error}"))
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
        // A 401 HERE IS NOT A DEATH STATEMENT, so it must not become one.
        //
        // InvalidGrant is reserved in this crate for a provider EXPLICITLY declaring a
        // grant dead: anthropic raises it only when the body literally contains
        // "invalid_grant", and a bare 400 falls through to Status. GitHub's 401 on an App
        // JWT carries no such statement -- it is returned for a revoked key AND for CLOCK
        // SKEW, since an `iat` in the future or an `exp` too far out are both rejected
        // this way.
        //
        // Mapped to InvalidGrant, a clock blip flips a healthy App to needs_reauth: a
        // permanent, serving-stopped state that only an operator re-deposit clears, for a
        // condition that heals itself. Transient is the honest reading -- a genuinely
        // dead key keeps failing and surfaces through auth_events, and a slow alarm is
        // cheaper than a wrong permanent verdict.
        if response.status == 401 {
            return Err(RefreshError::Status(
                401,
                format!(
                    "GitHub rejected the App JWT while discovering installations: {}",
                    String::from_utf8_lossy(&response.body)
                ),
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
        // Same reasoning as the discovery 401 above: transient, never InvalidGrant.
        if response.status == 401 {
            return Err(RefreshError::Status(
                401,
                format!(
                    "GitHub rejected the App JWT at the token exchange: {}",
                    String::from_utf8_lossy(&response.body)
                ),
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

/// Which ASN.1 container a private-key PEM carries, decided by its armour label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyEncoding {
    /// `-----BEGIN PRIVATE KEY-----`
    Pkcs8,
    /// `-----BEGIN RSA PRIVATE KEY-----`
    Pkcs1,
}

/// Decode a private-key PEM, accepting BOTH containers GitHub and OpenSSL emit.
///
/// THE DEFAULT GITHUB HANDS YOU IS PKCS#1, AND ONLY PKCS#1. "Generate a private key"
/// on an App's settings page downloads `-----BEGIN RSA PRIVATE KEY-----`. Accepting
/// only PKCS#8 therefore rejects every key an operator can actually obtain, while
/// passing every test written with a key made by `openssl genpkey` (whose default IS
/// PKCS#8). Measured, not assumed: 21 real App keys deposited across the fleet all
/// failed here with a decode error before any HTTP call.
///
/// The armour label is the discriminator, and it is reliable: the two containers are
/// different ASN.1 structures and the label names which one follows. `ring` parses each
/// with a different constructor, so the caller must know which it has -- hence returning
/// the encoding rather than silently normalising.
///
/// NOT SOLVED WITH DOCUMENTATION. Telling operators to run `openssl pkcs8 -topk8` first
/// would work and is what most projects do; it also means every future deposit is one
/// forgotten step away from a credential that decodes as garbage hours later. The vault
/// takes the key the platform issues.
fn private_key_der_from_pem(pem: &str) -> Result<(KeyEncoding, Vec<u8>), RefreshError> {
    let encoding = if pem.contains("-----BEGIN PRIVATE KEY-----") {
        KeyEncoding::Pkcs8
    } else if pem.contains("-----BEGIN RSA PRIVATE KEY-----") {
        KeyEncoding::Pkcs1
    } else {
        // Name what WAS found rather than only what was wanted -- an EC or encrypted key
        // pasted here should say so, not produce a generic "must be PEM".
        let found = pem
            .lines()
            .find(|line| line.starts_with("-----BEGIN"))
            .unwrap_or("no PEM armour at all");
        return Err(RefreshError::Decode(format!(
            "GitHub App private key must be an RSA PEM (PKCS#1 or PKCS#8); found: {found}"
        )));
    };
    let encoded: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| RefreshError::Decode(format!("decode GitHub App key PEM: {error}")))?;
    Ok((encoding, der))
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    // `base64::Engine` is deliberately NOT imported here: the parent module imports it
    // and `use super::*` below brings it in, so an explicit one is redundant. The
    // decode call further down proves it is still in scope -- if this comment is ever
    // wrong, that call stops compiling rather than silently degrading.
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
    /// The key format GitHub ACTUALLY issues must sign, not merely the one our
    /// fixtures were generated with.
    ///
    /// "Generate a private key" on an App's settings page downloads PKCS#1
    /// (`BEGIN RSA PRIVATE KEY`). `openssl genpkey` -- the natural way to make a test
    /// key -- emits PKCS#8. So a PKCS#8-only parser passes every test and rejects every
    /// real key, which is exactly what happened: 21 deposited App keys all failed with a
    /// decode error before any HTTP call.
    ///
    /// Both arms are asserted because accepting only PKCS#1 would be the same defect
    /// mirrored, and a fixture-shaped key must keep working.
    #[test]
    fn both_pem_containers_parse_because_github_issues_the_one_openssl_does_not_default_to() {
        let pkcs1 = std::process::Command::new("openssl")
            .args(["genrsa", "2048"])
            .output()
            .expect("openssl genrsa");
        let pkcs1 = String::from_utf8(pkcs1.stdout).expect("pem is utf8");
        assert!(
            pkcs1.contains("BEGIN RSA PRIVATE KEY"),
            "openssl genrsa should emit PKCS#1; got: {}",
            pkcs1.lines().next().unwrap_or("")
        );
        let (encoding, der) = private_key_der_from_pem(&pkcs1).expect("PKCS#1 must decode");
        assert_eq!(encoding, KeyEncoding::Pkcs1);
        signature::RsaKeyPair::from_der(&der).expect("PKCS#1 DER must load as a signing key");

        let pkcs8 = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ])
            .output()
            .expect("openssl genpkey");
        let pkcs8 = String::from_utf8(pkcs8.stdout).expect("pem is utf8");
        let (encoding, der) = private_key_der_from_pem(&pkcs8).expect("PKCS#8 must decode");
        assert_eq!(encoding, KeyEncoding::Pkcs8);
        signature::RsaKeyPair::from_pkcs8(&der).expect("PKCS#8 DER must load as a signing key");

        // A key that is neither must name what it found, so an EC or encrypted key pasted
        // here is diagnosable rather than a generic refusal.
        let err = private_key_der_from_pem(
            "-----BEGIN EC PRIVATE KEY-----\nAA==\n-----END EC PRIVATE KEY-----",
        )
        .expect_err("an EC key must be refused");
        assert!(
            format!("{err}").contains("EC PRIVATE KEY"),
            "the refusal must name what was found; got {err}"
        );
    }

    /// EVERY GitHub call must carry a User-Agent, on the wire, not in a constant.
    ///
    /// GitHub's REST API refuses a request without one -- `403 "Request forbidden by
    /// administrative rules. Please make sure your request has a User-Agent header"` --
    /// and `reqwest` sends none unless configured. A peer lost hours to exactly this on
    /// 2026-08-17: five hypotheses eliminated from the outside because a bare 403 is
    /// compatible with all of them, and the body named the cause in one line.
    ///
    /// WHY OUR SUCCESS DOES NOT PROVE OUR SAFETY, which is the reason this test exists:
    /// enforcement VARIES BY ENDPOINT on this vendor. GitHub's MCP surface does not
    /// enforce it, and the peer's REST path did. So an adapter can pass every live call
    /// it happens to make today and fail the moment it reaches a stricter endpoint --
    /// installation discovery and the token exchange are two different paths, and this
    /// asserts BOTH rather than trusting that a shared helper stays shared.
    ///
    /// Asserted on the CAPTURED REQUEST, never on the constant: a test that reads
    /// `USER_AGENT` proves a value is stored, not that a vendor would see it.
    #[tokio::test]
    async fn every_github_request_carries_a_user_agent_because_the_api_refuses_without_one() {
        let http = fixture_transport(vec![
            (200, RECORDED_INSTALLATIONS),
            (201, RECORDED_ACCESS_TOKENS),
        ]);
        let adapter = GithubAppAdapter::default();
        let _ = adapter.refresh(&credential(), &http).await;

        let requests = http.requests();
        assert!(
            requests.len() >= 2,
            "expected discovery AND exchange to be attempted; got {}",
            requests.len()
        );
        for request in requests.iter() {
            let ua = request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"));
            assert!(
                ua.is_some(),
                "no User-Agent on {} -- GitHub answers 403 with an administrative-rules \
                 message, which is indistinguishable from a permission refusal",
                request.url
            );
            assert!(
                !ua.expect("checked").1.is_empty(),
                "an empty User-Agent is refused the same as a missing one: {}",
                request.url
            );
        }
    }

    /// A GitHub 401 must be TRANSIENT, never a permanent needs_reauth.
    ///
    /// GitHub returns 401 on an App JWT for a revoked key AND for clock skew. Only the
    /// first is permanent, and nothing in the response distinguishes them -- so the
    /// classification has to take the recoverable reading. InvalidGrant here would flip
    /// a healthy App to needs_reauth on a clock blip: serving stops, and only an
    /// operator re-deposit clears it.
    #[tokio::test]
    async fn a_github_401_is_transient_because_clock_skew_also_produces_one() {
        let http = fixture_transport(vec![(
            401,
            br#"{"message":"A JSON web token could not be decoded"}"#,
        )]);
        let adapter = GithubAppAdapter::default();
        let err = adapter
            .refresh(&credential(), &http)
            .await
            .expect_err("a 401 must fail the refresh");
        assert!(
            !matches!(err, RefreshError::InvalidGrant(_)),
            "a bare 401 is not the provider declaring the key dead; got {err:?}"
        );
        assert!(
            matches!(err, RefreshError::Status(401, _)),
            "expected a transient status error carrying the code; got {err:?}"
        );
    }

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
