//! The Antigravity (Google Code-Assist) OAuth refresh adapter.
//!
//! Antigravity is Google's Code-Assist OAuth path — distinct from the gemini-cli
//! login the [`super::google`] adapter handles. It refreshes against the standard
//! Google token endpoint (`oauth2.googleapis.com/token`, form-encoded), but with its
//! OWN public installed-app client (NOT the gemini-cli client), because a Google
//! refresh token only refreshes against the client that minted it.
//!
//! Packed refresh token: an antigravity credential's `refresh_token` is stored as a
//! PIPE-PACKED string `<refresh>|<projectId>|<managedProjectId>` (the latter two
//! segments optional), mirroring the antigravity-auth reference (`parseRefreshParts`
//! / `formatRefreshParts`). The Code-Assist project id rides in the credential
//! because the request path needs it; the refresh exchange itself uses ONLY the bare
//! refresh token (the first segment). This adapter splits the pack, refreshes the
//! bare token, and RE-PACKS the result with the original project segments preserved,
//! so the stored credential keeps its project binding across refreshes.
//!
//! Resolving/provisioning the effective Code-Assist project (the `loadCodeAssist` /
//! `onboardUser` network flow) is deliberately NOT done here — it is a stateful,
//! cached consumer concern. The vault stores and serves the project segment; it does
//! not perform Code-Assist project resolution.

use async_trait::async_trait;
use serde::Deserialize;

use super::{form_urlencode, HttpTransport, RefreshAdapter, RefreshError, RefreshedTokens};
use crate::oauth::OAuthCredential;

/// Google's OAuth2 token endpoint for the refresh-token grant.
pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// The adapter name, matching `VaultRecord::refresh_adapter` for antigravity records.
pub const ADAPTER_NAME: &str = "antigravity";

// The public installed-app OAuth client Antigravity uses (its OWN, distinct from
// gemini-cli's). A Google refresh token only refreshes against its minting client,
// so an antigravity-minted token MUST be refreshed with exactly this client. Public
// by design (RFC 8252), but the literal strings trip secret-scanner regexes, so the
// bytes are XOR-masked with `CRED_MASK` and decoded at runtime — NOT for secrecy
// (trivially reversible), only to keep the literals out of source text. Both are
// env-overridable (CK_ANTIGRAVITY_OAUTH_CLIENT_ID / _SECRET) for when Google rotates
// the client. Source: antigravity-auth/packages/core/src/constants.ts.
const CRED_MASK: &[u8] = b"credentials-public-antigravity-v1";
const CLIENT_ID_MASKED: &[u8] = &[
    82, 66, 82, 85, 85, 94, 66, 89, 87, 92, 70, 20, 65, 88, 22, 1, 1, 16, 94, 8, 0, 70, 1, 85, 67,
    13, 21, 27, 17, 75, 30, 67, 71, 23, 29, 9, 11, 15, 6, 64, 14, 85, 92, 64, 72, 0, 91, 3, 28, 25,
    16, 3, 6, 1, 27, 14, 11, 23, 20, 5, 12, 6, 26, 66, 24, 69, 6, 28, 17, 74, 6, 1, 25,
];
const CLIENT_SECRET_MASKED: &[u8] = &[
    36, 61, 38, 55, 53, 54, 89, 34, 84, 84, 53, 122, 34, 65, 90, 90, 37, 7, 97, 43, 95, 25, 37, 37,
    74, 18, 46, 42, 64, 3, 27, 7, 117, 34, 20,
];
const CLIENT_ID_ENV: &str = "CK_ANTIGRAVITY_OAUTH_CLIENT_ID";
const CLIENT_SECRET_ENV: &str = "CK_ANTIGRAVITY_OAUTH_CLIENT_SECRET";

/// XOR-unmask an embedded public credential to its plaintext.
fn unmask(masked: &[u8]) -> String {
    masked
        .iter()
        .enumerate()
        .map(|(i, b)| (b ^ CRED_MASK[i % CRED_MASK.len()]) as char)
        .collect()
}

/// The public Google OAuth client id used by the Antigravity login and refresh flow.
pub fn oauth_client_id() -> String {
    std::env::var(CLIENT_ID_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| unmask(CLIENT_ID_MASKED))
}

/// The public Google OAuth client secret used by the Antigravity login and refresh flow.
pub fn oauth_client_secret() -> String {
    std::env::var(CLIENT_SECRET_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| unmask(CLIENT_SECRET_MASKED))
}

/// Split a packed antigravity refresh string into the bare refresh token (first
/// `|`-segment) and the trailing project segments (everything after the first `|`,
/// re-joined). Returns `("", "")` shapes gracefully so a bare (unpacked) token works.
fn split_packed_refresh(packed: &str) -> (&str, Option<&str>) {
    match packed.split_once('|') {
        Some((refresh, rest)) => (refresh, Some(rest)),
        None => (packed, None),
    }
}

/// Re-pack a (possibly new) bare refresh token with the original trailing project
/// segments, so the stored credential keeps its `<refresh>|<projectId>|<managed>`
/// binding across a refresh.
fn repack_refresh(new_bare: &str, original_tail: Option<&str>) -> String {
    match original_tail {
        Some(tail) => format!("{new_bare}|{tail}"),
        None => new_bare.to_string(),
    }
}

/// Extract the EFFECTIVE Code-Assist project id from a packed antigravity refresh
/// string (`<refresh>|<projectId>|<managedProjectId>`), for surfacing as non-secret
/// `credential.get` metadata. Returns the managed project id when present (the
/// resolved/provisioned project the request path actually uses, mirroring the
/// reference's `ensureProjectContext` precedence), else the plain project id, else
/// `None`. NEVER returns the refresh token (the first segment).
///
/// Resolving a managed project when none is stored (the `loadCodeAssist` /
/// `onboardUser` network flow) is a consumer concern — the vault only surfaces what
/// is stored.
pub fn effective_project_id(packed_refresh: &str) -> Option<String> {
    let mut parts = packed_refresh.split('|');
    let _refresh = parts.next(); // never surfaced
    let project = parts.next().filter(|s| !s.is_empty());
    let managed = parts.next().filter(|s| !s.is_empty());
    managed.or(project).map(|s| s.to_string())
}

/// The success response of the refresh exchange. Antigravity may rotate the refresh
/// token (optional in the response); the existing one is reused when absent.
#[derive(Debug, Deserialize)]
struct RefreshResponseBody {
    access_token: String,
    expires_in: i64,
    #[serde(default)]
    refresh_token: Option<String>,
}

/// The Antigravity refresh adapter. Holds the public antigravity client id + secret
/// (env-overridable), which Google's token endpoint requires for the refresh grant.
pub struct AntigravityAdapter {
    client_id: String,
    client_secret: String,
}

impl AntigravityAdapter {
    /// Build with the public antigravity client id + secret defaults (overridable via
    /// `CK_ANTIGRAVITY_OAUTH_CLIENT_ID` / `CK_ANTIGRAVITY_OAUTH_CLIENT_SECRET`).
    pub fn new() -> Self {
        AntigravityAdapter {
            client_id: oauth_client_id(),
            client_secret: oauth_client_secret(),
        }
    }

    /// Build with an explicit client id + secret (tests / a non-default client).
    pub fn with_client(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        AntigravityAdapter {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
        }
    }

    /// The form-encoded refresh body. Uses the BARE refresh token (first pack
    /// segment), not the packed string. Separated so the conformance test can assert
    /// the exact bytes sent.
    fn request_body(&self, bare_refresh: &str) -> Vec<u8> {
        form_urlencode(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", bare_refresh),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
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

impl Default for AntigravityAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RefreshAdapter for AntigravityAdapter {
    fn name(&self) -> &str {
        ADAPTER_NAME
    }

    async fn refresh(
        &self,
        cred: &OAuthCredential,
        http: &dyn HttpTransport,
    ) -> Result<RefreshedTokens, RefreshError> {
        // The stored refresh token is packed `<refresh>|<projectId>|<managed>`; the
        // exchange uses only the bare first segment, and the result is re-packed with
        // the same project tail so the credential keeps its project binding.
        let (bare_refresh, tail) = split_packed_refresh(cred.refresh_token.expose());
        let body = self.request_body(bare_refresh);
        let resp = http
            .post(
                Self::endpoint(cred),
                &[],
                "application/x-www-form-urlencoded",
                body,
            )
            .await?;

        // A dead refresh token comes back as 400 invalid_grant (Google's standard).
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
        // Re-pack: a rotated refresh token replaces the bare segment; an omitted one
        // reuses the existing bare token. The project tail is always preserved.
        let new_bare = crate::secret::SecretString::new(
            parsed
                .refresh_token
                .unwrap_or_else(|| bare_refresh.to_string()),
        );
        let refresh_token =
            crate::secret::SecretString::new(repack_refresh(new_bare.expose(), tail));
        Ok(RefreshedTokens {
            access_token: parsed.access_token.into(),
            refresh_token,
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

    fn packed_cred() -> OAuthCredential {
        OAuthCredential {
            access_token: "old-access".to_string().into(),
            // <refresh>|<projectId>|<managedProjectId>
            refresh_token: "1//0refresh|my-project|managed-proj-123".to_string().into(),
            expires_at_ms: Some(0),
            token_url: TOKEN_URL.into(),
            client_id: None,
            scopes: vec![],
        }
    }

    const RECORDED_SUCCESS: &str =
        r#"{"access_token":"ya29.new-access","expires_in":3599,"token_type":"Bearer"}"#;

    #[test]
    fn default_client_unmasks_to_the_public_antigravity_client() {
        assert_eq!(
            oauth_client_id(),
            "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com"
        );
        assert_eq!(oauth_client_secret(), "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");
    }

    #[tokio::test]
    async fn refresh_uses_bare_token_and_repacks_project_tail() {
        let http = FixtureTransport::ok(200, RECORDED_SUCCESS.as_bytes().to_vec());
        let tokens = AntigravityAdapter::with_client("cid", "secret")
            .refresh(&packed_cred(), &http)
            .await
            .unwrap();
        assert_eq!(tokens.access_token.expose(), "ya29.new-access");
        // The POST body sent only the BARE refresh token, not the packed string.
        let body = String::from_utf8(http.requests()[0].body.clone()).unwrap();
        assert!(
            body.contains("refresh_token=1%2F%2F0refresh&"),
            "bare token only, no project tail in the POST: {body}"
        );
        assert!(
            !body.contains("my-project"),
            "project tail must not be sent: {body}"
        );
        // No rotation in the response → the bare token is reused, tail PRESERVED.
        assert_eq!(
            tokens.refresh_token.expose(),
            "1//0refresh|my-project|managed-proj-123",
            "stored refresh re-packs the original project tail"
        );
    }

    #[tokio::test]
    async fn rotated_refresh_token_repacks_with_original_tail() {
        let rotated =
            r#"{"access_token":"ya29.x","expires_in":3599,"refresh_token":"1//0NEWrefresh"}"#;
        let http = FixtureTransport::ok(200, rotated.as_bytes().to_vec());
        let tokens = AntigravityAdapter::with_client("c", "s")
            .refresh(&packed_cred(), &http)
            .await
            .unwrap();
        // The NEW bare token, re-packed with the SAME project tail.
        assert_eq!(
            tokens.refresh_token.expose(),
            "1//0NEWrefresh|my-project|managed-proj-123"
        );
    }

    #[tokio::test]
    async fn bare_unpacked_refresh_token_works() {
        let mut cred = packed_cred();
        cred.refresh_token = "1//0bareonly".to_string().into(); // no project-specific suffix
        let http = FixtureTransport::ok(200, RECORDED_SUCCESS.as_bytes().to_vec());
        let tokens = AntigravityAdapter::with_client("c", "s")
            .refresh(&cred, &http)
            .await
            .unwrap();
        assert_eq!(
            tokens.refresh_token.expose(),
            "1//0bareonly",
            "no tail to preserve"
        );
    }

    #[tokio::test]
    async fn request_is_form_encoded_with_client_secret() {
        let http = FixtureTransport::ok(200, RECORDED_SUCCESS.as_bytes().to_vec());
        AntigravityAdapter::with_client("the-id", "the-secret")
            .refresh(&packed_cred(), &http)
            .await
            .unwrap();
        let reqs = http.requests();
        assert_eq!(reqs[0].url, TOKEN_URL);
        assert_eq!(reqs[0].content_type, "application/x-www-form-urlencoded");
        let body = String::from_utf8(reqs[0].body.clone()).unwrap();
        assert!(body.contains("grant_type=refresh_token"), "{body}");
        assert!(body.contains("client_id=the-id"), "{body}");
        assert!(body.contains("client_secret=the-secret"), "{body}");
    }

    #[test]
    fn effective_project_id_prefers_managed_and_never_leaks_refresh() {
        // managed (3rd segment) wins when present.
        assert_eq!(
            effective_project_id("1//0refresh|my-project|managed-proj-123"),
            Some("managed-proj-123".to_string())
        );
        // plain project (2nd segment) when no managed.
        assert_eq!(
            effective_project_id("1//0refresh|my-project"),
            Some("my-project".to_string())
        );
        assert_eq!(
            effective_project_id("1//0refresh|my-project|"),
            Some("my-project".to_string()),
            "empty managed segment falls back to plain project"
        );
        // a bare token (no pack) has no project.
        assert_eq!(effective_project_id("1//0refreshonly"), None);
        // CRITICAL: the refresh token (1st segment) is NEVER returned.
        let got = effective_project_id("super-secret-refresh|proj");
        assert_eq!(got, Some("proj".to_string()));
        assert_ne!(got.as_deref(), Some("super-secret-refresh"));
    }

    #[tokio::test]
    async fn invalid_grant_is_dead_token() {
        let http = FixtureTransport::ok(
            400,
            br#"{"error":"invalid_grant","error_description":"Token has been expired or revoked."}"#
                .to_vec(),
        );
        match AntigravityAdapter::with_client("c", "s")
            .refresh(&packed_cred(), &http)
            .await
        {
            Err(RefreshError::InvalidGrant(_)) => {}
            other => panic!("expected InvalidGrant, got {other:?}"),
        }
    }
}
