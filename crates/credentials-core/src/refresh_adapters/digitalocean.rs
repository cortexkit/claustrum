//! DigitalOcean implicit-grant login and static-token adapter.
//!
//! The provider returns its access token in the browser URL fragment, which is not
//! sent to an HTTP server. The CLI listener serves a tiny fragment bootstrap page;
//! this module parses the token fields posted back by that page.

use async_trait::async_trait;

use super::{HttpTransport, RefreshAdapter, RefreshError, RefreshedTokens};
use crate::oauth::OAuthCredential;
use crate::oauth_login::LoginTokens;

pub const ADAPTER_NAME: &str = "digitalocean";
pub const DEFAULT_ID: &str = "oauth:digitalocean";
pub const AUTHORIZE_URL: &str = "https://cloud.digitalocean.com/v1/oauth/authorize";
pub const CLIENT_ID: &str = "b1a6c5158156caac821fd1b30253ca8acb52454a48fa744420e41889cb589f82";
pub const REDIRECT_URI: &str = "http://localhost:1456/auth/callback";
pub const SCOPE: &str = "genai:read inference:query";
pub const SCOPES: &[&str] = &["genai:read", "inference:query"];

/// Build the implicit-grant URL. The scope and redirect are provider-registered
/// constants; only the per-login state is variable.
pub fn authorize_url(state: &str) -> String {
    let encoded_state: String = url::form_urlencoded::byte_serialize(state.as_bytes()).collect();
    format!(
        "{AUTHORIZE_URL}?client_id={CLIENT_ID}&response_type=token&redirect_uri=http%3A%2F%2Flocalhost%3A1456%2Fauth%2Fcallback&scope=genai%3Aread%20inference%3Aquery&state={encoded_state}"
    )
}

/// Parse the form posted by the fragment-capture page, or a pasted callback URL/hash.
pub fn parse_fragment_capture(
    raw: &str,
    expected_state: &str,
    now_ms: i64,
) -> Result<LoginTokens, String> {
    let text = raw.trim();
    let fragment = if let Some(url) = text
        .strip_prefix("http://")
        .or_else(|| text.strip_prefix("https://"))
    {
        let parsed = url::Url::parse(&format!("https://{url}"))
            .map_err(|_| "invalid DigitalOcean callback")?;
        parsed.fragment().unwrap_or("").to_string()
    } else {
        text.strip_prefix('#').unwrap_or(text).to_string()
    };
    let fields: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(fragment.as_bytes())
            .into_owned()
            .collect();
    let state = fields.get("state").map(String::as_str).unwrap_or("");
    if state != expected_state {
        return Err("DigitalOcean callback state did not match".into());
    }
    let access_token = fields
        .get("access_token")
        .cloned()
        .ok_or_else(|| "DigitalOcean callback omitted access_token".to_string())?;
    let expires_in = fields
        .get("expires_in")
        .ok_or_else(|| "DigitalOcean callback omitted expires_in".to_string())?
        .parse::<i64>()
        .map_err(|_| "DigitalOcean callback had an invalid expires_in".to_string())?;
    Ok(LoginTokens {
        access_token,
        refresh_token: String::new(),
        expires_at_ms: Some(now_ms.saturating_add(expires_in.saturating_mul(1000))),
        id_token: None,
        account: None,
        organization: None,
    })
}

/// There is no DigitalOcean refresh token. The adapter deliberately returns the
/// vault's terminal refresh error so an expired record surfaces as needs_reauth.
#[derive(Debug, Default)]
pub struct DigitalOceanAdapter;

impl DigitalOceanAdapter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RefreshAdapter for DigitalOceanAdapter {
    fn name(&self) -> &str {
        ADAPTER_NAME
    }

    async fn refresh(
        &self,
        _cred: &OAuthCredential,
        _http: &dyn HttpTransport,
    ) -> Result<RefreshedTokens, RefreshError> {
        Err(RefreshError::InvalidGrant(
            "DigitalOcean access tokens are re-login-only".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refresh_adapters::fixture::FixtureTransport;

    #[test]
    fn authorize_url_has_implicit_scope_and_state() {
        let url = authorize_url("state value");
        assert!(url.starts_with(AUTHORIZE_URL));
        let parsed = url::Url::parse(&url).unwrap();
        let params: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(params.get("client_id").unwrap(), CLIENT_ID);
        assert_eq!(params.get("response_type").unwrap(), "token");
        assert_eq!(params.get("redirect_uri").unwrap(), REDIRECT_URI);
        assert_eq!(params.get("scope").unwrap(), SCOPE);
        assert_eq!(params.get("state").unwrap(), "state value");
    }

    #[test]
    fn fragment_response_parses_expiry_without_identity() {
        let tokens = parse_fragment_capture(
            "#access_token=do-token&token_type=bearer&expires_in=3600&scope=genai%3Aread%20inference%3Aquery&state=state",
            "state",
            1000,
        )
        .unwrap();
        assert_eq!(tokens.access_token, "do-token");
        assert!(tokens.refresh_token.is_empty());
        assert_eq!(tokens.expires_at_ms, Some(3_601_000));
        assert!(tokens.account.is_none());
    }

    #[test]
    fn fragment_state_is_required() {
        assert!(parse_fragment_capture("#access_token=t&expires_in=60", "state", 0).is_err());
    }

    #[tokio::test]
    async fn adapter_surfaces_relogin_and_never_networks() {
        let http = FixtureTransport::new(Vec::new());
        let cred = OAuthCredential {
            access_token: "token".into(),
            refresh_token: String::new(),
            expires_at_ms: Some(0),
            token_url: String::new(),
            client_id: Some(CLIENT_ID.into()),
            scopes: vec![SCOPE.into()],
        };
        assert!(matches!(
            DigitalOceanAdapter::new().refresh(&cred, &http).await,
            Err(RefreshError::InvalidGrant(_))
        ));
        assert!(http.requests().is_empty());
    }
}
