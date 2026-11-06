//! Google-family login wire helpers shared by the offline CLI.
//!
//! Gemini CLI and Antigravity use public installed-app clients; Gmail uses the
//! operator's own Desktop client. All share Google authorization-code endpoints
//! with separate loopback redirects. This module keeps
//! those provider-specific constants together with the Code Assist project
//! provisioning needed before an Antigravity credential can be stored.

use std::time::Duration;

use serde_json::Value;

use crate::refresh_adapters::{HttpResponse, HttpTransport, RefreshError};

/// Google OAuth authorization endpoint shared by both login families.
pub const AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
/// Google OAuth token endpoint shared by both login families.
pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// Google userinfo endpoint used for best-effort email identity capture.
pub const USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json";
/// Gemini CLI's registered loopback redirect.
pub const GEMINI_REDIRECT_URI: &str = "http://127.0.0.1:8085/oauth2callback";
/// Antigravity's registered loopback redirect.
pub const ANTIGRAVITY_REDIRECT_URI: &str = "http://127.0.0.1:51121/callback";
/// Desktop clients permit arbitrary loopback ports (RFC 8252). Keep Gmail
/// separate from the two public Code Assist clients' listeners.
pub const GMAIL_REDIRECT_URI: &str = "http://127.0.0.1:8086/oauth2callback";
/// Send-only mailbox authority plus the identity required by consumers.
pub const GMAIL_SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/gmail.send",
    "openid",
    "email",
];
/// The scope set used by both Google desktop clients.
pub const SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
];
/// Google requires an offline refresh grant and an explicit consent screen.
pub const AUTHORIZE_EXTRA_PARAMS: &[(&str, &str)] =
    &[("access_type", "offline"), ("prompt", "consent")];

/// Code Assist project lookup endpoint used by Antigravity.
pub const LOAD_CODE_ASSIST_URL: &str =
    "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist";
/// Code Assist project provisioning endpoint used by Antigravity.
pub const ONBOARD_USER_URL: &str = "https://cloudcode-pa.googleapis.com/v1internal:onboardUser";
const CODE_ASSIST_METADATA: &str = "{\"metadata\":{\"ideType\":\"ANTIGRAVITY\"}}";
// Google uses this User-Agent to decide whether the free tier and companion project
// are available. These values follow the antigravity-auth plugin's AGY_CLI_VERSION
// and AGY_CLI_CHANGE_LIST in packages/core/src/fingerprint.ts.
const AGY_CLI_VERSION: &str = "1.3.5";
const AGY_CLI_CHANGE_LIST: &str = "998863838";
const MAX_ONBOARD_ATTEMPTS: usize = 5;
const ONBOARD_POLL_DELAY: Duration = Duration::from_secs(2);

fn antigravity_user_agent(os: &str, arch: &str) -> String {
    let os = match os {
        "macos" => "darwin",
        "" => "unknown",
        other => other,
    };
    let arch = match arch {
        "x86_64" => "amd64",
        "x86" => "386",
        "aarch64" => "arm64",
        "" => "unknown",
        other => other,
    };
    format!("antigravity/cli/{AGY_CLI_VERSION} (aidev_client; os_type={os}; arch={arch}; cl={AGY_CLI_CHANGE_LIST}; auth_method=consumer)")
}

/// Which Google client policy, scopes and redirect belong to a login provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoogleLoginProvider {
    /// Google Code Assist as used by Gemini CLI.
    Gemini,
    /// Google Code Assist as used by Antigravity.
    Antigravity,
    /// Send email as the operator using their own Desktop OAuth client.
    Gmail,
}

impl GoogleLoginProvider {
    /// Resolve the CLI provider flag.
    pub fn parse(provider: &str) -> Option<Self> {
        match provider {
            "google" => Some(Self::Gemini),
            "antigravity" => Some(Self::Antigravity),
            "gmail" => Some(Self::Gmail),
            _ => None,
        }
    }

    /// Stable method-scoped default credential id.
    pub const fn default_id(self) -> &'static str {
        match self {
            Self::Gemini => "oauth:google",
            Self::Antigravity => "antigravity:google",
            Self::Gmail => "oauth:gmail",
        }
    }

    /// The registered loopback redirect.
    pub const fn redirect_uri(self) -> &'static str {
        match self {
            Self::Gemini => GEMINI_REDIRECT_URI,
            Self::Antigravity => ANTIGRAVITY_REDIRECT_URI,
            Self::Gmail => GMAIL_REDIRECT_URI,
        }
    }

    /// The adapter name persisted on the vault record.
    pub const fn adapter_name(self) -> &'static str {
        match self {
            Self::Gemini => "google",
            Self::Antigravity => "antigravity",
            Self::Gmail => "gmail",
        }
    }

    /// The public client id, including the operator override used by refresh.
    /// Gmail has no public default; its CLI requires the operator's client id.
    pub fn client_id(self) -> String {
        match self {
            Self::Gemini => crate::refresh_adapters::google::oauth_client_id(),
            Self::Antigravity => crate::refresh_adapters::antigravity::oauth_client_id(),
            Self::Gmail => String::new(), // supplied by the operator, never a public default
        }
    }

    /// The public client secret, including the operator override used by refresh.
    /// Gmail has no public default; its CLI requires a client-secret file.
    pub fn client_secret(self) -> String {
        match self {
            Self::Gemini => crate::refresh_adapters::google::oauth_client_secret(),
            Self::Antigravity => crate::refresh_adapters::antigravity::oauth_client_secret(),
            Self::Gmail => String::new(), // supplied by file, never an environment default
        }
    }

    pub const fn scopes(self) -> &'static [&'static str] {
        match self {
            Self::Gmail => GMAIL_SCOPES,
            Self::Gemini | Self::Antigravity => SCOPES,
        }
    }
}

/// Build a Gmail record only when the durable refresh grant and account identity
/// are both usable. Keeping this before the store operation makes refusal atomic.
pub fn gmail_login_record(
    tokens: crate::oauth_login::LoginTokens,
    client_id: String,
    client_secret: crate::secret::SecretString,
    email: Option<String>,
) -> Result<crate::record::VaultRecord, &'static str> {
    if tokens.refresh_token.trim().is_empty() {
        return Err("Gmail token response omitted refresh_token; login again with consent");
    }
    let email = email.filter(|email| !email.trim().is_empty()).ok_or(
        "Gmail userinfo omitted email; refusing to store a credential without account identity",
    )?;
    let oauth = crate::oauth::OAuthCredential {
        access_token: tokens.access_token.clone().into(),
        refresh_token: tokens.refresh_token.into(),
        expires_at_ms: tokens.expires_at_ms,
        token_url: TOKEN_URL.into(),
        client_id: Some(client_id),
        client_secret: Some(client_secret),
        scopes: GMAIL_SCOPES.iter().map(|s| (*s).to_string()).collect(),
    };
    Ok(crate::record::VaultRecord::new_oauth(
        "login",
        "gmail",
        oauth,
        tokens.access_token.into_bytes(),
    )
    .with_identity(crate::record::RecordIdentity {
        account_id: Some(email.clone()),
        email: Some(email),
        org_name: None,
    }))
}

/// A discovered Code Assist project binding. Both ids are persisted in the
/// Antigravity packed refresh token because consumers use the managed id while
/// the provider may also require the user's plain project id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntigravityProject {
    pub project_id: String,
    pub managed_project_id: String,
}

/// Pack the bare Google refresh token with the project binding required by the
/// Antigravity adapter. The project ids come only from successful discovery.
pub fn pack_antigravity_refresh(refresh_token: &str, project: &AntigravityProject) -> String {
    format!(
        "{}|{}|{}",
        refresh_token, project.project_id, project.managed_project_id
    )
}

/// Discover or provision the Code Assist project required by Antigravity.
///
/// A successful `loadCodeAssist` response wins. When it has no companion project,
/// the free-tier onboarding operation is re-posted until it reports `done`, with
/// at most five attempts. The production polling delay is two seconds; tests can
/// use [`discover_antigravity_project_with_delay`] with zero delay.
pub async fn discover_antigravity_project(
    http: &dyn HttpTransport,
    access_token: &str,
) -> Result<AntigravityProject, GoogleLoginError> {
    discover_antigravity_project_with_delay(http, access_token, ONBOARD_POLL_DELAY).await
}

/// Testable form of [`discover_antigravity_project`] with an injected polling
/// delay. The request bodies and response parsing are identical to production.
pub async fn discover_antigravity_project_with_delay(
    http: &dyn HttpTransport,
    access_token: &str,
    poll_delay: Duration,
) -> Result<AntigravityProject, GoogleLoginError> {
    let authorization = format!("Bearer {access_token}");
    let user_agent = antigravity_user_agent(std::env::consts::OS, std::env::consts::ARCH);
    let headers = [
        ("Authorization", authorization.as_str()),
        ("User-Agent", user_agent.as_str()),
    ];
    let load_body = code_assist_response(
        "loadCodeAssist",
        http.post(
            LOAD_CODE_ASSIST_URL,
            &headers,
            "application/json",
            CODE_ASSIST_METADATA.as_bytes().to_vec(),
        )
        .await,
    )?;
    if let Some(project) = project_from_load_response(&load_body) {
        return Ok(project);
    }

    let allowed_tiers = load_body.get("allowedTiers").and_then(Value::as_array);
    let tier = allowed_tiers.and_then(|tiers| {
        tiers
            .iter()
            .find(|tier| tier.get("isDefault").and_then(Value::as_bool) == Some(true))
            .or_else(|| tiers.first())
    });
    if tier
        .and_then(|tier| tier.get("userDefinedCloudaicompanionProject"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        return Err(GoogleLoginError::UserDefinedProject);
    }
    let tier_id = tier
        .and_then(|tier| tier.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("free-tier");
    let onboard_body = serde_json::json!({
        "tierId": tier_id,
        "metadata": { "ideType": "ANTIGRAVITY" }
    })
    .to_string()
    .into_bytes();

    for attempt in 0..MAX_ONBOARD_ATTEMPTS {
        if attempt > 0 && !poll_delay.is_zero() {
            tokio::time::sleep(poll_delay).await;
        }
        let operation = code_assist_response(
            "onboardUser",
            http.post(
                ONBOARD_USER_URL,
                &headers,
                "application/json",
                onboard_body.clone(),
            )
            .await,
        )?;
        if operation.get("done").and_then(Value::as_bool) == Some(true) {
            if let Some(project) = project_from_onboard_response(&operation) {
                return Ok(project);
            }
            return Err(GoogleLoginError::NoProject);
        }
    }
    Err(GoogleLoginError::NoProject)
}

/// Capture the Google account email without making it a login prerequisite.
pub async fn google_userinfo_email(http: &dyn HttpTransport, access_token: &str) -> Option<String> {
    let authorization = format!("Bearer {access_token}");
    let response = http
        .get(USERINFO_URL, &[("Authorization", authorization.as_str())])
        .await
        .ok()?;
    if response.status != 200 {
        return None;
    }
    #[derive(serde::Deserialize)]
    struct UserInfo {
        #[serde(default)]
        email: Option<String>,
    }
    serde_json::from_slice::<UserInfo>(&response.body)
        .ok()?
        .email
        .filter(|email| !email.is_empty())
}

fn code_assist_response(
    call: &'static str,
    response: Result<HttpResponse, RefreshError>,
) -> Result<Value, GoogleLoginError> {
    let result = response
        .map_err(GoogleLoginError::from)
        .and_then(|response| {
            if response.status != 200 {
                return Err(GoogleLoginError::from_status(
                    response.status,
                    &response.body,
                ));
            }
            serde_json::from_slice(&response.body).map_err(|_| GoogleLoginError::Decode)
        });
    result.map_err(|error| GoogleLoginError::Call {
        call,
        error: Box::new(error),
    })
}

/// Errors from Code Assist discovery. Only schema status names and field paths
/// survive response parsing; free-form provider text can contain sensitive data.
#[derive(Debug)]
pub enum GoogleLoginError {
    Transport,
    Status {
        status: u16,
        google_status: Option<&'static str>,
        field_paths: Vec<String>,
    },
    Decode,
    InvalidGrant,
    SubscriptionRequired,
    Call {
        call: &'static str,
        error: Box<Self>,
    },
    NoProject,
    UserDefinedProject,
}

impl std::fmt::Display for GoogleLoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport => f.write_str("transport error"),
            Self::Status { status, google_status, field_paths } => {
                write!(f, "status {status}")?;
                if let Some(google_status) = google_status {
                    write!(f, " ({google_status})")?;
                }
                if !field_paths.is_empty() {
                    write!(f, "; fields: {}", field_paths.join(", "))?;
                }
                Ok(())
            }
            Self::Decode => f.write_str("response decode error"),
            Self::InvalidGrant => f.write_str("authentication rejected (invalid_grant)"),
            Self::SubscriptionRequired => f.write_str("subscription required (subscription_required)"),
            Self::Call { call, error } => write!(f, "Google Code Assist {call} failed: {error}"),
            Self::NoProject => f.write_str(
                "Google Code Assist did not return a project id; Antigravity login cannot continue",
            ),
            Self::UserDefinedProject => f.write_str(
                "Antigravity account needs its own Google Cloud project; this login does not support user-defined projects",
            ),
        }
    }
}

impl std::error::Error for GoogleLoginError {}

impl From<RefreshError> for GoogleLoginError {
    fn from(error: RefreshError) -> Self {
        match error {
            RefreshError::Transport(_) => Self::Transport,
            RefreshError::Decode(_) => Self::Decode,
            RefreshError::Status(status, body) => Self::from_status(status, body.as_bytes()),
            RefreshError::InvalidGrant(_) => Self::InvalidGrant,
            RefreshError::SubscriptionRequired => Self::SubscriptionRequired,
        }
    }
}

impl GoogleLoginError {
    fn from_status(status: u16, body: &[u8]) -> Self {
        let body = serde_json::from_slice::<Value>(body).unwrap_or(Value::Null);
        let error = &body["error"];
        let google_status = match error["status"].as_str() {
            Some("OK") => Some("OK"),
            Some("CANCELLED") => Some("CANCELLED"),
            Some("UNKNOWN") => Some("UNKNOWN"),
            Some("INVALID_ARGUMENT") => Some("INVALID_ARGUMENT"),
            Some("DEADLINE_EXCEEDED") => Some("DEADLINE_EXCEEDED"),
            Some("NOT_FOUND") => Some("NOT_FOUND"),
            Some("ALREADY_EXISTS") => Some("ALREADY_EXISTS"),
            Some("PERMISSION_DENIED") => Some("PERMISSION_DENIED"),
            Some("RESOURCE_EXHAUSTED") => Some("RESOURCE_EXHAUSTED"),
            Some("FAILED_PRECONDITION") => Some("FAILED_PRECONDITION"),
            Some("ABORTED") => Some("ABORTED"),
            Some("OUT_OF_RANGE") => Some("OUT_OF_RANGE"),
            Some("UNIMPLEMENTED") => Some("UNIMPLEMENTED"),
            Some("INTERNAL") => Some("INTERNAL"),
            Some("UNAVAILABLE") => Some("UNAVAILABLE"),
            Some("DATA_LOSS") => Some("DATA_LOSS"),
            Some("UNAUTHENTICATED") => Some("UNAUTHENTICATED"),
            _ => None,
        };
        let mut field_paths = Vec::new();
        if let Some(details) = error["details"].as_array() {
            for detail in details {
                if detail["@type"].as_str() != Some("type.googleapis.com/google.rpc.BadRequest") {
                    continue;
                }
                if let Some(violations) = detail["fieldViolations"].as_array() {
                    for violation in violations {
                        if let Some(field) = violation["field"]
                            .as_str()
                            .filter(|field| is_schema_field_path(field))
                        {
                            field_paths.push(field.to_owned());
                        }
                    }
                }
            }
        }
        field_paths.sort();
        field_paths.dedup();
        Self::Status {
            status,
            google_status,
            field_paths,
        }
    }
}

// Field paths contain identifiers and numeric list indices, not quoted map keys
// or prose. Reject other forms rather than echoing provider-controlled data.
fn is_schema_field_path(field: &str) -> bool {
    let mut bytes = field.bytes().peekable();
    loop {
        if !bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        {
            return false;
        }
        while bytes
            .peek()
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        {
            bytes.next();
        }
        while bytes.peek() == Some(&b'[') {
            bytes.next();
            if !bytes.next().is_some_and(|b| b.is_ascii_digit()) {
                return false;
            }
            while bytes.peek().is_some_and(u8::is_ascii_digit) {
                bytes.next();
            }
            if bytes.next() != Some(b']') {
                return false;
            }
        }
        match bytes.next() {
            None => return true,
            Some(b'.') => (),
            _ => return false,
        }
    }
}

fn project_from_load_response(body: &Value) -> Option<AntigravityProject> {
    let managed = project_id(body.get("cloudaicompanionProject")?)?;
    let project = body
        .get("projectId")
        .and_then(project_id)
        .or_else(|| body.get("project_id").and_then(project_id))
        .unwrap_or_else(|| managed.clone());
    Some(AntigravityProject {
        project_id: project,
        managed_project_id: managed,
    })
}

fn project_from_onboard_response(body: &Value) -> Option<AntigravityProject> {
    let companion = body
        .get("response")
        .and_then(|response| response.get("cloudaicompanionProject"))
        .or_else(|| body.get("cloudaicompanionProject"))?;
    let id = project_id(companion)?;
    Some(AntigravityProject {
        project_id: id.clone(),
        managed_project_id: id,
    })
}

fn project_id(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_string)
        .or_else(|| value.get("id").and_then(Value::as_str).map(str::to_string))
        .filter(|id| !id.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refresh_adapters::fixture::FixtureTransport;

    const ACCESS_TOKEN: &str = "ya29.access";

    fn expected_user_agent() -> String {
        let os = match std::env::consts::OS {
            "macos" => "darwin",
            other => other,
        };
        let arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "x86" => "386",
            "aarch64" => "arm64",
            other => other,
        };
        format!("antigravity/cli/1.3.5 (aidev_client; os_type={os}; arch={arch}; cl=998863838; auth_method=consumer)")
    }

    fn assert_discovery_headers(request: &crate::refresh_adapters::fixture::RecordedRequest) {
        assert_eq!(
            request.headers,
            vec![
                ("Authorization".into(), "Bearer ya29.access".into()),
                ("User-Agent".into(), expected_user_agent()),
            ]
        );
    }

    fn response(body: Value) -> Result<crate::refresh_adapters::HttpResponse, RefreshError> {
        Ok(crate::refresh_adapters::HttpResponse {
            status: 200,
            body: serde_json::to_vec(&body).unwrap(),
        })
    }

    fn onboard_done() -> Value {
        serde_json::json!({
            "done": true,
            "response": { "cloudaicompanionProject": { "id": "free-project" } }
        })
    }

    fn load_response(project: &str) -> Vec<u8> {
        serde_json::json!({ "cloudaicompanionProject": project })
            .to_string()
            .into_bytes()
    }

    #[tokio::test]
    async fn load_code_assist_request_and_project_extraction_are_exact() {
        let http = FixtureTransport::ok(200, load_response("managed-project"));
        let project = discover_antigravity_project_with_delay(&http, ACCESS_TOKEN, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(
            project,
            AntigravityProject {
                project_id: "managed-project".into(),
                managed_project_id: "managed-project".into(),
            }
        );
        let request = &http.requests()[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.url, LOAD_CODE_ASSIST_URL);
        assert_eq!(request.content_type, "application/json");
        assert_eq!(request.body, br#"{"metadata":{"ideType":"ANTIGRAVITY"}}"#);
        assert_discovery_headers(request);
    }

    #[tokio::test]
    async fn onboarding_request_shape_and_done_response_are_exact() {
        let operation = serde_json::json!({
            "done": true,
            "response": { "cloudaicompanionProject": { "id": "free-project" } }
        });
        let http = FixtureTransport::new(vec![
            Ok(crate::refresh_adapters::HttpResponse {
                status: 200,
                body: b"{}".to_vec(),
            }),
            Ok(crate::refresh_adapters::HttpResponse {
                status: 200,
                body: serde_json::to_vec(&operation).unwrap(),
            }),
        ]);
        let project = discover_antigravity_project_with_delay(&http, ACCESS_TOKEN, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(project.project_id, "free-project");
        assert_eq!(project.managed_project_id, "free-project");
        let requests = http.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].method, "POST");
        assert_eq!(requests[1].url, ONBOARD_USER_URL);
        assert_eq!(requests[1].content_type, "application/json");
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[1].body).unwrap(),
            serde_json::json!({"tierId":"free-tier","metadata":{"ideType":"ANTIGRAVITY"}})
        );
        assert_discovery_headers(&requests[0]);
        assert_discovery_headers(&requests[1]);
    }

    #[tokio::test]
    async fn discovery_user_agent_is_sent_on_both_calls() {
        let http = FixtureTransport::new(vec![
            response(serde_json::json!({})),
            response(onboard_done()),
        ]);
        discover_antigravity_project_with_delay(&http, ACCESS_TOKEN, Duration::ZERO)
            .await
            .unwrap();
        let requests = http.requests();
        assert_eq!(requests.len(), 2);
        for request in requests {
            assert_discovery_headers(&request);
        }
    }

    async fn assert_tier_choice(allowed_tiers: Value, expected: &str) {
        let http = FixtureTransport::new(vec![
            response(serde_json::json!({"allowedTiers": allowed_tiers})),
            response(onboard_done()),
        ]);
        let project = discover_antigravity_project_with_delay(&http, ACCESS_TOKEN, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(project.project_id, "free-project");
        let requests = http.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].url, ONBOARD_USER_URL);
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[1].body).unwrap(),
            serde_json::json!({"tierId": expected,"metadata":{"ideType":"ANTIGRAVITY"}})
        );
        assert_discovery_headers(&requests[1]);
    }

    #[tokio::test]
    async fn discovery_chooses_default_allowed_tier() {
        assert_tier_choice(
            serde_json::json!([
                {"id":"first-tier"}, {"id":"default-tier", "isDefault":true}
            ]),
            "default-tier",
        )
        .await;
    }

    #[tokio::test]
    async fn discovery_chooses_first_tier_without_default() {
        assert_tier_choice(
            serde_json::json!([
                {"id":"first-tier"}, {"id":"second-tier"}
            ]),
            "first-tier",
        )
        .await;
    }

    #[tokio::test]
    async fn discovery_chooses_free_tier_when_allowed_tiers_empty() {
        assert_tier_choice(serde_json::json!([]), "free-tier").await;
    }

    #[tokio::test]
    async fn discovery_refuses_user_defined_project_without_onboarding() {
        for tiers in [
            serde_json::json!([{"id":"standard-tier","userDefinedCloudaicompanionProject":true}]),
            serde_json::json!([
                {"id":"free-tier"},
                {"id":"standard-tier","isDefault":true,"userDefinedCloudaicompanionProject":true}
            ]),
        ] {
            let http = FixtureTransport::new(vec![
                response(serde_json::json!({"allowedTiers":tiers})),
                response(onboard_done()),
            ]);
            let error =
                discover_antigravity_project_with_delay(&http, ACCESS_TOKEN, Duration::ZERO)
                    .await
                    .expect_err("user-defined projects are unsupported");
            let text = error.to_string();
            assert!(text.contains("own Google Cloud project"), "{text}");
            assert!(text.contains("not support"), "{text}");
            assert_eq!(http.requests().len(), 1, "must not call onboardUser");
        }
    }

    #[tokio::test]
    async fn discovery_error_names_call_status_and_field_but_not_message() {
        for call in ["loadCodeAssist", "onboardUser"] {
            let mut responses = vec![];
            if call == "onboardUser" {
                responses.push(response(serde_json::json!({})));
            }
            responses.push(Ok(crate::refresh_adapters::HttpResponse {
                status: 400,
                body: serde_json::to_vec(&serde_json::json!({"error": {
                    "code":400, "status":"INVALID_ARGUMENT", "message":"private error message",
                    "details":[{
                        "@type":"type.googleapis.com/google.rpc.BadRequest",
                        "fieldViolations":[{"field":"metadata.plugin_type","description":"private violation description"}]
                    }]
                }})).unwrap(),
            }));
            let http = FixtureTransport::new(responses);
            let text = discover_antigravity_project_with_delay(&http, ACCESS_TOKEN, Duration::ZERO)
                .await
                .unwrap_err()
                .to_string();
            for expected in [call, "400", "INVALID_ARGUMENT", "metadata.plugin_type"] {
                assert!(text.contains(expected), "missing {expected}: {text}");
            }
            assert!(!text.contains("private"), "{text}");
        }
    }

    #[test]
    fn discovery_refresh_errors_keep_real_class_without_response_text() {
        for (error, expected) in [
            (
                RefreshError::InvalidGrant("private response".into()),
                "invalid_grant",
            ),
            (RefreshError::SubscriptionRequired, "subscription_required"),
        ] {
            let text = GoogleLoginError::from(error).to_string();
            assert!(text.contains(expected), "{text}");
            assert!(!text.contains("400"), "{text}");
            assert!(!text.contains("private"), "{text}");
        }
    }

    #[test]
    fn antigravity_user_agent_maps_rust_platforms_and_architectures() {
        for (os, expected_os) in [
            ("macos", "darwin"),
            ("linux", "linux"),
            ("windows", "windows"),
            ("freebsd", "freebsd"),
            ("", "unknown"),
        ] {
            for (arch, expected_arch) in [
                ("x86_64", "amd64"),
                ("x86", "386"),
                ("aarch64", "arm64"),
                ("arm", "arm"),
                ("", "unknown"),
            ] {
                assert_eq!(
                    antigravity_user_agent(os, arch),
                    format!("antigravity/cli/1.3.5 (aidev_client; os_type={expected_os}; arch={expected_arch}; cl=998863838; auth_method=consumer)")
                );
            }
        }
    }

    #[tokio::test]
    async fn discovery_errors_discard_unstructured_or_untrusted_response_text() {
        for (body, expected) in [
            (
                b"private non-JSON response".to_vec(),
                "Google Code Assist loadCodeAssist failed: status 400",
            ),
            (
                serde_json::to_vec(&serde_json::json!({"error":{
                "status":"PRIVATE_UNKNOWN_ENUM",
                "message":"private message",
                "details":[
                    {"@type":"private type", "fieldViolations":[{"field":"private_field"}]},
                    {"@type":"type.googleapis.com/google.rpc.BadRequest", "fieldViolations":[
                        {"field":"private prose"},
                        {"field":"metadata[\"private-key\"]"},
                        {"field":"metadata.plugin_type", "description":"private description"},
                        {"field":"metadata.plugin_type"},
                        {"field":"tiers[0].id"}
                    ]}
                ]
                }}))
                .unwrap(),
                "Google Code Assist loadCodeAssist failed: status 400; fields: metadata.plugin_type, tiers[0].id",
            ),
        ] {
            let http = FixtureTransport::ok(400, body);
            let error =
                discover_antigravity_project_with_delay(&http, ACCESS_TOKEN, Duration::ZERO)
                    .await
                    .unwrap_err();
            let text = error.to_string();
            assert_eq!(text, expected);
            assert!(!text.to_lowercase().contains("private"), "{text}");
            assert!(!format!("{error:?}").to_lowercase().contains("private"));
        }
    }

    #[tokio::test]
    async fn discovery_transport_and_decode_errors_name_call_without_raw_text() {
        for call in ["loadCodeAssist", "onboardUser"] {
            for (reply, kind) in [
                (
                    Err(RefreshError::Transport("private transport detail".into())),
                    "transport error",
                ),
                (
                    Err(RefreshError::Decode("private decode detail".into())),
                    "response decode error",
                ),
                (
                    Ok(HttpResponse {
                        status: 200,
                        body: b"private invalid JSON".to_vec(),
                    }),
                    "response decode error",
                ),
                (
                    Err(RefreshError::InvalidGrant("private grant detail".into())),
                    "authentication rejected (invalid_grant)",
                ),
                (
                    Err(RefreshError::SubscriptionRequired),
                    "subscription required (subscription_required)",
                ),
            ] {
                let mut replies = vec![];
                if call == "onboardUser" {
                    replies.push(response(serde_json::json!({})));
                }
                replies.push(reply);
                let http = FixtureTransport::new(replies);
                let text =
                    discover_antigravity_project_with_delay(&http, ACCESS_TOKEN, Duration::ZERO)
                        .await
                        .unwrap_err()
                        .to_string();
                assert_eq!(text, format!("Google Code Assist {call} failed: {kind}"));
            }
        }
    }

    #[tokio::test]
    async fn onboarding_polls_and_fails_closed_without_a_project() {
        let pending = br#"{"done":false,"name":"operations/1"}"#;
        let pending_responses: Vec<_> = (0..MAX_ONBOARD_ATTEMPTS)
            .map(|_| {
                Ok(crate::refresh_adapters::HttpResponse {
                    status: 200,
                    body: pending.to_vec(),
                })
            })
            .collect();
        let http = FixtureTransport::new({
            let mut responses = vec![Ok(crate::refresh_adapters::HttpResponse {
                status: 200,
                body: b"{}".to_vec(),
            })];
            responses.extend(pending_responses);
            responses
        });
        let err = discover_antigravity_project_with_delay(&http, ACCESS_TOKEN, Duration::ZERO)
            .await
            .unwrap_err();
        assert!(matches!(err, GoogleLoginError::NoProject));
        assert_eq!(http.requests().len(), MAX_ONBOARD_ATTEMPTS + 1);
    }

    /// The onboarding loop gets exactly `MAX_ONBOARD_ATTEMPTS` posts. A project that
    /// completes on the last allowed post is accepted; one that would complete only on
    /// the post after it is never asked for, so discovery fails closed with the
    /// finished operation still queued.
    #[tokio::test]
    async fn onboarding_accepts_the_last_allowed_attempt_and_never_makes_one_more() {
        fn ok(body: Vec<u8>) -> Result<crate::refresh_adapters::HttpResponse, RefreshError> {
            Ok(crate::refresh_adapters::HttpResponse { status: 200, body })
        }
        let pending = br#"{"done":false,"name":"operations/1"}"#.to_vec();
        let done = serde_json::to_vec(&serde_json::json!({
            "done": true,
            "response": { "cloudaicompanionProject": { "id": "late-project" } }
        }))
        .unwrap();
        // The load call answers with no project, then `pending_posts` unfinished
        // operations, then the finished one.
        let script = |pending_posts: usize| {
            let mut responses = vec![ok(b"{}".to_vec())];
            responses.extend((0..pending_posts).map(|_| ok(pending.clone())));
            responses.push(ok(done.clone()));
            FixtureTransport::new(responses)
        };

        let at_limit = script(MAX_ONBOARD_ATTEMPTS - 1);
        let project =
            discover_antigravity_project_with_delay(&at_limit, ACCESS_TOKEN, Duration::ZERO)
                .await
                .expect("the operation finishing on the last allowed post is accepted");
        assert_eq!(project.project_id, "late-project");
        assert_eq!(at_limit.requests().len(), 1 + MAX_ONBOARD_ATTEMPTS);

        let past_limit = script(MAX_ONBOARD_ATTEMPTS);
        let err =
            discover_antigravity_project_with_delay(&past_limit, ACCESS_TOKEN, Duration::ZERO)
                .await
                .unwrap_err();
        assert!(matches!(err, GoogleLoginError::NoProject), "{err:?}");
        assert_eq!(
            past_limit.requests().len(),
            1 + MAX_ONBOARD_ATTEMPTS,
            "no post is made after the last allowed attempt"
        );
    }

    #[tokio::test]
    async fn userinfo_captures_email_and_ignores_error_shapes() {
        let http = FixtureTransport::ok(200, br#"{"email":"user@example.com"}"#.to_vec());
        assert_eq!(
            google_userinfo_email(&http, ACCESS_TOKEN).await.as_deref(),
            Some("user@example.com")
        );
        let request = &http.requests()[0];
        assert_eq!(request.method, "GET");
        assert_eq!(request.url, USERINFO_URL);
        assert_eq!(request.content_type, "");
        assert!(request.body.is_empty());
        assert_eq!(
            request.headers,
            vec![("Authorization".into(), "Bearer ya29.access".into())]
        );

        let failed = FixtureTransport::ok(503, br#"{"error":"temporarily unavailable"}"#);
        assert_eq!(google_userinfo_email(&failed, ACCESS_TOKEN).await, None);
    }

    #[test]
    fn packed_refresh_contains_both_project_segments() {
        let project = AntigravityProject {
            project_id: "user-project".into(),
            managed_project_id: "managed-project".into(),
        };
        assert_eq!(
            pack_antigravity_refresh("1//refresh", &project),
            "1//refresh|user-project|managed-project"
        );
    }
}
