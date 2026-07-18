//! Google-family login wire helpers shared by the offline CLI.
//!
//! Gemini CLI and Antigravity use the same Google authorization-code endpoints but
//! different public installed-app clients and loopback redirects. This module keeps
//! those provider-specific constants together with the Code Assist project
//! provisioning needed before an Antigravity credential can be stored.

use std::time::Duration;

use serde_json::Value;

use crate::refresh_adapters::{HttpTransport, RefreshError};

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
/// Code Assist free-tier provisioning endpoint used by Antigravity.
pub const ONBOARD_USER_URL: &str = "https://cloudcode-pa.googleapis.com/v1internal:onboardUser";
const CODE_ASSIST_METADATA: &str =
    "{\"metadata\":{\"ideType\":\"IDE_UNSPECIFIED\",\"platform\":\"PLATFORM_UNSPECIFIED\",\"pluginType\":\"ANTIGRAVITY\"}}";
const ONBOARD_USER_BODY: &str =
    "{\"tierId\":\"free-tier\",\"metadata\":{\"ideType\":\"IDE_UNSPECIFIED\",\"platform\":\"PLATFORM_UNSPECIFIED\",\"pluginType\":\"ANTIGRAVITY\"},\"cloudaicompanionProject\":null}";
const MAX_ONBOARD_ATTEMPTS: usize = 5;
const ONBOARD_POLL_DELAY: Duration = Duration::from_secs(2);

/// Which public Google client and redirect belong to a login provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoogleLoginProvider {
    /// Google Code Assist as used by Gemini CLI.
    Gemini,
    /// Google Code Assist as used by Antigravity.
    Antigravity,
}

impl GoogleLoginProvider {
    /// Resolve the CLI provider flag.
    pub fn parse(provider: &str) -> Option<Self> {
        match provider {
            "google" => Some(Self::Gemini),
            "antigravity" => Some(Self::Antigravity),
            _ => None,
        }
    }

    /// Stable method-scoped default credential id.
    pub const fn default_id(self) -> &'static str {
        match self {
            Self::Gemini => "oauth:google",
            Self::Antigravity => "antigravity:google",
        }
    }

    /// The registered loopback redirect.
    pub const fn redirect_uri(self) -> &'static str {
        match self {
            Self::Gemini => GEMINI_REDIRECT_URI,
            Self::Antigravity => ANTIGRAVITY_REDIRECT_URI,
        }
    }

    /// The adapter name persisted on the vault record.
    pub const fn adapter_name(self) -> &'static str {
        match self {
            Self::Gemini => "google",
            Self::Antigravity => "antigravity",
        }
    }

    /// The public client id, including the operator override used by refresh.
    pub fn client_id(self) -> String {
        match self {
            Self::Gemini => crate::refresh_adapters::google::oauth_client_id(),
            Self::Antigravity => crate::refresh_adapters::antigravity::oauth_client_id(),
        }
    }

    /// The public client secret, including the operator override used by refresh.
    pub fn client_secret(self) -> String {
        match self {
            Self::Gemini => crate::refresh_adapters::google::oauth_client_secret(),
            Self::Antigravity => crate::refresh_adapters::antigravity::oauth_client_secret(),
        }
    }
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
    let load = http
        .post(
            LOAD_CODE_ASSIST_URL,
            &[("Authorization", authorization.as_str())],
            "application/json",
            CODE_ASSIST_METADATA.as_bytes().to_vec(),
        )
        .await
        .map_err(GoogleLoginError::from)?;
    if load.status != 200 {
        return Err(GoogleLoginError::Status(load.status));
    }
    let load_body: Value =
        serde_json::from_slice(&load.body).map_err(|e| GoogleLoginError::Decode(e.to_string()))?;
    if let Some(project) = project_from_load_response(&load_body) {
        return Ok(project);
    }

    for attempt in 0..MAX_ONBOARD_ATTEMPTS {
        if attempt > 0 && !poll_delay.is_zero() {
            tokio::time::sleep(poll_delay).await;
        }
        let onboard = http
            .post(
                ONBOARD_USER_URL,
                &[("Authorization", authorization.as_str())],
                "application/json",
                ONBOARD_USER_BODY.as_bytes().to_vec(),
            )
            .await
            .map_err(GoogleLoginError::from)?;
        if onboard.status != 200 {
            return Err(GoogleLoginError::Status(onboard.status));
        }
        let operation: Value = serde_json::from_slice(&onboard.body)
            .map_err(|e| GoogleLoginError::Decode(e.to_string()))?;
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

/// Errors from Code Assist discovery. Error text never includes response bodies,
/// which could contain provider-controlled sensitive data.
#[derive(Debug)]
pub enum GoogleLoginError {
    Transport(String),
    Status(u16),
    Decode(String),
    NoProject,
}

impl std::fmt::Display for GoogleLoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(message) => {
                write!(f, "Google Code Assist discovery transport error: {message}")
            }
            Self::Status(status) => write!(
                f,
                "Google Code Assist discovery failed with status {status}"
            ),
            Self::Decode(message) => write!(
                f,
                "Google Code Assist discovery response decode error: {message}"
            ),
            Self::NoProject => f.write_str(
                "Google Code Assist did not return a project id; Antigravity login cannot continue",
            ),
        }
    }
}

impl std::error::Error for GoogleLoginError {}

impl From<RefreshError> for GoogleLoginError {
    fn from(error: RefreshError) -> Self {
        match error {
            RefreshError::Transport(message) => Self::Transport(message),
            RefreshError::Decode(message) => Self::Decode(message),
            RefreshError::Status(status, _) => Self::Status(status),
            RefreshError::InvalidGrant(_) => Self::Status(400),
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
        assert_eq!(request.body, CODE_ASSIST_METADATA.as_bytes());
        assert_eq!(
            request.headers,
            vec![("Authorization".into(), "Bearer ya29.access".into())]
        );
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
        assert_eq!(requests[1].body, ONBOARD_USER_BODY.as_bytes());
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
