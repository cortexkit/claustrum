//! RFC 8628 device authorization flows shared by vault-native login providers.
//!
//! The engine owns the polling policy and response vocabulary. Provider drivers only
//! supply the endpoint, encoding, and headers, so a headless login cannot accidentally
//! drift from the same pending/slow-down/expiry behavior.

use std::future::Future;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::oauth_login::LoginError;
use crate::refresh_adapters::{form_urlencode, HttpResponse, HttpTransport, RefreshError};

/// The body encoding used by a device authorization provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceBodyEncoding {
    Json,
    Form,
}

/// Provider-specific inputs for an RFC 8628 device flow.
#[derive(Debug, Clone)]
pub struct DeviceFlowConfig {
    pub device_code_url: String,
    pub token_url: String,
    pub client_id: String,
    pub scope: Option<String>,
    pub grant_type: String,
    pub body_encoding: DeviceBodyEncoding,
    pub extra_headers: Vec<(String, String)>,
    /// The minimum interval between token polls. A provider-returned interval may
    /// increase this floor, but never shortens it.
    pub poll_floor: Duration,
}

impl DeviceFlowConfig {
    /// Construct a standard device-flow configuration with the RFC grant type.
    pub fn new(
        device_code_url: impl Into<String>,
        token_url: impl Into<String>,
        client_id: impl Into<String>,
        body_encoding: DeviceBodyEncoding,
    ) -> Self {
        Self {
            device_code_url: device_code_url.into(),
            token_url: token_url.into(),
            client_id: client_id.into(),
            scope: None,
            grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            body_encoding,
            extra_headers: Vec::new(),
            poll_floor: Duration::from_secs(5),
        }
    }
}

/// The user-facing part of a device authorization response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAuthorization {
    pub user_code: String,
    pub device_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: Option<u64>,
    pub interval: Option<u64>,
}

/// Tokens returned by a successful device token poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at_ms: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct DeviceAuthorizationResponse {
    user_code: String,
    device_code: String,
    #[serde(alias = "verification_url")]
    verification_uri: Option<String>,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    interval: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct DeviceTokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    interval: Option<u64>,
}

/// Poll-loop decisions shared by the standard and OpenAI's pinned device wires.
enum PollDecision {
    Pending {
        slow_down: bool,
        returned_interval: Option<u64>,
    },
    Success(DeviceTokens),
    Terminal(LoginError),
    Failure(Option<u16>),
}

/// Run a standard RFC 8628 device flow. The sink is called once after device
/// authorization succeeds, before the first poll, so a CLI can print instructions.
pub async fn run_device_flow<F>(
    http: &dyn HttpTransport,
    cfg: &DeviceFlowConfig,
    sink: F,
) -> Result<DeviceTokens, LoginError>
where
    F: Fn(&DeviceAuthorization) + Send + Sync,
{
    run_device_flow_with_sleeper(http, cfg, &sink, |duration| async move {
        tokio::time::sleep(duration).await;
    })
    .await
}

async fn run_device_flow_with_sleeper<S, Fut>(
    http: &dyn HttpTransport,
    cfg: &DeviceFlowConfig,
    sink: &dyn Fn(&DeviceAuthorization),
    mut sleep: S,
) -> Result<DeviceTokens, LoginError>
where
    S: FnMut(Duration) -> Fut,
    Fut: Future<Output = ()>,
{
    let headers = header_refs(&cfg.extra_headers);
    let (content_type, body) = encode_device_request(
        cfg.body_encoding,
        &cfg.client_id,
        cfg.scope.as_deref(),
        None,
        &cfg.grant_type,
    );
    let response = http
        .post(&cfg.device_code_url, &headers, content_type, body)
        .await
        .map_err(device_transport_error)?;
    if !(200..300).contains(&response.status) {
        return Err(LoginError::Status(
            response.status,
            "device authorization request was rejected".to_string(),
        ));
    }

    let auth: DeviceAuthorizationResponse =
        serde_json::from_slice(&response.body).map_err(|_| {
            LoginError::Decode("device authorization response was not valid JSON".into())
        })?;
    let auth = DeviceAuthorization {
        user_code: auth.user_code,
        device_code: auth.device_code,
        verification_uri: auth.verification_uri.unwrap_or_default(),
        verification_uri_complete: auth.verification_uri_complete,
        expires_in: auth.expires_in,
        interval: auth.interval,
    };
    sink(&auth);

    let initial_interval = auth.interval.unwrap_or(5);
    let mut interval = max_duration(Duration::from_secs(initial_interval), cfg.poll_floor);
    let deadline = Instant::now() + Duration::from_secs(auth.expires_in.unwrap_or(900).max(1));
    let poll_headers = header_refs(&cfg.extra_headers);
    let device_code = auth.device_code;
    let mut request = || async {
        let (_, body) = encode_device_request(
            cfg.body_encoding,
            &cfg.client_id,
            None,
            Some(&device_code),
            &cfg.grant_type,
        );
        http.post(
            &cfg.token_url,
            &poll_headers,
            content_type_for(cfg.body_encoding),
            body,
        )
        .await
    };

    run_poll_loop_typed(
        &mut request,
        &mut interval,
        deadline,
        &mut sleep,
        parse_token_response,
    )
    .await
}

/// The OpenAI account device wire uses `device_auth_id` and `user_code` instead of
/// RFC 8628's `device_code`. Keeping this small driver separate preserves the exact
/// pinned request shape while reusing the standard closed error vocabulary.
pub async fn run_openai_device_flow<F>(
    http: &dyn HttpTransport,
    client_id: &str,
    sink: F,
) -> Result<DeviceTokens, LoginError>
where
    F: Fn(&DeviceAuthorization) + Send + Sync,
{
    run_openai_device_flow_with_sleeper(http, client_id, &sink, |duration| async move {
        tokio::time::sleep(duration).await;
    })
    .await
}

async fn run_openai_device_flow_with_sleeper<S, Fut>(
    http: &dyn HttpTransport,
    client_id: &str,
    sink: &dyn Fn(&DeviceAuthorization),
    mut sleep: S,
) -> Result<DeviceTokens, LoginError>
where
    S: FnMut(Duration) -> Fut,
    Fut: Future<Output = ()>,
{
    let body = serde_json::to_vec(&serde_json::json!({ "client_id": client_id }))
        .expect("serializing a fixed-shape JSON body never fails");
    let response = http
        .post(
            "https://auth.openai.com/api/accounts/deviceauth/usercode",
            &[],
            "application/json",
            body,
        )
        .await
        .map_err(device_transport_error)?;
    if !(200..300).contains(&response.status) {
        return Err(LoginError::Status(
            response.status,
            "device authorization request was rejected".to_string(),
        ));
    }
    let auth: OpenAiDeviceAuthorizationResponse =
        serde_json::from_slice(&response.body).map_err(|_| {
            LoginError::Decode("device authorization response was not valid JSON".into())
        })?;
    let auth_for_sink = DeviceAuthorization {
        user_code: auth.user_code.clone(),
        device_code: auth.device_auth_id.clone(),
        verification_uri: "https://auth.openai.com/codex/device".into(),
        verification_uri_complete: None,
        expires_in: auth.expires_in,
        interval: auth.interval,
    };
    sink(&auth_for_sink);

    let mut interval = Duration::from_secs(auth.interval.unwrap_or(5));
    let deadline = Instant::now() + Duration::from_secs(auth.expires_in.unwrap_or(900).max(1));
    let device_auth_id = auth.device_auth_id;
    let user_code = auth.user_code;
    let mut request = || async {
        let body = serde_json::to_vec(&serde_json::json!({
            "device_auth_id": device_auth_id,
            "user_code": user_code,
        }))
        .expect("serializing a fixed-shape JSON body never fails");
        let poll = http
            .post(
                "https://auth.openai.com/api/accounts/deviceauth/token",
                &[],
                "application/json",
                body,
            )
            .await?;
        // Codex reports an unapproved device as 403/404 without requiring a JSON
        // error body. Normalize that pinned response to the shared pending error.
        if poll.status == 403 || poll.status == 404 {
            return Ok(HttpResponse {
                status: 400,
                body: br#"{"error":"authorization_pending"}"#.to_vec(),
            });
        }
        if !(200..300).contains(&poll.status) {
            return Ok(poll);
        }
        let parsed: OpenAiDevicePollResponse = match serde_json::from_slice(&poll.body) {
            Ok(parsed) => parsed,
            Err(_) => return Ok(poll),
        };
        if parsed.access_token.is_some() {
            return Ok(poll);
        }
        let Some(authorization_code) = parsed.authorization_code else {
            return Ok(poll);
        };
        let Some(code_verifier) = parsed.code_verifier else {
            return Ok(poll);
        };
        let fields = [
            ("grant_type", "authorization_code"),
            ("code", authorization_code.as_str()),
            (
                "redirect_uri",
                "https://auth.openai.com/deviceauth/callback",
            ),
            ("client_id", client_id),
            ("code_verifier", code_verifier.as_str()),
        ];
        let token_response = http
            .post(
                "https://auth.openai.com/oauth/token",
                &[],
                "application/x-www-form-urlencoded",
                form_urlencode(&fields).into_bytes(),
            )
            .await?;
        Ok(token_response)
    };
    run_poll_loop_typed(
        &mut request,
        &mut interval,
        deadline,
        &mut sleep,
        parse_token_response,
    )
    .await
}

#[derive(Debug, Deserialize)]
struct OpenAiDeviceAuthorizationResponse {
    #[serde(alias = "usercode")]
    user_code: String,
    device_auth_id: String,
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    expires_in: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    interval: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct OpenAiDevicePollResponse {
    #[serde(default)]
    authorization_code: Option<String>,
    #[serde(default)]
    code_verifier: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
}

fn deserialize_optional_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| serde::de::Error::custom("expected an unsigned integer"))
            .map(Some),
        serde_json::Value::String(string) => string
            .parse::<u64>()
            .map(Some)
            .map_err(|_| serde::de::Error::custom("expected an unsigned integer string")),
        _ => Err(serde::de::Error::custom("expected an unsigned integer")),
    }
}

async fn run_poll_loop_typed<S, SleepFut, R, RequestFut>(
    request: &mut R,
    interval: &mut Duration,
    deadline: Instant,
    sleep: &mut S,
    mut parse: impl FnMut(HttpResponse) -> PollDecision,
) -> Result<DeviceTokens, LoginError>
where
    R: FnMut() -> RequestFut,
    RequestFut: Future<Output = Result<HttpResponse, RefreshError>>,
    S: FnMut(Duration) -> SleepFut,
    SleepFut: Future<Output = ()>,
{
    let mut consecutive_failures = 0u8;
    loop {
        if Instant::now() >= deadline {
            return Err(LoginError::Device("device authorization expired".into()));
        }
        sleep(*interval).await;
        if Instant::now() >= deadline {
            return Err(LoginError::Device("device authorization expired".into()));
        }
        let response = match request().await {
            Ok(response) => response,
            Err(_error) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                if consecutive_failures >= 3 {
                    return Err(LoginError::Transport(
                        "device token polling failed three consecutive times".into(),
                    ));
                }
                continue;
            }
        };
        match parse(response) {
            PollDecision::Success(tokens) => return Ok(tokens),
            PollDecision::Pending {
                slow_down,
                returned_interval,
            } => {
                consecutive_failures = 0;
                if let Some(seconds) = returned_interval {
                    *interval = max_duration(*interval, Duration::from_secs(seconds));
                }
                if slow_down {
                    *interval = interval.saturating_add(Duration::from_secs(5));
                }
            }
            PollDecision::Terminal(error) => return Err(error),
            PollDecision::Failure(status) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                if consecutive_failures >= 3 {
                    return Err(match status {
                        Some(status) => LoginError::Status(
                            status,
                            "device token polling failed three consecutive times".into(),
                        ),
                        None => LoginError::Decode(
                            "device token polling returned three consecutive invalid responses"
                                .into(),
                        ),
                    });
                }
            }
        }
    }
}

fn parse_token_response(response: HttpResponse) -> PollDecision {
    let status = response.status;
    let parsed = match serde_json::from_slice::<DeviceTokenResponse>(&response.body) {
        Ok(parsed) => parsed,
        Err(_) => return PollDecision::Failure(Some(status)),
    };
    if let Some(error) = parsed.error.as_deref() {
        return match error {
            "authorization_pending" => PollDecision::Pending {
                slow_down: false,
                returned_interval: parsed.interval,
            },
            "slow_down" => PollDecision::Pending {
                slow_down: true,
                returned_interval: parsed.interval,
            },
            "expired_token" | "access_denied" => {
                PollDecision::Terminal(LoginError::Device(error.to_string()))
            }
            _ => PollDecision::Terminal(LoginError::Device(
                "device provider returned an unsupported error".into(),
            )),
        };
    }
    if !(200..300).contains(&status) {
        return PollDecision::Failure(Some(status));
    }
    let Some(access_token) = parsed.access_token else {
        return PollDecision::Failure(Some(status));
    };
    let expires_at_ms = parsed.expires_in.and_then(|seconds| {
        (seconds >= 0).then(|| now_ms().saturating_add(seconds.saturating_mul(1000)))
    });
    PollDecision::Success(DeviceTokens {
        access_token,
        refresh_token: parsed.refresh_token,
        expires_at_ms,
    })
}

fn encode_device_request(
    encoding: DeviceBodyEncoding,
    client_id: &str,
    scope: Option<&str>,
    device_code: Option<&str>,
    grant_type: &str,
) -> (&'static str, Vec<u8>) {
    match encoding {
        DeviceBodyEncoding::Json => {
            let mut body = serde_json::json!({
                "client_id": client_id,
            });
            if let Some(scope) = scope {
                body["scope"] = serde_json::Value::String(scope.to_string());
            }
            if let Some(device_code) = device_code {
                body["device_code"] = serde_json::Value::String(device_code.to_string());
                body["grant_type"] = serde_json::Value::String(grant_type.to_string());
            }
            (
                "application/json",
                serde_json::to_vec(&body).expect("serializing a fixed-shape JSON body never fails"),
            )
        }
        DeviceBodyEncoding::Form => {
            let mut pairs = vec![("client_id", client_id)];
            if let Some(scope) = scope {
                pairs.push(("scope", scope));
            }
            if let Some(device_code) = device_code {
                pairs.push(("device_code", device_code));
                pairs.push(("grant_type", grant_type));
            }
            (
                "application/x-www-form-urlencoded",
                form_urlencode(&pairs).into_bytes(),
            )
        }
    }
}

fn content_type_for(encoding: DeviceBodyEncoding) -> &'static str {
    match encoding {
        DeviceBodyEncoding::Json => "application/json",
        DeviceBodyEncoding::Form => "application/x-www-form-urlencoded",
    }
}

fn header_refs(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}

fn max_duration(left: Duration, right: Duration) -> Duration {
    if left >= right {
        left
    } else {
        right
    }
}

fn device_transport_error(error: RefreshError) -> LoginError {
    LoginError::Transport(match error {
        RefreshError::Transport(_) => "device flow transport failure".into(),
        _ => "device flow HTTP failure".into(),
    })
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refresh_adapters::fixture::FixtureTransport;
    use std::sync::{Arc, Mutex};

    fn config() -> DeviceFlowConfig {
        let mut config = DeviceFlowConfig::new(
            "https://issuer.test/device",
            "https://issuer.test/token",
            "client-123",
            DeviceBodyEncoding::Json,
        );
        config.scope = Some("read:user".into());
        config.extra_headers = vec![("Accept".into(), "application/json".into())];
        config.poll_floor = Duration::from_millis(1);
        config
    }

    #[tokio::test]
    async fn pending_then_slow_down_then_success_uses_exact_requests_and_grows_wait() {
        let http = FixtureTransport::new(vec![
            Ok(HttpResponse {
                status: 200,
                body: br#"{"user_code":"ABCD-EFGH","device_code":"device-1","verification_uri":"https://issuer.test/verify","expires_in":120,"interval":1}"#.to_vec(),
            }),
            Ok(HttpResponse {
                status: 400,
                body: br#"{"error":"authorization_pending"}"#.to_vec(),
            }),
            Ok(HttpResponse {
                status: 400,
                body: br#"{"error":"slow_down","interval":2}"#.to_vec(),
            }),
            Ok(HttpResponse {
                status: 200,
                body: br#"{"access_token":"access-1","token_type":"bearer","scope":"read:user"}"#.to_vec(),
            }),
        ]);
        let waits = Arc::new(Mutex::new(Vec::new()));
        let seen_waits = Arc::clone(&waits);
        let mut cfg = config();
        cfg.device_code_url = "https://github.com/login/device/code".into();
        cfg.token_url = "https://github.com/login/oauth/access_token".into();
        cfg.client_id = "Ov23li8tweQw6odWQebz".into();
        cfg.poll_floor = Duration::from_secs(1);
        let shown = Arc::new(Mutex::new(None));
        let shown_sink = Arc::clone(&shown);
        let sink = move |auth: &DeviceAuthorization| {
            *shown_sink.lock().unwrap() = Some(auth.clone());
        };
        let tokens = run_device_flow_with_sleeper(&http, &cfg, &sink, move |duration| {
            seen_waits.lock().unwrap().push(duration);
            async {}
        })
        .await
        .unwrap();

        assert_eq!(tokens.access_token, "access-1");
        assert_eq!(tokens.refresh_token, None);
        assert_eq!(
            shown.lock().unwrap().as_ref().unwrap().user_code,
            "ABCD-EFGH"
        );

        let requests = http.requests();
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[0].url, "https://github.com/login/device/code");
        assert_eq!(requests[0].content_type, "application/json");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&requests[0].body).unwrap(),
            serde_json::json!({"client_id":"Ov23li8tweQw6odWQebz","scope":"read:user"})
        );
        assert_eq!(
            requests[1].url,
            "https://github.com/login/oauth/access_token"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&requests[1].body).unwrap(),
            serde_json::json!({"client_id":"Ov23li8tweQw6odWQebz","device_code":"device-1","grant_type":"urn:ietf:params:oauth:grant-type:device_code"})
        );
        assert_eq!(
            requests[1].headers,
            vec![("Accept".into(), "application/json".into())]
        );
        assert_eq!(
            waits.lock().unwrap().as_slice(),
            &[
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(7)
            ]
        );
    }

    #[tokio::test]
    async fn provider_form_wire_uses_auth_scope_then_exact_poll_body() {
        let http = FixtureTransport::new(vec![
            Ok(HttpResponse {
                status: 200,
                body: br#"{"user_code":"KIMI-CODE","device_code":"kimi-device","verification_uri":"https://auth.kimi.com/verify","expires_in":60,"interval":0}"#.to_vec(),
            }),
            Ok(HttpResponse {
                status: 200,
                body: br#"{"access_token":"kimi-access","refresh_token":"kimi-refresh","expires_in":3600}"#.to_vec(),
            }),
        ]);
        let mut cfg = DeviceFlowConfig::new(
            "https://auth.kimi.com/api/oauth/device_authorization",
            "https://auth.kimi.com/api/oauth/token",
            "17e5f671-d194-4dfb-9706-5516cb48c098",
            DeviceBodyEncoding::Form,
        );
        cfg.extra_headers = vec![
            ("Accept".into(), "application/json".into()),
            ("User-Agent".into(), "cortexkit-credentials/0.1.0".into()),
            ("X-Msh-Platform".into(), "kimi_cli".into()),
            (
                "X-Msh-Device-Id".into(),
                "0123456789abcdef0123456789abcdef".into(),
            ),
        ];
        let waits = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&waits);
        run_device_flow_with_sleeper(&http, &cfg, &|_| {}, move |duration| {
            seen.lock().unwrap().push(duration);
            async {}
        })
        .await
        .unwrap();
        let requests = http.requests();
        assert_eq!(
            String::from_utf8(requests[0].body.clone()).unwrap(),
            "client_id=17e5f671-d194-4dfb-9706-5516cb48c098"
        );
        assert_eq!(
            String::from_utf8(requests[1].body.clone()).unwrap(),
            "client_id=17e5f671-d194-4dfb-9706-5516cb48c098&device_code=kimi-device&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
        );
        assert_eq!(requests[0].headers, requests[1].headers);
        assert_eq!(waits.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn xai_form_wire_uses_device_scope_and_grant() {
        let http = FixtureTransport::new(vec![
            Ok(HttpResponse {
                status: 200,
                body: br#"{"user_code":"XAI-CODE","device_code":"xai-device","verification_uri":"https://auth.x.ai/verify","expires_in":60,"interval":0}"#.to_vec(),
            }),
            Ok(HttpResponse {
                status: 200,
                body: br#"{"access_token":"xai-access","refresh_token":"xai-refresh","expires_in":3600}"#.to_vec(),
            }),
        ]);
        let mut cfg = DeviceFlowConfig::new(
            "https://auth.x.ai/oauth2/device/code",
            "https://auth.x.ai/oauth2/token",
            "b1a00492-073a-47ea-816f-4c329264a828",
            DeviceBodyEncoding::Form,
        );
        cfg.scope = Some("openid profile email offline_access grok-cli:access api:access".into());
        cfg.extra_headers = vec![("Accept".into(), "application/json".into())];
        cfg.poll_floor = Duration::ZERO;
        run_device_flow_with_sleeper(&http, &cfg, &|_| {}, |_| async {})
            .await
            .unwrap();
        let requests = http.requests();
        assert_eq!(
            String::from_utf8(requests[0].body.clone()).unwrap(),
            "client_id=b1a00492-073a-47ea-816f-4c329264a828&scope=openid+profile+email+offline_access+grok-cli%3Aaccess+api%3Aaccess"
        );
        assert_eq!(
            String::from_utf8(requests[1].body.clone()).unwrap(),
            "client_id=b1a00492-073a-47ea-816f-4c329264a828&device_code=xai-device&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
        );
        assert_eq!(requests[0].headers, requests[1].headers);
    }

    #[tokio::test]
    async fn openai_pinned_wire_polls_then_exchanges_authorization_code() {
        let http = FixtureTransport::new(vec![
            Ok(HttpResponse {
                status: 200,
                body: br#"{"device_auth_id":"auth-id","user_code":"ABCD-1234","interval":"0"}"#.to_vec(),
            }),
            Ok(HttpResponse {
                status: 200,
                body: br#"{"authorization_code":"authorization-code","code_challenge":"challenge","code_verifier":"verifier"}"#.to_vec(),
            }),
            Ok(HttpResponse {
                status: 200,
                body: br#"{"access_token":"openai-access","refresh_token":"openai-refresh"}"#.to_vec(),
            }),
        ]);
        let tokens = run_openai_device_flow_with_sleeper(
            &http,
            "app_EMoamEEZ73f0CkXaXp7hrann",
            &|_| {},
            |_| async {},
        )
        .await
        .unwrap();
        assert_eq!(tokens.access_token, "openai-access");
        assert_eq!(tokens.refresh_token.as_deref(), Some("openai-refresh"));
        let requests = http.requests();
        assert_eq!(
            requests[0].url,
            "https://auth.openai.com/api/accounts/deviceauth/usercode"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&requests[0].body).unwrap(),
            serde_json::json!({"client_id":"app_EMoamEEZ73f0CkXaXp7hrann"})
        );
        assert_eq!(
            requests[1].url,
            "https://auth.openai.com/api/accounts/deviceauth/token"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&requests[1].body).unwrap(),
            serde_json::json!({"device_auth_id":"auth-id","user_code":"ABCD-1234"})
        );
        assert_eq!(requests[2].url, "https://auth.openai.com/oauth/token");
        assert_eq!(
            requests[2].content_type,
            "application/x-www-form-urlencoded"
        );
        assert_eq!(
            String::from_utf8(requests[2].body.clone()).unwrap(),
            "grant_type=authorization_code&code=authorization-code&redirect_uri=https%3A%2F%2Fauth.openai.com%2Fdeviceauth%2Fcallback&client_id=app_EMoamEEZ73f0CkXaXp7hrann&code_verifier=verifier"
        );
    }

    #[tokio::test]
    async fn three_invalid_poll_responses_are_terminal() {
        let http = FixtureTransport::new(vec![
            Ok(HttpResponse {
                status: 200,
                body: br#"{"user_code":"CODE","device_code":"DEVICE","verification_uri":"https://issuer.test/verify","expires_in":120}"#.to_vec(),
            }),
            Ok(HttpResponse { status: 500, body: b"no-json".to_vec() }),
            Ok(HttpResponse { status: 500, body: b"no-json".to_vec() }),
            Ok(HttpResponse { status: 500, body: b"no-json".to_vec() }),
        ]);
        let mut cfg = config();
        cfg.poll_floor = Duration::ZERO;
        let err = run_device_flow_with_sleeper(&http, &cfg, &|_| {}, |_| async {})
            .await
            .unwrap_err();
        assert!(matches!(err, LoginError::Status(500, _)));
    }
}
