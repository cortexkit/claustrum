pub use credentials_core::catalog::{
    ApiKeyProvider, AuthHeaderScheme, KeyValidation, API_KEY_PROVIDERS,
};
use credentials_core::refresh_adapters::HttpTransport;

/// Check the account id given for `row` (from `--account-id` or the login prompt).
///
/// A row without an `account_id_prompt` takes none: an account id stored on such a
/// record would be served to consumers as the account's identity although nothing ever
/// asked for or checked it. A row with one requires it in the row's format.
///
/// The refusal never repeats the value: an operator who pastes the token into the
/// account-id field by mistake would otherwise see the secret echoed back.
pub fn check_account_id(row: &ApiKeyProvider, account_id: Option<&str>) -> Result<(), String> {
    match (row.account_id_prompt, account_id) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(format!(
            "--account-id does not apply to {}: only providers whose login asks for an \
             account id take one",
            row.display_name
        )),
        (Some(_), None) => Err(format!("{} needs an account id", row.display_name)),
        (Some(prompt), Some(value)) if prompt.format.accepts(value) => Ok(()),
        (Some(prompt), Some(value)) => Err(format!(
            "the {} account id given ({} characters) is not valid: expected {}",
            row.display_name,
            value.chars().count(),
            prompt.format.describe()
        )),
    }
}

/// The whole login-time check for `row`: the account id first, then the key probe.
///
/// The account-id check runs before the probe so that a malformed account id is
/// refused locally and no request carrying the token is ever sent to a URL built
/// from it.
pub async fn check_login_key(
    transport: &dyn HttpTransport,
    row: &ApiKeyProvider,
    key: &str,
    account_id: Option<&str>,
) -> Result<ValidationOutcome, String> {
    check_account_id(row, account_id)?;
    Ok(validate_key(transport, &row.validation, key, account_id).await)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationOutcome {
    Valid,
    Invalid(String),
    Warning(String),
    /// No probe was run, by design, for the reason given. Distinct from `Valid` so login
    /// never claims a key was checked when it was not.
    Unchecked(&'static str),
}

/// The message Amazon Q returns, with a 403, for a bearer it does not accept. Observed on
/// 2026-10-06 for both a `ksk_`-prefixed and a malformed synthetic key.
const AWS_INVALID_BEARER_MESSAGE: &str = "The bearer token included in the request is invalid.";

/// Check a key with the row's probe. `account_id` is the non-secret account the key
/// acts on, for rows with an `account_id_prompt`; every other row passes `None`.
pub async fn validate_key(
    transport: &dyn HttpTransport,
    validation: &KeyValidation,
    key: &str,
    account_id: Option<&str>,
) -> ValidationOutcome {
    // Before the test bypass below, so that a key with no probe is never reported as
    // "valid" even in a test build: that would be a claim about a check that cannot run.
    if let KeyValidation::Unvalidated { reason } = validation {
        return ValidationOutcome::Unchecked(reason);
    }
    // Test-only escape hatch, compiled OUT of release builds.
    //
    // The CLI integration test drives a real `login --provider zai` end to end and has
    // no provider to talk to, so it needs validation to return without a network call.
    // But an env var that turns a REFUSAL into a stored credential must not exist in an
    // operator's binary: on the shipped path an Invalid result is the only outcome that
    // stops a bad key being stored, and this would skip it while printing "API key is
    // valid." -- a validation claim for a check that never ran.
    //
    // Gated on debug_assertions rather than a cargo feature deliberately. The property
    // wanted is exactly "absent from the release binary", and release builds are the
    // thing shipped and signed; a feature gate would instead have to be remembered at
    // every build site, and forgetting it is silent. Verified by asserting the env-var
    // string is absent from `cargo build --release` output.
    #[cfg(debug_assertions)]
    if std::env::var("CORTEXKIT_TEST_BYPASS_VALIDATION").is_ok() {
        return ValidationOutcome::Valid;
    }
    // Only a successful probe verifies the key. Other non-auth statuses might
    // describe a missing endpoint or a proxy failure rather than key acceptance.
    match validation {
        KeyValidation::OpenAiChat { base_url, model } => {
            let url = format!("{}/chat/completions", base_url);
            let auth_header = format!("Bearer {}", key);
            let headers = [("Authorization", auth_header.as_str())];
            let body = serde_json::json!({
                "model": model,
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 1
            });
            let body_bytes = serde_json::to_vec(&body).unwrap();
            match transport
                .post(&url, &headers, "application/json", body_bytes)
                .await
            {
                Ok(resp) => {
                    if resp.status == 401 || resp.status == 403 {
                        ValidationOutcome::Invalid(format!("unauthorized (status {})", resp.status))
                    } else if (200..=299).contains(&resp.status) {
                        ValidationOutcome::Valid
                    } else {
                        ValidationOutcome::Warning(format!("unexpected status {}", resp.status))
                    }
                }
                Err(e) => ValidationOutcome::Warning(format!("transport error: {}", e)),
            }
        }
        KeyValidation::AnthropicMessages { base_url, model } => {
            let url = format!("{}/v1/messages", base_url);
            let headers = [("x-api-key", key), ("anthropic-version", "2023-06-01")];
            let body = serde_json::json!({
                "model": model,
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 1
            });
            let body_bytes = serde_json::to_vec(&body).unwrap();
            match transport
                .post(&url, &headers, "application/json", body_bytes)
                .await
            {
                Ok(resp) => {
                    if resp.status == 401 || resp.status == 403 {
                        ValidationOutcome::Invalid(format!("unauthorized (status {})", resp.status))
                    } else if (200..=299).contains(&resp.status) {
                        ValidationOutcome::Valid
                    } else {
                        ValidationOutcome::Warning(format!("unexpected status {}", resp.status))
                    }
                }
                Err(e) => ValidationOutcome::Warning(format!("transport error: {}", e)),
            }
        }
        KeyValidation::AwsApiKeyGet { url } => {
            // Request from decolua/9router src/lib/oauth/services/kiro.js,
            // listAvailableApiKeyModels at a99cf57239ff778b61e434c2786009d5ed1c412c.
            // TokenType makes Amazon Q authenticate the bearer as an API key.
            // Curl with invalid keys returned 403 here but 200 with empty profiles
            // on bearer-only profile listing; the catalog records those observations.
            let auth = format!("Bearer {}", key);
            let headers = [
                ("Authorization", auth.as_str()),
                ("TokenType", "API_KEY"),
                ("Accept", "application/json"),
            ];
            match transport.get(url, &headers).await {
                Ok(resp) if (200..=299).contains(&resp.status) => ValidationOutcome::Valid,
                // Only the refusal actually observed for a bad key counts as Invalid. AWS
                // also answers 403 AccessDenied for reasons that say nothing about the key
                // (no subscription, a policy denial), and refusing a good key blocks the
                // login outright; those 403s fall through to Warning and the key is kept.
                Ok(resp)
                    if resp.status == 403
                        && String::from_utf8_lossy(&resp.body)
                            .contains(AWS_INVALID_BEARER_MESSAGE) =>
                {
                    ValidationOutcome::Invalid("unauthorized (status 403)".to_string())
                }
                Ok(resp) => {
                    ValidationOutcome::Warning(format!("unexpected status {}", resp.status))
                }
                Err(e) => ValidationOutcome::Warning(format!("transport error: {}", e)),
            }
        }
        KeyValidation::FirecrawlCreditUsage { url } => {
            let auth = format!("Bearer {}", key);
            let headers = [("Authorization", auth.as_str())];
            match transport.get(url, &headers).await {
                Ok(resp) if (200..=299).contains(&resp.status) => ValidationOutcome::Valid,
                Ok(resp)
                    if resp.status == 401
                        && serde_json::from_slice::<serde_json::Value>(&resp.body)
                            .ok()
                            .and_then(|body| {
                                body.get("error")
                                    .and_then(serde_json::Value::as_str)
                                    .map(str::to_owned)
                            })
                            .as_deref()
                            == Some("Unauthorized: Invalid token") =>
                {
                    ValidationOutcome::Invalid("unauthorized (status 401)".to_string())
                }
                Ok(resp) => {
                    ValidationOutcome::Warning(format!("unexpected status {}", resp.status))
                }
                Err(e) => ValidationOutcome::Warning(format!("transport error: {}", e)),
            }
        }
        KeyValidation::TinyFishWallet { url } => {
            let headers = [("X-API-Key", key)];
            match transport.get(url, &headers).await {
                Ok(resp) if (200..=299).contains(&resp.status) => ValidationOutcome::Valid,
                Ok(resp)
                    if resp.status == 401
                        && serde_json::from_slice::<serde_json::Value>(&resp.body)
                            .ok()
                            .and_then(|body| {
                                body.get("error")
                                    .and_then(|error| error.get("code"))
                                    .and_then(serde_json::Value::as_str)
                                    .map(str::to_owned)
                            })
                            .as_deref()
                            == Some("INVALID_API_KEY") =>
                {
                    ValidationOutcome::Invalid("unauthorized (status 401)".to_string())
                }
                Ok(resp) => {
                    ValidationOutcome::Warning(format!("unexpected status {}", resp.status))
                }
                Err(e) => ValidationOutcome::Warning(format!("transport error: {}", e)),
            }
        }
        KeyValidation::GetEndpoint { url, auth_header } => {
            let headers = match auth_header {
                AuthHeaderScheme::Bearer => vec![("Authorization", format!("Bearer {}", key))],
                AuthHeaderScheme::XGoogApiKey => vec![("x-goog-api-key", key.to_string())],
                AuthHeaderScheme::BraveSubscriptionToken => {
                    vec![("X-Subscription-Token", key.to_string())]
                }
                AuthHeaderScheme::AnthropicApiKey => vec![
                    ("x-api-key", key.to_string()),
                    ("anthropic-version", "2023-06-01".to_string()),
                ],
            };
            let headers_ref: Vec<(&str, &str)> =
                headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
            match transport.get(url, &headers_ref).await {
                Ok(resp) => {
                    if resp.status == 401 || resp.status == 403 {
                        ValidationOutcome::Invalid(format!("unauthorized (status {})", resp.status))
                    } else if (200..=299).contains(&resp.status) {
                        ValidationOutcome::Valid
                    } else {
                        ValidationOutcome::Warning(format!("unexpected status {}", resp.status))
                    }
                }
                Err(e) => ValidationOutcome::Warning(format!("transport error: {}", e)),
            }
        }
        KeyValidation::CloudflareWorkersAiModels { api_base } => {
            let Some(account_id) = account_id else {
                // The account is part of the URL, so there is nothing to probe without
                // it. Login always supplies one for this row; refusing here keeps a
                // future caller that forgets from storing an unchecked token silently.
                return ValidationOutcome::Invalid(
                    "no Cloudflare account id was given to check the token against".to_string(),
                );
            };
            let url = format!("{api_base}/accounts/{account_id}/ai/models/search?per_page=1");
            let auth = format!("Bearer {key}");
            let headers = [("Authorization", auth.as_str())];
            match transport.get(&url, &headers).await {
                Ok(resp) => classify_cloudflare_workers_ai(resp.status, &resp.body, account_id),
                Err(e) => ValidationOutcome::Warning(format!("transport error: {}", e)),
            }
        }
        KeyValidation::Unvalidated { reason } => ValidationOutcome::Unchecked(reason),
    }
}

/// Cloudflare's error code for a credential header it could not parse at all.
const CLOUDFLARE_MALFORMED_AUTH_CODE: i64 = 9106;

/// Classify Cloudflare's answer to the Workers AI model search.
///
/// Observed on 2026-10-21 by sending the probe with fake credentials (no real token
/// involved) to `/client/v4/accounts/0123456789abcdef0123456789abcdef/ai/models/search?per_page=1`:
/// - a well-formed but unknown Bearer token -> 401,
///   `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],...}`;
/// - a Bearer value Cloudflare cannot parse (contains a space or non-ASCII) -> 400,
///   `{"errors":[{"code":9106,"message":"Authentication failed (status: 400)"}],...}`.
///
/// Both mean the token itself is bad, so the login refuses it. A 403 is what Cloudflare
/// returns for a token it authenticated but that may not act here: the token lacks the
/// Workers AI permission, or the account id is not one the token is scoped to. Wrangler
/// treats Workers AI 403s (codes 10000 and 1031) as missing permissions. That case was
/// not reproduced live, since it needs a real token. It also refuses, because storing
/// such a token would only fail on first use. Anything else (5xx, rate limiting, an
/// unexpected 4xx) says nothing certain about the token and only warns, as other rows do.
///
/// Messages carry Cloudflare's numeric error codes, never the token.
fn classify_cloudflare_workers_ai(status: u16, body: &[u8], account_id: &str) -> ValidationOutcome {
    let codes: Vec<i64> = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|body| {
            body.get("errors")?.as_array().map(|errors| {
                errors
                    .iter()
                    .filter_map(|e| e.get("code")?.as_i64())
                    .collect()
            })
        })
        .unwrap_or_default();
    let code_note = if codes.is_empty() {
        String::new()
    } else {
        let joined: Vec<String> = codes.iter().map(i64::to_string).collect();
        format!(", Cloudflare error code {}", joined.join(", "))
    };
    match status {
        200..=299 => ValidationOutcome::Valid,
        401 => ValidationOutcome::Invalid(format!(
            "Cloudflare rejected the API token (status 401{code_note}); check that it was \
             copied whole and has not been revoked"
        )),
        400 if codes.contains(&CLOUDFLARE_MALFORMED_AUTH_CODE) => {
            ValidationOutcome::Invalid(format!(
                "Cloudflare could not read the API token (status 400{code_note}); it is \
                 malformed"
            ))
        }
        403 => ValidationOutcome::Invalid(format!(
            "Cloudflare accepted the API token but refused Workers AI access on account \
             {account_id} (status 403{code_note}); the token most likely lacks the Workers AI \
             Read and Edit permissions, or the account id is not an account the token is \
             scoped to"
        )),
        _ => ValidationOutcome::Warning(format!("unexpected status {status}{code_note}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use credentials_core::credential_id::parse_credential_id;
    use credentials_core::refresh_adapters::HttpResponse;
    use credentials_core::refresh_adapters::RefreshError;

    #[derive(Debug, Clone)]
    pub struct RecordedRequest {
        pub url: String,
        pub headers: Vec<(String, String)>,
        pub content_type: String,
        pub body: Vec<u8>,
    }

    pub struct FixtureTransport {
        responses: std::sync::Mutex<std::collections::VecDeque<Result<HttpResponse, RefreshError>>>,
        requests: std::sync::Mutex<Vec<RecordedRequest>>,
    }

    impl FixtureTransport {
        pub fn new(responses: Vec<Result<HttpResponse, RefreshError>>) -> Self {
            Self {
                responses: std::sync::Mutex::new(responses.into_iter().collect()),
                requests: std::sync::Mutex::new(Vec::new()),
            }
        }

        pub fn ok(status: u16, body: impl Into<Vec<u8>>) -> Self {
            Self::new(vec![Ok(HttpResponse {
                status,
                body: body.into(),
            })])
        }

        pub fn requests(&self) -> Vec<RecordedRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl HttpTransport for FixtureTransport {
        async fn post(
            &self,
            url: &str,
            headers: &[(&str, &str)],
            content_type: &str,
            body: Vec<u8>,
        ) -> Result<HttpResponse, RefreshError> {
            self.requests.lock().unwrap().push(RecordedRequest {
                url: url.to_string(),
                headers: headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                content_type: content_type.to_string(),
                body,
            });
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("no response queued")
        }

        async fn get(
            &self,
            url: &str,
            headers: &[(&str, &str)],
        ) -> Result<HttpResponse, RefreshError> {
            self.requests.lock().unwrap().push(RecordedRequest {
                url: url.to_string(),
                headers: headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                content_type: "".to_string(),
                body: Vec::new(),
            });
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("no response queued")
        }
    }

    #[test]
    fn test_table_sanity() {
        for provider in API_KEY_PROVIDERS {
            let parsed = parse_credential_id(provider.default_id);
            assert_eq!(
                parsed.method,
                Some(credentials_core::credential_id::AuthMethod::ApiKey),
                "provider {} default_id {} must parse to apikey method",
                provider.key,
                provider.default_id
            );
            assert!(
                !provider.dashboard_url.is_empty(),
                "dashboard_url must not be empty"
            );
            assert!(
                !provider.placeholder.is_empty(),
                "placeholder must not be empty"
            );
        }
    }

    #[tokio::test]
    async fn firecrawl_credit_usage_classifies_only_the_documented_invalid_token() {
        let provider = API_KEY_PROVIDERS
            .iter()
            .find(|provider| provider.key == "firecrawl")
            .unwrap();
        let transport =
            FixtureTransport::ok(200, r#"{"success":true,"data":{"remainingCredits":1}}"#);
        assert_eq!(
            validate_key(&transport, &provider.validation, "fc_fixture", None).await,
            ValidationOutcome::Valid
        );
        assert_eq!(
            transport.requests()[0].url,
            "https://api.firecrawl.dev/v2/team/credit-usage"
        );
        assert_eq!(
            transport.requests()[0].headers,
            vec![("Authorization".to_string(), "Bearer fc_fixture".to_string())]
        );

        for (status, body, expected) in [
            (
                401,
                r#"{"success":false,"error":"Unauthorized: Invalid token"}"#,
                ValidationOutcome::Invalid("unauthorized (status 401)".to_string()),
            ),
            (
                401,
                r#"{"success":false,"error":"Unauthorized"}"#,
                ValidationOutcome::Warning("unexpected status 401".to_string()),
            ),
            (
                403,
                r#"{"success":false,"error":"Unauthorized: Invalid token"}"#,
                ValidationOutcome::Warning("unexpected status 403".to_string()),
            ),
        ] {
            let transport = FixtureTransport::ok(status, body);
            assert_eq!(
                validate_key(&transport, &provider.validation, "fc_fixture", None).await,
                expected
            );
        }
    }

    #[tokio::test]
    async fn tinyfish_wallet_classifies_only_the_documented_invalid_api_key() {
        let provider = API_KEY_PROVIDERS
            .iter()
            .find(|provider| provider.key == "tinyfish")
            .unwrap();
        let transport = FixtureTransport::ok(200, r#"{"balance":0}"#);
        assert_eq!(
            validate_key(&transport, &provider.validation, "tf_fixture", None).await,
            ValidationOutcome::Valid
        );
        assert_eq!(
            transport.requests()[0].url,
            "https://api.tinyfish.ai/v1/wallet"
        );
        assert_eq!(
            transport.requests()[0].headers,
            vec![("X-API-Key".to_string(), "tf_fixture".to_string())]
        );

        for (status, body, expected) in [
            (
                401,
                r#"{"error":{"code":"INVALID_API_KEY","message":"Invalid or expired API key"}}"#,
                ValidationOutcome::Invalid("unauthorized (status 401)".to_string()),
            ),
            (
                401,
                r#"{"error":{"code":"MISSING_API_KEY","message":"Missing API key"}}"#,
                ValidationOutcome::Warning("unexpected status 401".to_string()),
            ),
            (
                403,
                r#"{"error":{"code":"INVALID_API_KEY"}}"#,
                ValidationOutcome::Warning("unexpected status 403".to_string()),
            ),
        ] {
            let transport = FixtureTransport::ok(status, body);
            assert_eq!(
                validate_key(&transport, &provider.validation, "tf_fixture", None).await,
                expected
            );
        }
    }

    #[tokio::test]
    async fn aws_api_key_get_pins_request_shape() {
        let provider = API_KEY_PROVIDERS.iter().find(|p| p.key == "kiro").unwrap();
        let transport = FixtureTransport::ok(200, r#"{"models":[{"modelId":"test"}]}"#);
        assert_eq!(
            validate_key(&transport, &provider.validation, "ksk_test_fixture", None).await,
            ValidationOutcome::Valid
        );
        let reqs = transport.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(
            reqs[0].url,
            "https://q.us-east-1.amazonaws.com/ListAvailableModels?origin=AI_EDITOR"
        );
        assert_eq!(
            reqs[0].headers,
            vec![
                (
                    "Authorization".to_string(),
                    "Bearer ksk_test_fixture".to_string()
                ),
                ("TokenType".to_string(), "API_KEY".to_string()),
                ("Accept".to_string(), "application/json".to_string()),
            ]
        );
        assert!(reqs[0].body.is_empty());
        assert!(reqs[0].content_type.is_empty());
    }

    #[tokio::test]
    async fn aws_api_key_get_classifies_observed_auth_refusal() {
        let validation = KeyValidation::AwsApiKeyGet {
            url: "https://q.us-east-1.amazonaws.com/ListAvailableModels?origin=AI_EDITOR",
        };
        for status in [200, 299, 400, 401, 403, 429, 500] {
            let transport = FixtureTransport::ok(
                status,
                r#"{"message":"The bearer token included in the request is invalid.","reason":null}"#,
            );
            let outcome = validate_key(&transport, &validation, "ksk_test_fixture", None).await;
            match status {
                200 | 299 => assert_eq!(outcome, ValidationOutcome::Valid),
                403 => assert!(matches!(outcome, ValidationOutcome::Invalid(_))),
                _ => assert!(
                    matches!(outcome, ValidationOutcome::Warning(_)),
                    "status {status}"
                ),
            }
        }
        let transport = FixtureTransport::new(vec![Err(RefreshError::Transport(
            "network down".to_string(),
        ))]);
        assert!(matches!(
            validate_key(&transport, &validation, "ksk_test_fixture", None).await,
            ValidationOutcome::Warning(_)
        ));
        // A 403 that is not the invalid-bearer refusal says nothing about the key, so
        // it must not refuse the login.
        let transport = FixtureTransport::ok(
            403,
            r#"{"message":"User is not authorized to access this resource","reason":null}"#,
        );
        assert!(matches!(
            validate_key(&transport, &validation, "ksk_test_fixture", None).await,
            ValidationOutcome::Warning(_)
        ));
    }

    #[tokio::test]
    async fn test_validation_openai_chat() {
        let validation = KeyValidation::OpenAiChat {
            base_url: "https://api.openai.com/v1",
            model: "gpt-4",
        };

        // 1. Valid response (200)
        let transport = FixtureTransport::ok(200, "{}");
        let outcome = validate_key(&transport, &validation, "test-key", None).await;
        assert_eq!(outcome, ValidationOutcome::Valid);
        let reqs = transport.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].url, "https://api.openai.com/v1/chat/completions");
        assert_eq!(reqs[0].content_type, "application/json");
        assert_eq!(
            reqs[0].headers,
            vec![("Authorization".to_string(), "Bearer test-key".to_string())]
        );
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["model"], "gpt-4");
        assert_eq!(body["max_tokens"], 1);

        // A body error does not prove that authentication was checked.
        let transport = FixtureTransport::ok(400, "{}");
        let outcome = validate_key(&transport, &validation, "test-key", None).await;
        assert!(matches!(outcome, ValidationOutcome::Warning(_)));

        // 3. Invalid response (401)
        let transport = FixtureTransport::ok(401, "{}");
        let outcome = validate_key(&transport, &validation, "test-key", None).await;
        assert!(matches!(outcome, ValidationOutcome::Invalid(_)));

        // 4. Invalid response (403)
        let transport = FixtureTransport::ok(403, "{}");
        let outcome = validate_key(&transport, &validation, "test-key", None).await;
        assert!(matches!(outcome, ValidationOutcome::Invalid(_)));

        // 5. Warning response (500)
        let transport = FixtureTransport::ok(500, "{}");
        let outcome = validate_key(&transport, &validation, "test-key", None).await;
        assert!(matches!(outcome, ValidationOutcome::Warning(_)));

        // 6. Warning response (transport error)
        let transport = FixtureTransport::new(vec![Err(RefreshError::Transport(
            "network down".to_string(),
        ))]);
        let outcome = validate_key(&transport, &validation, "test-key", None).await;
        assert!(matches!(outcome, ValidationOutcome::Warning(_)));
    }

    /// The Anthropic API-key row probes GET /v1/models with Anthropic's own headers. A
    /// bearer header there would get 401 for a good key and refuse the login.
    #[tokio::test]
    async fn anthropic_api_key_row_probes_models_with_anthropic_headers() {
        let row = API_KEY_PROVIDERS
            .iter()
            .find(|p| p.default_id == "apikey:anthropic")
            .expect("an Anthropic API-key row exists");
        assert_eq!(row.key, "anthropic");

        let transport = FixtureTransport::ok(200, "{}");
        let outcome = validate_key(&transport, &row.validation, "sk-ant-test", None).await;
        assert_eq!(outcome, ValidationOutcome::Valid);
        let reqs = transport.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].url, "https://api.anthropic.com/v1/models");
        assert_eq!(
            reqs[0].headers,
            vec![
                ("x-api-key".to_string(), "sk-ant-test".to_string()),
                ("anthropic-version".to_string(), "2023-06-01".to_string())
            ]
        );

        let transport = FixtureTransport::ok(401, "{}");
        let outcome = validate_key(&transport, &row.validation, "sk-ant-test", None).await;
        assert!(matches!(outcome, ValidationOutcome::Invalid(_)));
    }

    #[tokio::test]
    async fn test_validation_anthropic_messages() {
        let validation = KeyValidation::AnthropicMessages {
            base_url: "https://api.anthropic.com",
            model: "claude-3",
        };

        // 1. Valid response (200)
        let transport = FixtureTransport::ok(200, "{}");
        let outcome = validate_key(&transport, &validation, "test-key", None).await;
        assert_eq!(outcome, ValidationOutcome::Valid);
        let reqs = transport.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].url, "https://api.anthropic.com/v1/messages");
        assert_eq!(reqs[0].content_type, "application/json");
        assert_eq!(
            reqs[0].headers,
            vec![
                ("x-api-key".to_string(), "test-key".to_string()),
                ("anthropic-version".to_string(), "2023-06-01".to_string())
            ]
        );
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["model"], "claude-3");
        assert_eq!(body["max_tokens"], 1);

        // A body error does not prove that authentication was checked.
        let transport = FixtureTransport::ok(400, "{}");
        let outcome = validate_key(&transport, &validation, "test-key", None).await;
        assert!(matches!(outcome, ValidationOutcome::Warning(_)));

        // 3. Invalid response (401)
        let transport = FixtureTransport::ok(401, "{}");
        let outcome = validate_key(&transport, &validation, "test-key", None).await;
        assert!(matches!(outcome, ValidationOutcome::Invalid(_)));

        // 4. Invalid response (403)
        let transport = FixtureTransport::ok(403, "{}");
        let outcome = validate_key(&transport, &validation, "test-key", None).await;
        assert!(matches!(outcome, ValidationOutcome::Invalid(_)));

        // 5. Warning response (500)
        let transport = FixtureTransport::ok(500, "{}");
        let outcome = validate_key(&transport, &validation, "test-key", None).await;
        assert!(matches!(outcome, ValidationOutcome::Warning(_)));

        // 6. Warning response (transport error)
        let transport = FixtureTransport::new(vec![Err(RefreshError::Transport(
            "network down".to_string(),
        ))]);
        let outcome = validate_key(&transport, &validation, "test-key", None).await;
        assert!(matches!(outcome, ValidationOutcome::Warning(_)));
    }

    #[tokio::test]
    async fn test_validation_get_endpoint() {
        // 1. Bearer scheme
        let validation_bearer = KeyValidation::GetEndpoint {
            url: "https://api.example.com/user",
            auth_header: AuthHeaderScheme::Bearer,
        };
        let transport = FixtureTransport::ok(200, "{}");
        let outcome = validate_key(&transport, &validation_bearer, "test-key", None).await;
        assert_eq!(outcome, ValidationOutcome::Valid);
        let reqs = transport.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].url, "https://api.example.com/user");
        assert_eq!(
            reqs[0].headers,
            vec![("Authorization".to_string(), "Bearer test-key".to_string())]
        );

        // 2. XGoogApiKey scheme
        let validation_goog = KeyValidation::GetEndpoint {
            url: "https://api.example.com/user",
            auth_header: AuthHeaderScheme::XGoogApiKey,
        };
        let transport = FixtureTransport::ok(200, "{}");
        let outcome = validate_key(&transport, &validation_goog, "test-key", None).await;
        assert_eq!(outcome, ValidationOutcome::Valid);
        let reqs = transport.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].url, "https://api.example.com/user");
        assert_eq!(
            reqs[0].headers,
            vec![("x-goog-api-key".to_string(), "test-key".to_string())]
        );

        let validation_brave = KeyValidation::GetEndpoint {
            url: "https://api.example.com/user",
            auth_header: AuthHeaderScheme::BraveSubscriptionToken,
        };
        let transport = FixtureTransport::ok(200, "{}");
        assert_eq!(
            validate_key(&transport, &validation_brave, "test-key", None).await,
            ValidationOutcome::Valid
        );
        assert_eq!(
            transport.requests()[0].headers,
            vec![("X-Subscription-Token".to_string(), "test-key".to_string())]
        );

        // 3. Invalid response (401)
        let transport = FixtureTransport::ok(401, "{}");
        let outcome = validate_key(&transport, &validation_bearer, "test-key", None).await;
        assert!(matches!(outcome, ValidationOutcome::Invalid(_)));

        // 4. Warning response (500)
        let transport = FixtureTransport::ok(500, "{}");
        let outcome = validate_key(&transport, &validation_bearer, "test-key", None).await;
        assert!(matches!(outcome, ValidationOutcome::Warning(_)));
    }

    const CLOUDFLARE_ACCOUNT: &str = "0123456789abcdef0123456789abcdef";

    fn cloudflare_row() -> &'static ApiKeyProvider {
        API_KEY_PROVIDERS
            .iter()
            .find(|provider| provider.key == "cloudflare-workers-ai")
            .expect("Cloudflare Workers AI row")
    }

    /// Cloudflare's responses to the probe, recorded live with fake credentials. See the
    /// fixture's `about` for how each was captured.
    fn cloudflare_fixture(group: &str, case: &str) -> (u16, String) {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/cloudflare_workers_ai_probe.json"
        ))
        .unwrap();
        let case = &fixture[group][case];
        (
            case["status"].as_u64().unwrap() as u16,
            case["body"].as_str().unwrap().to_string(),
        )
    }

    #[tokio::test]
    async fn cloudflare_probe_sends_the_token_to_the_account_model_search() {
        let transport = FixtureTransport::ok(200, r#"{"success":true,"result":[]}"#);
        assert_eq!(
            check_login_key(
                &transport,
                cloudflare_row(),
                "cf-token",
                Some(CLOUDFLARE_ACCOUNT)
            )
            .await,
            Ok(ValidationOutcome::Valid)
        );
        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].url,
            "https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef/ai/models/search?per_page=1"
        );
        assert_eq!(
            requests[0].headers,
            vec![("Authorization".to_string(), "Bearer cf-token".to_string())]
        );
    }

    #[tokio::test]
    async fn cloudflare_probe_classifies_the_recorded_responses() {
        let token = "cf-secret-token-value";
        let run = |status: u16, body: String| async move {
            let transport = FixtureTransport::ok(status, body);
            validate_key(
                &transport,
                &cloudflare_row().validation,
                token,
                Some(CLOUDFLARE_ACCOUNT),
            )
            .await
        };

        let (status, body) = cloudflare_fixture("recorded", "unknown_well_formed_token");
        let ValidationOutcome::Invalid(invalid) = run(status, body).await else {
            panic!("a 401 for an unknown token must refuse the login");
        };
        assert!(
            invalid.contains("rejected the API token (status 401, Cloudflare error code 10000)")
        );

        let (status, body) = cloudflare_fixture("recorded", "unparseable_token");
        let ValidationOutcome::Invalid(malformed) = run(status, body).await else {
            panic!("a 400/9106 for an unparseable token must refuse the login");
        };
        assert!(malformed.contains("malformed"), "{malformed}");

        let (status, body) = cloudflare_fixture(
            "documented",
            "token_without_workers_ai_permission_or_wrong_account",
        );
        let ValidationOutcome::Invalid(forbidden) = run(status, body).await else {
            panic!("a 403 must refuse the login");
        };
        assert!(forbidden.contains("Workers AI"), "{forbidden}");
        assert!(forbidden.contains("account id"), "{forbidden}");
        assert!(forbidden.contains(CLOUDFLARE_ACCOUNT), "{forbidden}");

        // A 400 that is not the auth-header refusal says nothing about the token.
        let other_400 = run(
            400,
            r#"{"success":false,"errors":[{"code":7003,"message":"Could not route"}]}"#.to_string(),
        )
        .await;
        assert_eq!(
            other_400,
            ValidationOutcome::Warning(
                "unexpected status 400, Cloudflare error code 7003".to_string()
            )
        );

        let server_error = run(500, "upstream failure".to_string()).await;
        assert_eq!(
            server_error,
            ValidationOutcome::Warning("unexpected status 500".to_string())
        );

        let transport = FixtureTransport::new(vec![Err(RefreshError::Transport(
            "network down".to_string(),
        ))]);
        let network = validate_key(
            &transport,
            &cloudflare_row().validation,
            token,
            Some(CLOUDFLARE_ACCOUNT),
        )
        .await;
        assert!(
            matches!(network, ValidationOutcome::Warning(_)),
            "{network:?}"
        );

        for message in [invalid, malformed, forbidden] {
            assert!(
                !message.contains(token),
                "message echoes the token: {message}"
            );
        }
    }

    /// A malformed account id never reaches the network: the probe URL is built from it
    /// and carries the token, so it must be refused before any request is made.
    #[tokio::test]
    async fn a_malformed_cloudflare_account_id_is_refused_before_any_request() {
        for bad in [
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef",
            "0123456789abcdef0123456789abcdef/../../user",
            "",
        ] {
            // A success is queued so that, if the check ever let this id through, the
            // probe would answer "valid" and the failure below would name the accepted
            // id, rather than the transport panicking for want of a response.
            let transport = FixtureTransport::ok(200, r#"{"success":true,"result":[]}"#);
            let refused =
                check_login_key(&transport, cloudflare_row(), "cf-secret-token", Some(bad)).await;
            let Err(message) = refused else {
                panic!("accepted account id {bad:?}");
            };
            assert!(message.contains("32 lowercase hexadecimal"), "{message}");
            assert!(!message.contains("cf-secret-token"), "{message}");
            assert!(
                transport.requests().is_empty(),
                "a request was sent for {bad:?}"
            );
        }
        // No account id at all is refused the same way.
        let transport = FixtureTransport::new(Vec::new());
        assert!(check_login_key(&transport, cloudflare_row(), "t", None)
            .await
            .is_err());
        assert!(transport.requests().is_empty());
    }

    /// An account id on a row that never asks for one would be served to consumers as
    /// the account identity although nothing checked it, so it is refused.
    #[tokio::test]
    async fn an_account_id_is_refused_on_a_row_without_the_prompt() {
        let zai = API_KEY_PROVIDERS.iter().find(|p| p.key == "zai").unwrap();
        assert!(zai.account_id_prompt.is_none());
        let refusal = check_account_id(zai, Some(CLOUDFLARE_ACCOUNT)).unwrap_err();
        assert!(refusal.contains("--account-id does not apply"), "{refusal}");
        let transport = FixtureTransport::ok(200, "{}");
        assert!(
            check_login_key(&transport, zai, "t", Some(CLOUDFLARE_ACCOUNT))
                .await
                .is_err()
        );
        assert!(transport.requests().is_empty());
        assert_eq!(check_account_id(zai, None), Ok(()));
    }

    /// A provider with no usable probe must make no network call at all (a request to an
    /// endpoint that cannot judge the key could only refuse a valid one) and must come
    /// back as Unchecked, never Valid, so login does not print "API key is valid."
    #[tokio::test]
    async fn an_unvalidated_provider_is_reported_unchecked_without_a_request() {
        let validation = KeyValidation::Unvalidated {
            reason: "no probe exists",
        };
        let transport = FixtureTransport::new(Vec::new());
        assert_eq!(
            validate_key(&transport, &validation, "test-key", None).await,
            ValidationOutcome::Unchecked("no probe exists")
        );
        assert!(transport.requests().is_empty());
    }

    #[tokio::test]
    async fn only_successful_probes_verify_api_keys() {
        let probes = [
            KeyValidation::OpenAiChat {
                base_url: "https://api.example.com/v1",
                model: "test",
            },
            KeyValidation::AnthropicMessages {
                base_url: "https://api.example.com",
                model: "test",
            },
            KeyValidation::GetEndpoint {
                url: "https://api.example.com/models",
                auth_header: AuthHeaderScheme::Bearer,
            },
        ];
        for probe in probes {
            for status in [200, 299, 302, 400, 401, 403, 404, 405, 407, 429, 500] {
                let transport = FixtureTransport::ok(status, "{}");
                let outcome = validate_key(&transport, &probe, "test-key", None).await;
                match status {
                    200 | 299 => assert_eq!(outcome, ValidationOutcome::Valid),
                    401 | 403 => assert!(matches!(outcome, ValidationOutcome::Invalid(_))),
                    _ => assert!(
                        matches!(outcome, ValidationOutcome::Warning(_)),
                        "status {status}"
                    ),
                }
            }
        }
    }
}
