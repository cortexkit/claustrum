pub use credentials_core::catalog::{AuthHeaderScheme, KeyValidation, API_KEY_PROVIDERS};
use credentials_core::refresh_adapters::HttpTransport;

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

pub async fn validate_key(
    transport: &dyn HttpTransport,
    validation: &KeyValidation,
    key: &str,
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
        KeyValidation::GetEndpoint { url, auth_header } => {
            let headers = match auth_header {
                AuthHeaderScheme::Bearer => vec![("Authorization", format!("Bearer {}", key))],
                AuthHeaderScheme::XGoogApiKey => vec![("x-goog-api-key", key.to_string())],
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
        KeyValidation::Unvalidated { reason } => ValidationOutcome::Unchecked(reason),
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
    async fn aws_api_key_get_pins_request_shape() {
        let provider = API_KEY_PROVIDERS.iter().find(|p| p.key == "kiro").unwrap();
        let transport = FixtureTransport::ok(200, r#"{"models":[{"modelId":"test"}]}"#);
        assert_eq!(
            validate_key(&transport, &provider.validation, "ksk_test_fixture").await,
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
            let outcome = validate_key(&transport, &validation, "ksk_test_fixture").await;
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
            validate_key(&transport, &validation, "ksk_test_fixture").await,
            ValidationOutcome::Warning(_)
        ));
        // A 403 that is not the invalid-bearer refusal says nothing about the key, so
        // it must not refuse the login.
        let transport = FixtureTransport::ok(
            403,
            r#"{"message":"User is not authorized to access this resource","reason":null}"#,
        );
        assert!(matches!(
            validate_key(&transport, &validation, "ksk_test_fixture").await,
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
        let outcome = validate_key(&transport, &validation, "test-key").await;
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
        let outcome = validate_key(&transport, &validation, "test-key").await;
        assert!(matches!(outcome, ValidationOutcome::Warning(_)));

        // 3. Invalid response (401)
        let transport = FixtureTransport::ok(401, "{}");
        let outcome = validate_key(&transport, &validation, "test-key").await;
        assert!(matches!(outcome, ValidationOutcome::Invalid(_)));

        // 4. Invalid response (403)
        let transport = FixtureTransport::ok(403, "{}");
        let outcome = validate_key(&transport, &validation, "test-key").await;
        assert!(matches!(outcome, ValidationOutcome::Invalid(_)));

        // 5. Warning response (500)
        let transport = FixtureTransport::ok(500, "{}");
        let outcome = validate_key(&transport, &validation, "test-key").await;
        assert!(matches!(outcome, ValidationOutcome::Warning(_)));

        // 6. Warning response (transport error)
        let transport = FixtureTransport::new(vec![Err(RefreshError::Transport(
            "network down".to_string(),
        ))]);
        let outcome = validate_key(&transport, &validation, "test-key").await;
        assert!(matches!(outcome, ValidationOutcome::Warning(_)));
    }

    #[tokio::test]
    async fn test_validation_anthropic_messages() {
        let validation = KeyValidation::AnthropicMessages {
            base_url: "https://api.anthropic.com",
            model: "claude-3",
        };

        // 1. Valid response (200)
        let transport = FixtureTransport::ok(200, "{}");
        let outcome = validate_key(&transport, &validation, "test-key").await;
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
        let outcome = validate_key(&transport, &validation, "test-key").await;
        assert!(matches!(outcome, ValidationOutcome::Warning(_)));

        // 3. Invalid response (401)
        let transport = FixtureTransport::ok(401, "{}");
        let outcome = validate_key(&transport, &validation, "test-key").await;
        assert!(matches!(outcome, ValidationOutcome::Invalid(_)));

        // 4. Invalid response (403)
        let transport = FixtureTransport::ok(403, "{}");
        let outcome = validate_key(&transport, &validation, "test-key").await;
        assert!(matches!(outcome, ValidationOutcome::Invalid(_)));

        // 5. Warning response (500)
        let transport = FixtureTransport::ok(500, "{}");
        let outcome = validate_key(&transport, &validation, "test-key").await;
        assert!(matches!(outcome, ValidationOutcome::Warning(_)));

        // 6. Warning response (transport error)
        let transport = FixtureTransport::new(vec![Err(RefreshError::Transport(
            "network down".to_string(),
        ))]);
        let outcome = validate_key(&transport, &validation, "test-key").await;
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
        let outcome = validate_key(&transport, &validation_bearer, "test-key").await;
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
        let outcome = validate_key(&transport, &validation_goog, "test-key").await;
        assert_eq!(outcome, ValidationOutcome::Valid);
        let reqs = transport.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].url, "https://api.example.com/user");
        assert_eq!(
            reqs[0].headers,
            vec![("x-goog-api-key".to_string(), "test-key".to_string())]
        );

        // 3. Invalid response (401)
        let transport = FixtureTransport::ok(401, "{}");
        let outcome = validate_key(&transport, &validation_bearer, "test-key").await;
        assert!(matches!(outcome, ValidationOutcome::Invalid(_)));

        // 4. Warning response (500)
        let transport = FixtureTransport::ok(500, "{}");
        let outcome = validate_key(&transport, &validation_bearer, "test-key").await;
        assert!(matches!(outcome, ValidationOutcome::Warning(_)));
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
            validate_key(&transport, &validation, "test-key").await,
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
                let outcome = validate_key(&transport, &probe, "test-key").await;
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
