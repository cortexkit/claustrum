use credentials_core::refresh_adapters::HttpTransport;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthHeaderScheme {
    Bearer,
    XGoogApiKey,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyValidation {
    OpenAiChat {
        base_url: &'static str,
        model: &'static str,
    },
    AnthropicMessages {
        base_url: &'static str,
        model: &'static str,
    },
    GetEndpoint {
        url: &'static str,
        auth_header: AuthHeaderScheme,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationOutcome {
    Valid,
    Invalid(String),
    Warning(String),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ApiKeyProvider {
    pub key: &'static str,
    pub display_name: &'static str,
    pub default_id: &'static str,
    pub dashboard_url: &'static str,
    pub placeholder: &'static str,
    pub validation: KeyValidation,
}

pub const API_KEY_PROVIDERS: &[ApiKeyProvider] = &[
    ApiKeyProvider {
        key: "zai",
        display_name: "Z.AI (GLM Coding Plan)",
        default_id: "apikey:zai",
        dashboard_url: "https://z.ai/manage-apikey/apikey-list",
        placeholder: "sk-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.z.ai/api/coding/paas/v4",
            model: "glm-5.2",
        },
    },
    ApiKeyProvider {
        key: "openrouter",
        display_name: "OpenRouter",
        default_id: "apikey:openrouter",
        dashboard_url: "https://openrouter.ai/keys",
        placeholder: "sk-or-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://openrouter.ai/api/v1/auth/key",
            auth_header: AuthHeaderScheme::Bearer,
        },
    },
    ApiKeyProvider {
        key: "deepseek",
        display_name: "DeepSeek",
        default_id: "apikey:deepseek",
        dashboard_url: "https://platform.deepseek.com/api_keys",
        placeholder: "sk-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.deepseek.com",
            model: "deepseek-chat",
        },
    },
    ApiKeyProvider {
        key: "cerebras",
        display_name: "Cerebras",
        default_id: "apikey:cerebras",
        dashboard_url: "https://cloud.cerebras.ai",
        placeholder: "csk-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.cerebras.ai/v1",
            model: "llama3.1-8b",
        },
    },
    ApiKeyProvider {
        key: "fireworks-ai",
        display_name: "Fireworks AI",
        default_id: "apikey:fireworks-ai",
        dashboard_url: "https://app.fireworks.ai/settings/users/api-keys",
        placeholder: "fw-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.fireworks.ai/inference/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
    },
    ApiKeyProvider {
        key: "groq",
        display_name: "Groq",
        default_id: "apikey:groq",
        dashboard_url: "https://console.groq.com/keys",
        placeholder: "gsk_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.groq.com/openai/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
    },
    ApiKeyProvider {
        key: "mistral",
        display_name: "Mistral",
        default_id: "apikey:mistral",
        dashboard_url: "https://console.mistral.ai/api-keys",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.mistral.ai/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
    },
    ApiKeyProvider {
        key: "together",
        display_name: "Together AI",
        default_id: "apikey:together",
        dashboard_url: "https://api.together.ai/settings/api-keys",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.together.xyz/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
    },
    ApiKeyProvider {
        key: "perplexity",
        display_name: "Perplexity",
        default_id: "apikey:perplexity",
        dashboard_url: "https://www.perplexity.ai/settings/api",
        placeholder: "pplx-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.perplexity.ai",
            model: "sonar",
        },
    },
    ApiKeyProvider {
        key: "moonshot",
        display_name: "Moonshot",
        default_id: "apikey:moonshot",
        dashboard_url: "https://platform.moonshot.ai/console/api-keys",
        placeholder: "sk-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.moonshot.ai/v1",
            model: "moonshot-v1-8k",
        },
    },
    ApiKeyProvider {
        key: "huggingface",
        display_name: "Hugging Face",
        default_id: "apikey:huggingface",
        dashboard_url: "https://huggingface.co/settings/tokens",
        placeholder: "hf_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://huggingface.co/api/whoami-v2",
            auth_header: AuthHeaderScheme::Bearer,
        },
    },
    ApiKeyProvider {
        key: "nvidia",
        display_name: "NVIDIA",
        default_id: "apikey:nvidia",
        dashboard_url: "https://build.nvidia.com",
        placeholder: "nvapi-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://integrate.api.nvidia.com/v1",
            model: "meta/llama-3.1-8b-instruct",
        },
    },
    ApiKeyProvider {
        key: "xai",
        display_name: "xAI (API Key)",
        default_id: "apikey:xai",
        dashboard_url: "https://console.x.ai",
        placeholder: "xai-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.x.ai/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
    },
    ApiKeyProvider {
        key: "openai",
        display_name: "OpenAI (API Key)",
        default_id: "apikey:openai",
        dashboard_url: "https://platform.openai.com/api-keys",
        placeholder: "sk-proj-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.openai.com/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
    },
    ApiKeyProvider {
        key: "google",
        display_name: "Google AI Studio (API Key)",
        default_id: "apikey:google",
        dashboard_url: "https://aistudio.google.com/apikey",
        placeholder: "AIzaSy...",
        validation: KeyValidation::GetEndpoint {
            url: "https://generativelanguage.googleapis.com/v1beta/models",
            auth_header: AuthHeaderScheme::XGoogApiKey,
        },
    },
];

pub async fn validate_key(
    transport: &dyn HttpTransport,
    validation: &KeyValidation,
    key: &str,
) -> ValidationOutcome {
    if std::env::var("CORTEXKIT_TEST_BYPASS_VALIDATION").is_ok() {
        return ValidationOutcome::Valid;
    }
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
                    } else if (200..=299).contains(&resp.status)
                        || (400..=499).contains(&resp.status)
                    {
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
                    } else if (200..=299).contains(&resp.status)
                        || (400..=499).contains(&resp.status)
                    {
                        ValidationOutcome::Valid
                    } else {
                        ValidationOutcome::Warning(format!("unexpected status {}", resp.status))
                    }
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

        // 2. Valid response (400 model error)
        let transport = FixtureTransport::ok(400, "{}");
        let outcome = validate_key(&transport, &validation, "test-key").await;
        assert_eq!(outcome, ValidationOutcome::Valid);

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

        // 2. Valid response (400 model error)
        let transport = FixtureTransport::ok(400, "{}");
        let outcome = validate_key(&transport, &validation, "test-key").await;
        assert_eq!(outcome, ValidationOutcome::Valid);

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
}
