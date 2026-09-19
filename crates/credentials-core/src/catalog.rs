//! Provider registries and the non-secret classification derived from credential ids.
//!
//! `categories` is authorization data: a mistaken value can widen a category grant.
//! `serves` is advisory consumer metadata: it never participates in authorization.

use crate::{google_login as google, refresh_adapters};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CredentialCategory {
    LlmProvider,
    DataWarehouse,
    CloudInfrastructure,
}

impl CredentialCategory {
    pub const ALL: &[Self] = &[
        Self::LlmProvider,
        Self::DataWarehouse,
        Self::CloudInfrastructure,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LlmProvider => "llm-provider",
            Self::DataWarehouse => "data-warehouse",
            Self::CloudInfrastructure => "cloud-infrastructure",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ModelVendor {
    Anthropic,
    OpenAI,
    Google,
    XAI,
    DeepSeek,
    Mistral,
    Moonshot,
    Zhipu,
    Meta,
    Qwen,
    Perplexity,
    Nvidia,
}

impl ModelVendor {
    pub const ALL: &[Self] = &[
        Self::Anthropic,
        Self::OpenAI,
        Self::Google,
        Self::XAI,
        Self::DeepSeek,
        Self::Mistral,
        Self::Moonshot,
        Self::Zhipu,
        Self::Meta,
        Self::Qwen,
        Self::Perplexity,
        Self::Nvidia,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAI => "openai",
            Self::Google => "google",
            Self::XAI => "xai",
            Self::DeepSeek => "deepseek",
            Self::Mistral => "mistral",
            Self::Moonshot => "moonshot",
            Self::Zhipu => "zhipu",
            Self::Meta => "meta",
            Self::Qwen => "qwen",
            Self::Perplexity => "perplexity",
            Self::Nvidia => "nvidia",
        }
    }
}

const LLM: &[CredentialCategory] = &[CredentialCategory::LlmProvider];
const DATA_WAREHOUSE: &[CredentialCategory] = &[CredentialCategory::DataWarehouse];
const CLOUD_INFRASTRUCTURE: &[CredentialCategory] = &[CredentialCategory::CloudInfrastructure];
const NO_CATEGORIES: &[CredentialCategory] = &[];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthHeaderScheme {
    Bearer,
    XGoogApiKey,
}

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

#[derive(Debug, Clone)]
pub struct ApiKeyProvider {
    pub key: &'static str,
    pub display_name: &'static str,
    pub default_id: &'static str,
    pub dashboard_url: &'static str,
    pub placeholder: &'static str,
    pub validation: KeyValidation,
    pub categories: &'static [CredentialCategory],
    pub serves: &'static [ModelVendor],
}

use ModelVendor::{
    Anthropic, DeepSeek, Google, Meta, Mistral, Moonshot, Nvidia, OpenAI, Perplexity, Qwen, Zhipu,
    XAI,
};

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
        categories: LLM,
        serves: &[Zhipu],
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
        categories: LLM,
        serves: ModelVendor::ALL,
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
        categories: LLM,
        serves: &[DeepSeek],
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
        categories: LLM,
        serves: &[Meta, Qwen, OpenAI],
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
        categories: LLM,
        serves: &[Meta, Qwen, DeepSeek, Mistral, OpenAI],
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
        categories: LLM,
        serves: &[Meta, Qwen, OpenAI, Moonshot, Mistral],
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
        categories: LLM,
        serves: &[Mistral],
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
        categories: LLM,
        serves: &[Meta, Qwen, DeepSeek, Mistral, OpenAI, Moonshot],
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
        categories: LLM,
        serves: &[Perplexity],
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
        categories: LLM,
        serves: &[Moonshot],
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
        categories: LLM,
        serves: &[Meta, Qwen, DeepSeek, Mistral, OpenAI, Moonshot, Zhipu],
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
        categories: LLM,
        serves: &[Nvidia, Meta, Qwen, DeepSeek, Mistral, OpenAI, Moonshot],
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
        categories: LLM,
        serves: &[XAI],
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
        categories: LLM,
        serves: &[OpenAI],
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
        categories: LLM,
        serves: &[Google],
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    Xai,
    OpenAi,
    GithubCopilot,
    Kimi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeWire {
    AnthropicJson,
    RfcForm,
}

#[derive(Debug, Clone, Copy)]
pub struct LoginProvider {
    pub key: &'static str,
    pub authorize_url: &'static str,
    pub token_url: &'static str,
    pub client_id: &'static str,
    pub redirect_uri: &'static str,
    pub scopes: &'static [&'static str],
    pub extra_authorize_params: &'static [(&'static str, &'static str)],
    pub adapter_name: &'static str,
    pub default_id: &'static str,
    pub exchange: ExchangeWire,
    pub needs_oidc_nonce: bool,
    pub exchange_echoes_challenge: bool,
    pub paste_prompt: &'static str,
    pub device: Option<DeviceKind>,
    pub categories: &'static [CredentialCategory],
    pub serves: &'static [ModelVendor],
}

pub const LOGIN_PROVIDERS: &[LoginProvider] = &[
    LoginProvider {
        key: "anthropic",
        authorize_url: refresh_adapters::anthropic::AUTHORIZE_URL,
        token_url: refresh_adapters::anthropic::LOGIN_TOKEN_URL,
        client_id: refresh_adapters::anthropic::CLAUDE_CODE_CLIENT_ID,
        redirect_uri: refresh_adapters::anthropic::LOGIN_REDIRECT_URI,
        scopes: refresh_adapters::anthropic::LOGIN_SCOPES,
        extra_authorize_params: refresh_adapters::anthropic::LOGIN_EXTRA_AUTHORIZE_PARAMS,
        adapter_name: refresh_adapters::anthropic::ADAPTER_NAME,
        default_id: "oauth:anthropic",
        exchange: ExchangeWire::AnthropicJson,
        needs_oidc_nonce: false,
        exchange_echoes_challenge: false,
        paste_prompt: "After approving, the browser will fail to connect to localhost:54545 — that is expected (nothing listens there).\nCopy the FULL URL from the browser's address bar (or the code#state if shown) and paste it here, then Enter:",
        device: None,
        categories: LLM,
        serves: &[Anthropic],
    },
    LoginProvider {
        key: "openai",
        authorize_url: refresh_adapters::openai::AUTHORIZE_URL,
        token_url: refresh_adapters::openai::TOKEN_URL,
        client_id: refresh_adapters::openai::CODEX_CLIENT_ID,
        redirect_uri: refresh_adapters::openai::LOGIN_REDIRECT_URI,
        scopes: refresh_adapters::openai::LOGIN_SCOPES,
        extra_authorize_params: refresh_adapters::openai::LOGIN_EXTRA_AUTHORIZE_PARAMS,
        adapter_name: refresh_adapters::openai::ADAPTER_NAME,
        default_id: "chatgpt:openai",
        exchange: ExchangeWire::RfcForm,
        needs_oidc_nonce: false,
        exchange_echoes_challenge: false,
        paste_prompt: "After approving, the browser will fail to connect to localhost:1455 — that is expected (nothing listens there).\nCopy the FULL URL from the browser's address bar and paste it here, then Enter:",
        device: Some(DeviceKind::OpenAi),
        categories: LLM,
        serves: &[OpenAI],
    },
    LoginProvider {
        key: "xai",
        authorize_url: refresh_adapters::xai::AUTHORIZE_URL,
        token_url: refresh_adapters::xai::TOKEN_URL,
        client_id: refresh_adapters::xai::GROK_CLI_CLIENT_ID,
        redirect_uri: refresh_adapters::xai::LOGIN_REDIRECT_URI,
        scopes: refresh_adapters::xai::LOGIN_SCOPES,
        extra_authorize_params: refresh_adapters::xai::LOGIN_EXTRA_AUTHORIZE_PARAMS,
        adapter_name: refresh_adapters::xai::ADAPTER_NAME,
        default_id: "oauth:xai",
        exchange: ExchangeWire::RfcForm,
        needs_oidc_nonce: true,
        exchange_echoes_challenge: true,
        paste_prompt: "After approving, the browser will fail to connect to 127.0.0.1:56121 — that is expected (nothing listens there).\nCopy the FULL URL from the browser's address bar and paste it here, then Enter:",
        device: Some(DeviceKind::Xai),
        categories: LLM,
        serves: &[XAI],
    },
    LoginProvider {
        key: "github-copilot",
        authorize_url: "",
        token_url: refresh_adapters::github_copilot::DEVICE_TOKEN_URL,
        client_id: refresh_adapters::github_copilot::CLIENT_ID,
        redirect_uri: "",
        scopes: &["read:user"],
        extra_authorize_params: &[],
        adapter_name: refresh_adapters::github_copilot::ADAPTER_NAME,
        default_id: "copilot:github",
        exchange: ExchangeWire::RfcForm,
        needs_oidc_nonce: false,
        exchange_echoes_challenge: false,
        paste_prompt: "",
        device: Some(DeviceKind::GithubCopilot),
        categories: LLM,
        serves: &[OpenAI, Anthropic, Google, XAI],
    },
    LoginProvider {
        key: "kimi",
        authorize_url: "",
        token_url: refresh_adapters::kimi::TOKEN_URL,
        client_id: refresh_adapters::kimi::CLIENT_ID,
        redirect_uri: "",
        scopes: &[],
        extra_authorize_params: &[],
        adapter_name: refresh_adapters::kimi::ADAPTER_NAME,
        default_id: "oauth:kimi",
        exchange: ExchangeWire::RfcForm,
        needs_oidc_nonce: false,
        exchange_echoes_challenge: false,
        paste_prompt: "",
        device: Some(DeviceKind::Kimi),
        categories: LLM,
        serves: &[Moonshot],
    },
    LoginProvider {
        key: "google",
        authorize_url: google::AUTHORIZE_URL,
        token_url: google::TOKEN_URL,
        client_id: "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com",
        redirect_uri: google::GEMINI_REDIRECT_URI,
        scopes: google::SCOPES,
        extra_authorize_params: google::AUTHORIZE_EXTRA_PARAMS,
        adapter_name: "google",
        default_id: "oauth:google",
        exchange: ExchangeWire::RfcForm,
        needs_oidc_nonce: false,
        exchange_echoes_challenge: false,
        paste_prompt: "After approving, the browser may fail to connect to 127.0.0.1:8085 — that is expected. Copy the FULL URL from the address bar and paste it here, then Enter:",
        device: None,
        categories: LLM,
        serves: &[Google],
    },
    LoginProvider {
        key: "antigravity",
        authorize_url: google::AUTHORIZE_URL,
        token_url: google::TOKEN_URL,
        client_id: "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com",
        redirect_uri: google::ANTIGRAVITY_REDIRECT_URI,
        scopes: google::SCOPES,
        extra_authorize_params: google::AUTHORIZE_EXTRA_PARAMS,
        adapter_name: "antigravity",
        default_id: "antigravity:google",
        exchange: ExchangeWire::RfcForm,
        needs_oidc_nonce: false,
        exchange_echoes_challenge: false,
        paste_prompt: "After approving, the browser may fail to connect to 127.0.0.1:51121 — that is expected. Copy the FULL URL from the address bar and paste it here, then Enter:",
        device: None,
        categories: LLM,
        serves: &[Google, Anthropic, OpenAI],
    },
    LoginProvider {
        key: "cursor",
        authorize_url: refresh_adapters::cursor::LOGIN_URL,
        token_url: refresh_adapters::cursor::TOKEN_URL,
        client_id: "",
        redirect_uri: "",
        scopes: &[],
        extra_authorize_params: &[],
        adapter_name: refresh_adapters::cursor::ADAPTER_NAME,
        default_id: refresh_adapters::cursor::DEFAULT_ID,
        exchange: ExchangeWire::RfcForm,
        needs_oidc_nonce: false,
        exchange_echoes_challenge: false,
        paste_prompt: "Cursor login is completed by browser polling.",
        device: None,
        categories: LLM,
        serves: &[Anthropic, OpenAI, Google, XAI],
    },
    LoginProvider {
        key: "devin",
        authorize_url: refresh_adapters::devin::AUTHORIZE_URL,
        token_url: refresh_adapters::devin::TOKEN_URL,
        client_id: "",
        redirect_uri: refresh_adapters::devin::LOGIN_REDIRECT_URI,
        scopes: &[],
        extra_authorize_params: &[],
        adapter_name: refresh_adapters::devin::ADAPTER_NAME,
        default_id: refresh_adapters::devin::DEFAULT_ID,
        exchange: ExchangeWire::RfcForm,
        needs_oidc_nonce: false,
        exchange_echoes_challenge: false,
        paste_prompt: "After approving Devin, paste the callback URL.",
        device: None,
        categories: NO_CATEGORIES,
        serves: &[],
    },
    LoginProvider {
        key: "snowflake",
        authorize_url: refresh_adapters::snowflake::TOKEN_URL_BASE,
        token_url: refresh_adapters::snowflake::TOKEN_URL_BASE,
        client_id: refresh_adapters::snowflake::CLIENT_ID,
        redirect_uri: "http://127.0.0.1:0/",
        scopes: &[],
        extra_authorize_params: &[],
        adapter_name: refresh_adapters::snowflake::ADAPTER_NAME,
        default_id: "oauth:snowflake",
        exchange: ExchangeWire::RfcForm,
        needs_oidc_nonce: false,
        exchange_echoes_challenge: false,
        paste_prompt: "After approving Snowflake, paste the callback URL.",
        device: None,
        categories: DATA_WAREHOUSE,
        serves: &[],
    },
    LoginProvider {
        key: "digitalocean",
        authorize_url: refresh_adapters::digitalocean::AUTHORIZE_URL,
        token_url: refresh_adapters::digitalocean::AUTHORIZE_URL,
        client_id: refresh_adapters::digitalocean::CLIENT_ID,
        redirect_uri: refresh_adapters::digitalocean::REDIRECT_URI,
        scopes: refresh_adapters::digitalocean::SCOPES,
        extra_authorize_params: &[],
        adapter_name: refresh_adapters::digitalocean::ADAPTER_NAME,
        default_id: refresh_adapters::digitalocean::DEFAULT_ID,
        exchange: ExchangeWire::RfcForm,
        needs_oidc_nonce: false,
        exchange_echoes_challenge: false,
        paste_prompt: "After approving DigitalOcean, paste the full callback URL including its fragment.",
        device: None,
        categories: CLOUD_INFRASTRUCTURE,
        serves: &[],
    },
];

pub fn api_key_provider(key: &str) -> Option<&'static ApiKeyProvider> {
    API_KEY_PROVIDERS.iter().find(|entry| entry.key == key)
}

pub fn login_provider(key: &str) -> Option<&'static LoginProvider> {
    LOGIN_PROVIDERS.iter().find(|entry| entry.key == key)
}

#[derive(Debug, Clone, Copy)]
enum CatalogEntry {
    ApiKey(&'static ApiKeyProvider),
    Login(&'static LoginProvider),
}

impl CatalogEntry {
    fn categories(self) -> &'static [CredentialCategory] {
        match self {
            Self::ApiKey(entry) => entry.categories,
            Self::Login(entry) => entry.categories,
        }
    }

    fn serves(self) -> &'static [ModelVendor] {
        match self {
            Self::ApiKey(entry) => entry.serves,
            Self::Login(entry) => entry.serves,
        }
    }
}

fn catalog_match(id: &str) -> Option<CatalogEntry> {
    let mut segments = id.split(':');
    let first = segments.next()?;
    let second = segments.next();
    let boundary_id = second.map(|second| format!("{first}:{second}"));
    let matches = |default_id: &str| {
        id == default_id
            || boundary_id
                .as_deref()
                .is_some_and(|prefix| prefix == default_id)
    };

    API_KEY_PROVIDERS
        .iter()
        .find(|entry| matches(entry.default_id))
        .map(CatalogEntry::ApiKey)
        .or_else(|| {
            LOGIN_PROVIDERS
                .iter()
                .find(|entry| matches(entry.default_id))
                .map(CatalogEntry::Login)
        })
}

pub fn category_defaults(credential_id: &str) -> Vec<&'static str> {
    catalog_match(credential_id)
        .map(|entry| {
            entry
                .categories()
                .iter()
                .copied()
                .map(CredentialCategory::as_str)
                .collect()
        })
        .unwrap_or_default()
}

pub fn serves_for(credential_id: &str) -> &'static [ModelVendor] {
    catalog_match(credential_id)
        .map(CatalogEntry::serves)
        .unwrap_or_default()
}

pub fn credential_type(credential_id: &str) -> &'static str {
    let method = credential_id.split(':').next().unwrap_or_default();
    if API_KEY_PROVIDERS
        .iter()
        .any(|entry| entry.default_id.split(':').next() == Some(method))
    {
        return "apikey";
    }
    if LOGIN_PROVIDERS
        .iter()
        .any(|entry| entry.default_id.split(':').next() == Some(method))
    {
        return "oauth";
    }
    match method {
        "cookie" => "cookie",
        "signing" => "signing",
        "github_app" => "github_app",
        "apple" => "apple",
        _ => "unknown",
    }
}

pub fn valid_category_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (2..=32).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashSet};

    use super::*;

    #[test]
    fn catalog_entry_expectations_are_separate_from_no_match_expectations() {
        let entry_rows = [
            ("apikey:zai", vec!["llm-provider"]),
            ("apikey:openrouter", vec!["llm-provider"]),
            ("oauth:anthropic", vec!["llm-provider"]),
            ("oauth:anthropic:fourth", vec!["llm-provider"]),
            ("chatgpt:openai", vec!["llm-provider"]),
            ("oauth:snowflake", vec!["data-warehouse"]),
            ("oauth:digitalocean", vec!["cloud-infrastructure"]),
            ("copilot:github", vec!["llm-provider"]),
            ("oauth:cursor", vec!["llm-provider"]),
            ("oauth:devin", vec![]),
        ];
        for (id, expected) in &entry_rows {
            assert!(
                catalog_match(id).is_some(),
                "entry row became a no-match row: {id}"
            );
            assert_eq!(category_defaults(id), *expected, "entry row {id}");
        }
        let non_empty: BTreeSet<Vec<&str>> = entry_rows
            .iter()
            .map(|(id, _)| category_defaults(id))
            .filter(|categories| !categories.is_empty())
            .collect();
        assert!(
            non_empty.len() >= 2,
            "entry rows need distinct non-empty lists"
        );
        assert!(
            entry_rows
                .iter()
                .any(|(id, _)| !category_defaults(id).is_empty()
                    && category_defaults(id) != ["llm-provider"]),
            "an entry row, not a no-match row, must carry a non-llm category"
        );

        for id in ["apikey:zai-work", "apikey:apns-alfonso", "apple:notes"] {
            assert!(
                catalog_match(id).is_none(),
                "no-match row counted as an entry: {id}"
            );
            assert!(category_defaults(id).is_empty());
        }
    }

    #[test]
    fn both_catalogs_have_exact_owner_supplied_assignments() {
        assert_eq!(API_KEY_PROVIDERS.len(), 15);
        assert_eq!(LOGIN_PROVIDERS.len(), 11);
        assert!(API_KEY_PROVIDERS
            .iter()
            .all(|entry| entry.categories == LLM));
        let login_categories: Vec<_> = LOGIN_PROVIDERS
            .iter()
            .map(|entry| {
                (
                    entry.default_id,
                    entry
                        .categories
                        .iter()
                        .map(|c| c.as_str())
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        assert_eq!(
            login_categories,
            vec![
                ("oauth:anthropic", vec!["llm-provider"]),
                ("chatgpt:openai", vec!["llm-provider"]),
                ("oauth:xai", vec!["llm-provider"]),
                ("copilot:github", vec!["llm-provider"]),
                ("oauth:kimi", vec!["llm-provider"]),
                ("oauth:google", vec!["llm-provider"]),
                ("antigravity:google", vec!["llm-provider"]),
                ("oauth:cursor", vec!["llm-provider"]),
                ("oauth:devin", vec![]),
                ("oauth:snowflake", vec!["data-warehouse"]),
                ("oauth:digitalocean", vec!["cloud-infrastructure"]),
            ]
        );
        assert_eq!(
            CredentialCategory::ALL
                .iter()
                .map(|v| v.as_str())
                .collect::<Vec<_>>(),
            ["llm-provider", "data-warehouse", "cloud-infrastructure"]
        );
        assert_eq!(
            ModelVendor::ALL
                .iter()
                .map(|v| v.as_str())
                .collect::<Vec<_>>(),
            [
                "anthropic",
                "openai",
                "google",
                "xai",
                "deepseek",
                "mistral",
                "moonshot",
                "zhipu",
                "meta",
                "qwen",
                "perplexity",
                "nvidia"
            ]
        );
    }

    #[test]
    fn closed_vocabularies_pin_every_variant_and_wire_spelling() {
        assert_eq!(
            CredentialCategory::ALL
                .iter()
                .map(|value| value.as_str())
                .collect::<Vec<_>>(),
            ["llm-provider", "data-warehouse", "cloud-infrastructure"]
        );
        assert_eq!(
            ModelVendor::ALL
                .iter()
                .map(|value| value.as_str())
                .collect::<Vec<_>>(),
            [
                "anthropic",
                "openai",
                "google",
                "xai",
                "deepseek",
                "mistral",
                "moonshot",
                "zhipu",
                "meta",
                "qwen",
                "perplexity",
                "nvidia",
            ]
        );
    }

    #[test]
    fn catalog_categories_are_valid_and_default_id_sets_are_disjoint() {
        for category in API_KEY_PROVIDERS
            .iter()
            .flat_map(|entry| entry.categories)
            .chain(LOGIN_PROVIDERS.iter().flat_map(|entry| entry.categories))
        {
            assert!(
                valid_category_name(category.as_str()),
                "invalid catalog category {}",
                category.as_str()
            );
        }
        let api: HashSet<_> = API_KEY_PROVIDERS
            .iter()
            .map(|entry| entry.default_id)
            .collect();
        for entry in LOGIN_PROVIDERS {
            assert!(
                !api.contains(entry.default_id),
                "cross-catalog default id collision: {}",
                entry.default_id
            );
        }
    }

    #[test]
    fn serves_and_categories_use_one_catalog_match() {
        assert_eq!(serves_for("oauth:anthropic:fourth"), &[Anthropic]);
        assert_eq!(
            category_defaults("oauth:anthropic:fourth"),
            ["llm-provider"]
        );
        assert!(serves_for("oauth:snowflake").is_empty());
        assert_eq!(category_defaults("oauth:snowflake"), ["data-warehouse"]);
        assert!(serves_for("amazon-bedrock:main").is_empty());
        assert!(category_defaults("amazon-bedrock:main").is_empty());
        assert!(serves_for("apikey:openrouter").contains(&Anthropic));
    }

    #[test]
    fn credential_type_is_total_over_both_catalogs() {
        for default_id in API_KEY_PROVIDERS
            .iter()
            .map(|entry| entry.default_id)
            .chain(LOGIN_PROVIDERS.iter().map(|entry| entry.default_id))
        {
            assert_ne!(
                credential_type(default_id),
                "unknown",
                "catalog id maps to unknown: {default_id}"
            );
        }
        for (id, expected) in [
            ("copilot:github", "oauth"),
            ("oauth:cursor", "oauth"),
            ("oauth:devin", "oauth"),
            ("oauth:digitalocean", "oauth"),
            ("oauth:snowflake", "oauth"),
            ("cookie:x", "cookie"),
            ("signing:x", "signing"),
            ("github_app:x", "github_app"),
            ("apple:x", "apple"),
        ] {
            assert_eq!(credential_type(id), expected);
        }
    }
}

#[cfg(test)]
mod source_ownership_tests {
    use super::*;

    #[test]
    fn api_key_catalog_has_no_bin_local_second_copy() {
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../credentials-module/src/bin/cli_support/api_key_login.rs"
        ));
        assert!(!source.contains("pub struct ApiKeyProvider"));
        assert!(!source.contains("pub const API_KEY_PROVIDERS"));
    }

    #[test]
    fn login_catalog_has_no_bin_local_second_copy() {
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../credentials-module/src/bin/credentials_cli.rs"
        ));
        assert!(!source.contains("struct LoginProvider"));
        assert!(!source.contains("fn login_provider("));
    }

    #[test]
    fn serves_assignments_are_exact_for_every_catalog_entry() {
        let api: Vec<_> = API_KEY_PROVIDERS
            .iter()
            .map(|entry| {
                (
                    entry.key,
                    entry
                        .serves
                        .iter()
                        .map(|value| value.as_str())
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        assert_eq!(
            api,
            vec![
                ("zai", vec!["zhipu"]),
                (
                    "openrouter",
                    ModelVendor::ALL.iter().map(|v| v.as_str()).collect()
                ),
                ("deepseek", vec!["deepseek"]),
                ("cerebras", vec!["meta", "qwen", "openai"]),
                (
                    "fireworks-ai",
                    vec!["meta", "qwen", "deepseek", "mistral", "openai"]
                ),
                (
                    "groq",
                    vec!["meta", "qwen", "openai", "moonshot", "mistral"]
                ),
                ("mistral", vec!["mistral"]),
                (
                    "together",
                    vec!["meta", "qwen", "deepseek", "mistral", "openai", "moonshot"]
                ),
                ("perplexity", vec!["perplexity"]),
                ("moonshot", vec!["moonshot"]),
                (
                    "huggingface",
                    vec!["meta", "qwen", "deepseek", "mistral", "openai", "moonshot", "zhipu"]
                ),
                (
                    "nvidia",
                    vec!["nvidia", "meta", "qwen", "deepseek", "mistral", "openai", "moonshot"]
                ),
                ("xai", vec!["xai"]),
                ("openai", vec!["openai"]),
                ("google", vec!["google"]),
            ]
        );
        let login: Vec<_> = LOGIN_PROVIDERS
            .iter()
            .map(|entry| {
                (
                    entry.default_id,
                    entry
                        .serves
                        .iter()
                        .map(|value| value.as_str())
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        assert_eq!(
            login,
            vec![
                ("oauth:anthropic", vec!["anthropic"]),
                ("chatgpt:openai", vec!["openai"]),
                ("oauth:xai", vec!["xai"]),
                (
                    "copilot:github",
                    vec!["openai", "anthropic", "google", "xai"]
                ),
                ("oauth:kimi", vec!["moonshot"]),
                ("oauth:google", vec!["google"]),
                ("antigravity:google", vec!["google", "anthropic", "openai"]),
                ("oauth:cursor", vec!["anthropic", "openai", "google", "xai"]),
                ("oauth:devin", vec![]),
                ("oauth:snowflake", vec![]),
                ("oauth:digitalocean", vec![]),
            ]
        );
    }
}
