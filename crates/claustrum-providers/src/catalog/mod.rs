//! Provider registries and the non-secret classification derived from credential ids.
//!
//! `categories` is authorization data: a mistaken value can widen a category grant.
//! `serves` is advisory consumer metadata: it never participates in authorization.

use crate::{google_login as google, refresh_adapters};
use ModelVendor::{Anthropic, Google, Meta, Moonshot, OpenAI, XAI};
#[cfg(test)]
use ModelVendor::{DeepSeek, Inception, MiniMax, Qwen, Zhipu};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CredentialCategory {
    LlmProvider,
    LlmGateway,
    DataWarehouse,
    CloudInfrastructure,
    /// Keys for web search APIs (Tavily, Kagi, Exa, Parallel, Brave, Firecrawl, Jina,
    /// TinyFish, SearXNG). Kept apart from `llm-provider` for search-only providers: every
    /// model consumer is granted `llm-provider`, and a search key filed there would reach
    /// all of them.
    WebSearch,
    MediaProvider,
    EmbeddingProvider,
}

impl CredentialCategory {
    pub const ALL: &[Self] = &[
        Self::LlmProvider,
        Self::LlmGateway,
        Self::DataWarehouse,
        Self::CloudInfrastructure,
        Self::WebSearch,
        Self::MediaProvider,
        Self::EmbeddingProvider,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LlmProvider => "llm-provider",
            Self::LlmGateway => "llm-gateway",
            Self::DataWarehouse => "data-warehouse",
            Self::CloudInfrastructure => "cloud-infrastructure",
            Self::WebSearch => "web-search",
            Self::MediaProvider => "media-provider",
            Self::EmbeddingProvider => "embedding-provider",
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
    MiniMax,
    Xiaomi,
    StepFun,
    /// Inception Labs, whose own model family is Mercury.
    Inception,
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
        Self::MiniMax,
        Self::Xiaomi,
        Self::StepFun,
        Self::Inception,
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
            Self::MiniMax => "minimax",
            Self::Xiaomi => "xiaomi",
            Self::StepFun => "stepfun",
            Self::Inception => "inception",
        }
    }
}

/// Provider identities used to resolve model-family routing aliases, not key offerings.
/// Qwen's model family is published under Alibaba; product-specific ids stay on rows.
pub const MODEL_VENDOR_FUSIFORM_IDS: &[(ModelVendor, &str)] = &[
    (ModelVendor::Anthropic, "anthropic"),
    (ModelVendor::OpenAI, "openai"),
    (ModelVendor::Google, "google"),
    (ModelVendor::XAI, "xai"),
    (ModelVendor::DeepSeek, "deepseek"),
    (ModelVendor::Mistral, "mistral"),
    (ModelVendor::Moonshot, "moonshotai"),
    (ModelVendor::Zhipu, "zhipuai"),
    (ModelVendor::Meta, "meta"),
    (ModelVendor::Qwen, "alibaba"),
    (ModelVendor::Perplexity, "perplexity"),
    (ModelVendor::Nvidia, "nvidia"),
    (ModelVendor::MiniMax, "minimax"),
    (ModelVendor::Xiaomi, "xiaomi"),
    (ModelVendor::StepFun, "stepfun-ai"),
    (ModelVendor::Inception, "inception"),
];

const LLM: &[CredentialCategory] = &[CredentialCategory::LlmProvider];
const LLM_AND_MEDIA: &[CredentialCategory] = &[
    CredentialCategory::LlmProvider,
    CredentialCategory::MediaProvider,
];
const MEDIA: &[CredentialCategory] = &[CredentialCategory::MediaProvider];
const LLM_AND_WEB_SEARCH: &[CredentialCategory] = &[
    CredentialCategory::LlmProvider,
    CredentialCategory::WebSearch,
];
const DATA_WAREHOUSE: &[CredentialCategory] = &[CredentialCategory::DataWarehouse];
const CLOUD_INFRASTRUCTURE: &[CredentialCategory] = &[CredentialCategory::CloudInfrastructure];
const WEB_SEARCH: &[CredentialCategory] = &[CredentialCategory::WebSearch];
const NO_CATEGORIES: &[CredentialCategory] = &[];

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthScheme {
    Bearer,
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct AuthDescriptor {
    pub header: &'static str,
    pub scheme: AuthScheme,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct InvalidKeyEvidence {
    pub status: u16,
    pub error_code: Option<&'static str>,
    /// RFC 6901 pointer to the observed string, present exactly when `error_code` is.
    pub error_code_field: Option<&'static str>,
}

const BEARER_AUTH: AuthDescriptor = AuthDescriptor {
    header: "authorization",
    scheme: AuthScheme::Bearer,
};

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
    /// Amazon Q's API-key GET requires `TokenType: API_KEY` as well as a bearer.
    /// Curl probes on 2026-10-06 with prefixed and malformed synthetic keys both
    /// returned 403 (AccessDeniedException header; body: "The bearer token included
    /// in the request is invalid."). CodeWhisperer ListAvailableProfiles instead
    /// returned 200 with empty profiles for an invalid key, so it cannot verify keys.
    AwsApiKeyGet { url: &'static str },
    /// Firecrawl's credit-usage read returns a documented, exact invalid-token error.
    FirecrawlCreditUsage { url: &'static str },
    /// TinyFish's wallet read returns a documented `INVALID_API_KEY` error code.
    TinyFishWallet { url: &'static str },
    GetEndpoint {
        url: &'static str,
        extra_headers: &'static [(&'static str, &'static str)],
    },
    /// Cloudflare Workers AI: `GET {api_base}/accounts/{account_id}/ai/models/search?per_page=1`
    /// with a Bearer token. Free and read-only, and unlike `/user/tokens/verify` (which
    /// account-owned tokens fail) it checks the token and the account pairing at once.
    /// The row must carry an `account_id_prompt`, since the account id is part of the URL.
    CloudflareWorkersAiModels { api_base: &'static str },
    /// The key is stored without any probe. Used where no check is possible without
    /// something this table cannot express (a provider-specific header, a per-deployment
    /// base URL, a model-denied response that must not count as a bad key), or where the
    /// provider has no endpoint that rejects a bad key. A probe that refuses a valid key
    /// blocks the login outright, which is worse than not checking. `reason` is printed
    /// at login so the operator knows the key was not verified and why.
    Unvalidated { reason: &'static str },
}

/// The accepted shape of a provider account id, checked at login before any network
/// call so a typo is refused locally instead of surfacing as a confusing provider error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountIdFormat {
    /// Exactly 32 lowercase hexadecimal characters: the shape of a Cloudflare account id.
    LowerHex32,
}

impl AccountIdFormat {
    pub fn accepts(self, value: &str) -> bool {
        match self {
            Self::LowerHex32 => {
                value.len() == 32
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }
        }
    }

    /// The shape in words, for the refusal message.
    pub const fn describe(self) -> &'static str {
        match self {
            Self::LowerHex32 => "32 lowercase hexadecimal characters (0-9, a-f)",
        }
    }
}

/// A second, NON-secret value some API-key logins need besides the key: the provider
/// account the key acts on. Login asks for it after the key, as visible input (or takes
/// `--account-id`), and stores it as the record's `identity.account_id`, which the read
/// surface serves to consumers on `credential.get_scoped` and `credential.list_scoped`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountIdPrompt {
    /// Shown in the interactive prompt; says where to find the value.
    pub label: &'static str,
    pub format: AccountIdFormat,
}

#[derive(Debug, Clone)]
pub struct ApiKeyProvider {
    pub key: &'static str,
    /// Published Fusiform provider id for joining display facts, independent of routing ids.
    /// `None` only for a row in `PENDING_FUSIFORM_PROVIDER_IDS`.
    pub fusiform_provider_id: Option<&'static str>,
    pub default_provider_ids: &'static [&'static str],
    pub display_name: &'static str,
    pub default_id: &'static str,
    pub dashboard_url: &'static str,
    pub placeholder: &'static str,
    pub auth: Option<AuthDescriptor>,
    pub hosts: &'static [&'static str],
    /// Provider documentation for the key presentation and fixed receiving hosts.
    pub hosts_doc: &'static str,
    /// Observation from a deliberately bogus key, not a rule evaluated by the vault.
    pub invalid_key: Option<InvalidKeyEvidence>,
    pub validation: KeyValidation,
    pub categories: &'static [CredentialCategory],
    pub serves: &'static [ModelVendor],
    /// `Some` only for providers whose key is unusable without an account id (Cloudflare
    /// Workers AI puts the account in every request path). Every other row is `None`.
    pub account_id_prompt: Option<AccountIdPrompt>,
}

/// Rows without a published Fusiform identity pending an upstream or search-service ruling.
/// Remove a row from this list when assigning its published id; mapped rows cannot stay here.
pub const PENDING_FUSIFORM_PROVIDER_IDS: &[(&str, &str)] = &[];

/// Reviewed Fusiform ids deliberately not carried by an API-key row, paired with
/// one of the reasons below. Unreviewed providers remain gaps, not automatic skips.
pub const FUSIFORM_PROVIDER_SKIPS: &[(&str, &str)] = &[
    // Bedrock API keys are bound to the AWS Region they were created in, and each Region
    // has its own bedrock-runtime host.
    (
        "amazon-bedrock",
        "a second secret or a per-account host in the style of Azure, Bedrock or Vertex",
    ),
    // Atomic Chat is a local desktop app with no hosted API or API key.
    ("atomic-chat", "no API key in its documentation"),
    // Azure OpenAI sends each key to its own resource's {resource}.openai.azure.com host.
    (
        "azure",
        "a second secret or a per-account host in the style of Azure, Bedrock or Vertex",
    ),
    // Azure Cognitive Services keys likewise belong to one resource and its host.
    (
        "azure-cognitive-services",
        "a second secret or a per-account host in the style of Azure, Bedrock or Vertex",
    ),
    // AI Gateway requests carry the Cloudflare account id and gateway id in the URL.
    (
        "cloudflare-ai-gateway",
        "a second secret or a per-account host in the style of Azure, Bedrock or Vertex",
    ),
    // Databricks model serving is reached through each workspace's own host.
    (
        "databricks",
        "a second secret or a per-account host in the style of Azure, Bedrock or Vertex",
    ),
    // Copilot takes a GitHub account token, not an inference key, and the Copilot runtime
    // uses it at a host chosen per account: github.com, or the enterprise's own hostname
    // under GitHub Enterprise Cloud with data residency.
    (
        "github-copilot",
        "a second secret or a per-account host in the style of Azure, Bedrock or Vertex",
    ),
    // GitLab Duo takes a GitLab token sent to the user's own instance (GitLab.com,
    // Self-Managed or Dedicated), which exchanges it for short-lived AI gateway tokens.
    (
        "gitlab",
        "a second secret or a per-account host in the style of Azure, Bedrock or Vertex",
    ),
    // Claude on Vertex AI is not offered in express mode, so it needs a Google Cloud project
    // and a regional host.
    (
        "google-vertex-anthropic",
        "a second secret or a per-account host in the style of Azure, Bedrock or Vertex",
    ),
    // Search does not select credentials by provider id. The same Kimi Code key keeps
    // its model-provider identity rather than adopting the separate search offering id.
    (
        "kimi-for-coding",
        "a web-search offering served by an existing model key row, which keeps its model identity",
    ),
    // LM Studio tokens belong to a local server at the user's own address and port,
    // not a fixed hosted API; authentication is optional on that server.
    (
        "lmstudio",
        "a user-hosted local server rather than a fixed provider API",
    ),
    // Lynkr is a self-hosted proxy. Its sk- placeholder is not a provider API key;
    // authentication to models happens with the configured upstream's credentials.
    ("lynkr", "no API key in its documentation"),
    // Modal proxy authentication needs both a token ID and token secret; dedicated
    // inference endpoints also have deployment-specific URLs.
    (
        "modal",
        "a second secret or a per-account host in the style of Azure, Bedrock or Vertex",
    ),
    // Neon AI Gateway tokens are sent to a branch-specific hostname.
    (
        "neon",
        "a second secret or a per-account host in the style of Azure, Bedrock or Vertex",
    ),
    // OCI Generative AI keys belong to one region and its regional inference host.
    (
        "oci",
        "a second secret or a per-account host in the style of Azure, Bedrock or Vertex",
    ),
    // OpenReason now documents telemetry ingestion, not a model API. Its ingestion
    // key does not authenticate model requests to an OpenReason inference service.
    ("openreason", "no API key in its documentation"),
    // QVAC serves its API from a local runtime at the user's chosen address and port.
    (
        "qvac",
        "a user-hosted local server rather than a fixed provider API",
    ),
    // SAP AI Core exchanges a client ID and client secret for an access token.
    (
        "sap-ai-core",
        "a second secret or a per-account host in the style of Azure, Bedrock or Vertex",
    ),
    // Cortex PATs are sent to the user's own <account-identifier>.snowflakecomputing.com.
    (
        "snowflake-cortex",
        "a second secret or a per-account host in the style of Azure, Bedrock or Vertex",
    ),
    // The organization guide issues the same Umans Code keys as the existing umans row.
    ("umans-ai", "a duplicate offering of an existing row"),
    // These services have closed or their documented API/documentation hosts no longer resolve.
    ("clarifai", "the service is discontinued or unreachable"),
    ("lilac", "the service is discontinued or unreachable"),
    ("llmtech", "the service is discontinued or unreachable"),
    ("neosmith", "the service is discontinued or unreachable"),
    ("routing-run", "the service is discontinued or unreachable"),
    // Public pages do not establish both where the key goes and how it is presented.
    (
        "ebcloud",
        "its public documentation does not name both the API host and the key header",
    ),
    (
        "hetzner",
        "its public documentation does not name both the API host and the key header",
    ),
    (
        "kuae-cloud-coding-plan",
        "its public documentation does not name both the API host and the key header",
    ),
    (
        "nova",
        "its public documentation does not name both the API host and the key header",
    ),
    (
        "qihang-ai",
        "its public documentation does not name both the API host and the key header",
    ),
    (
        "scnet-token-plan",
        "its public documentation does not name both the API host and the key header",
    ),
    (
        "scx-ai",
        "its public documentation does not name both the API host and the key header",
    ),
    (
        "tencent-coding-plan",
        "its public documentation does not name both the API host and the key header",
    ),
    (
        "tencent-token-plan",
        "its public documentation does not name both the API host and the key header",
    ),
    (
        "tencent-tokenhub",
        "its public documentation does not name both the API host and the key header",
    ),
    (
        "tokenrouter",
        "its public documentation does not name both the API host and the key header",
    ),
    (
        "vispark",
        "its public documentation does not name both the API host and the key header",
    ),
    // IBM Cloud API keys must first be exchanged for expiring IAM bearer tokens.
    (
        "watsonx",
        "the key is exchanged for a short-lived token before use",
    ),
];

/// The permitted dispositions for a provider researched but not added to the catalog.
pub const FUSIFORM_SKIP_REASONS: &[&str] = &[
    "OAuth only",
    "no API key in its documentation",
    "a duplicate offering of an existing row",
    "a second secret or a per-account host in the style of Azure, Bedrock or Vertex",
    "a user-hosted local server rather than a fixed provider API",
    "the service is discontinued or unreachable",
    "its public documentation does not name both the API host and the key header",
    "the key is exchanged for a short-lived token before use",
    "a web-search offering served by an existing model key row, which keeps its model identity",
];

mod rows;

pub use rows::API_KEY_PROVIDERS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    Xai,
    OpenAi,
    GithubCopilot,
    Kimi,
    Meta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeWire {
    AnthropicJson,
    RfcForm,
}

#[derive(Debug, Clone, Copy)]
pub struct LoginProvider {
    pub key: &'static str,
    /// The product name shown on a connector row, when the catalog knows it.
    pub connector_display_name: Option<&'static str>,
    /// A connectors-page category; group-based categories take precedence.
    pub connector_category: Option<&'static str>,
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
    /// A redirect the provider renders as a visible `code#state` instead of
    /// redirecting to a socket. Used ONLY when no loopback listener is bound, so an
    /// operator approving on another machine has something short to carry back.
    /// `None` means this provider has no such URL and paste stays address-bar shaped.
    pub code_redirect_uri: Option<&'static str>,
    /// The paste prompt for `code_redirect_uri`. Required when it is `Some`.
    pub code_paste_prompt: Option<&'static str>,
    pub device: Option<DeviceKind>,
    pub categories: &'static [CredentialCategory],
    pub serves: &'static [ModelVendor],
    /// Exact hosts a consumer may send this provider's access token to. The
    /// consumer's send check depends on this list not containing any other host.
    /// Sorted and unique; consumers must not interpret the order as a preference.
    pub hosts: &'static [&'static str],
    /// The catalog provider ids a fresh login stores when the operator passes no
    /// `--provider-id`. Only subscription logins whose routing id is settled name one;
    /// every other row is empty, and such a login stores no provider id unless the
    /// operator gives one. Kept on the row (rather than matched on the credential id)
    /// so the mapping lives in one place next to the ids it derives from.
    pub default_provider_ids: &'static [&'static str],
}

pub const LOGIN_PROVIDERS: &[LoginProvider] = &[
    LoginProvider {
        key: "anthropic",
        connector_display_name: Some("Claude"),
        connector_category: Some("ai_models"),
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
        // The only verified code-display redirect in this table: the same OAuth app
        // registers it, and the first-party anthropic-auth plugin uses it in
        // production with this client id.
        code_redirect_uri: Some(refresh_adapters::anthropic::LOGIN_CODE_REDIRECT_URI),
        code_paste_prompt: Some("After approving, the page shows a short code of the form code#state (a long code, a '#', then a shorter value).\nCopy the WHOLE thing, including the '#', and paste it here, then Enter:"),
        device: None,
        categories: LLM,
        serves: &[Anthropic],
        hosts: &["api.anthropic.com"],
        default_provider_ids: &["anthropic"],
    },
    LoginProvider {
        key: "openai",
        connector_display_name: Some("ChatGPT"),
        connector_category: Some("ai_models"),
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
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: Some(DeviceKind::OpenAi),
        categories: LLM,
        serves: &[OpenAI],
        hosts: &["chatgpt.com"],
        default_provider_ids: &["openai"],
    },
    LoginProvider {
        key: "xai",
        connector_display_name: Some("xAI Grok"),
        connector_category: Some("ai_models"),
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
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: Some(DeviceKind::Xai),
        categories: LLM,
        serves: &[XAI],
        hosts: &["api.x.ai"],
        default_provider_ids: &["xai"],
    },
    LoginProvider {
        key: "github-copilot",
        connector_display_name: Some("GitHub Copilot"),
        connector_category: Some("ai_models"),
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
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: Some(DeviceKind::GithubCopilot),
        categories: LLM,
        serves: &[OpenAI, Anthropic, Google, XAI],
        hosts: &[],
        default_provider_ids: &[],
    },
    LoginProvider {
        key: "kimi",
        connector_display_name: Some("Kimi"),
        connector_category: Some("ai_models"),
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
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: Some(DeviceKind::Kimi),
        categories: LLM,
        serves: &[Moonshot],
        hosts: &[],
        default_provider_ids: &[],
    },
    LoginProvider {
        key: "meta",
        connector_display_name: Some("Meta AI"),
        connector_category: Some("ai_models"),
        authorize_url: "",
        token_url: refresh_adapters::meta::DEVICE_TOKEN_URL,
        client_id: refresh_adapters::meta::CLIENT_ID,
        redirect_uri: "",
        scopes: &[],
        extra_authorize_params: &[],
        adapter_name: refresh_adapters::meta::ADAPTER_NAME,
        default_id: "oauth:meta",
        exchange: ExchangeWire::RfcForm,
        needs_oidc_nonce: false,
        exchange_echoes_challenge: false,
        paste_prompt: "",
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: Some(DeviceKind::Meta),
        categories: LLM,
        serves: &[Meta],
        hosts: &["api.meta.ai"],
        default_provider_ids: &["meta"],
    },
    LoginProvider {
        key: "google",
        connector_display_name: Some("Gemini"),
        connector_category: Some("ai_models"),
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
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: None,
        categories: LLM,
        serves: &[Google],
        hosts: &[],
        default_provider_ids: &[],
    },
    LoginProvider {
        key: "gmail",
        connector_display_name: Some("Gmail"),
        connector_category: Some("communication"),
        authorize_url: google::AUTHORIZE_URL,
        token_url: google::TOKEN_URL,
        client_id: "", // operator-owned Desktop client; supplied by the login flags
        redirect_uri: google::GMAIL_REDIRECT_URI,
        scopes: google::GMAIL_SCOPES,
        extra_authorize_params: google::AUTHORIZE_EXTRA_PARAMS,
        adapter_name: "gmail",
        default_id: "oauth:gmail",
        exchange: ExchangeWire::RfcForm,
        needs_oidc_nonce: false,
        exchange_echoes_challenge: false,
        paste_prompt: "Copy the FULL URL from the browser address bar and paste it here, then Enter:",
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: None,
        categories: NO_CATEGORIES,
        serves: &[],
        hosts: &[],
        default_provider_ids: &[],
    },
    LoginProvider {
        key: "antigravity",
        connector_display_name: Some("Antigravity"),
        connector_category: Some("ai_models"),
        authorize_url: google::AUTHORIZE_URL,
        token_url: google::TOKEN_URL,
        client_id: "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com",
        redirect_uri: google::ANTIGRAVITY_REDIRECT_URI,
        scopes: google::SCOPES,
        extra_authorize_params: google::AUTHORIZE_EXTRA_PARAMS,
        adapter_name: refresh_adapters::antigravity::ADAPTER_NAME,
        default_id: "antigravity:google",
        exchange: ExchangeWire::RfcForm,
        needs_oidc_nonce: false,
        exchange_echoes_challenge: false,
        paste_prompt: "After approving, the browser may fail to connect to 127.0.0.1:51121 — that is expected. Copy the FULL URL from the address bar and paste it here, then Enter:",
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: None,
        categories: LLM,
        serves: &[Google, Anthropic, OpenAI],
        hosts: &[
            "cloudcode-pa.googleapis.com",
            "daily-cloudcode-pa.googleapis.com",
        ],
        default_provider_ids: &["google"],
    },
    LoginProvider {
        key: "cursor",
        connector_display_name: Some("Cursor"),
        connector_category: Some("ai_models"),
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
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: None,
        categories: LLM,
        serves: &[Anthropic, OpenAI, Google, XAI],
        hosts: &[],
        default_provider_ids: &[],
    },
    LoginProvider {
        key: "devin",
        connector_display_name: Some("Devin"),
        connector_category: None,
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
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: None,
        categories: NO_CATEGORIES,
        serves: &[],
        hosts: &[],
        default_provider_ids: &[],
    },
    LoginProvider {
        key: "snowflake",
        connector_display_name: Some("Snowflake"),
        connector_category: None,
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
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: None,
        categories: DATA_WAREHOUSE,
        serves: &[],
        hosts: &[],
        default_provider_ids: &[],
    },
    LoginProvider {
        key: "digitalocean",
        connector_display_name: Some("DigitalOcean"),
        connector_category: None,
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
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: None,
        categories: CLOUD_INFRASTRUCTURE,
        serves: &[],
        hosts: &[],
        default_provider_ids: &[],
    },
];

pub fn api_key_provider(key: &str) -> Option<&'static ApiKeyProvider> {
    API_KEY_PROVIDERS.iter().find(|entry| entry.key == key)
}

pub fn login_provider(key: &str) -> Option<&'static LoginProvider> {
    LOGIN_PROVIDERS.iter().find(|entry| entry.key == key)
}

/// A login without a catalogued receiving host has no host fact to serve.
pub fn login_hosts(adapter: &str) -> Option<&'static [&'static str]> {
    LOGIN_PROVIDERS
        .iter()
        .find(|entry| entry.adapter_name == adapter && !entry.hosts.is_empty())
        .map(|entry| entry.hosts)
}

const LOGIN_CONDITIONS: &[(&str, &str, &[&str])] = &[
    (
        refresh_adapters::antigravity::ADAPTER_NAME,
        "provider_verification_required",
        &["accounts.google.com"],
    ),
    (
        refresh_adapters::antigravity::ADAPTER_NAME,
        "provider_ineligible",
        &[],
    ),
];

/// `None` means the adapter does not admit this reason. An empty host list means
/// the reason is admitted but cannot carry an action link.
pub fn condition_link_hosts(adapter: &str, reason: &str) -> Option<&'static [&'static str]> {
    LOGIN_CONDITIONS
        .iter()
        .find(|(name, admitted, _)| *name == adapter && *admitted == reason)
        .map(|(_, _, hosts)| *hosts)
}

#[cfg(test)]
#[test]
fn only_antigravity_admits_login_conditions() {
    let verification = "provider_verification_required";
    let ineligible = "provider_ineligible";
    assert_eq!(
        condition_link_hosts("antigravity", verification),
        Some(["accounts.google.com"].as_slice()),
    );
    assert_eq!(
        condition_link_hosts("antigravity", ineligible),
        Some([].as_slice())
    );
    assert_eq!(condition_link_hosts("antigravity", "future_reason"), None);
    for login in LOGIN_PROVIDERS
        .iter()
        .filter(|row| row.adapter_name != "antigravity")
    {
        assert_eq!(condition_link_hosts(login.adapter_name, verification), None);
        assert_eq!(condition_link_hosts(login.adapter_name, ineligible), None);
    }
}

/// Published providers still awaiting a reviewed row or skip, ordered by provider id.
/// Any API-key row carrying an id covers it, independent of its routing defaults.
pub fn missing_fusiform_providers() -> Vec<&'static crate::fusiform_providers::FusiformProvider> {
    uncovered_fusiform_providers(
        crate::fusiform_providers::fusiform_providers(),
        API_KEY_PROVIDERS,
        FUSIFORM_PROVIDER_SKIPS,
    )
}

fn uncovered_fusiform_providers<'a>(
    providers: &'a [crate::fusiform_providers::FusiformProvider],
    rows: &[ApiKeyProvider],
    skips: &[(&str, &str)],
) -> Vec<&'a crate::fusiform_providers::FusiformProvider> {
    let mut missing: Vec<_> = providers
        .iter()
        .filter(|provider| {
            !rows
                .iter()
                .any(|row| row.fusiform_provider_id == Some(provider.id.as_str()))
                && !skips.iter().any(|(id, _)| *id == provider.id)
        })
        .collect();
    missing.sort_by(|left, right| left.id.cmp(&right.id));
    missing
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

/// Resolve an API-key credential id, including labels, without matching login rows.
pub fn api_key_provider_for_credential(id: &str) -> Option<&'static ApiKeyProvider> {
    match catalog_match(id)? {
        CatalogEntry::ApiKey(entry) => Some(entry),
        CatalogEntry::Login(_) => None,
    }
}

/// The categories a credential is stamped with at creation.
///
/// Two kinds, and they answer different questions:
///
/// - A PURPOSE category (`llm-provider`, `data-warehouse`) says what a credential is FOR.
///   A consumer that needs any model provider grants on this.
/// - A NATIVE-FAMILY category (`<adapter>-native`) says whose PROTOCOL it speaks. A
///   consumer that sends tokens to one provider's own endpoints grants on this.
///
/// WHY BOTH EXIST. `llm-provider` covers sixteen credentials here; a consumer talking to
/// Anthropic's native endpoints can use four of them. Granting the purpose category to get
/// the four hands read authority over the other twelve, and no consumer-side filtering
/// reduces that — the capability is already issued. `serves` cannot substitute either: it
/// names the model vendors a credential can REACH, so `apikey:openrouter`,
/// `antigravity:google` and `oauth:cursor` all serve Anthropic models through protocols
/// that are not Anthropic's.
///
/// DERIVED FROM THE ID, NOT FROM THE RECORD, because stamping happens at creation and a
/// migration cannot decrypt. That is also why it covers FUTURE credentials with no
/// operator action: a new `oauth:anthropic:<account>` is stamped `anthropic-native` when
/// it is created. A static key gets no native category at all — it speaks no refresh
/// protocol, and inventing one would put `apikey:openrouter` in a family whose endpoints
/// would refuse it.
///
/// Underscores become hyphens because `valid_category_name` admits neither underscores nor
/// colons, so `github_app` stamps as `github-app-native`.
pub fn category_defaults(credential_id: &str) -> Vec<String> {
    if credential_id.starts_with("cookie:") {
        return vec!["browser-session".to_owned()];
    }
    let mut categories: Vec<String> = catalog_match(credential_id)
        .map(|entry| {
            entry
                .categories()
                .iter()
                .copied()
                .map(|category| CredentialCategory::as_str(category).to_owned())
                .collect()
        })
        .unwrap_or_default();
    if let Some(native) = native_family_category(credential_id) {
        categories.push(native);
    }
    categories
}

/// The `<adapter>-native` category for a credential that speaks a provider's own protocol,
/// or `None` for a static credential that speaks none.
///
/// Refuses to emit a name `valid_category_name` would reject rather than stamping
/// something the grant path cannot select on: a category nothing can name is worse than an
/// absent one, because it reads as coverage in `ck auth categories` and reaches nothing.
pub fn native_family_category(credential_id: &str) -> Option<String> {
    let parsed = crate::credential_id::parse_credential_id(credential_id);
    // THE METHOD MUST BE EXPLICIT. `default_refresh_adapter` treats a MISSING method as
    // legacy oauth, which is right for resolving an adapter on an old record and wrong
    // here: it would stamp `apple:notes` as `notes-native`, inventing a protocol family
    // for a static credential whose method we simply do not recognise. Claiming a
    // credential speaks someone's protocol is a claim that must come from a method we
    // actually parsed.
    let method = parsed.method?;
    let adapter =
        crate::credential_id::default_refresh_adapter(Some(method), parsed.provider.as_str())?;
    let candidate = format!("{}-native", adapter.replace('_', "-"));
    valid_category_name(&candidate).then_some(candidate)
}

pub fn serves_for(credential_id: &str) -> &'static [ModelVendor] {
    catalog_match(credential_id)
        .map(CatalogEntry::serves)
        .unwrap_or_default()
}

/// The catalog provider ids a fresh `ck auth login` or `put` stores when the operator
/// passes no `--provider-id`.
///
/// Labeled accounts share their provider's default through the same catalog
/// match that stamps categories, not through string matching on the id.
pub fn default_provider_ids(credential_id: &str) -> &'static [&'static str] {
    match catalog_match(credential_id) {
        Some(CatalogEntry::ApiKey(entry)) => entry.default_provider_ids,
        Some(CatalogEntry::Login(entry)) => entry.default_provider_ids,
        None => &[],
    }
}

/// The service name, not a routing provider id, from the category catalog match.
pub fn provider(credential_id: &str) -> Option<&'static str> {
    match catalog_match(credential_id)? {
        CatalogEntry::ApiKey(entry) => Some(entry.key),
        CatalogEntry::Login(entry) => Some(entry.key),
    }
}

/// Connector labels use the same boundary-aware matcher as catalog defaults.
pub fn connector_metadata(id: &str) -> (Option<&'static str>, Option<&'static str>) {
    match catalog_match(id) {
        Some(CatalogEntry::ApiKey(entry)) => (Some(entry.display_name), None),
        Some(CatalogEntry::Login(entry)) => {
            (entry.connector_display_name, entry.connector_category)
        }
        None => (None, None),
    }
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
        "kem" => "kem",
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
    #[test]
    fn antigravity_login_hosts_include_production_fallback_in_sorted_order() {
        assert_eq!(
            super::login_hosts("antigravity"),
            Some(
                [
                    "cloudcode-pa.googleapis.com",
                    "daily-cloudcode-pa.googleapis.com",
                ]
                .as_slice()
            )
        );
    }

    #[test]
    fn fusiform_catalog_has_no_unreviewed_gaps() {
        let missing: Vec<_> = missing_fusiform_providers()
            .into_iter()
            .map(|provider| provider.id.as_str())
            .collect();
        assert_eq!(missing, Vec::<&str>::new());
    }

    #[test]
    fn fusiform_kimi_search_offering_preserves_the_model_key_identity() {
        let row = api_key_provider("kimi-for-coding").unwrap();
        assert_eq!(row.fusiform_provider_id, Some("kimi-code-plan-global"));
        assert_eq!(row.default_provider_ids, ["kimi-code-plan-global"]);
        assert_eq!(row.hosts, ["api.kimi.ai", "api.kimi.com"]);
        assert_eq!(row.categories, LLM_AND_WEB_SEARCH);
        assert!(FUSIFORM_PROVIDER_SKIPS.contains(&(
            "kimi-for-coding",
            "a web-search offering served by an existing model key row, which keeps its model identity",
        )));

        let published: serde_json::Value =
            serde_json::from_slice(crate::fusiform_providers::FUSIFORM_PROVIDERS_JSON).unwrap();
        let search = published["providers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|provider| provider["id"] == "kimi-for-coding")
            .unwrap();
        assert_eq!(
            search,
            &serde_json::json!({
                "id": "kimi-for-coding",
                "name": "Kimi Code",
                "doc": "https://www.kimi.com/code/docs/kimi-code/membership.html",
                "source": "hand_kept",
                "kind": "web_search",
                "env": [],
                "output_modalities": [],
            })
        );
    }

    #[test]
    fn fusiform_gaps_exclude_any_carried_id_and_reviewed_skips() {
        let mut providers = crate::fusiform_providers::fusiform_providers()[..4].to_vec();
        for (provider, id) in providers
            .iter_mut()
            .zip(["z-gap", "covered", "skipped", "a-gap"])
        {
            provider.id = id.to_owned();
        }
        let mut pending = API_KEY_PROVIDERS[0].clone();
        pending.fusiform_provider_id = None;
        // Neither a matching row key nor routing defaults stand in for the display id.
        pending.key = "z-gap";
        pending.default_provider_ids = &["a-gap"];
        let mut carried = API_KEY_PROVIDERS[0].clone();
        carried.fusiform_provider_id = Some("covered");
        carried.default_provider_ids = &[];
        let rows = [pending, carried.clone(), carried];
        let missing = uncovered_fusiform_providers(&providers, &rows, &[("skipped", "OAuth only")]);
        assert_eq!(
            missing
                .iter()
                .map(|provider| provider.id.as_str())
                .collect::<Vec<_>>(),
            ["a-gap", "z-gap"]
        );
        assert!(uncovered_fusiform_providers(&[], &rows, &[]).is_empty());
    }

    fn assert_published_fusiform_ids(rows: &[ApiKeyProvider], pending: &[(&str, &str)]) {
        let published_ids: std::collections::BTreeSet<_> =
            crate::fusiform_providers::fusiform_providers()
                .iter()
                .map(|provider| provider.id.as_str())
                .collect();
        let mut pending_keys = std::collections::BTreeSet::new();
        for &(key, reason) in pending {
            assert!(pending_keys.insert(key), "duplicate pending row: {key}");
            assert!(
                matches!(
                    reason,
                    "pending_fusiform_decision" | "search_service_pending_ruling"
                ),
                "{key} has an unknown Fusiform pending reason: {reason}"
            );
            let Some(row) = rows.iter().find(|row| row.key == key) else {
                panic!("pending Fusiform row is not in the catalog: {key}");
            };
            assert!(
                row.fusiform_provider_id.is_none(),
                "pending Fusiform row already has an id: {key}"
            );
        }
        for row in rows {
            match row.fusiform_provider_id {
                Some(id) => assert!(
                    published_ids.contains(id),
                    "{} names an unknown Fusiform provider id: {id}",
                    row.key
                ),
                None => assert!(
                    pending_keys.contains(row.key),
                    "{} has no Fusiform provider id and is not pending",
                    row.key
                ),
            }
        }
    }

    #[test]
    fn api_key_rows_reference_published_fusiform_providers() {
        assert_published_fusiform_ids(API_KEY_PROVIDERS, PENDING_FUSIFORM_PROVIDER_IDS);
    }

    #[test]
    #[should_panic(expected = "names an unknown Fusiform provider id")]
    fn api_key_rows_reject_unknown_fusiform_provider_ids() {
        let mut row = API_KEY_PROVIDERS[0].clone();
        row.fusiform_provider_id = Some("not-a-published-fusiform-provider");
        assert_published_fusiform_ids(&[row], &[]);
    }

    #[test]
    #[should_panic(expected = "has no Fusiform provider id and is not pending")]
    fn api_key_rows_reject_missing_fusiform_ids_unless_pending() {
        let mut row = API_KEY_PROVIDERS[0].clone();
        row.fusiform_provider_id = None;
        assert_published_fusiform_ids(&[row], &[]);
    }

    #[test]
    #[should_panic(expected = "pending Fusiform row already has an id")]
    fn api_key_rows_reject_mapped_fusiform_ids_in_pending_list() {
        assert_published_fusiform_ids(
            std::slice::from_ref(&API_KEY_PROVIDERS[0]),
            &[("kiro", "pending_fusiform_decision")],
        );
    }

    #[test]
    #[should_panic(expected = "pending Fusiform row is not in the catalog")]
    fn api_key_rows_reject_unknown_keys_in_fusiform_pending_list() {
        assert_published_fusiform_ids(
            API_KEY_PROVIDERS,
            &[("not-a-catalog-key", "pending_fusiform_decision")],
        );
    }

    #[test]
    fn api_key_fusiform_ids_preserve_product_and_shared_provider_identities() {
        for (key, fusiform_id) in [
            ("zai", "zai-coding-plan"),
            ("together", "togetherai"),
            ("moonshot", "moonshotai"),
            ("anthropic", "anthropic"),
            ("abliteration", "abliteration-ai"),
            ("charm-hyper", "hyper"),
            ("cline-pass", "cline-pass"),
            ("firepass", "fireworks-fire-pass"),
            ("fireworks-ai", "fireworks-ai"),
            ("gmi-cloud", "gmicloud"),
            ("meta", "meta"),
            ("minimax-code", "minimax-coding-plan"),
            ("minimax-code-cn", "minimax-cn-coding-plan"),
            ("nanogpt", "nano-gpt"),
            ("novita", "novita-ai"),
            ("opencode-zen", "opencode"),
            ("umans", "umans-ai-coding-plan"),
            ("vercel-ai-gateway", "vercel"),
            ("wafer-serverless", "wafer.ai"),
            ("zhipu-coding-plan", "zhipuai-coding-plan"),
            ("kimi-for-coding", "kimi-code-plan-global"),
            ("kiro", "kiro"),
            ("qianfan", "qianfan"),
            ("qwen-portal", "qwen-portal"),
            ("typesafe", "typesafe"),
            ("yolo-auto", "yolo-auto"),
            ("singularityapi-dev", "singularityapi"),
            ("singularityapi-tech", "singularityapi-reserved"),
        ] {
            let Some(row) = api_key_provider(key) else {
                panic!("missing catalog row: {key}");
            };
            match row.fusiform_provider_id {
                Some(id) => assert_eq!(id, fusiform_id, "{key}"),
                None => panic!("{key} has no published Fusiform id"),
            }
        }
    }

    #[test]
    fn search_rows_match_their_published_fusiform_offerings() {
        let providers = crate::fusiform_providers::fusiform_providers();
        for (key, name, doc_host) in [
            ("brave", "Brave Search", "api-dashboard.search.brave.com"),
            ("exa", "Exa", "exa.ai"),
            ("firecrawl", "Firecrawl", "docs.firecrawl.dev"),
            ("jina", "Jina AI", "docs.jina.ai"),
            ("kagi", "Kagi", "kagi.com"),
            ("parallel", "Parallel", "docs.parallel.ai"),
            ("searxng", "SearXNG", "docs.searxng.org"),
            ("tavily", "Tavily", "docs.tavily.com"),
            ("tinyfish", "TinyFish", "docs.tinyfish.ai"),
        ] {
            let row = api_key_provider(key).unwrap();
            assert_eq!(row.fusiform_provider_id, Some(key), "{key}");
            let published = providers
                .iter()
                .find(|provider| Some(provider.id.as_str()) == row.fusiform_provider_id)
                .unwrap();
            assert_eq!(published.name, name, "{key}");
            let doc = url::Url::parse(&published.doc).unwrap();
            assert_eq!(doc.domain(), Some(doc_host), "{key}");
            assert_eq!(category_defaults(row.default_id), ["web-search"], "{key}");
        }
    }

    #[test]
    fn api_key_fusiform_ids_match_offering_host_domains() {
        fn provider_domain(host: &str) -> &str {
            let Some(subdomains) = host.rsplitn(3, '.').nth(2) else {
                return host;
            };
            &host[subdomains.len() + 1..]
        }

        const EXEMPTIONS: &[(&str, &str)] = &[
            ("byteplus", "BytePlus documents ModelArk on byteplus.com; its data plane uses bytepluses.com"),
            ("searxng", "SearXNG is self-hosted, with no fixed receiving host; its published name is checked separately"),
            ("kiro", "Kiro keys are sent to Amazon Q endpoints"),
            ("google", "AI Studio uses Google's separate API domain"),
            (
                "qianfan",
                "Baidu hosts Qianfan APIs on baidubce.com, not baidu.com",
            ),
            (
                "qwen-portal",
                "Qwen documents the portal on qwenlm.github.io; keys go to portal.qwen.ai",
            ),
            (
                "siliconflow-cn",
                "China API and provider documentation use different domains",
            ),
            (
                "minimax-code-cn",
                "China plan documentation and API use different MiniMax domains",
            ),
            (
                "vercel-ai-gateway",
                "Fusiform links GitHub documentation; gateway requests use vercel.sh",
            ),
            (
                "ainetcafe",
                "ainetcafe's guides send K3 keys to its API host, microquickjs.com",
            ),
            (
                "alibaba",
                "Alibaba Cloud documents Model Studio on alibabacloud.com; APIs use aliyuncs.com",
            ),
            (
                "alibaba-cn",
                "Alibaba Cloud documents Model Studio on alibabacloud.com; APIs use aliyuncs.com",
            ),
            (
                "alibaba-coding-plan",
                "Alibaba Cloud documents Coding Plan on alibabacloud.com; APIs use aliyuncs.com",
            ),
            (
                "alibaba-coding-plan-cn",
                "Alibaba Cloud documents Coding Plan on aliyun.com; APIs use aliyuncs.com",
            ),
            (
                "alibaba-token-plan",
                "Alibaba Cloud documents Token Plan on alibabacloud.com; APIs use aliyuncs.com",
            ),
            (
                "alibaba-token-plan-cn",
                "Alibaba Cloud documents Token Plan on alibabacloud.com; APIs use aliyuncs.com",
            ),
            (
                "bailing",
                "Ant Group documents Ling on yuque.com; keys go to api.ant-ling.com",
            ),
            (
                "bothub",
                "Bothub documents its API on bothub.ru; keys go to openai.bothub.chat",
            ),
            (
                "digitalocean",
                "DigitalOcean documents serverless inference on digitalocean.com; it runs on do-ai.run",
            ),
            (
                "edenai",
                "Eden AI documents its API on edenai.co; keys go to edenai.run",
            ),
            (
                "google-vertex",
                "Google documents Vertex AI on google.com; APIs use googleapis.com",
            ),
            (
                "io-net",
                "io.net documents IO Intelligence on io.net; its API runs on io.solutions",
            ),
            (
                "klokintegration",
                "Klok documents its API on klokintegration.se; keys go to the fixed ipaas.se gateway hosts",
            ),
            (
                "minimax-cn",
                "China API documentation uses minimaxi.com; the documented API runs on minimax.cn",
            ),
            (
                "mixlayer",
                "Mixlayer documents its API on mixlayer.com; inference uses mixlayer.ai",
            ),
            (
                "ovhcloud",
                "OVHcloud documents AI Endpoints on ovhcloud.com; inference uses the shared ovh.net host",
            ),
            (
                "pioneer",
                "Pioneer's documentation now directs API keys to Fastino's api.fastino.ai",
            ),
            (
                "prime",
                "Prime Intellect documents its inference API on the separate pinference.ai domain",
            ),
            (
                "qiniu-ai",
                "Qiniu documents its AI API on qiniu.com; keys go to api.qnaigc.com",
            ),
            (
                "salad-cloud",
                "Salad documents AI Gateway on salad.com; gateway keys go to ai.salad.cloud",
            ),
            (
                "standardcompute",
                "Standard Compute documents its API on standardcompute.com; keys go to stdcmpt.com",
            ),
            (
                "submodel",
                "Submodel documents InstaGen on GitBook; its guides send keys to submodel.ai and clawplay.world",
            ),
            (
                "thinkingmachines",
                "Thinking Machines documents Tinker on thinkingmachines.ai; inference uses thinkingmachines.dev",
            ),
            (
                "tokengo",
                "TokenGo's quickstart sends its keys to api.thorbase.com",
            ),
            (
                "volcengine",
                "Volcengine documents Ark on volcengine.com; its data plane uses volces.com",
            ),
            (
                "scaleway",
                "Scaleway documents Generative APIs on scaleway.com; keys go to api.scaleway.ai",
            ),
            (
                "stackit",
                "STACKIT documents model serving on stackit.cloud; its shared API uses onstackit.cloud",
            ),
            (
                "volcengine-coding-plan",
                "Volcengine documents Coding Plan on volcengine.com; its data plane uses volces.com",
            ),
        ];
        let mut unchecked_exemptions = std::collections::BTreeSet::new();
        for &(key, reason) in EXEMPTIONS {
            assert!(
                !reason.is_empty(),
                "{key} needs an offering-domain exemption reason"
            );
            assert!(
                unchecked_exemptions.insert(key),
                "duplicate offering-domain exemption: {key}"
            );
        }

        let providers = crate::fusiform_providers::fusiform_providers();
        for row in API_KEY_PROVIDERS {
            let Some(id) = row.fusiform_provider_id else {
                continue;
            };
            let Some(provider) = providers.iter().find(|provider| provider.id == id) else {
                panic!("{} names an unknown Fusiform provider: {id}", row.key);
            };
            let Ok(doc) = url::Url::parse(&provider.doc) else {
                panic!("{id} has an invalid documentation URL: {}", provider.doc);
            };
            let Some(doc_host) = doc.domain() else {
                panic!("{id} has no documentation domain: {}", provider.doc);
            };
            if unchecked_exemptions.remove(row.key) {
                continue;
            }
            assert!(
                row.hosts.iter().any(|host| provider_domain(host) == provider_domain(doc_host)),
                "{} maps to {id} with documentation host {doc_host}, outside its receiving host domains: {:?}",
                row.key,
                row.hosts
            );
        }
        assert!(
            unchecked_exemptions.is_empty(),
            "offering-domain exemptions must name mapped catalog rows: {unchecked_exemptions:?}"
        );
    }

    fn published_fusiform_ids() -> std::collections::BTreeSet<&'static str> {
        crate::fusiform_providers::fusiform_providers()
            .iter()
            .map(|provider| provider.id.as_str())
            .collect()
    }

    fn fusiform_skip_errors(
        rows: &[ApiKeyProvider],
        skips: &[(&str, &str)],
        document: &str,
    ) -> Vec<String> {
        let published = published_fusiform_ids();
        let mut errors = Vec::new();
        let mut expected = std::collections::BTreeMap::new();
        for row in rows {
            if let Some(id) = row.fusiform_provider_id {
                if !published.contains(id) {
                    errors.push(format!("unknown row Fusiform id: {id}"));
                }
            }
        }
        for &(id, reason) in skips {
            if !published.contains(id) {
                errors.push(format!("unknown skip Fusiform id: {id}"));
            }
            if rows.iter().any(|row| row.fusiform_provider_id == Some(id)) {
                errors.push(format!("Fusiform id is both skipped and carried: {id}"));
            }
            if !FUSIFORM_SKIP_REASONS.contains(&reason) {
                errors.push(format!("unapproved skip reason for {id}: {reason}"));
            }
            if expected.insert(id, reason).is_some() {
                errors.push(format!("duplicate Fusiform skip: {id}"));
            }
        }

        let mut lines = document
            .lines()
            .skip_while(|line| line.trim() != "| Fusiform id | reason |");
        if lines.next().is_none() {
            errors.push("missing Fusiform skip table".to_owned());
            return errors;
        }
        if lines.next().map(str::trim) != Some("| --- | --- |") {
            errors.push("malformed Fusiform skip table header".to_owned());
        }
        let mut documented = std::collections::BTreeMap::new();
        for line in lines.take_while(|line| line.starts_with('|')) {
            let columns: Vec<_> = line.trim_matches('|').split('|').map(str::trim).collect();
            if columns.len() != 2 {
                errors.push(format!("malformed Fusiform skip line: {line}"));
            } else if documented.insert(columns[0], columns[1]).is_some() {
                errors.push(format!(
                    "duplicate documented Fusiform skip: {}",
                    columns[0]
                ));
            }
        }
        if documented != expected {
            errors.push("Fusiform skip table differs from documented skips".to_owned());
        }
        errors
    }

    #[test]
    fn fusiform_skips_are_published_uncarried_and_documented() {
        assert_eq!(
            fusiform_skip_errors(
                API_KEY_PROVIDERS,
                FUSIFORM_PROVIDER_SKIPS,
                include_str!("../../../../docs/provider-key-evidence.md"),
            ),
            Vec::<String>::new()
        );
    }

    #[test]
    fn fusiform_skip_gate_rejects_unknown_ids_overlap_and_unapproved_reasons() {
        for (id, reason, expected) in [
            (
                "not-published",
                "OAuth only",
                "unknown skip Fusiform id: not-published",
            ),
            (
                "anthropic",
                "not researched",
                "unapproved skip reason for anthropic: not researched",
            ),
        ] {
            let document =
                format!("| Fusiform id | reason |\n| --- | --- |\n| {id} | {reason} |\n");
            assert_eq!(
                fusiform_skip_errors(&[], &[(id, reason)], &document),
                [expected]
            );
        }
        let mut row = API_KEY_PROVIDERS[0].clone();
        row.fusiform_provider_id = Some("anthropic");
        let document = "| Fusiform id | reason |\n| --- | --- |\n| anthropic | OAuth only |\n";
        assert_eq!(
            fusiform_skip_errors(
                std::slice::from_ref(&row),
                &[("anthropic", "OAuth only")],
                document
            ),
            ["Fusiform id is both skipped and carried: anthropic"]
        );
        row.fusiform_provider_id = Some("not-published");
        assert_eq!(
            fusiform_skip_errors(&[row], &[], "| Fusiform id | reason |\n| --- | --- |\n"),
            ["unknown row Fusiform id: not-published"]
        );
    }

    #[test]
    fn fusiform_skip_gate_checks_document_ids_reasons_and_duplicates() {
        let skips = &[("anthropic", "OAuth only")];
        let header = "| Fusiform id | reason |\n| --- | --- |\n";
        let entry = "| anthropic | OAuth only |\n";
        assert!(fusiform_skip_errors(&[], skips, &format!("{header}{entry}")).is_empty());
        for document in [
            header.to_owned(),
            format!("{header}| openai | OAuth only |\n"),
            format!("{header}| anthropic | no API key in its documentation |\n"),
            format!("{header}{entry}| openai | OAuth only |\n"),
        ] {
            assert_eq!(
                fusiform_skip_errors(&[], skips, &document),
                ["Fusiform skip table differs from documented skips"]
            );
        }
        assert_eq!(
            fusiform_skip_errors(&[], skips, &format!("{header}{entry}{entry}")),
            ["duplicate documented Fusiform skip: anthropic"]
        );
        assert_eq!(
            fusiform_skip_errors(&[], &[skips[0], skips[0]], &format!("{header}{entry}")),
            ["duplicate Fusiform skip: anthropic"]
        );
        assert_eq!(
            fusiform_skip_errors(&[], &[], ""),
            ["missing Fusiform skip table"]
        );
    }

    fn fusiform_vendor_mapping_errors(mapping: &[(ModelVendor, &str)]) -> Vec<String> {
        let published = published_fusiform_ids();
        let mut seen = std::collections::BTreeSet::new();
        let mut errors = Vec::new();
        for &(vendor, id) in mapping {
            if !seen.insert(vendor) {
                errors.push(format!(
                    "duplicate Fusiform mapping for {}",
                    vendor.as_str()
                ));
            }
            if !published.contains(id) {
                errors.push(format!("unknown vendor Fusiform id: {id}"));
            }
        }
        for vendor in ModelVendor::ALL {
            if !seen.contains(vendor) {
                errors.push(format!("unmapped ModelVendor: {}", vendor.as_str()));
            }
        }
        errors
    }

    #[test]
    fn fusiform_vendor_mapping_covers_every_vendor_with_a_published_id() {
        assert_eq!(
            fusiform_vendor_mapping_errors(MODEL_VENDOR_FUSIFORM_IDS),
            Vec::<String>::new()
        );
    }

    #[test]
    fn fusiform_vendor_mapping_gate_rejects_missing_unknown_and_duplicate_entries() {
        let mut mapping = MODEL_VENDOR_FUSIFORM_IDS.to_vec();
        mapping.remove(0);
        assert_eq!(
            fusiform_vendor_mapping_errors(&mapping),
            ["unmapped ModelVendor: anthropic"]
        );
        mapping.insert(0, (Anthropic, "not-published"));
        assert_eq!(
            fusiform_vendor_mapping_errors(&mapping),
            ["unknown vendor Fusiform id: not-published"]
        );
        mapping[0].1 = "anthropic";
        mapping.push(mapping[0]);
        assert_eq!(
            fusiform_vendor_mapping_errors(&mapping),
            ["duplicate Fusiform mapping for anthropic"]
        );
    }

    fn fusiform_routing_resolutions(
        api_rows: &[ApiKeyProvider],
        login_rows: &[LoginProvider],
        mapping: &[(ModelVendor, &str)],
    ) -> Result<std::collections::BTreeMap<String, String>, Vec<String>> {
        let published = published_fusiform_ids();
        let mut vendors_by_id: std::collections::BTreeMap<_, std::collections::BTreeSet<_>> =
            std::collections::BTreeMap::new();
        for (ids, vendors) in api_rows
            .iter()
            .map(|row| (row.default_provider_ids, row.serves))
            .chain(
                login_rows
                    .iter()
                    .map(|row| (row.default_provider_ids, row.serves)),
            )
        {
            for &id in ids {
                vendors_by_id.entry(id).or_default().extend(vendors);
            }
        }
        let mut resolutions = std::collections::BTreeMap::new();
        let mut errors = Vec::new();
        for (id, vendors) in vendors_by_id {
            // A published provider id resolves directly, even on a multi-vendor row.
            if published.contains(id) {
                continue;
            }
            let mut targets = std::collections::BTreeSet::new();
            for vendor in vendors {
                if let Some((_, target)) = mapping.iter().find(|(value, _)| *value == vendor) {
                    targets.insert(*target);
                } else {
                    errors.push(format!(
                        "{id} serves unmapped ModelVendor: {}",
                        vendor.as_str()
                    ));
                }
            }
            if targets.len() != 1 {
                errors.push(format!(
                    "{id} must resolve to exactly one Fusiform id, got {targets:?}"
                ));
            } else {
                resolutions.insert(id.to_owned(), targets.first().unwrap().to_string());
            }
        }
        if errors.is_empty() {
            Ok(resolutions)
        } else {
            Err(errors)
        }
    }

    #[test]
    fn fusiform_routing_gate_resolves_both_catalogs_and_pins_every_alias() {
        let actual = fusiform_routing_resolutions(
            API_KEY_PROVIDERS,
            LOGIN_PROVIDERS,
            MODEL_VENDOR_FUSIFORM_IDS,
        )
        .unwrap_or_else(|errors| panic!("unresolvable catalog routing ids: {errors:?}"));
        let expected: std::collections::BTreeMap<String, String> =
            serde_json::from_str(include_str!(
                "../../../credentials-core/tests/fixtures/fusiform/routing-resolution.json"
            ))
            .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn fusiform_routing_gate_uses_all_serves_across_both_catalogs() {
        let mut api = API_KEY_PROVIDERS[0].clone();
        api.default_provider_ids = &["test-alias"];
        api.serves = &[Anthropic];
        let mut login = LOGIN_PROVIDERS[0];
        login.default_provider_ids = &["test-alias"];
        login.serves = &[OpenAI];
        assert_eq!(
            fusiform_routing_resolutions(&[api.clone()], &[login], MODEL_VENDOR_FUSIFORM_IDS),
            Err(vec!["test-alias must resolve to exactly one Fusiform id, got {\"anthropic\", \"openai\"}".to_owned()])
        );
        assert_eq!(
            fusiform_routing_resolutions(&[], &[login], MODEL_VENDOR_FUSIFORM_IDS).unwrap(),
            [("test-alias".to_owned(), "openai".to_owned())].into()
        );
        // Distinct model vendors are allowed when their mapped provider identity is the same.
        assert_eq!(
            fusiform_routing_resolutions(
                &[api],
                &[login],
                &[(Anthropic, "anthropic"), (OpenAI, "anthropic")],
            )
            .unwrap(),
            [("test-alias".to_owned(), "anthropic".to_owned())].into()
        );
    }

    #[test]
    fn fusiform_routing_gate_rejects_empty_or_unmapped_serves_but_accepts_direct_ids() {
        let mut row = API_KEY_PROVIDERS[0].clone();
        row.default_provider_ids = &["test-alias"];
        row.serves = &[];
        assert_eq!(
            fusiform_routing_resolutions(
                std::slice::from_ref(&row),
                &[],
                MODEL_VENDOR_FUSIFORM_IDS
            ),
            Err(vec![
                "test-alias must resolve to exactly one Fusiform id, got {}".to_owned()
            ])
        );
        row.serves = &[Anthropic, OpenAI];
        assert_eq!(
            fusiform_routing_resolutions(std::slice::from_ref(&row), &[], &[(OpenAI, "openai")]),
            Err(vec![
                "test-alias serves unmapped ModelVendor: anthropic".to_owned()
            ])
        );
        row.default_provider_ids = &["openai"];
        assert!(fusiform_routing_resolutions(&[row], &[], &[])
            .unwrap()
            .is_empty());
    }

    const NO_DESCRIPTORS: &[(&str, &str)] = &[
        (
            "kagi",
            "Kagi's API portal documents Authorization: Bot <key>, not Bearer or a raw key",
        ),
        (
            "searxng",
            "SearXNG is self-hosted, with instance-specific authentication and hosts",
        ),
    ];

    fn canonical_host(host: &str) -> bool {
        !host.is_empty()
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                    && label.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
    }

    fn canonical_header(header: &str) -> bool {
        !header.is_empty()
            && header.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&b)
            })
    }

    fn check_url(validation: &KeyValidation) -> Option<&str> {
        match validation {
            KeyValidation::OpenAiChat { base_url, .. }
            | KeyValidation::AnthropicMessages { base_url, .. } => Some(base_url),
            KeyValidation::AwsApiKeyGet { url }
            | KeyValidation::FirecrawlCreditUsage { url }
            | KeyValidation::TinyFishWallet { url }
            | KeyValidation::GetEndpoint { url, .. } => Some(url),
            KeyValidation::CloudflareWorkersAiModels { api_base } => Some(api_base),
            KeyValidation::Unvalidated { .. } => None,
        }
    }

    fn row_model_errors(row: &ApiKeyProvider) -> Vec<&'static str> {
        let mut errors = Vec::new();
        let exempt = NO_DESCRIPTORS.iter().any(|(key, _)| *key == row.key);
        if row.hosts.is_empty() && !exempt {
            errors.push("empty hosts");
        }
        if !row.hosts.iter().all(|host| canonical_host(host)) {
            errors.push("non-canonical host");
        }
        if !row.hosts.windows(2).all(|pair| pair[0] < pair[1]) {
            errors.push("unsorted or duplicate hosts");
        }
        match row.auth {
            Some(auth) if !canonical_header(auth.header) => errors.push("non-canonical header"),
            None if !exempt => errors.push("missing auth"),
            _ => {}
        }
        if row.auth.is_none() && !matches!(row.validation, KeyValidation::Unvalidated { .. }) {
            errors.push("checked row without auth");
        }
        if !row.hosts_doc.starts_with("https://")
            || !url::Url::parse(row.hosts_doc)
                .is_ok_and(|url| url.scheme() == "https" && url.host_str().is_some())
        {
            errors.push("non-https documentation");
        }
        if let Some(url) = check_url(&row.validation) {
            if !url::Url::parse(url)
                .is_ok_and(|url| url.host_str().is_some_and(|host| row.hosts.contains(&host)))
            {
                errors.push("check host outside hosts");
            }
        }
        errors
    }

    #[test]
    fn api_key_row_hosts_and_auth_are_canonical_and_cover_checks() {
        for row in API_KEY_PROVIDERS {
            assert_eq!(row_model_errors(row), Vec::<&str>::new(), "{}", row.key);
        }
        let no_auth: Vec<_> = API_KEY_PROVIDERS
            .iter()
            .filter(|row| row.auth.is_none())
            .map(|row| row.key)
            .collect();
        assert_eq!(
            no_auth
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>(),
            NO_DESCRIPTORS
                .iter()
                .map(|(key, _)| *key)
                .collect::<std::collections::BTreeSet<_>>()
        );
        assert_eq!(no_auth.len(), NO_DESCRIPTORS.len());
        assert!(NO_DESCRIPTORS.iter().all(|(_, reason)| !reason.is_empty()));
    }

    #[test]
    fn api_key_row_host_gate_refuses_each_malformed_shape() {
        let original = api_key_provider("openai").unwrap();
        const BAD_HOSTS: &[&[&str]] = &[
            &[],
            &["API.openai.com"],
            &["api.openai.com:443"],
            &["https://api.openai.com"],
            &["api.openai.com/path"],
            &["*.openai.com"],
            &["api.openai.com."],
            &["api..openai.com"],
            &["other.example"],
            &["z.example", "api.openai.com"],
            &["api.openai.com", "api.openai.com"],
        ];
        for &hosts in BAD_HOSTS {
            let mut row = original.clone();
            row.hosts = hosts;
            assert!(!row_model_errors(&row).is_empty(), "accepted {hosts:?}");
        }
        for header in [
            "",
            "Authorization",
            "x api key",
            "x-api-key:",
            "x-api-key\n",
        ] {
            let mut row = original.clone();
            row.auth = Some(AuthDescriptor {
                header,
                scheme: AuthScheme::Raw,
            });
            assert!(row_model_errors(&row).contains(&"non-canonical header"));
        }
        for doc in ["http://docs.example", "not a URL", "https:opaque"] {
            let mut row = original.clone();
            row.hosts_doc = doc;
            assert!(row_model_errors(&row).contains(&"non-https documentation"));
        }
        let mut row = original.clone();
        row.auth = None;
        assert!(row_model_errors(&row).contains(&"missing auth"));
        row.validation = KeyValidation::Unvalidated { reason: "test" };
        assert!(row_model_errors(&row).contains(&"missing auth"));
        row = api_key_provider("kagi").unwrap().clone();
        row.validation = original.validation.clone();
        assert!(row_model_errors(&row).contains(&"checked row without auth"));
    }

    fn valid_json_pointer(pointer: &str) -> bool {
        if !pointer.is_empty() && !pointer.starts_with('/') {
            return false;
        }
        let mut chars = pointer.chars();
        while let Some(c) = chars.next() {
            if c == '~' && !matches!(chars.next(), Some('0' | '1')) {
                return false;
            }
        }
        true
    }

    fn evidence_errors(document: &str, rows: &[ApiKeyProvider]) -> Vec<String> {
        let mut errors = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut lines = document.lines().skip_while(|line| {
            line.trim() != "| row | url | date | status | error_code | code field |"
        });
        if lines.next().is_none() {
            return vec!["missing evidence table".to_string()];
        }
        lines.next();
        for line in lines.take_while(|line| line.starts_with('|')) {
            let columns: Vec<_> = line.trim_matches('|').split('|').map(str::trim).collect();
            if columns.len() != 6 {
                errors.push(format!("bad evidence line: {line}"));
                continue;
            }
            let key = columns[0];
            if !seen.insert(key) {
                errors.push(format!("duplicate evidence: {key}"));
            }
            let Some(row) = rows.iter().find(|row| row.key == key) else {
                errors.push(format!("unknown evidence row: {key}"));
                continue;
            };
            let Some(evidence) = row.invalid_key else {
                errors.push(format!("unexpected evidence: {key}"));
                continue;
            };
            if columns[3].parse::<u16>().ok() != Some(evidence.status)
                || columns[4] != evidence.error_code.unwrap_or("-")
                || columns[5] != evidence.error_code_field.unwrap_or("-")
            {
                errors.push(format!("differing evidence: {key}"));
            }
            if !url::Url::parse(columns[1])
                .is_ok_and(|url| url.host_str().is_some_and(|host| row.hosts.contains(&host)))
            {
                errors.push(format!("evidence host outside hosts: {key}"));
            }
        }
        for row in rows {
            if let Some(evidence) = row.invalid_key {
                if !seen.contains(row.key) {
                    errors.push(format!("missing evidence: {}", row.key));
                }
                if evidence.error_code.is_some() != evidence.error_code_field.is_some()
                    || evidence
                        .error_code_field
                        .is_some_and(|pointer| !valid_json_pointer(pointer))
                {
                    errors.push(format!("invalid code pointer pair: {}", row.key));
                }
            }
        }
        errors
    }

    #[test]
    fn api_key_invalid_key_evidence_matches_recorded_lines() {
        assert_eq!(
            evidence_errors(
                include_str!("../../../../docs/provider-key-evidence.md"),
                API_KEY_PROVIDERS
            ),
            Vec::<String>::new()
        );
    }

    #[test]
    fn api_key_evidence_gate_refuses_missing_extra_duplicate_and_differing_lines() {
        let header = "| row | url | date | status | error_code | code field |\n| --- | --- | --- | --- | --- | --- |\n";
        let line = "| openai | https://api.openai.com/v1/models | 2026-11-10 | 401 | invalid_api_key | /error/code |\n";
        let mut row = api_key_provider("openai").unwrap().clone();
        row.invalid_key = Some(InvalidKeyEvidence {
            status: 401,
            error_code: Some("invalid_api_key"),
            error_code_field: Some("/error/code"),
        });
        let document = format!("{header}{line}");
        assert!(evidence_errors(&document, std::slice::from_ref(&row)).is_empty());
        for bad in [
            header.to_string(),
            format!("{document}{line}"),
            document.replace("401", "403"),
            document.replace("invalid_api_key", "other"),
            document.replace("/error/code", "/code"),
            document.replace("api.openai.com", "other.example"),
        ] {
            assert!(
                !evidence_errors(&bad, std::slice::from_ref(&row)).is_empty(),
                "accepted {bad}"
            );
        }
        for pair in [
            (None, Some("/error/code")),
            (Some("invalid_api_key"), None),
            (Some("invalid_api_key"), Some("/error/~2code")),
        ] {
            row.invalid_key.as_mut().unwrap().error_code = pair.0;
            row.invalid_key.as_mut().unwrap().error_code_field = pair.1;
            let matching_line = format!(
                "{header}| openai | https://api.openai.com/v1/models | 2026-11-10 | 401 | {} | {} |\n",
                pair.0.unwrap_or("-"), pair.1.unwrap_or("-")
            );
            assert!(evidence_errors(&matching_line, std::slice::from_ref(&row))
                .contains(&"invalid code pointer pair: openai".to_string()));
        }
        row.invalid_key = None;
        assert!(!evidence_errors(&document, &[row]).is_empty());
        assert!(valid_json_pointer("/a~0b/c~1d"));
        assert!(valid_json_pointer(""));
        assert!(!valid_json_pointer("error/code"));
    }
    use std::collections::{BTreeSet, HashSet};

    use super::*;

    #[test]
    fn catalog_entry_expectations_are_separate_from_no_match_expectations() {
        let entry_rows = [
            ("apikey:zai", vec!["llm-provider", "web-search"]),
            ("apikey:openrouter", vec!["llm-provider"]),
            ("oauth:anthropic", vec!["llm-provider", "anthropic-native"]),
            (
                "oauth:anthropic:fourth",
                vec!["llm-provider", "anthropic-native"],
            ),
            ("chatgpt:openai", vec!["llm-provider", "openai-native"]),
            (
                "oauth:snowflake",
                vec!["data-warehouse", "snowflake-native"],
            ),
            (
                "oauth:digitalocean",
                vec!["cloud-infrastructure", "digitalocean-native"],
            ),
            (
                "copilot:github",
                vec!["llm-provider", "github-copilot-native"],
            ),
            ("oauth:cursor", vec!["llm-provider", "cursor-native"]),
            ("oauth:devin", vec!["devin-native"]),
        ];
        for (id, expected) in &entry_rows {
            assert!(
                catalog_match(id).is_some(),
                "entry row became a no-match row: {id}"
            );
            assert_eq!(category_defaults(id), *expected, "entry row {id}");
        }
        let non_empty: BTreeSet<Vec<String>> = entry_rows
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

        // Cookie defaults are a family rule, independent of either provider catalog.
        for id in [
            "cookie:example.com:me",
            "cookie:x",
            "cookie:oauth:anthropic",
        ] {
            assert_eq!(
                category_defaults(id),
                ["browser-session"],
                "cookie row {id}"
            );
        }
        for id in ["apikey:zai-work", "apikey:apns-alfonso", "apple:notes"] {
            assert!(
                catalog_match(id).is_none(),
                "no-match row counted as an entry: {id}"
            );
            assert!(category_defaults(id).is_empty());
        }
    }

    #[test]
    fn kiro_api_key_catalog_entry_is_llm_provider() {
        let row = api_key_provider("kiro").expect("Kiro api-key row");
        assert_eq!(row.default_id, "apikey:kiro");
        assert_eq!(row.display_name, "Kiro");
        assert_eq!(row.dashboard_url, "https://app.kiro.dev");
        assert_eq!(row.placeholder, "ksk_...");
        assert_eq!(category_defaults("apikey:kiro"), ["llm-provider"]);
        assert_eq!(category_defaults("apikey:kiro:work"), ["llm-provider"]);
        assert_eq!(row.serves, &[Anthropic, DeepSeek, Qwen, Zhipu, MiniMax]);
        assert_eq!(
            row.validation,
            KeyValidation::AwsApiKeyGet {
                url: "https://q.us-east-1.amazonaws.com/ListAvailableModels?origin=AI_EDITOR",
            }
        );
    }

    /// `--provider inception` must find this row, stamp new keys `llm-provider` and
    /// nothing else, and probe with a chat completion. The model listing cannot be the
    /// probe: it answers 200 even without a key, so every key would pass.
    #[test]
    fn inception_api_key_catalog_entry_is_llm_provider_and_probed_by_chat() {
        let row = api_key_provider("inception").expect("Inception api-key row");
        assert_eq!(row.default_id, "apikey:inception");
        assert_eq!(
            row.dashboard_url,
            "https://platform.inceptionlabs.ai/dashboard/api-keys"
        );
        assert_eq!(row.categories, LLM);
        assert_eq!(category_defaults("apikey:inception"), ["llm-provider"]);
        assert_eq!(category_defaults("apikey:inception:work"), ["llm-provider"]);
        assert_eq!(row.serves, &[Inception]);
        assert_eq!(serves_for("apikey:inception"), &[Inception]);
        assert_eq!(
            row.validation,
            KeyValidation::OpenAiChat {
                base_url: "https://api.inceptionlabs.ai/v1",
                model: "mercury-2",
            }
        );
    }

    #[test]
    fn byteplus_api_key_row_uses_documented_bearer_chat_and_records_the_auth_refusal() {
        let row = api_key_provider("byteplus").expect("BytePlus api-key row");
        assert_eq!(row.fusiform_provider_id, Some("byteplus"));
        assert_eq!(row.default_id, "apikey:byteplus");
        assert_eq!(row.default_provider_ids, ["byteplus"]);
        assert_eq!(row.display_name, "BytePlus ModelArk");
        assert_eq!(row.auth, Some(BEARER_AUTH));
        assert_eq!(row.hosts, ["ark.ap-southeast.bytepluses.com"]);
        assert_eq!(
            row.hosts_doc,
            "https://docs.byteplus.com/en/docs/ModelArk/1298459"
        );
        assert_eq!(
            row.dashboard_url,
            "https://ai.byteplus.com/ark/region:ap-southeast-1/apiKey"
        );
        assert_eq!(row.categories, LLM);
        assert_eq!(category_defaults("apikey:byteplus"), ["llm-provider"]);
        assert_eq!(category_defaults("apikey:byteplus:work"), ["llm-provider"]);
        assert!(row.serves.is_empty());
        assert!(row.account_id_prompt.is_none());
        assert_eq!(
            row.invalid_key,
            Some(InvalidKeyEvidence {
                status: 401,
                error_code: Some("AuthenticationError"),
                error_code_field: Some("/error/code"),
            })
        );
        assert_eq!(
            row.validation,
            KeyValidation::OpenAiChat {
                base_url: "https://ark.ap-southeast.bytepluses.com/api/v3",
                model: "seed-2-0-lite-260228",
            }
        );
    }

    /// `--provider cloudflare-workers-ai` must find this row, stamp new tokens
    /// `llm-provider` only, probe the account-scoped model search, and ask for an account
    /// id in Cloudflare's shape. It is the only row that asks for one.
    #[test]
    fn cloudflare_workers_ai_row_is_llm_provider_and_asks_for_a_hex_account_id() {
        let row = api_key_provider("cloudflare-workers-ai").expect("Cloudflare api-key row");
        assert_eq!(row.default_id, "apikey:cloudflare-workers-ai");
        assert_eq!(row.display_name, "Cloudflare Workers AI");
        assert_eq!(
            row.dashboard_url,
            "https://dash.cloudflare.com/profile/api-tokens"
        );
        assert!(row.placeholder.contains("Workers AI"));
        assert!(row.placeholder.contains("not the Global API Key"));
        assert_eq!(row.categories, LLM);
        assert_eq!(
            category_defaults("apikey:cloudflare-workers-ai"),
            ["llm-provider"]
        );
        assert_eq!(
            category_defaults("apikey:cloudflare-workers-ai:work"),
            ["llm-provider"]
        );
        assert_eq!(
            row.validation,
            KeyValidation::CloudflareWorkersAiModels {
                api_base: "https://api.cloudflare.com/client/v4",
            }
        );
        let prompt = row.account_id_prompt.expect("asks for an account id");
        assert_eq!(prompt.format, AccountIdFormat::LowerHex32);
        let with_prompt: Vec<_> = API_KEY_PROVIDERS
            .iter()
            .filter(|entry| entry.account_id_prompt.is_some())
            .map(|entry| entry.key)
            .collect();
        assert_eq!(with_prompt, ["cloudflare-workers-ai"]);
    }

    #[test]
    fn lower_hex_32_accepts_only_a_cloudflare_shaped_account_id() {
        let format = AccountIdFormat::LowerHex32;
        assert!(format.accepts("0123456789abcdef0123456789abcdef"));
        for bad in [
            "",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcdeg",
            " 0123456789abcdef0123456789abcde",
            "0123456789abcdef-123456789abcdef",
        ] {
            assert!(!format.accepts(bad), "accepted {bad:?}");
        }
    }

    #[test]
    fn api_key_routing_ids_match_the_reviewed_table() {
        let expected: &[(&str, &[&str])] = &[
            ("kiro", &[]),
            ("zai", &["zai-coding-plan"]),
            ("openrouter", &["openrouter"]),
            ("deepseek", &["deepseek"]),
            ("cerebras", &["cerebras"]),
            ("fireworks-ai", &["fireworks-ai"]),
            ("groq", &["groq"]),
            ("mistral", &["mistral"]),
            ("together", &["togetherai"]),
            ("perplexity", &["perplexity"]),
            ("moonshot", &["moonshotai"]),
            ("huggingface", &["huggingface"]),
            ("nvidia", &["nvidia"]),
            ("xai", &["xai"]),
            ("openai", &["openai"]),
            ("google", &["google"]),
            ("anthropic", &["anthropic-platform"]),
            ("inception", &["inception"]),
            ("cloudflare-workers-ai", &["cloudflare-workers-ai"]),
            ("abliteration", &["abliteration-ai"]),
            ("aiand", &["aiand"]),
            ("baseten", &["baseten"]),
            ("charm-hyper", &["hyper"]),
            ("cline-pass", &[]),
            ("commandcode", &["commandcode"]),
            ("deepinfra", &["deepinfra"]),
            ("firepass", &[]),
            ("gmi-cloud", &["gmicloud"]),
            ("meta", &[]),
            ("minimax-code", &["minimax-coding-plan"]),
            ("minimax-code-cn", &["minimax-cn-coding-plan"]),
            ("nanogpt", &["nano-gpt"]),
            ("novita", &["novita-ai"]),
            ("ollama-cloud", &["ollama-cloud"]),
            ("opencode-go", &["opencode-go"]),
            ("opencode-zen", &["opencode"]),
            ("qianfan", &[]),
            ("qwen-portal", &[]),
            ("sakana", &["sakana"]),
            ("siliconflow", &["siliconflow"]),
            ("siliconflow-cn", &["siliconflow-cn"]),
            ("singularityapi-dev", &[]),
            ("singularityapi-tech", &[]),
            ("stepfun", &["stepfun-ai"]),
            ("synthetic", &["synthetic"]),
            ("typesafe", &["typesafe"]),
            ("umans", &["umans-ai-coding-plan"]),
            ("venice", &["venice"]),
            ("vercel-ai-gateway", &["vercel"]),
            ("wafer-serverless", &[]),
            ("xiaomi-token-plan-ams", &["xiaomi-token-plan-ams"]),
            ("xiaomi-token-plan-cn", &["xiaomi-token-plan-cn"]),
            ("xiaomi-token-plan-sgp", &["xiaomi-token-plan-sgp"]),
            ("yolo-auto", &[]),
            ("zenmux", &["zenmux"]),
            ("zhipu-coding-plan", &["zhipuai-coding-plan"]),
            ("kimi-for-coding", &["kimi-code-plan-global"]),
            ("tavily", &[]),
            ("kagi", &[]),
            ("exa", &[]),
            ("parallel", &[]),
            ("brave", &[]),
            ("firecrawl", &[]),
            ("jina", &[]),
            ("tinyfish", &[]),
            ("searxng", &[]),
            ("elevenlabs", &["elevenlabs"]),
            ("302ai", &["302ai"]),
            ("abacus", &["abacus"]),
            ("above", &["above"]),
            ("agentrouter", &["agentrouter"]),
            ("agnes", &["agnes"]),
            ("ai-router", &["ai-router"]),
            ("ai21", &["ai21"]),
            ("aihubmix", &["aihubmix"]),
            ("aimlapi", &["aimlapi"]),
            ("ainetcafe", &["ainetcafe"]),
            ("aixy", &["aixy"]),
            ("aki-io", &["aki-io"]),
            ("alibaba", &["alibaba"]),
            ("alibaba-cn", &["alibaba-cn"]),
            ("alibaba-coding-plan", &["alibaba-coding-plan"]),
            ("alibaba-coding-plan-cn", &["alibaba-coding-plan-cn"]),
            ("alibaba-token-plan", &["alibaba-token-plan"]),
            ("alibaba-token-plan-cn", &["alibaba-token-plan-cn"]),
            ("ambient", &["ambient"]),
            ("amd", &["amd"]),
            ("anyapi", &["anyapi"]),
            ("arcee", &["arcee"]),
            ("auriko", &["auriko"]),
            ("bailing", &["bailing"]),
            ("bee", &["bee"]),
            ("berget", &["berget"]),
            ("blueclaw", &["blueclaw"]),
            ("bothub", &["bothub"]),
            ("boundless", &["boundless"]),
            ("chutes", &["chutes"]),
            ("claudinio", &["claudinio"]),
            ("cloudferro-sherlock", &["cloudferro-sherlock"]),
            ("cohere", &["cohere"]),
            ("coralbricks", &["coralbricks"]),
            ("cortecs", &["cortecs"]),
            ("crossmodel", &["crossmodel"]),
            ("crusoe", &["crusoe"]),
            ("daoxe", &["daoxe"]),
            ("digitalocean", &["digitalocean"]),
            ("dinference", &["dinference"]),
            ("drun", &["drun"]),
            ("echo", &["echo"]),
            ("edenai", &["edenai"]),
            ("empiriolabs", &["empiriolabs"]),
            ("engy", &["engy"]),
            ("evroc", &["evroc"]),
            ("fastrouter", &["fastrouter"]),
            ("freemodel", &["freemodel"]),
            ("friendli", &["friendli"]),
            ("frogbot", &["frogbot"]),
            ("google-vertex", &["google-vertex"]),
            ("greenpt", &["greenpt"]),
            ("helicone", &["helicone"]),
            ("hopper", &["hopper"]),
            ("hpc-ai", &["hpc-ai"]),
            ("impossibl", &["impossibl"]),
            ("inceptron", &["inceptron"]),
            ("inco", &["inco"]),
            ("infer", &["infer"]),
            ("inference", &["inference"]),
            ("inferx", &["inferx"]),
            ("infomaniak", &["infomaniak"]),
            ("io-net", &["io-net"]),
            ("iteracompute", &["iteracompute"]),
            ("jalapeno", &["jalapeno"]),
            ("jiekou", &["jiekou"]),
            ("kenari", &["kenari"]),
            ("kilo", &["kilo"]),
            ("kimi-code-plan-cn", &["kimi-code-plan-cn"]),
            ("klokintegration", &["klokintegration"]),
            ("kosmik", &["kosmik"]),
            ("liquid", &["liquid"]),
            ("llmgateway", &["llmgateway"]),
            ("llmgateway-providers", &["llmgateway-providers"]),
            ("llmtr", &["llmtr"]),
            ("longcat", &["longcat"]),
            ("lowrouter", &["lowrouter"]),
            ("lucidquery", &["lucidquery"]),
            ("meganova", &["meganova"]),
            ("melious", &["melious"]),
            ("merge-gateway", &["merge-gateway"]),
            ("minimax", &["minimax"]),
            ("minimax-cn", &["minimax-cn"]),
            ("mixlayer", &["mixlayer"]),
            ("moark", &["moark"]),
            ("model-oracle-ai", &["model-oracle-ai"]),
            ("modular", &["modular"]),
            ("moonshotai-cn", &["moonshotai-cn"]),
            ("morph", &["morph"]),
            ("munito", &["munito"]),
            ("munito-eu", &["munito-eu"]),
            ("nan", &["nan"]),
            ("nearai", &["nearai"]),
            ("nebius", &["nebius"]),
            ("neuralwatt", &["neuralwatt"]),
            ("ofox", &["ofox"]),
            ("opper", &["opper"]),
            ("orcarouter", &["orcarouter"]),
            ("ovhcloud", &["ovhcloud"]),
            ("pareto", &["pareto"]),
            ("pendra", &["pendra"]),
            ("perplexity-agent", &["perplexity-agent"]),
            ("pioneer", &["pioneer"]),
            ("poe", &["poe"]),
            ("prime", &["prime"]),
            ("privatemode-ai", &["privatemode-ai"]),
            ("qiniu-ai", &["qiniu-ai"]),
            ("reflection", &["reflection"]),
            ("requesty", &["requesty"]),
            ("runinfra", &["runinfra"]),
            ("salad-cloud", &["salad-cloud"]),
            ("sambanova", &["sambanova"]),
            ("sarvam", &["sarvam"]),
            ("standardcompute", &["standardcompute"]),
            ("stepfun-cn", &["stepfun"]),
            ("stepfun-ai-step-plan", &["stepfun-ai-step-plan"]),
            ("stepfun-step-plan", &["stepfun-step-plan"]),
            ("subconscious", &["subconscious"]),
            ("submodel", &["submodel"]),
            ("tempr", &["tempr"]),
            ("tensorx", &["tensorx"]),
            ("the-grid-ai", &["the-grid-ai"]),
            ("thinkingmachines", &["thinkingmachines"]),
            ("tinfoil", &["tinfoil"]),
            ("tokengo", &["tokengo"]),
            ("trustedrouter", &["trustedrouter"]),
            ("unorouter", &["unorouter"]),
            ("upstage", &["upstage"]),
            ("vivgrid", &["vivgrid"]),
            ("volcengine", &["volcengine"]),
            ("vultr", &["vultr"]),
            ("wallaby", &["wallaby"]),
            ("wally", &["wally"]),
            ("wandb", &["wandb"]),
            ("xiaomi", &["xiaomi"]),
            ("xpersona", &["xpersona"]),
            ("zai-api", &["zai"]),
            ("zeldoc", &["zeldoc"]),
            ("zenifra", &["zenifra"]),
            ("zhipuai", &["zhipuai"]),
            ("modelis", &["modelis"]),
            ("modelscope", &["modelscope"]),
            ("poolside", &["poolside"]),
            ("regolo-ai", &["regolo-ai"]),
            ("scaleway", &["scaleway"]),
            ("sensenova", &["sensenova"]),
            ("stackit", &["stackit"]),
            ("vancine", &["vancine"]),
            ("volcengine-coding-plan", &["volcengine-coding-plan"]),
            ("byteplus", &["byteplus"]),
        ];
        assert_eq!(
            API_KEY_PROVIDERS
                .iter()
                .map(|row| row.key)
                .collect::<Vec<_>>(),
            expected.iter().map(|(key, _)| *key).collect::<Vec<_>>()
        );
        for (key, ids) in expected {
            for id in [format!("apikey:{key}"), format!("apikey:{key}:work")] {
                assert_eq!(default_provider_ids(&id), *ids, "{id}");
                assert_eq!(provider(&id), Some(*key));
                // Media consumers receive only the rows assigned to their group.
                assert_eq!(
                    category_defaults(&id)
                        .iter()
                        .any(|category| category == "media-provider"),
                    matches!(*key, "openai" | "google" | "elevenlabs")
                        || FUSIFORM_LLM_AND_MEDIA_KEYS.contains(key),
                    "{id}"
                );
            }
        }
        assert_eq!(provider("apikey:unknown"), None);
        assert_eq!(provider("chatgpt:openai:work"), Some("openai"));
        assert_eq!(provider("copilot:github"), Some("github-copilot"));
        assert!(matches!(
            api_key_provider("minimax-code-cn").unwrap().validation,
            KeyValidation::OpenAiChat {
                base_url: "https://api.minimax.cn/v1",
                ..
            }
        ));
    }

    #[test]
    fn both_catalogs_have_exact_owner_supplied_assignments() {
        // 15 original API-key rows, 37 model providers mirrored from oh-my-pi,
        // Kiro, Anthropic, Inception, Cloudflare Workers AI, Kimi coding,
        // 9 search APIs, ElevenLabs for media, and 150 rows proposed from Fusiform's
        // provider list.
        assert_eq!(API_KEY_PROVIDERS.len(), 217);
        assert_eq!(LOGIN_PROVIDERS.len(), 13);
        // The category tests below pin the model, search and media rows and require
        // every row to be listed.
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
                ("oauth:meta", vec!["llm-provider"]),
                ("oauth:google", vec!["llm-provider"]),
                ("oauth:gmail", vec![]),
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
            [
                "llm-provider",
                "llm-gateway",
                "data-warehouse",
                "cloud-infrastructure",
                "web-search",
                "media-provider",
                "embedding-provider"
            ]
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
                "nvidia",
                "minimax",
                "xiaomi",
                "stepfun",
                "inception"
            ]
        );
    }

    /// The api-key model providers this table held before oh-my-pi's were mirrored.
    const ORIGINAL_LLM_KEYS: &[&str] = &[
        "openrouter",
        "cerebras",
        "fireworks-ai",
        "groq",
        "mistral",
        "together",
        "moonshot",
        "huggingface",
        "nvidia",
        "xai",
        "openai",
        "google",
    ];

    /// Every oh-my-pi `login "api-key"` model provider this table did not already have,
    /// under oh-my-pi's own provider id. Two live credentials already sit at
    /// `apikey:opencode-go` and `apikey:ollama-cloud`, so those spellings are load-bearing.
    const MIRRORED_LLM_KEYS: &[&str] = &[
        "abliteration",
        "aiand",
        "baseten",
        "charm-hyper",
        "cline-pass",
        "commandcode",
        "deepinfra",
        "firepass",
        "gmi-cloud",
        "meta",
        "minimax-code",
        "minimax-code-cn",
        "nanogpt",
        "novita",
        "opencode-go",
        "opencode-zen",
        "qianfan",
        "qwen-portal",
        "sakana",
        "siliconflow",
        "siliconflow-cn",
        "singularityapi-dev",
        "singularityapi-tech",
        "stepfun",
        "typesafe",
        "umans",
        "venice",
        "vercel-ai-gateway",
        "wafer-serverless",
        "xiaomi-token-plan-ams",
        "xiaomi-token-plan-cn",
        "xiaomi-token-plan-sgp",
        "yolo-auto",
        "zenmux",
        "zhipu-coding-plan",
    ];

    /// Search-only APIs. Their keys are not model credentials.
    const SEARCH_KEYS: &[&str] = &[
        "tavily",
        "kagi",
        "exa",
        "parallel",
        "brave",
        "firecrawl",
        "jina",
        "tinyfish",
        "searxng",
    ];

    const MEDIA_ONLY_KEYS: &[&str] = &["elevenlabs"];

    /// Model providers added from Fusiform's provider list, each under its Fusiform id.
    const FUSIFORM_LLM_KEYS: &[&str] = &[
        "302ai",
        "abacus",
        "above",
        "agentrouter",
        "agnes",
        "ai-router",
        "ai21",
        "aihubmix",
        "aimlapi",
        "ainetcafe",
        "aixy",
        "aki-io",
        "alibaba",
        "alibaba-cn",
        "alibaba-coding-plan",
        "alibaba-coding-plan-cn",
        "alibaba-token-plan",
        "alibaba-token-plan-cn",
        "ambient",
        "amd",
        "anyapi",
        "arcee",
        "auriko",
        "bailing",
        "bee",
        "berget",
        "blueclaw",
        "bothub",
        "boundless",
        "chutes",
        "claudinio",
        "cloudferro-sherlock",
        "cohere",
        "coralbricks",
        "cortecs",
        "crossmodel",
        "crusoe",
        "daoxe",
        "digitalocean",
        "dinference",
        "drun",
        "echo",
        "edenai",
        "empiriolabs",
        "engy",
        "evroc",
        "fastrouter",
        "freemodel",
        "friendli",
        "frogbot",
        "google-vertex",
        "greenpt",
        "helicone",
        "hopper",
        "hpc-ai",
        "impossibl",
        "inceptron",
        "inco",
        "infer",
        "inference",
        "inferx",
        "infomaniak",
        "io-net",
        "iteracompute",
        "jalapeno",
        "jiekou",
        "kenari",
        "kilo",
        "kimi-code-plan-cn",
        "klokintegration",
        "kosmik",
        "liquid",
        "llmgateway",
        "llmgateway-providers",
        "llmtr",
        "longcat",
        "lowrouter",
        "lucidquery",
        "meganova",
        "melious",
        "merge-gateway",
        "minimax",
        "minimax-cn",
        "mixlayer",
        "moark",
        "model-oracle-ai",
        "modular",
        "moonshotai-cn",
        "morph",
        "munito",
        "munito-eu",
        "nan",
        "nearai",
        "nebius",
        "neuralwatt",
        "ofox",
        "opper",
        "orcarouter",
        "ovhcloud",
        "pareto",
        "pendra",
        "perplexity-agent",
        "pioneer",
        "poe",
        "prime",
        "privatemode-ai",
        "qiniu-ai",
        "reflection",
        "requesty",
        "runinfra",
        "salad-cloud",
        "sambanova",
        "sarvam",
        "standardcompute",
        "stepfun-cn",
        "stepfun-ai-step-plan",
        "stepfun-step-plan",
        "subconscious",
        "submodel",
        "tempr",
        "tensorx",
        "the-grid-ai",
        "thinkingmachines",
        "tinfoil",
        "tokengo",
        "trustedrouter",
        "unorouter",
        "upstage",
        "vivgrid",
        "volcengine",
        "vultr",
        "wallaby",
        "wally",
        "wandb",
        "xiaomi",
        "xpersona",
        "zai-api",
        "zeldoc",
        "zenifra",
        "zhipuai",
        "modelis",
        "modelscope",
        "poolside",
        "regolo-ai",
        "scaleway",
        "sensenova",
        "stackit",
        "vancine",
        "volcengine-coding-plan",
        "byteplus",
    ];

    /// The rows in `FUSIFORM_LLM_KEYS` whose Fusiform entry also lists audio, image or
    /// video output, so they default to `media-provider` as well.
    const FUSIFORM_LLM_AND_MEDIA_KEYS: &[&str] = &[
        "302ai",
        "abacus",
        "aihubmix",
        "aimlapi",
        "alibaba",
        "alibaba-cn",
        "alibaba-token-plan",
        "alibaba-token-plan-cn",
        "digitalocean",
        "edenai",
        "fastrouter",
        "google-vertex",
        "kenari",
        "kilo",
        "merge-gateway",
        "nan",
        "nearai",
        "poe",
        "qiniu-ai",
        "requesty",
        "regolo-ai",
        "stepfun-cn",
    ];

    /// Catalogued keys used by both model and web-search consumers.
    const DUAL_USE_KEYS: &[&str] = &[
        "deepseek",
        "ollama-cloud",
        "perplexity",
        "synthetic",
        "zai",
        "kimi-for-coding",
    ];

    /// Providers whose keys cannot be stored as a plain pasted key, so they have no row:
    /// - local servers whose "key" is a localhost placeholder, so there is no secret;
    /// - keys usable only with per-deployment settings a row cannot carry (litellm needs
    ///   the proxy's base URL, coreweave an OpenAI-Project header);
    /// - providers whose login is a custom, OAuth or device-code flow, not a pasted key.
    const LEFT_OUT_KEYS: &[&str] = &[
        "llama.cpp",
        "lm-studio",
        "ollama",
        "vllm",
        "litellm",
        "coreweave",
        "cloudflare-ai-gateway",
        "cursor",
        "devin",
        "github-copilot",
        "gitlab-duo",
        "gitlab-duo-agent",
        "google-antigravity",
        "google-gemini-cli",
        "kimi-code",
        "muse-code",
        "openai-codex",
        "openai-codex-device",
        "stencil",
        "xai-oauth",
        "zai-coding-plan",
    ];

    /// A key created under any model provider must be stamped `llm-provider`, or no LLM
    /// consumer's category grant reaches it until an operator fixes it by hand. Checked
    /// for the bare id and for a labeled account, since both are stamped at creation.
    #[test]
    fn every_model_provider_row_is_stamped_llm_provider() {
        for key in ORIGINAL_LLM_KEYS
            .iter()
            .chain(MIRRORED_LLM_KEYS)
            .chain(FUSIFORM_LLM_KEYS)
            .chain([
                &"kiro",
                &"anthropic",
                &"inception",
                &"cloudflare-workers-ai",
            ])
        {
            let row = api_key_provider(key).unwrap_or_else(|| panic!("no api-key row {key}"));
            assert_eq!(row.default_id, format!("apikey:{key}"));
            for id in [format!("apikey:{key}"), format!("apikey:{key}:work")] {
                let expected = if matches!(*key, "openai" | "google")
                    || FUSIFORM_LLM_AND_MEDIA_KEYS.contains(key)
                {
                    vec!["llm-provider", "media-provider"]
                } else {
                    vec!["llm-provider"]
                };
                assert_eq!(category_defaults(&id), expected, "{id}");
            }
        }
        // Every row must be listed somewhere, so a new row cannot land uncategorised
        // without this test naming it.
        for entry in API_KEY_PROVIDERS {
            assert!(
                ORIGINAL_LLM_KEYS.contains(&entry.key)
                    || MIRRORED_LLM_KEYS.contains(&entry.key)
                    || FUSIFORM_LLM_KEYS.contains(&entry.key)
                    || DUAL_USE_KEYS.contains(&entry.key)
                    || SEARCH_KEYS.contains(&entry.key)
                    || MEDIA_ONLY_KEYS.contains(&entry.key)
                    || entry.key == "kiro"
                    || entry.key == "anthropic"
                    || entry.key == "inception"
                    || entry.key == "cloudflare-workers-ai",
                "api-key row {} is in no category list",
                entry.key
            );
        }
    }

    /// Every LLM consumer is granted `llm-provider`, so search-only keys must not be filed
    /// there. The search-only rows receive `web-search`; dual-use rows receive both categories.
    #[test]
    fn search_keys_are_web_search_and_never_llm_provider() {
        for key in SEARCH_KEYS {
            let row = api_key_provider(key).unwrap_or_else(|| panic!("no api-key row {key}"));
            assert_eq!(row.default_id, format!("apikey:{key}"));
            assert!(row.serves.is_empty(), "{key} serves no model vendor");
            for id in [format!("apikey:{key}"), format!("apikey:{key}:work")] {
                assert_eq!(category_defaults(&id), ["web-search"], "{id}");
            }
        }
        let without_llm: Vec<_> = API_KEY_PROVIDERS
            .iter()
            .filter(|entry| !entry.categories.contains(&CredentialCategory::LlmProvider))
            .map(|entry| entry.key)
            .collect();
        assert_eq!(
            without_llm,
            SEARCH_KEYS
                .iter()
                .chain(MEDIA_ONLY_KEYS)
                .copied()
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn media_only_keys_have_no_model_vendors() {
        for key in MEDIA_ONLY_KEYS {
            let row = api_key_provider(key).unwrap();
            assert_eq!(row.default_id, format!("apikey:{key}"));
            assert!(row.serves.is_empty());
            for id in [format!("apikey:{key}"), format!("apikey:{key}:work")] {
                assert_eq!(category_defaults(&id), ["media-provider"], "{id}");
            }
        }
    }

    #[test]
    fn elevenlabs_checks_the_authenticated_read_only_user_endpoint() {
        let row = api_key_provider("elevenlabs").unwrap();
        assert_eq!(row.fusiform_provider_id, Some("elevenlabs"));
        assert_eq!(row.default_provider_ids, ["elevenlabs"]);
        assert!(matches!(
            row.validation,
            KeyValidation::GetEndpoint {
                url: "https://api.elevenlabs.io/v1/user",
                extra_headers: [],
            }
        ));
        assert_eq!(
            row.hosts_doc,
            "https://elevenlabs.io/docs/api-reference/authentication"
        );
        assert_eq!(
            row.auth,
            Some(AuthDescriptor {
                header: "xi-api-key",
                scheme: AuthScheme::Raw
            })
        );
        assert_eq!(row.hosts, ["api.elevenlabs.io"]);
    }

    #[test]
    fn dual_use_api_key_rows_carry_both_llm_provider_and_web_search_categories() {
        for key in DUAL_USE_KEYS {
            let row = api_key_provider(key).unwrap_or_else(|| panic!("no api-key row {key}"));
            assert_eq!(row.default_id, format!("apikey:{key}"));
            assert_eq!(row.categories, LLM_AND_WEB_SEARCH, "{key}");
            for id in [format!("apikey:{key}"), format!("apikey:{key}:work")] {
                assert_eq!(
                    category_defaults(&id),
                    ["llm-provider", "web-search"],
                    "{id}"
                );
            }
        }
    }

    #[test]
    fn providers_this_table_cannot_hold_are_absent() {
        for key in LEFT_OUT_KEYS {
            assert!(
                api_key_provider(key).is_none(),
                "{key} was left out on purpose"
            );
            let id = format!("apikey:{key}");
            assert!(catalog_match(&id).is_none(), "{id}");
            assert!(category_defaults(&id).is_empty(), "{id}");
        }
    }

    /// The rows stored without a probe, pinned so a row cannot quietly lose its check.
    /// Each has a reason printed at login; an empty one would print a notice that
    /// explains nothing, and one naming where a row was copied from (another
    /// project's catalog) tells the operator nothing about the provider.
    #[test]
    fn unvalidated_rows_are_exactly_the_ones_without_a_usable_probe() {
        let unvalidated: Vec<_> = API_KEY_PROVIDERS
            .iter()
            .filter_map(|entry| match entry.validation {
                KeyValidation::Unvalidated { reason } => {
                    assert!(!reason.trim().is_empty(), "{} has no reason", entry.key);
                    assert!(
                        !reason.to_ascii_lowercase().contains("oh-my-pi"),
                        "{} reason names the source catalog, not the provider: {reason}",
                        entry.key
                    );
                    Some(entry.key)
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            unvalidated,
            [
                "cline-pass",
                "commandcode",
                "ollama-cloud",
                "opencode-go",
                "opencode-zen",
                "qianfan",
                "typesafe",
                "vercel-ai-gateway",
                "kimi-for-coding",
                "tavily",
                "kagi",
                "exa",
                "parallel",
                "brave",
                "jina",
                "searxng",
                "agentrouter",
                "bailing",
                "drun",
                "echo",
                "google-vertex",
                "inferx",
                "modelis",
                "modelscope",
                "poolside",
                "regolo-ai",
                "scaleway",
                "stackit",
                "volcengine-coding-plan",
            ]
        );
    }

    /// Fireworks' `/inference/v1/models` lists the caller's DEPLOYED models and answers
    /// 500 for an account with none, so probing it flags valid keys. The serverless
    /// catalog listing only needs the key to authenticate.
    #[test]
    fn fireworks_is_probed_on_the_serverless_catalog_not_the_deployment_listing() {
        let row = api_key_provider("fireworks-ai").expect("the fireworks-ai row");
        assert_eq!(
            row.validation,
            KeyValidation::GetEndpoint {
                url: "https://api.fireworks.ai/v1/accounts/fireworks/models?filter=supports_serverless%3Dtrue&pageSize=1",
                extra_headers: &[],
            }
        );
    }

    #[test]
    fn embedding_provider_round_trips_through_catalog_vocabulary() {
        assert_eq!(
            CredentialCategory::EmbeddingProvider.as_str(),
            "embedding-provider"
        );
        assert_eq!(
            CredentialCategory::ALL
                .iter()
                .find(|category| category.as_str() == "embedding-provider"),
            Some(&CredentialCategory::EmbeddingProvider),
        );
    }

    #[test]
    fn closed_vocabularies_pin_every_variant_and_wire_spelling() {
        assert_eq!(
            CredentialCategory::ALL
                .iter()
                .map(|value| value.as_str())
                .collect::<Vec<_>>(),
            [
                "llm-provider",
                "llm-gateway",
                "data-warehouse",
                "cloud-infrastructure",
                "web-search",
                "media-provider",
                "embedding-provider"
            ]
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
                "minimax",
                "xiaomi",
                "stepfun",
                "inception",
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

    /// THE NATIVE FAMILY IS THE GRANT AXIS; `serves` AND THE PURPOSE CATEGORY ARE NOT.
    ///
    /// A consumer that sends tokens to one provider's own endpoints needs a selector that
    /// reaches exactly the credentials speaking that protocol. `serves` doesn't: it names
    /// every row that can serve a vendor's models, API keys and other providers' logins
    /// included. Nor does the purpose category `llm-provider`, which reaches every model
    /// credential. A plugin that only speaks Claude OAuth, granted either of those, could
    /// read keys it never uses, and filtering on the consumer side doesn't shrink what the
    /// grant allows. The `<protocol>-native` categories below are that narrower axis.
    #[test]
    fn the_native_family_separates_protocol_from_purpose_and_from_serves() {
        // Same purpose, same served vendor, three different protocols.
        assert!(category_defaults("oauth:anthropic").contains(&"anthropic-native".to_owned()));
        assert!(category_defaults("oauth:cursor").contains(&"cursor-native".to_owned()));
        assert!(category_defaults("antigravity:google").contains(&"antigravity-native".to_owned()));

        // A STATIC KEY JOINS NO FAMILY. apikey:openrouter serves Anthropic models and
        // speaks no refresh protocol, so a native-family grant must not reach it.
        assert_eq!(native_family_category("apikey:openrouter"), None);
        assert!(!category_defaults("apikey:openrouter")
            .iter()
            .any(|category| category.ends_with("-native")));

        // AND AN UNRECOGNISED METHOD JOINS NONE EITHER. `default_refresh_adapter` reads a
        // missing method as legacy oauth, which would invent `notes-native` here.
        assert_eq!(native_family_category("apple:notes"), None);

        // FUTURE ACCOUNTS ARE COVERED WITH NO OPERATOR ACTION: the family is derived from
        // the id, so a new account stamps itself at creation.
        assert_eq!(
            native_family_category("oauth:anthropic:someone-new"),
            Some("anthropic-native".to_owned())
        );

        // Every emitted name must be selectable by a grant, or it reads as coverage in
        // `ck auth categories` while reaching nothing.
        for id in [
            "oauth:anthropic",
            "chatgpt:openai",
            "copilot:github",
            "antigravity:google",
            "github_app:some-app",
        ] {
            if let Some(category) = native_family_category(id) {
                assert!(valid_category_name(&category), "{id} -> {category}");
            }
        }
        // github_app carries an underscore the grammar rejects, so it must be normalised
        // rather than dropped.
        assert_eq!(
            native_family_category("github_app:some-app"),
            Some("github-app-native".to_owned())
        );
    }

    #[test]
    fn serves_and_categories_use_one_catalog_match() {
        assert_eq!(serves_for("oauth:anthropic:fourth"), &[Anthropic]);
        assert_eq!(
            category_defaults("oauth:anthropic:fourth"),
            ["llm-provider", "anthropic-native"]
        );
        assert!(serves_for("oauth:snowflake").is_empty());
        assert_eq!(
            category_defaults("oauth:snowflake"),
            ["data-warehouse", "snowflake-native"]
        );
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
            ("kem:x", "kem"),
            ("github_app:x", "github_app"),
            ("apple:x", "apple"),
        ] {
            assert_eq!(credential_type(id), expected);
        }
    }

    /// A code-display redirect is unusable without instructions describing the code,
    /// so the pair moves together — asserted over the WHOLE table rather than for the
    /// one row that has it. A row setting only the URL would send the operator to a
    /// page showing a code while the prompt asked for an address bar; a row setting
    /// only the prompt would print instructions for a page nobody is looking at.
    #[test]
    fn a_code_display_redirect_and_its_paste_prompt_are_set_together() {
        for entry in LOGIN_PROVIDERS {
            assert_eq!(
                entry.code_redirect_uri.is_some(),
                entry.code_paste_prompt.is_some(),
                "{}: code_redirect_uri and code_paste_prompt must both be set or both be absent",
                entry.key
            );
        }
        let carrying_a_code_redirect: Vec<_> = LOGIN_PROVIDERS
            .iter()
            .filter(|entry| entry.code_redirect_uri.is_some())
            .map(|entry| entry.key)
            .collect();
        assert_eq!(
            carrying_a_code_redirect,
            ["anthropic"],
            "a code-display redirect is a redirect the provider ACTUALLY registered, \
             never a console URL that looks plausible: an unregistered one is refused \
             at the authorize step, so adding a row here means someone verified it"
        );

        let anthropic = login_provider("anthropic").expect("the anthropic row");
        assert_eq!(
            anthropic.code_redirect_uri,
            Some("https://platform.claude.com/oauth/code/callback")
        );
        // Both redirects are registered on the same app, and they must stay distinct:
        // equal values would make the no-listener path send the loopback redirect
        // again, which is the defect this field exists to fix.
        assert_eq!(anthropic.redirect_uri, "http://localhost:54545/callback");
        assert!(
            anthropic
                .code_paste_prompt
                .expect("the anthropic code prompt")
                .contains("code#state"),
            "the prompt for a code-display redirect must name the shape the page renders"
        );
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
                (
                    "kiro",
                    vec!["anthropic", "deepseek", "qwen", "zhipu", "minimax"]
                ),
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
                ("anthropic", vec!["anthropic"]),
                ("inception", vec!["inception"]),
                (
                    "cloudflare-workers-ai",
                    vec![
                        "openai", "google", "deepseek", "mistral", "moonshot", "zhipu", "meta",
                        "qwen", "nvidia"
                    ]
                ),
                ("abliteration", vec!["zhipu"]),
                (
                    "aiand",
                    vec!["openai", "google", "deepseek", "moonshot", "zhipu", "qwen"]
                ),
                (
                    "baseten",
                    vec!["openai", "deepseek", "moonshot", "zhipu", "nvidia"]
                ),
                ("charm-hyper", vec!["google", "moonshot", "zhipu"]),
                (
                    "cline-pass",
                    vec![
                        "google", "deepseek", "moonshot", "zhipu", "meta", "qwen", "minimax",
                        "xiaomi"
                    ]
                ),
                (
                    "commandcode",
                    vec![
                        "anthropic",
                        "openai",
                        "google",
                        "xai",
                        "deepseek",
                        "moonshot",
                        "zhipu",
                        "meta",
                        "qwen",
                        "nvidia",
                        "minimax",
                        "xiaomi",
                        "stepfun"
                    ]
                ),
                (
                    "deepinfra",
                    vec![
                        "anthropic",
                        "openai",
                        "google",
                        "deepseek",
                        "mistral",
                        "moonshot",
                        "zhipu",
                        "meta",
                        "qwen",
                        "nvidia",
                        "minimax",
                        "xiaomi"
                    ]
                ),
                ("firepass", vec!["moonshot", "zhipu"]),
                ("gmi-cloud", vec!["deepseek"]),
                ("meta", vec!["meta"]),
                ("minimax-code", vec!["minimax"]),
                ("minimax-code-cn", vec!["minimax"]),
                (
                    "nanogpt",
                    ModelVendor::ALL.iter().map(|v| v.as_str()).collect()
                ),
                (
                    "novita",
                    vec![
                        "openai", "google", "deepseek", "mistral", "moonshot", "zhipu", "meta",
                        "qwen", "nvidia", "minimax", "xiaomi", "stepfun"
                    ]
                ),
                (
                    "ollama-cloud",
                    vec![
                        "openai", "google", "deepseek", "mistral", "moonshot", "zhipu", "qwen",
                        "nvidia", "minimax"
                    ]
                ),
                (
                    "opencode-go",
                    vec![
                        "openai", "xai", "deepseek", "moonshot", "zhipu", "meta", "qwen",
                        "minimax", "xiaomi"
                    ]
                ),
                (
                    "opencode-zen",
                    vec![
                        "anthropic",
                        "openai",
                        "google",
                        "xai",
                        "deepseek",
                        "moonshot",
                        "zhipu",
                        "meta",
                        "qwen",
                        "nvidia",
                        "minimax",
                        "xiaomi"
                    ]
                ),
                ("qianfan", vec!["deepseek"]),
                ("qwen-portal", vec!["qwen"]),
                ("sakana", vec![]),
                ("siliconflow", vec!["zhipu"]),
                ("siliconflow-cn", vec!["deepseek"]),
                ("singularityapi-dev", vec!["deepseek", "moonshot", "zhipu"]),
                ("singularityapi-tech", vec!["deepseek"]),
                ("stepfun", vec!["stepfun"]),
                (
                    "synthetic",
                    vec!["openai", "deepseek", "moonshot", "zhipu", "qwen", "nvidia"]
                ),
                ("typesafe", vec![]),
                (
                    "umans",
                    vec!["deepseek", "moonshot", "zhipu", "qwen", "xiaomi"]
                ),
                (
                    "venice",
                    vec![
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
                        "nvidia",
                        "minimax",
                        "xiaomi"
                    ]
                ),
                (
                    "vercel-ai-gateway",
                    ModelVendor::ALL.iter().map(|v| v.as_str()).collect()
                ),
                (
                    "wafer-serverless",
                    vec!["deepseek", "moonshot", "zhipu", "qwen", "minimax"]
                ),
                ("xiaomi-token-plan-ams", vec!["xiaomi"]),
                ("xiaomi-token-plan-cn", vec!["xiaomi"]),
                ("xiaomi-token-plan-sgp", vec!["xiaomi"]),
                ("yolo-auto", vec!["deepseek", "qwen"]),
                (
                    "zenmux",
                    vec![
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
                        "minimax",
                        "xiaomi",
                        "stepfun"
                    ]
                ),
                ("zhipu-coding-plan", vec!["zhipu"]),
                ("kimi-for-coding", vec!["moonshot"]),
                ("tavily", vec![]),
                ("kagi", vec![]),
                ("exa", vec![]),
                ("parallel", vec![]),
                ("brave", vec![]),
                ("firecrawl", vec![]),
                ("jina", vec![]),
                ("tinyfish", vec![]),
                ("searxng", vec![]),
                ("elevenlabs", vec![]),
                ("302ai", vec![]),
                ("abacus", vec![]),
                ("above", vec![]),
                ("agentrouter", vec![]),
                ("agnes", vec![]),
                ("ai-router", vec![]),
                ("ai21", vec![]),
                ("aihubmix", vec![]),
                ("aimlapi", vec![]),
                ("ainetcafe", vec![]),
                ("aixy", vec![]),
                ("aki-io", vec![]),
                ("alibaba", vec![]),
                ("alibaba-cn", vec![]),
                ("alibaba-coding-plan", vec![]),
                ("alibaba-coding-plan-cn", vec![]),
                ("alibaba-token-plan", vec![]),
                ("alibaba-token-plan-cn", vec![]),
                ("ambient", vec![]),
                ("amd", vec![]),
                ("anyapi", vec![]),
                ("arcee", vec![]),
                ("auriko", vec![]),
                ("bailing", vec![]),
                ("bee", vec![]),
                ("berget", vec![]),
                ("blueclaw", vec![]),
                ("bothub", vec![]),
                ("boundless", vec![]),
                ("chutes", vec![]),
                ("claudinio", vec![]),
                ("cloudferro-sherlock", vec![]),
                ("cohere", vec![]),
                ("coralbricks", vec![]),
                ("cortecs", vec![]),
                ("crossmodel", vec![]),
                ("crusoe", vec![]),
                ("daoxe", vec![]),
                ("digitalocean", vec![]),
                ("dinference", vec![]),
                ("drun", vec![]),
                ("echo", vec![]),
                ("edenai", vec![]),
                ("empiriolabs", vec![]),
                ("engy", vec![]),
                ("evroc", vec![]),
                ("fastrouter", vec![]),
                ("freemodel", vec![]),
                ("friendli", vec![]),
                ("frogbot", vec![]),
                ("google-vertex", vec![]),
                ("greenpt", vec![]),
                ("helicone", vec![]),
                ("hopper", vec![]),
                ("hpc-ai", vec![]),
                ("impossibl", vec![]),
                ("inceptron", vec![]),
                ("inco", vec![]),
                ("infer", vec![]),
                ("inference", vec![]),
                ("inferx", vec![]),
                ("infomaniak", vec![]),
                ("io-net", vec![]),
                ("iteracompute", vec![]),
                ("jalapeno", vec![]),
                ("jiekou", vec![]),
                ("kenari", vec![]),
                ("kilo", vec![]),
                ("kimi-code-plan-cn", vec![]),
                ("klokintegration", vec![]),
                ("kosmik", vec![]),
                ("liquid", vec![]),
                ("llmgateway", vec![]),
                ("llmgateway-providers", vec![]),
                ("llmtr", vec![]),
                ("longcat", vec![]),
                ("lowrouter", vec![]),
                ("lucidquery", vec![]),
                ("meganova", vec![]),
                ("melious", vec![]),
                ("merge-gateway", vec![]),
                ("minimax", vec![]),
                ("minimax-cn", vec![]),
                ("mixlayer", vec![]),
                ("moark", vec![]),
                ("model-oracle-ai", vec![]),
                ("modular", vec![]),
                ("moonshotai-cn", vec![]),
                ("morph", vec![]),
                ("munito", vec![]),
                ("munito-eu", vec![]),
                ("nan", vec![]),
                ("nearai", vec![]),
                ("nebius", vec![]),
                ("neuralwatt", vec![]),
                ("ofox", vec![]),
                ("opper", vec![]),
                ("orcarouter", vec![]),
                ("ovhcloud", vec![]),
                ("pareto", vec![]),
                ("pendra", vec![]),
                ("perplexity-agent", vec![]),
                ("pioneer", vec![]),
                ("poe", vec![]),
                ("prime", vec![]),
                ("privatemode-ai", vec![]),
                ("qiniu-ai", vec![]),
                ("reflection", vec![]),
                ("requesty", vec![]),
                ("runinfra", vec![]),
                ("salad-cloud", vec![]),
                ("sambanova", vec![]),
                ("sarvam", vec![]),
                ("standardcompute", vec![]),
                ("stepfun-cn", vec![]),
                ("stepfun-ai-step-plan", vec![]),
                ("stepfun-step-plan", vec![]),
                ("subconscious", vec![]),
                ("submodel", vec![]),
                ("tempr", vec![]),
                ("tensorx", vec![]),
                ("the-grid-ai", vec![]),
                ("thinkingmachines", vec![]),
                ("tinfoil", vec![]),
                ("tokengo", vec![]),
                ("trustedrouter", vec![]),
                ("unorouter", vec![]),
                ("upstage", vec![]),
                ("vivgrid", vec![]),
                ("volcengine", vec![]),
                ("vultr", vec![]),
                ("wallaby", vec![]),
                ("wally", vec![]),
                ("wandb", vec![]),
                ("xiaomi", vec![]),
                ("xpersona", vec![]),
                ("zai-api", vec![]),
                ("zeldoc", vec![]),
                ("zenifra", vec![]),
                ("zhipuai", vec![]),
                ("modelis", vec![]),
                ("modelscope", vec![]),
                ("poolside", vec![]),
                ("regolo-ai", vec![]),
                ("scaleway", vec![]),
                ("sensenova", vec![]),
                ("stackit", vec![]),
                ("vancine", vec![]),
                ("volcengine-coding-plan", vec![]),
                ("byteplus", vec![]),
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
                ("oauth:meta", vec!["meta"]),
                ("oauth:google", vec!["google"]),
                ("oauth:gmail", vec![]),
                ("antigravity:google", vec!["google", "anthropic", "openai"]),
                ("oauth:cursor", vec!["anthropic", "openai", "google", "xai"]),
                ("oauth:devin", vec![]),
                ("oauth:snowflake", vec![]),
                ("oauth:digitalocean", vec![]),
            ]
        );
    }
}

#[cfg(test)]
mod key_label_tests {
    use super::*;

    #[test]
    fn fireworks_placeholder_uses_the_provider_key_prefix() {
        let fireworks = API_KEY_PROVIDERS
            .iter()
            .find(|entry| entry.default_id == "apikey:fireworks-ai")
            .unwrap();
        assert!(fireworks.placeholder.starts_with("fw_"));
    }
}
