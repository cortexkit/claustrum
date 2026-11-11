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
    /// Keys for web search APIs (Tavily, Kagi, Exa, Parallel, Brave, Firecrawl, Jina,
    /// TinyFish, SearXNG). Kept apart from `llm-provider` for search-only providers: every
    /// model consumer is granted `llm-provider`, and a search key filed there would reach
    /// all of them.
    WebSearch,
    MediaProvider,
}

impl CredentialCategory {
    pub const ALL: &[Self] = &[
        Self::LlmProvider,
        Self::DataWarehouse,
        Self::CloudInfrastructure,
        Self::WebSearch,
        Self::MediaProvider,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LlmProvider => "llm-provider",
            Self::DataWarehouse => "data-warehouse",
            Self::CloudInfrastructure => "cloud-infrastructure",
            Self::WebSearch => "web-search",
            Self::MediaProvider => "media-provider",
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
pub const PENDING_FUSIFORM_PROVIDER_IDS: &[(&str, &str)] = &[
    ("tavily", "search_service_pending_ruling"),
    ("kagi", "search_service_pending_ruling"),
    ("exa", "search_service_pending_ruling"),
    ("parallel", "search_service_pending_ruling"),
    ("brave", "search_service_pending_ruling"),
    ("firecrawl", "search_service_pending_ruling"),
    ("jina", "search_service_pending_ruling"),
    ("tinyfish", "search_service_pending_ruling"),
    ("searxng", "search_service_pending_ruling"),
];

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
];

/// The permitted dispositions for a provider researched but not added to the catalog.
pub const FUSIFORM_SKIP_REASONS: &[&str] = &[
    "OAuth only",
    "no API key in its documentation",
    "a duplicate offering of an existing row",
    "a second secret or a per-account host in the style of Azure, Bedrock or Vertex",
    "a user-hosted local server rather than a fixed provider API",
];

use ModelVendor::{
    Anthropic, DeepSeek, Google, Inception, Meta, MiniMax, Mistral, Moonshot, Nvidia, OpenAI,
    Perplexity, Qwen, StepFun, Xiaomi, Zhipu, XAI,
};

pub const API_KEY_PROVIDERS: &[ApiKeyProvider] = &[
    ApiKeyProvider {
        key: "kiro",
        fusiform_provider_id: Some("kiro"),
        auth: Some(BEARER_AUTH),
        hosts: &["q.us-east-1.amazonaws.com"],
        hosts_doc: "https://kiro.dev/docs/getting-started/authentication/",
        invalid_key: Some(InvalidKeyEvidence { status: 403, error_code: None, error_code_field: None }),
        default_provider_ids: &[],
        display_name: "Kiro",
        default_id: "apikey:kiro",
        dashboard_url: "https://app.kiro.dev",
        placeholder: "ksk_...",
        validation: KeyValidation::AwsApiKeyGet {
            url: "https://q.us-east-1.amazonaws.com/ListAvailableModels?origin=AI_EDITOR",
        },
        categories: LLM,
        // 9router's open-sse/providers/registry/kiro.js lists Claude, DeepSeek,
        // Qwen, GLM and MiniMax models. Its kiroConstants.js adds thinking/agentic
        // suffix variants of those models, not additional model vendors.
        serves: &[Anthropic, DeepSeek, Qwen, Zhipu, MiniMax],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "zai",
        fusiform_provider_id: Some("zai-coding-plan"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.z.ai"],
        hosts_doc: "https://docs.z.ai/devpack/quick-start",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("401"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["zai-coding-plan"],
        display_name: "Z.AI (GLM Coding Plan)",
        default_id: "apikey:zai",
        dashboard_url: "https://z.ai/manage-apikey/apikey-list",
        placeholder: "sk-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.z.ai/api/coding/paas/v4",
            model: "glm-5.2",
        },
        categories: LLM_AND_WEB_SEARCH,
        serves: &[Zhipu],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "openrouter",
        fusiform_provider_id: Some("openrouter"),
        auth: Some(BEARER_AUTH),
        hosts: &["openrouter.ai"],
        hosts_doc: "https://openrouter.ai/docs/api-reference/authentication",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["openrouter"],
        display_name: "OpenRouter",
        default_id: "apikey:openrouter",
        dashboard_url: "https://openrouter.ai/keys",
        placeholder: "sk-or-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://openrouter.ai/api/v1/auth/key",
            extra_headers: &[],
        },
        categories: LLM,
        serves: ModelVendor::ALL,
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "deepseek",
        fusiform_provider_id: Some("deepseek"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.deepseek.com"],
        hosts_doc: "https://api-docs.deepseek.com/quick_start",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_request_error"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["deepseek"],
        display_name: "DeepSeek",
        default_id: "apikey:deepseek",
        dashboard_url: "https://platform.deepseek.com/api_keys",
        placeholder: "sk-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.deepseek.com",
            model: "deepseek-chat",
        },
        categories: LLM_AND_WEB_SEARCH,
        serves: &[DeepSeek],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "cerebras",
        fusiform_provider_id: Some("cerebras"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.cerebras.ai"],
        hosts_doc: "https://inference-docs.cerebras.ai/quickstart",
        invalid_key: None,
        default_provider_ids: &["cerebras"],
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
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "fireworks-ai",
        fusiform_provider_id: Some("fireworks-ai"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.fireworks.ai"],
        hosts_doc: "https://docs.fireworks.ai/api-reference",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("UNAUTHORIZED"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["fireworks-ai"],
        display_name: "Fireworks AI",
        default_id: "apikey:fireworks-ai",
        dashboard_url: "https://app.fireworks.ai/settings/users/api-keys",
        placeholder: "fw_...",
        // Not `/inference/v1/models`, which this row used to probe. oh-my-pi's
        // fireworks.kdl records why: "The OpenAI-compatible inference listing
        // (`/inference/v1/models`) enumerates the caller's *deployed* models and returns
        // `500 Error listing deployed models` for accounts without active deployments,
        // which rejected valid `fw_…` keys during `/login`. The control-plane `List
        // Models` API hits the static `fireworks` serverless catalog (same endpoint
        // discovery uses) and only requires the key to authenticate, not to own any
        // deployments." Here a 500 only warns rather than refusing, but a warning on
        // every valid key is noise that hides a real one.
        validation: KeyValidation::GetEndpoint {
            url: "https://api.fireworks.ai/v1/accounts/fireworks/models?filter=supports_serverless%3Dtrue&pageSize=1",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[Meta, Qwen, DeepSeek, Mistral, OpenAI],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "groq",
        fusiform_provider_id: Some("groq"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.groq.com"],
        hosts_doc: "https://console.groq.com/docs/api-reference",
        invalid_key: None,
        default_provider_ids: &["groq"],
        display_name: "Groq",
        default_id: "apikey:groq",
        dashboard_url: "https://console.groq.com/keys",
        placeholder: "gsk_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.groq.com/openai/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[Meta, Qwen, OpenAI, Moonshot, Mistral],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "mistral",
        fusiform_provider_id: Some("mistral"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.mistral.ai"],
        hosts_doc: "https://docs.mistral.ai/api/",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["mistral"],
        display_name: "Mistral",
        default_id: "apikey:mistral",
        dashboard_url: "https://console.mistral.ai/api-keys",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.mistral.ai/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[Mistral],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "together",
        fusiform_provider_id: Some("togetherai"),
        auth: Some(BEARER_AUTH),
        hosts: &["api-inference.together.ai", "api.together.ai", "api.together.xyz", "us-api.together.ai"],
        hosts_doc: "https://docs.together.ai/docs/inference/openai-compatibility",
        invalid_key: None,
        default_provider_ids: &["togetherai"],
        display_name: "Together AI",
        default_id: "apikey:together",
        dashboard_url: "https://api.together.ai/settings/api-keys",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.together.xyz/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[Meta, Qwen, DeepSeek, Mistral, OpenAI, Moonshot],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "perplexity",
        fusiform_provider_id: Some("perplexity"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.perplexity.ai"],
        hosts_doc: "https://docs.perplexity.ai/getting-started/quickstart",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["perplexity"],
        display_name: "Perplexity",
        default_id: "apikey:perplexity",
        dashboard_url: "https://www.perplexity.ai/settings/api",
        placeholder: "pplx-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.perplexity.ai",
            model: "sonar",
        },
        categories: LLM_AND_WEB_SEARCH,
        serves: &[Perplexity],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "moonshot",
        fusiform_provider_id: Some("moonshotai"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.moonshot.ai"],
        hosts_doc: "https://platform.moonshot.ai/docs/guide/quickstart",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_authentication_error"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["moonshotai"],
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
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "huggingface",
        fusiform_provider_id: Some("huggingface"),
        auth: Some(BEARER_AUTH),
        hosts: &["huggingface.co", "router.huggingface.co"],
        hosts_doc: "https://huggingface.co/docs/inference-providers/main/en/index",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["huggingface"],
        display_name: "Hugging Face",
        default_id: "apikey:huggingface",
        dashboard_url: "https://huggingface.co/settings/tokens",
        placeholder: "hf_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://huggingface.co/api/whoami-v2",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[Meta, Qwen, DeepSeek, Mistral, OpenAI, Moonshot, Zhipu],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "nvidia",
        fusiform_provider_id: Some("nvidia"),
        auth: Some(BEARER_AUTH),
        hosts: &["integrate.api.nvidia.com"],
        hosts_doc: "https://docs.api.nvidia.com/nim/reference/nvidia-llama-3_3-nemotron-super-49b-v1-infer",
        invalid_key: None,
        default_provider_ids: &["nvidia"],
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
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "xai",
        fusiform_provider_id: Some("xai"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.x.ai"],
        hosts_doc: "https://docs.x.ai/docs/overview",
        invalid_key: Some(InvalidKeyEvidence { status: 400, error_code: Some("invalid-argument"), error_code_field: Some("/code") }),
        default_provider_ids: &["xai"],
        display_name: "xAI (API Key)",
        default_id: "apikey:xai",
        dashboard_url: "https://console.x.ai",
        placeholder: "xai-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.x.ai/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[XAI],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "openai",
        fusiform_provider_id: Some("openai"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.openai.com"],
        hosts_doc: "https://developers.openai.com/api/reference/overview",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["openai"],
        display_name: "OpenAI (API Key)",
        default_id: "apikey:openai",
        dashboard_url: "https://platform.openai.com/api-keys",
        placeholder: "sk-proj-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.openai.com/v1/models",
            extra_headers: &[],
        },
        categories: LLM_AND_MEDIA,
        serves: &[OpenAI],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "google",
        fusiform_provider_id: Some("google"),
        auth: Some(AuthDescriptor { header: "x-goog-api-key", scheme: AuthScheme::Raw }),
        hosts: &["generativelanguage.googleapis.com"],
        hosts_doc: "https://ai.google.dev/api",
        invalid_key: Some(InvalidKeyEvidence { status: 400, error_code: Some("API_KEY_INVALID"), error_code_field: Some("/error/details/0/reason") }),
        default_provider_ids: &["google"],
        display_name: "Google AI Studio (API Key)",
        default_id: "apikey:google",
        dashboard_url: "https://aistudio.google.com/apikey",
        placeholder: "AIzaSy...",
        validation: KeyValidation::GetEndpoint {
            url: "https://generativelanguage.googleapis.com/v1beta/models",
            extra_headers: &[],
        },
        categories: LLM_AND_MEDIA,
        serves: &[Google],
        account_id_prompt: None,
    },
    // Anthropic's paid API, as opposed to the `oauth:anthropic` subscription login. A bare
    // `--provider anthropic` still means the OAuth login; this row is reached with
    // `--id apikey:anthropic` or from the picker. It joins `llm-provider` only, never
    // `anthropic-native`, which stays the subscription accounts' family.
    ApiKeyProvider {
        key: "anthropic",
        fusiform_provider_id: Some("anthropic"),
        auth: Some(AuthDescriptor { header: "x-api-key", scheme: AuthScheme::Raw }),
        hosts: &["api.anthropic.com"],
        hosts_doc: "https://platform.claude.com/docs/en/api/overview",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("authentication_error"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["anthropic-platform"],
        display_name: "Anthropic (API Key)",
        default_id: "apikey:anthropic",
        dashboard_url: "https://console.anthropic.com/settings/keys",
        placeholder: "sk-ant-api03-...",
        // GET /v1/models rejects a bad key with 401 and costs no tokens, unlike a
        // messages probe.
        validation: KeyValidation::GetEndpoint {
            url: "https://api.anthropic.com/v1/models",
            extra_headers: &[("anthropic-version", "2023-06-01")],
        },
        categories: LLM,
        serves: &[Anthropic],
        account_id_prompt: None,
    },
    // Inception Labs' API for its Mercury models: OpenAI-compatible, Bearer key, env var
    // INCEPTION_API_KEY in its docs (https://docs.inceptionlabs.ai/llms.txt). The key
    // prefix is undocumented, so the placeholder is generic.
    ApiKeyProvider {
        key: "inception",
        fusiform_provider_id: Some("inception"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.inceptionlabs.ai"],
        hosts_doc: "https://docs.inceptionlabs.ai/get-started.md",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["inception"],
        display_name: "Inception (Mercury)",
        default_id: "apikey:inception",
        dashboard_url: "https://platform.inceptionlabs.ai/dashboard/api-keys",
        placeholder: "API key",
        // A one-token chat completion, not GET /v1/models: the model listing answers 200
        // with or without a key, so it cannot tell a bad key from a good one, and no other
        // free authenticated endpoint exists. The body is validated before auth, so the
        // probe must be a well-formed request; with a bad key it then answers 401
        // `invalid_api_key`.
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.inceptionlabs.ai/v1",
            model: "mercury-2",
        },
        categories: LLM,
        serves: &[Inception],
        account_id_prompt: None,
    },
    // Cloudflare Workers AI, through Cloudflare's REST API. The token alone is not enough:
    // every Workers AI request path names the account, so this row also asks for the
    // (non-secret) account id and stores it as the record's identity `account_id`.
    //
    // The placeholder steers the operator to an account API token scoped to Workers AI
    // (Read and Edit). The Global API Key is never wanted: it grants the whole account,
    // and it authenticates with X-Auth-Email/X-Auth-Key headers rather than a Bearer
    // token, so it would not work here anyway.
    ApiKeyProvider {
        key: "cloudflare-workers-ai",
        fusiform_provider_id: Some("cloudflare-workers-ai"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.cloudflare.com"],
        hosts_doc: "https://developers.cloudflare.com/workers-ai/get-started/rest-api/",
        invalid_key: Some(InvalidKeyEvidence { status: 400, error_code: None, error_code_field: None }),
        default_provider_ids: &["cloudflare-workers-ai"],
        display_name: "Cloudflare Workers AI",
        default_id: "apikey:cloudflare-workers-ai",
        dashboard_url: "https://dash.cloudflare.com/profile/api-tokens",
        placeholder: "an API token with Workers AI Read and Edit permissions (not the Global API Key)",
        validation: KeyValidation::CloudflareWorkersAiModels {
            api_base: "https://api.cloudflare.com/client/v4",
        },
        categories: LLM,
        // A model host rather than a model maker, so like the other hosting rows `serves`
        // lists the vendors with at least one current text-generation model in the
        // catalog (https://developers.cloudflare.com/workers-ai/models/, read 2026-10-21):
        // gpt-oss, Gemma, DeepSeek, Mistral, Kimi, GLM, Llama, Qwen and Nemotron. Its
        // other text-generation authors (Cloudflare, IBM, swiss-ai and others) have no
        // `ModelVendor`.
        serves: &[OpenAI, Google, DeepSeek, Mistral, Moonshot, Zhipu, Meta, Qwen, Nvidia],
        account_id_prompt: Some(AccountIdPrompt {
            label: "Cloudflare account id (32 hex characters; shown on the dashboard's Account home and in the Workers AI 'Use REST API' panel)",
            format: AccountIdFormat::LowerHex32,
        }),
    },
    // The rows below mirror oh-my-pi's API-key providers. Each `// oh-my-pi auth/<key>.kdl`
    // line names the file (packages/catalog/src/compat/rules/auth/ in that repo) that the
    // display name, dashboard URL, placeholder and probe were copied from. Its validate
    // kinds map as: "models-endpoint" -> GetEndpoint with a Bearer key, "chat-completions"
    // -> OpenAiChat, "anthropic-messages" -> AnthropicMessages, and no probe (or one this
    // table cannot express) -> Unvalidated. "serves from its models.json rows" means the
    // vendor list was read off the model families of that provider's rows in
    // packages/catalog/src/models.json; families with no `ModelVendor` (Baidu, ByteDance,
    // Cohere and others) are left out, since `serves` is advisory and additive.
    // oh-my-pi auth/abliteration.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "abliteration",
        fusiform_provider_id: Some("abliteration-ai"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.abliteration.ai"],
        hosts_doc: "https://docs.abliteration.ai/api/introduction.md",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["abliteration-ai"],
        display_name: "Abliteration",
        default_id: "apikey:abliteration",
        dashboard_url: "https://abliteration.ai/console",
        placeholder: "ak_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.abliteration.ai/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[Zhipu],
        account_id_prompt: None,
    },
    // oh-my-pi auth/aiand.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "aiand",
        fusiform_provider_id: Some("aiand"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.aiand.com"],
        hosts_doc: "https://docs.aiand.com",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["aiand"],
        display_name: "ai&",
        default_id: "apikey:aiand",
        dashboard_url: "https://console.aiand.com/api-keys",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.aiand.com/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[OpenAI, Google, DeepSeek, Moonshot, Zhipu, Qwen],
        account_id_prompt: None,
    },
    // oh-my-pi auth/baseten.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "baseten",
        fusiform_provider_id: Some("baseten"),
        auth: Some(BEARER_AUTH),
        hosts: &["inference.baseten.co"],
        hosts_doc: "https://docs.baseten.co/reference/inference-api/chat-completions",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["baseten"],
        display_name: "Baseten",
        default_id: "apikey:baseten",
        dashboard_url: "https://app.baseten.co/settings/api_keys",
        placeholder: "bt_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://inference.baseten.co/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[OpenAI, DeepSeek, Moonshot, Zhipu, Nvidia],
        account_id_prompt: None,
    },
    // oh-my-pi auth/charm-hyper.kdl.
    // The probe is `/v1/credits`, not `/v1/models`: charm-hyper.kdl records that the models
    // endpoint is public and answers 200 for a bogus key, so it could never reject one.
    // The roster is live-only (no static model rows), so `serves` lists only the families
    // oh-my-pi's providers/charm-hyper.kdl names: GLM (default model), Kimi and Gemma.
    ApiKeyProvider {
        key: "charm-hyper",
        fusiform_provider_id: Some("hyper"),
        auth: Some(BEARER_AUTH),
        hosts: &["hyper.charm.land"],
        hosts_doc: "https://hyper.charm.land/docs",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("authentication_error"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["hyper"],
        display_name: "Charm Hyper",
        default_id: "apikey:charm-hyper",
        dashboard_url: "https://hyper.charm.land/",
        placeholder: "sk-hyper-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://hyper.charm.land/v1/credits",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[Google, Moonshot, Zhipu],
        account_id_prompt: None,
    },
    // oh-my-pi auth/cline-pass.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "cline-pass",
        fusiform_provider_id: Some("cline-pass"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.cline.bot"],
        hosts_doc: "https://docs.cline.bot/getting-started/clinepass",
        invalid_key: None,
        default_provider_ids: &[],
        display_name: "ClinePass",
        default_id: "apikey:cline-pass",
        dashboard_url: "https://app.cline.bot/dashboard/account",
        placeholder: "sk_...",
        validation: KeyValidation::Unvalidated {
            reason: "ClinePass checks keys on an account route that also needs client headers this login does not send",
        },
        categories: LLM,
        serves: &[Google, DeepSeek, Moonshot, Zhipu, Meta, Qwen, MiniMax, Xiaomi],
        account_id_prompt: None,
    },
    // oh-my-pi auth/commandcode.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "commandcode",
        fusiform_provider_id: Some("commandcode"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.commandcode.ai"],
        hosts_doc: "https://commandcode.ai/docs/provider",
        invalid_key: None,
        default_provider_ids: &["commandcode"],
        display_name: "Command Code",
        default_id: "apikey:commandcode",
        dashboard_url: "https://commandcode.ai/studio",
        placeholder: "user_...",
        validation: KeyValidation::Unvalidated {
            reason: "Command Code has no endpoint that rejects a bad key without billing it: its model list is public, and a chat probe bills the key and refuses Go-plan keys that are still valid",
        },
        categories: LLM,
        serves: &[Anthropic, OpenAI, Google, XAI, DeepSeek, Moonshot, Zhipu, Meta, Qwen, Nvidia, MiniMax, Xiaomi, StepFun],
        account_id_prompt: None,
    },
    // oh-my-pi auth/deepinfra.kdl; serves from its models.json rows.
    // A chat probe rather than `/models`: deepinfra.kdl records that DeepInfra's models
    // endpoint is public and would accept any string as a key.
    ApiKeyProvider {
        key: "deepinfra",
        fusiform_provider_id: Some("deepinfra"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.deepinfra.com"],
        hosts_doc: "https://docs.deepinfra.com/api-reference/introduction",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["deepinfra"],
        display_name: "DeepInfra",
        default_id: "apikey:deepinfra",
        dashboard_url: "https://deepinfra.com/dash/api_keys",
        placeholder: "...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.deepinfra.com/v1/openai",
            model: "deepseek-ai/DeepSeek-V4-Flash-0731",
        },
        categories: LLM,
        serves: &[Anthropic, OpenAI, Google, DeepSeek, Mistral, Moonshot, Zhipu, Meta, Qwen, Nvidia, MiniMax, Xiaomi],
        account_id_prompt: None,
    },
    // oh-my-pi auth/firepass.kdl; serves from its models.json rows.
    // firepass.kdl: Fire Pass keys are scoped to router endpoints and do not authorize
    // `/v1/models`, so the probe is a chat request to a router model.
    ApiKeyProvider {
        key: "firepass",
        fusiform_provider_id: Some("fireworks-fire-pass"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.fireworks.ai"],
        hosts_doc: "https://docs.fireworks.ai/firepass/",
        invalid_key: None,
        default_provider_ids: &[],
        display_name: "Fire Pass (Fireworks subscription)",
        default_id: "apikey:firepass",
        dashboard_url: "https://app.fireworks.ai/settings/users/api-keys",
        placeholder: "fpk_...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.fireworks.ai/inference/v1",
            model: "accounts/fireworks/routers/glm-5p2-fast",
        },
        categories: LLM,
        serves: &[Moonshot, Zhipu],
        account_id_prompt: None,
    },
    // oh-my-pi auth/gmi-cloud.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "gmi-cloud",
        fusiform_provider_id: Some("gmicloud"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.gmi-serving.com", "console.gmicloud.ai"],
        hosts_doc: "https://docs.gmicloud.ai/api-reference/introduction",
        invalid_key: None,
        default_provider_ids: &["gmicloud"],
        display_name: "GMI Cloud",
        default_id: "apikey:gmi-cloud",
        dashboard_url: "https://console.gmicloud.ai",
        placeholder: "eyJ...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.gmi-serving.com/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[DeepSeek],
        account_id_prompt: None,
    },
    // oh-my-pi auth/meta.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "meta",
        fusiform_provider_id: Some("meta"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.meta.ai"],
        hosts_doc: "https://dev.meta.ai/docs/api-reference",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &[],
        display_name: "Meta Model API",
        default_id: "apikey:meta",
        dashboard_url: "https://developer.meta.com/ai/",
        placeholder: "Model API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.meta.ai/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[Meta],
        account_id_prompt: None,
    },
    // oh-my-pi auth/minimax-code.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "minimax-code",
        fusiform_provider_id: Some("minimax-coding-plan"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.minimax.io", "www.minimax.io"],
        hosts_doc: "https://platform.minimax.io/docs/m-plan/faq",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("authorized_error"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["minimax-coding-plan"],
        display_name: "MiniMax Token Plan (International)",
        default_id: "apikey:minimax-code",
        dashboard_url: "https://platform.minimax.io/subscribe/token-plan",
        placeholder: "sk-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.minimax.io/v1",
            model: "MiniMax-M3",
        },
        categories: LLM,
        serves: &[MiniMax],
        account_id_prompt: None,
    },
    // oh-my-pi auth/minimax-code-cn.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "minimax-code-cn",
        fusiform_provider_id: Some("minimax-cn-coding-plan"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.minimax.cn", "www.minimax.cn"],
        hosts_doc: "https://platform.minimaxi.com/docs/m-plan/faq",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("authorized_error"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["minimax-cn-coding-plan"],
        display_name: "MiniMax Token Plan (China)",
        default_id: "apikey:minimax-code-cn",
        dashboard_url: "https://platform.minimaxi.com/subscribe/token-plan",
        placeholder: "sk-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.minimax.cn/v1",
            model: "MiniMax-M3",
        },
        categories: LLM,
        serves: &[MiniMax],
        account_id_prompt: None,
    },
    // oh-my-pi auth/nanogpt.kdl.
    // A broad aggregator: its catalog carries models from every vendor listed here.
    ApiKeyProvider {
        key: "nanogpt",
        fusiform_provider_id: Some("nano-gpt"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.nano-gpt.com", "nano-gpt.com"],
        hosts_doc: "https://docs.nano-gpt.com/api-reference/miscellaneous/api-hosts",
        invalid_key: None,
        default_provider_ids: &["nano-gpt"],
        display_name: "NanoGPT",
        default_id: "apikey:nanogpt",
        dashboard_url: "https://nano-gpt.com/api",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://nano-gpt.com/api/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: ModelVendor::ALL,
        account_id_prompt: None,
    },
    // oh-my-pi auth/novita.kdl; serves from its models.json rows.
    // novita.kdl: the probe is inference, not billing, because the billing route needs a
    // Balance permission some team roles lack, which rejected their valid keys.
    ApiKeyProvider {
        key: "novita",
        fusiform_provider_id: Some("novita-ai"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.novita.ai"],
        hosts_doc: "https://novita.ai/docs/api-reference",
        invalid_key: None,
        default_provider_ids: &["novita-ai"],
        display_name: "Novita",
        default_id: "apikey:novita",
        dashboard_url: "https://novita.ai/settings/key-management",
        placeholder: "sk_...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.novita.ai/openai/v1",
            model: "moonshotai/kimi-k2.7-code",
        },
        categories: LLM,
        serves: &[OpenAI, Google, DeepSeek, Mistral, Moonshot, Zhipu, Meta, Qwen, Nvidia, MiniMax, Xiaomi, StepFun],
        account_id_prompt: None,
    },
    // oh-my-pi auth/ollama-cloud.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "ollama-cloud",
        fusiform_provider_id: Some("ollama-cloud"),
        auth: Some(BEARER_AUTH),
        hosts: &["ollama.com"],
        hosts_doc: "https://docs.ollama.com/api/authentication",
        invalid_key: None,
        default_provider_ids: &["ollama-cloud"],
        display_name: "Ollama Cloud",
        default_id: "apikey:ollama-cloud",
        dashboard_url: "https://ollama.com/settings/keys",
        placeholder: "ollama-cloud-api-key",
        validation: KeyValidation::Unvalidated {
            reason: "no known Ollama Cloud endpoint reliably rejects a bad key without cost, so a wrong key shows up on first use",
        },
        categories: LLM_AND_WEB_SEARCH,
        serves: &[OpenAI, Google, DeepSeek, Mistral, Moonshot, Zhipu, Qwen, Nvidia, MiniMax],
        account_id_prompt: None,
    },
    // oh-my-pi auth/opencode-go.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "opencode-go",
        fusiform_provider_id: Some("opencode-go"),
        auth: Some(BEARER_AUTH),
        hosts: &["opencode.ai"],
        hosts_doc: "https://opencode.ai/docs/console/go/",
        invalid_key: None,
        default_provider_ids: &["opencode-go"],
        display_name: "OpenCode Go",
        default_id: "apikey:opencode-go",
        dashboard_url: "https://opencode.ai/auth",
        placeholder: "sk-...",
        validation: KeyValidation::Unvalidated {
            reason: "no known OpenCode Go endpoint reliably rejects a bad key without cost, so a wrong key shows up on first use",
        },
        categories: LLM,
        serves: &[OpenAI, XAI, DeepSeek, Moonshot, Zhipu, Meta, Qwen, MiniMax, Xiaomi],
        account_id_prompt: None,
    },
    // oh-my-pi auth/opencode-zen.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "opencode-zen",
        fusiform_provider_id: Some("opencode"),
        auth: Some(BEARER_AUTH),
        hosts: &["opencode.ai"],
        hosts_doc: "https://opencode.ai/docs/zen/",
        invalid_key: None,
        default_provider_ids: &["opencode"],
        display_name: "OpenCode Zen",
        default_id: "apikey:opencode-zen",
        dashboard_url: "https://opencode.ai/auth",
        placeholder: "sk-...",
        validation: KeyValidation::Unvalidated {
            reason: "no known OpenCode Zen endpoint reliably rejects a bad key without cost, so a wrong key shows up on first use",
        },
        categories: LLM,
        serves: &[Anthropic, OpenAI, Google, XAI, DeepSeek, Moonshot, Zhipu, Meta, Qwen, Nvidia, MiniMax, Xiaomi],
        account_id_prompt: None,
    },
    // oh-my-pi auth/qianfan.kdl; serves from its models.json rows.
    // Unvalidated rather than a chat probe: oh-my-pi's probe for Qianfan tolerates a 401
    // whose error code is `invalid_model` (the account lacks the probe model), and the
    // chat probe here treats every 401 as a bad key, so it would refuse valid keys.
    ApiKeyProvider {
        key: "qianfan",
        fusiform_provider_id: Some("qianfan"),
        auth: Some(BEARER_AUTH),
        hosts: &["qianfan.baidubce.com"],
        hosts_doc: "https://cloud.baidu.com/doc/qianfan/s/rmh4stn9m",
        invalid_key: None,
        default_provider_ids: &[],
        display_name: "Qianfan",
        default_id: "apikey:qianfan",
        dashboard_url: "https://console.bce.baidu.com/qianfan/ais/console/apiKey",
        placeholder: "bce-v3/ALTAK-...",
        validation: KeyValidation::Unvalidated {
            reason: "Qianfan answers 401 when the probe model is not enabled on the account, and this login cannot tell that apart from a bad key",
        },
        categories: LLM,
        serves: &[DeepSeek],
        account_id_prompt: None,
    },
    // oh-my-pi auth/qwen-portal.kdl.
    // Qwen's own portal (portal.qwen.ai); its model ids are opaque aliases, so `serves` is
    // the operator's own vendor rather than read off model ids.
    ApiKeyProvider {
        key: "qwen-portal",
        fusiform_provider_id: Some("qwen-portal"),
        auth: Some(BEARER_AUTH),
        hosts: &["portal.qwen.ai"],
        hosts_doc: "https://qwenlm.github.io/qwen-code-docs/en/users/configuration/auth/",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &[],
        display_name: "Qwen Portal",
        default_id: "apikey:qwen-portal",
        dashboard_url: "https://chat.qwen.ai",
        placeholder: "sk-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://portal.qwen.ai/v1",
            model: "coder-model",
        },
        categories: LLM,
        serves: &[Qwen],
        account_id_prompt: None,
    },
    // oh-my-pi auth/sakana.kdl.
    // Serves Sakana's own models only, and Sakana is not a vendor in `ModelVendor`.
    ApiKeyProvider {
        key: "sakana",
        fusiform_provider_id: Some("sakana"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.sakana.ai"],
        hosts_doc: "https://sakana.ai/",
        invalid_key: None,
        default_provider_ids: &["sakana"],
        display_name: "Sakana AI",
        default_id: "apikey:sakana",
        dashboard_url: "https://console.sakana.ai/api-keys",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.sakana.ai/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // oh-my-pi auth/siliconflow.kdl.
    // The roster is live-only; `serves` is only the default model's family (GLM) named in
    // oh-my-pi's providers/siliconflow.kdl, not the full catalog.
    ApiKeyProvider {
        key: "siliconflow",
        fusiform_provider_id: Some("siliconflow"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.siliconflow.com"],
        hosts_doc: "https://docs.siliconflow.com/en/api-reference/chat-completions/chat-completions",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["siliconflow"],
        display_name: "SiliconFlow",
        default_id: "apikey:siliconflow",
        dashboard_url: "https://cloud.siliconflow.com/account/ak",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.siliconflow.com/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[Zhipu],
        account_id_prompt: None,
    },
    // oh-my-pi auth/siliconflow-cn.kdl.
    // The roster is live-only; `serves` is only the default model's family (DeepSeek) named
    // in oh-my-pi's providers/siliconflow-cn.kdl, not the full catalog.
    ApiKeyProvider {
        key: "siliconflow-cn",
        fusiform_provider_id: Some("siliconflow-cn"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.siliconflow.cn"],
        hosts_doc: "https://docs.siliconflow.cn/api-reference/chat-completions/chat-completions",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["siliconflow-cn"],
        display_name: "SiliconFlow (China)",
        default_id: "apikey:siliconflow-cn",
        dashboard_url: "https://cloud.siliconflow.cn/account/ak",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.siliconflow.cn/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[DeepSeek],
        account_id_prompt: None,
    },
    // oh-my-pi auth/singularityapi-dev.kdl.
    // The roster is per key; `serves` is the families oh-my-pi's
    // providers/singularityapi-dev.kdl names (DeepSeek, Kimi, GLM), not the full catalog.
    ApiKeyProvider {
        key: "singularityapi-dev",
        fusiform_provider_id: Some("singularityapi"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.singularityapi.dev"],
        hosts_doc: "https://docs.singularityapi.dev/",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &[],
        display_name: "SingularityAPI",
        default_id: "apikey:singularityapi-dev",
        dashboard_url: "https://app.singularityapi.dev",
        placeholder: "sk-sapi-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.singularityapi.dev/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[DeepSeek, Moonshot, Zhipu],
        account_id_prompt: None,
    },
    // oh-my-pi auth/singularityapi-tech.kdl. The roster is per key (no models.json rows);
    // `serves` comes from oh-my-pi's providers/singularityapi-tech.kdl, which says this
    // deployment routes requests only to DeepSeek models.
    ApiKeyProvider {
        key: "singularityapi-tech",
        fusiform_provider_id: Some("singularityapi-reserved"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.singularityapi.tech"],
        hosts_doc: "https://singularityapi.tech/",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("401"), error_code_field: Some("/error/code") }),
        default_provider_ids: &[],
        display_name: "SingularityAPI Reserved Lanes",
        default_id: "apikey:singularityapi-tech",
        dashboard_url: "https://app.singularityapi.tech/compute/billing",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.singularityapi.tech/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[DeepSeek],
        account_id_prompt: None,
    },
    // oh-my-pi auth/stepfun.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "stepfun",
        fusiform_provider_id: Some("stepfun-ai"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.stepfun.ai"],
        hosts_doc: "https://platform.stepfun.ai/docs/en/quickstart/overview",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["stepfun-ai"],
        display_name: "StepFun",
        default_id: "apikey:stepfun",
        dashboard_url: "https://platform.stepfun.ai/interface-key",
        placeholder: "...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.stepfun.ai/v1",
            model: "step-5-preview",
        },
        categories: LLM,
        serves: &[StepFun],
        account_id_prompt: None,
    },
    // oh-my-pi auth/synthetic.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "synthetic",
        fusiform_provider_id: Some("synthetic"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.synthetic.new"],
        hosts_doc: "https://dev.synthetic.new/docs/api/overview",
        invalid_key: None,
        default_provider_ids: &["synthetic"],
        display_name: "Synthetic",
        default_id: "apikey:synthetic",
        dashboard_url: "https://dev.synthetic.new/docs/api/overview",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.synthetic.new/openai/v1/models",
            extra_headers: &[],
        },
        categories: LLM_AND_WEB_SEARCH,
        serves: &[OpenAI, DeepSeek, Moonshot, Zhipu, Qwen, Nvidia],
        account_id_prompt: None,
    },
    // oh-my-pi auth/typesafe.kdl.
    // Serves TypeSafe's own judgment models only, which match no vendor in `ModelVendor`.
    ApiKeyProvider {
        key: "typesafe",
        fusiform_provider_id: Some("typesafe"),
        auth: None,
        hosts: &[],
        hosts_doc: "https://docs.typesafe.ai/introduction/quickstart",
        invalid_key: None,
        default_provider_ids: &["typesafe"],
        display_name: "TypeSafe",
        default_id: "apikey:typesafe",
        dashboard_url: "https://console.typesafe.ai/",
        placeholder: "API key",
        validation: KeyValidation::Unvalidated {
            reason: "a TypeSafe key may belong to a deployment at a custom base URL, and probing the public host would refuse it",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // oh-my-pi auth/umans.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "umans",
        fusiform_provider_id: Some("umans-ai-coding-plan"),
        auth: Some(AuthDescriptor { header: "x-api-key", scheme: AuthScheme::Raw }),
        hosts: &["api.code.umans.ai"],
        hosts_doc: "https://app.umans.ai/offers/code/docs",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("authentication_error"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["umans-ai-coding-plan"],
        display_name: "Umans AI Coding Plan",
        default_id: "apikey:umans",
        dashboard_url: "https://app.umans.ai/billing",
        placeholder: "sk-...",
        validation: KeyValidation::AnthropicMessages {
            base_url: "https://api.code.umans.ai",
            model: "umans-coder",
        },
        categories: LLM,
        serves: &[DeepSeek, Moonshot, Zhipu, Qwen, Xiaomi],
        account_id_prompt: None,
    },
    // oh-my-pi auth/venice.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "venice",
        fusiform_provider_id: Some("venice"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.venice.ai"],
        hosts_doc: "https://docs.venice.ai/api-reference",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["venice"],
        display_name: "Venice",
        default_id: "apikey:venice",
        dashboard_url: "https://venice.ai/settings/api",
        placeholder: "vapi_...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.venice.ai/api/v1",
            model: "qwen3-4b",
        },
        categories: LLM,
        serves: &[Anthropic, OpenAI, Google, XAI, DeepSeek, Mistral, Moonshot, Zhipu, Meta, Qwen, Nvidia, MiniMax, Xiaomi],
        account_id_prompt: None,
    },
    // oh-my-pi auth/vercel-ai-gateway.kdl.
    // A broad aggregator: its catalog carries models from every vendor listed here.
    ApiKeyProvider {
        key: "vercel-ai-gateway",
        fusiform_provider_id: Some("vercel"),
        auth: Some(BEARER_AUTH),
        hosts: &["ai-gateway.vercel.sh"],
        hosts_doc: "https://vercel.com/docs/ai-gateway/authentication-and-byok",
        invalid_key: None,
        default_provider_ids: &["vercel"],
        display_name: "Vercel AI Gateway",
        default_id: "apikey:vercel-ai-gateway",
        dashboard_url: "https://vercel.com/d?to=%2F%5Bteam%5D%2F%7E%2Fai-gateway%2Fapi-keys&title=AI+Gateway+API+Keys",
        placeholder: "vck_...",
        validation: KeyValidation::Unvalidated {
            reason: "no known Vercel AI Gateway endpoint reliably rejects a bad key without cost, so a wrong key shows up on first use",
        },
        categories: LLM,
        serves: ModelVendor::ALL,
        account_id_prompt: None,
    },
    // oh-my-pi auth/wafer-serverless.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "wafer-serverless",
        fusiform_provider_id: Some("wafer.ai"),
        auth: Some(BEARER_AUTH),
        hosts: &["pass.wafer.ai"],
        hosts_doc: "https://docs.wafer.ai",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &[],
        display_name: "Wafer Serverless (pay-as-you-go)",
        default_id: "apikey:wafer-serverless",
        dashboard_url: "https://app.wafer.ai/usage",
        placeholder: "wfr_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://pass.wafer.ai/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[DeepSeek, Moonshot, Zhipu, Qwen, MiniMax],
        account_id_prompt: None,
    },
    // oh-my-pi auth/xiaomi-token-plan-ams.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "xiaomi-token-plan-ams",
        fusiform_provider_id: Some("xiaomi-token-plan-ams"),
        auth: Some(BEARER_AUTH),
        hosts: &["token-plan-ams.xiaomimimo.com"],
        hosts_doc: "https://platform.xiaomimimo.com/docs",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("401"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["xiaomi-token-plan-ams"],
        display_name: "Xiaomi Token Plan (Europe)",
        default_id: "apikey:xiaomi-token-plan-ams",
        dashboard_url: "https://platform.xiaomimimo.com/console/plan-manage",
        placeholder: "tp-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://token-plan-ams.xiaomimimo.com/v1",
            model: "mimo-v2.5",
        },
        categories: LLM,
        serves: &[Xiaomi],
        account_id_prompt: None,
    },
    // oh-my-pi auth/xiaomi-token-plan-cn.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "xiaomi-token-plan-cn",
        fusiform_provider_id: Some("xiaomi-token-plan-cn"),
        auth: Some(BEARER_AUTH),
        hosts: &["token-plan-cn.xiaomimimo.com"],
        hosts_doc: "https://platform.xiaomimimo.com/docs",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("401"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["xiaomi-token-plan-cn"],
        display_name: "Xiaomi Token Plan (China)",
        default_id: "apikey:xiaomi-token-plan-cn",
        dashboard_url: "https://platform.xiaomimimo.com/console/plan-manage",
        placeholder: "tp-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://token-plan-cn.xiaomimimo.com/v1",
            model: "mimo-v2.5",
        },
        categories: LLM,
        serves: &[Xiaomi],
        account_id_prompt: None,
    },
    // oh-my-pi auth/xiaomi-token-plan-sgp.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "xiaomi-token-plan-sgp",
        fusiform_provider_id: Some("xiaomi-token-plan-sgp"),
        auth: Some(BEARER_AUTH),
        hosts: &["token-plan-sgp.xiaomimimo.com"],
        hosts_doc: "https://platform.xiaomimimo.com/docs",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("401"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["xiaomi-token-plan-sgp"],
        display_name: "Xiaomi Token Plan (Singapore)",
        default_id: "apikey:xiaomi-token-plan-sgp",
        dashboard_url: "https://platform.xiaomimimo.com/console/plan-manage",
        placeholder: "tp-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://token-plan-sgp.xiaomimimo.com/v1",
            model: "mimo-v2.5",
        },
        categories: LLM,
        serves: &[Xiaomi],
        account_id_prompt: None,
    },
    // oh-my-pi auth/yolo-auto.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "yolo-auto",
        fusiform_provider_id: Some("yolo-auto"),
        auth: Some(BEARER_AUTH),
        hosts: &["yolo-auto.com"],
        hosts_doc: "https://yolo-auto.com/docs/api",
        invalid_key: None,
        default_provider_ids: &[],
        display_name: "Yolo-Auto",
        default_id: "apikey:yolo-auto",
        dashboard_url: "https://yolo-auto.com/app",
        placeholder: "yolo_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://yolo-auto.com/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[DeepSeek, Qwen],
        account_id_prompt: None,
    },
    // oh-my-pi auth/zenmux.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "zenmux",
        fusiform_provider_id: Some("zenmux"),
        auth: Some(BEARER_AUTH),
        hosts: &["zenmux.ai"],
        hosts_doc: "https://docs.zenmux.ai/docs/guide/quickstart.html",
        invalid_key: None,
        default_provider_ids: &["zenmux"],
        display_name: "ZenMux",
        default_id: "apikey:zenmux",
        dashboard_url: "https://zenmux.ai/settings/keys",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://zenmux.ai/api/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[Anthropic, OpenAI, Google, XAI, DeepSeek, Mistral, Moonshot, Zhipu, Meta, Qwen, MiniMax, Xiaomi, StepFun],
        account_id_prompt: None,
    },
    // oh-my-pi auth/zhipu-coding-plan.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "zhipu-coding-plan",
        fusiform_provider_id: Some("zhipuai-coding-plan"),
        auth: Some(BEARER_AUTH),
        hosts: &["open.bigmodel.cn"],
        hosts_doc: "https://docs.bigmodel.cn/cn/coding-plan/quick-start",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("401"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["zhipuai-coding-plan"],
        display_name: "Zhipu Coding Plan (智谱)",
        default_id: "apikey:zhipu-coding-plan",
        dashboard_url: "https://bigmodel.cn/coding-plan/personal/overview",
        placeholder: "<id>.<secret>",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://open.bigmodel.cn/api/coding/paas/v4",
            model: "glm-5.1",
        },
        categories: LLM,
        serves: &[Zhipu],
        account_id_prompt: None,
    },
    // oh-my-pi auth/tavily.kdl. A web search API, not a model provider.
    ApiKeyProvider {
        key: "kimi-for-coding",
        fusiform_provider_id: Some("kimi-code-plan-global"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.kimi.ai", "api.kimi.com"],
        hosts_doc: "https://www.kimi.com/code/docs/en",
        invalid_key: None,
        default_provider_ids: &["kimi-code-plan-global"],
        display_name: "Kimi for Coding",
        default_id: "apikey:kimi-for-coding",
        dashboard_url: "https://www.kimi.com/code/console",
        placeholder: "sk-...",
        validation: KeyValidation::Unvalidated {
            reason: "No known endpoint reliably rejects an invalid key without cost.",
        },
        categories: LLM_AND_WEB_SEARCH,
        serves: &[Moonshot],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "tavily",
        fusiform_provider_id: None,
        auth: Some(BEARER_AUTH),
        hosts: &["api.tavily.com"],
        hosts_doc: "https://docs.tavily.com/documentation/api-reference/endpoint/search",
        invalid_key: None,
        default_provider_ids: &[],
        display_name: "Tavily",
        default_id: "apikey:tavily",
        dashboard_url: "https://app.tavily.com/home",
        placeholder: "tvly-...",
        validation: KeyValidation::Unvalidated {
            reason: "no known Tavily endpoint reliably rejects a bad key without cost, so a wrong key shows up on first use",
        },
        categories: WEB_SEARCH,
        serves: &[],
        account_id_prompt: None,
    },
    // oh-my-pi auth/kagi.kdl. A web search API, not a model provider.
    ApiKeyProvider {
        key: "kagi",
        fusiform_provider_id: None,
        auth: None,
        hosts: &["kagi.com"],
        hosts_doc: "https://help.kagi.com/kagi/api/api-portal.html",
        invalid_key: None,
        default_provider_ids: &[],
        display_name: "Kagi",
        default_id: "apikey:kagi",
        dashboard_url: "https://kagi.com/settings/api",
        placeholder: "KG_...",
        validation: KeyValidation::Unvalidated {
            reason: "no known Kagi endpoint reliably rejects a bad key without cost, so a wrong key shows up on first use",
        },
        categories: WEB_SEARCH,
        serves: &[],
        account_id_prompt: None,
    },
    // oh-my-pi auth/exa.kdl. A web search API, not a model provider.
    ApiKeyProvider {
        key: "exa",
        fusiform_provider_id: None,
        auth: Some(AuthDescriptor { header: "x-api-key", scheme: AuthScheme::Raw }),
        hosts: &["api.exa.ai"],
        hosts_doc: "https://docs.exa.ai/reference/search",
        invalid_key: None,
        default_provider_ids: &[],
        display_name: "Exa",
        default_id: "apikey:exa",
        dashboard_url: "https://dashboard.exa.ai/api-keys",
        placeholder: "API key",
        validation: KeyValidation::Unvalidated {
            reason: "no known Exa endpoint reliably rejects a bad key without cost, so a wrong key shows up on first use",
        },
        categories: WEB_SEARCH,
        serves: &[],
        account_id_prompt: None,
    },
    // oh-my-pi auth/parallel.kdl. A web search API, not a model provider.
    ApiKeyProvider {
        key: "parallel",
        fusiform_provider_id: None,
        auth: Some(AuthDescriptor { header: "x-api-key", scheme: AuthScheme::Raw }),
        hosts: &["api.parallel.ai"],
        hosts_doc: "https://docs.parallel.ai/api-reference/search",
        invalid_key: None,
        default_provider_ids: &[],
        display_name: "Parallel",
        default_id: "apikey:parallel",
        dashboard_url: "https://platform.parallel.ai/settings?tab=api-keys",
        placeholder: "sk_...",
        validation: KeyValidation::Unvalidated {
            reason: "no known Parallel endpoint reliably rejects a bad key without cost, so a wrong key shows up on first use",
        },
        categories: WEB_SEARCH,
        serves: &[],
        account_id_prompt: None,
    },
    // Brave documents this header and endpoint, but not a distinct bad-key response; keep
    // the credential unchecked instead of treating every authorization refusal as a bad key.
    // https://api-dashboard.search.brave.com/documentation/guides/authentication
    // https://api-dashboard.search.brave.com/api-reference/web/search/get
    ApiKeyProvider {
        key: "brave",
        fusiform_provider_id: None,
        auth: Some(AuthDescriptor { header: "x-subscription-token", scheme: AuthScheme::Raw }),
        hosts: &["api.search.brave.com"],
        hosts_doc: "https://api-dashboard.search.brave.com/documentation/guides/authentication",
        invalid_key: None,
        default_provider_ids: &[],
        display_name: "Brave Search",
        default_id: "apikey:brave",
        dashboard_url: "https://api-dashboard.search.brave.com/app/keys",
        placeholder: "API key",
        validation: KeyValidation::Unvalidated {
            reason: "Brave documents no distinct invalid-key response for its Search API",
        },
        categories: WEB_SEARCH,
        serves: &[],
        account_id_prompt: None,
    },
    // Firecrawl documents the exact invalid-token message on its read-only credit-usage route.
    // https://docs.firecrawl.dev/api-reference/introduction
    // https://docs.firecrawl.dev/api-reference/endpoint/credit-usage
    // https://docs.firecrawl.dev/api-reference/errors
    ApiKeyProvider {
        key: "firecrawl",
        fusiform_provider_id: None,
        auth: Some(BEARER_AUTH),
        hosts: &["api.firecrawl.dev"],
        hosts_doc: "https://docs.firecrawl.dev/api-reference/introduction",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &[],
        display_name: "Firecrawl",
        default_id: "apikey:firecrawl",
        dashboard_url: "https://www.firecrawl.dev/app/api-keys",
        placeholder: "fc-...",
        validation: KeyValidation::FirecrawlCreditUsage {
            url: "https://api.firecrawl.dev/v2/team/credit-usage",
        },
        categories: WEB_SEARCH,
        serves: &[],
        account_id_prompt: None,
    },
    // Jina documents bearer auth but no unique invalid-key response, so do not use a
    // metered embedding request as a login probe.
    // https://docs.jina.ai/embedding-api
    ApiKeyProvider {
        key: "jina",
        fusiform_provider_id: None,
        auth: Some(BEARER_AUTH),
        hosts: &["api.jina.ai", "eu.r.jina.ai", "eu.s.jina.ai", "r.jina.ai", "s.jina.ai"],
        hosts_doc: "https://docs.jina.ai/embedding-api",
        invalid_key: None,
        default_provider_ids: &[],
        display_name: "Jina AI",
        default_id: "apikey:jina",
        dashboard_url: "https://jina.ai/?sui=apikey",
        placeholder: "jina_...",
        validation: KeyValidation::Unvalidated {
            reason: "Jina's public API docs do not specify a distinct invalid-key response",
        },
        categories: WEB_SEARCH,
        serves: &[],
        account_id_prompt: None,
    },
    // TinyFish's wallet read is authenticated with X-API-Key and documents
    // INVALID_API_KEY separately from the missing-key response.
    // https://docs.tinyfish.ai/authentication
    // https://docs.tinyfish.ai/error-codes
    ApiKeyProvider {
        key: "tinyfish",
        fusiform_provider_id: None,
        auth: Some(AuthDescriptor { header: "x-api-key", scheme: AuthScheme::Raw }),
        hosts: &["agent.tinyfish.ai", "api.browser.tinyfish.ai", "api.fetch.tinyfish.ai", "api.search.tinyfish.ai", "api.tinyfish.ai"],
        hosts_doc: "https://docs.tinyfish.ai/authentication",
        invalid_key: None,
        default_provider_ids: &[],
        display_name: "TinyFish",
        default_id: "apikey:tinyfish",
        dashboard_url: "https://agent.tinyfish.ai/api-keys",
        placeholder: "API key",
        validation: KeyValidation::TinyFishWallet {
            url: "https://api.tinyfish.ai/v1/wallet",
        },
        categories: WEB_SEARCH,
        serves: &[],
        account_id_prompt: None,
    },
    // SearXNG instances are self-hosted; only instances requiring an API key need a stored key.
    ApiKeyProvider {
        key: "searxng",
        fusiform_provider_id: None,
        auth: None,
        hosts: &[],
        hosts_doc: "https://docs.searxng.org/dev/search_api.html",
        invalid_key: None,
        default_provider_ids: &[],
        display_name: "SearXNG",
        default_id: "apikey:searxng",
        dashboard_url: "https://docs.searxng.org/admin/settings/settings.html",
        placeholder: "API key",
        validation: KeyValidation::Unvalidated {
            reason: "SearXNG is self-hosted, so there is no shared endpoint to check a key against; a wrong key shows up on first use",
        },
        categories: WEB_SEARCH,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "elevenlabs",
        fusiform_provider_id: Some("elevenlabs"),
        auth: Some(AuthDescriptor { header: "xi-api-key", scheme: AuthScheme::Raw }),
        hosts: &["api.elevenlabs.io"],
        hosts_doc: "https://elevenlabs.io/docs/api-reference/authentication",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("unauthorized"), error_code_field: Some("/detail/code") }),
        default_provider_ids: &["elevenlabs"],
        display_name: "ElevenLabs",
        default_id: "apikey:elevenlabs",
        dashboard_url: "https://elevenlabs.io/app/settings/api-keys",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.elevenlabs.io/v1/user",
            extra_headers: &[],
        },
        categories: MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    // Rows below were taken from each provider's own documentation, starting from the
    // proposal that `cargo run -p credentials-core --example ckdev_provider_rows` prints
    // for its Fusiform id. Checks that answered a deliberately bogus key are recorded in
    // docs/provider-key-evidence.md.
    //
    // 302.AI's OpenAI SDK guide sets this base URL with the key as the SDK's API key,
    // which the SDK sends as a Bearer token.
    ApiKeyProvider {
        key: "302ai",
        fusiform_provider_id: Some("302ai"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.302.ai"],
        hosts_doc: "https://help.302.ai/docs/ji-cheng-dao-OpenAI-guan-fang-SDK",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["302ai"],
        display_name: "302.AI",
        default_id: "apikey:302ai",
        dashboard_url: "https://dash.302.ai/apis/list",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.302.ai/v1/models",
            extra_headers: &[],
        },
        categories: LLM_AND_MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    // Abacus.AI's self-serve RouteLLM host; Enterprise workspaces use a per-workspace
    // host that this row does not cover. Its model list is public, so the check is a chat.
    ApiKeyProvider {
        key: "abacus",
        fusiform_provider_id: Some("abacus"),
        auth: Some(BEARER_AUTH),
        hosts: &["routellm.abacus.ai"],
        hosts_doc: "https://abacus.ai/help/route-llm/",
        invalid_key: Some(InvalidKeyEvidence { status: 403, error_code: Some("GenericPermissionDeniedError"), error_code_field: Some("/errorType") }),
        default_provider_ids: &["abacus"],
        display_name: "Abacus",
        default_id: "apikey:abacus",
        dashboard_url: "https://abacus.ai/app/route-llm-apis",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://routellm.abacus.ai/v1",
            model: "route-llm",
        },
        categories: LLM_AND_MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    // above.dev's model list is public, so the check is a chat.
    ApiKeyProvider {
        key: "above",
        fusiform_provider_id: Some("above"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.above.dev"],
        hosts_doc: "https://above.dev/docs",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["above"],
        display_name: "above.dev",
        default_id: "apikey:above",
        dashboard_url: "https://above.dev/dashboard",
        placeholder: "sk-gw-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.above.dev/v1",
            model: "deepseek-v4.1-flash",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // AgentRouter's own Claude app guide sends users to ps.air-outer.com to create tokens.
    ApiKeyProvider {
        key: "agentrouter",
        fusiform_provider_id: Some("agentrouter"),
        auth: Some(BEARER_AUTH),
        hosts: &["agentrouter.org"],
        hosts_doc: "https://agentrouter.org/docs/opencode.html",
        invalid_key: None,
        default_provider_ids: &["agentrouter"],
        display_name: "AgentRouter",
        default_id: "apikey:agentrouter",
        dashboard_url: "https://ps.air-outer.com/console/token",
        placeholder: "sk-...",
        validation: KeyValidation::Unvalidated {
            reason: "AgentRouter answers 401 \"unauthorized client detected\" to requests from clients it does not recognise, with or without a key, so a check cannot tell a bad key from a good one",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Agnes AI's model list does not need a key, so the check is a chat.
    ApiKeyProvider {
        key: "agnes",
        fusiform_provider_id: Some("agnes"),
        auth: Some(BEARER_AUTH),
        hosts: &["apihub.agnes-ai.com"],
        hosts_doc: "https://agnes-ai.com/doc",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["agnes"],
        display_name: "Agnes AI",
        default_id: "apikey:agnes",
        dashboard_url: "https://agnes-ai.com",
        placeholder: "sk-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://apihub.agnes-ai.com/v1",
            model: "agnes-3.0-flash",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // AI-ROUTER documents its API without a /v1 prefix.
    ApiKeyProvider {
        key: "ai-router",
        fusiform_provider_id: Some("ai-router"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.ai-router.dev"],
        hosts_doc: "https://ai-router.dev/docs/getting-started/first-request/",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("INVALID_API_KEY"), error_code_field: Some("/code") }),
        default_provider_ids: &["ai-router"],
        display_name: "AI-ROUTER",
        default_id: "apikey:ai-router",
        dashboard_url: "https://ai-router.dev",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.ai-router.dev/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // AI21's model list answers any key, so the check lists the account's library files.
    ApiKeyProvider {
        key: "ai21",
        fusiform_provider_id: Some("ai21"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.ai21.com"],
        hosts_doc: "https://docs.ai21.com/reference/authentication",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["ai21"],
        display_name: "AI21 Labs",
        default_id: "apikey:ai21",
        dashboard_url: "https://studio.ai21.com/v2?tab=maestro",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.ai21.com/studio/v1/library/files",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // AIHubMix documents api.inferera.com as a fallback for aihubmix.com. Its model list
    // answers any key, so the check is a chat.
    ApiKeyProvider {
        key: "aihubmix",
        fusiform_provider_id: Some("aihubmix"),
        auth: Some(BEARER_AUTH),
        hosts: &["aihubmix.com", "api.inferera.com"],
        hosts_doc: "https://docs.aihubmix.com/cn/quick-start",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["aihubmix"],
        display_name: "AIHubMix",
        default_id: "apikey:aihubmix",
        dashboard_url: "https://console.aihubmix.com/workspaces/default/keys",
        placeholder: "sk-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://aihubmix.com/v1",
            model: "gpt-4o-mini",
        },
        categories: LLM_AND_MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    // AI/ML API's model list is public, so the check reads the account balance.
    ApiKeyProvider {
        key: "aimlapi",
        fusiform_provider_id: Some("aimlapi"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.aimlapi.com"],
        hosts_doc: "https://docs.aimlapi.com/readme-1",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("UnauthorizedException"), error_code_field: Some("/error/name") }),
        default_provider_ids: &["aimlapi"],
        display_name: "AI/ML API",
        default_id: "apikey:aimlapi",
        dashboard_url: "https://aimlapi.com/app/keys",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.aimlapi.com/v2/billing",
            extra_headers: &[],
        },
        categories: LLM_AND_MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    // ainetcafe's K3 guides send keys to its API host, microquickjs.com.
    ApiKeyProvider {
        key: "ainetcafe",
        fusiform_provider_id: Some("ainetcafe"),
        auth: Some(BEARER_AUTH),
        hosts: &["microquickjs.com"],
        hosts_doc: "https://ainetcafe.com/k3/guides/codewhale.html",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["ainetcafe"],
        display_name: "ainetcafe",
        default_id: "apikey:ainetcafe",
        dashboard_url: "https://microquickjs.com",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://microquickjs.com/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "aixy",
        fusiform_provider_id: Some("aixy"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.aixy-gateway.com"],
        hosts_doc: "https://docs.aixy-gateway.com/integrations/overview",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_gateway_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["aixy"],
        display_name: "Aixy",
        default_id: "apikey:aixy",
        dashboard_url: "https://docs.aixy-gateway.com/quickstart",
        placeholder: "gak_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.aixy-gateway.com/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "aki-io",
        fusiform_provider_id: Some("aki-io"),
        auth: Some(BEARER_AUTH),
        hosts: &["aki.io"],
        hosts_doc: "https://aki.io/docs/compatibility/openai-api-compatibility/",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["aki-io"],
        display_name: "AKI.IO",
        default_id: "apikey:aki-io",
        dashboard_url: "https://aki.io/admin/user",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://aki.io/openai/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Alibaba Cloud Model Studio, Singapore region. Keys belong to one region; keys from
    // other regions and workspace-specific hosts are not covered by this row.
    ApiKeyProvider {
        key: "alibaba",
        fusiform_provider_id: Some("alibaba"),
        auth: Some(BEARER_AUTH),
        hosts: &["dashscope-intl.aliyuncs.com"],
        hosts_doc: "https://www.alibabacloud.com/help/en/model-studio/base-url",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["alibaba"],
        display_name: "Alibaba",
        default_id: "apikey:alibaba",
        dashboard_url: "https://modelstudio.console.alibabacloud.com/ap-southeast-1/settings/api-key",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/models",
            extra_headers: &[],
        },
        categories: LLM_AND_MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    // Alibaba Cloud Model Studio, Beijing region; workspace-specific hosts are not covered.
    ApiKeyProvider {
        key: "alibaba-cn",
        fusiform_provider_id: Some("alibaba-cn"),
        auth: Some(BEARER_AUTH),
        hosts: &["dashscope.aliyuncs.com"],
        hosts_doc: "https://help.aliyun.com/zh/model-studio/base-url",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["alibaba-cn"],
        display_name: "Alibaba (China)",
        default_id: "apikey:alibaba-cn",
        dashboard_url: "https://bailian.console.aliyun.com/cn-beijing/model/settings/api-key",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://dashscope.aliyuncs.com/compatible-mode/v1/models",
            extra_headers: &[],
        },
        categories: LLM_AND_MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    // Coding Plan keys are for interactive coding tools. The plan's model list answers
    // any key, so the check is a chat.
    ApiKeyProvider {
        key: "alibaba-coding-plan",
        fusiform_provider_id: Some("alibaba-coding-plan"),
        auth: Some(BEARER_AUTH),
        hosts: &["coding-intl.dashscope.aliyuncs.com"],
        hosts_doc: "https://www.alibabacloud.com/help/en/model-studio/coding-plan",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["alibaba-coding-plan"],
        display_name: "Alibaba Coding Plan",
        default_id: "apikey:alibaba-coding-plan",
        dashboard_url: "https://modelstudio.console.alibabacloud.com/ap-southeast-1/subscription/coding-plan",
        placeholder: "sk-sp-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://coding-intl.dashscope.aliyuncs.com/v1",
            model: "qwen3.5-plus",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // The China Coding Plan; its model list answers any key, so the check is a chat.
    ApiKeyProvider {
        key: "alibaba-coding-plan-cn",
        fusiform_provider_id: Some("alibaba-coding-plan-cn"),
        auth: Some(BEARER_AUTH),
        hosts: &["coding.dashscope.aliyuncs.com"],
        hosts_doc: "https://help.aliyun.com/zh/model-studio/coding-plan",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["alibaba-coding-plan-cn"],
        display_name: "Alibaba Coding Plan (China)",
        default_id: "apikey:alibaba-coding-plan-cn",
        dashboard_url: "https://bailian.console.aliyun.com/cn-beijing/subscription/coding-plan",
        placeholder: "sk-sp-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://coding.dashscope.aliyuncs.com/v1",
            model: "qwen3.5-plus",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "alibaba-token-plan",
        fusiform_provider_id: Some("alibaba-token-plan"),
        auth: Some(BEARER_AUTH),
        hosts: &["token-plan.ap-southeast-1.maas.aliyuncs.com"],
        hosts_doc: "https://www.alibabacloud.com/help/en/model-studio/base-url",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("InvalidApiKey"), error_code_field: Some("/code") }),
        default_provider_ids: &["alibaba-token-plan"],
        display_name: "Alibaba Token Plan",
        default_id: "apikey:alibaba-token-plan",
        dashboard_url: "https://modelstudio.console.alibabacloud.com/subscription/token-plan/personal",
        placeholder: "sk-sp-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1/models",
            extra_headers: &[],
        },
        categories: LLM_AND_MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "alibaba-token-plan-cn",
        fusiform_provider_id: Some("alibaba-token-plan-cn"),
        auth: Some(BEARER_AUTH),
        hosts: &["token-plan.cn-beijing.maas.aliyuncs.com"],
        hosts_doc: "https://help.aliyun.com/zh/model-studio/base-url",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("InvalidApiKey"), error_code_field: Some("/code") }),
        default_provider_ids: &["alibaba-token-plan-cn"],
        display_name: "Alibaba Token Plan (China)",
        default_id: "apikey:alibaba-token-plan-cn",
        dashboard_url: "https://bailian.console.aliyun.com/cn-beijing/subscription/token-plan/personal",
        placeholder: "sk-sp-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1/models",
            extra_headers: &[],
        },
        categories: LLM_AND_MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    // Ambient's model list needs no key, so the check lists the account's assistants.
    ApiKeyProvider {
        key: "ambient",
        fusiform_provider_id: Some("ambient"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.ambient.xyz"],
        hosts_doc: "https://ambient.xyz/docs/build/api",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("authentication_error"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["ambient"],
        display_name: "Ambient",
        default_id: "apikey:ambient",
        dashboard_url: "https://app.ambient.xyz/keys",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.ambient.xyz/v1/assistants",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // AMD Radeon Cloud Token Factory, served from AMD's China developer site.
    ApiKeyProvider {
        key: "amd",
        fusiform_provider_id: Some("amd"),
        auth: Some(BEARER_AUTH),
        hosts: &["developer.amd.com.cn"],
        hosts_doc: "https://amd-aim.github.io/radeon-cloud-docs/api/authentication/",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["amd"],
        display_name: "AMD",
        default_id: "apikey:amd",
        dashboard_url: "https://developer.amd.com.cn/radeon/tokenfactory",
        placeholder: "rc-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://developer.amd.com.cn/radeon/api/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "anyapi",
        fusiform_provider_id: Some("anyapi"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.anyapi.ai"],
        hosts_doc: "https://docs.anyapi.ai/guides/authentication",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("401"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["anyapi"],
        display_name: "AnyAPI",
        default_id: "apikey:anyapi",
        dashboard_url: "https://dash.anyapi.ai/?page=api-keys",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.anyapi.ai/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "arcee",
        fusiform_provider_id: Some("arcee"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.arcee.ai"],
        hosts_doc: "https://docs.arcee.ai/api-reference/your-first-api-call",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["arcee"],
        display_name: "Arcee",
        default_id: "apikey:arcee",
        dashboard_url: "https://platform.arcee.ai/api/api-keys",
        placeholder: "rcai-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.arcee.ai/api/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "auriko",
        fusiform_provider_id: Some("auriko"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.auriko.ai"],
        hosts_doc: "https://docs.auriko.ai/api-reference/authentication",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["auriko"],
        display_name: "Auriko",
        default_id: "apikey:auriko",
        dashboard_url: "https://auriko.ai/dashboard?tab=api-keys",
        placeholder: "ak_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.auriko.ai/v1/me",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Ant Group's Ling guide sends Bearer tokens to api.ant-ling.com. That host refused
    // requests from outside China during review, so no check could be observed.
    ApiKeyProvider {
        key: "bailing",
        fusiform_provider_id: Some("bailing"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.ant-ling.com"],
        hosts_doc: "https://alipaytbox.yuque.com/org-wiki-knowledgepie-mvkzao/pxit93/get_started",
        invalid_key: None,
        default_provider_ids: &["bailing"],
        display_name: "Bailing",
        default_id: "apikey:bailing",
        dashboard_url: "https://chat.ant-ling.com/platform/api",
        placeholder: "API token",
        validation: KeyValidation::Unvalidated {
            reason: "Ling's API host answered requests from outside China with an HTML block page, so no check has been confirmed to tell a bad key from a good one",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Bee's model list does not need a key, so the check is a chat.
    ApiKeyProvider {
        key: "bee",
        fusiform_provider_id: Some("bee"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.bee.heossi.com"],
        hosts_doc: "https://bee.heossi.com/docs/sdks",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("unauthorized"), error_code_field: Some("/error") }),
        default_provider_ids: &["bee"],
        display_name: "Bee by HEOSSI",
        default_id: "apikey:bee",
        dashboard_url: "https://workspace.bee.heossi.com/account/api-keys",
        placeholder: "bee_sk_live_...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.bee.heossi.com/bee",
            model: "bee-cell",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Berget.AI's model list does not need a key, so the check is a chat.
    ApiKeyProvider {
        key: "berget",
        fusiform_provider_id: Some("berget"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.berget.ai"],
        hosts_doc: "https://docs.berget.ai/quickstart",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["berget"],
        display_name: "Berget.AI",
        default_id: "apikey:berget",
        dashboard_url: "https://console.berget.ai/api-keys",
        placeholder: "sk_ber_...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.berget.ai/v1",
            model: "mistralai/Mistral-Small-3.2-24B-Instruct-2506",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "blueclaw",
        fusiform_provider_id: Some("blueclaw"),
        auth: Some(BEARER_AUTH),
        hosts: &["openai.blueclaw.network"],
        hosts_doc: "https://blueclaw.network/quickstart.html",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["blueclaw"],
        display_name: "Blue Claw",
        default_id: "apikey:blueclaw",
        dashboard_url: "https://portal.blueclaw.network/",
        placeholder: "bc_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://openai.blueclaw.network/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Bothub's API guide sets this base URL with the access token as the OpenAI SDK's
    // API key, which the SDK sends as a Bearer token.
    ApiKeyProvider {
        key: "bothub",
        fusiform_provider_id: Some("bothub"),
        auth: Some(BEARER_AUTH),
        hosts: &["openai.bothub.chat"],
        hosts_doc: "https://bothub.ru/free",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("UNAUTHORIZED"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["bothub"],
        display_name: "Bothub",
        default_id: "apikey:bothub",
        dashboard_url: "https://bothub.ru/profile/for-developers",
        placeholder: "access token",
        validation: KeyValidation::GetEndpoint {
            url: "https://openai.bothub.chat/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Boundless also accepts the key in `x-api-key`; the row uses the documented Bearer
    // form. The check is the documented balance read, which uses the inference key.
    ApiKeyProvider {
        key: "boundless",
        fusiform_provider_id: Some("boundless"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.inference.boundless.network"],
        hosts_doc: "https://inference.boundless.network/docs/api-compatibility",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("authentication_error"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["boundless"],
        display_name: "Boundless",
        default_id: "apikey:boundless",
        dashboard_url: "https://inference.boundless.network/settings/api-keys",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.inference.boundless.network/v1/credits",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Chutes serves inference on llm.chutes.ai and its platform API on api.chutes.ai,
    // both with the same key. Its model list does not need a key, so the check is the
    // documented account read.
    ApiKeyProvider {
        key: "chutes",
        fusiform_provider_id: Some("chutes"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.chutes.ai", "llm.chutes.ai"],
        hosts_doc: "https://chutes.ai/docs/getting-started/authentication",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["chutes"],
        display_name: "Chutes",
        default_id: "apikey:chutes",
        dashboard_url: "https://chutes.ai/app/settings/api-keys",
        placeholder: "cpk_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.chutes.ai/users/me",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Claudinio also accepts the key in `x-api-key`; the row uses the Bearer form.
    ApiKeyProvider {
        key: "claudinio",
        fusiform_provider_id: Some("claudinio"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.claudin.io"],
        hosts_doc: "https://claudin.io/docs/api-reference/",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("token_not_found_in_db"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["claudinio"],
        display_name: "Claudinio",
        default_id: "apikey:claudinio",
        dashboard_url: "https://claudin.io/dashboard",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.claudin.io/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "cloudferro-sherlock",
        fusiform_provider_id: Some("cloudferro-sherlock"),
        auth: Some(BEARER_AUTH),
        hosts: &["api-sherlock.cloudferro.com"],
        hosts_doc: "https://docs.cloudferro.com/en/latest/sherlock/Package-installation-and-examples-of-Sherlock-AI-code-on-CloudFerro-Cloud.html",
        invalid_key: Some(InvalidKeyEvidence { status: 403, error_code: None, error_code_field: None }),
        default_provider_ids: &["cloudferro-sherlock"],
        display_name: "CloudFerro Sherlock",
        default_id: "apikey:cloudferro-sherlock",
        dashboard_url: "https://portal.cloudferro.com/en/sherlock",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api-sherlock.cloudferro.com/openai/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Cohere's API reference uses api.cohere.com; its OpenAI compatibility API uses
    // api.cohere.ai with the same key.
    ApiKeyProvider {
        key: "cohere",
        fusiform_provider_id: Some("cohere"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.cohere.ai", "api.cohere.com"],
        hosts_doc: "https://docs.cohere.com/reference/list-models",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["cohere"],
        display_name: "Cohere",
        default_id: "apikey:cohere",
        dashboard_url: "https://dashboard.cohere.com/api-keys",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.cohere.com/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // The check is the documented balance read, which works at a zero balance.
    ApiKeyProvider {
        key: "coralbricks",
        fusiform_provider_id: Some("coralbricks"),
        auth: Some(BEARER_AUTH),
        hosts: &["inference.coralbricks.ai"],
        hosts_doc: "https://www.coralbricks.ai/docs",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["coralbricks"],
        display_name: "CoralBricks",
        default_id: "apikey:coralbricks",
        dashboard_url: "https://www.coralbricks.ai/api-keys",
        placeholder: "cb_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://inference.coralbricks.ai/v1/quota",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Cortecs' model list does not need a key, so the check is a chat.
    ApiKeyProvider {
        key: "cortecs",
        fusiform_provider_id: Some("cortecs"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.cortecs.ai"],
        hosts_doc: "https://docs.cortecs.ai/api/api-compatibility",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("auth_error"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["cortecs"],
        display_name: "Cortecs",
        default_id: "apikey:cortecs",
        dashboard_url: "https://cortecs.ai/userArea/console?tab=credentials",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.cortecs.ai/v1",
            model: "glm-5.3-flash",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // CrossModel serves its OpenAI and Anthropic surfaces from one host. The Anthropic
    // surface also accepts `x-api-key`; the row uses the Bearer form both accept.
    ApiKeyProvider {
        key: "crossmodel",
        fusiform_provider_id: Some("crossmodel"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.crossmodel.ai"],
        hosts_doc: "https://www.crossmodel.ai/docs/authentication",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["crossmodel"],
        display_name: "CrossModel",
        default_id: "apikey:crossmodel",
        dashboard_url: "https://www.crossmodel.ai/docs/authentication",
        placeholder: "cm-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.crossmodel.ai/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Crusoe's serverless inference guide sets this base URL with the key as the OpenAI
    // SDK's API key, which the SDK sends as a Bearer token.
    ApiKeyProvider {
        key: "crusoe",
        fusiform_provider_id: Some("crusoe"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.inference.crusoecloud.com"],
        hosts_doc: "https://docs.crusoe.ai/quickstart/getting-started-with-serverless-inference/",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["crusoe"],
        display_name: "Crusoe",
        default_id: "apikey:crusoe",
        dashboard_url: "https://console.crusoecloud.com/foundry/models",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.inference.crusoecloud.com/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // DaoXE's quickstart host. Alternative routes that its route list may return are
    // not covered.
    ApiKeyProvider {
        key: "daoxe",
        fusiform_provider_id: Some("daoxe"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.daoxe.com"],
        hosts_doc: "https://daoxe.com/docs/start/quickstart",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["daoxe"],
        display_name: "DaoXE",
        default_id: "apikey:daoxe",
        dashboard_url: "https://daoxe.com/console",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.daoxe.com/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // DigitalOcean's serverless inference accepts a model access key or a personal
    // access token. This row is separate from the `oauth:digitalocean` login, which
    // stores a cloud-infrastructure token.
    ApiKeyProvider {
        key: "digitalocean",
        fusiform_provider_id: Some("digitalocean"),
        auth: Some(BEARER_AUTH),
        hosts: &["inference.do-ai.run"],
        hosts_doc: "https://docs.digitalocean.com/products/inference/how-to/si-endpoints/",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("Unauthorized"), error_code_field: Some("/id") }),
        default_provider_ids: &["digitalocean"],
        display_name: "DigitalOcean",
        default_id: "apikey:digitalocean",
        dashboard_url: "https://cloud.digitalocean.com/model-studio/manage-keys",
        placeholder: "model access key",
        validation: KeyValidation::GetEndpoint {
            url: "https://inference.do-ai.run/v1/models",
            extra_headers: &[],
        },
        categories: LLM_AND_MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    // DInference's API page sets this base URL with the key as the OpenAI SDK's API
    // key, which the SDK sends as a Bearer token.
    ApiKeyProvider {
        key: "dinference",
        fusiform_provider_id: Some("dinference"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.dinference.com"],
        hosts_doc: "https://dinference.com/docs",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("token_not_found_in_db"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["dinference"],
        display_name: "DInference",
        default_id: "apikey:dinference",
        dashboard_url: "https://panel.dinference.com/login",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.dinference.com/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // D.Run's pay-per-token host. Dedicated instances use per-region hosts that this
    // row does not cover.
    ApiKeyProvider {
        key: "drun",
        fusiform_provider_id: Some("drun"),
        auth: Some(BEARER_AUTH),
        hosts: &["chat.d.run"],
        hosts_doc: "https://docs.d.run/en/models/api-call",
        invalid_key: None,
        default_provider_ids: &["drun"],
        display_name: "D.Run (China)",
        default_id: "apikey:drun",
        dashboard_url: "https://console.d.run/",
        placeholder: "sk-...",
        validation: KeyValidation::Unvalidated {
            reason: "D.Run's API host reset connections from outside China during review, so no check has been confirmed to tell a bad key from a good one",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Echo keys belong to a workspace, and every documented request path names the
    // workspace, which the key alone does not reveal.
    ApiKeyProvider {
        key: "echo",
        fusiform_provider_id: Some("echo"),
        auth: Some(BEARER_AUTH),
        hosts: &["echo.tracerml.ai"],
        hosts_doc: "https://echo.tracerml.ai/docs/api",
        invalid_key: None,
        default_provider_ids: &["echo"],
        display_name: "Echo",
        default_id: "apikey:echo",
        dashboard_url: "https://echo.tracerml.ai/company?view=settings#api",
        placeholder: "API key",
        validation: KeyValidation::Unvalidated {
            reason: "Echo's API paths include the key's workspace id, which the key alone does not reveal, so there is no request to check it with",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Eden AI serves the same API on a global and an EU host, with one key. Its model list
    // does not need a key, so the check is a chat.
    ApiKeyProvider {
        key: "edenai",
        fusiform_provider_id: Some("edenai"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.edenai.run", "api.eu.edenai.run"],
        hosts_doc: "https://www.edenai.co/docs/v3/data-governance/eu-endpoint",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["edenai"],
        display_name: "Eden AI",
        default_id: "apikey:edenai",
        dashboard_url: "https://app.edenai.run/settings/api-keys",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.edenai.run/v3",
            model: "openai/gpt-4o-mini",
        },
        categories: LLM_AND_MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    // The check is the documented account usage read, which returns the key's balance.
    ApiKeyProvider {
        key: "empiriolabs",
        fusiform_provider_id: Some("empiriolabs"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.empiriolabs.ai"],
        hosts_doc: "https://docs.empiriolabs.ai/authentication",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["empiriolabs"],
        display_name: "EmpirioLabs AI",
        default_id: "apikey:empiriolabs",
        dashboard_url: "https://platform.empiriolabs.ai",
        placeholder: "sk-empiriolabs-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.empiriolabs.ai/v1/account/usage?limit=1",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Engy's model list does not need a key, so the check is a chat. Its separate
    // management API on engy.ai takes account tokens, not inference keys.
    ApiKeyProvider {
        key: "engy",
        fusiform_provider_id: Some("engy"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.engy.ai"],
        hosts_doc: "https://engy.ai/docs/api-reference/inference-api/overview",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("authentication_error"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["engy"],
        display_name: "engy",
        default_id: "apikey:engy",
        dashboard_url: "https://engy.ai/dashboard",
        placeholder: "sk-engy-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.engy.ai/v1",
            model: "glm-5.3-flash",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // evroc Think shared models; dedicated model instances are not covered.
    ApiKeyProvider {
        key: "evroc",
        fusiform_provider_id: Some("evroc"),
        auth: Some(BEARER_AUTH),
        hosts: &["models.think.evroc.com"],
        hosts_doc: "https://docs.evroc.com/products/think/openai-compatibility.html",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("authentication_error"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["evroc"],
        display_name: "evroc",
        default_id: "apikey:evroc",
        dashboard_url: "https://cloud.evroc.com/",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://models.think.evroc.com/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // FastRouter's model list does not need a key, so the check is a chat.
    ApiKeyProvider {
        key: "fastrouter",
        fusiform_provider_id: Some("fastrouter"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.fastrouter.ai"],
        hosts_doc: "https://docs.fastrouter.ai/",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["fastrouter"],
        display_name: "FastRouter",
        default_id: "apikey:fastrouter",
        dashboard_url: "https://fastrouter.ai/",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.fastrouter.ai/api/v1",
            model: "openai/gpt-4o-mini",
        },
        categories: LLM_AND_MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    // FreeModel's site configures the OpenAI SDK with this base URL and the key as its
    // API key, which the SDK sends as a Bearer token. Its Anthropic-style endpoint on
    // cc.freemodel.dev takes the key in another header and is not covered. The model list
    // does not need a key, so the check is a chat.
    ApiKeyProvider {
        key: "freemodel",
        fusiform_provider_id: Some("freemodel"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.freemodel.dev"],
        hosts_doc: "https://freemodel.dev/docs",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["freemodel"],
        display_name: "FreeModel",
        default_id: "apikey:freemodel",
        dashboard_url: "https://freemodel.dev/dashboard",
        placeholder: "fe_oa_...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.freemodel.dev/v1",
            model: "gpt-6-luna",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Friendli's serverless model list does not need a key, so the check is a chat.
    ApiKeyProvider {
        key: "friendli",
        fusiform_provider_id: Some("friendli"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.friendli.ai"],
        hosts_doc: "https://friendli.ai/docs/guides/introduction/get-started",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["friendli"],
        display_name: "Friendli",
        default_id: "apikey:friendli",
        dashboard_url: "https://friendli.ai/suite/~/setting/keys",
        placeholder: "flp_...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.friendli.ai/serverless/v1",
            model: "zai-org/GLM-5.3-Flash",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // FrogBot also accepts the key in `x-api-key`; the row uses the documented Bearer form.
    ApiKeyProvider {
        key: "frogbot",
        fusiform_provider_id: Some("frogbot"),
        auth: Some(BEARER_AUTH),
        hosts: &["app.frogbot.ai"],
        hosts_doc: "https://docs.frogbot.ai/api-keys",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("Unauthorized"), error_code_field: Some("/error") }),
        default_provider_ids: &["frogbot"],
        display_name: "FrogBot",
        default_id: "apikey:frogbot",
        dashboard_url: "https://app.frogbot.ai",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://app.frogbot.ai/api/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Covers Vertex AI express-mode API keys only: Gemini models at the global endpoint,
    // with no project or region. Vertex used through a project and region (service
    // account credentials and regional hosts) is not covered.
    ApiKeyProvider {
        key: "google-vertex",
        fusiform_provider_id: Some("google-vertex"),
        auth: Some(AuthDescriptor { header: "x-goog-api-key", scheme: AuthScheme::Raw }),
        hosts: &["aiplatform.googleapis.com"],
        hosts_doc: "https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/start/express-mode/overview",
        invalid_key: None,
        default_provider_ids: &["google-vertex"],
        display_name: "Vertex (express mode)",
        default_id: "apikey:google-vertex",
        dashboard_url: "https://console.cloud.google.com/agent-platform/studio/settings/api-keys",
        placeholder: "API key",
        validation: KeyValidation::Unvalidated {
            reason: "Vertex AI answered a bogus express-mode key with the same 401 it gives a call that takes no API keys at all, and its only documented express-mode requests are billed model calls, so no free check tells a bad key from a good one",
        },
        categories: LLM_AND_MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "greenpt",
        fusiform_provider_id: Some("greenpt"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.greenpt.ai"],
        hosts_doc: "https://docs.greenpt.ai/get-started",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["greenpt"],
        display_name: "GreenPT",
        default_id: "apikey:greenpt",
        dashboard_url: "https://account.greenpt.ai/api/keys",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.greenpt.ai/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Helicone's AI gateway. Its model list does not need a key, so the check is a chat.
    ApiKeyProvider {
        key: "helicone",
        fusiform_provider_id: Some("helicone"),
        auth: Some(BEARER_AUTH),
        hosts: &["ai-gateway.helicone.ai"],
        hosts_doc: "https://docs.helicone.ai/getting-started/quick-start",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["helicone"],
        display_name: "Helicone",
        default_id: "apikey:helicone",
        dashboard_url: "https://us.helicone.ai/settings/api-keys",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://ai-gateway.helicone.ai",
            model: "gpt-4o-mini",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // The check is the documented balance read, which is free and answers at zero balance.
    ApiKeyProvider {
        key: "hopper",
        fusiform_provider_id: Some("hopper"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.withhopper.com"],
        hosts_doc: "https://docs.withhopper.com",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["hopper"],
        display_name: "Hopper",
        default_id: "apikey:hopper",
        dashboard_url: "https://withhopper.com/console/keys",
        placeholder: "sk_hopper_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.withhopper.com/v1/balance",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "hpc-ai",
        fusiform_provider_id: Some("hpc-ai"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.hpc-ai.com"],
        hosts_doc: "https://www.hpc-ai.com/doc/docs/Model-APIs/API-Reference/OpenAI-Compatible-API/OpenAI-SDK",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["hpc-ai"],
        display_name: "HPC-AI",
        default_id: "apikey:hpc-ai",
        dashboard_url: "https://www.hpc-ai.com/models-console/api-key",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.hpc-ai.com/inference/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Impossibl's model list does not need a key, so the check is the documented read of
    // the key's latest request.
    ApiKeyProvider {
        key: "impossibl",
        fusiform_provider_id: Some("impossibl"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.impossibl.com"],
        hosts_doc: "https://impossibl.com/docs/quickstart",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("authentication_error"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["impossibl"],
        display_name: "Impossibl",
        default_id: "apikey:impossibl",
        dashboard_url: "https://impossibl.com/dashboard",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.impossibl.com/v1/requests?limit=1",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Inceptron's model list does not need a key, so the check is a chat.
    ApiKeyProvider {
        key: "inceptron",
        fusiform_provider_id: Some("inceptron"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.inceptron.io"],
        hosts_doc: "https://docs.inceptron.io",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("unauthorized"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["inceptron"],
        display_name: "Inceptron",
        default_id: "apikey:inceptron",
        dashboard_url: "https://console.inceptron.io",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.inceptron.io/v1",
            model: "zai-org/GLM-5.3-Flash",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Inco documents its model list as public without a key, so the check is a chat.
    ApiKeyProvider {
        key: "inco",
        fusiform_provider_id: Some("inco"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.inco.ai"],
        hosts_doc: "https://platform.inco.ai/docs",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["inco"],
        display_name: "Inco",
        default_id: "apikey:inco",
        dashboard_url: "https://platform.inco.ai/keys",
        placeholder: "sk-inco-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.inco.ai/v1",
            model: "glm-5.3-flash",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Infer's docs give no direct key-page URL, so the row's key page is the API guide.
    ApiKeyProvider {
        key: "infer",
        fusiform_provider_id: Some("infer"),
        auth: Some(BEARER_AUTH),
        hosts: &["infer.flow7.org"],
        hosts_doc: "https://infer.flow7.org/docs",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["infer"],
        display_name: "Infer by Flow7",
        default_id: "apikey:infer",
        dashboard_url: "https://infer.flow7.org/docs",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://infer.flow7.org/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Inference.net serves a default and a US-only host with one key. Its model list does
    // not need a key, so the check is a chat.
    ApiKeyProvider {
        key: "inference",
        fusiform_provider_id: Some("inference"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.inference.net", "us.api.inference.net"],
        hosts_doc: "https://docs.inference.net/api/api-quickstart",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("InvalidApiKey"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["inference"],
        display_name: "Inference",
        default_id: "apikey:inference",
        dashboard_url: "https://inference.net/dashboard/api-keys",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.inference.net/v1",
            model: "llama-3.2-1b-instruct",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // InferX's console gives each key a tenant- and endpoint-specific base URL on this
    // host, so there is no fixed request to check a key with.
    ApiKeyProvider {
        key: "inferx",
        fusiform_provider_id: Some("inferx"),
        auth: Some(BEARER_AUTH),
        hosts: &["model.inferx.net"],
        hosts_doc: "https://inferx.net/docs/authentication",
        invalid_key: None,
        default_provider_ids: &["inferx"],
        display_name: "InferX",
        default_id: "apikey:inferx",
        dashboard_url: "https://model.inferx.net/login",
        placeholder: "API key",
        validation: KeyValidation::Unvalidated {
            reason: "InferX gives each key a tenant- and endpoint-specific base URL in its console, so a fixed check URL could refuse a good key",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Infomaniak AI requests carry the account's AI Tools product id in the path, which
    // consumers must supply. The check lists the token's AI products, which needs no id.
    ApiKeyProvider {
        key: "infomaniak",
        fusiform_provider_id: Some("infomaniak"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.infomaniak.com"],
        hosts_doc: "https://developer.infomaniak.com/docs/api/post/2/ai/%7Bproduct_id%7D/openai/v1/chat/completions",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("not_authorized"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["infomaniak"],
        display_name: "Infomaniak",
        default_id: "apikey:infomaniak",
        dashboard_url: "https://manager.infomaniak.com/v3/ng/accounts/token/list",
        placeholder: "API token",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.infomaniak.com/1/ai",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // IO Intelligence's model list does not need a key, so the check is a chat.
    ApiKeyProvider {
        key: "io-net",
        fusiform_provider_id: Some("io-net"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.intelligence.io.solutions"],
        hosts_doc: "https://io.net/docs/reference/ai-models/get-started-with-io-intelligence-api",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["io-net"],
        display_name: "IO.NET",
        default_id: "apikey:io-net",
        dashboard_url: "https://ai.io.net/ai/api-keys",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.intelligence.io.solutions/api/v1",
            model: "meta-llama/Llama-3.3-70B-Instruct",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // IteraCompute's model catalog is public; its free Auto chat still checks the key.
    ApiKeyProvider {
        key: "iteracompute",
        fusiform_provider_id: Some("iteracompute"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.iteracompute.com"],
        hosts_doc: "https://iteracompute.com/docs.html",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["iteracompute"],
        display_name: "IteraCompute",
        default_id: "apikey:iteracompute",
        dashboard_url: "https://iteracompute.com/console/api-keys",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.iteracompute.com/v1",
            model: "Auto",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "jalapeno",
        fusiform_provider_id: Some("jalapeno"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.jalapeno-cloud.ai"],
        hosts_doc: "https://www.jalapeno-cloud.ai/docs/",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["jalapeno"],
        display_name: "Jalapeno Cloud",
        default_id: "apikey:jalapeno",
        dashboard_url: "https://www.jalapeno-cloud.ai/keys",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.jalapeno-cloud.ai/v1",
            model: "DeepSeek-V4-Pro",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "jiekou",
        fusiform_provider_id: Some("jiekou"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.highwayapi.ai", "api.jiekou.ai"],
        hosts_doc: "https://docs.jiekou.ai/docs/model/llm.md",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("FAILED_TO_AUTH"), error_code_field: Some("/reason") }),
        default_provider_ids: &["jiekou"],
        display_name: "Jiekou.AI",
        default_id: "apikey:jiekou",
        dashboard_url: "https://jiekou.vip/settings/key-management",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.jiekou.ai/openai/v1",
            model: "deepseek/deepseek-r1",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "kenari",
        fusiform_provider_id: Some("kenari"),
        auth: Some(BEARER_AUTH),
        hosts: &["kenari.id"],
        hosts_doc: "https://kenari.id/docs/quickstart",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["kenari"],
        display_name: "Kenari",
        default_id: "apikey:kenari",
        dashboard_url: "https://kenari.id/login",
        placeholder: "kn-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://kenari.id/v1",
            model: "step-3-7-flash:free",
        },
        categories: LLM_AND_MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "kilo",
        fusiform_provider_id: Some("kilo"),
        auth: Some(BEARER_AUTH),
        hosts: &["ai-gateway.kilo.ai"],
        hosts_doc: "https://docs.kilo.ai/docs/gateway/authentication",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("INVALID_TOKEN"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["kilo"],
        display_name: "Kilo Gateway",
        default_id: "apikey:kilo",
        dashboard_url: "https://app.kilo.ai",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://ai-gateway.kilo.ai/api/v1",
            model: "kilo-auto/free",
        },
        categories: LLM_AND_MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "kimi-code-plan-cn",
        fusiform_provider_id: Some("kimi-code-plan-cn"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.kimi.com"],
        hosts_doc: "https://www.kimi.com/code/docs/en/third-party-tools/codex.html",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_authentication_error"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["kimi-code-plan-cn"],
        display_name: "Kimi For Coding (kimi.com)",
        default_id: "apikey:kimi-code-plan-cn",
        dashboard_url: "https://www.kimi.com/code/console",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.kimi.com/coding/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "klokintegration",
        fusiform_provider_id: Some("klokintegration"),
        auth: Some(BEARER_AUTH),
        hosts: &["ai.klok.ipaas.se", "api-gw.klok.ipaas.se"],
        hosts_doc: "https://klokintegration.se/docs/ai-api",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["klokintegration"],
        display_name: "klokintegration.se",
        default_id: "apikey:klokintegration",
        dashboard_url: "https://klokintegration.se",
        placeholder: "API token",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://ai.klok.ipaas.se/proxy/kloker-key/v1",
            model: "Kloker",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "kosmik",
        fusiform_provider_id: Some("kosmik"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.koscompute.com"],
        hosts_doc: "https://api.koscompute.com/docs/overview/quickstart/",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["kosmik"],
        display_name: "Kosmik Compute",
        default_id: "apikey:kosmik",
        dashboard_url: "https://api.koscompute.com/docs/overview/quickstart/",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.koscompute.com/v1",
            model: "qwen/qwen3.8-27b",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "liquid",
        fusiform_provider_id: Some("liquid"),
        auth: Some(BEARER_AUTH),
        hosts: &["router.inference.ai.exchange"],
        hosts_doc: "https://inference.ai.exchange/docs/api.md",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["liquid"],
        display_name: "Liquid Inference",
        default_id: "apikey:liquid",
        dashboard_url: "https://inference.ai.exchange/docs/quickstart",
        placeholder: "sk-liquid-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://router.inference.ai.exchange/v1",
            model: "gpt-oss-120b",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "llmgateway",
        fusiform_provider_id: Some("llmgateway"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.llmgateway.io"],
        hosts_doc: "https://docs.llmgateway.io/developers/devpass-usage",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["llmgateway"],
        display_name: "DevPass (LLM Gateway)",
        default_id: "apikey:llmgateway",
        dashboard_url: "https://docs.llmgateway.io/features/api-keys",
        placeholder: "llmgtwy_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.llmgateway.io/v1/key",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // DevPass and pay-as-you-go use the same gateway, but are separate published
    // offerings. The key-status read works for both without spending their allowance.
    ApiKeyProvider {
        key: "llmgateway-providers",
        fusiform_provider_id: Some("llmgateway-providers"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.llmgateway.io"],
        hosts_doc: "https://docs.llmgateway.io/developers/devpass-usage",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["llmgateway-providers"],
        display_name: "LLM Gateway",
        default_id: "apikey:llmgateway-providers",
        dashboard_url: "https://docs.llmgateway.io/features/api-keys",
        placeholder: "llmgtwy_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.llmgateway.io/v1/key",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "llmtr",
        fusiform_provider_id: Some("llmtr"),
        auth: Some(BEARER_AUTH),
        hosts: &["llmtr.com"],
        hosts_doc: "https://llmtr.com/docs/en/quickstart/",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("auth_error"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["llmtr"],
        display_name: "LLMTR",
        default_id: "apikey:llmtr",
        dashboard_url: "https://llmtr.com/docs/en/api-keys/",
        placeholder: "llmtr-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://llmtr.com/v1",
            model: "openai/gpt-6-luna",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "longcat",
        fusiform_provider_id: Some("longcat"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.longcat.chat"],
        hosts_doc: "https://longcat.chat/platform/docs/",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["longcat"],
        display_name: "LongCat",
        default_id: "apikey:longcat",
        dashboard_url: "https://longcat.chat/platform/api_keys",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.longcat.chat/openai/v1",
            model: "LongCat-2.5",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "lowrouter",
        fusiform_provider_id: Some("lowrouter"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.lowrouter.ai"],
        hosts_doc: "https://lowrouter.ai/docs/integrations/openai-compatible",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("api_key_not_registered"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["lowrouter"],
        display_name: "LowRouter",
        default_id: "apikey:lowrouter",
        dashboard_url: "https://lowrouter.ai/app/keys",
        placeholder: "sk-lr-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.lowrouter.ai/v1",
            model: "auto/mistralai/mistral-large-2512",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "lucidquery",
        fusiform_provider_id: Some("lucidquery"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.lucidquery.com"],
        hosts_doc: "https://lucidquery.com/docs",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["lucidquery"],
        display_name: "LucidQuery",
        default_id: "apikey:lucidquery",
        dashboard_url: "https://lucidquery.com/dashboard/keys",
        placeholder: "sk_lucidquery_...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.lucidquery.com/v1",
            model: "lucidquery-agi-01-swift",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "meganova",
        fusiform_provider_id: Some("meganova"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.meganova.ai", "enterprise.api.meganova.ai"],
        hosts_doc: "https://docs.meganova.ai/inference-models.md",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("token_not_found"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["meganova"],
        display_name: "Meganova",
        default_id: "apikey:meganova",
        dashboard_url: "https://console.meganova.ai",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.meganova.ai/v1",
            model: "meganova-ai/manta-mini-1.0",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    // Model listing needs a separate scope, so check a chat key with a chat instead.
    ApiKeyProvider {
        key: "melious",
        fusiform_provider_id: Some("melious"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.melious.ai"],
        hosts_doc: "https://melious.ai/docs/get-started/quickstart",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["melious"],
        display_name: "Melious",
        default_id: "apikey:melious",
        dashboard_url: "https://melious.ai/account/api/keys",
        placeholder: "sk-mel-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.melious.ai/v1",
            model: "qwen3.6-35b-a3b",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "merge-gateway",
        fusiform_provider_id: Some("merge-gateway"),
        auth: Some(BEARER_AUTH),
        hosts: &["api-gateway.merge.dev"],
        hosts_doc: "https://docs.merge.dev/merge-gateway/api-overview",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["merge-gateway"],
        display_name: "Merge Gateway",
        default_id: "apikey:merge-gateway",
        dashboard_url: "https://gateway.merge.dev/api-keys",
        placeholder: "mg_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api-gateway.merge.dev/v1/models",
            extra_headers: &[],
        },
        categories: LLM_AND_MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "minimax",
        fusiform_provider_id: Some("minimax"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.minimax.io"],
        hosts_doc: "https://platform.minimax.io/docs/api-reference/models/openai/list-models",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("authorized_error"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["minimax"],
        display_name: "MiniMax (minimax.io)",
        default_id: "apikey:minimax",
        dashboard_url: "https://platform.minimax.io/user-center/basic-information/interface-key",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.minimax.io/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "minimax-cn",
        fusiform_provider_id: Some("minimax-cn"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.minimax.cn"],
        hosts_doc: "https://platform.minimaxi.com/docs/api-reference/models/openai/list-models",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("authorized_error"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["minimax-cn"],
        display_name: "MiniMax (minimax.cn)",
        default_id: "apikey:minimax-cn",
        dashboard_url: "https://platform.minimax.cn/user-center/basic-information/interface-key",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.minimax.cn/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "mixlayer",
        fusiform_provider_id: Some("mixlayer"),
        auth: Some(BEARER_AUTH),
        hosts: &["mixlayer.ai"],
        hosts_doc: "https://docs.mixlayer.com/quickstart",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["mixlayer"],
        display_name: "Mixlayer",
        default_id: "apikey:mixlayer",
        dashboard_url: "https://console.mixlayer.com/app/api-keys",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://mixlayer.ai/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "moark",
        fusiform_provider_id: Some("moark"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.moark.com"],
        hosts_doc: "https://moark.com/docs/getting-started",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("401"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["moark"],
        display_name: "Moark",
        default_id: "apikey:moark",
        dashboard_url: "https://moark.com/dashboard/tokens",
        placeholder: "Access token",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.moark.com/v1",
            model: "DeepSeek-R1",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "model-oracle-ai",
        fusiform_provider_id: Some("model-oracle-ai"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.modeloracle.com"],
        hosts_doc: "https://modeloracle.com/setup/",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("Unauthorized"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["model-oracle-ai"],
        display_name: "Model Oracle AI",
        default_id: "apikey:model-oracle-ai",
        dashboard_url: "https://app.modeloracle.com/",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.modeloracle.com/api/v1",
            model: "auto",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "modular",
        fusiform_provider_id: Some("modular"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.modular.com"],
        hosts_doc: "https://docs.modular.com/quickstart",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["modular"],
        display_name: "Modular",
        default_id: "apikey:modular",
        dashboard_url: "https://console.modular.com/api_keys",
        placeholder: "sk-mod-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.modular.com/v1",
            model: "minimax/minimax-m3",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "moonshotai-cn",
        fusiform_provider_id: Some("moonshotai-cn"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.moonshot.cn"],
        hosts_doc: "https://platform.moonshot.cn/docs/get-api-key.md",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_authentication_error"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["moonshotai-cn"],
        display_name: "Moonshot AI (China)",
        default_id: "apikey:moonshotai-cn",
        dashboard_url: "https://platform.kimi.com/console/api-keys",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.moonshot.cn/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "morph",
        fusiform_provider_id: Some("morph"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.morphllm.com"],
        hosts_doc: "https://docs.morphllm.com/general-inference",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["morph"],
        display_name: "Morph",
        default_id: "apikey:morph",
        dashboard_url: "https://www.morphllm.com/dashboard/api-keys",
        placeholder: "sk-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.morphllm.com/v1",
            model: "morph-glm53-744b",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "munito",
        fusiform_provider_id: Some("munito"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.eu.munito.ai", "api.munito.ai", "api.us.munito.ai"],
        hosts_doc: "https://docs.munito.ai/quickstart",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["munito"],
        display_name: "Munito AI",
        default_id: "apikey:munito",
        dashboard_url: "https://console.munito.ai/keys",
        placeholder: "munitoai_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.munito.ai/inference/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "munito-eu",
        fusiform_provider_id: Some("munito-eu"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.eu.munito.ai", "api.munito.ai", "api.us.munito.ai"],
        hosts_doc: "https://docs.munito.ai/quickstart",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["munito-eu"],
        display_name: "Munito AI (EU)",
        default_id: "apikey:munito-eu",
        dashboard_url: "https://console.munito.ai/keys",
        placeholder: "munitoai_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.eu.munito.ai/inference/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "nan",
        fusiform_provider_id: Some("nan"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.nan.builders"],
        hosts_doc: "https://nan.builders/docs/getting-started",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("401"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["nan"],
        display_name: "NaN",
        default_id: "apikey:nan",
        dashboard_url: "https://cloud.nan.builders/",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.nan.builders/v1/models",
            extra_headers: &[],
        },
        categories: LLM_AND_MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "nearai",
        fusiform_provider_id: Some("nearai"),
        auth: Some(BEARER_AUTH),
        hosts: &["cloud-api.near.ai"],
        hosts_doc: "https://docs.near.ai/cloud/quickstart.md",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["nearai"],
        display_name: "NEAR AI Cloud",
        default_id: "apikey:nearai",
        dashboard_url: "https://cloud.near.ai/dashboard/organizations",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://cloud-api.near.ai/v1/attestation/report",
            extra_headers: &[],
        },
        categories: LLM_AND_MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "nebius",
        fusiform_provider_id: Some("nebius"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.tokenfactory.nebius.com"],
        hosts_doc: "https://docs.tokenfactory.nebius.com/quickstart",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["nebius"],
        display_name: "Nebius Token Factory",
        default_id: "apikey:nebius",
        dashboard_url: "https://tokenfactory.nebius.com/project/api-keys",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.tokenfactory.nebius.com/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "neuralwatt",
        fusiform_provider_id: Some("neuralwatt"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.neuralwatt.com"],
        hosts_doc: "https://portal.neuralwatt.com/docs",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["neuralwatt"],
        display_name: "Neuralwatt",
        default_id: "apikey:neuralwatt",
        dashboard_url: "https://portal.neuralwatt.com",
        placeholder: "sk-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.neuralwatt.com/v1",
            model: "glm-5.3",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "ofox",
        fusiform_provider_id: Some("ofox"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.ofox.ai"],
        hosts_doc: "https://ofox.ai/docs/develop/authentication",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("unauthorized"), error_code_field: Some("/error") }),
        default_provider_ids: &["ofox"],
        display_name: "Ofox",
        default_id: "apikey:ofox",
        dashboard_url: "https://app.ofox.ai/manage/api-keys",
        placeholder: "sk-of-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.ofox.ai/v1/user/balance",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "opper",
        fusiform_provider_id: Some("opper"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.opper.ai", "eu.gw.opper.ai", "gw.opper.ai"],
        hosts_doc: "https://docs.opper.ai/overview/quickstart",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["opper"],
        display_name: "Opper",
        default_id: "apikey:opper",
        dashboard_url: "https://platform.opper.ai/settings/api-keys",
        placeholder: "op-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.opper.ai/v3/compat/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "orcarouter",
        fusiform_provider_id: Some("orcarouter"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.orcarouter.ai"],
        hosts_doc: "https://docs.orcarouter.ai/getting-started/get-api-key",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("orcarouter_api_error"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["orcarouter"],
        display_name: "OrcaRouter",
        default_id: "apikey:orcarouter",
        dashboard_url: "https://www.orcarouter.ai/console",
        placeholder: "sk-orca-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.orcarouter.ai/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "ovhcloud",
        fusiform_provider_id: Some("ovhcloud"),
        auth: Some(BEARER_AUTH),
        hosts: &["oai.endpoints.kepler.ai.cloud.ovh.net"],
        hosts_doc: "https://www.ovhcloud.com/en/public-cloud/ai-endpoints/catalog/qwen-guard-gen-06b/",
        invalid_key: Some(InvalidKeyEvidence { status: 403, error_code: None, error_code_field: None }),
        default_provider_ids: &["ovhcloud"],
        display_name: "OVHcloud AI Endpoints",
        default_id: "apikey:ovhcloud",
        dashboard_url: "https://www.ovh.com/manager/",
        placeholder: "Access token",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1",
            model: "Qwen3Guard-Gen-0.6B",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "pareto",
        fusiform_provider_id: Some("pareto"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.paretoinference.com"],
        hosts_doc: "https://docs.paretoinference.com/api-reference",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("401"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["pareto"],
        display_name: "Pareto Inference",
        default_id: "apikey:pareto",
        dashboard_url: "https://paretoinference.com/dashboard",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.paretoinference.com/v1",
            model: "z-ai/glm-5.3-flash",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "pendra",
        fusiform_provider_id: Some("pendra"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.pendra.ai"],
        hosts_doc: "https://pendra.ai/docs/api/authentication",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["pendra"],
        display_name: "Pendra",
        default_id: "apikey:pendra",
        dashboard_url: "https://console.pendra.ai",
        placeholder: "pdr_sk_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.pendra.ai/api/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "perplexity-agent",
        fusiform_provider_id: Some("perplexity-agent"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.perplexity.ai"],
        hosts_doc: "https://docs.perplexity.ai/docs/getting-started/quickstart",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/type") }),
        default_provider_ids: &["perplexity-agent"],
        display_name: "Perplexity Agent",
        default_id: "apikey:perplexity-agent",
        dashboard_url: "https://console.perplexity.ai",
        placeholder: "API key",
        // All Perplexity APIs share a key; Orchestrator accepts the supported chat probe.
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.perplexity.ai/orchestrator/v1",
            model: "perplexity/kimi-k3",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "pioneer",
        fusiform_provider_id: Some("pioneer"),
        auth: Some(AuthDescriptor { header: "x-api-key", scheme: AuthScheme::Raw }),
        hosts: &["api.fastino.ai"],
        hosts_doc: "https://docs.fastino.ai/authentication.md",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["pioneer"],
        display_name: "Pioneer",
        default_id: "apikey:pioneer",
        dashboard_url: "https://agent.fastino.ai",
        placeholder: "fast_sk_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.fastino.ai/v1/model-status/fastino/gliner2.5-multi-v1",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "poe",
        fusiform_provider_id: Some("poe"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.poe.com"],
        hosts_doc: "https://creator.poe.com/docs/external-applications/openai-compatible-api",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["poe"],
        display_name: "Poe",
        default_id: "apikey:poe",
        dashboard_url: "https://poe.com/api/keys",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.poe.com/v1",
            model: "Claude-Sonnet-4.6",
        },
        categories: LLM_AND_MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "prime",
        fusiform_provider_id: Some("prime"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.pinference.ai"],
        hosts_doc: "https://docs.primeintellect.ai/inference/overview",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["prime"],
        display_name: "Prime Inference",
        default_id: "apikey:prime",
        dashboard_url: "https://app.primeintellect.ai/dashboard/tokens",
        placeholder: "API key with Inference permission",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.pinference.ai/api/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "privatemode-ai",
        fusiform_provider_id: Some("privatemode-ai"),
        auth: Some(BEARER_AUTH),
        hosts: &["proxyless-api.privatemode.ai"],
        hosts_doc: "https://docs.privatemode.ai/api/proxyless-api/",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["privatemode-ai"],
        display_name: "Privatemode AI",
        default_id: "apikey:privatemode-ai",
        dashboard_url: "https://portal.privatemode.ai",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://proxyless-api.privatemode.ai/v1",
            model: "glm-latest",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "qiniu-ai",
        fusiform_provider_id: Some("qiniu-ai"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.qnaigc.com"],
        hosts_doc: "https://developer.qiniu.com/aitokenapi/13379/real-time-ai-interface-api",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("auth_api_key_missing"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["qiniu-ai"],
        display_name: "Qiniu",
        default_id: "apikey:qiniu-ai",
        dashboard_url: "https://portal.qiniu.com/ai-inference/api-key",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.qnaigc.com/v1",
            model: "deepseek-v3",
        },
        categories: LLM_AND_MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "reflection",
        fusiform_provider_id: Some("reflection"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.reflection.ai"],
        hosts_doc: "https://developers.reflection.ai/models",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["reflection"],
        display_name: "Reflection",
        default_id: "apikey:reflection",
        dashboard_url: "https://platform.reflection.ai",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.reflection.ai/openai/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "requesty",
        fusiform_provider_id: Some("requesty"),
        auth: Some(BEARER_AUTH),
        hosts: &["router.ap.requesty.ai", "router.eu.requesty.ai", "router.requesty.ai", "router.us.requesty.ai"],
        hosts_doc: "https://docs.requesty.ai/api-reference/endpoint/models-list",
        invalid_key: Some(InvalidKeyEvidence { status: 403, error_code: None, error_code_field: None }),
        default_provider_ids: &["requesty"],
        display_name: "Requesty",
        default_id: "apikey:requesty",
        dashboard_url: "https://app.requesty.ai/api-keys",
        placeholder: "API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://router.requesty.ai/v1/models",
            extra_headers: &[],
        },
        categories: LLM_AND_MEDIA,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "runinfra",
        fusiform_provider_id: Some("runinfra"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.runinfra.ai"],
        hosts_doc: "https://runinfra.ai/docs/api-reference/authentication.md",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["runinfra"],
        display_name: "RunInfra",
        default_id: "apikey:runinfra",
        dashboard_url: "https://runinfra.ai/settings/api-keys",
        placeholder: "Workspace API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.runinfra.ai/v1/models",
            extra_headers: &[],
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "salad-cloud",
        fusiform_provider_id: Some("salad-cloud"),
        auth: Some(BEARER_AUTH),
        hosts: &["ai.salad.cloud"],
        hosts_doc: "https://docs.salad.com/ai-gateway/explanation/overview",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: None, error_code_field: None }),
        default_provider_ids: &["salad-cloud"],
        display_name: "SaladCloud AI Gateway",
        default_id: "apikey:salad-cloud",
        dashboard_url: "https://portal.salad.com",
        placeholder: "AI Gateway key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://ai.salad.cloud/v1",
            model: "qwen3.6-35b-a3b",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "sambanova",
        fusiform_provider_id: Some("sambanova"),
        auth: Some(BEARER_AUTH),
        hosts: &["api.sambanova.ai"],
        hosts_doc: "https://docs.sambanova.ai/cloud/docs/get-started/quickstart",
        invalid_key: Some(InvalidKeyEvidence { status: 401, error_code: Some("invalid_api_key"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["sambanova"],
        display_name: "SambaNova",
        default_id: "apikey:sambanova",
        dashboard_url: "https://cloud.sambanova.ai/apis",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.sambanova.ai/v1",
            model: "Meta-Llama-3.3-70B-Instruct",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
    ApiKeyProvider {
        key: "sarvam",
        fusiform_provider_id: Some("sarvam"),
        auth: Some(AuthDescriptor { header: "api-subscription-key", scheme: AuthScheme::Raw }),
        hosts: &["api.sarvam.ai"],
        hosts_doc: "https://docs.sarvam.ai/api/getting-started/quickstart",
        invalid_key: Some(InvalidKeyEvidence { status: 403, error_code: Some("invalid_api_key_error"), error_code_field: Some("/error/code") }),
        default_provider_ids: &["sarvam"],
        display_name: "Sarvam AI",
        default_id: "apikey:sarvam",
        dashboard_url: "https://indus.sarvam.ai/key-management?ref=docs",
        placeholder: "API key",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.sarvam.ai/v1",
            model: "sarvam-105b",
        },
        categories: LLM,
        serves: &[],
        account_id_prompt: None,
    },
];

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
    /// The catalog provider ids a fresh login stores when the operator passes no
    /// `--provider-id`. Only the subscription rows the live vault already carries
    /// ids for name one here; every other row is empty and stays as today. Kept on
    /// the row (rather than matched on the credential id) so the mapping lives in
    /// one place next to the ids it derives from.
    pub default_provider_ids: &'static [&'static str],
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
        // The only verified code-display redirect in this table: the same OAuth app
        // registers it, and the first-party anthropic-auth plugin uses it in
        // production with this client id.
        code_redirect_uri: Some(refresh_adapters::anthropic::LOGIN_CODE_REDIRECT_URI),
        code_paste_prompt: Some("After approving, the page shows a short code of the form code#state (a long code, a '#', then a shorter value).\nCopy the WHOLE thing, including the '#', and paste it here, then Enter:"),
        device: None,
        categories: LLM,
        serves: &[Anthropic],
        default_provider_ids: &["anthropic"],
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
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: Some(DeviceKind::OpenAi),
        categories: LLM,
        serves: &[OpenAI],
        default_provider_ids: &["openai"],
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
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: Some(DeviceKind::Xai),
        categories: LLM,
        serves: &[XAI],
        default_provider_ids: &["xai"],
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
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: Some(DeviceKind::GithubCopilot),
        categories: LLM,
        serves: &[OpenAI, Anthropic, Google, XAI],
        default_provider_ids: &[],
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
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: Some(DeviceKind::Kimi),
        categories: LLM,
        serves: &[Moonshot],
        default_provider_ids: &[],
    },
    LoginProvider {
        key: "meta",
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
        default_provider_ids: &["meta"],
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
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: None,
        categories: LLM,
        serves: &[Google],
        default_provider_ids: &[],
    },
    LoginProvider {
        key: "gmail",
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
        default_provider_ids: &[],
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
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: None,
        categories: LLM,
        serves: &[Google, Anthropic, OpenAI],
        default_provider_ids: &["google"],
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
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: None,
        categories: LLM,
        serves: &[Anthropic, OpenAI, Google, XAI],
        default_provider_ids: &[],
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
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: None,
        categories: NO_CATEGORIES,
        serves: &[],
        default_provider_ids: &[],
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
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: None,
        categories: DATA_WAREHOUSE,
        serves: &[],
        default_provider_ids: &[],
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
        code_redirect_uri: None,
        code_paste_prompt: None,
        device: None,
        categories: CLOUD_INFRASTRUCTURE,
        serves: &[],
        default_provider_ids: &[],
    },
];

pub fn api_key_provider(key: &str) -> Option<&'static ApiKeyProvider> {
    API_KEY_PROVIDERS.iter().find(|entry| entry.key == key)
}

pub fn login_provider(key: &str) -> Option<&'static LoginProvider> {
    LOGIN_PROVIDERS.iter().find(|entry| entry.key == key)
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
    fn api_key_fusiform_ids_match_offering_host_domains() {
        fn provider_domain(host: &str) -> &str {
            let Some(subdomains) = host.rsplitn(3, '.').nth(2) else {
                return host;
            };
            &host[subdomains.len() + 1..]
        }

        const EXEMPTIONS: &[(&str, &str)] = &[
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
            ("typesafe", "TypeSafe has no fixed receiving hosts yet"),
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
                include_str!("../../../docs/provider-key-evidence.md"),
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
        let expected: std::collections::BTreeMap<String, String> = serde_json::from_str(
            include_str!("../tests/fixtures/fusiform/routing-resolution.json"),
        )
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
        (
            "typesafe",
            "TypeSafe keys may belong to a deployment at a custom base URL",
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
                include_str!("../../../docs/provider-key-evidence.md"),
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
        // 9 search APIs, ElevenLabs for media, and 113 rows proposed from Fusiform's
        // provider list.
        assert_eq!(API_KEY_PROVIDERS.len(), 180);
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
                "data-warehouse",
                "cloud-infrastructure",
                "web-search",
                "media-provider"
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
        "xiaomi",
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
    fn closed_vocabularies_pin_every_variant_and_wire_spelling() {
        assert_eq!(
            CredentialCategory::ALL
                .iter()
                .map(|value| value.as_str())
                .collect::<Vec<_>>(),
            [
                "llm-provider",
                "data-warehouse",
                "cloud-infrastructure",
                "web-search",
                "media-provider"
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
    /// reaches exactly the credentials speaking that protocol. Measured on the live vault:
    /// `serves` contains "anthropic" for EIGHT rows and only five are Claude OAuth, and
    /// granting the purpose category `llm-provider` to reach those five hands read
    /// authority over sixteen. Neither narrows to the family.
    ///
    /// Reported by the anthropic-auth seat: "granting category:llm-provider gives the
    /// enrollment token read authority over all 17 LLM credentials, despite needing only
    /// native Anthropic OAuth accounts. Consumer-side filtering does not reduce that
    /// capability's blast radius."
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
