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
    /// Keys for web search APIs (Tavily, Kagi, Exa, Parallel). Kept apart from
    /// `llm-provider` on purpose: every model consumer is granted `llm-provider`, and a
    /// search key filed there would reach all of them.
    WebSearch,
}

impl CredentialCategory {
    pub const ALL: &[Self] = &[
        Self::LlmProvider,
        Self::DataWarehouse,
        Self::CloudInfrastructure,
        Self::WebSearch,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LlmProvider => "llm-provider",
            Self::DataWarehouse => "data-warehouse",
            Self::CloudInfrastructure => "cloud-infrastructure",
            Self::WebSearch => "web-search",
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
        }
    }
}

const LLM: &[CredentialCategory] = &[CredentialCategory::LlmProvider];
const DATA_WAREHOUSE: &[CredentialCategory] = &[CredentialCategory::DataWarehouse];
const CLOUD_INFRASTRUCTURE: &[CredentialCategory] = &[CredentialCategory::CloudInfrastructure];
const WEB_SEARCH: &[CredentialCategory] = &[CredentialCategory::WebSearch];
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
    /// Amazon Q's API-key GET requires `TokenType: API_KEY` as well as a bearer.
    /// Curl probes on 2026-10-06 with prefixed and malformed synthetic keys both
    /// returned 403 (AccessDeniedException header; body: "The bearer token included
    /// in the request is invalid."). CodeWhisperer ListAvailableProfiles instead
    /// returned 200 with empty profiles for an invalid key, so it cannot verify keys.
    AwsApiKeyGet { url: &'static str },
    GetEndpoint {
        url: &'static str,
        auth_header: AuthHeaderScheme,
    },
    /// The key is stored without any probe. Used where no check is possible without
    /// something this table cannot express (a provider-specific header, a per-deployment
    /// base URL, a model-denied response that must not count as a bad key), or where the
    /// provider has no endpoint that rejects a bad key. A probe that refuses a valid key
    /// blocks the login outright, which is worse than not checking. `reason` is printed
    /// at login so the operator knows the key was not verified and why.
    Unvalidated { reason: &'static str },
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
    Anthropic, DeepSeek, Google, Meta, MiniMax, Mistral, Moonshot, Nvidia, OpenAI, Perplexity,
    Qwen, StepFun, Xiaomi, Zhipu, XAI,
};

pub const API_KEY_PROVIDERS: &[ApiKeyProvider] = &[
    ApiKeyProvider {
        key: "kiro",
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
    },
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
        display_name: "Abliteration",
        default_id: "apikey:abliteration",
        dashboard_url: "https://abliteration.ai/console",
        placeholder: "ak_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.abliteration.ai/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
        categories: LLM,
        serves: &[Zhipu],
    },
    // oh-my-pi auth/aiand.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "aiand",
        display_name: "ai&",
        default_id: "apikey:aiand",
        dashboard_url: "https://console.aiand.com/api-keys",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.aiand.com/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
        categories: LLM,
        serves: &[OpenAI, Google, DeepSeek, Moonshot, Zhipu, Qwen],
    },
    // oh-my-pi auth/baseten.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "baseten",
        display_name: "Baseten",
        default_id: "apikey:baseten",
        dashboard_url: "https://app.baseten.co/settings/api_keys",
        placeholder: "bt_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://inference.baseten.co/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
        categories: LLM,
        serves: &[OpenAI, DeepSeek, Moonshot, Zhipu, Nvidia],
    },
    // oh-my-pi auth/charm-hyper.kdl.
    // The probe is `/v1/credits`, not `/v1/models`: charm-hyper.kdl records that the models
    // endpoint is public and answers 200 for a bogus key, so it could never reject one.
    // The roster is live-only (no static model rows), so `serves` lists only the families
    // oh-my-pi's providers/charm-hyper.kdl names: GLM (default model), Kimi and Gemma.
    ApiKeyProvider {
        key: "charm-hyper",
        display_name: "Charm Hyper",
        default_id: "apikey:charm-hyper",
        dashboard_url: "https://hyper.charm.land/",
        placeholder: "sk-hyper-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://hyper.charm.land/v1/credits",
            auth_header: AuthHeaderScheme::Bearer,
        },
        categories: LLM,
        serves: &[Google, Moonshot, Zhipu],
    },
    // oh-my-pi auth/cline-pass.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "cline-pass",
        display_name: "ClinePass",
        default_id: "apikey:cline-pass",
        dashboard_url: "https://app.cline.bot/dashboard/account",
        placeholder: "sk_...",
        validation: KeyValidation::Unvalidated {
            reason: "ClinePass checks keys on an account route that also needs client headers this login does not send",
        },
        categories: LLM,
        serves: &[Google, DeepSeek, Moonshot, Zhipu, Meta, Qwen, MiniMax, Xiaomi],
    },
    // oh-my-pi auth/commandcode.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "commandcode",
        display_name: "Command Code",
        default_id: "apikey:commandcode",
        dashboard_url: "https://commandcode.ai/studio",
        placeholder: "user_...",
        validation: KeyValidation::Unvalidated {
            reason: "Command Code has no endpoint that rejects a bad key without billing it: its model list is public, and a chat probe bills the key and refuses Go-plan keys that are still valid",
        },
        categories: LLM,
        serves: &[Anthropic, OpenAI, Google, XAI, DeepSeek, Moonshot, Zhipu, Meta, Qwen, Nvidia, MiniMax, Xiaomi, StepFun],
    },
    // oh-my-pi auth/deepinfra.kdl; serves from its models.json rows.
    // A chat probe rather than `/models`: deepinfra.kdl records that DeepInfra's models
    // endpoint is public and would accept any string as a key.
    ApiKeyProvider {
        key: "deepinfra",
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
    },
    // oh-my-pi auth/firepass.kdl; serves from its models.json rows.
    // firepass.kdl: Fire Pass keys are scoped to router endpoints and do not authorize
    // `/v1/models`, so the probe is a chat request to a router model.
    ApiKeyProvider {
        key: "firepass",
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
    },
    // oh-my-pi auth/gmi-cloud.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "gmi-cloud",
        display_name: "GMI Cloud",
        default_id: "apikey:gmi-cloud",
        dashboard_url: "https://console.gmicloud.ai",
        placeholder: "eyJ...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.gmi-serving.com/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
        categories: LLM,
        serves: &[DeepSeek],
    },
    // oh-my-pi auth/meta.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "meta",
        display_name: "Meta Model API",
        default_id: "apikey:meta",
        dashboard_url: "https://developer.meta.com/ai/",
        placeholder: "Model API key",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.meta.ai/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
        categories: LLM,
        serves: &[Meta],
    },
    // oh-my-pi auth/minimax-code.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "minimax-code",
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
    },
    // oh-my-pi auth/minimax-code-cn.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "minimax-code-cn",
        display_name: "MiniMax Token Plan (China)",
        default_id: "apikey:minimax-code-cn",
        dashboard_url: "https://platform.minimaxi.com/subscribe/token-plan",
        placeholder: "sk-...",
        validation: KeyValidation::OpenAiChat {
            base_url: "https://api.minimaxi.com/v1",
            model: "MiniMax-M3",
        },
        categories: LLM,
        serves: &[MiniMax],
    },
    // oh-my-pi auth/nanogpt.kdl.
    // A broad aggregator: its catalog carries models from every vendor listed here.
    ApiKeyProvider {
        key: "nanogpt",
        display_name: "NanoGPT",
        default_id: "apikey:nanogpt",
        dashboard_url: "https://nano-gpt.com/api",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://nano-gpt.com/api/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
        categories: LLM,
        serves: ModelVendor::ALL,
    },
    // oh-my-pi auth/novita.kdl; serves from its models.json rows.
    // novita.kdl: the probe is inference, not billing, because the billing route needs a
    // Balance permission some team roles lack, which rejected their valid keys.
    ApiKeyProvider {
        key: "novita",
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
    },
    // oh-my-pi auth/ollama-cloud.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "ollama-cloud",
        display_name: "Ollama Cloud",
        default_id: "apikey:ollama-cloud",
        dashboard_url: "https://ollama.com/settings/keys",
        placeholder: "ollama-cloud-api-key",
        validation: KeyValidation::Unvalidated {
            reason: "oh-my-pi declares no validation probe for Ollama Cloud",
        },
        categories: LLM,
        serves: &[OpenAI, Google, DeepSeek, Mistral, Moonshot, Zhipu, Qwen, Nvidia, MiniMax],
    },
    // oh-my-pi auth/opencode-go.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "opencode-go",
        display_name: "OpenCode Go",
        default_id: "apikey:opencode-go",
        dashboard_url: "https://opencode.ai/auth",
        placeholder: "sk-...",
        validation: KeyValidation::Unvalidated {
            reason: "oh-my-pi declares no validation probe for OpenCode Go",
        },
        categories: LLM,
        serves: &[OpenAI, XAI, DeepSeek, Moonshot, Zhipu, Meta, Qwen, MiniMax, Xiaomi],
    },
    // oh-my-pi auth/opencode-zen.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "opencode-zen",
        display_name: "OpenCode Zen",
        default_id: "apikey:opencode-zen",
        dashboard_url: "https://opencode.ai/auth",
        placeholder: "sk-...",
        validation: KeyValidation::Unvalidated {
            reason: "oh-my-pi declares no validation probe for OpenCode Zen",
        },
        categories: LLM,
        serves: &[Anthropic, OpenAI, Google, XAI, DeepSeek, Moonshot, Zhipu, Meta, Qwen, Nvidia, MiniMax, Xiaomi],
    },
    // oh-my-pi auth/qianfan.kdl; serves from its models.json rows.
    // Unvalidated rather than a chat probe: oh-my-pi's probe for Qianfan tolerates a 401
    // whose error code is `invalid_model` (the account lacks the probe model), and the
    // chat probe here treats every 401 as a bad key, so it would refuse valid keys.
    ApiKeyProvider {
        key: "qianfan",
        display_name: "Qianfan",
        default_id: "apikey:qianfan",
        dashboard_url: "https://console.bce.baidu.com/qianfan/ais/console/apiKey",
        placeholder: "bce-v3/ALTAK-...",
        validation: KeyValidation::Unvalidated {
            reason: "Qianfan answers 401 when the probe model is not enabled on the account, and this login cannot tell that apart from a bad key",
        },
        categories: LLM,
        serves: &[DeepSeek],
    },
    // oh-my-pi auth/qwen-portal.kdl.
    // Qwen's own portal (portal.qwen.ai); its model ids are opaque aliases, so `serves` is
    // the operator's own vendor rather than read off model ids.
    ApiKeyProvider {
        key: "qwen-portal",
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
    },
    // oh-my-pi auth/sakana.kdl.
    // Serves Sakana's own models only, and Sakana is not a vendor in `ModelVendor`.
    ApiKeyProvider {
        key: "sakana",
        display_name: "Sakana AI",
        default_id: "apikey:sakana",
        dashboard_url: "https://console.sakana.ai/api-keys",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.sakana.ai/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
        categories: LLM,
        serves: &[],
    },
    // oh-my-pi auth/siliconflow.kdl.
    // The roster is live-only; `serves` is only the default model's family (GLM) named in
    // oh-my-pi's providers/siliconflow.kdl, not the full catalog.
    ApiKeyProvider {
        key: "siliconflow",
        display_name: "SiliconFlow",
        default_id: "apikey:siliconflow",
        dashboard_url: "https://cloud.siliconflow.com/account/ak",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.siliconflow.com/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
        categories: LLM,
        serves: &[Zhipu],
    },
    // oh-my-pi auth/siliconflow-cn.kdl.
    // The roster is live-only; `serves` is only the default model's family (DeepSeek) named
    // in oh-my-pi's providers/siliconflow-cn.kdl, not the full catalog.
    ApiKeyProvider {
        key: "siliconflow-cn",
        display_name: "SiliconFlow (China)",
        default_id: "apikey:siliconflow-cn",
        dashboard_url: "https://cloud.siliconflow.cn/account/ak",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.siliconflow.cn/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
        categories: LLM,
        serves: &[DeepSeek],
    },
    // oh-my-pi auth/singularityapi-dev.kdl.
    // The roster is per key; `serves` is the families oh-my-pi's
    // providers/singularityapi-dev.kdl names (DeepSeek, Kimi, GLM), not the full catalog.
    ApiKeyProvider {
        key: "singularityapi-dev",
        display_name: "SingularityAPI",
        default_id: "apikey:singularityapi-dev",
        dashboard_url: "https://app.singularityapi.dev",
        placeholder: "sk-sapi-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.singularityapi.dev/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
        categories: LLM,
        serves: &[DeepSeek, Moonshot, Zhipu],
    },
    // oh-my-pi auth/singularityapi-tech.kdl. The roster is per key (no models.json rows);
    // `serves` comes from oh-my-pi's providers/singularityapi-tech.kdl, which says this
    // deployment routes requests only to DeepSeek models.
    ApiKeyProvider {
        key: "singularityapi-tech",
        display_name: "SingularityAPI Reserved Lanes",
        default_id: "apikey:singularityapi-tech",
        dashboard_url: "https://app.singularityapi.tech/compute/billing",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.singularityapi.tech/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
        categories: LLM,
        serves: &[DeepSeek],
    },
    // oh-my-pi auth/stepfun.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "stepfun",
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
    },
    // oh-my-pi auth/synthetic.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "synthetic",
        display_name: "Synthetic",
        default_id: "apikey:synthetic",
        dashboard_url: "https://dev.synthetic.new/docs/api/overview",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://api.synthetic.new/openai/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
        categories: LLM,
        serves: &[OpenAI, DeepSeek, Moonshot, Zhipu, Qwen, Nvidia],
    },
    // oh-my-pi auth/typesafe.kdl.
    // Serves TypeSafe's own judgment models only, which match no vendor in `ModelVendor`.
    ApiKeyProvider {
        key: "typesafe",
        display_name: "TypeSafe",
        default_id: "apikey:typesafe",
        dashboard_url: "https://console.typesafe.ai/",
        placeholder: "API key",
        validation: KeyValidation::Unvalidated {
            reason: "a TypeSafe key may belong to a deployment at a custom base URL, and probing the public host would refuse it",
        },
        categories: LLM,
        serves: &[],
    },
    // oh-my-pi auth/umans.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "umans",
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
    },
    // oh-my-pi auth/venice.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "venice",
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
    },
    // oh-my-pi auth/vercel-ai-gateway.kdl.
    // A broad aggregator: its catalog carries models from every vendor listed here.
    ApiKeyProvider {
        key: "vercel-ai-gateway",
        display_name: "Vercel AI Gateway",
        default_id: "apikey:vercel-ai-gateway",
        dashboard_url: "https://vercel.com/d?to=%2F%5Bteam%5D%2F%7E%2Fai-gateway%2Fapi-keys&title=AI+Gateway+API+Keys",
        placeholder: "vck_...",
        validation: KeyValidation::Unvalidated {
            reason: "oh-my-pi declares no validation probe for Vercel AI Gateway",
        },
        categories: LLM,
        serves: ModelVendor::ALL,
    },
    // oh-my-pi auth/wafer-serverless.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "wafer-serverless",
        display_name: "Wafer Serverless (pay-as-you-go)",
        default_id: "apikey:wafer-serverless",
        dashboard_url: "https://app.wafer.ai/usage",
        placeholder: "wfr_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://pass.wafer.ai/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
        categories: LLM,
        serves: &[DeepSeek, Moonshot, Zhipu, Qwen, MiniMax],
    },
    // oh-my-pi auth/xiaomi-token-plan-ams.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "xiaomi-token-plan-ams",
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
    },
    // oh-my-pi auth/xiaomi-token-plan-cn.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "xiaomi-token-plan-cn",
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
    },
    // oh-my-pi auth/xiaomi-token-plan-sgp.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "xiaomi-token-plan-sgp",
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
    },
    // oh-my-pi auth/yolo-auto.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "yolo-auto",
        display_name: "Yolo-Auto",
        default_id: "apikey:yolo-auto",
        dashboard_url: "https://yolo-auto.com/app",
        placeholder: "yolo_...",
        validation: KeyValidation::GetEndpoint {
            url: "https://yolo-auto.com/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
        categories: LLM,
        serves: &[DeepSeek, Qwen],
    },
    // oh-my-pi auth/zenmux.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "zenmux",
        display_name: "ZenMux",
        default_id: "apikey:zenmux",
        dashboard_url: "https://zenmux.ai/settings/keys",
        placeholder: "sk-...",
        validation: KeyValidation::GetEndpoint {
            url: "https://zenmux.ai/api/v1/models",
            auth_header: AuthHeaderScheme::Bearer,
        },
        categories: LLM,
        serves: &[Anthropic, OpenAI, Google, XAI, DeepSeek, Mistral, Moonshot, Zhipu, Meta, Qwen, MiniMax, Xiaomi, StepFun],
    },
    // oh-my-pi auth/zhipu-coding-plan.kdl; serves from its models.json rows.
    ApiKeyProvider {
        key: "zhipu-coding-plan",
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
    },
    // oh-my-pi auth/tavily.kdl. A web search API, not a model provider.
    ApiKeyProvider {
        key: "tavily",
        display_name: "Tavily",
        default_id: "apikey:tavily",
        dashboard_url: "https://app.tavily.com/home",
        placeholder: "tvly-...",
        validation: KeyValidation::Unvalidated {
            reason: "oh-my-pi declares no validation probe for Tavily",
        },
        categories: WEB_SEARCH,
        serves: &[],
    },
    // oh-my-pi auth/kagi.kdl. A web search API, not a model provider.
    ApiKeyProvider {
        key: "kagi",
        display_name: "Kagi",
        default_id: "apikey:kagi",
        dashboard_url: "https://kagi.com/settings/api",
        placeholder: "KG_...",
        validation: KeyValidation::Unvalidated {
            reason: "oh-my-pi declares no validation probe for Kagi",
        },
        categories: WEB_SEARCH,
        serves: &[],
    },
    // oh-my-pi auth/exa.kdl. A web search API, not a model provider.
    ApiKeyProvider {
        key: "exa",
        display_name: "Exa",
        default_id: "apikey:exa",
        dashboard_url: "https://dashboard.exa.ai/api-keys",
        placeholder: "API key",
        validation: KeyValidation::Unvalidated {
            reason: "oh-my-pi declares no validation probe for Exa",
        },
        categories: WEB_SEARCH,
        serves: &[],
    },
    // oh-my-pi auth/parallel.kdl. A web search API, not a model provider.
    ApiKeyProvider {
        key: "parallel",
        display_name: "Parallel",
        default_id: "apikey:parallel",
        dashboard_url: "https://platform.parallel.ai/settings?tab=api-keys",
        placeholder: "sk_...",
        validation: KeyValidation::Unvalidated {
            reason: "oh-my-pi declares no validation probe for Parallel",
        },
        categories: WEB_SEARCH,
        serves: &[],
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
    use std::collections::{BTreeSet, HashSet};

    use super::*;

    #[test]
    fn catalog_entry_expectations_are_separate_from_no_match_expectations() {
        let entry_rows = [
            ("apikey:zai", vec!["llm-provider"]),
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

    #[test]
    fn both_catalogs_have_exact_owner_supplied_assignments() {
        // 15 original API-key rows, 37 model providers mirrored from oh-my-pi,
        // Kiro, and 4 search APIs.
        assert_eq!(API_KEY_PROVIDERS.len(), 57);
        assert_eq!(LOGIN_PROVIDERS.len(), 11);
        // Which api-key rows are `llm-provider` and which are `web-search` is pinned by
        // the two category tests below, which also require every row to be listed.
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
            [
                "llm-provider",
                "data-warehouse",
                "cloud-infrastructure",
                "web-search"
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
                "stepfun"
            ]
        );
    }

    /// The api-key model providers this table held before oh-my-pi's were mirrored.
    const ORIGINAL_LLM_KEYS: &[&str] = &[
        "zai",
        "openrouter",
        "deepseek",
        "cerebras",
        "fireworks-ai",
        "groq",
        "mistral",
        "together",
        "perplexity",
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
        "ollama-cloud",
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
        "synthetic",
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

    /// Web search APIs. Their keys are not model credentials.
    const SEARCH_KEYS: &[&str] = &["tavily", "kagi", "exa", "parallel"];

    /// oh-my-pi providers deliberately NOT in this table:
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
        "alibaba-coding-plan",
        "alibaba-token-plan",
        "cloudflare-ai-gateway",
        "kilo",
        "xiaomi",
        "anthropic",
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
            .chain([&"kiro"])
        {
            let row = api_key_provider(key).unwrap_or_else(|| panic!("no api-key row {key}"));
            assert_eq!(row.default_id, format!("apikey:{key}"));
            for id in [format!("apikey:{key}"), format!("apikey:{key}:work")] {
                assert_eq!(category_defaults(&id), ["llm-provider"], "{id}");
            }
        }
        // Every row must be listed somewhere, so a new row cannot land uncategorised
        // without this test naming it.
        for entry in API_KEY_PROVIDERS {
            assert!(
                ORIGINAL_LLM_KEYS.contains(&entry.key)
                    || MIRRORED_LLM_KEYS.contains(&entry.key)
                    || SEARCH_KEYS.contains(&entry.key)
                    || entry.key == "kiro",
                "api-key row {} is in no category list",
                entry.key
            );
        }
    }

    /// Every LLM consumer is granted `llm-provider`, so a search key filed there would be
    /// readable by all of them. Search keys get `web-search` and nothing else, and the
    /// search rows are the ONLY api-key rows outside `llm-provider`.
    #[test]
    fn search_keys_are_web_search_and_never_llm_provider() {
        for key in SEARCH_KEYS {
            let row = api_key_provider(key).unwrap_or_else(|| panic!("no api-key row {key}"));
            assert!(row.serves.is_empty(), "{key} serves no model vendor");
            for id in [format!("apikey:{key}"), format!("apikey:{key}:work")] {
                assert_eq!(category_defaults(&id), ["web-search"], "{id}");
            }
        }
        let outside_llm: Vec<_> = API_KEY_PROVIDERS
            .iter()
            .filter(|entry| entry.categories != LLM)
            .map(|entry| entry.key)
            .collect();
        assert_eq!(outside_llm, SEARCH_KEYS);
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
    /// explains nothing.
    #[test]
    fn unvalidated_rows_are_exactly_the_ones_without_a_usable_probe() {
        let unvalidated: Vec<_> = API_KEY_PROVIDERS
            .iter()
            .filter_map(|entry| match entry.validation {
                KeyValidation::Unvalidated { reason } => {
                    assert!(!reason.trim().is_empty(), "{} has no reason", entry.key);
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
                "tavily",
                "kagi",
                "exa",
                "parallel",
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
                auth_header: AuthHeaderScheme::Bearer,
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
                "web-search"
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
                ("tavily", vec![]),
                ("kagi", vec![]),
                ("exa", vec![]),
                ("parallel", vec![]),
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
