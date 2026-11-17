//! Provider observations stored beside credential tokens.

use serde::{Deserialize, Serialize};

/// The subscription plan a provider reported, stored encrypted inside the VaultRecord
/// beside its tokens. `raw` is the provider's own string (a ChatGPT `chatgpt_plan_type`,
/// a Claude `rate_limit_tier`); one the mapping does not recognise is kept in `raw` for
/// diagnosis and gets no `tier`, never a guessed one.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetectedPlan {
    pub tier: Option<String>,
    pub raw: Option<String>,
    pub observed_at_ms: i64,
}

impl DetectedPlan {
    pub fn observed(raw: Option<String>, tier: Option<&str>) -> Self {
        Self {
            tier: tier.map(str::to_owned),
            raw,
            observed_at_ms: chrono::Utc::now().timestamp_millis(),
        }
    }
}

pub fn chatgpt_plan(access_token: &str) -> DetectedPlan {
    let raw = crate::oauth::decode_jwt_claims(access_token).and_then(|claims| {
        claims
            .get("https://api.openai.com/auth")?
            .get("chatgpt_plan_type")?
            .as_str()
            .map(str::to_owned)
    });
    let tier = match raw.as_deref() {
        Some("pro") => Some("pro_200"),
        Some("prolite") => Some("pro_100"),
        // OpenAI's Pro Max plan, $500 a month; Fusiform prices it as `openai/pro_500`.
        Some("promax") => Some("pro_500"),
        Some("plus") => Some("plus"),
        _ => None,
    };
    DetectedPlan::observed(raw, tier)
}
