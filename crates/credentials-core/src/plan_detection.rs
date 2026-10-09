//! Provider observations, separate from the operator's pricing override.

use serde::{Deserialize, Serialize};

use crate::refresh_adapters::{HttpTransport, RefreshError};

pub const PROFILE_URL: &str = "https://api.anthropic.com/api/oauth/profile";
pub const PROFILE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Provider subscription metadata encrypted inside VaultRecord beside its tokens.
/// An unknown provider string is retained for diagnosis, never given a guessed tier.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetectedPlan {
    pub tier: Option<String>,
    pub raw: Option<String>,
    pub observed_at_ms: i64,
}

impl DetectedPlan {
    fn observed(raw: Option<String>, tier: Option<&str>) -> Self {
        Self {
            tier: tier.map(str::to_owned),
            raw,
            observed_at_ms: chrono::Utc::now().timestamp_millis(),
        }
    }
}

pub fn chatgpt_plan(access_token: &str) -> DetectedPlan {
    let raw = crate::oauth_login::decode_jwt_claims(access_token).and_then(|claims| {
        claims
            .get("https://api.openai.com/auth")?
            .get("chatgpt_plan_type")?
            .as_str()
            .map(str::to_owned)
    });
    let tier = match raw.as_deref() {
        Some("pro") => Some("pro_200"),
        Some("prolite") => Some("pro_100"),
        Some("plus") => Some("plus"),
        _ => None,
    };
    DetectedPlan::observed(raw, tier)
}

/// Read only the profile fields needed for pricing; unrelated profile data is ignored.
pub fn anthropic_profile(body: &[u8]) -> Result<DetectedPlan, RefreshError> {
    #[derive(Deserialize)]
    struct Profile {
        organization: Organization,
    }
    #[derive(Deserialize)]
    struct Organization {
        #[serde(default)]
        rate_limit_tier: Option<String>,
        #[serde(default)]
        organization_type: Option<String>,
    }
    let profile: Profile =
        serde_json::from_slice(body).map_err(|e| RefreshError::Decode(e.to_string()))?;
    let org = profile.organization;
    let raw = org.rate_limit_tier.or(org.organization_type);
    let tier = match raw.as_deref() {
        Some("default_claude_max_20x") => Some("max_20x"),
        Some("default_claude_max_5x") => Some("max_5x"),
        Some("default_claude_pro") | Some("claude_pro") => Some("pro"),
        _ => None,
    };
    Ok(DetectedPlan::observed(raw, tier))
}

/// A separate deadline bounds metadata work, not the token endpoint's request.
pub async fn fetch_anthropic_plan(
    http: &dyn HttpTransport,
    access_token: &str,
) -> Result<DetectedPlan, RefreshError> {
    tokio::time::timeout(PROFILE_TIMEOUT, async {
        let authorization = format!("Bearer {access_token}");
        let response = http
            .get(PROFILE_URL, &[("Authorization", &authorization)])
            .await?;
        if response.status != 200 {
            return Err(RefreshError::Status(
                response.status,
                "profile unavailable".into(),
            ));
        }
        anthropic_profile(&response.body)
    })
    .await
    .map_err(|_| RefreshError::Transport("profile timed out".into()))?
}

/// Interactive login tolerates an unavailable profile and deposits its tokens anyway.
pub async fn detect_login_plan(
    http: &dyn HttpTransport,
    record: &mut crate::record::VaultRecord,
) -> Result<(), RefreshError> {
    if record.refresh_adapter.as_deref() != Some("anthropic") {
        return Ok(());
    }
    // A record without OAuth material has no access token to ask with; it simply
    // gets no detected tier.
    let Some(oauth) = record.oauth.as_ref() else {
        return Ok(());
    };
    let plan = fetch_anthropic_plan(http, oauth.access_token.expose()).await?;
    record.detected_plan = Some(plan);
    Ok(())
}

/// Use the override whenever present, even if detection disagrees.
pub fn effective_plan(
    operator: Option<String>,
    detected: Option<&DetectedPlan>,
) -> (Option<String>, Option<String>) {
    if let Some(tier) = operator {
        (Some(tier), Some("operator".into()))
    } else if let Some(tier) = detected.and_then(|plan| plan.tier.clone()) {
        (Some(tier), Some("detected".into()))
    } else {
        (None, None)
    }
}

#[cfg(test)]
#[path = "plan_detection_tests.rs"]
pub(crate) mod tests;
