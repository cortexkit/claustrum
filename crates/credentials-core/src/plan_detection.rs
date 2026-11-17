//! Provider observations, separate from the operator's pricing override.

use serde::Deserialize;

pub use claustrum_model::plan_detection::{chatgpt_plan, DetectedPlan};

use crate::refresh_adapters::{HttpTransport, RefreshError};

pub const PROFILE_URL: &str = "https://api.anthropic.com/api/oauth/profile";
pub const PROFILE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

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
    let tier = match (
        org.rate_limit_tier.as_deref(),
        org.organization_type.as_deref(),
    ) {
        (Some("default_claude_max_20x"), _) => Some("max_20x"),
        (Some("default_claude_max_5x"), _) => Some("max_5x"),
        (Some("default_claude_pro"), _) | (None, Some("claude_pro")) => Some("pro"),
        _ => None,
    };
    let raw = org.rate_limit_tier.or(org.organization_type);
    Ok(DetectedPlan::observed(raw, tier))
}

/// The profile request has its own timeout, separate from the token endpoint's, so a slow
/// profile service can only lose the plan reading, never delay a token.
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

/// Ask Claude's profile endpoint for the plan before an interactive login stores its
/// record. The caller stores the tokens even when this returns an error.
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
