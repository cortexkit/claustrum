use super::*;
use crate::oauth::OAuthCredential;
use crate::record::VaultRecord;
use crate::refresh_adapters::{fixture::FixtureTransport, HttpResponse};
use base64::Engine;

pub(crate) fn jwt(plan: Option<&str>) -> String {
    let claims = match plan {
        Some(plan) => {
            serde_json::json!({"https://api.openai.com/auth": {"chatgpt_plan_type": plan}})
        }
        None => serde_json::json!({}),
    };
    format!(
        "e30.{}.signature",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap())
    )
}

// The profile fields used for pricing are organization.organization_type and
// organization.rate_limit_tier. This sanitized public example (Claude Code issue
// #48460) pins that nesting, not an independently captured live response.
pub(crate) const PROFILE: &[u8] = br#"{"account":{"uuid":"account"},"organization":{"uuid":"org","organization_type":"claude_max","rate_limit_tier":"default_claude_max_20x"}}"#;
pub(crate) const ANTHROPIC_TOKENS: &[u8] = br#"{"token_type":"Bearer","access_token":"sk-ant-oat01-new-access","refresh_token":"sk-ant-ort01-new-refresh","expires_in":28800,"scope":"user:profile user:inference"}"#;

#[test]
fn chatgpt_mapping_is_exact_and_unknown_claims_never_guess() {
    for (raw, tier) in [
        (Some("pro"), Some("pro_200")),
        (Some("prolite"), Some("pro_100")),
        (Some("plus"), Some("plus")),
        (Some("pro_500"), None),
        (Some("PRO"), None),
        (Some(""), None),
        (None, None),
    ] {
        let plan = chatgpt_plan(&jwt(raw));
        assert_eq!(plan.tier.as_deref(), tier, "{raw:?}");
        assert_eq!(plan.raw.as_deref(), raw);
        assert!(plan.observed_at_ms > 0);
    }
    assert_eq!(chatgpt_plan("not a jwt").tier, None);
}

#[test]
fn anthropic_mapping_is_exact_not_a_suffix_guess() {
    for (raw, tier) in [
        ("default_claude_max_20x", Some("max_20x")),
        ("default_claude_max_5x", Some("max_5x")),
        ("default_claude_pro", Some("pro")),
        ("future_max_20x", None),
        ("default_claude_max_100x", None),
        ("", None),
    ] {
        let body = serde_json::to_vec(&serde_json::json!({"organization":{"organization_type":"claude_max","rate_limit_tier":raw}})).unwrap();
        let plan = anthropic_profile(&body).unwrap();
        assert_eq!(plan.tier.as_deref(), tier, "{raw}");
        assert_eq!(plan.raw.as_deref(), Some(raw));
    }
    assert_eq!(
        anthropic_profile(br#"{"organization":{"organization_type":"claude_pro"}}"#)
            .unwrap()
            .tier
            .as_deref(),
        Some("pro")
    );
    assert_eq!(
        anthropic_profile(br#"{"organization":{}}"#).unwrap().tier,
        None
    );
    assert!(anthropic_profile(br#"{"organization":{"rate_limit_tier":42}}"#).is_err());
}

fn record(adapter: &str, access: String) -> VaultRecord {
    VaultRecord::new_oauth(
        "login",
        adapter,
        OAuthCredential {
            access_token: access.clone().into(),
            refresh_token: "refresh".to_owned().into(),
            expires_at_ms: None,
            token_url: String::new(),
            client_id: None,
            client_secret: None,
            scopes: vec!["user:profile".into()],
        },
        access.into_bytes(),
    )
}

#[tokio::test]
async fn chatgpt_login_detects_the_access_token_not_the_id_token() {
    let body = serde_json::to_vec(&serde_json::json!({"access_token":jwt(Some("prolite")),"refresh_token":"refresh","id_token":jwt(Some("pro"))})).unwrap();
    let http = FixtureTransport::ok(200, body);
    let tokens = crate::oauth_login::exchange_authorization_code_form(
        &http,
        crate::refresh_adapters::openai::TOKEN_URL,
        "client",
        "redirect",
        &crate::oauth_login::Callback {
            code: "code".into(),
            state: "state".into(),
        },
        "state",
        "verifier",
        &[],
        0,
    )
    .await
    .unwrap();
    let mut record = record("openai", tokens.access_token);
    detect_login_plan(&http, &mut record).await.unwrap();
    assert_eq!(
        record.detected_plan.unwrap().tier.as_deref(),
        Some("pro_100")
    );
    assert_eq!(http.requests().len(), 1, "ChatGPT adds no request");
}

#[tokio::test]
async fn anthropic_login_detects_profile_with_the_minted_bearer() {
    let http = FixtureTransport::new(vec![
        Ok(HttpResponse {
            status: 200,
            body: ANTHROPIC_TOKENS.to_vec(),
        }),
        Ok(HttpResponse {
            status: 200,
            body: PROFILE.to_vec(),
        }),
    ]);
    let tokens = crate::oauth_login::exchange_authorization_code(
        &http,
        crate::refresh_adapters::anthropic::LOGIN_TOKEN_URL,
        "client",
        "redirect",
        &crate::oauth_login::Callback {
            code: "code".into(),
            state: "state".into(),
        },
        "state",
        "verifier",
        0,
    )
    .await
    .unwrap();
    let mut record = record("anthropic", tokens.access_token);
    detect_login_plan(&http, &mut record).await.unwrap();
    assert_eq!(
        record.detected_plan.unwrap().tier.as_deref(),
        Some("max_20x")
    );
    let requests = http.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].method, "GET");
    assert_eq!(requests[1].url, PROFILE_URL);
    assert_eq!(
        requests[1].headers,
        [(
            "Authorization".into(),
            "Bearer sk-ant-oat01-new-access".into()
        )]
    );
}

#[tokio::test]
async fn anthropic_profile_failure_preserves_login_tokens_and_old_detection() {
    for response in [
        Err(RefreshError::Transport("offline".into())),
        Ok(HttpResponse {
            status: 503,
            body: vec![],
        }),
        Ok(HttpResponse {
            status: 200,
            body: b"invalid".to_vec(),
        }),
    ] {
        let http = FixtureTransport::new(vec![response]);
        let mut record = record("anthropic", "access".into());
        record.detected_plan = Some(anthropic_profile(PROFILE).unwrap());
        let before = record.clone();
        assert!(detect_login_plan(&http, &mut record).await.is_err());
        assert_eq!(record, before);
    }
}
