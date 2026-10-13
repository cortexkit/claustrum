use super::*;
use crate::refresh_adapters::fixture::FixtureTransport;

pub(super) fn device_tokens(optionals: bool) -> DeviceTokens {
    DeviceTokens {
        access_token: "meta-identity-token".into(),
        refresh_token: optionals.then(|| "meta-refresh-token".into()),
        expires_at_ms: optionals.then_some(123),
        expiry_field_present: optionals,
    }
}

#[tokio::test]
async fn meta_login_mints_key_and_captures_identity_and_presence_without_serving_session() {
    for (body, optional, expiry) in [
        (fixtures::KEY, false, false),
        (fixtures::KEY_EXPIRY, true, true),
    ] {
        let before = now_ms();
        let http = FixtureTransport::ok(200, body);
        let (record, fields) = login_record(device_tokens(optional), &http).await.unwrap();
        assert_eq!(record.payload.expose(), b"muse-inference-key");
        assert_eq!(record.identity.account_id.as_deref(), Some("meta-account"));
        assert_eq!(
            record.identity.email.as_deref(),
            (!expiry).then_some("muse@example.invalid")
        );
        assert_eq!(record.refresh_adapter.as_deref(), Some("meta"));
        assert_eq!(fields.refresh_token_present, optional);
        assert_eq!(fields.device_expiry_field_present, optional);
        assert_eq!(fields.key_expiry_field_present, expiry);
        let oauth = record.oauth.unwrap();
        let session: MetaSession = serde_json::from_str(oauth.refresh_token.expose()).unwrap();
        assert_eq!(session.identity_token.expose(), "meta-identity-token");
        assert_eq!(
            session.refresh_token.as_ref().map(|s| s.expose().as_str()),
            optional.then_some("meta-refresh-token")
        );
        let lifetime = if expiry { 3_600_000 } else { 86_400_000 };
        assert!(oauth.expires_at_ms.unwrap() >= before + lifetime);
        assert!(oauth.expires_at_ms.unwrap() <= now_ms() + lifetime);
        let requests = http.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://api.meta.ai/muse-code/key");
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].content_type, "application/json");
        assert_eq!(
            requests[0].headers,
            vec![
                ("Authorization".into(), "Bearer meta-identity-token".into()),
                ("User-Agent".into(), super::USER_AGENT.into()),
                ("x-api-version".into(), "1.0.0".into()),
                ("Accept".into(), "application/json".into())
            ]
        );
        assert_eq!(requests[0].body, br#"{"onboard":true}"#);
    }
}

/// auth.meta.com redirects any request without a User-Agent to
/// `facebook.com/unsupportedbrowser` (a 302 our client must not follow), which
/// broke the first live login before any token existed. Both device-flow calls
/// carry it through `extra_headers`.
#[test]
fn meta_device_flow_sends_a_user_agent_on_both_auth_meta_calls() {
    let cfg = super::device_config();
    let has = |name: &str, value: &str| {
        cfg.extra_headers
            .iter()
            .any(|(n, v)| n == name && v == value)
    };
    assert!(super::USER_AGENT.starts_with("cortexkit-credentials/"));
    assert!(
        has("User-Agent", super::USER_AGENT),
        "no User-Agent: Meta answers 302"
    );
    assert!(has("Accept", "application/json"));
    assert!(has("x-api-version", super::API_VERSION));
}

#[test]
fn meta_assumed_key_expiry_is_fresh_one_tick_before_24h_and_expired_at_24h() {
    let parsed: KeyResponse = serde_json::from_str(fixtures::KEY).unwrap();
    let minted_at = 1_000_000;
    let expires_at = parsed
        .expiry(parsed.api_key.as_ref().unwrap(), minted_at)
        .unwrap();
    assert_eq!(expires_at, minted_at + 86_400_000);
    let oauth = OAuthCredential {
        access_token: "key".to_string().into(),
        refresh_token: "session".to_string().into(),
        expires_at_ms: Some(expires_at),
        token_url: String::new(),
        client_id: None,
        client_secret: None,
        scopes: vec![],
    };
    assert!(!oauth.is_access_expired(minted_at + 86_400_000 - 1, 0));
    assert!(oauth.is_access_expired(minted_at + 86_400_000, 0));
}

#[tokio::test]
async fn meta_expiry_prefers_response_then_jwt_before_assumed_horizon() {
    let minted = mint_key(
        &"identity".to_string().into(),
        &FixtureTransport::ok(200, fixtures::KEY_JWT),
    )
    .await
    .unwrap();
    assert_eq!(minted.expires_at_ms, 2_000_000_000_000);
    assert!(!minted.expiry_field_present);
    for (field, expected) in [
        (r#""expires_at":2000000001"#, 2_000_000_001_000),
        (r#""expires_at":"2033-05-18T03:33:22Z""#, 2_000_000_002_000),
        (r#""expires_at_ms":2000000003000"#, 2_000_000_003_000),
    ] {
        let body = fixtures::KEY_JWT.replace('}', &format!(",{field}}}"));
        let minted = mint_key(
            &"identity".to_string().into(),
            &FixtureTransport::ok(200, body),
        )
        .await
        .unwrap();
        assert_eq!(minted.expires_at_ms, expected);
        assert!(minted.expiry_field_present);
    }
}

#[tokio::test]
async fn meta_refresh_preserves_both_stored_tokens_and_only_mints_at_key_endpoint() {
    let (record, _) = login_record(
        device_tokens(true),
        &FixtureTransport::ok(200, fixtures::KEY),
    )
    .await
    .unwrap();
    let cred = record.oauth.unwrap();
    let http = FixtureTransport::ok(200, fixtures::KEY_JWT);
    let refreshed = MetaAdapter.refresh(&cred, &http).await.unwrap();
    assert_eq!(
        refreshed.access_token.expose(),
        "e30.eyJleHAiOjIwMDAwMDAwMDB9.sig"
    );
    assert_eq!(refreshed.refresh_token, cred.refresh_token);
    assert_eq!(refreshed.expires_at_ms, Some(2_000_000_000_000));
    assert_eq!(http.requests().len(), 1);
    assert_eq!(http.requests()[0].url, "https://api.meta.ai/muse-code/key");
    assert!(MetaAdapter.non_mutating_check(&cred, &http).await.is_none());
}

#[tokio::test]
async fn meta_mint_classifies_session_subscription_and_transient_failures_narrowly() {
    for (status, body, expected) in [
        (401, fixtures::UNAUTHORIZED, "invalid_grant"),
        (403, fixtures::FORBIDDEN, "invalid_grant"),
        (200, fixtures::INACTIVE, "subscription_required"),
        (200, fixtures::PAYMENT, "subscription_required"),
        (200, fixtures::PAYMENT_ACTION, "subscription_required"),
        (402, fixtures::PAYMENT, "subscription_required"),
        (429, fixtures::TRANSIENT, "status"),
        (503, fixtures::TRANSIENT, "status"),
        (400, fixtures::PAYMENT, "status"),
    ] {
        let err = login_record(device_tokens(false), &FixtureTransport::ok(status, body))
            .await
            .unwrap_err();
        assert_eq!(err.variant_name(), expected, "status {status}");
        if expected == "subscription_required" {
            assert!(err.to_string().contains("subscription"));
        }
    }
    let body = fixtures::KEY.replace(
        '}',
        r#", "require_payment":true,"action_url":"https://meta.ai/subscribe"}"#,
    );
    assert!(
        login_record(device_tokens(false), &FixtureTransport::ok(200, body))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn meta_login_rejects_missing_key_identity_and_invalid_expiry_without_echoing_secrets() {
    for body in [
        r#"{"api_key":"SECRET"}"#,
        r#"{"user_id":"account"}"#,
        r#"{"api_key":"SECRET","user_id":"account","expires_in":-1}"#,
        r#"{"api_key":"SECRET","user_id":"account","expires_at":"SECRET"}"#,
        r#"{"api_key":"SECRET","user_id":"account","expires_at_ms":-1}"#,
        r#"{"api_key":"SECRET","user_id":"account","expires_in":"SECRET"}"#,
    ] {
        let error = login_record(device_tokens(false), &FixtureTransport::ok(200, body))
            .await
            .unwrap_err();
        assert_eq!(error.variant_name(), "decode");
        assert!(!format!("{error:?} {error}").contains("SECRET"));
    }
    for status in [401, 403, 429, 503] {
        let error = login_record(
            device_tokens(false),
            &FixtureTransport::ok(status, "SECRET"),
        )
        .await
        .unwrap_err();
        assert!(!format!("{error:?} {error}").contains("SECRET"));
    }
}

#[test]
fn meta_catalog_stamps_oauth_labels_with_native_family_and_serves_meta() {
    for id in ["oauth:meta", "oauth:meta:work"] {
        assert_eq!(
            crate::catalog::category_defaults(id),
            ["llm-provider", "meta-native"]
        );
        assert_eq!(
            crate::catalog::serves_for(id),
            [crate::catalog::ModelVendor::Meta]
        );
    }
    let provider = crate::catalog::login_provider("meta").unwrap();
    assert_eq!(provider.default_id, "oauth:meta");
    assert_eq!(provider.device, Some(crate::catalog::DeviceKind::Meta));
    assert_eq!(provider.client_id, "1031625952748946");
    assert_eq!(
        provider.token_url,
        "https://auth.meta.com/oidc/device/token/"
    );
    assert!(provider.scopes.is_empty());
}
