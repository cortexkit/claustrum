use super::*;
use crate::refresh_adapters::{fixture::FixtureTransport, HttpResponse};
use serde_json::{json, Value};

type MintError = GithubNarrowedInstallationError;

const RECORD_ID: &str = "github_app:plex-alfonso";
const INSTALLATIONS: &[u8] =
    include_bytes!("../../../credentials-core/tests/fixtures/github_app/installations.json");
const ACCESS_TOKENS: &[u8] =
    include_bytes!("../../../credentials-core/tests/fixtures/github_app/access_tokens.json");
const REPO: &str = "cortexkit/claustrum";
const TOKEN_MARKER: &str = "token-sentinel-for-redaction";

fn credential() -> OAuthCredential {
    let installations: Value = serde_json::from_slice(INSTALLATIONS).unwrap();
    OAuthCredential {
        access_token: String::new().into(),
        refresh_token: include_str!(
            "../../../credentials-core/tests/fixtures/github_app/test_private_key.pem"
        )
        .to_owned()
        .into(),
        expires_at_ms: None,
        token_url: String::new(),
        client_id: Some(installations[0]["client_id"].as_str().unwrap().to_owned()),
        client_secret: None,
        scopes: vec![],
    }
}

fn response(status: u16, body: impl Into<Vec<u8>>) -> Result<HttpResponse, RefreshError> {
    Ok(HttpResponse {
        status,
        body: body.into(),
    })
}

fn json_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn permissions() -> BTreeMap<String, String> {
    BTreeMap::from([("issues".into(), "read".into())])
}

fn narrowed_reply() -> Value {
    let mut reply: Value = serde_json::from_slice(ACCESS_TOKENS).unwrap();
    reply["token"] = json!(TOKEN_MARKER);
    reply["expires_at"] = json!((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339());
    reply["repositories"] = json!([{"full_name": "CortexKit/CLAUSTRUM"}]);
    reply["permissions"] = json!({"issues": "read", "metadata": "read"});
    reply
}

async fn mint(http: &FixtureTransport) -> Result<GithubNarrowedInstallationToken, MintError> {
    mint_narrowed_installation_token(
        RECORD_ID,
        &credential(),
        &[REPO.into()],
        &permissions(),
        http,
    )
    .await
}

#[tokio::test]
async fn narrowed_mint_posts_one_short_name_and_only_requested_permissions() {
    let mut installations: Value = serde_json::from_slice(INSTALLATIONS).unwrap();
    installations[0]["account"]["login"] = json!("CortexKit");
    let reply = narrowed_reply();
    let http = FixtureTransport::new(vec![
        response(200, json_bytes(&installations)),
        response(201, json_bytes(&reply)),
    ]);

    let token = mint(&http).await.unwrap();
    assert!(token.access_token.expose() == TOKEN_MARKER);
    assert_eq!(token.repositories, [REPO]);
    assert_eq!(token.permissions, permissions());
    assert_eq!(
        token.expires_at_ms,
        chrono::DateTime::parse_from_rfc3339(reply["expires_at"].as_str().unwrap())
            .unwrap()
            .timestamp_millis(),
    );

    let requests = http.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].url, INSTALLATIONS_URL);
    assert_eq!(requests[1].method, "POST");
    assert_eq!(
        requests[1].url.as_str(),
        installations[0]["access_tokens_url"].as_str().unwrap()
    );
    assert_eq!(requests[1].content_type, "application/json");
    let body: Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(
        body,
        json!({"repositories": ["claustrum"], "permissions": {"issues": "read"}})
    );
}

#[tokio::test]
async fn narrowed_mint_canonicalizes_a_whole_binding_and_requires_each_owner_to_match() {
    let selected = ["CORTEXKIT/OTHER".into(), REPO.into()];
    let mut requested = permissions();
    requested.insert("metadata".into(), "read".into());
    let mut reply = narrowed_reply();
    reply["repositories"] = json!([{"full_name": "CORTEXKIT/OtHeR"}, {"full_name": REPO}]);
    let http = FixtureTransport::new(vec![
        response(200, INSTALLATIONS),
        response(201, json_bytes(&reply)),
    ]);
    let minted =
        mint_narrowed_installation_token(RECORD_ID, &credential(), &selected, &requested, &http)
            .await
            .unwrap();
    assert_eq!(minted.repositories, [REPO, "cortexkit/other"]);
    assert_eq!(minted.permissions, requested);
    let requests = http.requests();
    assert_eq!(requests.len(), 2);
    let body: Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(
        body,
        json!({"repositories": ["claustrum", "other"], "permissions": {"issues": "read", "metadata": "read"}})
    );

    let http = FixtureTransport::ok(200, INSTALLATIONS);
    assert_eq!(
        mint_narrowed_installation_token(
            RECORD_ID,
            &credential(),
            &[REPO.into(), "elsewhere/other".into()],
            &requested,
            &http,
        )
        .await
        .unwrap_err(),
        MintError::InstallationUnusable,
    );
    assert_eq!(http.requests().len(), 1);
}

#[tokio::test]
async fn narrowed_mint_refuses_unusable_local_material_without_network() {
    let http = FixtureTransport::new(vec![]);
    let mut absent = credential();
    absent.client_id = None;
    let mut empty = credential();
    empty.client_id = Some(String::new());
    let mut invalid_key = credential();
    invalid_key.refresh_token = String::from("not a PEM key").into();
    for cred in [absent, empty, invalid_key] {
        assert_eq!(
            mint_narrowed_installation_token(
                RECORD_ID,
                &cred,
                &[REPO.into()],
                &permissions(),
                &http
            )
            .await
            .unwrap_err(),
            MintError::InstallationUnusable,
        );
    }
    for scope in [
        vec![],
        vec!["claustrum".into()],
        vec![REPO.into(), REPO.to_ascii_uppercase()],
    ] {
        assert_eq!(
            mint_narrowed_installation_token(
                RECORD_ID,
                &credential(),
                &scope,
                &permissions(),
                &http
            )
            .await
            .unwrap_err(),
            MintError::ScopeUnavailable,
        );
    }
    assert!(http.requests().is_empty());
}

#[tokio::test]
async fn narrowed_discovery_checks_suspension_before_validating_login() {
    let recorded: Value = serde_json::from_slice(INSTALLATIONS).unwrap();
    for (account, expected) in [
        (None, MintError::GithubUnavailable),
        (Some(Value::Null), MintError::GithubUnavailable),
        (Some(json!(["cortexkit"])), MintError::GithubUnavailable),
        (Some(json!({})), MintError::GithubUnavailable),
        (Some(json!({"login": null})), MintError::GithubUnavailable),
        (Some(json!({"login": 123})), MintError::GithubUnavailable),
        (Some(json!({"login": ""})), MintError::GithubUnavailable),
        (
            Some(json!({"login": "elsewhere"})),
            MintError::InstallationUnusable,
        ),
    ] {
        let mut installations = recorded.clone();
        set_field(&mut installations[0], "account", account);
        let http = FixtureTransport::ok(200, json_bytes(&installations));
        assert_eq!(mint(&http).await.unwrap_err(), expected);
        assert_eq!(http.requests().len(), 1);

        installations[0]["suspended_at"] = json!("2026-08-17T09:03:48Z");
        let http = FixtureTransport::ok(200, json_bytes(&installations));
        assert_eq!(
            mint(&http).await.unwrap_err(),
            MintError::InstallationSuspended
        );
        assert_eq!(http.requests().len(), 1);
    }
}

#[tokio::test]
async fn narrowed_discovery_configuration_failures_do_not_exchange() {
    let recorded: Value = serde_json::from_slice(INSTALLATIONS).unwrap();
    let mut several = recorded.clone();
    several.as_array_mut().unwrap().push(recorded[0].clone());
    let mut mismatch = recorded;
    mismatch[0]["app_slug"] = json!("different-app");
    for rejected in [json!([]), several, mismatch] {
        let http = FixtureTransport::ok(200, json_bytes(&rejected));
        assert_eq!(
            mint(&http).await.unwrap_err(),
            MintError::InstallationUnusable
        );
        assert_eq!(http.requests().len(), 1);
    }
}

#[tokio::test]
async fn broad_refresh_ignores_absent_or_malformed_account_and_app_id() {
    let recorded: Value = serde_json::from_slice(INSTALLATIONS).unwrap();
    for (account, app_id) in [
        (None, None),
        (
            Some(json!(["unexpected account"])),
            Some(json!({"bad": "id"})),
        ),
        (Some(Value::Null), Some(json!("4617236"))),
    ] {
        let mut installations = recorded.clone();
        set_field(&mut installations[0], "account", account);
        set_field(&mut installations[0], "app_id", app_id);
        let http = FixtureTransport::new(vec![
            response(200, json_bytes(&installations)),
            response(201, ACCESS_TOKENS),
        ]);
        let tokens = GithubAppAdapter::new()
            .refresh_for_record(RECORD_ID, &credential(), &http)
            .await
            .unwrap();
        let recorded_token: Value = serde_json::from_slice(ACCESS_TOKENS).unwrap();
        assert!(tokens.access_token.expose() == recorded_token["token"].as_str().unwrap());
        let requests = http.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].body, b"{}");
    }
}

fn set_field(record: &mut Value, key: &str, value: Option<Value>) {
    let object = record.as_object_mut().unwrap();
    if let Some(value) = value {
        object.insert(key.into(), value);
    } else {
        object.remove(key);
    }
}

#[tokio::test]
async fn narrowed_exchange_rejects_any_repository_or_permission_scope_mismatch() {
    for (field, value) in [
        ("repositories", None),
        ("repositories", Some(Value::Null)),
        ("repositories", Some(json!({"full_name": REPO}))),
        ("repositories", Some(json!([REPO]))),
        ("repositories", Some(json!([{"full_name": 1}]))),
        ("repositories", Some(json!([]))),
        (
            "repositories",
            Some(json!([{"full_name": "cortexkit/other"}])),
        ),
        (
            "repositories",
            Some(json!([{"full_name": REPO}, {"full_name": "cortexkit/other"}])),
        ),
        (
            "repositories",
            Some(json!([{"full_name": REPO}, {"full_name": "CortexKit/CLAUSTRUM"}])),
        ),
        ("permissions", None),
        ("permissions", Some(Value::Null)),
        ("permissions", Some(json!(["issues", "read"]))),
        ("permissions", Some(json!({"issues": 1}))),
        ("permissions", Some(json!({"metadata": "read"}))),
        ("permissions", Some(json!({"issues": "write"}))),
        (
            "permissions",
            Some(json!({"issues": "read", "contents": "read"})),
        ),
        (
            "permissions",
            Some(json!({"issues": "read", "metadata": "write"})),
        ),
    ] {
        let mut reply = narrowed_reply();
        set_field(&mut reply, field, value);
        let error = refused_exchange(201, json_bytes(&reply)).await;
        assert_eq!(error, MintError::ScopeMismatch, "mutated {field}");
    }

    let mut requested = permissions();
    requested.insert("metadata".into(), "read".into());
    let mut reply = narrowed_reply();
    reply["permissions"] = json!({"issues": "read"});
    let http = FixtureTransport::new(vec![
        response(200, INSTALLATIONS),
        response(201, json_bytes(&reply)),
    ]);
    assert_eq!(
        mint_narrowed_installation_token(
            RECORD_ID,
            &credential(),
            &[REPO.into()],
            &requested,
            &http
        )
        .await
        .unwrap_err(),
        MintError::ScopeMismatch,
    );
    assert_eq!(http.requests().len(), 2);
}

async fn refused_exchange(status: u16, body: impl Into<Vec<u8>>) -> MintError {
    let http = FixtureTransport::new(vec![response(200, INSTALLATIONS), response(status, body)]);
    let error = mint(&http).await.unwrap_err();
    let requests = http.requests();
    assert_eq!(
        requests.len(),
        2,
        "no second or broad exchange after refusal"
    );
    assert_eq!(requests[1].method, "POST");
    assert!(!format!("{error:?}").contains(TOKEN_MARKER));
    error
}

#[tokio::test]
async fn narrowed_exchange_requires_a_nonempty_token_and_unexpired_timestamp() {
    assert_eq!(
        refused_exchange(201, b"not JSON".as_slice()).await,
        MintError::GithubUnavailable
    );
    let reply = narrowed_reply();
    let positional_fields = json!([
        reply["token"],
        reply["expires_at"],
        reply["repositories"],
        reply["permissions"]
    ]);
    assert_eq!(
        refused_exchange(201, json_bytes(&positional_fields)).await,
        MintError::GithubUnavailable,
    );
    for (field, value) in [
        ("token", None),
        ("token", Some(json!(""))),
        ("token", Some(json!(123))),
        ("expires_at", None),
        ("expires_at", Some(json!("not a timestamp"))),
        ("expires_at", Some(json!("2000-01-01T00:00:00Z"))),
    ] {
        let mut reply = narrowed_reply();
        set_field(&mut reply, field, value);
        assert_eq!(
            refused_exchange(201, json_bytes(&reply)).await,
            MintError::GithubUnavailable
        );
    }
}

#[tokio::test]
async fn narrowed_exchange_classifies_status_without_forwarding_provider_body() {
    let body = json_bytes(&json!({"message": format!("suspended; echoed {TOKEN_MARKER}")}));
    assert_eq!(
        refused_exchange(422, body.clone()).await,
        MintError::ScopeUnavailable
    );
    for status in [200, 401, 403, 404, 429, 500, 503] {
        assert_eq!(
            refused_exchange(status, body.clone()).await,
            MintError::GithubUnavailable
        );
    }

    let http = FixtureTransport::ok(422, body);
    assert_eq!(mint(&http).await.unwrap_err(), MintError::GithubUnavailable);
    assert_eq!(
        http.requests().len(),
        1,
        "only exchange 422 proves a scope refusal"
    );
}

#[tokio::test]
async fn narrowed_mint_treats_transport_failures_as_retryable_at_either_stage() {
    for mut responses in [vec![], vec![response(200, INSTALLATIONS)]] {
        let expected_requests = responses.len() + 1;
        responses.push(Err(RefreshError::Transport(TOKEN_MARKER.into())));
        let http = FixtureTransport::new(responses);
        let error = mint(&http).await.unwrap_err();
        assert_eq!(error, MintError::GithubUnavailable);
        assert!(!format!("{error:?}").contains(TOKEN_MARKER));
        assert_eq!(http.requests().len(), expected_requests);
    }
}
