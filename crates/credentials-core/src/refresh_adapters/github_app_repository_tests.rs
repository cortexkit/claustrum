use super::*;
use crate::refresh_adapters::{fixture::FixtureTransport, HttpResponse};
use serde_json::{json, Value};

const RECORD_ID: &str = "github_app:plex-alfonso";
const INSTALLATIONS: &[u8] = include_bytes!("../../tests/fixtures/github_app/installations.json");
const ACCESS_TOKENS: &[u8] = include_bytes!("../../tests/fixtures/github_app/access_tokens.json");

fn credential() -> OAuthCredential {
    let installation: Value = serde_json::from_slice(INSTALLATIONS).unwrap();
    OAuthCredential {
        access_token: "previous-token".to_string().into(),
        refresh_token: include_str!("../../tests/fixtures/github_app/test_private_key.pem")
            .to_string()
            .into(),
        expires_at_ms: Some(0),
        token_url: String::new(),
        client_id: Some(installation[0]["client_id"].as_str().unwrap().to_owned()),
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

fn page(total: usize, names: &[&str]) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "total_count": total,
        "repositories": names.iter().map(|name| json!({"full_name": name})).collect::<Vec<_>>()
    }))
    .unwrap()
}

fn transport(pages: Vec<Result<HttpResponse, RefreshError>>) -> FixtureTransport {
    let mut responses = vec![response(200, INSTALLATIONS), response(201, ACCESS_TOKENS)];
    responses.extend(pages);
    FixtureTransport::new(responses)
}

async fn check(http: &FixtureTransport) -> GithubRepositoryCheck {
    check_github_repository(RECORD_ID, &credential(), "CORTEXKIT/CLAUSTRUM", http).await
}

#[tokio::test]
async fn typed_mint_preserves_installation_permissions_not_token_permissions() {
    let http = transport(vec![]);
    let cred = credential();
    let before = serde_json::to_vec(&cred).unwrap();
    let GithubInstallationOutcome::Minted(token) = mint_installation_token(RECORD_ID, &cred, &http)
        .await
        .unwrap()
    else {
        panic!("recorded installation must mint")
    };
    let installation: Value = serde_json::from_slice(INSTALLATIONS).unwrap();
    assert_eq!(
        serde_json::to_value(&token.installation_permissions).unwrap(),
        installation[0]["permissions"]
    );
    assert_eq!(token.installation_permissions["contents"], "read");
    let exchange: Value = serde_json::from_slice(ACCESS_TOKENS).unwrap();
    assert_eq!(
        token.access_token.expose(),
        exchange["token"].as_str().unwrap()
    );
    assert_eq!(serde_json::to_vec(&cred).unwrap(), before);
    assert_eq!(http.requests().len(), 2);

    let mut narrower = exchange;
    narrower["permissions"] = json!({"contents": "write"});
    let http = FixtureTransport::new(vec![
        response(200, INSTALLATIONS),
        response(201, serde_json::to_vec(&narrower).unwrap()),
    ]);
    let GithubInstallationOutcome::Minted(token) = mint_installation_token(RECORD_ID, &cred, &http)
        .await
        .unwrap()
    else {
        panic!("recorded installation must mint")
    };
    assert_eq!(
        serde_json::to_value(token.installation_permissions).unwrap(),
        installation[0]["permissions"]
    );
}

#[tokio::test]
async fn refresh_ignores_absent_malformed_and_unknown_installation_permissions() {
    for permissions in [
        None,
        Some(Value::Null),
        Some(json!([])),
        Some(json!({"contents": 1})),
        Some(json!({"new_scope": "new_level"})),
    ] {
        let mut installation: Value = serde_json::from_slice(INSTALLATIONS).unwrap();
        if let Some(permissions) = permissions {
            installation[0]["permissions"] = permissions;
        } else {
            installation[0]
                .as_object_mut()
                .unwrap()
                .remove("permissions");
        }
        let http = FixtureTransport::new(vec![
            response(200, serde_json::to_vec(&installation).unwrap()),
            response(201, ACCESS_TOKENS),
        ]);
        let tokens = GithubAppAdapter::new()
            .refresh_for_record(RECORD_ID, &credential(), &http)
            .await
            .unwrap();
        let recorded: Value = serde_json::from_slice(ACCESS_TOKENS).unwrap();
        assert_eq!(
            tokens.access_token.expose(),
            recorded["token"].as_str().unwrap()
        );
        assert_eq!(
            serde_json::to_value(tokens.github_app_permissions).unwrap(),
            recorded["permissions"]
        );
        assert_eq!(http.requests().len(), 2);
    }
}

#[tokio::test]
async fn recorded_installation_checks_remain_typed_and_never_exchange_on_refusal() {
    let recorded: Value = serde_json::from_slice(INSTALLATIONS).unwrap();
    let mut several = recorded.clone();
    several.as_array_mut().unwrap().push(recorded[0].clone());
    let mut mismatch = recorded.clone();
    mismatch[0]["app_slug"] = json!("different-app");
    let mut suspended = recorded.clone();
    suspended[0]["suspended_at"] = json!("2026-08-17T09:03:48.000Z");
    for (body, expected) in [
        (json!([]), GithubRepositoryCheck::NotInstalled),
        (several, GithubRepositoryCheck::InstallationUnusable),
        (mismatch, GithubRepositoryCheck::InstallationUnusable),
        (suspended, GithubRepositoryCheck::InstallationUnusable),
    ] {
        let bytes = serde_json::to_vec(&body).unwrap();
        let http = FixtureTransport::new(vec![response(200, bytes.clone())]);
        let observation = mint_installation_token(RECORD_ID, &credential(), &http)
            .await
            .unwrap();
        match (&expected, observation) {
            (
                GithubRepositoryCheck::NotInstalled,
                GithubInstallationOutcome::Check(GithubAppCheck::NotInstalled),
            ) => {}
            (
                GithubRepositoryCheck::InstallationUnusable,
                GithubInstallationOutcome::Check(
                    GithubAppCheck::SeveralInstallations(2) | GithubAppCheck::Mismatch { .. },
                )
                | GithubInstallationOutcome::Suspended,
            ) => {}
            other => panic!("unexpected typed observation: {other:?}"),
        }
        assert_eq!(http.requests().len(), 1);
        let http = FixtureTransport::new(vec![response(200, bytes)]);
        assert_eq!(check(&http).await, expected);
        assert_eq!(http.requests().len(), 1);
    }
}

#[tokio::test]
async fn repository_page_one_refuses_all_and_too_large_before_matching_or_paging() {
    for (selection, total, expected) in [
        ("all", 1, GithubRepositoryCheck::InstallationAll),
        ("all", 1001, GithubRepositoryCheck::InstallationAll),
        (
            "selected",
            1001,
            GithubRepositoryCheck::InstallationTooLarge,
        ),
    ] {
        let mut installation: Value = serde_json::from_slice(INSTALLATIONS).unwrap();
        installation[0]["repository_selection"] = json!(selection);
        let http = FixtureTransport::new(vec![
            response(200, serde_json::to_vec(&installation).unwrap()),
            response(201, ACCESS_TOKENS),
            response(200, page(total, &["CortexKit/claustrum"])),
        ]);
        assert_eq!(check(&http).await, expected);
        assert_eq!(http.requests().len(), 3);
    }
}

#[tokio::test]
async fn repository_count_accepts_1000_and_refuses_1001() {
    let http = transport(vec![response(200, page(1000, &["CortexKit/claustrum"]))]);
    assert!(matches!(
        check(&http).await,
        GithubRepositoryCheck::Found { .. }
    ));
    assert_eq!(http.requests().len(), 3);
    let http = transport(vec![response(200, page(1001, &["CortexKit/claustrum"]))]);
    assert_eq!(
        check(&http).await,
        GithubRepositoryCheck::InstallationTooLarge
    );
    assert_eq!(http.requests().len(), 3);
}

#[tokio::test]
async fn repository_selection_comes_from_installation_and_optional_page_values_must_agree() {
    let mut matching_page: Value =
        serde_json::from_slice(&page(1, &["CortexKit/claustrum"])).unwrap();
    matching_page["repository_selection"] = json!("selected");
    let http = transport(vec![response(
        200,
        serde_json::to_vec(&matching_page).unwrap(),
    )]);
    assert!(matches!(
        check(&http).await,
        GithubRepositoryCheck::Found { .. }
    ));

    for first_page in [true, false] {
        let mut conflicting_page = matching_page.clone();
        conflicting_page["repository_selection"] = json!("all");
        let mut pages = Vec::new();
        if !first_page {
            pages.push(response(200, page(2, &["owner/other"])));
            conflicting_page["total_count"] = json!(2);
        }
        pages.push(response(
            200,
            serde_json::to_vec(&conflicting_page).unwrap(),
        ));
        let http = transport(pages);
        assert_eq!(check(&http).await, GithubRepositoryCheck::GithubUnavailable);
        assert_eq!(http.requests().len(), if first_page { 3 } else { 4 });
    }
    for selection in [Value::Null, json!("unknown")] {
        let mut installation: Value = serde_json::from_slice(INSTALLATIONS).unwrap();
        installation[0]["repository_selection"] = selection;
        let http = FixtureTransport::new(vec![
            response(200, serde_json::to_vec(&installation).unwrap()),
            response(201, ACCESS_TOKENS),
            response(200, page(1, &["CortexKit/claustrum"])),
        ]);
        assert_eq!(check(&http).await, GithubRepositoryCheck::GithubUnavailable);
        assert_eq!(http.requests().len(), 3);
    }
}

#[tokio::test]
async fn repository_match_preserves_full_name_and_uses_ephemeral_bearer_on_each_page() {
    let http = transport(vec![
        response(200, page(3, &["CortexKit/other"])),
        response(200, page(3, &["CortexKit/claustrum"])),
    ]);
    let permissions: Value = serde_json::from_slice(INSTALLATIONS).unwrap();
    assert_eq!(
        check(&http).await,
        GithubRepositoryCheck::Found {
            full_name: "CortexKit/claustrum".into(),
            installation_permissions: serde_json::from_value(permissions[0]["permissions"].clone())
                .unwrap(),
        }
    );
    let token: Value = serde_json::from_slice(ACCESS_TOKENS).unwrap();
    let requests = http.requests();
    assert_eq!(
        requests.len(),
        4,
        "a match stops even before the listing is complete"
    );
    for (index, request) in requests[2..].iter().enumerate() {
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.url,
            format!(
                "https://api.github.com/installation/repositories?per_page=100&page={}",
                index + 1
            )
        );
        assert!(request.headers.contains(&(
            "Authorization".into(),
            format!("Bearer {}", token["token"].as_str().unwrap())
        )));
        assert!(request
            .headers
            .contains(&("User-Agent".into(), "claustrum".into())));
        assert!(request
            .headers
            .contains(&("Accept".into(), "application/vnd.github+json".into())));
        assert!(request
            .headers
            .contains(&("X-GitHub-Api-Version".into(), "2022-11-28".into())));
    }
}

#[tokio::test]
async fn repository_absence_requires_complete_listing_including_zero_repositories() {
    let http = transport(vec![response(200, page(0, &[]))]);
    assert_eq!(check(&http).await, GithubRepositoryCheck::NotInstalled);
    assert_eq!(http.requests().len(), 3);
    let http = transport(vec![
        response(200, page(2, &["owner/one"])),
        response(200, page(2, &["owner/two"])),
    ]);
    assert_eq!(check(&http).await, GithubRepositoryCheck::NotInstalled);
    assert_eq!(http.requests().len(), 4);
}

#[tokio::test]
async fn repository_requests_never_classify_http_error_text() {
    for status in [401, 403, 404, 429, 422, 500, 503] {
        for stage in 0..3 {
            let mut responses = vec![response(200, INSTALLATIONS), response(201, ACCESS_TOKENS)];
            responses.truncate(stage);
            responses.push(response(
                status,
                br#"{"message":"installation suspended; API rate limit exceeded"}"#,
            ));
            let http = FixtureTransport::new(responses);
            assert_eq!(
                check(&http).await,
                GithubRepositoryCheck::GithubUnavailable,
                "stage {stage}, status {status}"
            );
            assert_eq!(http.requests().len(), stage + 1);
        }
    }
}

#[tokio::test]
async fn repository_page_two_failure_is_unavailable_not_absence() {
    let http = transport(vec![
        response(200, page(3, &["owner/one"])),
        response(429, br#"{"message":"rate limited"}"#),
    ]);
    assert_eq!(check(&http).await, GithubRepositoryCheck::GithubUnavailable);
    assert_eq!(http.requests().len(), 4);
}

#[tokio::test]
async fn repository_empty_page_before_total_is_unavailable() {
    for pages in [
        vec![response(200, page(3, &[]))],
        vec![
            response(200, page(3, &["owner/one"])),
            response(200, page(3, &[])),
        ],
    ] {
        let count = pages.len();
        let http = transport(pages);
        assert_eq!(check(&http).await, GithubRepositoryCheck::GithubUnavailable);
        assert_eq!(http.requests().len(), count + 2);
    }
}

#[tokio::test]
async fn repository_changed_total_and_overfull_pages_are_unavailable_even_with_a_match() {
    for pages in [
        vec![
            response(200, page(3, &["owner/one"])),
            response(200, page(2, &["CortexKit/claustrum"])),
        ],
        vec![response(
            200,
            page(1, &["owner/one", "CortexKit/claustrum"]),
        )],
        vec![
            response(200, page(2, &["owner/one"])),
            response(200, page(2, &["owner/two", "CortexKit/claustrum"])),
        ],
    ] {
        let count = pages.len();
        let http = transport(pages);
        assert_eq!(check(&http).await, GithubRepositoryCheck::GithubUnavailable);
        assert_eq!(http.requests().len(), count + 2);
    }
}

#[tokio::test]
async fn repository_paging_accepts_page_10_but_never_requests_page_11() {
    for last_name in ["CortexKit/claustrum", "owner/last"] {
        let mut pages = (1..10)
            .map(|_| response(200, page(10, &["owner/other"])))
            .collect::<Vec<_>>();
        pages.push(response(200, page(10, &[last_name])));
        let http = transport(pages);
        let result = check(&http).await;
        if last_name == "CortexKit/claustrum" {
            assert!(matches!(result, GithubRepositoryCheck::Found { .. }));
        } else {
            assert_eq!(result, GithubRepositoryCheck::NotInstalled);
        }
        assert_eq!(http.requests().len(), 12);
    }
    // Eleven one-entry pages would complete this allowed total. Ten short pages
    // cannot prove absence, and the checker must not issue the eleventh request.
    let pages = (1..=11)
        .map(|_| response(200, page(11, &["owner/other"])))
        .collect();
    let http = transport(pages);
    assert_eq!(check(&http).await, GithubRepositoryCheck::GithubUnavailable);
    assert_eq!(http.requests().len(), 12);
}

#[tokio::test]
async fn repository_transport_timeout_and_decode_failures_at_every_stage_are_unavailable() {
    for stage in 0..4 {
        for failure in [
            Err(RefreshError::Transport("connection reset".into())),
            Err(RefreshError::Transport("request timed out".into())),
            response(if stage == 1 { 201 } else { 200 }, b"undecodable"),
        ] {
            let mut responses = vec![
                response(200, INSTALLATIONS),
                response(201, ACCESS_TOKENS),
                response(200, page(2, &["owner/other"])),
            ];
            responses.truncate(stage);
            responses.push(failure);
            let http = FixtureTransport::new(responses);
            assert_eq!(
                check(&http).await,
                GithubRepositoryCheck::GithubUnavailable,
                "stage {stage}"
            );
            assert_eq!(http.requests().len(), stage + 1);
        }
    }
}

#[tokio::test]
async fn repository_malformed_permissions_or_listing_shape_is_unavailable() {
    for permissions in [
        Value::Null,
        json!({"contents": 1}),
        json!({"contents": "unknown"}),
        json!([]),
    ] {
        let mut installation: Value = serde_json::from_slice(INSTALLATIONS).unwrap();
        installation[0]["permissions"] = permissions;
        let http = FixtureTransport::new(vec![
            response(200, serde_json::to_vec(&installation).unwrap()),
            response(201, ACCESS_TOKENS),
        ]);
        assert_eq!(check(&http).await, GithubRepositoryCheck::GithubUnavailable);
        assert_eq!(http.requests().len(), 2);
    }
    for body in [
        json!({"repository_selection": "unknown", "total_count": 1, "repositories": []}),
        json!({"repository_selection": "selected", "repositories": []}),
        json!({"repository_selection": "selected", "total_count": -1, "repositories": []}),
        json!({"repository_selection": "selected", "total_count": 1, "repositories": [{}]}),
    ] {
        let http = transport(vec![response(200, serde_json::to_vec(&body).unwrap())]);
        assert_eq!(check(&http).await, GithubRepositoryCheck::GithubUnavailable);
        assert_eq!(http.requests().len(), 3);
    }
}

#[tokio::test]
async fn refresh_does_not_classify_discovery_403_as_exchange_suspension() {
    let http = FixtureTransport::new(vec![response(
        403,
        br#"{"message":"installation suspended"}"#,
    )]);
    assert!(matches!(
        GithubAppAdapter::new()
            .refresh_for_record(RECORD_ID, &credential(), &http)
            .await,
        Err(RefreshError::Status(403, _))
    ));
    assert_eq!(http.requests().len(), 1);
}
