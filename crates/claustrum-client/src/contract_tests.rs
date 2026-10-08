use super::*;

fn producer_operation(op: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../credentials-module/tests/fixtures/enrollment_wire_contract.json");
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(path).expect("producer fixture must be available in the checkout"),
    )
    .expect("producer fixture is JSON");
    fixture["operations"]
        .as_array()
        .expect("fixture operations")
        .iter()
        .find(|operation| operation["op"] == op)
        .unwrap_or_else(|| panic!("producer fixture has no {op}"))
        .clone()
}

fn producer_reply(reply: &Value) -> Value {
    serde_json::from_str(reply.as_str().expect("serialized producer reply"))
        .expect("producer reply is JSON")
}

#[test]
fn malformed_grant_tuples_fail_closed_without_discarding_healthy_entries() {
    let valid =
        json!({"selector_kind": "category", "selector": "llm-provider", "operation": "read"});
    for field in ["selector_kind", "selector", "operation"] {
        for invalid in [None, Some(Value::Null), Some(json!(17)), Some(json!(""))] {
            let mut malformed = valid.clone();
            let tuple = malformed.as_object_mut().unwrap();
            if let Some(value) = invalid {
                tuple.insert(field.to_string(), value);
            } else {
                tuple.remove(field);
            }
            let listing = decode_list_scoped_reply(json!({"result": {
                "credentials": [{"id": "oauth:anthropic", "categories": [], "type": "oauth",
                    "serves": [], "state": "active", "record_version": 1, "operations": ["read"]}],
                "grant_tuples": [valid.clone(), malformed, valid.clone()], "view": "v"
            }}))
            .expect("a malformed tuple is local to that tuple");
            let expected = ListedGrant {
                selector_kind: "category".into(),
                selector: "llm-provider".into(),
                operation: "read".into(),
            };
            assert_eq!(
                listing.grant_tuples,
                [expected.clone(), expected],
                "{field}"
            );
            assert_eq!(
                listing.undecodable_grants,
                [format!("grant tuple 1: {field} is not a non-empty string")]
            );
            assert_eq!(listing.credentials.len(), 1);
            assert_eq!(listing.credentials[0].id, "oauth:anthropic");
            assert!(listing.undecodable_credentials.is_empty());
            assert_eq!(listing.view, "v");
        }
    }
}

#[test]
fn producer_list_scoped_reply_decodes_every_metadata_field_and_grant() {
    let operation = producer_operation("credential.list_scoped");
    let listing = decode_list_scoped_reply(producer_reply(&operation["reply"])).unwrap();
    assert_eq!(
        listing,
        ScopedCredentialListing {
            credentials: vec![
                ListedCredential {
                    id: "antigravity:google".into(),
                    categories: vec!["llm-provider".into()],
                    credential_type: "oauth".into(),
                    serves: vec!["google".into(), "anthropic".into(), "openai".into()],
                    provider_ids: vec!["google-antigravity".into()],
                    auth_method: Some("antigravity".into()),
                    refresh_adapter: Some("antigravity".into()),
                    state: "active".into(),
                    record_version: 5,
                    operations: vec!["read".into()],
                    account_id: None,
                    email: None,
                    org_name: None,
                },
                ListedCredential {
                    id: "apikey:openrouter".into(),
                    categories: vec!["llm-provider".into()],
                    credential_type: "apikey".into(),
                    serves: [
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
                    .into_iter()
                    .map(String::from)
                    .collect(),
                    provider_ids: vec!["openrouter".into()],
                    auth_method: Some("apikey".into()),
                    refresh_adapter: None,
                    state: "active".into(),
                    record_version: 3,
                    operations: vec!["read".into()],
                    account_id: None,
                    email: None,
                    org_name: None,
                },
                ListedCredential {
                    id: "chatgpt:openai".into(),
                    categories: vec!["llm-provider".into()],
                    credential_type: "oauth".into(),
                    serves: vec!["openai".into()],
                    provider_ids: vec![],
                    auth_method: Some("chatgpt".into()),
                    refresh_adapter: Some("openai".into()),
                    state: "active".into(),
                    record_version: 11,
                    operations: vec!["read".into()],
                    account_id: None,
                    email: None,
                    org_name: None,
                },
                ListedCredential {
                    id: "github_app:plex-alfonso".into(),
                    categories: vec!["github-app-native".into()],
                    credential_type: "github_app".into(),
                    serves: vec![],
                    provider_ids: vec![],
                    auth_method: None,
                    refresh_adapter: Some("github_app".into()),
                    state: "active".into(),
                    record_version: 2,
                    operations: vec!["read".into()],
                    account_id: None,
                    email: None,
                    org_name: None,
                },
                ListedCredential {
                    id: "oauth:anthropic".into(),
                    categories: vec!["anthropic-native".into(), "llm-provider".into()],
                    credential_type: "oauth".into(),
                    serves: vec!["anthropic".into()],
                    provider_ids: vec!["anthropic".into(), "claude-code".into()],
                    auth_method: Some("oauth".into()),
                    refresh_adapter: Some("anthropic".into()),
                    state: "active".into(),
                    record_version: 232,
                    operations: vec!["read".into()],
                    account_id: Some("00000000-0000-4000-8000-000000000000".into()),
                    email: Some("consumer@example.invalid".into()),
                    org_name: Some("Example Org".into()),
                },
            ],
            grant_tuples: vec![
                ListedGrant {
                    selector_kind: "category".into(),
                    selector: "llm-provider".into(),
                    operation: "read".into()
                },
                ListedGrant {
                    selector_kind: "category".into(),
                    selector: "github-app-native".into(),
                    operation: "read".into()
                },
            ],
            view: "IwusRgF84sqN4878AwhqRl7XAHzhBMJibYwwWIlMGDo=".into(),
            undecodable_credentials: vec![],
            undecodable_grants: vec![],
        }
    );
}

#[test]
fn producer_list_only_reply_preserves_list_operation_and_identity() {
    let operation = producer_operation("credential.list_scoped");
    let listing = decode_list_scoped_reply(producer_reply(&operation["list_only_reply"])).unwrap();
    assert_eq!(
        listing,
        ScopedCredentialListing {
            credentials: vec![ListedCredential {
                id: "oauth:anthropic".into(),
                categories: vec!["llm-provider".into()],
                credential_type: "oauth".into(),
                serves: vec!["anthropic".into()],
                provider_ids: vec!["anthropic".into()],
                auth_method: Some("oauth".into()),
                refresh_adapter: Some("anthropic".into()),
                state: "active".into(),
                record_version: 232,
                operations: vec!["list".into()],
                account_id: Some("00000000-0000-4000-8000-000000000000".into()),
                email: Some("consumer@example.invalid".into()),
                org_name: Some("Example Org".into()),
            }],
            grant_tuples: vec![ListedGrant {
                selector_kind: "category".into(),
                selector: "llm-provider".into(),
                operation: "list".into()
            }],
            view: "Oj5KK0yt7FvfNQByawwRHX8Omd0BYj6GEu2L1haq4AA=".into(),
            undecodable_credentials: vec![],
            undecodable_grants: vec![],
        }
    );
}

struct ProducerGetTarget(Value);

impl CredentialGetTarget for ProducerGetTarget {
    fn credential_get<'a>(
        &'a self,
        _raw_handle: &'a str,
        _min_ttl_ms: Option<u64>,
        _force_refresh: bool,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(async { Ok(self.0.clone()) })
    }

    fn credential_get_scoped<'a>(
        &'a self,
        _credential_id: &'a str,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(async { Ok(self.0.clone()) })
    }
}

#[tokio::test]
async fn producer_get_result_bytes_decode_through_handle_and_scoped_reads() {
    // read_surface.rs serializes both get and get_scoped as GetOutcome::Ok(GetResult).
    // The shared producer type makes these present/absent optional-field cases valid
    // for both client decoder paths. A dedicated real get_scoped reply is pinned below.
    let operation = producer_operation("credential.get");
    let replies = operation["success"].as_array().unwrap();
    assert_eq!(replies.len(), 2);
    for (reply, (version, expires_at_ms)) in replies
        .iter()
        .zip([("42", Some(1_900_000_000_000)), ("7", None)])
    {
        let resolver = ClaustrumCredentialResolver::with_target(
            Arc::new(ProducerGetTarget(producer_reply(reply))),
            0,
        );
        for decoded in [
            resolver.resolve("ckh_fixture", None, false).await.unwrap(),
            resolver.get_scoped("oauth:example").await.unwrap(),
        ] {
            assert_eq!(decoded.expose(), b"fixture-not-a-secret");
            assert_eq!(decoded.record_version, version);
            assert_eq!(decoded.expires_at_ms, expires_at_ms);
        }
    }
}

#[test]
fn producer_status_replies_decode_resolved_and_unresolved_handles() {
    let operation = producer_operation("credential.status");
    let replies = operation["success"].as_array().unwrap();
    assert_eq!(replies.len(), 2);
    assert_eq!(
        decode_credential_status_reply(producer_reply(&replies[0])).unwrap(),
        CredentialStatus {
            ready: true,
            record_version: Some("1".into()),
            stale_pending: false,
            last_error_code: None,
        }
    );
    assert_eq!(
        decode_credential_status_reply(producer_reply(&replies[1])).unwrap(),
        CredentialStatus {
            ready: false,
            record_version: None,
            stale_pending: false,
            last_error_code: Some("not_found".into()),
        }
    );
}

fn fixture_hex_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("fixture hex"))
        .collect()
}

#[test]
fn producer_read_surface_sign_reply_decodes_and_verifies_ed25519() {
    let sign = producer_operation("credential.sign");
    let decoded = decode_signature_reply(producer_reply(&sign["success"][0])).unwrap();
    assert_eq!(decoded.key_id, "56475aa75463474c");
    assert_eq!(
        decoded.signature_hex,
        "8ff89352b18d737f7e06040db6e5d2b4f40782bbb3b31babed28aafdf9441b381\
         f8c221b23456cd32d53a636f27022977d8d302e6d8c97fd87764f53b0f3f302"
    );

    // Use the producer's public bytes directly here so a public-key decoder defect
    // fails its own test, independently of this signature decoder and crypto check.
    let public = producer_operation("credential.public_key");
    let reply = producer_reply(&public["success"][0]);
    let public_bytes = fixture_hex_bytes(reply["result"]["public_key_hex"].as_str().unwrap());
    let request = producer_reply(&sign["request"]);
    let message = base64::engine::general_purpose::STANDARD
        .decode(request["payload_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(message, b"fixture-ed25519-message");
    let signature = fixture_hex_bytes(&decoded.signature_hex);
    let verifier = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_bytes);
    verifier
        .verify(&message, &signature)
        .expect("valid Ed25519 signature over exact input bytes");
    assert!(verifier.verify(b"different-message", &signature).is_err());
}

#[test]
fn producer_read_surface_public_key_reply_decodes_exact_metadata() {
    let operation = producer_operation("credential.public_key");
    assert_eq!(
        decode_public_key_reply(producer_reply(&operation["success"][0])).unwrap(),
        CredentialPublicKey {
            key_id: "56475aa75463474c".into(),
            algorithm: "ed25519".into(),
            public_key_hex: "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
                .into(),
        }
    );
}

#[tokio::test]
async fn producer_read_surface_get_scoped_reply_decodes_served_material() {
    let operation = producer_operation("credential.get_scoped");
    let resolver = ClaustrumCredentialResolver::with_target(
        Arc::new(ProducerGetTarget(producer_reply(&operation["success"][0]))),
        0,
    );
    let decoded = resolver.get_scoped("oauth:anthropic").await.unwrap();
    assert_eq!(decoded.expose(), b"fixture-not-a-secret");
    assert_eq!(decoded.record_version, "1");
    assert_eq!(decoded.expires_at_ms, Some(4_102_444_800_000));
}
