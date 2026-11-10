use super::*;

#[test]
fn provider_catalog_client_decodes_real_new_rows_and_old_or_null_metadata() {
    let reply = producer_vector_reply("list-scoped-v2.json", "catalog_and_lifecycle");
    let listing = decode_list_scoped_reply(reply.clone()).unwrap();
    assert!(listing.undecodable_credentials.is_empty());
    let kimi = listing
        .credentials
        .iter()
        .find(|row| row.id == "apikey:kimi-for-coding")
        .unwrap();
    assert_eq!(kimi.provider.as_deref(), Some("kimi-for-coding"));
    assert_eq!(
        kimi.incarnation.as_deref(),
        Some("00000000000000000000000000000002")
    );
    assert_eq!(kimi.plan_tier_observed_at_ms, Some(1_700_000_000_000));
    for null in [false, true] {
        let mut older = reply.clone();
        for row in older["result"]["credentials"].as_array_mut().unwrap() {
            for field in ["provider", "incarnation", "plan_tier_observed_at_ms"] {
                if null {
                    row[field] = Value::Null;
                } else {
                    row.as_object_mut().unwrap().remove(field);
                }
            }
        }
        let listing = decode_list_scoped_reply(older).unwrap();
        assert_eq!(listing.credentials.len(), 4);
        assert!(listing.credentials.iter().all(|row| row.provider.is_none()
            && row.incarnation.is_none()
            && row.plan_tier_observed_at_ms.is_none()));
    }
    for (field, malformed) in [
        ("provider", json!(1)),
        ("incarnation", json!([])),
        ("plan_tier_observed_at_ms", json!("yesterday")),
    ] {
        let mut broken = reply.clone();
        broken["result"]["credentials"][0][field] = malformed;
        let listing = decode_list_scoped_reply(broken).unwrap();
        assert_eq!(listing.credentials.len(), 3);
        assert_eq!(listing.undecodable_credentials.len(), 1);
        assert!(listing.undecodable_credentials[0].contains(field));
    }
}

fn producer_vector_reply(file: &str, case: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../credentials-module/tests/vectors")
        .join(file);
    let vector: Value = serde_json::from_slice(
        &std::fs::read(path).expect("producer vector must be available in the checkout"),
    )
    .expect("producer vector is JSON");
    vector["cases"]
        .as_array()
        .expect("vector cases")
        .iter()
        .find(|entry| entry["case"] == case)
        .unwrap_or_else(|| panic!("producer vector {file} has no {case}"))["reply"]
        .clone()
}

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
fn provider_catalog_decodes_producer_hosts_and_absence() {
    let reply = producer_vector_reply("list-scoped-v2.json", "descriptor_presence");
    let listing = decode_list_scoped_reply(reply.clone()).unwrap();
    assert!(listing.undecodable_credentials.is_empty());
    assert_eq!(listing.credentials.len(), 3);
    for (decoded, wire) in listing
        .credentials
        .iter()
        .zip(reply["result"]["credentials"].as_array().unwrap())
    {
        assert_eq!(decoded.id, wire["id"].as_str().unwrap());
        assert_eq!(serde_json::to_value(&decoded.hosts).unwrap(), wire["hosts"]);
        assert_eq!(
            decoded.fusiform_provider_id.as_deref(),
            wire.get("fusiform_provider_id").and_then(Value::as_str)
        );
    }
    let openai = listing
        .credentials
        .iter()
        .find(|row| row.id == "apikey:openai")
        .unwrap();
    assert_eq!(openai.hosts, Some(vec!["api.openai.com".into()]));
    let oauth = listing
        .credentials
        .iter()
        .find(|row| row.id == "oauth:anthropic")
        .unwrap();
    assert_eq!(oauth.hosts, None);
    assert_eq!(oauth.fusiform_provider_id, None);
}

#[test]
fn provider_catalog_decodes_fusiform_ids_and_empty_hosts_missing_from_vectors() {
    let mut reply = producer_vector_reply("list-scoped-v2.json", "descriptor_presence");
    // The producer has hosts, but no Fusiform ids or explicitly empty host arrays yet.
    assert!(reply["result"]["credentials"][1]
        .get("fusiform_provider_id")
        .is_none());
    reply["result"]["credentials"][1]["fusiform_provider_id"] = json!("openai");
    assert!(reply["result"]["credentials"][2].get("hosts").is_none());
    reply["result"]["credentials"][2]["hosts"] = json!([]);
    let listing = decode_list_scoped_reply(reply).unwrap();
    assert!(listing.undecodable_credentials.is_empty());
    assert_eq!(
        listing.credentials[1].fusiform_provider_id.as_deref(),
        Some("openai")
    );
    assert_eq!(listing.credentials[2].hosts, Some(vec![]));
}

#[test]
fn provider_catalog_decodes_omitted_and_null_fusiform_ids_and_hosts_as_absent() {
    for null in [false, true] {
        let mut reply = producer_vector_reply("list-scoped-v2.json", "descriptor_presence");
        for row in reply["result"]["credentials"].as_array_mut().unwrap() {
            for field in ["fusiform_provider_id", "hosts"] {
                if null {
                    row[field] = Value::Null;
                } else {
                    row.as_object_mut().unwrap().remove(field);
                }
            }
        }
        let listing = decode_list_scoped_reply(reply).unwrap();
        assert_eq!(listing.credentials.len(), 3);
        assert!(listing.undecodable_credentials.is_empty());
        assert!(listing
            .credentials
            .iter()
            .all(|row| row.fusiform_provider_id.is_none() && row.hosts.is_none()));
    }
}

#[test]
fn provider_catalog_refuses_malformed_fusiform_ids_and_hosts_row_locally() {
    for (field, malformed) in [
        ("fusiform_provider_id", json!(1)),
        ("fusiform_provider_id", json!([])),
        ("hosts", json!("api.openai.com")),
        ("hosts", json!([1])),
        ("hosts", json!([null])),
    ] {
        let mut reply = producer_vector_reply("list-scoped-v2.json", "descriptor_presence");
        reply["result"]["credentials"][0][field] = malformed;
        let listing = decode_list_scoped_reply(reply).unwrap();
        assert_eq!(listing.credentials.len(), 2);
        assert_eq!(listing.undecodable_credentials.len(), 1);
        assert!(listing.undecodable_credentials[0].contains(field));
    }
}

#[test]
fn producer_get_scoped_decodes_real_auth_hosts_and_invalid_key() {
    for case in ["catalog_with_evidence", "catalog_without_evidence"] {
        let reply = producer_vector_reply("get-scoped-v1.json", case);
        let decoded = decode_credential_reply(reply.clone()).unwrap();
        assert_eq!(decoded.expose(), b"vector-test-key");
        assert_eq!(
            decoded.auth,
            Some(AuthDescriptor {
                header: "authorization".into(),
                scheme: AuthScheme::Bearer
            })
        );
        assert_eq!(
            serde_json::to_value(&decoded.hosts).unwrap(),
            reply["result"]["hosts"]
        );
        let expected_evidence = if case == "catalog_with_evidence" {
            assert_eq!(decoded.hosts, Some(vec!["api.openai.com".into()]));
            Some(InvalidKeyEvidence {
                status: 401,
                error_code: Some("invalid_api_key".into()),
                error_code_field: Some("/error/code".into()),
            })
        } else {
            assert_eq!(reply["result"].get("invalid_key"), Some(&Value::Null));
            None
        };
        assert_eq!(decoded.invalid_key, expected_evidence);
    }
    let reply = producer_vector_reply("get-scoped-v1.json", "oauth_without_descriptor");
    for field in ["auth", "hosts", "invalid_key"] {
        assert!(reply["result"].get(field).is_none());
    }
    let decoded = decode_credential_reply(reply).unwrap();
    assert_eq!(decoded.expose(), b"vector-test-key");
    assert_eq!(decoded.auth, None);
    assert_eq!(decoded.hosts, None);
    assert_eq!(decoded.invalid_key, None);
}

#[test]
fn producer_get_scoped_decodes_descriptor_values_missing_from_vectors() {
    // Preserve the catalog descriptors and inject only wire values absent from the vectors.
    let mut reply = producer_vector_reply("get-scoped-v1.json", "oauth_without_descriptor");
    reply["result"]["auth"] = json!({"header": "authorization", "scheme": "raw"});
    let decoded = decode_credential_reply(reply).unwrap();
    assert_eq!(
        decoded.auth,
        Some(AuthDescriptor {
            header: "authorization".into(),
            scheme: AuthScheme::Raw
        })
    );
    for status in [0, 65535] {
        let mut reply = producer_vector_reply("get-scoped-v1.json", "oauth_without_descriptor");
        reply["result"]["hosts"] = json!([]);
        reply["result"]["invalid_key"] =
            json!({"status": status, "error_code": null, "error_code_field": null});
        let decoded = decode_credential_reply(reply).unwrap();
        assert_eq!(decoded.hosts, Some(vec![]));
        assert_eq!(
            decoded.invalid_key,
            Some(InvalidKeyEvidence {
                status,
                error_code: None,
                error_code_field: None
            })
        );
    }
}

#[test]
fn producer_get_scoped_decodes_omitted_and_null_descriptors_as_absent() {
    for null in [false, true] {
        let mut reply = producer_vector_reply("get-scoped-v1.json", "catalog_with_evidence");
        for field in ["auth", "hosts", "invalid_key"] {
            if null {
                reply["result"][field] = Value::Null;
            } else {
                reply["result"].as_object_mut().unwrap().remove(field);
            }
        }
        let decoded = decode_credential_reply(reply).unwrap();
        assert_eq!(decoded.auth, None);
        assert_eq!(decoded.hosts, None);
        assert_eq!(decoded.invalid_key, None);
    }
}

#[test]
fn producer_get_scoped_refuses_malformed_auth_hosts_and_invalid_key() {
    for (field, malformed) in [
        ("auth", json!([])),
        ("auth", json!("bearer")),
        ("auth", json!({})),
        ("auth", json!({"header": 1, "scheme": "raw"})),
        ("auth", json!({"header": "authorization"})),
        (
            "auth",
            json!({"header": "authorization", "scheme": "basic"}),
        ),
        ("auth", json!({"header": "authorization", "scheme": null})),
        ("hosts", json!("api.openai.com")),
        ("hosts", json!([1])),
        ("hosts", json!([null])),
        ("invalid_key", json!([])),
        ("invalid_key", json!("unauthorized")),
        ("invalid_key", json!({})),
        ("invalid_key", json!({"status": "401"})),
        ("invalid_key", json!({"status": 1.5})),
        ("invalid_key", json!({"status": -1})),
        ("invalid_key", json!({"status": 65536})),
        (
            "invalid_key",
            json!({"status": 401, "error_code": 1, "error_code_field": null}),
        ),
        (
            "invalid_key",
            json!({"status": 401, "error_code": null, "error_code_field": []}),
        ),
        (
            "invalid_key",
            json!({"status": 401, "error_code": "invalid_api_key", "error_code_field": null}),
        ),
        (
            "invalid_key",
            json!({"status": 401, "error_code": null, "error_code_field": "/error/code"}),
        ),
    ] {
        let mut reply = producer_vector_reply("get-scoped-v1.json", "catalog_with_evidence");
        reply["result"][field] = malformed;
        let error = decode_credential_reply(reply).unwrap_err();
        assert_eq!(
            error.class,
            CredentialErrorClass::InvalidResponse,
            "{field}"
        );
        assert!(error.to_string().contains(field));
    }
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
                    provider: Some("antigravity".into()),
                    incarnation: Some("0123456789abcdef0123456789abcdef".into()),
                    plan_tier_observed_at_ms: None,
                    fusiform_provider_id: None,
                    hosts: None,
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
                    plan_tier: None,
                    plan_tier_source: None,
                },
                ListedCredential {
                    provider: Some("openrouter".into()),
                    incarnation: Some("0123456789abcdef0123456789abcdef".into()),
                    plan_tier_observed_at_ms: None,
                    fusiform_provider_id: None,
                    hosts: Some(vec!["openrouter.ai".into()]),
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
                        "stepfun",
                        "inception"
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
                    plan_tier: None,
                    plan_tier_source: None,
                },
                ListedCredential {
                    provider: Some("openai".into()),
                    incarnation: Some("0123456789abcdef0123456789abcdef".into()),
                    plan_tier_observed_at_ms: None,
                    fusiform_provider_id: None,
                    hosts: None,
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
                    plan_tier: Some("pro_200".into()),
                    plan_tier_source: Some("detected".into()),
                },
                ListedCredential {
                    provider: None,
                    incarnation: Some("0123456789abcdef0123456789abcdef".into()),
                    plan_tier_observed_at_ms: None,
                    fusiform_provider_id: None,
                    hosts: None,
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
                    plan_tier: None,
                    plan_tier_source: None,
                },
                ListedCredential {
                    provider: Some("anthropic".into()),
                    incarnation: Some("0123456789abcdef0123456789abcdef".into()),
                    plan_tier_observed_at_ms: None,
                    fusiform_provider_id: None,
                    hosts: None,
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
                    plan_tier: Some("max_20x".into()),
                    plan_tier_source: Some("operator".into()),
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
            view: "5nGCY1+bA0OaU3AWJqQzwycYy8es/tHZWUOMc25xrNk=".into(),
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
                provider: Some("anthropic".into()),
                incarnation: Some("0123456789abcdef0123456789abcdef".into()),
                plan_tier_observed_at_ms: None,
                fusiform_provider_id: None,
                hosts: None,
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
                plan_tier: Some("max_5x".into()),
                plan_tier_source: Some("detected".into()),
            }],
            grant_tuples: vec![ListedGrant {
                selector_kind: "category".into(),
                selector: "llm-provider".into(),
                operation: "list".into()
            }],
            view: "Xqi9f8zrVXEj+oY9i33BPScGE8JAedPfEwj5rD/GGpk=".into(),
            undecodable_credentials: vec![],
            undecodable_grants: vec![],
        }
    );
}

#[test]
fn producer_get_replies_decode_without_a_resolver() {
    let operation = producer_operation("credential.get");
    for (reply, (version, expires_at_ms)) in operation["success"]
        .as_array()
        .unwrap()
        .iter()
        .zip([("42", Some(1_900_000_000_000)), ("7", None)])
    {
        let decoded = decode_credential_reply(producer_reply(reply)).unwrap();
        assert_eq!(decoded.expose(), b"fixture-not-a-secret");
        assert_eq!(decoded.record_version, version);
        assert_eq!(decoded.expires_at_ms, expires_at_ms);
        if version == "42" {
            assert_eq!(
                decoded.account_id.as_deref(),
                Some("00000000-0000-4000-8000-000000000000")
            );
            assert_eq!(decoded.email.as_deref(), Some("consumer@example.invalid"));
            assert_eq!(decoded.org_name.as_deref(), Some("Example Org"));
        } else {
            assert_eq!(decoded.account_id, None);
            assert_eq!(decoded.email, None);
            assert_eq!(decoded.org_name, None);
        }
        assert!(!format!("{decoded:?}").contains("fixture-not-a-secret"));
    }
}

#[test]
fn producer_get_scoped_reply_decodes_without_a_resolver() {
    let operation = producer_operation("credential.get_scoped");
    let decoded = decode_credential_reply(producer_reply(&operation["success"][0])).unwrap();
    assert_eq!(decoded.expose(), b"fixture-not-a-secret");
    assert_eq!(decoded.record_version, "1");
    assert_eq!(decoded.expires_at_ms, Some(4_102_444_800_000));
    assert_eq!(decoded.account_id, None);
    assert_eq!(decoded.email, None);
    assert_eq!(decoded.org_name, None);
}

#[cfg(feature = "transport")]
struct ProducerGetTarget(Value);

#[cfg(feature = "transport")]
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

#[cfg(feature = "transport")]
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
            if version == "42" {
                assert_eq!(
                    decoded.account_id.as_deref(),
                    Some("00000000-0000-4000-8000-000000000000")
                );
                assert_eq!(decoded.email.as_deref(), Some("consumer@example.invalid"));
                assert_eq!(decoded.org_name.as_deref(), Some("Example Org"));
                let debug = format!("{decoded:?}");
                assert!(debug.contains("account_id"));
                assert!(!debug.contains("fixture-not-a-secret"));
            } else {
                assert_eq!(decoded.account_id, None);
                assert_eq!(decoded.email, None);
                assert_eq!(decoded.org_name, None);
            }
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
            algorithm: PublicKeyAlgorithm::Ed25519,
            public_key_hex: "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
                .into(),
        }
    );
}

/// The vault serves a KEM key's public half through the same operation, and a sealed
/// message's recipient needs it to open the message. This sample comes from the same
/// synthetic vault KEM key that produced the seal sample.
#[test]
fn producer_read_surface_x25519_public_key_reply_decodes_as_x25519() {
    let operation = producer_operation("credential.public_key");
    assert_eq!(
        producer_reply(&operation["x25519_request"]),
        json!({"credential_id": "kem:wire-fixture"})
    );
    let decoded = decode_public_key_reply(producer_reply(&operation["success"][1])).unwrap();
    assert_eq!(
        decoded,
        CredentialPublicKey {
            key_id: "a0289810032eb417".into(),
            algorithm: PublicKeyAlgorithm::X25519,
            public_key_hex: "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
                .into(),
        }
    );
    // The seal reply names its sending key by this same id, which is how a recipient
    // matches a sealed message to the public key it fetched.
    let seal = producer_reply(&producer_operation("credential.seal")["success"][0]);
    assert_eq!(seal["result"]["key_id"], decoded.key_id.as_str());
}

#[cfg(feature = "transport")]
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
    assert_eq!(decoded.account_id, None);
    assert_eq!(decoded.email, None);
    assert_eq!(decoded.org_name, None);
}

#[test]
fn producer_report_auth_failure_reply_decodes_the_accepted_answer() {
    let operation = producer_operation("credential.report_auth_failure");
    let replies = operation["success"].as_array().unwrap();
    assert_eq!(replies.len(), 1);
    assert!(decode_report_auth_failure_reply(producer_reply(&replies[0])).unwrap());
}

/// The producer's pinned seal request, decoded back into the bytes a caller passes.
fn producer_seal_inputs() -> (String, [u8; 32], Vec<u8>, Vec<u8>, Vec<u8>) {
    let request = producer_reply(&producer_operation("credential.seal")["request"]);
    let field = |name: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(request[name].as_str().unwrap())
            .unwrap()
    };
    (
        request["credential_id"].as_str().unwrap().to_owned(),
        field("recipient_public_key_b64").try_into().unwrap(),
        field("info_b64"),
        field("aad_b64"),
        field("plaintext_b64"),
    )
}

#[test]
fn producer_seal_request_is_what_the_client_sends() {
    let (credential_id, recipient, info, aad, plaintext) = producer_seal_inputs();
    let sent = credential_seal_request(SealRequest {
        credential_id: &credential_id,
        recipient_public_key: &recipient,
        info: &info,
        aad: &aad,
        plaintext: &plaintext,
    });
    assert_eq!(sent["method"], "credential.seal");
    assert_eq!(
        sent["params"],
        producer_reply(&producer_operation("credential.seal")["request"]),
        "the client must send exactly the parameters the producer accepted"
    );
}

#[test]
fn producer_seal_reply_decodes_exact_bytes() {
    let operation = producer_operation("credential.seal");
    let reply = producer_reply(&operation["success"][0]);
    let decoded = decode_seal_reply(reply.clone()).unwrap();
    let raw = |field: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(reply["result"][field].as_str().unwrap())
            .unwrap()
    };
    assert_eq!(decoded.enc, raw("enc_b64"));
    assert_eq!(decoded.enc.len(), 32);
    assert_eq!(decoded.ciphertext, raw("ciphertext_b64"));
    let (_, _, _, _, plaintext) = producer_seal_inputs();
    assert_eq!(
        decoded.ciphertext.len(),
        plaintext.len() + 16,
        "ChaCha20-Poly1305 adds exactly one 16-byte tag"
    );
    assert_eq!(decoded.key_id, "a0289810032eb417");

    // Malformed replies are refused, never decoded into a usable seal.
    for broken in [
        json!({"result": {"enc_b64": "AAAA", "ciphertext_b64": reply["result"]["ciphertext_b64"], "key_id": "a0289810032eb417"}}),
        json!({"result": {"enc_b64": reply["result"]["enc_b64"], "ciphertext_b64": "AAAA", "key_id": "a0289810032eb417"}}),
        json!({"result": {"enc_b64": reply["result"]["enc_b64"], "ciphertext_b64": reply["result"]["ciphertext_b64"], "key_id": "A0289810032EB417"}}),
        json!({"result": {"ciphertext_b64": reply["result"]["ciphertext_b64"], "key_id": "a0289810032eb417"}}),
    ] {
        assert_eq!(
            decode_seal_reply(broken).unwrap_err().class,
            CredentialErrorClass::InvalidResponse
        );
    }
    // A vault refusal is classified like every other operation's, not as a bad reply.
    let refusal = json!({"result": {"error": {"code": "not_found", "class": "permanent"}}});
    let refused = decode_seal_reply(refusal.clone()).unwrap_err();
    assert_ne!(refused.class, CredentialErrorClass::InvalidResponse);
    assert_eq!(
        refused.class,
        decode_signature_reply(refusal).unwrap_err().class
    );
}

#[cfg(feature = "transport")]
struct ProducerSealTarget(Value);

#[cfg(feature = "transport")]
impl CredentialGetTarget for ProducerSealTarget {
    fn credential_get<'a>(
        &'a self,
        _raw_handle: &'a str,
        _min_ttl_ms: Option<u64>,
        _force_refresh: bool,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(async { Err(CredentialResolverError::unavailable()) })
    }

    fn credential_seal<'a>(
        &'a self,
        _request: SealRequest<'a>,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(async { Ok(self.0.clone()) })
    }
}

/// Answers seal with a retryable error the first time and the producer's success reply
/// after that, counting every call.
#[cfg(feature = "transport")]
struct FlakySealTarget {
    success: Value,
    calls: std::sync::atomic::AtomicUsize,
}

#[cfg(feature = "transport")]
impl CredentialGetTarget for FlakySealTarget {
    fn credential_get<'a>(
        &'a self,
        _raw_handle: &'a str,
        _min_ttl_ms: Option<u64>,
        _force_refresh: bool,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(async { Err(CredentialResolverError::unavailable()) })
    }

    fn credential_seal<'a>(
        &'a self,
        _request: SealRequest<'a>,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        let first = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0;
        let success = self.success.clone();
        Box::pin(async move {
            if first {
                Err(CredentialResolverError::new(
                    CredentialErrorClass::Transient,
                    "credential service is temporarily unavailable",
                ))
            } else {
                Ok(success)
            }
        })
    }
}

/// Every seal is a fresh ciphertext with its own audit row, so the caller owns retries.
/// A resolver configured to retry other operations must still try a seal exactly once
/// and hand the retryable error back, even though a second attempt would succeed.
#[cfg(feature = "transport")]
#[tokio::test]
async fn seal_makes_exactly_one_attempt_even_when_retries_are_allowed() {
    let operation = producer_operation("credential.seal");
    let target = Arc::new(FlakySealTarget {
        success: producer_reply(&operation["success"][0]),
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let resolver = ClaustrumCredentialResolver::with_target(target.clone(), 2);
    let (credential_id, recipient, info, aad, plaintext) = producer_seal_inputs();
    let error = resolver
        .seal(SealRequest {
            credential_id: &credential_id,
            recipient_public_key: &recipient,
            info: &info,
            aad: &aad,
            plaintext: &plaintext,
        })
        .await
        .unwrap_err();
    assert!(
        error.retryable(),
        "the caller must see that a retry is allowed"
    );
    assert_eq!(target.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[cfg(feature = "transport")]
#[tokio::test]
async fn producer_seal_reply_decodes_through_the_resolver() {
    let operation = producer_operation("credential.seal");
    let resolver = ClaustrumCredentialResolver::with_target(
        Arc::new(ProducerSealTarget(producer_reply(&operation["success"][0]))),
        0,
    );
    let (credential_id, recipient, info, aad, plaintext) = producer_seal_inputs();
    let sealed = resolver
        .seal(SealRequest {
            credential_id: &credential_id,
            recipient_public_key: &recipient,
            info: &info,
            aad: &aad,
            plaintext: &plaintext,
        })
        .await
        .unwrap();
    assert_eq!(sealed.key_id, "a0289810032eb417");
    assert_eq!(sealed.enc.len(), 32);
}
