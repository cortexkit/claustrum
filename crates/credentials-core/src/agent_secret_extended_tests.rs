use super::*;
use serde_json::{json, Value};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    let (pairs, tail) = text.as_bytes().as_chunks::<2>();
    assert!(tail.is_empty(), "hex fixtures contain whole bytes");
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn fields(params: &Value) -> Value {
    let mut fields = json!({});
    for key in ["host", "path_prefix", "origin", "rules", "origins"] {
        if let Some(value) = params.get(key) {
            fields[key] = value.clone();
        }
    }
    fields
}

#[test]
fn extended_deposit_vectors_use_real_encoders_without_rewriting_fixtures() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../tests/vectors/multi-host/secret-deposit-v2.json"
    ))
    .unwrap();
    let mut encoded = 0;
    for case in vectors["cases"].as_array().unwrap() {
        if case.get("aad_hex").is_none() {
            continue;
        }
        let p = &case["params"];
        let kind = p["kind"].as_str().unwrap();
        let scope = SecretScope::from_input(kind, &fields(p), p["location"].as_str()).unwrap();
        let aad = deposit_aad(
            p["deposit_id"].as_str().unwrap(),
            p["member_id"].as_str().unwrap(),
            p["name"].as_str().unwrap(),
            &scope,
        )
        .unwrap();
        assert_eq!(json!(hex(&aad)), case["aad_hex"], "{} AAD", case["case"]);
        let m = &case["material"];
        let material = match kind {
            "agent_api_key" => {
                SecretMaterial::ApiKey(Secret::new(unhex(m["api_key_hex"].as_str().unwrap())))
            }
            "site_login" => SecretMaterial::SiteLogin {
                username: Secret::new(m["username"].as_str().unwrap().to_owned()),
                password: Secret::new(m["password"].as_str().unwrap().to_owned()),
                otpauth: m["otpauth"].as_str().map(|uri| Secret::new(uri.to_owned())),
            },
            _ => panic!("unexpected vector kind"),
        };
        assert_eq!(
            json!(hex(deposit_plaintext(&material).expose())),
            case["plaintext_hex"],
            "{} plaintext",
            case["case"]
        );
        assert_eq!(
            json!(hex(sealed_body(&scope, &material).unwrap().expose())),
            case["sealed_body_hex"],
            "{} body",
            case["case"]
        );
        assert_eq!(json!(SECRET_RECORD_VERSION), case["record_version"]);
        if let Some(expected) = case["expect"].get("stored_scope") {
            assert_eq!(
                &scope.canonicalized().unwrap().use_fields(),
                expected,
                "{} stored scope",
                case["case"]
            );
        }
        encoded += 1;
    }
    assert_eq!(encoded, 13, "every binary encoding vector is exercised");
}

#[test]
fn extended_scope_json_is_canonical_strict_and_uses_stored_grammar() {
    let valid = r#"[{"host":"*.github.io","path_prefix":""}]"#;
    let scope = SecretScope::from_scope_json("agent_api_key", Some("header:X-Key"), valid).unwrap();
    let SecretScope::ApiKeyRules { rules, .. } = &scope else {
        panic!("extended rule scope");
    };
    assert_eq!(rules[0].path_prefix, None);
    assert_eq!(scope.scope_json().unwrap().as_deref(), Some(valid));
    assert!(
        validate_scope(&scope).is_err(),
        "only the input parser applies the PSL"
    );
    assert!(UseTarget::ApiKey {
        scheme: "https".into(),
        host: "a.github.io".into(),
        port: 443,
        path: "/".into()
    }
    .matches(&scope));
    let invalid = [
        "not json".to_owned(),
        "[]".to_owned(),
        r#"[{"host":"*.x.test"}]"#.to_owned(),
        r#"[ {"host":"*.x.test","path_prefix":""}]"#.to_owned(),
        r#"[{"path_prefix":"","host":"*.x.test"}]"#.to_owned(),
        r#"[{"host":"x.test","path_prefix":""}]"#.to_owned(),
        r#"[{"host":"*.x.test","path_prefix":""},{"host":"*.x.test","path_prefix":""}]"#.to_owned(),
        r#"[{"host":"z.test","path_prefix":""},{"host":"a.test","path_prefix":""}]"#.to_owned(),
        r#"[{"host":"*.x.test","host":"*.x.test","path_prefix":""}]"#.to_owned(),
        serde_json::to_string(
            &(0..9)
                .map(|i| json!({"host":format!("h{i}.test"),"path_prefix":""}))
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    ];
    for raw in invalid {
        assert!(
            SecretScope::from_scope_json("agent_api_key", Some("header:X-Key"), &raw).is_err(),
            "{raw}"
        );
    }
    for raw in [
        json!(["https://x.test"]),
        json!(["https://x.test", "https://x.test:443"]),
        json!([
            "https://a.test",
            "https://b.test",
            "https://c.test",
            "https://d.test",
            "https://e.test"
        ]),
    ] {
        assert!(SecretScope::from_scope_json("site_login", None, &raw.to_string()).is_err());
    }
    for (kind, array, location) in [
        (
            "agent_api_key",
            json!((0..8)
                .map(|i| json!({"host":format!("h{i}.test"), "path_prefix":""}))
                .collect::<Vec<_>>()),
            Some("header:X-Key"),
        ),
        (
            "site_login",
            json!([
                "https://a.test",
                "https://b.test",
                "https://c.test",
                "https://d.test"
            ]),
            None,
        ),
    ] {
        let raw = array.to_string();
        assert_eq!(
            SecretScope::from_scope_json(kind, location, &raw)
                .unwrap()
                .scope_json()
                .unwrap()
                .as_deref(),
            Some(raw.as_str())
        );
    }
    assert!(SecretScope::from_input(
        "agent_api_key",
        &json!({"rules":[{"host":"*.x.test","path_prefix":""}]}),
        Some("header:X-Key")
    )
    .is_err());
}

#[test]
fn extended_and_legacy_rows_require_their_own_body_versions() {
    let key = MasterKey::from_bytes([12; 32]);
    let incarnation = "0123456789abcdef0123456789abcdef";
    for (legacy, extended, material) in [
        (
            SecretScope::ApiKey {
                host: "x.test".into(),
                path_prefix: None,
                location: "header:X-Key".into(),
            },
            SecretScope::from_input(
                "agent_api_key",
                &json!({"rules":[{"host":"*.x.test"}]}),
                Some("header:X-Key"),
            )
            .unwrap(),
            SecretMaterial::ApiKey(Secret::new(b"test-key".to_vec())),
        ),
        (
            SecretScope::SiteLogin {
                origin: "https://x.test".into(),
            },
            SecretScope::from_input(
                "site_login",
                &json!({"origins":["https://x.test","https://y.test"]}),
                None,
            )
            .unwrap(),
            SecretMaterial::SiteLogin {
                username: Secret::new("user".into()),
                password: Secret::new("test-password".into()),
                otpauth: None,
            },
        ),
    ] {
        for (scope, wrong_tag) in [(&legacy, SEALED_BODY_V2_TAG), (&extended, SEALED_BODY_TAG)] {
            let body = sealed_body(scope, &material).unwrap();
            let mut mismatched = body.expose().clone();
            // Change only the version tag, leaving every scope/material frame untouched.
            let mut tag = Vec::new();
            push_field(&mut tag, wrong_tag);
            mismatched[..tag.len()].copy_from_slice(&tag);
            let id = record_binding(scope.kind(), incarnation, "key").unwrap();
            let blob = envelope::seal(
                &key,
                &mismatched,
                &RecordBinding {
                    credential_id: &id,
                    record_version: SECRET_RECORD_VERSION,
                },
            )
            .unwrap();
            assert!(open(&key, incarnation, "key", scope, &blob).is_err());
            let blob = seal(&key, incarnation, "key", scope, &material).unwrap();
            assert_eq!(
                open(&key, incarnation, "key", scope, &blob).unwrap(),
                material
            );
        }
    }
}

#[test]
fn extended_v3_statement_vectors_use_real_builders_and_pin_jcs_and_digest() {
    const REQUEST: &str = "01HF7YAT000000000000000001";
    const HOME: &str = "fed-computer:22222222222222222222222222222222";
    const INCARNATION: &str = "00000000000000000000000000000149";
    const OTHER: &str = "fed-computer:33333333333333333333333333333333";
    const EXPIRY: i64 = 1_700_000_600_000;
    assert_eq!(USE_STATEMENT_V3_TAG, USE_STATEMENT_V3.as_bytes());
    assert_eq!(FLOW_STATEMENT_V3_TAG, FLOW_STATEMENT_V3.as_bytes());
    let mut statements = 0;
    let mut refusals = 0;
    for (flow_case, corpus) in [
        (
            false,
            include_str!("../tests/vectors/multi-host/secret-approval-v3.json"),
        ),
        (
            true,
            include_str!("../tests/vectors/multi-host/secret-flow-approval-v3.json"),
        ),
    ] {
        let corpus: Value = serde_json::from_str(corpus).unwrap();
        for case in corpus["cases"].as_array().unwrap() {
            let setup = &case["setup"];
            let kind = setup["kind"].as_str().unwrap();
            let stored = &setup["stored_scope"];
            let array = if kind == "agent_api_key" {
                &stored["rules"]
            } else {
                &stored["origins"]
            };
            let scope =
                SecretScope::from_scope_json(kind, stored["location"].as_str(), &array.to_string())
                    .unwrap();
            let name = if kind == "agent_api_key" {
                "key"
            } else {
                "login"
            };
            let asker = setup["pending_asking_member_id"]
                .as_str()
                .or_else(|| setup["asking_member_id"].as_str())
                .unwrap();
            let flow = FlowIdentity {
                flow_id: case["params"]["flow"]["flow_id"]
                    .as_str()
                    .unwrap_or("daily-fetch")
                    .to_owned(),
                version: 7,
                code_hash: "0123456789abcdef".repeat(4),
                install_id: "install-A".into(),
            };
            let mut statement = if flow_case {
                let result = flow_approval_statement_for_asker(
                    REQUEST,
                    HOME,
                    INCARNATION,
                    name,
                    &flow,
                    &scope,
                    (kind == "agent_api_key").then_some(["POST".into(), "GET".into()].as_slice()),
                    EXPIRY,
                    asker,
                );
                if case.get("statement").is_none() {
                    assert_eq!(
                        result.unwrap_err(),
                        ValidationError::InvalidParams,
                        "{}",
                        case["case"]
                    );
                    refusals += 1;
                    continue;
                }
                result.unwrap()
            } else {
                let call = SecretUse {
                    name: name.into(),
                    sender: SecretSender::Basal,
                    scope: AskingScope {
                        owner: "reserved:prefrontal-core".into(),
                        kind: "head".into(),
                        scope_ref: "H".into(),
                        epoch: 7,
                    },
                    worker_parent: None,
                    coverage: "scope".into(),
                    agent_id: Some("agent-A".into()),
                    target: UseTarget::SiteLogin {
                        origin: "https://x.test".into(),
                    },
                };
                approval_statement_for_asker(
                    REQUEST,
                    HOME,
                    INCARNATION,
                    &call,
                    &scope,
                    EXPIRY,
                    asker,
                )
            };
            // The refusal fixtures submit an otherwise valid statement with a changed
            // asker; reconstruct that candidate without using its expected object.
            match case["case"].as_str().unwrap() {
                "asker-added" | "asker-different" => statement["asking_member_id"] = json!(OTHER),
                "asker-missing" => {
                    statement
                        .as_object_mut()
                        .unwrap()
                        .remove("asking_member_id");
                }
                _ => {}
            }
            assert_eq!(statement, case["statement"], "{} object", case["case"]);
            let jcs = serde_json::to_vec(&statement).unwrap();
            assert_eq!(
                jcs,
                unhex(case["statement_jcs_hex"].as_str().unwrap()),
                "{} JCS",
                case["case"]
            );
            assert_eq!(
                json!(hex(&Sha256::digest(&jcs))),
                case["statement_sha256"],
                "{} digest",
                case["case"]
            );
            statements += 1;
        }
    }
    assert_eq!(statements, 22);
    assert_eq!(refusals, 4);
}
