use super::*;

fn one_leg() -> BrokerActionStatement {
    BrokerActionStatement {
        request_id: "01HF7YAT000000000000000001".into(),
        agent_id: "agent-alf".into(),
        scope: BrokerActionScope {
            owner: "reserved:aft".into(),
            kind: "head".into(),
            scope_ref: "sample-head".into(),
            epoch: 7,
        },
        service: "github".into(),
        identity: "github_app:example-garden".into(),
        action: "close_issue".into(),
        host: "api.github.example".into(),
        resource: "example-garden/demo-notes".into(),
        policy_version: 7,
        policy_sha256: "01".repeat(32),
        fields: vec![BrokerActionField {
            name: "Issue".into(),
            value: FieldValue::Integer(7),
        }],
        shape: BrokerActionShape::OneLeg {
            kind: "close_issue".into(),
            method: "PATCH".into(),
            request_sha256: "02".repeat(32),
        },
        context: None,
        expires_at_ms: 1_800_000_600_000,
    }
}

fn raw_statement() -> Value {
    serde_json::from_slice(one_leg().encode().unwrap().bytes()).unwrap()
}

fn check_raw(value: Value) -> Result<CheckedStatement, StatementError> {
    check_statement(&BASE64_URL_SAFE_NO_PAD.encode(canonical_bytes(value).unwrap()))
}

#[test]
fn broker_action_statement_accepts_524288_decoded_bytes_and_refuses_524289() {
    let mut statement = one_leg();
    statement.fields[0].value = FieldValue::String(String::new());
    let overhead = statement.encode().unwrap().bytes().len();
    let at_limit = "x".repeat(524_288 - overhead);
    statement.fields[0].value = FieldValue::String(at_limit.clone());
    let checked = statement.encode().unwrap();
    assert_eq!(checked.bytes().len(), 524_288);
    assert_eq!(
        check_statement(checked.b64url()).unwrap().bytes().len(),
        524_288
    );

    let mut above_limit = at_limit;
    above_limit.push('x');
    let mut raw = raw_statement();
    raw["fields"][0]["value"] = json!(above_limit);
    let bytes = canonical_bytes(raw).unwrap();
    assert_eq!(bytes.len(), 524_289);
    assert_eq!(
        check_statement(&BASE64_URL_SAFE_NO_PAD.encode(bytes))
            .unwrap_err()
            .member(),
        ENCODING
    );
    statement.fields[0].value = FieldValue::String(above_limit);
    assert_eq!(statement.encode().unwrap_err().member(), ENCODING);
}

#[test]
fn broker_action_statement_accepts_16_fields_in_order_and_refuses_17() {
    let mut statement = one_leg();
    statement.fields = (0..16)
        .rev()
        .map(|n| BrokerActionField {
            name: format!("Field {n}"),
            value: FieldValue::Integer(n),
        })
        .collect();
    let checked = statement.encode().unwrap();
    let value: Value = serde_json::from_slice(checked.bytes()).unwrap();
    let labels: Vec<_> = value["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        labels,
        (0..16)
            .rev()
            .map(|n| format!("Field {n}"))
            .collect::<Vec<_>>()
    );
    statement.fields.push(statement.fields[0].clone());
    assert_eq!(statement.encode().unwrap_err().member(), "fields");
}

#[test]
fn broker_action_statement_accepts_1_and_16_legs_but_refuses_0_and_17() {
    let mut statement = one_leg();
    let leg = BrokerActionLeg {
        kind: "close_issue".into(),
        method: "PATCH".into(),
        resource: statement.resource.clone(),
        request_sha256: "02".repeat(32),
    };
    for count in [1, 16] {
        statement.shape = BrokerActionShape::Legs(vec![leg.clone(); count]);
        let checked = statement.encode().unwrap();
        let value: Value = serde_json::from_slice(checked.bytes()).unwrap();
        assert_eq!(value["legs"].as_array().unwrap().len(), count);
        for key in ["kind", "method", "request_sha256"] {
            assert!(value.get(key).is_none());
            let mut mixed = value.clone();
            mixed[key] = Value::Null;
            assert_eq!(check_raw(mixed).unwrap_err().member(), key);
        }
    }
    for count in [0, 17] {
        statement.shape = BrokerActionShape::Legs(vec![leg.clone(); count]);
        assert_eq!(statement.encode().unwrap_err().member(), "legs");
    }
}

#[test]
fn broker_action_statement_context_accepts_200_characters_and_refuses_201() {
    let mut statement = one_leg();
    statement.context = Some("🐙".repeat(200));
    assert!(statement.encode().is_ok());
    statement.context = Some("🐙".repeat(201));
    assert_eq!(statement.encode().unwrap_err().member(), "context");
}

#[test]
fn broker_action_statement_context_refuses_cc_cf_zl_zp_and_empty() {
    let mut statement = one_leg();
    for c in ['\u{85}', '\u{202e}', '\u{e007f}', '\u{2028}', '\u{2029}'] {
        statement.context = Some(format!("one{c}two"));
        assert_eq!(statement.encode().unwrap_err().member(), "context");
    }
    statement.context = Some(String::new());
    assert_eq!(statement.encode().unwrap_err().member(), "context");
    let mut value = raw_statement();
    value["context"] = Value::Null;
    assert_eq!(check_raw(value).unwrap_err().member(), "context");
}

#[test]
fn broker_action_statement_nested_field_value_is_jcs_and_keeps_all_json_types() {
    let mut statement = one_leg();
    // UTF-16 order puts the supplementary-plane key before the BMP key.
    let value = json!({"\u{e000}": true, "🐙": [null, false, "  exact\ntext  ", -9_007_199_254_740_991i64, 9_007_199_254_740_991i64]});
    statement.fields[0].value = FieldValue::try_from(value).unwrap();
    let checked = statement.encode().unwrap();
    let json = std::str::from_utf8(checked.bytes()).unwrap();
    assert!(json.contains("\"value\":{\"🐙\":[null,false,\"  exact\\ntext  \",-9007199254740991,9007199254740991],\"\u{e000}\":true}"));
    let decoded = check_statement(checked.b64url()).unwrap();
    assert!(decoded.statement() == &statement);
    assert!(decoded.statement().encode().unwrap().bytes() == checked.bytes());
}

#[test]
fn broker_action_statement_refuses_unsafe_integers_and_any_float() {
    let mut raw = raw_statement();
    for number in [
        json!(-9_007_199_254_740_992i64),
        json!(9_007_199_254_740_992u64),
        json!(7.0),
        json!(7.5),
    ] {
        raw["fields"][0]["value"] = json!([{"number": number}]);
        assert_eq!(check_raw(raw.clone()).unwrap_err().member(), "fields.value");
    }
    let mut statement = one_leg();
    statement.fields[0].value = FieldValue::Array(vec![FieldValue::Integer(i64::MAX)]);
    assert_eq!(statement.encode().unwrap_err().member(), "fields.value");
    let mut statement = one_leg();
    statement.scope.epoch = 9_007_199_254_740_991;
    statement.policy_version = 9_007_199_254_740_991;
    statement.expires_at_ms = 9_007_199_254_740_991;
    assert!(statement.encode().is_ok());
    statement.scope.epoch += 1;
    assert_eq!(statement.encode().unwrap_err().member(), "scope.epoch");
    statement.scope.epoch -= 1;
    statement.policy_version += 1;
    assert_eq!(statement.encode().unwrap_err().member(), "policy_version");
    statement.policy_version -= 1;
    statement.expires_at_ms += 1;
    assert_eq!(statement.encode().unwrap_err().member(), "expires_at_ms");
}

#[test]
fn broker_action_statement_refuses_wrong_scalar_shapes_and_unknown_keys() {
    let valid = raw_statement();
    for (pointer, value, member) in [
        ("/v", json!("ck-broker-action-statement/v2"), "v"),
        (
            "/request_id",
            json!("81HF7YAT000000000000000001"),
            "request_id",
        ),
        (
            "/request_id",
            json!("01hf7yat000000000000000001"),
            "request_id",
        ),
        ("/agent_id", json!(""), "agent_id"),
        ("/action", json!(""), "action"),
        ("/kind", json!("comment"), "kind"),
        ("/method", json!("Patch"), "method"),
        ("/method", json!("PATCH2"), "method"),
        ("/request_sha256", json!("ab".repeat(31)), "request_sha256"),
        ("/policy_sha256", json!("AB".repeat(32)), "policy_sha256"),
        ("/service", json!("gitlab"), "service"),
        ("/identity", json!("github_app:UPPER"), "identity"),
        ("/resource", json!("owner/repo/other"), "resource"),
        ("/scope/kind", json!("other"), "scope.kind"),
        ("/scope/owner", json!("reserved:"), "scope.owner"),
        ("/scope/ref", json!(7), "scope.ref"),
        ("/scope/epoch", json!(-1), "scope.epoch"),
        ("/fields/0/name", json!(null), "fields.name"),
    ] {
        let mut raw = valid.clone();
        *raw.pointer_mut(pointer).unwrap() = value;
        assert_eq!(check_raw(raw).unwrap_err().member(), member);
    }
    let mut raw = valid.clone();
    raw["scope"]["unexpected"] = json!(null);
    assert_eq!(check_raw(raw).unwrap_err().member(), "scope");
    let mut raw = valid.clone();
    raw["fields"][0]["unexpected"] = json!(null);
    assert_eq!(check_raw(raw).unwrap_err().member(), "fields");
    let mut raw = valid.clone();
    raw["fields"][0].as_object_mut().unwrap().remove("value");
    assert_eq!(check_raw(raw).unwrap_err().member(), "fields.value");
    let mut raw = valid;
    raw["fields"] = json!([]);
    assert!(check_raw(raw).is_ok());
}

#[test]
fn broker_action_statement_host_accepts_only_canonical_nondefault_ports() {
    let mut statement = one_leg();
    let host = statement.host.clone();
    for port in ["1", "65535"] {
        statement.host = format!("{host}:{port}");
        assert!(statement.encode().is_ok());
    }
    for port in ["", "0", "01", "443", "65536", "+444", "4:45"] {
        statement.host = format!("{host}:{port}");
        assert_eq!(statement.encode().unwrap_err().member(), "host");
    }
    statement.host = host.to_ascii_uppercase();
    assert_eq!(statement.encode().unwrap_err().member(), "host");
}

#[test]
fn broker_action_statement_refuses_duplicate_keys_and_noncanonical_encoding() {
    let checked = one_leg().encode().unwrap();
    let json = std::str::from_utf8(checked.bytes()).unwrap();
    let duplicate = format!("{{\"action\":\"duplicate\",{}", &json[1..]);
    for bytes in [duplicate.as_bytes(), format!(" {json}").as_bytes()] {
        assert_eq!(
            check_statement(&BASE64_URL_SAFE_NO_PAD.encode(bytes))
                .unwrap_err()
                .member(),
            ENCODING
        );
    }
    for b64 in [
        format!("{}=", checked.b64url()),
        format!("{}\n", checked.b64url()),
    ] {
        assert_eq!(check_statement(&b64).unwrap_err().member(), ENCODING);
    }
}

#[test]
fn broker_action_statement_debug_and_errors_do_not_expose_payloads() {
    let mut statement = one_leg();
    statement.context = Some("context-canary".into());
    statement.fields[0].value = FieldValue::String("value-canary".into());
    let checked = statement.encode().unwrap();
    for debug in [
        format!("{checked:?}"),
        format!("{:?}", checked.statement()),
        format!("{:?}", statement.fields[0].value),
    ] {
        assert!(!debug.contains("context-canary"));
        assert!(!debug.contains("value-canary"));
        assert!(!debug.contains(checked.b64url()));
    }
    let mut raw: Value = serde_json::from_slice(checked.bytes()).unwrap();
    raw["key-canary"] = json!("unknown-value-canary");
    let error = check_raw(raw).unwrap_err();
    assert_eq!(error.member(), "key-canary");
    for text in [format!("{error:?}"), error.to_string()] {
        assert!(!text.contains("canary"));
    }
}
