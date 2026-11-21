//! Verify the vault's statement codec against the pinned Cingulate handler samples.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use credentials_core::broker_action::check_statement;
use serde_json::Value;
use sha2::{Digest, Sha256};

const SUMS: &str = include_str!("vectors/broker-action-v1/SHA256SUMS");
const CASES: &[u8] = include_bytes!("vectors/broker-action-v1/cases.json");
const DEVELOPMENT: &[u8] = include_bytes!("vectors/broker-action-v1/development.json");

#[test]
fn broker_action_cingulate_checksums_match() {
    // Both files are compile-time inputs, so absence is also a build failure.
    let expected = format!(
        "{:x}  cases.json\n{:x}  development.json\n",
        Sha256::digest(CASES),
        Sha256::digest(DEVELOPMENT),
    );
    assert_eq!(SUMS, expected);
}

#[test]
fn broker_action_cingulate_statement_cases_agree() {
    let cases: Value = serde_json::from_slice(CASES).unwrap();
    let development: Value = serde_json::from_slice(DEVELOPMENT).unwrap();
    let cases = cases["cases"].as_object().unwrap();
    let mut accepted = 0;
    let mut refused = 0;
    for (name, case) in cases.iter().chain(development.as_object().unwrap()) {
        let mut statements = Vec::new();
        find_statements(case, &mut statements);
        if let Some(recipe) = case.get("params_recipe") {
            assert!(statements.is_empty(), "{name}");
            let source = recipe["from"].as_str().unwrap();
            let base = cases[source]["params"]["broker_action"]["statement_b64url"]
                .as_str()
                .unwrap();
            let mut value: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(base).unwrap()).unwrap();
            let pointer = recipe["decoded_statement_pointer"].as_str().unwrap();
            let count = recipe["count"].as_u64().unwrap().try_into().unwrap();
            *value.pointer_mut(pointer).unwrap() =
                Value::String(recipe["repeat"].as_str().unwrap().repeat(count));
            let bytes = serde_json::to_vec(&value).unwrap();
            statements.push(URL_SAFE_NO_PAD.encode(bytes));
        }

        let reply_error = &case["reply"]["error"];
        // The expiry override is an outer RPC parameter, not a statement member.
        let defect = (case["method"] == "consent.request"
            && reply_error["code"] == "elicitation_invalid_request"
            && name != "expiry-override-refused")
            .then(|| {
                reply_error["message"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("invalid broker_action.")
                    .unwrap()
            });
        if let Some(member) = defect {
            assert_eq!(statements.len(), 1, "{name}");
            let err = check_statement(&statements[0]).expect_err(name);
            assert_eq!(err.member(), member, "{name}");
            refused += 1;
        } else {
            for statement in statements {
                let checked = check_statement(&statement).expect(name);
                let reencoded = checked.statement().encode().expect(name);
                assert!(reencoded.b64url() == statement, "{name}");
                accepted += 1;
            }
        }
    }
    assert!(accepted > 0);
    assert_eq!(refused, 7);
}

fn find_statements(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if key == "statement_b64url" {
                    out.push(value.as_str().unwrap().to_owned());
                } else {
                    find_statements(value, out);
                }
            }
        }
        Value::Array(values) => values.iter().for_each(|value| find_statements(value, out)),
        _ => {}
    }
}
