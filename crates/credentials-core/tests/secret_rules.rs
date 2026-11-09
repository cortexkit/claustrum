use credentials_core::agent_secret::{self, SecretScope, UseTarget};
use secret_rules::scope::{SecretScope as RuleScope, UseTarget as RuleTarget, PSL_SNAPSHOT};
use serde_json::{json, Value};

fn corpus() -> Value {
    serde_json::from_str(include_str!(
        "vectors/multi-host/secret-scope-match-v1.json"
    ))
    .unwrap()
}

fn vault_target(value: &Value) -> UseTarget {
    if let Some(origin) = value.get("origin") {
        UseTarget::SiteLogin {
            origin: origin.as_str().unwrap().into(),
        }
    } else {
        UseTarget::ApiKey {
            scheme: value["scheme"].as_str().unwrap().into(),
            host: value["host"].as_str().unwrap().into(),
            port: u16::try_from(value["port"].as_u64().unwrap()).unwrap(),
            path: value["path"].as_str().unwrap().into(),
        }
    }
}

fn rule_target(target: &UseTarget) -> RuleTarget<'_> {
    match target {
        UseTarget::ApiKey {
            scheme,
            host,
            port,
            path,
        } => RuleTarget::ApiKey {
            scheme,
            host,
            port: *port,
            path,
        },
        UseTarget::SiteLogin { origin } => RuleTarget::SiteLogin { origin },
    }
}

#[test]
fn rules_psl_snapshot_matches_published_scope_corpus() {
    assert_eq!(
        json!({
            "url": PSL_SNAPSHOT.url,
            "date": PSL_SNAPSHOT.date,
            "sha256": PSL_SNAPSHOT.sha256,
        }),
        corpus()["psl_snapshot"]
    );
}

#[test]
fn rules_release_passes_every_published_scope_case() {
    let corpus = corpus();
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 92);
    for case in cases {
        let name = case["case"].as_str().unwrap();
        let kind = case["kind"].as_str().unwrap();
        let fields = &case["scope"];
        let parsed = match case["form"].as_str().unwrap() {
            "input" => RuleScope::parse_input(kind, fields),
            "stored" => RuleScope::decode_stored(kind, fields),
            form => panic!("unknown scope form {form}: {name}"),
        };
        if let Some(code) = case["expect"].get("scope_refused") {
            assert_eq!(parsed.unwrap_err().code(), code.as_str().unwrap(), "{name}");
            continue;
        }
        let scope = parsed.unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(
            scope.is_extended(),
            fields.get("rules").is_some() || fields.get("origins").is_some(),
            "{name}"
        );
        assert_eq!(
            RuleScope::decode_stored(kind, &scope.to_value()).unwrap(),
            scope,
            "emitted scope must reopen: {name}"
        );
        let target = vault_target(&case["target"]);
        let expected = match case["expect"].as_str().unwrap() {
            "match" => true,
            "no_match" => false,
            expect => panic!("unknown expectation {expect}: {name}"),
        };
        assert_eq!(scope.matches(rule_target(&target)), expected, "{name}");
    }
}

#[test]
fn vault_legacy_scopes_match_every_published_input_case() {
    let corpus = corpus();
    let mut checked = 0;
    for case in corpus["cases"].as_array().unwrap() {
        let fields = &case["scope"];
        if case["form"] != "input"
            || (fields.get("host").is_none() && fields.get("origin").is_none())
        {
            continue;
        }
        checked += 1;
        let name = case["case"].as_str().unwrap();
        let scope = match case["kind"].as_str().unwrap() {
            "agent_api_key" => SecretScope::ApiKey {
                host: fields["host"].as_str().unwrap().into(),
                path_prefix: fields
                    .get("path_prefix")
                    .map(|prefix| prefix.as_str().unwrap().into()),
                location: "authorization_bearer".into(),
            },
            "site_login" => SecretScope::SiteLogin {
                origin: fields["origin"].as_str().unwrap().into(),
            },
            kind => panic!("unknown scope kind {kind}: {name}"),
        };
        if let Some(code) = case["expect"].get("scope_refused") {
            assert_eq!(
                agent_secret::validate_scope(&scope)
                    .unwrap_err()
                    .wire_code(),
                code.as_str().unwrap(),
                "{name}"
            );
        } else {
            assert_eq!(agent_secret::validate_scope(&scope), Ok(()), "{name}");
            let target = vault_target(&case["target"]);
            assert_eq!(
                target.matches(&scope),
                case["expect"].as_str().unwrap() == "match",
                "{name}"
            );
        }
        if let SecretScope::ApiKey {
            mut location,
            host,
            path_prefix,
        } = scope
        {
            // Scope grammar and byte caps must still precede vault-only location checks.
            location.clear();
            let invalid_location = SecretScope::ApiKey {
                host,
                path_prefix,
                location,
            };
            let expected = case["expect"]
                .get("scope_refused")
                .and_then(Value::as_str)
                .unwrap_or("invalid_params");
            assert_eq!(
                agent_secret::validate_scope(&invalid_location)
                    .unwrap_err()
                    .wire_code(),
                expected,
                "location precedence: {name}"
            );
        }
    }
    assert_eq!(
        checked, 43,
        "every legacy input case must reach the vault API"
    );
}

#[test]
fn vault_login_target_numeric_default_ports_remain_compatible() {
    let corpus = corpus();
    let origin = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|case| case["scope"].get("origin").and_then(Value::as_str))
        .unwrap();
    let scope = SecretScope::SiteLogin {
        origin: origin.into(),
    };
    for port in ["443", "00443", "+443"] {
        let target = UseTarget::SiteLogin {
            origin: format!("{origin}:{port}"),
        };
        assert_eq!(target.validate(), Ok(()), "port {port}");
        assert!(target.matches(&scope), "numeric HTTPS default port {port}");
    }
}
