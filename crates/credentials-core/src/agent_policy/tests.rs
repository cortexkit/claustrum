use super::*;
use serde_json::json;

fn node_repository() -> Value {
    json!({
        "kind":"node_repository", "class":"read", "approval":"none", "identity":"agent",
        "credential":{"github_permissions":{"metadata":"read","issues":"read","pull_requests":"read"}},
        "requests":[{"graphql":{"operation":"query","fields":["node"]}}],
        "ownership":null, "consent":null
    })
}

fn sample() -> Value {
    json!({
        "schema":"ck-agent-policy/v1", "version":7, "issued_at_unix_secs":1795000000,
        "root_key_id":"c9ad111282d1da10",
        "bindings":[
            {"service":"github","agent":"alpha","identity":"github_app:alpha-bot","resources":["org/a","org/b"]},
            {"service":"github","agent":"beta","identity":"github_app:beta-bot","resources":["org/c"]}
        ],
        "rule_sets":{"github":{
            "rule_set":"github", "revision":1, "source":{"release":"defaults.1","sha256":"b".repeat(64)},
            "extractor":"github-rest-graphql/v1", "hosts":["api.github.com","uploads.github.com"],
            "redirect_hosts":["codeload.github.com"],
            "kinds":[{
                "kind":"edit_issue", "class":"speech", "approval":"none", "identity":"agent",
                "credential":{"github_permissions":{"issues":"write"}}, "ownership":null,
                "requests":[{"rest":{"method":"PATCH","host":"api.github.com",
                    "path":"/repos/{owner}/{repo}/issues/{number}",
                    "body":{"required":["title"],"forbidden":["state"]}}}],
                "consent":null
            },{
                "kind":"close_issue", "class":"speech", "approval":"none", "identity":"agent",
                "credential":{"github_permissions":{"issues":"write"}}, "ownership":null,
                "requests":[{"rest":{"method":"PATCH","host":"api.github.com",
                    "path":"/repos/{owner}/{repo}/issues/{number}",
                    "body":{"fixed":{"state":"closed"}}}},
                    {"graphql":{"operation":"mutation","fields":["closeIssue"],
                        "arguments":{"input.issueId":"node_in_scope"}}}],
                "consent":null
            },node_repository()],
            "actions":[{"action":"close","legs":[{"kind":"edit_issue","optional":true},{"kind":"close_issue"}]}]
        }}
    })
}

fn parse(value: &Value) -> Result<AgentPolicy, PolicyError> {
    AgentPolicy::parse_canonical(&canonical_bytes(value).unwrap())
}

#[test]
fn sample_round_trips_byte_for_byte() {
    // The sample uses only ASCII keys, so serde_json's object ordering also gives JCS.
    let input = serde_json::to_vec(&sample()).unwrap();
    let policy = AgentPolicy::parse_canonical(&input).unwrap();
    assert_eq!(policy.canonical_bytes().unwrap(), input);
    let rules = &policy.rule_sets["github"];
    assert_eq!(
        RuleSet::parse_canonical(&rules.canonical_bytes().unwrap()).unwrap(),
        *rules
    );
    assert_eq!(policy.github_projection()["org/b"], "alpha");
}

#[test]
fn jcs_sorts_object_keys_by_utf16_and_leaves_array_order_intact() {
    let mut input = sample();
    input["rule_sets"]["github"]["kinds"][0]["requests"][0]["rest"]["body"] = json!({
        "fixed":{"\u{e000}":"x\n\u{0001}","😀":true,"Å":null},
        "optional":["z","a"]
    });
    let lexical_utf8 = serde_json::to_string(&input).unwrap();
    let jcs = lexical_utf8.replace(
        r#""Å":null,"":"x\n\u0001","😀":true"#,
        r#""Å":null,"😀":true,"":"x\n\u0001""#,
    );
    assert_ne!(lexical_utf8, jcs);
    assert_eq!(
        parse(&input).unwrap().canonical_bytes().unwrap(),
        jcs.as_bytes()
    );
    assert_eq!(
        AgentPolicy::parse_canonical(lexical_utf8.as_bytes()),
        Err(PolicyError::NotCanonical)
    );
}

#[test]
fn refuses_noncanonical_bytes() {
    let input = serde_json::to_string(&sample()).unwrap();
    for bytes in [
        format!("{input}\n"),
        format!(" {input}"),
        input.replace("alpha", "\\u0061lpha"),
        input.replace("\"version\":7", "\"version\": 7"),
    ] {
        assert_eq!(
            AgentPolicy::parse_canonical(bytes.as_bytes()),
            Err(PolicyError::NotCanonical)
        );
    }
}

#[test]
fn refuses_duplicate_keys_in_dynamic_maps() {
    let input = serde_json::to_string(&sample()).unwrap().replace(
        r#""github_permissions":{"issues":"write"}"#,
        r#""github_permissions":{"issues":"write","issues":"read"}"#,
    );
    assert_eq!(
        AgentPolicy::parse_canonical(input.as_bytes()),
        Err(PolicyError::InvalidJson)
    );
}

#[test]
fn refuses_unknown_members_at_every_object_layer() {
    for pointer in [
        "",
        "/bindings/0",
        "/rule_sets/github",
        "/rule_sets/github/source",
        "/rule_sets/github/kinds/0",
        "/rule_sets/github/kinds/0/credential",
        "/rule_sets/github/kinds/0/requests/0",
        "/rule_sets/github/kinds/0/requests/0/rest",
        "/rule_sets/github/kinds/0/requests/0/rest/body",
        "/rule_sets/github/kinds/1/requests/1/graphql",
        "/rule_sets/github/actions/0",
        "/rule_sets/github/actions/0/legs/0",
    ] {
        let mut input = sample();
        input.pointer_mut(pointer).unwrap()["unknown"] = json!(true);
        assert_eq!(parse(&input), Err(PolicyError::InvalidShape), "{pointer}");
    }
    for (field, value) in [
        ("consent", json!({"fields":[],"unknown":null})),
        (
            "ownership",
            json!({"check":"own_issue","reads":["node_repository"],"unknown":null}),
        ),
    ] {
        let mut input = sample();
        input["rule_sets"]["github"]["kinds"][0][field] = value;
        assert_eq!(parse(&input), Err(PolicyError::InvalidShape), "{field}");
    }
}

#[test]
fn refuses_positional_structs_null_optionals_and_missing_nullables() {
    let mut input = sample();
    input["bindings"][0] = json!(["github", "alpha", "github_app:alpha-bot", ["org/a"]]);
    assert_eq!(parse(&input), Err(PolicyError::InvalidShape));
    let mut input = sample();
    input["rule_sets"]["github"]["kinds"][0]["requests"][0]["rest"]["query"] = Value::Null;
    assert_eq!(parse(&input), Err(PolicyError::InvalidShape));
    let mut input = sample();
    input["rule_sets"]["github"]["kinds"][0]
        .as_object_mut()
        .unwrap()
        .remove("consent");
    assert_eq!(parse(&input), Err(PolicyError::InvalidShape));
}

#[test]
fn exact_integer_bound_and_no_fraction_or_exponent() {
    use PolicyError::InvalidInteger;
    let base = serde_json::to_string(&sample()).unwrap();
    for (literal, accepted) in [
        ("9007199254740991", true),
        ("-9007199254740991", true),
        ("9007199254740992", false),
        ("-9007199254740992", false),
        ("1.0", false),
        ("1e0", false),
        ("0.5", false),
    ] {
        let file = base.replace("1795000000", literal);
        let actual = AgentPolicy::parse_canonical(file.as_bytes());
        if accepted {
            assert!(actual.is_ok(), "{literal}: {actual:?}");
        } else {
            assert_eq!(actual, Err(InvalidInteger), "{literal}");
        }
    }
    let file = base.replace(r#""state":"closed""#, r#""state":9007199254740992"#);
    assert_eq!(
        AgentPolicy::parse_canonical(file.as_bytes()),
        Err(InvalidInteger)
    );
}

#[test]
fn policy_document_cap_accepts_1_mib_and_refuses_one_more_byte() {
    let base = serde_json::to_string(&sample()).unwrap();
    let title = "a".repeat(MAX_POLICY_DOCUMENT_BYTES - base.len() + "title".len());
    let input = base.replace("\"title\"", &format!("\"{title}\""));
    assert_eq!(input.len(), MAX_POLICY_DOCUMENT_BYTES);
    assert!(AgentPolicy::parse_canonical(input.as_bytes()).is_ok());
    let long = input.replace(&title, &(title.clone() + "a"));
    assert_eq!(long.len(), MAX_POLICY_DOCUMENT_BYTES + 1);
    assert_eq!(
        AgentPolicy::parse_canonical(long.as_bytes()),
        Err(PolicyError::TooLarge)
    );
}

#[test]
fn signed_input_checks_the_separator_and_both_sides_of_the_signer_cap() {
    let cap = MAX_SIGN_PAYLOAD - 19;
    assert_eq!(check_signed_input_len(cap), Ok(MAX_SIGN_PAYLOAD));
    assert_eq!(check_signed_input_len(cap + 1), Err(PolicyError::TooLarge));
    assert_eq!(
        check_signed_input_len(usize::MAX),
        Err(PolicyError::TooLarge)
    );
    assert_eq!(PolicyError::TooLarge.to_string(), "policy_too_large");
    assert_eq!(
        signed_input(b"{}"),
        Ok("ck-agent-policy/v1\0{}".as_bytes().to_vec())
    );
}

#[test]
fn envelope_keeps_the_exact_policy_text() {
    let policy = serde_json::to_string(&sample()).unwrap();
    let envelope = AgentPolicyEnvelope::new(policy.clone(), "c9ad111282d1da10".into(), &[0; 64]);
    let json = serde_json::to_value(&envelope).unwrap();
    assert_eq!(json["v"], 1);
    assert_eq!(json["policy"], policy);
    assert_eq!(json["key_id"], "c9ad111282d1da10");
    assert_eq!(json["signature_b64"], format!("{}==", "A".repeat(86)));
}

macro_rules! refuses {
    ($name:ident, $variant:ident, $doc:ident, $mutate:expr) => {
        #[test]
        fn $name() {
            let mut $doc = sample();
            $mutate;
            assert_eq!(parse(&$doc), Err(PolicyError::$variant));
        }
    };
}

refuses!(
    wrong_schema,
    WrongSchema,
    p,
    p["schema"] = json!("ck-agent-policy/v2")
);
refuses!(version_zero, InvalidVersion, p, p["version"] = json!(0));
refuses!(
    uppercase_root,
    InvalidRootKeyId,
    p,
    p["root_key_id"] = json!("A9ad111282d1da10")
);
refuses!(
    other_service,
    UnsupportedService,
    p,
    p["rule_sets"]["npm"] = p["rule_sets"]["github"].clone()
);
refuses!(
    wrong_rule_set_name,
    WrongRuleSetName,
    p,
    p["rule_sets"]["github"]["rule_set"] = json!("npm")
);
refuses!(
    wrong_extractor,
    WrongExtractor,
    p,
    p["rule_sets"]["github"]["extractor"] = json!("github-rest-graphql/v2")
);
refuses!(
    invalid_source_digest,
    InvalidSourceDigest,
    p,
    p["rule_sets"]["github"]["source"]["sha256"] = json!("B".repeat(64))
);
refuses!(
    host_order,
    HostOrder,
    p,
    p["rule_sets"]["github"]["redirect_hosts"] = json!(["z.example", "a.example"])
);
refuses!(
    duplicate_hosts,
    HostOrder,
    p,
    p["rule_sets"]["github"]["redirect_hosts"] = json!(["a.example", "a.example"])
);
refuses!(
    redirect_hosts_disjoint,
    RedirectHostConflict,
    p,
    p["rule_sets"]["github"]["redirect_hosts"] = json!(["api.github.com"])
);
refuses!(
    duplicate_kind,
    DuplicateKind,
    p,
    p["rule_sets"]["github"]["kinds"][1]["kind"] = json!("edit_issue")
);
refuses!(
    blank_kind_name,
    EmptyKindName,
    p,
    p["rule_sets"]["github"]["kinds"][0]["kind"] = json!("")
);
refuses!(
    unknown_class,
    InvalidShape,
    p,
    p["rule_sets"]["github"]["kinds"][0]["class"] = json!("write")
);
refuses!(
    unknown_approval,
    InvalidShape,
    p,
    p["rule_sets"]["github"]["kinds"][0]["approval"] = json!("always")
);
refuses!(
    unknown_kind_identity,
    InvalidShape,
    p,
    p["rule_sets"]["github"]["kinds"][0]["identity"] = json!("person")
);
refuses!(
    operator_requires_once,
    OperatorNeedsApproval,
    p,
    p["rule_sets"]["github"]["kinds"][0]["class"] = json!("operator")
);
refuses!(
    anonymous_has_no_credential,
    AnonymousCredential,
    p,
    p["rule_sets"]["github"]["kinds"][0]["identity"] = json!("anonymous")
);
refuses!(anonymous_is_read, AnonymousNotRead, p, {
    p["rule_sets"]["github"]["kinds"][0]["identity"] = json!("anonymous");
    p["rule_sets"]["github"]["kinds"][0]["credential"] = Value::Null;
});
refuses!(
    empty_permissions,
    InvalidPermissions,
    p,
    p["rule_sets"]["github"]["kinds"][0]["credential"]["github_permissions"] = json!({})
);
refuses!(
    bad_permission_name,
    InvalidPermissions,
    p,
    p["rule_sets"]["github"]["kinds"][0]["credential"]["github_permissions"] =
        json!({"Issues":"write"})
);
refuses!(
    bad_permission_level,
    InvalidPermissions,
    p,
    p["rule_sets"]["github"]["kinds"][0]["credential"]["github_permissions"] =
        json!({"issues":"all"})
);
refuses!(
    missing_requests,
    MissingRequests,
    p,
    p["rule_sets"]["github"]["kinds"][0]["requests"] = json!([])
);
refuses!(
    consent_only_once,
    UnexpectedConsent,
    p,
    p["rule_sets"]["github"]["kinds"][0]["consent"] = json!({"fields":["repo"]})
);
refuses!(
    consent_requires_declared_fields,
    UndeclaredConsentField,
    p,
    {
        p["rule_sets"]["github"]["kinds"][0]["approval"] = json!("once");
        p["rule_sets"]["github"]["kinds"][0]["consent"] = json!({"fields":["state"]});
    }
);
refuses!(
    invalid_ownership_check,
    InvalidShape,
    p,
    p["rule_sets"]["github"]["kinds"][0]["ownership"] =
        json!({"check":"unknown","reads":["node_repository"]})
);
refuses!(
    ownership_read_count,
    InvalidOwnershipReads,
    p,
    p["rule_sets"]["github"]["kinds"][0]["ownership"] =
        json!({"check":"own_last_comment","reads":["node_repository"]})
);
refuses!(
    ownership_unknown_read,
    UnknownOwnershipRead,
    p,
    p["rule_sets"]["github"]["kinds"][0]["ownership"] =
        json!({"check":"own_issue","reads":["unknown"]})
);
refuses!(
    ownership_write_read,
    OwnershipReadNotRead,
    p,
    p["rule_sets"]["github"]["kinds"][0]["ownership"] =
        json!({"check":"own_issue","reads":["close_issue"]})
);
refuses!(node_predicate_needs_pre_read, MissingNodeRepository, p, {
    p["rule_sets"]["github"]["kinds"]
        .as_array_mut()
        .unwrap()
        .pop();
});
refuses!(
    node_repo_never_writes,
    InvalidNodeRepository,
    p,
    p["rule_sets"]["github"]["kinds"][2]["credential"]["github_permissions"]["issues"] =
        json!("write")
);
refuses!(
    node_repo_is_never_speech,
    InvalidNodeRepository,
    p,
    p["rule_sets"]["github"]["kinds"][2]["class"] = json!("speech")
);
refuses!(
    node_repo_no_approval,
    InvalidNodeRepository,
    p,
    p["rule_sets"]["github"]["kinds"][2]["approval"] = json!("once")
);
refuses!(
    node_repo_agent_identity,
    InvalidNodeRepository,
    p,
    p["rule_sets"]["github"]["kinds"][2]["identity"] = json!("anonymous")
);
refuses!(
    node_repo_exact_fields,
    InvalidNodeRepository,
    p,
    p["rule_sets"]["github"]["kinds"][2]["requests"][0]["graphql"]["fields"] =
        json!(["node", "repository"])
);
refuses!(
    node_repo_no_predicates,
    InvalidNodeRepository,
    p,
    p["rule_sets"]["github"]["kinds"][2]["requests"][0]["graphql"]["arguments"] =
        json!({"id":"node_in_scope"})
);
refuses!(
    node_repo_no_ownership,
    InvalidNodeRepository,
    p,
    p["rule_sets"]["github"]["kinds"][2]["ownership"] =
        json!({"check":"own_issue","reads":["node_repository"]})
);
refuses!(
    node_repo_no_consent,
    InvalidNodeRepository,
    p,
    p["rule_sets"]["github"]["kinds"][2]["consent"] = json!({"fields":[]})
);

#[test]
fn denied_kind_has_no_requests_credential_ownership_or_consent() {
    for (field, value) in [
        (
            "requests",
            json!([{"graphql":{"operation":"query","fields":["viewer"]}}]),
        ),
        (
            "credential",
            json!({"github_permissions":{"issues":"write"}}),
        ),
        (
            "ownership",
            json!({"check":"own_issue","reads":["node_repository"]}),
        ),
        ("consent", json!({"fields":[]})),
    ] {
        let mut doc = sample();
        let mut denied = json!({
            "kind":"blocked", "class":"denied", "approval":"none", "identity":"agent",
            "requests":[], "credential":null, "ownership":null, "consent":null
        });
        let kinds = doc["rule_sets"]["github"]["kinds"].as_array_mut().unwrap();
        kinds.push(denied.clone());
        assert!(parse(&doc).is_ok());
        denied[field] = value;
        doc["rule_sets"]["github"]["kinds"][3] = denied;
        assert_eq!(parse(&doc), Err(PolicyError::DeniedKindContent), "{field}");
    }
}

#[test]
fn source_release_length_boundaries() {
    for (release, accepted) in [
        ("".to_owned(), false),
        ("a".to_owned(), true),
        ("a".repeat(64), true),
        ("a".repeat(65), false),
        ("A".to_owned(), false),
        ("release/2".to_owned(), false),
    ] {
        let mut doc = sample();
        doc["rule_sets"]["github"]["source"]["release"] = json!(release);
        if accepted {
            assert!(parse(&doc).is_ok());
        } else {
            assert_eq!(parse(&doc), Err(PolicyError::InvalidSourceRelease));
        }
    }
}

#[test]
fn dns_host_and_label_length_boundaries() {
    let label = "a".repeat(63);
    let host = format!("{label}.{label}.{label}.{}", "b".repeat(61));
    assert_eq!(host.len(), 253);
    assert!(valid_host(&host));
    assert!(!valid_host(&(host + "b")));
    assert!(valid_host(&format!("{label}.b")));
    assert!(!valid_host(&format!("{label}a.b")));
    for bad in [
        "single",
        "A.com",
        "a..com",
        "-a.com",
        "a-.com",
        "a.com:443",
        "*.a.com",
        "127.0.0.1",
        "[::1]",
    ] {
        let mut doc = sample();
        doc["rule_sets"]["github"]["redirect_hosts"] = json!([bad]);
        assert_eq!(parse(&doc), Err(PolicyError::InvalidHost), "{bad}");
    }
}

#[test]
fn binding_app_slug_length_boundaries() {
    assert!(valid_app_slug("a"));
    assert!(valid_app_slug(&"a".repeat(100)));
    assert!(!valid_app_slug(&"a".repeat(101)));
    assert!(!valid_app_slug(""));
    assert!(!valid_app_slug("a_B"));
}

refuses!(
    invalid_method,
    InvalidMethod,
    p,
    p["rule_sets"]["github"]["kinds"][0]["requests"][0]["rest"]["method"] = json!("P ATCH")
);
refuses!(
    undeclared_host,
    UndeclaredHost,
    p,
    p["rule_sets"]["github"]["kinds"][0]["requests"][0]["rest"]["host"] = json!("other.example")
);
refuses!(
    unnormalized_path,
    InvalidPath,
    p,
    p["rule_sets"]["github"]["kinds"][0]["requests"][0]["rest"]["path"] = json!("/repos/../issues")
);
refuses!(
    unknown_path_parameter,
    UnknownPathParameter,
    p,
    p["rule_sets"]["github"]["kinds"][0]["requests"][0]["rest"]["path"] = json!("/issues/{thing}")
);
refuses!(
    tail_must_be_last,
    MisplacedTail,
    p,
    p["rule_sets"]["github"]["kinds"][0]["requests"][0]["rest"]["path"] =
        json!("/issues/{ref*}/end")
);
refuses!(
    resource_owner_occurs_once,
    RepeatedResourceParameter,
    p,
    p["rule_sets"]["github"]["kinds"][0]["requests"][0]["rest"]["path"] =
        json!("/repos/{owner}/{repo}/{owner}")
);
refuses!(
    resource_repo_occurs_once,
    RepeatedResourceParameter,
    p,
    p["rule_sets"]["github"]["kinds"][0]["requests"][0]["rest"]["path"] =
        json!("/repos/{owner}/{repo}/{repo}")
);
refuses!(
    tail_cannot_reuse_a_resource_parameter,
    RepeatedResourceParameter,
    p,
    p["rule_sets"]["github"]["kinds"][0]["requests"][0]["rest"]["path"] =
        json!("/repos/{owner}/{repo}/{owner*}")
);
refuses!(
    owner_requires_repo,
    UnboundOwner,
    p,
    p["rule_sets"]["github"]["kinds"][0]["requests"][0]["rest"]["path"] = json!("/orgs/{owner}")
);
refuses!(
    graphql_path_is_reserved,
    ReservedGraphqlPath,
    p,
    p["rule_sets"]["github"]["kinds"][0]["requests"][0]["rest"]["path"] = json!("/{name}")
);
refuses!(
    conflicting_constraint_members,
    ConflictingConstraintName,
    p,
    p["rule_sets"]["github"]["kinds"][0]["requests"][0]["rest"]["body"]["optional"] =
        json!(["state"])
);
refuses!(
    body_fixed_must_be_scalar,
    InvalidBodyFixedValue,
    p,
    p["rule_sets"]["github"]["kinds"][0]["requests"][0]["rest"]["body"]["fixed"] =
        json!({"count":[1]})
);
refuses!(
    query_fixed_must_be_string,
    InvalidQueryFixedValue,
    p,
    p["rule_sets"]["github"]["kinds"][0]["requests"][0]["rest"]["query"] =
        json!({"fixed":{"count":1}})
);
refuses!(
    forbid_query_array_shorthand,
    InvalidShape,
    p,
    p["rule_sets"]["github"]["kinds"][0]["requests"][0]["rest"]["query"] = json!(["count"])
);
refuses!(
    write_body_closed_if_given,
    OpenWriteBody,
    p,
    p["rule_sets"]["github"]["kinds"][0]["requests"][0]["rest"]["body"]["additional"] =
        json!("allow")
);
refuses!(
    graphql_exact_fields_are_unique,
    InvalidGraphqlFields,
    p,
    p["rule_sets"]["github"]["kinds"][1]["requests"][1]["graphql"]["fields"] =
        json!(["closeIssue", "closeIssue"])
);
refuses!(
    graphql_operation_is_closed,
    InvalidShape,
    p,
    p["rule_sets"]["github"]["kinds"][1]["requests"][1]["graphql"]["operation"] =
        json!("subscription")
);
refuses!(
    graphql_invalid_dotted_argument_path,
    InvalidGraphqlArgumentPath,
    p,
    p["rule_sets"]["github"]["kinds"][1]["requests"][1]["graphql"]["arguments"] =
        json!({"input..issueId":"node_in_scope"})
);
refuses!(
    graphql_repository_predicate_applies_only_to_repository,
    InvalidGraphqlArgumentPath,
    p,
    p["rule_sets"]["github"]["kinds"][1]["requests"][1]["graphql"]["arguments"] =
        json!({"repository":"repository_in_scope"})
);
refuses!(
    graphql_predicate_is_closed,
    InvalidShape,
    p,
    p["rule_sets"]["github"]["kinds"][1]["requests"][1]["graphql"]["arguments"] =
        json!({"input.issueId":"anything"})
);
refuses!(
    unknown_action_leg,
    UnknownActionLeg,
    p,
    p["rule_sets"]["github"]["actions"][0]["legs"][0]["kind"] = json!("unknown")
);
refuses!(
    reject_stored_action_class,
    InvalidShape,
    p,
    p["rule_sets"]["github"]["actions"][0]["class"] = json!("read")
);
refuses!(
    reject_stored_action_approval,
    InvalidShape,
    p,
    p["rule_sets"]["github"]["actions"][0]["approval"] = json!("none")
);
refuses!(
    empty_action,
    EmptyAction,
    p,
    p["rule_sets"]["github"]["actions"][0]["legs"] = json!([])
);
refuses!(
    empty_action_name,
    EmptyActionName,
    p,
    p["rule_sets"]["github"]["actions"][0]["action"] = json!("")
);
refuses!(duplicate_action, DuplicateAction, p, {
    let actions = p["rule_sets"]["github"]["actions"].as_array_mut().unwrap();
    actions.push(actions[0].clone());
});
refuses!(denied_action_leg, DeniedActionLeg, p, {
    let kind = &mut p["rule_sets"]["github"]["kinds"][0];
    kind["class"] = json!("denied");
    kind["credential"] = Value::Null;
    kind["requests"] = json!([]);
});
refuses!(
    agent_name_required,
    EmptyAgentName,
    p,
    p["bindings"][0]["agent"] = json!("")
);
refuses!(
    binding_agent_unique,
    DuplicateBinding,
    p,
    p["bindings"][1]["agent"] = json!("alpha")
);
refuses!(
    github_app_identity,
    InvalidIdentity,
    p,
    p["bindings"][0]["identity"] = json!("api_key:alpha-bot")
);
refuses!(
    identity_cannot_be_shared,
    SharedIdentity,
    p,
    p["bindings"][1]["identity"] = json!("github_app:alpha-bot")
);
refuses!(
    binding_order,
    BindingOrder,
    p,
    p["bindings"].as_array_mut().unwrap().swap(0, 1)
);
refuses!(
    resources_nonempty,
    EmptyResources,
    p,
    p["bindings"][0]["resources"] = json!([])
);
refuses!(
    resource_lowercase,
    InvalidResource,
    p,
    p["bindings"][0]["resources"][0] = json!("Org/a")
);
refuses!(
    resource_owner_and_repo,
    InvalidResource,
    p,
    p["bindings"][0]["resources"][0] = json!("org/team/repo")
);
refuses!(
    resource_in_only_one_binding,
    DuplicateResource,
    p,
    p["bindings"][1]["resources"][0] = json!("org/a")
);
refuses!(
    resource_unique_within_binding,
    DuplicateResource,
    p,
    p["bindings"][0]["resources"][1] = json!("org/a")
);
refuses!(
    resource_order,
    ResourceOrder,
    p,
    p["bindings"][0]["resources"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1)
);

#[test]
fn account_level_read_must_be_anonymous() {
    let mut doc = sample();
    let kind = &mut doc["rule_sets"]["github"]["kinds"][0];
    kind["class"] = json!("read");
    kind["requests"][0]["rest"]["path"] = json!("/orgs/{owner}");
    assert_eq!(parse(&doc), Err(PolicyError::UnboundOwner));
    let kind = &mut doc["rule_sets"]["github"]["kinds"][0];
    kind["identity"] = json!("anonymous");
    kind["credential"] = Value::Null;
    assert!(parse(&doc).is_ok());
}

#[test]
fn action_requirements_derive_from_all_legs_including_optional_ones() {
    let mut doc = sample();
    doc["rule_sets"]["github"]["kinds"][0]["class"] = json!("operator");
    doc["rule_sets"]["github"]["kinds"][0]["approval"] = json!("once");
    doc["rule_sets"]["github"]["kinds"][0]["consent"] = json!({"fields":["owner","repo","title"]});
    let policy = parse(&doc).unwrap();
    let rules = &policy.rule_sets["github"];
    assert_eq!(
        rules.actions[0].requirements(rules),
        Ok((Class::Operator, Approval::Once))
    );
}

#[test]
fn overlap_rejects_unrestricted_edit_copy_but_allows_close() {
    let mut doc = sample();
    assert!(parse(&doc).is_ok());
    let kinds = doc["rule_sets"]["github"]["kinds"].as_array_mut().unwrap();
    let mut copy = kinds[0].clone();
    copy["kind"] = json!("unrestricted_edit_issue");
    copy["requests"][0]["rest"]["body"]
        .as_object_mut()
        .unwrap()
        .remove("forbidden");
    kinds.push(copy);
    assert_eq!(parse(&doc), Err(PolicyError::RequestOverlap));
}

#[test]
fn graphql_overlap_uses_exact_set_not_order_or_predicates() {
    let mut doc = sample();
    let kinds = doc["rule_sets"]["github"]["kinds"].as_array_mut().unwrap();
    kinds[1]["requests"][1]["graphql"]["fields"] = json!(["closeIssue", "viewer"]);
    let mut copy = kinds[1].clone();
    copy["kind"] = json!("copy");
    copy["requests"] =
        json!([{"graphql":{"operation":"mutation", "fields":["viewer","closeIssue"]}}]);
    kinds.push(copy);
    assert_eq!(parse(&doc), Err(PolicyError::RequestOverlap));
    doc["rule_sets"]["github"]["kinds"][3]["requests"][0]["graphql"]["fields"] = json!(["viewer"]);
    assert!(parse(&doc).is_ok());
}

#[test]
fn manifest_projection_lowercases_keys_and_refuses_a_collision() {
    fn manifest(bindings: &[(&str, &str)]) -> GhManifest {
        let bindings = bindings.iter().copied().collect::<BTreeMap<_, _>>();
        let mut bytes = serde_json::to_vec_pretty(&json!({
            "manifest_version":42, "issued_at_unix_secs":1, "bindings":bindings
        }))
        .unwrap();
        bytes.push(b'\n');
        GhManifest::parse_reproducible(&bytes).unwrap()
    }
    let policy = parse(&sample()).unwrap();
    let valid = manifest(&[("Org/A", "alpha"), ("org/B", "alpha"), ("org/c", "beta")]);
    assert_eq!(
        manifest_projection(&valid).unwrap(),
        policy.github_projection()
    );
    let collision = manifest(&[("Org/A", "alpha"), ("org/a", "alpha")]);
    assert_eq!(
        manifest_projection(&collision),
        Err(PolicyError::ManifestProjectionCollision)
    );
}
