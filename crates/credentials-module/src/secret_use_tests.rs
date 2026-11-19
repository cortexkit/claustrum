use super::*;
use credentials_core::{key::MasterKey, test_support::TestTempDir};
use serde_json::json;
use subc_protocol::scope::{ScopeAttributes, ScopeParent};

fn rig(tag: &str) -> (TestTempDir, Arc<EncryptedStore>) {
    let root = TestTempDir::new(format!("secret-use-{tag}-{}", std::process::id()));
    let descriptor = cortexkit_store::StorageDescriptor {
        module_id: "claustrum".into(),
        storage_namespace: tag.into(),
        isolation: cortexkit_store::Isolation::Module,
        backend: cortexkit_store::StorageBackend::Sqlite {
            path: root.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let sqlite = cortexkit_store::open_sqlite(&descriptor).unwrap();
    EncryptedStore::migrate(&sqlite).unwrap();
    (
        root,
        Arc::new(EncryptedStore::open(sqlite, MasterKey::from_bytes([91; 32])).unwrap()),
    )
}
fn principal(module: &str) -> Principal {
    Principal::Reserved {
        module_id: module.into(),
    }
}
fn stamp(kind: ScopeKind) -> ScopeStamp {
    ScopeStamp::new(principal("prefrontal-core"), "H", 7, kind)
        .with_attributes(ScopeAttributes::new().with_agent_id(Some("agent-A".into())))
}
fn params() -> Value {
    json!({"name":"key","stamp":stamp(ScopeKind::Head),"target":{"scheme":"https","host":"x.test","path":"/repos/a/canary-token"}})
}
fn body(answer: UseAnswer) -> Value {
    match answer {
        UseAnswer::Reply(v) => v,
        UseAnswer::InvalidParams => json!({"transport":"invalid_params"}),
    }
}

#[test]
fn secret_use_only_trusted_senders_parse_and_write_diagnostics() {
    let (_root, store) = rig("caller");
    for p in [
        None,
        Some(Principal::Direct),
        Some(Principal::Unverified),
        Some(principal("callosum")),
        Some(principal("prefrontal-core")),
        Some(principal("cingulate")),
        Some(principal("harness:aft")),
    ] {
        assert_eq!(
            body(serve(&store, p.as_ref(), &json!({}), || 1000)),
            SecretError::NotFound.body(),
            "non-senders must refuse before parsing"
        );
    }
    assert!(
        store.recent_auth_events(100).unwrap().is_empty(),
        "step one must not write diagnostics"
    );
    for module in ["aft", "cerebellum"] {
        assert_eq!(
            body(serve(&store, Some(&principal(module)), &json!({}), || 1000)),
            json!({"transport":"invalid_params"})
        );
        assert_eq!(
            body(serve(&store, Some(&principal(module)), &params(), || 1000)),
            SecretError::NotFound.body()
        );
    }
    let events = store.recent_auth_events(100).unwrap();
    assert_eq!(events.len(), 4);
    assert!(events
        .iter()
        .all(|e| e.credential_id == "secret-use|unaddressed"
            && e.kind == "secret_use_refusal"
            && e.principal_kind.as_deref() == Some("reserved")));
    assert!(!format!("{events:?}").contains("canary-token"));
}

#[test]
fn secret_federated_scope_maps_to_nothing_and_is_refused() {
    // A federated agent scope comes from another computer and has no approval shape on
    // this one, so it must not map even with a linked prefrontal parent.
    let parent = ScopeParent::new(principal("prefrontal-core"), "parent-H", 7);
    let federated = stamp(ScopeKind::Federated)
        .with_parent(Some(parent))
        .with_parent_state(Some(ParentState::Linked));
    assert!(asking(&federated).is_none());
    let (_root, store) = rig("federated");
    let mut p = params();
    p["stamp"] = json!(federated);
    for module in ["aft", "cerebellum"] {
        assert_eq!(
            body(serve(&store, Some(&principal(module)), &p, || 1000)),
            SecretError::NotFound.body()
        );
    }
    assert!(store
        .recent_auth_events(100)
        .unwrap()
        .iter()
        .all(|e| e.kind == "secret_use_refusal"));
}

#[test]
fn secret_ephemeral_mapping_requires_live_prefrontal_parent_and_equal_epoch() {
    let parent = ScopeParent::new(principal("prefrontal"), "parent-H", 7);
    let base = stamp(ScopeKind::Ephemeral)
        .with_parent(Some(parent))
        .with_parent_state(Some(ParentState::Linked));
    let (mapped, worker) = asking(&base).expect("live prefrontal parent maps");
    assert_eq!(
        (
            mapped.owner.as_str(),
            mapped.kind.as_str(),
            mapped.scope_ref.as_str(),
            mapped.epoch
        ),
        ("reserved:prefrontal", "head", "parent-H", 7)
    );
    assert!(worker.is_none());
    // The module's id before its rename no longer maps, nor does a look-alike.
    for owner in ["prefrontal-core", "prefrontal-x"] {
        let mut other = base.clone();
        other.parent.as_mut().unwrap().owner = principal(owner);
        assert!(asking(&other).is_none(), "{owner} must not map");
    }
    for mode in [
        "no-parent",
        "no-state",
        "pending",
        "ended",
        "owner",
        "epoch",
        "flow",
    ] {
        let mut s = base.clone();
        match mode {
            "no-parent" => s.parent = None,
            "no-state" => s.parent_state = None,
            "pending" => s.parent_state = Some(ParentState::Pending),
            "ended" => s.parent_state = Some(ParentState::Ended),
            "owner" => s.parent.as_mut().unwrap().owner = principal("other"),
            "epoch" => s.parent.as_mut().unwrap().scope_epoch = 6,
            "flow" => s.attributes.flow_id = Some("flow:read".into()),
            _ => unreachable!(),
        }
        assert!(
            asking(&s).is_none(),
            "Ephemeral mapping must require live prefrontal parent and equal epoch: {mode}"
        );
    }
    let (_root, store) = rig("unmapped");
    let expected = serde_json::to_vec(&SecretError::NotFound.body()).unwrap();
    for field in ["owner", "ref", "scope_epoch", "kind", "owner_authorized"] {
        let mut p = params();
        p["stamp"].as_object_mut().unwrap().remove(field);
        assert_eq!(
            serde_json::to_vec(&body(serve(&store, Some(&principal("aft")), &p, || 1000))).unwrap(),
            expected,
            "missing stamp facts are uniform not_found"
        );
    }
    let mut p = params();
    p["stamp"] = json!(base.with_parent_state(None));
    assert_eq!(
        serde_json::to_vec(&body(serve(&store, Some(&principal("aft")), &p, || 1000))).unwrap(),
        expected
    );
    p["stamp"] = json!(stamp(ScopeKind::Head)
        .with_attributes(ScopeAttributes::new().with_flow_id(Some("flow-read".into()))));
    assert_eq!(
        body(serve(&store, Some(&principal("aft")), &p, || 1000)),
        SecretError::NotFound.body()
    );
}

#[test]
fn secret_worker_under_head_requires_owner_ref_live_state_and_equal_epoch() {
    for (owner, expected) in [
        (Principal::Direct, "direct"),
        (Principal::Unverified, "unverified"),
        (principal("other"), "reserved:other"),
    ] {
        let s = ScopeStamp::new(owner, "H", 7, ScopeKind::Head);
        assert_eq!(
            asking(&s).unwrap().0.owner,
            expected,
            "Head mapping preserves the stamped owner without a stored-state lookup"
        );
    }
    let base = stamp(ScopeKind::Worker)
        .with_parent(Some(ScopeParent::new(
            principal("prefrontal-core"),
            "parent-H",
            7,
        )))
        .with_parent_state(Some(ParentState::Linked));
    let (mapped, parent) = asking(&base).unwrap();
    assert_eq!(mapped.kind, "worker");
    assert_eq!(
        parent.unwrap().scope_ref,
        "parent-H",
        "live Worker can inherit Head coverage"
    );
    for mode in ["no-parent", "no-state", "pending", "ended", "epoch"] {
        let mut s = base.clone();
        match mode {
            "no-parent" => s.parent = None,
            "no-state" => s.parent_state = None,
            "pending" => s.parent_state = Some(ParentState::Pending),
            "ended" => s.parent_state = Some(ParentState::Ended),
            "epoch" => s.parent.as_mut().unwrap().scope_epoch = 6,
            _ => unreachable!(),
        }
        assert!(
            asking(&s).unwrap().1.is_none(),
            "Worker under Head requires live parent and equal epoch: {mode}"
        );
    }
    let (_root, store) = rig("coverage");
    let mut p = params();
    p["coverage"] = json!("agent_and_workers");
    p["stamp"] = json!(base);
    assert_eq!(
        body(serve(&store, Some(&principal("aft")), &p, || 1000)),
        json!({"transport":"invalid_params"})
    );
    p["stamp"] = json!(stamp(ScopeKind::Ephemeral)
        .with_parent(Some(ScopeParent::new(
            principal("prefrontal"),
            "parent-H",
            7
        )))
        .with_parent_state(Some(ParentState::Linked)));
    assert_eq!(
        body(serve(&store, Some(&principal("aft")), &p, || 1000)),
        SecretError::NotFound.body(),
        "mapped Ephemeral Head coverage gets as far as the name lookup"
    );
    assert_eq!(
        store.recent_auth_events(1).unwrap()[0].detail.as_deref(),
        Some("unknown_name")
    );
}

#[test]
fn secret_use_grammar_targets_and_key_sets() {
    let (_root, store) = rig("grammar");
    let run = |p: &Value| body(serve(&store, Some(&principal("aft")), p, || 1000));
    let invalid = json!({"transport":"invalid_params"});
    let mut p = params();
    p["stamp"]["scope_epoch"] = json!(9_007_199_254_740_991u64);
    assert_eq!(run(&p), SecretError::NotFound.body());
    p["stamp"]["scope_epoch"] = json!(9_007_199_254_740_992u64);
    assert_eq!(run(&p), invalid);
    for name in ["", ".leading", "a b", "a|b", "a\n", "é", "a\u{202e}"] {
        let mut p = params();
        p["name"] = json!(name);
        assert_eq!(run(&p), invalid);
    }
    let mut p = params();
    p["name"] = json!("a".repeat(64));
    assert_eq!(run(&p), SecretError::NotFound.body());
    p["name"] = json!("a".repeat(65));
    assert_eq!(run(&p), SecretError::LimitExceeded.body());
    // The vault takes no caller-supplied agent name; passing one is an unknown key.
    let mut p = params();
    p["display_name"] = json!("Alice");
    assert_eq!(run(&p), invalid);
    for path in ["/repos/a?x=1", "/repos/a#f", "/a//b", "/a/%2e", "/a/%25"] {
        let mut p = params();
        p["target"]["path"] = json!(path);
        assert_eq!(run(&p), invalid);
    }
    // Only the name may be omitted: a target-only request now selects a Basic
    // sign-in secret, and an empty vault has no matching candidate.
    let mut nameless = params();
    nameless.as_object_mut().unwrap().remove("name");
    assert_eq!(run(&nameless), SecretError::NotFound.body());
    for key in ["stamp", "target"] {
        let mut p = params();
        p.as_object_mut().unwrap().remove(key);
        assert_eq!(run(&p), invalid);
    }
    let mut p = params();
    p["extra"] = json!(true);
    assert_eq!(run(&p), invalid);
    for key in ["scheme", "host", "path"] {
        let mut p = params();
        p["target"].as_object_mut().unwrap().remove(key);
        assert_eq!(run(&p), invalid);
    }
    let mut p = params();
    p["target"]["extra"] = json!(1);
    assert_eq!(run(&p), invalid);
    for port in [json!(-1), json!(65536), json!(443.5), json!("443")] {
        let mut p = params();
        p["target"]["port"] = port;
        assert_eq!(run(&p), invalid);
    }
    for target in [
        json!({"scheme":"https","host":"x.test","port":443,"path":"/"}),
        json!({"origin":"https://x.test:443"}),
    ] {
        let mut p = params();
        p["target"] = target;
        assert_eq!(run(&p), SecretError::NotFound.body());
    }
}

fn local_params() -> Value {
    json!({"name":"sudo","stamp":stamp(ScopeKind::Head),"target":{
        "program":"sudo","use":"sudo_password","target":{"user":"root"},
        "command":"apt upgrade","workdir":"/home/alice","purpose":"update packages",
        "expects":"password prompt","undoable":"no"
    }})
}

fn ssh_params() -> Value {
    json!({"key":"signing:ssh:1","stamp":stamp(ScopeKind::Head),
        "target":{"user":"alice","host":params()["target"]["host"],"port":22},
        "command":"ssh server","workdir":"/home/alice","data":""})
}

fn programs_on(store: &EncryptedStore) {
    store
        .set_secret_local_programs_audited(
            true,
            credentials_core::audit::AuditCtx::admin(
                credentials_core::audit::AuditOp::SecretLocalProgramsSet,
            ),
        )
        .unwrap();
}

#[test]
fn ssh_sign_refuses_unreadable_card_key_ids_before_lookup_without_writes() {
    let (_root, store) = rig("ssh-card-id");
    for id in [
        "signing:".to_owned(),
        format!("signing:{}x", "é".repeat(124)),
        "signing:a\nb".to_owned(),
        "signing:a\u{e007f}b".to_owned(),
        "signing:a\u{2028}b".to_owned(),
        "signing:a\u{2029}b".to_owned(),
        "signing:bad|id".to_owned(),
    ] {
        let mut p = ssh_params();
        p["key"] = json!(id);
        assert_eq!(
            body(serve_ssh_sign(&store, Some(&principal("aft")), &p, || 1000)),
            json!({"transport":"invalid_params"})
        );
    }
    assert!(store.recent_auth_events(100).unwrap().is_empty());
    assert!(store.read_audit(None).unwrap().is_empty());
}

#[test]
fn local_ops_check_admission_closed_params_setting_then_scope_and_text() {
    let (_root, store) = rig("local-order");
    assert!(
        !store.secret_local_programs_enabled().unwrap(),
        "missing means off"
    );
    let invalid = json!({"transport":"invalid_params"});
    let disabled = SecretError::SecretLocalProgramsDisabled.body();
    for ssh in [false, true] {
        let run = |who: Option<&Principal>, p: &Value| {
            body(if ssh {
                serve_ssh_sign(&store, who, p, || 1000)
            } else {
                serve(&store, who, p, || 1000)
            })
        };
        let mut p = if ssh { ssh_params() } else { local_params() };
        p["stamp"] = json!({});
        if ssh {
            p["command"] = json!("x".repeat(MAX_LOCAL_COMMAND_BYTES + 1));
        } else {
            p["target"]["command"] = json!("x".repeat(MAX_LOCAL_COMMAND_BYTES + 1));
        }
        for who in [
            None,
            Some(Principal::Direct),
            Some(principal("basal")),
            Some(principal("cerebellum")),
            Some(principal("cingulate")),
        ] {
            assert_eq!(run(who.as_ref(), &p), SecretError::NotFound.body());
        }
        let mut extra = p.clone();
        extra["unknown"] = json!(true);
        assert_eq!(
            run(Some(&principal("aft")), &extra),
            invalid,
            "closed before off"
        );
        if ssh {
            extra = p.clone();
            extra["key"] = json!("apikey:ssh");
            assert_eq!(
                run(Some(&principal("aft")), &extra),
                invalid,
                "key grammar before off"
            );
        } else {
            for required in ["expects", "undoable"] {
                extra = p.clone();
                extra["target"].as_object_mut().unwrap().remove(required);
                assert_eq!(
                    run(Some(&principal("aft")), &extra),
                    invalid,
                    "missing {required} before off"
                );
            }
        }
        assert_eq!(
            run(Some(&principal("aft")), &p),
            disabled,
            "off before stamp or cap"
        );
    }
    assert!(
        store.recent_auth_events(100).unwrap().is_empty(),
        "steps 1–3 are silent"
    );
    programs_on(&store);
    assert!(store.secret_local_programs_enabled().unwrap());
    for ssh in [false, true] {
        let run = |p: &Value| {
            body(if ssh {
                serve_ssh_sign(&store, Some(&principal("aft")), p, || 1000)
            } else {
                serve(&store, Some(&principal("aft")), p, || 1000)
            })
        };
        let base = if ssh { ssh_params() } else { local_params() };
        let mut p = base.clone();
        p["stamp"] = json!({});
        if ssh {
            p["command"] = json!("x".repeat(MAX_LOCAL_COMMAND_BYTES + 1));
        } else {
            p["target"]["command"] = json!("x".repeat(MAX_LOCAL_COMMAND_BYTES + 1));
        }
        assert_eq!(run(&p), SecretError::NotFound.body(), "stamp before text");
        p["stamp"] = base["stamp"].clone();
        p["coverage"] = json!("agent_and_workers");
        assert_eq!(run(&p), invalid, "coverage before text");
        p["coverage"] = json!("scope");
        assert_eq!(
            run(&p),
            json!({"error":{"code":"limit_exceeded","class":"permanent"}}),
            "cap before lookup"
        );
        for text in ["", "echo\npassword", "echo\u{202e}password"] {
            p = base.clone();
            if ssh {
                p["command"] = json!(text);
            } else {
                p["target"]["command"] = json!(text);
            }
            assert_eq!(run(&p), invalid);
        }
    }
    let events = store.recent_auth_events(100).unwrap();
    assert!(events
        .iter()
        .all(|e| e.credential_id == "secret|sudo" || e.credential_id == "signing:ssh:1"));
    assert!(!format!("{events:?}").contains("password"));
}

#[test]
fn local_use_closed_target_and_legacy_limit_framing_stay_distinct() {
    let (_root, store) = rig("local-shapes");
    programs_on(&store);
    let run = |p: &Value| body(serve(&store, Some(&principal("aft")), p, || 1000));
    let invalid = json!({"transport":"invalid_params"});
    for key in [
        "program", "use", "target", "command", "workdir", "purpose", "expects", "undoable",
    ] {
        let mut p = local_params();
        p["target"].as_object_mut().unwrap().remove(key);
        assert_eq!(run(&p), invalid, "missing {key}");
    }
    for (key, value) in [
        ("extra", json!(1)),
        ("expects", Value::Null),
        ("undoable", Value::Null),
        ("workdir", json!("C:/windows")),
        ("use", json!("ssh_sign")),
    ] {
        let mut p = local_params();
        p["target"][key] = value;
        assert_eq!(run(&p), invalid, "bad {key}");
    }
    let mut local = local_params();
    local["target"]["command"] = json!("x".repeat(MAX_LOCAL_COMMAND_BYTES));
    assert_eq!(
        run(&local),
        SecretError::NotFound.body(),
        "last accepted command length"
    );
    local["target"]["command"] = json!("x".repeat(MAX_LOCAL_COMMAND_BYTES + 1));
    assert_eq!(
        run(&local),
        json!({"error":{"code":"limit_exceeded","class":"permanent"}})
    );
    let mut legacy = params();
    legacy["name"] = json!("a".repeat(65));
    assert_eq!(
        serde_json::to_vec(&run(&legacy)).unwrap(),
        br#"{"error":{"class":"context_overflow","code":"limit_exceeded"}}"#
    );
    for target in [
        params()["target"].clone(),
        json!({"origin":"https://x.test"}),
    ] {
        let mut legacy = params();
        legacy["target"] = target;
        legacy["target"]["command"] = json!("unexpected local field");
        assert_eq!(
            body(serve(
                &store,
                Some(&principal("cerebellum")),
                &legacy,
                || 1000
            )),
            invalid
        );
    }
}

fn put_basic(store: &EncryptedStore, name: &str) {
    use credentials_core::audit::{AuditCtx, AuditOp};
    store
        .set_federation_self_member_audited(
            "fed-computer:22222222222222222222222222222222",
            AuditCtx::admin(AuditOp::FederationSelfSet),
        )
        .unwrap();
    store
        .set_secret_basic_auth_audited(true, AuditCtx::admin(AuditOp::SecretBasicAuthSet))
        .unwrap();
    store
        .secret_put_audited(
            &SecretPut {
                name: name.into(),
                kind: "agent_api_key".into(),
                host: Some("x.test".into()),
                path_prefix: Some("/repos/a".into()),
                location: Some("authorization_basic:git".into()),
                origin: None,
                rules: None,
                origins: None,
                program: None,
                r#use: None,
                targets: None,
                material_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                    deposit_plaintext(&SecretMaterial::ApiKey(
                        credentials_core::secret::Secret::new(b"token".to_vec()),
                    ))
                    .expose(),
                ),
            },
            "operator",
        )
        .unwrap();
}

#[test]
fn nameless_secret_use_refuses_cerebellum_basal_and_flow_with_uniform_not_found() {
    let (_root, store) = rig("nameless-admission");
    put_basic(&store, "key");
    let mut request = params();
    request.as_object_mut().unwrap().remove("name");
    for module in ["cerebellum", "basal", "unknown"] {
        assert_eq!(
            serde_json::to_vec(&body(serve(
                &store,
                Some(&principal(module)),
                &request,
                || 1000
            )))
            .unwrap(),
            serde_json::to_vec(&SecretError::NotFound.body()).unwrap()
        );
        assert!(sender_call("secret.use", Some(&principal(module)), &request).is_none());
    }
    request["stamp"]["attributes"]["flow_id"] = json!("flow-A");
    for module in ["aft", "cerebellum", "basal"] {
        assert_eq!(
            body(serve(&store, Some(&principal(module)), &request, || 1000)),
            SecretError::NotFound.body()
        );
    }
}

#[test]
fn nameless_secret_use_parses_only_absence_and_reuses_the_named_card() {
    let (_root, store) = rig("nameless-parsing");
    put_basic(&store, "key");
    let named = body(serve(&store, Some(&principal("aft")), &params(), || 1000));
    assert_eq!(named["status"], "approval_required");
    let mut request = params();
    request.as_object_mut().unwrap().remove("name");
    assert!(sender_call("secret.use", Some(&principal("aft")), &request).is_some());
    assert_eq!(
        serde_json::to_vec(&named).unwrap(),
        serde_json::to_vec(&body(serve(
            &store,
            Some(&principal("aft")),
            &request,
            || 1000
        )))
        .unwrap()
    );
    for name in [json!(""), Value::Null, json!(42)] {
        request["name"] = name;
        assert_eq!(
            body(serve(&store, Some(&principal("aft")), &request, || 1000)),
            json!({"transport":"invalid_params"})
        );
    }
    request.as_object_mut().unwrap().remove("name");
    put_basic(&store, "other");
    assert_eq!(
        body(serve(&store, Some(&principal("aft")), &request, || 1000)),
        SecretError::Ambiguous.body()
    );
}
