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
    json!({"name":"key","display_name":"Alice","stamp":stamp(ScopeKind::Head),"target":{"scheme":"https","host":"x.test","path":"/repos/a/canary-token"}})
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
fn secret_ephemeral_mapping_requires_live_prefrontal_parent_and_equal_epoch() {
    let parent = ScopeParent::new(principal("prefrontal-core"), "parent-H", 7);
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
        ("reserved:prefrontal-core", "head", "parent-H", 7)
    );
    assert!(worker.is_none());
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
            principal("prefrontal-core"),
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
fn secret_use_grammar_targets_key_sets_and_display_name_boundaries() {
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
    for display in [
        "a\u{202e}",
        "a\u{200b}",
        "a\u{feff}",
        "a\u{2028}",
        "a\u{2029}",
        "a\n",
        "a\u{00ad}",
    ] {
        let mut p = params();
        p["display_name"] = json!(display);
        assert_eq!(run(&p), invalid);
    }
    let mut p = params();
    p["display_name"] = json!("é".repeat(64));
    assert_eq!(run(&p), SecretError::NotFound.body());
    p["display_name"] = json!(format!("{}a", "é".repeat(64)));
    assert_eq!(run(&p), SecretError::LimitExceeded.body());
    for path in ["/repos/a?x=1", "/repos/a#f", "/a//b", "/a/%2e", "/a/%25"] {
        let mut p = params();
        p["target"]["path"] = json!(path);
        assert_eq!(run(&p), invalid);
    }
    for key in ["name", "stamp", "display_name", "target"] {
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
