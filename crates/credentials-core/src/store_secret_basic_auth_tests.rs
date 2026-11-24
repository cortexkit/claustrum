use super::*;
use crate::agent_secret::SecretUseByTarget;

fn by_target(call: SecretUse) -> SecretUseByTarget {
    SecretUseByTarget {
        sender: call.sender,
        scope: call.scope,
        worker_parent: call.worker_parent,
        coverage: call.coverage,
        agent_id: call.agent_id,
        target: call.target,
    }
}

fn basic_scope() -> SecretScope {
    SecretScope::ApiKey {
        host: "x.test".into(),
        path_prefix: Some("/repos/a".into()),
        location: "authorization_basic:git".into(),
    }
}

fn selected_reply(store: &EncryptedStore, call: &SecretUseByTarget) -> Value {
    store
        .secret_use_by_target(call, || NOW)
        .map_or_else(|e| e.body(), |o| o.reply)
}

#[test]
fn nameless_basic_miss_records_an_unaddressed_refusal_diagnostic() {
    let (_root, store) = setup("basic-miss-diagnostic");
    let query = "SELECT COUNT(*) FROM auth_events WHERE credential_id='secret-use|unaddressed' AND detail='unknown_name'";
    assert_eq!(count(&store, query), 0);
    assert_eq!(
        selected_reply(&store, &by_target(call())),
        SecretError::NotFound.body()
    );
    assert_eq!(count(&store, query), 1);
}

#[test]
fn nameless_basic_repeat_release_does_not_take_another_write() {
    let (_root, store) = setup("basic-repeat-read");
    sql(&store, "DELETE FROM agent_secrets");
    seed(
        &store,
        "key",
        &basic_scope(),
        &SecretMaterial::ApiKey(Secret::new(b"token".to_vec())),
    );
    grant(&store, "hour", "hour", NOW + 3_600_000, NOW);
    let request = by_target(call());

    let first_write = store.subscribe_writes();
    assert_eq!(selected_reply(&store, &request)["status"], "released");
    assert!(first_write.has_changed().unwrap());

    let repeat_write = store.subscribe_writes();
    assert_eq!(selected_reply(&store, &request)["status"], "released");
    assert!(!repeat_write.has_changed().unwrap());
}

#[test]
fn nameless_never_selects_bearer_header_query_login_or_local_secrets() {
    let (_root, store) = setup("basic-excluded");
    for (name, location) in [
        ("bearer", "authorization_bearer"),
        ("query", "query:key"),
        ("pointer", "json_pointer:/key"),
    ] {
        let mut scope = basic_scope();
        if let SecretScope::ApiKey {
            location: value, ..
        } = &mut scope
        {
            *value = location.into();
        }
        seed(
            &store,
            name,
            &scope,
            &SecretMaterial::ApiKey(Secret::new(b"token".to_vec())),
        );
    }
    seed(
        &store,
        "login",
        &SecretScope::SiteLogin {
            origin: "https://x.test".into(),
        },
        &SecretMaterial::SiteLogin {
            username: Secret::new("git".into()),
            password: Secret::new("token".into()),
            otpauth: None,
        },
    );
    seed(
        &store,
        "local",
        &SecretScope::LocalProgram {
            program: agent_secret::LocalProgram::Sudo,
            r#use: agent_secret::LocalProgramUse::SudoPassword,
            targets: vec![agent_secret::LocalProgramTarget::Sudo {
                user: "root".into(),
            }],
        },
        &SecretMaterial::LocalProgram(Secret::new("password".into())),
    );
    let mut missing = call();
    missing.name = "missing".into();
    assert_eq!(
        serde_json::to_vec(&selected_reply(&store, &by_target(call()))).unwrap(),
        serde_json::to_vec(&use_reply(&store, &missing, NOW)).unwrap()
    );
    assert_eq!(
        count(&store, "SELECT count(*) FROM secret_pending_requests"),
        0
    );
}

#[test]
fn nameless_replies_are_byte_identical_to_named_pending_and_release_with_setting_off() {
    let (_root, store) = setup("basic-identical");
    sql(&store, "DELETE FROM agent_secrets");
    seed(
        &store,
        "key",
        &basic_scope(),
        &SecretMaterial::ApiKey(Secret::new(vec![0, 255, b':', b'\n'])),
    );
    let request = by_target(call());
    let named = use_reply(&store, &call(), NOW);
    assert_eq!(named["status"], "approval_required");
    assert_eq!(
        serde_json::to_vec(&named).unwrap(),
        serde_json::to_vec(&selected_reply(&store, &request)).unwrap()
    );
    assert_eq!(
        count(&store, "SELECT count(*) FROM secret_pending_requests"),
        1
    );
    grant(&store, "hour", "hour", NOW + 3_600_000, NOW);
    for _ in 0..2 {
        let named = use_reply(&store, &call(), NOW);
        assert_eq!(named["location"], "authorization_basic:git");
        assert_eq!(named["key_b64url"], "AP86Cg");
        assert_eq!(
            serde_json::to_vec(&named).unwrap(),
            serde_json::to_vec(&selected_reply(&store, &request)).unwrap()
        );
    }
}

#[test]
fn nameless_ambiguous_coverage_ignores_grants_and_changes_nothing() {
    let (_root, store) = setup("basic-ambiguous");
    sql(&store, "DELETE FROM agent_secrets");
    for name in ["key", "other"] {
        seed(
            &store,
            name,
            &basic_scope(),
            &SecretMaterial::ApiKey(Secret::new(b"token".to_vec())),
        );
    }
    grant(&store, "once", "once", NOW + 1000, NOW);
    let audit = count(&store, "SELECT count(*) FROM audit_log");
    assert_eq!(
        selected_reply(&store, &by_target(call())),
        SecretError::Ambiguous.body()
    );
    assert_eq!(count(&store, "SELECT count(*) FROM audit_log"), audit);
    assert_eq!(count(&store, "SELECT count(*) FROM secret_grants"), 1);
    assert_eq!(
        count(&store, "SELECT count(*) FROM secret_pending_requests"),
        0
    );
    sql(
        &store,
        "UPDATE agent_secrets SET state='corrupt' WHERE name='other'",
    );
    assert_eq!(
        selected_reply(&store, &by_target(call()))["status"],
        "released"
    );
}

#[test]
fn nameless_refuses_cerebellum_basal_flow_and_non_https_443_targets_uniformly() {
    let (_root, store) = setup("basic-admission");
    seed(
        &store,
        "basic",
        &basic_scope(),
        &SecretMaterial::ApiKey(Secret::new(b"token".to_vec())),
    );
    for sender in [SecretSender::Cerebellum, SecretSender::Basal] {
        let mut request = by_target(call());
        request.sender = sender;
        assert_eq!(
            selected_reply(&store, &request),
            SecretError::NotFound.body()
        );
    }
    for kind in ["flow", "ephemeral"] {
        let mut request = by_target(call());
        request.scope.kind = kind.into();
        assert_eq!(
            selected_reply(&store, &request),
            SecretError::NotFound.body()
        );
    }
    for (scheme, port) in [("http", 443), ("https", 80), ("https", 444)] {
        let mut request = by_target(call());
        if let agent_secret::UseTarget::ApiKey {
            scheme: s, port: p, ..
        } = &mut request.target
        {
            *s = scheme.into();
            *p = port;
        }
        assert_eq!(
            selected_reply(&store, &request),
            SecretError::NotFound.body()
        );
    }
    assert_eq!(
        count(&store, "SELECT count(*) FROM secret_pending_requests"),
        0
    );
}

#[test]
fn nameless_multi_host_scope_counts_secrets_not_matching_rules() {
    let (_root, store) = setup("basic-rules");
    let scope = SecretScope::ApiKeyRules {
        rules: vec![
            agent_secret::SecretRule {
                host: "*.x.test".into(),
                path_prefix: None,
            },
            agent_secret::SecretRule {
                host: "sub.x.test".into(),
                path_prefix: Some("/repos".into()),
            },
        ],
        location: "authorization_basic:git@example.test".into(),
    };
    let incarnation = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let blob = agent_secret::seal(
        &store.key,
        incarnation,
        "rules",
        &scope,
        &SecretMaterial::ApiKey(Secret::new(b"token".to_vec())),
    )
    .unwrap();
    store.fenced_write(|tx| tx.execute("INSERT INTO agent_secrets (name,kind,incarnation,state,location,record_version,key_id,envelope,created_at_ms,scope_json) VALUES ('rules','agent_api_key',?1,'active','authorization_basic:git@example.test',1,?2,?3,?4,?5)", rusqlite::params![incarnation, store.key_id.to_hex(), blob, NOW, scope.scope_json().unwrap()]).map(|_| ())).unwrap();
    let mut named = call();
    named.name = "rules".into();
    if let agent_secret::UseTarget::ApiKey { host, .. } = &mut named.target {
        *host = "sub.x.test".into();
    }
    let expected = use_reply(&store, &named, NOW);
    assert_eq!(expected["status"], "approval_required");
    assert_eq!(
        serde_json::to_vec(&expected).unwrap(),
        serde_json::to_vec(&selected_reply(&store, &by_target(named))).unwrap()
    );
}
