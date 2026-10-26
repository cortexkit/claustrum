use super::*;
use crate::{secret::Secret, store::taxonomy_tests::rig};
use std::sync::{Arc, Barrier};

#[path = "store_secret_approval_tests.rs"]
mod approval_tests;

const MEMBER: &str = "fed-computer:22222222222222222222222222222222";
const NOW: i64 = 1_700_000_000_000;
fn scope() -> SecretScope {
    SecretScope::ApiKey {
        host: "x.test".into(),
        path_prefix: Some("/repos/a".into()),
        location: "header:X-Api-Key".into(),
    }
}
fn call() -> SecretUse {
    SecretUse {
        name: "key".into(),
        sender: SecretSender::Aft,
        scope: AskingScope {
            owner: "reserved:prefrontal-core".into(),
            kind: "head".into(),
            scope_ref: "H".into(),
            epoch: 7,
        },
        worker_parent: None,
        coverage: "scope".into(),
        agent_id: Some("agent-A".into()),
        display_name: "Alice".into(),
        target: agent_secret::UseTarget::ApiKey {
            scheme: "https".into(),
            host: "x.test".into(),
            port: 443,
            path: "/repos/a/canary-token".into(),
        },
    }
}
fn seed(store: &EncryptedStore, name: &str, scope: &SecretScope, material: &SecretMaterial) {
    let incarnation = format!("{:032x}", name.bytes().map(u64::from).sum::<u64>());
    let blob = agent_secret::seal(&store.key, &incarnation, name, scope, material).unwrap();
    let (host, prefix, location, origin) = phone::columns(scope);
    store.fenced_write(|tx|tx.execute("INSERT INTO agent_secrets (name,kind,incarnation,state,host,path_prefix,location,origin,record_version,key_id,envelope,created_at_ms) VALUES (?1,?2,?3,'active',?4,?5,?6,?7,1,?8,?9,?10)",rusqlite::params![name,scope.kind(),incarnation,host,prefix,location,origin,store.key_id.to_hex(),blob,NOW]).map(|_|())).unwrap();
}
fn setup(tag: &str) -> (crate::test_support::TestTempDir, Arc<EncryptedStore>) {
    let (root, store) = rig(tag, 65);
    store
        .set_federation_self_member_audited(MEMBER, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    seed(
        &store,
        "key",
        &scope(),
        &SecretMaterial::ApiKey(Secret::new(b"material-canary".to_vec())),
    );
    (root, Arc::new(store))
}
fn sql(store: &EncryptedStore, query: &str) {
    store.store.with_conn(|c| c.execute_batch(query)).unwrap();
}
fn count(store: &EncryptedStore, query: &str) -> i64 {
    store
        .store
        .with_conn(|c| c.query_row(query, [], |r| r.get(0)))
        .unwrap()
}
fn grant(store: &EncryptedStore, id: &str, duration: &str, expiry: i64, created: i64) {
    store.fenced_write(|tx|tx.execute("INSERT INTO secret_grants (grant_id,secret_name,incarnation,scope_owner,scope_kind,scope_ref,coverage,duration,expires_at_ms,granted_at_ms,envelope_sha256) SELECT ?1,name,incarnation,'reserved:prefrontal-core','head','H','scope',?2,?3,?4,'envelope-hash' FROM agent_secrets WHERE name='key'",rusqlite::params![id,duration,expiry,created]).map(|_|())).unwrap();
}
fn use_reply(store: &EncryptedStore, call: &SecretUse, now: i64) -> Value {
    store
        .secret_use(call, || now)
        .map_or_else(|e| e.body(), |o| o.reply)
}

#[test]
fn secret_targets_enforce_raw_path_segments_and_exact_https_authority() {
    for path in ["/", "/repos/a", "/repos/a/", "/repos/a/x", "/repos/%7E"] {
        assert!(agent_secret::validate_path(path).is_ok(), "{path}");
    }
    for path in [
        "/repos/a/../ab",
        "/repos/a%2F..%2Fb",
        "/repos//a",
        "/repos/a/x\\..\\..\\b",
        "/repos/a/%5C..%5cb",
        "/repos/a/..;/b",
        "/repos/a/.;/b",
        "/repos/a/%00",
        "/repos/a?x=1",
        "/repos/a#f",
        "/a b",
        "/a\n",
        "/é",
        "/%2e",
        "/%25",
        "/%3B",
        "/%7f",
        "/a[0]",
        "/a|b",
        "/%xx",
    ] {
        assert!(agent_secret::validate_path(path).is_err(), "{path}");
    }
    for prefix in ["/", "/repos/a/", ""] {
        let s = SecretScope::ApiKey {
            host: "x.test".into(),
            path_prefix: Some(prefix.into()),
            location: "authorization_bearer".into(),
        };
        assert!(agent_secret::validate_scope(&s).is_err());
    }
    let target = |scheme: &str, host: &str, port, path: &str| agent_secret::UseTarget::ApiKey {
        scheme: scheme.into(),
        host: host.into(),
        port,
        path: path.into(),
    };
    for path in ["/repos/a", "/repos/a/", "/repos/a/x"] {
        assert!(
            target("https", "x.test", 443, path).matches(&scope()),
            "segment prefix must cover a child"
        );
    }
    for (scheme, host, port, path) in [
        ("http", "x.test", 443, "/repos/a"),
        ("https", "y.test", 443, "/repos/a"),
        ("https", "x.test", 444, "/repos/a"),
        ("https", "x.test", 443, "/repos/ab"),
    ] {
        assert!(
            !target(scheme, host, port, path).matches(&scope()),
            "exact HTTPS host and port, with segment-boundary prefix, are required"
        );
    }
    let mut s = scope();
    if let SecretScope::ApiKey { path_prefix, .. } = &mut s {
        *path_prefix = Some("/repos/~".into());
    }
    assert!(!target("https", "x.test", 443, "/repos/%7E").matches(&s));
    if let SecretScope::ApiKey { path_prefix, .. } = &mut s {
        *path_prefix = None;
    }
    for path in ["/", "/x/y"] {
        assert!(target("https", "x.test", 443, path).matches(&s));
    }
    let s = SecretScope::SiteLogin {
        origin: "https://x.test".into(),
    };
    for (origin, expected) in [
        ("https://x.test", true),
        ("https://x.test:443", true),
        ("http://x.test", false),
        ("https://y.test", false),
        ("https://x.test:444", false),
    ] {
        assert_eq!(
            agent_secret::UseTarget::SiteLogin {
                origin: origin.into()
            }
            .matches(&s),
            expected,
            "origin must match exactly modulo default port"
        );
    }
}

#[test]
fn secret_release_is_by_kind_and_sender_only() {
    let (_root, store) = setup("secret-release-kind");
    grant(&store, "g", "permanent", 0, NOW);
    let reply = use_reply(&store, &call(), NOW);
    assert_eq!(
        reply,
        json!({"status":"released","kind":"agent_api_key","key_b64url":"bWF0ZXJpYWwtY2FuYXJ5","location":"header:X-Api-Key"}),
        "AFT receives key bytes and location only"
    );
    let mut wrong = call();
    wrong.sender = SecretSender::Cerebellum;
    assert_eq!(
        use_reply(&store, &wrong, NOW),
        SecretError::NotFound.body(),
        "Cerebellum cannot receive an API key"
    );
    let login = SecretScope::SiteLogin {
        origin: "https://x.test".into(),
    };
    seed(
        &store,
        "login",
        &login,
        &SecretMaterial::SiteLogin {
            username: Secret::new("user".into()),
            password: Secret::new("password-canary".into()),
            otpauth: Some(Secret::new(
                "otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8".into(),
            )),
        },
    );
    sql(&store,"UPDATE secret_grants SET secret_name='login',incarnation=(SELECT incarnation FROM agent_secrets WHERE name='login'),first_released=0");
    let mut login_call = call();
    login_call.name = "login".into();
    login_call.target = agent_secret::UseTarget::SiteLogin {
        origin: "https://x.test:443".into(),
    };
    assert_eq!(
        use_reply(&store, &login_call, 59_000),
        SecretError::NotFound.body(),
        "AFT cannot receive a login"
    );
    login_call.sender = SecretSender::Cerebellum;
    assert_eq!(
        use_reply(&store, &login_call, 59_000),
        json!({"status":"released","kind":"site_login","username":"user","password":"password-canary","totp":"94287082"})
    );
    let audit = store.read_audit(None).unwrap();
    assert!(!format!("{audit:?}").contains("canary"));
}

#[test]
fn secret_pending_reuse_caps_cleanup_and_member_binding() {
    let (_root, store) = setup("secret-pending");
    let mut c = call();
    let first = use_reply(&store, &c, NOW);
    assert_eq!(first["status"], "approval_required");
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(first["statement_b64url"].as_str().unwrap())
        .unwrap();
    let statement: Value = serde_json::from_slice(&decoded).unwrap();
    assert_eq!(statement["v"], "ck-secret-use-statement/v1");
    assert_eq!(
        statement["scope"],
        json!({"owner":"reserved:prefrontal-core","kind":"head","ref":"H","epoch":7})
    );
    assert_eq!(
        statement["use"],
        json!({"host":"x.test","path_prefix":"/repos/a","location":"header:X-Api-Key"})
    );
    assert_eq!(
        statement["durations"],
        json!(["once", "hour", "session", "permanent"])
    );
    assert!(!String::from_utf8(decoded.clone())
        .unwrap()
        .contains("canary-token"));
    let id = first["request_id"].as_str().unwrap();
    let golden = format!(
        r#"{{"agent":"Alice","coverage":"scope","durations":["once","hour","session","permanent"],"member_id":"fed-computer:22222222222222222222222222222222","request_expires_at_ms":1700000600000,"request_id":"{id}","scope":{{"epoch":7,"kind":"head","owner":"reserved:prefrontal-core","ref":"H"}},"secret":{{"incarnation":"00000000000000000000000000000149","kind":"agent_api_key","name":"key"}},"use":{{"host":"x.test","location":"header:X-Api-Key","path_prefix":"/repos/a"}},"v":"ck-secret-use-statement/v1"}}"#
    );
    assert_eq!(
        decoded,
        golden.as_bytes(),
        "statement bytes follow the independently written JCS golden"
    );
    if let agent_secret::UseTarget::ApiKey { path, .. } = &mut c.target {
        *path = "/repos/a/other".into();
    }
    c.agent_id = Some("different".into());
    assert_eq!(
        use_reply(&store, &c, NOW + SECRET_PENDING_LIFETIME_LIMIT_MS - 1),
        first,
        "reuse is live strictly before expiry and ignores requested path and attribution"
    );
    assert_ne!(
        use_reply(&store, &c, NOW + SECRET_PENDING_LIFETIME_LIMIT_MS)["request_id"],
        first["request_id"]
    );
    assert_eq!(
        count(&store, "SELECT COUNT(*) FROM secret_pending_requests"),
        1
    );
    sql(&store, "DELETE FROM secret_pending_requests");
    for i in 0..MAX_SECRET_PENDING_PER_SCOPE {
        let name = format!("key{i}");
        seed(
            &store,
            &name,
            &scope(),
            &SecretMaterial::ApiKey(Secret::new(vec![1])),
        );
        c.name = name;
        assert_eq!(use_reply(&store, &c, NOW)["status"], "approval_required");
    }
    c.name = "key".into();
    assert_eq!(
        use_reply(&store, &c, NOW),
        SecretError::PendingLimit.body(),
        "ninth approval in a mapped scope is refused"
    );
    sql(
        &store,
        "UPDATE secret_pending_requests SET request_kind='delete'",
    );
    assert_eq!(
        use_reply(&store, &c, NOW)["status"],
        "approval_required",
        "delete requests do not count"
    );
    sql(&store, "DELETE FROM secret_pending_requests");
    for i in 0..MAX_SECRET_PENDING_TOTAL {
        c.scope.scope_ref = format!("H{i}");
        assert_eq!(use_reply(&store, &c, NOW)["status"], "approval_required");
    }
    c.scope.scope_ref = "next".into();
    assert_eq!(
        use_reply(&store, &c, NOW),
        SecretError::PendingLimit.body(),
        "65th approval is refused"
    );
    sql(&store,"UPDATE secret_pending_requests SET consumed=1 WHERE request_id=(SELECT request_id FROM secret_pending_requests LIMIT 1)");
    assert_eq!(use_reply(&store, &c, NOW)["status"], "approval_required");
    assert_eq!(
        count(&store, "SELECT COUNT(*) FROM secret_pending_requests"),
        64
    );
    let member = "fed-computer:33333333333333333333333333333333";
    store
        .set_federation_self_member_audited(member, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    let fresh = use_reply(&store, &c, NOW);
    assert_eq!(fresh["status"], "approval_required");
    assert_eq!(
        count(&store, "SELECT COUNT(*) FROM secret_pending_requests"),
        1
    );
    assert!(String::from_utf8(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(fresh["statement_b64url"].as_str().unwrap())
            .unwrap()
    )
    .unwrap()
    .contains(member));
    for i in 1..=65 {
        assert_eq!(
            use_reply(&store, &c, NOW + i * SECRET_PENDING_LIFETIME_LIMIT_MS)["status"],
            "approval_required"
        );
        assert_eq!(
            count(&store, "SELECT COUNT(*) FROM secret_pending_requests"),
            1,
            "more than 64 expired requests are removed, not retained"
        );
    }
}

#[test]
fn secret_statement_jcs_pins_unicode_and_escaping_without_normalizing() {
    let (_root, store) = setup("secret-jcs");
    let mut c = call();
    c.display_name = "Al\"ice\\é".into();
    c.scope.scope_ref = "H\u{1}".into();
    let reply = use_reply(&store, &c, NOW);
    let id = reply["request_id"].as_str().unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(reply["statement_b64url"].as_str().unwrap())
        .unwrap();
    let golden = format!(
        r#"{{"agent":"Al\"ice\\é","coverage":"scope","durations":["once","hour","session","permanent"],"member_id":"fed-computer:22222222222222222222222222222222","request_expires_at_ms":1700000600000,"request_id":"{id}","scope":{{"epoch":7,"kind":"head","owner":"reserved:prefrontal-core","ref":"H\u0001"}},"secret":{{"incarnation":"00000000000000000000000000000149","kind":"agent_api_key","name":"key"}},"use":{{"host":"x.test","location":"header:X-Api-Key","path_prefix":"/repos/a"}},"v":"ck-secret-use-statement/v1"}}"#
    );
    assert_eq!(
        bytes,
        golden.as_bytes(),
        "JCS escaping and UTF-8 are pinned independently of the serializer"
    );
}

#[test]
fn secret_grant_choice_total_order_and_marker_are_persistent() {
    let (_root, store) = setup("secret-order");
    grant(&store, "once", "once", NOW + 5000, NOW);
    grant(&store, "hour", "hour", NOW + 5000, NOW);
    grant(&store, "permanent", "permanent", 0, NOW);
    assert_eq!(use_reply(&store, &call(), NOW)["status"], "released");
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM secret_grants WHERE first_released=1 AND grant_id='permanent'"
        ),
        1,
        "permanent serves before hour and once"
    );
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM secret_grants WHERE last_use_ms IS NOT NULL"
        ),
        1
    );
    assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_grants"), 3);
    // Trimming all diagnostics and even reading a later audit tip must not reset the marker.
    sql(&store, "DELETE FROM auth_events");
    assert_eq!(use_reply(&store, &call(), NOW + 1)["status"], "released");
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM audit_log WHERE op='secret_first_release'"
        ),
        1
    );
    sql(
        &store,
        "DELETE FROM secret_grants WHERE grant_id='permanent'",
    );
    assert_eq!(use_reply(&store, &call(), NOW)["status"], "released");
    assert_eq!(
        count(
            &store,
            "SELECT first_released FROM secret_grants WHERE grant_id='hour'"
        ),
        1,
        "equal-expiry hour beats once and is not consumed"
    );
    grant(&store, "later", "hour", NOW + 6000, NOW + 1);
    assert_eq!(use_reply(&store, &call(), NOW)["status"], "released");
    assert_eq!(
        count(
            &store,
            "SELECT first_released FROM secret_grants WHERE grant_id='later'"
        ),
        1
    );
    grant(&store, "early", "hour", NOW + 6000, NOW - 1);
    grant(&store, "a", "hour", NOW + 6000, NOW - 1);
    assert_eq!(use_reply(&store, &call(), NOW)["status"], "released");
    assert_eq!(
        count(
            &store,
            "SELECT first_released FROM secret_grants WHERE grant_id='a'"
        ),
        1,
        "earlier creation then lower id break ties"
    );
}

#[test]
fn secret_once_is_atomic_and_first_release_is_once_per_grant() {
    for duration in ["once", "permanent"] {
        let (_root, store) = setup(&format!("secret-concurrent-{duration}"));
        grant(
            &store,
            "g",
            duration,
            if duration == "once" { NOW + 600_000 } else { 0 },
            NOW,
        );
        let barrier = Arc::new(Barrier::new(3));
        let threads = (0..2)
            .map(|_| {
                let (s, b) = (Arc::clone(&store), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    b.wait();
                    use_reply(&s, &call(), NOW)
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let replies = threads
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            replies.iter().filter(|r| r["status"] == "released").count(),
            if duration == "once" { 1 } else { 2 },
            "once must release to exactly one concurrent caller"
        );
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM audit_log WHERE op='secret_first_release'"
            ),
            1,
            "concurrent first use writes one transition"
        );
        assert_eq!(
            count(&store, "SELECT COUNT(*) FROM secret_grants"),
            if duration == "once" { 0 } else { 1 }
        );
    }
}

#[test]
fn secret_duration_boundaries_sweep_only_after_valid_step_four() {
    for (duration, lifetime) in [
        ("once", 600_000),
        ("hour", 3_600_000),
        ("session", 86_400_000),
    ] {
        let (_root, store) = setup(&format!("secret-expiry-{duration}"));
        grant(&store, "expired", duration, NOW + lifetime, NOW);
        let mut c = call();
        c.name = "absent".into();
        assert_eq!(
            use_reply(&store, &c, NOW + lifetime),
            SecretError::NotFound.body()
        );
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM audit_log WHERE op='secret_grant_expire'"
            ),
            0
        );
        assert_eq!(
            use_reply(&store, &call(), NOW + lifetime)["status"],
            "approval_required"
        );
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM audit_log WHERE op='secret_grant_expire'"
            ),
            1
        );
        assert_eq!(
            use_reply(&store, &call(), NOW + lifetime)["status"],
            "approval_required"
        );
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM audit_log WHERE op='secret_grant_expire'"
            ),
            1
        );
        grant(&store, "live", duration, NOW + lifetime, NOW);
        assert_eq!(
            use_reply(&store, &call(), NOW + lifetime - 1)["status"],
            "released"
        );
    }
}

#[test]
fn secret_audit_failure_keeps_once_and_last_use_failure_does_not_block() {
    let (_root, store) = setup("secret-rollback");
    grant(&store, "once", "once", NOW + 600_000, NOW);
    sql(&store,"CREATE TRIGGER fail_release BEFORE INSERT ON audit_log WHEN NEW.op='secret_first_release' BEGIN SELECT RAISE(FAIL,'injected'); END;");
    assert_eq!(
        use_reply(&store, &call(), NOW),
        SecretError::StoreError.body()
    );
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM secret_grants WHERE grant_id='once'"
        ),
        1
    );
    sql(&store, "DROP TRIGGER fail_release");
    assert_eq!(use_reply(&store, &call(), NOW)["status"], "released");
    grant(&store, "permanent", "permanent", 0, NOW);
    assert_eq!(use_reply(&store, &call(), NOW)["status"], "released");
    sql(&store,"CREATE TRIGGER fail_last_use BEFORE UPDATE OF last_use_ms ON secret_grants BEGIN SELECT RAISE(FAIL,'injected'); END;");
    let outcome = store.secret_use(&call(), || NOW + 1).unwrap();
    assert_eq!(outcome.reply["status"], "released");
    let (id, now) = outcome.last_use.unwrap();
    store.secret_use_last_use(&id, now);
    assert_eq!(
        count(
            &store,
            "SELECT last_use_ms FROM secret_grants WHERE grant_id='permanent'"
        ),
        NOW
    );
}

#[test]
fn secret_uniform_refusal_and_quarantine_flip_are_opaque_even_on_write_failure() {
    let (_root, store) = setup("secret-quarantine");
    let expected = serde_json::to_vec(&SecretError::NotFound.body()).unwrap();
    let mut c = call();
    for mode in ["unknown", "kind", "target", "corrupt"] {
        c.name = if mode == "unknown" {
            "absent".into()
        } else {
            "key".into()
        };
        c.sender = if mode == "kind" {
            SecretSender::Cerebellum
        } else {
            SecretSender::Aft
        };
        if let agent_secret::UseTarget::ApiKey { host, .. } = &mut c.target {
            *host = if mode == "target" {
                "other.test".into()
            } else {
                "x.test".into()
            };
        }
        if mode == "corrupt" {
            sql(&store, "UPDATE agent_secrets SET state='corrupt'");
        }
        assert_eq!(
            serde_json::to_vec(&use_reply(&store, &c, NOW)).unwrap(),
            expected,
            "not_found is byte-identical"
        );
    }
    assert_eq!(
        count(&store, "SELECT COUNT(*) FROM secret_pending_requests"),
        0
    );
    sql(
        &store,
        "UPDATE agent_secrets SET state='active',host='changed.test'",
    );
    sql(&store,"CREATE TRIGGER fail_quarantine BEFORE INSERT ON audit_log WHEN NEW.op='secret_quarantine' BEGIN SELECT RAISE(FAIL,'injected'); END; CREATE TRIGGER fail_auth BEFORE INSERT ON auth_events BEGIN SELECT RAISE(FAIL,'injected'); END;");
    assert_eq!(
        serde_json::to_vec(&use_reply(&store, &call(), NOW)).unwrap(),
        expected
    );
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM agent_secrets WHERE state='active'"
        ),
        1
    );
    sql(
        &store,
        "DROP TRIGGER fail_quarantine; DROP TRIGGER fail_auth;",
    );
    for _ in 0..2 {
        assert_eq!(
            serde_json::to_vec(&use_reply(&store, &call(), NOW)).unwrap(),
            expected
        );
    }
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM audit_log WHERE op='secret_quarantine'"
        ),
        1,
        "one row per active-to-corrupt flip"
    );
    assert_eq!(
        count(&store, "SELECT COUNT(*) FROM secret_pending_requests"),
        0
    );
}

#[test]
fn secret_scope_coverage_isolates_owner_kind_ref_and_worker_parent() {
    let (_root, store) = setup("secret-scope");
    grant(&store, "head", "permanent", 0, NOW);
    let mut c = call();
    c.scope.owner = "reserved:other".into();
    assert_eq!(
        use_reply(&store, &c, NOW)["status"],
        "approval_required",
        "same ref on another owner is isolated"
    );
    c = call();
    c.scope.kind = "worker".into();
    c.scope.scope_ref = "W".into();
    c.worker_parent = Some(call().scope);
    assert_eq!(
        use_reply(&store, &c, NOW)["status"],
        "approval_required",
        "a scope grant on a Head does not cover its Worker"
    );
    sql(
        &store,
        "UPDATE secret_grants SET coverage='agent_and_workers'",
    );
    assert_eq!(
        use_reply(&store, &c, NOW)["status"],
        "released",
        "Head agent_and_workers coverage serves a mapped Worker"
    );
    for mode in ["absent", "owner", "ref"] {
        c.worker_parent = Some(call().scope);
        match mode {
            "absent" => c.worker_parent = None,
            "owner" => c.worker_parent.as_mut().unwrap().owner = "reserved:other".into(),
            "ref" => c.worker_parent.as_mut().unwrap().scope_ref = "other-H".into(),
            _ => unreachable!(),
        }
        assert_eq!(
            use_reply(&store, &c, NOW)["status"],
            "approval_required",
            "Worker parent must identify the exact Head: {mode}"
        );
    }
    sql(
        &store,
        "UPDATE secret_grants SET scope_kind='worker',scope_ref='W',coverage='scope'",
    );
    assert_eq!(
        use_reply(&store, &call(), NOW)["status"],
        "approval_required",
        "a Worker grant cannot serve its Head"
    );
    assert_eq!(
        use_reply(&store, &c, NOW)["status"],
        "released",
        "a Worker scope grant needs no parent"
    );
}

#[test]
fn secret_refusal_partitions_are_bounded_and_credential_writers_cannot_trim_them() {
    let (_root, store) = setup("secret-diagnostics");
    store.record_secret_use_refusal(SecretSender::Aft, Some("use"), "target");
    for i in 0..AUTH_EVENTS_PER_CREDENTIAL + 1 {
        let mut c = call();
        c.name = format!("unknown{i}");
        assert_eq!(use_reply(&store, &c, NOW), SecretError::NotFound.body());
    }
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM auth_events WHERE credential_id='secret-use|unaddressed'"
        ),
        AUTH_EVENTS_PER_CREDENTIAL as i64
    );
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM auth_events WHERE credential_id='secret|use'"
        ),
        1
    );
    let observation = || AuthObservation {
        kind: AuthEventKind::ScopedReadRefusal.as_str(),
        provider_status: None,
        detail: Some("test"),
        reporter_source: None,
        principal: Some(AuthEventPrincipal::Direct),
    };
    for _ in 0..AUTH_EVENTS_PER_CREDENTIAL + 1 {
        store
            .record_auth_event("secret|use", observation(), None)
            .unwrap();
        store
            .record_scoped_read_refusal("secret|use", "direct", None, ScopedReadRefusal::NoGrant)
            .unwrap();
    }
    store
        .record_scoped_first_use("secret|use", "direct", None, GrantOperation::Read)
        .unwrap();
    store
        .record_stale_refresh_deferred("secret|use", 1)
        .unwrap();
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM auth_events WHERE credential_id='secret|use'"
        ),
        1,
        "credential probes cannot enter the secret partition"
    );
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM auth_events WHERE credential_id='credential.invalid_id'"
        ),
        AUTH_EVENTS_PER_CREDENTIAL as i64
    );
    store
        .record_auth_event("secret:use", observation(), None)
        .unwrap();
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM auth_events WHERE credential_id='secret:use'"
        ),
        1
    );
    assert!(!format!("{:?}", store.recent_auth_events(1000).unwrap()).contains("canary-token"));
}
