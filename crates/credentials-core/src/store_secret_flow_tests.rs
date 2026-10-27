use super::*;
use agent_secret::{FlowIdentity, SecretFlowApproval, SecretFlowUse, UseTarget};
use sha2::{Digest, Sha256};

fn identity() -> FlowIdentity {
    FlowIdentity {
        flow_id: "daily-fetch".into(),
        version: 7,
        code_hash: "0123456789abcdef".repeat(4),
        install_id: "install-A".into(),
    }
}

fn install() -> SecretFlowApproval {
    SecretFlowApproval {
        name: "key".into(),
        flow: identity(),
        target: call().target,
        methods: Some(vec!["GET".into()]),
    }
}

fn run() -> SecretFlowUse {
    SecretFlowUse {
        name: "key".into(),
        flow: identity(),
        target: call().target,
        method: Some("GET".into()),
    }
}

fn request(store: &EncryptedStore, call: &SecretFlowApproval, now: i64) -> Value {
    store
        .secret_request_flow_approval(call, || now)
        .map_or_else(|e| e.body(), |o| o.reply)
}

fn release_flow(store: &EncryptedStore, call: &SecretFlowUse, now: i64) -> Value {
    match store.secret_flow_use(call, || now) {
        Ok(outcome) => {
            if let Some((id, now)) = outcome.last_use {
                store.secret_use_last_use(&id, now);
            }
            outcome.reply
        }
        Err(error) => error.body(),
    }
}

fn registered(tag: &str) -> (crate::test_support::TestTempDir, Arc<EncryptedStore>) {
    let (root, store) = setup(tag);
    phone(
        &store,
        &PhoneOperation::Register {
            deposit_pub: vec![2; 32],
            approval_pub: signer()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        },
        NOW,
    )
    .unwrap();
    (root, store)
}

fn approve(store: &EncryptedStore, request: &Value) -> Vec<u8> {
    let bytes = serde_json::to_vec(&envelope(vec![item(request)], "version", NOW)).unwrap();
    assert_eq!(
        phone(store, &signed_bytes(bytes.clone(), false), NOW).unwrap(),
        json!({"results":[granted(request)]})
    );
    bytes
}

fn audit_rows(store: &EncryptedStore, op: &str) -> Vec<(String, String)> {
    store
        .store
        .with_conn(|c| {
            c.prepare("SELECT credential_id,payload_hash FROM audit_log WHERE op=?1 ORDER BY seq")?
                .query_map([op], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect()
        })
        .unwrap()
}

fn framed_hash(fields: &[&str]) -> String {
    let mut bytes = Vec::new();
    for field in fields {
        bytes.extend_from_slice(&(field.len() as u64).to_le_bytes());
        bytes.extend_from_slice(field.as_bytes());
    }
    format!("{:x}", Sha256::digest(bytes))
}

fn grant_rows(store: &EncryptedStore) -> Vec<(String, String, String, u64)> {
    store.store.with_conn(|c| {
        c.prepare("SELECT grant_id,incarnation,flow_id,flow_version FROM secret_flow_grants ORDER BY grant_id")?
            .query_map([], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?.collect()
    }).unwrap()
}

#[test]
fn secret_flow_pending_retries_bind_identity_methods_and_incarnation_not_target() {
    let (_root, store) = setup("flow-pending-retry");
    let mut c = install();
    c.methods = Some(vec!["POST".into(), "GET".into()]);
    let original = request(&store, &c, NOW);
    assert_eq!(original["status"], "approval_required");
    let statement: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(original["statement_b64url"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(statement["use"]["methods"], json!(["GET", "POST"]));
    assert_eq!(statement["use"]["path_prefix"], "/repos/a");
    assert_eq!(statement["flow"], serde_json::to_value(identity()).unwrap());
    assert_eq!(statement["durations"], json!(["version"]));
    c.methods.as_mut().unwrap().reverse();
    if let UseTarget::ApiKey { path, .. } = &mut c.target {
        *path = "/repos/a/other".into();
    }
    assert_eq!(request(&store, &c, NOW + 1), original);
    let agent = use_reply(&store, &call(), NOW);
    assert_ne!(agent["request_id"], original["request_id"]);
    assert_eq!(use_reply(&store, &call(), NOW + 1), agent);
    for field in 0..5 {
        let mut c = install();
        c.methods = Some(vec!["GET".into(), "POST".into()]);
        match field {
            0 => c.flow.flow_id.push('x'),
            1 => c.flow.version += 1,
            2 => c.flow.code_hash = "f".repeat(64),
            3 => c.flow.install_id.push('x'),
            _ => c.methods = Some(vec!["GET".into()]),
        }
        assert_ne!(
            request(&store, &c, NOW)["request_id"],
            original["request_id"]
        );
    }
    assert_eq!(
        count(&store, "SELECT COUNT(*) FROM secret_pending_requests"),
        7
    );
    assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_pending_requests WHERE flow_id IS NOT NULL AND (mapped_owner IS NOT NULL OR mapped_kind IS NOT NULL OR mapped_ref IS NOT NULL OR mapped_epoch IS NOT NULL OR coverage IS NOT NULL OR agent_id IS NOT NULL)"), 0);
    sql(&store, "DELETE FROM agent_secrets WHERE name='key'");
    seed(
        &store,
        "key",
        &scope(),
        &SecretMaterial::ApiKey(crate::secret::Secret::new(vec![9])),
    );
    // Re-sealing under a new incarnation models deletion and recreation of the same name.
    let incarnation = "f".repeat(32);
    let blob = agent_secret::seal(
        &store.key,
        &incarnation,
        "key",
        &scope(),
        &SecretMaterial::ApiKey(crate::secret::Secret::new(vec![9])),
    )
    .unwrap();
    store
        .store
        .with_conn(|c| {
            c.execute(
                "UPDATE agent_secrets SET incarnation=?1,envelope=?2 WHERE name='key'",
                rusqlite::params![incarnation, blob],
            )
            .map(|_| ())
        })
        .unwrap();
    let recreated = request(&store, &install(), NOW);
    assert_ne!(recreated["request_id"], original["request_id"]);
    let expired = request(&store, &install(), NOW + 86_400_000);
    assert_ne!(expired["request_id"], recreated["request_id"]);
    assert_eq!(
        count(&store, "SELECT COUNT(*) FROM secret_pending_requests"),
        1
    );
    assert!(audit_rows(&store, "secret_grant_create").is_empty());
}

#[test]
fn secret_flow_pending_lifetime_is_24_hours_and_cleanup_preserves_live_flows() {
    let (_root, store) = setup("flow-pending-lifetime");
    let first = request(&store, &install(), NOW);
    assert_eq!(first["status"], "approval_required");
    assert_eq!(first["expires_at_ms"], NOW + 86_400_000);
    let statement: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(first["statement_b64url"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(statement["request_expires_at_ms"], NOW + 86_400_000);
    let agent = use_reply(&store, &call(), NOW);
    assert_eq!(agent["expires_at_ms"], NOW + 600_000);
    for delta in [600_000, 82_800_000, 86_399_999] {
        let fresh_agent = use_reply(&store, &call(), NOW + delta);
        assert_eq!(fresh_agent["status"], "approval_required");
        assert_ne!(fresh_agent["request_id"], agent["request_id"]);
        assert_eq!(request(&store, &install(), NOW + delta), first);
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM secret_pending_requests WHERE flow_id IS NOT NULL"
            ),
            1
        );
    }
    assert_ne!(
        request(&store, &install(), NOW + 86_400_000)["request_id"],
        first["request_id"]
    );
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM secret_pending_requests WHERE flow_id IS NOT NULL"
        ),
        1
    );
}

#[test]
fn secret_flow_pending_per_install_allows_16_across_versions_and_refuses_17() {
    let (_root, store) = setup("flow-pending-install-limit");
    let mut c = install();
    let first = request(&store, &c, NOW);
    assert_eq!(first["status"], "approval_required");
    for version in 8..23 {
        c.flow.version = version;
        assert_eq!(request(&store, &c, NOW)["status"], "approval_required");
    }
    assert_eq!(
        count(&store, "SELECT COUNT(*) FROM secret_pending_requests"),
        16
    );
    c.flow.version = 23;
    assert_eq!(request(&store, &c, NOW), SecretError::PendingLimit.body());
    assert_eq!(
        request(&store, &install(), NOW + 1),
        first,
        "retry still succeeds at the limit"
    );
    assert_eq!(
        count(&store, "SELECT COUNT(*) FROM secret_pending_requests"),
        16
    );
    c.flow.install_id = "another-install".into();
    assert_eq!(request(&store, &c, NOW)["status"], "approval_required");
}

#[test]
fn secret_flow_pending_total_allows_256_and_refuses_257_independently_of_agents() {
    let (_root, store) = setup("flow-pending-total-limit");
    let mut agent = call();
    assert_eq!(
        use_reply(&store, &agent, NOW)["status"],
        "approval_required"
    );
    let mut c = install();
    let first = request(&store, &c, NOW);
    assert_eq!(first["status"], "approval_required");
    for n in 1..256 {
        c.flow.install_id = format!("install-{n}");
        assert_eq!(request(&store, &c, NOW)["status"], "approval_required");
    }
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM secret_pending_requests WHERE flow_id IS NOT NULL"
        ),
        256
    );
    c.flow.install_id = "one-too-many".into();
    assert_eq!(request(&store, &c, NOW), SecretError::PendingLimit.body());
    assert_eq!(request(&store, &install(), NOW + 1), first);
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM secret_pending_requests WHERE flow_id IS NOT NULL"
        ),
        256
    );
    agent.scope.scope_ref.push('x');
    assert_eq!(
        use_reply(&store, &agent, NOW)["status"],
        "approval_required",
        "256 live flow requests do not fill the agent pool"
    );
    assert_eq!(
        request(&store, &c, NOW + 86_400_000)["status"],
        "approval_required"
    );
    assert_eq!(
        count(&store, "SELECT COUNT(*) FROM secret_pending_requests"),
        1
    );
}

#[test]
fn secret_flow_pending_is_not_limited_by_64_live_agent_requests() {
    let (_root, store) = setup("flow-pending-agent-pool-full");
    let mut agent = call();
    for n in 0..64 {
        agent.scope.scope_ref = format!("H{n}");
        assert_eq!(
            use_reply(&store, &agent, NOW)["status"],
            "approval_required"
        );
    }
    agent.scope.scope_ref = "one-too-many".into();
    assert_eq!(
        use_reply(&store, &agent, NOW),
        SecretError::PendingLimit.body()
    );
    assert_eq!(
        request(&store, &install(), NOW)["status"],
        "approval_required"
    );
    assert_eq!(
        count(&store, "SELECT COUNT(*) FROM secret_pending_requests"),
        65
    );
}

#[test]
fn secret_flow_request_validation_precedes_lookup_and_store_failure_is_atomic() {
    let (_root, store) = setup("flow-request-errors");
    for name in ["key", "missing"] {
        for methods in [
            None,
            Some(vec![]),
            Some(vec!["get".into()]),
            Some(vec!["GET".into(), "GET".into()]),
        ] {
            let mut c = install();
            c.name = name.into();
            c.methods = methods;
            assert_eq!(request(&store, &c, NOW), SecretError::InvalidParams.body());
        }
        let mut c = install();
        c.name = name.into();
        c.target = UseTarget::SiteLogin {
            origin: "https://x.test".into(),
        };
        c.methods = None;
        assert_eq!(request(&store, &c, NOW), SecretError::NotFound.body());
    }
    let mut c = install();
    c.name = "a".repeat(257);
    assert_eq!(request(&store, &c, NOW), SecretError::LimitExceeded.body());
    sql(
        &store,
        "DELETE FROM settings WHERE name='federation.self_member'",
    );
    assert_eq!(
        request(&store, &install(), NOW),
        SecretError::SecretSetupIncomplete.body()
    );
    store
        .set_federation_self_member_audited(MEMBER, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    sql(&store, "CREATE TRIGGER fail_flow_pending BEFORE INSERT ON secret_pending_requests BEGIN SELECT RAISE(ABORT,'injected'); END;");
    assert_eq!(
        request(&store, &install(), NOW),
        SecretError::StoreError.body()
    );
    assert_eq!(
        count(&store, "SELECT COUNT(*) FROM secret_pending_requests"),
        0
    );
}

#[test]
fn secret_flow_approval_creation_time_and_24_hour_expiry_boundaries() {
    for (issued_delta, now_delta, valid) in [
        (0, 0, true),
        (-1, 0, false),
        (82_800_000, 82_800_000, true),
        (0, 82_800_000, false),
        (86_399_999, 86_399_999, true),
        (86_399_999, 86_400_000, false),
        (86_400_000, 86_399_999, false),
    ] {
        let (_root, store) = registered("flow-approve-time");
        let r = request(&store, &install(), NOW);
        let e = envelope(vec![item(&r)], "version", NOW + issued_delta);
        assert_eq!(
            phone(&store, &signed(&e, false), NOW + now_delta).unwrap(),
            json!({"results":[if valid {granted(&r)}else{refused(&r)}]}),
            "issued {issued_delta}, now {now_delta}"
        );
        assert_eq!(grant_rows(&store).len(), usize::from(valid));
        if valid {
            assert_eq!(
                release_flow(&store, &run(), NOW + now_delta)["status"],
                "released"
            );
        }
    }
}

#[test]
fn secret_flow_install_approval_releases_three_runs_and_audits_exact_hashes() {
    let (_root, store) = registered("flow-release-audit");
    let r = request(&store, &install(), NOW);
    let bytes = approve(&store, &r);
    let grants = grant_rows(&store);
    assert_eq!(grants.len(), 1);
    let (id, incarnation, flow_id, version) = &grants[0];
    let expected_hash = format!("{:x}", Sha256::digest(&bytes));
    assert_eq!(
        audit_rows(&store, "secret_grant_create"),
        vec![("secret|key".into(), expected_hash.clone())]
    );
    store.store.with_conn(|c| {
        let row: (String,u64,String,String,String,String,String) = c.query_row("SELECT flow_id,flow_version,flow_code_hash,flow_install_id,methods,envelope_sha256,card_ref FROM secret_flow_grants", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?)))?;
        assert_eq!(row, (identity().flow_id, identity().version, identity().code_hash, identity().install_id, "[\"GET\"]".into(), expected_hash, "card-1".into()));
        Ok(())
    }).unwrap();
    for (now, path) in [
        (NOW, "/repos/a/first"),
        (NOW + 1, "/repos/a/second"),
        (NOW + 172_800_000, "/repos/a"),
    ] {
        let mut c = run();
        if let UseTarget::ApiKey { path: p, .. } = &mut c.target {
            *p = path.into();
        }
        assert_eq!(release_flow(&store, &c, now)["status"], "released");
    }
    assert_eq!(
        audit_rows(&store, "secret_first_release"),
        vec![(
            "secret|key".into(),
            framed_hash(&[id, incarnation, flow_id, &version.to_string()])
        )]
    );
    assert_eq!(
        count(&store, "SELECT last_use_ms FROM secret_flow_grants"),
        NOW + 172_800_000
    );
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM secret_pending_requests WHERE consumed=0"
        ),
        0
    );
    // An exact resend learns the first reply instead of reading the consumed request as refused.
    assert_eq!(
        phone(&store, &signed_bytes(bytes, false), NOW).unwrap(),
        json!({"results":[granted(&r)]})
    );
    assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_flow_grants"), 1);
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn secret_flow_runtime_refuses_identity_method_target_and_incarnation_without_pending() {
    let (_root, store) = registered("flow-runtime-refusals");
    let r = request(&store, &install(), NOW);
    approve(&store, &r);
    for field in 0..8 {
        let mut c = run();
        match field {
            0 => c.flow.flow_id.push('x'),
            1 => c.flow.version += 1,
            2 => c.flow.code_hash = "f".repeat(64),
            3 => c.flow.install_id.push('x'),
            4 => c.method = Some("POST".into()),
            5 => {
                if let UseTarget::ApiKey { path, .. } = &mut c.target {
                    *path = "/repos/ab".into();
                }
            }
            6 => {
                c.target = UseTarget::SiteLogin {
                    origin: "https://x.test".into(),
                }
            }
            _ => c.name = "unknown".into(),
        }
        if field == 6 {
            c.method = None;
        }
        assert_eq!(
            release_flow(&store, &c, NOW),
            SecretError::NotFound.body(),
            "field {field}"
        );
    }
    for method in [
        None,
        Some("get".into()),
        Some("".into()),
        Some("A".repeat(17)),
    ] {
        for name in ["key", "missing"] {
            let mut c = run();
            c.method = method.clone();
            c.name = name.into();
            assert_eq!(
                release_flow(&store, &c, NOW),
                SecretError::InvalidParams.body()
            );
        }
    }
    let mut c = run();
    c.flow.install_id.clear();
    assert_eq!(release_flow(&store, &c, NOW), SecretError::NotFound.body());
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM auth_events WHERE detail='flow_identity'"
        ),
        1
    );
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM auth_events WHERE detail='flow_method'"
        ),
        1
    );
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM auth_events WHERE detail='flow_no_grant'"
        ),
        4
    );
    assert!(audit_rows(&store, "secret_first_release").is_empty());
    assert_eq!(
        count(&store, "SELECT COUNT(*) FROM secret_pending_requests"),
        1
    );
    let incarnation = "e".repeat(32);
    let blob = agent_secret::seal(
        &store.key,
        &incarnation,
        "key",
        &scope(),
        &SecretMaterial::ApiKey(crate::secret::Secret::new(vec![1])),
    )
    .unwrap();
    store
        .store
        .with_conn(|c| {
            c.execute(
                "UPDATE agent_secrets SET incarnation=?1,envelope=?2",
                rusqlite::params![incarnation, blob],
            )
            .map(|_| ())
        })
        .unwrap();
    assert_eq!(
        release_flow(&store, &run(), NOW),
        SecretError::NotFound.body()
    );
    assert_eq!(
        count(&store, "SELECT COUNT(*) FROM secret_pending_requests"),
        1
    );
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn secret_flow_and_agent_grants_never_authorize_each_other_or_basal_agent_scope() {
    let (_root, store) = registered("flow-agent-isolation");
    grant(&store, "agent-only", "permanent", 0, NOW);
    assert_eq!(
        release_flow(&store, &run(), NOW),
        SecretError::NotFound.body()
    );
    assert_eq!(
        count(&store, "SELECT COUNT(*) FROM secret_pending_requests"),
        0
    );
    let mut c = call();
    c.sender = SecretSender::Basal;
    assert_eq!(use_reply(&store, &c, NOW), SecretError::NotFound.body());
    assert_eq!(
        count(&store, "SELECT COUNT(*) FROM secret_pending_requests"),
        0
    );
    assert_eq!(count(&store, "SELECT first_released FROM secret_grants"), 0);
    sql(&store, "DELETE FROM secret_grants");
    let r = request(&store, &install(), NOW);
    approve(&store, &r);
    assert_eq!(
        use_reply(&store, &call(), NOW)["status"],
        "approval_required"
    );
    assert_eq!(release_flow(&store, &run(), NOW)["status"], "released");
}

#[test]
fn secret_flow_login_approval_and_runtime_forbid_methods_and_release() {
    let (_root, store) = registered("flow-login");
    let s = SecretScope::SiteLogin {
        origin: "https://x.test".into(),
    };
    seed(
        &store,
        "login",
        &s,
        &SecretMaterial::SiteLogin {
            username: crate::secret::Secret::new("user".into()),
            password: crate::secret::Secret::new("pass".into()),
            otpauth: None,
        },
    );
    let c = SecretFlowApproval {
        name: "login".into(),
        flow: identity(),
        target: UseTarget::SiteLogin {
            origin: "https://x.test:443".into(),
        },
        methods: None,
    };
    let r = request(&store, &c, NOW);
    approve(&store, &r);
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM secret_flow_grants WHERE methods IS NULL"
        ),
        1
    );
    let mut c = SecretFlowUse {
        name: "login".into(),
        flow: identity(),
        target: UseTarget::SiteLogin {
            origin: "https://x.test".into(),
        },
        method: None,
    };
    assert_eq!(
        release_flow(&store, &c, NOW),
        json!({"status":"released","kind":"site_login","username":"user","password":"pass"})
    );
    c.method = Some("GET".into());
    assert_eq!(
        release_flow(&store, &c, NOW),
        SecretError::InvalidParams.body()
    );
    let mut c = install();
    c.target = UseTarget::SiteLogin {
        origin: "https://x.test".into(),
    };
    assert_eq!(request(&store, &c, NOW), SecretError::InvalidParams.body());
}

#[test]
fn secret_flow_concurrent_first_releases_audit_once_and_audit_failure_blocks_release() {
    let (_root, store) = registered("flow-first-race");
    let r = request(&store, &install(), NOW);
    approve(&store, &r);
    sql(&store, "CREATE TRIGGER fail_flow_audit BEFORE INSERT ON audit_log WHEN NEW.op='secret_first_release' BEGIN SELECT RAISE(ABORT,'injected'); END;");
    assert_eq!(
        release_flow(&store, &run(), NOW),
        SecretError::StoreError.body()
    );
    assert_eq!(
        count(&store, "SELECT first_released FROM secret_flow_grants"),
        0
    );
    sql(&store, "DROP TRIGGER fail_flow_audit");
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let store = store.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                release_flow(&store, &run(), NOW)
            })
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap()["status"], "released");
    }
    assert_eq!(audit_rows(&store, "secret_first_release").len(), 1);
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn secret_flow_revoke_selects_install_and_version_cancels_requests_and_audits_zero() {
    let (_root, store) = registered("flow-revoke-selectors");
    let mut outstanding = Vec::new();
    for install_id in ["install-A", "install-B"] {
        for version in [7, 8] {
            let mut c = install();
            c.flow.install_id = install_id.into();
            c.flow.version = version;
            let r = request(&store, &c, NOW);
            approve(&store, &r);
            c.methods = Some(vec!["POST".into()]);
            let r = request(&store, &c, NOW);
            outstanding.push((
                install_id,
                version,
                signed(&envelope(vec![item(&r)], "version", NOW), false),
                r,
            ));
        }
    }
    // A separate agent request and grant must survive both selectors.
    let agent_request = use_reply(&store, &call(), NOW);
    grant(&store, "agent", "permanent", 0, NOW);
    let rows = grant_rows(&store);
    assert_eq!(store.revoke_flow_grants("install-A", Some(7)).unwrap(), 1);
    assert_eq!(store.revoke_flow_grants("install-A", Some(7)).unwrap(), 0);
    assert_eq!(store.revoke_flow_grants("install-B", None).unwrap(), 2);
    for (install_id, version, op, r) in outstanding {
        let mut c = run();
        c.flow.install_id = install_id.into();
        c.flow.version = version;
        if install_id == "install-A" && version == 8 {
            assert_eq!(release_flow(&store, &c, NOW)["status"], "released");
            assert_eq!(
                phone(&store, &op, NOW).unwrap(),
                json!({"results":[granted(&r)]})
            );
        } else {
            assert_eq!(release_flow(&store, &c, NOW), SecretError::NotFound.body());
            assert_eq!(
                phone(&store, &op, NOW).unwrap(),
                json!({"results":[refused(&r)]})
            );
        }
    }
    assert_eq!(use_reply(&store, &call(), NOW)["status"], "released");
    assert_eq!(
        request(&store, &install(), NOW)["status"],
        "approval_required",
        "explicit reinstall can request fresh approval"
    );
    let revoked = audit_rows(&store, "secret_grant_revoke");
    assert_eq!(revoked.len(), 6);
    let surviving_ids: Vec<_> = grant_rows(&store)
        .into_iter()
        .map(|(id, _, _, _)| id)
        .collect();
    let expected_grants: Vec<_> = rows
        .into_iter()
        .filter(|(id, _, _, _)| !surviving_ids.contains(id))
        .collect();
    assert_eq!(expected_grants.len(), 3);
    for (id, incarnation, flow_id, version) in expected_grants {
        assert!(revoked.contains(&(
            "secret|key".into(),
            framed_hash(&[&id, &incarnation, &flow_id, &version.to_string()])
        )));
    }
    assert!(revoked.contains(&(
        "secret-flow|install-A".into(),
        framed_hash(&["install-A", "7", "1"])
    )));
    assert!(revoked.contains(&(
        "secret-flow|install-A".into(),
        framed_hash(&["install-A", "7", "0"])
    )));
    assert!(revoked.contains(&(
        "secret-flow|install-B".into(),
        framed_hash(&["install-B", "", "2"])
    )));
    assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_pending_requests WHERE flow_install_id='install-B' AND consumed=0"), 0);
    let id = agent_request["request_id"].as_str().unwrap();
    store.store.with_conn(|c| {
        assert!(c.query_row("SELECT EXISTS(SELECT 1 FROM secret_pending_requests WHERE request_id=?1 AND consumed=0)", [id], |r| r.get::<_,bool>(0))?);
        Ok(())
    }).unwrap();
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn secret_flow_revoke_failure_rolls_back_grants_requests_and_audit_together() {
    let (_root, store) = registered("flow-revoke-atomic");
    let r = request(&store, &install(), NOW);
    approve(&store, &r);
    let mut c = install();
    c.methods = Some(vec!["POST".into()]);
    request(&store, &c, NOW);
    sql(&store, "CREATE TRIGGER fail_flow_summary BEFORE INSERT ON audit_log WHEN NEW.credential_id='secret-flow|install-A' BEGIN SELECT RAISE(ABORT,'injected'); END;");
    assert_eq!(
        store.revoke_flow_grants("install-A", None),
        Err(SecretError::StoreError)
    );
    assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_flow_grants"), 1);
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM secret_pending_requests WHERE consumed=0"
        ),
        1
    );
    assert!(audit_rows(&store, "secret_grant_revoke").is_empty());
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[path = "store_secret_asking_member_tests.rs"]
mod asking_member_tests;
