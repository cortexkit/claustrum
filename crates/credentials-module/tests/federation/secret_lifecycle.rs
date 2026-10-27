//! Release receipts, holder-scoped flow grants, and role boundaries over the two-vault wire.

use super::*;

use std::time::Duration;

use crate::support::Held;

fn count(rig: &Rig, sql: &str) -> i64 {
    let conn = rusqlite::Connection::open_with_flags(
        rig.vaults.a.store_path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    conn.query_row(sql, [], |row| row.get(0)).unwrap()
}

fn release_state(rig: &Rig) -> (i64, i64, i64, i64) {
    (
        count(rig, "SELECT COUNT(*) FROM secret_grants"),
        count(rig, "SELECT COUNT(*) FROM secret_release_receipts"),
        count(
            rig,
            "SELECT COUNT(*) FROM audit_log WHERE op='secret_first_release'",
        ),
        count(rig, "SELECT COUNT(*) FROM auth_events"),
    )
}

fn retry_call(rig: &Rig, params: &Value) -> RouteCall {
    RouteCall {
        target: management_surface(&fed_provider_module(&rig.home_id())),
        prelude: None,
        request: json!({"method": OP_SECRET_USE, "params": params}),
    }
}

fn last_use_params(callosum: &SharedCallosumStandIn) -> Value {
    callosum
        .ledger()
        .into_iter()
        .rev()
        .find_map(|row| match row {
            Ledger::Request { method, params, .. } if method == OP_SECRET_USE => Some(params),
            _ => None,
        })
        .expect("a forwarded secret.use request")
}

fn secret_hops(callosum: &SharedCallosumStandIn) -> Vec<(String, String)> {
    callosum
        .ledger()
        .into_iter()
        .filter_map(|row| match row {
            Ledger::Request { target, method, .. } if method.starts_with("federation.secret_") => {
                Some((target, method))
            }
            _ => None,
        })
        .collect()
}

async fn retry(rig: &Rig, params: &Value) -> Value {
    rig.vaults
        .b
        .outbound
        .call(
            "secret-receipt-retry",
            retry_call(rig, params),
            Duration::from_secs(5),
        )
        .await
        .expect("the retry route answers")
}

async fn approved_agent(rig: &Rig, duration: &str) -> Value {
    let asked = rig.use_on_b("aft", &golden("use.request.api_key")).await;
    let params = last_use_params(&rig.vaults.callosum);
    rig.grant(&asked, duration);
    params
}

/// Commit the release, hold its reply, then close the transport without delivering it.
async fn drop_committed_reply(rig: &Rig, params: &Value) -> Value {
    let saved = Arc::new(Mutex::new(None));
    let capture = Arc::clone(&saved);
    let held = Held::new();
    let hold = held.clone();
    let home = Arc::downgrade(&rig.home);
    let member = rig.requester();
    rig.vaults.callosum.answer(
        TARGET_MODULE,
        OP_SECRET_USE,
        Reply::Handler(Responder(Arc::new(move |params| {
            let capture = Arc::clone(&capture);
            let home = home.upgrade().expect("home is running");
            let member = member.clone();
            let hold = hold.clone();
            Box::pin(async move {
                let HomeAnswer::Reply(body) = home.serve(&member, OP_SECRET_USE, &params).await
                else {
                    panic!("release params were invalid")
                };
                assert_eq!(body["status"], "sealed", "{body}");
                *capture.lock().unwrap() = Some(body);
                Reply::Hold(hold)
            })
        }))),
    );
    let request = async {
        rig.vaults
            .b
            .outbound
            .call(
                "secret-receipt-retry",
                retry_call(rig, params),
                Duration::from_secs(5),
            )
            .await
    };
    let lose_reply = async {
        held.arrived().await;
        rig.vaults.callosum.close_connections(false).await;
        held.release(Reply::Stall);
    };
    let (lost, ()) = tokio::join!(request, lose_reply);
    assert!(lost.is_err(), "the committed reply reached B: {lost:?}");
    let body = saved
        .lock()
        .unwrap()
        .take()
        .expect("committed sealed reply");
    restore_use_route(rig);
    body
}

fn restore_use_route(rig: &Rig) {
    let home = Arc::downgrade(&rig.home);
    let member = rig.requester();
    rig.vaults.callosum.answer(
        TARGET_MODULE,
        OP_SECRET_USE,
        Reply::Handler(Responder(Arc::new(move |params| {
            let home = home.upgrade().expect("home is running");
            let member = member.clone();
            Box::pin(async move {
                match home.serve(&member, OP_SECRET_USE, &params).await {
                    HomeAnswer::Reply(body) => Reply::Ok(body),
                    HomeAnswer::InvalidParams(_) => panic!("retry params were invalid"),
                }
            })
        }))),
    );
}

async fn restart_home(mut rig: Rig) -> Rig {
    // No release is in flight: the response was held only after serve returned.
    // Weak responder references let the old engine and store lease drop here.
    rig.vaults.callosum.forget_answers();
    let stopped_home = Arc::downgrade(&rig.home);
    let stopped_store = Arc::downgrade(&rig.a.store);
    drop(rig.home);
    drop(rig.a);
    assert!(stopped_home.upgrade().is_none(), "old home still running");
    assert!(stopped_store.upgrade().is_none(), "old store still leased");
    rig.a = HomeStore::open(&rig.vaults.a.data_dir);
    let clock = rig.vaults.a.clock.clone();
    let home = HomeVault::new(Arc::clone(&rig.a.engine))
        .with_secret_clock(Arc::new(move || clock.wall_ms()));
    assert!(home.attach_outbound(rig.vaults.a.outbound.clone()));
    rig.home = Arc::new(home);
    restore_use_route(&rig);
    rig
}

#[tokio::test]
async fn a_dropped_once_release_survives_restart_and_two_gated_duplicates() {
    let rig = Rig::new("secret-once-restart").await;
    let params = approved_agent(&rig, "once").await;
    assert_eq!(release_state(&rig), (1, 0, 0, 0));
    let committed = drop_committed_reply(&rig, &params).await;
    assert_eq!(release_state(&rig), (0, 1, 1, 0));
    let audits = count(&rig, "SELECT COUNT(*) FROM audit_log");
    let rig = restart_home(rig).await;

    let arrived = Arc::new(tokio::sync::Barrier::new(3));
    let release = Arc::new(tokio::sync::Notify::new());
    let home = Arc::clone(&rig.home);
    let member = rig.requester();
    let gate = Arc::clone(&arrived);
    let open = Arc::clone(&release);
    rig.vaults.callosum.answer(
        TARGET_MODULE,
        OP_SECRET_USE,
        Reply::Handler(Responder(Arc::new(move |params| {
            let home = Arc::clone(&home);
            let member = member.clone();
            let gate = Arc::clone(&gate);
            let open = Arc::clone(&open);
            Box::pin(async move {
                // Register the waiter before announcing arrival so opening the gate
                // cannot miss either duplicate.
                let wait = open.notified();
                tokio::pin!(wait);
                wait.as_mut().enable();
                gate.wait().await;
                wait.await;
                match home.serve(&member, OP_SECRET_USE, &params).await {
                    HomeAnswer::Reply(body) => Reply::Ok(body),
                    HomeAnswer::InvalidParams(_) => panic!("duplicate params were invalid"),
                }
            })
        }))),
    );
    let duplicates = async { tokio::join!(retry(&rig, &params), retry(&rig, &params)) };
    let unblock = async {
        arrived.wait().await;
        release.notify_waiters();
    };
    let ((first, second), ()) = tokio::join!(duplicates, unblock);
    assert_eq!(first, committed);
    assert_eq!(second, committed);
    restore_use_route(&rig);
    assert_eq!(retry(&rig, &params).await, committed);
    assert_eq!(release_state(&rig), (0, 1, 1, 0));
    assert_eq!(count(&rig, "SELECT COUNT(*) FROM audit_log"), audits);
    rig.assert_reply_custody(&[]);
}

#[tokio::test]
async fn a_once_receipt_rejects_changed_params_or_aad_bytes() {
    let rig = Rig::new("secret-once-exact-aad").await;
    let params = approved_agent(&rig, "once").await;
    let sealed = retry(&rig, &params).await;
    assert_eq!(sealed["status"], "sealed", "{sealed}");

    let aad = params["aad"].as_str().unwrap();
    let parsed: Value = serde_json::from_str(aad).unwrap();
    let mut reordered = params.clone();
    reordered["aad"] = json!(serde_json::to_string(&parsed).unwrap());
    assert_ne!(
        reordered["aad"], params["aad"],
        "encoder field order differs from sorted JSON"
    );
    let mut respaced = params.clone();
    respaced["aad"] = json!(aad.replacen('{', "{ ", 1));
    let mut other_key = params.clone();
    other_key["aad"] = json!(aad.replace(
        parsed["recipient_key_id"].as_str().unwrap(),
        "ffffffffffffffff",
    ));
    let mut other_call = params.clone();
    other_call["call"]["target"]["path"] = json!("/repos/a/issues/2");
    other_call["aad"] = json!(aad.replace(
        parsed["call_sha256"].as_str().unwrap(),
        &secret_call_sha256("aft", &other_call["call"]).unwrap(),
    ));

    for altered in [other_call, reordered, respaced, other_key] {
        assert_ne!(altered, params);
        let before = release_state(&rig).3;
        assert_eq!(retry(&rig, &altered).await, not_found(), "{altered}");
        assert!(
            release_state(&rig).3 > before,
            "authoritative refusal is recorded"
        );
    }
    assert_eq!(retry(&rig, &params).await, sealed);
    let (grants, receipts, releases, _) = release_state(&rig);
    assert_eq!((grants, receipts, releases), (0, 1, 1));
    rig.assert_reply_custody(&[]);
}

#[tokio::test]
async fn a_transient_pairing_lookup_preserves_the_committed_once_receipt() {
    let rig = Rig::new("secret-receipt-lookup").await;
    let params = approved_agent(&rig, "once").await;
    let committed = drop_committed_reply(&rig, &params).await;
    let state = release_state(&rig);
    let audits = count(&rig, "SELECT COUNT(*) FROM audit_log");
    assert_eq!(state, (0, 1, 1, 0));
    rig.vaults.callosum.answer(
        TARGET_MODULE,
        "callosum.paired_devices_read",
        Reply::RetrySafe("fed_not_ready".into()),
    );
    let refused = retry(&rig, &params).await;
    assert_eq!(error_code(&refused), "home_unavailable", "{refused}");
    assert_eq!(refused["error"]["class"], "transient");
    assert_eq!(
        release_state(&rig),
        state,
        "no refusal audit or receipt mutation"
    );
    assert_eq!(count(&rig, "SELECT COUNT(*) FROM audit_log"), audits);
    rig.vaults.callosum.forget_answers();
    restore_use_route(&rig);
    assert_eq!(retry(&rig, &params).await, committed);
    assert_eq!(release_state(&rig), state);
    assert_eq!(count(&rig, "SELECT COUNT(*) FROM audit_log"), audits);
    rig.assert_reply_custody(&[]);
}

#[tokio::test]
async fn a_once_receipt_does_not_outlive_the_member_grant_or_pairing() {
    for re_pair in [false, true] {
        let rig = Rig::new("secret-receipt-member").await;
        let params = approved_agent(&rig, "once").await;
        let _committed = drop_committed_reply(&rig, &params).await;
        assert_eq!(release_state(&rig), (0, 1, 1, 0));
        if re_pair {
            rig.vaults
                .callosum
                .set_pairing(&rig.requester(), Some("pair-b-new"));
        } else {
            rig.a
                .store
                .revoke_member_grant_audited(
                    &rig.requester(),
                    MemberGrantOperation::SecretUse,
                    &MemberGrantSelector::None,
                )
                .unwrap();
        }
        assert_eq!(retry(&rig, &params).await, not_found());
        let (grants, receipts, releases, refusals) = release_state(&rig);
        assert_eq!((grants, receipts, releases), (0, 1, 1));
        assert!(refusals > 0);
        rig.assert_reply_custody(&[]);
    }
}

fn phone(rig: &Rig, op: &PhoneOperation) -> Value {
    let now = rig.vaults.a.clock.wall_ms();
    rig.a
        .store
        .secret_phone_operation(PHONE_FP, Some(PHONE_PAIRING), now, op, || true, || now)
        .expect("phone operation")
}

#[tokio::test]
async fn a_permanent_receipt_ends_when_the_phone_revokes_or_the_secret_is_recreated() {
    for recreate in [false, true] {
        let rig = Rig::new("secret-receipt-revoke").await;
        let params = approved_agent(&rig, "permanent").await;
        assert_eq!(retry(&rig, &params).await["status"], "sealed");
        let grant_id: String = rusqlite::Connection::open_with_flags(
            rig.vaults.a.store_path(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap()
        .query_row("SELECT grant_id FROM secret_grants", [], |row| row.get(0))
        .unwrap();
        if recreate {
            assert_eq!(
                rig.a
                    .store
                    .secret_operator_delete_audited("key", "operator")
                    .unwrap(),
                json!({"status":"deleted"})
            );
            put_secret(&rig.a.store, api_key_put());
        } else {
            assert_eq!(
                phone(&rig, &PhoneOperation::Revoke { grant_id }),
                json!({"outcome":"revoked"})
            );
        }
        assert_eq!(retry(&rig, &params).await, not_found());
        assert_eq!(
            count(
                &rig,
                "SELECT COUNT(*) FROM audit_log WHERE op='secret_first_release'"
            ),
            1
        );
        rig.assert_reply_custody(&[]);
    }
}

#[tokio::test]
async fn a_forwarded_flow_is_approved_and_revoked_only_for_its_asking_computer() {
    let rig = Rig::new("secret-flow-lifecycle").await;
    let c = rig.other_asker().await;
    let c_line = HomeLine {
        home: Arc::downgrade(&rig.home),
        member: c.member.clone(),
        script: Arc::default(),
        home_pem: rig.home_pem.clone(),
        asker_public: Vec::new(),
    };
    route_to_home(&c.callosum, OP_SECRET_REQUEST_FLOW_APPROVAL, &c_line);
    let approval = golden("request_flow_approval.request.api_key");
    let run = golden("use.request.flow.api_key");
    let asked = rig
        .on_b("basal", "secret.request_flow_approval", &approval)
        .await;
    let s = statement(&asked);
    assert_eq!(s["v"], "ck-secret-flow-statement/v2");
    assert_eq!(s["member_id"], rig.home_id());
    assert_eq!(s["asking_member_id"], rig.requester());
    rig.grant(&asked, "version");
    let released = rig.use_on_b("basal", &run).await;
    assert_eq!(released["status"], "released", "{released}");
    assert_eq!(released["key_b64url"], b64url(API_KEY));
    let receipt_params = last_use_params(&rig.vaults.callosum);
    assert_eq!(
        ask_through(&c.reader, "basal", "secret.use", &run).await,
        not_found()
    );
    assert_eq!(rig.use_on_home("basal", &run), not_found());

    let c_asked = ask_through(
        &c.reader,
        "basal",
        "secret.request_flow_approval",
        &approval,
    )
    .await;
    assert_eq!(statement(&c_asked)["asking_member_id"], c.member);
    rig.grant(&c_asked, "version");
    let principal = Principal::Reserved {
        module_id: "basal".into(),
    };
    let now = rig.vaults.a.clock.wall_ms();
    let claustrum_module_probe::secret_use::UseAnswer::Reply(local_asked) =
        claustrum_module_probe::secret_use::serve_flow_approval(
            &rig.a.store,
            Some(&principal),
            &approval,
            || now,
        )
    else {
        panic!("local flow approval params")
    };
    assert_eq!(statement(&local_asked)["v"], "ck-secret-flow-statement/v1");
    rig.grant(&local_asked, "version");
    assert_eq!(count(&rig, "SELECT COUNT(*) FROM secret_flow_grants"), 3);
    assert_eq!(
        ask_through(&c.reader, "basal", "secret.use", &run).await["status"],
        "released"
    );
    assert_eq!(rig.use_on_home("basal", &run)["status"], "released");

    let revoked = rig
        .on_b(
            "basal",
            "secret.revoke_flow_grants",
            &golden("revoke_flow_grants.request"),
        )
        .await;
    assert_eq!(revoked, json!({"status":"revoked","grants":1}));
    assert_eq!(count(&rig, "SELECT COUNT(*) FROM secret_flow_grants"), 2);
    assert_eq!(retry(&rig, &receipt_params).await, not_found());
    assert_eq!(rig.use_on_b("basal", &run).await, not_found());
    assert_eq!(
        ask_through(&c.reader, "basal", "secret.use", &run).await["status"],
        "released"
    );
    assert_eq!(rig.use_on_home("basal", &run)["status"], "released");
    rig.assert_reply_custody(&[&c.callosum]);
}

fn assert_no_secret_rows(fixture: &VaultFixture) {
    let conn = rusqlite::Connection::open_with_flags(
        fixture.store_path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    for table in [
        "agent_secrets",
        "secret_grants",
        "secret_flow_grants",
        "secret_pending_requests",
        "secret_phone_keys",
        "secret_release_receipts",
    ] {
        let rows: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            rows, 0,
            "{} acquired rows in {table}",
            fixture.member.member_id
        );
    }
}

#[tokio::test]
async fn a_remote_role_phone_is_sent_home_without_creating_secret_state() {
    use claustrum_module_probe::secret_phone::{serve, PhoneAnswer};
    let rig = Rig::new("secret-remote-phone").await;
    rig.vaults
        .callosum
        .set_pairing(&format!("fed-phone:{PHONE_FP}"), Some(PHONE_PAIRING));
    for (method, id) in [
        ("secret.phone_keys_register", "phone_keys_register.request"),
        ("secret.deposit_keys", "deposit_keys.request"),
        ("secret.deposit", "deposit.request.api_key"),
        ("secret.approve", "approve.request"),
        ("secret.list", "list.request"),
        ("secret.delete", "delete.request.name"),
        ("secret.delete", "delete.request.signed"),
        ("secret.revoke_grant", "revoke_grant.request"),
    ] {
        let PhoneAnswer::Reply(reply) = serve(
            Arc::clone(&rig._b.store),
            Some(&rig.vaults.b.outbound),
            PHONE_FP,
            method,
            &golden(id),
        )
        .await
        else {
            panic!("phone op {method} did not answer")
        };
        assert_eq!(
            reply,
            json!({"error":{"code":"secret_home_elsewhere","class":"permanent","remedy_member":rig.home_id()}}),
            "{method}"
        );
        assert_no_secret_rows(&rig.vaults.b);
    }
    let PhoneAnswer::Reply(home) = serve(
        Arc::clone(&rig._b.store),
        Some(&rig.vaults.b.outbound),
        PHONE_FP,
        "secret.home",
        &json!({}),
    )
    .await
    else {
        panic!("secret.home did not answer")
    };
    assert_eq!(home, json!({"home":false,"home_member_id":rig.home_id()}));
    assert_no_secret_rows(&rig.vaults.b);
}

#[tokio::test]
async fn a_misconfigured_cycle_stops_after_one_hop_without_writing_secret_state() {
    let root = crate::support::temp_root("secret-home-cycle");
    let vaults = TwoVaults::new(&root).await;
    let a = HomeStore::open(&vaults.a.data_dir);
    let b = HomeStore::open(&vaults.b.data_dir);
    let a_id = vaults.home_member().to_string();
    let b_id = vaults.requester_member().to_string();
    let (_, a_public) = install_transfer_key(&a.store, &a_id);
    let (_, b_public) = install_transfer_key(&b.store, &b_id);
    a.store
        .set_secret_home_audited(Some(&b_id), AuditCtx::admin(SECRET_HOME_SET))
        .unwrap();
    b.store
        .set_secret_home_audited(Some(&a_id), AuditCtx::admin(SECRET_HOME_SET))
        .unwrap();
    vaults.callosum.announce_peer_key(&a_id, &hex(&a_public));
    vaults.callosum.announce_peer_key(&b_id, &hex(&b_public));
    let home = Arc::new(HomeVault::new(Arc::clone(&a.engine)));
    assert!(home.attach_outbound(vaults.a.outbound.clone()));
    let line = HomeLine {
        home: Arc::downgrade(&home),
        member: b_id,
        script: Arc::default(),
        home_pem: String::new(),
        asker_public: Vec::new(),
    };
    for op in [
        OP_SECRET_USE,
        OP_SECRET_REQUEST_FLOW_APPROVAL,
        OP_SECRET_REVOKE_FLOW_GRANTS,
    ] {
        route_to_home(&vaults.callosum, op, &line);
    }
    let reader = reader_over(&b, &vaults.b);
    for (method, params) in [
        ("secret.use", golden("use.request.api_key")),
        (
            "secret.request_flow_approval",
            golden("request_flow_approval.request.api_key"),
        ),
        (
            "secret.revoke_flow_grants",
            golden("revoke_flow_grants.request"),
        ),
    ] {
        let before = secret_hops(&vaults.callosum).len();
        let sender = if method == "secret.use" {
            "aft"
        } else {
            "basal"
        };
        assert_eq!(
            ask_through(&reader, sender, method, &params).await,
            not_found()
        );
        assert_eq!(
            secret_hops(&vaults.callosum).len(),
            before + 1,
            "{method} forwarded more than once"
        );
        assert_eq!(
            secret_hops(&vaults.callosum).last().unwrap().0,
            fed_provider_module(&a_id)
        );
        assert_no_secret_rows(&vaults.a);
        assert_no_secret_rows(&vaults.b);
    }
}

fn assert_v1_statement_bytes(rig: &Rig, reply: &Value, golden_id: &str) {
    let mut expected = golden(golden_id);
    expected["member_id"] = json!(rig.home_id());
    expected["request_id"] = reply["request_id"].clone();
    expected["request_expires_at_ms"] = reply["expires_at_ms"].clone();
    let incarnation: String = rusqlite::Connection::open_with_flags(
        rig.vaults.a.store_path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
    .query_row(
        "SELECT incarnation FROM agent_secrets WHERE name='key'",
        [],
        |row| row.get(0),
    )
    .unwrap();
    expected["secret"]["incarnation"] = json!(incarnation);
    let actual = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(reply["statement_b64url"].as_str().expect("statement bytes"))
        .unwrap();
    assert_eq!(
        actual,
        serde_json::to_vec(&expected).unwrap(),
        "{golden_id}"
    );
}

#[tokio::test]
async fn an_unset_home_keeps_v1_statement_bytes_and_accepts_a_flow_named_for_a_v2_tag() {
    let rig = Rig::new("secret-single-v1").await;
    rig.a
        .store
        .set_secret_home_audited(None, AuditCtx::admin(SECRET_HOME_SET))
        .unwrap();
    let request = rig.use_on_home("aft", &golden("use.request.api_key"));
    assert_v1_statement_bytes(&rig, &request, "statement.use");
    let principal = Principal::Reserved {
        module_id: "basal".into(),
    };
    let now = rig.vaults.a.clock.wall_ms();
    let ask = |params: &Value| {
        let claustrum_module_probe::secret_use::UseAnswer::Reply(reply) =
            claustrum_module_probe::secret_use::serve_flow_approval(
                &rig.a.store,
                Some(&principal),
                params,
                || now,
            )
        else {
            panic!("local flow params")
        };
        reply
    };
    let flow = ask(&golden("request_flow_approval.request.api_key"));
    assert_v1_statement_bytes(&rig, &flow, "statement.flow");
    let mut named = golden("request_flow_approval.request.api_key");
    named["flow"]["flow_id"] = json!("ck-secret-flow-statement/v2");
    let named_request = ask(&named);
    assert_eq!(
        statement(&named_request)["v"],
        "ck-secret-flow-statement/v1"
    );
    rig.grant(&named_request, "version");
    let mut run = golden("use.request.flow.api_key");
    run["stamp"]["attributes"]["flow_id"] = named["flow"]["flow_id"].clone();
    let released = rig.use_on_home("basal", &run);
    assert_eq!(released["status"], "released", "{released}");
    assert_eq!(released["key_b64url"], b64url(API_KEY));
    assert!(
        secret_hops(&rig.vaults.callosum).is_empty(),
        "single-vault use must stay local"
    );
}
