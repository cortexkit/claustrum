use super::*;
use crate::federation::member_watch;
use crate::tests::federation_fixture_support::{
    fed_provider_name, temp_root, wait_for_signal, wait_until, Held, HomeStore, HomeWatchRelay,
    Ledger, Reply, Responder, TwoVaults, TARGET_MODULE,
};
use claustrum_module_probe::federation::{ingress as fed, outbound};
use credentials_core::federation::{
    MemberGrantOperation, MemberGrantSelector, NewRemoteRecord, VAULT_TRANSFER_ID,
};

const PAIR: &str = "condition-pair";
const OTHER_HOME: &str = "fed-computer:22223333444455556666777788889999";

struct PeerRig {
    vaults: TwoVaults,
    home: HomeStore,
    member: HomeStore,
    surface: Arc<ReadSurface>,
    admin: Arc<admin_surface::AdminSurface>,
    home_handler: Arc<fed::HomeVault>,
    token: String,
    _root: TestTempDir,
}

impl PeerRig {
    async fn new(name: &str, home_adapter: &str) -> Self {
        use credentials_core::enrollment::{enrollment_secret_hash, EnrollmentPoll};

        let root = temp_root(name);
        let vaults = TwoVaults::new(&root).await;
        let home = HomeStore::open(&vaults.a.data_dir);
        let member = HomeStore::open(&vaults.b.data_dir);
        for (local, identity) in [
            (&home, vaults.home_member()),
            (&member, vaults.requester_member()),
        ] {
            local
                .store
                .set_federation_self_member_audited(
                    identity,
                    AuditCtx::admin(AuditOp::FederationSelfSet),
                )
                .unwrap();
            local
                .store
                .set_federation_member_mapping_audited(
                    true,
                    AuditCtx::admin(AuditOp::FederationGateSet),
                )
                .unwrap();
            crate::federation::transfer::ensure_transfer_key(&local.store, "vault").unwrap();
            let key = local.store.get(VAULT_TRANSFER_ID).unwrap();
            let (public, _) = credentials_core::kem::public_half(
                std::str::from_utf8(key.payload.expose()).unwrap(),
            )
            .unwrap();
            let public: String = public.iter().map(|byte| format!("{byte:02x}")).collect();
            vaults.callosum.announce_peer_key(identity, &public);
            vaults.callosum.set_pairing(identity, Some(PAIR));
        }
        home.store
            .create(ID, &oauth_record_with_adapter(home_adapter))
            .unwrap();
        home.store
            .create_member_grant_audited(
                vaults.requester_member(),
                MemberGrantOperation::RemoteRead,
                &MemberGrantSelector::Exact(ID.into()),
                PAIR,
            )
            .unwrap();
        let home_handler = Arc::new(fed::HomeVault::new(Arc::clone(&home.engine)));
        assert!(home_handler.attach_outbound(vaults.a.outbound.clone()));
        let surface = Arc::new(
            ReadSurface::new(
                Arc::clone(&member.engine),
                FetchLimiter::new(Caps::default()),
            )
            .with_refresh_adapter_names(["antigravity".into()]),
        );
        assert!(surface
            .remote()
            .attach_outbound(crate::federation::OutboundClient::for_daemon(
                vaults.b.connection_file.clone(),
                "claustrum",
                Some("harness-launch-nonce"),
            )));
        let key = MasterKey::from_bytes([42; MASTER_KEY_LEN]);
        let admin = Arc::new(admin_surface::AdminSurface::new(
            Arc::clone(&member.engine),
            credentials_core::admin_auth::AdminMacKey::derive(&key),
            credentials_core::vault_id_for(&vaults.b.data_dir).unwrap(),
            key.key_id(),
        ));
        admin.record_bind_at(CHANNEL, 1, subc_protocol::Principal::Direct, "");
        admin.record_bind_at(56, 1, reserved("cingulate"), "");
        let secret = "ac".repeat(32);
        let enrollee = "member-condition-reader";
        let request = member
            .store
            .propose_enrollment(enrollee, &enrollment_secret_hash(&secret).unwrap())
            .unwrap();
        member
            .store
            .approve_enrollment(&request.request_id, enrollee, "operator")
            .unwrap();
        let EnrollmentPoll::Approved { token, .. } = member
            .store
            .poll_enrollment(&request.request_id, &secret)
            .unwrap()
        else {
            panic!("expected an approved enrollment");
        };
        member
            .store
            .create_read_grant_audited(
                "enrolled",
                enrollee,
                SelectorKind::Exact,
                ID,
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
        let rig = Self {
            vaults,
            home,
            member,
            surface,
            admin,
            home_handler,
            token,
            _root: root,
        };
        for method in [
            fed::OP_REPORT_CONDITION,
            fed::OP_CLEAR_CONDITION,
            fed::OP_REMOTE_TOKEN,
        ] {
            rig.relay(method, None);
        }
        rig
    }

    fn target(&self) -> String {
        fed_provider_name(self.vaults.home_member())
    }

    fn relay(&self, method: &'static str, lose_reply: Option<Held>) {
        let home = Arc::clone(&self.home_handler);
        let member = self.vaults.requester_member().to_owned();
        self.vaults.callosum.answer(
            TARGET_MODULE,
            method,
            Reply::Handler(Responder(Arc::new(move |params| {
                let home = Arc::clone(&home);
                let member = member.clone();
                let lose_reply = lose_reply.clone();
                Box::pin(async move {
                    match home.serve(&member, method, &params).await {
                        fed::HomeAnswer::Reply(body) => {
                            if let Some(held) = lose_reply {
                                assert_eq!(
                                    body[if method == fed::OP_REPORT_CONDITION {
                                        "accepted"
                                    } else {
                                        "cleared"
                                    }],
                                    true
                                );
                                Reply::Hold(held)
                            } else {
                                Reply::Ok(body)
                            }
                        }
                        fed::HomeAnswer::InvalidParams(_) => {
                            Reply::RouteRefusal("invalid_params".into())
                        }
                    }
                })
            }))),
        );
    }

    fn mark(&self) -> Option<Condition> {
        self.home
            .store
            .credential_condition(ID, &self.home.store.credential_incarnation(ID).unwrap())
            .unwrap()
    }

    fn copy(&self) -> credentials_core::federation::RemoteRecord {
        self.member.store.remote_record(ID).unwrap().unwrap()
    }

    fn copy_mark(&self) -> Option<Condition> {
        self.member
            .store
            .remote_record_condition(ID, &self.copy().incarnation)
            .unwrap()
    }

    fn add_operator_copy(&self, home: &str, adapter: &str) {
        add_operator_copy(&self.member.store, home, adapter);
    }

    async fn reader_call(&self, method: &str, mut params: Value) -> Value {
        params["enrollment_token"] = json!(self.token);
        routed_json(&self.surface, &self.admin, CHANNEL, method, params).await
    }

    fn requests(&self, method: &str) -> Vec<(String, Value)> {
        self.vaults
            .callosum
            .ledger()
            .into_iter()
            .filter_map(|row| match row {
                Ledger::Request {
                    target,
                    method: seen,
                    params,
                } if seen == method => Some((target, params)),
                _ => None,
            })
            .collect()
    }

    fn watch(
        &self,
    ) -> (
        tokio::sync::watch::Sender<member_watch::PairedComputers>,
        tokio::task::JoinHandle<()>,
    ) {
        let fp = self
            .vaults
            .home_member()
            .strip_prefix("fed-computer:")
            .unwrap();
        let (tx, rx) = tokio::sync::watch::channel(Some(vec![(fp.into(), PAIR.into())]));
        let client = crate::federation::OutboundClient::for_daemon(
            self.vaults.b.connection_file.clone(),
            "claustrum",
            Some("harness-launch-nonce"),
        );
        let task = tokio::spawn(member_watch::run(
            Arc::clone(&self.member.store),
            client,
            rx,
        ));
        (tx, task)
    }
}

fn add_operator_copy(store: &EncryptedStore, home: &str, adapter: &str) {
    store
        .remote_add_audited(&NewRemoteRecord {
            credential_id: ID.into(),
            home_member: home.into(),
            refresh_adapter: Some(adapter.into()),
            detected_plan: None,
            identity: Default::default(),
            home_version: 1,
            categories: Vec::new(),
        })
        .unwrap();
}

#[tokio::test]
async fn peer_condition_live_watch_propagates_home_only_mutations_and_pins_the_peer_sample() {
    let rig = PeerRig::new("peer-condition-live", "antigravity").await;
    let relay = HomeWatchRelay::new(Arc::clone(&rig.home_handler), rig.vaults.requester_member());
    rig.vaults
        .callosum
        .answer(TARGET_MODULE, fed::OP_REMOTE_WATCH, Reply::HomeWatch(relay));
    let (pairings, task) = rig.watch();
    wait_until(|| rig.member.store.remote_record(ID).unwrap().is_some()).await;
    let before = rig.copy();
    assert_eq!(
        before.source,
        credentials_core::federation::RemoteRecordSource::HomeWatch
    );
    assert_eq!(rig.copy_mark(), None);

    let get = || rig.reader_call(OP_GET_SCOPED, json!({"credential_id": ID}));
    let token = wait_for_signal(get()).await;
    assert_eq!(token["result"]["record_version"], 1);
    assert_eq!(rig.requests(fed::OP_REMOTE_TOKEN).len(), 1);
    let stamp = rig.surface.remote().cached_generation_for_test(ID).unwrap();
    assert!(stamp.1);
    let link = verification_link();
    let report_params = report(1, VERIFY, 403, Some(&link));
    assert_eq!(
        wait_for_signal(rig.reader_call(OP_REPORT_CONDITION, report_params.clone())).await,
        result("accepted", true)
    );
    let mark = rig.mark().unwrap();
    assert_eq!(mark.reason, VERIFY);
    assert_eq!(mark.action_url.as_deref(), Some(link.as_str()));
    assert_eq!(
        rig.requests(fed::OP_REPORT_CONDITION),
        [(rig.target(), report_params)]
    );
    assert_home_event(&rig, "report_condition");
    let reporter: String = rusqlite::Connection::open(rig.vaults.a.store_path())
        .unwrap()
        .query_row(
            "SELECT reporter FROM credential_conditions WHERE credential_id = ?1",
            [ID],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(reporter, rig.vaults.requester_member());
    wait_until(|| rig.copy_mark() == Some(mark.clone())).await;

    let link2 = format!("{link}&replacement=1");
    assert_eq!(
        wait_for_signal(rig.reader_call(OP_REPORT_CONDITION, report(1, VERIFY, 403, Some(&link2))))
            .await,
        result("accepted", true)
    );
    let changed = rig.mark().unwrap();
    assert_eq!(changed.since_ms, mark.since_ms);
    wait_until(|| rig.copy_mark() == Some(changed.clone())).await;
    assert_eq!(rig.copy().last_home_version, before.last_home_version);
    assert_eq!(rig.copy().reported_version, before.reported_version);
    assert_eq!(
        rig.surface.remote().cached_generation_for_test(ID),
        Some(stamp)
    );
    assert_eq!(wait_for_signal(get()).await, token);
    assert_eq!(rig.requests(fed::OP_REMOTE_TOKEN).len(), 1);

    let list = rig.reader_call(OP_LIST_SCOPED, json!({})).await;
    assert_eq!(
        list["result"]["credentials"][0]["condition"],
        json!({"reason":VERIFY, "since_ms": changed.since_ms})
    );
    no_query(&list.to_string());
    let connector = routed_json(&rig.surface, &rig.admin, 56, "connectors.list", json!({})).await;
    assert_eq!(
        connector["result"]["rows"][0]["condition"]["action_url"],
        link2
    );

    let db = rusqlite::Connection::open(rig.vaults.a.store_path()).unwrap();
    db.execute(
        "UPDATE credential_conditions SET since_ms = 7 WHERE credential_id = ?1",
        [ID],
    )
    .unwrap();
    let peer = rig
        .home_handler
        .remote_watch_projection(rig.vaults.requester_member(), PAIR)
        .unwrap();
    let wire = fed::remote_watch_logins_wire(&peer);
    assert_eq!(
        wire[0]["condition"],
        json!({"reason": VERIFY, "since_ms": 7, "action_url": link2})
    );
    pin_samples(
        "peer-list.json",
        &BTreeMap::from([("peer_list_condition", wire[0].clone())]),
    );

    db.execute(
        "UPDATE credentials SET state = 'needs_reauth' WHERE credential_id = ?1",
        [ID],
    )
    .unwrap();
    assert_eq!(
        wait_for_signal(rig.reader_call(OP_CLEAR_CONDITION, clear(1))).await,
        result("cleared", true)
    );
    assert_eq!(
        rig.home.store.meta(ID).unwrap().state,
        RecordState::NeedsReauth
    );
    assert_eq!(rig.mark(), None);
    assert_home_event(&rig, "clear_condition");
    wait_until(|| rig.copy_mark().is_none()).await;
    assert_eq!(
        rig.requests(fed::OP_CLEAR_CONDITION),
        [(rig.target(), clear(1))]
    );
    let audit = rig.member.store.read_audit(None).unwrap();
    assert_eq!(
        audit.iter().filter(|row| row.op == "remote_update").count(),
        3
    );
    assert!(!audit
        .iter()
        .any(|row| matches!(row.op.as_str(), "report_condition" | "clear_condition")));
    let events = rig.member.store.recent_auth_events(30).unwrap();
    assert!(events.iter().any(|event| event.kind == "scoped_first_use"
        && event.principal_id.as_deref() == Some("member-condition-reader")));
    assert!(!events.iter().any(|event| matches!(
        event.kind.as_str(),
        "consumer_report_condition" | "consumer_clear_condition" | "consumer_report_stale"
    )));
    no_query(&format!("{audit:?} {events:?}"));
    drop(pairings);
    wait_for_signal(task).await.unwrap();
}

fn assert_home_event(rig: &PeerRig, op: &str) {
    let audit = rig.home.store.read_audit(None).unwrap();
    let row = audit.last().unwrap();
    assert_eq!(row.op, op);
    assert_eq!(row.actor, rig.vaults.requester_member());
    let events = rig.home.store.recent_auth_events(30).unwrap();
    let event = &events[0];
    assert_eq!(event.kind, format!("consumer_{op}"));
    assert_eq!(event.principal_kind.as_deref(), Some("member"));
    assert_eq!(
        event.principal_id.as_deref(),
        Some(rig.vaults.requester_member())
    );
    assert!(event.applied);
    assert!(event.detail.is_none());
    no_query(&format!("{audit:?} {events:?}"));
}

#[tokio::test]
async fn peer_condition_refusals_are_checked_on_both_vaults_and_mapped() {
    let rig = PeerRig::new("peer-condition-refused", "antigravity").await;
    let home = &rig.home_handler;
    let member = rig.vaults.requester_member();
    let link = verification_link();
    let bad_link = format!("{link}#fragment");
    let good = report(1, VERIFY, 403, Some(&link));
    let home_audit = rig.home.store.read_audit(None).unwrap();
    let home_events = rig.home.store.recent_auth_events(30).unwrap().len();
    rig.add_operator_copy(rig.vaults.home_member(), "antigravity");
    for (params, code) in [
        (
            report(99, "future_reason", 401, Some(&bad_link)),
            "condition_not_admitted",
        ),
        (
            report(99, VERIFY, 401, Some(&bad_link)),
            "condition_status_refused",
        ),
        (
            report(99, VERIFY, 403, Some(&bad_link)),
            "condition_link_refused",
        ),
    ] {
        let response = home.serve(member, fed::OP_REPORT_CONDITION, &params).await;
        no_query(&format!("{response:?}"));
        let expected = refused("accepted", code);
        assert!(matches!(response, fed::HomeAnswer::Reply(body) if body == expected["result"]));
        assert_eq!(rig.reader_call(OP_REPORT_CONDITION, params).await, expected);
    }
    for (method, mut params) in [
        (fed::OP_REPORT_CONDITION, good.clone()),
        (fed::OP_CLEAR_CONDITION, clear(1)),
    ] {
        params[QUERY] = json!(link);
        let response = home.serve(member, method, &params).await;
        assert!(
            matches!(&response, fed::HomeAnswer::InvalidParams(detail) if detail == "invalid condition parameters")
        );
        no_query(&format!("{response:?}"));
    }
    assert!(rig.requests(fed::OP_REPORT_CONDITION).is_empty());
    assert_eq!(rig.home.store.read_audit(None).unwrap(), home_audit);
    assert_eq!(
        rig.home.store.recent_auth_events(30).unwrap().len(),
        home_events
    );
    assert_eq!(rig.mark(), None);

    rig.vaults
        .callosum
        .set_pairing(member, Some("different-pair"));
    assert_eq!(
        wait_for_signal(rig.reader_call(OP_REPORT_CONDITION, good.clone())).await,
        refused("accepted", "not_found")
    );
    assert_eq!(
        wait_for_signal(rig.reader_call(OP_CLEAR_CONDITION, clear(1))).await,
        refused("cleared", "not_found")
    );
    assert_eq!(rig.mark(), None);
    assert_eq!(rig.home.store.read_audit(None).unwrap(), home_audit);
    rig.vaults.callosum.set_pairing(member, Some(PAIR));

    // A result refusal is permanent on the member, regardless of the home's class.
    for code in [
        "not_found",
        "condition_status_refused",
        "condition_link_refused",
    ] {
        rig.vaults.callosum.answer(
            TARGET_MODULE,
            fed::OP_REPORT_CONDITION,
            Reply::Ok(json!({"accepted":false, "error":{"code":code,"class":"transient"}})),
        );
        assert_eq!(
            wait_for_signal(rig.reader_call(OP_REPORT_CONDITION, good.clone())).await,
            refused("accepted", code)
        );
    }
    for response in [
        Reply::RouteRefusal("unknown_method".into()),
        Reply::Ok(json!({"accepted":false,"error":{"code":"future_refusal","class":"permanent"}})),
    ] {
        rig.vaults
            .callosum
            .answer(TARGET_MODULE, fed::OP_REPORT_CONDITION, response);
        assert_eq!(
            wait_for_signal(rig.reader_call(OP_REPORT_CONDITION, good.clone())).await,
            json!({"result":{"accepted":false,"error":{"code":"home_unavailable","class":"transient"}}})
        );
    }
}

#[tokio::test]
async fn peer_condition_checks_adapter_on_the_copy_and_again_on_a_non_admitted_home() {
    let rig = PeerRig::new("peer-condition-adapter", "anthropic").await;
    let params = report(1, VERIFY, 403, None);
    let home = rig.vaults.home_member();
    rig.add_operator_copy(home, "anthropic");
    assert_eq!(
        rig.reader_call(OP_REPORT_CONDITION, params.clone()).await,
        refused("accepted", "condition_not_admitted")
    );
    assert!(rig.requests(fed::OP_REPORT_CONDITION).is_empty());
    assert_eq!(
        wait_for_signal(rig.reader_call(OP_CLEAR_CONDITION, clear(1))).await,
        result("cleared", false)
    );
    assert_eq!(
        rig.requests(fed::OP_CLEAR_CONDITION),
        [(rig.target(), clear(1))]
    );
    rig.member.store.remote_remove_audited(ID).unwrap();
    rig.add_operator_copy(home, "antigravity");
    let audit = rig.home.store.read_audit(None).unwrap();
    let events = rig.home.store.recent_auth_events(30).unwrap().len();
    assert_eq!(
        wait_for_signal(rig.reader_call(OP_REPORT_CONDITION, params.clone())).await,
        refused("accepted", "condition_not_admitted")
    );
    assert_eq!(
        rig.requests(fed::OP_REPORT_CONDITION),
        [(rig.target(), params)]
    );
    assert_eq!(rig.home.store.read_audit(None).unwrap(), audit);
    assert_eq!(rig.home.store.recent_auth_events(30).unwrap().len(), events);
    assert_eq!(rig.copy_mark(), None);
    assert_eq!(rig.mark(), None);
}

#[tokio::test]
async fn peer_condition_home_fences_valid_mutations_at_the_home_version() {
    let rig = PeerRig::new("peer-condition-home-fence", "antigravity").await;
    rig.add_operator_copy(rig.vaults.home_member(), "antigravity");
    let audit = rig.home.store.read_audit(None).unwrap();
    assert_eq!(
        wait_for_signal(rig.reader_call(OP_REPORT_CONDITION, report(2, VERIFY, 403, None))).await,
        result("accepted", true)
    );
    assert_eq!(rig.mark(), None);
    assert_eq!(rig.home.store.read_audit(None).unwrap(), audit);
    let event = &rig.home.store.recent_auth_events(30).unwrap()[0];
    assert_eq!(event.kind, "consumer_report_condition");
    assert!(!event.applied);

    let home = &rig.home_handler;
    let member = rig.vaults.requester_member();
    assert!(
        matches!(home.serve(member, fed::OP_REPORT_CONDITION, &report(1, VERIFY, 403, None)).await,
        fed::HomeAnswer::Reply(body) if body == json!({"accepted":true}))
    );
    let mark = rig.mark();
    let audit = rig.home.store.read_audit(None).unwrap();
    assert_eq!(
        wait_for_signal(rig.reader_call(OP_CLEAR_CONDITION, clear(2))).await,
        result("cleared", false)
    );
    assert_eq!(rig.mark(), mark);
    assert_eq!(rig.home.store.read_audit(None).unwrap(), audit);
    let event = &rig.home.store.recent_auth_events(30).unwrap()[0];
    assert_eq!(event.kind, "consumer_clear_condition");
    assert!(!event.applied);
}

#[tokio::test]
async fn peer_condition_route_debug_redacts_the_same_call_whose_link_reaches_the_home() {
    let rig = PeerRig::new("peer-condition-debug", "antigravity").await;
    let link = verification_link();
    let params = report(1, VERIFY, 403, Some(&link));
    let call = outbound::RouteCall {
        target: outbound::management_surface(&rig.target()),
        prelude: None,
        request: json!({"method":fed::OP_REPORT_CONDITION,"params":params}),
    };
    let debug = format!("{call:?}");
    assert!(debug.contains("[redacted]") && debug.contains(fed::OP_REPORT_CONDITION));
    no_query(&debug);
    let incoming = ReadRequest {
        method: fed::OP_REPORT_CONDITION.into(),
        params: params.clone(),
    };
    no_query(&format!("{incoming:?}"));
    assert_eq!(
        wait_for_signal(rig.vaults.b.outbound.call(
            "test-debug",
            call,
            outbound::CONSUMER_FACING_DEADLINE
        ))
        .await
        .unwrap(),
        json!({"accepted":true})
    );
    assert_eq!(
        rig.requests(fed::OP_REPORT_CONDITION),
        [(rig.target(), params)]
    );
    assert_eq!(rig.mark().unwrap().action_url, Some(link));
}

#[tokio::test]
async fn peer_condition_rechecks_copy_lifetime_before_dispatch_and_keeps_captured_home_afterward() {
    for replacement_home in [None, Some(OTHER_HOME)] {
        let rig = PeerRig::new("peer-condition-copy-race", "antigravity").await;
        rig.add_operator_copy(rig.vaults.home_member(), "antigravity");
        let store = Arc::clone(&rig.member.store);
        let original_home = rig.vaults.home_member().to_owned();
        let old_incarnation = rig.copy().incarnation;
        rig.surface.set_incarnation_hook("admitted", move || {
            store.remote_remove_audited(ID).unwrap();
            add_operator_copy(
                &store,
                replacement_home.unwrap_or(&original_home),
                "antigravity",
            );
            if replacement_home.is_some() {
                // Keep the same incarnation to independently exercise the home check.
                store.force_remote_incarnation_for_test(ID, &old_incarnation);
            }
        });
        assert_eq!(
            rig.reader_call(OP_REPORT_CONDITION, report(1, VERIFY, 403, None))
                .await,
            refused("accepted", "not_found")
        );
        assert!(rig.requests(fed::OP_REPORT_CONDITION).is_empty());
        assert_eq!(rig.mark(), None);
    }

    let rig = Arc::new(PeerRig::new("peer-condition-captured-home", "antigravity").await);
    rig.add_operator_copy(rig.vaults.home_member(), "antigravity");
    let gate = Held::new();
    rig.vaults.callosum.gate_open(&rig.target(), gate.clone());
    let mut request = tokio::spawn({
        let rig = Arc::clone(&rig);
        async move {
            rig.reader_call(OP_REPORT_CONDITION, report(1, VERIFY, 403, None))
                .await
        }
    });
    gate.arrived_before(&mut request).await;
    rig.member.store.remote_remove_audited(ID).unwrap();
    rig.add_operator_copy(OTHER_HOME, "antigravity");
    gate.release(Reply::Ok(json!({})));
    assert_eq!(
        wait_for_signal(request).await.unwrap(),
        result("accepted", true)
    );
    assert_eq!(
        rig.requests(fed::OP_REPORT_CONDITION),
        [(rig.target(), report(1, VERIFY, 403, None))]
    );
    assert_eq!(rig.copy().home_member, OTHER_HOME);
    assert_eq!(rig.copy_mark(), None);
    assert_eq!(rig.mark().unwrap().reason, VERIFY);
}

#[tokio::test]
async fn peer_condition_reports_lost_replies_without_dispatching_report_or_clear_again() {
    let rig = Arc::new(PeerRig::new("peer-condition-lost-replies", "antigravity").await);
    rig.add_operator_copy(rig.vaults.home_member(), "antigravity");
    let response = |field: &str| json!({"result":{(field):false,"error":{"code":"home_unreachable","class":"transient"}}});
    for (consumer_op, federation_op, field, params) in [
        (
            OP_REPORT_CONDITION,
            fed::OP_REPORT_CONDITION,
            "accepted",
            report(1, VERIFY, 403, None),
        ),
        (
            OP_CLEAR_CONDITION,
            fed::OP_CLEAR_CONDITION,
            "cleared",
            clear(1),
        ),
    ] {
        let held = Held::new();
        rig.relay(federation_op, Some(held.clone()));
        let mut request = tokio::spawn({
            let rig = Arc::clone(&rig);
            let params = params.clone();
            async move { rig.reader_call(consumer_op, params).await }
        });
        held.arrived_before(&mut request).await;
        if federation_op == fed::OP_CLEAR_CONDITION {
            assert_eq!(rig.mark(), None);
            let other = rig.home.store.report_condition_in_incarnation(
                ID,
                1,
                &rig.home.store.credential_incarnation(ID).unwrap(),
                credentials_core::store::ConditionReport {
                    reason: INELIGIBLE,
                    provider_status: 403,
                    action_url: None,
                },
                AuditCtx {
                    op: AuditOp::ReportCondition,
                    actor: "other-reader",
                    alarm: None,
                },
                credentials_core::store::AuthEventPrincipal::Reserved("other-reader"),
            );
            assert!(other.unwrap());
        } else {
            assert_eq!(rig.mark().unwrap().reason, VERIFY);
        }
        // A retry would go through a working stand-in and really invoke the home again.
        rig.relay(federation_op, None);
        rig.vaults.callosum.close_connections(false).await;
        assert_eq!(wait_for_signal(request).await.unwrap(), response(field));
        assert_eq!(rig.requests(federation_op), [(rig.target(), params)]);
        assert_eq!(rig.copy_mark(), None);
    }
    assert_eq!(rig.mark().unwrap().reason, INELIGIBLE);
}

#[tokio::test]
async fn peer_condition_malformed_rows_keep_their_marks_and_do_not_end_the_watch() {
    let logs = Logged::default();
    let _capture = tracing::subscriber::set_default(logs.clone());
    let rig = PeerRig::new("peer-condition-invalid-rows", "antigravity").await;
    let link = verification_link();
    let disallowed = format!("{link}#fragment");
    let malformed = [
        Value::Null,
        json!("not an object"),
        json!({"reason": VERIFY, "since_ms": 1, "action_url": disallowed}),
        json!({"reason": INELIGIBLE, "since_ms": 1, "action_url": link}),
        json!({"reason": "future_reason", "since_ms": 1, "action_url": link}),
        json!({"reason": VERIFY, "since_ms": -1}),
        json!({"reason": VERIFY, "since_ms": 9_007_199_254_740_992_u64}),
        json!({"reason": VERIFY, "since_ms": "1"}),
        json!({"reason": "", "since_ms": 1}),
        json!({"reason": "Invalid", "since_ms": 1}),
        json!({"reason": "invalid-reason", "since_ms": 1}),
        json!({"reason": QUERY, "since_ms": 1}),
    ];
    let initial = json!({"reason": VERIFY, "since_ms": 11, "action_url": link});
    let row = |id: &str, condition: Option<&Value>| {
        let mut row = json!({"credential_id":id, "state":"active", "refresh_adapter":"antigravity", "identity":{}, "categories":[], "home_version":1});
        if let Some(condition) = condition {
            row["condition"] = condition.clone();
        }
        row
    };
    let notice = |seq, logins: Vec<Value>| json!({"kind":"snapshot", "home":rig.vaults.home_member(), "epoch":"ab".repeat(16), "seq":seq, "logins":logins});
    let ids: Vec<_> = (0..malformed.len())
        .map(|n| format!("oauth:malformed-{n}"))
        .collect();
    rig.vaults.callosum.answer(
        TARGET_MODULE,
        fed::OP_REMOTE_WATCH,
        Reply::Watch(notice(
            1,
            ids.iter().map(|id| row(id, Some(&initial))).collect(),
        )),
    );
    let (pairings, task) = rig.watch();
    let store = &rig.member.store;
    wait_until(|| store.remote_record(ids.last().unwrap()).unwrap().is_some()).await;
    let condition = |id: &str| {
        let copy = store.remote_record(id).unwrap().unwrap();
        store
            .remote_record_condition(id, &copy.incarnation)
            .unwrap()
    };
    let saved: Vec<_> = ids.iter().map(|id| condition(id)).collect();
    assert!(saved.iter().all(Option::is_some));
    let mut incoming: Vec<_> = ids
        .iter()
        .zip(&malformed)
        .map(|(id, bad)| row(id, Some(bad)))
        .collect();
    let valid = json!({"reason":"future_reason", "since_ms":9_007_199_254_740_991_u64});
    incoming.push(row(ID, Some(&valid)));
    rig.vaults
        .callosum
        .watch_snapshot(Some(notice(2, incoming)))
        .await;
    wait_until(|| store.remote_record(ID).unwrap().is_some()).await;
    assert_eq!(
        ids.iter().map(|id| condition(id)).collect::<Vec<_>>(),
        saved
    );
    assert_eq!(rig.copy_mark().unwrap().reason, "future_reason");
    assert_eq!(rig.copy_mark().unwrap().since_ms, 9_007_199_254_740_991);
    assert_eq!(rig.requests(fed::OP_REMOTE_WATCH).len(), 1);
    {
        let logs = logs.0.lock().unwrap();
        assert_eq!(
            logs.matches("home watch row rejected; existing row unchanged")
                .count(),
            malformed.len()
        );
        no_query(&logs);
    }

    rig.vaults
        .callosum
        .watch_snapshot(Some(notice(3, vec![row(ID, None)])))
        .await;
    wait_until(|| rig.copy_mark().is_none()).await;
    assert_eq!(rig.requests(fed::OP_REMOTE_WATCH).len(), 1);

    rig.vaults
        .callosum
        .watch_snapshot(Some(notice(4, vec![row(ID, Some(&initial))])))
        .await;
    wait_until(|| rig.copy_mark().is_some()).await;
    rig.vaults.callosum.answer(
        TARGET_MODULE,
        fed::OP_REMOTE_WATCH,
        Reply::RouteRefusal("home_unavailable".into()),
    );
    rig.vaults.callosum.watch_snapshot(None).await;
    wait_until(|| logs.0.lock().unwrap().contains("stream_end")).await;
    let paired = pairings.borrow().clone();
    pairings.send_replace(paired);
    wait_until(|| rig.requests(fed::OP_REMOTE_WATCH).len() == 2).await;
    rig.vaults
        .callosum
        .reply_fence(&rig.vaults.b.outbound)
        .await;
    assert_eq!(
        rig.copy_mark().unwrap().action_url.as_deref(),
        Some(link.as_str())
    );
    drop(pairings);
    wait_for_signal(task).await.unwrap();

    let PeerRig {
        vaults,
        member,
        surface,
        admin,
        token,
        _root,
        ..
    } = rig;
    drop((member, surface, admin));
    let restarted = HomeStore::open(&vaults.b.data_dir);
    let restarted_surface = Arc::new(ReadSurface::new(
        Arc::clone(&restarted.engine),
        FetchLimiter::new(Caps::default()),
    ));
    let key = MasterKey::from_bytes([42; MASTER_KEY_LEN]);
    let restarted_admin = Arc::new(admin_surface::AdminSurface::new(
        Arc::clone(&restarted.engine),
        credentials_core::admin_auth::AdminMacKey::derive(&key),
        credentials_core::vault_id_for(&vaults.b.data_dir).unwrap(),
        key.key_id(),
    ));
    restarted_admin.record_bind_at(CHANNEL, 1, subc_protocol::Principal::Direct, "");
    restarted_admin.record_bind_at(56, 1, reserved("cingulate"), "");
    let list = routed_json(
        &restarted_surface,
        &restarted_admin,
        CHANNEL,
        OP_LIST_SCOPED,
        json!({"enrollment_token": token}),
    )
    .await;
    assert_eq!(
        list["result"]["credentials"][0]["condition"],
        json!({"reason":VERIFY, "since_ms":11})
    );
    let connectors = routed_json(
        &restarted_surface,
        &restarted_admin,
        56,
        "connectors.list",
        json!({}),
    )
    .await;
    assert_eq!(connectors["result"]["rows"][0]["condition"], initial);
}
