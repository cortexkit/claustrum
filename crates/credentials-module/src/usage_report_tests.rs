use super::federation_fixture_support::{
    self as support, Held, Ledger, Reply, SharedCallosumStandIn,
};
use super::*;
use crate::usage_forwarder::{self, UsageForwarder};

const USAGE_ID: &str = "oauth:claude:synthetic";

fn usage_enrollment(store: &EncryptedStore) -> String {
    let secret = "c".repeat(64);
    let hash = credentials_core::enrollment::enrollment_secret_hash(&secret).unwrap();
    let proposed = store.propose_enrollment("synthetic", &hash).unwrap();
    store
        .approve_enrollment(&proposed.request_id, "synthetic", "operator")
        .unwrap();
    match store
        .poll_enrollment(&proposed.request_id, &secret)
        .unwrap()
    {
        credentials_core::enrollment::EnrollmentPoll::Approved { token, .. } => token,
        other => panic!("expected enrollment token: {other:?}"),
    }
}

fn usage_seed(store: &EncryptedStore) {
    store
        .create(
            USAGE_ID,
            &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"synthetic".to_vec(), None),
        )
        .unwrap();
}

fn usage_grant(
    store: &EncryptedStore,
    kind: &str,
    name: &str,
    selector_kind: SelectorKind,
    selector: &str,
    operation: GrantOperation,
) {
    store
        .create_read_grant_audited(
            kind,
            name,
            selector_kind,
            selector,
            operation,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap()
}

async fn usage_frame(
    surface: &Arc<ReadSurface>,
    admin: &Arc<admin_surface::AdminSurface>,
    principal: Option<subc_protocol::Principal>,
    params: serde_json::Value,
) -> Frame {
    deposit_cookie_frame(surface, admin, principal, OP_USAGE_REPORT_SCOPED, params).await
}

#[test]
fn usage_report_scoped_manifest_and_request_key_set_are_pinned() {
    let manifest = manifest("claustrum", None);
    let ProviderRole::ManagementSurface { operations, .. } = &manifest.provides[0] else {
        panic!("management surface")
    };
    let op = operations
        .iter()
        .find(|op| op.name == OP_USAGE_REPORT_SCOPED)
        .expect("declared usage op");
    assert_eq!(op.kind, ManagementOperationKind::Query);
    for token in [None, Some("synthetic-token".into())] {
        let expected = if token.is_some() {
            vec!["credential_id", "reading", "enrollment_token"]
        } else {
            vec!["credential_id", "reading"]
        };
        assert_request_key_set(
            read_surface::UsageReportScopedParams {
                credential_id: USAGE_ID.into(),
                reading: json!({}),
                enrollment_token: token,
            },
            &expected,
            OP_USAGE_REPORT_SCOPED,
        );
    }
}

#[tokio::test]
async fn usage_report_scoped_granted_enrollment_queues_vouched_row_and_records_first_use_once() {
    let (surface, admin, store) = deposit_cookie_rig(201);
    usage_seed(&store);
    usage_grant(
        &store,
        "enrolled",
        "synthetic",
        SelectorKind::Exact,
        USAGE_ID,
        GrantOperation::Read,
    );
    let token = usage_enrollment(&store);
    let audit = store.read_audit(None).unwrap().len();
    let reading =
        json!({"observedAtMs": 12, "provider": "claude", "headers": {"arbitrary": "opaque"}});
    for _ in 0..2 {
        let frame = usage_frame(
            &surface,
            &admin,
            None,
            json!({
                "credential_id": USAGE_ID, "enrollment_token": token, "reading": reading,
            }),
        )
        .await;
        assert_eq!(frame.header.ty, FrameType::Response);
        assert_eq!(
            deposit_cookie_body(&frame),
            json!({"result":{"accepted":true}})
        );
    }
    assert_eq!(
        surface.usage.pending(),
        vec![json!({
            "observedAtMs":12, "provider":"claude", "headers":{"arbitrary":"opaque"},
            "credentialId":USAGE_ID, "vouched":{"principal":"enrolled:synthetic", "credentialId":USAGE_ID},
        })]
    );
    assert_eq!(store.read_audit(None).unwrap().len(), audit);
    let events: Vec<_> = store
        .recent_auth_events(100)
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == "scoped_first_use" && event.credential_id == USAGE_ID)
        .collect();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].principal_kind.as_deref(), Some("enrolled"));
    assert_eq!(events[0].principal_id.as_deref(), Some("synthetic"));
    assert_eq!(events[0].detail.as_deref(), Some("read"));
}

#[tokio::test]
async fn usage_report_scoped_category_grants_work_and_refusals_are_get_scoped_bytes() {
    let (surface, admin, store) = deposit_cookie_rig(202);
    usage_seed(&store);
    store
        .set_categories_audited(
            USAGE_ID,
            credentials_core::store::SetCategoryMode::Set,
            &["llm-provider".into()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
    usage_grant(
        &store,
        "reserved",
        "reader",
        SelectorKind::Category,
        "llm-provider",
        GrantOperation::Read,
    );
    let principal = Some(reserved("reader"));
    let good = usage_frame(
        &surface,
        &admin,
        principal.clone(),
        json!({"credential_id":USAGE_ID,"reading":{}}),
    )
    .await;
    assert_eq!(
        deposit_cookie_body(&good),
        json!({"result":{"accepted":true}})
    );
    assert_eq!(
        surface.usage.pending()[0]["vouched"]["principal"],
        "reserved:reader"
    );
    for (who, id) in [
        (Some(reserved("ungranted")), USAGE_ID),
        (principal.clone(), "unknown"),
    ] {
        let report = usage_frame(
            &surface,
            &admin,
            who.clone(),
            json!({"credential_id":id,"reading":{}}),
        )
        .await;
        let get = deposit_cookie_frame(
            &surface,
            &admin,
            who,
            OP_GET_SCOPED,
            json!({"credential_id":id}),
        )
        .await;
        assert_eq!(report.body, get.body);
        assert_eq!(
            deposit_cookie_body(&report),
            json!({"result":{"error":{"code":"not_found","class":"permanent"}}})
        );
    }
    store
        .revoke_read_grant_audited(
            "reserved",
            "reader",
            SelectorKind::Category,
            "llm-provider",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantRevoke),
        )
        .unwrap();
    let report = usage_frame(
        &surface,
        &admin,
        principal.clone(),
        json!({"credential_id":USAGE_ID,"reading":{}}),
    )
    .await;
    let get = deposit_cookie_frame(
        &surface,
        &admin,
        principal,
        OP_GET_SCOPED,
        json!({"credential_id":USAGE_ID}),
    )
    .await;
    assert_eq!(report.body, get.body);
    assert_eq!(surface.usage.pending().len(), 1);
}

#[tokio::test]
async fn usage_report_scoped_revoked_enrollment_never_falls_back_to_reserved_identity() {
    let (surface, admin, store) = deposit_cookie_rig(203);
    usage_seed(&store);
    usage_grant(
        &store,
        "enrolled",
        "synthetic",
        SelectorKind::Exact,
        USAGE_ID,
        GrantOperation::Read,
    );
    usage_grant(
        &store,
        "reserved",
        "reader",
        SelectorKind::Exact,
        USAGE_ID,
        GrantOperation::Read,
    );
    let token = usage_enrollment(&store);
    store.revoke_enrollment("synthetic", "operator").unwrap();
    let params = json!({"credential_id":USAGE_ID,"enrollment_token":token});
    let mut report_params = params.clone();
    report_params["reading"] = json!({});
    let report = usage_frame(&surface, &admin, Some(reserved("reader")), report_params).await;
    let get = deposit_cookie_frame(
        &surface,
        &admin,
        Some(reserved("reader")),
        OP_GET_SCOPED,
        params,
    )
    .await;
    assert_eq!(report.body, get.body);
    assert_eq!(
        deposit_cookie_body(&report)["result"]["error"]["code"],
        "not_found"
    );
    assert!(surface.usage.pending().is_empty());
}

#[tokio::test]
async fn usage_report_scoped_reading_accepts_15360_bytes_and_refuses_15361_and_invalid_shapes() {
    let (surface, admin, store) = deposit_cookie_rig(204);
    usage_seed(&store);
    usage_grant(
        &store,
        "reserved",
        "reader",
        SelectorKind::Exact,
        USAGE_ID,
        GrantOperation::Read,
    );
    let principal = Some(reserved("reader"));
    let reading = json!({"x": "a".repeat(15_352)});
    assert_eq!(serde_json::to_vec(&reading).unwrap().len(), 15_360);
    let good = usage_frame(
        &surface,
        &admin,
        principal.clone(),
        json!({"credential_id":USAGE_ID,"reading":reading}),
    )
    .await;
    assert_eq!(
        deposit_cookie_body(&good),
        json!({"result":{"accepted":true}})
    );
    let invalid = [
        json!({"x":"a".repeat(15_353)}),
        json!({"credentialId":null}),
        json!({"vouched":null}),
        json!([]),
        json!(null),
        json!(1),
        json!("object"),
    ];
    assert_eq!(serde_json::to_vec(&invalid[0]).unwrap().len(), 15_361);
    for reading in invalid {
        let refused = usage_frame(
            &surface,
            &admin,
            principal.clone(),
            json!({"credential_id":USAGE_ID,"reading":reading}),
        )
        .await;
        assert_eq!(refused.header.ty, FrameType::Error);
        assert_eq!(deposit_cookie_body(&refused)["code"], "invalid_params");
    }
    assert_eq!(surface.usage.pending().len(), 1);
}

#[test]
fn usage_report_scoped_insula_vectors_match_row_and_decode_ignored_reason() {
    use sha2::{Digest, Sha256};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/insula/usage-observe-v1");
    let sums = std::fs::read_to_string(root.join("SHA256SUMS")).unwrap();
    assert_eq!(sums.lines().count(), 9);
    for line in sums.lines() {
        let (sum, name) = line.split_once("  ").unwrap();
        assert_eq!(
            format!(
                "{:x}",
                Sha256::digest(std::fs::read(root.join(name)).unwrap())
            ),
            sum,
            "{name}"
        );
    }
    let request: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("claustrum-vouched-claude-request.json")).unwrap(),
    )
    .unwrap();
    let expected = &request["params"]["observations"][0];
    let mut reading = expected.as_object().unwrap().clone();
    reading.remove("credentialId");
    reading.remove("vouched");
    assert_eq!(
        usage_forwarder::vouched_row(reading, USAGE_ID, "enrolled", "synthetic"),
        *expected
    );
    let reply = usage_forwarder::decode_reply(
        serde_json::from_slice(
            &std::fs::read(root.join("claustrum-vouched-claude-reply.json")).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let queue = UsageForwarder::default();
    queue.record_reply(2, Some(reply));
    assert_eq!(
        queue.metrics(),
        json!({"usageForwardedRows":2,"usageDroppedRows":0,"usageIgnoredReasons":{"unknown_credential":1}})
    );
}

fn usage_row(id: &str, reading: serde_json::Value) -> serde_json::Value {
    usage_forwarder::vouched_row(
        reading.as_object().unwrap().clone(),
        id,
        "enrolled",
        "synthetic",
    )
}

#[test]
fn usage_report_scoped_queue_holds_16_credentials_and_evicts_only_on_the_17th() {
    let queue = UsageForwarder::default();
    for id in 0..16 {
        queue.enqueue(usage_row(&format!("credential-{id}"), json!({})));
    }
    assert_eq!(queue.pending().len(), 16);
    assert_eq!(queue.metrics()["usageDroppedRows"], 0);
    queue.enqueue(usage_row("credential-16", json!({})));
    assert_eq!(queue.pending().len(), 16);
    assert_eq!(queue.pending()[0]["credentialId"], "credential-1");
    assert_eq!(queue.pending()[15]["credentialId"], "credential-16");
    assert_eq!(queue.metrics()["usageDroppedRows"], 1);
}

#[tokio::test(start_paused = true)]
async fn usage_report_scoped_coalesces_newest_and_tie_latest_once_in_one_attested_batch() {
    let root = support::temp_root("usage-coalesce");
    let stand_in = SharedCallosumStandIn::start(&root).await;
    // The federation stand-in scripts replies under TARGET_MODULE but records each
    // route's real target in its ledger, which we assert below is insula.
    stand_in.answer(
        support::TARGET_MODULE,
        "usage.observe",
        Reply::Ok(json!({"accepted":2,"ignored":[]})),
    );
    let client = federation::OutboundClient::for_daemon(
        stand_in.connection_file(),
        "claustrum",
        Some("usage-nonce"),
    );
    let queue = Arc::new(UsageForwarder::default());
    queue.enqueue(usage_row(
        USAGE_ID,
        json!({"observedAtMs": 12,"value":"old"}),
    ));
    queue.enqueue(usage_row(
        USAGE_ID,
        json!({"observedAtMs": 14,"value":"new"}),
    ));
    queue.enqueue(usage_row(
        USAGE_ID,
        json!({"observedAtMs": 13,"value":"late-but-old"}),
    ));
    queue.enqueue(usage_row(
        USAGE_ID,
        json!({"observedAtMs": 14,"value":"tie-latest"}),
    ));
    // Provider fields, including invalid timestamps, remain insula's responsibility.
    queue.enqueue(usage_row("no-time", json!({"observedAtMs":"invalid"})));
    let guard = AbortOnDrop(Arc::clone(&queue).spawn(client));
    tokio::task::yield_now().await;
    assert!(stand_in.methods("insula").is_empty());
    tokio::time::advance(usage_forwarder::USAGE_FLUSH_INTERVAL).await;
    support::wait_until(|| queue.metrics()["usageForwardedRows"] == 2).await;
    let requests: Vec<_> = stand_in
        .ledger()
        .into_iter()
        .filter_map(|entry| match entry {
            Ledger::Request {
                target,
                method,
                params,
            } if target == "insula" && method == "usage.observe" => Some(params),
            _ => None,
        })
        .collect();
    assert_eq!(
        requests,
        vec![json!({"observations":[
            usage_row(USAGE_ID, json!({"observedAtMs":14,"value":"tie-latest"})),
            usage_row("no-time", json!({"observedAtMs":"invalid"})),
        ]})]
    );
    let opens = stand_in.opens("insula");
    assert_eq!(opens.len(), 1);
    assert_eq!(
        opens[0]["consumer_identity"],
        json!({"module_id":"claustrum","launch_nonce":"usage-nonce"})
    );
    assert_eq!(
        opens[0]["target"],
        serde_json::to_value(federation::management_surface("insula")).unwrap()
    );
    assert!(queue.pending().is_empty());
    tokio::time::advance(usage_forwarder::USAGE_FLUSH_INTERVAL).await;
    tokio::task::yield_now().await;
    assert_eq!(stand_in.methods("insula"), ["usage.observe"]);
    assert_eq!(queue.metrics()["usageDroppedRows"], 3);
    drop(guard);
}

#[tokio::test(start_paused = true)]
async fn usage_report_scoped_stalled_insula_never_blocks_reports_or_reads_and_batch_is_dropped() {
    let (surface, admin, store) = deposit_cookie_rig(205);
    usage_seed(&store);
    usage_grant(
        &store,
        "reserved",
        "reader",
        SelectorKind::Exact,
        USAGE_ID,
        GrantOperation::Read,
    );
    let root = support::temp_root("usage-stalled");
    let stand_in = SharedCallosumStandIn::start(&root).await;
    let held = Held::new();
    stand_in.answer(
        support::TARGET_MODULE,
        "usage.observe",
        Reply::Hold(held.clone()),
    );
    let client = federation::OutboundClient::for_daemon(
        stand_in.connection_file(),
        "claustrum",
        Some("usage-nonce"),
    );
    let principal = Some(reserved("reader"));
    let initial = usage_frame(
        &surface,
        &admin,
        principal.clone(),
        json!({"credential_id":USAGE_ID,"reading":{}}),
    )
    .await;
    assert_eq!(
        deposit_cookie_body(&initial),
        json!({"result":{"accepted":true}})
    );
    let queue = Arc::clone(&surface.usage);
    let delivering_queue = Arc::clone(&queue);
    let delivery = tokio::spawn(async move { delivering_queue.flush(&client).await });
    support::wait_for_signal(held.arrived()).await;
    assert!(!delivery.is_finished());
    let report = usage_frame(
        &surface,
        &admin,
        principal.clone(),
        json!({"credential_id":USAGE_ID,"reading":{"observedAtMs":2}}),
    );
    let get = deposit_cookie_frame(
        &surface,
        &admin,
        principal,
        OP_GET_SCOPED,
        json!({"credential_id":USAGE_ID}),
    );
    let (reported, got) = support::wait_for_signal(async { tokio::join!(report, get) }).await;
    assert_eq!(
        deposit_cookie_body(&reported),
        json!({"result":{"accepted":true}})
    );
    assert_eq!(
        deposit_cookie_body(&got)["result"]["payload"],
        json!(b"synthetic")
    );
    assert!(
        !delivery.is_finished(),
        "neither route waited for insula's reply"
    );
    support::resolved_after_advance(delivery, usage_forwarder::USAGE_DELIVERY_DEADLINE).await;
    assert_eq!(queue.metrics()["usageDroppedRows"], 1);
    assert_eq!(
        queue.pending().len(),
        1,
        "reports admitted during I/O survive for the next batch"
    );
    let ModuleControlResponse::HealthCheck {
        metrics: Some(metrics),
        ..
    } = health_report_with_usage(&surface)
    else {
        panic!("health metrics")
    };
    assert_eq!(metrics["usageDroppedRows"], 1);
    assert_eq!(metrics["usageForwardedRows"], 0);
    assert_eq!(metrics["usageIgnoredReasons"], json!({}));
    assert_eq!(stand_in.methods("insula"), ["usage.observe"]);
}

#[tokio::test]
async fn usage_report_scoped_wire_contract_goldens_are_checked() {
    let (surface, admin, store) = deposit_cookie_rig(206);
    usage_seed(&store);
    usage_grant(
        &store,
        "reserved",
        "reader",
        SelectorKind::Exact,
        USAGE_ID,
        GrantOperation::Read,
    );
    let request = secret_golden("usage.report_scoped.request");
    assert_eq!(request["method"], OP_USAGE_REPORT_SCOPED);
    let params: read_surface::UsageReportScopedParams =
        serde_json::from_value(request["params"].clone()).unwrap();
    assert_eq!(serde_json::to_value(&params).unwrap(), request["params"]);
    let reply = usage_frame(
        &surface,
        &admin,
        Some(reserved("reader")),
        request["params"].clone(),
    )
    .await;
    assert_eq!(
        deposit_cookie_body(&reply),
        secret_golden("usage.report_scoped.result")
    );
}

#[test]
fn usage_report_scoped_malformed_reply_drops_batch_without_accepting_partial_verdicts() {
    let queue = UsageForwarder::default();
    for reply in [
        json!({}),
        json!({"accepted":1,"ignored":{}}),
        json!({"accepted":0,"ignored":[]}),
    ] {
        queue.record_reply(1, usage_forwarder::decode_reply(reply).ok());
    }
    assert_eq!(queue.metrics()["usageDroppedRows"], 3);
    assert_eq!(queue.metrics()["usageForwardedRows"], 0);
}
