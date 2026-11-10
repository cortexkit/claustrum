use super::home_watch_projection_tests::{login, rig};
use super::*;
use subc_protocol::{EnvelopeHeader, Flags, Frame, FrameType, Priority, PROTOCOL_VERSION};
use tokio::sync::mpsc;

const MEMBER: &str = "fed-computer:aa11bb22cc33dd44ee55ff6600112233";
const HOME: &str = "fed-computer:00000000000000000000000000000001";
const OTHER: &str = "fed-computer:00000000000000000000000000000002";

fn paired(home: HomeVault) -> HomeVault {
    home.with_callosum_stub(Arc::new(|method| {
        assert_eq!(method, "callosum.paired_devices_read");
        Some(json!({"devices":[
            {"class":"computer","fingerprint":MEMBER.strip_prefix("fed-computer:").unwrap(),"pairing_id":"pair-1"},
            {"class":"computer","fingerprint":OTHER.strip_prefix("fed-computer:").unwrap(),"pairing_id":"pair-other"}
        ]}))
    }))
}

fn setup(home: &HomeVault) {
    let store = home.engine.store();
    store
        .set_federation_self_member_audited(HOME, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    store
        .create(
            VAULT_TRANSFER_ID,
            &VaultRecord::new_static(
                CredentialKind::KemKey,
                "test",
                credentials_core::kem::pem_from_scalar(&[197; 32]).into_bytes(),
                None,
            ),
        )
        .unwrap();
}

fn header(channel: u16, corr: u64) -> EnvelopeHeader {
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        channel,
        1,
        corr,
        Vec::new(),
    )
    .unwrap()
    .header
}

async fn open(
    home: &HomeVault,
    writer: &mpsc::Sender<Frame>,
    channel: u16,
    corr: u64,
    member: &str,
    params: Value,
) {
    let header = header(channel, corr);
    let pending = home.remote_watches.register(header);
    home.remote_watches
        .open(home, pending, writer, header, member, &params)
        .await
        .unwrap();
}

fn body(frame: Frame, ty: FrameType) -> Value {
    assert_eq!(frame.header.ty, ty);
    serde_json::from_slice(&frame.body).unwrap()
}

fn error(code: &str, class: &str) -> Value {
    json!({"result":{"error":{"code":code,"class":class}}})
}

#[tokio::test]
async fn remote_watch_open_checks_pairing_before_strict_params_and_matches_token_refusals() {
    let (_root, home, _conn) = rig();
    let home = home.with_callosum_stub(Arc::new(|_| Some(json!({"devices":[]}))));
    let (writer, mut rx) = mpsc::channel(8);
    for params in [
        json!({}),
        json!({"unexpected":true}),
        json!([]),
        json!(null),
    ] {
        open(&home, &writer, 1, 1, MEMBER, params.clone()).await;
        let answer = rx.try_recv().unwrap();
        let HomeAnswer::Reply(token) = home.serve(MEMBER, OP_REMOTE_TOKEN, &params).await else {
            panic!("pairing precedes parse");
        };
        assert_eq!(answer.header.ty, FrameType::Response);
        assert_eq!(
            answer.body,
            serde_json::to_vec(&json!({"result":token})).unwrap()
        );
        assert_eq!(home.remote_watches.entry_count(), 0);
    }
    let params = json!({"handle":"test-bearer"});
    open(&home, &writer, 1, 1, MEMBER, params.clone()).await;
    let wire = body(rx.try_recv().unwrap(), FrameType::Error);
    let HomeAnswer::InvalidParams(detail) = home.serve(MEMBER, OP_REMOTE_TOKEN, &params).await
    else {
        panic!("bearer refusal must come first");
    };
    assert_eq!(wire["code"], "invalid_params");
    assert_eq!(wire["message"], format!("params not decodable: {detail}"));
}

#[tokio::test]
async fn remote_watch_open_rejects_every_nonempty_or_nonobject_params_before_setup() {
    let (_root, home, _conn) = rig();
    let home = paired(home);
    let (writer, mut rx) = mpsc::channel(8);
    for params in [
        json!({"unexpected":true}),
        json!([]),
        json!(null),
        json!(""),
        json!(0),
        json!(false),
    ] {
        open(&home, &writer, 1, 1, MEMBER, params).await;
        assert_eq!(
            body(rx.try_recv().unwrap(), FrameType::Error)["code"],
            "invalid_params"
        );
        assert_eq!(home.remote_watches.entry_count(), 0);
    }
    open(&home, &writer, 1, 1, MEMBER, json!({})).await;
    assert_eq!(
        body(rx.try_recv().unwrap(), FrameType::Response),
        error("remote_setup_incomplete", "permanent")
    );
}

#[tokio::test]
async fn remote_watch_open_setup_key_and_pairing_unavailability_keep_their_answers() {
    let (_root, home, conn) = rig();
    let home = paired(home);
    let (writer, mut rx) = mpsc::channel(8);
    home.engine
        .store()
        .set_federation_self_member_audited(HOME, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    open(&home, &writer, 1, 1, MEMBER, json!({})).await;
    let mut expected = error("remote_setup_incomplete", "permanent");
    expected["result"]["error"]["remedy_member"] = json!(HOME);
    assert_eq!(body(rx.try_recv().unwrap(), FrameType::Response), expected);
    conn.execute("DROP TABLE settings", []).unwrap();
    open(&home, &writer, 1, 1, MEMBER, json!({})).await;
    assert_eq!(
        body(rx.try_recv().unwrap(), FrameType::Response),
        error("store_error", "transient")
    );
    for lookup in [None, Some(json!({"code":"fed_not_ready"}))] {
        let (_root, home, _conn) = rig();
        let home = home.with_callosum_stub(Arc::new(move |_| lookup.clone()));
        open(&home, &writer, 1, 1, MEMBER, json!({"bad":true})).await;
        assert_eq!(
            body(rx.try_recv().unwrap(), FrameType::Response),
            error("home_unavailable", "transient")
        );
    }
}

#[tokio::test]
async fn remote_watch_open_first_snapshot_is_sorted_and_no_grant_is_empty_without_writes() {
    let (_root, home, conn) = rig();
    let home = paired(home);
    setup(&home);
    let store = home.engine.store();
    for id in ["oauth:z", "oauth:a"] {
        store.create(id, &login()).unwrap();
    }
    let (writer, mut rx) = mpsc::channel(8);
    let mut writes = store.subscribe_writes();
    open(&home, &writer, 1, 1, MEMBER, json!({})).await;
    let snapshot = body(rx.try_recv().unwrap(), FrameType::StreamData);
    assert_eq!(snapshot["logins"], json!([]));
    assert!(!writes.has_changed().unwrap());
    for id in ["oauth:a", "oauth:z"] {
        store
            .create_member_grant_audited(
                MEMBER,
                MemberGrantOperation::RemoteRead,
                &MemberGrantSelector::Exact(id.into()),
                "pair-1",
            )
            .unwrap();
    }
    writes.borrow_and_update();
    let version: i64 = conn
        .query_row("PRAGMA data_version", [], |row| row.get(0))
        .unwrap();
    open(&home, &writer, 1, 2, MEMBER, json!({})).await;
    let snapshot = body(rx.try_recv().unwrap(), FrameType::StreamData);
    assert_eq!(snapshot["home"], HOME);
    assert_eq!(snapshot["kind"], "snapshot");
    assert_eq!(snapshot["seq"], 1);
    assert_eq!(snapshot.as_object().unwrap().len(), 5);
    let epoch = snapshot["epoch"].as_str().unwrap();
    assert_eq!(epoch.len(), 32);
    assert!(epoch.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(
        snapshot["logins"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["credential_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["oauth:a", "oauth:z"]
    );
    assert_eq!(
        conn.query_row("PRAGMA data_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        version
    );
    assert!(!writes.has_changed().unwrap());
    assert_eq!(home.remote_watches.entry_count(), 2);
}

#[tokio::test]
async fn remote_watch_four_streams_and_fifth_evicts_oldest_only_after_success() {
    let (_root, home, conn) = rig();
    let home = paired(home);
    setup(&home);
    let (writer, mut rx) = mpsc::channel(16);
    open(&home, &writer, 3, 99, OTHER, json!({})).await;
    body(rx.try_recv().unwrap(), FrameType::StreamData);
    for corr in 1..=4 {
        open(&home, &writer, 1, corr, MEMBER, json!({})).await;
        let snapshot = rx.try_recv().unwrap();
        assert_eq!(snapshot.header.corr, corr);
        assert_eq!(body(snapshot, FrameType::StreamData)["seq"], 1);
        assert!(rx.try_recv().is_err(), "the fourth stream must not evict");
    }
    assert_eq!(home.remote_watches.entry_count(), 5);
    open(&home, &writer, 1, 5, MEMBER, json!({"bad":true})).await;
    assert_eq!(
        body(rx.try_recv().unwrap(), FrameType::Error)["code"],
        "invalid_params"
    );
    assert_eq!(home.remote_watches.entry_count(), 5);
    assert!(rx.try_recv().is_err());
    conn.execute("ALTER TABLE member_grants RENAME TO unavailable_grants", [])
        .unwrap();
    open(&home, &writer, 1, 5, MEMBER, json!({})).await;
    assert_eq!(
        body(rx.try_recv().unwrap(), FrameType::Response),
        error("store_error", "transient")
    );
    assert_eq!(home.remote_watches.entry_count(), 5);
    assert!(
        rx.try_recv().is_err(),
        "a failed first projection cannot evict"
    );
    conn.execute("ALTER TABLE unavailable_grants RENAME TO member_grants", [])
        .unwrap();
    open(&home, &writer, 2, 5, MEMBER, json!({})).await;
    let end = rx.try_recv().unwrap();
    assert_eq!(
        (end.header.ty, end.header.channel, end.header.corr),
        (FrameType::StreamEnd, 1, 1)
    );
    let snapshot = rx.try_recv().unwrap();
    assert_eq!((snapshot.header.channel, snapshot.header.corr), (2, 5));
    assert_eq!(body(snapshot, FrameType::StreamData)["seq"], 1);
    assert_eq!(home.remote_watches.entry_count(), 5);
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn remote_watch_correlation_cancel_route_close_and_drain_preserve_other_entries() {
    let (_root, home, _conn) = rig();
    let home = paired(home);
    setup(&home);
    let (writer, mut rx) = mpsc::channel(16);
    for (channel, corr) in [(1, 1), (1, 2), (2, 1)] {
        open(&home, &writer, channel, corr, MEMBER, json!({})).await;
        body(rx.try_recv().unwrap(), FrameType::StreamData);
    }
    home.remote_watches.cancel(1, 99);
    assert_eq!(home.remote_watches.entry_count(), 3);
    home.remote_watches.cancel(1, 1);
    assert_eq!(home.remote_watches.entry_count(), 2);
    home.remote_watches.close(1);
    assert_eq!(home.remote_watches.entry_count(), 1);
    assert!(rx.try_recv().is_err(), "teardown is silent");
    home.remote_watches.finish_all().await.unwrap();
    let end = rx.try_recv().unwrap();
    assert_eq!(
        (end.header.ty, end.header.channel, end.header.corr),
        (FrameType::StreamEnd, 2, 1)
    );
    assert_eq!(home.remote_watches.entry_count(), 0);
    open(&home, &writer, 1, 3, MEMBER, json!({"bad":true})).await;
    assert_eq!(
        body(rx.try_recv().unwrap(), FrameType::Response),
        error("home_unavailable", "transient")
    );
}

#[tokio::test]
async fn remote_watch_cancel_during_first_send_and_reused_correlation_are_silent() {
    use std::future::{poll_fn, Future};
    use std::task::Poll;
    let (_root, home, _conn) = rig();
    let home = paired(home);
    setup(&home);
    let (writer, mut rx) = mpsc::channel(1);
    writer
        .try_send(
            Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Response,
                Flags::new(false, Priority::Interactive, false),
                1,
                1,
                99,
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap();
    let mut opening = Box::pin(open(&home, &writer, 1, 1, MEMBER, json!({})));
    assert!(poll_fn(|cx| Poll::Ready(opening.as_mut().poll(cx)))
        .await
        .is_pending());
    assert_eq!(home.remote_watches.entry_count(), 1);
    home.remote_watches.cancel(1, 1);
    let replacement = home.remote_watches.register(header(1, 1));
    assert_eq!(rx.try_recv().unwrap().header.corr, 99);
    opening.await;
    assert!(
        rx.try_recv().is_err(),
        "the removed open cannot borrow the replacement entry"
    );
    assert_eq!(home.remote_watches.entry_count(), 1);
    home.remote_watches
        .open(
            &home,
            replacement,
            &writer,
            header(1, 1),
            MEMBER,
            &json!({}),
        )
        .await
        .unwrap();
    body(rx.try_recv().unwrap(), FrameType::StreamData);
}

#[tokio::test]
async fn remote_watch_backpressured_eviction_cannot_remove_a_reused_correlation() {
    use std::future::{poll_fn, Future};
    use std::task::Poll;
    let (_root, home, _conn) = rig();
    let home = paired(home);
    setup(&home);
    let (old_writer, mut old_rx) = mpsc::channel(1);
    let (writer, mut rx) = mpsc::channel(8);
    for corr in 1..=4 {
        open(&home, &old_writer, 1, corr, MEMBER, json!({})).await;
        body(old_rx.try_recv().unwrap(), FrameType::StreamData);
    }
    old_writer
        .try_send(
            Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Response,
                Flags::new(false, Priority::Interactive, false),
                1,
                1,
                99,
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap();
    let mut fifth = Box::pin(open(&home, &writer, 2, 5, MEMBER, json!({})));
    assert!(poll_fn(|cx| Poll::Ready(fifth.as_mut().poll(cx)))
        .await
        .is_pending());
    home.remote_watches.cancel(1, 1);
    let _replacement = home.remote_watches.register(header(1, 1));
    assert_eq!(old_rx.try_recv().unwrap().header.corr, 99);
    fifth.await;
    body(rx.try_recv().unwrap(), FrameType::StreamData);
    assert_eq!(
        home.remote_watches.entry_count(),
        5,
        "the replacement must survive the old stream's eviction"
    );
    assert!(
        old_rx.try_recv().is_err(),
        "the cancelled stream ends silently"
    );
    home.remote_watches.cancel(1, 1);
    assert_eq!(home.remote_watches.entry_count(), 4);
}

#[tokio::test]
async fn remote_watch_budget_overrun_never_admits_or_evicts_a_stream() {
    let (_root, home, _conn) = rig();
    let mut home = paired(home);
    setup(&home);
    let (writer, mut rx) = mpsc::channel(8);
    for corr in 1..=4 {
        open(&home, &writer, 1, corr, MEMBER, json!({})).await;
        body(rx.try_recv().unwrap(), FrameType::StreamData);
    }
    home.op_deadline = Duration::ZERO;
    open(&home, &writer, 1, 5, MEMBER, json!({})).await;
    assert_eq!(
        body(rx.try_recv().unwrap(), FrameType::Response),
        error("home_unavailable", "transient")
    );
    assert_eq!(home.remote_watches.entry_count(), 4);
    assert!(rx.try_recv().is_err());
}
