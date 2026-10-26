use super::*;
#[cfg(feature = "transport")]
use tokio::net::TcpListener;

fn samples() -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../credentials-module/tests/fixtures/enrollment_wire_contract.json");
    let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    // `op` labels fixture sections, not route requests, whose operation key is `method`.
    fixture["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|op| op["op"] == "auth.watch_scoped")
        .unwrap()["success"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

fn notice(seq: u64, epoch: &str) -> Value {
    json!({"kind":"changed", "epoch":epoch, "seq":seq, "view":"view", "keys":"keys"})
}

#[cfg(feature = "transport")]
fn refusal() -> Value {
    json!({"result":{"error":{"class":"permanent", "code":"not_found"}}})
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StandInReadRequest {
    method: String,
    #[serde(default, rename = "params")]
    _params: Value,
}

#[cfg(feature = "transport")]
async fn accept_request(server: &mut TcpStream, frame: &Frame, method: &str) -> bool {
    let code = match serde_json::from_slice::<StandInReadRequest>(&frame.body) {
        Ok(request) if request.method == method => return true,
        Ok(_) => "unknown_method",
        Err(_) => "invalid_request",
    };
    let reply = Frame::build(
        FrameType::Error,
        Flags::new(false, Priority::Interactive, false),
        frame.header.channel,
        frame.header.epoch,
        frame.header.corr,
        serde_json::to_vec(&json!({"code":code, "message":"request body not decodable"})).unwrap(),
    )
    .unwrap();
    write_frame(server, &reply).await.unwrap();
    false
}

#[cfg(feature = "transport")]
async fn stand_in(
    frames: Vec<(FrameType, Value)>,
    list_reply: Value,
) -> (ScopedWatch, tokio::task::JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (client, server) = tokio::join!(TcpStream::connect(address), listener.accept());
    let (mut server, _) = server.unwrap();
    let task = tokio::spawn(async move {
        let request = read_frame(&mut server).await.unwrap().unwrap();
        let mut requests = vec![serde_json::from_slice::<Value>(&request.body).unwrap()];
        if accept_request(&mut server, &request, "auth.watch_scoped").await {
            for (ty, body) in frames {
                let bytes = if ty == FrameType::StreamEnd {
                    vec![]
                } else {
                    serde_json::to_vec(&body).unwrap()
                };
                let frame = Frame::build(
                    ty,
                    Flags::new(false, Priority::Interactive, false),
                    7,
                    9,
                    request.header.corr,
                    bytes,
                )
                .unwrap();
                write_frame(&mut server, &frame).await.unwrap();
            }
        }
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut server))
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if frame.header.ty == FrameType::Cancel {
                break;
            }
            assert_eq!(frame.header.ty, FrameType::Request);
            requests.push(serde_json::from_slice(&frame.body).unwrap());
            if !accept_request(&mut server, &frame, CREDENTIAL_LIST_SCOPED_OP).await {
                continue;
            }
            let reply = Frame::build(
                FrameType::Response,
                Flags::new(false, Priority::Interactive, false),
                7,
                9,
                frame.header.corr,
                serde_json::to_vec(&list_reply).unwrap(),
            )
            .unwrap();
            write_frame(&mut server, &reply).await.unwrap();
        }
        requests
    });
    let consumer = ClaustrumConsumer {
        stream: client.unwrap(),
        route_channel: 7,
        route_epoch: 9,
        next_corr: 1,
    };
    let watch = Box::new(consumer)
        .into_scoped_watch(Some("token".into()))
        .await
        .unwrap();
    (watch, task)
}

#[cfg(feature = "transport")]
async fn closed(watch: &mut ScopedWatch) -> ScopedWatchOutcome {
    tokio::time::timeout(Duration::from_secs(3), watch.closed())
        .await
        .expect("watch must terminate")
}

#[test]
fn producer_notices_decode_exactly() {
    let notices: Vec<ScopedWatchNotice> = samples()
        .iter()
        .map(|s| WatchNotice::decode(s.as_bytes()).unwrap())
        .collect();
    assert_eq!(
        notices,
        vec![
            ScopedWatchNotice {
                kind: ScopedWatchKind::Changed,
                epoch: "00000000000000000000000000000000".into(),
                seq: 1,
                view: "WJ4kwtxL+iITIKBjbo2xVnNBe5EIH6Xu+QGOrGBoIKs=".into(),
                keys: "gWYprQh+NPmmtg2ZrKBrOv9X/F9BYAiK+6rtaHR2xxA=".into()
            },
            ScopedWatchNotice {
                kind: ScopedWatchKind::Changed,
                epoch: "00000000000000000000000000000000".into(),
                seq: 2,
                view: "voJahchvv3WOVUvaYC1dqSvNT7k4hUZZrrLYEujPSkg=".into(),
                keys: "gWYprQh+NPmmtg2ZrKBrOv9X/F9BYAiK+6rtaHR2xxA=".into()
            },
        ]
    );
}

#[test]
fn notice_schema_is_strict() {
    for (key, value) in [
        ("kind", json!("other")),
        ("epoch", json!("")),
        ("epoch", json!(1)),
        ("seq", json!(0)),
        ("seq", json!(-1)),
        ("seq", json!(1.5)),
        ("seq", json!(9_007_199_254_740_992u64)),
        ("view", Value::Null),
        ("keys", json!(1)),
        ("extra", json!(true)),
    ] {
        let mut invalid = notice(1, "epoch");
        invalid[key] = value;
        assert!(
            serde_json::from_value::<ScopedWatchNotice>(invalid).is_err(),
            "{key}"
        );
    }
    for key in ["kind", "epoch", "seq", "view", "keys"] {
        let mut invalid = notice(1, "epoch");
        invalid.as_object_mut().unwrap().remove(key);
        assert!(
            serde_json::from_value::<ScopedWatchNotice>(invalid).is_err(),
            "{key}"
        );
    }
}

#[cfg(feature = "transport")]
#[tokio::test]
async fn stream_end_preserves_sequence_epoch_and_params() {
    let (mut watch, server) = stand_in(
        vec![
            (FrameType::StreamData, notice(1, "a")),
            (FrameType::StreamData, notice(3, "a")),
            (FrameType::StreamData, notice(1, "b")),
            (FrameType::StreamEnd, Value::Null),
        ],
        Value::Null,
    )
    .await;
    let mut received = vec![];
    while let Some(notice) = watch.next().await {
        received.push((notice.seq, notice.epoch));
    }
    assert_eq!(
        received,
        vec![(1, "a".into()), (3, "a".into()), (1, "b".into())]
    );
    assert!(matches!(
        closed(&mut watch).await,
        ScopedWatchOutcome::Ended
    ));
    assert_eq!(
        server.await.unwrap(),
        vec![json!({"method":"auth.watch_scoped", "params":{"enrollment_token":"token"}})]
    );
}

#[cfg(feature = "transport")]
#[tokio::test]
async fn response_refusal_is_terminal_even_after_notices() {
    for sent_notice in [false, true] {
        let mut frames = vec![];
        if sent_notice {
            frames.push((FrameType::StreamData, notice(1, "a")));
        }
        frames.push((FrameType::Response, refusal()));
        let (mut watch, server) = stand_in(frames, Value::Null).await;
        let outcome = closed(&mut watch).await;
        let ScopedWatchOutcome::Refused(error) = outcome else {
            panic!("{outcome:?}")
        };
        assert_eq!(error.class, CredentialErrorClass::CredentialAbsent);
        assert_eq!(server.await.unwrap().len(), 1);
    }
}

#[cfg(feature = "transport")]
#[tokio::test]
async fn route_closed_is_transport_loss() {
    let (mut watch, server) = stand_in(
        vec![(
            FrameType::Error,
            json!({"code":"route_closed", "message":"closed"}),
        )],
        Value::Null,
    )
    .await;
    let outcome = closed(&mut watch).await;
    let ScopedWatchOutcome::TransportLost(error) = outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!(error.code(), "route_closed");
    assert_eq!(server.await.unwrap().len(), 1);
}

#[cfg(feature = "transport")]
#[tokio::test]
async fn unknown_method_is_polling_fallback() {
    let (mut watch, server) = stand_in(
        vec![(
            FrameType::Error,
            json!({"code":"unknown_method", "message":"old vault"}),
        )],
        Value::Null,
    )
    .await;
    assert!(matches!(
        closed(&mut watch).await,
        ScopedWatchOutcome::Unsupported
    ));
    assert_eq!(server.await.unwrap().len(), 1);
}

#[cfg(feature = "transport")]
#[tokio::test]
async fn zero_notice_close_confirms_list_once() {
    for (reply, refused) in [
        (refusal(), true),
        (json!({"result":{"credentials":[], "view":"view"}}), false),
    ] {
        let (mut watch, server) = stand_in(vec![(FrameType::StreamEnd, Value::Null)], reply).await;
        let outcome = closed(&mut watch).await;
        if refused {
            assert!(matches!(outcome, ScopedWatchOutcome::Refused(_)));
        } else {
            assert!(matches!(outcome, ScopedWatchOutcome::NotAccepting));
        }
        assert_eq!(
            server.await.unwrap(),
            vec![
                json!({"method":"auth.watch_scoped", "params":{"enrollment_token":"token"}}),
                json!({"method":"credential.list_scoped", "params":{"enrollment_token":"token"}})
            ]
        );
    }
}

#[test]
fn stand_in_rejects_op_and_extra_read_envelope_keys() {
    for body in [
        json!({"op":"auth.watch_scoped", "params":{}}),
        json!({"method":"auth.watch_scoped", "op":"auth.watch_scoped", "params":{}}),
        json!({"method":"credential.list_scoped", "params":{}, "extra":true}),
        json!({"method":1, "params":{}}),
    ] {
        assert!(serde_json::from_value::<StandInReadRequest>(body).is_err());
    }
    let request =
        serde_json::from_value::<StandInReadRequest>(json!({"method":"credential.list_scoped"}))
            .unwrap();
    assert_eq!(request.method, "credential.list_scoped");
}

#[cfg(feature = "transport")]
#[tokio::test]
async fn malformed_stream_cancels_with_typed_outcome() {
    let (mut watch, server) = stand_in(
        vec![(FrameType::StreamData, json!({"kind":"wrong"}))],
        Value::Null,
    )
    .await;
    assert!(matches!(
        closed(&mut watch).await,
        ScopedWatchOutcome::InvalidNotice
    ));
    assert!(watch.next().await.is_none());
    assert_eq!(server.await.unwrap().len(), 1);
}

#[cfg(feature = "transport")]
#[tokio::test]
async fn stop_sends_cancel_and_settles() {
    let (mut watch, server) = stand_in(vec![], Value::Null).await;
    watch.stop();
    watch.stop();
    assert!(matches!(
        closed(&mut watch).await,
        ScopedWatchOutcome::Stopped
    ));
    assert_eq!(server.await.unwrap().len(), 1);
}

fn tracked() -> WatchTracker {
    let mut tracker = WatchTracker::default();
    tracker.notice(&decoded_notice(1, "epoch", "view", "keys"));
    tracker.inventory_read("view");
    tracker.keys_read("keys");
    tracker
}

fn decoded_notice(seq: u64, epoch: &str, view: &str, keys: &str) -> WatchNotice {
    WatchNotice {
        kind: ScopedWatchKind::Changed,
        seq,
        epoch: epoch.into(),
        view: view.into(),
        keys: keys.into(),
    }
}

#[test]
fn tracker_first_notice_rereads_inventory_and_keys() {
    assert_eq!(
        WatchTracker::default().notice(&decoded_notice(1, "epoch", "view", "keys")),
        WatchAction::Reread {
            inventory: true,
            keys: true
        }
    );
    let mut tracker = WatchTracker::default();
    tracker.inventory_read("view");
    tracker.keys_read("keys");
    assert_eq!(
        tracker.notice(&decoded_notice(1, "epoch", "view", "keys")),
        WatchAction::Reread {
            inventory: true,
            keys: false
        }
    );
}

#[test]
fn tracker_contiguous_unchanged_notice_needs_no_read() {
    assert_eq!(
        tracked().notice(&decoded_notice(2, "epoch", "view", "keys")),
        WatchAction::Reread {
            inventory: false,
            keys: false
        }
    );
}

#[test]
fn tracker_view_change_rereads_inventory_only() {
    assert_eq!(
        tracked().notice(&decoded_notice(2, "epoch", "new-view", "keys")),
        WatchAction::Reread {
            inventory: true,
            keys: false
        }
    );
}

#[test]
fn tracker_epoch_change_rereads_inventory() {
    assert_eq!(
        tracked().notice(&decoded_notice(2, "new-epoch", "view", "keys")),
        WatchAction::Reread {
            inventory: true,
            keys: false
        }
    );
}

#[test]
fn tracker_sequence_gap_rereads_inventory() {
    assert_eq!(
        tracked().notice(&decoded_notice(3, "epoch", "view", "keys")),
        WatchAction::Reread {
            inventory: true,
            keys: false
        }
    );
}

#[test]
fn tracker_keys_only_change_rereads_keys_only() {
    assert_eq!(
        tracked().notice(&decoded_notice(2, "epoch", "view", "new-keys")),
        WatchAction::Reread {
            inventory: false,
            keys: true
        }
    );
}

#[test]
fn tracker_unacknowledged_view_keeps_requesting_a_read() {
    let mut tracker = tracked();
    tracker.notice(&decoded_notice(2, "epoch", "new-view", "keys"));
    assert_eq!(
        tracker.notice(&decoded_notice(3, "epoch", "new-view", "keys")),
        WatchAction::Reread {
            inventory: true,
            keys: false
        }
    );
}

#[test]
fn tracker_close_after_notices_resubscribes_once() {
    assert_eq!(tracked().closed(), WatchAction::ResubscribeAndReread);
}

#[test]
fn tracker_duplicate_close_stops() {
    let mut tracker = tracked();
    tracker.closed();
    assert_eq!(tracker.closed(), WatchAction::Stop);
}

#[test]
fn tracker_zero_notice_close_reads_list_once_never_resubscribes() {
    let mut tracker = WatchTracker::default();
    assert_eq!(tracker.closed(), WatchAction::ReadListOnce);
    assert_eq!(tracker.closed(), WatchAction::Stop);
}

#[test]
fn tracker_zero_notice_list_success_waits_for_caller() {
    let mut tracker = WatchTracker::default();
    tracker.closed();
    assert_eq!(tracker.list_result(true), WatchAction::RetryLater);
}

#[test]
fn tracker_zero_notice_list_refusal_stops() {
    let mut tracker = WatchTracker::default();
    tracker.closed();
    assert_eq!(tracker.list_result(false), WatchAction::Stop);
}

#[test]
fn tracker_route_loss_reconnects_and_rereads() {
    assert_eq!(tracked().route_lost(), WatchAction::ReconnectAndReread);
}

#[test]
fn tracker_confirming_read_transport_loss_reconnects() {
    let mut tracker = WatchTracker::default();
    tracker.closed();
    assert_eq!(tracker.route_lost(), WatchAction::ReconnectAndReread);
}

#[test]
fn tracker_duplicate_route_loss_stops() {
    let mut tracker = tracked();
    tracker.route_lost();
    assert_eq!(tracker.route_lost(), WatchAction::Stop);
}

#[test]
fn tracker_unsolicited_list_result_stops() {
    assert_eq!(tracked().list_result(true), WatchAction::Stop);
}

#[test]
fn tracker_unknown_method_is_named_fallback() {
    assert_eq!(tracked().unknown_method(), WatchAction::Fallback);
}

#[test]
fn tracker_refusal_stops() {
    assert_eq!(tracked().refused(), WatchAction::Stop);
}

#[test]
fn tracker_notice_after_close_stops() {
    let mut tracker = tracked();
    tracker.closed();
    assert_eq!(
        tracker.notice(&decoded_notice(2, "epoch", "new-view", "keys")),
        WatchAction::Stop
    );
}

#[test]
fn tracker_reopen_forgets_old_sequence_and_notices() {
    let mut tracker = tracked();
    tracker.closed();
    tracker.opened();
    assert_eq!(tracker.closed(), WatchAction::ReadListOnce);
    tracker.opened();
    assert_eq!(
        tracker.notice(&decoded_notice(2, "epoch", "view", "keys")),
        WatchAction::Reread {
            inventory: true,
            keys: false
        }
    );
}
