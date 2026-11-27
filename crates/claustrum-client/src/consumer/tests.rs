use super::*;
use subc_transport::{authenticate_server, ConnectionInfo, Endpoint};
use tokio::net::TcpListener;

struct Rig {
    root: PathBuf,
    stream: TcpStream,
    consumer: Arc<SubcConsumer>,
    route_opens: Vec<Value>,
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Rig {
    async fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/consumer-tests")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
        std::fs::create_dir_all(&root).unwrap();
        // The SDK refuses a connection file whose folder other users can reach. On
        // Windows a folder under target/ inherits broad grants, so narrow it to the owner.
        #[cfg(windows)]
        subc_os::windows_acl::create_private_dir(&root).unwrap();
        let path = root.join("connection.json");
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let info = ConnectionInfo {
            schema: connection_file::SCHEMA_VERSION,
            wire_version: None,
            endpoints: vec![Endpoint {
                host: std::net::Ipv4Addr::LOCALHOST.to_string(),
                port: listener.local_addr().unwrap().port(),
            }],
            key: vec![9; 32],
            daemon_id: [4; 16],
            pid: std::process::id(),
            daemon_ver: "0.41.0".into(),
        };
        connection_file::write_atomic(&path, &info).unwrap();
        let (consumer, stream) = tokio::join!(
            SubcConsumer::connect(&path, subc_client_rs::ConsumerOptions::default()),
            async {
                let (mut stream, _) = listener.accept().await.unwrap();
                authenticate_server(
                    &mut stream,
                    &info.key,
                    &info.daemon_id,
                    &info.daemon_ver,
                    Duration::from_secs(3),
                )
                .await
                .unwrap();
                stream
            }
        );
        Self {
            root,
            stream,
            consumer: Arc::new(consumer.unwrap()),
            route_opens: Vec::new(),
        }
    }

    async fn next(&mut self) -> (Frame, Value) {
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut self.stream))
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if matches!(frame.header.ty, FrameType::Cancel | FrameType::Goodbye) {
                continue;
            }
            let body: Value = serde_json::from_slice(&frame.body).unwrap();
            if body["op"] == "server.describe" {
                self.reply(&frame, FrameType::Response, json!({"op":"server.describe", "protocol_ver":2, "subc_ops":[], "capabilities":[], "connected_clients":1}))
                    .await;
            } else if body["op"] == "route.open" {
                self.route_opens.push(body.clone());
                assert_eq!(
                    body["target"],
                    json!({"kind":"management_surface", "module_id":"claustrum"})
                );
                assert!(
                    body.get("consumer_identity").is_none(),
                    "SDK routes must not override the connection binding: {body}"
                );
                assert!(!String::from_utf8(frame.body.clone())
                    .unwrap()
                    .contains("launch_nonce"));
                self.reply(
                    &frame,
                    FrameType::Response,
                    json!({"op":"route.open", "route_channel":6 + self.route_opens.len(),"route_epoch":3, "request_window":8, "watch_window":8}),
                )
                .await;
            } else {
                return (frame, body);
            }
        }
    }

    async fn reply(&mut self, request: &Frame, ty: FrameType, body: Value) {
        self.reply_with_flags(
            request,
            ty,
            body,
            Flags::new(false, Priority::Interactive, false).with_daemon_origin(),
        )
        .await;
    }

    async fn reply_with_flags(
        &mut self,
        request: &Frame,
        ty: FrameType,
        body: Value,
        flags: Flags,
    ) {
        let frame = Frame::build(
            ty,
            flags,
            request.header.channel,
            request.header.epoch,
            request.header.corr,
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
        write_frame(&mut self.stream, &frame).await.unwrap();
    }
}

#[tokio::test]
async fn module_secret_consumer_uses_a_second_route_and_never_replays_busy_operations() {
    let mut rig = Rig::new().await;
    let resolver = ClaustrumCredentialResolver::with_consumer(Arc::clone(&rig.consumer));
    let calls = async {
        assert!(resolver.get_scoped("barrier").await.is_err());
        for operation in 0..4 {
            let error = match operation {
                0 => resolver
                    .module_secret_put("key", Secret::new(vec![42]), None, None)
                    .await
                    .unwrap_err(),
                1 => resolver.module_secret_get("key").await.unwrap_err(),
                2 => resolver
                    .module_secret_delete("key", None)
                    .await
                    .unwrap_err(),
                _ => resolver.module_secret_list().await.unwrap_err(),
            };
            assert!(matches!(
                error,
                ModuleSecretError::Other(CredentialResolverError {
                    class: CredentialErrorClass::Transient,
                    ..
                })
            ));
        }
        assert!(resolver.get_scoped("barrier").await.is_err());
    };
    let server = async {
        for method in [
            "credential.get_scoped",
            "module_secret.put",
            "module_secret.get",
            "module_secret.delete",
            "module_secret.list",
            "credential.get_scoped",
        ] {
            let (frame, body) = rig.next().await;
            assert_eq!(
                body["method"], method,
                "no module-secret operation may replay before the next caller operation"
            );
            assert_eq!(
                frame.header.channel,
                if method == "credential.get_scoped" {
                    7
                } else {
                    8
                }
            );
            rig.reply(
                &frame,
                FrameType::Response,
                if method == "credential.get_scoped" {
                    json!({"result":{"error":{"code":"not_found","class":"permanent"}}})
                } else {
                    json!({"result":{"error":{"code":"route_busy","class":"transient"}}})
                },
            )
            .await;
        }
    };
    tokio::join!(calls, server);
    assert_eq!(rig.route_opens.len(), 2);
    assert_eq!(
        rig.route_opens[0]["identity"]["harness"],
        "claustrum-client"
    );
    assert_eq!(rig.route_opens[1]["identity"]["harness"], "callosum-self");
    let mut original = rig.route_opens[0].clone();
    original["identity"]["harness"] = json!("callosum-self");
    assert_eq!(
        original, rig.route_opens[1],
        "only the bind harness changes"
    );
    rig.consumer.close().await;
}

#[tokio::test]
async fn module_secret_consumer_returns_transport_route_busy_as_transient_without_replaying() {
    let mut rig = Rig::new().await;
    let resolver = ClaustrumCredentialResolver::with_consumer(Arc::clone(&rig.consumer));
    let calls = async {
        let error = resolver
            .module_secret_put("key", Secret::new(vec![42]), None, None)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ModuleSecretError::Other(CredentialResolverError {
                class: CredentialErrorClass::Transient,
                ..
            })
        ));
        assert!(resolver.get_scoped("barrier").await.is_err());
    };
    let server = async {
        let (frame, body) = rig.next().await;
        assert_eq!(body["method"], "module_secret.put");
        rig.reply(
            &frame,
            FrameType::Error,
            json!({"code":"route_busy","message":"busy"}),
        )
        .await;
        let (frame, body) = rig.next().await;
        assert_eq!(
            body["method"], "credential.get_scoped",
            "the put must not replay"
        );
        rig.reply(
            &frame,
            FrameType::Response,
            json!({"result":{"error":{"code":"not_found","class":"permanent"}}}),
        )
        .await;
    };
    tokio::join!(calls, server);
    rig.consumer.close().await;
}

#[tokio::test]
async fn consumer_routes_every_operation_without_identity_override() {
    let mut rig = Rig::new().await;
    let resolver = ClaustrumCredentialResolver::with_consumer(Arc::clone(&rig.consumer));
    let caller = Arc::clone(&rig.consumer);
    let calls = async {
        assert_eq!(resolver.get_scoped("id").await.unwrap().expose(), b"sdk");
        assert!(resolver.resolve("handle", Some(12), true).await.is_err());
        assert!(resolver.get_scoped_with_min_ttl("id", 12).await.is_err());
        assert!(resolver.report_auth_failure("id", 4, 401).await.is_err());
        assert!(resolver.status_scoped("id").await.is_err());
        assert!(resolver.sign("id", b"payload").await.is_err());
        assert!(resolver.public_key("id").await.is_err());
        assert!(resolver.list_scoped().await.is_err());
        drop(resolver);
        let handle = caller
            .open_route(target(), identity(), options())
            .await
            .unwrap();
        let reply = caller
            .request(
                &handle,
                br#"{"method":"caller.barrier"}"#.to_vec(),
                options(),
            )
            .await
            .unwrap();
        assert_eq!(reply, br#"{"alive":true}"#);
    };
    let server = async {
        for (index, expected) in [
            credential_get_scoped_request("id", None),
            credential_get_request("handle", Some(12), true),
            credential_get_scoped_request("id", Some(12)),
            credential_report_auth_failure_request("id", 4, 401),
            credential_status_request("id"),
            credential_sign_request("id", b"payload"),
            credential_public_key_request("id"),
            credential_list_scoped_request(),
        ]
        .into_iter()
        .enumerate()
        {
            let (frame, body) = rig.next().await;
            assert_eq!(body, expected);
            let reply = if index == 0 {
                json!({"result":{"payload":[115,100,107],"record_version":4}})
            } else {
                json!({"result":{"error":{"code":"not_found", "message":"not found"}}})
            };
            rig.reply(&frame, FrameType::Response, reply).await;
        }
        let (frame, body) = rig.next().await;
        assert_eq!(body, json!({"method":"caller.barrier"}));
        rig.reply(&frame, FrameType::Response, json!({"alive":true}))
            .await;
    };
    tokio::join!(calls, server);
    rig.consumer.close().await;
}

#[tokio::test]
async fn established_route_unknown_channel_reopens_and_resends() {
    established_route_reopens_and_resends(
        "unknown_channel",
        Flags::new(false, Priority::Interactive, false).with_daemon_origin(),
    )
    .await;
}

#[tokio::test]
async fn established_route_stale_route_epoch_reopens_and_resends() {
    established_route_reopens_and_resends(
        "stale_route_epoch",
        Flags::new(false, Priority::Interactive, false).with_daemon_origin(),
    )
    .await;
}

#[tokio::test]
async fn established_route_error_without_daemon_origin_still_reopens_and_resends() {
    established_route_reopens_and_resends(
        "unknown_channel",
        Flags::new(false, Priority::Interactive, false),
    )
    .await;
}

async fn established_route_reopens_and_resends(code: &str, flags: Flags) {
    let mut rig = Rig::new().await;
    let resolver = ClaustrumCredentialResolver::with_consumer(Arc::clone(&rig.consumer));
    let calls = async {
        let credential = resolver
            .resolve("handle", Some(12), true)
            .await
            .expect("a dead route must reopen and resend");
        assert_eq!(credential.expose(), b"sdk");
    };
    let server = async {
        let (initial, request) = rig.next().await;
        assert_eq!(request, credential_get_request("handle", Some(12), true));
        rig.reply_with_flags(
            &initial,
            FrameType::Error,
            json!({"code":code,"message":"route no longer exists"}),
            flags,
        )
        .await;
        let (retry, resent) = rig.next().await;
        assert_eq!(resent, request);
        assert_ne!(retry.header.channel, initial.header.channel);
        rig.reply(
            &retry,
            FrameType::Response,
            json!({"result":{"payload":[115,100,107],"record_version":4}}),
        )
        .await;
    };
    tokio::join!(calls, server);
    assert_eq!(rig.route_opens.len(), 2, "exactly one replacement route");
    rig.consumer.close().await;
}

#[tokio::test]
async fn established_route_ordinary_refusal_and_transport_error_do_not_reopen() {
    let mut rig = Rig::new().await;
    let resolver = ClaustrumCredentialResolver::with_consumer(Arc::clone(&rig.consumer));
    let calls = async {
        let refusal = resolver.resolve("handle", None, false).await.unwrap_err();
        assert_eq!(refusal.code(), "invalid_params");
        assert_eq!(refusal.class, CredentialErrorClass::Unclassified);
        let timeout = resolver.status_scoped("timeout").await.unwrap_err();
        assert_eq!(timeout.code(), "module_timeout");
        assert_eq!(timeout.class, CredentialErrorClass::Transport);
        // The next caller operation lets the server distinguish a replay or
        // replacement route from normal reuse of the SDK's cached route.
        let barrier = resolver.status_scoped("barrier").await.unwrap_err();
        assert_eq!(barrier.code(), "invalid_params");
    };
    let server = async {
        for (request, code) in [
            (
                credential_get_request("handle", None, false),
                "invalid_params",
            ),
            (credential_status_request("timeout"), "module_timeout"),
            (credential_status_request("barrier"), "invalid_params"),
        ] {
            let (frame, body) = rig.next().await;
            assert_eq!(body, request);
            assert_eq!(frame.header.channel, 7, "the SDK route should be reused");
            rig.reply(
                &frame,
                FrameType::Error,
                json!({"code":code,"message":"request refused"}),
            )
            .await;
        }
    };
    tokio::join!(calls, server);
    assert_eq!(rig.route_opens.len(), 1);
    rig.consumer.close().await;
}

#[test]
fn established_route_adapter_uses_sdk_verdict_not_the_code() {
    let body = ErrorBody {
        code: "unknown_channel".to_owned(),
        message: "request refused".to_owned(),
        detail: None,
    };
    for (route_dead, call, watch) in [
        (
            false,
            CallError::Module(body.clone()),
            SubscriptionEnd::Error(body.clone()),
        ),
        (
            true,
            CallError::RouteDead(Box::new(body.clone())),
            SubscriptionEnd::RouteDead(body.clone()),
        ),
    ] {
        let WatchFrame::Error(watch_error) = decode_subscription_end(watch).unwrap() else {
            panic!("expected a watch error");
        };
        for error in [decode_established_call_error(call), watch_error] {
            assert_eq!(error.code(), body.code);
            assert_eq!(error.established_route_dead, route_dead);
            assert_eq!(
                error.class,
                if route_dead {
                    CredentialErrorClass::Transport
                } else {
                    CredentialErrorClass::Unclassified
                }
            );
        }
    }
}

#[tokio::test]
async fn established_route_death_on_resend_surfaces_without_a_third_attempt() {
    let mut rig = Rig::new().await;
    let resolver = ClaustrumCredentialResolver::with_consumer(Arc::clone(&rig.consumer));
    let calls = async {
        let error = resolver.resolve("handle", None, false).await.unwrap_err();
        assert_eq!(error.class, CredentialErrorClass::Transport);
        assert_eq!(error.code(), "stale_route_epoch");
        assert!(resolver.status_scoped("barrier").await.is_err());
    };
    let server = async {
        for code in ["unknown_channel", "stale_route_epoch"] {
            let (frame, body) = rig.next().await;
            assert_eq!(body, credential_get_request("handle", None, false));
            rig.reply(
                &frame,
                FrameType::Error,
                json!({"code":code,"message":"route no longer exists"}),
            )
            .await;
        }
        let (frame, body) = rig.next().await;
        assert_eq!(body, credential_status_request("barrier"));
        rig.reply(
            &frame,
            FrameType::Error,
            json!({"code":"invalid_params","message":"barrier"}),
        )
        .await;
    };
    tokio::join!(calls, server);
    rig.consumer.close().await;
}

#[tokio::test]
async fn consumer_closed_by_caller_refuses_scoped_read_as_transport() {
    let rig = Rig::new().await;
    let resolver = ClaustrumCredentialResolver::with_consumer(Arc::clone(&rig.consumer));
    rig.consumer.close().await;
    let refusal = resolver
        .get_scoped("id")
        .await
        .expect_err("closed consumer refusal");
    assert_eq!(refusal.class, CredentialErrorClass::Transport);
    assert_eq!(refusal.code(), "credential_transport");
}

#[tokio::test]
async fn consumer_seal_returns_route_busy_without_replaying() {
    let mut rig = Rig::new().await;
    let resolver = ClaustrumCredentialResolver::with_consumer(Arc::clone(&rig.consumer));
    let calls = async {
        let error = resolver
            .seal(SealRequest {
                credential_id: "key",
                recipient_public_key: &[1; 32],
                info: b"info",
                aad: b"aad",
                plaintext: b"test-only",
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), "route_busy");
        assert!(resolver.status_scoped("barrier").await.is_err());
    };
    let server = async {
        let (frame, body) = rig.next().await;
        assert_eq!(body["method"], "credential.seal");
        rig.reply(
            &frame,
            FrameType::Error,
            json!({"code":"route_busy", "message":"busy"}),
        )
        .await;
        let (frame, body) = rig.next().await;
        assert_eq!(
            body["method"], "credential.status",
            "seal must not be replayed before the next caller operation"
        );
        rig.reply(
            &frame,
            FrameType::Error,
            json!({"code":"invalid_params", "message":"barrier"}),
        )
        .await;
    };
    tokio::join!(calls, server);
    rig.consumer.close().await;
}

#[tokio::test]
async fn consumer_watch_drains_notices_and_confirms_empty_streams() {
    let mut rig = Rig::new().await;
    let resolver = ClaustrumCredentialResolver::with_consumer(Arc::clone(&rig.consumer));
    let calls = async {
        let mut watch = resolver.watch_scoped(None).await.unwrap();
        assert_eq!(watch.next().await.unwrap().seq, 1);
        assert!(watch.next().await.is_none());
        assert!(matches!(watch.closed().await, ScopedWatchOutcome::Ended));
        let mut watch = resolver.watch_scoped(Some("enrolled")).await.unwrap();
        assert!(watch.next().await.is_none());
        assert!(matches!(
            watch.closed().await,
            ScopedWatchOutcome::NotAccepting
        ));
    };
    let server = async {
        let (frame, body) = rig.next().await;
        assert_eq!(body, json!({"method":"auth.watch_scoped","params":{}}));
        assert!(frame.header.flags.is_subscription());
        rig.reply(
            &frame,
            FrameType::StreamData,
            json!({"kind":"changed","epoch":"launch","seq":1,"view":"v1","keys":"k1"}),
        )
        .await;
        rig.reply(&frame, FrameType::StreamEnd, Value::Null).await;
        let (frame, body) = rig.next().await;
        assert_eq!(
            body,
            json!({"method":"auth.watch_scoped","params":{"enrollment_token":"enrolled"}})
        );
        rig.reply(&frame, FrameType::StreamEnd, Value::Null).await;
        let (frame, body) = rig.next().await;
        assert_eq!(
            body,
            json!({"method":"credential.list_scoped","params":{"enrollment_token":"enrolled"}})
        );
        rig.reply(
            &frame,
            FrameType::Response,
            json!({"result":{"credentials":[],"view":"view"}}),
        )
        .await;
    };
    tokio::join!(calls, server);
    rig.consumer.close().await;
}

#[tokio::test]
async fn established_route_death_releases_sdk_watch_handles() {
    let mut rig = Rig::new().await;
    let resolver = ClaustrumCredentialResolver::with_consumer(Arc::clone(&rig.consumer));
    let codes = ["unknown_channel", "stale_route_epoch"];
    let calls = async {
        for code in codes {
            let mut watch = resolver.watch_scoped(None).await.unwrap();
            assert_eq!(watch.next().await.unwrap().seq, 1);
            assert_dead_watch(watch.closed().await, code);
        }
        for code in codes {
            let mut watch = resolver.policy_watch().await.unwrap();
            assert_dead_watch(watch.closed().await, code);
        }
    };
    let server = async {
        for (index, (method, code)) in ["auth.watch_scoped", "policy.watch"]
            .into_iter()
            .flat_map(|method| codes.map(|code| (method, code)))
            .enumerate()
        {
            let (frame, body) = rig.next().await;
            assert_eq!(body["method"], method);
            assert_eq!(usize::from(frame.header.channel), 7 + index);
            if method == "auth.watch_scoped" {
                rig.reply(
                    &frame,
                    FrameType::StreamData,
                    json!({"kind":"changed","epoch":"launch","seq":1,"view":"v1","keys":"k1"}),
                )
                .await;
            }
            rig.reply(
                &frame,
                FrameType::Error,
                json!({"code":code,"message":"route no longer exists"}),
            )
            .await;
        }
    };
    tokio::join!(calls, server);
    assert_eq!(rig.route_opens.len(), 4);
    rig.consumer.close().await;
}

fn assert_dead_watch(outcome: ScopedWatchOutcome, code: &str) {
    let ScopedWatchOutcome::TransportLost(error) = outcome else {
        panic!("{code} must use the reconnect path: {outcome:?}");
    };
    assert_eq!(error.code(), code);
    assert_eq!(error.class, CredentialErrorClass::Transport);
}

#[tokio::test]
async fn policy_calls_use_the_attested_route_and_decode_vault_samples() {
    let mut rig = Rig::new().await;
    let resolver = ClaustrumCredentialResolver::with_consumer(Arc::clone(&rig.consumer));
    let sample = |case: &str| {
        let contract = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/wire-contract-v1.md"
        ))
        .unwrap();
        let (_, rest) = contract
            .split_once(&format!("<!-- golden:{case} -->\n```json\n"))
            .unwrap();
        serde_json::from_str::<Value>(rest.split_once("\n```").unwrap().0).unwrap()
    };
    let ready = sample("policy.active.ready");
    let request = PolicyTokenRequest {
        identity: "github_app:agent",
        service: "github",
        kind: "add_issue_comment",
        resource: "org/r",
        policy_version: 1,
    };
    let calls = async {
        assert!(resolver.policy_active().await.unwrap().is_none());
        let active = resolver.policy_active().await.unwrap().unwrap();
        assert_eq!(active.version, 1);
        assert_eq!(active.manifest_version, 41);
        assert_eq!(
            active.policy_text,
            ready["result"]["policy_text"].as_str().unwrap()
        );
        let mut watch = resolver.policy_watch().await.unwrap();
        let none = watch.next().await.unwrap();
        assert_eq!(
            (none.seq, none.version, none.policy_sha256),
            (1, None, None)
        );
        let changed = watch.next().await.unwrap();
        assert_eq!((changed.seq, changed.version), (2, Some(1)));
        assert_eq!(
            changed.policy_sha256.as_deref(),
            Some(active.policy_sha256.as_str())
        );
        assert!(watch.next().await.is_none());
        let ScopedWatchOutcome::Refused(error) = watch.closed().await else {
            panic!("expected a terminal role refusal");
        };
        assert_eq!(error.code(), "not_found");
        assert_eq!(error.class, CredentialErrorClass::Permanent);

        let token = resolver.policy_token(request).await.unwrap();
        assert_eq!(token.token.expose(), "fixture-token-1");
        assert_eq!(token.expires_at_ms, 4_102_444_800_000);
        assert_eq!(token.repositories, ["org/r"]);
        assert_eq!(
            token.permissions,
            BTreeMap::from([
                ("issues".into(), "write".into()),
                ("pull_requests".into(), "write".into()),
            ])
        );
        assert!(!format!("{token:?}").contains("fixture-token-1"));
        let error = resolver.policy_token(request).await.unwrap_err();
        assert_eq!(error.code(), "policy_version_not_active");
        assert_eq!(error.class, CredentialErrorClass::Permanent);
    };
    let server = async {
        let (first, body) = rig.next().await;
        assert_eq!(body, json!({"method":"policy.active","params":{}}));
        rig.reply(&first, FrameType::Response, sample("policy.active.none"))
            .await;
        let (second, body) = rig.next().await;
        assert_eq!(body, json!({"method":"policy.active","params":{}}));
        rig.reply(&second, FrameType::Response, ready.clone()).await;
        let (watch, body) = rig.next().await;
        assert_eq!(body, json!({"method":"policy.watch","params":{}}));
        assert!(watch.header.flags.is_subscription());
        assert_ne!(first.header.channel, watch.header.channel);
        rig.reply(
            &watch,
            FrameType::StreamData,
            sample("policy.watch.initial"),
        )
        .await;
        rig.reply(
            &watch,
            FrameType::StreamData,
            sample("policy.watch.changed"),
        )
        .await;
        rig.reply(
            &watch,
            FrameType::Response,
            json!({"result":{"error":{"code":"not_found","class":"permanent"}}}),
        )
        .await;
        let token_request = json!({"method":"credential.policy_token","params":{
            "identity":"github_app:agent","service":"github","kind":"add_issue_comment","resource":"org/r","policy_version":1,
        }});
        let (frame, body) = rig.next().await;
        assert_eq!(body, token_request);
        rig.reply(&frame, FrameType::Response, json!({"result":{
            "token":"fixture-token-1","expires_at_ms":4_102_444_800_000i64,"repositories":["org/r"],
            "permissions":{"issues":"write","pull_requests":"write"},
        }})).await;
        let (frame, body) = rig.next().await;
        assert_eq!(body, token_request);
        rig.reply(
            &frame,
            FrameType::Response,
            json!({"result":{"error":{
                "code":"policy_version_not_active","class":"permanent",
            }}}),
        )
        .await;
    };
    tokio::join!(calls, server);
    rig.consumer.close().await;
}

#[tokio::test]
async fn fleet_epoch_consumer_uses_the_normal_attested_route() {
    let mut rig = Rig::new().await;
    let resolver = ClaustrumCredentialResolver::with_consumer(Arc::clone(&rig.consumer));
    let calls = async {
        assert!(resolver.get_scoped("barrier").await.is_err());
        let plaintext = Secret::new(vec![255]);
        let seal = FleetEpochSealRequest {
            aad: &[251],
            plaintext: &plaintext,
        };
        let sealed = resolver.fleet_epoch_seal(seal).await.unwrap();
        let open = FleetEpochOpenRequest {
            epoch: sealed.epoch,
            nonce: &sealed.nonce,
            ciphertext: &sealed.ciphertext,
            aad: seal.aad,
        };
        let opened = resolver.fleet_epoch_open(open).await.unwrap();
        assert_eq!(opened.expose(), plaintext.expose());
        let error = resolver
            .fleet_epoch_seal_batch(&[seal, seal])
            .await
            .unwrap_err();
        assert_eq!(error.class, CredentialErrorClass::InvalidResponse);
        let opened = resolver
            .fleet_epoch_open_batch(&[open, open])
            .await
            .unwrap();
        assert_eq!(opened.len(), 2);
        assert_eq!(opened[0].as_ref().unwrap().expose(), plaintext.expose());
        assert_eq!(
            opened[1].as_ref().unwrap_err().code(),
            "fleet_epoch_open_failed"
        );
    };
    let server = async {
        let seal = json!({"aad":"-w","plaintext":"_w"});
        let sealed =
            json!({"epoch":7,"nonce":"_".repeat(32),"ciphertext":"AAAAAAAAAAAAAAAAAAAAAA"});
        let mut open = sealed.clone();
        open["aad"] = json!("-w");
        for (method, params, result) in [
            (
                "credential.get_scoped",
                json!({"credential_id":"barrier"}),
                json!({"error":{"code":"not_found","class":"permanent"}}),
            ),
            ("fleet.epoch_seal", seal.clone(), sealed.clone()),
            ("fleet.epoch_open", open.clone(), json!({"plaintext":"_w"})),
            // A valid slot count in the protocol is still an incomplete reply for this request.
            (
                "fleet.epoch_seal_batch",
                json!({"items":[seal.clone(), seal]}),
                json!({"items":[sealed]}),
            ),
            (
                "fleet.epoch_open_batch",
                json!({"items":[open.clone(), open]}),
                json!({"items":[{"plaintext":"_w"},{"error":{"code":"fleet_epoch_open_failed","class":"permanent"}}]}),
            ),
        ] {
            let (frame, body) = rig.next().await;
            assert_eq!(frame.header.channel, 7);
            assert_eq!(body, json!({"method":method,"params":params}));
            rig.reply(&frame, FrameType::Response, json!({"result":result}))
                .await;
        }
    };
    tokio::join!(calls, server);
    assert_eq!(rig.route_opens.len(), 1);
    assert_eq!(
        rig.route_opens[0]["identity"]["harness"],
        "claustrum-client"
    );
    rig.consumer.close().await;
}

#[tokio::test]
async fn fleet_epoch_consumer_does_not_replay_a_refusal() {
    let mut rig = Rig::new().await;
    let resolver = ClaustrumCredentialResolver::with_consumer(Arc::clone(&rig.consumer));
    let calls = async {
        let plaintext = Secret::new(vec![]);
        let seal = FleetEpochSealRequest {
            aad: &[],
            plaintext: &plaintext,
        };
        let open = FleetEpochOpenRequest {
            epoch: 1,
            nonce: &[0; 24],
            ciphertext: &[0; 16],
            aad: &[],
        };
        let error = resolver.fleet_epoch_seal(seal).await.unwrap_err();
        assert_eq!(error.code(), "route_busy");
        for error in [
            resolver.fleet_epoch_open(open).await.unwrap_err(),
            resolver.fleet_epoch_seal_batch(&[seal]).await.unwrap_err(),
            resolver.fleet_epoch_open_batch(&[open]).await.unwrap_err(),
        ] {
            assert_eq!(error.code(), "fleet_epoch_unavailable");
            assert_eq!(error.class, CredentialErrorClass::Transient);
        }
    };
    let server = async {
        let (frame, body) = rig.next().await;
        assert_eq!(body["method"], "fleet.epoch_seal");
        rig.reply(
            &frame,
            FrameType::Error,
            json!({"code":"route_busy","message":"busy"}),
        )
        .await;
        for method in [
            "fleet.epoch_open",
            "fleet.epoch_seal_batch",
            "fleet.epoch_open_batch",
        ] {
            let (frame, body) = rig.next().await;
            assert_eq!(body["method"], method);
            rig.reply(
                &frame,
                FrameType::Response,
                json!({"result":{"error":{"code":"fleet_epoch_unavailable","class":"transient"}}}),
            )
            .await;
        }
    };
    tokio::join!(calls, server);
    rig.consumer.close().await;
}
