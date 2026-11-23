use super::*;
use crate::{Egress, ModuleConfig, StorageDescriptor, PROTOCOL_VERSION};
use cortexkit_store::{Isolation, StorageBackend};
use credentials_core::test_support::TestTempDir;
use rusqlite::OptionalExtension;
use serde_json::{json, Value};
use subc_protocol::{ModuleHelloAckBody, ModuleHelloBody};
use subc_transport::{read_frame, write_frame};
use tokio::{io::DuplexStream, task::JoinHandle};

use crate::tests::federation_fixture_support as transport_support;

struct Rig {
    root: TestTempDir,
    wire: DuplexStream,
    task: JoinHandle<Result<(), ModuleError>>,
    writer: JoinHandle<Result<(), ModuleError>>,
    db: rusqlite::Connection,
    path: std::path::PathBuf,
}

impl Rig {
    async fn new(gated: bool, persisted: Option<bool>, disk: &str) -> Self {
        Self::new_with_hub(gated, persisted, disk, std::future::ready(None)).await
    }

    async fn new_with_hub(
        gated: bool,
        persisted: Option<bool>,
        disk: &str,
        hub: impl std::future::Future<Output = Option<Arc<dyn crate::federation::hub::Hub>>>
            + Send
            + 'static,
    ) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = TestTempDir::new(format!(
            "config-gate-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let data_dir = root.join("vault");
        credentials_core::resolver::bootstrap(&credentials_core::resolver::ResolverConfig {
            data_dir: data_dir.clone(),
            source: credentials_core::resolver::KeySource::OperatorPath {
                path: root.join("master.key"),
            },
        })
        .unwrap();
        let descriptor = StorageDescriptor {
            module_id: credentials_core::MODULE_ID.into(),
            storage_namespace: credentials_core::STORAGE_NAMESPACE.into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: data_dir.join("store.db").to_string_lossy().into_owned(),
            },
        };
        let ack: ModuleHelloAckBody = serde_json::from_value(json!({
            "negotiated_ver": PROTOCOL_VERSION, "subc_ops": [],
            "subc_capabilities": if gated { vec![CONFIG_GATE_CAPABILITY] } else { vec![] },
            "storage": descriptor,
        }))
        .unwrap();
        let path = root.join("claustrum.jsonc");
        // With the gate, building the store must not apply even the missing-file default.
        let (surface, admin, poll, _) =
            crate::build_surface(&ack, credentials_core::MODULE_ID, path.clone())
                .await
                .unwrap();
        if let Some(value) = persisted {
            surface
                .store()
                .set_login_sharing_audited(value, "test:seed")
                .unwrap();
        }
        drop((surface, admin, poll));
        std::fs::write(&path, disk).unwrap();
        let db = rusqlite::Connection::open(data_dir.join("store.db")).unwrap();
        let (module, wire) = tokio::io::duplex(65536);
        let (reader, write) = tokio::io::split(module);
        let (control, control_rx) = mpsc::channel(crate::CONTROL_EGRESS_BUFFER);
        let (route, route_rx) = mpsc::channel(crate::EGRESS_BUFFER);
        let writer = tokio::spawn(crate::drain_writer(write, control_rx, route_rx));
        let config = ModuleConfig {
            connection_file_path: root.join("no-outbound-daemon"),
            module_id: credentials_core::MODULE_ID.into(),
            registration: crate::Registration::Channel(Default::default()),
            launch_nonce: None,
            launch_nonce_source: None,
        };
        let config_path = path.clone();
        let task = tokio::spawn(async move {
            crate::module_loop_with_config_path(
                reader,
                Egress { control, route },
                &config,
                config_path,
                |_| Ok(()),
                hub,
            )
            .await
        });
        let mut rig = Self {
            root,
            wire,
            task,
            writer,
            db,
            path,
        };
        let hello = rig.recv().await;
        assert_eq!(hello.header.ty, FrameType::Hello);
        let hello: ModuleHelloBody = serde_json::from_slice(&hello.body).unwrap();
        assert_eq!(hello.manifest.registration_channel, Some(true));
        assert!(hello.launch_nonce.is_none());
        assert_eq!(
            hello.control_ops.unwrap(),
            vec!["health.check", "config.review"]
        );
        rig.send(FrameType::HelloAck, 1, serde_json::to_value(ack).unwrap())
            .await;
        rig
    }

    async fn recv(&mut self) -> Frame {
        transport_support::wait_for_signal(read_frame(&mut self.wire))
            .await
            .unwrap()
            .unwrap()
    }
    async fn send(&mut self, ty: FrameType, corr: u64, value: Value) {
        let body = if matches!(ty, FrameType::Ping | FrameType::Goodbye) {
            vec![]
        } else {
            serde_json::to_vec(&value).unwrap()
        };
        write_frame(
            &mut self.wire,
            &Frame::build(ty, crate::control_flags(), 0, 0, corr, body).unwrap(),
        )
        .await
        .unwrap();
    }
    async fn request(&mut self, op: &str) -> Frame {
        let frame = self.recv().await;
        assert_eq!(frame.header.ty, FrameType::Request);
        assert_eq!(body(&frame)["op"], op);
        frame
    }
    async fn ok(&mut self, frame: Frame, value: impl serde::Serialize) {
        self.send(
            FrameType::Response,
            frame.header.corr,
            serde_json::to_value(value).unwrap(),
        )
        .await;
    }
    async fn refuse(&mut self, frame: Frame, code: &str) {
        self.send(
            FrameType::Error,
            frame.header.corr,
            serde_json::to_value(subc_protocol::ErrorBody::new(code, "test refusal")).unwrap(),
        )
        .await;
    }
    async fn declared(&mut self) {
        let declaration = self.request(CONFIG_DECLARE_OP).await;
        let declaration: ConfigDeclareRequest = serde_json::from_slice(&declaration.body).unwrap();
        assert_eq!(declaration.schema, login_sharing::schema());
        assert!(std::path::Path::new(&declaration.user_file).is_absolute());
        assert_eq!(declaration.user_file, self.path.to_str().unwrap());
        assert!(declaration.project_dirs.is_empty());
        // The first module-originated call follows HELLO's correlation id.
        self.send(
            FrameType::Response,
            2,
            serde_json::to_value(ConfigDeclareReply::new()).unwrap(),
        )
        .await;
    }
    async fn get(&mut self, active: Option<ConfigView>, pending: Option<ConfigView>) {
        let get = self.request(CONFIG_GET_OP).await;
        assert_eq!(
            body(&get),
            serde_json::to_value(ConfigGetRequest::new()).unwrap()
        );
        self.ok(get, ConfigGetReply::new(active, pending)).await;
    }
    async fn hint(&mut self, generation: u64) {
        self.send(
            FrameType::Push,
            0,
            serde_json::to_value(ConfigChanged::new(
                generation,
                vec!["/login_sharing".into()],
            ))
            .unwrap(),
        )
        .await;
    }
    fn value(&self) -> Option<bool> {
        self.db
            .query_row(
                "SELECT value FROM settings WHERE name='federation.login_sharing'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .unwrap()
            .map(|s| s == "true")
    }
    async fn applied(&self, wanted: bool) {
        transport_support::wait_until(|| self.value() == Some(wanted)).await;
    }
    async fn ping(&mut self) {
        self.send(FrameType::Ping, 900, Value::Null).await;
        let pong = self.recv().await;
        // Any unexpected applied or declare frame fails this barrier too.
        assert_eq!((pong.header.ty, pong.header.corr), (FrameType::Pong, 900));
    }
    async fn finish(mut self) {
        self.send(FrameType::Goodbye, 0, Value::Null).await;
        self.task.await.unwrap().unwrap();
        self.writer.await.unwrap().unwrap();
        drop(self.root);
    }
}

#[tokio::test(start_paused = true)]
async fn daemon_serves_when_hub_is_unavailable_and_retries_in_the_background() {
    use cortexkit_bus_client::Error;
    let (attempts, mut observed) = mpsc::unbounded_channel();
    let mut first = true;
    let hub = crate::hub_nats::connect_with_retry(move || {
        let first = std::mem::take(&mut first);
        let attempts = attempts.clone();
        async move {
            attempts.send(()).unwrap();
            if first {
                Err(Error::HubUnavailable)
            } else {
                std::future::pending().await
            }
        }
    });
    let mut rig = Rig::new_with_hub(false, None, "{}", hub).await;
    transport_support::wait_for_signal(observed.recv())
        .await
        .unwrap();
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    transport_support::wait_for_signal(observed.recv())
        .await
        .unwrap();
    rig.ping().await;
    rig.finish().await;
    assert!(transport_support::wait_for_signal(observed.recv())
        .await
        .is_none());
}

#[tokio::test(start_paused = true)]
async fn daemon_serves_when_hub_is_not_granted_and_does_not_retry() {
    use cortexkit_bus_client::Error;
    let (attempts, mut observed) = mpsc::unbounded_channel();
    let hub = crate::hub_nats::connect_with_retry(move || {
        attempts.send(()).unwrap();
        std::future::ready(Err(Error::HubNotGranted))
    });
    let mut rig = Rig::new_with_hub(false, None, "{}", hub).await;
    transport_support::wait_for_signal(observed.recv())
        .await
        .unwrap();
    rig.ping().await;
    // The connector must be dropped after the refusal, with the module still up.
    assert!(transport_support::wait_for_signal(observed.recv())
        .await
        .is_none());
    rig.finish().await;
}

fn body(frame: &Frame) -> Value {
    serde_json::from_slice(&frame.body).unwrap()
}
fn view(
    path: &std::path::Path,
    generation: u64,
    status: ConfigStatus,
    bytes: Option<&[u8]>,
) -> ConfigView {
    let mut view = ConfigView::new(
        generation,
        json!({"login_sharing":false}),
        Default::default(),
        vec![ConfigLayerSnapshot::file(
            credentials_core::MODULE_ID,
            ConfigLayer::User,
            path.to_string_lossy(),
            bytes.map(<[u8]>::to_vec),
        )],
        status,
    );
    view.attempt = (generation != 0).then_some(generation + 100);
    view
}

#[tokio::test(start_paused = true)]
async fn gate_declares_the_login_sharing_schema_before_get() {
    let mut rig = Rig::new(true, None, "{}").await;
    let frame = rig.request(CONFIG_DECLARE_OP).await;
    assert_eq!((frame.header.channel, frame.header.corr), (0, 2));
    let user_file = serde_json::to_string(&rig.path).unwrap();
    let expected = format!(
        concat!(
            r#"{{"op":"config.declare","schema":{{"#,
            r#""$schema":"https://json-schema.org/draft/2020-12/schema","#,
            r#""properties":{{"login_sharing":{{"default":true,"description":"#,
            "\"Set to false to stop sharing this computer's logins with paired computers ",
            "and drop automatic copies of their logins.\",",
            r#""type":"boolean","x-ck-apply":"live","x-ck-layers":["user"]}}}},"#,
            r#""type":"object","unevaluatedProperties":false}},"user_file":{},"project_dirs":[]}}"#,
        ),
        user_file,
    );
    assert_eq!(std::str::from_utf8(&frame.body).unwrap(), expected);
    let request: ConfigDeclareRequest = serde_json::from_slice(&frame.body).unwrap();
    subc_config::Schema::new(request.schema).expect("the daemon must admit the declared schema");

    rig.ok(frame, ConfigDeclareReply::new()).await;
    let get = rig.request(CONFIG_GET_OP).await;
    rig.refuse(get, "config_gated").await;
    rig.finish().await;
}

#[tokio::test(start_paused = true)]
async fn gate_present_uses_only_view_bytes_and_changed_gets_without_redeclare() {
    let mut rig = Rig::new(true, None, r#"{"login_sharing":true}"#).await;
    assert_eq!(
        rig.value(),
        None,
        "gate startup must not read the local file"
    );
    rig.declared().await;
    rig.get(
        Some(view(
            &rig.path,
            0,
            ConfigStatus::Unstamped,
            Some(br#"{"login_sharing":false}"#),
        )),
        None,
    )
    .await;
    rig.applied(false).await;
    rig.ping().await;
    tokio::time::advance(std::time::Duration::from_secs(4)).await;
    rig.ping().await;
    assert_eq!(rig.value(), Some(false), "no legacy poll under the gate");
    rig.hint(0).await;
    // Missing bytes mean absent file; the contradictory effective field is not a byte source.
    rig.get(
        Some(view(&rig.path, 0, ConfigStatus::Unstamped, None)),
        None,
    )
    .await;
    rig.applied(true).await;
    rig.ping().await;
    rig.hint(1).await;
    let get = rig.request(CONFIG_GET_OP).await;
    rig.refuse(get, "config_gated").await;
    rig.ping().await;
    assert_eq!(
        rig.value(),
        Some(true),
        "a refusal also retains an in-run apply"
    );
    rig.finish().await;
}

#[test]
fn gate_warns_once_per_distinct_refusal_code() {
    struct Capture(Arc<Mutex<Vec<String>>>);
    struct Fields(String);
    impl tracing::field::Visit for Fields {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!("{field}={value:?};"));
        }
    }
    impl tracing::Subscriber for Capture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            assert_eq!(*event.metadata().level(), tracing::Level::WARN);
            let mut fields = Fields(String::new());
            event.record(&mut fields);
            self.0.lock().unwrap().push(fields.0);
        }
    }
    let logs = Arc::new(Mutex::new(vec![]));
    tracing::subscriber::with_default(Capture(Arc::clone(&logs)), || {
        let mut warned = HashSet::new();
        for code in [
            "config_gated",
            "config_gated",
            "not_delivery_target",
            "config_gated",
        ] {
            warn_once(&mut warned, code.into());
        }
    });
    let logs = logs.lock().unwrap();
    assert_eq!(logs.len(), 2);
    assert!(logs[0].contains("config_gated"));
    assert!(logs[1].contains("not_delivery_target"));
}

#[tokio::test(start_paused = true)]
async fn gate_pending_reports_after_apply_and_replays_anchor_pending_before_get() {
    let mut rig = Rig::new(true, Some(false), r#"{"login_sharing":false}"#).await;
    rig.declared().await;
    rig.get(
        None,
        Some(view(
            &rig.path,
            1,
            ConfigStatus::Pending,
            Some(br#"{"login_sharing":true}"#),
        )),
    )
    .await;
    let report = rig.request(CONFIG_APPLIED_OP).await;
    assert_eq!(rig.value(), Some(true), "apply must precede report");
    assert_eq!(
        body(&report),
        serde_json::to_value(ConfigAppliedRequest::new(
            1,
            101,
            ConfigApplyResult::Ack,
            vec![]
        ))
        .unwrap()
    );
    let retained = body(&report);
    rig.refuse(report, "anchor_pending").await;
    rig.ping().await;
    rig.hint(1).await;
    let replay = rig.request(CONFIG_APPLIED_OP).await;
    assert_eq!(body(&replay), retained);
    rig.ok(replay, ConfigAppliedReply::new()).await;
    rig.get(
        Some(view(
            &rig.path,
            1,
            ConfigStatus::Active,
            Some(br#"{"login_sharing":true}"#),
        )),
        None,
    )
    .await;
    rig.ping().await;
    rig.finish().await;
}

#[tokio::test(start_paused = true)]
async fn gate_acknowledges_active_catch_up_while_declaration_is_pending() {
    let mut rig = Rig::new(true, Some(true), r#"{"login_sharing":true}"#).await;
    rig.declared().await;
    let get = rig.request(CONFIG_GET_OP).await;
    let active = view(
        &rig.path,
        3,
        ConfigStatus::Active,
        Some(br#"{"login_sharing":false}"#),
    );
    // An empty marker means the declaration is awaiting a plan. The delivery
    // attempt still belongs to the approved active view, not the declaration.
    let mut reply = ConfigGetReply::new(Some(active), None);
    reply.declaration_pending = Some(ConfigDeclarationPending::default());
    rig.ok(get, reply).await;
    let report = rig.request(CONFIG_APPLIED_OP).await;
    assert_eq!(rig.value(), Some(false), "apply must precede report");
    assert_eq!(
        std::str::from_utf8(&report.body).unwrap(),
        r#"{"op":"config.applied","generation":3,"attempt":103,"result":"ack","reasons":[]}"#
    );
    rig.ok(report, ConfigAppliedReply::new()).await;
    rig.ping().await;
    rig.finish().await;
}

#[tokio::test(start_paused = true)]
async fn gate_refusals_retain_persisted_startup_value_without_file_fallback() {
    for persisted in [None, Some(false), Some(true)] {
        let disk = if persisted == Some(false) {
            r#"{"login_sharing":true}"#
        } else {
            r#"{"login_sharing":false}"#
        };
        let mut rig = Rig::new(true, persisted, disk).await;
        rig.declared().await;
        let get = rig.request(CONFIG_GET_OP).await;
        rig.refuse(get, "config_gated").await;
        rig.ping().await;
        assert_eq!(rig.value(), persisted);
        for code in ["config_gated", "not_delivery_target", "config_gated"] {
            rig.hint(1).await;
            let get = rig.request(CONFIG_GET_OP).await;
            rig.refuse(get, code).await;
            rig.ping().await;
            tokio::time::advance(std::time::Duration::from_secs(2)).await;
            assert_eq!(
                rig.value(),
                persisted,
                "refusal cannot enable a file fallback"
            );
        }
        rig.finish().await;
    }
}

#[tokio::test(start_paused = true)]
async fn gate_declare_refusal_consumes_declaration_and_changed_gets() {
    let mut rig = Rig::new(true, Some(false), r#"{"login_sharing":true}"#).await;
    let declare = rig.request(CONFIG_DECLARE_OP).await;
    rig.refuse(declare, "config_gated").await;
    rig.ping().await;
    assert_eq!(rig.value(), Some(false));
    rig.hint(1).await;
    rig.get(
        Some(view(
            &rig.path,
            0,
            ConfigStatus::Unstamped,
            Some(br#"{"login_sharing":true}"#),
        )),
        None,
    )
    .await;
    rig.applied(true).await;
    rig.ping().await;
    rig.finish().await;
}

#[tokio::test(start_paused = true)]
async fn gate_invalid_startup_is_off_and_invalid_edit_retains_applied_value() {
    let mut rig = Rig::new(true, Some(true), r#"{"login_sharing":true}"#).await;
    rig.declared().await;
    rig.get(
        Some(view(
            &rig.path,
            0,
            ConfigStatus::Unstamped,
            Some(b"invalid"),
        )),
        None,
    )
    .await;
    rig.applied(false).await;
    rig.ping().await;
    rig.hint(1).await;
    rig.get(
        None,
        Some(view(
            &rig.path,
            1,
            ConfigStatus::Pending,
            Some(br#"{"login_sharing":true}"#),
        )),
    )
    .await;
    let report = rig.request(CONFIG_APPLIED_OP).await;
    rig.ok(report, ConfigAppliedReply::new()).await;
    rig.hint(2).await;
    rig.get(
        None,
        Some(view(&rig.path, 2, ConfigStatus::Pending, Some(b"invalid"))),
    )
    .await;
    let report = rig.request(CONFIG_APPLIED_OP).await;
    assert_eq!(body(&report)["result"], "nack");
    assert_eq!(rig.value(), Some(true));
    rig.ok(report, ConfigAppliedReply::new()).await;
    rig.ping().await;
    rig.finish().await;
}

#[tokio::test(start_paused = true)]
async fn gate_first_pending_failure_keeps_the_active_recovery_bytes() {
    let mut rig = Rig::new(true, Some(false), r#"{"login_sharing":false}"#).await;
    rig.declared().await;
    rig.get(
        Some(view(
            &rig.path,
            1,
            ConfigStatus::Active,
            Some(br#"{"login_sharing":true}"#),
        )),
        Some(view(&rig.path, 2, ConfigStatus::Pending, Some(b"invalid"))),
    )
    .await;
    let report = rig.request(CONFIG_APPLIED_OP).await;
    assert_eq!(body(&report)["result"], "nack");
    assert_eq!(
        rig.value(),
        Some(true),
        "active recovery must precede pending apply"
    );
    rig.ok(report, ConfigAppliedReply::new()).await;
    rig.ping().await;
    rig.finish().await;
}

#[tokio::test(start_paused = true)]
async fn gate_absent_keeps_direct_startup_and_virtual_clock_poll() {
    let mut rig = Rig::new(false, None, r#"{"login_sharing":false}"#).await;
    rig.applied(false).await;
    rig.ping().await;
    std::fs::write(&rig.path, r#"{"login_sharing":true}"#).unwrap();
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    rig.applied(true).await;
    rig.ping().await;
    rig.finish().await;
}

#[tokio::test(start_paused = true)]
async fn gate_review_reply_uses_supplied_bytes_and_base_not_disk() {
    let mut rig = Rig::new(true, Some(false), "invalid local file").await;
    rig.declared().await;
    // Review must still be answered while config.get is awaiting its response.
    let get = rig.request(CONFIG_GET_OP).await;
    // The recorded old value is false despite these old bytes containing true.
    // Review must use the supplied effective record, not resolve the old bytes again.
    let mut base = view(
        &rig.path,
        1,
        ConfigStatus::Active,
        Some(br#"{"login_sharing":true}"#),
    );
    base.sources.insert("/login_sharing".into(), Layer::User);
    for (bytes, valid) in [
        (br#"{"login_sharing":true}"#.as_slice(), true),
        (br#"{"login_sharing":"private-marker"}"#.as_slice(), false),
    ] {
        let request = ConfigReviewRequest::new(
            1,
            vec![ConfigLayerSnapshot::file(
                credentials_core::MODULE_ID,
                ConfigLayer::User,
                rig.path.to_string_lossy(),
                Some(bytes.to_vec()),
            )],
            Some(base.clone()),
        );
        rig.send(
            FrameType::Request,
            901,
            serde_json::to_value(request).unwrap(),
        )
        .await;
        let frame = rig.recv().await;
        assert_eq!(
            (frame.header.ty, frame.header.corr),
            (FrameType::Response, 901)
        );
        let reply: ConfigReviewReply = serde_json::from_slice(&frame.body).unwrap();
        if valid {
            assert!(reply.refusals.is_empty());
            let field = &reply.fields[0];
            assert_eq!(reply.fields.len(), 1);
            assert_eq!(field.path, "/login_sharing");
            assert_eq!(field.module_id, credentials_core::MODULE_ID);
            assert_eq!(field.old, RecordedValue::new(json!(false)));
            assert_eq!(field.new, RecordedValue::new(json!(true)));
            assert_eq!(
                (field.old_source, field.new_source),
                (Layer::User, Layer::User)
            );
            assert_eq!(field.apply, ApplyKind::Live);
        } else {
            assert!(reply.fields.is_empty());
            assert_eq!(reply.refusals[0].code, "value_invalid");
            assert_eq!(reply.refusals[0].paths, vec!["/login_sharing"]);
            assert!(!String::from_utf8(frame.body)
                .unwrap()
                .contains("private-marker"));
        }
        assert_eq!(rig.value(), Some(false), "review has no apply side effects");
    }
    rig.refuse(get, "config_gated").await;
    rig.ping().await;
    rig.finish().await;
}
