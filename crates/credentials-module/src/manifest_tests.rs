use super::*;
use crate::manifest_active_report::ReportParams;
use credentials_core::{
    admin_auth::AdminMacKey,
    audit::{AuditCtx, AuditOp},
    engine::RefreshEngine,
    key::{MasterKey, MASTER_KEY_LEN},
    store::{GhManifestSource, GhManifestVersion},
};
use rusqlite::{types::Value as SqlValue, Connection};
use std::{collections::BTreeMap, sync::Mutex};
use subc_protocol::{Flags, Priority, PROTOCOL_VERSION};

use crate::tests::federation_fixture_support as federation_support;

const SELF: &str = "fed-computer:22222222222222222222222222222222";
const OTHER: &str = "fed-computer:33333333333333333333333333333333";
const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Rig {
    surface: Arc<ReadSurface>,
    store: Arc<EncryptedStore>,
    admin: Arc<crate::admin_surface::AdminSurface>,
    path: std::path::PathBuf,
    _root: credentials_core::test_support::TestTempDir,
    tx: mpsc::Sender<Frame>,
    rx: mpsc::Receiver<Frame>,
}

impl Rig {
    fn new() -> Self {
        let (surface, store, path, root) = crate::tests::tmp_surface_with_store(202);
        let key = MasterKey::from_bytes([202; MASTER_KEY_LEN]);
        let engine = Arc::new(RefreshEngine::new(
            Arc::clone(&store),
            vec![],
            Arc::new(crate::test_support::NoHttp),
        ));
        let admin = Arc::new(crate::admin_surface::AdminSurface::new(
            engine,
            AdminMacKey::derive(&key),
            [0; 32],
            key.key_id(),
        ));
        let (tx, rx) = mpsc::channel(256);
        Self {
            surface,
            store,
            admin,
            path,
            _root: root,
            tx,
            rx,
        }
    }

    fn self_member(&self) {
        self.store
            .set_federation_self_member_audited(SELF, AuditCtx::admin(AuditOp::FederationSelfSet))
            .unwrap();
    }

    fn sql(&self, sql: &str) {
        Connection::open(&self.path)
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }

    fn store_version(&self, version: i64) {
        let bytes = format!("{{\n  \"manifest_version\": {version}\n}}\n");
        self.store
            .store_gh_manifest(
                &GhManifestVersion {
                    version,
                    manifest_bytes: bytes.as_bytes(),
                    manifest_sha256: HASH,
                    key_id: "0123456789abcdef",
                    signature: &[7; 64],
                    signed_at_ms: 10,
                    source: GhManifestSource::Import,
                    approval_audit_seq: None,
                },
                AuditCtx::admin(AuditOp::GhManifestStore),
            )
            .unwrap();
    }

    fn snapshot(&self) -> Vec<Vec<Vec<SqlValue>>> {
        let conn = Connection::open(&self.path).unwrap();
        [
            "gh_manifests",
            "gh_manifest_proposals",
            "gh_manifest_activations",
            "gh_manifest_activation_audits",
            "audit_log",
        ]
        .iter()
        .map(|table| {
            let mut stmt = conn
                .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                .unwrap();
            let count = stmt.column_count();
            stmt.query_map([], |row| {
                (0..count)
                    .map(|i| row.get(i))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
        })
        .collect()
    }

    async fn request(
        &self,
        caller: crate::federation::RouteCaller,
        method: &str,
        params: Value,
        channel: u16,
        corr: u64,
    ) {
        let frame = request(method, params, channel, corr);
        crate::dispatch_route_request(frame, &self.tx, &self.surface, &self.admin, caller, None)
            .await
            .unwrap();
    }

    async fn call(&mut self, module: &str, method: &str, params: Value) -> Value {
        self.request(caller(module), method, params, 1, 1).await;
        let frame = self.rx.recv().await.unwrap();
        assert_eq!(frame.header.ty, FrameType::Response);
        body(&frame)["result"].clone()
    }

    async fn notice(&mut self, channel: u16, corr: u64, seq: u64) -> Value {
        let frame = self.rx.recv().await.unwrap();
        assert_eq!(frame.header.ty, FrameType::StreamData);
        assert_eq!(
            (frame.header.channel, frame.header.epoch, frame.header.corr),
            (channel, 3, corr)
        );
        assert_eq!(
            frame.header.flags.admission_class(),
            Some(subc_protocol::AdmissionClass::Sheddable)
        );
        let value = body(&frame);
        assert_eq!(value["kind"], "changed");
        assert_eq!(value["seq"], seq);
        assert_eq!(value.as_object().unwrap().len(), 5);
        let epoch = value["epoch"].as_str().unwrap();
        assert_eq!(epoch.len(), 32);
        assert!(epoch
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        value
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.surface.watches.close_all();
    }
}

fn caller(module: &str) -> crate::federation::RouteCaller {
    crate::federation::RouteCaller::Principal(Some(Principal::Reserved {
        module_id: module.into(),
    }))
}

fn request(method: &str, params: Value, channel: u16, corr: u64) -> Frame {
    let mut flags = Flags::new(false, Priority::Interactive, false);
    if method == OP_WATCH {
        flags.0 |= subc_protocol::FLAG_SUBSCRIPTION;
    }
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        flags,
        channel,
        3,
        corr,
        serde_json::to_vec(&json!({"method":method,"params":params})).unwrap(),
    )
    .unwrap()
}

fn body(frame: &Frame) -> Value {
    serde_json::from_slice(&frame.body).unwrap()
}
fn report(version: i64) -> Value {
    json!({"version":version,"payload_sha256":HASH,"verdict":"valid","reason":null})
}

#[tokio::test]
async fn manifest_delivery_and_readiness_still_work_after_one_tap_is_turned_off() {
    let mut rig = Rig::new();
    rig.self_member();
    for enabled in [true, false] {
        rig.store
            .set_manifest_one_tap_audited(enabled, AuditCtx::admin(AuditOp::GhManifestOneTapSet))
            .unwrap();
    }
    assert!(!rig.store.manifest_one_tap_enabled());
    rig.store_version(28);
    assert_eq!(rig.call("aft", OP_LATEST, json!({})).await["version"], 28);
    rig.request(caller("aft"), OP_WATCH, json!({}), 7, 9).await;
    assert_eq!(rig.notice(7, 9, 1).await["version"], 28);
    assert_eq!(
        rig.call("aft", OP_REPORT_ACTIVE, report(28)).await["status"],
        "recorded"
    );
    assert_eq!(
        rig.call("plexus", OP_ACTIVE_STATUS, json!({"version":28}))
            .await["ready"],
        true
    );
}

#[tokio::test]
async fn manifest_latest_returns_newest_handoff_or_domain_refusal() {
    let mut rig = Rig::new();
    assert_eq!(
        rig.call("aft", OP_LATEST, json!({})).await,
        refusal("not_found", "permanent")
    );
    for version in [28, 29] {
        rig.store_version(version);
    }
    rig.sql(
        "INSERT INTO settings(name,value,updated_at_ms) VALUES('secrets.home_member','self',0)",
    );
    let before = rig.snapshot();
    let reply = rig.call("aft", OP_LATEST, json!({})).await;
    assert_eq!(
        reply,
        json!({"version":29,"envelope":{
            "key_id":"0123456789abcdef", "manifest_bytes":"{\n  \"manifest_version\": 29\n}\n",
            "signature":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBw=="
        }})
    );
    assert_eq!(rig.snapshot(), before);
    rig.sql("DROP TABLE gh_manifests");
    assert_eq!(
        rig.call("aft", OP_LATEST, json!({})).await,
        refusal("store_error", "transient")
    );
}

#[tokio::test]
async fn manifest_report_records_self_and_active_status_tracks_missing_invalid_and_ready() {
    let mut rig = Rig::new();
    rig.store_version(28);
    let before = rig.snapshot();
    assert_eq!(
        rig.call("aft", OP_REPORT_ACTIVE, report(28)).await,
        refusal("secret_setup_incomplete", "permanent")
    );
    assert_eq!(rig.snapshot(), before);
    rig.self_member();
    let status = rig
        .call("plexus", OP_ACTIVE_STATUS, json!({"version":28}))
        .await;
    assert_eq!(
        status,
        json!({"version":28,"manifest_sha256":HASH,"ready":false,"computers":[{
            "member_id":SELF,"version":null,"payload_sha256":null,"verdict":null,"reason":null,"reported_at_ms":null
        }]})
    );
    assert_eq!(
        rig.call("aft", OP_REPORT_ACTIVE, report(28)).await,
        json!({"status":"recorded","member_id":SELF,"version":28})
    );
    let status = rig
        .call("plexus", OP_ACTIVE_STATUS, json!({"version":28}))
        .await;
    assert_eq!(status["ready"], true);
    assert_eq!(status["computers"][0]["member_id"], SELF);
    assert_eq!(status["computers"][0]["version"], 28);
    assert_eq!(status["computers"][0]["payload_sha256"], HASH);
    assert_eq!(status["computers"][0]["verdict"], "valid");
    assert!(status["computers"][0]["reported_at_ms"].as_i64().unwrap() > 0);
    rig.sql(&format!(
        "INSERT INTO member_grants(member_id,operation,selector_kind,selector,pairing_id,created_at_ms,source) VALUES('{OTHER}','secret_use','none','','pairing',1,'operator')"
    ));
    let status = rig
        .call("plexus", OP_ACTIVE_STATUS, json!({"version":28}))
        .await;
    assert_eq!(status["ready"], false);
    assert_eq!(
        status["computers"][1],
        json!({"member_id":OTHER,"version":null,"payload_sha256":null,"verdict":null,"reason":null,"reported_at_ms":null})
    );
    let p: ReportParams = serde_json::from_value(report(28)).unwrap();
    assert_eq!(
        record_manifest_active_report(&rig.store, OTHER, &p)["status"],
        "recorded"
    );
    assert_eq!(
        rig.call("plexus", OP_ACTIVE_STATUS, json!({"version":28}))
            .await["ready"],
        true
    );
    let mut invalid = report(28);
    invalid["verdict"] = json!("invalid");
    invalid["reason"] = json!("bad signature");
    rig.call("aft", OP_REPORT_ACTIVE, invalid).await;
    assert_eq!(
        rig.call("plexus", OP_ACTIVE_STATUS, json!({"version":28}))
            .await["ready"],
        false
    );
    let before = rig.snapshot();
    assert_eq!(
        rig.call("plexus", OP_ACTIVE_STATUS, json!({"version":99}))
            .await,
        refusal("unknown_version", "transient")
    );
    assert_eq!(rig.snapshot(), before);
}

#[tokio::test]
async fn manifest_principals_are_uniformly_hidden_before_parameter_preflight() {
    let mut rig = Rig::new();
    let unknown = rig
        .call(
            "aft",
            "credential.get_scoped",
            json!({"credential_id":"apikey:unknown"}),
        )
        .await;
    let expected = serde_json::to_vec(&crate::wrap_result(unknown)).unwrap();
    for (op, wrong) in [
        (OP_LATEST, "plexus"),
        (OP_WATCH, "cingulate"),
        (OP_REPORT_ACTIVE, "plexus"),
        (OP_ACTIVE_STATUS, "aft"),
    ] {
        for c in [
            caller(wrong),
            crate::federation::RouteCaller::Principal(None),
            crate::federation::RouteCaller::Refused,
            crate::federation::RouteCaller::Phone("a".repeat(32)),
            crate::federation::RouteCaller::Member(OTHER.into()),
        ] {
            let before = rig.snapshot();
            rig.request(c, op, json!({"unrecognized":"must not be parsed"}), 1, 1)
                .await;
            let frame = rig.rx.recv().await.unwrap();
            assert_eq!(frame.header.ty, FrameType::Response);
            assert_eq!(frame.body, expected, "{op}");
            assert_eq!(rig.snapshot(), before);
        }
    }
}

#[tokio::test]
async fn manifest_report_reason_accepts_512_characters_and_refuses_513() {
    let mut rig = Rig::new();
    rig.self_member();
    let mut p = report(1);
    p["verdict"] = json!("invalid");
    p["reason"] = json!("é".repeat(512));
    assert_eq!(
        rig.call("aft", OP_REPORT_ACTIVE, p.clone()).await["status"],
        "recorded"
    );
    p["reason"] = json!("é".repeat(513));
    let before = rig.snapshot();
    rig.request(caller("aft"), OP_REPORT_ACTIVE, p, 1, 1).await;
    let frame = rig.rx.recv().await.unwrap();
    assert_eq!(frame.header.ty, FrameType::Error);
    assert_eq!(body(&frame)["code"], "invalid_params");
    assert_eq!(rig.snapshot(), before);
}

#[tokio::test]
async fn manifest_params_are_exact_and_status_is_home_only() {
    let mut rig = Rig::new();
    rig.self_member();
    let mut bad_reports = vec![json!({}), json!(null)];
    for (key, value) in [
        ("version", json!(0)),
        ("version", json!(-1)),
        ("version", json!(1.5)),
        ("payload_sha256", json!("A".repeat(64))),
        ("payload_sha256", json!("a".repeat(63))),
        ("payload_sha256", json!("a".repeat(65))),
        ("payload_sha256", json!("g".repeat(64))),
        ("verdict", json!("unknown")),
        ("reason", json!("not null")),
        ("member_id", json!(OTHER)),
    ] {
        let mut p = report(1);
        p[key] = value;
        bad_reports.push(p);
    }
    for key in ["version", "payload_sha256", "verdict", "reason"] {
        let mut p = report(1);
        p.as_object_mut().unwrap().remove(key);
        bad_reports.push(p);
    }
    let mut invalid = report(1);
    invalid["verdict"] = json!("invalid");
    bad_reports.push(invalid);
    let before = rig.snapshot();
    for (op, module, params) in bad_reports
        .into_iter()
        .map(|p| (OP_REPORT_ACTIVE, "aft", p))
        .chain([
            (OP_WATCH, "aft", json!({"version":1})),
            (OP_WATCH, "plexus", json!(null)),
            (OP_WATCH, "aft", json!([])),
            (OP_LATEST, "aft", json!({"extra":1})),
            (OP_ACTIVE_STATUS, "plexus", json!({"version":0})),
            (
                OP_ACTIVE_STATUS,
                "plexus",
                json!({"version":1,"extra":true}),
            ),
            (OP_ACTIVE_STATUS, "plexus", json!({})),
        ])
    {
        rig.request(caller(module), op, params, 1, 1).await;
        let frame = rig.rx.recv().await.unwrap();
        assert_eq!(frame.header.ty, FrameType::Error, "{op}: {}", body(&frame));
        assert_eq!(body(&frame)["code"], "invalid_params");
        assert_eq!(rig.snapshot(), before);
    }
    rig.store_version(28);
    for setup in [true, false] {
        if !setup {
            rig.sql("DELETE FROM settings WHERE name='federation.self_member'");
        }
        rig.sql(&format!("INSERT OR REPLACE INTO settings(name,value,updated_at_ms) VALUES('secrets.home_member','{OTHER}',0)"));
        assert_eq!(
            rig.call("plexus", OP_ACTIVE_STATUS, json!({"version":28}))
                .await,
            refusal("not_found", "permanent")
        );
    }
}

#[tokio::test]
async fn manifest_watch_initial_empty_and_stored_then_only_new_versions_notify() {
    let mut rig = Rig::new();
    let mut completed = rig.surface.watches.completed.subscribe();
    rig.request(caller("aft"), OP_WATCH, json!({}), 1, 11).await;
    let initial = rig.notice(1, 11, 1).await;
    assert_eq!(initial["version"], Value::Null);
    assert_eq!(initial["manifest_sha256"], Value::Null);
    completed.wait_for(|count| *count >= 1).await.unwrap();
    rig.store_version(28);
    let changed = rig.notice(1, 11, 2).await;
    assert_eq!(changed["epoch"], initial["epoch"]);
    assert_eq!(changed["version"], 28);
    assert_eq!(changed["manifest_sha256"], HASH);
    completed.wait_for(|count| *count >= 2).await.unwrap();
    // A committed activation wakes the hub but cannot change the manifest notice.
    let p: ReportParams = serde_json::from_value(report(28)).unwrap();
    record_manifest_active_report(&rig.store, SELF, &p);
    completed.wait_for(|count| *count >= 3).await.unwrap();
    assert!(matches!(
        rig.rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    rig.request(caller("plexus"), OP_WATCH, json!({}), 2, 22)
        .await;
    let stored = rig.notice(2, 22, 1).await;
    assert_eq!(stored["version"], 28);
    assert_eq!(stored["manifest_sha256"], HASH);
    assert_eq!(stored["epoch"], initial["epoch"]);
    rig.store_version(29);
    let mut notices = vec![rig.rx.recv().await.unwrap(), rig.rx.recv().await.unwrap()];
    notices.sort_by_key(|frame| frame.header.channel);
    assert_eq!(body(&notices[0])["seq"], 3);
    assert_eq!(body(&notices[1])["seq"], 2);
    for frame in notices {
        assert_eq!(frame.header.ty, FrameType::StreamData);
        assert_eq!(body(&frame)["version"], 29);
        assert_eq!(body(&frame)["manifest_sha256"], HASH);
    }
}

#[tokio::test]
async fn manifest_watch_shares_route_replacement_cap_cancel_goodbye_and_drain() {
    let mut rig = Rig::new();
    for channel in 1..=64 {
        rig.request(caller("aft"), OP_WATCH, json!({}), channel, 11)
            .await;
        rig.notice(channel, 11, 1).await;
    }
    rig.request(caller("aft"), OP_WATCH, json!({}), 65, 11)
        .await;
    let frame = rig.rx.recv().await.unwrap();
    assert_eq!(frame.header.ty, FrameType::Response);
    assert_eq!(body(&frame), crate::uniform_not_found());
    // A scoped watch replaces the manifest watch on the same route, not a second slot.
    rig.request(caller("aft"), "auth.watch_scoped", json!({}), 1, 12)
        .await;
    let a = rig.rx.recv().await.unwrap();
    let b = rig.rx.recv().await.unwrap();
    assert!([&a, &b]
        .iter()
        .any(|f| f.header.ty == FrameType::StreamEnd && f.header.corr == 11));
    assert!([&a, &b].iter().any(|f| f.header.ty == FrameType::StreamData
        && f.header.corr == 12
        && body(f)["seq"] == 1));
    rig.surface.watches.cancel(1, 11);
    assert!(rig.surface.watches.contains(1));
    let routes = Arc::new(crate::RouteEpochs::default());
    let (control, _rx) = mpsc::channel(8);
    let egress = crate::Egress {
        control,
        route: rig.tx.clone(),
    };
    routes.install(1, 3);
    routes.install(2, 3);
    routes.install(65, 3);
    for (ty, channel, corr) in [(FrameType::Cancel, 1, 12), (FrameType::Goodbye, 2, 0)] {
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            ty,
            Flags::new(false, Priority::Interactive, false),
            channel,
            3,
            corr,
            vec![],
        )
        .unwrap();
        crate::handle_frame(frame, &egress, &rig.surface, &rig.admin, &routes)
            .await
            .unwrap();
        assert!(!rig.surface.watches.contains(channel));
    }
    // Ingress registration is synchronous, so a following cancel sees the new watch.
    rig.admin.record_bind_at(
        65,
        3,
        Principal::Reserved {
            module_id: "aft".into(),
        },
        "",
    );
    crate::handle_frame(
        request(OP_WATCH, json!({}), 65, 33),
        &egress,
        &rig.surface,
        &rig.admin,
        &routes,
    )
    .await
    .unwrap();
    assert!(rig.surface.watches.contains(65));
    let cancel = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Cancel,
        Flags::new(false, Priority::Interactive, false),
        65,
        3,
        33,
        vec![],
    )
    .unwrap();
    crate::handle_frame(cancel, &egress, &rig.surface, &rig.admin, &routes)
        .await
        .unwrap();
    assert!(!rig.surface.watches.contains(65));
    rig.surface.watches.finish_all().await.unwrap();
    let mut endings = 0;
    while let Ok(frame) = rig.rx.try_recv() {
        assert_eq!(frame.header.ty, FrameType::StreamEnd);
        assert!((3..=64).contains(&frame.header.channel));
        endings += 1;
    }
    assert_eq!(endings, 62);
    rig.request(caller("aft"), OP_WATCH, json!({}), 3, 44).await;
    let frame = rig.rx.recv().await.unwrap();
    assert_eq!(frame.header.ty, FrameType::Response);
    assert_eq!(body(&frame), crate::uniform_not_found());
}

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

struct Fields(BTreeMap<String, String>);
impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().into(), format!("{value:?}"));
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
    fn event(&self, event: &tracing::Event<'_>) {
        if *event.metadata().level() == tracing::Level::WARN {
            let mut fields = Fields(BTreeMap::new());
            event.record(&mut fields);
            self.0.lock().unwrap().push(fields.0);
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn manifest_lower_version_report_logs_exactly_one_bounded_warning_after_commit() {
    let rig = Rig::new();
    let events = Arc::new(Mutex::new(vec![]));
    tracing::subscriber::with_default(Capture(Arc::clone(&events)), || {
        for version in [29, 29, 28, 28] {
            let mut params = report(version);
            params["verdict"] = json!("invalid");
            params["reason"] = json!("private report detail");
            let params: ReportParams = serde_json::from_value(params).unwrap();
            assert_eq!(
                record_manifest_active_report(&rig.store, SELF, &params)["status"],
                "recorded"
            );
        }
        rig.sql("CREATE TRIGGER fail_report BEFORE UPDATE ON gh_manifest_activations BEGIN SELECT RAISE(ABORT,'unavailable'); END");
        let params: ReportParams = serde_json::from_value(report(27)).unwrap();
        assert_eq!(
            record_manifest_active_report(&rig.store, SELF, &params),
            refusal("store_error", "transient")
        );
    });
    let events = events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0],
        BTreeMap::from([
            ("member_id".into(), format!("{SELF:?}")),
            ("reported".into(), "28".into()),
            ("active".into(), "29".into()),
            ("message".into(), "lower manifest version reported".into()),
        ])
    );
}

struct FederationRig {
    member: Rig,
    home_store: federation_support::HomeStore,
    home: Arc<claustrum_module_probe::federation::HomeVault>,
    vaults: federation_support::TwoVaults,
    _root: credentials_core::test_support::TestTempDir,
}

impl FederationRig {
    async fn new() -> Self {
        use federation_support::{HomeStore, TwoVaults};
        let root = federation_support::temp_root("manifest-forwarding");
        let vaults = TwoVaults::new(&root).await;
        let home_store = HomeStore::open(&vaults.a.data_dir);
        home_store
            .store
            .set_federation_self_member_audited(
                vaults.home_member(),
                AuditCtx::admin(AuditOp::FederationSelfSet),
            )
            .unwrap();
        Connection::open(vaults.a.store_path()).unwrap().execute_batch(
            "INSERT OR REPLACE INTO settings(name,value,updated_at_ms) VALUES('secrets.home_member','self',0)"
        ).unwrap();
        home_store
            .store
            .set_federation_member_mapping_audited(
                true,
                AuditCtx::admin(AuditOp::FederationGateSet),
            )
            .unwrap();
        let home = Arc::new(claustrum_module_probe::federation::HomeVault::new(
            Arc::clone(&home_store.engine),
        ));
        home.attach_outbound(vaults.a.outbound.clone());
        vaults
            .callosum
            .set_pairing(vaults.requester_member(), Some("manifest-pair"));
        home_store
            .store
            .create_member_grant_audited(
                vaults.requester_member(),
                credentials_core::federation::MemberGrantOperation::SecretUse,
                &credentials_core::federation::MemberGrantSelector::None,
                "manifest-pair",
            )
            .unwrap();
        let member = Rig::new();
        member
            .store
            .set_federation_self_member_audited(
                vaults.requester_member(),
                AuditCtx::admin(AuditOp::FederationSelfSet),
            )
            .unwrap();
        member.sql(&format!("INSERT OR REPLACE INTO settings(name,value,updated_at_ms) VALUES('secrets.home_member','{}',0)", vaults.home_member()));
        member
            .surface
            .remote()
            .attach_outbound(crate::federation::OutboundClient::for_daemon(
                &vaults.b.connection_file,
                "claustrum",
                Some("harness-launch-nonce"),
            ));
        Self {
            member,
            home_store,
            home,
            vaults,
            _root: root,
        }
    }

    fn route(&self, method: &'static str, hold: Option<federation_support::Held>) {
        use federation_support::{Reply, Responder};
        let home = Arc::clone(&self.home);
        let member = self.vaults.requester_member().to_owned();
        let hold = Arc::new(Mutex::new(hold));
        self.vaults.callosum.answer(
            "claustrum",
            method,
            Reply::Handler(Responder(Arc::new(move |params| {
                let home = Arc::clone(&home);
                let member = member.clone();
                let hold = Arc::clone(&hold);
                Box::pin(async move {
                    match home.serve(&member, method, &params).await {
                        claustrum_module_probe::federation::HomeAnswer::Reply(reply) => {
                            if let Some(held) = hold.lock().unwrap().take() {
                                assert_eq!(reply["status"], "recorded");
                                Reply::Hold(held)
                            } else {
                                Reply::Ok(reply)
                            }
                        }
                        claustrum_module_probe::federation::HomeAnswer::InvalidParams(_) => {
                            Reply::RouteRefusal("invalid_params".into())
                        }
                    }
                })
            }))),
        );
    }

    fn target(&self) -> String {
        format!(
            "fed:{}:claustrum",
            self.vaults
                .home_member()
                .strip_prefix("fed-computer:")
                .unwrap()
        )
    }

    fn store_version(&self, version: i64) {
        let bytes = format!("{{\n  \"manifest_version\": {version}\n}}\n");
        self.home_store
            .store
            .store_gh_manifest(
                &GhManifestVersion {
                    version,
                    manifest_bytes: bytes.as_bytes(),
                    manifest_sha256: HASH,
                    key_id: "0123456789abcdef",
                    signature: &[7; 64],
                    signed_at_ms: 10,
                    source: GhManifestSource::Import,
                    approval_audit_seq: None,
                },
                AuditCtx::admin(AuditOp::GhManifestStore),
            )
            .unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn manifest_federation_latest_recovers_missed_notice_and_report_retry_deduplicates() {
    use crate::federation::ingress::{OP_MANIFEST_LATEST, OP_MANIFEST_REPORT_ACTIVE};
    use federation_support::{wait_for_signal, Held, Reply};
    let mut rig = FederationRig::new().await;
    rig.store_version(28);
    rig.store_version(29);
    rig.route(OP_MANIFEST_LATEST, None);
    let latest = wait_for_signal(rig.member.call("aft", OP_LATEST, json!({}))).await;
    assert_eq!(latest["version"], 29);
    assert_eq!(
        latest["envelope"]["manifest_bytes"],
        "{\n  \"manifest_version\": 29\n}\n"
    );
    assert!(rig.member.store.latest_gh_manifest().unwrap().is_none());
    let held = Held::new();
    rig.route(OP_MANIFEST_REPORT_ACTIVE, Some(held.clone()));
    let losing = async {
        held.arrived().await;
        wait_for_signal(rig.vaults.callosum.close_connections(false)).await;
        held.release(Reply::Stall);
    };
    let (lost, ()) = tokio::join!(rig.member.call("aft", OP_REPORT_ACTIVE, report(29)), losing);
    assert_eq!(lost, refusal("home_unavailable", "transient"));
    let audits = || {
        rig.home_store
            .store
            .read_audit(None)
            .unwrap()
            .into_iter()
            .filter(|row| row.op == "gh_manifest_activation")
            .count()
    };
    assert_eq!(
        audits(),
        1,
        "the home committed before its reply was dropped"
    );
    let retried = wait_for_signal(rig.member.call("aft", OP_REPORT_ACTIVE, report(29))).await;
    assert_eq!(
        retried,
        json!({"status":"recorded","member_id":rig.vaults.requester_member(),"version":29})
    );
    assert_eq!(audits(), 1);
    let conn = Connection::open(rig.vaults.a.store_path()).unwrap();
    let member: String = conn
        .query_row("SELECT member_id FROM gh_manifest_activations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(member, rig.vaults.requester_member());
    assert_eq!(
        rig.vaults
            .callosum
            .methods(&rig.target())
            .iter()
            .filter(|method| method.as_str() == OP_MANIFEST_REPORT_ACTIVE)
            .count(),
        2
    );
}

#[tokio::test(start_paused = true)]
async fn manifest_federation_watch_shares_upstream_relays_and_ends_on_loss() {
    use crate::federation::ingress::OP_MANIFEST_WATCH;
    use federation_support::{wait_for_signal, HomeWatchRelay, Reply};
    let mut rig = FederationRig::new().await;
    rig.store_version(28);
    let relay = HomeWatchRelay::new(Arc::clone(&rig.home), rig.vaults.requester_member());
    rig.vaults.callosum.answer(
        "claustrum",
        OP_MANIFEST_WATCH,
        Reply::HomeWatch(relay.clone()),
    );
    rig.member
        .request(caller("aft"), OP_WATCH, json!({}), 7, 1)
        .await;
    let first = wait_for_signal(rig.member.notice(7, 1, 1)).await;
    assert_eq!(first["version"], 28);
    rig.member
        .request(caller("plexus"), OP_WATCH, json!({}), 8, 2)
        .await;
    let second = wait_for_signal(rig.member.notice(8, 2, 1)).await;
    assert_eq!(first["epoch"], second["epoch"]);
    assert_eq!(
        rig.vaults
            .callosum
            .methods(&rig.target())
            .iter()
            .filter(|method| method.as_str() == OP_MANIFEST_WATCH)
            .count(),
        1
    );
    let home_first = body(&relay.frames()[0]);
    assert_ne!(
        first["epoch"], home_first["epoch"],
        "the member owns its notice sequence"
    );
    rig.store_version(29);
    wait_for_signal(rig.home.remote_watches.waking_for_test()).await;
    tokio::time::advance(std::time::Duration::from_millis(250)).await;
    let mut channels = Vec::new();
    for _ in 0..2 {
        let frame = wait_for_signal(rig.member.rx.recv()).await.unwrap();
        assert_eq!(frame.header.ty, FrameType::StreamData);
        channels.push(frame.header.channel);
        let value = body(&frame);
        assert_eq!(value["seq"], 2);
        assert_eq!(value["version"], 29);
        assert_eq!(value["epoch"], first["epoch"]);
    }
    channels.sort();
    assert_eq!(channels, [7, 8]);
    wait_for_signal(rig.vaults.callosum.close_connections(false)).await;
    for _ in 0..2 {
        assert_eq!(
            wait_for_signal(rig.member.rx.recv())
                .await
                .unwrap()
                .header
                .ty,
            FrameType::StreamEnd
        );
    }
    rig.vaults.callosum.answer(
        "claustrum",
        OP_MANIFEST_WATCH,
        Reply::Permanent("fed_peer_unreachable".into()),
    );
    rig.member
        .request(caller("aft"), OP_WATCH, json!({}), 9, 3)
        .await;
    let frame = wait_for_signal(rig.member.rx.recv()).await.unwrap();
    assert_eq!(frame.header.ty, FrameType::Response);
    assert_eq!(
        body(&frame)["result"],
        refusal("home_unavailable", "transient")
    );
}

#[tokio::test(start_paused = true)]
async fn manifest_federation_missing_grant_and_nonmember_watch_are_not_found() {
    use crate::federation::ingress::{
        OP_MANIFEST_LATEST, OP_MANIFEST_REPORT_ACTIVE, OP_MANIFEST_WATCH,
    };
    use federation_support::{wait_for_signal, HomeWatchRelay, Reply};
    let mut rig = FederationRig::new().await;
    rig.store_version(28);
    Connection::open(rig.vaults.a.store_path())
        .unwrap()
        .execute("DELETE FROM member_grants", [])
        .unwrap();
    let before = rig.home_store.store.read_audit(None).unwrap();
    for (local, forwarded, params) in [
        (OP_LATEST, OP_MANIFEST_LATEST, json!({})),
        (OP_REPORT_ACTIVE, OP_MANIFEST_REPORT_ACTIVE, report(28)),
    ] {
        rig.route(forwarded, None);
        assert_eq!(
            wait_for_signal(rig.member.call("aft", local, params)).await,
            refusal("not_found", "permanent")
        );
    }
    let relay = HomeWatchRelay::new(Arc::clone(&rig.home), rig.vaults.requester_member());
    rig.vaults.callosum.answer(
        "claustrum",
        OP_MANIFEST_WATCH,
        Reply::HomeWatch(relay.clone()),
    );
    let mut upstream = wait_for_signal(rig.vaults.b.outbound.subscribe(
        "manifest-denied",
        claustrum_module_probe::federation::RouteCall {
            target: claustrum_module_probe::federation::management_surface(&format!(
                    "fed:{}:claustrum",
                    rig.vaults
                        .home_member()
                        .strip_prefix("fed-computer:")
                        .unwrap()
                )),
            prelude: None,
            request: json!({"method":OP_MANIFEST_WATCH,"params":{}}),
        },
        std::time::Duration::from_secs(5),
    ))
    .await
    .unwrap();
    let event = wait_for_signal(upstream.next_event()).await.unwrap();
    assert!(
        matches!(event, claustrum_module_probe::federation::outbound::SubscriptionEvent::Error { ref code, .. } if code == "not_found"),
        "{event:?}"
    );
    assert_eq!(
        relay.frames()[0].header.ty,
        FrameType::Error,
        "Callosum preserves Error bodies, but drops terminal Response bodies"
    );
    assert_eq!(rig.home_store.store.read_audit(None).unwrap(), before);
    for nonmember in [
        caller("aft"),
        crate::federation::RouteCaller::Refused,
        crate::federation::RouteCaller::Phone("phone".into()),
    ] {
        rig.member
            .request(nonmember, OP_MANIFEST_WATCH, json!({}), 10, 4)
            .await;
        let frame = rig.member.rx.recv().await.unwrap();
        assert_eq!(frame.header.ty, FrameType::Error);
        assert_eq!(body(&frame)["code"], "not_found");
    }
}

#[tokio::test(start_paused = true)]
async fn manifest_federation_setup_and_unreachable_refusals_are_explicit() {
    use crate::federation::ingress::{OP_MANIFEST_LATEST, OP_MANIFEST_REPORT_ACTIVE};
    use federation_support::{wait_for_signal, Reply};
    let mut rig = FederationRig::new().await;
    for (local, forwarded, params) in [
        (OP_LATEST, OP_MANIFEST_LATEST, json!({})),
        (OP_REPORT_ACTIVE, OP_MANIFEST_REPORT_ACTIVE, report(28)),
    ] {
        rig.vaults
            .callosum
            .answer("claustrum", forwarded, Reply::Drop);
        assert_eq!(
            wait_for_signal(rig.member.call("aft", local, params)).await,
            refusal("home_unavailable", "transient")
        );
    }
    rig.member.sql(&format!(
        "UPDATE settings SET value='{}' WHERE name='secrets.home_member'",
        rig.vaults.requester_member()
    ));
    let before = rig.member.snapshot();
    for (op, params) in [(OP_LATEST, json!({})), (OP_REPORT_ACTIVE, report(28))] {
        assert_eq!(
            rig.member.call("aft", op, params).await,
            json!({"error":{"code":"remote_setup_incomplete","class":"permanent","remedy_member":rig.vaults.requester_member()}})
        );
    }
    rig.member
        .request(caller("aft"), OP_WATCH, json!({}), 5, 1)
        .await;
    let frame = wait_for_signal(rig.member.rx.recv()).await.unwrap();
    assert_eq!(frame.header.ty, FrameType::Response);
    assert_eq!(
        body(&frame)["result"],
        json!({"error":{"code":"remote_setup_incomplete","class":"permanent","remedy_member":rig.vaults.requester_member()}})
    );
    assert_eq!(rig.member.snapshot(), before);
}
