use super::*;
use credentials_core::{
    admin_ops::{apply, AdminOpBody, ADMIN_OP_SCHEMA_V2},
    federation::{MemberGrantOperation, MemberGrantSelector},
    record::{CredentialKind, VaultRecord},
    signing::public_key_ed25519,
    store::{GhManifestActivationReport, GhManifestVerdict},
};
use std::time::Duration;
use tokio::sync::{oneshot, watch};

#[path = "policy_token_tests.rs"]
mod policy_token_tests;

const PAIRING: &str = "0123456789abcdef0123456789abcdef";
const ABSENT: Value = Value::Null;

struct Ingress {
    egress: crate::Egress,
    routes: Arc<crate::RouteEpochs>,
    _control: mpsc::Receiver<Frame>,
}

impl Ingress {
    fn new(rig: &Rig) -> Self {
        let (control, rx) = mpsc::channel(8);
        Self {
            egress: crate::Egress {
                control,
                route: rig.tx.clone(),
            },
            routes: Arc::default(),
            _control: rx,
        }
    }

    fn bind(&self, rig: &Rig, channel: u16, module: &str) {
        self.routes.install(channel, 3);
        rig.admin.record_bind_at(
            channel,
            3,
            Principal::Reserved {
                module_id: module.into(),
            },
            "",
        );
    }

    async fn dispatch(&self, rig: &Rig, frame: Frame) {
        assert!(
            crate::handle_frame(frame, &self.egress, &rig.surface, &rig.admin, &self.routes)
                .await
                .unwrap()
        );
    }

    async fn open(&self, rig: &Rig, channel: u16, corr: u64) {
        self.dispatch(rig, request(OP_POLICY_WATCH, json!({}), channel, corr))
            .await;
    }

    async fn stop(&self, rig: &Rig, ty: FrameType, channel: u16, corr: u64) {
        self.dispatch(
            rig,
            Frame::build_with_version(
                PROTOCOL_VERSION,
                ty,
                Flags::new(false, Priority::Interactive, false),
                channel,
                3,
                corr,
                vec![],
            )
            .unwrap(),
        )
        .await;
    }
}

fn root(rig: &Rig) -> String {
    use base64::Engine as _;
    // RFC 8410 PKCS#8 with a fixed test seed so the published sample is reproducible.
    let mut der = vec![
        0x30, 0x2e, 2, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 4, 0x22, 4, 0x20,
    ];
    der.extend_from_slice(&[19; 32]);
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    );
    let key = public_key_ed25519(&pem).unwrap().key_id;
    rig.store
        .put_legacy_manifest_root_for_tests(
            &VaultRecord::new_static(
                CredentialKind::SigningKey,
                "operator",
                pem.into_bytes(),
                None,
            ),
            credentials_core::audit::AuditCtx::admin(credentials_core::audit::AuditOp::Put),
        )
        .unwrap();
    key
}

fn manifest(rig: &Rig, version: i64) -> String {
    manifest_with_bindings(rig, version, json!({"Org/R": "agent"}))
}

fn manifest_with_bindings(rig: &Rig, version: i64, bindings: Value) -> String {
    let manifest_bytes = serde_json::to_string_pretty(&json!({
        "manifest_version": version, "issued_at_unix_secs": 1, "bindings": bindings,
    }))
    .unwrap()
        + "\n";
    apply(
        &rig.store,
        AdminOpBody::ManifestSign {
            v: ADMIN_OP_SCHEMA_V2,
            manifest_bytes,
            approver: "operator".into(),
        },
        "test",
    )
    .unwrap();
    rig.store.latest_gh_manifest_metadata().unwrap().unwrap().1
}

fn policy(rig: &Rig, key_id: &str, version: i64, manifest_version: i64) -> Value {
    let policy_bytes = json!({
        "schema": "ck-agent-policy/v1", "version": version, "issued_at_unix_secs": 1,
        "root_key_id": key_id, "rule_sets": {},
        "bindings": [{"service": "github", "agent": "agent", "identity": "github_app:agent", "resources": ["org/r"]}],
    }).to_string();
    let stored = apply(
        &rig.store,
        AdminOpBody::AgentPolicySign {
            v: ADMIN_OP_SCHEMA_V2,
            policy_bytes,
            manifest_version,
            approver: "operator".into(),
        },
        "test",
    )
    .unwrap();
    json!({"version": version, "manifest_version": manifest_version,
        "policy_text": stored["envelope"]["policy"], "policy_sha256": stored["policy_sha256"]})
}

fn report_version(rig: &Rig, member: &str, version: i64, digest: &str, verdict: GhManifestVerdict) {
    let report = GhManifestActivationReport {
        member_id: member,
        version,
        payload_sha256: digest,
        verdict,
        reason: (verdict == GhManifestVerdict::Invalid).then_some("fixture_invalid"),
        reported_at_ms: 100,
    };
    let ctx = AuditCtx::admin(AuditOp::GhManifestActivation);
    if member == SELF {
        rig.store.record_hub_own_report(&report, ctx).unwrap();
    } else {
        rig.store
            .seed_gh_manifest_activation_for_tests(&report, ctx)
            .unwrap();
    }
}

fn ready(rig: &Rig, member: &str, version: i64, digest: &str) {
    report_version(rig, member, version, digest, GhManifestVerdict::Valid);
}

fn admit_peer(rig: &Rig) {
    rig.store
        .create_member_grant_audited(
            OTHER,
            MemberGrantOperation::SecretUse,
            &MemberGrantSelector::None,
            PAIRING,
        )
        .unwrap();
}

fn use_remote_home(rig: &Rig) {
    rig.store
        .set_secret_home_audited(Some(OTHER), AuditCtx::admin(AuditOp::SecretHomeSet))
        .unwrap();
}

async fn wait_count(signal: &mut watch::Receiver<u64>, count: u64) {
    tokio::time::timeout(Duration::from_secs(5), signal.wait_for(|n| *n >= count))
        .await
        .unwrap()
        .unwrap();
}

async fn frame(rig: &mut Rig) -> Frame {
    tokio::time::timeout(Duration::from_secs(5), rig.rx.recv())
        .await
        .unwrap()
        .unwrap()
}

async fn policy_notice(rig: &mut Rig, corr: u64, seq: u64, version: Value, hash: &Value) -> Value {
    let notice = tokio::time::timeout(Duration::from_secs(5), rig.notice(1, corr, seq))
        .await
        .unwrap_or_else(|_| panic!("no policy notice for correlation {corr}, sequence {seq}"));
    assert_eq!(
        notice,
        json!({"epoch": notice["epoch"], "kind": "changed", "seq": seq, "version": version, "policy_sha256": hash})
    );
    notice
}

fn stall_snapshot(rig: &Rig) -> (oneshot::Receiver<()>, std::sync::mpsc::Sender<()>) {
    let (started, reached) = oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    *rig.surface.watches.policy_snapshot_hook.lock().unwrap() = Some(Box::new(move |reply| {
        started.send(()).unwrap();
        let _ = blocked.recv();
        reply
    }));
    (reached, release)
}

#[tokio::test]
async fn policy_watch_projects_ready_metadata_without_decoding_the_document() {
    let mut rig = Rig::new();
    let ingress = Ingress::new(&rig);
    ingress.bind(&rig, 1, "plexus");
    root(&rig);
    rig.self_member();
    let digest = manifest(&rig, 41);
    let hash = "a".repeat(64);
    rig.sql(&format!("INSERT INTO agent_policies VALUES (1, x'ff', '{hash}', '0123456789abcdef', zeroblob(64), 1, 'ceremony', 1, 41)"));
    let mut completed = rig.surface.watches.completed.subscribe();
    ingress.open(&rig, 1, 11).await;
    policy_notice(&mut rig, 11, 1, ABSENT, &ABSENT).await;
    ready(&rig, SELF, 41, &digest);
    wait_count(&mut completed, 2).await;
    let changed = rig
        .rx
        .try_recv()
        .expect("the ready pair does not need policy text");
    assert_eq!(body(&changed)["policy_sha256"], hash);
    assert_eq!(
        rig.call("plexus", OP_POLICY_ACTIVE, json!({})).await,
        refusal("store_error", "transient")
    );
    rig.store
        .set_manifest_one_tap_audited(true, AuditCtx::admin(AuditOp::GhManifestOneTapSet))
        .unwrap();
    wait_count(&mut completed, 3).await;
    assert!(rig.rx.try_recv().is_err());
}

#[tokio::test]
async fn policy_reads_follow_the_fleet_floor_and_pin_the_public_samples() {
    let mut rig = Rig::new();
    let ingress = Ingress::new(&rig);
    ingress.bind(&rig, 1, "plexus");
    let key_id = root(&rig);
    rig.self_member();
    admit_peer(&rig);
    let m1 = manifest(&rig, 41);
    assert!(rig
        .call("plexus", OP_ACTIVE_STATUS, json!({"version":41}))
        .await
        .get("policy")
        .is_none());
    ready(&rig, SELF, 41, &m1);
    ready(&rig, OTHER, 41, &m1);
    let absent =
        json!({"version":null,"policy_sha256":null,"manifest_version":null,"policy_text":null});
    let result = rig.call("aft", OP_POLICY_ACTIVE, json!({})).await;
    assert_eq!(result, absent);
    assert_sample("policy.active.none", json!({"result": result}));
    let mut completed = rig.surface.watches.completed.subscribe();

    // A commit after the first read (but before its notice) must wake recomputation.
    let (reached, release) = stall_snapshot(&rig);
    ingress.open(&rig, 1, 11).await;
    tokio::time::timeout(Duration::from_secs(5), reached)
        .await
        .unwrap()
        .unwrap();
    let p1 = policy(&rig, &key_id, 1, 41);
    release.send(()).unwrap();
    let empty = policy_notice(&mut rig, 11, 1, ABSENT, &ABSENT).await;
    let changed = policy_notice(&mut rig, 11, 2, json!(1), &p1["policy_sha256"]).await;
    assert_eq!(empty["epoch"], changed["epoch"]);
    let result = rig.call("plexus", OP_POLICY_ACTIVE, json!({})).await;
    assert_eq!(result, p1);
    assert_sample("policy.active.ready", json!({"result": result}));
    for (label, mut notice) in [
        ("policy.watch.initial", empty),
        ("policy.watch.changed", changed),
    ] {
        notice["epoch"] = json!("00112233445566778899aabbccddeeff");
        assert_sample(label, notice);
    }

    wait_count(&mut completed, 2).await;
    let m2 = manifest(&rig, 42);
    let unpaired = rig
        .call("plexus", OP_ACTIVE_STATUS, json!({"version":42}))
        .await;
    assert_eq!(unpaired.get("policy"), Some(&ABSENT));
    let p2 = policy(&rig, &key_id, 2, 42);
    let pending = rig
        .call("plexus", OP_ACTIVE_STATUS, json!({"version":42}))
        .await;
    assert_eq!(pending["ready"], false);
    assert_eq!(
        pending["policy"],
        json!({"version":2,"policy_sha256":p2["policy_sha256"]})
    );
    let mut p1_during_rollout = p1.clone();
    p1_during_rollout["rollout"] = json!({"manifest_version":42,"policy_version":2});
    assert_eq!(
        rig.call("aft", OP_POLICY_ACTIVE, json!({})).await,
        p1_during_rollout
    );
    policy_notice(&mut rig, 11, 3, json!(1), &p1["policy_sha256"]).await;
    wait_count(&mut completed, 3).await;
    assert!(rig.rx.try_recv().is_err());

    let before_report = *completed.borrow();
    ready(&rig, SELF, 42, &m2);
    wait_count(&mut completed, before_report + 1).await;
    assert!(rig.rx.try_recv().is_err());
    assert_eq!(
        rig.call("aft", OP_POLICY_ACTIVE, json!({})).await,
        p1_during_rollout
    );
    ready(&rig, OTHER, 42, &m2);
    policy_notice(&mut rig, 11, 4, json!(2), &p2["policy_sha256"]).await;
    assert_eq!(rig.call("aft", OP_POLICY_ACTIVE, json!({})).await, p2);

    // Keep the old report when the grant is revoked to isolate the admission input.
    // A normal hub revoke also clears the report fields in the same commit.
    rig.sql(
        "CREATE TRIGGER keep_report BEFORE UPDATE ON gh_manifest_activations
             WHEN NEW.version IS NULL BEGIN SELECT RAISE(IGNORE); END;",
    );
    rig.store
        .revoke_member_grant_audited(
            OTHER,
            MemberGrantOperation::SecretUse,
            &MemberGrantSelector::None,
        )
        .unwrap();
    policy_notice(&mut rig, 11, 5, ABSENT, &ABSENT).await;
    admit_peer(&rig);
    policy_notice(&mut rig, 11, 6, json!(2), &p2["policy_sha256"]).await;
    rig.sql("DROP TRIGGER keep_report;");
    wait_count(&mut completed, 7).await;
    let original = *completed.borrow();
    ready(&rig, OTHER, 42, &m2);
    wait_count(&mut completed, original + 1).await;
    assert!(rig.rx.try_recv().is_err());

    // A missed recomputation sends nothing and does not consume a sequence number.
    *rig.surface.watches.policy_snapshot_hook.lock().unwrap() =
        Some(Box::new(|_| refusal("store_error", "transient")));
    ready(&rig, SELF, 41, &m1);
    wait_count(&mut completed, original + 2).await;
    assert!(rig.rx.try_recv().is_err());
    rig.store
        .set_manifest_one_tap_audited(true, AuditCtx::admin(AuditOp::GhManifestOneTapSet))
        .unwrap();
    policy_notice(&mut rig, 11, 7, json!(1), &p1["policy_sha256"]).await;
    ready(&rig, SELF, 42, &m2);
    policy_notice(&mut rig, 11, 8, json!(2), &p2["policy_sha256"]).await;
    wait_count(&mut completed, original + 4).await;
    ready(&rig, SELF, 41, &m1);
    ready(&rig, SELF, 42, &m2);
    wait_count(&mut completed, original + 5).await;
    assert!(rig.rx.try_recv().is_err());

    // Manifest watch still projects only the newest manifest, even when a policy exists.
    rig.request(caller("aft"), OP_WATCH, json!({}), 2, 22).await;
    assert_eq!(rig.notice(2, 22, 1).await["manifest_sha256"], m2);
    rig.surface.watches.close(2);
    use_remote_home(&rig);
    let end = frame(&mut rig).await;
    assert_eq!((end.header.ty, end.header.corr), (FrameType::Response, 11));
    assert_eq!(body(&end), crate::uniform_not_found());
    assert_eq!(
        rig.call("plexus", OP_POLICY_ACTIVE, json!({})).await,
        refusal("not_found", "permanent")
    );
    assert!(rig.rx.try_recv().is_err());
}

async fn policy_active_reply_bytes(rig: &mut Rig, corr: u64) -> Vec<u8> {
    rig.request(caller("aft"), OP_POLICY_ACTIVE, json!({}), 2, corr)
        .await;
    let reply = frame(rig).await;
    assert_eq!(
        (reply.header.ty, reply.header.corr),
        (FrameType::Response, corr)
    );
    reply.body.as_slice().to_vec()
}

#[tokio::test]
async fn policy_active_rollout_samples_and_watch_changes() {
    let mut rig = Rig::new();
    let ingress = Ingress::new(&rig);
    ingress.bind(&rig, 1, "plexus");
    let key = root(&rig);
    rig.self_member();
    admit_peer(&rig);
    let m1 = manifest(&rig, 41);
    let p1 = policy(&rig, &key, 1, 41);
    let unready = policy_active_reply_bytes(&mut rig, 20).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&unready).unwrap(),
        json!({"result": {
            "version":null, "policy_sha256":null, "manifest_version":null, "policy_text":null,
            "rollout":{"manifest_version":41,"policy_version":1},
        }})
    );
    ready(&rig, SELF, 41, &m1);
    ready(&rig, OTHER, 41, &m1);
    ingress.open(&rig, 1, 12).await;
    policy_notice(&mut rig, 12, 1, json!(1), &p1["policy_sha256"]).await;
    let settled = policy_active_reply_bytes(&mut rig, 21).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&settled).unwrap(),
        json!({"result":p1})
    );

    manifest(&rig, 42);
    assert_eq!(rig.call("aft", OP_POLICY_ACTIVE, json!({})).await, p1);
    policy(&rig, &key, 2, 42);
    policy_notice(&mut rig, 12, 2, json!(1), &p1["policy_sha256"]).await;
    let rolling = policy_active_reply_bytes(&mut rig, 22).await;
    let mut want = p1.clone();
    want["rollout"] = json!({"manifest_version":42,"policy_version":2});
    assert_eq!(
        serde_json::from_slice::<Value>(&rolling).unwrap(),
        json!({"result":want})
    );

    let m3 = manifest(&rig, 43);
    let p3 = policy(&rig, &key, 3, 43);
    policy_notice(&mut rig, 12, 3, json!(1), &p1["policy_sha256"]).await;
    want["rollout"] = json!({"manifest_version":43,"policy_version":3});
    assert_eq!(rig.call("aft", OP_POLICY_ACTIVE, json!({})).await, want);

    ready(&rig, SELF, 43, &m3);
    ready(&rig, OTHER, 43, &m3);
    policy_notice(&mut rig, 12, 4, json!(3), &p3["policy_sha256"]).await;
    assert_eq!(rig.call("aft", OP_POLICY_ACTIVE, json!({})).await, p3);

    pin_policy_active_samples([
        ("policy.active.ready.json", settled.as_slice()),
        ("policy.active.rollout.json", rolling.as_slice()),
        ("policy.active.rollout-unready.json", unready.as_slice()),
    ]);
}

fn pin_policy_active_samples(samples: [(&str, &[u8]); 3]) {
    use std::{fs, path::Path};
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/agent-policy-v1");
    let emit = std::env::var("CK_EMIT_SECRET_VECTORS").as_deref() == Ok("1");
    if emit {
        fs::create_dir_all(&directory).unwrap();
    }
    let mut sums = String::new();
    for (name, bytes) in samples {
        let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
        let hash: String = digest
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        sums.push_str(&format!("{hash}  {name}\n"));
        let file = directory.join(name);
        if emit {
            fs::write(&file, bytes).unwrap();
        } else {
            assert_eq!(fs::read(&file).unwrap(), bytes, "{}", file.display());
        }
    }
    let sums_file = directory.join("SHA256SUMS");
    if emit {
        fs::write(sums_file, sums).unwrap();
    } else {
        assert_eq!(fs::read_to_string(sums_file).unwrap(), sums);
    }
}

fn assert_sample(label: &str, actual: Value) {
    let docs = include_str!("../../../docs/wire-contract-v1.md");
    let sample = docs
        .split_once(&format!("<!-- golden:{label} -->\n```json\n"))
        .unwrap()
        .1
        .split_once("\n```")
        .unwrap()
        .0;
    assert_eq!(
        actual,
        serde_json::from_str::<Value>(sample).unwrap(),
        "{label}"
    );
}

#[tokio::test]
async fn policy_watch_registers_in_frame_order_and_releases_stalled_routes() {
    let mut rig = Rig::new();
    let ingress = Ingress::new(&rig);
    ingress.bind(&rig, 1, "aft");
    let mut exited = rig.surface.watches.exited.subscribe();
    for (index, ty) in [FrameType::Cancel, FrameType::Goodbye]
        .into_iter()
        .enumerate()
    {
        let (reached, release) = stall_snapshot(&rig);
        let corr = index as u64 + 11;
        ingress.open(&rig, 1, corr).await;
        assert!(
            rig.surface.watches.contains(1),
            "registration must finish on the frame loop"
        );
        tokio::time::timeout(Duration::from_secs(5), reached)
            .await
            .unwrap()
            .unwrap();
        ingress.stop(&rig, ty, 1, corr).await;
        assert!(!rig.surface.watches.contains(1));
        wait_count(&mut exited, index as u64 + 1).await;
        release.send(()).unwrap();
        assert!(rig.rx.try_recv().is_err());
    }

    ingress.bind(&rig, 1, "aft");
    let (reached, release) = stall_snapshot(&rig);
    ingress.open(&rig, 1, 21).await;
    tokio::time::timeout(Duration::from_secs(5), reached)
        .await
        .unwrap()
        .unwrap();
    ingress
        .dispatch(&rig, request(OP_POLICY_WATCH, json!({"extra":true}), 1, 22))
        .await;
    let invalid = frame(&mut rig).await;
    assert_eq!(
        (invalid.header.ty, invalid.header.corr),
        (FrameType::Error, 22)
    );
    ingress.bind(&rig, 1, "other");
    ingress.open(&rig, 1, 23).await;
    let refused = frame(&mut rig).await;
    assert_eq!(
        (refused.header.ty, refused.header.corr),
        (FrameType::Response, 23)
    );
    assert_eq!(body(&refused), crate::uniform_not_found());
    ingress.bind(&rig, 1, "plexus");
    ingress.open(&rig, 1, 24).await;
    let mut frames = [frame(&mut rig).await, frame(&mut rig).await];
    frames.sort_by_key(|f| f.header.corr);
    assert_eq!(
        (frames[0].header.ty, frames[0].header.corr),
        (FrameType::StreamEnd, 21)
    );
    assert_eq!(
        (frames[1].header.ty, frames[1].header.corr),
        (FrameType::StreamData, 24)
    );
    assert_eq!(body(&frames[1])["seq"], 1);
    release.send(()).unwrap();
    rig.surface.watches.finish_all().await.unwrap();
    let end = frame(&mut rig).await;
    assert_eq!((end.header.ty, end.header.corr), (FrameType::StreamEnd, 24));
    assert!(rig.rx.try_recv().is_err());
}

#[tokio::test]
async fn policy_watch_shares_the_daemon_cap() {
    let mut rig = Rig::new();
    let ingress = Ingress::new(&rig);
    for channel in 1..=64 {
        ingress.bind(&rig, channel, "aft");
        ingress.open(&rig, channel, 11).await;
        let next = frame(&mut rig).await;
        assert_eq!(
            (next.header.ty, next.header.channel),
            (FrameType::StreamData, channel)
        );
    }
    ingress.bind(&rig, 65, "aft");
    ingress.open(&rig, 65, 11).await;
    let next = frame(&mut rig).await;
    assert_eq!(
        (next.header.ty, next.header.channel),
        (FrameType::Response, 65)
    );
    assert_eq!(body(&next), crate::uniform_not_found());
}

#[tokio::test]
async fn policy_reads_hide_roles_and_never_relay_on_a_remote_vault() {
    let mut rig = Rig::new();
    let ingress = Ingress::new(&rig);
    ingress.bind(&rig, 1, "aft");
    use_remote_home(&rig);
    for ready_self in [false, true] {
        if ready_self {
            rig.self_member();
        }
        ingress.open(&rig, 1, 11).await;
        let refused = frame(&mut rig).await;
        assert_eq!(
            (refused.header.ty, refused.header.corr),
            (FrameType::Response, 11)
        );
        assert_eq!(body(&refused), crate::uniform_not_found());
        assert_eq!(
            rig.call("aft", OP_POLICY_ACTIVE, json!({})).await,
            refusal("not_found", "permanent")
        );
    }
    rig.sql(&format!(
        "UPDATE settings SET value = 'broken' WHERE name = '{}'",
        credentials_core::store::SECRET_HOME_SETTING
    ));
    assert_eq!(
        rig.call("other", OP_POLICY_ACTIVE, json!({"bad":true}))
            .await,
        refusal("not_found", "permanent")
    );
    assert_eq!(
        rig.call("aft", OP_POLICY_ACTIVE, json!({})).await,
        refusal("store_error", "transient")
    );
    ingress.open(&rig, 1, 12).await;
    let refused = frame(&mut rig).await;
    assert_eq!(
        (refused.header.ty, refused.header.corr),
        (FrameType::Response, 12)
    );
    assert_eq!(
        body(&refused)["result"],
        refusal("store_error", "transient")
    );
    ingress.bind(&rig, 1, "other");
    ingress.open(&rig, 1, 13).await;
    let refused = frame(&mut rig).await;
    assert_eq!(
        (refused.header.ty, refused.header.corr),
        (FrameType::Response, 13)
    );
    assert_eq!(body(&refused), crate::uniform_not_found());
}
