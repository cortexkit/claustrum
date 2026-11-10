//! Automatic inventories cross real home/member reconcilers and Callosum sockets.

use std::sync::Arc;
use std::time::Duration;

use claustrum_module_probe::admin_surface::{AdminOutcome, AdminSurface};
use claustrum_module_probe::federation::{
    ingress::{OP_REMOTE_TOKEN, OP_REMOTE_WATCH},
    member_watch, sharing,
    transfer::ensure_transfer_key,
    HomeAnswer, HomeVault, RemoteAnswer, RemoteReader,
};
use credentials_core::admin_auth::AdminMacKey;
use credentials_core::admin_ops::{AdminOpBody, ADMIN_OP_SCHEMA_V2};
use credentials_core::audit::{AuditCtx, AuditOp};
use credentials_core::federation::{
    MemberGrantOperation, MemberGrantSelector, MemberGrantSource, RemoteHomeState, RemoteRecord,
    RemoteRecordSource, VAULT_TRANSFER_ID,
};
use credentials_core::key::MasterKey;
use credentials_core::oauth::OAuthCredential;
use credentials_core::plan_detection::DetectedPlan;
use credentials_core::record::{CredentialKind, VaultRecord};
use credentials_core::store::SetCategoryMode;
use credentials_core::test_support::TestTempDir;
use serde_json::{json, Value};
use subc_protocol::FrameType;
use tokio::sync::watch;

use crate::support::{
    temp_root, wait_for_signal, wait_until, wall_ms, HomeStore, HomeWatchRelay, Reply, Responder,
    SharedCallosumStandIn, TwoVaults, VaultFixture, FAKE_ADAPTERS, TARGET_MODULE,
};

const READ: &str = "callosum.paired_devices_read";
const WATCH: &str = "callosum.paired_devices_watch";
const LOGIN: &str = "oauth:watched";
const OPERATOR: &str = "oauth:operator";
const COLLISION: &str = "oauth:collision";

fn inventory(peer: &VaultFixture, pairing: Option<&str>, sharing: bool) -> Value {
    let devices = pairing
        .map(|pairing| {
            json!({
                "class":"computer", "fingerprint":peer.member.member_id.strip_prefix("fed-computer:").unwrap(),
                "pairing_id":pairing, "shares":[{"share":"vault", "enabled":sharing}],
            })
        })
        .into_iter()
        .collect::<Vec<_>>();
    json!({"self":{"static_public_key_hex":"01".repeat(32)}, "devices":devices})
}

fn oauth(adapter: &str) -> VaultRecord {
    VaultRecord::new_oauth(
        "operator",
        adapter,
        OAuthCredential {
            access_token: "access-from-a".to_string().into(),
            refresh_token: "refresh-at-a".to_string().into(),
            expires_at_ms: Some(wall_ms() + 3_600_000),
            token_url: "https://token.test/oauth".into(),
            client_id: Some("client".into()),
            client_secret: None,
            scopes: vec![],
        },
        b"access-from-a".to_vec(),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct MemberTasks {
    sharing: tokio::task::JoinHandle<()>,
    member: tokio::task::JoinHandle<()>,
}

struct Rig {
    vaults: TwoVaults,
    b_callosum: SharedCallosumStandIn,
    a: HomeStore,
    b: HomeStore,
    home: Arc<HomeVault>,
    admin: AdminSurface,
    reader: Arc<RemoteReader>,
    relay: HomeWatchRelay,
    home_task: tokio::task::JoinHandle<()>,
    member_tasks: Option<MemberTasks>,
    operator: RemoteRecord,
    _root: TestTempDir,
}

impl Rig {
    async fn new(name: &str, switch: bool) -> Self {
        let root = temp_root(name);
        let mut vaults = TwoVaults::new(&root).await;
        // Each computer's local Callosum reports its own outgoing sharing switches.
        let b_dir = root.join("callosum-b");
        std::fs::create_dir_all(&b_dir).unwrap();
        let b_callosum = SharedCallosumStandIn::start(&b_dir).await;
        vaults.b = VaultFixture::new(
            &root,
            "vault-b",
            vaults
                .b
                .member
                .member_id
                .strip_prefix("fed-computer:")
                .unwrap(),
            &b_callosum,
        );
        let a = HomeStore::open(&vaults.a.data_dir);
        let b = HomeStore::open(&vaults.b.data_dir);
        // OAuth under a reserved transfer-key id must be omitted because of its id,
        // not merely because ordinary KEM key material cannot refresh.
        // Seed it before installing the real key: an active transfer key forbids
        // writes to every kem:vault-transfer:* id, including this second key id.
        a.store
            .create("kem:vault-transfer:2", &oauth("anthropic"))
            .unwrap();
        a.store
            .set_categories_audited(
                "kem:vault-transfer:2",
                SetCategoryMode::Set,
                &["llm-provider".into()],
                AuditCtx::admin(AuditOp::SetCategory),
            )
            .unwrap();
        for (local, member) in [(&a, vaults.home_member()), (&b, vaults.requester_member())] {
            local
                .store
                .set_federation_self_member_audited(
                    member,
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
            ensure_transfer_key(&local.store, "vault").unwrap();
        }
        for (bus, peer, store) in [
            (&vaults.callosum, vaults.requester_member(), &b.store),
            (&b_callosum, vaults.home_member(), &a.store),
        ] {
            bus.set_pairing(peer, Some("pair-1"));
            let key = store.get(VAULT_TRANSFER_ID).unwrap();
            let (public, _) = credentials_core::kem::public_half(
                std::str::from_utf8(key.payload.expose()).unwrap(),
            )
            .unwrap();
            bus.announce_peer_key(peer, &hex(&public));
        }
        let home = Arc::new(HomeVault::new(Arc::clone(&a.engine)));
        assert!(home.attach_outbound(vaults.a.outbound.clone()));
        let relay = HomeWatchRelay::new(Arc::clone(&home), vaults.requester_member());
        b_callosum.answer(
            TARGET_MODULE,
            OP_REMOTE_WATCH,
            Reply::HomeWatch(relay.clone()),
        );
        let token_home = Arc::clone(&home);
        let requester = vaults.requester_member().to_string();
        b_callosum.answer(
            TARGET_MODULE,
            OP_REMOTE_TOKEN,
            Reply::Handler(Responder(Arc::new(move |params| {
                let home = Arc::clone(&token_home);
                let requester = requester.clone();
                Box::pin(async move {
                    match home.serve(&requester, OP_REMOTE_TOKEN, &params).await {
                        HomeAnswer::Reply(body) => Reply::Ok(body),
                        HomeAnswer::InvalidParams(_) => {
                            Reply::RouteRefusal("invalid_params".into())
                        }
                    }
                })
            }))),
        );
        let key = MasterKey::from_bytes([42; 32]);
        let admin = AdminSurface::new(
            Arc::clone(&b.engine),
            AdminMacKey::derive(&key),
            [9; 32],
            key.key_id(),
        );
        assert!(admin.home().attach_outbound(vaults.b.outbound.clone()));
        let reader = Arc::new(RemoteReader::new(
            Arc::clone(&b.store),
            FAKE_ADAPTERS.iter().map(|s| s.to_string()),
        ));
        assert!(reader.attach_outbound(vaults.b.outbound.clone()));
        assert!(admin.attach_remote_reader(Arc::clone(&reader)));
        let initial = inventory(&vaults.b, Some("pair-1"), switch);
        vaults
            .callosum
            .answer(TARGET_MODULE, READ, Reply::Ok(initial.clone()));
        vaults
            .callosum
            .answer(TARGET_MODULE, WATCH, Reply::Watch(initial));
        let home_task = tokio::spawn(sharing::run_with_home_watches(
            Arc::clone(&a.store),
            vaults.a.outbound.clone(),
            Some(Arc::clone(&home.remote_watches)),
        ));
        wait_until(|| vaults.callosum.saw_method(WATCH)).await;
        wait_until(|| a.store.list_member_grants().unwrap().len() == if switch { 2 } else { 0 })
            .await;
        if !switch {
            a.store
                .create_member_grant_audited(
                    vaults.requester_member(),
                    MemberGrantOperation::RemoteRead,
                    &MemberGrantSelector::Category("llm-provider".into()),
                    "pair-1",
                )
                .unwrap();
        }
        a.store.create(OPERATOR, &oauth("anthropic")).unwrap();
        a.store
            .set_categories_audited(
                OPERATOR,
                SetCategoryMode::Set,
                &["llm-provider".into()],
                AuditCtx::admin(AuditOp::SetCategory),
            )
            .unwrap();
        let added = wait_for_signal(super::admin::run_on(
            &admin,
            &AdminOpBody::RemoteAdd {
                v: ADMIN_OP_SCHEMA_V2,
                credential_id: OPERATOR.into(),
                home: vaults.home_member().into(),
            },
        ))
        .await;
        match added {
            AdminOutcome::Ok(_) => {}
            AdminOutcome::Refused(reason) => panic!("operator remote add refused: {reason}"),
            AdminOutcome::Challenge { .. } => panic!("remote add returned another challenge"),
        }
        let operator = b.store.remote_record(OPERATOR).unwrap().unwrap();
        assert_eq!(operator.source, RemoteRecordSource::Operator);
        b.store
            .create(
                COLLISION,
                &VaultRecord::new_static(
                    CredentialKind::ApiKey,
                    "operator",
                    b"local-wins".to_vec(),
                    None,
                ),
            )
            .unwrap();
        let initial = inventory(&vaults.a, Some("pair-1"), false);
        b_callosum.answer(TARGET_MODULE, READ, Reply::Ok(initial.clone()));
        b_callosum.answer(TARGET_MODULE, WATCH, Reply::Watch(initial));
        Self {
            vaults,
            b_callosum,
            a,
            b,
            home,
            admin,
            reader,
            relay,
            home_task,
            member_tasks: None,
            operator,
            _root: root,
        }
    }

    fn login(&self, id: &str, record: &VaultRecord) {
        self.a.store.create(id, record).unwrap();
        self.categories(id, &["llm-provider"]);
    }

    fn categories(&self, id: &str, categories: &[&str]) {
        self.a
            .store
            .set_categories_audited(
                id,
                SetCategoryMode::Set,
                &categories
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect::<Vec<_>>(),
                AuditCtx::admin(AuditOp::SetCategory),
            )
            .unwrap();
    }

    fn start_b(&mut self) {
        assert!(self.member_tasks.is_none());
        let (tx, rx) = watch::channel(None);
        let member = tokio::spawn(member_watch::run(
            Arc::clone(&self.b.store),
            self.vaults.b.outbound.clone(),
            rx,
        ));
        let sharing = tokio::spawn(sharing::run_with_reconcilers(
            Arc::clone(&self.b.store),
            self.vaults.b.outbound.clone(),
            None,
            Some(tx),
        ));
        self.member_tasks = Some(MemberTasks { sharing, member });
    }

    async fn stop_b(&mut self) {
        let tasks = self.member_tasks.take().unwrap();
        tasks.sharing.abort();
        assert!(wait_for_signal(tasks.sharing)
            .await
            .unwrap_err()
            .is_cancelled());
        wait_for_signal(tasks.member).await.unwrap();
    }

    fn row(&self, id: &str) -> RemoteRecord {
        self.b.store.remote_record(id).unwrap().unwrap()
    }

    async fn installed(&self, id: &str) {
        wait_until(|| self.b.store.remote_record(id).unwrap().is_some()).await;
    }

    async fn cycle(&self) {
        wait_for_signal(self.home.remote_watches.waking_for_test()).await;
        tokio::time::advance(Duration::from_millis(250)).await;
        wait_for_signal(self.home.remote_watches.refreshed_for_test()).await;
        self.relay.fence().await;
    }

    fn snapshots(&self) -> Vec<Value> {
        self.relay
            .frames()
            .into_iter()
            .filter(|f| f.header.ty == FrameType::StreamData)
            .map(|f| serde_json::from_slice(&f.body).unwrap())
            .collect()
    }

    fn protected_rows(&self) {
        assert_eq!(self.row(OPERATOR), self.operator);
        assert_eq!(
            self.b.store.get(COLLISION).unwrap().payload.expose(),
            b"local-wins"
        );
        assert!(self.b.store.remote_record(COLLISION).unwrap().is_none());
    }

    async fn a_inventory(&self, pairing: Option<&str>, switch: bool) {
        self.vaults
            .callosum
            .set_pairing(self.vaults.requester_member(), pairing);
        let snapshot = inventory(&self.vaults.b, pairing, switch);
        self.vaults
            .callosum
            .answer(TARGET_MODULE, READ, Reply::Ok(snapshot.clone()));
        self.vaults
            .callosum
            .answer(TARGET_MODULE, WATCH, Reply::Watch(snapshot.clone()));
        assert_eq!(self.vaults.callosum.watch_snapshot(Some(snapshot)).await, 1);
    }

    async fn b_inventory(&self, pairing: Option<&str>) {
        self.b_callosum
            .set_pairing(self.vaults.home_member(), pairing);
        let snapshot = inventory(&self.vaults.a, pairing, false);
        self.b_callosum
            .answer(TARGET_MODULE, READ, Reply::Ok(snapshot.clone()));
        self.b_callosum
            .answer(TARGET_MODULE, WATCH, Reply::Watch(snapshot.clone()));
        assert_eq!(
            self.b_callosum
                .watch_frame("callosum", FrameType::StreamData, snapshot)
                .await,
            1
        );
    }

    async fn stop(mut self) {
        self.stop_b().await;
        self.home_task.abort();
        assert!(wait_for_signal(&mut self.home_task)
            .await
            .unwrap_err()
            .is_cancelled());
        self.protected_rows();
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.home_task.abort();
        if let Some(tasks) = &self.member_tasks {
            tasks.sharing.abort();
            tasks.member.abort();
        }
    }
}

#[test]
fn two_vault_lifecycle_relay_matches_callosum_error_and_completion_contract() {
    use crate::support::reexport_home_watch_frame;
    use subc_protocol::{Flags, Frame, Priority};

    let frame = |kind, body: Value| {
        Frame::build(
            kind,
            Flags::new(false, Priority::Interactive, false),
            11,
            2,
            7,
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap()
    };
    let data = frame(FrameType::StreamData, json!({"kind":"snapshot", "seq":1}));
    let forwarded = reexport_home_watch_frame(data.clone());
    assert_eq!(forwarded.header.ty, FrameType::StreamData);
    assert_eq!(forwarded.body, data.body);
    assert_eq!(
        (
            forwarded.header.channel,
            forwarded.header.epoch,
            forwarded.header.corr
        ),
        (11, 2, 7)
    );

    let ordinary = json!({"code":"not_found", "message":"not listed", "detail":{"home":"A"}});
    let forwarded = reexport_home_watch_frame(frame(FrameType::Error, ordinary.clone()));
    assert_eq!(forwarded.header.ty, FrameType::Error);
    assert_eq!(
        serde_json::from_slice::<Value>(&forwarded.body).unwrap(),
        ordinary
    );

    // Pin Callosum fed-reexport-watch-v1.0's reserved_module_error_body encoding:
    // only the original code/message survive inside detail, never its own detail.
    let reserved =
        json!({"code":"fed_not_exposed", "message":"module message", "detail":{"ignored":true}});
    let forwarded = reexport_home_watch_frame(frame(FrameType::Error, reserved));
    assert_eq!(forwarded.header.ty, FrameType::Error);
    assert_eq!(forwarded.body, br#"{"code":"executor_error","message":"module used a reserved federation error code","detail":{"code":"fed_not_exposed","message":"module message"}}"#);
    let forwarded = reexport_home_watch_frame(frame(
        FrameType::Error,
        json!({"code":"fed_bad_call", "detail":{"ignored":true}}),
    ));
    assert_eq!(forwarded.body, br#"{"code":"executor_error","message":"module used a reserved federation error code","detail":{"code":"fed_bad_call"}}"#);

    let completed = reexport_home_watch_frame(frame(
        FrameType::Response,
        json!({"result":{"error":{"code":"not_found"}}}),
    ));
    assert_eq!(completed.header.ty, FrameType::StreamEnd);
    assert!(completed.body.is_empty());
}

#[tokio::test(start_paused = true)]
async fn two_vault_lifecycle_automatic_login_token_metadata_and_eligibility() {
    let mut rig = Rig::new("two-vault-metadata", true).await;
    rig.login(LOGIN, &oauth("anthropic"));
    let mut openai = oauth("openai");
    openai.detected_plan = Some(DetectedPlan {
        tier: Some("pro".into()),
        raw: Some("pro".into()),
        observed_at_ms: 42,
    });
    rig.login("oauth:openai", &openai);
    rig.login("oauth:needs", &oauth("anthropic"));
    rig.a.store.invalidate("oauth:needs").unwrap();
    rig.login("oauth:retired", &oauth("anthropic"));
    rig.a
        .store
        .retire_and_revoke_all_audited("oauth:retired", AuditCtx::admin(AuditOp::Invalidate))
        .unwrap();
    rig.login(
        "apikey:static",
        &VaultRecord::new_static(
            CredentialKind::ApiKey,
            "operator",
            b"static-at-a".to_vec(),
            None,
        ),
    );
    rig.login(COLLISION, &oauth("anthropic"));
    rig.start_b();
    rig.installed(LOGIN).await;
    rig.installed("oauth:needs").await;
    assert_eq!(
        rig.row("oauth:needs").last_home_state,
        RemoteHomeState::NeedsReauth
    );
    let first = rig.snapshots();
    assert_eq!(first.len(), 1);
    let listed: Vec<_> = first[0]["logins"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["credential_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        listed,
        [COLLISION, "oauth:needs", "oauth:openai", OPERATOR, LOGIN]
    );
    for id in [
        "oauth:retired",
        "apikey:static",
        VAULT_TRANSFER_ID,
        "kem:vault-transfer:2",
    ] {
        assert!(
            rig.b.store.remote_record(id).unwrap().is_none(),
            "unexpected remote {id}"
        );
    }
    let original = rig.row(LOGIN);
    assert_eq!(original.source, RemoteRecordSource::HomeWatch);
    assert_eq!(original.home_pairing_id.as_deref(), Some("pair-1"));
    let listed = wait_for_signal(super::admin::run_on(
        &rig.admin,
        &AdminOpBody::RemoteList {
            v: ADMIN_OP_SCHEMA_V2,
        },
    ))
    .await;
    let AdminOutcome::Ok(listed) = listed else {
        panic!("remote list refused")
    };
    let row = listed["remote_records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["credential_id"] == LOGIN)
        .unwrap();
    assert_eq!(row["source"], "home_watch");
    assert_eq!(row["home_pairing_id"], "pair-1");

    let RemoteAnswer::Served(token) = wait_for_signal(rig.reader.get(&original, None)).await else {
        panic!("B consumer could not read A's automatically installed login")
    };
    assert_eq!(token.payload, b"access-from-a");
    assert_eq!(rig.a.upstream_calls(), 0);
    // Token issuance audits at A also wake the inventory. Drain that cycle before
    // observing the independent refresh and metadata-only writes below.
    rig.cycle().await;
    let mut writes = rig.b.store.subscribe_writes();
    let b_tip = rig.b.store.audit_tip().unwrap();
    let refreshed = wait_for_signal(rig.a.engine.get(LOGIN, None, true))
        .await
        .unwrap();
    assert_eq!(rig.a.upstream_calls(), 1);
    assert_ne!(refreshed.payload.expose(), b"access-from-a");
    rig.cycle().await;
    assert_eq!(
        rig.snapshots().len(),
        1,
        "token rotation must not emit inventory"
    );
    assert!(!writes.has_changed().unwrap());
    assert_eq!(rig.b.store.audit_tip().unwrap(), b_tip);

    openai.detected_plan.as_mut().unwrap().observed_at_ms = 84;
    rig.a
        .store
        .overwrite_unconditional_audited("oauth:openai", &openai, AuditCtx::admin(AuditOp::Put))
        .unwrap();
    rig.cycle().await;
    assert_eq!(
        rig.snapshots().len(),
        1,
        "plan observation time must not emit inventory"
    );
    assert!(!writes.has_changed().unwrap());
    assert_eq!(rig.b.store.audit_tip().unwrap(), b_tip);

    rig.categories(LOGIN, &["llm-provider", "work"]);
    rig.cycle().await;
    wait_until(|| rig.b.store.categories(LOGIN).unwrap() == ["llm-provider", "work"]).await;
    assert_eq!(rig.row(LOGIN).incarnation, original.incarnation);
    assert_eq!(rig.row(LOGIN).refresh_adapter, original.refresh_adapter);
    assert_eq!(rig.snapshots().len(), 2);
    writes.borrow_and_update();
    let mut changed = rig.a.store.get(LOGIN).unwrap();
    changed.refresh_adapter = Some("meta".into());
    rig.a
        .store
        .overwrite_unconditional_audited(LOGIN, &changed, AuditCtx::admin(AuditOp::Put))
        .unwrap();
    rig.cycle().await;
    wait_until(|| rig.row(LOGIN).refresh_adapter.as_deref() == Some("meta")).await;
    assert_eq!(rig.row(LOGIN).incarnation, original.incarnation);
    assert_eq!(
        rig.b.store.categories(LOGIN).unwrap(),
        ["llm-provider", "work"]
    );
    let snapshots = rig.snapshots();
    assert_eq!(snapshots.len(), 3);
    assert_eq!(
        snapshots
            .iter()
            .map(|s| s["seq"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert!(writes.has_changed().unwrap());
    rig.protected_rows();
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn two_vault_lifecycle_switch_revocation_and_unpair_remove_only_automatic_rows() {
    let mut rig = Rig::new("two-vault-revoke", true).await;
    rig.login(LOGIN, &oauth("anthropic"));
    rig.login(COLLISION, &oauth("anthropic"));
    rig.start_b();
    rig.installed(LOGIN).await;
    assert!(rig
        .a
        .store
        .list_member_grants()
        .unwrap()
        .iter()
        .all(|g| g.source == MemberGrantSource::SharingSwitch));
    rig.a_inventory(Some("pair-1"), false).await;
    wait_until(|| rig.a.store.list_member_grants().unwrap().is_empty()).await;
    rig.cycle().await;
    wait_until(|| rig.b.store.remote_record(LOGIN).unwrap().is_none()).await;
    assert_eq!(rig.snapshots().last().unwrap()["logins"], json!([]));
    assert_eq!(
        rig.b.store.list_remote_records().unwrap(),
        [rig.operator.clone()]
    );
    rig.protected_rows();

    rig.a_inventory(Some("pair-1"), true).await;
    wait_until(|| rig.a.store.list_member_grants().unwrap().len() == 2).await;
    rig.cycle().await;
    rig.installed(LOGIN).await;
    rig.b_inventory(None).await;
    wait_until(|| rig.b.store.remote_record(LOGIN).unwrap().is_none()).await;
    assert_eq!(
        rig.b.store.list_remote_records().unwrap(),
        [rig.operator.clone()]
    );
    rig.protected_rows();
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn two_vault_lifecycle_operator_only_repair_ends_not_found_without_home_write() {
    let mut rig = Rig::new("two-vault-operator-repair", false).await;
    rig.login(LOGIN, &oauth("anthropic"));
    rig.start_b();
    rig.installed(LOGIN).await;
    let writes = rig.a.store.subscribe_writes();
    let tip = rig.a.store.audit_tip().unwrap();
    let start = tokio::time::Instant::now();
    // B's inventory deliberately stays at pair-1: only A learns the new pairing,
    // so removal must come from A's terminal error, not B's inventory cleanup.
    rig.a_inventory(Some("pair-2"), false).await;
    wait_for_signal(rig.home.remote_watches.waking_for_test()).await;
    tokio::time::advance(Duration::from_millis(250)).await;
    wait_until(|| {
        rig.relay
            .frames()
            .iter()
            .any(|f| f.header.ty == FrameType::Error)
    })
    .await;
    let terminal = rig
        .relay
        .frames()
        .into_iter()
        .find(|f| f.header.ty == FrameType::Error)
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&terminal.body).unwrap()["code"],
        "not_found"
    );
    assert!(tokio::time::Instant::now() - start <= Duration::from_secs(1));
    wait_until(|| rig.b.store.remote_record(LOGIN).unwrap().is_none()).await;
    assert_eq!(
        rig.b.store.list_remote_records().unwrap(),
        [rig.operator.clone()]
    );
    assert!(!writes.has_changed().unwrap());
    assert_eq!(rig.a.store.audit_tip().unwrap(), tip);
    let grants = rig.a.store.list_member_grants().unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].source, MemberGrantSource::Operator);
    assert_eq!(grants[0].pairing_id, "pair-1");
    rig.protected_rows();
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn two_vault_lifecycle_offline_and_live_repair_replace_every_old_incarnation() {
    let mut rig = Rig::new("two-vault-repair", true).await;
    let ids = [LOGIN, "oauth:second", "oauth:needs"];
    for id in ids {
        rig.login(id, &oauth("anthropic"));
    }
    rig.a.store.invalidate("oauth:needs").unwrap();
    rig.login(COLLISION, &oauth("anthropic"));
    rig.start_b();
    for id in ids {
        rig.installed(id).await;
    }
    let original = ids.map(|id| rig.row(id));
    rig.stop_b().await;
    rig.a_inventory(Some("pair-2"), true).await;
    wait_until(|| {
        rig.a
            .store
            .list_member_grants()
            .unwrap()
            .iter()
            .all(|g| g.pairing_id == "pair-2")
    })
    .await;
    let snapshot = inventory(&rig.vaults.a, Some("pair-2"), false);
    rig.b_callosum
        .answer(TARGET_MODULE, READ, Reply::Ok(snapshot.clone()));
    rig.b_callosum
        .answer(TARGET_MODULE, WATCH, Reply::Watch(snapshot));
    // Hold the new stream before it can install anything: the first inventory
    // after restart must independently remove all persisted old-pairing rows.
    let held = crate::support::Held::new();
    rig.b_callosum
        .answer(TARGET_MODULE, OP_REMOTE_WATCH, Reply::Hold(held.clone()));
    rig.start_b();
    held.arrived().await;
    assert_eq!(
        rig.b.store.list_remote_records().unwrap(),
        [rig.operator.clone()]
    );
    rig.protected_rows();
    rig.stop_b().await;
    rig.b_callosum.answer(
        TARGET_MODULE,
        OP_REMOTE_WATCH,
        Reply::HomeWatch(rig.relay.clone()),
    );
    rig.start_b();
    for (id, old) in ids.into_iter().zip(&original) {
        rig.installed(id).await;
        let row = rig.row(id);
        assert_eq!(row.home_pairing_id.as_deref(), Some("pair-2"));
        assert_ne!(row.incarnation, old.incarnation);
    }
    let before_live = ids.map(|id| rig.row(id));
    rig.a_inventory(Some("pair-3"), true).await;
    wait_until(|| {
        rig.a
            .store
            .list_member_grants()
            .unwrap()
            .iter()
            .all(|g| g.pairing_id == "pair-3")
    })
    .await;
    rig.b_inventory(Some("pair-3")).await;
    for (id, old) in ids.into_iter().zip(&before_live) {
        wait_until(|| {
            rig.b
                .store
                .remote_record(id)
                .unwrap()
                .is_some_and(|r| r.home_pairing_id.as_deref() == Some("pair-3"))
        })
        .await;
        assert_ne!(rig.row(id).incarnation, old.incarnation);
    }
    let automatic: Vec<_> = rig
        .b
        .store
        .list_remote_records()
        .unwrap()
        .into_iter()
        .filter(|r| r.source == RemoteRecordSource::HomeWatch)
        .collect();
    assert_eq!(automatic.len(), ids.len());
    assert!(automatic
        .iter()
        .all(|r| r.home_pairing_id.as_deref() == Some("pair-3")));
    assert_eq!(
        rig.row("oauth:needs").last_home_state,
        RemoteHomeState::NeedsReauth
    );
    rig.protected_rows();
    rig.stop().await;
}
