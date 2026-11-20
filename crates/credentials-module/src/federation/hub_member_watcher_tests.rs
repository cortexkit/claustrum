use super::*;
use crate::federation::{
    hub::{
        stand_in::{StandIn, StandInClient},
        HubWatch,
    },
    hub_logins::seal,
    sharing::decode_snapshot,
};
use async_trait::async_trait;
use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::{
    audit::{AuditCtx, AuditOp},
    federation::{NewRemoteRecord, RemoteHomeState, RemoteRecord},
    hub_counters::HubGeneration,
    key::MasterKey,
    record::RecordIdentity,
    test_support::TestTempDir,
};
use serde_json::{json, Value};
use std::{
    future::Future,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Duration,
};
use tokio::{sync::Notify, task::JoinHandle};

const HOME_FP: &str = "01010101010101010101010101010101";
const HOME: &str = "fed-computer:01010101010101010101010101010101";
const MEMBER: &str = "fed-computer:02020202020202020202020202020202";
const HOME_BOX: &str = "11111111111111111111111111111111";
const SECOND_BOX: &str = "12121212121212121212121212121212";
const MEMBER_BOX: &str = "22222222222222222222222222222222";
const LOGIN_KEY: &str = "11111111111111111111111111111111.22222222222222222222222222222222";
const SECOND_KEY: &str = "12121212121212121212121212121212.22222222222222222222222222222222";
const PAIR: &str = "pair:1";
const REPAIR: &str = "pair:2";
const SENDER: u8 = 12;
const RECIPIENT: u8 = 13;
const ID: &str = "oauth:hub-member";
const OTHER: &str = "oauth:hub-other";

fn pem(scalar: u8) -> String {
    kem::pem_from_scalar(&[scalar; 32])
}

fn public(scalar: u8) -> [u8; 32] {
    kem::public_half(&pem(scalar))
        .unwrap()
        .0
        .try_into()
        .unwrap()
}

fn transfer_key(scalar: u8) -> VaultRecord {
    VaultRecord::new_static(
        CredentialKind::KemKey,
        "test",
        pem(scalar).into_bytes(),
        None,
    )
}

fn aad(generation: i64) -> LoginAad {
    LoginAad {
        home: HOME.into(),
        member: MEMBER.into(),
        home_box: HOME_BOX.into(),
        member_box: MEMBER_BOX.into(),
        generation: HubGeneration::new(generation).unwrap(),
        sender_key_id: key_id_for_public(&public(SENDER)),
        recipient_key_id: key_id_for_public(&public(RECIPIENT)),
    }
}

fn sealed(aad: &LoginAad, sender: u8, recipient: u8, body: &Value) -> Vec<u8> {
    seal(
        aad,
        &pem(sender),
        &public(recipient),
        &serde_json::to_vec(body).unwrap(),
    )
    .unwrap()
}

fn row(id: &str, version: u64) -> Value {
    json!({"credential_id":id, "state":"active", "identity":{"org_name":"original"}, "categories":[], "home_version":version})
}

fn snapshot(rows: Vec<Value>) -> Value {
    json!({"kind":"snapshot", "logins": rows})
}

fn login(generation: i64, rows: Vec<Value>) -> Vec<u8> {
    sealed(&aad(generation), SENDER, RECIPIENT, &snapshot(rows))
}

fn ended(generation: i64) -> Vec<u8> {
    sealed(
        &aad(generation),
        SENDER,
        RECIPIENT,
        &json!({"kind":"ended"}),
    )
}

fn paired(pair: Option<&str>) -> Arc<VaultSharingSnapshot> {
    let devices: Vec<_> = pair
        .into_iter()
        .map(|pair| {
            json!({
                "fingerprint": HOME_FP, "pairing_id":pair, "class":"computer", "shares":[]
            })
        })
        .collect();
    Arc::new(
        decode_snapshot(
            &json!({"self":{"static_public_key_hex":"00".repeat(32)}, "devices":devices}),
        )
        .unwrap(),
    )
}

fn joined(pairs: &VaultSharingSnapshot, peer: Option<(&str, &str, u8)>) -> HubBindings {
    let peers: Vec<_> = peer.into_iter().map(|(pair, box_id, scalar)| json!({
        "fingerprint":HOME_FP, "pairing_id":pair, "class":"computer", "machine_id":box_id,
        "key_record":{"keys":{"vault_transfer_x25519":{"pub":public(scalar).iter().map(|b| format!("{b:02x}")).collect::<String>()}}}
    })).collect();
    HubBindings::join(MEMBER_BOX, pairs, &json!({"peers":peers})).unwrap()
}

fn open_store() -> (TestTempDir, Arc<EncryptedStore>, rusqlite::Connection) {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let root = TestTempDir::new(format!(
        "hub-member-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let path = root.join("store.db");
    let db = open_sqlite(&StorageDescriptor {
        module_id: "claustrum".into(),
        storage_namespace: "vault".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    })
    .unwrap();
    EncryptedStore::migrate(&db).unwrap();
    let store = Arc::new(EncryptedStore::open(db, MasterKey::from_bytes([24; 32])).unwrap());
    (root, store, rusqlite::Connection::open(path).unwrap())
}

struct Rig {
    _root: TestTempDir,
    store: Arc<EncryptedStore>,
    raw: rusqlite::Connection,
    hub: StandIn,
    bindings: watch::Sender<Option<HubBindings>>,
    pairs: watch::Sender<Option<Arc<VaultSharingSnapshot>>>,
    handled: mpsc::UnboundedReceiver<HubEvent>,
    attempted: Arc<Notify>,
    task: Option<JoinHandle<()>>,
}

impl Rig {
    fn new(bound: bool) -> Self {
        let (_root, store, raw) = open_store();
        store
            .create(VAULT_TRANSFER_ID, &transfer_key(RECIPIENT))
            .unwrap();
        store
            .set_federation_self_member_audited(MEMBER, AuditCtx::admin(AuditOp::FederationSelfSet))
            .unwrap();
        store.set_login_sharing_audited(true, "test").unwrap();
        let pair = bound.then(|| paired(Some(PAIR)));
        let view = pair
            .as_ref()
            .map(|pair| joined(pair, Some((PAIR, HOME_BOX, SENDER))));
        Self {
            _root,
            store,
            raw,
            hub: StandIn::new(),
            bindings: watch::channel(view).0,
            pairs: watch::channel(pair).0,
            handled: mpsc::unbounded_channel().1,
            attempted: Arc::new(Notify::new()),
            task: None,
        }
    }

    fn views(&self, pair: Option<&str>, peer: Option<(&str, &str, u8)>) {
        let pair = paired(pair);
        self.pairs.send_replace(Some(Arc::clone(&pair)));
        self.bindings.send_replace(Some(joined(&pair, peer)));
    }

    fn start(&mut self) {
        self.start_on(Arc::new(self.hub.client(MEMBER_BOX)), None);
    }

    fn start_on(&mut self, hub: Arc<dyn Hub>, gate: Option<super::super::ingress::IssueAuditGate>) {
        assert!(self.task.is_none());
        let (handled, rx) = mpsc::unbounded_channel();
        self.handled = rx;
        self.attempted = Arc::new(Notify::new());
        self.task = Some(tokio::spawn(run_inner(
            Arc::clone(&self.store),
            hub,
            self.bindings.subscribe(),
            self.pairs.subscribe(),
            TestHooks {
                before_apply: gate,
                apply_attempted: Some(Arc::clone(&self.attempted)),
                handled: Some(handled),
            },
        )));
    }

    async fn stop(&mut self) {
        let task = self.task.take().unwrap();
        task.abort();
        assert!(wait(task).await.unwrap_err().is_cancelled());
    }

    fn row(&self, id: &str) -> Option<RemoteRecord> {
        self.store.remote_record(id).unwrap()
    }
    fn state(&self) -> Option<HubLoginHomeState> {
        self.store.hub_login_home_state(HOME).unwrap()
    }
    fn generation(&self) -> Option<i64> {
        self.state().map(|state| state.generation.get())
    }
    fn sharing(&self, enabled: bool) {
        self.store
            .set_login_sharing_audited(enabled, "test")
            .unwrap();
    }
    fn watch_opens(&self) -> usize {
        self.hub.watch_opens(SHARED_LOGINS)
    }

    fn add_handmade(&self, id: &str) {
        self.store
            .remote_add_audited(&NewRemoteRecord {
                credential_id: id.into(),
                home_member: HOME.into(),
                refresh_adapter: None,
                detected_plan: None,
                identity: RecordIdentity::default(),
                home_version: 1,
                categories: vec![],
            })
            .unwrap();
    }

    fn put(&self, bytes: &[u8]) -> u64 {
        self.put_at(LOGIN_KEY, bytes)
    }
    fn put_at(&self, key: &str, bytes: &[u8]) -> u64 {
        self.hub.tamper(SHARED_LOGINS, key, bytes).unwrap()
    }

    async fn seen(&mut self, revision: u64) {
        wait(async {
            while let Some(event) = self.handled.recv().await {
                if matches!(event, HubEvent::Entry(entry) if entry.revision == revision) {
                    return;
                }
            }
            panic!("watcher dropped the event signal");
        })
        .await;
    }

    async fn reset_seen(&mut self) {
        wait(async {
            while let Some(event) = self.handled.recv().await {
                if matches!(event, HubEvent::BucketReset { .. }) {
                    return;
                }
            }
            panic!("watcher dropped the reset signal");
        })
        .await;
    }

    async fn put_seen(&mut self, bytes: &[u8]) {
        self.seen(self.put(bytes)).await;
    }
    async fn opened(&self, count: usize) {
        until(|| self.watch_opens() >= count).await;
    }

    fn fail_apply(&self) {
        self.raw.execute_batch("CREATE TRIGGER fail_apply BEFORE INSERT ON hub_login_homes BEGIN SELECT RAISE(ABORT, 'test apply failure'); END;").unwrap();
    }

    fn recover_apply(&self) {
        self.raw.execute_batch("DROP TRIGGER fail_apply").unwrap();
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

// Keep paused Tokio time under the test's control while waiting on blocking store work.
async fn wait<T>(signal: impl Future<Output = T>) -> T {
    tokio::pin!(signal);
    let limit = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        tokio::select! {
            biased;
            value = &mut signal => return value,
            _ = tokio::task::yield_now() => assert!(std::time::Instant::now() < limit, "expected progress"),
        }
    }
}

async fn until(mut condition: impl FnMut() -> bool) {
    wait(async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

async fn tick() {
    tokio::time::advance(Duration::from_secs(1)).await;
}

#[tokio::test(start_paused = true)]
async fn member_rows_and_aad_fail_closed_while_valid_siblings_apply() {
    let mut rig = Rig::new(true);
    rig.add_handmade("oauth:handmade");
    rig.start();
    rig.opened(1).await;
    rig.put_seen(&login(1, vec![row(ID, 1), row(OTHER, 1)]))
        .await;
    let before = rig.row(ID).unwrap();
    let audit = rig.store.read_audit(None).unwrap();

    let end = json!({"kind":"ended"});
    for field in 0..6 {
        let mut wrong = aad(2);
        match field {
            0 => wrong.home = MEMBER.into(),
            1 => wrong.member = HOME.into(),
            2 => wrong.home_box = SECOND_BOX.into(),
            3 => wrong.member_box = SECOND_BOX.into(),
            4 => wrong.sender_key_id = key_id_for_public(&public(99)),
            _ => wrong.recipient_key_id = key_id_for_public(&public(99)),
        }
        rig.put_seen(&sealed(&wrong, SENDER, RECIPIENT, &end)).await;
    }
    rig.put_seen(&sealed(&aad(2), 99, RECIPIENT, &end)).await;
    rig.put_seen(&sealed(&aad(2), SENDER, 99, &end)).await;
    rig.put_seen(b"unopenable").await;
    rig.put_seen(&sealed(
        &aad(2),
        SENDER,
        RECIPIENT,
        &json!({"kind":"ended", "logins":[]}),
    ))
    .await;
    rig.put_seen(&login(2, vec![row(ID, 2), row(ID, 2)])).await;
    let mut corrupt = row(ID, 2);
    corrupt["state"] = json!("corrupt");
    rig.put_seen(&login(2, vec![corrupt, row(OTHER, 2)])).await;
    let revision = rig.hub.delete(SHARED_LOGINS, LOGIN_KEY).unwrap();
    rig.seen(revision).await;
    let revision = rig.hub.purge(SHARED_LOGINS, LOGIN_KEY).unwrap();
    rig.seen(revision).await;
    assert_eq!(rig.generation(), Some(1));
    assert_eq!(rig.store.read_audit(None).unwrap(), audit);
    assert_eq!(rig.row(ID), Some(before.clone()));

    let mut invalid = row(ID, 2);
    invalid["condition"] = json!({"reason":"reauth", "since_ms":"not-an-integer"});
    let mut sibling = row(OTHER, 2);
    sibling["identity"]["org_name"] = json!("changed");
    sibling["ignored_row_extension"] = json!(true);
    rig.put_seen(&login(2, vec![invalid, sibling])).await;
    assert_eq!(rig.generation(), Some(2));
    assert_eq!(rig.row(ID), Some(before));
    assert_eq!(
        rig.row(OTHER).unwrap().identity.org_name.as_deref(),
        Some("changed")
    );
    rig.put_seen(&ended(i64::MAX)).await;
    assert_eq!(rig.generation(), Some(i64::MAX));
    assert!(rig.row(ID).is_none() && rig.row(OTHER).is_none());
    assert_eq!(
        rig.row("oauth:handmade").unwrap().source,
        RemoteRecordSource::Operator
    );
}

#[tokio::test(start_paused = true)]
async fn greatest_pending_retries_with_no_further_delivery_even_across_sharing_toggle() {
    for toggle in [false, true] {
        let mut rig = Rig::new(true);
        rig.start();
        rig.opened(1).await;
        rig.put_seen(&login(5, vec![row(ID, 5)])).await;
        let audit = rig.store.read_audit(None).unwrap();
        rig.fail_apply();
        rig.put_seen(&ended(7)).await;
        assert_eq!(rig.generation(), Some(5));
        assert_eq!(rig.store.read_audit(None).unwrap(), audit);
        assert!(rig.row(ID).is_some());

        if toggle {
            rig.sharing(false);
        }
        rig.put_seen(&login(6, vec![row(OTHER, 6)])).await;
        assert_eq!(rig.generation(), Some(5));
        assert!(rig.row(OTHER).is_none());
        rig.recover_apply();
        if toggle {
            tick().await;
            assert_eq!(rig.generation(), Some(5));
            assert!(rig.state().unwrap().reapply);
            rig.sharing(true);
        } else {
            tick().await;
        }
        until(|| rig.generation() == Some(7)).await;
        assert!(rig.row(ID).is_none());
        assert!(rig.row(OTHER).is_none());
        assert!(!rig.state().unwrap().reapply);
        assert_eq!(rig.watch_opens(), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn reset_drops_pending_ended_and_keeps_watching_relisted_values() {
    let mut rig = Rig::new(true);
    let five = login(5, vec![row(ID, 5)]);
    rig.start();
    rig.opened(1).await;
    rig.put_seen(&five).await;
    rig.fail_apply();
    rig.put_seen(&ended(8)).await;
    assert_eq!(rig.generation(), Some(5));
    let before = rig.store.read_audit(None).unwrap();
    let old = rig.row(ID).unwrap();

    rig.hub.reset_bucket(SHARED_LOGINS, &[(LOGIN_KEY, &five)]);
    rig.reset_seen().await;
    rig.seen(1).await;
    rig.recover_apply();
    tick().await;
    // A subsequent lower delivery is still ignored; the earlier end must not retry.
    rig.put_seen(&ended(4)).await;
    assert_eq!(rig.generation(), Some(5));
    assert_eq!(rig.row(ID), Some(old));
    assert_eq!(rig.store.read_audit(None).unwrap(), before);
    assert_eq!(rig.watch_opens(), 1);

    let greater = login(7, vec![row(OTHER, 7)]);
    rig.hub
        .reset_bucket(SHARED_LOGINS, &[(LOGIN_KEY, &greater)]);
    rig.reset_seen().await;
    rig.seen(1).await;
    assert_eq!(rig.generation(), Some(7));
    assert!(rig.row(ID).is_none());
    assert_eq!(rig.row(OTHER).unwrap().last_home_version, 7);
    assert_eq!(rig.watch_opens(), 1);
}

struct ReadGatedHub {
    client: StandInClient,
    allowed: watch::Receiver<bool>,
    requests: mpsc::UnboundedSender<()>,
}

#[async_trait]
impl Hub for ReadGatedHub {
    fn box_id(&self) -> &str {
        self.client.box_id()
    }
    fn connection_changes(&self) -> watch::Receiver<u64> {
        self.client.connection_changes()
    }
    async fn watch_bucket(&self, bucket: &str) -> Result<Box<dyn HubWatch>, HubError> {
        self.client.watch_bucket(bucket).await
    }
    async fn entry(&self, bucket: &str, key: &str) -> Result<Option<HubEntry>, HubError> {
        let _ = self.requests.send(());
        drop(
            self.allowed
                .clone()
                .wait_for(|allow| *allow)
                .await
                .map_err(|_| HubError::Unavailable)?,
        );
        self.client.entry(bucket, key).await
    }
    async fn create(&self, _: &str, _: &str, _: Vec<u8>) -> Result<u64, HubError> {
        panic!("member never writes to hub")
    }
    async fn update(&self, _: &str, _: &str, _: Vec<u8>, _: u64) -> Result<u64, HubError> {
        panic!("member never writes to hub")
    }
}

#[tokio::test(start_paused = true)]
async fn restart_restores_only_from_entry_after_late_binding_and_failed_transaction() {
    let mut rig = Rig::new(true);
    let saved = login(1, vec![row(ID, 1)]);
    rig.start();
    rig.opened(1).await;
    rig.put_seen(&saved).await;
    rig.stop().await;
    rig.sharing(false);
    rig.sharing(true);
    assert!(rig.state().unwrap().reapply);
    assert!(rig.row(ID).is_none());
    rig.bindings.send_replace(None);

    let (allowed, gate) = watch::channel(false);
    let (requests, mut reads) = mpsc::unbounded_channel();
    let hub = Arc::new(ReadGatedHub {
        client: rig.hub.client(MEMBER_BOX),
        allowed: gate,
        requests,
    });
    rig.start_on(hub, None);
    rig.seen(1).await;
    assert!(rig.row(ID).is_none());
    rig.views(Some(PAIR), Some((PAIR, HOME_BOX, SENDER)));
    wait(reads.recv()).await.unwrap();

    rig.hub.reset_bucket(SHARED_LOGINS, &[(LOGIN_KEY, &saved)]);
    rig.reset_seen().await;
    rig.seen(1).await;
    assert!(
        rig.row(ID).is_none(),
        "the relist cannot restore an equal generation"
    );
    assert!(rig.state().unwrap().reapply);
    let audit = rig.store.read_audit(None).unwrap();
    rig.fail_apply();
    allowed.send_replace(true);
    wait(rig.attempted.notified()).await;
    assert!(rig.state().unwrap().reapply);
    assert!(rig.row(ID).is_none());
    assert_eq!(rig.store.read_audit(None).unwrap(), audit);

    rig.recover_apply();
    tick().await;
    until(|| rig.row(ID).is_some()).await;
    assert!(!rig.state().unwrap().reapply);
    assert_eq!(rig.generation(), Some(1));
    assert_eq!(
        rig.watch_opens(),
        2,
        "binding and reset keep the second watch open"
    );
}

#[tokio::test(start_paused = true)]
async fn running_member_restores_equal_generation_when_sharing_is_reenabled() {
    let mut rig = Rig::new(true);
    rig.start();
    rig.opened(1).await;
    rig.put_seen(&login(5, vec![row(ID, 5)])).await;
    rig.sharing(false);
    assert!(rig.row(ID).is_none());
    assert!(rig.state().unwrap().reapply);
    rig.sharing(true);
    until(|| rig.row(ID).is_some()).await;
    assert_eq!(rig.generation(), Some(5));
    assert!(!rig.state().unwrap().reapply);
    assert_eq!(rig.watch_opens(), 1);
}

#[tokio::test(start_paused = true)]
async fn local_collision_release_only_inserts_skipped_ids_without_a_new_put() {
    for (stop_before_release, stop_after_release, offline) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let mut rig = Rig::new(true);
        rig.add_handmade(OTHER);
        rig.start();
        rig.opened(1).await;
        rig.put_seen(&login(1, vec![row(ID, 1), row(OTHER, 1)]))
            .await;
        assert_eq!(rig.state().unwrap().skipped_ids, [OTHER]);

        let original = rig.row(ID).unwrap();
        rig.store
            .remote_record_apply_home_state(
                ID,
                &original.incarnation,
                RemoteHomeState::NeedsReauth,
                "needs_reauth",
            )
            .unwrap();
        let local_outcome = rig.row(ID).unwrap();
        if stop_before_release {
            rig.stop().await;
        }
        if offline {
            rig.hub.set_online(false);
        }
        rig.store.remote_remove_audited(OTHER).unwrap();
        assert!(rig.row(OTHER).is_none());
        // The single-threaded runtime has not yet handed the write signal to the watcher.
        if stop_after_release {
            rig.stop().await;
        }
        if stop_before_release || stop_after_release {
            rig.start();
        }
        if offline {
            tick().await;
            assert!(rig.row(OTHER).is_none());
            rig.hub.set_online(true);
            advance_until(|| rig.row(OTHER).is_some()).await;
        } else {
            until(|| rig.row(OTHER).is_some()).await;
        }
        assert_eq!(
            rig.row(OTHER).unwrap().source,
            RemoteRecordSource::HomeWatch
        );
        assert_eq!(
            rig.row(ID),
            Some(local_outcome),
            "collision fill must preserve token-side metadata"
        );
        assert!(rig.state().unwrap().skipped_ids.is_empty());
        assert_eq!(rig.generation(), Some(1));
        assert_eq!(
            rig.hub
                .client(MEMBER_BOX)
                .entry(SHARED_LOGINS, LOGIN_KEY)
                .await
                .unwrap()
                .unwrap()
                .revision,
            1
        );
    }
}

async fn advance_until(mut condition: impl FnMut() -> bool) {
    wait(async {
        while !condition() {
            tick().await;
            tokio::task::yield_now().await;
        }
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn discovery_reads_current_value_on_original_watch_and_requires_both_views() {
    let mut rig = Rig::new(false);
    let value = login(1, vec![row(ID, 1)]);
    rig.start();
    rig.opened(1).await;
    rig.put_seen(&value).await;
    assert!(rig.state().is_none());
    for (pair, peer) in [
        (None, Some((PAIR, HOME_BOX, SENDER))),
        (Some(PAIR), None),
        (Some(PAIR), Some((REPAIR, HOME_BOX, SENDER))),
    ] {
        rig.views(pair, peer);
        rig.put_seen(&value).await;
        assert!(rig.state().is_none());
        assert!(rig.row(ID).is_none());
    }
    rig.views(Some(PAIR), Some((PAIR, HOME_BOX, SENDER)));
    until(|| rig.row(ID).is_some()).await;
    assert_eq!(rig.generation(), Some(1));
    assert_eq!(rig.watch_opens(), 1);
}

#[tokio::test(start_paused = true)]
async fn applying_waits_for_current_binding_and_serializes_with_pairing_removal() {
    for unpair in [false, true] {
        let mut rig = Rig::new(true);
        let armed = Arc::new(AtomicBool::new(false));
        let entered = Arc::new(Notify::new());
        let proceed = Arc::new(Notify::new());
        let gate = {
            let (armed, entered, proceed) = (armed.clone(), entered.clone(), proceed.clone());
            Arc::new(move || {
                let (armed, entered, proceed) = (armed.clone(), entered.clone(), proceed.clone());
                Box::pin(async move {
                    if armed.swap(false, Ordering::SeqCst) {
                        entered.notify_one();
                        proceed.notified().await;
                    }
                }) as std::pin::Pin<Box<dyn Future<Output = ()> + Send>>
            })
        };
        rig.start_on(Arc::new(rig.hub.client(MEMBER_BOX)), Some(gate));
        rig.opened(1).await;
        rig.put_seen(&login(1, vec![row(ID, 1)])).await;

        armed.store(true, Ordering::SeqCst);
        let waiting = rig.put(&login(2, vec![row(OTHER, 2)]));
        wait(entered.notified()).await;
        if unpair {
            // The pairing snapshot shows the unpair before the peer-key view does.
            rig.views(None, Some((PAIR, HOME_BOX, SENDER)));
        } else {
            rig.views(Some(PAIR), Some((PAIR, SECOND_BOX, SENDER)));
        }
        assert!(
            rig.row(ID).is_some(),
            "removal does not start during an apply"
        );
        proceed.notify_one();
        rig.seen(waiting).await;
        assert_eq!(rig.generation(), Some(1));
        assert!(rig.row(OTHER).is_none());
        if unpair {
            until(|| rig.row(ID).is_none()).await;
            assert!(rig.state().unwrap().pairing_id.is_none());
        } else {
            assert!(rig.row(ID).is_some());
            let mut moved = aad(3);
            moved.home_box = SECOND_BOX.into();
            let revision = rig.put_at(
                SECOND_KEY,
                &sealed(&moved, SENDER, RECIPIENT, &snapshot(vec![row(OTHER, 3)])),
            );
            rig.seen(revision).await;
            assert_eq!(rig.generation(), Some(3));
            assert!(rig.row(ID).is_none());
            assert!(rig.row(OTHER).is_some());
        }
    }
}

#[tokio::test(start_paused = true)]
async fn offline_repair_preserves_high_water_even_for_empty_or_disabled_pairings() {
    for (had_rows, sharing_off) in [(true, false), (false, false), (true, true)] {
        let mut rig = Rig::new(true);
        rig.start();
        rig.opened(1).await;
        let old = login(5, if had_rows { vec![row(ID, 5)] } else { vec![] });
        rig.put_seen(&old).await;
        assert_eq!(rig.generation(), Some(5));
        rig.stop().await;
        if sharing_off {
            rig.sharing(false);
        }
        rig.views(Some(REPAIR), Some((REPAIR, HOME_BOX, SENDER)));
        rig.start();
        rig.seen(1).await;
        until(|| rig.state().unwrap().pairing_id.is_none()).await;
        assert!(rig.row(ID).is_none());
        assert!(!rig.state().unwrap().reapply);
        if sharing_off {
            rig.sharing(true);
        }

        rig.put_seen(&login(4, vec![row(ID, 4)])).await;
        rig.put_seen(&ended(5)).await;
        assert_eq!(rig.generation(), Some(5));
        assert!(rig.row(ID).is_none());
        rig.put_seen(&login(6, vec![row(OTHER, 6)])).await;
        assert_eq!(rig.generation(), Some(6));
        assert_eq!(
            rig.row(OTHER).unwrap().home_pairing_id.as_deref(),
            Some(REPAIR)
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_pending_value_from_the_replaced_home_key_cannot_apply() {
    let mut rig = Rig::new(true);
    rig.start();
    rig.opened(1).await;
    rig.put_seen(&login(5, vec![row(ID, 5)])).await;
    rig.fail_apply();
    rig.put_seen(&ended(6)).await;
    rig.views(Some(PAIR), Some((PAIR, HOME_BOX, 98)));
    rig.recover_apply();
    tick().await;
    rig.put_seen(&ended(6)).await;
    assert_eq!(rig.generation(), Some(5));
    assert!(rig.row(ID).is_some());
    let mut rotated = aad(7);
    rotated.sender_key_id = key_id_for_public(&public(98));
    rig.put_seen(&sealed(
        &rotated,
        98,
        RECIPIENT,
        &snapshot(vec![row(OTHER, 7)]),
    ))
    .await;
    assert_eq!(rig.generation(), Some(7));
    assert!(rig.row(OTHER).is_some());
    assert_eq!(rig.watch_opens(), 1);
}

#[tokio::test(start_paused = true)]
async fn watch_recovers_missed_writes_and_true_end_without_a_connection_tick() {
    let mut rig = Rig::new(true);
    // A still-running startup point read must not satisfy the watch recovery test.
    let (_hold, allowed) = watch::channel(false);
    let (requests, _reads) = mpsc::unbounded_channel();
    rig.start_on(
        Arc::new(ReadGatedHub {
            client: rig.hub.client(MEMBER_BOX),
            allowed,
            requests,
        }),
        None,
    );
    rig.opened(1).await;
    rig.put_seen(&login(1, vec![row(ID, 1)])).await;
    rig.hub.set_online(false);
    assert!(rig.row(ID).is_some());
    rig.hub.set_online(true);
    rig.put(&login(2, vec![row(OTHER, 2)]));
    advance_until(|| rig.generation() == Some(2)).await;
    assert!(rig.row(ID).is_none() && rig.row(OTHER).is_some());
    assert_eq!(rig.watch_opens(), 2);

    rig.hub.terminate_watches(SHARED_LOGINS);
    rig.put(&login(3, vec![row(ID, 3)]));
    advance_until(|| rig.generation() == Some(3)).await;
    assert!(rig.row(ID).is_some() && rig.row(OTHER).is_none());
    assert_eq!(rig.watch_opens(), 3);
}

#[tokio::test(start_paused = true)]
async fn replay_and_no_diff_home_restart_preserve_rows_and_audit_but_advance_generation() {
    use crate::federation::hub_home_writer;
    use credentials_core::{
        federation::{MemberGrantOperation, MemberGrantSelector},
        oauth::OAuthCredential,
    };

    let mut rig = Rig::new(true);
    let (_root, home, _) = open_store();
    home.create(VAULT_TRANSFER_ID, &transfer_key(SENDER))
        .unwrap();
    home.set_federation_self_member_audited(HOME, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    home.set_federation_member_mapping_audited(true, AuditCtx::admin(AuditOp::FederationGateSet))
        .unwrap();
    home.set_login_sharing_audited(true, "test").unwrap();
    let mut oauth = VaultRecord::new_oauth(
        "test",
        "anthropic",
        OAuthCredential {
            access_token: "test-access".to_string().into(),
            refresh_token: "test-refresh".to_string().into(),
            expires_at_ms: Some(0),
            token_url: String::new(),
            client_id: None,
            client_secret: None,
            scopes: vec![],
        },
        vec![],
    );
    oauth.refresh_adapter = Some("anthropic".into());
    home.create(ID, &oauth).unwrap();
    home.create_member_grant_audited(
        MEMBER,
        MemberGrantOperation::RemoteRead,
        &MemberGrantSelector::Exact(ID.into()),
        PAIR,
    )
    .unwrap();
    let pairs = decode_snapshot(&json!({"self":{"static_public_key_hex":"00".repeat(32)}, "devices":[{
        "fingerprint": MEMBER.strip_prefix("fed-computer:").unwrap(), "pairing_id":PAIR, "class":"computer", "shares":[]
    }]})).unwrap();
    let peers = json!({"peers":[{
        "fingerprint":MEMBER.strip_prefix("fed-computer:").unwrap(), "pairing_id":PAIR, "class":"computer", "machine_id":MEMBER_BOX,
        "key_record":{"keys":{"vault_transfer_x25519":{"pub":public(RECIPIENT).iter().map(|b| format!("{b:02x}")).collect::<String>()}}}
    }]});
    let bindings = watch::channel(HubBindings::join(HOME_BOX, &pairs, &peers)).0;
    let hub = rig.hub.clone();
    let home_task = tokio::spawn(hub_home_writer::run(
        home.clone(),
        Arc::new(hub.client(HOME_BOX)),
        bindings.subscribe(),
    ));
    rig.start();
    until(|| rig.generation() == Some(1)).await;
    let before = rig.row(ID).unwrap();
    let audit = rig.store.read_audit(None).unwrap();
    rig.stop().await;
    rig.start();
    rig.seen(1).await;
    assert_eq!(rig.generation(), Some(1));
    assert_eq!(rig.row(ID), Some(before.clone()));
    assert_eq!(rig.store.read_audit(None).unwrap(), audit);

    home_task.abort();
    assert!(wait(home_task).await.unwrap_err().is_cancelled());
    let home_task = tokio::spawn(hub_home_writer::run(
        home,
        Arc::new(hub.client(HOME_BOX)),
        bindings.subscribe(),
    ));
    until(|| rig.generation() == Some(2)).await;
    assert_eq!(rig.row(ID), Some(before.clone()));
    assert_eq!(rig.store.read_audit(None).unwrap(), audit);

    home_task.abort();
    assert!(wait(home_task).await.unwrap_err().is_cancelled());
    rig.stop().await;
    let old = rig.put(&login(1, vec![row(OTHER, 1)]));
    rig.start();
    rig.seen(old).await;
    assert_eq!(rig.generation(), Some(2));
    assert_eq!(rig.row(ID), Some(before));
    assert!(rig.row(OTHER).is_none());
    assert_eq!(rig.store.read_audit(None).unwrap(), audit);
}
