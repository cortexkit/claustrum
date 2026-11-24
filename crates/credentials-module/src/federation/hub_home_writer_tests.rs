use super::*;
use crate::federation::{
    hub::{stand_in::StandIn, HubWatch},
    sharing::decode_snapshot,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::{
    audit::{AuditCtx, AuditOp},
    federation::{MemberGrantSelector, VAULT_TRANSFER_ID},
    kem,
    key::MasterKey,
    oauth::OAuthCredential,
    record::{CredentialKind, RecordIdentity, VaultRecord},
    test_support::TestTempDir,
};
use serde_json::Value;
use std::{
    future::Future,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{sync::Notify, task::JoinHandle};

const HOME_BOX: &str = "00000000000000000000000000000001";
const MEMBER_BOX: &str = "00000000000000000000000000000002";
const HOME: &str = "fed-computer:00000000000000000000000000000007";
const FP: &str = "00000000000000000000000000000008";
const MEMBER: &str = "fed-computer:00000000000000000000000000000008";
const NEW_FP: &str = "00000000000000000000000000000009";
const NEW_MEMBER: &str = "fed-computer:00000000000000000000000000000009";
const ID: &str = "oauth:hub-test";
const PAIR: &str = "pair:1";
const NEW_PAIR: &str = "pair:2";
const HOME_SCALAR: u8 = 12;
const MEMBER_SCALAR: u8 = 13;

fn pem(scalar: u8) -> String {
    kem::pem_from_scalar(&[scalar; 32])
}
fn key(scalar: u8) -> Vec<u8> {
    kem::public_half(&pem(scalar)).unwrap().0
}
fn transfer_record(scalar: u8) -> VaultRecord {
    VaultRecord::new_static(
        CredentialKind::KemKey,
        "test",
        pem(scalar).into_bytes(),
        None,
    )
}

fn joined(paired: &[(&str, &str)], peers: &[(&str, &str, u8)]) -> HubBindings {
    let paired = decode_snapshot(&json!({
        "self": {"static_public_key_hex": "00".repeat(32)},
        "devices": paired.iter().map(|(fp, pairing)| json!({
            "fingerprint": fp, "pairing_id": pairing, "class":"computer", "shares": [{"share":"vault", "enabled":false}]
        })).collect::<Vec<_>>(),
    })).unwrap();
    let peer_keys = json!({"peers": peers.iter().map(|(fp, pairing, scalar)| json!({
        "fingerprint": fp, "pairing_id": pairing, "class":"computer", "machine_id": MEMBER_BOX,
        "key_record": { "keys": {"vault_transfer_x25519": {"pub": key(*scalar).iter().map(|b| format!("{b:02x}")).collect::<String>()}}}
    })).collect::<Vec<_>>()});
    HubBindings::join(HOME_BOX, &paired, &peer_keys).unwrap()
}

fn paired(pairing: &str, scalar: u8) -> HubBindings {
    joined(&[(FP, pairing)], &[(FP, pairing, scalar)])
}

fn open(entry: &HubEntry, member_scalar: u8, home_public: &[u8]) -> (LoginAad, Value, usize) {
    assert_eq!(entry.operation, HubOperation::Put);
    let envelope: LoginEnvelope = serde_json::from_slice(&entry.value).unwrap();
    assert_eq!(envelope.v, 1);
    let aad: LoginAad = serde_json::from_str(&envelope.aad).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&envelope.aad)
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        7,
    );
    assert_eq!(aad.home, HOME);
    assert_eq!(aad.home_box, HOME_BOX);
    assert_eq!(aad.member_box, MEMBER_BOX);
    assert_eq!(aad.sender_key_id, key_id_for_public(home_public));
    assert_eq!(aad.recipient_key_id, key_id_for_public(&key(member_scalar)));
    let bytes = kem::open_hub_logins(
        &pem(member_scalar),
        home_public,
        &STANDARD.decode(envelope.enc_b64).unwrap(),
        &STANDARD.decode(envelope.ciphertext_b64).unwrap(),
        envelope.aad.as_bytes(),
    )
    .unwrap();
    (aad, serde_json::from_slice(&bytes).unwrap(), bytes.len())
}

fn login() -> VaultRecord {
    let mut row = VaultRecord::new_oauth(
        "test",
        "anthropic",
        OAuthCredential {
            access_token: "test-access".to_owned().into(),
            refresh_token: "test-refresh".to_owned().into(),
            expires_at_ms: Some(0),
            token_url: String::new(),
            client_id: None,
            client_secret: None,
            scopes: vec![],
        },
        Vec::new(),
    )
    .with_identity(RecordIdentity {
        org_name: Some("original".into()),
        ..RecordIdentity::default()
    });
    row.refresh_adapter = Some("anthropic".into());
    row
}

struct Rig {
    store: Arc<EncryptedStore>,
    raw: rusqlite::Connection,
    hub: StandIn,
    client: super::super::hub::stand_in::StandInClient,
    binding: watch::Sender<Option<HubBindings>>,
    decided: Arc<Notify>,
    task: Option<JoinHandle<()>>,
    _root: TestTempDir,
}

impl Rig {
    fn new() -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = TestTempDir::new(format!(
            "hub-home-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let path = root.join("store.db");
        let sqlite = open_sqlite(&StorageDescriptor {
            module_id: "claustrum".into(),
            storage_namespace: "vault".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        })
        .unwrap();
        EncryptedStore::migrate(&sqlite).unwrap();
        let store =
            Arc::new(EncryptedStore::open(sqlite, MasterKey::from_bytes([24; 32])).unwrap());
        let hub = StandIn::new();
        Self {
            store,
            raw: rusqlite::Connection::open(path).unwrap(),
            client: hub.client(HOME_BOX),
            hub,
            binding: watch::channel(None).0,
            decided: Arc::new(Notify::new()),
            task: None,
            _root: root,
        }
    }

    fn setup(&self) {
        self.store
            .create(VAULT_TRANSFER_ID, &transfer_record(HOME_SCALAR))
            .unwrap();
        self.set_self();
        self.store
            .set_federation_member_mapping_audited(
                true,
                AuditCtx::admin(AuditOp::FederationGateSet),
            )
            .unwrap();
        self.store.set_login_sharing_audited(true, "test").unwrap();
        self.store.create(ID, &login()).unwrap();
        self.grant(MEMBER, PAIR, ID);
    }

    fn set_self(&self) {
        self.store
            .set_federation_self_member_audited(HOME, AuditCtx::admin(AuditOp::FederationSelfSet))
            .unwrap();
    }

    fn grant(&self, member: &str, pairing: &str, id: &str) {
        self.store
            .create_member_grant_audited(
                member,
                MemberGrantOperation::RemoteRead,
                &MemberGrantSelector::Exact(id.into()),
                pairing,
            )
            .unwrap();
    }

    fn revoke(&self) {
        self.store
            .revoke_member_grant_audited(
                MEMBER,
                MemberGrantOperation::RemoteRead,
                &MemberGrantSelector::Exact(ID.into()),
            )
            .unwrap();
    }

    fn bind(&self, binding: Option<HubBindings>) {
        self.binding.send_replace(binding);
    }

    fn target(&self, member: &str) -> Option<HubLoginTarget> {
        self.store
            .list_hub_login_targets()
            .unwrap()
            .into_iter()
            .find(|row| row.member_id == member)
    }

    fn start(&mut self) {
        self.start_with(TestHooks::default());
    }

    fn start_with(&mut self, hooks: TestHooks) {
        self.start_on(Arc::new(self.client.clone()), hooks);
    }

    fn start_on(&mut self, hub: Arc<dyn Hub>, mut hooks: TestHooks) {
        assert!(self.task.is_none());
        hooks.decided = Some(Arc::clone(&self.decided));
        self.task = Some(tokio::spawn(run_inner(
            Arc::clone(&self.store),
            hub,
            self.binding.subscribe(),
            hooks,
        )));
    }

    async fn stop(&mut self) {
        let task = self.task.take().unwrap();
        task.abort();
        assert!(wait(task).await.unwrap_err().is_cancelled());
    }

    async fn entry(&self) -> Option<HubEntry> {
        self.client.entry(SHARED_LOGINS, &hub_key()).await.unwrap()
    }

    async fn watch(&self) -> Box<dyn HubWatch> {
        self.hub
            .client(MEMBER_BOX)
            .watch_bucket(SHARED_LOGINS)
            .await
            .unwrap()
    }

    fn overwrite(&self, record: &VaultRecord) {
        self.store
            .overwrite_unconditional_audited(ID, record, AuditCtx::admin(AuditOp::Put))
            .unwrap();
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn hub_key() -> String {
    format!("{HOME_BOX}.{MEMBER_BOX}")
}

async fn wait<T>(signal: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), signal)
        .await
        .expect("expected progress")
}

async fn until(mut ready: impl FnMut() -> bool) {
    wait(async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await;
}

async fn put(watch: &mut dyn HubWatch) -> HubEntry {
    loop {
        if let HubEvent::Entry(entry) = wait(watch.next()).await.unwrap().unwrap() {
            if entry.operation == HubOperation::Put {
                return entry;
            }
        }
    }
}

#[tokio::test]
async fn operator_grant_with_vault_share_off_seals_and_refresh_does_not_write() {
    let mut rig = Rig::new();
    rig.setup();
    rig.bind(Some(paired(PAIR, MEMBER_SCALAR)));
    let mut observer = rig.watch().await;
    rig.start();
    let initial = put(observer.as_mut()).await;
    let (aad, contents, _) = open(&initial, MEMBER_SCALAR, &key(HOME_SCALAR));
    assert_eq!(aad.member, MEMBER);
    assert_eq!(aad.generation.get(), 1);
    assert_eq!(contents["kind"], "snapshot");
    assert_eq!(contents["logins"][0]["credential_id"], ID);
    assert_eq!(contents["logins"][0]["identity"]["org_name"], "original");

    let mut row = login();
    row.oauth.as_mut().unwrap().access_token = "refreshed".to_owned().into();
    rig.overwrite(&row);
    row.identity.org_name = Some("changed".into());
    rig.overwrite(&row);
    let updated = put(observer.as_mut()).await;
    let (aad, contents, _) = open(&updated, MEMBER_SCALAR, &key(HOME_SCALAR));
    assert_eq!(aad.generation.get(), 2);
    assert_eq!(updated.revision, initial.revision + 1);
    assert_eq!(contents["logins"][0]["identity"]["org_name"], "changed");
    // The refresh alone must not write even after its projection was processed.
    until(|| rig.target(MEMBER).is_some_and(|row| row.delivered)).await;
    let _ = tokio::time::timeout(Duration::ZERO, rig.decided.notified()).await;
    row.oauth.as_mut().unwrap().access_token = "refreshed-again".to_owned().into();
    rig.overwrite(&row);
    wait(rig.decided.notified()).await;
    assert_eq!(rig.target(MEMBER).unwrap().generation.get(), 2);
    assert_eq!(rig.entry().await.unwrap(), updated);
}

#[tokio::test]
async fn oversize_list_leaves_old_value_but_return_to_sealed_rows_clears_stale() {
    let mut rig = Rig::new();
    rig.setup();
    let mut row = login();
    row.identity.org_name = Some("\"".repeat(256));
    for (category, count) in [("llm-provider", 120), ("overflow", 190)] {
        for n in 0..count {
            let id = format!("oauth:{category}-{n}");
            rig.store.create(&id, &row).unwrap();
            rig.store
                .set_categories_audited(
                    &id,
                    credentials_core::store::SetCategoryMode::Set,
                    &[category.into()],
                    AuditCtx::admin(AuditOp::SetCategory),
                )
                .unwrap();
        }
    }
    let grant_category = |category: &str| MemberGrantSelector::Category(category.into());
    rig.store
        .create_member_grant_audited(
            MEMBER,
            MemberGrantOperation::RemoteRead,
            &grant_category("llm-provider"),
            PAIR,
        )
        .unwrap();
    rig.bind(Some(paired(PAIR, MEMBER_SCALAR)));
    let mut observer = rig.watch().await;
    let refusals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    rig.start_with(TestHooks {
        refusals: Some(Arc::clone(&refusals)),
        ..TestHooks::default()
    });
    let initial = put(observer.as_mut()).await;
    let (_, _, size) = open(&initial, MEMBER_SCALAR, &key(HOME_SCALAR));
    assert!(size > 65_536);
    rig.store
        .create_member_grant_audited(
            MEMBER,
            MemberGrantOperation::RemoteRead,
            &grant_category("overflow"),
            PAIR,
        )
        .unwrap();
    until(|| rig.target(MEMBER).is_some_and(|target| target.stale)).await;
    assert_eq!(rig.entry().await.unwrap(), initial);
    // Unrelated writes repeat the same refusal; it is logged once.
    for n in 0..3 {
        let _ = tokio::time::timeout(Duration::ZERO, rig.decided.notified()).await;
        rig.store
            .create(&format!("oauth:unrelated-{n}"), &login())
            .unwrap();
        wait(rig.decided.notified()).await;
    }
    assert_eq!(refusals.load(std::sync::atomic::Ordering::SeqCst), 1);
    rig.store
        .revoke_member_grant_audited(
            MEMBER,
            MemberGrantOperation::RemoteRead,
            &grant_category("overflow"),
        )
        .unwrap();
    let repaired = put(observer.as_mut()).await;
    let (aad, _, _) = open(&repaired, MEMBER_SCALAR, &key(HOME_SCALAR));
    assert_eq!(aad.generation.get(), 2);
    assert!(!rig.target(MEMBER).unwrap().stale);
}

#[tokio::test]
async fn startup_unknown_neither_reseals_nor_repairs_until_both_views_agree() {
    let mut rig = Rig::new();
    rig.setup();
    rig.bind(Some(paired(PAIR, MEMBER_SCALAR)));
    let mut observer = rig.watch().await;
    rig.start();
    let first = put(observer.as_mut()).await;
    rig.stop().await;
    rig.bind(None);
    rig.hub.delete(SHARED_LOGINS, &hub_key()).unwrap();
    let _ = tokio::time::timeout(Duration::ZERO, rig.decided.notified()).await;
    rig.start();
    wait(rig.decided.notified()).await;
    assert_eq!(rig.entry().await.unwrap().operation, HubOperation::Delete);
    assert_eq!(rig.target(MEMBER).unwrap().generation.get(), 1);

    for view in [
        joined(&[(FP, PAIR)], &[]),
        joined(&[], &[(FP, PAIR, MEMBER_SCALAR)]),
        joined(&[(FP, PAIR)], &[(FP, NEW_PAIR, MEMBER_SCALAR)]),
    ] {
        rig.bind(Some(view));
        wait(rig.decided.notified()).await;
        assert_eq!(rig.target(MEMBER).unwrap().generation.get(), 1);
        assert_eq!(rig.entry().await.unwrap().operation, HubOperation::Delete);
    }
    rig.bind(Some(paired(PAIR, MEMBER_SCALAR)));
    let next = put(observer.as_mut()).await;
    let (aad, body, _) = open(&next, MEMBER_SCALAR, &key(HOME_SCALAR));
    assert_eq!(aad.generation.get(), 2);
    assert_eq!(body["kind"], "snapshot");
    assert_ne!(next.value, first.value);
}

#[tokio::test]
async fn missing_self_or_active_home_key_never_creates_a_key_or_seals() {
    let mut rig = Rig::new();
    rig.bind(Some(paired(PAIR, MEMBER_SCALAR)));
    rig.start();
    wait(rig.decided.notified()).await;
    assert!(matches!(
        rig.store.get(VAULT_TRANSFER_ID),
        Err(StoreOpError::NotFound)
    ));
    assert!(rig.target(MEMBER).is_none());
    rig.store
        .create(VAULT_TRANSFER_ID, &transfer_record(HOME_SCALAR))
        .unwrap();
    wait(rig.decided.notified()).await;
    assert!(
        rig.target(MEMBER).is_none(),
        "having a transfer key does not supply a self id"
    );
    rig.raw
        .execute(
            "UPDATE credentials SET state = 'needs_reauth' WHERE credential_id = ?1",
            [VAULT_TRANSFER_ID],
        )
        .unwrap();
    rig.set_self();
    wait(rig.decided.notified()).await;
    assert!(rig.target(MEMBER).is_none());
    assert!(rig.entry().await.is_none());
    assert!(matches!(
        rig.store.get(VAULT_TRANSFER_ID),
        Err(StoreOpError::NeedsReauth)
    ));
}

#[tokio::test]
async fn confirmed_repair_uses_the_current_pairing_grant_and_key() {
    for grant_before_binding in [false, true] {
        let mut rig = Rig::new();
        rig.setup();
        rig.bind(Some(paired(PAIR, MEMBER_SCALAR)));
        let mut observer = rig.watch().await;
        rig.start();
        put(observer.as_mut()).await;
        let new_scalar = MEMBER_SCALAR + 3;
        if grant_before_binding {
            rig.store.create("oauth:new-pair", &login()).unwrap();
            rig.grant(MEMBER, NEW_PAIR, "oauth:new-pair");
        }
        rig.bind(Some(paired(NEW_PAIR, new_scalar)));
        let next = put(observer.as_mut()).await;
        let (aad, body, _) = open(&next, new_scalar, &key(HOME_SCALAR));
        assert_eq!(aad.generation.get(), 2);
        assert_eq!(rig.target(MEMBER).unwrap().pairing_id, NEW_PAIR);
        if grant_before_binding {
            assert_eq!(body["kind"], "snapshot");
            assert_eq!(body["logins"].as_array().unwrap().len(), 1);
            assert_eq!(body["logins"][0]["credential_id"], "oauth:new-pair");
        } else {
            assert_eq!(body, json!({"kind":"ended"}));
            rig.grant(MEMBER, NEW_PAIR, ID);
            let restored = put(observer.as_mut()).await;
            let (aad, body, _) = open(&restored, new_scalar, &key(HOME_SCALAR));
            assert_eq!(aad.generation.get(), 3);
            assert_eq!(body["kind"], "snapshot");
        }
    }
}

#[tokio::test]
async fn first_addressable_noneligible_member_receives_ended_then_start_repairs_same_bytes() {
    let mut rig = Rig::new();
    rig.setup();
    rig.revoke();
    rig.start();
    let mut observer = rig.watch().await;
    rig.bind(Some(paired(PAIR, MEMBER_SCALAR)));
    let first = put(observer.as_mut()).await;
    let (aad, body, _) = open(&first, MEMBER_SCALAR, &key(HOME_SCALAR));
    assert_eq!(aad.generation.get(), 1);
    assert_eq!(body, json!({"kind":"ended"}));
    rig.stop().await;
    rig.hub.delete(SHARED_LOGINS, &hub_key()).unwrap();
    rig.start();
    let next = put(observer.as_mut()).await;
    assert_eq!(next.value, first.value);
}

#[tokio::test]
async fn revoke_during_outage_commits_ended_before_hub_recovery_and_restart_sends_it() {
    let mut rig = Rig::new();
    rig.setup();
    rig.bind(Some(paired(PAIR, MEMBER_SCALAR)));
    rig.hub.set_online(false);
    rig.start();
    until(|| {
        rig.target(MEMBER)
            .is_some_and(|row| row.kind == HubLoginKind::Snapshot)
    })
    .await;
    rig.revoke();
    until(|| {
        rig.target(MEMBER)
            .is_some_and(|row| row.kind == HubLoginKind::Ended)
    })
    .await;
    let ended = rig.target(MEMBER).unwrap();
    assert_eq!(ended.generation.get(), 2);
    assert!(!ended.delivered);
    rig.stop().await;
    rig.hub.set_online(true);
    let mut observer = rig.watch().await;
    rig.start();
    let delivered = put(observer.as_mut()).await;
    assert_eq!(delivered.value, ended.sealed_bytes.unwrap());
    assert_eq!(
        open(&delivered, MEMBER_SCALAR, &key(HOME_SCALAR)).1,
        json!({"kind":"ended"})
    );
}

#[tokio::test]
async fn rekey_then_revoke_and_unpair_use_the_correct_recipient_and_home_rotation_repairs() {
    let mut rig = Rig::new();
    rig.setup();
    rig.bind(Some(paired(PAIR, MEMBER_SCALAR)));
    let mut observer = rig.watch().await;
    rig.start();
    put(observer.as_mut()).await;
    let newer = MEMBER_SCALAR + 3;
    rig.bind(Some(paired(PAIR, newer)));
    let current = put(observer.as_mut()).await;
    assert_eq!(
        open(&current, newer, &key(HOME_SCALAR)).1["kind"],
        "snapshot"
    );
    rig.revoke();
    let ended = put(observer.as_mut()).await;
    assert_eq!(
        open(&ended, newer, &key(HOME_SCALAR)).1,
        json!({"kind":"ended"})
    );
    let new_home = {
        rig.raw
            .execute(
                "UPDATE credentials SET state = 'needs_reauth' WHERE credential_id = ?1",
                [VAULT_TRANSFER_ID],
            )
            .unwrap();
        rig.store
            .recover_vault_transfer_key_audited(
                &transfer_record(HOME_SCALAR + 3),
                AuditCtx::route_admin(AuditOp::Overwrite, "test"),
            )
            .unwrap();
        let own = own_key(&rig.store).unwrap().unwrap();
        kem::public_half(own.pem.expose()).unwrap().0
    };
    let resealed = put(observer.as_mut()).await;
    assert_eq!(open(&resealed, newer, &new_home).1, json!({"kind":"ended"}));
    let opens = rig.hub.watch_opens(SHARED_LOGINS);
    rig.hub.reset_bucket(SHARED_LOGINS, &[]);
    assert_eq!(put(observer.as_mut()).await.value, resealed.value);
    assert_eq!(
        rig.hub.watch_opens(SHARED_LOGINS),
        opens,
        "reset stays on the same watch"
    );

    rig.grant(MEMBER, PAIR, ID);
    let eligible = put(observer.as_mut()).await;
    assert_eq!(open(&eligible, newer, &new_home).1["kind"], "snapshot");
    rig.bind(Some(joined(&[], &[])));
    let unpaired = put(observer.as_mut()).await;
    assert_eq!(open(&unpaired, newer, &new_home).1, json!({"kind":"ended"}));
}

#[tokio::test]
async fn revocation_during_projection_prevents_a_stale_snapshot_commit() {
    let mut rig = Rig::new();
    rig.setup();
    rig.bind(Some(paired(PAIR, MEMBER_SCALAR)));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let once = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let gate = {
        let (entered, release) = (Arc::clone(&entered), Arc::clone(&release));
        Arc::new(move || {
            let (entered, release) = (Arc::clone(&entered), Arc::clone(&release));
            let stall = once.swap(false, Ordering::SeqCst);
            Box::pin(async move {
                if stall {
                    entered.notify_one();
                    release.notified().await;
                }
            }) as Pin<Box<dyn Future<Output = ()> + Send>>
        })
    };
    let mut observer = rig.watch().await;
    rig.start_with(TestHooks {
        project: Some(gate),
        ..TestHooks::default()
    });
    wait(entered.notified()).await;
    rig.revoke();
    release.notify_one();
    let only = put(observer.as_mut()).await;
    let (aad, body, _) = open(&only, MEMBER_SCALAR, &key(HOME_SCALAR));
    assert_eq!(aad.generation.get(), 1);
    assert_eq!(body, json!({"kind":"ended"}));
}

#[tokio::test]
async fn failed_ended_commit_blocks_snapshot_repair_and_retries_without_another_change() {
    let mut rig = Rig::new();
    rig.setup();
    rig.bind(Some(paired(PAIR, MEMBER_SCALAR)));
    let mut observer = rig.watch().await;
    let failed = Arc::new(Notify::new());
    rig.start_with(TestHooks {
        failed: Some(Arc::clone(&failed)),
        ..TestHooks::default()
    });
    put(observer.as_mut()).await;
    until(|| rig.target(MEMBER).is_some_and(|row| row.delivered)).await;
    rig.raw.execute_batch("CREATE TRIGGER fail_ended BEFORE UPDATE ON hub_login_targets WHEN NEW.kind = 'ended' BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    rig.revoke();
    wait(failed.notified()).await;
    assert_eq!(rig.target(MEMBER).unwrap().generation.get(), 1);
    rig.hub.delete(SHARED_LOGINS, &hub_key()).unwrap();
    // Dropping the trigger does not produce a store notification, so only the
    // task's retry can commit and publish the end marker.
    assert_eq!(rig.entry().await.unwrap().operation, HubOperation::Delete);
    rig.raw.execute_batch("DROP TRIGGER fail_ended;").unwrap();
    let ended = put(observer.as_mut()).await;
    let (aad, body, _) = open(&ended, MEMBER_SCALAR, &key(HOME_SCALAR));
    assert_eq!(aad.generation.get(), 2);
    assert_eq!(body, json!({"kind":"ended"}));
}

#[tokio::test]
async fn lost_acknowledgement_tampering_and_tombstone_repair_reuse_exact_bytes() {
    let mut rig = Rig::new();
    rig.setup();
    rig.bind(Some(paired(PAIR, MEMBER_SCALAR)));
    rig.hub.lose_next_ack(SHARED_LOGINS, &hub_key());
    let mut observer = rig.watch().await;
    rig.start();
    let first = put(observer.as_mut()).await;
    until(|| rig.target(MEMBER).is_some_and(|row| row.delivered)).await;
    assert_eq!(rig.entry().await.unwrap(), first);
    assert_eq!(rig.target(MEMBER).unwrap().generation.get(), 1);

    let mut tampered: Value = serde_json::from_slice(&first.value).unwrap();
    tampered["ciphertext_b64"] = json!("AAAA");
    let bad = serde_json::to_vec(&tampered).unwrap();
    rig.hub.tamper(SHARED_LOGINS, &hub_key(), &bad).unwrap();
    assert_eq!(put(observer.as_mut()).await.value, bad);
    assert_eq!(put(observer.as_mut()).await.value, first.value);
    rig.hub.delete(SHARED_LOGINS, &hub_key()).unwrap();
    let repaired = put(observer.as_mut()).await;
    assert_eq!(repaired.value, first.value);
    assert_eq!(rig.target(MEMBER).unwrap().generation.get(), 1);
}

#[tokio::test]
async fn delayed_snapshot_can_land_after_a_revocation_but_watch_repairs_to_ended() {
    let mut rig = Rig::new();
    rig.setup();
    rig.bind(Some(paired(PAIR, MEMBER_SCALAR)));
    let mut delayed = rig.hub.delay_next_write(SHARED_LOGINS, &hub_key());
    let mut observer = rig.watch().await;
    rig.start();
    wait(delayed.wait_parked()).await;
    let previous = rig.target(MEMBER).unwrap();
    assert_eq!(previous.kind, HubLoginKind::Snapshot);
    rig.client.replace_connection();
    rig.revoke();
    let end = put(observer.as_mut()).await;
    assert_eq!(
        open(&end, MEMBER_SCALAR, &key(HOME_SCALAR)).1,
        json!({"kind":"ended"})
    );
    rig.hub.pause_delivery(SHARED_LOGINS);
    rig.hub.reset_bucket(SHARED_LOGINS, &[]);
    delayed.deliver().await.unwrap();
    assert_eq!(
        rig.entry().await.unwrap().value,
        previous.sealed_bytes.unwrap()
    );
    rig.hub.resume_delivery(SHARED_LOGINS);
    put(observer.as_mut()).await; // the delayed snapshot
    assert_eq!(put(observer.as_mut()).await.value, end.value);
}

#[tokio::test]
async fn old_fingerprint_discards_bytes_and_cannot_displace_new_box_owner() {
    let mut rig = Rig::new();
    rig.setup();
    rig.bind(Some(paired(PAIR, MEMBER_SCALAR)));
    let mut observer = rig.watch().await;
    rig.start();
    put(observer.as_mut()).await;
    rig.hub.set_online(false);
    rig.bind(Some(joined(&[], &[])));
    until(|| {
        rig.target(MEMBER)
            .is_some_and(|row| row.kind == HubLoginKind::Ended)
    })
    .await;
    let new_scalar = MEMBER_SCALAR + 3;
    rig.grant(NEW_MEMBER, NEW_PAIR, ID);
    rig.bind(Some(joined(
        &[(NEW_FP, NEW_PAIR)],
        &[(NEW_FP, NEW_PAIR, new_scalar)],
    )));
    until(|| {
        rig.target(MEMBER)
            .is_some_and(|row| row.sealed_bytes.is_none())
    })
    .await;
    rig.hub.set_online(true);
    let mut fresh = rig.watch().await;
    put(fresh.as_mut()).await; // earlier snapshot in replay
    let new = put(fresh.as_mut()).await;
    assert_eq!(
        open(&new, new_scalar, &key(HOME_SCALAR)).0.member,
        NEW_MEMBER
    );
    let old = rig.target(MEMBER).unwrap();
    assert_eq!(old.generation.get(), 2);
    assert!(old.sealed_bytes.is_none());
    rig.hub.delete(SHARED_LOGINS, &hub_key()).unwrap();
    assert_eq!(put(fresh.as_mut()).await.value, new.value);
}

#[tokio::test]
async fn exhausted_generation_marks_current_bytes_stale_without_put() {
    let mut rig = Rig::new();
    rig.setup();
    rig.bind(Some(paired(PAIR, MEMBER_SCALAR)));
    let mut observer = rig.watch().await;
    rig.start();
    let first = put(observer.as_mut()).await;
    rig.stop().await;
    rig.raw
        .execute(
            "UPDATE hub_login_targets SET generation = ?1 WHERE member_id = ?2",
            rusqlite::params![i64::MAX, MEMBER],
        )
        .unwrap();
    rig.start();
    until(|| rig.target(MEMBER).is_some_and(|row| row.stale)).await;
    assert_eq!(rig.target(MEMBER).unwrap().generation.get(), i64::MAX);
    assert_eq!(rig.entry().await.unwrap(), first);
}

struct ConflictingHub {
    inner: Arc<dyn Hub>,
    conflict: Notify,
    reread: Notify,
    release: Notify,
    reads: AtomicU64,
    creates: AtomicU64,
    pause_reread: bool,
}

#[async_trait::async_trait]
impl Hub for ConflictingHub {
    fn box_id(&self) -> &str {
        self.inner.box_id()
    }

    fn connection_changes(&self) -> watch::Receiver<u64> {
        self.inner.connection_changes()
    }

    async fn watch_bucket(&self, bucket: &str) -> Result<Box<dyn HubWatch>, HubError> {
        self.inner.watch_bucket(bucket).await
    }

    async fn entry(&self, bucket: &str, key: &str) -> Result<Option<HubEntry>, HubError> {
        if self.reads.fetch_add(1, Ordering::SeqCst) == 1 && self.pause_reread {
            self.reread.notify_one();
            self.release.notified().await;
        }
        self.inner.entry(bucket, key).await
    }

    async fn create(&self, bucket: &str, key: &str, value: Vec<u8>) -> Result<u64, HubError> {
        if self.creates.fetch_add(1, Ordering::SeqCst) == 0 {
            self.conflict.notify_one();
            return Err(HubError::Conflict);
        }
        self.inner.create(bucket, key, value).await
    }

    async fn update(
        &self,
        bucket: &str,
        key: &str,
        value: Vec<u8>,
        revision: u64,
    ) -> Result<u64, HubError> {
        self.inner.update(bucket, key, value, revision).await
    }
}

#[tokio::test]
async fn newer_commit_cancels_the_snapshot_retry_in_backoff_or_conflict_reread() {
    for pause_reread in [false, true] {
        let mut rig = Rig::new();
        rig.setup();
        rig.bind(Some(paired(PAIR, MEMBER_SCALAR)));
        let hub = Arc::new(ConflictingHub {
            inner: Arc::new(rig.client.clone()),
            conflict: Notify::new(),
            reread: Notify::new(),
            release: Notify::new(),
            reads: AtomicU64::new(0),
            creates: AtomicU64::new(0),
            pause_reread,
        });
        let mut observer = rig.watch().await;
        rig.start_on(hub.clone(), TestHooks::default());
        wait(hub.conflict.notified()).await;
        if pause_reread {
            wait(hub.reread.notified()).await;
        }
        assert_eq!(rig.target(MEMBER).unwrap().kind, HubLoginKind::Snapshot);
        assert!(rig.entry().await.is_none());
        rig.revoke();
        let only = put(observer.as_mut()).await;
        let (aad, body, _) = open(&only, MEMBER_SCALAR, &key(HOME_SCALAR));
        assert_eq!(aad.generation.get(), 2);
        assert_eq!(body, json!({"kind":"ended"}));
        hub.release.notify_one();
        assert_eq!(hub.creates.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn a_recipient_writer_that_ends_is_restarted() {
    let mut rig = Rig::new();
    rig.setup();
    rig.bind(Some(paired(PAIR, MEMBER_SCALAR)));
    let mut observer = rig.watch().await;
    let exit = Arc::new(std::sync::atomic::AtomicBool::new(true));
    rig.start_with(TestHooks {
        exit_once: Some(Arc::clone(&exit)),
        ..TestHooks::default()
    });
    // The first writer for the recipient ends before it publishes anything.
    let published = put(observer.as_mut()).await;
    assert!(!exit.load(std::sync::atomic::Ordering::SeqCst));
    let (aad, contents, _) = open(&published, MEMBER_SCALAR, &key(HOME_SCALAR));
    assert_eq!(aad.generation.get(), 1);
    assert_eq!(contents["kind"], "snapshot");
}

#[tokio::test]
async fn a_rewound_target_seals_above_the_generation_already_on_the_hub() {
    let mut rig = Rig::new();
    rig.setup();
    rig.bind(Some(paired(PAIR, MEMBER_SCALAR)));
    let mut observer = rig.watch().await;
    rig.start();
    put(observer.as_mut()).await;
    let mut row = login();
    for org in ["second", "third"] {
        row.identity.org_name = Some(org.into());
        rig.overwrite(&row);
        put(observer.as_mut()).await;
    }
    until(|| {
        rig.target(MEMBER)
            .is_some_and(|row| row.delivered && row.generation.get() == 3)
    })
    .await;
    rig.stop().await;
    // A store restored from an older backup: the hub still holds generation 3.
    rig.raw
        .execute(
            "UPDATE hub_login_targets SET generation = 1 WHERE member_id = ?1",
            [MEMBER],
        )
        .unwrap();
    rig.start();
    let next = put(observer.as_mut()).await;
    let (aad, contents, _) = open(&next, MEMBER_SCALAR, &key(HOME_SCALAR));
    assert!(aad.generation.get() > 3, "republished at {}", aad.generation.get());
    assert_eq!(contents["logins"][0]["identity"]["org_name"], "third");
    until(|| rig.target(MEMBER).is_some_and(|row| row.generation == aad.generation)).await;
}
