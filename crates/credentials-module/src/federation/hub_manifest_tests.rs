use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::{
    audit::{AuditCtx, AuditOp},
    federation::{MemberGrantOperation, MemberGrantSelector},
    fleet::RECORD_KEY_ID,
    hub_counters::HubReportSeq,
    key::MasterKey,
    signing::public_key_ed25519,
    store::{EncryptedStore, GhManifestSource, GhManifestVerdict, GhManifestVersion, HubOwnReport},
    test_support::TestTempDir,
};
use serde_json::{json, Value};
use tokio::{sync::watch, task::JoinHandle};

use super::{
    hub::{
        stand_in::{StandIn, StandInClient},
        Hub, HubEntry, HubOperation, MANIFEST_ACTIVE,
    },
    hub_binding::{HubBinding, HubBindings},
    hub_manifest::{seal, verify},
    hub_manifest_collector, hub_manifest_reporter,
    sharing::{decode_snapshot, VaultSharingSnapshot},
};
use crate::manifest_active_report::{parse_active_report, record_own_manifest_active_report};

const HOME: &str = "fed-computer:01010101010101010101010101010101";
const PEER: &str = "fed-computer:02020202020202020202020202020202";
const PEER_FP: &str = "02020202020202020202020202020202";
const HOME_BOX: &str = "11111111111111111111111111111111";
const PEER_BOX: &str = "22222222222222222222222222222222";
const BOX_2: &str = "33333333333333333333333333333333";
const PAIR: &str = "pair:1";
const REPAIR: &str = "pair:2";
const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Vault {
    store: Arc<EncryptedStore>,
    path: PathBuf,
    _root: TestTempDir,
}

impl Vault {
    fn new(member: &str, home: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = TestTempDir::new(format!(
            "hub-report-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
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
        let store = Arc::new(EncryptedStore::open(db, MasterKey::from_bytes([18; 32])).unwrap());
        store
            .set_federation_self_member_audited(member, AuditCtx::vault(AuditOp::FederationSelfSet))
            .unwrap();
        store.ensure_fleet_keys(0).unwrap();
        let vault = Self {
            store,
            path,
            _root: root,
        };
        vault.sql(&format!("INSERT INTO settings (name, value, updated_at_ms) VALUES ('secrets.home_member', '{home}', 0)"));
        vault
    }

    fn sql(&self, sql: &str) {
        rusqlite::Connection::open(&self.path)
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }

    fn pem(&self) -> String {
        let meta = self.store.meta(RECORD_KEY_ID).unwrap();
        let key = self
            .store
            .get_snapshot(RECORD_KEY_ID, meta.incarnation.as_deref().unwrap())
            .unwrap();
        std::str::from_utf8(key.record.payload.expose())
            .unwrap()
            .into()
    }

    fn record(&self, member: &str, version: i64, reason: Option<&str>) {
        let report = parse_active_report(&json!({"version":version,"payload_sha256":HASH,
            "verdict":if reason.is_some() { "invalid" } else { "valid" }, "reason":reason}))
        .unwrap();
        assert_eq!(
            record_own_manifest_active_report(&self.store, member, &report)["status"],
            "recorded"
        );
    }

    fn store_manifest(&self) {
        self.store
            .store_gh_manifest(
                &GhManifestVersion {
                    version: 28,
                    manifest_bytes: b"{}",
                    manifest_sha256: HASH,
                    key_id: "test",
                    signature: &[7; 64],
                    signed_at_ms: 1,
                    source: GhManifestSource::Import,
                    approval_audit_seq: None,
                },
                AuditCtx::admin(AuditOp::GhManifestStore),
            )
            .unwrap();
    }
}

fn public(pem: &str) -> [u8; 32] {
    let hex = public_key_ed25519(pem).unwrap().public_key_hex;
    std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
}

fn binding(box_id: &str, pem: &str) -> HubBinding {
    HubBinding {
        member_id: PEER.into(),
        box_id: box_id.into(),
        pairing_id: PAIR.into(),
        vault_transfer_x25519: None,
        fleet_record_ed25519: Some(public(pem)),
    }
}

struct Rig {
    home: Vault,
    peer: Vault,
    hub: StandIn,
    peer_client: StandInClient,
    home_client: StandInClient,
    paired: watch::Sender<Option<Arc<VaultSharingSnapshot>>>,
    joined: watch::Sender<Option<HubBindings>>,
}

impl Rig {
    fn new() -> Self {
        let hub = StandIn::new();
        let result = Self {
            home: Vault::new(HOME, "self"),
            peer: Vault::new(PEER, HOME),
            peer_client: hub.client(PEER_BOX),
            home_client: hub.client(HOME_BOX),
            hub,
            paired: watch::channel(None).0,
            joined: watch::channel(None).0,
        };
        result.home.store_manifest();
        result.home.record(HOME, 28, None);
        result.views(Some(PAIR), Some((PAIR, PEER_BOX, &result.peer.pem())));
        result
    }

    fn views(&self, paired: Option<&str>, peer: Option<(&str, &str, &str)>) {
        let devices: Vec<_> = paired
            .into_iter()
            .map(|p| {
                json!({
                    "fingerprint":PEER_FP,"class":"computer","pairing_id":p,"shares":[]
                })
            })
            .collect();
        let snapshot = Arc::new(
            decode_snapshot(
                &json!({"self":{"static_public_key_hex":"00".repeat(32)},"devices":devices}),
            )
            .unwrap(),
        );
        let peers: Vec<_> = peer.into_iter().map(|(p, b, pem)| json!({
            "fingerprint":PEER_FP,"class":"computer","pairing_id":p,"machine_id":b,
            "key_record":{"keys":{"fleet_record_ed25519":{"pub":public_key_ed25519(pem).unwrap().public_key_hex}}}
        })).collect();
        self.joined.send_replace(HubBindings::join(
            HOME_BOX,
            &snapshot,
            &json!({"peers":peers}),
        ));
        self.paired.send_replace(Some(snapshot));
    }

    fn grant(&self, pairing: &str) {
        assert!(self
            .home
            .store
            .create_member_grant_audited(
                PEER,
                MemberGrantOperation::SecretUse,
                &MemberGrantSelector::None,
                pairing
            )
            .unwrap());
    }

    fn revoke(&self) {
        self.home
            .store
            .revoke_member_grant_audited(
                PEER,
                MemberGrantOperation::SecretUse,
                &MemberGrantSelector::None,
            )
            .unwrap();
    }

    fn collect(&self) -> JoinHandle<()> {
        tokio::spawn(hub_manifest_collector::run(
            Arc::clone(&self.home.store),
            Arc::new(self.home_client.clone()),
            self.joined.subscribe(),
            self.paired.subscribe(),
        ))
    }

    fn publish(&self) -> JoinHandle<()> {
        tokio::spawn(hub_manifest_reporter::run(
            Arc::clone(&self.peer.store),
            Arc::new(self.peer_client.clone()),
        ))
    }

    fn put(&self, box_id: &str, bytes: &[u8]) {
        self.hub.tamper(MANIFEST_ACTIVE, box_id, bytes).unwrap();
    }

    fn stored_peer(&self) -> Option<(GhManifestVerdict, Option<String>, i64)> {
        self.home
            .store
            .gh_manifest_active_status(28)
            .unwrap()
            .unwrap()
            .computers
            .into_iter()
            .find(|r| r.member_id == PEER)
            .and_then(|r| Some((r.verdict?, r.reason, r.version?)))
    }

    fn ready(&self) -> bool {
        self.home
            .store
            .gh_manifest_active_status(28)
            .unwrap()
            .unwrap()
            .ready
    }

    fn seq(&self, box_id: &str) -> Option<i64> {
        self.home
            .store
            .list_hub_manifest_high_waters()
            .unwrap()
            .into_iter()
            .find(|r| r.member_id == PEER && r.box_id == box_id)
            .map(|r| r.seq.get())
    }

    async fn entry(&self, key: &str) -> Option<HubEntry> {
        self.home_client.entry(MANIFEST_ACTIVE, key).await.unwrap()
    }

    async fn published(&self, expected: i64) -> HubEntry {
        bounded(async {
            loop {
                if let Some(entry) = self
                    .entry(PEER_BOX)
                    .await
                    .filter(|e| e.operation == HubOperation::Put)
                {
                    let outer: Value = serde_json::from_slice(&entry.value).unwrap();
                    let body: Value =
                        serde_json::from_str(outer["body"].as_str().unwrap()).unwrap();
                    if body["seq"] == expected {
                        return entry;
                    }
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
    }
}

fn signed(pem: &str, box_id: &str, member: &str, seq: i64, verdict: GhManifestVerdict) -> Vec<u8> {
    seal(
        &HubOwnReport {
            version: 28,
            payload_sha256: HASH.into(),
            verdict,
            reason: Some("private report reason".into()),
        },
        box_id,
        member,
        HubReportSeq::new(seq).unwrap(),
        pem,
    )
    .unwrap()
}

async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    // Leave room on the paused clock for retries that back off for up to ten minutes.
    tokio::time::timeout(Duration::from_secs(3600), future)
        .await
        .expect("hub manifest signal did not arrive")
}

async fn wait(mut done: impl FnMut() -> bool) {
    bounded(async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await;
}

async fn stop(task: JoinHandle<()>) {
    task.abort();
    assert!(bounded(task).await.unwrap_err().is_cancelled());
}

#[test]
fn strict_manifest_report_checks_signature_and_binding_before_acceptance() {
    let vault = Vault::new(PEER, HOME);
    let pem = vault.pem();
    let valid = signed(&pem, PEER_BOX, PEER, 1, GhManifestVerdict::Valid);
    let reporter = binding(PEER_BOX, &pem);
    assert_eq!(verify(&valid, &reporter).unwrap().seq, HubReportSeq::FIRST);
    assert!(verify(&valid, &binding(BOX_2, &pem)).is_none());
    let wrong = Vault::new(HOME, "self");
    assert!(verify(&valid, &binding(PEER_BOX, &wrong.pem())).is_none());
    assert!(verify(
        &signed(&pem, PEER_BOX, HOME, 1, GhManifestVerdict::Valid),
        &reporter
    )
    .is_none());
    let envelope: Value = serde_json::from_slice(&valid).unwrap();
    let mutate = |field: &str, value: Value| {
        let mut altered = envelope.clone();
        altered[field] = value;
        serde_json::to_vec(&altered).unwrap()
    };
    assert!(verify(&mutate("key_id", json!("wrong")), &reporter).is_none());
    let tampered = envelope["body"]
        .as_str()
        .unwrap()
        .replace("\"version\":28", "\"version\":29");
    assert!(verify(&mutate("body", json!(tampered)), &reporter).is_none());
    for token in ["9007199254740992", "\"1\"", "1.0", "1e0"] {
        let body = envelope["body"]
            .as_str()
            .unwrap()
            .replace("\"seq\":1", &format!("\"seq\":{token}"));
        // Authenticate the malformed body, so these refusals cannot come from a bad signature.
        let sig = credentials_core::signing::sign_ed25519(
            &pem,
            &[
                "ck-vault-hub/manifest-active/v1\0".as_bytes(),
                body.as_bytes(),
            ]
            .concat(),
        )
        .unwrap();
        let mut altered = envelope.clone();
        altered["signature_b64"] = json!(sig.signature_b64);
        altered["body"] = json!(body);
        assert!(
            verify(&serde_json::to_vec(&altered).unwrap(), &reporter).is_none(),
            "seq token {token}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn reporter_recovers_local_commit_and_repairs_delete_reset_and_record_key_change() {
    let rig = Rig::new();
    rig.grant(PAIR);
    let pem = rig.peer.pem();
    let home = rig.collect();
    rig.put(
        PEER_BOX,
        &signed(&pem, PEER_BOX, PEER, 5, GhManifestVerdict::Valid),
    );
    wait(|| rig.seq(PEER_BOX) == Some(5)).await;
    // Use a high-water that does not belong to this pairing. The member finds that
    // value under its own key and signs above it, and the Home admits it after a
    // re-pair.
    rig.grant(REPAIR);
    rig.views(Some(REPAIR), Some((REPAIR, PEER_BOX, &pem)));
    rig.peer.record(PEER, 28, Some("a local-only diagnostic"));
    assert!(
        rig.peer.store.hub_report_task_state().unwrap().is_none(),
        "AFT does not sign"
    );
    rig.hub.set_online(false);
    let reporter = rig.publish();
    wait(|| rig.peer.store.hub_report_task_state().unwrap().is_some()).await;
    assert!(
        !rig.peer
            .store
            .hub_report_task_state()
            .unwrap()
            .unwrap()
            .sent
    );
    rig.hub.set_online(true);
    rig.hub.lose_next_ack(MANIFEST_ACTIVE, PEER_BOX);
    rig.peer_client.replace_connection();
    rig.home_client.replace_connection();
    let first = rig.published(6).await;
    assert!(!std::str::from_utf8(&first.value)
        .unwrap()
        .contains("a local-only diagnostic"));
    assert_eq!(
        verify(&first.value, &binding(PEER_BOX, &pem))
            .unwrap()
            .reason,
        "reported_invalid"
    );
    wait(|| {
        rig.stored_peer()
            == Some((
                GhManifestVerdict::Invalid,
                Some("reported_invalid".into()),
                28,
            ))
    })
    .await;
    stop(reporter).await;
    let opens = rig.hub.watch_opens(MANIFEST_ACTIVE);
    let reporter = rig.publish();
    wait(|| rig.hub.watch_opens(MANIFEST_ACTIVE) > opens).await;
    rig.hub
        .tamper(MANIFEST_ACTIVE, PEER_BOX, &first.value)
        .unwrap();
    rig.hub.delete(MANIFEST_ACTIVE, PEER_BOX).unwrap();
    let second = rig.published(7).await;
    wait(|| rig.seq(PEER_BOX) == Some(7)).await;
    assert!(second.revision > first.revision);
    rig.hub
        .reset_bucket(MANIFEST_ACTIVE, &[(PEER_BOX, &second.value)]);
    rig.published(8).await;
    wait(|| rig.seq(PEER_BOX) == Some(8)).await;
    assert!(rig.home.store.hub_own_report().unwrap().is_some());

    rig.peer
        .store
        .remove_audited(RECORD_KEY_ID, AuditCtx::admin(AuditOp::Remove))
        .unwrap();
    rig.peer.store.ensure_fleet_keys(1).unwrap();
    let new_pem = rig.peer.pem();
    let fourth = rig.published(9).await;
    assert!(verify(&fourth.value, &binding(PEER_BOX, &pem)).is_none());
    assert!(verify(&fourth.value, &binding(PEER_BOX, &new_pem)).is_some());
    rig.views(Some(REPAIR), Some((REPAIR, PEER_BOX, &new_pem)));
    wait(|| rig.seq(PEER_BOX) == Some(9)).await;
    stop(reporter).await;
    stop(home).await;
}

#[tokio::test(start_paused = true)]
async fn later_local_report_supersedes_an_inflight_put_before_its_delayed_delivery() {
    let rig = Rig::new();
    let task = rig.publish();
    rig.peer.record(PEER, 28, None);
    rig.published(1).await;
    let mut held = rig.hub.delay_next_write(MANIFEST_ACTIVE, PEER_BOX);
    rig.peer.record(PEER, 29, None);
    bounded(held.wait_parked()).await;
    let state = rig.peer.store.hub_report_task_state().unwrap().unwrap();
    assert!(
        state.sent,
        "the sent mark is durable before the put is issued"
    );
    rig.peer.record(PEER, 30, None);
    let latest = rig.published(3).await;
    assert_eq!(
        verify(&latest.value, &binding(PEER_BOX, &rig.peer.pem()))
            .unwrap()
            .version,
        30
    );
    assert!(
        bounded(held.deliver()).await.is_err(),
        "new report won the hub CAS"
    );
    assert_eq!(rig.entry(PEER_BOX).await.unwrap(), latest);
    stop(task).await;
}

#[tokio::test(start_paused = true)]
async fn collector_keeps_fields_on_empty_reopen_but_not_for_a_box_move_while_stopped() {
    let rig = Rig::new();
    rig.grant(PAIR);
    let pem = rig.peer.pem();
    let first = signed(&pem, PEER_BOX, PEER, 2, GhManifestVerdict::Valid);
    rig.put(PEER_BOX, &first);
    let task = rig.collect();
    wait(|| rig.ready()).await;
    stop(task).await;
    // No delete or reset is observed by the collector. An empty history is not proof.
    rig.hub.reset_bucket(MANIFEST_ACTIVE, &[]);
    let opens = rig.hub.watch_opens(MANIFEST_ACTIVE);
    let task = rig.collect();
    wait(|| rig.hub.watch_opens(MANIFEST_ACTIVE) > opens).await;
    assert!(rig.ready());
    assert_eq!(rig.seq(PEER_BOX), Some(2));
    stop(task).await;
    rig.views(Some(PAIR), Some((PAIR, BOX_2, &pem)));
    let opens = rig.hub.watch_opens(MANIFEST_ACTIVE);
    let task = rig.collect();
    wait(|| rig.hub.watch_opens(MANIFEST_ACTIVE) > opens).await;
    assert!(!rig.ready());
    assert_eq!(rig.stored_peer(), None);
    assert_eq!(rig.seq(PEER_BOX), Some(2));
    rig.put(
        BOX_2,
        &signed(&pem, BOX_2, PEER, 1, GhManifestVerdict::Valid),
    );
    wait(|| rig.ready()).await;
    rig.put(PEER_BOX, &first);
    rig.views(Some(PAIR), Some((PAIR, PEER_BOX, &pem)));
    wait(|| !rig.ready()).await;
    rig.put(
        PEER_BOX,
        &signed(&pem, PEER_BOX, PEER, 3, GhManifestVerdict::Valid),
    );
    wait(|| rig.ready()).await;
    stop(task).await;
}

#[tokio::test(start_paused = true)]
async fn collector_checks_admission_provenance_and_replays_only_greater_sequences() {
    let rig = Rig::new();
    let pem = rig.peer.pem();
    let first = signed(&pem, PEER_BOX, PEER, 1, GhManifestVerdict::Valid);
    rig.put(PEER_BOX, &first);
    let task = rig.collect();
    wait(|| rig.hub.watch_opens(MANIFEST_ACTIVE) == 1).await;
    assert_eq!(rig.seq(PEER_BOX), None);
    rig.grant(PAIR);
    wait(|| rig.ready()).await;
    rig.hub.set_online(false);
    rig.revoke();
    assert!(!rig.ready());
    assert_eq!(rig.stored_peer(), None);
    assert_eq!(rig.seq(PEER_BOX), Some(1));
    rig.grant(PAIR);
    rig.hub.set_online(true);
    rig.home_client.replace_connection();
    wait(|| rig.hub.watch_opens(MANIFEST_ACTIVE) == 2).await;
    assert!(!rig.ready());
    rig.put(
        PEER_BOX,
        &signed(&pem, PEER_BOX, PEER, 2, GhManifestVerdict::Valid),
    );
    wait(|| rig.ready()).await;
    stop(task).await;
    // The new pairing arrived while the collector was stopped. Keep the existing
    // grant transition out of the store API to exercise startup reconciliation.
    rig.home
        .sql("UPDATE member_grants SET pairing_id = 'pair:2'");
    rig.views(Some(REPAIR), Some((PAIR, PEER_BOX, &pem)));
    rig.put(PEER_BOX, &first);
    let task = rig.collect();
    wait(|| rig.hub.watch_opens(MANIFEST_ACTIVE) == 3).await;
    assert_eq!(rig.seq(PEER_BOX), None);
    assert!(!rig.ready());
    rig.views(Some(REPAIR), Some((REPAIR, PEER_BOX, &pem)));
    wait(|| rig.ready()).await;
    assert_eq!(rig.seq(PEER_BOX), Some(1));
    stop(task).await;
}

#[test]
fn hub_manifest_value_limit_accepts_the_bucket_bound_and_refuses_one_more_byte() {
    let vault = Vault::new(PEER, HOME);
    let pem = vault.pem();
    let binding = binding(PEER_BOX, &pem);
    let mut value = signed(&pem, PEER_BOX, PEER, 1, GhManifestVerdict::Valid);
    value.resize(16_384, b' ');
    assert!(verify(&value, &binding).is_some());
    value.push(b' ');
    assert!(verify(&value, &binding).is_none());
}

#[tokio::test(start_paused = true)]
async fn reporter_retries_a_failed_signed_bytes_commit_without_another_report() {
    let rig = Rig::new();
    rig.peer.record(PEER, 28, None);
    rig.peer.sql("CREATE TRIGGER refuse_report BEFORE INSERT ON hub_report_task BEGIN SELECT RAISE(ABORT, 'signed persist failed'); END;");
    let failed = Arc::new(tokio::sync::Notify::new());
    let task = tokio::spawn(hub_manifest_reporter::run_inner(
        Arc::clone(&rig.peer.store),
        Arc::new(rig.peer_client.clone()),
        Some(Arc::clone(&failed)),
    ));
    bounded(failed.notified()).await;
    assert!(rig.entry(PEER_BOX).await.is_none());
    assert!(rig.peer.store.hub_report_task_state().unwrap().is_none());
    rig.peer.sql("DROP TRIGGER refuse_report;");
    tokio::time::advance(Duration::from_secs(1)).await;
    rig.published(1).await;
    stop(task).await;
}

#[tokio::test(start_paused = true)]
async fn collector_rereads_under_a_new_key_and_ignores_a_queued_older_delete() {
    let rig = Rig::new();
    let old_pem = rig.peer.pem();
    let new_vault = Vault::new(PEER, HOME);
    let new_pem = new_vault.pem();
    rig.grant(PAIR);
    rig.put(
        PEER_BOX,
        &signed(&old_pem, PEER_BOX, PEER, 1, GhManifestVerdict::Valid),
    );
    let task = rig.collect();
    wait(|| rig.ready()).await;

    rig.put(
        PEER_BOX,
        &signed(&new_pem, PEER_BOX, PEER, 2, GhManifestVerdict::Valid),
    );
    wait(|| rig.stored_peer().is_none()).await;
    assert_eq!(rig.seq(PEER_BOX), Some(1));
    rig.views(Some(PAIR), Some((PAIR, PEER_BOX, &new_pem)));
    wait(|| rig.seq(PEER_BOX) == Some(2)).await;
    assert!(
        rig.ready(),
        "the same revision is valid once the new key arrives"
    );

    rig.hub.pause_delivery(MANIFEST_ACTIVE);
    rig.hub.delete(MANIFEST_ACTIVE, PEER_BOX).unwrap();
    rig.put(
        PEER_BOX,
        &signed(&old_pem, PEER_BOX, PEER, 3, GhManifestVerdict::Valid),
    );
    rig.views(Some(PAIR), Some((PAIR, PEER_BOX, &old_pem)));
    wait(|| rig.seq(PEER_BOX) == Some(3)).await;
    // If the queued delete acts, its failed clear blocks the later report behind it.
    rig.home.sql(
        "CREATE TRIGGER refuse_clear BEFORE UPDATE OF version ON gh_manifest_activations
        WHEN OLD.member_id = 'fed-computer:02020202020202020202020202020202' AND NEW.version IS NULL
        BEGIN SELECT RAISE(ABORT, 'queued delete attempted a clear'); END;",
    );
    rig.hub.resume_delivery(MANIFEST_ACTIVE);
    rig.put(
        PEER_BOX,
        &signed(&old_pem, PEER_BOX, PEER, 4, GhManifestVerdict::Valid),
    );
    wait(|| rig.seq(PEER_BOX) == Some(4)).await;
    assert!(rig.ready());
    assert_eq!(rig.hub.watch_opens(MANIFEST_ACTIVE), 1);
    stop(task).await;
}

#[tokio::test(start_paused = true)]
async fn queued_reset_clears_a_report_accepted_by_earlier_point_read_without_forgetting_its_seq() {
    let rig = Rig::new();
    rig.grant(PAIR);
    let pem = rig.peer.pem();
    let newer = Vault::new(PEER, HOME).pem();
    rig.put(
        PEER_BOX,
        &signed(&pem, PEER_BOX, PEER, 1, GhManifestVerdict::Valid),
    );
    let task = rig.collect();
    wait(|| rig.ready()).await;
    rig.hub.pause_delivery(MANIFEST_ACTIVE);
    let second = signed(&newer, PEER_BOX, PEER, 2, GhManifestVerdict::Valid);
    rig.hub
        .reset_bucket(MANIFEST_ACTIVE, &[(PEER_BOX, &second)]);
    rig.views(Some(PAIR), Some((PAIR, PEER_BOX, &newer)));
    wait(|| rig.seq(PEER_BOX) == Some(2)).await;
    assert!(rig.ready());
    rig.hub.resume_delivery(MANIFEST_ACTIVE);
    wait(|| rig.stored_peer().is_none()).await;
    assert_eq!(rig.seq(PEER_BOX), Some(2));
    rig.put(PEER_BOX, &second);
    rig.put(
        PEER_BOX,
        &signed(&newer, PEER_BOX, PEER, 3, GhManifestVerdict::Valid),
    );
    wait(|| rig.ready()).await;
    assert_eq!(rig.seq(PEER_BOX), Some(3));
    assert_eq!(rig.hub.watch_opens(MANIFEST_ACTIVE), 1);
    stop(task).await;
}

#[tokio::test(start_paused = true)]
async fn collector_start_clears_only_local_admission_losses_while_hub_and_callosum_are_down() {
    let rig = Rig::new();
    let pem = rig.peer.pem();
    rig.grant(PAIR);
    let task = rig.collect();
    rig.put(
        PEER_BOX,
        &signed(&pem, PEER_BOX, PEER, 1, GhManifestVerdict::Valid),
    );
    wait(|| rig.ready()).await;
    stop(task).await;
    rig.hub.set_online(false);
    rig.paired.send_replace(None);
    rig.joined.send_replace(None);
    let read = rusqlite::Connection::open(&rig.home.path).unwrap();
    let raw_version = |member| {
        read.query_row(
            "SELECT version FROM gh_manifest_activations WHERE member_id = ?1",
            [member],
            |row| row.get::<_, Option<i64>>(0),
        )
        .unwrap()
    };
    let mut initialized = rig.home.store.subscribe_writes();
    let task = rig.collect();
    bounded(initialized.changed()).await.unwrap();
    assert_eq!(
        raw_version(PEER),
        Some(28),
        "unavailable Callosum did not prove membership loss"
    );
    stop(task).await;
    // Restore a stale slot as it might look when a collector starts after an offline
    // grant loss. Status is already closed, so inspect the physical row as well.
    rig.home.sql("DELETE FROM member_grants");
    assert!(!rig.ready());
    assert_eq!(raw_version(PEER), Some(28));
    let task = rig.collect();
    wait(|| raw_version(PEER).is_none()).await;
    assert_eq!(raw_version(HOME), Some(28));
    assert_eq!(rig.seq(PEER_BOX), Some(1));
    stop(task).await;
}

#[tokio::test(start_paused = true)]
async fn repeating_the_local_report_after_a_regrant_restores_readiness_with_a_new_sequence() {
    let rig = Rig::new();
    rig.grant(PAIR);
    let collector = rig.collect();
    let reporter = rig.publish();
    rig.peer.record(PEER, 28, None);
    rig.published(1).await;
    wait(|| rig.ready()).await;
    // Revoking the last grant clears readiness but keeps the sequence high-water,
    // so the unchanged report on the hub cannot restore it by itself.
    rig.revoke();
    assert!(!rig.ready());
    rig.grant(PAIR);
    let activations = |store: &EncryptedStore| {
        store
            .read_audit(None)
            .unwrap()
            .iter()
            .filter(|row| row.op == "gh_manifest_activation")
            .count()
    };
    let local_before = activations(&rig.peer.store);
    // The computer repeats the identical report explicitly.
    rig.peer.record(PEER, 28, None);
    rig.published(2).await;
    wait(|| rig.ready()).await;
    assert_eq!(rig.seq(PEER_BOX), Some(2));
    assert_eq!(activations(&rig.peer.store), local_before);
    stop(reporter).await;
    stop(collector).await;
}

#[tokio::test(start_paused = true)]
async fn a_rewound_report_sequence_signs_above_the_one_on_the_hub() {
    let rig = Rig::new();
    rig.grant(PAIR);
    let collector = rig.collect();
    let reporter = rig.publish();
    for (seq, reason) in [(1, None), (2, Some("reported_invalid")), (3, None)] {
        rig.peer.record(PEER, 28, reason);
        rig.published(seq).await;
    }
    wait(|| rig.seq(PEER_BOX) == Some(3)).await;
    stop(reporter).await;
    // A store restored from an older backup: the hub still holds sequence 3.
    rig.peer.sql("UPDATE hub_report_task SET seq = 1");
    let reporter = rig.publish();
    rig.peer.record(PEER, 28, Some("reported_invalid"));
    rig.published(4).await;
    wait(|| rig.seq(PEER_BOX) == Some(4)).await;
    assert_eq!(
        rig.stored_peer().map(|(verdict, _, _)| verdict),
        Some(GhManifestVerdict::Invalid)
    );
    stop(reporter).await;
    stop(collector).await;
}
