use std::{path::Path, sync::Arc};

use claustrum_module_probe::{
    federation::{transfer::ensure_transfer_key, OutboundClient},
    hub_test_support::{record_manifest_report, HubFixture, RunningVault},
};
use credentials_core::{
    audit::{AuditCtx, AuditOp},
    federation::{NewRemoteRecord, RemoteRecord, RemoteRecordSource, VAULT_TRANSFER_ID},
    fleet::RECORD_KEY_ID,
    oauth::OAuthCredential,
    record::{RecordIdentity, VaultRecord},
    store::{EncryptedStore, GhManifestSource, GhManifestVersion, HubLoginKind, SetCategoryMode},
    test_support::TestTempDir,
};
use serde_json::{json, Value};

use super::support::{
    poll_until_ready, temp_root, wait_until, Held, HomeStore, Reply, SharedCallosumStandIn,
    VaultFixture, TARGET_MODULE,
};

const HOME_FP: &str = "00000000000000000000000000000007";
const MEMBER_FP: &str = "00000000000000000000000000000008";
const HOME_BOX: &str = "00000000000000000000000000000001";
const MEMBER_BOX: &str = "00000000000000000000000000000002";
const PAIR: &str = "pair:1";
const REPAIR: &str = "pair:2";
const LOGIN: &str = "oauth:hub-lifecycle";
const MANUAL: &str = "oauth:hub-lifecycle-manual";
const READ: &str = "callosum.paired_devices_read";
const WATCH: &str = "callosum.paired_devices_watch";
const KEYS: &str = "callosum.peer_keys_watch";
const MANIFEST_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Rig {
    home_tasks: RunningVault,
    member_tasks: RunningVault,
    member_outbound: OutboundClient,
    hub: HubFixture,
    home: Arc<EncryptedStore>,
    member: Arc<EncryptedStore>,
    home_callosum: SharedCallosumStandIn,
    member_callosum: SharedCallosumStandIn,
    _dir: TestTempDir,
}

impl Rig {
    async fn new(name: &str) -> Self {
        let root = temp_root(name);
        let (home_callosum, home_fixture, home) = prepare(&root.join("home"), HOME_FP).await;
        let (member_callosum, member_fixture, member) =
            prepare(&root.join("member"), MEMBER_FP).await;
        home.set_secret_home_audited(Some("self"), AuditCtx::admin(AuditOp::SecretHomeSet))
            .unwrap();
        member
            .set_secret_home_audited(
                Some(&member_id(HOME_FP)),
                AuditCtx::admin(AuditOp::SecretHomeSet),
            )
            .unwrap();

        home.create(LOGIN, &login("original")).unwrap();
        home.set_categories_audited(
            LOGIN,
            SetCategoryMode::Add,
            &["llm-provider".into()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
        answer(
            &home_callosum,
            &roster(&member, MEMBER_FP, MEMBER_BOX, PAIR),
        );
        answer(&member_callosum, &roster(&home, HOME_FP, HOME_BOX, PAIR));
        let hub = HubFixture::default();
        let home_tasks = hub.start_vault(Arc::clone(&home), home_fixture.outbound, HOME_BOX);
        let member_outbound = member_fixture.outbound.clone();
        let member_tasks =
            hub.start_vault(Arc::clone(&member), member_fixture.outbound, MEMBER_BOX);
        Self {
            home_tasks,
            member_tasks,
            member_outbound,
            hub,
            home,
            member,
            home_callosum,
            member_callosum,
            _dir: root,
        }
    }

    fn overwrite(&self, org: &str) {
        self.home
            .overwrite_unconditional_audited(LOGIN, &login(org), AuditCtx::admin(AuditOp::Put))
            .unwrap();
    }

    fn remote(&self) -> Option<RemoteRecord> {
        self.member.remote_record(LOGIN).unwrap()
    }

    async fn wait_for_login(&self, org: &str, pairing: &str) -> RemoteRecord {
        let row = poll_until_ready(std::future::poll_fn(|_| {
            match self.remote().filter(|row| {
                row.identity.org_name.as_deref() == Some(org)
                    && row.home_pairing_id.as_deref() == Some(pairing)
            }) {
                Some(row) => std::task::Poll::Ready(row),
                None => std::task::Poll::Pending,
            }
        })).await.unwrap_or_else(|| {
            panic!("no automatic login for {org:?}, {pairing}; remote={:?} home grants={:?} home targets={:?} member state={:?} home watches={:?} member watches={:?}",
                self.remote(), self.home.list_member_grants().unwrap(),
                self.home.list_hub_login_targets().unwrap().iter().map(|row| (row.kind, row.delivered, row.pairing_id.clone())).collect::<Vec<_>>(),
                self.member.hub_login_home_state(&member_id(HOME_FP)).unwrap(),
                [READ, WATCH, KEYS].map(|method| self.home_callosum.saw_method(method)),
                [READ, WATCH, KEYS].map(|method| self.member_callosum.saw_method(method)));
        });
        assert_eq!(row.source, RemoteRecordSource::HomeWatch);
        assert_eq!(row.home_member, member_id(HOME_FP));
        row
    }

    async fn re_pair(&self) {
        for (callosum, body) in [
            (
                &self.home_callosum,
                roster(&self.member, MEMBER_FP, MEMBER_BOX, REPAIR),
            ),
            (
                &self.member_callosum,
                roster(&self.home, HOME_FP, HOME_BOX, REPAIR),
            ),
        ] {
            answer(callosum, &body);
            wait_until(|| callosum.saw_method(WATCH)).await;
            // The harness broadcasts to both Callosum watches, so this full frame
            // carries the paired-device view and the peer-keys view together.
            assert_eq!(callosum.watch_snapshot(Some(body)).await, 2);
        }
    }
}

async fn prepare(
    root: &Path,
    fingerprint: &str,
) -> (SharedCallosumStandIn, VaultFixture, Arc<EncryptedStore>) {
    std::fs::create_dir(root).unwrap();
    let callosum = SharedCallosumStandIn::start(root).await;
    let fixture = VaultFixture::new(root, "vault", fingerprint, &callosum);
    let store = HomeStore::open(&fixture.data_dir).store;
    store
        .set_federation_self_member_audited(
            &member_id(fingerprint),
            AuditCtx::admin(AuditOp::FederationSelfSet),
        )
        .unwrap();
    store
        .set_federation_member_mapping_audited(true, AuditCtx::admin(AuditOp::FederationGateSet))
        .unwrap();
    store.set_login_sharing_audited(true, "test").unwrap();
    store.ensure_fleet_keys(0).unwrap();
    ensure_transfer_key(&store, "test").unwrap();
    (callosum, fixture, store)
}

fn member_id(fp: &str) -> String {
    format!("fed-computer:{fp}")
}

fn public_half(store: &EncryptedStore, id: &str, encode: impl FnOnce(&str) -> String) -> String {
    let meta = store.meta(id).unwrap();
    let snapshot = store
        .get_snapshot(id, meta.incarnation.as_deref().unwrap())
        .unwrap();
    encode(std::str::from_utf8(snapshot.record.payload.expose()).unwrap())
}

fn roster(peer: &EncryptedStore, fp: &str, box_id: &str, pairing: &str) -> Value {
    let transfer = public_half(peer, VAULT_TRANSFER_ID, |pem| {
        credentials_core::kem::public_half(pem)
            .unwrap()
            .0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    });
    let record = public_half(peer, RECORD_KEY_ID, |pem| {
        credentials_core::signing::public_key_ed25519(pem)
            .unwrap()
            .public_key_hex
    });
    json!({
        "self": {"static_public_key_hex": "00".repeat(32)},
        "devices": [{"class": "computer", "fingerprint": fp, "pairing_id": pairing,
            "shares": [{"share": "vault", "enabled": true}]}],
        "peers": [{"class": "computer", "fingerprint": fp, "machine_id": box_id,
            "pairing_id": pairing, "key_record": {"keys": {
                "vault_transfer_x25519": {"pub": transfer},
                "fleet_record_ed25519": {"pub": record}
            }}}]
    })
}

fn answer(callosum: &SharedCallosumStandIn, body: &Value) {
    callosum.answer(TARGET_MODULE, READ, Reply::Ok(body.clone()));
    callosum.answer(TARGET_MODULE, WATCH, Reply::Watch(body.clone()));
    callosum.answer(TARGET_MODULE, KEYS, Reply::Watch(body.clone()));
}

fn login(org: &str) -> VaultRecord {
    let mut row = VaultRecord::new_oauth(
        "test",
        "anthropic",
        OAuthCredential {
            access_token: format!("test-access-{org}").into(),
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
        org_name: Some(org.into()),
        ..Default::default()
    });
    row.refresh_adapter = Some("anthropic".into());
    row
}

#[tokio::test]
async fn publishes_login_updates_and_ended_preserves_manual_copies() {
    let rig = Rig::new("hub-entries-ended").await;
    let original = rig.wait_for_login("original", PAIR).await;
    let generation = || {
        rig.member
            .hub_login_home_state(&member_id(HOME_FP))
            .unwrap()
            .unwrap()
            .generation
    };
    let initial_generation = generation();
    rig.overwrite("updated");
    let updated = rig.wait_for_login("updated", PAIR).await;
    assert_eq!(updated.incarnation, original.incarnation);
    assert!(generation() > initial_generation);

    // Seed the same manual row that a successful `ck auth remote add` commits.
    let manual = rig
        .member
        .remote_add_audited(&NewRemoteRecord {
            provider_ids: Vec::new(),
            credential_id: MANUAL.into(),
            home_member: member_id(HOME_FP),
            refresh_adapter: None,
            detected_plan: None,
            identity: RecordIdentity::default(),
            home_version: 1,
            categories: Vec::new(),
        })
        .unwrap();
    rig.home.set_login_sharing_audited(false, "test").unwrap();
    wait_until(|| rig.remote().is_none()).await;
    wait_until(|| {
        rig.home
            .list_hub_login_targets()
            .unwrap()
            .iter()
            .any(|row| {
                row.member_id == member_id(MEMBER_FP)
                    && row.kind == HubLoginKind::Ended
                    && row.delivered
                    && row.sealed_bytes.is_some()
            })
    })
    .await;
    assert_eq!(rig.member.remote_record(MANUAL).unwrap(), Some(manual));
}

#[tokio::test]
async fn outage_and_replacement_catch_up_and_an_empty_bucket_reset_keeps_the_copy() {
    let rig = Rig::new("hub-entries-outage").await;
    let original = rig.wait_for_login("original", PAIR).await;
    let version = rig.home.list_hub_login_targets().unwrap()[0].generation;
    rig.hub.set_online(false);
    rig.overwrite("written offline");
    wait_until(|| {
        rig.home
            .list_hub_login_targets()
            .unwrap()
            .iter()
            .any(|row| row.generation > version && !row.delivered)
    })
    .await;
    assert_eq!(rig.remote(), Some(original.clone()));

    rig.hub.set_online(true);
    rig.home_tasks.replace_connection();
    rig.member_tasks.replace_connection();
    let caught_up = rig.wait_for_login("written offline", PAIR).await;
    assert_eq!(caught_up.incarnation, original.incarnation);

    rig.hub.reset_shared_logins();
    assert!(!rig.hub.has_login_list(HOME_BOX, MEMBER_BOX));
    wait_until(|| rig.hub.has_login_list(HOME_BOX, MEMBER_BOX)).await;
    rig.overwrite("after reset");
    let after_reset = rig.wait_for_login("after reset", PAIR).await;
    assert_eq!(
        after_reset.incarnation, original.incarnation,
        "a reset must not remove and recreate the copy"
    );
}

#[tokio::test]
async fn re_pair_replaces_the_previous_automatic_copy() {
    let rig = Rig::new("hub-entries-re-pair").await;
    let original = rig.wait_for_login("original", PAIR).await;
    rig.re_pair().await;
    let replacement = rig.wait_for_login("original", REPAIR).await;
    assert_ne!(replacement.incarnation, original.incarnation);
    assert_eq!(rig.member.list_remote_records().unwrap(), [replacement]);
}

#[tokio::test]
async fn signed_member_manifest_report_becomes_readiness_on_the_home() {
    let rig = Rig::new("hub-entries-manifest").await;
    rig.wait_for_login("original", PAIR).await;
    rig.home
        .store_gh_manifest(
            &GhManifestVersion {
                version: 28,
                manifest_bytes: b"{}",
                manifest_sha256: MANIFEST_HASH,
                key_id: "test",
                signature: &[7; 64],
                signed_at_ms: 1,
                source: GhManifestSource::Import,
                approval_audit_seq: None,
            },
            AuditCtx::admin(AuditOp::GhManifestStore),
        )
        .unwrap();
    let report =
        json!({"version": 28, "payload_sha256": MANIFEST_HASH, "verdict": "valid", "reason": null});
    assert_eq!(
        record_manifest_report(&rig.home, &member_id(HOME_FP), &report)["status"],
        "recorded"
    );
    let status = || rig.home.gh_manifest_active_status(28).unwrap().unwrap();
    assert!(!status().ready);
    assert_eq!(
        record_manifest_report(&rig.member, &member_id(MEMBER_FP), &report)["status"],
        "recorded"
    );
    wait_until(|| status().ready).await;
    let member = status()
        .computers
        .into_iter()
        .find(|row| row.member_id == member_id(MEMBER_FP))
        .unwrap();
    assert_eq!(member.version, Some(28));
}

#[tokio::test]
async fn a_confirmed_unpair_removes_automatic_copies_while_the_hub_is_unreachable() {
    let mut rig = Rig::new("hub-entries-cold-unpair").await;
    rig.wait_for_login("original", PAIR).await;
    let manual = rig
        .member
        .remote_add_audited(&NewRemoteRecord {
            provider_ids: Vec::new(),
            credential_id: MANUAL.into(),
            home_member: member_id(HOME_FP),
            refresh_adapter: None,
            detected_plan: None,
            identity: RecordIdentity::default(),
            home_version: 1,
            categories: Vec::new(),
        })
        .unwrap();
    // Restart the member's tasks with its hub connection still pending.
    let first = Held::new();
    rig.member_callosum
        .answer(TARGET_MODULE, READ, Reply::Hold(first.clone()));
    let (tasks, connect) = rig.hub.start_vault_pending(
        Arc::clone(&rig.member),
        rig.member_outbound.clone(),
        MEMBER_BOX,
    );
    rig.member_tasks = tasks;
    first.arrived().await;
    let second = Held::new();
    rig.member_callosum
        .answer(TARGET_MODULE, READ, Reply::Hold(second.clone()));
    first.release(Reply::RetrySafe("fed_target_unavailable".into()));
    second.arrived().await;
    // An unavailable feed proves nothing: both copies remain.
    assert!(rig.remote().is_some());
    assert_eq!(
        rig.member.remote_record(MANUAL).unwrap(),
        Some(manual.clone())
    );
    // Callosum then confirms that the home is no longer paired.
    let unpaired = json!({"self": {"static_public_key_hex": "00".repeat(32)},
        "devices": [], "peers": []});
    answer(&rig.member_callosum, &unpaired);
    second.release(Reply::Ok(unpaired));
    wait_until(|| rig.remote().is_none()).await;
    assert_eq!(rig.member.remote_record(MANUAL).unwrap(), Some(manual));
    // The hub never connected.
    drop(connect);
}
