use std::sync::Arc;

use claustrum_module_probe::federation::{member_watch, sharing};
use credentials_core::federation::{NewRemoteRecord, RemoteHomeState, RemoteRecordSource};
use serde_json::{json, Value};
use tokio::sync::watch;

use crate::support::{wait_for_signal, wait_until, HomeStore, Reply, TwoVaults};

const FP: &str = "aa11bb22cc33dd44ee55ff6600112233";
const HOME: &str = "fed-computer:aa11bb22cc33dd44ee55ff6600112233";
const TARGET: &str = "fed:aa11bb22cc33dd44ee55ff6600112233:claustrum";
const OP: &str = "federation.remote_watch";

fn login(id: &str) -> Value {
    json!({"credential_id": id, "state": "needs_reauth", "refresh_adapter": "openai",
        "identity": {"account_id": "account"}, "categories": ["llm-provider"],
        "detected_plan": {"tier": "pro", "raw": "pro", "observed_at_ms": 42},
        "home_version": 7})
}

fn notice(rows: Vec<Value>) -> Value {
    json!({"kind": "snapshot", "home": HOME, "epoch": "ab".repeat(16), "seq": 1, "logins": rows})
}

fn paired() -> member_watch::PairedComputers {
    Some(vec![(FP.into(), "pair-a".into())])
}

struct Rig {
    vaults: TwoVaults,
    home: HomeStore,
    pairings: watch::Sender<member_watch::PairedComputers>,
    join: tokio::task::JoinHandle<()>,
    _root: credentials_core::test_support::TestTempDir,
}

impl Rig {
    async fn new(name: &str, reply: Reply) -> Self {
        let root = crate::support::temp_root(name);
        let vaults = TwoVaults::new(&root).await;
        let home = HomeStore::open(&vaults.b.data_dir);
        vaults.callosum.answer("claustrum", OP, reply);
        let (pairings, rx) = watch::channel(None);
        let join = tokio::spawn(member_watch::run(
            Arc::clone(&home.store),
            vaults.b.outbound.clone(),
            rx,
        ));
        Self {
            vaults,
            home,
            pairings,
            join,
            _root: root,
        }
    }

    async fn row(&self, id: &str) {
        wait_until(|| self.home.store.remote_record(id).unwrap().is_some()).await;
    }

    fn requests(&self) -> usize {
        self.vaults
            .callosum
            .methods(TARGET)
            .iter()
            .filter(|m| *m == OP)
            .count()
    }

    async fn stop(self) {
        drop(self.pairings);
        wait_for_signal(self.join).await.unwrap();
    }
}

#[tokio::test]
async fn member_watch_applies_full_snapshots_and_preserves_invalid_and_colliding_rows() {
    let rig = Rig::new(
        "member-full",
        Reply::Watch(notice(vec![login("oauth:x"), login("oauth:gone")])),
    )
    .await;
    rig.pairings.send_replace(paired());
    rig.row("oauth:gone").await;
    let before = rig.home.store.remote_record("oauth:x").unwrap().unwrap();
    assert_eq!(before.source, RemoteRecordSource::HomeWatch);
    assert_eq!(before.home_pairing_id.as_deref(), Some("pair-a"));
    assert_eq!(before.home_member, HOME);
    assert_eq!(before.last_home_state, RemoteHomeState::NeedsReauth);
    assert_eq!(before.last_home_version, 7);
    assert_eq!(
        rig.vaults.callosum.harnesses(TARGET),
        ["claustrum-outbound"]
    );
    assert!(rig
        .vaults
        .callosum
        .opens(TARGET)
        .iter()
        .all(|open| open["consumer_identity"]["module_id"] == "claustrum"
            && open["consumer_identity"]["launch_nonce"] == "harness-launch-nonce"));
    assert!(rig
        .vaults
        .callosum
        .opens(TARGET)
        .iter()
        .all(|open| open.get("scope").is_none()));
    rig.home
        .store
        .remote_add_audited(&NewRemoteRecord {
            credential_id: "oauth:operator".into(),
            home_member: HOME.into(),
            refresh_adapter: None,
            identity: Default::default(),
            categories: vec![],
            detected_plan: None,
            home_version: 1,
        })
        .unwrap();
    let operator = rig
        .home
        .store
        .remote_record("oauth:operator")
        .unwrap()
        .unwrap();
    let mut invalid = login("oauth:x");
    invalid["categories"] = json!(["not a category"]);
    let mut updated = login("oauth:new");
    updated["state"] = json!("active");
    updated["future"] = json!({"ignored": true});
    let mut snapshot = notice(vec![invalid, updated, login("oauth:operator")]);
    snapshot["future"] = json!(true);
    assert_eq!(rig.vaults.callosum.watch_snapshot(Some(snapshot)).await, 1);
    rig.row("oauth:new").await;
    assert_eq!(
        rig.home.store.remote_record("oauth:x").unwrap().unwrap(),
        before
    );
    assert_eq!(
        rig.home
            .store
            .remote_record("oauth:operator")
            .unwrap()
            .unwrap(),
        operator
    );
    assert!(rig
        .home
        .store
        .remote_record("oauth:gone")
        .unwrap()
        .is_none());
    let mut update = login("oauth:new");
    update["categories"] = json!(["changed"]);
    update["refresh_adapter"] = json!("anthropic");
    let installed = rig.home.store.remote_record("oauth:new").unwrap().unwrap();
    rig.vaults
        .callosum
        .watch_snapshot(Some(notice(vec![update])))
        .await;
    wait_until(|| rig.home.store.categories("oauth:new").unwrap() == ["changed"]).await;
    let after = rig.home.store.remote_record("oauth:new").unwrap().unwrap();
    assert_eq!(after.incarnation, installed.incarnation);
    assert_eq!(after.refresh_adapter.as_deref(), Some("anthropic"));
    rig.stop().await;
}

#[tokio::test]
async fn member_watch_retries_bad_notices_clean_end_and_disconnect_without_deleting() {
    let rig = Rig::new("member-retry", Reply::Watch(notice(vec![login("oauth:x")]))).await;
    rig.pairings.send_replace(paired());
    rig.row("oauth:x").await;
    let before = rig.home.store.remote_record("oauth:x").unwrap().unwrap();
    let audit = rig.home.store.read_audit(None).unwrap();
    let mut wrong_home = notice(vec![]);
    wrong_home["home"] = json!("fed-computer:11223344556677889900112233445566");
    for broken in [wrong_home, json!({"kind": "snapshot"})] {
        let count = rig.requests();
        rig.vaults.callosum.watch_snapshot(Some(broken)).await;
        wait_until(|| rig.vaults.callosum.cancelled_watches() > 0).await;
        rig.pairings.send_replace(paired());
        wait_until(|| rig.requests() > count).await;
    }
    let count = rig.requests();
    rig.vaults.callosum.watch_snapshot(None).await;
    rig.pairings.send_replace(paired());
    wait_until(|| rig.requests() > count).await;
    rig.vaults.callosum.close_connections(false).await;
    rig.pairings.send_replace(paired());
    wait_until(|| rig.requests() > count + 1).await;
    assert_eq!(
        rig.home.store.remote_record("oauth:x").unwrap().unwrap(),
        before
    );
    assert_eq!(rig.home.store.read_audit(None).unwrap(), audit);
    rig.stop().await;
}

#[tokio::test]
async fn member_watch_all_non_authoritative_refusals_retry_on_paired_snapshot() {
    for (index, reply) in [
        Reply::Permanent("unknown_operation".into()),
        Reply::Permanent("fed_not_exposed".into()),
        Reply::Permanent("fed_limits_unsupported".into()),
        Reply::Permanent("fed_claim_unsupported".into()),
        Reply::Ok(json!({"error": {"code": "home_unavailable"}})),
        Reply::SubscriptionError {
            channel_zero: false,
            body: json!({"code": "module_error", "detail": {"code": "store_error"}}),
        },
        Reply::SubscriptionError {
            channel_zero: false,
            body: json!({"code": "fed_subscription_ended", "detail": {"reason": "draining"}}),
        },
    ]
    .into_iter()
    .enumerate()
    {
        let rig = Rig::new(&format!("member-refusal-{index}"), reply).await;
        rig.pairings.send_replace(paired());
        wait_until(|| rig.requests() == 1).await;
        rig.vaults
            .callosum
            .reply_fence(&rig.vaults.b.outbound)
            .await;
        rig.vaults.callosum.answer(
            "claustrum",
            OP,
            Reply::Watch(notice(vec![login("oauth:recovered")])),
        );
        rig.pairings.send_replace(paired());
        rig.row("oauth:recovered").await;
        assert_eq!(rig.requests(), 2);
        rig.stop().await;
    }
}

#[tokio::test]
async fn member_watch_sharing_fanout_uses_all_computers_and_rejects_whole_bad_inventory() {
    let rig = Rig::new(
        "member-fanout",
        Reply::Watch(notice(vec![login("oauth:x")])),
    )
    .await;
    let mut body = json!({"self": {"static_public_key_hex": "ab".repeat(32)}, "devices": [
        {"class": "computer", "fingerprint": FP, "pairing_id": "pair-a", "shares": []},
        {"class": "phone", "fingerprint": "cd".repeat(16), "pairing_id": "phone", "shares": []}
    ]});
    rig.vaults.callosum.answer(
        "claustrum",
        "callosum.paired_devices_read",
        Reply::Ok(body.clone()),
    );
    rig.vaults.callosum.answer(
        "claustrum",
        "callosum.paired_devices_watch",
        Reply::Watch(body.clone()),
    );
    let sharing = tokio::spawn(sharing::run_with_reconcilers(
        Arc::clone(&rig.home.store),
        rig.vaults.b.outbound.clone(),
        None,
        Some(rig.pairings.clone()),
    ));
    rig.row("oauth:x").await;
    assert_eq!(rig.pairings.borrow().as_ref().unwrap().len(), 1);
    assert_eq!(rig.requests(), 1);
    body["devices"][0]["fingerprint"] = json!("malformed");
    assert!(sharing::decode_snapshot(&body).is_none());
    rig.vaults.callosum.answer(
        "claustrum",
        "callosum.paired_devices_read",
        Reply::Ok(body.clone()),
    );
    rig.vaults.callosum.watch_snapshot(Some(body)).await;
    rig.vaults
        .callosum
        .reply_fence(&rig.vaults.b.outbound)
        .await;
    assert_eq!(*rig.pairings.borrow(), paired());
    sharing.abort();
    let _ = sharing.await;
    rig.stop().await;
}

#[tokio::test]
async fn member_watch_owns_one_task_per_pair_and_routes_homes_independently() {
    let rig = Rig::new(
        "member-pair-tasks",
        Reply::Watch(notice(vec![login("oauth:x")])),
    )
    .await;
    rig.pairings.send_replace(paired());
    rig.row("oauth:x").await;
    let before = rig.home.store.remote_record("oauth:x").unwrap().unwrap();
    let c = "11223344556677889900112233445566";
    let target_c = format!("fed:{c}:claustrum");
    rig.pairings.send_replace(Some(vec![
        (FP.into(), "pair-a".into()),
        (c.into(), "pair-c".into()),
    ]));
    wait_until(|| {
        rig.vaults
            .callosum
            .methods(&target_c)
            .iter()
            .any(|m| m == OP)
    })
    .await;
    assert_eq!(
        rig.requests(),
        1,
        "same-pair inventory updates do not duplicate a live stream"
    );
    rig.pairings.send_replace(Some(vec![]));
    wait_until(|| rig.vaults.callosum.cancelled_watches() >= 2).await;
    assert_eq!(
        rig.home.store.remote_record("oauth:x").unwrap().unwrap(),
        before,
        "lost pairing keeps rows until authoritative removal is implemented"
    );
    rig.pairings
        .send_replace(Some(vec![(FP.into(), "pair-new".into())]));
    wait_until(|| rig.requests() == 2).await;
    assert_eq!(
        rig.home.store.remote_record("oauth:x").unwrap().unwrap(),
        before,
        "old pairing rows are not overwritten by the new task"
    );
    rig.stop().await;
}
