use std::{sync::Arc, time::Duration};

use claustrum_module_probe::federation::{member_watch, sharing};
use credentials_core::federation::{
    NewRemoteRecord, RemoteHomeState, RemoteRecordSource, RemoteWatchApplyMode, RemoteWatchRow,
};
use serde_json::{json, Value};
use subc_protocol::FrameType;
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

fn seed(rig: &Rig, home: &str, pairing: &str, id: &str) {
    rig.home
        .store
        .remote_watch_apply_audited(
            home,
            pairing,
            &[RemoteWatchRow {
                credential_id: id.into(),
                state: RemoteHomeState::NeedsReauth,
                refresh_adapter: Some("openai".into()),
                identity: Default::default(),
                categories: vec!["llm-provider".into()],
                detected_plan: None,
                home_version: 1,
            }],
            RemoteWatchApplyMode::Full,
            &[],
        )
        .unwrap();
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
    let installed = rig.home.store.remote_record("oauth:x").unwrap().unwrap();
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
    assert_eq!(
        rig.home.store.remote_record("oauth:x").unwrap().unwrap(),
        installed,
        "a rejected paired-devices snapshot must not change installed rows"
    );
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
    wait_until(|| rig.home.store.remote_record("oauth:x").unwrap().is_none()).await;
    rig.pairings
        .send_replace(Some(vec![(FP.into(), "pair-new".into())]));
    wait_until(|| rig.requests() == 2).await;
    rig.row("oauth:x").await;
    let after = rig.home.store.remote_record("oauth:x").unwrap().unwrap();
    assert_eq!(after.home_pairing_id.as_deref(), Some("pair-new"));
    assert_ne!(after.incarnation, before.incarnation);
    rig.stop().await;
}

#[tokio::test]
async fn member_watch_first_inventory_cleans_persisted_pairings_before_open() {
    let rig = Rig::new(
        "member-startup-cleanup",
        Reply::Watch(notice(vec![login("oauth:x")])),
    )
    .await;
    seed(&rig, HOME, "old-pair", "oauth:x");
    let before = rig.home.store.remote_record("oauth:x").unwrap().unwrap();
    let absent = "fed-computer:11223344556677889900112233445566";
    seed(&rig, absent, "absent-pair", "oauth:absent");
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
    rig.pairings.send_replace(paired());
    wait_until(|| {
        rig.home
            .store
            .remote_record("oauth:x")
            .unwrap()
            .is_some_and(|r| r.home_pairing_id.as_deref() == Some("pair-a"))
    })
    .await;
    let after = rig.home.store.remote_record("oauth:x").unwrap().unwrap();
    assert_ne!(after.incarnation, before.incarnation);
    assert!(rig
        .home
        .store
        .remote_record("oauth:absent")
        .unwrap()
        .is_none());
    assert_eq!(
        rig.home
            .store
            .remote_record("oauth:operator")
            .unwrap()
            .unwrap(),
        operator
    );
    assert_eq!(rig.requests(), 1);
    rig.stop().await;
}

fn authoritative_endings() -> Vec<(FrameType, Value)> {
    vec![
        (
            FrameType::Error,
            json!({"code":"not_found","message":"not found","detail":{"class":"permanent"}}),
        ),
        (
            FrameType::Error,
            json!({"code": "fed_subscription_ended", "detail": {"reason": "revoked"}}),
        ),
        (
            FrameType::Error,
            json!({"code": "fed_subscription_ended", "detail": {"reason": "not_exposed"}, "message": "remote subscription ended"}),
        ),
    ]
}

#[tokio::test(start_paused = true)]
async fn member_watch_authoritative_open_refusals_remove_and_recover_without_inventory_event() {
    for (index, (_, body)) in authoritative_endings().into_iter().enumerate() {
        let reply = Reply::SubscriptionError {
            channel_zero: index == 2,
            body,
        };
        let rig = Rig::new(&format!("member-open-removal-{index}"), reply).await;
        seed(&rig, HOME, "pair-a", "oauth:old");
        rig.pairings.send_replace(paired());
        wait_until(|| rig.home.store.remote_record("oauth:old").unwrap().is_none()).await;
        rig.vaults.callosum.answer(
            "claustrum",
            OP,
            Reply::Watch(notice(vec![login("oauth:recovered")])),
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        rig.row("oauth:recovered").await;
        assert_eq!(rig.requests(), 2, "one timed retry after removal");
        rig.stop().await;
    }
}

#[tokio::test(start_paused = true)]
async fn member_watch_authoritative_terminal_drops_failed_apply_until_a_new_stream_snapshot() {
    for (index, (kind, body)) in authoritative_endings().into_iter().enumerate() {
        let rig = Rig::new(
            &format!("member-terminal-removal-{index}"),
            Reply::Watch(notice(vec![login("oauth:old")])),
        )
        .await;
        rig.pairings.send_replace(paired());
        rig.row("oauth:old").await;
        let sql = rusqlite::Connection::open(rig.vaults.b.store_path()).unwrap();
        sql.execute_batch("CREATE TRIGGER fail_member_apply BEFORE INSERT ON audit_log WHEN NEW.op = 'remote_add' BEGIN SELECT RAISE(ABORT, 'apply unavailable'); END;").unwrap();
        assert_eq!(
            rig.vaults
                .callosum
                .watch_frame(
                    TARGET,
                    FrameType::StreamData,
                    notice(vec![login("oauth:failed")])
                )
                .await,
            1
        );
        rig.vaults.callosum.answer("claustrum", OP, Reply::Stall);
        assert_eq!(rig.vaults.callosum.watch_frame(TARGET, kind, body).await, 1);
        wait_until(|| rig.home.store.remote_record("oauth:old").unwrap().is_none()).await;
        sql.execute_batch("DROP TRIGGER fail_member_apply").unwrap();
        tokio::time::advance(Duration::from_secs(2)).await;
        wait_until(|| rig.requests() == 2).await;
        assert!(
            rig.home
                .store
                .remote_record("oauth:failed")
                .unwrap()
                .is_none(),
            "the failed snapshot was discarded, not retried after removal"
        );
        rig.vaults.callosum.answer(
            "claustrum",
            OP,
            Reply::Watch(notice(vec![login("oauth:failed")])),
        );
        wait_for_signal(rig.vaults.callosum.goodbye_routes(TARGET)).await;
        rig.pairings.send_replace(paired());
        rig.row("oauth:failed").await;
        rig.stop().await;
    }
}

#[tokio::test]
async fn member_watch_collision_replay_inserts_only_skipped_rows_and_fences_repair() {
    let c = "11223344556677889900112233445566";
    let home_c = format!("fed-computer:{c}");
    let target_c = format!("fed:{c}:claustrum");
    let mut c_snapshot = notice(vec![login("oauth:x")]);
    c_snapshot["home"] = json!(home_c);
    let rig = Rig::new("member-collision-replay", Reply::Watch(c_snapshot.clone())).await;
    rig.pairings
        .send_replace(Some(vec![(c.into(), "pair-c".into())]));
    rig.row("oauth:x").await;
    rig.vaults.callosum.answer(
        "claustrum",
        OP,
        Reply::Watch(notice(vec![login("oauth:x"), login("oauth:y")])),
    );
    rig.pairings.send_replace(Some(vec![
        (c.into(), "pair-c".into()),
        (FP.into(), "pair-a".into()),
    ]));
    rig.row("oauth:y").await;
    let y = rig.home.store.remote_record("oauth:y").unwrap().unwrap();
    // The read path owns this status after insert; replaying Full would overwrite
    // its status with the older needs_reauth snapshot.
    rig.home
        .store
        .remote_record_apply_home_state(
            "oauth:y",
            &y.incarnation,
            RemoteHomeState::Corrupt,
            "corrupt",
        )
        .unwrap();
    let y = rig.home.store.remote_record("oauth:y").unwrap().unwrap();
    c_snapshot["logins"] = json!([]);
    assert_eq!(
        rig.vaults
            .callosum
            .watch_frame(&target_c, FrameType::StreamData, c_snapshot)
            .await,
        1
    );
    wait_until(|| {
        rig.home
            .store
            .remote_record("oauth:x")
            .unwrap()
            .is_some_and(|r| r.home_member == HOME)
    })
    .await;
    assert_eq!(
        rig.home.store.remote_record("oauth:y").unwrap().unwrap(),
        y,
        "InsertOnly never updates an installed row"
    );

    // C now skips X. The empty snapshot sent to TARGET frees X and wakes C
    // while C changes pairing.
    let mut c_snapshot = notice(vec![login("oauth:x"), login("oauth:z")]);
    c_snapshot["home"] = json!(home_c);
    rig.vaults
        .callosum
        .watch_frame(&target_c, FrameType::StreamData, c_snapshot.clone())
        .await;
    rig.row("oauth:z").await;
    let z = rig.home.store.remote_record("oauth:z").unwrap().unwrap();
    rig.vaults
        .callosum
        .answer("claustrum", OP, Reply::Watch(c_snapshot));
    rig.vaults
        .callosum
        .watch_frame(TARGET, FrameType::StreamData, notice(vec![]))
        .await;
    rig.pairings.send_replace(Some(vec![
        (c.into(), "pair-c-new".into()),
        (FP.into(), "pair-a".into()),
    ]));
    wait_until(|| {
        rig.home
            .store
            .remote_record("oauth:x")
            .unwrap()
            .is_some_and(|r| {
                r.home_member == home_c && r.home_pairing_id.as_deref() == Some("pair-c-new")
            })
    })
    .await;
    wait_until(|| {
        rig.home
            .store
            .remote_record("oauth:z")
            .unwrap()
            .is_some_and(|r| r.home_pairing_id.as_deref() == Some("pair-c-new"))
    })
    .await;
    assert_ne!(
        rig.home
            .store
            .remote_record("oauth:z")
            .unwrap()
            .unwrap()
            .incarnation,
        z.incarnation
    );
    assert!(rig
        .home
        .store
        .list_remote_records()
        .unwrap()
        .iter()
        .all(|r| r.home_member != home_c || r.home_pairing_id.as_deref() == Some("pair-c-new")));
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn member_resilience_unknown_operation_open_keeps_existing_rows() {
    let rig = Rig::new(
        "resilience-unknown-op",
        Reply::Watch(notice(vec![login("oauth:x")])),
    )
    .await;
    rig.pairings.send_replace(paired());
    rig.row("oauth:x").await;
    let before = rig.home.store.remote_record("oauth:x").unwrap().unwrap();
    let audit = rig.home.store.read_audit(None).unwrap();
    // The live stream ends cleanly so the next open is the unknown-operation
    // refusal. That local refusal must not be treated as revocation.
    rig.vaults.callosum.answer(
        "claustrum",
        OP,
        Reply::Permanent("unknown_operation".into()),
    );
    assert_eq!(rig.vaults.callosum.watch_snapshot(None).await, 1);
    assert_eq!(
        rig.home.store.remote_record("oauth:x").unwrap().unwrap(),
        before
    );
    let count = rig.requests();
    rig.pairings.send_replace(paired());
    wait_until(|| rig.requests() > count).await;
    assert_eq!(
        rig.home.store.remote_record("oauth:x").unwrap().unwrap(),
        before
    );
    assert_eq!(rig.home.store.read_audit(None).unwrap(), audit);
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn member_resilience_switch_off_and_on_restores_rows_without_another_event() {
    let rig = Rig::new(
        "resilience-switch",
        Reply::Watch(notice(vec![login("oauth:x")])),
    )
    .await;
    rig.pairings.send_replace(paired());
    rig.row("oauth:x").await;
    let revoked = json!({"code": "fed_subscription_ended", "detail": {"reason": "revoked"}});
    assert_eq!(
        rig.vaults
            .callosum
            .watch_frame(TARGET, FrameType::Error, revoked)
            .await,
        1
    );
    wait_until(|| rig.home.store.remote_record("oauth:x").unwrap().is_none()).await;
    // The switch coming back is not a paired-devices event on B. Only the
    // backoff timer may reopen.
    rig.vaults.callosum.answer(
        "claustrum",
        OP,
        Reply::Watch(notice(vec![login("oauth:x")])),
    );
    let opens = rig.requests();
    tokio::time::advance(Duration::from_secs(1)).await;
    rig.row("oauth:x").await;
    assert_eq!(
        rig.requests(),
        opens + 1,
        "one timed retry, no inventory wake"
    );
    let restored = rig.home.store.remote_record("oauth:x").unwrap().unwrap();
    assert_eq!(restored.source, RemoteRecordSource::HomeWatch);
    assert_eq!(restored.home_member, HOME);
    assert_eq!(restored.home_pairing_id.as_deref(), Some("pair-a"));
    assert_eq!(restored.last_home_state, RemoteHomeState::NeedsReauth);
    rig.stop().await;
}

#[tokio::test]
async fn member_resilience_repair_during_home_removal_installs_the_new_snapshot() {
    let c = "11223344556677889900112233445566";
    let home_c = format!("fed-computer:{c}");
    let mut c_snapshot = notice(vec![login("oauth:x"), login("oauth:y")]);
    c_snapshot["home"] = json!(home_c);
    let rig = Rig::new(
        "resilience-repair-replay",
        Reply::Watch(notice(vec![login("oauth:x")])),
    )
    .await;
    rig.pairings
        .send_replace(Some(vec![(FP.into(), "pair-h".into())]));
    rig.row("oauth:x").await;
    assert_eq!(
        rig.home
            .store
            .remote_record("oauth:x")
            .unwrap()
            .unwrap()
            .home_member,
        HOME
    );
    rig.vaults
        .callosum
        .answer("claustrum", OP, Reply::Watch(c_snapshot));
    rig.pairings.send_replace(Some(vec![
        (FP.into(), "pair-h".into()),
        (c.into(), "pair-c".into()),
    ]));
    rig.row("oauth:y").await;
    assert_eq!(
        rig.home
            .store
            .remote_record("oauth:x")
            .unwrap()
            .unwrap()
            .home_member,
        HOME,
        "C skips X while H's home_watch row holds it"
    );
    let mut renewed = notice(vec![login("oauth:x"), login("oauth:y"), login("oauth:z")]);
    renewed["home"] = json!(home_c);
    rig.vaults
        .callosum
        .answer("claustrum", OP, Reply::Watch(renewed));
    // H leaving frees X and signals C's InsertOnly. Wait until that removal
    // has committed before changing C, so the re-pair is not coalesced away.
    rig.pairings
        .send_replace(Some(vec![(c.into(), "pair-c".into())]));
    wait_until(|| {
        let row = rig.home.store.remote_record("oauth:x").unwrap();
        row.is_none() || row.is_some_and(|record| record.home_member == home_c)
    })
    .await;
    rig.pairings
        .send_replace(Some(vec![(c.into(), "pair-c-new".into())]));
    wait_until(|| {
        let rows = rig.home.store.list_remote_records().unwrap();
        ["oauth:x", "oauth:y", "oauth:z"].iter().all(|id| {
            rows.iter().any(|row| {
                row.credential_id == *id
                    && row.home_member == home_c
                    && row.home_pairing_id.as_deref() == Some("pair-c-new")
            })
        })
    })
    .await;
    let rows = rig.home.store.list_remote_records().unwrap();
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|row| {
        row.home_member == home_c && row.home_pairing_id.as_deref() == Some("pair-c-new")
    }));
    rig.stop().await;
}
