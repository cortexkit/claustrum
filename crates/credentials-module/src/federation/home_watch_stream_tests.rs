use super::home_watch_open_tests::{body, open, paired, setup};
use super::home_watch_projection_tests::{login, rig};
use super::*;
use subc_protocol::FrameType;
use tokio::sync::mpsc;

const MEMBER: &str = "fed-computer:aa11bb22cc33dd44ee55ff6600112233";
const ID: &str = "oauth:stream";
const COALESCE: Duration = Duration::from_millis(250);

fn seed(home: &HomeVault) -> VaultRecord {
    setup(home);
    let store = home.engine.store();
    store
        .set_federation_member_mapping_audited(true, AuditCtx::admin(AuditOp::FederationGateSet))
        .unwrap();
    let mut record = login();
    record.refresh_adapter = Some("openai".into());
    store.create(ID, &record).unwrap();
    grant(home);
    record
}

fn grant(home: &HomeVault) {
    home.engine
        .store()
        .create_member_grant_audited(
            MEMBER,
            MemberGrantOperation::RemoteRead,
            &MemberGrantSelector::Exact(ID.into()),
            "pair-1",
        )
        .unwrap();
}

fn overwrite(home: &HomeVault, record: &VaultRecord) {
    home.engine
        .store()
        .overwrite_unconditional_audited(ID, record, AuditCtx::admin(AuditOp::Put))
        .unwrap();
}

async fn cycle(home: &HomeVault) {
    home.remote_watches.waking.notified().await;
    tokio::time::advance(COALESCE).await;
    home.remote_watches.refreshed.notified().await;
}

#[tokio::test(start_paused = true)]
async fn remote_watch_stream_idle_four_windows_never_writes_or_emits() {
    let (_root, home, _conn) = rig();
    let home = paired(home);
    seed(&home);
    let writes = home.engine.store().subscribe_writes();
    let (writer, mut rx) = mpsc::channel(16);
    open(&home, &writer, 1, 1, MEMBER, json!({})).await;
    assert_eq!(
        body(rx.try_recv().unwrap(), FrameType::StreamData)["seq"],
        1
    );
    for _ in 0..4 {
        tokio::time::advance(COALESCE).await;
        assert!(rx.try_recv().is_err());
        assert!(!writes.has_changed().unwrap());
        assert_eq!(home.remote_watches.entry_count(), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn remote_watch_stream_suppresses_refresh_and_plan_observation_then_coalesces_current_rows() {
    let (_root, home, _conn) = rig();
    let home = paired(home);
    let mut record = seed(&home);
    let (writer, mut rx) = mpsc::channel(16);
    open(&home, &writer, 1, 1, MEMBER, json!({})).await;
    let first = body(rx.try_recv().unwrap(), FrameType::StreamData);

    record.oauth.as_mut().unwrap().access_token = "new-private-access".to_owned().into();
    overwrite(&home, &record);
    cycle(&home).await;
    assert!(
        rx.try_recv().is_err(),
        "a refresh changes no projected field"
    );
    record.detected_plan.as_mut().unwrap().observed_at_ms = 999;
    overwrite(&home, &record);
    cycle(&home).await;
    assert!(
        rx.try_recv().is_err(),
        "observation time alone is not a change"
    );

    home.engine
        .store()
        .set_categories_audited(
            ID,
            credentials_core::store::SetCategoryMode::Set,
            &["llm-provider".into()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
    home.remote_watches.waking.notified().await;
    tokio::time::advance(COALESCE - Duration::from_millis(1)).await;
    assert!(rx.try_recv().is_err());
    record.identity.org_name = Some("updated-workspace".into());
    overwrite(&home, &record);
    tokio::time::advance(Duration::from_millis(1)).await;
    home.remote_watches.refreshed.notified().await;
    let next = body(rx.try_recv().unwrap(), FrameType::StreamData);
    assert_eq!(next["seq"], 2);
    assert_eq!(next["epoch"], first["epoch"]);
    assert_eq!(next["logins"][0]["categories"], json!(["llm-provider"]));
    assert_eq!(
        next["logins"][0]["identity"]["org_name"],
        "updated-workspace"
    );
    assert_eq!(next["logins"][0]["detected_plan"]["observed_at_ms"], 999);
    assert_eq!(
        next["logins"][0]["home_version"],
        home.engine.store().meta(ID).unwrap().record_version
    );
    assert!(rx.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn remote_watch_stream_grant_narrowing_is_empty_snapshot_but_gate_off_is_terminal() {
    let (_root, home, _conn) = rig();
    let home = paired(home);
    seed(&home);
    let (writer, mut rx) = mpsc::channel(16);
    open(&home, &writer, 1, 1, MEMBER, json!({})).await;
    rx.try_recv().unwrap();
    home.engine
        .store()
        .revoke_member_grant_audited(
            MEMBER,
            MemberGrantOperation::RemoteRead,
            &MemberGrantSelector::Exact(ID.into()),
        )
        .unwrap();
    cycle(&home).await;
    let smaller = body(rx.try_recv().unwrap(), FrameType::StreamData);
    assert_eq!(smaller["seq"], 2);
    assert_eq!(smaller["logins"], json!([]));
    assert_eq!(home.remote_watches.entry_count(), 1);
    grant(&home);
    cycle(&home).await;
    assert_eq!(
        body(rx.try_recv().unwrap(), FrameType::StreamData)["seq"],
        3
    );
    home.engine
        .store()
        .set_federation_member_mapping_audited(false, AuditCtx::admin(AuditOp::FederationGateSet))
        .unwrap();
    cycle(&home).await;
    assert_eq!(
        body(rx.try_recv().unwrap(), FrameType::Response),
        json!({"result":{"error":{"code":"not_found","class":"permanent"}}})
    );
    assert_eq!(home.remote_watches.entry_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn remote_watch_stream_store_and_gate_failures_retain_last_list_and_retry_on_timer() {
    for table in ["member_grants", "settings"] {
        let (_root, home, conn) = rig();
        let home = paired(home);
        let mut record = seed(&home);
        let (writer, mut rx) = mpsc::channel(16);
        open(&home, &writer, 1, 1, MEMBER, json!({})).await;
        rx.try_recv().unwrap();
        conn.execute(&format!("ALTER TABLE {table} RENAME TO unavailable"), [])
            .unwrap();
        record.identity.account_id = Some("changed-account".into());
        overwrite(&home, &record);
        cycle(&home).await;
        assert!(rx.try_recv().is_err());
        assert_eq!(home.remote_watches.entry_count(), 1);
        conn.execute(&format!("ALTER TABLE unavailable RENAME TO {table}"), [])
            .unwrap();
        // Restoring the table sends no store-write notification; the timer must retry.
        tokio::time::advance(Duration::from_secs(60)).await;
        cycle(&home).await;
        let next = body(rx.try_recv().unwrap(), FrameType::StreamData);
        assert_eq!(next["seq"], 2);
        assert_eq!(
            next["logins"][0]["identity"]["account_id"],
            "changed-account"
        );
        home.remote_watches.close(1);
    }
}

#[tokio::test(start_paused = true)]
async fn remote_watch_stream_pairing_snapshot_ends_without_a_store_write() {
    for devices in [
        vec![],
        vec![(
            MEMBER.strip_prefix("fed-computer:").unwrap().to_owned(),
            "pair-2".into(),
        )],
    ] {
        let (_root, home, _conn) = rig();
        let home = paired(home);
        seed(&home);
        // A snapshot from before the open is not evidence of a change since it opened.
        home.remote_watches.paired_devices(vec![]);
        let (writer, mut rx) = mpsc::channel(16);
        open(&home, &writer, 1, 1, MEMBER, json!({})).await;
        rx.try_recv().unwrap();
        let writes = home.engine.store().subscribe_writes();
        tokio::time::advance(Duration::from_secs(60)).await;
        cycle(&home).await;
        assert!(
            rx.try_recv().is_err(),
            "no new decoded snapshot keeps the open pairing"
        );
        let decoded_at = tokio::time::Instant::now();
        home.remote_watches.paired_devices(devices);
        cycle(&home).await;
        assert_eq!(
            body(rx.try_recv().unwrap(), FrameType::Response),
            json!({"result":{"error":{"code":"not_found","class":"permanent"}}})
        );
        assert!(tokio::time::Instant::now() - decoded_at <= Duration::from_secs(1));
        assert!(!writes.has_changed().unwrap());
        assert_eq!(home.remote_watches.entry_count(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn remote_watch_stream_budget_overrun_is_silent_and_retries_on_next_wake() {
    let (_root, home, _conn) = rig();
    let home = paired(home);
    let mut record = seed(&home);
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let gate: IssueAuditGate = {
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        Arc::new(move || {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            Box::pin(async move {
                entered.notify_one();
                release.notified().await;
            })
        })
    };
    assert!(home.remote_watches.before_projection.set(gate).is_ok());
    let (writer, mut rx) = mpsc::channel(16);
    open(&home, &writer, 1, 1, MEMBER, json!({})).await;
    rx.try_recv().unwrap();
    record.refresh_adapter = Some("anthropic".into());
    overwrite(&home, &record);
    home.remote_watches.waking.notified().await;
    tokio::time::advance(COALESCE).await;
    entered.notified().await;
    tokio::time::advance(HOME_OP_DEADLINE).await;
    home.remote_watches.refreshed.notified().await;
    assert!(rx.try_recv().is_err());
    assert_eq!(home.remote_watches.entry_count(), 1);
    release.notify_one();
    home.remote_watches.paired_devices(vec![(
        MEMBER.strip_prefix("fed-computer:").unwrap().into(),
        "pair-1".into(),
    )]);
    cycle(&home).await;
    let next = body(rx.try_recv().unwrap(), FrameType::StreamData);
    assert_eq!(next["seq"], 2);
    assert_eq!(next["logins"][0]["refresh_adapter"], "anthropic");
}

#[tokio::test(start_paused = true)]
async fn remote_watch_stream_repair_interrupts_a_pending_projection() {
    let (_root, home, _conn) = rig();
    let home = paired(home);
    let mut record = seed(&home);
    let entered = Arc::new(tokio::sync::Notify::new());
    let gate: IssueAuditGate = Arc::new({
        let entered = Arc::clone(&entered);
        move || {
            let entered = Arc::clone(&entered);
            Box::pin(async move {
                entered.notify_one();
                std::future::pending().await
            })
        }
    });
    assert!(home.remote_watches.before_projection.set(gate).is_ok());
    let (writer, mut rx) = mpsc::channel(16);
    open(&home, &writer, 1, 1, MEMBER, json!({})).await;
    rx.try_recv().unwrap();
    record.identity.account_id = Some("changed-account".into());
    overwrite(&home, &record);
    home.remote_watches.waking.notified().await;
    tokio::time::advance(COALESCE).await;
    entered.notified().await;
    let decoded_at = tokio::time::Instant::now();
    home.remote_watches.paired_devices(vec![]);
    cycle(&home).await;
    assert_eq!(
        body(rx.try_recv().unwrap(), FrameType::Response)["result"]["error"]["code"],
        "not_found"
    );
    assert!(tokio::time::Instant::now() - decoded_at <= Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn remote_watch_stream_subscribes_before_first_projection_publication() {
    use std::future::{poll_fn, Future};
    use std::task::Poll;

    let (_root, home, _conn) = rig();
    let home = paired(home);
    let mut record = seed(&home);
    let (writer, mut rx) = mpsc::channel(1);
    open(&home, &writer, 1, 1, MEMBER, json!({})).await;
    home.remote_watches.cancel(1, 1);
    // Leave the old notice in the writer to hold the new open after its projection.
    let mut opening = Box::pin(open(&home, &writer, 1, 2, MEMBER, json!({})));
    assert!(poll_fn(|cx| Poll::Ready(opening.as_mut().poll(cx)))
        .await
        .is_pending());
    record.identity.org_name = Some("after-projection".into());
    overwrite(&home, &record);
    assert_eq!(rx.try_recv().unwrap().header.corr, 1);
    opening.await;
    let first = body(rx.try_recv().unwrap(), FrameType::StreamData);
    assert_eq!(first["seq"], 1);
    assert_eq!(first["logins"][0]["identity"]["org_name"], "workspace");
    cycle(&home).await;
    let next = body(rx.try_recv().unwrap(), FrameType::StreamData);
    assert_eq!(next["seq"], 2);
    assert_eq!(
        next["logins"][0]["identity"]["org_name"],
        "after-projection"
    );
}
