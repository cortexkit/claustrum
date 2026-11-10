use super::*;

const FP: &str = "aa11bb22cc33dd44ee55ff6600112233";
const HOME: &str = "fed-computer:aa11bb22cc33dd44ee55ff6600112233";

struct Rig {
    reconciler: Reconciler,
    endings: mpsc::UnboundedReceiver<HomeEvent>,
    sql: rusqlite::Connection,
    _root: credentials_core::test_support::TestTempDir,
}

impl Rig {
    fn new(name: &str) -> Self {
        let root = credentials_core::test_support::TestTempDir::new(format!(
            "{name}-{}",
            std::process::id()
        ));
        let path = root.join("store.db");
        let descriptor = cortexkit_store::StorageDescriptor {
            module_id: "claustrum".into(),
            storage_namespace: "member-removal".into(),
            isolation: cortexkit_store::Isolation::Module,
            backend: cortexkit_store::StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        };
        let sqlite = cortexkit_store::open_sqlite(&descriptor).unwrap();
        EncryptedStore::migrate(&sqlite).unwrap();
        let store = Arc::new(
            EncryptedStore::open(
                sqlite,
                credentials_core::key::MasterKey::from_bytes([42; 32]),
            )
            .unwrap(),
        );
        let (events, endings) = mpsc::unbounded_channel();
        Self {
            reconciler: Reconciler {
                store,
                client: OutboundClient::for_daemon(root.join("unused.json"), "claustrum", None),
                tasks: BTreeMap::new(),
                pending: BTreeMap::new(),
                retrying: BTreeMap::new(),
                current: BTreeMap::new(),
                events,
                logged: Arc::new(Logged::default()),
                generation: 0,
                removal_attempted: Arc::new(tokio::sync::Notify::new()),
            },
            endings,
            sql: rusqlite::Connection::open(path).unwrap(),
            _root: root,
        }
    }

    fn seed(&self, pairing: &str, id: &str) {
        self.reconciler
            .store
            .remote_watch_apply_audited(
                HOME,
                pairing,
                &[RemoteWatchRow {
                    credential_id: id.into(),
                    state: RemoteHomeState::Active,
                    refresh_adapter: Some("openai".into()),
                    identity: Default::default(),
                    categories: vec![],
                    detected_plan: None,
                    home_version: 1,
                }],
                RemoteWatchApplyMode::Full,
                &[],
            )
            .unwrap();
    }

    fn fail_removal(&self) {
        self.sql.execute_batch("CREATE TRIGGER fail_watch_remove BEFORE INSERT ON audit_log WHEN NEW.op = 'remote_remove' BEGIN SELECT RAISE(ABORT, 'removal unavailable'); END;").unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn member_removal_retries_while_unpaired_without_another_event() {
    let mut rig = Rig::new("member-unpaired-removal");
    rig.seed("old", "oauth:x");
    rig.fail_removal();
    let attempted = Arc::clone(&rig.reconciler.removal_attempted);
    let store = Arc::clone(&rig.reconciler.store);
    let (pairs, pairings) = watch::channel(Some(vec![]));
    let task = tokio::spawn(async move {
        supervise(rig.reconciler, pairings, &mut rig.endings).await;
    });
    attempted.notified().await;
    assert!(
        store.remote_record("oauth:x").unwrap().is_some(),
        "failed removal rolled back"
    );
    rig.sql
        .execute_batch("DROP TRIGGER fail_watch_remove")
        .unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;
    attempted.notified().await;
    assert!(store.remote_record("oauth:x").unwrap().is_none());
    drop(pairs);
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn member_pending_removal_blocks_streams_retries_on_inventory_and_newer_pair_wins() {
    let mut rig = Rig::new("member-newer-removal");
    rig.seed("old", "oauth:old");
    rig.seed("newest", "oauth:current");
    rig.fail_removal();
    let (_pairs, pairings) = watch::channel(Some(vec![(FP.into(), "next".into())]));
    rig.reconciler
        .inventory(vec![(FP.into(), "next".into())])
        .await;
    rig.reconciler.start_tasks(&pairings);
    assert!(
        rig.reconciler.tasks.is_empty(),
        "no new stream before removal commits"
    );
    assert_eq!(rig.reconciler.pending.len(), 1);
    assert_eq!(
        rig.reconciler.pending[FP].keep_pairing.as_deref(),
        Some("next")
    );
    rig.reconciler.inventory(vec![]).await;
    assert_eq!(rig.reconciler.pending.len(), 1);
    assert!(rig.reconciler.pending[FP].keep_pairing.is_none());
    rig.sql
        .execute_batch("DROP TRIGGER fail_watch_remove")
        .unwrap();
    // No time advances: the newer paired snapshot itself retries the failed
    // removal and replaces its keep-pairing before it touches the store.
    rig.reconciler
        .inventory(vec![(FP.into(), "newest".into())])
        .await;
    assert!(rig.reconciler.pending.is_empty());
    assert!(rig
        .reconciler
        .store
        .remote_record("oauth:old")
        .unwrap()
        .is_none());
    assert_eq!(
        rig.reconciler
            .store
            .remote_record("oauth:current")
            .unwrap()
            .unwrap()
            .home_pairing_id
            .as_deref(),
        Some("newest")
    );
}

#[test]
fn member_callosum_ending_vectors_classify_removal() {
    // Verbatim body_json from Callosum fed-reexport-watch-v1.0, commit
    // 1c9d715de67ee705aa2d54155adb6a770e26760c,
    // test-vectors/fed-reexport-watch-v1/local.json; each row names its case.
    let cases = [
        (
            "cap_refusal",
            r#"{"code":"fed_subscription_limit","message":"peer subscription cap reached"}"#,
            false,
        ),
        (
            "module_error",
            r#"{"code":"denied","detail":{"scope":"a"},"message":"private"}"#,
            false,
        ),
        (
            "lagged",
            r#"{"code":"fed_subscription_ended","detail":{"reason":"lagged"},"message":"remote subscription ended"}"#,
            false,
        ),
        (
            "module_restarted",
            r#"{"code":"fed_subscription_ended","detail":{"reason":"module_restarted"},"message":"remote subscription ended"}"#,
            false,
        ),
        (
            "not_exposed",
            r#"{"code":"fed_subscription_ended","detail":{"reason":"not_exposed"},"message":"remote subscription ended"}"#,
            true,
        ),
        (
            "revoked",
            r#"{"code":"fed_subscription_ended","detail":{"reason":"revoked"},"message":"remote subscription ended"}"#,
            true,
        ),
        (
            "rotating",
            r#"{"code":"fed_subscription_ended","detail":{"reason":"rotating"},"message":"remote subscription ended"}"#,
            false,
        ),
        (
            "draining",
            r#"{"code":"fed_subscription_ended","detail":{"reason":"draining"},"message":"remote subscription ended"}"#,
            false,
        ),
        (
            "future_reason",
            r#"{"code":"fed_subscription_ended","detail":{"reason":"future_reason"},"message":"remote subscription ended"}"#,
            false,
        ),
        (
            "session_closed",
            r#"{"code":"fed_subscription_ended","detail":{"reason":"session_closed"},"message":"remote subscription ended"}"#,
            false,
        ),
    ];
    for (case, body, removes) in cases {
        let body: Value = serde_json::from_str(body).unwrap();
        let event = SubscriptionEvent::Error {
            code: body["code"].as_str().unwrap().into(),
            message: body["message"].as_str().unwrap().into(),
            detail: body.get("detail").cloned(),
        };
        assert_eq!(
            SessionEnd::Terminal(event).removes_home(),
            removes,
            "{case}"
        );
    }
    for case in ["completed", "unsubscribed"] {
        assert!(
            !SessionEnd::Terminal(SubscriptionEvent::End).removes_home(),
            "{case}"
        );
    }
    // Home refusal and defensive non-authoritative inputs below are not vectors.
    assert!(SessionEnd::Terminal(SubscriptionEvent::Error {
        code: "not_found".into(),
        message: "not found".into(),
        detail: Some(json!({"class":"permanent"})),
    })
    .removes_home());
    for event in [
        SubscriptionEvent::Error {
            code: "executor_error".into(),
            message: "executor error".into(),
            detail: Some(json!({"code":"fed_not_found"})),
        },
        SubscriptionEvent::Error {
            code: "module_error".into(),
            message: "unknown error".into(),
            detail: Some(json!({"code":"not_found"})),
        },
        SubscriptionEvent::Response(json!({"error":{"code":"not_found"}})),
    ] {
        assert!(!SessionEnd::Terminal(event).removes_home());
    }
}

#[tokio::test(start_paused = true)]
async fn member_terminal_removal_joins_owner_and_retries_without_a_stream() {
    let mut rig = Rig::new("member-terminal-pending");
    rig.seed("pair-a", "oauth:x");
    rig.fail_removal();
    let (stopped, mut stop) = watch::channel(false);
    let (wake, _wakes) = watch::channel(());
    let (replay, _replays) = watch::channel(());
    let joined = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let owner_joined = Arc::clone(&joined);
    let owner = tokio::spawn(async move {
        stop.changed().await.unwrap();
        owner_joined.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    rig.reconciler.tasks.insert(
        FP.into(),
        HomeTask {
            pairing: "pair-a".into(),
            generation: 1,
            stopped,
            wake,
            replay,
            join: Some(owner),
        },
    );
    rig.reconciler
        .events
        .send(HomeEvent {
            fingerprint: FP.into(),
            generation: 1,
            kind: HomeEventKind::Remove(RetryStart {
                backoff: Backoff(1),
                retry_at: Instant::now() + Duration::from_secs(1),
            }),
        })
        .unwrap();
    let attempted = Arc::clone(&rig.reconciler.removal_attempted);
    let store = Arc::clone(&rig.reconciler.store);
    let (pairs, pairings) = watch::channel(Some(vec![(FP.into(), "pair-a".into())]));
    let task = tokio::spawn(async move {
        supervise(rig.reconciler, pairings, &mut rig.endings).await;
    });
    attempted.notified().await;
    assert!(
        joined.load(std::sync::atomic::Ordering::SeqCst),
        "the old writer exits before removal is attempted"
    );
    assert!(store.remote_record("oauth:x").unwrap().is_some());
    rig.sql
        .execute_batch("DROP TRIGGER fail_watch_remove")
        .unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;
    attempted.notified().await;
    assert!(store.remote_record("oauth:x").unwrap().is_none());
    drop(pairs);
    task.await.unwrap();
}
