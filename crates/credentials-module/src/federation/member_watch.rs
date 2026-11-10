//! Keep non-secret remote inventory from each paired computer's home watch.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use credentials_core::{
    federation::{
        is_lower_hex_16_bytes, validate_remote_watch_row, RemoteHomeState, RemoteWatchApplyMode,
        RemoteWatchRow,
    },
    plan_detection::DetectedPlan,
    record::RecordIdentity,
    store::EncryptedStore,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::{mpsc, watch};

use super::outbound::{
    management_surface, OutboundClient, OutboundError, RouteCall, SubscriptionEvent,
    ADMIN_OP_BUDGET,
};

/// None means no authoritative inventory has decoded yet. Some includes computers
/// whose local sharing switch is off: that switch does not describe the home.
pub type PairedComputers = Option<Vec<(String, String)>>;

const MAX_MEMBER_RETRY_SECONDS: u64 = 600;

#[derive(Default)]
struct Logged(Mutex<BTreeSet<(String, String)>>);

impl Logged {
    fn first(&self, home: &str, id: &str) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert((home.into(), id.into()))
    }
}

#[derive(Default)]
struct Backoff(u32);

impl Backoff {
    fn next_delay(&mut self) -> Duration {
        let delay = 1u64
            .checked_shl(self.0)
            .unwrap_or(u64::MAX)
            .min(MAX_MEMBER_RETRY_SECONDS);
        self.0 = self.0.saturating_add(1);
        Duration::from_secs(delay)
    }

    fn completed(&mut self, applied: bool, event: &SubscriptionEvent) {
        // Callosum maps completed and unsubscribed to StreamEnd.
        if applied && matches!(event, SubscriptionEvent::End) {
            self.0 = 0;
        }
    }
}

struct Worker {
    store: Arc<EncryptedStore>,
    client: OutboundClient,
    fingerprint: String,
    pairing: String,
    stop: watch::Receiver<bool>,
    wakes: watch::Receiver<()>,
    events: mpsc::UnboundedSender<HomeEvent>,
    logged: Arc<Logged>,
    #[cfg(test)]
    attempted: Arc<tokio::sync::Notify>,
}

impl Worker {
    async fn retry(&mut self, backoff: &mut Backoff) -> bool {
        if *self.stop.borrow() {
            return false;
        }
        tokio::select! {
            biased;
            _ = self.stop.changed() => false,
            _ = self.wakes.changed() => true,
            _ = tokio::time::sleep(backoff.next_delay()) => true,
        }
    }

    async fn apply(&mut self, home: &str, snapshot: &Snapshot) -> bool {
        let store = Arc::clone(&self.store);
        let home_owned = home.to_string();
        let pairing = self.pairing.clone();
        let snapshot = snapshot.clone();
        // Do not select cancellation against this join: stop() must also fence any
        // already-running blocking transaction before the next pairing can write.
        let result = tokio::task::spawn_blocking(move || {
            store.remote_watch_apply_audited(
                &home_owned,
                &pairing,
                &snapshot.rows,
                RemoteWatchApplyMode::Full,
                &snapshot.retained_ids,
            )
        })
        .await;
        #[cfg(test)]
        self.attempted.notify_one();
        match result {
            Ok(Ok(result)) => {
                for id in result.skipped {
                    if self.logged.first(home, &id) {
                        tracing::warn!(target: "federation", home, %id, "home watch id already held; existing holder wins");
                    }
                }
                true
            }
            error => {
                tracing::warn!(target: "federation", ?error, "home watch apply failed; retaining snapshot for retry");
                false
            }
        }
    }

    async fn apply_snapshot(
        &mut self,
        home: &str,
        snapshot: &Snapshot,
        backoff: &mut Backoff,
    ) -> bool {
        loop {
            self.wakes.borrow_and_update();
            if *self.stop.borrow() {
                return false;
            }
            if self.apply(home, snapshot).await {
                return true;
            }
            if !self.retry(backoff).await {
                return false;
            }
        }
    }

    async fn session(&mut self, home: &str, backoff: &mut Backoff) -> Option<SessionEnd> {
        let request = RouteCall {
            target: management_surface(&format!("fed:{}:claustrum", self.fingerprint)),
            prelude: None,
            request: json!({"method": "federation.remote_watch", "params": {}}),
        };
        let route_key = format!("member-watch:{home}");
        let opened = tokio::select! {
            biased;
            _ = self.stop.changed() => return None,
            // The daemon client's consumer identity attests reserved:claustrum.
            // Cache bindings separately for each home, not under that shared identity.
            result = self.client.subscribe(&route_key, request, ADMIN_OP_BUDGET) => result,
        };
        let mut subscription = match opened {
            Ok(subscription) => subscription,
            Err(error) => return Some(SessionEnd::Dropped(error)),
        };
        let mut applied = false;
        loop {
            let event = tokio::select! {
                biased;
                _ = self.stop.changed() => return None,
                event = subscription.next_event() => event,
            };
            match event {
                Ok(SubscriptionEvent::Data(body)) => {
                    let Some(snapshot) = decode_notice(home, body, &self.logged) else {
                        return Some(SessionEnd::Undecodable);
                    };
                    if !self.apply_snapshot(home, &snapshot, backoff).await {
                        return None;
                    }
                    applied = true;
                }
                Ok(terminal) => {
                    backoff.completed(applied, &terminal);
                    return Some(SessionEnd::Terminal(terminal));
                }
                Err(error) => return Some(SessionEnd::Dropped(error)),
            }
        }
    }

    async fn run(mut self) {
        let home = format!("fed-computer:{}", self.fingerprint);
        let mut backoff = Backoff::default();
        loop {
            self.wakes.borrow_and_update();
            if *self.stop.borrow() {
                return;
            }
            let Some(ending) = self.session(&home, &mut backoff).await else {
                return;
            };
            let _ = self.events.send(HomeEvent {
                fingerprint: self.fingerprint.clone(),
                pairing: self.pairing.clone(),
                ending,
            });
            if !self.retry(&mut backoff).await {
                return;
            }
        }
    }
}

#[derive(Deserialize)]
struct Notice {
    kind: String,
    home: String,
    epoch: String,
    seq: u64,
    logins: Vec<Login>,
}

#[derive(Deserialize)]
struct Login {
    credential_id: String,
    state: RemoteHomeState,
    refresh_adapter: Option<String>,
    identity: RecordIdentity,
    categories: Vec<String>,
    detected_plan: Option<DetectedPlan>,
    home_version: u64,
}

#[derive(Clone, Debug)]
struct Snapshot {
    rows: Vec<RemoteWatchRow>,
    retained_ids: Vec<String>,
}

fn decode_notice(home: &str, body: Value, logged: &Logged) -> Option<Snapshot> {
    let notice: Notice = serde_json::from_value(body).ok()?;
    if notice.kind != "snapshot"
        || notice.home != home
        || !is_lower_hex_16_bytes(&notice.epoch)
        || notice.seq == 0
    {
        return None;
    }
    let mut ids = BTreeSet::new();
    let mut rows = Vec::new();
    let mut retained_ids = Vec::new();
    for login in notice.logins {
        if login.state == RemoteHomeState::Corrupt || !ids.insert(login.credential_id.clone()) {
            return None;
        }
        let row = RemoteWatchRow {
            credential_id: login.credential_id,
            state: login.state,
            refresh_adapter: login.refresh_adapter,
            identity: login.identity,
            categories: login.categories,
            detected_plan: login.detected_plan,
            home_version: login.home_version,
        };
        if let Err(error) = validate_remote_watch_row(home, &row) {
            if logged.first(home, &row.credential_id) {
                tracing::warn!(target: "federation", home, id = %row.credential_id, %error, "home watch row rejected; existing row unchanged");
            }
            retained_ids.push(row.credential_id);
        } else {
            rows.push(row);
        }
    }
    Some(Snapshot { rows, retained_ids })
}

#[derive(Debug)]
enum SessionEnd {
    Terminal(SubscriptionEvent),
    Dropped(OutboundError),
    Undecodable,
}

struct HomeEvent {
    fingerprint: String,
    pairing: String,
    ending: SessionEnd,
}

struct HomeTask {
    pairing: String,
    stopped: watch::Sender<bool>,
    wake: watch::Sender<()>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl HomeTask {
    async fn stop(mut self) {
        self.stopped.send_replace(true);
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

impl Drop for HomeTask {
    fn drop(&mut self) {
        // A blocking apply must finish before its task exits, even during shutdown.
        self.stopped.send_replace(true);
    }
}

/// Consume only validated inventories published by the existing sharing watch.
pub async fn run(
    store: Arc<EncryptedStore>,
    client: OutboundClient,
    mut pairings: watch::Receiver<PairedComputers>,
) {
    let mut tasks: BTreeMap<String, HomeTask> = BTreeMap::new();
    let (events, mut endings) = mpsc::unbounded_channel::<HomeEvent>();
    let logged = Arc::new(Logged::default());
    loop {
        let inventory = pairings.borrow_and_update().clone();
        if let Some(inventory) = inventory {
            let current: BTreeMap<_, _> = inventory.into_iter().collect();
            let lost: Vec<_> = tasks
                .iter()
                .filter(|(fp, task)| current.get(*fp) != Some(&task.pairing))
                .map(|(fp, _)| fp.clone())
                .collect();
            for fp in lost {
                tasks.remove(&fp).expect("listed task").stop().await;
                // Authoritative removal belongs here, after the old writer is joined
                // and before a replacement pairing may start. Without a removal
                // handler, retain stored rows rather than risking an unsafe deletion.
            }
            for (fingerprint, pairing) in current {
                if let Some(task) = tasks.get(&fingerprint) {
                    task.wake.send_replace(());
                    continue;
                }
                let (stopped, stop) = watch::channel(false);
                let (wake, wakes) = watch::channel(());
                let worker = Worker {
                    store: Arc::clone(&store),
                    client: client.clone(),
                    fingerprint: fingerprint.clone(),
                    pairing: pairing.clone(),
                    stop,
                    wakes,
                    events: events.clone(),
                    logged: Arc::clone(&logged),
                    #[cfg(test)]
                    attempted: Arc::new(tokio::sync::Notify::new()),
                };
                let join = tokio::spawn(worker.run());
                tasks.insert(
                    fingerprint,
                    HomeTask {
                        pairing,
                        stopped,
                        wake,
                        join: Some(join),
                    },
                );
            }
        }
        loop {
            tokio::select! {
                changed = pairings.changed() => {
                    if changed.is_err() {
                        for (_, task) in tasks { task.stop().await; }
                        return;
                    }
                    break;
                }
                Some(event) = endings.recv() => {
                    if tasks.get(&event.fingerprint).is_some_and(|task| task.pairing == event.pairing) {
                        // Keep the typed terminal for authoritative removal handling;
                        // a dropped link or an undecodable notice must never remove rows.
                        match event.ending {
                            SessionEnd::Terminal(terminal) => tracing::debug!(target: "federation", ?terminal, "home watch ended; inventory retained"),
                            SessionEnd::Dropped(error) => tracing::debug!(target: "federation", ?error, "home watch disconnected; inventory retained"),
                            SessionEnd::Undecodable => tracing::warn!(target: "federation", "home watch notice rejected; inventory retained"),
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "fed-computer:aa11bb22cc33dd44ee55ff6600112233";

    fn notice() -> Value {
        json!({"kind": "snapshot", "home": HOME, "epoch": "ab".repeat(16), "seq": 1,
            "logins": [{"credential_id": "oauth:x", "state": "active", "refresh_adapter": "openai",
                "identity": {"account_id": "account"}, "categories": ["llm-provider"],
                "detected_plan": null, "home_version": 1}]})
    }

    #[test]
    fn member_retry_doubles_and_caps_at_ten_minutes() {
        let mut backoff = Backoff::default();
        for seconds in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 600, 600] {
            assert_eq!(backoff.next_delay(), Duration::from_secs(seconds));
        }
        backoff.0 = u32::MAX;
        assert_eq!(backoff.next_delay(), Duration::from_secs(600));
        backoff.completed(false, &SubscriptionEvent::End);
        assert_eq!(backoff.next_delay(), Duration::from_secs(600));
        backoff.completed(true, &SubscriptionEvent::Response(json!({})));
        assert_eq!(backoff.next_delay(), Duration::from_secs(600));
        backoff.completed(true, &SubscriptionEvent::End);
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
        assert_eq!(backoff.next_delay(), Duration::from_secs(2));
    }

    #[test]
    fn member_notice_validates_used_fields_and_ignores_unknown_fields() {
        let logged = Logged::default();
        let mut body = notice();
        body["extra"] = json!(true);
        body["logins"][0]["extra"] = json!(true);
        body["logins"][0]["identity"]["extra"] = json!(true);
        assert_eq!(decode_notice(HOME, body, &logged).unwrap().rows.len(), 1);
        for (field, invalid) in [
            ("kind", json!("delta")),
            ("home", json!("another-home")),
            ("epoch", json!("invalid")),
            ("seq", json!(0)),
            ("seq", json!(-1)),
            ("logins", json!(null)),
        ] {
            let mut bad = notice();
            bad[field] = invalid;
            assert!(decode_notice(HOME, bad, &logged).is_none(), "{field}");
        }
        for (field, invalid) in [
            ("state", json!("retired")),
            ("state", json!("corrupt")),
            ("identity", json!(null)),
            ("home_version", json!(-1)),
            ("categories", json!([1])),
        ] {
            let mut bad = notice();
            bad["logins"][0][field] = invalid;
            assert!(decode_notice(HOME, bad, &logged).is_none(), "{field}");
        }
        let mut duplicate = notice();
        duplicate["logins"]
            .as_array_mut()
            .unwrap()
            .push(notice()["logins"][0].clone());
        assert!(decode_notice(HOME, duplicate, &logged).is_none());
    }

    #[test]
    fn member_notice_store_rejections_retain_ids_and_log_once_per_home() {
        let logged = Logged::default();
        for (field, invalid) in [
            ("credential_id", json!("category:reserved")),
            ("identity", json!({"account_id": " "})),
            ("categories", json!(["not a category"])),
            (
                "detected_plan",
                json!({"tier": "invalid tier", "raw": null, "observed_at_ms": 1}),
            ),
            ("home_version", json!(u64::MAX)),
        ] {
            let mut body = notice();
            body["logins"][0][field] = invalid;
            let valid = notice()["logins"][0].clone();
            body["logins"][0]["credential_id"] = if field == "credential_id" {
                json!("category:reserved")
            } else {
                json!("oauth:bad")
            };
            body["logins"].as_array_mut().unwrap().push(valid);
            let snapshot = decode_notice(HOME, body, &logged).unwrap();
            assert_eq!(snapshot.rows.len(), 1, "{field}");
            assert_eq!(snapshot.rows[0].credential_id, "oauth:x");
            assert_eq!(snapshot.retained_ids.len(), 1, "{field}");
        }
        assert!(!logged.first(HOME, "oauth:bad"));
        assert!(logged.first("another-home", "oauth:bad"));
        assert!(!logged.first("another-home", "oauth:bad"));
    }

    #[tokio::test(start_paused = true)]
    async fn member_failed_apply_retries_retained_snapshot_without_a_notice() {
        let root = credentials_core::test_support::TestTempDir::new(format!(
            "member-pending-apply-{}",
            std::process::id()
        ));
        let path = root.join("store.db");
        let descriptor = cortexkit_store::StorageDescriptor {
            module_id: "claustrum".into(),
            storage_namespace: "member-watch".into(),
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
        let sql = rusqlite::Connection::open(path).unwrap();
        sql.execute_batch("CREATE TRIGGER fail_watch_apply BEFORE INSERT ON audit_log WHEN NEW.op = 'remote_add' BEGIN SELECT RAISE(ABORT, 'apply unavailable'); END;").unwrap();
        let (stopped, stop) = watch::channel(false);
        let (_wake, wakes) = watch::channel(());
        let (events, _endings) = mpsc::unbounded_channel();
        let attempted = Arc::new(tokio::sync::Notify::new());
        let mut worker = Worker {
            store: Arc::clone(&store),
            client: OutboundClient::for_daemon(root.join("unused.json"), "claustrum", None),
            fingerprint: "aa11bb22cc33dd44ee55ff6600112233".into(),
            pairing: "pair".into(),
            stop,
            wakes,
            events,
            logged: Arc::new(Logged::default()),
            attempted: Arc::clone(&attempted),
        };
        let snapshot = decode_notice(HOME, notice(), &worker.logged).unwrap();
        let mut call = tokio::spawn(async move {
            worker
                .apply_snapshot(HOME, &snapshot, &mut Backoff::default())
                .await
        });
        attempted.notified().await;
        assert!(
            store.remote_record("oauth:x").unwrap().is_none(),
            "the failed transaction rolled back"
        );
        assert!(!call.is_finished(), "a failed apply remains pending");
        sql.execute_batch("DROP TRIGGER fail_watch_apply").unwrap();
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!((&mut call).await.unwrap());
        assert!(store.remote_record("oauth:x").unwrap().is_some());
        drop(stopped);
    }
}
