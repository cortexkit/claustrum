//! Keep non-secret remote inventory from each paired computer's home watch.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use credentials_core::{
    federation::{
        is_lower_hex_16_bytes, validate_remote_watch_row, RemoteHomeState, RemoteRecordSource,
        RemoteWatchApplyMode, RemoteWatchRow,
    },
    plan_detection::DetectedPlan,
    record::RecordIdentity,
    store::EncryptedStore,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::{
    sync::{mpsc, watch},
    time::Instant,
};

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
    replays: watch::Receiver<()>,
    pairings: watch::Receiver<PairedComputers>,
    generation: u64,
    backoff: Backoff,
    retained: Option<Snapshot>,
    skipped: BTreeSet<String>,
    pending_apply: bool,
    events: mpsc::UnboundedSender<HomeEvent>,
    logged: Arc<Logged>,
    #[cfg(test)]
    attempted: Arc<tokio::sync::Notify>,
}

impl Worker {
    fn current(&self) -> bool {
        !*self.stop.borrow()
            && self.pairings.borrow().as_ref().is_some_and(|pairs| {
                pairs
                    .iter()
                    .any(|(fp, p)| fp == &self.fingerprint && p == &self.pairing)
            })
    }

    async fn retry(&mut self, retry_at: Instant) -> bool {
        if *self.stop.borrow() {
            return false;
        }
        let delay = tokio::time::sleep_until(retry_at);
        tokio::pin!(delay);
        loop {
            tokio::select! {
                biased;
                _ = self.stop.changed() => return false,
                _ = self.replays.changed() => self.replay().await,
                _ = self.wakes.changed() => return true,
                _ = &mut delay => return true,
            }
        }
    }

    async fn apply(&mut self, mode: RemoteWatchApplyMode) -> bool {
        if !self.current() {
            return false;
        }
        let Some(snapshot) = &self.retained else {
            return true;
        };
        let store = Arc::clone(&self.store);
        let home = format!("fed-computer:{}", self.fingerprint);
        let home_owned = home.clone();
        let pairing = self.pairing.clone();
        let rows: Vec<_> = snapshot
            .rows
            .iter()
            .filter(|row| {
                mode == RemoteWatchApplyMode::Full || self.skipped.contains(&row.credential_id)
            })
            .cloned()
            .collect();
        let retained_ids = snapshot.retained_ids.clone();
        // Do not select cancellation against this join: stop() must also fence any
        // already-running blocking transaction before the next pairing can write.
        let result = tokio::task::spawn_blocking(move || {
            store.remote_watch_apply_audited(&home_owned, &pairing, &rows, mode, &retained_ids)
        })
        .await;
        #[cfg(test)]
        self.attempted.notify_one();
        match result {
            Ok(Ok(result)) => {
                self.skipped = result.skipped.into_iter().collect();
                for id in &self.skipped {
                    if self.logged.first(&home, id) {
                        tracing::warn!(target: "federation", home, %id, "home watch id already held; existing holder wins");
                    }
                }
                if result.removed > 0 {
                    self.report(HomeEventKind::Removed);
                }
                true
            }
            error => {
                tracing::warn!(target: "federation", ?error, "home watch apply failed; retaining snapshot for retry");
                false
            }
        }
    }

    async fn replay(&mut self) {
        // Only collisions may be retried from an old projection. In particular,
        // replay must not overwrite status metadata written by the token read path.
        if !self.pending_apply && !self.skipped.is_empty() {
            self.apply(RemoteWatchApplyMode::InsertOnly).await;
        }
    }

    async fn apply_latest(&mut self) -> bool {
        if self.pending_apply && self.apply(RemoteWatchApplyMode::Full).await {
            self.pending_apply = false;
        }
        !self.pending_apply
    }

    fn report(&self, kind: HomeEventKind) {
        let _ = self.events.send(HomeEvent {
            fingerprint: self.fingerprint.clone(),
            generation: self.generation,
            kind,
        });
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
        let mut retry_at = Instant::now();
        if self.pending_apply {
            retry_at += backoff.next_delay();
        }
        loop {
            let event = tokio::select! {
                biased;
                _ = self.stop.changed() => return None,
                event = subscription.next_event() => event,
                _ = self.replays.changed() => { self.replay().await; continue; },
                _ = self.wakes.changed(), if self.pending_apply => {
                    applied |= self.apply_latest().await;
                    if self.pending_apply { retry_at = Instant::now() + backoff.next_delay(); }
                    continue;
                },
                _ = tokio::time::sleep_until(retry_at), if self.pending_apply => {
                    applied |= self.apply_latest().await;
                    if self.pending_apply { retry_at = Instant::now() + backoff.next_delay(); }
                    continue;
                },
            };
            match event {
                Ok(SubscriptionEvent::Data(body)) => {
                    let Some(snapshot) = decode_notice(home, body, &self.logged) else {
                        return Some(SessionEnd::Undecodable);
                    };
                    self.retained = Some(snapshot);
                    self.skipped.clear();
                    self.pending_apply = true;
                    applied |= self.apply_latest().await;
                    if self.pending_apply {
                        retry_at = Instant::now() + backoff.next_delay();
                    }
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
        let mut backoff = std::mem::take(&mut self.backoff);
        loop {
            self.wakes.borrow_and_update();
            if *self.stop.borrow() {
                return;
            }
            self.apply_latest().await;
            let Some(ending) = self.session(&home, &mut backoff).await else {
                return;
            };
            let retry_at = Instant::now() + backoff.next_delay();
            if ending.removes_home() {
                // A refusal invalidates even a failed apply. Nothing retained from
                // this stream may recreate rows after the removal commits.
                self.retained = None;
                self.skipped.clear();
                self.pending_apply = false;
                self.report(HomeEventKind::Remove(RetryStart { backoff, retry_at }));
                return;
            } else {
                tracing::debug!(target: "federation", ?ending, "home watch ended; inventory retained");
            }
            if !self.retry(retry_at).await {
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

impl SessionEnd {
    fn removes_home(&self) -> bool {
        match self {
            Self::Terminal(SubscriptionEvent::Error { code, detail, .. }) => {
                let detail = detail.as_ref();
                code == "not_found"
                    || (code == "fed_subscription_ended"
                        && detail
                            .and_then(|d| d.get("reason"))
                            .and_then(Value::as_str)
                            .is_some_and(|reason| matches!(reason, "revoked" | "not_exposed")))
            }
            Self::Dropped(error) => {
                tracing::debug!(target: "federation", ?error, "home watch disconnected");
                false
            }
            _ => false,
        }
    }
}

enum HomeEventKind {
    Removed,
    Remove(RetryStart),
}

struct HomeEvent {
    fingerprint: String,
    generation: u64,
    kind: HomeEventKind,
}

struct HomeTask {
    pairing: String,
    generation: u64,
    stopped: watch::Sender<bool>,
    wake: watch::Sender<()>,
    replay: watch::Sender<()>,
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

struct PendingRemoval {
    keep_pairing: Option<String>,
    backoff: Backoff,
    retry_at: Instant,
}

impl PendingRemoval {
    fn new(keep_pairing: Option<String>) -> Self {
        Self {
            keep_pairing,
            backoff: Backoff::default(),
            retry_at: Instant::now(),
        }
    }
}

struct RetryStart {
    backoff: Backoff,
    retry_at: Instant,
}

struct Reconciler {
    store: Arc<EncryptedStore>,
    client: OutboundClient,
    tasks: BTreeMap<String, HomeTask>,
    pending: BTreeMap<String, PendingRemoval>,
    retrying: BTreeMap<String, RetryStart>,
    current: BTreeMap<String, String>,
    events: mpsc::UnboundedSender<HomeEvent>,
    logged: Arc<Logged>,
    generation: u64,
    #[cfg(test)]
    removal_attempted: Arc<tokio::sync::Notify>,
}

impl Reconciler {
    fn replay_others(&self, removed: &str) {
        for (fp, task) in &self.tasks {
            if fp != removed
                && !self.pending.contains_key(fp)
                && self.current.get(fp) == Some(&task.pairing)
            {
                task.replay.send_replace(());
            }
        }
    }

    async fn retry_removals(&mut self, force: bool) {
        let due: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, removal)| force || removal.retry_at <= Instant::now())
            .map(|(fp, removal)| (fp.clone(), removal.keep_pairing.clone()))
            .collect();
        for (fp, keep) in due {
            let store = Arc::clone(&self.store);
            let home = format!("fed-computer:{fp}");
            let result = tokio::task::spawn_blocking(move || {
                store.remote_watch_remove_audited(&home, keep.as_deref())
            })
            .await;
            match result {
                Ok(Ok(_)) => {
                    self.pending.remove(&fp).expect("pending removal");
                    self.replay_others(&fp);
                }
                error => {
                    tracing::warn!(target: "federation", ?error, home = %fp, "home watch removal failed; retaining removal for retry");
                    let removal = self.pending.get_mut(&fp).expect("pending removal");
                    removal.retry_at = Instant::now() + removal.backoff.next_delay();
                }
            }
            #[cfg(test)]
            self.removal_attempted.notify_one();
        }
    }

    async fn inventory(&mut self, inventory: Vec<(String, String)>) {
        let previous = std::mem::replace(&mut self.current, inventory.into_iter().collect());
        let lost: Vec<_> = self
            .tasks
            .iter()
            .filter(|(fp, task)| self.current.get(*fp) != Some(&task.pairing))
            .map(|(fp, _)| fp.clone())
            .collect();
        for fp in &lost {
            self.tasks.remove(fp).expect("listed task").stop().await;
            self.pending.insert(
                fp.clone(),
                PendingRemoval::new(self.current.get(fp).cloned()),
            );
        }
        // Scan persisted rows even on the first inventory after startup. There may
        // be no old task to tell us that the home re-paired while we were stopped.
        match self.store.list_remote_records() {
            Ok(records) => {
                for row in records {
                    if row.source != RemoteRecordSource::HomeWatch {
                        continue;
                    }
                    let Some(fp) = row.home_member.strip_prefix("fed-computer:") else {
                        continue;
                    };
                    let keep = self.current.get(fp).cloned();
                    if row.home_pairing_id != keep {
                        // Do not replace an already pending all-pairings removal with
                        // a weaker cleanup of the same obsolete pairing.
                        self.pending
                            .entry(fp.into())
                            .or_insert_with(|| PendingRemoval::new(keep));
                    }
                }
            }
            Err(error) => {
                tracing::warn!(target: "federation", %error, "home watch startup inventory unavailable")
            }
        }
        // A newer pairing supersedes an older pending removal, even when the old
        // task was already joined during an earlier failed removal.
        for (fp, removal) in &mut self.pending {
            if previous.get(fp) != self.current.get(fp) {
                *removal = PendingRemoval::new(self.current.get(fp).cloned());
            }
        }
        self.retrying.retain(|fp, retry| {
            retry.retry_at = Instant::now();
            previous.get(fp) == self.current.get(fp)
        });
        self.retry_removals(true).await;
        for task in self.tasks.values() {
            task.wake.send_replace(());
        }
    }

    fn start_tasks(&mut self, pairings: &watch::Receiver<PairedComputers>) {
        for (fingerprint, pairing) in &self.current {
            if !pairings.borrow().as_ref().is_some_and(|pairs| {
                pairs
                    .iter()
                    .any(|(fp, p)| fp == fingerprint && p == pairing)
            }) {
                continue;
            }
            if self.tasks.contains_key(fingerprint) || self.pending.contains_key(fingerprint) {
                continue;
            }
            if self
                .retrying
                .get(fingerprint)
                .is_some_and(|retry| retry.retry_at > Instant::now())
            {
                continue;
            }
            let backoff = self
                .retrying
                .remove(fingerprint)
                .map(|retry| retry.backoff)
                .unwrap_or_default();
            self.generation += 1;
            let (stopped, stop) = watch::channel(false);
            let (wake, wakes) = watch::channel(());
            let (replay, replays) = watch::channel(());
            let worker = Worker {
                store: Arc::clone(&self.store),
                client: self.client.clone(),
                fingerprint: fingerprint.clone(),
                pairing: pairing.clone(),
                stop,
                wakes,
                replays,
                pairings: pairings.clone(),
                generation: self.generation,
                backoff,
                retained: None,
                skipped: BTreeSet::new(),
                pending_apply: false,
                events: self.events.clone(),
                logged: Arc::clone(&self.logged),
                #[cfg(test)]
                attempted: Arc::new(tokio::sync::Notify::new()),
            };
            self.tasks.insert(
                fingerprint.clone(),
                HomeTask {
                    pairing: pairing.clone(),
                    generation: self.generation,
                    stopped,
                    wake,
                    replay,
                    join: Some(tokio::spawn(worker.run())),
                },
            );
        }
    }
}

/// Consume only validated inventories published by the existing sharing watch.
pub async fn run(
    store: Arc<EncryptedStore>,
    client: OutboundClient,
    pairings: watch::Receiver<PairedComputers>,
) {
    let (events, mut endings) = mpsc::unbounded_channel::<HomeEvent>();
    let reconciler = Reconciler {
        store,
        client,
        tasks: BTreeMap::new(),
        pending: BTreeMap::new(),
        retrying: BTreeMap::new(),
        current: BTreeMap::new(),
        events,
        logged: Arc::new(Logged::default()),
        generation: 0,
        #[cfg(test)]
        removal_attempted: Arc::new(tokio::sync::Notify::new()),
    };
    supervise(reconciler, pairings, &mut endings).await;
}

async fn supervise(
    mut reconciler: Reconciler,
    mut pairings: watch::Receiver<PairedComputers>,
    endings: &mut mpsc::UnboundedReceiver<HomeEvent>,
) {
    let mut inventory_changed = true;
    loop {
        if inventory_changed {
            let inventory = pairings.borrow_and_update().clone();
            if let Some(inventory) = inventory {
                reconciler.inventory(inventory).await;
            }
            inventory_changed = false;
        }
        reconciler.start_tasks(&pairings);
        let next_removal = reconciler
            .pending
            .values()
            .map(|r| r.retry_at)
            .chain(
                reconciler
                    .retrying
                    .iter()
                    .filter(|(fp, _)| !reconciler.pending.contains_key(*fp))
                    .map(|(_, retry)| retry.retry_at),
            )
            .min();
        tokio::select! {
            biased;
            changed = pairings.changed() => {
                if changed.is_err() {
                    for (_, task) in reconciler.tasks { task.stop().await; }
                    return;
                }
                inventory_changed = true;
            }
            Some(event) = endings.recv() => {
                if reconciler.tasks.get(&event.fingerprint).is_some_and(|task| task.generation == event.generation) {
                    match event.kind {
                        HomeEventKind::Removed => reconciler.replay_others(&event.fingerprint),
                        HomeEventKind::Remove(retry) => {
                            reconciler.tasks.remove(&event.fingerprint).expect("current task").stop().await;
                            reconciler.retrying.insert(event.fingerprint.clone(), retry);
                            reconciler.pending.insert(event.fingerprint, PendingRemoval::new(None));
                            reconciler.retry_removals(false).await;
                        }
                    }
                }
            }
            _ = async {
                match next_removal {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => reconciler.retry_removals(false).await,
        }
    }
}

#[cfg(test)]
#[path = "member_watch_removal_tests.rs"]
mod removal_tests;

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
        let (_replay, replays) = watch::channel(());
        let (_pairs, pairings) = watch::channel(Some(vec![(
            "aa11bb22cc33dd44ee55ff6600112233".into(),
            "pair".into(),
        )]));
        let (events, _endings) = mpsc::unbounded_channel();
        let attempted = Arc::new(tokio::sync::Notify::new());
        let mut worker = Worker {
            store: Arc::clone(&store),
            client: OutboundClient::for_daemon(root.join("unused.json"), "claustrum", None),
            fingerprint: "aa11bb22cc33dd44ee55ff6600112233".into(),
            pairing: "pair".into(),
            stop,
            wakes,
            replays,
            pairings,
            generation: 1,
            backoff: Backoff::default(),
            retained: None,
            skipped: BTreeSet::new(),
            pending_apply: true,
            events,
            logged: Arc::new(Logged::default()),
            attempted: Arc::clone(&attempted),
        };
        let snapshot = decode_notice(HOME, notice(), &worker.logged).unwrap();
        worker.retained = Some(snapshot);
        let mut call = tokio::spawn(async move {
            let mut backoff = Backoff::default();
            while !worker.apply_latest().await {
                if !worker.retry(Instant::now() + backoff.next_delay()).await {
                    return false;
                }
            }
            true
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
