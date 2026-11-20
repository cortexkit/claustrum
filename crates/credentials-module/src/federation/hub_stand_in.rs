//! In-process hub for federation tests. All clients share state and get their own
//! connection-change signal. Tests control delivery without real-time sleeps.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use tokio::sync::{mpsc, oneshot};

use super::*;

type Delivery = Result<HubEvent, HubError>;
type WriteResult = Result<u64, HubError>;

#[derive(Clone)]
pub(crate) struct StandIn(Arc<Mutex<State>>);

struct State {
    online: bool,
    buckets: BTreeMap<String, Bucket>,
}

#[derive(Default)]
struct Bucket {
    revision: u64,
    entries: BTreeMap<String, HubEntry>,
    watchers: Vec<WatchSink>,
    watch_opens: usize,
    paused: bool,
    lose_ack: Option<String>,
    delay: Option<(String, ParkedWrite)>,
}

struct WatchSink {
    tx: mpsc::UnboundedSender<Delivery>,
    queued: Vec<HubEvent>,
}

impl Bucket {
    fn change(&mut self, key: &str, value: Vec<u8>, operation: HubOperation) -> u64 {
        self.revision += 1;
        let entry = HubEntry {
            key: key.into(),
            value,
            revision: self.revision,
            operation,
        };
        self.entries.insert(key.into(), entry.clone());
        self.deliver(HubEvent::Entry(entry));
        self.revision
    }

    fn history(&self) -> Vec<HubEvent> {
        let mut entries: Vec<_> = self.entries.values().cloned().collect();
        entries.sort_unstable_by_key(|entry| entry.revision);
        entries
            .into_iter()
            .map(HubEvent::Entry)
            .chain([HubEvent::CaughtUp])
            .collect()
    }

    fn deliver(&mut self, event: HubEvent) {
        self.watchers.retain_mut(|sink| {
            if self.paused && !sink.tx.is_closed() {
                sink.queued.push(event.clone());
                true
            } else {
                sink.tx.send(Ok(event.clone())).is_ok()
            }
        });
    }
}

impl State {
    fn bucket(&mut self, bucket: &str) -> Result<&mut Bucket, HubError> {
        if !self.online {
            return Err(HubError::Unavailable);
        }
        self.buckets.get_mut(bucket).ok_or(HubError::Unavailable)
    }
}

impl StandIn {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(State {
            online: true,
            buckets: [SHARED_LOGINS, MANIFEST_ACTIVE]
                .into_iter()
                .map(|name| (name.into(), Bucket::default()))
                .collect(),
        })))
    }

    pub(crate) fn client(&self, box_id: &str) -> StandInClient {
        StandInClient {
            hub: self.clone(),
            box_id: box_id.into(),
            connections: watch::channel(0).0,
        }
    }

    pub(crate) fn set_online(&self, online: bool) {
        let mut state = self.0.lock().unwrap();
        state.online = online;
        if !online {
            for bucket in state.buckets.values_mut() {
                for sink in bucket.watchers.drain(..) {
                    let _ = sink.tx.send(Err(HubError::Unavailable));
                }
            }
        }
    }

    pub(crate) fn terminate_watches(&self, bucket: &str) {
        self.0
            .lock()
            .unwrap()
            .buckets
            .get_mut(bucket)
            .unwrap()
            .watchers
            .clear();
    }

    pub(crate) fn watch_opens(&self, bucket: &str) -> usize {
        self.0.lock().unwrap().buckets[bucket].watch_opens
    }

    pub(crate) fn pause_delivery(&self, bucket: &str) {
        self.0
            .lock()
            .unwrap()
            .buckets
            .get_mut(bucket)
            .unwrap()
            .paused = true;
    }

    pub(crate) fn resume_delivery(&self, bucket: &str) {
        let mut state = self.0.lock().unwrap();
        let bucket = state.buckets.get_mut(bucket).unwrap();
        bucket.paused = false;
        bucket.watchers.retain_mut(|sink| {
            sink.queued
                .drain(..)
                .all(|event| sink.tx.send(Ok(event)).is_ok())
        });
    }

    pub(crate) fn delete(&self, bucket: &str, key: &str) -> WriteResult {
        Ok(self
            .0
            .lock()
            .unwrap()
            .bucket(bucket)?
            .change(key, Vec::new(), HubOperation::Delete))
    }

    pub(crate) fn purge(&self, bucket: &str, key: &str) -> WriteResult {
        Ok(self
            .0
            .lock()
            .unwrap()
            .bucket(bucket)?
            .change(key, Vec::new(), HubOperation::Purge))
    }

    pub(crate) fn tamper(&self, bucket: &str, key: &str, value: &[u8]) -> WriteResult {
        Ok(self
            .0
            .lock()
            .unwrap()
            .bucket(bucket)?
            .change(key, value.into(), HubOperation::Put))
    }

    pub(crate) fn reset_bucket(&self, bucket: &str, entries: &[(&str, &[u8])]) {
        let mut state = self.0.lock().unwrap();
        let name = bucket;
        let bucket = state.buckets.get_mut(name).unwrap();
        bucket.revision = 0;
        bucket.entries.clear();
        bucket.deliver(HubEvent::BucketReset {
            bucket: name.into(),
        });
        for (key, value) in entries {
            bucket.change(key, (*value).into(), HubOperation::Put);
        }
        bucket.deliver(HubEvent::CaughtUp);
    }

    pub(crate) fn lose_next_ack(&self, bucket: &str, key: &str) {
        let mut state = self.0.lock().unwrap();
        let previous = state
            .buckets
            .get_mut(bucket)
            .unwrap()
            .lose_ack
            .replace(key.into());
        assert!(previous.is_none(), "lost acknowledgement already armed");
    }

    pub(crate) fn delay_next_write(&self, bucket: &str, key: &str) -> DelayedWrite {
        let (parked_tx, parked) = oneshot::channel();
        let (deliver, deliver_rx) = oneshot::channel();
        let (done_tx, done) = oneshot::channel();
        let parked_write = ParkedWrite {
            parked: parked_tx,
            deliver: deliver_rx,
            done: done_tx,
        };
        let mut state = self.0.lock().unwrap();
        let previous = state
            .buckets
            .get_mut(bucket)
            .unwrap()
            .delay
            .replace((key.into(), parked_write));
        assert!(previous.is_none(), "delayed write already armed");
        DelayedWrite {
            parked,
            deliver,
            done,
        }
    }

    fn commit(&self, write: Write) -> WriteResult {
        let mut state = self.0.lock().unwrap();
        let bucket = state.bucket(&write.bucket)?;
        let existing = bucket.entries.get(&write.key);
        let matches = match write.expected {
            Some(expected) => existing.is_some_and(|entry| entry.revision == expected),
            None => existing.is_none_or(|entry| entry.operation != HubOperation::Put),
        };
        if !matches {
            return Err(HubError::Conflict);
        }
        let revision = bucket.change(&write.key, write.value, HubOperation::Put);
        if bucket.lose_ack.as_deref() == Some(&write.key) {
            bucket.lose_ack = None;
            return Err(HubError::Unavailable);
        }
        Ok(revision)
    }
}

struct Write {
    bucket: String,
    key: String,
    value: Vec<u8>,
    expected: Option<u64>,
}

pub(crate) struct DelayedWrite {
    parked: oneshot::Receiver<()>,
    deliver: oneshot::Sender<()>,
    done: oneshot::Receiver<WriteResult>,
}

impl DelayedWrite {
    pub(crate) async fn wait_parked(&mut self) {
        (&mut self.parked).await.expect("request reached hub");
    }

    pub(crate) async fn deliver(self) -> WriteResult {
        self.deliver.send(()).expect("hub retained request");
        self.done.await.expect("hub processed request")
    }
}

struct ParkedWrite {
    parked: oneshot::Sender<()>,
    deliver: oneshot::Receiver<()>,
    done: oneshot::Sender<WriteResult>,
}

#[derive(Clone)]
pub(crate) struct StandInClient {
    hub: StandIn,
    box_id: String,
    connections: watch::Sender<u64>,
}

impl StandInClient {
    pub(crate) fn replace_connection(&self) {
        self.connections.send_modify(|generation| *generation += 1);
    }

    async fn write(
        &self,
        bucket: &str,
        key: &str,
        value: Vec<u8>,
        expected: Option<u64>,
    ) -> WriteResult {
        let write = Write {
            bucket: bucket.into(),
            key: key.into(),
            value,
            expected,
        };
        let delayed = {
            let mut state = self.hub.0.lock().unwrap();
            let bucket = state.bucket(bucket)?;
            if bucket.delay.as_ref().is_some_and(|(armed, _)| armed == key) {
                bucket.delay.take().map(|(_, parked)| parked)
            } else {
                None
            }
        };
        let Some(delayed) = delayed else {
            return self.hub.commit(write);
        };
        // The hub can receive a write after the caller has dropped the old connection.
        // Only the reply is tied to the caller's future.
        let hub = self.hub.clone();
        let (ack, reply) = oneshot::channel();
        tokio::spawn(async move {
            let _ = delayed.parked.send(());
            let result = match delayed.deliver.await {
                Ok(()) => hub.commit(write),
                Err(_) => Err(HubError::Unavailable),
            };
            let _ = delayed.done.send(result);
            let _ = ack.send(result);
        });
        reply.await.unwrap_or(Err(HubError::Unavailable))
    }
}

#[async_trait]
impl Hub for StandInClient {
    fn box_id(&self) -> &str {
        &self.box_id
    }

    fn connection_changes(&self) -> watch::Receiver<u64> {
        self.connections.subscribe()
    }

    async fn watch_bucket(&self, bucket: &str) -> Result<Box<dyn HubWatch>, HubError> {
        let mut state = self.hub.0.lock().unwrap();
        let bucket = state.bucket(bucket)?;
        let (tx, rx) = mpsc::unbounded_channel();
        for item in bucket.history() {
            tx.send(Ok(item)).expect("receiver still open");
        }
        bucket.watchers.push(WatchSink {
            tx,
            queued: Vec::new(),
        });
        bucket.watch_opens += 1;
        Ok(Box::new(StandInWatch(rx)))
    }

    async fn entry(&self, bucket: &str, key: &str) -> Result<Option<HubEntry>, HubError> {
        Ok(self
            .hub
            .0
            .lock()
            .unwrap()
            .bucket(bucket)?
            .entries
            .get(key)
            .cloned())
    }

    async fn create(&self, bucket: &str, key: &str, value: Vec<u8>) -> WriteResult {
        self.write(bucket, key, value, None).await
    }

    async fn update(&self, bucket: &str, key: &str, value: Vec<u8>, revision: u64) -> WriteResult {
        self.write(bucket, key, value, Some(revision)).await
    }
}

struct StandInWatch(mpsc::UnboundedReceiver<Delivery>);

#[async_trait]
impl HubWatch for StandInWatch {
    async fn next(&mut self) -> Option<Delivery> {
        self.0.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUCKET: &str = SHARED_LOGINS;
    const KEY: &str = "h.m";
    const OTHER: &str = "h.n";

    fn put(key: &str, value: &[u8], revision: u64) -> HubEvent {
        HubEvent::Entry(HubEntry {
            key: key.into(),
            value: value.into(),
            revision,
            operation: HubOperation::Put,
        })
    }

    async fn next(watch: &mut dyn HubWatch) -> HubEvent {
        watch
            .next()
            .await
            .expect("watch is still open")
            .expect("watch did not fail")
    }

    #[tokio::test]
    async fn history_one_cas_and_tombstones_match_point_reads() {
        let hub = StandIn::new();
        let home = hub.client("home");
        let member = hub.client("member");
        assert_eq!((home.box_id(), member.box_id()), ("home", "member"));
        assert_eq!(member.entry(BUCKET, KEY).await, Ok(None));
        assert_eq!(home.create(BUCKET, KEY, b"old".to_vec()).await, Ok(1));
        assert_eq!(
            home.create(BUCKET, KEY, b"old".to_vec()).await,
            Err(HubError::Conflict)
        );
        assert_eq!(home.create(BUCKET, OTHER, b"other".to_vec()).await, Ok(2));
        assert_eq!(
            home.update(BUCKET, KEY, b"older".to_vec(), 2).await,
            Err(HubError::Conflict)
        );
        assert_eq!(home.update(BUCKET, KEY, b"new".to_vec(), 1).await, Ok(3));
        assert_eq!(hub.delete(BUCKET, OTHER), Ok(4));

        let mut watch = member.watch_bucket(BUCKET).await.unwrap();
        assert_eq!(next(&mut *watch).await, put(KEY, b"new", 3));
        let tombstone = member.entry(BUCKET, OTHER).await.unwrap().unwrap();
        assert_eq!(tombstone.operation, HubOperation::Delete);
        assert_eq!(tombstone.revision, 4);
        assert!(tombstone.value.is_empty());
        assert_eq!(next(&mut *watch).await, HubEvent::Entry(tombstone));
        assert_eq!(next(&mut *watch).await, HubEvent::CaughtUp);

        assert_eq!(hub.purge(BUCKET, OTHER), Ok(5));
        let tombstone = member.entry(BUCKET, OTHER).await.unwrap().unwrap();
        assert_eq!(tombstone.operation, HubOperation::Purge);
        assert_eq!(tombstone.revision, 5);
        assert_eq!(next(&mut *watch).await, HubEvent::Entry(tombstone));
        assert_eq!(
            home.update(BUCKET, OTHER, b"after purge".to_vec(), 5).await,
            Ok(6)
        );
        assert_eq!(next(&mut *watch).await, put(OTHER, b"after purge", 6));
    }

    #[tokio::test]
    async fn queued_reset_reuses_revisions_and_relists_on_the_same_watch() {
        let hub = StandIn::new();
        let home = hub.client("home");
        let member = hub.client("member");
        let mut watch = member.watch_bucket(BUCKET).await.unwrap();
        assert_eq!(next(&mut *watch).await, HubEvent::CaughtUp);
        hub.pause_delivery(BUCKET);
        assert_eq!(
            home.create(BUCKET, KEY, b"old incarnation".to_vec()).await,
            Ok(1)
        );
        hub.reset_bucket(BUCKET, &[(KEY, b"new incarnation")]);
        assert_eq!(hub.tamper(BUCKET, KEY, b"tampered"), Ok(2));
        assert_eq!(
            member.entry(BUCKET, KEY).await.unwrap().unwrap().value,
            b"tampered"
        );
        tokio::select! {
            biased;
            event = watch.next() => panic!("delivery is paused, got {event:?}"),
            () = std::future::ready(()) => {}
        }
        hub.resume_delivery(BUCKET);
        assert_eq!(next(&mut *watch).await, put(KEY, b"old incarnation", 1));
        assert_eq!(
            next(&mut *watch).await,
            HubEvent::BucketReset {
                bucket: BUCKET.into()
            }
        );
        assert_eq!(next(&mut *watch).await, put(KEY, b"new incarnation", 1));
        assert_eq!(next(&mut *watch).await, HubEvent::CaughtUp);
        assert_eq!(next(&mut *watch).await, put(KEY, b"tampered", 2));
        assert_eq!(hub.watch_opens(BUCKET), 1);
    }

    #[tokio::test]
    async fn outage_and_clean_end_are_independent_of_replacement() {
        let hub = StandIn::new();
        let home = hub.client("home");
        let member = hub.client("member");
        let home_connection = home.connection_changes();
        let mut member_connection = member.connection_changes();
        let mut watch = member.watch_bucket(BUCKET).await.unwrap();
        assert_eq!(next(&mut *watch).await, HubEvent::CaughtUp);
        hub.terminate_watches(BUCKET);
        assert_eq!(watch.next().await, None);
        assert!(!member_connection.has_changed().unwrap());
        let mut watch = member.watch_bucket(BUCKET).await.unwrap();
        assert_eq!(next(&mut *watch).await, HubEvent::CaughtUp);
        hub.set_online(false);
        assert_eq!(watch.next().await, Some(Err(HubError::Unavailable)));
        assert_eq!(watch.next().await, None);
        assert!(matches!(
            member.watch_bucket(BUCKET).await,
            Err(HubError::Unavailable)
        ));
        assert_eq!(home.entry(BUCKET, KEY).await, Err(HubError::Unavailable));
        assert_eq!(
            home.create(BUCKET, KEY, b"missed".to_vec()).await,
            Err(HubError::Unavailable)
        );
        hub.set_online(true);
        member.replace_connection();
        assert!(member_connection.has_changed().unwrap());
        assert_eq!(*member_connection.borrow_and_update(), 1);
        assert!(!home_connection.has_changed().unwrap());
        assert_eq!(home.create(BUCKET, KEY, b"restored".to_vec()).await, Ok(1));
        let mut watch = member.watch_bucket(BUCKET).await.unwrap();
        assert_eq!(next(&mut *watch).await, put(KEY, b"restored", 1));
        assert_eq!(next(&mut *watch).await, HubEvent::CaughtUp);
    }

    #[tokio::test]
    async fn delayed_request_can_land_after_connection_replacement_and_lost_ack() {
        let hub = StandIn::new();
        let home = hub.client("home");
        let member = hub.client("member");
        let mut watch = member.watch_bucket(BUCKET).await.unwrap();
        assert_eq!(next(&mut *watch).await, HubEvent::CaughtUp);
        let mut delayed = hub.delay_next_write(BUCKET, KEY);
        let task = tokio::spawn({
            let home = home.clone();
            async move { home.create(BUCKET, KEY, b"late".to_vec()).await }
        });
        delayed.wait_parked().await;
        assert_eq!(member.entry(BUCKET, KEY).await, Ok(None));
        home.replace_connection();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        hub.lose_next_ack(BUCKET, KEY);
        assert_eq!(delayed.deliver().await, Err(HubError::Unavailable));
        assert_eq!(next(&mut *watch).await, put(KEY, b"late", 1));
        let late = member.entry(BUCKET, KEY).await.unwrap().unwrap();
        assert_eq!(late.value, b"late");
        assert_eq!(
            home.update(BUCKET, KEY, b"latest".to_vec(), late.revision)
                .await,
            Ok(2)
        );
        assert_eq!(next(&mut *watch).await, put(KEY, b"latest", 2));
    }
}
