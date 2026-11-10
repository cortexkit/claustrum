//! Home-side remote inventory streams, including opens still checking their pairing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use credentials_core::federation::RemoteWatchRow;
use credentials_core::store::EncryptedStore;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use subc_protocol::{EnvelopeHeader, Flags, Frame, FrameType, Priority};
use tokio::sync::{mpsc, watch, Semaphore};

use super::ingress::{remote_watch_lists_equal, remote_watch_logins_wire, HomeAnswer, HomeVault};

const COALESCE: Duration = Duration::from_millis(250);
const RECHECK: Duration = Duration::from_secs(60);

async fn send(writer: &mpsc::Sender<Frame>, frame: Frame) -> Result<(), String> {
    writer
        .send(frame)
        .await
        .map_err(|_| "egress channel closed".to_owned())
}

pub(crate) const MAX_REMOTE_WATCHES_PER_MEMBER: usize = 4;
type Key = (u16, u64);

pub(crate) struct PreparedWatch {
    pub member: String,
    pub pairing: String,
    pub home: String,
    pub rows: Vec<RemoteWatchRow>,
    pub store: Arc<EncryptedStore>,
    pub writes: watch::Receiver<()>,
    pub budget: Duration,
}

pub struct PendingOpen {
    key: Key,
    identity: Arc<()>,
    pairing_generation: u64,
}

struct Live {
    member: String,
    order: u64,
    writer: mpsc::Sender<Frame>,
    header: EnvelopeHeader,
}

struct Entry {
    identity: Arc<()>,
    live: Option<Live>,
    stopped: watch::Sender<()>,
}

#[derive(Default)]
struct Registry {
    entries: HashMap<Key, Entry>,
    draining: bool,
    order: u64,
}

#[derive(Default)]
struct Pairings {
    generation: u64,
    devices: HashMap<String, String>,
}

pub struct RemoteWatchHub {
    registry: Arc<Mutex<Registry>>,
    // Serialize admission and terminal publication, never the pairing/store checks.
    publication: Arc<tokio::sync::Mutex<()>>,
    pairings: watch::Sender<Arc<Pairings>>,
    snapshots: Arc<Semaphore>,
    #[cfg(test)]
    pub(crate) before_checks: OnceLock<super::ingress::IssueAuditGate>,
    #[cfg(test)]
    pub(crate) completed: tokio::sync::Notify,
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) waking: Arc<tokio::sync::Notify>,
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) refreshed: Arc<tokio::sync::Notify>,
    #[cfg(test)]
    pub(crate) before_projection: Arc<OnceLock<super::ingress::IssueAuditGate>>,
}

impl Default for RemoteWatchHub {
    fn default() -> Self {
        Self {
            registry: Arc::default(),
            publication: Arc::default(),
            pairings: watch::channel(Arc::new(Pairings::default())).0,
            snapshots: Arc::new(Semaphore::new(MAX_REMOTE_WATCHES_PER_MEMBER)),
            #[cfg(test)]
            before_checks: OnceLock::new(),
            #[cfg(test)]
            completed: tokio::sync::Notify::new(),
            #[cfg(any(test, feature = "test-support"))]
            waking: Arc::default(),
            #[cfg(any(test, feature = "test-support"))]
            refreshed: Arc::default(),
            #[cfg(test)]
            before_projection: Arc::default(),
        }
    }
}

#[cfg(test)]
struct Completed<'a>(&'a tokio::sync::Notify);

#[cfg(test)]
impl Drop for Completed<'_> {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

fn epoch() -> &'static str {
    static EPOCH: OnceLock<String> = OnceLock::new();
    EPOCH.get_or_init(|| {
        let mut bytes = [0; 16];
        SystemRandom::new().fill(&mut bytes).expect("OS randomness");
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    })
}

fn unavailable() -> HomeAnswer {
    HomeAnswer::Reply(json!({"error":{"code":"home_unavailable","class":"transient"}}))
}

fn frame(header: EnvelopeHeader, ty: FrameType, body: Vec<u8>) -> Result<Frame, String> {
    let flags = Flags::new(false, Priority::Interactive, false);
    let flags = if ty == FrameType::StreamData {
        flags.with_admission_class(subc_protocol::AdmissionClass::Sheddable)
    } else {
        flags
    };
    Frame::build_with_version(
        header.ver,
        ty,
        flags,
        header.channel,
        header.epoch,
        header.corr,
        body,
    )
    .map_err(|error| error.to_string())
}

pub(crate) fn refusal(header: EnvelopeHeader, answer: HomeAnswer) -> Result<Frame, String> {
    let mut detail = match answer {
        HomeAnswer::Reply(reply) => reply
            .get("error")
            .and_then(Value::as_object)
            .cloned()
            .ok_or_else(|| "watch refusal missing error".to_owned())?,
        HomeAnswer::InvalidParams(_) => serde_json::Map::from_iter([
            ("code".into(), json!("invalid_params")),
            ("class".into(), json!("permanent")),
        ]),
    };
    let code = detail
        .remove("code")
        .and_then(|code| code.as_str().map(str::to_owned))
        .ok_or_else(|| "watch refusal missing code".to_owned())?;
    // Callosum drops the body of a watch Response as a clean completion. Only an
    // Error carries the home's refusal back to the subscribing member.
    let body = json!({"code": code, "message": code.replace('_', " "), "detail": detail});
    frame(
        header,
        FrameType::Error,
        serde_json::to_vec(&body).map_err(|error| error.to_string())?,
    )
}

impl Registry {
    fn contains(&self, pending: &PendingOpen) -> bool {
        self.entries
            .get(&pending.key)
            .is_some_and(|entry| Arc::ptr_eq(&entry.identity, &pending.identity))
    }
}

impl RemoteWatchHub {
    /// Let socket integration tests advance coalescing only after a stream wakes.
    #[cfg(feature = "test-support")]
    pub async fn waking_for_test(&self) {
        self.waking.notified().await;
    }

    /// Let integration tests observe an inventory re-read even if nothing changed.
    #[cfg(feature = "test-support")]
    pub async fn refreshed_for_test(&self) {
        self.refreshed.notified().await;
    }

    /// No I/O: the frame loop installs this before it can read a following Cancel.
    pub fn register(&self, header: EnvelopeHeader) -> PendingOpen {
        let pending = PendingOpen {
            key: (header.channel, header.corr),
            identity: Arc::new(()),
            pairing_generation: self.pairings.borrow().generation,
        };
        self.registry
            .lock()
            .expect("remote watches")
            .entries
            .insert(
                pending.key,
                Entry {
                    identity: Arc::clone(&pending.identity),
                    live: None,
                    stopped: watch::channel(()).0,
                },
            );
        pending
    }

    /// A decoded full inventory is authoritative even if reconciling its grants fails.
    /// Include devices whose vault switch is off: operator grants can still cover them.
    pub fn paired_devices(&self, devices: impl IntoIterator<Item = (String, String)>) {
        self.pairings.send_modify(|current| {
            *current = Arc::new(Pairings {
                generation: current.generation + 1,
                devices: devices
                    .into_iter()
                    .map(|(fingerprint, pairing)| (format!("fed-computer:{fingerprint}"), pairing))
                    .collect(),
            });
        });
    }

    pub fn cancel(&self, channel: u16, corr: u64) {
        self.registry
            .lock()
            .expect("remote watches")
            .entries
            .remove(&(channel, corr));
    }

    pub fn close(&self, channel: u16) {
        self.registry
            .lock()
            .expect("remote watches")
            .entries
            .retain(|key, _| key.0 != channel);
    }

    pub async fn finish_all(&self) -> Result<(), String> {
        // Latch before waiting for publication: pending checks must observe draining
        // even when an older stream's writer is backpressured.
        self.registry.lock().expect("remote watches").draining = true;
        let _publication = self.publication.lock().await;
        let live: Vec<_> = {
            let mut registry = self.registry.lock().expect("remote watches");
            let mut live = Vec::new();
            registry.entries.retain(|_, entry| match entry.live.take() {
                Some(stream) => {
                    live.push(stream);
                    false
                }
                None => true,
            });
            live
        };
        for stream in live {
            send(
                &stream.writer,
                frame(stream.header, FrameType::StreamEnd, Vec::new())?,
            )
            .await?;
        }
        Ok(())
    }

    pub async fn open(
        &self,
        home: &HomeVault,
        pending: PendingOpen,
        writer: &mpsc::Sender<Frame>,
        header: EnvelopeHeader,
        member: &str,
        params: &Value,
    ) -> Result<(), String> {
        #[cfg(test)]
        let _completed = Completed(&self.completed);
        let draining = {
            let registry = self.registry.lock().expect("remote watches");
            if !registry.contains(&pending) {
                return Ok(());
            }
            registry.draining
        };
        #[cfg(test)]
        if !draining {
            if let Some(gate) = self.before_checks.get() {
                gate().await;
            }
        }
        let prepared = if draining {
            Err(unavailable())
        } else {
            home.prepare_remote_watch(member, params).await
        };
        let result = self.publish(&pending, writer, header, prepared).await;
        if result.is_err() {
            let mut registry = self.registry.lock().expect("remote watches");
            if registry.contains(&pending) {
                registry.entries.remove(&pending.key);
            }
        }
        result
    }

    async fn publish(
        &self,
        pending: &PendingOpen,
        writer: &mpsc::Sender<Frame>,
        header: EnvelopeHeader,
        prepared: Result<PreparedWatch, HomeAnswer>,
    ) -> Result<(), String> {
        let _publication = self.publication.lock().await;
        let snapshot = prepared
            .as_ref()
            .ok()
            .map(|watch| {
                serde_json::to_vec(&json!({
                    "kind":"snapshot", "home":watch.home, "epoch":epoch(), "seq":1,
                    "logins":remote_watch_logins_wire(&watch.rows),
                }))
                .map_err(|error| error.to_string())
                .and_then(|body| frame(header, FrameType::StreamData, body))
            })
            .transpose()?;
        let oldest = {
            let registry = self.registry.lock().expect("remote watches");
            if !registry.contains(pending) {
                return Ok(());
            }
            prepared
                .as_ref()
                .ok()
                .filter(|_| !registry.draining)
                .and_then(|watch| {
                    let live: Vec<_> = registry
                        .entries
                        .iter()
                        .filter_map(|(key, entry)| {
                            entry
                                .live
                                .as_ref()
                                .filter(|live| live.member == watch.member)
                                .map(|live| (*key, Arc::clone(&entry.identity), live))
                        })
                        .collect();
                    (live.len() >= MAX_REMOTE_WATCHES_PER_MEMBER).then(|| {
                        let (key, identity, live) = live
                            .into_iter()
                            .min_by_key(|(_, _, live)| live.order)
                            .expect("at cap");
                        (key, identity, live.writer.clone(), live.header)
                    })
                })
        };
        if let Some((key, identity, old_writer, old_header)) = oldest {
            let end = frame(old_header, FrameType::StreamEnd, Vec::new())?;
            let permit = old_writer.reserve().await;
            let mut registry = self.registry.lock().expect("remote watches");
            if !registry.contains(pending) {
                return Ok(());
            }
            let same_stream = registry
                .entries
                .get(&key)
                .is_some_and(|entry| Arc::ptr_eq(&entry.identity, &identity));
            if !registry.draining && same_stream {
                registry.entries.remove(&key);
                if let Ok(permit) = permit {
                    permit.send(end);
                }
            }
        }
        // Reserve before rechecking the entry. Cancel/Goodbye during backpressure
        // removes it, and no frame for that correlation is then enqueued.
        let permit = writer
            .reserve()
            .await
            .map_err(|_| "egress channel closed".to_owned())?;
        let mut registry = self.registry.lock().expect("remote watches");
        if !registry.contains(pending) {
            return Ok(());
        }
        let prepared = if registry.draining {
            Err(unavailable())
        } else {
            prepared
        };
        match prepared {
            Err(answer) => {
                registry.entries.remove(&pending.key);
                permit.send(refusal(header, answer)?);
            }
            Ok(watch) => {
                registry.order += 1;
                let order = registry.order;
                registry
                    .entries
                    .get_mut(&pending.key)
                    .expect("pending open")
                    .live = Some(Live {
                    member: watch.member.clone(),
                    order,
                    writer: writer.clone(),
                    header,
                });
                permit.send(snapshot.expect("successful projection"));
                let subscription = Subscription {
                    registry: Arc::downgrade(&self.registry),
                    publication: Arc::clone(&self.publication),
                    pending: PendingOpen {
                        key: pending.key,
                        identity: Arc::clone(&pending.identity),
                        pairing_generation: pending.pairing_generation,
                    },
                    stopped: registry.entries[&pending.key].stopped.subscribe(),
                    pairings: self.pairings.subscribe(),
                    snapshots: Arc::clone(&self.snapshots),
                    writer: writer.clone(),
                    header,
                    watch,
                    #[cfg(any(test, feature = "test-support"))]
                    waking: Arc::clone(&self.waking),
                    #[cfg(any(test, feature = "test-support"))]
                    refreshed: Arc::clone(&self.refreshed),
                    #[cfg(test)]
                    before_projection: Arc::clone(&self.before_projection),
                };
                tokio::spawn(subscription.run());
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        self.registry.lock().expect("remote watches").entries.len()
    }
}

struct Subscription {
    registry: Weak<Mutex<Registry>>,
    publication: Arc<tokio::sync::Mutex<()>>,
    pending: PendingOpen,
    stopped: watch::Receiver<()>,
    pairings: watch::Receiver<Arc<Pairings>>,
    snapshots: Arc<Semaphore>,
    writer: mpsc::Sender<Frame>,
    header: EnvelopeHeader,
    watch: PreparedWatch,
    #[cfg(any(test, feature = "test-support"))]
    waking: Arc<tokio::sync::Notify>,
    #[cfg(any(test, feature = "test-support"))]
    refreshed: Arc<tokio::sync::Notify>,
    #[cfg(test)]
    before_projection: Arc<OnceLock<super::ingress::IssueAuditGate>>,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            let mut registry = registry.lock().expect("remote watches");
            if registry.contains(&self.pending) {
                registry.entries.remove(&self.pending.key);
            }
        }
    }
}

impl Subscription {
    fn pairing_lost(&self) -> bool {
        let latest = self.pairings.borrow();
        latest.generation > self.pending.pairing_generation
            && latest.devices.get(&self.watch.member) != Some(&self.watch.pairing)
    }

    async fn project(&self) -> Result<Option<Vec<RemoteWatchRow>>, ()> {
        let store = Arc::clone(&self.watch.store);
        let member = self.watch.member.clone();
        let pairing = self.watch.pairing.clone();
        let snapshots = Arc::clone(&self.snapshots);
        let deadline = tokio::time::Instant::now() + self.watch.budget;
        let result = tokio::time::timeout_at(deadline, async {
            #[cfg(test)]
            if let Some(gate) = self.before_projection.get() {
                gate().await;
            }
            let permit = snapshots.acquire_owned().await.map_err(|_| ())?;
            tokio::task::spawn_blocking(move || {
                // A timed-out SQLite read still owns its slot until the worker exits.
                let _permit = permit;
                if !store.federation_member_mapping().map_err(|_| ())? {
                    return Ok(None);
                }
                HomeVault::project_remote_watch(&store, &member, &pairing)
                    .map(Some)
                    .map_err(|_| ())
            })
            .await
            .map_err(|_| ())?
        })
        .await
        .map_err(|_| ())?;
        if tokio::time::Instant::now() >= deadline {
            return Err(());
        }
        result
    }

    async fn publish(&self, rows: Option<&[RemoteWatchRow]>, seq: u64) -> Result<(), String> {
        let _publication = self.publication.lock().await;
        let permit = self.writer.reserve().await.map_err(|e| e.to_string())?;
        let Some(registry) = self.registry.upgrade() else {
            return Ok(());
        };
        let mut registry = registry.lock().expect("remote watches");
        if registry.draining || !registry.contains(&self.pending) {
            return Ok(());
        }
        // A pairing snapshot can arrive while the projection or writer is waiting.
        let rows = rows.filter(|_| !self.pairing_lost());
        let next = match rows {
            Some(rows) => frame(
                self.header,
                FrameType::StreamData,
                serde_json::to_vec(&json!({
                    "kind":"snapshot", "home":self.watch.home, "epoch":epoch(), "seq":seq,
                    "logins":remote_watch_logins_wire(rows),
                }))
                .map_err(|e| e.to_string())?,
            )?,
            None => {
                registry.entries.remove(&self.pending.key);
                refusal(
                    self.header,
                    HomeAnswer::Reply(json!({"error":{"code":"not_found","class":"permanent"}})),
                )?
            }
        };
        permit.send(next);
        Ok(())
    }

    async fn run(mut self) {
        let mut seq = 1;
        let mut timer = tokio::time::interval_at(tokio::time::Instant::now() + RECHECK, RECHECK);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            // The decoded snapshot may have arrived during the open's checks, before
            // this receiver was created. Do not wait for another event to inspect it.
            if !self.pairing_lost() {
                tokio::select! {
                    biased;
                    _ = self.stopped.changed() => break,
                    _ = self.writer.closed() => break,
                    result = self.watch.writes.changed() => { if result.is_err() { break; } }
                    result = self.pairings.changed() => { if result.is_err() { break; } }
                    _ = timer.tick() => {}
                }
            }
            #[cfg(any(test, feature = "test-support"))]
            self.waking.notify_one();
            tokio::select! {
                biased;
                _ = self.stopped.changed() => break,
                _ = tokio::time::sleep(COALESCE) => {}
            }
            self.watch.writes.borrow_and_update();
            self.pairings.borrow_and_update();
            let mut stopped = self.stopped.clone();
            let mut pairings = self.pairings.clone();
            let writer = self.writer.clone();
            let cycle = async {
                if self.pairing_lost() {
                    return self.publish(None, seq).await;
                }
                match self.project().await {
                    Ok(None) => self.publish(None, seq).await,
                    Ok(Some(rows)) if !remote_watch_lists_equal(&self.watch.rows, &rows) => {
                        self.publish(Some(&rows), seq + 1).await?;
                        self.watch.rows = rows;
                        seq += 1;
                        Ok(())
                    }
                    // Failures retain the last list. They must never look like revocation.
                    _ => Ok(()),
                }
            };
            tokio::select! {
                biased;
                _ = stopped.changed() => break,
                _ = writer.closed() => break,
                // A re-pair must not wait out a slow store read's operation budget.
                result = pairings.changed() => { if result.is_err() { break; } else { continue; } }
                result = cycle => { if result.is_err() { break; } }
            }
            #[cfg(any(test, feature = "test-support"))]
            self.refreshed.notify_one();
        }
    }
}
