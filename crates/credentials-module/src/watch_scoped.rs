//! Held scoped-inventory subscriptions. Route teardown cancels publication promptly;
//! a separate snapshot budget stays occupied until blocking computations finish.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};
use serde_json::json;
use subc_protocol::{Flags, Frame, FrameType, Principal, Priority};
use tokio::sync::{mpsc, oneshot, watch, Semaphore};

use crate::read_surface::{ErrorBody, ListScopedParams, ReadError, ReadSurface};
use crate::{send, wrap_result, ModuleError};

pub(crate) const MAX_WATCHES: usize = 64;
const COALESCE: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, PartialEq)]
enum Stop {
    Running,
    Silent,
    Replaced,
    Finished,
}

struct Entry {
    corr: u64,
    stop: watch::Sender<Stop>,
    done: oneshot::Receiver<()>,
}

#[derive(Default)]
struct Registry {
    entries: HashMap<u16, Entry>,
    draining: bool,
}

pub(crate) struct WatchHub {
    entries: Arc<Mutex<Registry>>,
    snapshots: Arc<Semaphore>,
    manifest_upstreams: Arc<crate::federation::manifest_watch::Hub>,
    #[cfg(test)]
    pub(crate) completed: watch::Sender<u64>,
}

impl Default for WatchHub {
    fn default() -> Self {
        process_epoch();
        Self {
            entries: Arc::default(),
            snapshots: Arc::new(Semaphore::new(MAX_WATCHES)),
            manifest_upstreams: Arc::default(),
            #[cfg(test)]
            completed: watch::channel(0).0,
        }
    }
}

pub(crate) struct CloseOnDrop(pub Arc<ReadSurface>);
impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.watches.close_all();
    }
}

#[derive(Clone)]
enum Inventory {
    Scoped {
        principal: Option<Principal>,
        params: Arc<ListScopedParams>,
    },
    Connectors(Arc<crate::admin_surface::AdminSurface>),
    Manifest,
}

fn process_epoch() -> &'static str {
    static EPOCH: OnceLock<String> = OnceLock::new();
    EPOCH.get_or_init(|| {
        let mut bytes = [0; 16];
        SystemRandom::new().fill(&mut bytes).expect("OS randomness");
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    })
}

impl WatchHub {
    #[cfg(test)]
    pub(crate) fn contains(&self, channel: u16) -> bool {
        self.entries
            .lock()
            .expect("watches")
            .entries
            .contains_key(&channel)
    }

    pub(crate) fn close_all(&self) {
        for (_, entry) in self.entries.lock().expect("watches").entries.drain() {
            entry.stop.send_replace(Stop::Silent);
        }
    }

    pub(crate) fn close(&self, channel: u16) {
        if let Some(entry) = self
            .entries
            .lock()
            .expect("watches")
            .entries
            .remove(&channel)
        {
            entry.stop.send_replace(Stop::Silent);
        }
    }

    pub(crate) fn cancel(&self, channel: u16, corr: u64) {
        let mut entries = self.entries.lock().expect("watches");
        if entries
            .entries
            .get(&channel)
            .is_some_and(|entry| entry.corr == corr)
        {
            let entry = entries.entries.remove(&channel).expect("matched watch");
            entry.stop.send_replace(Stop::Silent);
        }
    }

    pub(crate) async fn finish_all(&self) -> Result<(), ModuleError> {
        let entries: Vec<_> = {
            let mut registry = self.entries.lock().expect("watches");
            // Process-lifetime latch: subc-protocol 0.31.0's
            // session::ModuleControlCommand::Draining documents that the daemon
            // kills the module at the drain ceiling regardless of module action.
            // That command has no resume/cancel counterpart; a new process gets
            // a new hub rather than reopening this one after drain.
            registry.draining = true;
            registry
                .entries
                .drain()
                .map(|(_, entry)| {
                    entry.stop.send_replace(Stop::Finished);
                    entry
                })
                .collect()
        };
        // Each task serializes its own data and terminal frames. Wait for its final
        // send so no racing snapshot can publish after STREAM_END, and no held
        // request consumes the supervisor's drain budget after dispatch returns.
        for entry in entries {
            let _ = entry.done.await;
        }
        Ok(())
    }

    pub(crate) fn open(
        &self,
        surface: Arc<ReadSurface>,
        writer: mpsc::Sender<Frame>,
        header: subc_protocol::EnvelopeHeader,
        principal: Option<Principal>,
        params: ListScopedParams,
    ) -> bool {
        self.open_inventory(
            surface,
            writer,
            header,
            Inventory::Scoped {
                principal,
                params: Arc::new(params),
            },
        )
    }

    pub(crate) fn open_connectors(
        &self,
        surface: Arc<ReadSurface>,
        writer: mpsc::Sender<Frame>,
        header: subc_protocol::EnvelopeHeader,
        admin: Arc<crate::admin_surface::AdminSurface>,
    ) -> bool {
        self.open_inventory(surface, writer, header, Inventory::Connectors(admin))
    }

    pub(crate) fn open_manifest(
        &self,
        surface: Arc<ReadSurface>,
        writer: mpsc::Sender<Frame>,
        header: subc_protocol::EnvelopeHeader,
    ) -> bool {
        self.open_inventory(surface, writer, header, Inventory::Manifest)
    }

    fn open_inventory(
        &self,
        surface: Arc<ReadSurface>,
        writer: mpsc::Sender<Frame>,
        header: subc_protocol::EnvelopeHeader,
        inventory: Inventory,
    ) -> bool {
        let (stop, stopped) = watch::channel(Stop::Running);
        let (finished, done) = oneshot::channel();
        {
            let mut entries = self.entries.lock().expect("watches");
            if entries.draining
                || (entries.entries.len() >= MAX_WATCHES
                    && !entries.entries.contains_key(&header.channel))
            {
                return false;
            }
            if let Some(old) = entries.entries.insert(
                header.channel,
                Entry {
                    corr: header.corr,
                    stop: stop.clone(),
                    done,
                },
            ) {
                old.stop.send_replace(Stop::Replaced);
            }
        }
        // Subscribe before the initial snapshot: a commit racing that snapshot must
        // either be included in it or wake the next recomputation.
        let writes = surface.subscribe_writes();
        let entries = Arc::clone(&self.entries);
        let snapshots = Arc::clone(&self.snapshots);
        let manifest_upstreams = Arc::clone(&self.manifest_upstreams);
        #[cfg(test)]
        let completed = self.completed.clone();
        tokio::spawn(async move {
            let mut subscription = Subscription {
                surface,
                writer,
                header,
                inventory,
                stopped,
                writes,
                snapshots,
                manifest_upstreams,
                #[cfg(test)]
                completed,
            };
            let _ = subscription.run().await;
            let mut entries = entries.lock().expect("watches");
            if entries
                .entries
                .get(&header.channel)
                .is_some_and(|entry| entry.stop.same_channel(&stop))
            {
                entries.entries.remove(&header.channel);
            }
            let _ = finished.send(());
        });
        true
    }
}

pub(crate) async fn refusal(
    writer: &mpsc::Sender<Frame>,
    header: subc_protocol::EnvelopeHeader,
    ty: FrameType,
    code: ReadError,
) -> Result<(), ModuleError> {
    emit(
        writer,
        header,
        ty,
        serde_json::to_vec(&wrap_result(
            json!({"error": ErrorBody { code, class: code.class() }}),
        ))
        .map_err(ModuleError::Json)?,
    )
    .await
}

async fn emit(
    writer: &mpsc::Sender<Frame>,
    header: subc_protocol::EnvelopeHeader,
    ty: FrameType,
    body: Vec<u8>,
) -> Result<(), ModuleError> {
    let flags = Flags::new(false, Priority::Interactive, false);
    let flags = if ty == FrameType::StreamData {
        flags.with_admission_class(subc_protocol::AdmissionClass::Sheddable)
    } else {
        flags
    };
    let frame = Frame::build_with_version(
        header.ver,
        ty,
        flags,
        header.channel,
        header.epoch,
        header.corr,
        body,
    )
    .map_err(|error| ModuleError::Message(error.to_string()))?;
    send(writer, frame).await
}

struct Subscription {
    surface: Arc<ReadSurface>,
    writer: mpsc::Sender<Frame>,
    header: subc_protocol::EnvelopeHeader,
    inventory: Inventory,
    stopped: watch::Receiver<Stop>,
    writes: watch::Receiver<()>,
    snapshots: Arc<Semaphore>,
    manifest_upstreams: Arc<crate::federation::manifest_watch::Hub>,
    #[cfg(test)]
    completed: watch::Sender<u64>,
}

async fn snapshot<T: Send + 'static>(
    slots: Arc<Semaphore>,
    compute: impl FnOnce() -> Result<T, ReadError> + Send + 'static,
) -> Result<T, ReadError> {
    let permit = slots
        .acquire_owned()
        .await
        .expect("snapshot budget is open");
    tokio::task::spawn_blocking(move || {
        // Dropping the awaiting subscription cannot stop a submitted blocking job.
        // The job therefore owns its slot, including while queued for a worker.
        let _permit = permit;
        compute()
    })
    .await
    .unwrap_or(Err(ReadError::StoreError))
}

impl Subscription {
    async fn run(&mut self) -> Result<(), ModuleError> {
        if matches!(self.inventory, Inventory::Manifest) {
            if let credentials_core::store::SecretHomeRole::Remote { home_member } =
                self.surface.store().secret_home_role()
            {
                return self.run_manifest_remote(&home_member).await;
            }
        }
        let mut last = None;
        let mut seq = 0u64;
        loop {
            // Cancellation wins over a ready snapshot/send. Dropping a blocking
            // worker cannot stop SQLite, but it can prevent publishing its result.
            let stopped = &mut self.stopped;
            let surface = Arc::clone(&self.surface);
            let writer = self.writer.clone();
            let header = self.header;
            let inventory = self.inventory.clone();
            let snapshots = Arc::clone(&self.snapshots);
            tokio::select! {
                biased;
                _ = stopped.changed() => break,
                result = async {
                    if let Inventory::Connectors(admin) = &inventory {
                        if !crate::connectors::admit(header, &writer, admin, false).await? {
                            return Ok(false);
                        }
                    }
                    let snapshot = snapshot(snapshots, move || match inventory {
                        Inventory::Scoped { principal, params } => surface.watch_scoped(principal.as_ref(), &params)
                            .map(|(view, keys)| json!({"view":view, "keys":keys})),
                        Inventory::Connectors(_) => crate::connectors::list(surface.store()).and_then(|reply| {
                            reply["version"].as_str().map(|version| json!({"version":version})).ok_or(ReadError::StoreError)
                        }),
                        Inventory::Manifest => {
                            let reply = crate::manifest::watch_snapshot(surface.store());
                            if reply["error"]["code"] == "store_error" { Err(ReadError::StoreError) } else { Ok(reply) }
                        }
                    }).await;
                    match snapshot {
                        Ok(values) => {
                            if values.get("error").is_some() {
                                let body = serde_json::to_vec(&wrap_result(values)).map_err(ModuleError::Json)?;
                                emit(&writer, header, FrameType::Response, body).await?;
                                return Ok(false);
                            }
                            if last.as_ref() != Some(&values) {
                                seq += 1;
                                let mut notice = values.clone();
                                notice["kind"] = json!("changed");
                                notice["epoch"] = json!(process_epoch());
                                notice["seq"] = json!(seq);
                                let body = serde_json::to_vec(&notice).map_err(ModuleError::Json)?;
                                emit(&writer, header, FrameType::StreamData, body).await?;
                                last = Some(values);
                            }
                            Ok(true)
                        }
                        Err(code) if seq == 0 || code == ReadError::NotFound => {
                            // Domain refusals use Response even after notices: SDKs
                            // decode Error as subc's transport ErrorBody, not result.error.
                            refusal(&writer, header, FrameType::Response, code).await?;
                            Ok(false)
                        }
                        // A transient store failure must not masquerade as a smaller
                        // inventory. Retain the last digests and retry on the next commit.
                        Err(_) => Ok(true),
                    }
                } => { if !result? { return Ok(()); } }
            }
            #[cfg(test)]
            self.completed.send_modify(|count| *count += 1);
            tokio::select! {
                biased;
                _ = self.stopped.changed() => break,
                result = self.writes.changed() => { if result.is_err() { break; } }
            }
            tokio::select! {
                biased;
                _ = self.stopped.changed() => break,
                _ = tokio::time::sleep(COALESCE) => {}
            }
            self.writes.borrow_and_update();
        }
        if *self.stopped.borrow() != Stop::Silent {
            emit(&self.writer, self.header, FrameType::StreamEnd, Vec::new()).await?;
        }
        Ok(())
    }

    async fn run_manifest_remote(&mut self, home: &str) -> Result<(), ModuleError> {
        use crate::federation::manifest_watch::State;
        let session = self
            .manifest_upstreams
            .subscribe(home, self.surface.remote().outbound_client());
        let mut current = session.current.clone();
        let mut seq = 0;
        let mut last = None;
        loop {
            let state = current.borrow_and_update().clone();
            tokio::select! {
                biased;
                _ = self.stopped.changed() => break,
                result = async {
                    match state {
                        State::Opening => {}
                        State::Current(value) => {
                            if last.as_ref() != Some(&value) {
                                seq += 1;
                                let mut notice = value.clone();
                                notice["kind"] = json!("changed");
                                notice["epoch"] = json!(process_epoch());
                                notice["seq"] = json!(seq);
                                emit(&self.writer, self.header, FrameType::StreamData, serde_json::to_vec(&notice).map_err(ModuleError::Json)?).await?;
                                last = Some(value);
                            }
                        }
                        State::Refused(reply) => {
                            emit(&self.writer, self.header, FrameType::Response, serde_json::to_vec(&wrap_result(reply)).map_err(ModuleError::Json)?).await?;
                            return Ok(false);
                        }
                        State::End => {
                            if seq == 0 {
                                emit(&self.writer, self.header, FrameType::Response, serde_json::to_vec(&wrap_result(json!({"error":{"code":"home_unavailable","class":"transient"}}))).map_err(ModuleError::Json)?).await?;
                            } else {
                                emit(&self.writer, self.header, FrameType::StreamEnd, Vec::new()).await?;
                            }
                            return Ok(false);
                        }
                    }
                    Ok::<_, ModuleError>(true)
                } => { if !result? { return Ok(()); } }
            }
            tokio::select! {
                biased;
                _ = self.stopped.changed() => break,
                result = current.changed() => { if result.is_err() { break; } }
            }
        }
        if *self.stopped.borrow() != Stop::Silent {
            emit(&self.writer, self.header, FrameType::StreamEnd, Vec::new()).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Condvar;
    use std::task::Poll;

    struct ReleaseOnDrop(Arc<(Mutex<bool>, Condvar)>);

    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            let (lock, changed) = &*self.0;
            *lock.lock().unwrap() = true;
            changed.notify_all();
        }
    }

    #[tokio::test]
    async fn cancelled_snapshots_keep_the_budget_until_blocking_jobs_finish() {
        let hub = WatchHub::default();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let release = ReleaseOnDrop(Arc::clone(&gate));
        let admitted = Arc::new(AtomicUsize::new(0));
        for _ in 0..MAX_WATCHES {
            let (started, arrived) = oneshot::channel();
            let gate = Arc::clone(&gate);
            let admitted = Arc::clone(&admitted);
            let mut pending = Box::pin(snapshot(Arc::clone(&hub.snapshots), move || {
                admitted.fetch_add(1, Ordering::SeqCst);
                started.send(()).unwrap();
                let (lock, changed) = &*gate;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = changed.wait(released).unwrap();
                }
                Ok(())
            }));
            tokio::select! {
                result = arrived => result.unwrap(),
                _ = &mut pending => panic!("snapshot finished before release"),
            }
            // This is the same future drop as the subscription's cancellation arm.
            drop(pending);
        }
        assert_eq!(admitted.load(Ordering::SeqCst), 64);
        assert_eq!(hub.snapshots.available_permits(), 0);
        let count = Arc::clone(&admitted);
        let mut next = Box::pin(snapshot(Arc::clone(&hub.snapshots), move || {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));
        std::future::poll_fn(|cx| {
            assert!(next.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(admitted.load(Ordering::SeqCst), 64);
        drop(release);
        next.await.unwrap();
        let _all = hub.snapshots.acquire_many(64).await.unwrap();
        assert_eq!(admitted.load(Ordering::SeqCst), 65);
    }
}
