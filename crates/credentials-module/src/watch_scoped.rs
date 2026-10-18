//! Held scoped-inventory subscriptions. The registry owns cancellation, not tasks,
//! so route teardown frees capacity even while a SQLite recomputation is in flight.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};
use serde_json::json;
use subc_protocol::{Flags, Frame, FrameType, Principal, Priority};
use tokio::sync::{mpsc, oneshot, watch};

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
}

impl Default for WatchHub {
    fn default() -> Self {
        process_epoch();
        Self {
            entries: Arc::default(),
        }
    }
}

pub(crate) struct CloseOnDrop(pub Arc<ReadSurface>);
impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.watches.close_all();
    }
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
        tokio::spawn(async move {
            let mut subscription = Subscription {
                surface,
                writer,
                header,
                principal,
                params: Arc::new(params),
                stopped,
                writes,
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
    principal: Option<Principal>,
    params: Arc<ListScopedParams>,
    stopped: watch::Receiver<Stop>,
    writes: watch::Receiver<()>,
}

impl Subscription {
    async fn run(&mut self) -> Result<(), ModuleError> {
        let mut last = None;
        let mut seq = 0u64;
        loop {
            // Cancellation wins over a ready snapshot/send. Dropping a blocking
            // worker cannot stop SQLite, but it can prevent publishing its result.
            let stopped = &mut self.stopped;
            let surface = Arc::clone(&self.surface);
            let writer = self.writer.clone();
            let header = self.header;
            let principal = self.principal.clone();
            let params = Arc::clone(&self.params);
            tokio::select! {
                biased;
                _ = stopped.changed() => break,
                result = async {
                    let snapshot = tokio::task::spawn_blocking(move || surface.watch_scoped(principal.as_ref(), &params))
                        .await.unwrap_or(Err(ReadError::StoreError));
                    match snapshot {
                        Ok(values) => {
                            if last.as_ref() != Some(&values) {
                                seq += 1;
                                let body = serde_json::to_vec(&json!({"kind":"changed", "epoch":process_epoch(), "seq":seq, "view":values.0, "keys":values.1})).map_err(ModuleError::Json)?;
                                emit(&writer, header, FrameType::StreamData, body).await?;
                                last = Some(values);
                            }
                            Ok(true)
                        }
                        Err(code) if seq == 0 || code == ReadError::NotFound => {
                            refusal(&writer, header, if seq == 0 { FrameType::Response } else { FrameType::Error }, code).await?;
                            Ok(false)
                        }
                        // A transient store failure must not masquerade as a smaller
                        // inventory. Retain the last digests and retry on the next commit.
                        Err(_) => Ok(true),
                    }
                } => { if !result? { return Ok(()); } }
            }
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
}
