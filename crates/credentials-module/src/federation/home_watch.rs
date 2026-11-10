//! Home-side remote inventory streams, including opens still checking their pairing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use credentials_core::federation::RemoteWatchRow;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use subc_protocol::{EnvelopeHeader, ErrorBody, Flags, Frame, FrameType, Priority};
use tokio::sync::mpsc;

use super::ingress::{remote_watch_logins_wire, HomeAnswer, HomeVault};

fn wrap_result(value: Value) -> Value {
    json!({"result": value})
}

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
}

pub struct PendingOpen {
    key: Key,
    identity: Arc<()>,
}

struct Live {
    member: String,
    _pairing: String,
    order: u64,
    writer: mpsc::Sender<Frame>,
    header: EnvelopeHeader,
}

struct Entry {
    identity: Arc<()>,
    live: Option<Live>,
}

#[derive(Default)]
struct Registry {
    entries: HashMap<Key, Entry>,
    draining: bool,
    order: u64,
}

#[derive(Default)]
pub struct RemoteWatchHub {
    registry: Mutex<Registry>,
    // Serialize admission and terminal publication, never the pairing/store checks.
    publication: tokio::sync::Mutex<()>,
    #[cfg(test)]
    pub(crate) before_checks: OnceLock<super::ingress::IssueAuditGate>,
    #[cfg(test)]
    pub(crate) completed: tokio::sync::Notify,
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

fn refusal(header: EnvelopeHeader, answer: HomeAnswer) -> Result<Frame, String> {
    let (ty, body) = match answer {
        HomeAnswer::Reply(reply) => (FrameType::Response, serde_json::to_vec(&wrap_result(reply))),
        HomeAnswer::InvalidParams(detail) => (
            FrameType::Error,
            serde_json::to_vec(&ErrorBody::new(
                "invalid_params",
                format!("params not decodable: {detail}"),
            )),
        ),
    };
    frame(header, ty, body.map_err(|error| error.to_string())?)
}

impl Registry {
    fn contains(&self, pending: &PendingOpen) -> bool {
        self.entries
            .get(&pending.key)
            .is_some_and(|entry| Arc::ptr_eq(&entry.identity, &pending.identity))
    }
}

impl RemoteWatchHub {
    /// No I/O: the frame loop installs this before it can read a following Cancel.
    pub fn register(&self, header: EnvelopeHeader) -> PendingOpen {
        let pending = PendingOpen {
            key: (header.channel, header.corr),
            identity: Arc::new(()),
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
                },
            );
        pending
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
                    member: watch.member,
                    _pairing: watch.pairing,
                    order,
                    writer: writer.clone(),
                    header,
                });
                permit.send(snapshot.expect("successful projection"));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        self.registry.lock().expect("remote watches").entries.len()
    }
}
