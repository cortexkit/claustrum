use super::*;
use serde::{Deserialize, Deserializer};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopedWatchKind {
    Changed,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedWatchNotice {
    pub kind: ScopedWatchKind,
    #[serde(deserialize_with = "nonempty_epoch")]
    pub epoch: String,
    #[serde(deserialize_with = "positive_safe_seq")]
    pub seq: u64,
    pub view: String,
    pub keys: String,
}

/// Transport-independent producer notice, also used by the raw watch handle.
pub type WatchNotice = ScopedWatchNotice;

impl ScopedWatchNotice {
    pub fn decode(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchAction {
    Reread { inventory: bool, keys: bool },
    ResubscribeAndReread,
    ReadListOnce,
    ReconnectAndReread,
    Fallback,
    RetryLater,
    Stop,
}

/// Tracks notifications separately from acknowledged inventory/key reads.
/// Call `opened` for each new subscription; duplicate closes never trigger retries.
#[derive(Debug, Default)]
pub struct WatchTracker {
    view: Option<String>,
    keys: Option<String>,
    last: Option<(String, u64)>,
    notices: bool,
    closed: bool,
    awaiting_list: bool,
}

impl WatchTracker {
    pub fn inventory_read(&mut self, view: impl Into<String>) {
        self.view = Some(view.into());
    }
    pub fn keys_read(&mut self, keys: impl Into<String>) {
        self.keys = Some(keys.into());
    }

    pub fn opened(&mut self) {
        self.notices = false;
        self.closed = false;
        self.awaiting_list = false;
        self.last = None;
    }

    pub fn notice(&mut self, notice: &WatchNotice) -> WatchAction {
        if self.closed {
            return WatchAction::Stop;
        }
        let discontinuity = self.last.as_ref().is_none_or(|(epoch, seq)| {
            epoch != &notice.epoch || seq.checked_add(1) != Some(notice.seq)
        });
        let inventory = discontinuity || self.view.as_deref() != Some(&notice.view);
        let keys = self.keys.as_deref() != Some(&notice.keys);
        self.last = Some((notice.epoch.clone(), notice.seq));
        self.notices = true;
        WatchAction::Reread { inventory, keys }
    }

    pub fn closed(&mut self) -> WatchAction {
        if self.closed {
            return WatchAction::Stop;
        }
        self.closed = true;
        self.awaiting_list = !self.notices;
        if self.notices {
            WatchAction::ResubscribeAndReread
        } else {
            WatchAction::ReadListOnce
        }
    }

    /// Feed the one confirming list read after `ReadListOnce`: true means success.
    /// A transport failure is instead fed to `route_lost`.
    pub fn list_result(&mut self, accepted: bool) -> WatchAction {
        if !self.awaiting_list {
            return WatchAction::Stop;
        }
        self.awaiting_list = false;
        self.closed = true;
        if accepted {
            WatchAction::RetryLater
        } else {
            WatchAction::Stop
        }
    }

    pub fn route_lost(&mut self) -> WatchAction {
        if self.closed && !self.awaiting_list {
            return WatchAction::Stop;
        }
        self.awaiting_list = false;
        self.closed = true;
        WatchAction::ReconnectAndReread
    }

    pub fn unknown_method(&mut self) -> WatchAction {
        self.awaiting_list = false;
        self.closed = true;
        WatchAction::Fallback
    }

    pub fn refused(&mut self) -> WatchAction {
        self.awaiting_list = false;
        self.closed = true;
        WatchAction::Stop
    }
}

fn nonempty_epoch<'de, D: Deserializer<'de>>(decoder: D) -> Result<String, D::Error> {
    let epoch = String::deserialize(decoder)?;
    if epoch.is_empty() {
        return Err(serde::de::Error::custom("empty watch epoch"));
    }
    Ok(epoch)
}

fn positive_safe_seq<'de, D: Deserializer<'de>>(decoder: D) -> Result<u64, D::Error> {
    let seq = u64::deserialize(decoder)?;
    if seq == 0 || seq > 9_007_199_254_740_991 {
        return Err(serde::de::Error::custom(
            "watch seq is not a positive safe integer",
        ));
    }
    Ok(seq)
}

#[derive(Debug)]
pub enum ScopedWatchOutcome {
    Refused(CredentialResolverError),
    Ended,
    NotAccepting,
    TransportLost(CredentialResolverError),
    Unsupported,
    InvalidNotice,
    InvalidResponse(CredentialResolverError),
    Stopped,
}

/// A single held request. No reconnect or resubscribe is performed automatically.
/// Drop or stop cancels it; drain notices with `next` before awaiting `closed`.
pub struct ScopedWatch {
    events: mpsc::Receiver<ScopedWatchNotice>,
    closed: oneshot::Receiver<ScopedWatchOutcome>,
    stop: Option<oneshot::Sender<()>>,
}

impl ScopedWatch {
    pub async fn next(&mut self) -> Option<ScopedWatchNotice> {
        self.events.recv().await
    }

    pub fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }

    pub async fn closed(&mut self) -> ScopedWatchOutcome {
        (&mut self.closed).await.unwrap_or_else(|_| {
            ScopedWatchOutcome::TransportLost(CredentialResolverError::transport(
                "scoped watch task ended without an outcome",
            ))
        })
    }
}

impl Drop for ScopedWatch {
    fn drop(&mut self) {
        self.stop();
    }
}

fn params(enrollment_token: Option<&str>) -> Value {
    enrollment_token.map_or_else(|| json!({}), |token| json!({"enrollment_token": token}))
}

impl ClaustrumConsumer {
    pub(super) async fn start_scoped_watch(
        mut self,
        enrollment_token: Option<String>,
    ) -> Result<ScopedWatch, CredentialResolverError> {
        let corr = self.next_correlation();
        self.write_request(
            self.route_channel,
            self.route_epoch,
            corr,
            Priority::Interactive,
            json!({"method":"auth.watch_scoped", "params":params(enrollment_token.as_deref())}),
        )
        .await?;
        let (events, receiver) = mpsc::channel(32);
        let (closed, outcome) = oneshot::channel();
        let (stop, mut stopped) = oneshot::channel();
        tokio::spawn(async move {
            let result = tokio::select! {
                biased;
                _ = &mut stopped => ScopedWatchOutcome::Stopped,
                result = self.read_scoped_watch(corr, enrollment_token.as_deref(), &events) => result,
            };
            // Also cancel malformed/overflowed streams so a live provider frees its slot.
            if let Ok(cancel) = Frame::build(
                FrameType::Cancel,
                Flags::new(false, Priority::Interactive, false),
                self.route_channel,
                self.route_epoch,
                corr,
                vec![],
            ) {
                let _ = tokio::time::timeout(
                    CREDENTIAL_READ_TIMEOUT,
                    write_frame(&mut self.stream, &cancel),
                )
                .await;
            }
            drop(events);
            let _ = closed.send(result);
        });
        Ok(ScopedWatch {
            events: receiver,
            closed: outcome,
            stop: Some(stop),
        })
    }

    async fn read_scoped_watch(
        &mut self,
        corr: u64,
        enrollment_token: Option<&str>,
        events: &mpsc::Sender<ScopedWatchNotice>,
    ) -> ScopedWatchOutcome {
        let mut tracker = WatchTracker::default();
        loop {
            let frame = match read_frame(&mut self.stream).await {
                Ok(Some(frame)) => frame,
                _ => {
                    return ScopedWatchOutcome::TransportLost(CredentialResolverError::transport(
                        "scoped watch connection lost",
                    ))
                }
            };
            if frame.header.channel != self.route_channel || frame.header.epoch != self.route_epoch
            {
                continue;
            }
            if frame.header.ty == FrameType::Goodbye {
                return ScopedWatchOutcome::TransportLost(CredentialResolverError::unclassified(
                    "route_closed",
                    "scoped watch route closed",
                ));
            }
            if frame.header.corr != corr {
                continue;
            }
            match frame.header.ty {
                FrameType::StreamData => {
                    let notice = match WatchNotice::decode(&frame.body) {
                        Ok(notice) => notice,
                        Err(_) => return ScopedWatchOutcome::InvalidNotice,
                    };
                    tracker.notice(&notice);
                    if events.try_send(notice).is_err() {
                        return ScopedWatchOutcome::TransportLost(
                            CredentialResolverError::transport("scoped watch consumer lagged"),
                        );
                    }
                }
                FrameType::Response => {
                    let value = serde_json::from_slice(&frame.body).unwrap_or(Value::Null);
                    if value.get("result").and_then(|r| r.get("error")).is_some() {
                        tracker.refused();
                        return ScopedWatchOutcome::Refused(
                            decode_list_scoped_reply(value).unwrap_err(),
                        );
                    }
                    return ScopedWatchOutcome::InvalidResponse(invalid_listing(
                        "unexpected watch response",
                    ));
                }
                FrameType::StreamEnd => {
                    if tracker.closed() == WatchAction::ResubscribeAndReread {
                        return ScopedWatchOutcome::Ended;
                    }
                    let response = self.credential_request(json!({"method":CREDENTIAL_LIST_SCOPED_OP, "params":params(enrollment_token)}), CREDENTIAL_LIST_SCOPED_OP).await;
                    return match response {
                        Ok(value) => {
                            let refused =
                                value.get("result").and_then(|r| r.get("error")).is_some();
                            match decode_list_scoped_reply(value) {
                                Ok(_) => {
                                    tracker.list_result(true);
                                    ScopedWatchOutcome::NotAccepting
                                }
                                Err(error) if refused => {
                                    tracker.list_result(false);
                                    ScopedWatchOutcome::Refused(error)
                                }
                                Err(error) => ScopedWatchOutcome::InvalidResponse(error),
                            }
                        }
                        Err(error) => ScopedWatchOutcome::TransportLost(error),
                    };
                }
                FrameType::Error => {
                    let value = serde_json::from_slice::<Value>(&frame.body).unwrap_or(Value::Null);
                    if value.get("code").and_then(Value::as_str) == Some("unknown_method") {
                        tracker.unknown_method();
                        return ScopedWatchOutcome::Unsupported;
                    }
                    tracker.route_lost();
                    return ScopedWatchOutcome::TransportLost(decode_wire_error(&frame.body));
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests;
