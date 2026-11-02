//! Best-effort, memory-only relay of grant-checked quota readings to insula.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::federation::{management_surface, OutboundClient, RouteCall};

pub(crate) const MAX_USAGE_READING_BYTES: usize = 15_360;
// At most roughly half a MiB of reading bodies, including the in-flight batch.
pub(crate) const MAX_PENDING_USAGE: usize = 16;
pub(crate) const USAGE_FLUSH_INTERVAL: Duration = Duration::from_secs(5);
pub(crate) const USAGE_DELIVERY_DEADLINE: Duration = Duration::from_secs(2);

pub(crate) fn valid_reading(reading: &Value) -> bool {
    reading.as_object().is_some_and(|object| {
        !object.contains_key("credentialId")
            && !object.contains_key("vouched")
            && serde_json::to_vec(reading).is_ok_and(|bytes| bytes.len() <= MAX_USAGE_READING_BYTES)
    })
}

pub(crate) fn vouched_row(
    mut reading: Map<String, Value>,
    credential_id: &str,
    kind: &str,
    principal_id: &str,
) -> Value {
    reading.insert("credentialId".into(), json!(credential_id));
    reading.insert(
        "vouched".into(),
        json!({"principal": format!("{kind}:{principal_id}"), "credentialId": credential_id}),
    );
    Value::Object(reading)
}

#[derive(Default)]
struct State {
    pending: VecDeque<Value>,
    forwarded: u64,
    dropped: u64,
    ignored: BTreeMap<String, u64>,
}

#[derive(Default)]
pub(crate) struct UsageForwarder {
    state: Mutex<State>,
}

#[derive(Deserialize)]
pub(crate) struct ObserveReply {
    accepted: usize,
    ignored: Vec<Ignored>,
}

#[derive(Deserialize)]
struct Ignored {
    reason: String,
}

pub(crate) fn decode_reply(reply: Value) -> Result<ObserveReply, serde_json::Error> {
    // OutboundClient unwraps result; accepting the envelope also lets contract vectors
    // exercise this decoder without duplicating transport normalization in the test.
    serde_json::from_value(reply.get("result").cloned().unwrap_or(reply))
}

fn older(incoming: &Value, pending: &Value) -> bool {
    let (Some(incoming), Some(pending)) = (
        incoming.get("observedAtMs").and_then(Value::as_number),
        pending.get("observedAtMs").and_then(Value::as_number),
    ) else {
        // Missing/non-numeric timestamps are still delivered for insula to judge.
        return false;
    };
    if let (Some(a), Some(b)) = (incoming.as_i64(), pending.as_i64()) {
        return a < b;
    }
    if let (Some(a), Some(b)) = (incoming.as_u64(), pending.as_u64()) {
        return a < b;
    }
    incoming.as_f64() < pending.as_f64()
}

impl UsageForwarder {
    pub(crate) fn enqueue(&self, row: Value) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(index) = state
            .pending
            .iter()
            .position(|pending| pending["credentialId"] == row["credentialId"])
        {
            state.dropped += 1;
            if older(&row, &state.pending[index]) {
                return;
            }
            state.pending.remove(index);
        } else if state.pending.len() == MAX_PENDING_USAGE {
            // Evict the least recently received credential so every admitted report
            // can be queued without waiting for a network operation or free capacity.
            state.pending.pop_front();
            state.dropped += 1;
        }
        state.pending.push_back(row);
    }

    pub(crate) fn metrics(&self) -> Value {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        json!({
            "usageForwardedRows": state.forwarded,
            "usageDroppedRows": state.dropped,
            "usageIgnoredReasons": state.ignored,
        })
    }

    pub(crate) fn record_reply(&self, rows: usize, reply: Option<ObserveReply>) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match reply {
            Some(reply) if reply.accepted.checked_add(reply.ignored.len()) == Some(rows) => {
                state.forwarded += rows as u64;
                for ignored in reply.ignored {
                    *state.ignored.entry(ignored.reason).or_default() += 1;
                }
            }
            _ => state.dropped += rows as u64,
        }
    }

    pub(crate) async fn flush(&self, client: &OutboundClient) {
        // Never hold the queue lock over I/O: reads and reports must not inherit an
        // insula deadline. Drained rows are discarded even if delivery fails.
        let rows: Vec<_> = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.pending.drain(..).collect()
        };
        if rows.is_empty() {
            return;
        }
        let count = rows.len();
        let reply = client
            .call(
                "insula-usage",
                RouteCall {
                    target: management_surface("insula"),
                    prelude: None,
                    request: json!({"method": "usage.observe", "params": {"observations": rows}}),
                },
                USAGE_DELIVERY_DEADLINE,
            )
            .await
            .ok()
            .and_then(|reply| decode_reply(reply).ok());
        self.record_reply(count, reply);
    }

    pub(crate) fn spawn(self: Arc<Self>, client: OutboundClient) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut cadence = tokio::time::interval_at(
                tokio::time::Instant::now() + USAGE_FLUSH_INTERVAL,
                USAGE_FLUSH_INTERVAL,
            );
            cadence.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                cadence.tick().await;
                self.flush(&client).await;
            }
        })
    }

    #[cfg(test)]
    pub(crate) fn pending(&self) -> Vec<Value> {
        self.state.lock().unwrap().pending.iter().cloned().collect()
    }
}
