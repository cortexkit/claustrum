//! One upstream manifest subscription shared by local watchers of the same home.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use serde_json::{json, Value};
use tokio::sync::watch;

use super::outbound::{
    management_surface, OutboundClient, RouteCall, SubscriptionEvent, CONSUMER_FACING_DEADLINE,
};

#[derive(Clone)]
pub enum State {
    Opening,
    Current(Value),
    Refused(Value),
    End,
}

pub struct Session {
    pub current: watch::Receiver<State>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Default)]
pub struct Hub(Mutex<HashMap<String, Weak<Session>>>);

impl Hub {
    pub fn subscribe(&self, home: &str, client: Option<OutboundClient>) -> Arc<Session> {
        let mut sessions = self.0.lock().expect("manifest upstreams");
        sessions.retain(|_, session| session.strong_count() > 0);
        if let Some(session) = sessions.get(home).and_then(Weak::upgrade) {
            if matches!(
                *session.current.borrow(),
                State::Opening | State::Current(_)
            ) {
                return session;
            }
        }
        let (current, rx) = watch::channel(State::Opening);
        let home_id = home.to_owned();
        let task = tokio::spawn(async move {
            let unavailable =
                || State::Refused(json!({"error":{"code":"home_unavailable","class":"transient"}}));
            let Some(client) = client else {
                current.send_replace(unavailable());
                return;
            };
            let Some(fp) = home_id.strip_prefix("fed-computer:") else {
                current.send_replace(unavailable());
                return;
            };
            let opening = async {
                let mut upstream = client
                    .subscribe(
                        &format!("manifest-watch:{home_id}"),
                        RouteCall {
                            target: management_surface(&format!("fed:{fp}:claustrum")),
                            prelude: None,
                            request: json!({"method":"federation.manifest_watch","params":{}}),
                        },
                        CONSUMER_FACING_DEADLINE,
                    )
                    .await
                    .ok()?;
                let first = upstream.next_event().await.ok()?;
                Some((upstream, first))
            };
            // A routed subscription opens before its first notice arrives. Bound both
            // steps so a home that accepts but never replies cannot hold local opens.
            let opened = tokio::time::timeout(CONSUMER_FACING_DEADLINE, opening).await;
            let Ok(Some((mut upstream, first))) = opened else {
                current.send_replace(unavailable());
                return;
            };
            let mut cursor = None;
            match decode(first, &mut cursor) {
                Some(value) => {
                    current.send_replace(State::Current(value));
                }
                None => {
                    current.send_replace(unavailable());
                    return;
                }
            }
            loop {
                match upstream
                    .next_event()
                    .await
                    .ok()
                    .and_then(|event| decode(event, &mut cursor))
                {
                    Some(value) => {
                        current.send_replace(State::Current(value));
                    }
                    None => {
                        current.send_replace(State::End);
                        break;
                    }
                }
            }
        });
        let session = Arc::new(Session { current: rx, task });
        sessions.insert(home.to_owned(), Arc::downgrade(&session));
        session
    }
}

fn decode(event: SubscriptionEvent, cursor: &mut Option<(String, u64)>) -> Option<Value> {
    let SubscriptionEvent::Data(value) = event else {
        return None;
    };
    let epoch = value.get("epoch")?.as_str()?;
    let seq = value.get("seq")?.as_u64()?;
    if value.get("kind")?.as_str()? != "changed"
        || epoch.len() != 32
        || !epoch.bytes().all(|c| c.is_ascii_hexdigit())
        || match cursor.as_ref() {
            None => seq != 1,
            Some((prior, last)) => prior != epoch || seq != last.checked_add(1)?,
        }
    {
        return None;
    }
    let version = value.get("version")?;
    let hash = value.get("manifest_sha256")?;
    if !(version.is_null() && hash.is_null())
        && !(version.as_i64().is_some_and(|v| v > 0)
            && hash.as_str().is_some_and(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }))
    {
        return None;
    }
    *cursor = Some((epoch.to_owned(), seq));
    Some(json!({"version":version,"manifest_sha256":hash}))
}
