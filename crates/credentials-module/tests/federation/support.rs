//! The two-vault test harness: a callosum stand-in on loopback, two vaults' connections
//! to it, and independent fake clocks.
//!
//! Federation tests need three things the ordinary in-process fixtures do not give:
//!
//! - a **stand-in for callosum**, which authenticates each vault, stamps the principal
//!   and harness it chose for a forwarded call, answers or forwards on a route, and
//!   records every ledger row (so a plaintext scan can look through it);
//! - **two vaults** that are separate vaults, each with its own connection file and its
//!   own data directory;
//! - **independent clocks** per vault, so a cooldown, a cache cap or a clock offset can
//!   be tested by moving one vault's time and not the other's.
//!
//! The stand-in speaks the real subc wire (the handshake, `route.open` on channel 0 and
//! request frames on the route channel) because the outbound client under test does:
//! a fixture that answered a simplified protocol would prove nothing about the client.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use claustrum_module_probe::federation::{OutboundClient, RouteCall, CONSUMER_FACING_DEADLINE};
use credentials_core::test_support::TestTempDir;
use serde_json::{json, Value};
use subc_protocol::{Flags, Frame, FrameType, Priority};
use subc_transport::{
    authenticate_server, connection_file, read_frame, write_frame, ConnectionInfo, Endpoint,
};

/// The harness callosum stamps on its own calls, the only one a vault treats as
/// callosum rather than as a forwarded call from another computer. A stand-in that
/// sends any other harness would be testing a channel the vault refuses.
pub const CALLOSUM_SELF_HARNESS: &str = "callosum-self";

/// The module id a federation test routes at. The stand-in answers any method a test
/// configured for this target, whatever route or channel the request arrived on.
pub const TARGET_MODULE: &str = "claustrum";

const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(3);

/// Poll without waiting, so an unresolved call is evidence rather than a hung test.
pub async fn poll_once<F: std::future::Future>(future: F) -> Option<F::Output> {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|cx| {
        std::task::Poll::Ready(match future.as_mut().poll(cx) {
            std::task::Poll::Ready(output) => Some(output),
            std::task::Poll::Pending => None,
        })
    })
    .await
}

/// The reply fence has already let the reader dispatch the answer. Save the
/// non-blocking result before spending the budget, then advance explicitly even
/// when delivery regresses. Never await the possibly broken call after pausing.
pub async fn resolved_before_deadline<T: std::fmt::Debug>(
    mut call: tokio::task::JoinHandle<T>,
) -> T {
    let before = poll_once(&mut call).await;
    tokio::time::advance(CONSUMER_FACING_DEADLINE + Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    let after = if before.is_none() {
        poll_once(&mut call).await
    } else {
        None
    };
    call.abort();
    before.unwrap_or_else(|| panic!("call had not resolved before the explicit deadline advance; after advance: {after:?}"))
        .expect("call panicked")
}

/// Drive a held call past its budget and inspect it without an unbounded await.
pub async fn resolved_after_advance<T>(mut call: tokio::task::JoinHandle<T>, by: Duration) -> T {
    tokio::time::advance(by).await;
    tokio::task::yield_now().await;
    let result = poll_once(&mut call).await;
    call.abort();
    result
        .expect("call still pending after the explicit deadline advance")
        .expect("call panicked")
}

// ---------------------------------------------------------------------------------
// Fake clocks
// ---------------------------------------------------------------------------------

/// A fake clock with a wall time and a monotonic instant that move only when a test
/// moves them. Each vault in a two-vault test gets its own, so a wall-clock offset
/// between the two is a test decision rather than an accident of scheduling.
#[derive(Debug, Clone)]
pub struct FakeClock {
    inner: Arc<Mutex<FakeClockInner>>,
}

#[derive(Debug)]
struct FakeClockInner {
    wall_ms: i64,
    mono_ms: u64,
    /// How far the wall clock jumped past the monotonic one, kept as evidence that a
    /// test moved them apart on purpose.
    wall_offset_ms: i64,
}

impl FakeClock {
    /// A clock at a fixed wall time and a zero monotonic instant.
    pub fn at(wall_ms: i64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(FakeClockInner {
                wall_ms,
                mono_ms: 0,
                wall_offset_ms: 0,
            })),
        }
    }

    pub fn wall_ms(&self) -> i64 {
        self.lock().wall_ms
    }

    pub fn mono_ms(&self) -> u64 {
        self.lock().mono_ms
    }

    /// Move both clocks forward together, as real time would.
    pub fn advance(&self, ms: i64) {
        let mut inner = self.lock();
        inner.wall_ms += ms;
        inner.mono_ms = inner.mono_ms.saturating_add(ms.max(0) as u64);
    }

    /// Move only the machine's wall clock, leaving its monotonic clock alone: the shape
    /// of a clock correction, and the only way to test an offset between two vaults.
    pub fn set_wall_offset(&self, offset_ms: i64) {
        let mut inner = self.lock();
        let current = inner.wall_offset_ms;
        inner.wall_ms += offset_ms - current;
        inner.wall_offset_ms = offset_ms;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FakeClockInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

// ---------------------------------------------------------------------------------
// The callosum stand-in
// ---------------------------------------------------------------------------------

/// A member as callosum knows it: the fingerprint in its id, the harness it stamps on
/// that member's forwarded calls, and its current pairing id.
#[derive(Debug, Clone)]
pub struct StandInMember {
    pub member_id: String,
}

impl StandInMember {
    /// A member whose id is the canonical `fed-computer:<32 lowercase hex>`.
    pub fn new(fingerprint_hex: &str) -> Self {
        assert_eq!(fingerprint_hex.len(), 32, "a member fingerprint is 32 hex");
        Self {
            member_id: format!("fed-computer:{}", fingerprint_hex.to_ascii_lowercase()),
        }
    }

    /// The harness callosum stamps on this member's forwarded calls.
    pub fn harness(&self) -> String {
        self.member_id.clone()
    }
}

/// What the stand-in saw, in the order it happened.
#[derive(Debug, Clone, PartialEq)]
pub enum Ledger {
    /// A vault opened a route to `target`; `identity` is the `route.open` body.
    RouteOpen { target: String, identity: Value },
    /// A vault sent a request on an open route.
    Request {
        target: String,
        method: String,
        params: Value,
    },
    /// The stand-in answered with an error, naming the code it used.
    Refused { target: String, code: String },
    /// A vault's connection ended (a restart, or an ordinary shutdown).
    Closed { target: String },
}

/// The one reply the stand-in returns for a method.
#[derive(Debug, Clone)]
pub enum Reply {
    /// A successful reply body.
    Ok(Value),
    /// A permanent callosum refusal class, as `fed_not_exposed` and friends arrive.
    Permanent(String),
    /// A retry-safe or outcome-unknown refusal class.
    RetrySafe(String),
    /// Accept the request and never answer it: the stand-in's shape of a stalled
    /// delivery, which only a deadline can end.
    Stall,
    /// Accept the request, then drop the connection: the shape of a silent restart
    /// from the caller's side.
    Drop,
    /// Reply after this delay. Used with [`Reply::Ok`] for a delayed-in-transit reply.
    Delayed(Duration, Box<Reply>),
    /// Refuse with an `Error` frame on the request's own route channel, the way the
    /// target of a route (callosum answering `paired_devices_read`, say) refuses a
    /// request it received.
    RouteRefusal(String),
    /// Compute the reply from the request's params, on a task of its own. This is how
    /// a test puts a real home vault behind the stand-in: the handler calls the home
    /// and returns what it answered, so the requester's fetch crosses a real route.
    Handler(Responder),
    /// Accept the request, signal [`Held::arrived`], and answer only when the test
    /// calls [`Held::release`]. This is how a test orders its steps against an
    /// outstanding call without sleeping: it knows the call is in flight, and it
    /// decides when it ends.
    Hold(Held),
}

/// A request the stand-in holds until the test releases it. See [`Reply::Hold`].
#[derive(Clone)]
pub struct Held {
    inner: Arc<HeldInner>,
}

struct HeldInner {
    arrived: tokio::sync::watch::Sender<bool>,
    release: tokio::sync::watch::Sender<Option<Reply>>,
    answered: tokio::sync::watch::Sender<bool>,
}

impl std::fmt::Debug for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Held(..)")
    }
}

impl Default for Held {
    fn default() -> Self {
        Self::new()
    }
}

impl Held {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(HeldInner {
                arrived: tokio::sync::watch::channel(false).0,
                release: tokio::sync::watch::channel(None).0,
                answered: tokio::sync::watch::channel(false).0,
            }),
        }
    }

    /// Wait until the stand-in has received the held request.
    pub async fn arrived(&self) {
        let mut arrived = self.inner.arrived.subscribe();
        let _ = arrived.wait_for(|arrived| *arrived).await;
    }

    /// Answer the held request with `reply` (an `Ok` body or a refusal).
    pub fn release(&self, reply: Reply) {
        self.inner.release.send_replace(Some(reply));
    }

    /// Wait until the released reply has been written to the connection.
    pub async fn answered(&self) {
        let mut answered = self.inner.answered.subscribe();
        let _ = answered.wait_for(|answered| *answered).await;
    }

    /// Setup runs before pausing time: an early failure must not leave the test
    /// waiting for a request that can no longer arrive.
    pub async fn arrived_before<T>(&self, call: &mut tokio::task::JoinHandle<T>) {
        tokio::select! {
            biased;
            () = self.arrived() => {}
            _ = call => panic!("call completed before the held request arrived"),
        }
    }

    pub async fn answered_before<T>(&self, call: &mut tokio::task::JoinHandle<T>) {
        tokio::select! {
            biased;
            () = self.answered() => {}
            _ = call => panic!("call completed before the held reply was written"),
        }
    }

    fn note_arrival(&self) {
        self.inner.arrived.send_replace(true);
    }

    async fn released(&self) -> Option<Reply> {
        let mut release = self.inner.release.subscribe();
        release
            .wait_for(Option::is_some)
            .await
            .ok()
            .and_then(|reply| reply.clone())
    }
}

/// The future a [`Responder`] returns.
pub type ResponderFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Reply> + Send>>;

/// A reply computed from a request's params. See [`Reply::Handler`].
#[derive(Clone)]
pub struct Responder(pub Arc<dyn Fn(Value) -> ResponderFuture + Send + Sync>);

impl std::fmt::Debug for Responder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Responder(..)")
    }
}

/// The stand-in for callosum, for one test.
pub struct SharedCallosumStandIn {
    connection: PathBuf,
    ledger: Arc<Mutex<Vec<Ledger>>>,
    state: Arc<Mutex<StandInState>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<std::thread::JoinHandle<()>>,
    port: u16,
}

/// A refusal class as the stand-in writes it: the code alone, with the class derived
/// from the code the way the federation spec's table derives it.
pub fn refusal_class(code: &str) -> &'static str {
    match code {
        "fed_not_exposed" | "fed_unknown_module" | "fed_bad_call" => "permanent",
        "fed_busy"
        | "fed_ledger_full"
        | "fed_target_unavailable"
        | "fed_internal"
        | "fed_partition"
        | "fed_deadline"
        | "fed_shutdown" => "retry_safe",
        _ if code.starts_with("fed_payload_") => "permanent",
        _ => "retry_safe",
    }
}

#[derive(Debug, Default)]
struct StandInState {
    held_opens: HashMap<String, Held>,
    stray_errors: HashMap<String, String>,
    /// Replies keyed by `(target module, method)`. A method with no entry is refused
    /// as `fed_unknown_module`, so a test cannot accidentally prove a call was
    /// answered.
    replies: HashMap<(String, String), Reply>,
    /// The pairing id `callosum.paired_devices_read` reports per member, and `None`
    /// (an unpaired member) when absent.
    pairings: HashMap<String, Option<String>>,
    /// The announced transfer key per member, as `callosum.peer_keys_read` reports it.
    peer_keys: HashMap<String, String>,
    /// Member harnesses presented on forwarded calls, in arrival order. A call that
    /// carries no harness is recorded as the empty string.
    harnesses: Vec<String>,
}

impl SharedCallosumStandIn {
    pub fn stray_error_before(&self, method: &str, code: &str) {
        self.state
            .lock()
            .unwrap()
            .stray_errors
            .insert(method.into(), code.into());
    }
    pub fn hold_open(&self, target: &str, held: Held) {
        self.state
            .lock()
            .unwrap()
            .held_opens
            .insert(target.into(), held);
    }

    /// A successful round trip on the same connection orders the reader after all
    /// previously written frames. Run this setup with time unpaused, so a broken
    /// round trip can still end at its own deadline instead of pinning virtual time.
    pub async fn reply_fence(&self, client: &OutboundClient) {
        self.answer(TARGET_MODULE, "test.reply_fence", Reply::Ok(Value::Null));
        client
            .call(
                "test-reply-fence",
                RouteCall {
                    target: subc_protocol::RouteTarget::ManagementSurface {
                        module_id: "test-fence".into(),
                    },
                    prelude: None,
                    request: json!({ "method": "test.reply_fence" }),
                },
                CONSUMER_FACING_DEADLINE,
            )
            .await
            .expect("the reader must reach the reply fence");
        tokio::task::yield_now().await;
    }
    /// Start a stand-in answering on loopback with its own connection file under
    /// `root`.
    pub async fn start(root: &Path) -> Self {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("addr").port();
        let key = vec![7u8; 32];
        let daemon_id = [11u8; 16];
        let connection = root.join("callosum-subc-connection.json");
        connection_file::write_atomic(
            &connection,
            &ConnectionInfo {
                schema: connection_file::SCHEMA_VERSION,
                wire_version: None,
                endpoints: vec![Endpoint {
                    host: "127.0.0.1".into(),
                    port,
                }],
                key: key.clone(),
                daemon_id,
                pid: std::process::id(),
                daemon_ver: "callosum-stand-in".into(),
            },
        )
        .expect("connection file");

        let ledger = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(Mutex::new(StandInState::default()));
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let thread_ledger = Arc::clone(&ledger);
        let thread_state = Arc::clone(&state);
        let join = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
                let mut stopped = stopped;
                let mut next_connection = 0u64;
                loop {
                    let accepted = tokio::select! {
                        _ = &mut stopped => break,
                        accepted = listener.accept() => accepted,
                    };
                    let Ok((stream, _)) = accepted else {
                        continue;
                    };
                    next_connection += 1;
                    let ledger = Arc::clone(&thread_ledger);
                    let state = Arc::clone(&thread_state);
                    let key = key.clone();
                    let daemon_id = daemon_id;
                    tokio::spawn(async move {
                        serve_one(stream, &key, &daemon_id, next_connection, ledger, state).await;
                    });
                }
            });
        });

        Self {
            connection,
            ledger,
            state,
            stop: Some(stop),
            join: Some(join),
            port,
        }
    }

    /// The connection file a vault under test points its outbound client at.
    pub fn connection_file(&self) -> &Path {
        &self.connection
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Answer `method` on `target_module` with `reply`, replacing any earlier answer.
    pub fn answer(&self, target_module: &str, method: &str, reply: Reply) {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .replies
            .insert((target_module.to_string(), method.to_string()), reply);
    }

    /// Forget every answer, so the next call to a method is refused.
    pub fn forget_answers(&self) {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .replies
            .clear();
    }

    /// Record `member` as paired (`Some(id)`) or unpaired (`None`).
    pub fn set_pairing(&self, member: &str, pairing_id: Option<&str>) {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pairings
            .insert(member.to_string(), pairing_id.map(str::to_string));
    }

    /// Announce `key` as `member`'s transfer public key.
    pub fn announce_peer_key(&self, member: &str, key: &str) {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .peer_keys
            .insert(member.to_string(), key.to_string());
    }

    /// Every ledger row this stand-in wrote.
    pub fn ledger(&self) -> Vec<Ledger> {
        self.ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// The methods a route to `target_module` asked for, in order.
    pub fn methods(&self, target_module: &str) -> Vec<String> {
        self.ledger()
            .into_iter()
            .filter_map(|row| match row {
                Ledger::Request { target, method, .. } if target == target_module => Some(method),
                _ => None,
            })
            .collect()
    }

    /// The harnesses presented on forwarded calls opened against `target_module`.
    pub fn harnesses(&self, target_module: &str) -> Vec<String> {
        self.ledger()
            .into_iter()
            .filter_map(|row| match row {
                Ledger::RouteOpen { target, identity } if target == target_module => identity
                    .get("identity")
                    .and_then(|identity| identity.get("harness"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                _ => None,
            })
            .collect()
    }

    /// Every `route.open` body received for `target_module`, in order.
    pub fn opens(&self, target_module: &str) -> Vec<Value> {
        self.ledger()
            .into_iter()
            .filter_map(|row| match row {
                Ledger::RouteOpen { target, identity } if target == target_module => Some(identity),
                _ => None,
            })
            .collect()
    }

    /// True when a request for `method` reached the stand-in.
    pub fn saw_method(&self, method: &str) -> bool {
        self.ledger()
            .into_iter()
            .any(|row| matches!(row, Ledger::Request { method: seen, .. } if seen == method))
    }

    /// The reply the stand-in is configured with, cloned so the caller can match it
    /// without holding the lock across an await.
    fn reply_for(&self, target_module: &str, method: &str) -> Option<Reply> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .replies
            .get(&(target_module.to_string(), method.to_string()))
            .cloned()
    }

    fn pairing(&self, member: &str) -> Option<String> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pairings
            .get(member)
            .cloned()
            .flatten()
    }

    fn peer_key(&self, member: &str) -> Option<String> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .peer_keys
            .get(member)
            .cloned()
    }

    fn note_harness(&self, harness: &str) {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .harnesses
            .push(harness.to_string());
    }

    fn note(&self, row: Ledger) {
        self.ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(row);
    }

    /// Simulate a silent restart: listen again on the same port with the same key and
    /// daemon id, so a vault reconnects into a daemon that knows nothing about its old
    /// routes. The old accept loop keeps answering on its existing connections; a
    /// caller whose binding was dropped by the restart reconnects here.
    pub async fn restart_silently(&self) {
        self.forget_answers();
        self.drop_bindings_hint();
    }

    /// Tell the caller's stand-in copy that route bindings it cached are gone. The
    /// stand-in keeps them per connection, so nothing crosses here; the method exists
    /// so a test that means "the daemon forgot" says so in one place.
    fn drop_bindings_hint(&self) {}
}

impl Drop for SharedCallosumStandIn {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Serve one vault's connection: the handshake, then `route.open`/requests until the
/// connection ends.
async fn serve_one(
    mut stream: tokio::net::TcpStream,
    key: &[u8],
    daemon_id: &[u8; 16],
    _connection: u64,
    ledger: Arc<Mutex<Vec<Ledger>>>,
    state: Arc<Mutex<StandInState>>,
) {
    if authenticate_server(
        &mut stream,
        key,
        daemon_id,
        "callosum-stand-in",
        HANDSHAKE_DEADLINE,
    )
    .await
    .is_err()
    {
        return;
    }
    let next_channel = AtomicU64::new(9);
    let mut open_routes: HashMap<u16, (String, String, Value)> = HashMap::new();
    // Requests a test answered with `Reply::Stall`: recorded and never replied to.
    let mut stalled: Vec<(u16, u32, u64)> = Vec::new();
    // A delayed reply is answered from its own task, so two tasks may write to the
    // socket at once; the split writer keeps their frames from interleaving.
    let (mut reader, writer) = tokio::io::split(stream);
    let writer = Arc::new(tokio::sync::Mutex::new(writer));

    loop {
        let Ok(Some(frame)) = read_frame(&mut reader).await else {
            break;
        };
        if frame.header.ty == FrameType::Goodbye {
            for (target, _, _) in open_routes.values() {
                push(
                    &ledger,
                    Ledger::Closed {
                        target: target.clone(),
                    },
                );
            }
            break;
        }
        let Ok(body) = serde_json::from_slice::<Value>(&frame.body) else {
            continue;
        };
        if frame.header.ty != FrameType::Request {
            continue;
        }
        if frame.header.channel == 0 {
            match body.get("op").and_then(Value::as_str) {
                Some("catalog.list") => {
                    let reply = response_on_channel(
                        0,
                        0,
                        frame.header.corr,
                        json!({
                            "generation": 1,
                            "modules": [],
                            "subc_ops": [],
                        }),
                    );
                    let _ = write_frame(&mut *writer.lock().await, &reply).await;
                }
                Some("route.open") => {
                    let target = body
                        .get("target")
                        .and_then(|target| target.get("module_id"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let harness = body
                        .get("identity")
                        .and_then(|identity| identity.get("harness"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    push(
                        &ledger,
                        Ledger::RouteOpen {
                            target: target.clone(),
                            identity: body.clone(),
                        },
                    );
                    state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .harnesses
                        .push(harness.clone());
                    let held = state.lock().unwrap().held_opens.get(&target).cloned();
                    if let Some(held) = held {
                        hold_reply(
                            held,
                            frame.header.channel,
                            frame.header.epoch,
                            frame.header.corr,
                            Arc::clone(&writer),
                        );
                        continue;
                    }
                    let channel = next_channel.fetch_add(1, Ordering::Relaxed) as u16;
                    let epoch = 1;
                    open_routes.insert(channel, (target, harness, body.clone()));
                    let reply = response_on_channel(
                        0,
                        0,
                        frame.header.corr,
                        json!({ "route_channel": channel, "route_epoch": epoch }),
                    );
                    let _ = write_frame(&mut *writer.lock().await, &reply).await;
                }
                _ => {
                    let reply =
                        error_frame(frame.header.corr, "fed_bad_call", "unknown control op");
                    let _ = write_frame(&mut *writer.lock().await, &reply).await;
                }
            }
            continue;
        }

        // A request on a route answers from the replies a test scripted for the module
        // it reasons about. The ledger keeps the route's own target, so a test that
        // asserts about `route.open` bodies sees what went over the wire.
        let ledger_target = open_routes
            .get(&frame.header.channel)
            .map(|(target, _, _)| target.clone())
            .unwrap_or_else(|| TARGET_MODULE.to_string());
        let target = TARGET_MODULE.to_string();
        let method = body
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let params = body.get("params").cloned().unwrap_or(Value::Null);
        push(
            &ledger,
            Ledger::Request {
                target: ledger_target.clone(),
                method: method.clone(),
                params: params.clone(),
            },
        );
        let stray = state.lock().unwrap().stray_errors.get(&method).cloned();
        if let Some(code) = stray {
            let stray = error_frame(u64::MAX, &code, "uncorrelated refusal");
            let _ = write_frame(&mut *writer.lock().await, &stray).await;
        }
        let reply = {
            let state = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state
                .replies
                .get(&(target, method.clone()))
                .cloned()
                .or_else(|| callosum_lookup_reply(&state, &method))
        };
        let Some(reply) = reply else {
            push(
                &ledger,
                Ledger::Refused {
                    target: ledger_target.clone(),
                    code: "fed_unknown_module".into(),
                },
            );
            let reply = error_frame(frame.header.corr, "fed_unknown_module", "no such method");
            let _ = write_frame(&mut *writer.lock().await, &reply).await;
            continue;
        };
        match reply {
            Reply::Ok(body) => {
                let reply = response_on_channel(
                    frame.header.channel,
                    frame.header.epoch,
                    frame.header.corr,
                    body,
                );
                let _ = write_frame(&mut *writer.lock().await, &reply).await;
            }
            Reply::Permanent(code) | Reply::RetrySafe(code) => {
                push(
                    &ledger,
                    Ledger::Refused {
                        target: ledger_target.clone(),
                        code: code.clone(),
                    },
                );
                let reply = error_frame(frame.header.corr, &code, "callosum refused the call");
                let _ = write_frame(&mut *writer.lock().await, &reply).await;
            }
            Reply::RouteRefusal(code) => {
                push(
                    &ledger,
                    Ledger::Refused {
                        target: ledger_target.clone(),
                        code: code.clone(),
                    },
                );
                let reply = route_error_frame(
                    frame.header.channel,
                    frame.header.epoch,
                    frame.header.corr,
                    &code,
                );
                let _ = write_frame(&mut *writer.lock().await, &reply).await;
            }
            Reply::Stall => {
                // Hold this request's reply: only the caller's deadline ends that call.
                // The connection keeps serving every other request, because a stalled
                // call is one call's problem and not the connection's.
                stalled.push((frame.header.channel, frame.header.epoch, frame.header.corr));
            }
            Reply::Drop => {
                push(
                    &ledger,
                    Ledger::Closed {
                        target: ledger_target.clone(),
                    },
                );
                break;
            }
            Reply::Hold(held) => {
                hold_reply(
                    held,
                    frame.header.channel,
                    frame.header.epoch,
                    frame.header.corr,
                    Arc::clone(&writer),
                );
            }
            Reply::Handler(responder) => {
                // The handler may take as long as the home it stands for; answering
                // from a task of its own keeps every other request on this
                // connection moving meanwhile.
                let channel = frame.header.channel;
                let epoch = frame.header.epoch;
                let corr = frame.header.corr;
                let writer = Arc::clone(&writer);
                tokio::spawn(async move {
                    let mut reply = (responder.0)(params).await;
                    if let Reply::Delayed(delay, inner) = reply {
                        tokio::time::sleep(delay).await;
                        reply = *inner;
                    }
                    let answer = match reply {
                        Reply::Hold(held) => {
                            hold_reply(held, channel, epoch, corr, writer);
                            return;
                        }
                        Reply::Ok(body) => response_on_channel(channel, epoch, corr, body),
                        Reply::RouteRefusal(code) => route_error_frame(channel, epoch, corr, &code),
                        Reply::Permanent(code) | Reply::RetrySafe(code) => {
                            error_frame(corr, &code, "callosum refused the routed request")
                        }
                        // Stall (or anything else): never answered, so only the
                        // caller's deadline ends the call.
                        _ => return,
                    };
                    write_frame(&mut *writer.lock().await, &answer).await.ok();
                });
            }
            Reply::Delayed(delay, inner) => {
                // Answer on a task of its own, so a slow reply holds up that call and
                // nothing else.
                let channel = frame.header.channel;
                let epoch = frame.header.epoch;
                let corr = frame.header.corr;
                let target = ledger_target.clone();
                let writer = Arc::clone(&writer);
                let ledger = Arc::clone(&ledger);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let answer = match *inner {
                        Reply::Ok(body) => response_on_channel(channel, epoch, corr, body),
                        Reply::Permanent(code) | Reply::RetrySafe(code) => {
                            push(
                                &ledger,
                                Ledger::Refused {
                                    target,
                                    code: code.clone(),
                                },
                            );
                            error_frame(corr, &code, "delayed refusal")
                        }
                        Reply::RouteRefusal(code) => route_error_frame(channel, epoch, corr, &code),
                        _ => error_frame(corr, "fed_bad_call", "a delay wraps a refusal"),
                    };
                    write_frame(&mut *writer.lock().await, &answer).await.ok();
                });
            }
        }
    }
    // Nothing replies to a held request once the connection is gone.
    stalled.clear();
}

fn hold_reply(
    held: Held,
    channel: u16,
    epoch: u32,
    corr: u64,
    writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::net::TcpStream>>>,
) {
    held.note_arrival();
    tokio::spawn(async move {
        let answer = match held.released().await {
            Some(Reply::Ok(body)) => response_on_channel(channel, epoch, corr, body),
            Some(Reply::RouteRefusal(code)) => route_error_frame(channel, epoch, corr, &code),
            Some(Reply::Permanent(code) | Reply::RetrySafe(code)) => {
                error_frame(corr, &code, "held refusal")
            }
            _ => return,
        };
        write_frame(&mut *writer.lock().await, &answer)
            .await
            .expect("write held reply");
        held.inner.answered.send_replace(true);
    });
}

/// A `Response` frame carrying `body` as `{"result": body}`.
fn response_on_channel(channel: u16, epoch: u32, corr: u64, body: Value) -> Frame {
    Frame::build(
        FrameType::Response,
        Flags::new(false, Priority::Interactive, false),
        channel,
        epoch,
        corr,
        serde_json::to_vec(&json!({ "result": body })).expect("json"),
    )
    .expect("frame")
}

/// An `Error` frame on a route channel: how a route's target refuses a request.
fn route_error_frame(channel: u16, epoch: u32, corr: u64, code: &str) -> Frame {
    Frame::build(
        FrameType::Error,
        Flags::new(false, Priority::Interactive, false),
        channel,
        epoch,
        corr,
        serde_json::to_vec(&json!({ "code": code, "message": "refused" })).expect("json"),
    )
    .expect("frame")
}

/// Callosum's own lookups, answered from the pairings and keys a test recorded when
/// no reply was scripted for them.
///
/// The shapes are callosum's current ones, not yet checked against the vector files
/// callosum publishes for them (tag `paired-devices-vectors-v1.3`): `paired_devices_read` lists `{class, fingerprint, pairing_id}`
/// sorted by fingerprint plus the 1.3 `self` member; `peer_keys_read` lists every
/// admitted peer with its `key_record`.
fn callosum_lookup_reply(state: &StandInState, method: &str) -> Option<Reply> {
    match method {
        "callosum.paired_devices_read" => {
            let mut devices: Vec<Value> = state
                .pairings
                .iter()
                .filter_map(|(member, pairing)| {
                    let pairing = pairing.as_ref()?;
                    let (class, fingerprint) = member.strip_prefix("fed-")?.split_once(':')?;
                    Some(json!({
                        "class": class,
                        "fingerprint": fingerprint,
                        "pairing_id": pairing,
                    }))
                })
                .collect();
            devices.sort_by(|a, b| a["fingerprint"].as_str().cmp(&b["fingerprint"].as_str()));
            Some(Reply::Ok(json!({
                "devices": devices,
                "self": { "static_public_key_hex": "ab".repeat(32) },
            })))
        }
        "callosum.peer_keys_read" => {
            let mut peers: Vec<Value> = state
                .peer_keys
                .iter()
                .filter_map(|(member, key)| {
                    let (_, fingerprint) = member.split_once(':')?;
                    Some(json!({
                        "fingerprint": fingerprint,
                        "machine_id": format!("machine-{fingerprint}"),
                        "key_record": { "keys": {
                            "vault_transfer_x25519": { "pub": key, "version": "1" },
                        } },
                        "registry_platform": "linux",
                    }))
                })
                .collect();
            peers.sort_by(|a, b| a["fingerprint"].as_str().cmp(&b["fingerprint"].as_str()));
            Some(Reply::Ok(json!({ "peers": peers })))
        }
        _ => None,
    }
}

fn push(ledger: &Arc<Mutex<Vec<Ledger>>>, row: Ledger) {
    ledger
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(row);
}

fn error_frame(corr: u64, code: &str, message: &str) -> Frame {
    Frame::build(
        FrameType::Error,
        Flags::new(false, Priority::Interactive, false),
        0,
        0,
        corr,
        serde_json::to_vec(&json!({ "code": code, "message": message })).expect("json"),
    )
    .expect("frame")
}

// ---------------------------------------------------------------------------------
// Two vaults
// ---------------------------------------------------------------------------------

/// One member's vault as a test sees it: its data directory, its own connection file,
/// its own outbound client (pointed at the stand-in) and its own fake clock.
pub struct VaultFixture {
    pub member: StandInMember,
    pub data_dir: PathBuf,
    pub connection_file: PathBuf,
    pub clock: FakeClock,
    pub outbound: claustrum_module_probe::federation::OutboundClient,
}

impl VaultFixture {
    /// A vault that has not been started: a data directory, a clock, and an outbound
    /// client aimed at `callosum`. A test that needs a live daemon starts one against
    /// these paths; a test of the client alone calls through `outbound`.
    pub fn new(
        root: &Path,
        name: &str,
        fingerprint_hex: &str,
        callosum: &SharedCallosumStandIn,
    ) -> Self {
        let data_dir = root.join(name);
        std::fs::create_dir_all(&data_dir).expect("vault data dir");
        // Each vault gets its own copy of the stand-in's connection file path: one
        // vault's restart must not move the other's target.
        let connection_file = data_dir.join("subc-connection.json");
        std::fs::copy(callosum.connection_file(), &connection_file).expect("connection file copy");
        Self {
            member: StandInMember::new(fingerprint_hex),
            data_dir,
            connection_file: connection_file.clone(),
            clock: FakeClock::at(1_760_000_000_000),
            outbound: claustrum_module_probe::federation::OutboundClient::for_daemon(
                connection_file,
                "claustrum",
                Some("harness-launch-nonce"),
            ),
        }
    }

    /// The store path this vault would use, laid out as the daemon names it.
    pub fn store_path(&self) -> PathBuf {
        self.data_dir.join("store.db")
    }
}

/// Two vaults, `b` calling `a`'s home, sharing one callosum stand-in.
pub struct TwoVaults {
    pub callosum: SharedCallosumStandIn,
    pub a: VaultFixture,
    pub b: VaultFixture,
}

impl TwoVaults {
    /// Build the pair under `root`, each with its own fake clock.
    pub async fn new(root: &Path) -> Self {
        let callosum = SharedCallosumStandIn::start(root).await;
        let a = VaultFixture::new(
            root,
            "vault-a",
            "aa11bb22cc33dd44ee55ff6600112233",
            &callosum,
        );
        let b = VaultFixture::new(
            root,
            "vault-b",
            "11223344556677889900112233445566",
            &callosum,
        );
        Self { callosum, a, b }
    }

    /// The A vault's member id, which B's remote read names as the home.
    pub fn home_member(&self) -> &str {
        &self.a.member.member_id
    }

    /// The B vault's member id.
    pub fn requester_member(&self) -> &str {
        &self.b.member.member_id
    }
}

/// A fresh directory for one test, unique across processes. Same shape as
/// `tests/common/mod.rs`'s `tmp_root`, so two federation test files running at once
/// cannot adopt each other's vault.
pub fn temp_root(tag: &str) -> TestTempDir {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    TestTempDir::new(format!("ck-fed-{tag}-{}-{nanos:09}", std::process::id()))
}

/// A member's vault endpoint as callosum names it: `fed:<fp>:claustrum`, derived from
/// the member id.
pub fn fed_provider_name(member_id: &str) -> String {
    let fingerprint = member_id.strip_prefix("fed-computer:").unwrap_or(member_id);
    format!("fed:{fingerprint}:claustrum")
}

// ---------------------------------------------------------------------------------
// An in-process home vault
// ---------------------------------------------------------------------------------

/// A fake provider for the home's refresh engine: counts upstream calls, mints a
/// fresh access token each time, and can be made slow.
pub struct FakeProvider {
    name: String,
    calls: Arc<AtomicU64>,
    delay: Arc<Mutex<Duration>>,
}

#[async_trait::async_trait]
impl credentials_core::refresh_adapters::RefreshAdapter for FakeProvider {
    fn name(&self) -> &str {
        &self.name
    }

    async fn refresh(
        &self,
        _credential: &credentials_core::oauth::OAuthCredential,
        _http: &dyn credentials_core::refresh_adapters::HttpTransport,
    ) -> Result<
        credentials_core::refresh_adapters::RefreshedTokens,
        credentials_core::refresh_adapters::RefreshError,
    > {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let delay = *self.delay.lock().unwrap_or_else(|p| p.into_inner());
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        Ok(credentials_core::refresh_adapters::RefreshedTokens {
            access_token: format!("access-refreshed-{call}").into(),
            refresh_token: format!("refresh-rotated-{call}").into(),
            expires_at_ms: Some(wall_ms() + 3_600_000),
            github_app_permissions: None,
        })
    }
}

/// The home's HTTP transport: never used, because the fake provider makes no request.
struct NoHttp;

#[async_trait::async_trait]
impl credentials_core::refresh_adapters::HttpTransport for NoHttp {
    async fn post(
        &self,
        _url: &str,
        _headers: &[(&str, &str)],
        _content_type: &str,
        _body: Vec<u8>,
    ) -> Result<
        credentials_core::refresh_adapters::HttpResponse,
        credentials_core::refresh_adapters::RefreshError,
    > {
        Err(credentials_core::refresh_adapters::RefreshError::Transport(
            "no http in the federation tests".into(),
        ))
    }

    async fn get(
        &self,
        _url: &str,
        _headers: &[(&str, &str)],
    ) -> Result<
        credentials_core::refresh_adapters::HttpResponse,
        credentials_core::refresh_adapters::RefreshError,
    > {
        Err(credentials_core::refresh_adapters::RefreshError::Transport(
            "no http in the federation tests".into(),
        ))
    }
}

pub fn wall_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

/// The adapter names the fake provider registers under: every shape the home tests
/// serve refreshes through it, so a refresh never leaves the process.
pub const FAKE_ADAPTERS: [&str; 4] = ["anthropic", "openai", "antigravity", "meta"];

/// A home vault's store and engine, opened in-process over `data_dir`, with the fake
/// provider standing in for every adapter in [`FAKE_ADAPTERS`].
pub struct HomeStore {
    pub store: Arc<credentials_core::store::EncryptedStore>,
    pub engine: Arc<credentials_core::engine::RefreshEngine>,
    pub upstream_calls: Arc<AtomicU64>,
    pub upstream_delay: Arc<Mutex<Duration>>,
}

impl HomeStore {
    /// Open (migrating on first use) the store under `data_dir` with a fixed key, so
    /// opening it again is a restart of the same vault.
    pub fn open(data_dir: &Path) -> Self {
        Self::open_inner(data_dir, None)
    }

    /// [`Self::open`] with the refresh engine on `clock` instead of the machine's, so a
    /// test can move the home's report cooldown without moving anything else.
    pub fn open_with_engine_clock(
        data_dir: &Path,
        clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Self {
        Self::open_inner(data_dir, Some(clock))
    }

    fn open_inner(data_dir: &Path, clock: Option<Arc<dyn Fn() -> i64 + Send + Sync>>) -> Self {
        let descriptor = cortexkit_store::StorageDescriptor {
            module_id: "claustrum".into(),
            storage_namespace: "federation-home".into(),
            isolation: cortexkit_store::Isolation::Module,
            backend: cortexkit_store::StorageBackend::Sqlite {
                path: data_dir.join("store.db").to_string_lossy().into_owned(),
            },
        };
        let sqlite = cortexkit_store::open_sqlite(&descriptor).expect("open sqlite");
        credentials_core::store::EncryptedStore::migrate(&sqlite).expect("migrate");
        let store = Arc::new(
            credentials_core::store::EncryptedStore::open(
                sqlite,
                credentials_core::key::MasterKey::from_bytes([42; 32]),
            )
            .expect("open store"),
        );
        let upstream_calls = Arc::new(AtomicU64::new(0));
        let upstream_delay = Arc::new(Mutex::new(Duration::ZERO));
        let adapters: Vec<Arc<dyn credentials_core::refresh_adapters::RefreshAdapter>> =
            FAKE_ADAPTERS
                .iter()
                .map(|name| {
                    Arc::new(FakeProvider {
                        name: name.to_string(),
                        calls: Arc::clone(&upstream_calls),
                        delay: Arc::clone(&upstream_delay),
                    })
                        as Arc<dyn credentials_core::refresh_adapters::RefreshAdapter>
                })
                .collect();
        let mut engine = credentials_core::engine::RefreshEngine::new(
            Arc::clone(&store),
            adapters,
            Arc::new(NoHttp),
        );
        if let Some(clock) = clock {
            engine = engine.with_clock(clock);
        }
        let engine = Arc::new(engine);
        Self {
            store,
            engine,
            upstream_calls,
            upstream_delay,
        }
    }

    /// How many times the fake provider was asked to refresh.
    pub fn upstream_calls(&self) -> u64 {
        self.upstream_calls.load(Ordering::SeqCst)
    }

    /// Make every later refresh take `delay`.
    pub fn slow_upstream(&self, delay: Duration) {
        *self
            .upstream_delay
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = delay;
    }
}
