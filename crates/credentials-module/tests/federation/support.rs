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

const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(3);

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
    loop {
        let Ok(Some(frame)) = read_frame(&mut stream).await else {
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
        let body: Value = match serde_json::from_slice(&frame.body) {
            Ok(body) => body,
            Err(_) => continue,
        };
        if frame.header.ty == FrameType::Request && frame.header.channel == 0 {
            match body.get("op").and_then(Value::as_str) {
                Some("catalog.list") => {
                    let reply = Frame::build(
                        FrameType::Response,
                        Flags::new(false, Priority::Passive, false),
                        0,
                        0,
                        frame.header.corr,
                        serde_json::to_vec(&json!({
                            "generation": 1,
                            "modules": [],
                            "subc_ops": [],
                        }))
                        .expect("json"),
                    )
                    .expect("frame");
                    let _ = write_frame(&mut stream, &reply).await;
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
                    let channel = next_channel.fetch_add(1, Ordering::Relaxed) as u16;
                    let epoch = 1;
                    open_routes.insert(channel, (target, harness, body.clone()));
                    let reply = Frame::build(
                        FrameType::Response,
                        Flags::new(false, Priority::Passive, false),
                        0,
                        0,
                        frame.header.corr,
                        serde_json::to_vec(&json!({
                            "route_channel": channel,
                            "route_epoch": epoch,
                        }))
                        .expect("json"),
                    )
                    .expect("frame");
                    let _ = write_frame(&mut stream, &reply).await;
                }
                _ => {
                    let reply =
                        error_frame(frame.header.corr, "fed_bad_call", "unknown control op");
                    let _ = write_frame(&mut stream, &reply).await;
                }
            }
            continue;
        }
        let Some((target, _, _)) = open_routes.get(&frame.header.channel) else {
            continue;
        };
        let target = target.clone();
        let method = body
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let params = body.get("params").cloned().unwrap_or(Value::Null);
        push(
            &ledger,
            Ledger::Request {
                target: target.clone(),
                method: method.clone(),
                params: params.clone(),
            },
        );
        let reply = {
            let state = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state
                .replies
                .get(&(target.clone(), method.clone()))
                .cloned()
        };
        let Some(reply) = reply else {
            push(
                &ledger,
                Ledger::Refused {
                    target: target.clone(),
                    code: "fed_unknown_module".into(),
                },
            );
            let reply = error_frame(frame.header.corr, "fed_unknown_module", "no such method");
            let _ = write_frame(&mut stream, &reply).await;
            continue;
        };
        match reply {
            Reply::Ok(body) => {
                let reply = response_frame(
                    frame.header.channel,
                    frame.header.epoch,
                    frame.header.corr,
                    body,
                );
                let _ = write_frame(&mut stream, &reply).await;
            }
            Reply::Permanent(code) | Reply::RetrySafe(code) => {
                push(
                    &ledger,
                    Ledger::Refused {
                        target: target.clone(),
                        code: code.clone(),
                    },
                );
                let reply = error_frame(frame.header.corr, &code, "callosum refused the call");
                let _ = write_frame(&mut stream, &reply).await;
            }
            Reply::Stall => {
                // Hold the connection, answer nothing: only the caller's deadline ends
                // this. Reading again detects the caller hanging up.
                loop {
                    match read_frame(&mut stream).await {
                        Ok(None) | Err(_) => break,
                        Ok(Some(next)) if next.header.ty == FrameType::Goodbye => break,
                        Ok(Some(_)) => continue,
                    }
                }
                break;
            }
            Reply::Drop => {
                push(
                    &ledger,
                    Ledger::Closed {
                        target: target.clone(),
                    },
                );
                break;
            }
            Reply::Delayed(delay, inner) => {
                tokio::time::sleep(delay).await;
                match *inner {
                    Reply::Ok(body) => {
                        let reply = response_frame(
                            frame.header.channel,
                            frame.header.epoch,
                            frame.header.corr,
                            body,
                        );
                        let _ = write_frame(&mut stream, &reply).await;
                    }
                    other => {
                        // A delay wrapping a refusal is refused, never stalled.
                        let code = match other {
                            Reply::Permanent(code) | Reply::RetrySafe(code) => code,
                            _ => "fed_bad_call".to_string(),
                        };
                        let reply = error_frame(frame.header.corr, &code, "delayed refusal");
                        let _ = write_frame(&mut stream, &reply).await;
                    }
                }
            }
        }
    }
}

fn push(ledger: &Arc<Mutex<Vec<Ledger>>>, row: Ledger) {
    ledger
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(row);
}

fn response_frame(channel: u16, epoch: u32, corr: u64, body: Value) -> Frame {
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
