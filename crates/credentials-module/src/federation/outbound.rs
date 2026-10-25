//! The vault's outbound client: the one place this daemon is a *consumer* of subc
//! instead of a provider.
//!
//! B's vault calls a home vault (or asks callosum about a peer) on the management
//! surface. It does that over its own authenticated connection to subc, never over
//! the inbound connection the supervisor holds open to this module: the inbound frame
//! loop is read by one task and answered on two egress lanes that deliberately serve
//! health replies first, so a request initiated there could not wait without either
//! blocking the health probe or inventing a third lane. Each call therefore runs on a
//! spawned task that awaits its own connection's reply, matched by correlation id, and
//! the caller's deadline is the only thing that bounds the wait.
//!
//! Every call carries a deadline, and each one is below the deadline of whoever waits
//! on it: the Rust consumer client gives up on a `get_scoped` reply after 3 s
//! (`CREDENTIAL_READ_TIMEOUT`, `crates/claustrum-client/src/lib.rs`) and the CLI waits
//! 15 s for `admin.op` (`route_client.rs`). If the vault's own call outlived those, the
//! consumer would see a transport timeout instead of the vault's definite refusal.
//!
//! A binding is a cache entry, not a fixture. Any missed deadline, `Goodbye`, EOF or
//! IO error drops it, so the next call opens a fresh route. A restarted subc or
//! callosum is silent about the old route (frames on a dead epoch are dropped without
//! an error, see `docs/wire-contract-v1.md` §9), and this is what turns that silence
//! into one transient failure followed by a success instead of a vault restart.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use subc_control::ConsumerIdentity;
use subc_protocol::{BindIdentity, Flags, Frame, FrameType, Priority, RouteTarget};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;

/// A consumer-facing forwarded call (B's remote read, B's forwarded report) must
/// finish end to end in this long, because the Rust client gives the reply frame 3 s.
pub const CONSUMER_FACING_DEADLINE: Duration = Duration::from_millis(2_500);

/// The home handles each federation op within this long, which keeps its work inside
/// the requester's 2.5 s budget with room for the round trip.
pub const HOME_OP_DEADLINE: Duration = Duration::from_millis(1_500);

/// One admin op may make several outbound calls (a key lookup then a delivery, a
/// pairing lookup then a fetch). They share this single budget, and the CLI's 15 s
/// reply wait leaves the operator a definite answer well before it expires.
pub const ADMIN_OP_BUDGET: Duration = Duration::from_secs(10);

const CONNECT_DEADLINE: Duration = Duration::from_secs(3);

/// What an outbound call can fail with, in the terms the federation surfaces speak.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundError {
    /// Nothing usable answered in time, or the connection died under the call. The
    /// binding is already dropped; the next call reopens.
    Unavailable(String),
}

impl OutboundError {
    /// True for a failure the caller may retry. Every error this client produces is
    /// transport-shaped, and none of them says anything about a credential.
    pub fn is_transient(&self) -> bool {
        true
    }

    /// A stable code for logs and stored fetch outcomes.
    pub fn code(&self) -> &'static str {
        "home_unreachable"
    }
}

/// One request to make on a route.
#[derive(Debug, Clone)]
pub struct RouteCall {
    /// The `route.open` target. The client, not the caller, builds the control body
    /// so the consumer identity is attached in exactly one place and no call site can
    /// forget it.
    pub target: RouteTarget,
    /// The channel-0 control request that resolves the route's target module, if the
    /// caller needs one before it can name a target (a peer fingerprint resolved to a
    /// module id, for example). Sent over the same connection, before the route opens.
    pub prelude: Option<Value>,
    /// The data-plane request body. The frame's own channel, epoch and correlation id
    /// are filled in by the client.
    pub request: Value,
}

/// A resolved binding the client reuses across calls until something breaks it.
#[derive(Debug, Clone)]
struct Binding {
    channel: u16,
    epoch: u32,
}

/// The outbound client. Cheap to clone; every clone shares one connection, one
/// binding cache and one request id space.
#[derive(Clone)]
pub struct OutboundClient {
    inner: Arc<Inner>,
}

struct Inner {
    connection_file: std::path::PathBuf,
    consumer_identity: Option<ConsumerIdentity>,
    /// Serializes work on the shared connection: the handshake, `route.open`,
    /// prelude calls, and the reply waits. Holding it for the whole op on the daemon
    /// is correct but head-of-line-blocks; callers that must not wait on each other
    /// (the admin path and the inbound read path) do, and each still holds it for
    /// only its own deadline.
    connection: AsyncMutex<Option<TcpStream>>,
    bindings: Mutex<HashMap<String, Binding>>,
    next_corr: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for OutboundClient {
    // `ConsumerIdentity` already redacts the launch nonce in its own `Debug`, and the
    // connection is not printed at all: it is a live socket, not state.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundClient")
            .field("consumer_identity", &self.inner.consumer_identity)
            .finish_non_exhaustive()
    }
}

impl OutboundClient {
    /// Build the client a supervised daemon uses. `consumer_identity` is built from the
    /// module id and the launch nonce the daemon already read at startup, so a peer
    /// daemon can attest this vault rather than trusting a claim in the request body.
    pub fn for_daemon(
        connection_file: impl Into<std::path::PathBuf>,
        module_id: &str,
        launch_nonce: Option<&str>,
    ) -> Self {
        let consumer_identity = launch_nonce.map(|launch_nonce| ConsumerIdentity {
            module_id: module_id.to_string(),
            launch_nonce: launch_nonce.to_string(),
        });
        Self::new(connection_file, consumer_identity)
    }

    /// Build the client from an explicit identity, including `None` for a caller that
    /// has no launch nonce to present (an unsupervised run, or a test).
    pub fn new(
        connection_file: impl Into<std::path::PathBuf>,
        consumer_identity: Option<ConsumerIdentity>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                connection_file: connection_file.into(),
                consumer_identity,
                connection: AsyncMutex::new(None),
                bindings: Mutex::new(HashMap::new()),
                next_corr: std::sync::atomic::AtomicU64::new(1),
            }),
        }
    }

    /// The identity this client presents on every `route.open`, for tests and for
    /// logging that never prints the nonce.
    pub fn consumer_identity(&self) -> Option<&ConsumerIdentity> {
        self.inner.consumer_identity.as_ref()
    }

    /// Forget every cached binding. Nothing calls this in normal operation: a broken
    /// binding is dropped where it breaks. It exists so a test can prove a stale
    /// binding is what fails, rather than the connection underneath it.
    pub fn drop_bindings(&self) {
        self.inner
            .bindings
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    /// Run one call, bounded by `deadline`.
    ///
    /// Returns the reply frame's body on `Response` and `Err` with the daemon's reason
    /// on an `Error` frame — a refusal from the peer is an answer, not a transport
    /// failure, so the caller classifies it. Everything else (no connection, no reply
    /// in time, a frame for another binding, `Goodbye`, EOF) is
    /// [`OutboundError::Unavailable`] and drops the binding that failed.
    pub async fn call(
        &self,
        route_key: &str,
        call: RouteCall,
        deadline: Duration,
    ) -> Result<Value, OutboundError> {
        let budget = tokio::time::Instant::now() + deadline;
        let outcome = self.call_inner(route_key, &call, budget).await;
        if outcome.is_err() {
            self.drop_binding(route_key);
            // Drop the connection too: a binding failure is diagnosed as a dead
            // epoch, but a missed deadline or an IO error can equally mean the socket
            // is a corpse. Reopening costs one handshake, once, and the call after it
            // is the one a recovery test expects to succeed.
            let mut connection = self.inner.connection.lock().await;
            *connection = None;
        }
        outcome
    }

    /// The channel-0 `route.open` body for `target`, carrying this client's consumer
    /// identity so the daemon stamps the vault's principal on the route bind.
    fn open_body(&self, target: &RouteTarget) -> Value {
        let mut body = json!({
            "op": "route.open",
            "target": target,
            "identity": bind_identity(),
        });
        if let Some(identity) = self.inner.consumer_identity.as_ref() {
            body["consumer_identity"] = json!({
                "module_id": identity.module_id,
                "launch_nonce": identity.launch_nonce,
            });
        }
        body
    }

    fn drop_binding(&self, route_key: &str) {
        self.inner
            .bindings
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(route_key);
    }

    fn next_corr(&self) -> u64 {
        self.inner
            .next_corr
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    async fn call_inner(
        &self,
        route_key: &str,
        call: &RouteCall,
        budget: tokio::time::Instant,
    ) -> Result<Value, OutboundError> {
        // One task owns the connection stream while it answers this call, and the
        // caller never touches the socket directly: the whole exchange is one future
        // so a deadline that fires mid-write cannot leave a half frame for the next
        // call's reply to be confused by.
        let mut connection = tokio::time::timeout_at(budget, self.inner.connection.lock())
            .await
            .map_err(|_| {
                OutboundError::Unavailable("outbound connection busy past deadline".into())
            })?;
        if connection.is_none() {
            let connect_budget = remaining(budget, || {
                OutboundError::Unavailable("no time to connect".into())
            })?;
            // The handshake identity is the daemon's own, so a peer daemon stamps
            // this vault as a supervised module rather than as a direct key-holder.
            let stream = connect(&self.inner.connection_file, connect_budget).await?;
            *connection = Some(stream);
        }
        let stream = connection
            .as_mut()
            .expect("the connection is installed just above");

        if let Some(prelude) = call.prelude.as_ref() {
            let corr = self.next_corr();
            let reply = exchange(
                stream,
                control_frame(corr, prelude),
                Some(0),
                corr,
                budget,
                "prelude",
            )
            .await?;
            if reply.header.ty == FrameType::Error {
                return Err(OutboundError::Unavailable(format!(
                    "prelude refused: {}",
                    error_reason(&reply.body)
                )));
            }
        }

        let binding = {
            let cached = self
                .inner
                .bindings
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(route_key)
                .cloned();
            match cached {
                Some(binding) => binding,
                None => {
                    let corr = self.next_corr();
                    let reply = exchange(
                        stream,
                        control_frame(corr, &self.open_body(&call.target)),
                        Some(0),
                        corr,
                        budget,
                        "route.open",
                    )
                    .await?;
                    if reply.header.ty == FrameType::Error {
                        return Err(OutboundError::Unavailable(format!(
                            "route.open refused: {}",
                            error_reason(&reply.body)
                        )));
                    }
                    let opened = parse_open(&reply.body)?;
                    self.inner
                        .bindings
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .insert(route_key.to_string(), opened.clone());
                    opened
                }
            }
        };

        let corr = self.next_corr();
        let request = Frame::build(
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            binding.channel,
            binding.epoch,
            corr,
            serde_json::to_vec(&call.request)
                .map_err(|error| OutboundError::Unavailable(format!("encode request: {error}")))?,
        )
        .map_err(|error| OutboundError::Unavailable(format!("build request frame: {error}")))?;
        let reply = exchange(
            stream,
            request,
            Some(binding.channel),
            corr,
            budget,
            "request",
        )
        .await?;
        serde_json::from_slice(&reply.body)
            .map_err(|error| OutboundError::Unavailable(format!("decode reply: {error}")))
    }
}

/// How long is left before `budget`, as a Duration; an expired budget is an error.
fn remaining(
    budget: tokio::time::Instant,
    error: impl FnOnce() -> OutboundError,
) -> Result<Duration, OutboundError> {
    let now = tokio::time::Instant::now();
    if budget <= now {
        return Err(error());
    }
    Ok(budget - now)
}

fn error_reason(body: &[u8]) -> String {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("message")
                .or_else(|| value.get("detail"))
                .or_else(|| value.get("code"))
                .and_then(Value::as_str)
                .map(String::from)
        })
        .unwrap_or_else(|| "the daemon refused the operation".to_string())
}

fn control_frame(corr: u64, body: &Value) -> Frame {
    Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        corr,
        serde_json::to_vec(body).expect("JSON control request"),
    )
    .expect("valid control frame")
}

fn parse_open(body: &[u8]) -> Result<Binding, OutboundError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|error| OutboundError::Unavailable(format!("decode route.open: {error}")))?;
    let channel = value["route_channel"]
        .as_u64()
        .and_then(|channel| u16::try_from(channel).ok())
        .ok_or_else(|| OutboundError::Unavailable("route.open returned no route_channel".into()))?;
    let epoch = value["route_epoch"]
        .as_u64()
        .and_then(|epoch| u32::try_from(epoch).ok())
        .ok_or_else(|| OutboundError::Unavailable("route.open returned no route_epoch".into()))?;
    Ok(Binding { channel, epoch })
}

/// Connect and complete the client handshake under `deadline` (the connect attempt
/// and the handshake share it).
async fn connect(
    connection_file_path: &std::path::Path,
    deadline: Duration,
) -> Result<TcpStream, OutboundError> {
    let budget = tokio::time::Instant::now() + deadline.min(CONNECT_DEADLINE);
    let conn = connection_file::read_for_client(connection_file_path)
        .map_err(|error| OutboundError::Unavailable(format!("no subc connection file: {error}")))?;
    let endpoint = conn
        .endpoints
        .first()
        .ok_or_else(|| OutboundError::Unavailable("connection file has no endpoint".into()))?;
    let stream_budget = remaining(budget, || {
        OutboundError::Unavailable("no time to connect".into())
    })?;
    let mut stream = tokio::time::timeout(
        stream_budget,
        TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
    )
    .await
    .map_err(|_| OutboundError::Unavailable("connect timed out".into()))?
    .map_err(|error| OutboundError::Unavailable(format!("connect: {error}")))?;
    let handshake_budget = remaining(budget, || {
        OutboundError::Unavailable("no time to handshake".into())
    })?;
    authenticate_client(&mut stream, &conn, handshake_budget)
        .await
        .map_err(|error| OutboundError::Unavailable(format!("client handshake: {error}")))?;
    Ok(stream)
}

/// Write `frame` and wait for the reply carrying `corr`, on `channel` unless it is
/// `None` (a control reply must carry channel 0; a route reply must carry the route's
/// channel). Frames for anything else on this connection are not ours: a `Goodbye`
/// ends the connection, and anything else is skipped, because a dropped request can
/// still produce a late reply for an earlier correlation id.
async fn exchange(
    stream: &mut TcpStream,
    frame: Frame,
    channel: Option<u16>,
    corr: u64,
    budget: tokio::time::Instant,
    stage: &'static str,
) -> Result<Frame, OutboundError> {
    tokio::time::timeout_at(budget, write_frame(stream, &frame))
        .await
        .map_err(|_| OutboundError::Unavailable(format!("writing the {stage} timed out")))?
        .map_err(|error| OutboundError::Unavailable(format!("writing the {stage}: {error}")))?;
    loop {
        let next = tokio::time::timeout_at(budget, read_frame(stream))
            .await
            .map_err(|_| OutboundError::Unavailable(format!("the {stage} reply timed out")))?
            .map_err(|error| OutboundError::Unavailable(format!("reading the {stage}: {error}")))?
            .ok_or_else(|| {
                OutboundError::Unavailable(format!("the connection closed during the {stage}"))
            })?;
        if matches!(
            next.header.ty,
            FrameType::Goodbye | FrameType::Ping | FrameType::Pong
        ) {
            // The daemon sends `Goodbye` on the control channel when it is shutting
            // down; a ping needs no answer from a client, and neither is a reply.
            if next.header.ty == FrameType::Goodbye {
                return Err(OutboundError::Unavailable(format!(
                    "the daemon said goodbye during the {stage}"
                )));
            }
            continue;
        }
        let matches_channel = channel.map_or(next.header.channel == 0, |channel| {
            next.header.channel == channel
        });
        if matches_channel
            && next.header.corr == corr
            && matches!(next.header.ty, FrameType::Response | FrameType::Error)
        {
            return Ok(next);
        }
    }
}

/// The route target for one module's management surface.
pub fn management_surface(module_id: &str) -> RouteTarget {
    RouteTarget::ManagementSurface {
        module_id: module_id.to_string(),
    }
}

/// The route identify a vault's outbound call uses. Every field is client-supplied;
/// it exists so the target's bind is attributable, and the target authorizes on the
/// principal its daemon stamps from `consumer_identity`, never on these.
pub fn bind_identity() -> BindIdentity {
    BindIdentity::new(".", "claustrum-outbound", "claustrum-federation")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_deadlines_sit_below_the_consumers_that_wait_on_them() {
        // The Rust consumer client allows 3 s per reply frame; the CLI allows 15 s for
        // the whole admin op. Both are external facts, quoted here so a change to
        // either deadline has to argue with them.
        assert!(CONSUMER_FACING_DEADLINE < Duration::from_secs(3));
        assert!(HOME_OP_DEADLINE < CONSUMER_FACING_DEADLINE);
        assert!(ADMIN_OP_BUDGET < Duration::from_secs(15));
    }

    #[test]
    fn a_daemon_client_presents_the_module_id_and_nonce_it_was_given() {
        let client = OutboundClient::for_daemon("/nonexistent", "claustrum", Some("nonce-1"));
        let identity = client.consumer_identity().expect("identity");
        assert_eq!(identity.module_id, "claustrum");
        assert_eq!(identity.launch_nonce, "nonce-1");
        assert!(
            !format!("{client:?}").contains("nonce-1"),
            "the nonce is never printed"
        );
    }

    #[test]
    fn a_client_without_a_nonce_presents_no_identity() {
        let client = OutboundClient::for_daemon("/nonexistent", "claustrum", None);
        assert!(client.consumer_identity().is_none());
    }
}
