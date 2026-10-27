//! The vault's outbound client: the one place this daemon is a *consumer* of subc
//! instead of a provider.
//!
//! The consuming vault calls the vault that homes a credential (or asks callosum about
//! a peer) on the management surface. It does that over its own authenticated
//! connection to subc, never over the inbound connection the supervisor holds open to
//! this module: the inbound frame loop is read by one task and answered on two egress
//! lanes that deliberately serve health replies first, so a request initiated there
//! could not wait without either blocking the health probe or inventing a third lane.
//! Each call therefore awaits its own connection's reply, and the caller's deadline is
//! the only thing that bounds the wait.
//!
//! Every call carries a deadline, and each one is below the deadline of whoever waits
//! on it: the Rust consumer client gives up on a `get_scoped` reply after 3 s
//! (`CREDENTIAL_READ_TIMEOUT`, `crates/claustrum-client/src/lib.rs`) and the CLI waits
//! 15 s for `admin.op` (`route_client.rs`). If the vault's own call outlived those, the
//! consumer would see a transport timeout instead of the vault's definite refusal.
//!
//! A binding is a cache entry, not a fixture. A missed deadline or a `Goodbye` on its
//! route channel drops it, and a binding never outlives the connection it was opened
//! on, so the next call opens a fresh route. A restarted subc or
//! callosum is silent about the old route (frames on a dead epoch are dropped without
//! an error, see `docs/wire-contract-v1.md` §9), and this is what turns that silence
//! into one transient failure followed by a success instead of a vault restart.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use subc_control::ConsumerIdentity;
use subc_protocol::{BindIdentity, Flags, Frame, FrameType, Priority, RouteTarget};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Mutex as AsyncMutex};

/// A consumer-facing forwarded call (B's remote read, B's forwarded report) must
/// finish end to end in this long, because the Rust client gives the reply frame 3 s.
pub const CONSUMER_FACING_DEADLINE: Duration = Duration::from_millis(2_500);

/// How long a vault whose secret home is another member keeps trying one forwarded
/// secret call (`secret.use` and the two flow ops), retries included. The local sender
/// waits for the reply as a consumer read does, so this is the consumer-facing
/// deadline. It is also far below the home's release-receipt lifetime
/// (`SECRET_RELEASE_RECEIPT_LIFETIME_MS`, 10 minutes): every retry of one call reaches
/// the home while the receipt for its nonce still exists, so a nonce is never answered
/// afresh after the home has swept its receipt.
pub const SECRET_FORWARD_DEADLINE: Duration = CONSUMER_FACING_DEADLINE;

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
    /// The daemon or broker answered with a definite refusal, not a timeout.
    Refused { code: String, message: String },
}

impl OutboundError {
    /// True for transport uncertainty or a retryable control refusal. A route refusal
    /// says nothing about the credential behind the route.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Unavailable(_) => true,
            Self::Refused { code, .. } => !is_permanent_callosum_class(code),
        }
    }

    /// The message a caller may log or return.
    pub fn message(&self) -> &str {
        match self {
            Self::Unavailable(message) => message,
            Self::Refused { message, .. } => message,
        }
    }
}

/// A failure paired with the connection that caused it, inside the client only: the
/// reader task condemns one connection as a unit, and `call` retires exactly that
/// link, never a newer one a concurrent call has already established.
#[derive(Debug, Clone)]
struct LinkFailure {
    error: OutboundError,
    dead: Option<Arc<Link>>,
}

impl From<OutboundError> for LinkFailure {
    /// A failure that leaves the connection healthy: only this call's binding is stale.
    fn from(error: OutboundError) -> Self {
        failure(error)
    }
}

/// A failure that leaves the connection healthy: only this call's binding is stale.
fn failure(error: OutboundError) -> LinkFailure {
    LinkFailure { error, dead: None }
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
    /// The [`Link::id`] of the connection the route was opened on. A route belongs to
    /// one connection, so a binding is never sent on any other.
    link: u64,
    /// The channel's [`Link::route_closures`] count when the route opened. A higher
    /// count means the daemon has closed this route since, even if it has handed the
    /// same channel number to a newer route.
    closures: u64,
}

/// The outbound client. Cheap to clone; every clone shares one connection, one
/// binding cache and one request id space.
#[derive(Clone)]
pub struct OutboundClient {
    inner: Arc<Inner>,
}

/// The multiplexed connection a client currently holds.
///
/// One connection carries many calls at once, so neither a slow call nor a failed one
/// can hold another up:
///
/// - the [`Link::write`] lock is taken only while a frame is encoded onto the socket,
///   never across a wait;
/// - a single reader task owns the read half and hands each reply to the call waiting
///   for its correlation id, so a call's wait is its own and nobody else's;
/// - a call that misses its deadline withdraws only its own waiter and drops only its
///   own binding, leaving the connection and every other call alone.
///
/// The daemon can end one route or the whole connection, and the reader tells the two
/// apart:
///
/// - A `Goodbye` on a route channel closes that route alone. subc sends one per route
///   when the far end of the route goes away (a callosum restart, say) and keeps the
///   connection open. The reader fails only the calls waiting on that channel, counts
///   the closure in [`Link::route_closures`], and keeps reading. A cached binding
///   saved under an earlier count is rejected on reuse, so the next call on that
///   route opens it again.
/// - A `Goodbye` on channel 0, EOF, an IO error or a frame that cannot be read ends the
///   connection. The reader sets [`Link::closed`], fails every pending call, closes its
///   write side so the daemon can release the connection, and stops.
///
/// A closed link is never used again, whether or not a call was in flight to see it
/// die: the client treats a closed link as absent and dials a new one. A call that
/// registers its waiter after the reader has already failed the pending ones sees the
/// flag and fails at once, rather than writing into a socket nobody reads and waiting
/// out its whole deadline.
struct Link {
    /// Names the link in its `Debug` output, so a log line can say which one died, and
    /// ties each [`Binding`] to the connection its route was opened on.
    id: u64,
    write: AsyncMutex<tokio::io::WriteHalf<TcpStream>>,
    waiters: std::sync::Mutex<HashMap<WaiterKey, oneshot::Sender<Result<Frame, String>>>>,
    /// Set by the reader before it fails the pending calls and stops. Nothing reads
    /// replies on a closed link, so nothing may be sent on it.
    closed: AtomicBool,
    /// How many route `Goodbye`s the reader has seen on each channel. subc may reuse a
    /// channel number for a later route, so a closure is counted rather than recorded
    /// as a yes/no: a binding is live only while the count is still the one it was
    /// opened under.
    route_closures: std::sync::Mutex<HashMap<u16, u64>>,
}

impl Link {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn closures(&self, channel: u16) -> u64 {
        self.route_closures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&channel)
            .copied()
            .unwrap_or(0)
    }

    /// True when `binding` was opened on this connection and its route has not been
    /// closed since.
    fn holds(&self, binding: &Binding) -> bool {
        binding.link == self.id && binding.closures == self.closures(binding.channel)
    }
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The write half is a live socket and the waiter map holds call state; neither
        // belongs in a log line. The id is enough to say which link died.
        f.debug_struct("Link")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// What a pending reply is matched on. A control reply arrives on channel 0; a route
/// reply arrives on the channel (and therefore the binding) its request went to, so a
/// reply for a channel the call no longer holds cannot be mistaken for its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum WaiterKey {
    Control(u64),
    Route(u16, u64),
}

struct Inner {
    connection_file: std::path::PathBuf,
    consumer_identity: Option<ConsumerIdentity>,
    /// The current link. The lock is held only while a link is read, installed or
    /// retired, never across a call: callers clone the `Arc` out and wait on their own
    /// oneshot.
    connection: AsyncMutex<Option<Arc<Link>>>,
    /// Guards the "connect if absent" step so two concurrent calls cannot both dial.
    /// Held only for the handshake, which is bounded by its own deadline.
    connector: AsyncMutex<()>,
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
                connector: AsyncMutex::new(()),
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
    /// in time, the connection dying) is [`OutboundError::Unavailable`].
    ///
    /// A failure withdraws this call's own waiter and drops this call's own binding.
    /// It never tears down a connection another call is using: only the reader task
    /// does that, and only when a frame proves the connection itself is gone.
    pub async fn call(
        &self,
        route_key: &str,
        call: RouteCall,
        deadline: Duration,
    ) -> Result<Value, OutboundError> {
        let budget = tokio::time::Instant::now() + deadline;
        match self.call_inner(route_key, &call, budget).await {
            Ok(reply) => Ok(reply),
            Err(failure) => {
                self.drop_binding(route_key);
                if let Some(dead) = failure.dead.as_ref() {
                    self.retire(dead, budget).await;
                }
                Err(failure.error)
            }
        }
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

    /// The live link, dialing one if the client has none yet.
    async fn link(&self, budget: tokio::time::Instant) -> Result<Arc<Link>, OutboundError> {
        if let Some(link) = self.current_link().await {
            return Ok(link);
        }
        // Two calls arriving on an idle client must not both dial: the second waits
        // for the first's handshake, still inside its own budget.
        let _dialing = tokio::time::timeout_at(budget, self.inner.connector.lock())
            .await
            .map_err(|_| OutboundError::Unavailable("no time to connect".into()))?;
        if let Some(link) = self.current_link().await {
            return Ok(link);
        }
        let connect_budget = remaining(budget, || {
            OutboundError::Unavailable("no time to connect".into())
        })?;
        let stream = connect(&self.inner.connection_file, connect_budget).await?;
        let link = self.install(stream).await;
        Ok(link)
    }

    /// The live link, or `None` when there is none or the one held has closed. A closed
    /// link is dropped here, so its socket is released even if no call ever saw it die.
    async fn current_link(&self) -> Option<Arc<Link>> {
        let mut slot = self.inner.connection.lock().await;
        if slot.as_ref().is_some_and(|link| link.is_closed()) {
            *slot = None;
        }
        slot.clone()
    }

    /// Split a freshly handshaken socket from its read half and start the reader task.
    async fn install(&self, stream: TcpStream) -> Arc<Link> {
        let (read_half, write_half) = tokio::io::split(stream);
        let link = Arc::new(Link {
            id: self.next_corr(),
            write: tokio::sync::Mutex::new(write_half),
            waiters: std::sync::Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
            route_closures: std::sync::Mutex::new(HashMap::new()),
        });
        let reader_link = Arc::clone(&link);
        tokio::spawn(async move {
            read_replies(read_half, reader_link).await;
        });
        *self.inner.connection.lock().await = Some(Arc::clone(&link));
        link
    }

    /// Forget `dead` if it is still the live link, so the next call dials a new one.
    ///
    /// The wait is bounded by this call's own budget. The only thing it can wait on is
    /// another caller's one `lock()` acquisition or a dialer's handshake, and the
    /// handshake has its own deadline, so a bounded wait here is never open-ended.
    async fn retire(&self, dead: &Arc<Link>, budget: tokio::time::Instant) {
        if let Ok(mut slot) = tokio::time::timeout_at(budget, self.inner.connection.lock()).await {
            if slot
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, dead))
            {
                *slot = None;
            }
        }
    }

    async fn call_inner(
        &self,
        route_key: &str,
        call: &RouteCall,
        budget: tokio::time::Instant,
    ) -> Result<Value, LinkFailure> {
        let link = self.link(budget).await.map_err(failure)?;

        if let Some(prelude) = call.prelude.as_ref() {
            let corr = self.next_corr();
            let reply = self
                .exchange(
                    &link,
                    control_frame(corr, prelude),
                    WaiterKey::Control(corr),
                    budget,
                    "prelude",
                    None,
                )
                .await?;
            if reply.header.ty == FrameType::Error {
                return Err(failure(control_refusal(&reply.body)));
            }
        }

        // A cached binding counts only if its route is still open on this very
        // connection: one opened on a connection that has since closed, or closed by a
        // route `Goodbye`, is reopened instead of written into a route nobody serves.
        let cached = {
            self.inner
                .bindings
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(route_key)
                .cloned()
        }
        .filter(|binding| link.holds(binding));
        let binding = match cached {
            Some(binding) => binding,
            None => {
                let corr = self.next_corr();
                let reply = self
                    .exchange(
                        &link,
                        control_frame(corr, &self.open_body(&call.target)),
                        WaiterKey::Control(corr),
                        budget,
                        "route.open",
                        None,
                    )
                    .await?;
                if reply.header.ty == FrameType::Error {
                    return Err(failure(control_refusal(&reply.body)));
                }
                let opened = parse_open(&reply.body, &link)?;
                self.inner
                    .bindings
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(route_key.to_string(), opened.clone());
                opened
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
        let reply = self
            .exchange(
                &link,
                request,
                WaiterKey::Route(binding.channel, corr),
                budget,
                "request",
                Some(&binding),
            )
            .await?;
        if reply.header.channel == 0 && reply.header.ty == FrameType::Error {
            return Err(failure(control_refusal(&reply.body)));
        }
        let body: Value = serde_json::from_slice(&reply.body)
            .map_err(|error| OutboundError::Unavailable(format!("decode reply: {error}")))?;
        // `call` hands back the reply's `result` member, whatever the channel: one
        // shape for every reply, the same shape the daemon's control commands use. A
        // body without that member is passed through unchanged, so a target that
        // answers with a bare object is still readable.
        Ok(body.get("result").cloned().unwrap_or(body))
    }

    /// Send one frame and wait for the reply matched by `key`, all inside `budget`.
    ///
    /// The waiter is registered before the write, so a reply that arrives immediately
    /// cannot be missed. Either way, this call removes its own waiter before returning,
    /// and a deadline withdraws it, so no later reply can be delivered to it.
    ///
    /// `route` is the binding a route request travels on, and `None` for a channel-0
    /// control request.
    async fn exchange(
        &self,
        link: &Arc<Link>,
        frame: Frame,
        key: WaiterKey,
        budget: tokio::time::Instant,
        stage: &'static str,
        route: Option<&Binding>,
    ) -> Result<Frame, LinkFailure> {
        let (sender, reply) = oneshot::channel();
        link.waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key, sender);
        // The reader marks a link closed (or counts a route closure) before it fails
        // the waiters already registered. Checking after registering therefore leaves
        // no gap: either the reader's sweep finds this waiter, or this check sees the
        // mark. Without it a call that raced the reader's exit would write into a
        // socket nobody reads and wait out its whole deadline.
        if link.is_closed() {
            withdraw(link, key);
            return Err(LinkFailure {
                error: OutboundError::Unavailable(format!(
                    "the connection closed before the {stage} was sent"
                )),
                dead: Some(Arc::clone(link)),
            });
        }
        if route.is_some_and(|binding| !link.holds(binding)) {
            withdraw(link, key);
            return Err(failure(OutboundError::Unavailable(format!(
                "the route closed before the {stage} was sent"
            ))));
        }
        let written = self
            .write(link, &frame, budget, stage)
            .await
            .map_err(failure);
        // The waiter is withdrawn on every path below: after a successful write a dead
        // connection's reader has already failed it, and after a failed write nothing
        // will ever reply to it.
        match written {
            Ok(()) => {}
            Err(error) => {
                withdraw(link, key);
                return Err(error);
            }
        }
        match tokio::time::timeout_at(budget, reply).await {
            Ok(Ok(Ok(frame))) => Ok(frame),
            // The reader failed this call. If it closed the whole connection, the call
            // hands the link back to be retired; a route `Goodbye` leaves the link
            // healthy and costs this call only its binding.
            Ok(Ok(Err(why))) => Err(LinkFailure {
                error: OutboundError::Unavailable(why),
                dead: link.is_closed().then(|| Arc::clone(link)),
            }),
            Ok(Err(_)) => Err(LinkFailure {
                error: OutboundError::Unavailable(format!("the {stage} reply channel closed")),
                dead: Some(Arc::clone(link)),
            }),
            Err(_) => {
                // Taking the waiter out is what makes a reply racing the deadline
                // either ours or dropped, never delivered to a call that has returned.
                // A deadline is this call's failure alone: the connection and every
                // other call on it are untouched.
                withdraw(link, key);
                Err(failure(OutboundError::Unavailable(format!(
                    "the {stage} reply timed out"
                ))))
            }
        }
    }

    /// Encode `frame` onto the socket. The write lock covers the bytes of one frame
    /// and nothing else: no reply wait, no handshake, no other call's work.
    async fn write(
        &self,
        link: &Arc<Link>,
        frame: &Frame,
        budget: tokio::time::Instant,
        stage: &'static str,
    ) -> Result<(), OutboundError> {
        let deadline = remaining(budget, || {
            OutboundError::Unavailable(format!("no time to send the {stage}"))
        })?;
        let write = link.write.lock();
        let mut write = match tokio::time::timeout(deadline, write).await {
            Ok(write) => write,
            Err(_) => {
                return Err(OutboundError::Unavailable(format!(
                    "writing the {stage} timed out"
                )))
            }
        };
        let sent = tokio::time::timeout_at(budget, write_frame(&mut *write, frame))
            .await
            .map_err(|_| OutboundError::Unavailable(format!("writing the {stage} timed out")))?;
        sent.map_err(|error| OutboundError::Unavailable(format!("writing the {stage}: {error}")))
    }
}

/// Remove `key`'s waiter, returning whether it was still there. A sender the reader
/// already took cannot be withdrawn, and the reader's own failure path does not need
/// it to be: it iterates the map it holds.
fn withdraw(link: &Link, key: WaiterKey) -> bool {
    link.waiters
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&key)
        .is_some()
}

/// The one reader of a connection. Every frame it reads is handed to the call waiting
/// for it; a frame nobody waits for (a late reply for a call that timed out, a ping) is
/// dropped, because a dropped request can still produce a reply for an earlier
/// correlation id. A route `Goodbye` fails that route's calls and reading goes on. A
/// frame that proves the connection is gone closes the link and ends this task, and
/// the next call, seeing the link closed, dials a fresh connection.
async fn read_replies<R>(mut reader: R, link: Arc<Link>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    loop {
        match read_frame(&mut reader).await {
            Ok(Some(frame)) => {
                if frame.header.ty == FrameType::Goodbye {
                    if frame.header.channel != 0 {
                        close_route(&link, frame.header.channel);
                        continue;
                    }
                    close_link(&link, "the daemon said goodbye").await;
                    return;
                }
                if frame.header.ty == FrameType::Ping || frame.header.ty == FrameType::Pong {
                    continue;
                }
                let key = if frame.header.channel == 0 {
                    WaiterKey::Control(frame.header.corr)
                } else {
                    WaiterKey::Route(frame.header.channel, frame.header.corr)
                };
                let mut waiters = link
                    .waiters
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let waiter = waiters.remove(&key).or_else(|| {
                    // A broker can refuse a routed request on channel zero. Correlation
                    // ids are connection-wide, so only its matching route waiter moves.
                    if frame.header.channel == 0 && frame.header.ty == FrameType::Error {
                        let route = waiters.keys().copied().find(|key| {
                            matches!(key, WaiterKey::Route(_, corr) if *corr == frame.header.corr)
                        });
                        route.and_then(|key| waiters.remove(&key))
                    } else {
                        None
                    }
                });
                if let Some(waiter) = waiter {
                    let _ = waiter.send(Ok(frame));
                }
            }
            Ok(None) => {
                close_link(&link, "the connection closed").await;
                return;
            }
            Err(error) => {
                close_link(&link, &format!("the connection failed: {error}")).await;
                return;
            }
        }
    }
}

/// End a connection the reader can no longer read: mark it closed first, so no call
/// registers a waiter that the sweep below would miss, then fail every pending call
/// and close the write side. Closing the write side tells the daemon this client has
/// finished with the connection, so it stops holding routes for a socket nobody
/// reads. The write lock is only ever held for one frame's bounded write, and the wait
/// for it is bounded here too, so the reader always finishes.
async fn close_link(link: &Link, why: &str) {
    link.closed.store(true, Ordering::SeqCst);
    fail_all(link, why);
    let _ = tokio::time::timeout(CONNECT_DEADLINE, async {
        let _ = link.write.lock().await.shutdown().await;
    })
    .await;
}

/// Close one route after the daemon's `Goodbye` on its channel. The closure is counted
/// before the route's waiters are failed, for the same no-gap reason as
/// [`close_link`]. Calls on other channels, and the connection, are untouched.
fn close_route(link: &Link, channel: u16) {
    *link
        .route_closures
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(channel)
        .or_insert(0) += 1;
    let pending: Vec<_> = {
        let mut waiters = link
            .waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let on_route: Vec<WaiterKey> = waiters
            .keys()
            .copied()
            .filter(|key| matches!(key, WaiterKey::Route(on, _) if *on == channel))
            .collect();
        on_route
            .into_iter()
            .filter_map(|key| waiters.remove(&key))
            .collect()
    };
    for waiter in pending {
        let _ = waiter.send(Err("the daemon closed the route".to_string()));
    }
}

/// Fail every pending call on a dead connection, so no caller waits out its whole
/// deadline for a reply that cannot come.
fn fail_all(link: &Link, why: &str) {
    let pending: Vec<_> = link
        .waiters
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .drain()
        .map(|(_, waiter)| waiter)
        .collect();
    for waiter in pending {
        let _ = waiter.send(Err(why.to_string()));
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

fn control_refusal(body: &[u8]) -> OutboundError {
    let code = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.get("code").and_then(Value::as_str).map(String::from))
        .unwrap_or_else(|| "unrecognised".into());
    OutboundError::Refused {
        code,
        message: error_reason(body),
    }
}

/// Callosum's permanent refusal classes describe a route that cannot be retried.
pub(super) fn is_permanent_callosum_class(code: &str) -> bool {
    matches!(
        code,
        "fed_not_exposed" | "fed_unknown_module" | "fed_bad_call"
    ) || code.starts_with("fed_payload_")
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

fn parse_open(body: &[u8], link: &Link) -> Result<Binding, OutboundError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|error| OutboundError::Unavailable(format!("decode route.open: {error}")))?;
    // `call` hands back the frame's `result` member, whatever the channel: one shape for
    // every reply, and the same shape the daemon's control commands use.
    let route = value.get("result").unwrap_or(&value);
    let channel = route["route_channel"]
        .as_u64()
        .and_then(|channel| u16::try_from(channel).ok())
        .ok_or_else(|| OutboundError::Unavailable("route.open returned no route_channel".into()))?;
    let epoch = route["route_epoch"]
        .as_u64()
        .and_then(|epoch| u32::try_from(epoch).ok())
        .ok_or_else(|| OutboundError::Unavailable("route.open returned no route_epoch".into()))?;
    Ok(Binding {
        channel,
        epoch,
        link: link.id,
        // Read after the reply arrived: the reader handles frames in order, so any
        // `Goodbye` for an earlier route on this channel number is already counted and
        // does not condemn this new one.
        closures: link.closures(channel),
    })
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

/// The route target for one module's management surface.
pub fn management_surface(module_id: &str) -> RouteTarget {
    RouteTarget::ManagementSurface {
        module_id: module_id.to_string(),
    }
}

/// The route identity a vault's outbound call sends. Every field is client-supplied;
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
