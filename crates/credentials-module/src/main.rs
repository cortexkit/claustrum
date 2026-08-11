#![forbid(unsafe_code)]

//! The claustrum subc module daemon (the credential vault).
//!
//! Connects out to the subc daemon, authenticates over loopback TCP, and registers
//! a reserved `ManagementSurface` — echoing the `SUBC_LAUNCH_NONCE` the supervisor
//! injected so only the spawned process can claim the `claustrum` id
//! (closing the vault-impersonation hole). It serves the ANONYMOUS READ surface
//! over the route channel only: `credential.get` / `get_many` / `status` /
//! `report_auth_failure`. There is deliberately NO write op on this channel — writes
//! live in the separate offline admin CLI, gated by master-key possession + the
//! single-writer lease.
//!
//! The subc registration handshake is a `HELLO` frame the module sends (carrying
//! its manifest and the launch nonce) and a `HELLO_ACK` the daemon returns
//! (carrying the resolved storage descriptor); the rest is a frame loop of route
//! requests. This mirrors the proven ai-provider-quota module.
//!
//! Boot sequence is a gate: resolve the master key → open + migrate the encrypted
//! store → reconcile any dangling refresh intents → ONLY THEN accept reads. A `get`
//! is never served while a crash-left refresh intent is unresolved.

mod admin_surface;
mod limiter;
mod read_surface;

use std::path::PathBuf;
use std::sync::Arc;

use cortexkit_store::{open_sqlite, StorageDescriptor};
use credentials_core::engine::RefreshEngine;
use credentials_core::http::ReqwestTransport;
use credentials_core::refresh_adapters::{
    anthropic::AnthropicAdapter, antigravity::AntigravityAdapter, cursor::CursorAdapter,
    devin::DevinAdapter, digitalocean::DigitalOceanAdapter, github_copilot::GithubCopilotAdapter,
    google::GoogleAdapter, kimi::KimiAdapter, openai::OpenAiAdapter, snowflake::SnowflakeAdapter,
    xai::XaiAdapter, RefreshAdapter,
};
use credentials_core::resolver::{self, KeySource, ResolverConfig};
use credentials_core::store::EncryptedStore;
use serde::Deserialize;
use serde_json::json;
use subc_protocol::{
    manifest::{
        Bindings, IdentityBinding, ManagementOperation, ManagementOperationKind, ModuleManifest,
        ProviderRole, StorageBinding, StorageKind, StorageScope, TrustTier,
    },
    session::{
        HealthStatus, ModuleControlRequest, ModuleControlResponse, MODULE_CONTROL_OP_HEALTH_CHECK,
    },
    ErrorBody, Flags, Frame, FrameType, ModuleHelloAckBody, ModuleHelloBody, Priority,
    PROTOCOL_VERSION, SUBC_LAUNCH_NONCE_ENV, SUBC_MODULE_ID_ENV,
};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter},
    net::TcpStream,
    sync::mpsc,
};

use limiter::{Caps, FetchLimiter};
use read_surface::{GetManyParams, GetParams, ReadSurface, ReportAuthFailureParams, StatusParams};

// The vault's module id — re-exported from the single cross-binary definition site
// so the daemon and CLI cannot drift. The env var (SUBC_MODULE_ID) still overrides
// it at launch; this is the fallback for a dev run without a supervisor.
const DEFAULT_MODULE_ID: &str = credentials_core::contract::MODULE_ID;
const HELLO_CORR: u64 = 1;
// The data-plane (route response) egress buffer. Route responses can burst, so this is
// generous — but a hostile/slow consumer filling it must NOT be able to stall the health
// reply, which is why control frames ride a SEPARATE lane below.
const EGRESS_BUFFER: usize = 64;
// The control-plane (channel-0) egress buffer: HELLO, pongs, route-bind-acks, and the
// health.check reply. Kept on its own small channel, drained with priority, so a full
// route-response queue can never block a control frame's `send().await` — the health
// reply must reach the supervisor within the prober deadline regardless of data-plane
// load (subc-health spec §2). Only rare, tiny control frames use it, so it stays near-
// empty and a control send never waits behind route traffic.
const CONTROL_EGRESS_BUFFER: usize = 16;

// How often the background refresher recomputes the cached health snapshot. Well
// under the prober's cadence so the served snapshot is never more than one tick
// stale, and each tick is a cheap no-decrypt scan that runs OFF the probe path.
const HEALTH_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

// Read-surface op names (the four anonymous route-channel operations).
const OP_GET: &str = "credential.get";
const OP_GET_MANY: &str = "credential.get_many";
const OP_STATUS: &str = "credential.status";
const OP_REPORT_AUTH_FAILURE: &str = "credential.report_auth_failure";
/// Admin ops on the running module (authenticated: direct principal + master-key
/// challenge-response). `admin.challenge` issues a nonce; `admin.op` carries the
/// authenticated op body + tag.
const OP_ADMIN_CHALLENGE: &str = "admin.challenge";
const OP_ADMIN_OP: &str = "admin.op";

#[tokio::main]
async fn main() -> Result<(), ModuleError> {
    let config = ModuleConfig::from_env()?;
    run(config).await
}

struct ModuleConfig {
    connection_file_path: PathBuf,
    module_id: String,
    /// The one-time launch nonce for a reserved module (echoed in HELLO). `None`
    /// for a non-reserved launch (the daemon would then reject a reserved id, but a
    /// dev run without a supervisor simply omits it).
    launch_nonce: Option<String>,
}

impl ModuleConfig {
    fn from_env() -> Result<Self, ModuleError> {
        let connection_file_path = parse_subc_arg(std::env::args_os().skip(1))?;
        let module_id = std::env::var(SUBC_MODULE_ID_ENV)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_MODULE_ID.to_string());
        let launch_nonce = std::env::var(SUBC_LAUNCH_NONCE_ENV)
            .ok()
            .filter(|v| !v.trim().is_empty());
        Ok(Self {
            connection_file_path,
            module_id,
            launch_nonce,
        })
    }
}

/// The two egress lanes to the supervisor. Control-plane frames (HELLO, pong, route-bind
/// ack, and the health.check reply) ride `control`; data-plane route responses ride
/// `route`. Two separate channels, drained control-first (see [`drain_writer`]), so a
/// hostile or slow route consumer that fills the route lane can never delay the health
/// reply past the prober deadline (subc-health spec §2). Cheap to clone (two `Sender`s).
#[derive(Clone)]
struct Egress {
    control: mpsc::Sender<Frame>,
    route: mpsc::Sender<Frame>,
}

/// Module-side route map: channel → binding epoch (wire v2, spec §3.3 layer 2).
///
/// The daemon's relay validation alone is insufficient (forwarding is not atomic
/// with its table lookup), so every endpoint keeps its own `channel → epoch` map:
/// installed when a `route.bind` is accepted, removed on an epoch-valid Goodbye,
/// and checked against every nonzero-channel ingress frame BEFORE dispatch or any
/// lifecycle effect. A mismatched or unknown slot is a silent drop — never an
/// Error frame (only the daemon's relay emits `unknown_channel`), because erroring
/// would inject into the slot's NEW binding's corr space.
#[derive(Default)]
struct RouteEpochs(std::sync::Mutex<std::collections::HashMap<u16, u32>>);

impl RouteEpochs {
    fn install(&self, channel: u16, epoch: u32) {
        let mut map = self.0.lock().unwrap_or_else(|p| p.into_inner());
        map.insert(channel, epoch);
    }

    /// Whether `channel` is a live binding at exactly `epoch`.
    fn matches(&self, channel: u16, epoch: u32) -> bool {
        let map = self.0.lock().unwrap_or_else(|p| p.into_inner());
        map.get(&channel) == Some(&epoch)
    }

    fn remove(&self, channel: u16) {
        let mut map = self.0.lock().unwrap_or_else(|p| p.into_inner());
        map.remove(&channel);
    }
}

async fn run(config: ModuleConfig) -> Result<(), ModuleError> {
    let stream = connect_to_subc(&config.connection_file_path).await?;
    let (mut read_half, write_half) = tokio::io::split(stream);
    let (control_tx, control_rx) = mpsc::channel::<Frame>(CONTROL_EGRESS_BUFFER);
    let (route_tx, route_rx) = mpsc::channel::<Frame>(EGRESS_BUFFER);
    let writer = tokio::spawn(drain_writer(write_half, control_rx, route_rx));
    let egress = Egress {
        control: control_tx,
        route: route_tx,
    };

    // The HELLO_ACK carries the resolved storage descriptor; the surface is built
    // AFTER the handshake (it needs the descriptor) and the boot gate runs before
    // any request is served. module_loop owns `egress` and drops it on return, closing
    // both lanes so the writer task finishes.
    let loop_result = module_loop(&mut read_half, egress, &config).await;

    let writer_result = writer
        .await
        .map_err(|e| ModuleError::Message(e.to_string()));
    match (loop_result, writer_result) {
        (Err(loop_err), _) => Err(loop_err),
        (Ok(()), Ok(Ok(()))) => Ok(()),
        (Ok(()), Ok(Err(writer_err))) => Err(ModuleError::Message(writer_err.to_string())),
        (Ok(()), Err(join_err)) => Err(join_err),
    }
}

async fn connect_to_subc(connection_file_path: &PathBuf) -> Result<TcpStream, ModuleError> {
    let conn = connection_file::read(connection_file_path)
        .map_err(|e| ModuleError::Message(format!("reading connection file: {e}")))?;
    let endpoint = conn
        .endpoints
        .first()
        .ok_or_else(|| ModuleError::Message("connection file has no endpoints".into()))?;
    let addr = format!("{}:{}", endpoint.host, endpoint.port);
    let mut stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| ModuleError::Message(format!("connect {addr}: {e}")))?;
    authenticate_client(&mut stream, &conn, std::time::Duration::from_secs(2))
        .await
        .map_err(|e| ModuleError::Message(format!("authenticate: {e}")))?;
    Ok(stream)
}

async fn module_loop<R>(
    read_half: &mut R,
    egress: Egress,
    config: &ModuleConfig,
) -> Result<(), ModuleError>
where
    R: AsyncRead + Unpin,
{
    // HELLO is a channel-0 control frame — send it on the control lane.
    send_hello(&egress.control, config).await?;
    let ack = expect_hello_ack(read_half).await?;

    // Boot gate: build the vault from the resolved descriptor, then reconcile any
    // dangling refresh intents BEFORE accepting any request.
    let (surface, admin) = build_surface(&ack).await?;
    let surface = Arc::new(surface);
    let admin = Arc::new(admin);
    // Wire v2: the module-side channel → epoch map (spec §3.3 layer 2).
    let routes = Arc::new(RouteEpochs::default());

    // Keep the cached health snapshot current OFF the probe path. The health.check
    // reply must be cheap/in-memory (spec §2), so the live store scan runs here on a
    // cadence, never on the channel-0 dispatch. Aborted on loop exit via the guard.
    let health_refresher = spawn_health_refresher(Arc::clone(&surface));
    let _refresher_guard = AbortOnDrop(health_refresher);

    loop {
        let Some(frame) = read_frame(read_half)
            .await
            .map_err(|e| ModuleError::Message(e.to_string()))?
        else {
            return Ok(()); // clean EOF: subc closed the connection.
        };
        if !handle_frame(frame, &egress, &surface, &admin, &routes).await? {
            return Ok(());
        }
    }
}

/// Spawn the background task that keeps the cached health snapshot current. It
/// ticks on [`HEALTH_REFRESH_INTERVAL`] and recomputes off the probe path, so the
/// channel-0 `health.check` reply is always a cheap in-memory read of the last
/// computed snapshot (spec §2: the reply must not do live store work).
fn spawn_health_refresher(surface: Arc<ReadSurface>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(HEALTH_REFRESH_INTERVAL);
        // Skip missed ticks rather than bursting to catch up if a scan ran long.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            surface.refresh_health();
        }
    })
}

/// Aborts the wrapped task when dropped, so the health refresher stops when the
/// serve loop returns (clean EOF or error) instead of outliving the connection.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Build the read surface from the HELLO_ACK's storage descriptor: resolve the
/// master key, open + migrate the encrypted store, build the refresh engine with
/// the four adapters, and run boot reconciliation (the gate).
async fn build_surface(
    ack: &ModuleHelloAckBody,
) -> Result<(ReadSurface, admin_surface::AdminSurface), ModuleError> {
    let descriptor_value = ack
        .storage
        .as_ref()
        .ok_or_else(|| ModuleError::Message("HELLO_ACK carried no storage descriptor".into()))?;
    let descriptor: StorageDescriptor = serde_json::from_value(descriptor_value.clone())
        .map_err(|e| ModuleError::Message(format!("decoding storage descriptor: {e}")))?;

    let data_dir = sqlite_data_dir(&descriptor)?;
    // Derive the vault identity before the data_dir is moved into the resolver config;
    // it binds the admin-op transcript to THIS vault.
    let vault_id = credentials_core::vault_id_for(&data_dir)
        .ok_or_else(|| ModuleError::Message("cannot derive vault id from data dir".into()))?;
    let kimi_device_id = credentials_core::refresh_adapters::kimi::read_device_id_or_unknown(
        &data_dir.join("kimi-device-id"),
    );
    let resolver_config = resolver_config_from_env(data_dir);

    // Open + migrate the store first, then read the database's plaintext key
    // fingerprint and resolve the master key crash-safely: pick whichever key-store
    // slot matches the database (so a rotation that crashed mid-handover still
    // opens). A locked keychain / no matching key is a clean fail-closed exit.
    let store =
        open_sqlite(&descriptor).map_err(|e| ModuleError::Message(format!("open store: {e}")))?;
    EncryptedStore::migrate(&store).map_err(|e| ModuleError::Message(format!("migrate: {e}")))?;
    let key = match EncryptedStore::read_db_key_id(&store)
        .map_err(|e| ModuleError::Message(format!("read db key id: {e}")))?
    {
        Some(db_key_id) => resolver::resolve_for_db(&resolver_config, db_key_id),
        // Brand-new vault (no audit-key row yet): the current slot is the only key.
        None => resolver::resolve(&resolver_config, None),
    }
    .map_err(|e| ModuleError::Message(format!("master key: {e}")))?;

    // Derive the admin-op authority material from the master key BEFORE it is moved
    // into the store: the MAC key (Gate 2's authority root) and this key's non-secret
    // fingerprint (returned in a challenge so the CLI resolves the same key without
    // opening the DB).
    let admin_mac_key = credentials_core::admin_auth::AdminMacKey::derive(&key);
    let admin_key_id = key.key_id();

    let store = EncryptedStore::open(store, key)
        .map_err(|e| ModuleError::Message(format!("open vault: {e}")))?;
    let store = Arc::new(store);

    let http =
        Arc::new(ReqwestTransport::new().map_err(|e| ModuleError::Message(format!("http: {e}")))?);
    let adapters: Vec<Arc<dyn RefreshAdapter>> = vec![
        Arc::new(AnthropicAdapter::new()),
        Arc::new(CursorAdapter::new()),
        Arc::new(DevinAdapter::new()),
        Arc::new(DigitalOceanAdapter::new()),
        Arc::new(OpenAiAdapter::new()),
        // Google defaults to the public gemini-cli client (id + secret) that opencode
        // mints against; CK_GOOGLE_OAUTH_CLIENT_ID / _SECRET override it. No prod env
        // is required for the common case.
        Arc::new(GoogleAdapter::new()),
        Arc::new(SnowflakeAdapter::new()),
        Arc::new(XaiAdapter::new()),
        Arc::new(GithubCopilotAdapter::new()),
        Arc::new(KimiAdapter::new(kimi_device_id)),
        // Antigravity (Google Code-Assist OAuth) — its own public client, distinct
        // from the gemini-cli client the google adapter uses.
        Arc::new(AntigravityAdapter::new()),
    ];
    let engine = Arc::new(RefreshEngine::new(store, adapters, http));

    // THE BOOT GATE: resolve every dangling intent before serving any read.
    //
    // Each outcome names WHY a credential was forced to needs_reauth, and that reason
    // is otherwise unrecoverable: the store's audit entry for these is a generic
    // `invalidate` from actor `vault`, identical whether the adapter had no validity
    // check, ran one and it failed, or the record could not be read. Only the
    // corruption-guard arm writes a distinguishing alarm. So an operator asking why a
    // credential needed re-login after a crash gets no answer unless the reason is
    // recorded here.
    //
    // Written to `auth_events` rather than the chain: the chain already holds the
    // authoritative invalidate, and this is the explanation, which is exactly the
    // split that table exists for. Best-effort -- a diagnostics write must never fail
    // the boot gate, whose job is to resolve intents before serving reads.
    let outcomes = engine
        .reconcile()
        .await
        .map_err(|e| ModuleError::Message(format!("boot reconciliation: {e}")))?;
    record_reconciliation_reasons(&engine, &outcomes);

    // The admin surface shares the engine (same store + per-credential single-flight
    // locks), so a route-driven admin write and a refresh for one credential are
    // serialized by the same lock.
    let admin = admin_surface::AdminSurface::new(
        Arc::clone(&engine),
        admin_mac_key,
        vault_id,
        admin_key_id,
    );
    Ok((
        ReadSurface::new(engine, FetchLimiter::new(Caps::default())),
        admin,
    ))
}

/// Record WHY boot reconciliation forced any credential to `needs_reauth`.
///
/// A free function rather than an inline loop so the boot gate and its test call the
/// SAME code. Written inline first, which made the test pass with the boot gate's copy
/// deleted -- it was exercising its own duplicate, not the daemon's path.
///
/// Best-effort: a diagnostics write must never fail the boot gate, whose job is to
/// resolve dangling intents before any read is served.
fn record_reconciliation_reasons(
    engine: &RefreshEngine,
    outcomes: &[credentials_core::engine::Reconciliation],
) {
    for outcome in outcomes {
        if let credentials_core::engine::Reconciliation::NeedsReauth {
            credential_id,
            reason,
        } = outcome
        {
            let _ = engine.store().record_auth_event(
                credential_id,
                credentials_core::store::AuthObservation {
                    kind: "reconcile_needs_reauth",
                    provider_status: None,
                    detail: Some(reason.as_str()),
                },
                None,
            );
        }
    }
}

/// Drain both egress lanes to the wire, CONTROL-FIRST. On every wakeup, all currently-
/// queued control frames are flushed before any route frame, and `select!` biases toward
/// the control lane — so a health.check reply can never sit behind a backlog of route
/// responses (the liveness guarantee: control egress is not starvable by data traffic).
/// Returns when BOTH lanes are closed (the serve loop dropped its `Egress`).
async fn drain_writer<W>(
    write_half: W,
    mut control_rx: mpsc::Receiver<Frame>,
    mut route_rx: mpsc::Receiver<Frame>,
) -> Result<(), ModuleError>
where
    W: AsyncWrite + Unpin,
{
    let mut writer = BufWriter::new(write_half);
    let mut control_open = true;
    let mut route_open = true;

    // Write every frame currently queued on a lane without awaiting new arrivals.
    macro_rules! drain_ready {
        ($rx:expr) => {
            while let Ok(frame) = $rx.try_recv() {
                write_frame(&mut writer, &frame)
                    .await
                    .map_err(|e| ModuleError::Message(e.to_string()))?;
            }
        };
    }

    while control_open || route_open {
        // Bias to control: `select!`'s first-listed branch is polled first, and after any
        // wakeup we flush ALL pending control frames before touching the route lane.
        tokio::select! {
            biased;
            maybe = control_rx.recv(), if control_open => match maybe {
                Some(frame) => {
                    write_frame(&mut writer, &frame)
                        .await
                        .map_err(|e| ModuleError::Message(e.to_string()))?;
                    drain_ready!(control_rx);
                }
                None => control_open = false,
            },
            maybe = route_rx.recv(), if route_open => match maybe {
                Some(frame) => {
                    // Control frames that arrived meanwhile jump ahead of this route frame.
                    drain_ready!(control_rx);
                    write_frame(&mut writer, &frame)
                        .await
                        .map_err(|e| ModuleError::Message(e.to_string()))?;
                    // Deliberately NO route-lane drain here: emit ONE route frame per
                    // iteration, then fall back to the biased select so the control
                    // lane is re-polled between every route frame. Draining all ready
                    // route frames in a loop would let a producer that keeps the route
                    // queue non-empty starve control indefinitely — the exact
                    // liveness hole the two-lane split exists to close.
                }
                None => route_open = false,
            },
        }
        writer
            .flush()
            .await
            .map_err(|e| ModuleError::Message(e.to_string()))?;
    }
    writer
        .flush()
        .await
        .map_err(|e| ModuleError::Message(e.to_string()))?;
    Ok(())
}

async fn send_hello(
    writer: &mpsc::Sender<Frame>,
    config: &ModuleConfig,
) -> Result<(), ModuleError> {
    let body = serde_json::to_vec(&ModuleHelloBody {
        manifest: manifest(&config.module_id),
        protocol_ver: PROTOCOL_VERSION,
        // Advertise health.check so the daemon actively probes us (capability-
        // gated: unadvertised = health "unknown", never probed). We answer L2
        // through the same channel-0 dispatch and report L3 domain health from a
        // cheap no-decrypt metadata scan.
        control_ops: Some(vec![MODULE_CONTROL_OP_HEALTH_CHECK.to_string()]),
        // Echo the supervisor's launch nonce. This is the module half of the
        // reserved-id ceremony: it proves this process was spawned by the
        // supervisor rather than merely able to complete the handshake.
        //
        // Whether the supervisor ENFORCES that is a property of its config, not of
        // this code -- an id it does not treat as reserved authorizes any HELLO,
        // and the echo is then a key for a lock nobody installed. This module
        // cannot observe which case it is in and must send the nonce either way,
        // so nothing here should be read as evidence that the check happens.
        launch_nonce: config.launch_nonce.clone(),
    })
    .map_err(ModuleError::Json)?;
    // Channel-0 control frames carry the reserved epoch 0 (wire v2 §3.1).
    let frame = Frame::build(FrameType::Hello, control_flags(), 0, 0, HELLO_CORR, body)
        .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, frame).await
}

async fn expect_hello_ack<R>(reader: &mut R) -> Result<ModuleHelloAckBody, ModuleError>
where
    R: AsyncRead + Unpin,
{
    let frame = read_frame(reader)
        .await
        .map_err(|e| ModuleError::Message(e.to_string()))?
        .ok_or_else(|| ModuleError::Message("connection closed before HELLO_ACK".into()))?;
    match frame.header.ty {
        FrameType::HelloAck => serde_json::from_slice(&frame.body).map_err(ModuleError::Json),
        FrameType::Error => {
            let body =
                serde_json::from_slice::<ErrorBody>(&frame.body).map_err(ModuleError::Json)?;
            Err(ModuleError::Message(format!(
                "subc rejected HELLO: {} — {}",
                body.code, body.message
            )))
        }
        ty => Err(ModuleError::Message(format!(
            "unexpected frame {ty:?} awaiting HELLO_ACK"
        ))),
    }
}

/// Returns `Ok(false)` to stop the loop (graceful goodbye / EOF). Channel-0 control
/// frames (ping/pong, route-bind, health.check) egress on the priority control lane;
/// data-plane route responses egress on the route lane, so control liveness is never
/// starved by route traffic.
async fn handle_frame(
    frame: Frame,
    egress: &Egress,
    surface: &Arc<ReadSurface>,
    admin: &Arc<admin_surface::AdminSurface>,
    routes: &Arc<RouteEpochs>,
) -> Result<bool, ModuleError> {
    // Wire v2 layer-2 validation (spec §3.3): every nonzero-channel ingress frame
    // is checked against the local route map BEFORE dispatch or any lifecycle
    // effect — Request, Cancel, and Goodbye alike. Epoch mismatch or unknown slot
    // is a SILENT drop (never an Error frame: only the daemon's relay emits
    // unknown_channel; a module-emitted Error would inject into the corr space of
    // the slot's next tenant, the exact confusion the epoch exists to prevent).
    if frame.header.channel != 0 && !routes.matches(frame.header.channel, frame.header.epoch) {
        return Ok(true);
    }
    match frame.header.ty {
        FrameType::Ping if frame.header.channel == 0 => {
            let pong = Frame::build_with_version(
                frame.header.ver,
                FrameType::Pong,
                frame.header.flags,
                0,
                0,
                frame.header.corr,
                Vec::new(),
            )
            .map_err(|e| ModuleError::Message(e.to_string()))?;
            send(&egress.control, pong).await?;
            Ok(true)
        }
        FrameType::Goodbye if frame.header.channel == 0 => Ok(false),
        FrameType::Goodbye => {
            // An epoch-valid route goodbye: forget the binding, that connection's
            // limiter state, AND its admin bind state (principal + nonce).
            routes.remove(frame.header.channel);
            surface.drop_connection(frame.header.channel as u64).await;
            admin.drop_bind(frame.header.channel);
            Ok(true)
        }
        FrameType::Request if frame.header.channel == 0 => {
            handle_control_request(frame, &egress.control, surface, admin, routes).await?;
            Ok(true)
        }
        FrameType::Request => {
            // Data-plane request on a route channel: a read op or an admin op. Spawn
            // so a slow refresh/commit never head-of-line-blocks another route. Its
            // response egresses on the route lane, never the control lane.
            let route = egress.route.clone();
            let surface = Arc::clone(surface);
            let admin = Arc::clone(admin);
            tokio::spawn(async move {
                let _ = handle_read_request(frame, &route, &surface, &admin).await;
            });
            Ok(true)
        }
        _ => Ok(true),
    }
}

async fn handle_control_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    surface: &Arc<ReadSurface>,
    admin: &Arc<admin_surface::AdminSurface>,
    routes: &Arc<RouteEpochs>,
) -> Result<(), ModuleError> {
    let request =
        serde_json::from_slice::<ModuleControlRequest>(&frame.body).map_err(ModuleError::Json)?;
    let response_body = match request {
        ModuleControlRequest::RouteBind {
            route_channel,
            epoch,
            principal,
            ..
        } => {
            // Wire v2: install the (channel → epoch) binding in the local route map.
            // Installed here — when the accepted ack is being queued — so no route
            // traffic can pass layer-2 validation before the bind is acknowledged
            // (§3.2: module traffic legally begins only after the RouteBind ack).
            routes.install(route_channel, epoch);
            // Record the bind's daemon-stamped principal (Gate 1 provenance) against
            // the route channel, with a fresh generation. An absent principal stamp
            // records as `Unverified` — never `direct` — so admin ops fail closed on
            // an older daemon. Reads remain anonymous/handle-scoped regardless.
            let principal = principal.unwrap_or(subc_protocol::Principal::Unverified);
            admin.record_bind(route_channel, principal);
            ModuleControlResponse::RouteBindAck {}
        }
        ModuleControlRequest::HealthCheck {} => {
            // L3 domain health: a cheap no-decrypt metadata scan. `Failing` only
            // when the store is unreadable (real serving inability); a credential
            // needing re-auth is `degraded` detail, never `failing`, so a healthy
            // vault is never restart-flapped.
            health_report(&surface.health_snapshot())
        }
    };
    let body = serde_json::to_vec(&response_body).map_err(ModuleError::Json)?;
    let response = Frame::build_with_version(
        frame.header.ver,
        FrameType::Response,
        control_flags(),
        0,
        0,
        frame.header.corr,
        body,
    )
    .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, response).await
}

/// Map the wire-agnostic core [`VaultHealth`] onto the subc health-report wire
/// shape. Status is the only field subc acts on; `detail`/`metrics` are opaque.
fn health_report(health: &credentials_core::health::VaultHealth) -> ModuleControlResponse {
    use credentials_core::health::VaultHealthStatus;
    let status = match health.status {
        VaultHealthStatus::Ok => HealthStatus::Ok,
        VaultHealthStatus::Degraded => HealthStatus::Degraded,
        VaultHealthStatus::Failing => HealthStatus::Failing,
    };
    let detail = if health.refresher_stalled {
        Some(
            "health refresher stalled: the background snapshot task stopped updating \
             (wedged or panicked); serving a possibly-stale snapshot, restart the daemon"
                .to_string(),
        )
    } else if health.fenced_out {
        Some(
            "fenced out by a newer writer: this daemon lost the single-writer lease \
             (find the other writer)"
                .to_string(),
        )
    } else if !health.store_readable {
        Some("store unreadable: cannot serve any credential (check disk / lease)".to_string())
    } else if health.needs_reauth > 0 || health.corrupt > 0 {
        // Name the affected credentials (ids are non-secret) so the alert is an
        // action, not a lookup. The ids are capped in the snapshot; the counts
        // above remain the true totals.
        let mut affected: Vec<&str> = health.needs_reauth_ids.iter().map(String::as_str).collect();
        affected.extend(health.corrupt_ids.iter().map(String::as_str));
        Some(format!(
            "{} of {} credentials need operator action ({} needs_reauth, {} corrupt); \
             {} serving [{}]",
            health.needs_reauth + health.corrupt,
            health.credentials_total,
            health.needs_reauth,
            health.corrupt,
            health.active,
            affected.join(", "),
        ))
    } else {
        None
    };
    // The counts are OMITTED when the store could not be read, rather than reported as
    // zero.
    //
    // Zero is what an empty vault reports, so a consumer plotting `active` cannot tell
    // "no credentials" from "could not count credentials" and draws a clean line either
    // way. The provenance is available -- `storeReadable` is false in the same object,
    // and `detail` names the reason -- but that requires the consumer to correlate two
    // fields, and nothing makes it. Omission does: a field that is absent cannot be
    // plotted as a value, so the bad reading becomes impossible instead of merely
    // avoidable.
    //
    // The flags stay present in both cases, because they are measurements about the
    // daemon rather than about the store, and they remain true when the store is
    // unreadable.
    let mut metrics = json!({
        "storeReadable": health.store_readable,
        "fencedOut": health.fenced_out,
        "refresherStalled": health.refresher_stalled,
    });
    if health.store_readable {
        let counted = json!({
            "credentialsTotal": health.credentials_total,
            "active": health.active,
            "needsReauth": health.needs_reauth,
            "corrupt": health.corrupt,
            "needsReauthIds": health.needs_reauth_ids,
            "corruptIds": health.corrupt_ids,
            "openIntents": health.open_intents,
        });
        if let (Some(target), Some(source)) = (metrics.as_object_mut(), counted.as_object()) {
            for (k, v) in source {
                target.insert(k.clone(), v.clone());
            }
        }
    }
    ModuleControlResponse::HealthCheck {
        status,
        detail,
        metrics: Some(metrics),
    }
}

/// A read-surface request body: `{ "method": "...", "params": { ... } }`.
#[derive(Debug, Deserialize)]
struct ReadRequest {
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

/// The `admin.op` request params: the EXACT authenticated op-body bytes (as a JSON
/// string, so the byte string the caller MAC'd survives the outer envelope verbatim)
/// plus the caller's transcript MAC.
#[derive(Debug, Deserialize)]
struct AdminOpParams {
    /// The op body EXACTLY as MAC'd, carried as a string so no JSON re-encoding on
    /// the outer envelope can perturb the authenticated bytes.
    op_body: String,
    tag_hex: String,
}

async fn handle_read_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    surface: &Arc<ReadSurface>,
    admin: &Arc<admin_surface::AdminSurface>,
) -> Result<(), ModuleError> {
    let channel = frame.header.channel;
    // Echo the validated ingress epoch on every frame of this route (wire v2:
    // a response must carry the epoch of the binding it answers for).
    let epoch = frame.header.epoch;
    let corr = frame.header.corr;
    let ver = frame.header.ver;
    let connection_id = channel as u64;

    let request: ReadRequest = match serde_json::from_slice(&frame.body) {
        Ok(r) => r,
        Err(e) => {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "invalid_request",
                &format!("request body not decodable: {e}"),
            )
            .await;
        }
    };

    let result = match request.method.as_str() {
        OP_GET => match serde_json::from_value::<GetParams>(request.params) {
            Ok(p) => json!({ "result": surface.get(connection_id, &p).await }),
            Err(e) => {
                return invalid_params(writer, ver, channel, epoch, corr, &e.to_string()).await
            }
        },
        OP_GET_MANY => match serde_json::from_value::<GetManyParams>(request.params) {
            Ok(p) => json!({ "results": surface.get_many(connection_id, &p).await }),
            Err(e) => {
                return invalid_params(writer, ver, channel, epoch, corr, &e.to_string()).await
            }
        },
        OP_STATUS => match serde_json::from_value::<StatusParams>(request.params) {
            Ok(p) => json!({ "result": surface.status(connection_id, &p).await }),
            Err(e) => {
                return invalid_params(writer, ver, channel, epoch, corr, &e.to_string()).await
            }
        },
        OP_REPORT_AUTH_FAILURE => {
            match serde_json::from_value::<ReportAuthFailureParams>(request.params) {
                Ok(p) => match surface.report_auth_failure(connection_id, &p).await {
                    Ok(()) => json!({ "result": { "accepted": true } }),
                    // Carry the produced error CLASS alongside the code (error-class
                    // contract), the same { code, class } shape get/get_many use, so a
                    // consumer branches on the class here too rather than on the code.
                    Err(code) => json!({
                        "result": {
                            "accepted": false,
                            "error": read_surface::ErrorBody { code, class: code.class() }
                        }
                    }),
                },
                Err(e) => {
                    return invalid_params(writer, ver, channel, epoch, corr, &e.to_string()).await
                }
            }
        }
        OP_ADMIN_CHALLENGE => match admin.challenge(channel) {
            admin_surface::AdminOutcome::Challenge {
                nonce_hex,
                vault_id_hex,
                key_id_hex,
            } => json!({ "result": {
                "nonce_hex": nonce_hex,
                "vault_id_hex": vault_id_hex,
                "key_id_hex": key_id_hex,
            }}),
            admin_surface::AdminOutcome::Refused(reason) => {
                return send_route_error(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "admin_refused",
                    &reason,
                )
                .await;
            }
            // challenge() only ever returns Challenge or Refused.
            admin_surface::AdminOutcome::Ok(_) => unreachable!("challenge returns Challenge"),
        },
        OP_ADMIN_OP => match serde_json::from_value::<AdminOpParams>(request.params) {
            Ok(p) => match admin
                .execute(channel, p.op_body.as_bytes(), &p.tag_hex)
                .await
            {
                admin_surface::AdminOutcome::Ok(v) => json!({ "result": v }),
                admin_surface::AdminOutcome::Refused(reason) => {
                    return send_route_error(
                        writer,
                        ver,
                        channel,
                        epoch,
                        corr,
                        "admin_refused",
                        &reason,
                    )
                    .await;
                }
                admin_surface::AdminOutcome::Challenge { .. } => {
                    unreachable!("execute never returns Challenge")
                }
            },
            Err(e) => {
                return invalid_params(writer, ver, channel, epoch, corr, &e.to_string()).await
            }
        },
        other => {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "unknown_method",
                &format!("unknown method '{other}'"),
            )
            .await;
        }
    };

    let body = serde_json::to_vec(&result).map_err(ModuleError::Json)?;
    let response = Frame::build_with_version(
        ver,
        FrameType::Response,
        Flags::new(false, Priority::Interactive, false),
        channel,
        epoch,
        corr,
        body,
    )
    .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, response).await
}

async fn invalid_params(
    writer: &mpsc::Sender<Frame>,
    ver: u8,
    channel: u16,
    epoch: u32,
    corr: u64,
    detail: &str,
) -> Result<(), ModuleError> {
    send_route_error(
        writer,
        ver,
        channel,
        epoch,
        corr,
        "invalid_params",
        &format!("params not decodable: {detail}"),
    )
    .await
}

async fn send_route_error(
    writer: &mpsc::Sender<Frame>,
    ver: u8,
    channel: u16,
    epoch: u32,
    corr: u64,
    code: &str,
    message: &str,
) -> Result<(), ModuleError> {
    let body = serde_json::to_vec(&ErrorBody {
        code: code.to_string(),
        message: message.to_string(),
    })
    .map_err(ModuleError::Json)?;
    let frame = Frame::build_with_version(
        ver,
        FrameType::Error,
        Flags::new(false, Priority::Interactive, false),
        channel,
        epoch,
        corr,
        body,
    )
    .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, frame).await
}

async fn send(writer: &mpsc::Sender<Frame>, frame: Frame) -> Result<(), ModuleError> {
    writer
        .send(frame)
        .await
        .map_err(|_| ModuleError::Message("egress channel closed".into()))
}

fn control_flags() -> Flags {
    Flags::new(false, Priority::Passive, false)
}

/// The data directory the vault lives in (the parent of the sqlite store path), so
/// the master-key resolver can enforce the operator key path is outside it.
fn sqlite_data_dir(descriptor: &StorageDescriptor) -> Result<PathBuf, ModuleError> {
    use cortexkit_store::StorageBackend;
    match &descriptor.backend {
        StorageBackend::Sqlite { path } => Ok(PathBuf::from(path)
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))),
        other => Err(ModuleError::Message(format!(
            "credential vault requires a sqlite backend, got {}",
            other.label()
        ))),
    }
}

/// Resolve the master-key source from the environment: an operator key path
/// (`CK_MASTER_KEY_PATH`, headless) takes precedence; otherwise the macOS keychain
/// (the desktop default) with fixed service/account strings.
fn resolver_config_from_env(data_dir: PathBuf) -> ResolverConfig {
    let source = if let Some(path) = std::env::var_os("CK_MASTER_KEY_PATH") {
        KeySource::OperatorPath {
            path: PathBuf::from(path),
        }
    } else {
        // Fieldless: the keychain item is scoped per-vault by the data dir inside the
        // backend (contract::keychain_service_for), identical to the CLI's derivation.
        KeySource::Keychain
    };
    ResolverConfig { data_dir, source }
}

/// The module's capability manifest: a ManagementSurface exposing the four read
/// operations. Storage is `owns_schema: true` (the vault owns its schema). The
/// `reserved: true` binding lives in the daemon's subc.jsonc config, not here; the
/// module proves its reserved identity by echoing the launch nonce in HELLO.
fn manifest(module_id: &str) -> ModuleManifest {
    ModuleManifest {
        module_id: module_id.to_string(),
        module_version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_ver: PROTOCOL_VERSION,
        trust_tier: TrustTier::FirstParty,
        provides: vec![ProviderRole::ManagementSurface {
            operations: vec![
                ManagementOperation {
                    name: OP_GET.to_string(),
                    kind: ManagementOperationKind::Query,
                },
                ManagementOperation {
                    name: OP_GET_MANY.to_string(),
                    kind: ManagementOperationKind::Query,
                },
                ManagementOperation {
                    name: OP_STATUS.to_string(),
                    kind: ManagementOperationKind::Query,
                },
                ManagementOperation {
                    name: OP_REPORT_AUTH_FAILURE.to_string(),
                    kind: ManagementOperationKind::Mutate,
                },
            ],
            config_schema: json!({ "type": "object" }),
            observability: Vec::new(),
            identity_scope: Vec::new(),
        }],
        consumes: Vec::new(),
        scheduled_tasks: Vec::new(),
        bindings: Bindings {
            storage: StorageBinding {
                kind: StorageKind::Sqlite,
                scope: StorageScope::Project,
                owns_schema: true,
            },
            vault_grants: Vec::new(),
            identity: IdentityBinding {
                requires: Vec::new(),
                optional: Vec::new(),
            },
        },
    }
}

fn parse_subc_arg(
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<PathBuf, ModuleError> {
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--subc" {
            let value = args
                .next()
                .ok_or_else(|| ModuleError::Message("--subc requires a value".into()))?;
            return Ok(PathBuf::from(value));
        }
        if let Some(raw) = arg.to_str().and_then(|a| a.strip_prefix("--subc=")) {
            if raw.is_empty() {
                return Err(ModuleError::Message("--subc= requires a value".into()));
            }
            return Ok(PathBuf::from(raw));
        }
    }
    Err(ModuleError::Message(
        "--subc <connection-file> is required".into(),
    ))
}

#[derive(Debug)]
enum ModuleError {
    Message(String),
    Json(serde_json::Error),
}

impl std::fmt::Display for ModuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(m) => write!(f, "{m}"),
            Self::Json(e) => write!(f, "json: {e}"),
        }
    }
}

impl std::error::Error for ModuleError {}

#[cfg(test)]
mod tests {
    use super::*;
    use cortexkit_store::{Isolation, StorageBackend};
    use credentials_core::audit::{AuditCtx, AuditOp};
    use credentials_core::key::{MasterKey, MASTER_KEY_LEN};
    use credentials_core::record::{CredentialKind, VaultRecord};
    use read_surface::ReadSurface;

    fn tmp_surface(seed: u8) -> Arc<ReadSurface> {
        tmp_surface_with_store(seed).0
    }

    /// Boot reconciliation's REASON survives as a durable row.
    ///
    /// The engine already returns why each dangling intent forced `needs_reauth`, and
    /// its own tests assert that. What was missing is that the module DISCARDED the
    /// value: the store's audit entry for these is a generic `invalidate` from actor
    /// `vault`, identical across every cause, so after a crash an operator could see
    /// that a credential needed re-login and never why.
    ///
    /// This drives the boot-gate sequence and asserts the reason lands. Written
    /// against the same call the daemon makes, because the defect was never in the
    /// engine -- it was at the call site.
    #[tokio::test]
    async fn boot_reconciliation_records_why_a_credential_needs_reauth() {
        let (_, store, _) = tmp_surface_with_store(71);
        let record = VaultRecord::new_oauth(
            "test",
            "stub",
            credentials_core::oauth::OAuthCredential {
                access_token: "at".into(),
                refresh_token: "rt".into(),
                expires_at_ms: Some(0),
                token_url: "https://example.invalid/token".into(),
                client_id: None,
                scopes: Vec::new(),
            },
            b"payload".to_vec(),
        );
        store.create("apikey:crashed", &record).expect("create");
        let hash = credentials_core::store::refresh_token_hash("rt");
        store
            .open_intent("apikey:crashed", 1, &hash)
            .expect("open intent");

        let http = Arc::new(ReqwestTransport::new().expect("http"));
        let engine = Arc::new(RefreshEngine::new(Arc::clone(&store), Vec::new(), http));

        // The daemon's own boot-gate sequence: reconcile, then record. Calls the same
        // function `build_surface` calls -- an inline copy here would pass with the
        // daemon's recording deleted, which is exactly what it did before this was
        // extracted.
        let outcomes = engine.reconcile().await.expect("reconcile");
        record_reconciliation_reasons(&engine, &outcomes);

        let events = store.recent_auth_events(10).expect("read events");
        assert_eq!(events.len(), 1, "the reconciliation must leave a row");
        assert_eq!(events[0].credential_id, "apikey:crashed");
        assert_eq!(events[0].kind, "reconcile_needs_reauth");
        assert_eq!(
            events[0].detail.as_deref(),
            Some("no_validity_check"),
            "the row must carry WHY, which is the whole point -- the audit chain's \
             entry for this is a generic invalidate that cannot distinguish causes"
        );
    }

    /// A test AdminSurface over the same engine/store shape as tmp_surface, with a
    /// known master key (seed) so tests can derive the same MAC key caller-side.
    fn tmp_admin(seed: u8) -> (Arc<admin_surface::AdminSurface>, Arc<EncryptedStore>) {
        let (_, store, db_path) = tmp_surface_with_store(seed);
        let http = Arc::new(ReqwestTransport::new().expect("http"));
        let engine = Arc::new(RefreshEngine::new(Arc::clone(&store), Vec::new(), http));
        let key = MasterKey::from_bytes([seed; MASTER_KEY_LEN]);
        let mac_key = credentials_core::admin_auth::AdminMacKey::derive(&key);
        let vault_id =
            credentials_core::vault_id_for(db_path.parent().expect("db dir")).expect("vault id");
        let admin = Arc::new(admin_surface::AdminSurface::new(
            engine,
            mac_key,
            vault_id,
            key.key_id(),
        ));
        (admin, store)
    }

    fn tmp_surface_with_store(
        seed: u8,
    ) -> (Arc<ReadSurface>, Arc<EncryptedStore>, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "ck-cred-health-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("mkdir");
        let db_path = root.join("store.db");
        let descriptor = StorageDescriptor {
            module_id: "cortexkit-credentials".into(),
            storage_namespace: "default".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: db_path.to_string_lossy().into_owned(),
            },
        };
        let store = open_sqlite(&descriptor).expect("open");
        EncryptedStore::migrate(&store).expect("migrate");
        let store = EncryptedStore::open(store, MasterKey::from_bytes([seed; MASTER_KEY_LEN]))
            .expect("open vault");
        // Seed one active + one needs_reauth so health is Degraded (never Failing).
        store
            .create(
                "apikey:active",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"k".to_vec(), None),
            )
            .expect("create active");
        store
            .create(
                "apikey:dead",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"k".to_vec(), None),
            )
            .expect("create dead");
        store.invalidate("apikey:dead").expect("invalidate");

        let store = Arc::new(store);
        let http = Arc::new(ReqwestTransport::new().expect("http"));
        let engine = Arc::new(RefreshEngine::new(Arc::clone(&store), Vec::new(), http));
        let surface = Arc::new(ReadSurface::new(engine, FetchLimiter::new(Caps::default())));
        (surface, store, db_path)
    }

    /// Bump the fence epoch above the holder on a vault's db, via a fresh raw sqlite
    /// connection (the module crate cannot reach core's test-only with_raw_conn). This
    /// simulates a newer writer claiming the single-writer lease, so the store's next
    /// fenced write is rejected and latches fenced_out — the lease-handover race.
    fn bump_fence_epoch(db_path: &std::path::Path) {
        let conn = rusqlite::Connection::open(db_path).expect("open raw db");
        conn.execute("UPDATE cortexkit_fence SET epoch = 999 WHERE id = 0", [])
            .expect("bump fence epoch");
    }

    /// A route producer that keeps the route lane non-empty must NOT starve the
    /// control lane. This drives the REAL `drain_writer` with a saturating route
    /// producer, then sends one control frame and asserts it reaches the wire
    /// within a small bounded number of frames. With an unbounded route drain
    /// (a `drain_ready!(route_rx)` loop after each route write), the producer
    /// refills the queue during every write await and the control frame never
    /// gets scheduled — this test fails against that implementation (verified),
    /// so it discriminates the exact starvation hole, not just the bias.
    #[tokio::test]
    async fn control_frame_is_not_starved_by_a_saturating_route_producer() {
        let (control_tx, control_rx) = mpsc::channel::<Frame>(CONTROL_EGRESS_BUFFER);
        let (route_tx, route_rx) = mpsc::channel::<Frame>(EGRESS_BUFFER);
        // A SMALL duplex buffer so only a handful of frames fit in flight: frames
        // already written before the control send are not starvation evidence, so
        // the wire window must be tight for the frames-until-control count to
        // measure the writer's scheduling rather than buffered backlog.
        let (client, mut server) = tokio::io::duplex(256);

        let writer_task = tokio::spawn(async move {
            let _ = drain_writer(client, control_rx, route_rx).await;
        });

        fn frame(channel: u16, corr: u64) -> Frame {
            Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Response,
                Flags::new(false, Priority::Interactive, false),
                channel,
                0,
                corr,
                vec![0u8; 32],
            )
            .unwrap()
        }

        // Saturating producer: keeps the route lane non-empty for the whole test.
        let producer = tokio::spawn(async move {
            loop {
                if route_tx.send(frame(5, 1)).await.is_err() {
                    break;
                }
            }
        });

        // Let the producer fill the queue and the writer start draining.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        control_tx.send(frame(0, 99)).await.expect("control send");

        // The control frame must appear within a small bounded number of frames.
        let mut frames_until_control = 0usize;
        loop {
            let got = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                subc_core::read_frame(&mut server),
            )
            .await
            .expect("wire stalled: control frame never arrived (starved)")
            .expect("read frame")
            .expect("stream closed before the control frame arrived");
            if got.header.channel == 0 && got.header.corr == 99 {
                break;
            }
            frames_until_control += 1;
            assert!(
                frames_until_control < 64,
                "control frame starved behind {frames_until_control}+ route frames"
            );
        }

        producer.abort();
        drop(control_tx);
        writer_task.abort();
    }

    /// Drive the REAL channel-0 control handler with a `health.check` Request and
    /// assert it answers with a well-formed `HealthCheck` Response carrying the
    /// domain metrics. Exercises the actual arm + surface + mapper, not a mock.
    #[tokio::test]
    async fn health_check_control_request_returns_domain_report() {
        let surface = tmp_surface(7);
        let (tx, mut rx) = mpsc::channel::<Frame>(4);

        let request = ModuleControlRequest::HealthCheck {};
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            control_flags(),
            0,
            0,
            42,
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();

        let (admin, _admin_store) = tmp_admin(7);
        let routes = Arc::new(RouteEpochs::default());
        handle_control_request(frame, &tx, &surface, &admin, &routes)
            .await
            .unwrap();

        let response = rx.try_recv().expect("a response frame was sent");
        assert_eq!(response.header.ty, FrameType::Response);
        assert_eq!(response.header.channel, 0);
        assert_eq!(response.header.corr, 42);

        let body: ModuleControlResponse = serde_json::from_slice(&response.body).unwrap();
        let ModuleControlResponse::HealthCheck {
            status, metrics, ..
        } = body
        else {
            panic!("expected a HealthCheck response");
        };
        // One active + one needs_reauth ⇒ Degraded, never Failing (the store is
        // readable, so the vault is serving; a dead credential is detail only).
        assert_eq!(status, HealthStatus::Degraded);
        let metrics = metrics.expect("health report carries metrics");
        let obj = metrics.as_object().expect("metrics is a JSON object");
        assert_eq!(obj["credentialsTotal"], 2);
        assert_eq!(obj["active"], 1);
        assert_eq!(obj["needsReauth"], 1);
        assert_eq!(obj["storeReadable"], true);
        // The report NAMES the credential needing action (the seeded dead id).
        assert_eq!(obj["needsReauthIds"], serde_json::json!(["apikey:dead"]));
    }

    /// The load-bearing property of the cached-snapshot fix: the probe reply is
    /// served from the in-memory snapshot and does NOT do a live store read. Prove
    /// it non-vacuously — mutate the store AFTER construction and assert the probe
    /// still returns the pre-mutation snapshot until `refresh_health` runs (the
    /// off-path recompute). A live-reading probe would reflect the mutation
    /// immediately; the cached one must not.
    #[tokio::test]
    async fn health_probe_serves_cached_snapshot_not_a_live_read() {
        let (surface, store, _db) = tmp_surface_with_store(11);

        // Initial snapshot (computed at construction): 1 active + 1 needs_reauth.
        let before = surface.health_snapshot();
        assert_eq!(before.credentials_total, 2);
        assert_eq!(before.needs_reauth, 1);

        // Mutate the store directly, off any refresh: add a third credential.
        store
            .create(
                "apikey:new",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"k".to_vec(), None),
            )
            .expect("create new");

        // The probe MUST still see the cached (stale) snapshot — proving it did not
        // read the store. A live read would already report 3.
        let still_cached = surface.health_snapshot();
        assert_eq!(
            still_cached.credentials_total, 2,
            "probe must serve the cached snapshot, not a live store scan"
        );

        // Only the off-path refresh picks up the mutation.
        surface.refresh_health();
        let after = surface.health_snapshot();
        assert_eq!(
            after.credentials_total, 3,
            "refresh recomputes from the store"
        );
    }

    /// A wedged/dead refresher must fail the probe CLOSED: if no refresh has completed
    /// within the stale limit, the probe reports Failing (refresher_stalled) instead of
    /// serving the last snapshot as healthy — turning a silent refresher death into an
    /// alert. Non-vacuous: the store is healthy (would be Ok/Degraded), so only the
    /// staleness gate can drive it to Failing here.
    #[tokio::test]
    async fn a_stalled_refresher_fails_the_probe_closed() {
        let surface = tmp_surface(13);
        // Fresh snapshot: healthy store, refresher just ran → not Failing.
        let fresh = surface.health_snapshot();
        assert_ne!(
            fresh.status,
            credentials_core::health::VaultHealthStatus::Failing
        );
        assert!(!fresh.refresher_stalled);

        // Backdate the last-refresh clock past the stale limit (refresher wedged/died).
        surface.force_stale_refresher_for_test();

        let stale = surface.health_snapshot();
        assert!(
            stale.refresher_stalled,
            "the probe must flag a stalled refresher live at read time"
        );
        assert_eq!(
            stale.status,
            credentials_core::health::VaultHealthStatus::Failing,
            "a stalled refresher fails the probe closed"
        );
        // And the control handler surfaces it as Failing on the wire.
        let report = health_report(&stale);
        let ModuleControlResponse::HealthCheck { status, .. } = report else {
            panic!("expected HealthCheck");
        };
        assert_eq!(status, HealthStatus::Failing);
    }

    /// A non-Ok health report ALWAYS names a reason. A degraded or failing status with an
    /// empty detail forces every observer to open an investigation just to discover whether
    /// one is needed, which is the most expensive possible way to say "something is wrong".
    ///
    /// The arms in `health_report` happen to cover today's status inputs one-for-one, so
    /// this holds by coincidence maintained by hand rather than by construction: a new
    /// input added to the ladder in `health.rs` without a matching arm here would flip the
    /// status while leaving the reason empty, and every existing test would still pass.
    /// This drives every non-Ok snapshot the ladder can produce through the wire mapping
    /// and requires a non-empty reason from each, so that omission fails here instead of
    /// arriving as an unexplained degraded state on a supervisor dashboard.
    #[test]
    fn unreadable_store_omits_counts_rather_than_reporting_zero() {
        use credentials_core::health::VaultHealth;

        // The counted fields. Each is a measurement OF THE STORE, so none of them has a
        // meaning when the store could not be read.
        const COUNTED: [&str; 7] = [
            "credentialsTotal",
            "active",
            "needsReauth",
            "corrupt",
            "needsReauthIds",
            "corruptIds",
            "openIntents",
        ];

        let unreadable = health_report(&VaultHealth::unreadable());
        let ModuleControlResponse::HealthCheck { metrics, .. } = unreadable else {
            panic!("expected HealthCheck");
        };
        let metrics = metrics.expect("an unreadable report still carries metrics");

        for field in COUNTED {
            assert!(
                metrics.get(field).is_none(),
                "{field} must be ABSENT when the store is unreadable: reporting 0 is what an \
                 empty vault reports, so a consumer plotting it cannot tell 'none' from \
                 'could not count'"
            );
        }
        // The flags describe the daemon rather than the store, so they survive.
        assert_eq!(
            metrics.get("storeReadable").and_then(|v| v.as_bool()),
            Some(false),
            "the reason the counts are missing must still be readable"
        );

        // THE DISAMBIGUATOR. Without this, an implementation that omitted the counts
        // unconditionally -- or emitted no metrics at all -- would satisfy every
        // assertion above, and the omission would be indistinguishable from the field
        // never existing.
        let readable = health_report(&VaultHealth::summarize(&[], 0, false));
        let ModuleControlResponse::HealthCheck { metrics, .. } = readable else {
            panic!("expected HealthCheck");
        };
        let metrics = metrics.expect("a healthy report carries metrics");
        for field in COUNTED {
            assert!(
                metrics.get(field).is_some(),
                "{field} must be PRESENT when the store was read, including when the count \
                 is genuinely zero -- that is the case the absent form has to be \
                 distinguishable from"
            );
        }
        assert_eq!(
            metrics.get("active").and_then(|v| v.as_u64()),
            Some(0),
            "an empty but readable vault reports a real zero"
        );
    }

    #[test]
    fn every_non_ok_health_report_carries_a_reason() {
        use credentials_core::health::{VaultHealth, VaultHealthStatus};
        use credentials_core::store::{RecordMeta, RecordState};

        fn scan_row(id: &str, state: RecordState) -> (String, RecordMeta) {
            (
                id.to_string(),
                RecordMeta {
                    record_version: 1,
                    key_id_hex: "00".repeat(8),
                    state,
                },
            )
        }

        // One snapshot per way the ladder can leave Ok, built through the same
        // constructors the daemon uses rather than by hand-setting `status` -- a
        // hand-built struct would prove the mapping handles values that cannot occur.
        let mut stalled = VaultHealth::summarize(&[], 0, false);
        stalled.mark_refresher_stalled();

        let fenced = VaultHealth::summarize(&[], 0, true);

        let unreadable = VaultHealth::unreadable();

        let needs_reauth = VaultHealth::summarize(
            &[scan_row("oauth:anthropic", RecordState::NeedsReauth)],
            0,
            false,
        );
        let corrupt =
            VaultHealth::summarize(&[scan_row("apikey:exa", RecordState::Corrupt)], 0, false);

        for (name, health) in [
            ("refresher_stalled", stalled),
            ("fenced_out", fenced),
            ("store_unreadable", unreadable),
            ("needs_reauth", needs_reauth),
            ("corrupt", corrupt),
        ] {
            assert_ne!(
                health.status,
                VaultHealthStatus::Ok,
                "{name}: this case must leave Ok, or it is not testing what it claims"
            );
            let ModuleControlResponse::HealthCheck { status, detail, .. } = health_report(&health)
            else {
                panic!("expected HealthCheck");
            };
            assert_ne!(
                status,
                HealthStatus::Ok,
                "{name}: wire status must be non-Ok"
            );
            let reason = detail.unwrap_or_default();
            assert!(
                !reason.trim().is_empty(),
                "{name}: a non-Ok report must name its reason, got an empty detail"
            );
        }

        // The positive control: a healthy vault needs no reason, so this proves the
        // assertion above is about non-Ok reports rather than about detail being
        // unconditionally present.
        let healthy =
            VaultHealth::summarize(&[scan_row("apikey:exa", RecordState::Active)], 0, false);
        assert_eq!(healthy.status, VaultHealthStatus::Ok);
        let ModuleControlResponse::HealthCheck { status, detail, .. } = health_report(&healthy)
        else {
            panic!("expected HealthCheck");
        };
        assert_eq!(status, HealthStatus::Ok);
        assert!(detail.is_none(), "a healthy report carries no reason");
    }

    /// A fenced-out daemon reports `ready=false`/`lease_held=false` from status, agreeing
    /// with the health probe instead of always claiming a healthy lease. Non-vacuous:
    /// before fencing, an Active credential is ready with the lease held; after fencing,
    /// the same probe flips both.
    #[tokio::test]
    async fn status_reflects_fenced_out_lease_loss() {
        let (surface, store, db_path) = tmp_surface_with_store(14);
        // Mint a handle for the active credential so a per-handle status has a target.
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "apikey:active",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put handle");

        let params = StatusParams {
            handle: Some(handle.raw.clone()),
        };
        let before = surface.status(1, &params).await;
        assert!(before.ready, "an active credential is ready before fencing");
        assert!(before.lease_held, "the lease is held before fencing");

        // A newer writer claims the db at a higher fence epoch; the next fenced write on
        // this store is rejected and latches fenced_out (the lease-handover race).
        bump_fence_epoch(&db_path);
        let _ = store.invalidate("apikey:active"); // trigger the fenced write to latch

        let after = surface.status(1, &params).await;
        assert!(
            !after.lease_held,
            "a fenced-out daemon does not hold the lease"
        );
        assert!(
            !after.ready,
            "a fenced-out daemon is not ready even for an Active row"
        );

        // The overall (no-handle) status also reflects the loss.
        let overall = surface.status(1, &StatusParams { handle: None }).await;
        assert!(!overall.ready);
        assert!(!overall.lease_held);
    }

    /// A status handle-probe runs the per-connection limiter BEFORE resolution, so a
    /// status-based enumeration sweep of unknown handles trips the same durable anomaly
    /// alarm as a get sweep — not a bypass. Proven by reading the audit log for the alarm.
    /// `status` must report each record state DISTINCTLY: a needs_reauth credential is
    /// not ready and names NeedsReauth, a corrupt one names Corrupt, and an active one
    /// names nothing.
    ///
    /// Both sibling status tests probe the ACTIVE row only — one for the fenced-out
    /// latch, one for the limiter — so neither can tell this mapping apart from a status
    /// that always answers `last_error_code: None`. Consumers branch on that field to
    /// decide whether a re-login is needed, so a collapsed mapping would present a dead
    /// credential as healthy.
    #[tokio::test]
    async fn status_names_the_state_of_each_credential() {
        let (surface, store, _db) = tmp_surface_with_store(16);

        // The rig seeds apikey:active (Active) and apikey:dead (NeedsReauth). Add a
        // corrupt row so all three arms of the mapping are exercised in one run.
        store
            .create(
                "apikey:broken",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"k".to_vec(), None),
            )
            .expect("create broken");
        store.quarantine("apikey:broken").expect("quarantine");

        let mint_for = |id: &str| {
            let handle = credentials_core::store::mint_handle().expect("mint handle");
            store
                .put_handle_hash(&handle.hash, id, AuditCtx::admin(AuditOp::MintHandle))
                .expect("put handle");
            handle.raw
        };
        let active = mint_for("apikey:active");
        let dead = mint_for("apikey:dead");
        let broken = mint_for("apikey:broken");

        // POSITIVE ARM: without it, a status reporting every credential as broken would
        // satisfy both negative assertions below.
        let ok = surface
            .status(
                2,
                &StatusParams {
                    handle: Some(active),
                },
            )
            .await;
        assert!(ok.ready, "an active credential is ready");
        assert_eq!(
            ok.last_error_code, None,
            "an active credential names no error"
        );

        let reauth = surface
            .status(2, &StatusParams { handle: Some(dead) })
            .await;
        assert!(!reauth.ready, "a needs_reauth credential is not ready");
        assert_eq!(
            reauth.last_error_code,
            Some(read_surface::ReadError::NeedsReauth),
            "needs_reauth must be named, not collapsed into a generic failure"
        );

        let corrupt = surface
            .status(
                2,
                &StatusParams {
                    handle: Some(broken),
                },
            )
            .await;
        assert!(!corrupt.ready, "a corrupt credential is not ready");
        assert_eq!(
            corrupt.last_error_code,
            Some(read_surface::ReadError::Corrupt),
            "corrupt is a DIFFERENT state from needs_reauth: one needs a re-login, the \
             other needs the record replaced"
        );

        // An unresolvable handle is uniformly not_found, so a probe cannot distinguish
        // a revoked handle from one that never existed.
        let unknown = surface
            .status(
                2,
                &StatusParams {
                    handle: Some("ckh_not_a_real_handle".to_string()),
                },
            )
            .await;
        assert!(!unknown.ready);
        assert_eq!(
            unknown.last_error_code,
            Some(read_surface::ReadError::NotFound)
        );
    }

    #[tokio::test]
    async fn status_handle_probe_runs_the_limiter() {
        let (surface, store, _db) = tmp_surface_with_store(15);
        // Sweep more distinct unknown handles than the distinct ceiling (16) on ONE
        // connection, all via status (not get). None resolve — the probe itself is the
        // signal — so this must still trip the anomaly.
        for i in 0..20 {
            let params = StatusParams {
                handle: Some(format!("ckh_unknown_{i}")),
            };
            let _ = surface.status(77, &params).await;
        }
        let alarms = store
            .read_audit(None)
            .expect("read audit")
            .into_iter()
            .filter(|e| e.op == "fetch_anomaly")
            .count();
        assert!(
            alarms >= 1,
            "a status sweep of unknown handles must raise a durable fetch-anomaly alarm"
        );
    }

    /// Wire v2 layer-2 validation (spec §3.3): a route frame whose epoch does not
    /// match the locally-installed binding — or whose slot is unknown — is dropped
    /// silently BEFORE dispatch: no Response, no Error (an Error would inject into
    /// the corr space of the slot's next tenant), and no lifecycle effect (a stale
    /// Goodbye must not tear down the new binding's admin state). Non-vacuous: the
    /// same frame at the CORRECT epoch is answered, so the drop discriminates the
    /// epoch check, not a broken dispatch path.
    #[tokio::test]
    async fn stale_epoch_route_frames_are_dropped_before_dispatch() {
        let surface = tmp_surface(21);
        let (admin, _admin_store) = tmp_admin(21);
        let (control_tx, _control_rx) = mpsc::channel::<Frame>(8);
        let (route_tx, mut route_rx) = mpsc::channel::<Frame>(8);
        let egress = Egress {
            control: control_tx,
            route: route_tx,
        };
        let routes = Arc::new(RouteEpochs::default());
        // The binding for channel 9 is at epoch 2 (a rebind after epoch 1 released).
        routes.install(9, 2);

        fn status_request(channel: u16, epoch: u32, corr: u64) -> Frame {
            Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Request,
                Flags::new(false, Priority::Interactive, false),
                channel,
                epoch,
                corr,
                serde_json::to_vec(&json!({ "method": "credential.status", "params": {} }))
                    .unwrap(),
            )
            .unwrap()
        }

        // (a) Stale epoch (1) on a live slot: dropped, no frame egresses.
        assert!(
            handle_frame(status_request(9, 1, 50), &egress, &surface, &admin, &routes)
                .await
                .unwrap()
        );
        // (b) Unknown slot entirely: dropped too.
        assert!(handle_frame(
            status_request(10, 1, 51),
            &egress,
            &surface,
            &admin,
            &routes
        )
        .await
        .unwrap());
        // (c) A stale-epoch Goodbye must NOT remove the live binding.
        let stale_goodbye = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Goodbye,
            Flags::new(false, Priority::Interactive, false),
            9,
            1,
            0,
            Vec::new(),
        )
        .unwrap();
        assert!(
            handle_frame(stale_goodbye, &egress, &surface, &admin, &routes)
                .await
                .unwrap()
        );
        assert!(
            routes.matches(9, 2),
            "a stale-epoch goodbye must not tear down the live binding"
        );

        // Nothing was dispatched for any of the three stale frames.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            route_rx.try_recv().is_err(),
            "stale frames must produce no response and no error"
        );

        // (d) The SAME request at the correct epoch is answered — the drops above
        // discriminate the epoch check, not a broken dispatch path.
        assert!(
            handle_frame(status_request(9, 2, 52), &egress, &surface, &admin, &routes)
                .await
                .unwrap()
        );
        let answered = tokio::time::timeout(std::time::Duration::from_secs(2), route_rx.recv())
            .await
            .expect("the valid-epoch request must be answered")
            .expect("route lane open");
        assert_eq!(answered.header.channel, 9);
        assert_eq!(
            answered.header.epoch, 2,
            "the response echoes the binding epoch"
        );
        assert_eq!(answered.header.corr, 52);
    }

    /// A legacy malformed row must never become a successful zero-byte credential.
    /// The fixture uses an OAuth-kind record with no refresh state so the current store
    /// can represent the historical bad row without bypassing the new static-write
    /// invariant; removing the read guard makes this test return `Ok([])`.
    #[tokio::test]
    async fn get_quarantines_an_empty_nonrefreshable_record() {
        use credentials_core::store::RecordState;

        let (surface, store, _db) = tmp_surface_with_store(20);
        let mut legacy = VaultRecord::new_oauth(
            "legacy-import",
            "legacy",
            credentials_core::oauth::OAuthCredential {
                access_token: String::new(),
                refresh_token: String::new(),
                expires_at_ms: None,
                token_url: String::new(),
                client_id: None,
                scopes: Vec::new(),
            },
            Vec::new(),
        );
        legacy.refresh_adapter = None;
        legacy.oauth = None;
        store
            .create("oauth:legacy-empty", &legacy)
            .expect("seed representable legacy record");
        let handle = credentials_core::store::mint_handle().expect("mint");
        store
            .put_handle_hash(
                &handle.hash,
                "oauth:legacy-empty",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put handle");

        let got = surface
            .get(
                77,
                &read_surface::GetParams {
                    handle: handle.raw,
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await;
        let read_surface::GetOutcome::Err { error } = got else {
            panic!("empty legacy payload must not be returned as success");
        };
        assert_eq!(error.code, read_surface::ReadError::Corrupt);
        assert_eq!(error.class, read_surface::ErrorClass::Permanent);
        assert_eq!(
            store.meta("oauth:legacy-empty").expect("meta").state,
            RecordState::Corrupt,
            "the exact inspected version must be quarantined"
        );
    }

    /// `report_auth_failure` invalidates ONLY on 401/403, and ONLY at the record version
    /// the reporting consumer was actually served.
    ///
    /// This is the one read-surface op that MUTATES, and each arm is load-bearing.
    /// Without the accepted arm, an implementation ignoring every report would pass;
    /// without the non-auth-status arm, one invalidating on any status would pass;
    /// without the stale-version arm, one ignoring the version and killing whatever is
    /// current would pass. The three wrong shapes are, respectively: a dead token served
    /// forever, a provider 500 nuking a healthy credential, and a slow consumer's stale
    /// 401 destroying a credential the vault has already repaired.
    #[tokio::test]
    async fn report_auth_failure_invalidates_only_on_auth_status_at_the_served_version() {
        use credentials_core::store::RecordState;

        let (surface, store, _db) = tmp_surface_with_store(31);
        let raw = credentials_core::store::mint_handle().expect("mint");
        store
            .put_handle_hash(
                &raw.hash,
                "apikey:active",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put handle");
        let handle = raw.raw;

        let state_of = |store: &EncryptedStore| {
            store
                .list_meta()
                .expect("list meta")
                .into_iter()
                .find(|(id, _)| id == "apikey:active")
                .expect("seeded credential is present")
                .1
                .state
        };
        let params = |status: u16, version: u64| read_surface::ReportAuthFailureParams {
            handle: handle.clone(),
            provider_status: status,
            record_version: version,
        };

        // A NON-AUTH status must not invalidate: a provider 500 is a hiccup, not a dead
        // credential.
        surface
            .report_auth_failure(7, &params(500, 1))
            .await
            .expect("a non-auth status is accepted");
        assert_eq!(
            state_of(&store),
            RecordState::Active,
            "a 500 must leave the credential serving"
        );

        // A STALE version must be a silent no-op. Bump the record past what our reporter
        // holds, exactly as a refresh would, then report the OLD version.
        store
            .overwrite_unconditional_audited(
                "apikey:active",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"k2".to_vec(), None),
                AuditCtx::admin(AuditOp::Put),
            )
            .expect("bump the record version");
        surface
            .report_auth_failure(7, &params(401, 1))
            .await
            .expect("a stale report is accepted, not errored");
        assert_eq!(
            state_of(&store),
            RecordState::Active,
            "a 401 for a version the vault has moved past must NOT invalidate: that \
             credential was already repaired"
        );

        // THE ACCEPTED ARM. Without it, an implementation that ignored every report
        // satisfies both assertions above.
        surface
            .report_auth_failure(7, &params(401, 2))
            .await
            .expect("a current-version 401 is accepted");
        assert_eq!(
            state_of(&store),
            RecordState::NeedsReauth,
            "a 401 at the served version must stop the vault serving that token"
        );

        // An unknown handle gets the same refusal as a revoked one, so a caller cannot
        // use this endpoint to discover which handles exist.
        let unknown = surface
            .report_auth_failure(
                7,
                &read_surface::ReportAuthFailureParams {
                    handle: "ckh_not_a_handle".to_string(),
                    provider_status: 401,
                    record_version: 1,
                },
            )
            .await;
        assert!(
            matches!(unknown, Err(read_surface::ReadError::NotFound)),
            "an unknown handle must be a uniform not_found, got {unknown:?}"
        );
    }

    /// `get_many` serves a batch at the cap and refuses one item past it, WHOLE rather
    /// than truncated. The at-cap arm is what gives the over-cap arm its meaning: a
    /// `get_many` that refused unconditionally would satisfy every over-cap assertion in
    /// this repo, since nothing else calls it with an accepted batch.
    #[tokio::test]
    async fn get_many_serves_at_the_cap_and_refuses_whole_past_it() {
        use crate::limiter::GET_MANY_MAX;

        let (surface, store, _db) = tmp_surface_with_store(24);
        let mut handles = Vec::new();
        for i in 0..GET_MANY_MAX {
            let id = format!("apikey:batch-{i}");
            let payload = format!("secret-{i}").into_bytes();
            store
                .create(
                    &id,
                    &VaultRecord::new_static(
                        credentials_core::record::CredentialKind::ApiKey,
                        "test",
                        payload,
                        None,
                    ),
                )
                .expect("seed batch record");
            let handle = credentials_core::store::mint_handle().expect("mint");
            store
                .put_handle_hash(&handle.hash, &id, AuditCtx::admin(AuditOp::MintHandle))
                .expect("put handle");
            handles.push(handle.raw);
        }
        let params = |raws: &[String]| read_surface::GetManyParams {
            items: raws
                .iter()
                .map(|raw| read_surface::GetParams {
                    handle: raw.clone(),
                    min_ttl_ms: None,
                    force_refresh: false,
                })
                .collect(),
        };

        // AT the cap: every item is served, with its own payload — so the batch path
        // works and the refusal below is about the bound, not about get_many at all.
        let served = surface.get_many(81, &params(&handles)).await;
        assert_eq!(served.len(), GET_MANY_MAX, "a batch at the cap is served");
        for (i, outcome) in served.iter().enumerate() {
            let read_surface::GetOutcome::Ok(result) = outcome else {
                panic!("item {i} must serve at the cap, got {outcome:?}");
            };
            assert_eq!(result.payload, format!("secret-{i}").into_bytes());
        }

        // ONE past the cap: a single refusal for the whole call. A truncating
        // implementation would return GET_MANY_MAX outcomes here instead.
        let mut over = handles.clone();
        over.push(handles[0].clone());
        let refused = surface.get_many(81, &params(&over)).await;
        assert_eq!(refused.len(), 1, "over-cap is refused whole, not truncated");
        let read_surface::GetOutcome::Err { error } = &refused[0] else {
            panic!("over-cap must refuse");
        };
        assert_eq!(error.code, read_surface::ReadError::TooManyItems);
        assert_eq!(error.class, read_surface::ErrorClass::ContextOverflow);
    }

    /// End-to-end: `get` surfaces the provider account identity for a chatgpt:openai
    /// record, parsed LIVE from the served access token's claim, and returns None for a
    /// record whose provider has no account claim (here an api-key with no adapter). This
    /// is the vault leg of account-scoped routing: the consumer joins (handle,
    /// record_version) -> account_id on this field. Non-vacuous — a real seeded oauth
    /// record flows through the real ReadSurface::get path, and the negative arm proves
    /// the field is not unconditionally populated.
    #[tokio::test]
    async fn get_surfaces_account_id_for_chatgpt_openai_and_none_otherwise() {
        use credentials_core::oauth::OAuthCredential;

        let (surface, store, _db) = tmp_surface_with_store(21);

        // A faithful OpenAI access-token JWT carrying the nested claim path
        // "https://api.openai.com/auth"."chatgpt_account_id" = "acct-e2e-7". Unsigned
        // (claims decoding never verifies the signature; transport is the trust anchor).
        let access_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.\
             eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiYWNjdC1lMmUtNyJ9fQ.\
             sig";
        let oauth = OAuthCredential {
            access_token: access_jwt.to_string(),
            refresh_token: "ref".to_string(),
            // Far-future expiry so the record is not stale and `get` serves it as-is
            // (no refresh, no network) — isolating the account_id surfacing.
            expires_at_ms: Some(4_102_444_800_000),
            token_url: "https://auth.openai.com/oauth/token".to_string(),
            client_id: Some("app_x".to_string()),
            scopes: Vec::new(),
        };
        let record =
            VaultRecord::new_oauth("login", "openai", oauth, access_jwt.as_bytes().to_vec());
        store
            .create("chatgpt:openai", &record)
            .expect("create chatgpt record");
        let oauth_handle = credentials_core::store::mint_handle().expect("mint");
        store
            .put_handle_hash(
                &oauth_handle.hash,
                "chatgpt:openai",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put oauth handle");

        // A handle for the seeded api-key record (no adapter → no account claim).
        let apikey_handle = credentials_core::store::mint_handle().expect("mint");
        store
            .put_handle_hash(
                &apikey_handle.hash,
                "apikey:active",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put apikey handle");

        let got = surface
            .get(
                1,
                &read_surface::GetParams {
                    handle: oauth_handle.raw.clone(),
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await;
        let read_surface::GetOutcome::Ok(result) = got else {
            panic!("expected an Ok get for the chatgpt:openai handle");
        };
        assert_eq!(
            result.account_id.as_deref(),
            Some("acct-e2e-7"),
            "get must surface the ChatGPT account id parsed from the served access token"
        );

        let got_apikey = surface
            .get(
                1,
                &read_surface::GetParams {
                    handle: apikey_handle.raw.clone(),
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await;
        let read_surface::GetOutcome::Ok(apikey_result) = got_apikey else {
            panic!("expected an Ok get for the api-key handle");
        };
        assert_eq!(
            apikey_result.account_id, None,
            "a record with no account-claim provider must not carry an account_id"
        );
    }

    /// End-to-end: `get` serves stored login-time identity (email + org_name +
    /// account_id fallback) for an opaque-token provider (anthropic), and serves NO
    /// identity fields for a pre-identity record (the additive-schema arm: old
    /// records decode with an empty identity and the wire omits the fields). This is
    /// the QTA display-label leg: email must ride WITH account_id, both from the
    /// stored identity, because an opaque access token has no live-parse path.
    #[tokio::test]
    async fn get_serves_stored_identity_for_anthropic_and_none_for_legacy_records() {
        use credentials_core::oauth::OAuthCredential;
        use credentials_core::record::RecordIdentity;

        let (surface, store, _db) = tmp_surface_with_store(22);

        let oauth = OAuthCredential {
            // Opaque (non-JWT) access token — the live claim parse yields nothing,
            // so any served identity provably comes from the stored RecordIdentity.
            access_token: "sk-ant-oat01-opaque".to_string(),
            refresh_token: "ref".to_string(),
            expires_at_ms: Some(4_102_444_800_000),
            token_url: "https://api.anthropic.com/v1/oauth/token".to_string(),
            client_id: Some("client".to_string()),
            scopes: Vec::new(),
        };
        let record = VaultRecord::new_oauth(
            "login",
            "anthropic",
            oauth.clone(),
            b"sk-ant-oat01-opaque".to_vec(),
        )
        .with_identity(RecordIdentity {
            account_id: Some("anthropic-acct-uuid".to_string()),
            email: Some("op@example.com".to_string()),
            org_name: Some("op@example.com's Organization".to_string()),
        });
        store
            .create("oauth:anthropic:work", &record)
            .expect("create labeled anthropic record");
        let handle = credentials_core::store::mint_handle().expect("mint");
        store
            .put_handle_hash(
                &handle.hash,
                "oauth:anthropic:work",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put handle");

        // A legacy-shaped record with NO identity (pre-identity mint).
        let legacy = VaultRecord::new_oauth("login", "anthropic", oauth, b"tok".to_vec());
        store
            .create("oauth:anthropic", &legacy)
            .expect("create legacy record");
        let legacy_handle = credentials_core::store::mint_handle().expect("mint");
        store
            .put_handle_hash(
                &legacy_handle.hash,
                "oauth:anthropic",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put legacy handle");

        let got = surface
            .get(
                1,
                &read_surface::GetParams {
                    handle: handle.raw.clone(),
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await;
        let read_surface::GetOutcome::Ok(result) = got else {
            panic!("expected an Ok get for the labeled anthropic handle");
        };
        assert_eq!(result.email.as_deref(), Some("op@example.com"));
        assert_eq!(
            result.org_name.as_deref(),
            Some("op@example.com's Organization")
        );
        assert_eq!(
            result.account_id.as_deref(),
            Some("anthropic-acct-uuid"),
            "account_id must fall back to stored identity for opaque tokens \
             (QTA invariant: email never ships without account_id)"
        );

        let got_legacy = surface
            .get(
                1,
                &read_surface::GetParams {
                    handle: legacy_handle.raw.clone(),
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await;
        let read_surface::GetOutcome::Ok(legacy_result) = got_legacy else {
            panic!("expected an Ok get for the legacy handle");
        };
        assert_eq!(legacy_result.email, None);
        assert_eq!(legacy_result.org_name, None);
        assert_eq!(legacy_result.account_id, None);
    }
}
