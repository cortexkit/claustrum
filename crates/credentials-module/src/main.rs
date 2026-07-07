#![forbid(unsafe_code)]

//! The cortexkit-credentials subc module daemon.
//!
//! Connects out to the subc daemon, authenticates over loopback TCP, and registers
//! a reserved `ManagementSurface` — echoing the `SUBC_LAUNCH_NONCE` the supervisor
//! injected so only the spawned process can claim the `cortexkit-credentials` id
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

mod limiter;
mod read_surface;

use std::path::PathBuf;
use std::sync::Arc;

use cortexkit_store::{open_sqlite, StorageDescriptor};
use credentials_core::engine::RefreshEngine;
use credentials_core::http::ReqwestTransport;
use credentials_core::refresh_adapters::{
    anthropic::AnthropicAdapter, antigravity::AntigravityAdapter, google::GoogleAdapter,
    openai::OpenAiAdapter, xai::XaiAdapter, RefreshAdapter,
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
const EGRESS_BUFFER: usize = 64;

// How often the background refresher recomputes the cached health snapshot. Well
// under the prober's cadence so the served snapshot is never more than one tick
// stale, and each tick is a cheap no-decrypt scan that runs OFF the probe path.
const HEALTH_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

// Read-surface op names (the four anonymous route-channel operations).
const OP_GET: &str = "credential.get";
const OP_GET_MANY: &str = "credential.get_many";
const OP_STATUS: &str = "credential.status";
const OP_REPORT_AUTH_FAILURE: &str = "credential.report_auth_failure";

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

async fn run(config: ModuleConfig) -> Result<(), ModuleError> {
    let stream = connect_to_subc(&config.connection_file_path).await?;
    let (mut read_half, write_half) = tokio::io::split(stream);
    let (tx, rx) = mpsc::channel::<Frame>(EGRESS_BUFFER);
    let writer = tokio::spawn(drain_writer(write_half, rx));

    // The HELLO_ACK carries the resolved storage descriptor; the surface is built
    // AFTER the handshake (it needs the descriptor) and the boot gate runs before
    // any request is served.
    let loop_result = module_loop(&mut read_half, tx.clone(), &config).await;
    drop(tx);

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
    writer: mpsc::Sender<Frame>,
    config: &ModuleConfig,
) -> Result<(), ModuleError>
where
    R: AsyncRead + Unpin,
{
    send_hello(&writer, config).await?;
    let ack = expect_hello_ack(read_half).await?;

    // Boot gate: build the vault from the resolved descriptor, then reconcile any
    // dangling refresh intents BEFORE accepting any request.
    let surface = Arc::new(build_surface(&ack).await?);

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
        if !handle_frame(frame, &writer, &surface).await? {
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
async fn build_surface(ack: &ModuleHelloAckBody) -> Result<ReadSurface, ModuleError> {
    let descriptor_value = ack
        .storage
        .as_ref()
        .ok_or_else(|| ModuleError::Message("HELLO_ACK carried no storage descriptor".into()))?;
    let descriptor: StorageDescriptor = serde_json::from_value(descriptor_value.clone())
        .map_err(|e| ModuleError::Message(format!("decoding storage descriptor: {e}")))?;

    let data_dir = sqlite_data_dir(&descriptor)?;
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

    let store = EncryptedStore::open(store, key)
        .map_err(|e| ModuleError::Message(format!("open vault: {e}")))?;
    let store = Arc::new(store);

    let http =
        Arc::new(ReqwestTransport::new().map_err(|e| ModuleError::Message(format!("http: {e}")))?);
    let adapters: Vec<Arc<dyn RefreshAdapter>> = vec![
        Arc::new(AnthropicAdapter::new()),
        Arc::new(OpenAiAdapter::new()),
        // Google defaults to the public gemini-cli client (id + secret) that opencode
        // mints against; CK_GOOGLE_OAUTH_CLIENT_ID / _SECRET override it. No prod env
        // is required for the common case.
        Arc::new(GoogleAdapter::new()),
        Arc::new(XaiAdapter::new()),
        // Antigravity (Google Code-Assist OAuth) — its own public client, distinct
        // from the gemini-cli client the google adapter uses.
        Arc::new(AntigravityAdapter::new()),
    ];
    let engine = Arc::new(RefreshEngine::new(store, adapters, http));

    // THE BOOT GATE: resolve every dangling intent before serving any read.
    engine
        .reconcile()
        .await
        .map_err(|e| ModuleError::Message(format!("boot reconciliation: {e}")))?;

    Ok(ReadSurface::new(engine, FetchLimiter::new(Caps::default())))
}

async fn drain_writer<W>(write_half: W, mut rx: mpsc::Receiver<Frame>) -> Result<(), ModuleError>
where
    W: AsyncWrite + Unpin,
{
    let mut writer = BufWriter::new(write_half);
    while let Some(frame) = rx.recv().await {
        write_frame(&mut writer, &frame)
            .await
            .map_err(|e| ModuleError::Message(e.to_string()))?;
        while let Ok(frame) = rx.try_recv() {
            write_frame(&mut writer, &frame)
                .await
                .map_err(|e| ModuleError::Message(e.to_string()))?;
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
        // Echo the supervisor's launch nonce so subc accepts our reserved id.
        launch_nonce: config.launch_nonce.clone(),
    })
    .map_err(ModuleError::Json)?;
    let frame = Frame::build(FrameType::Hello, control_flags(), 0, HELLO_CORR, body)
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

/// Returns `Ok(false)` to stop the loop (graceful goodbye / EOF).
async fn handle_frame(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    surface: &Arc<ReadSurface>,
) -> Result<bool, ModuleError> {
    match frame.header.ty {
        FrameType::Ping if frame.header.channel == 0 => {
            let pong = Frame::build_with_version(
                frame.header.ver,
                FrameType::Pong,
                frame.header.flags,
                0,
                frame.header.corr,
                Vec::new(),
            )
            .map_err(|e| ModuleError::Message(e.to_string()))?;
            send(writer, pong).await?;
            Ok(true)
        }
        FrameType::Goodbye if frame.header.channel == 0 => Ok(false),
        FrameType::Goodbye => {
            // A route goodbye: forget that connection's limiter state.
            surface.drop_connection(frame.header.channel as u64).await;
            Ok(true)
        }
        FrameType::Request if frame.header.channel == 0 => {
            handle_control_request(frame, writer, surface).await?;
            Ok(true)
        }
        FrameType::Request => {
            // Data-plane read request on a route channel. Spawn so a slow refresh
            // never head-of-line-blocks another route.
            let writer = writer.clone();
            let surface = Arc::clone(surface);
            tokio::spawn(async move {
                let _ = handle_read_request(frame, &writer, &surface).await;
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
) -> Result<(), ModuleError> {
    let request =
        serde_json::from_slice::<ModuleControlRequest>(&frame.body).map_err(ModuleError::Json)?;
    let response_body = match request {
        ModuleControlRequest::RouteBind { .. } => {
            // Anonymous, trusted-unscoped reads: accept every bind. Access is scoped
            // by capability handle at request time, not at bind.
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
    let detail = if health.fenced_out {
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
    let metrics = json!({
        "credentialsTotal": health.credentials_total,
        "active": health.active,
        "needsReauth": health.needs_reauth,
        "corrupt": health.corrupt,
        "needsReauthIds": health.needs_reauth_ids,
        "corruptIds": health.corrupt_ids,
        "openIntents": health.open_intents,
        "storeReadable": health.store_readable,
        "fencedOut": health.fenced_out,
    });
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

async fn handle_read_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    surface: &Arc<ReadSurface>,
) -> Result<(), ModuleError> {
    let channel = frame.header.channel;
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
            Err(e) => return invalid_params(writer, ver, channel, corr, &e.to_string()).await,
        },
        OP_GET_MANY => match serde_json::from_value::<GetManyParams>(request.params) {
            Ok(p) => json!({ "results": surface.get_many(connection_id, &p).await }),
            Err(e) => return invalid_params(writer, ver, channel, corr, &e.to_string()).await,
        },
        OP_STATUS => match serde_json::from_value::<StatusParams>(request.params) {
            Ok(p) => json!({ "result": surface.status(&p) }),
            Err(e) => return invalid_params(writer, ver, channel, corr, &e.to_string()).await,
        },
        OP_REPORT_AUTH_FAILURE => {
            match serde_json::from_value::<ReportAuthFailureParams>(request.params) {
                Ok(p) => match surface.report_auth_failure(connection_id, &p).await {
                    Ok(()) => json!({ "result": { "accepted": true } }),
                    Err(code) => {
                        json!({ "result": { "accepted": false, "error": { "code": code } } })
                    }
                },
                Err(e) => return invalid_params(writer, ver, channel, corr, &e.to_string()).await,
            }
        }
        other => {
            return send_route_error(
                writer,
                ver,
                channel,
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
    corr: u64,
    detail: &str,
) -> Result<(), ModuleError> {
    send_route_error(
        writer,
        ver,
        channel,
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
    use credentials_core::key::{MasterKey, MASTER_KEY_LEN};
    use credentials_core::record::{CredentialKind, VaultRecord};
    use read_surface::ReadSurface;

    fn tmp_surface(seed: u8) -> Arc<ReadSurface> {
        tmp_surface_with_store(seed).0
    }

    fn tmp_surface_with_store(seed: u8) -> (Arc<ReadSurface>, Arc<EncryptedStore>) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "ck-cred-health-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("mkdir");
        let descriptor = StorageDescriptor {
            module_id: "cortexkit-credentials".into(),
            storage_namespace: "default".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: root.join("store.db").to_string_lossy().into_owned(),
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
        (surface, store)
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
            42,
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();

        handle_control_request(frame, &tx, &surface).await.unwrap();

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
        let (surface, store) = tmp_surface_with_store(11);

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
}
