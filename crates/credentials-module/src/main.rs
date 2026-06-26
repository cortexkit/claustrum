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
    anthropic::AnthropicAdapter, google::GoogleAdapter, openai::OpenAiAdapter, xai::XaiAdapter,
    RefreshAdapter,
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
    session::{ModuleControlRequest, ModuleControlResponse},
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
        // Google needs the OAuth client secret; provided via env (operator-supplied),
        // empty when unset (a google refresh then fails cleanly rather than panicking).
        Arc::new(GoogleAdapter::new(
            std::env::var("CK_GOOGLE_OAUTH_CLIENT_SECRET").unwrap_or_default(),
        )),
        Arc::new(XaiAdapter::new()),
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
        control_ops: None,
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
            handle_control_request(frame, writer).await?;
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
) -> Result<(), ModuleError> {
    let request =
        serde_json::from_slice::<ModuleControlRequest>(&frame.body).map_err(ModuleError::Json)?;
    match request {
        ModuleControlRequest::RouteBind { .. } => {
            // Anonymous, trusted-unscoped reads: accept every bind. Access is scoped
            // by capability handle at request time, not at bind.
            let body = serde_json::to_vec(&ModuleControlResponse::RouteBindAck {})
                .map_err(ModuleError::Json)?;
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
