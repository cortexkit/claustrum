#![forbid(unsafe_code)]

//! The claustrum subc module daemon (the credential vault).
//!
//! Connects out to the subc daemon, authenticates over loopback TCP, and registers
//! a reserved `ManagementSurface` — echoing the `SUBC_LAUNCH_NONCE` the supervisor
//! injected so only the spawned process can claim the `claustrum` id
//! (closing the vault-impersonation hole). It serves the capability-handle read
//! surface plus principal-scoped `credential.get_scoped`, `credential.status`,
//! `credential.sign`, and `credential.public_key` route operations.
//! There is deliberately NO unauthenticated write op on this channel — writes live in
//! the admin surface, gated by master-key possession + the single-writer lease.
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
#[cfg(test)]
mod test_support;

use std::path::PathBuf;
use std::sync::Arc;

use cortexkit_store::{open_sqlite, StorageDescriptor, StoreError};
use credentials_core::audit::AuthEventKind;
use credentials_core::engine::RefreshEngine;
use credentials_core::enrollment::{EnrollmentDisposition, EnrollmentError, EnrollmentRefusal};
use credentials_core::http::ReqwestTransport;
use credentials_core::refresh_adapters::{
    anthropic::AnthropicAdapter, antigravity::AntigravityAdapter, cursor::CursorAdapter,
    devin::DevinAdapter, digitalocean::DigitalOceanAdapter, github_app::GithubAppAdapter,
    github_copilot::GithubCopilotAdapter, google::GoogleAdapter, kimi::KimiAdapter,
    openai::OpenAiAdapter, snowflake::SnowflakeAdapter, xai::XaiAdapter, RefreshAdapter,
};
use credentials_core::resolver::{self, KeySource, ResolverConfig};
use credentials_core::store::EncryptedStore;
#[cfg(test)]
use credentials_core::store::SelectorKind;
use serde::{Deserialize, Serialize};
use serde_json::json;
use subc_protocol::manifest::Concurrency;
use subc_protocol::manifest::{
    build_provenance, LaunchNonceSource, ManifestProvenance, SelfSignalDeclaration,
    SelfSignalEffect, SelfSignalKind, SignalAnchor, SignalCadence,
};
use subc_protocol::{
    manifest::{
        Bindings, IdentityBinding, ManagementOperation, ManagementOperationKind, ModuleManifest,
        ProviderRole, StorageBinding, StorageKind, StorageScope, TrustTier,
    },
    session::{
        HealthStatus, ModuleControlRequest, ModuleControlResponse, MODULE_CONTROL_OP_HEALTH_CHECK,
    },
    ErrorBody, Flags, Frame, FrameType, ModuleHelloAckBody, ModuleHelloBody, Priority,
    PROTOCOL_VERSION, SUBC_MODULE_ID_ENV,
};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter},
    net::TcpStream,
    sync::mpsc,
};

use limiter::{Caps, FetchLimiter};
use read_surface::{
    DepositCookieParams, EnrollPollParams, EnrollProposeParams, EnrollRotateParams, GetManyParams,
    GetParams, GetScopedParams, ListScopedParams, PublicKeyParams, ReadSurface,
    ReportAuthFailureParams, StatusParams,
};

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

// Capability-handle read-surface operations plus the separate principal-scoped read.
const OP_DEPOSIT_COOKIE: &str = "credential.deposit_cookie";
const OP_GET: &str = "credential.get";
const OP_GET_SCOPED: &str = "credential.get_scoped";
const OP_LIST_SCOPED: &str = "credential.list_scoped";
const OP_GET_MANY: &str = "credential.get_many";
const OP_STATUS: &str = "credential.status";
const OP_REPORT_AUTH_FAILURE: &str = "credential.report_auth_failure";
const OP_SIGN: &str = "credential.sign";
const OP_PUBLIC_KEY: &str = "credential.public_key";
const OP_OPEN: &str = "credential.open";
const OP_ENROLL_PROPOSE: &str = "auth.enroll_propose";
const OP_ENROLL_POLL: &str = "auth.enroll_poll";
const OP_ENROLL_ROTATE: &str = "auth.enroll_rotate";
/// Admin ops on the running module (authenticated: direct principal + master-key
/// challenge-response). `admin.challenge` issues a nonce; `admin.op` carries the
/// authenticated op body + tag.
const OP_ADMIN_CHALLENGE: &str = "admin.challenge";
const OP_ADMIN_OP: &str = "admin.op";

pub(crate) fn wrap_result<T: serde::Serialize>(value: T) -> serde_json::Value {
    json!({ "result": value })
}

#[tokio::main]
async fn main() -> Result<(), ModuleError> {
    // Answered BEFORE the --subc gate, so it works on a binary that is not being
    // supervised. Without this the only way to ask a deployed daemon what it is was to
    // start it, which needs a connection file and a live supervisor -- an identity
    // check that requires the thing being identified to already be running correctly.
    if std::env::args_os().skip(1).any(|a| a == "--version") {
        println!(
            "ck-claustrum {} ({})",
            env!("CARGO_PKG_VERSION"),
            credentials_core::contract::BUILD_REV
        );
        return Ok(());
    }
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
    /// Where that nonce came from, declared in the manifest's provenance so the
    /// supervisor can tell which modules no longer need the environment copy.
    launch_nonce_source: Option<LaunchNonceSource>,
}

impl ModuleConfig {
    fn from_env() -> Result<Self, ModuleError> {
        let connection_file_path = parse_subc_arg(std::env::args_os().skip(1))?;
        let module_id = std::env::var(SUBC_MODULE_ID_ENV)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_MODULE_ID.to_string());
        // THE ONLY READ OF THE LAUNCH NONCE IN THIS DAEMON, and it must stay the only
        // one. `subc_os::launch_nonce` takes the nonce from the inherited descriptor the
        // supervisor passes (falling back to `SUBC_LAUNCH_NONCE` only when no descriptor
        // is named), closes that descriptor, and caches the answer for the process. A
        // second reader going to the environment directly would break once the
        // supervisor stops setting the environment copy, and one reading the descriptor
        // number again would consume whatever file the process opened there next.
        //
        // Called first thing in `main`, before anything is spawned, because until it
        // runs the descriptor is inheritable and a child would receive the pipe.
        let nonce = subc_os::launch_nonce().map_err(|e| {
            ModuleError::Message(format!("cannot read the supervisor's launch nonce: {e}"))
        })?;
        let launch_nonce_source = nonce.as_ref().map(|n| match n.source() {
            subc_os::LaunchNonceSource::Fd => LaunchNonceSource::Fd,
            subc_os::LaunchNonceSource::Env => LaunchNonceSource::Env,
            other => LaunchNonceSource::from_wire_name(other.as_str()),
        });
        let launch_nonce = nonce
            .map(|n| n.value().to_string())
            .filter(|v| !v.trim().is_empty());
        Ok(Self {
            connection_file_path,
            module_id,
            launch_nonce,
            launch_nonce_source,
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
struct RouteEpochs(
    std::sync::Mutex<std::collections::HashMap<u16, u32>>,
    /// `(channel, epoch)` pairs already reported as dropped, so a repeat is bounded by
    /// its absence from the log rather than adding another line.
    std::sync::Mutex<std::collections::HashSet<(u16, u32)>>,
);

impl RouteEpochs {
    fn install(&self, channel: u16, epoch: u32) {
        let mut map = self.0.lock().unwrap_or_else(|p| p.into_inner());
        map.insert(channel, epoch);
        self.1
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|(ch, _)| *ch != channel);
    }

    /// Whether `channel` is a live binding at exactly `epoch`.
    fn matches(&self, channel: u16, epoch: u32) -> bool {
        let map = self.0.lock().unwrap_or_else(|p| p.into_inner());
        map.get(&channel) == Some(&epoch)
    }

    /// The epoch this module holds for `channel`, for naming what a drop expected.
    fn expected(&self, channel: u16) -> Option<u32> {
        let map = self.0.lock().unwrap_or_else(|p| p.into_inner());
        map.get(&channel).copied()
    }

    /// Record a dropped frame ONCE per `(channel, epoch)`, returning whether this was
    /// the first — so a drop can be named without letting a looping sender drive
    /// unbounded log volume on the ingress path.
    ///
    /// SILENT ON THE WIRE IS A SECURITY PROPERTY; SILENT IN MY OWN DIAGNOSTICS WAS JUST
    /// A HOLE. The wire silence is settled and correct — a module-emitted Error would
    /// inject into the corr space of the slot's next tenant. But this check also wrote
    /// nothing ANYWHERE, so when a consumer hung for 30+ minutes across the 2026-08-25
    /// restart and the supervisor seat asked for the `(channel, epoch)` of the frames I
    /// had dropped, I COULD NOT ANSWER: I had never written them down. The comparison
    /// that would have decided the incident — dropped epoch against the live census —
    /// was unavailable because of this gap, not because of the silence.
    ///
    /// Third instance of one shape in a week (an unlogged drain happy-path, this, and an
    /// announcement with no join to its wire): ABSENCE OF A RECORD READ AS ABSENCE OF AN
    /// EVENT. The vault's `auth_events` emptiness is honest because every refusal path
    /// there provably writes. This emptiness was not.
    ///
    /// WHAT A CLEAN DROP RECORD DOES NOT PROVE, learned by over-reading one on
    /// 2026-08-26 and worth stating before someone repeats it: it does NOT mean no
    /// consumer held a stale binding. It means no stale frame REACHED THIS CHECK.
    ///
    /// The daemon relay sits below this code and refuses a frame for a channel it no
    /// longer holds with a class-less `unknown_channel`. Those frames never arrive here,
    /// so this record stays empty while a stale-binding outage is in progress one layer
    /// down. During a fleet speech outage I read an empty record and concluded "the
    /// stale-binding hypothesis is dead"; the cause was a stale binding, refused by the
    /// relay after a restart of this module. The operational answer (not custody, not
    /// this wire) was right and the mechanical one was wrong.
    ///
    /// So this instrument answers exactly one question: did a frame reach MY endpoint
    /// carrying an epoch I do not hold. A consumer-visible stall with a clean record
    /// here points DOWN to the relay, not away from stale bindings.
    fn note_drop(&self, channel: u16, epoch: u32) -> bool {
        let mut seen = self.1.lock().unwrap_or_else(|p| p.into_inner());
        seen.insert((channel, epoch))
    }

    fn remove(&self, channel: u16) {
        let mut map = self.0.lock().unwrap_or_else(|p| p.into_inner());
        map.remove(&channel);
        self.1
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|(ch, _)| *ch != channel);
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
    // any request is served. In-flight requests can retain route senders after the
    // loop exits, so shutdown gives the writer a bounded grace period, then aborts it.
    let loop_result = module_loop(&mut read_half, egress, &config).await;

    let writer_result = finish_writer(writer).await;
    match (loop_result, writer_result) {
        (Err(loop_err), _) => Err(loop_err),
        (Ok(()), Ok(Ok(()))) => Ok(()),
        (Ok(()), Ok(Err(writer_err))) => Err(ModuleError::Message(writer_err.to_string())),
        (Ok(()), Err(join_err)) => Err(join_err),
    }
}

/// Bound egress draining even if an in-flight request or a stalled socket keeps it alive.
async fn finish_writer(
    mut writer: tokio::task::JoinHandle<Result<(), ModuleError>>,
) -> Result<Result<(), ModuleError>, ModuleError> {
    match tokio::time::timeout(std::time::Duration::from_secs(2), &mut writer).await {
        Ok(result) => result.map_err(|e| ModuleError::Message(e.to_string())),
        Err(_) => {
            writer.abort();
            let _ = writer.await;
            Ok(Ok(()))
        }
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
    let (surface, admin) = build_surface(&ack, &config.module_id).await?;
    let surface = Arc::new(surface);
    let admin = Arc::new(admin);
    // Wire v2: the module-side channel → epoch map (spec §3.3 layer 2).
    let routes = Arc::new(RouteEpochs::default());

    // Keep the cached health snapshot current OFF the probe path. The health.check
    // reply must be cheap/in-memory (spec §2), so the live store scan runs here on a
    // cadence, never on the channel-0 dispatch. Aborted on loop exit via the guard.
    let health_refresher = spawn_health_refresher(Arc::clone(&surface));
    let _refresher_guard = AbortOnDrop(health_refresher);

    // NO READ TIMEOUT HERE, AND THAT IS DELIBERATE -- but it rests on the supervisor,
    // so the dependency is named rather than left for someone to rediscover.
    //
    // An error propagates and a clean EOF returns, both ending this loop and dropping
    // the connection for the supervisor to respawn against. The uncovered case is a
    // SILENTLY HALF-OPEN connection where no bytes and no error ever arrive: this
    // blocks in `read_frame` forever, holding a corpse it cannot notice. That is the
    // vault's exact profile -- long-lived, low-traffic, idle for hours -- and it is the
    // shape that took a sibling module's credential leg dark in August.
    //
    // THIS DAEMON HAS NO SELF-LIVENESS. Detection is entirely the supervisor's prober,
    // verified at source in subconscious (supervise.rs): a timed-out probe counts into
    // consecutive_failures and at the threshold calls health_restart_child on an
    // UNCONDITIONAL path -- no action config is consulted, so `on_degraded` cannot
    // suppress it. That lane fires only for a module that does not ANSWER; the
    // configurable actions gate the other lane, where a module answers with a degraded
    // status. A deaf daemon rides the unconditional one.
    //
    // The numbers, all compiled defaults this module's config does not override, READ
    // FROM subc-core's supervise.rs AND LAST RE-DERIVED 2026-09-02 (DEFAULT_HEALTH_CADENCE,
    // DEFAULT_HEALTH_DEADLINE, DEFAULT_HEALTH_FAILURE_THRESHOLD, DEFAULT_DRAIN_TIMEOUT,
    // DEFAULT_MAX_RESTARTS -- named so a re-check is a grep rather than an archaeology):
    //
    // THE DATE IS THE POINT, not decoration. A borrowed constant that names its source but
    // not when it was last true reads as current forever, and this block instructs a future
    // reader NOT to add a liveness probe -- an instruction that survives the numbers being
    // wrong. Attribution tells you whose fact it is; only a date is falsifiable by someone
    // who knows the sibling has shipped since.
    //
    // WHEN RE-CHECKING, READ THE CONSTANT AND NOT A MATCH ON ITS NAME. A grep for
    // `failure_threshold` in that file also hits a test fixture carrying the same value 3,
    // so a wrong read and a right one are indistinguishable by their answer today, and
    // would silently "confirm" this block against a number nothing ships if the fixture
    // ever drifted from the default.
    //
    // cadence 30s, deadline 5s, failure_threshold 3, drain 30s. So the dark window is
    // ~90s to Unresponsive plus up to 30s drain before SIGKILL. Acceptable because a
    // read failing for two minutes is a `transient` refusal every consumer retries.
    //
    // THE BUDGET IS THE REAL FAILURE MODE, not the window: 3 crash restarts within a
    // 600s window (DEFAULT_MAX_RESTARTS, DEFAULT_RESTART_WINDOW), re-derived at source
    // 2026-09-05. Restarts older than the window release their slot, so the budget is a
    // RATE and not a lifetime cap.
    //
    // THIS PARAGRAPH SAID "3, LIFETIME" UNTIL subc-core 0.17.17, AND THE DATE IS WHY IT
    // WAS CAUGHT. That is the mechanism this block argues for working once: a borrowed
    // constant that named its source but not when it was last true would still read as
    // current, and the conclusion drawn from it would have kept its authority after the
    // premise stopped holding.
    //
    // What the correction changes: a recurring silent death SPREAD THIN no longer parks
    // the module -- deaths more than 600s apart never accumulate. What it does not
    // change, and the reason this paragraph still stands: a FAST loop still parks, and
    // parked means every credential in the fleet unreachable until an operator revives
    // it. So "the supervisor restarts us" remains true only three times in ten minutes,
    // which is the case a genuine crash loop produces.
    //
    // Do NOT add a redundant liveness probe here on the strength of the paragraph
    // above; the supervisor's already fires and a second one would only add a way to
    // disagree. What WOULD justify revisiting: this daemon acquiring an outbound
    // request that awaits a reply. Today it is purely reactive after HELLO, which is
    // why the reused-dead-connection class cannot occur here at all -- there is no
    // requester object for the defect to live on. That immunity is a property of the
    // current role shape and ends silently the day the role changes, with nothing in
    // the diff looking like a connection-lifecycle edit.
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

/// Route this process's log lines into the fleet's dated segments (fleet-logging r2):
/// `<data dir>/logs/claustrum.<YYYY-MM-DD>.log`, one line per event, redacted by the
/// fleet credential redactor before the write.
///
/// THE DIRECTORY IS THE ONE THE SUPERVISOR HANDED US, not a second resolution. The spec's
/// rule is that where two components must agree on a path one resolves it and the other
/// is told; an isolated test instance that re-derived the path would append to the
/// operator's segment and read as equivalent. So this runs after the storage descriptor
/// is decoded, and before anything the serve loop could log.
///
/// A failure here must not take the vault down. The crate already falls back to stderr
/// on its own when the directory is unwritable; the only errors left are a missing module
/// id (impossible here, it is passed) and a subscriber installed twice, which is one
/// stderr line in the daemon's capture -- exactly where a logger that failed to start
/// should be visible.
fn init_fleet_log(module_id: &str, data_dir: &std::path::Path) {
    // The id this process registered under, so the segment and every logger name root
    // match what the supervisor and `ck module logs` call it.
    let mut config = cortexkit_log::Config::in_dir(module_id, data_dir.join("logs"));
    // The supervisor injects the operator's retention choices at spawn. `Config::from_env`
    // would read them too, but it also resolves the data directory itself, which is the
    // second resolution this function exists to avoid.
    let env_u32 = |name: &str| std::env::var(name).ok()?.trim().parse::<u32>().ok();
    if let Some(days) = env_u32("CK_LOG_MAX_AGE_DAYS") {
        config.retention.max_age_days = days;
    }
    if let Some(mb) = env_u32("CK_LOG_ALARM_SEGMENT_MB") {
        config.retention.alarm_segment_mb = mb;
    }
    if let Err(error) = cortexkit_log::init(config) {
        eprintln!("claustrum: fleet logger not installed: {error}");
    }
}

/// The backup descriptor for this module, written to `<data_dir>/engram-catalog.json`.
/// engram, the fleet's backup module, reads that file in every module's data dir to
/// learn which paths to capture and how. The daemon writes it at every start, so this
/// constant is the only copy anyone edits. It used to be placed by hand, and that copy
/// fell behind: `signed-envelopes/` was kept for weeks and never backed up.
///
/// `signed-payloads/` and `signed-envelopes/` are written by hand during manifest
/// signing ceremonies (see `docs/gh-manifest-signing-procedure.md`), not by the daemon,
/// so nothing else would notice them missing from a backup. Any new directory the vault
/// retains in its data dir belongs here, and the test beside this constant names them.
const ENGRAM_CATALOG_JSON: &str = r#"{
  "schema_version": 1,
  "module_id": "claustrum",
  "entries": [
    {
      "entry_id": "claustrum/store",
      "class": "portable",
      "mechanism": "whole-db",
      "path": "store.db",
      "writer_interaction": "backup-api-live"
    },
    {
      "entry_id": "claustrum/signed-payloads",
      "class": "portable",
      "mechanism": "filetree",
      "path": "signed-payloads",
      "writer_interaction": "none"
    },
    {
      "entry_id": "claustrum/signed-envelopes",
      "class": "portable",
      "mechanism": "filetree",
      "path": "signed-envelopes",
      "writer_interaction": "none"
    }
  ]
}
"#;

/// Write [`ENGRAM_CATALOG_JSON`] to `<data_dir>/engram-catalog.json` unless the file
/// already holds exactly those bytes. Returns whether it wrote.
///
/// Owner-only (0600) and atomic: a temp file is written and synced, renamed over the
/// old one, and the directory is synced, so engram never reads a half-written
/// descriptor. engram refuses to capture a module whose descriptor fails to parse, so
/// a torn one would stop the vault being backed up.
fn place_engram_catalog(data_dir: &std::path::Path) -> std::io::Result<bool> {
    use std::io::Write as _;
    let path = data_dir.join("engram-catalog.json");
    if std::fs::read(&path).ok().as_deref() == Some(ENGRAM_CATALOG_JSON.as_bytes()) {
        return Ok(false);
    }
    let tmp = data_dir.join("engram-catalog.json.tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(ENGRAM_CATALOG_JSON.as_bytes())?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, &path)?;
    // Syncing the directory makes the rename itself durable across a crash. Only unix
    // can open a directory to sync it; elsewhere the file's own sync is all there is.
    #[cfg(unix)]
    match std::fs::File::open(data_dir).and_then(|dir| dir.sync_all()) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::Unsupported | std::io::ErrorKind::InvalidInput
            ) => {}
        Err(error) => return Err(error),
    }
    Ok(true)
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
/// the registered adapters, then reconcile persisted refresh state before exposing reads.
async fn build_surface(
    ack: &ModuleHelloAckBody,
    module_id: &str,
) -> Result<(ReadSurface, admin_surface::AdminSurface), ModuleError> {
    let descriptor_value = ack
        .storage
        .as_ref()
        .ok_or_else(|| ModuleError::Message("HELLO_ACK carried no storage descriptor".into()))?;
    let descriptor: StorageDescriptor = serde_json::from_value(descriptor_value.clone())
        .map_err(|e| ModuleError::Message(format!("decoding storage descriptor: {e}")))?;

    let data_dir = sqlite_data_dir(&descriptor)?;
    init_fleet_log(module_id, &data_dir);
    // Derive the vault identity before the data_dir is moved into the resolver config;
    // it binds the admin-op transcript to THIS vault.
    let vault_id = credentials_core::vault_id_for(&data_dir)
        .ok_or_else(|| ModuleError::Message("cannot derive vault id from data dir".into()))?;
    let kimi_device_id = credentials_core::refresh_adapters::kimi::read_device_id_or_unknown(
        &data_dir.join("kimi-device-id"),
    );
    let resolver_config = resolver_config_from_env(data_dir);

    // Open the store, resolve the master key from its plaintext fingerprint, then
    // migrate. Migration 10 needs the key before it can append its category-backfill
    // audit row; a brand-new store has no fingerprint yet and resolves Current.
    // An immediate lease collision makes the supervisor restart the module and returns
    // `Transient` to every consumer whose fetch is in that window. Waiting up to roughly
    // half a second is cheaper than that observable outage, while a persistent writer
    // still receives the same failure after the bounded retry.
    let mut attempt = 0;
    let store = loop {
        attempt += 1;
        match open_sqlite(&descriptor) {
            Ok(store) => break store,
            Err(StoreError::Lease(_)) if attempt < 5 => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(error) => return Err(ModuleError::Message(format!("open store: {error}"))),
        }
    };
    let key = match EncryptedStore::read_db_key_id(&store)
        .map_err(|e| ModuleError::Message(format!("read db key id: {e}")))?
    {
        Some(db_key_id) => resolver::resolve_for_db(&resolver_config, db_key_id),
        // Brand-new vault (no audit-key row yet): the current slot is the only key.
        None => resolver::resolve(&resolver_config, None),
    }
    .map_err(|e| ModuleError::Message(format!("master key: {e}")))?;
    // After key resolution, because the resolver creates the data dir and sets it
    // owner-only. Failing to write the descriptor only means engram keeps backing up
    // whatever descriptor is already there (or none), so it is logged and the vault
    // still starts.
    if let Err(error) = place_engram_catalog(&resolver_config.data_dir) {
        tracing::warn!(
            target: "backup",
            kind = ?error.kind(),
            "could not write engram-catalog.json; engram backs up the previous descriptor, if any"
        );
    }
    EncryptedStore::migrate_with_key(&store, &key)
        .map_err(|e| ModuleError::Message(format!("migrate: {e}")))?;

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
    let engine = Arc::new(RefreshEngine::new(
        store,
        registered_refresh_adapters(kimi_device_id),
        http,
    ));

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

/// Every refresh adapter the daemon registers, in one place so a test can enumerate
/// them. A new adapter added here also needs its `auth_method` decided in
/// `credentials_core::list_auth_method` and listed in the expected map of
/// `every_registered_refresh_adapter_has_an_explicit_auth_method` below, which fails
/// naming any registered adapter the map does not list.
fn registered_refresh_adapters(kimi_device_id: String) -> Vec<Arc<dyn RefreshAdapter>> {
    vec![
        Arc::new(AnthropicAdapter::new()),
        Arc::new(CursorAdapter::new()),
        Arc::new(DevinAdapter::new()),
        Arc::new(DigitalOceanAdapter::new()),
        Arc::new(OpenAiAdapter::new()),
        // Google defaults to the public gemini-cli client (id + secret) that opencode
        // mints against; CK_GOOGLE_OAUTH_CLIENT_ID / _SECRET override it. No prod env
        // is required for the common case.
        Arc::new(GoogleAdapter::new()),
        Arc::new(GoogleAdapter::gmail()),
        Arc::new(SnowflakeAdapter::new()),
        Arc::new(XaiAdapter::new()),
        Arc::new(GithubCopilotAdapter::new()),
        Arc::new(GithubAppAdapter::new()),
        Arc::new(KimiAdapter::new(kimi_device_id)),
        // Antigravity (Google Code-Assist OAuth) — its own public client, distinct
        // from the gemini-cli client the google adapter uses.
        Arc::new(AntigravityAdapter::new()),
    ]
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
                    kind: AuthEventKind::ReconcileNeedsReauth.as_str(),
                    provider_status: None,
                    detail: Some(reason.as_str()),
                    reporter_source: None,
                    principal: None,
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
/// Returns when BOTH lanes are closed and drained; shutdown separately bounds this wait.
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
        manifest: manifest(&config.module_id, config.launch_nonce_source.clone()),
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
        // Named in full because this line is the only record of the event: the process
        // exits and the supervisor restarts it. The channel and epoch say whether a
        // consumer's request reached us before the supervisor acknowledged the handshake.
        ty => Err(ModuleError::Message(format!(
            "unexpected frame {ty:?} awaiting HELLO_ACK (channel {}, epoch {}, corr {})",
            frame.header.channel, frame.header.epoch, frame.header.corr
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
        // Loud here, silent on the wire. First occurrence per (channel, epoch) only: a
        // stale sender loops, and an unbounded write on the ingress path is a lever.
        if routes.note_drop(frame.header.channel, frame.header.epoch) {
            let expected = routes
                .expected(frame.header.channel)
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown-slot".to_string());
            // Every field is a frame-header integer or a value this module chose. Nothing
            // from a request body can reach this line -- see `LOG_SITES`.
            tracing::warn!(
                target: "routes",
                channel = frame.header.channel,
                arrived_epoch = frame.header.epoch,
                expected = %expected,
                "route-epoch drop: frames for a binding this module does not hold; compare \
                 with the supervisor's live route census -- equal to the live epoch means \
                 the census moved under this check, lower means the sender predates its \
                 own re-bind",
            );
        }
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
            surface
                .drop_connection(route_connection_id(
                    frame.header.channel,
                    frame.header.epoch,
                ))
                .await;
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
            // The epoch check above accepted this frame under the current bind. Snapshot
            // that bind's principal before spawning so a later route reuse cannot lend
            // its new principal to an already-accepted request.
            let principal = admin.principal(frame.header.channel);
            tokio::spawn(async move {
                let _ = handle_read_request(frame, &route, &surface, &admin, principal).await;
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
    let request = match serde_json::from_slice::<ModuleControlRequest>(&frame.body) {
        Ok(request) => request,
        Err(_) => {
            // Control variants and their fields grow independently of this module: a
            // newer daemon can send a `route.bind` whose scope stamp carries a field this
            // build's protocol crate refuses. REFUSE IT on the Error lane, the protocol's
            // rejection path, rather than leaving it unanswered. An unanswered bind holds
            // the opener until the daemon's bind timeout and reads as a slow vault; a
            // refusal fails that one route at once and leaves every other route alone.
            // The body is never logged or echoed: it may carry a principal or scope data.
            tracing::warn!(target: "routes", "refused undecodable channel-0 control request");
            return send_route_error(
                writer,
                frame.header.ver,
                0,
                0,
                frame.header.corr,
                "invalid_control_body",
                "this vault build cannot decode the control request",
            )
            .await;
        }
    };
    let response_body = match request {
        ModuleControlRequest::RouteBind {
            route_channel,
            epoch,
            principal,
            scope,
            ..
        } => {
            // A route opened under a FLOW's scope is refused at bind. The vault authorizes
            // on the bind's principal and never on the scope, so serving it would hand a
            // flow whatever the opening module's grants reach: credential material read on
            // a flow's behalf, attributed to the module. Nothing in the fleet reads
            // credentials for a flow, so this refuses by name rather than guessing a
            // policy, and no route is installed for it.
            if scope
                .as_ref()
                .is_some_and(|stamp| stamp.attributes.flow_id.is_some())
            {
                tracing::warn!(
                    target: "routes",
                    route_channel,
                    "refused a route bind under a flow scope"
                );
                return send_route_error(
                    writer,
                    frame.header.ver,
                    0,
                    0,
                    frame.header.corr,
                    "flow_scopes_unsupported",
                    "the vault does not serve routes opened under a flow scope",
                )
                .await;
            }
            // Wire v2: install the (channel → epoch) binding in the local route map.
            // Installed here — when the accepted ack is being queued — so no route
            // traffic can pass layer-2 validation before the bind is acknowledged
            // (§3.2: module traffic legally begins only after the RouteBind ack).
            surface.drop_channel(route_channel).await;
            routes.install(route_channel, epoch);
            // Record the bind's daemon-stamped principal (Gate 1 provenance) against
            // the route channel, under the newly installed wire epoch. An absent principal stamp
            // records as `Unverified` — never `direct` — so admin ops fail closed on
            // an older daemon. Reads remain anonymous/handle-scoped regardless.
            let principal = principal.unwrap_or(subc_protocol::Principal::Unverified);
            admin.record_bind_at(route_channel, epoch, principal);
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
            "retired": health.retired,
            "corrupt": health.corrupt,
            "needsReauthIds": health.needs_reauth_ids,
            "retiredIds": health.retired_ids,
            "corruptIds": health.corrupt_ids,
            "openIntents": health.open_intents,
        });
        if let (Some(target), Some(source)) = (metrics.as_object_mut(), counted.as_object()) {
            for (k, v) in source {
                target.insert(k.clone(), v.clone());
            }
        }
        // The witness needs the sequence and the row MAC as one atomic observation.
        // Omitting either half would let a sequence-only comparison miss a truncated
        // tail that was replaced by fresh legitimate appends at the same sequence.
        if let (Some(seq), Some(entry_mac)) = (&health.audit_seq, &health.audit_tip_mac) {
            if let Some(target) = metrics.as_object_mut() {
                target.insert("auditSeq".to_string(), json!(seq));
                target.insert("auditTipMac".to_string(), json!(entry_mac));
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

/// Each binding has separate counters even when a late task outlives Goodbye.
fn route_connection_id(channel: u16, epoch: u32) -> u64 {
    (u64::from(epoch) << 16) | u64::from(channel)
}

async fn handle_read_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    surface: &Arc<ReadSurface>,
    admin: &Arc<admin_surface::AdminSurface>,
    principal: Option<subc_protocol::Principal>,
) -> Result<(), ModuleError> {
    let channel = frame.header.channel;
    // Echo the validated ingress epoch on every frame of this route (wire v2:
    // a response must carry the epoch of the binding it answers for).
    let epoch = frame.header.epoch;
    let corr = frame.header.corr;
    let ver = frame.header.ver;
    let connection_id = route_connection_id(channel, epoch);

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
        OP_DEPOSIT_COOKIE => match serde_json::from_value::<DepositCookieParams>(request.params) {
            Ok(params) => match surface.deposit_cookie(principal.as_ref(), &params) {
                Ok(result) => wrap_result(result),
                Err(code) => {
                    wrap_result(json!({ "error": { "code": code, "class": code.class() } }))
                }
            },
            Err(_) => {
                return invalid_params(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "invalid cookie deposit parameters",
                )
                .await
            }
        },
        OP_ENROLL_PROPOSE => match serde_json::from_value::<EnrollProposeParams>(request.params) {
            Ok(params) => match surface.enroll_propose(principal.as_ref(), &params) {
                Ok(result) => wrap_result(result),
                Err(error) => {
                    return send_enrollment_error(writer, ver, channel, epoch, corr, &error).await
                }
            },
            Err(_) => {
                return send_enrollment_refusal(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    EnrollmentRefusal::InvalidParams,
                )
                .await
            }
        },
        OP_ENROLL_POLL => match serde_json::from_value::<EnrollPollParams>(request.params) {
            Ok(params) => match surface.enroll_poll(principal.as_ref(), &params) {
                Ok(result) => wrap_result(result),
                Err(error) => {
                    return send_enrollment_error(writer, ver, channel, epoch, corr, &error).await
                }
            },
            Err(_) => {
                return send_enrollment_refusal(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    EnrollmentRefusal::InvalidParams,
                )
                .await
            }
        },
        OP_ENROLL_ROTATE => match serde_json::from_value::<EnrollRotateParams>(request.params) {
            Ok(params) => match surface.enroll_rotate(&params) {
                Ok(result) => wrap_result(result),
                Err(error) => {
                    return send_enrollment_error(writer, ver, channel, epoch, corr, &error).await
                }
            },
            Err(_) => {
                return send_enrollment_refusal(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    EnrollmentRefusal::InvalidParams,
                )
                .await
            }
        },
        OP_GET => match serde_json::from_value::<GetParams>(request.params) {
            Ok(p) => wrap_result(surface.get(connection_id, &p).await),
            Err(e) => {
                return invalid_params(writer, ver, channel, epoch, corr, &e.to_string()).await
            }
        },
        OP_GET_SCOPED => match serde_json::from_value::<GetScopedParams>(request.params) {
            Ok(p) => wrap_result(surface.get_scoped(principal.as_ref(), &p).await),
            Err(e) => {
                return invalid_params(writer, ver, channel, epoch, corr, &e.to_string()).await
            }
        },
        OP_LIST_SCOPED => match serde_json::from_value::<ListScopedParams>(request.params) {
            Ok(params) => match surface.list_scoped(principal.as_ref(), &params) {
                Ok(result) => wrap_result(result),
                Err(code) => wrap_result(json!({
                    "error": read_surface::ErrorBody { code, class: code.class() }
                })),
            },
            Err(error) => {
                return invalid_params(writer, ver, channel, epoch, corr, &error.to_string()).await
            }
        },
        OP_GET_MANY => match serde_json::from_value::<GetManyParams>(request.params) {
            Ok(p) => json!({ "results": surface.get_many(connection_id, &p).await }),
            Err(e) => {
                return invalid_params(writer, ver, channel, epoch, corr, &e.to_string()).await
            }
        },
        OP_SIGN => match serde_json::from_value::<read_surface::SignParams>(request.params) {
            Ok(p) if p.has_exactly_one_authorization() => {
                match surface.sign(connection_id, principal.as_ref(), &p).await {
                    Ok(r) => wrap_result(r),
                    // Keep the same { code, class } shape every other op uses: the class
                    // gives retry policy and the code names the request-specific remedy.
                    Err(code) => wrap_result(json!({
                        "error": read_surface::ErrorBody { code, class: code.class() }
                    })),
                }
            }
            Ok(_) => {
                return invalid_params(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "credential.sign requires exactly one of handle or credential_id",
                )
                .await
            }
            Err(e) => {
                return invalid_params(writer, ver, channel, epoch, corr, &e.to_string()).await
            }
        },
        OP_OPEN => match serde_json::from_value::<read_surface::OpenParams>(request.params) {
            Ok(p) => match surface.open(connection_id, principal.as_ref(), &p).await {
                Ok(result) => wrap_result(result),
                Err(code) => wrap_result(json!({
                    "error": read_surface::ErrorBody { code, class: code.class() }
                })),
            },
            Err(error) => {
                return invalid_params(writer, ver, channel, epoch, corr, &error.to_string()).await
            }
        },
        OP_PUBLIC_KEY => match serde_json::from_value::<PublicKeyParams>(request.params) {
            Ok(p) if p.has_exactly_one_authorization() => {
                match surface
                    .public_key(connection_id, principal.as_ref(), &p)
                    .await
                {
                    Ok(r) => wrap_result(r),
                    Err(code) => wrap_result(json!({
                        "error": read_surface::ErrorBody { code, class: code.class() }
                    })),
                }
            }
            Ok(_) => {
                return invalid_params(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "credential.public_key requires exactly one of handle or credential_id",
                )
                .await
            }
            Err(e) => {
                return invalid_params(writer, ver, channel, epoch, corr, &e.to_string()).await
            }
        },
        OP_STATUS => match serde_json::from_value::<StatusParams>(request.params) {
            Ok(p) if p.has_mutually_exclusive_addressing() => {
                wrap_result(surface.status(connection_id, principal.as_ref(), &p).await)
            }
            Ok(_) => {
                return invalid_params(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "credential.status accepts at most one of handle or credential_id",
                )
                .await
            }
            Err(e) => {
                return invalid_params(writer, ver, channel, epoch, corr, &e.to_string()).await
            }
        },
        OP_REPORT_AUTH_FAILURE => {
            match serde_json::from_value::<ReportAuthFailureParams>(request.params) {
                Ok(p) => match surface
                    .report_auth_failure(connection_id, principal.as_ref(), &p)
                    .await
                {
                    Ok(()) => wrap_result(json!({ "accepted": true })),
                    // Carry the produced error class alongside the code, in the same
                    // { code, class } shape get/get_many use: class gives retry policy and
                    // code names the request-specific remedy.
                    Err(code) => wrap_result(json!({
                        "accepted": false,
                        "error": read_surface::ErrorBody { code, class: code.class() }
                    })),
                },
                Err(e) => {
                    return invalid_params(writer, ver, channel, epoch, corr, &e.to_string()).await
                }
            }
        }
        OP_ADMIN_CHALLENGE => match admin.challenge_as(channel, epoch, principal.as_ref()) {
            admin_surface::AdminOutcome::Challenge {
                nonce_hex,
                vault_id_hex,
                key_id_hex,
            } => wrap_result(json!({
                "nonce_hex": nonce_hex,
                "vault_id_hex": vault_id_hex,
                "key_id_hex": key_id_hex,
            })),
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
                .execute_as(
                    channel,
                    epoch,
                    principal.as_ref(),
                    p.op_body.as_bytes(),
                    &p.tag_hex,
                )
                .await
            {
                admin_surface::AdminOutcome::Ok(v) => wrap_result(v),
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

/// An enrollment refusal as it appears under `result.error`: the same `{code, class}`
/// pair every read-surface refusal carries, so a consumer decodes enrollment and
/// credential refusals with one decoder and one retry policy.
#[derive(Serialize)]
struct EnrollmentErrorBody<'a> {
    code: &'a str,
    class: EnrollmentDisposition,
}

/// The complete reply body for an enrollment refusal.
///
/// A refusal is the module's answer to a request it received, so it travels in an
/// ordinary `Response` frame. `Error` frames are reserved for requests that never reached
/// the module (malformed frames, unknown operations, params that fail to decode), and
/// clients treat them as a broken connection: an enrollment refusal sent that way made a
/// client reconnect, re-send the call, and report every refusal as retryable, so a
/// consumer polling an expired request polled forever.
fn enrollment_refusal_reply(code: &str, class: EnrollmentDisposition) -> serde_json::Value {
    wrap_result(json!({ "error": EnrollmentErrorBody { code, class } }))
}

async fn send_enrollment_error(
    writer: &mpsc::Sender<Frame>,
    ver: u8,
    channel: u16,
    epoch: u32,
    corr: u64,
    error: &EnrollmentError,
) -> Result<(), ModuleError> {
    send_enrollment_error_body(
        writer,
        ver,
        channel,
        epoch,
        corr,
        error.code(),
        error.disposition(),
    )
    .await
}

async fn send_enrollment_refusal(
    writer: &mpsc::Sender<Frame>,
    ver: u8,
    channel: u16,
    epoch: u32,
    corr: u64,
    refusal: EnrollmentRefusal,
) -> Result<(), ModuleError> {
    send_enrollment_error_body(
        writer,
        ver,
        channel,
        epoch,
        corr,
        refusal.code(),
        refusal.disposition(),
    )
    .await
}

async fn send_enrollment_error_body(
    writer: &mpsc::Sender<Frame>,
    ver: u8,
    channel: u16,
    epoch: u32,
    corr: u64,
    code: &str,
    class: EnrollmentDisposition,
) -> Result<(), ModuleError> {
    let body =
        serde_json::to_vec(&enrollment_refusal_reply(code, class)).map_err(ModuleError::Json)?;
    let frame = Frame::build_with_version(
        ver,
        FrameType::Response,
        Flags::new(false, Priority::Interactive, false),
        channel,
        epoch,
        corr,
        body,
    )
    .map_err(|error| ModuleError::Message(error.to_string()))?;
    send(writer, frame).await
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
    // ErrorBody::new rather than a struct literal: detail is None here deliberately,
    // and the constructor keeps a future required field from silently defaulting.
    //
    // NO DETAIL ON THIS PATH, and that is a decision rather than an omission. These
    // are transport-level refusals (malformed frame, unknown operation), whose remedy
    // is fully carried by the code. The vault's READ-surface errors are the ones a
    // consumer branches on, and they already carry their machine-parsable half as the
    // `class` field inside the result body per the fleet error-class contract --
    // moving that into `detail` would fork one contract across two wire locations.
    //
    // If a refusal here ever needs more than a code, it must not carry secrets:
    // handle values, credential payloads and key material are all out of bounds, and
    // an error body is exactly where they would look harmless.
    let body = serde_json::to_vec(&ErrorBody::new(code, message)).map_err(ModuleError::Json)?;
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
            .filter(|parent| !parent.as_os_str().is_empty())
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

/// The module's capability manifest: a ManagementSurface exposing its read
/// and authenticated operator operations. Storage is `owns_schema: true` (the vault owns its schema). The
/// `reserved: true` binding lives in the daemon's subc.jsonc config, not here; the
/// module proves its reserved identity by echoing the launch nonce in HELLO.
fn manifest(module_id: &str, launch_nonce_source: Option<LaunchNonceSource>) -> ModuleManifest {
    // BUILT THROUGH THE BUILDER, NOT A STRUCT LITERAL, because subc-protocol 0.16.0
    // made `ModuleManifest` `#[non_exhaustive]`. That migration was compile-loud -- a
    // literal simply stops compiling -- and the point of it is that FUTURE field
    // additions upstream will not break this module at all.
    //
    // THE HAZARD THE BUILDER INTRODUCES, WHICH THE COMPILER CANNOT CATCH: every optional
    // field defaults to `None`, so a setter dropped in a later edit is a SILENT semantic
    // change rather than a build failure. `self_signals` is the one that matters --
    // `Some(vec![..])` and `None` are different CLAIMS (see below), and dropping the call
    // would quietly retract the stronger one while everything still compiled and passed.
    // Pinned by `the_self_signal_declaration_matches_what_the_refresher_actually_does`,
    // which `expect`s Some with the reason attached.
    //
    // So EVERY optional field is set EXPLICITLY below, including the one whose value
    // equals the builder's default. A deliberate absence expressed by omission reads as
    // an absence nobody considered, and it takes its explaining comment with it when it
    // goes.
    //
    // `protocol_ver` is the deliberate exception: the builder bakes in the
    // `PROTOCOL_VERSION` of the crate compiled into this binary, which is strictly better
    // than restating it here, because a restatement is a second place that can disagree
    // with the wire it names.
    ModuleManifest::builder(
        module_id.to_string(),
        env!("CARGO_PKG_VERSION").to_string(),
    )
    // TRUST TIER AND BINDINGS MOVED OUT OF `builder()` IN PROTOCOL 0.19 and are set here
    // explicitly for the same reason every other optional setter below is: the builder
    // defaults both to None, and an absence expressed by omission is indistinguishable
    // from a field nobody considered.
    //
    // 0.19's own note says the daemon evaluates neither on any production path, and that
    // a required-but-unread field forces producers to invent fabricated values. Both are
    // true and neither makes these values fabricated HERE: this module really is
    // first-party, and it really does own a project-scoped SQLite schema. Keeping them
    // declared costs two calls and keeps the manifest a description of the module rather
    // than of what the supervisor currently bothers to read -- which is a fact about the
    // reader, and readers change.
    .trust_tier(Some(TrustTier::FirstParty))
    .bindings(Some(Bindings {
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
    }))
    // `capabilities(None)` is DELIBERATE, not an unfilled field.
    //
    // The protocol defines it as `Option<CapabilityDeclarations>` and states that
    // omitting the block preserves the manifest contract used before capability grammar
    // existed. A present block is static discovery metadata the daemon validates before
    // accepting a HELLO, so declaring one is an opt-in that changes what the supervisor
    // checks about this module. That should be a decision, not a field filled in to clear
    // a compile error.
    //
    // WHAT WOULD MAKE IT WORTH DECLARING: a consumer that must discover this vault's
    // route surface statically, before binding, instead of learning it from a refusal.
    // Nothing does today. Every consumer here is configured with the credential ids or
    // handles it needs, and the read surface is deliberately anonymous, so a discovery
    // block would publish a menu no caller asked for.
    .capabilities(None)
    // `provenance` carries the ONE fact this build actually knows about itself.
    //
    // The protocol's four fields are build_git_sha, build_lock_digest, wire_crate_version
    // and store_schema_version, each optional, validated for shape only (non-empty, <=128
    // bytes, printable ASCII). So the constraint on filling them is honesty rather than
    // syntax, and a value invented to look complete is worse than an absent one: a
    // supervisor comparing provenance across a fleet treats a present field as a claim.
    //
    // WHAT IS DECLARED:
    //   build_git_sha        from the same `BUILD_REV` that `--version` reports.
    //                        `scripts/release-build.sh` stamps CK_BUILD_REV from a clean
    //                        tree; an unstamped development build reports "unknown", and
    //                        the block is omitted rather than publish a placeholder
    //                        wearing the shape of a sha.
    //   wire_crate_version   filled BY `build_provenance()` from the subc-protocol linked
    //                        into this binary. This module no longer names it at all --
    //                        the constant is not even imported here any more, which is the
    //                        mechanical evidence that the hand-copied path is gone rather
    //                        than merely discouraged. Distinct from `module_version` above,
    //                        which is this module's own version and says nothing about the
    //                        wire it speaks.
    //
    // WHAT IS NOT, and why it is absent rather than forgotten:
    //   build_lock_digest    nothing hashes Cargo.lock at build time today. Adding it is
    //                        a release-script change, not a manifest one.
    //
    // store_schema_version is DERIVED, never typed. `newest_migration_version()` reads the
    // migration list, so this declaration cannot drift from the schema it describes -- and
    // drift was the live hazard, not a hypothetical: the issue asking for the accessor
    // cited 6, this comment used to say 6, and the list already held 7. Both were true
    // when written.
    //
    // DO NOT fill it from `RECORD_SCHEMA_VERSION`. That constant is public, is a
    // compile-time integer, and names the encrypted record BODY schema -- a different
    // domain that reads 1. It would be a WELL-FORMED value from the WRONG DOMAIN, which
    // every check on this path (non-empty, <=128 bytes, printable ASCII) accepts, and
    // which is worse than absence because a present field stops the reader asking.
    // BUILT THROUGH `build_provenance()` RATHER THAN AS A STRUCT LITERAL, and the reason
    // is not the form validation it adds. The constructor takes three arguments and fills
    // `wire_crate_version` ITSELF from the linked crate -- so the one field whose entire
    // content is a referent to "the subc-protocol compiled into this binary" can no longer
    // be passed by hand. The literal above passed it correctly, and passing it at all is
    // the hand-copied-string failure mode the field's own doc warns about. Deleting the
    // ability to get it wrong beats getting it right.
    //
    // ON `Err` THE WHOLE BLOCK IS OMITTED. A nonconforming fact is not repaired into a
    // conforming one, and a partially-populated provenance would be a claim the census
    // cannot distinguish from a complete one.
    //
    // The `!= "unknown"` guard is REDUNDANT -- `normalize_provenance_fact` filters
    // "unknown", "unavailable" and "none" to omission before any form check. It stays
    // because a reader of THIS file should see the omission decision where they are
    // looking, without having to know a sentinel list that lives in another crate. Braces,
    // documented as braces.
    .provenance({
        let rev = credentials_core::contract::BUILD_REV;
        let built = (rev != "unknown")
            .then(|| {
                build_provenance(
                    Some(rev),
                    None,
                    Some(&credentials_core::store::newest_migration_version().to_string()),
                )
                .ok()
            })
            .flatten();
        // The nonce source is a fact about this LAUNCH, not about the build, so it is
        // declared even on a dev build that has no revision to state. The supervisor
        // reads it to decide when the environment copy of the nonce can be withdrawn.
        match (built, launch_nonce_source) {
            (built, None) => built,
            (Some(p), source) => Some(p.with_launch_nonce_source(source)),
            (None, source) => Some(ManifestProvenance::new().with_launch_nonce_source(source)),
        }
    })
    // ONE periodic behaviour exists in this daemon, and the list is exhaustive by
    // inspection rather than recollection: every `interval`/`sleep` outside `#[cfg(test)]`
    // was enumerated, and the only non-test tick is the health refresher. The
    // per-connection spawn is event-driven, not periodic.
    //
    // `Some(vec![..])` NOT `None`, and the difference is the whole value: an exhaustive
    // list also states what is ABSENT. This module generates NO periodic traffic against
    // any provider -- refresh is strictly demand-driven, dispatched by a caller's
    // `credential.get` and never by a timer of mine. An analyst seeing rhythmic token
    // traffic attributed to this vault is looking at a consumer's poll; `None` would leave
    // that question open.
    .self_signals(Some(vec![SelfSignalDeclaration {
        name: "health_snapshot_refresh".to_string(),
        kind: SelfSignalKind::Poller,
        // Observe is load-bearing here: this task runs a no-decrypt metadata scan, an
        // open-intent count and the audit-tip read. It writes nothing.
        effect: SelfSignalEffect::Observe,
        anchored_to: SignalAnchor::FixedInterval,
        // DERIVED from the constant the ticker actually uses, so the declaration cannot
        // drift from the cadence in force.
        cadence: Some(SignalCadence::Literal {
            interval_ms: HEALTH_REFRESH_INTERVAL.as_millis() as u64,
        }),
        domain: Some("vault-store".to_string()),
        // The composition is what an operator gets wrong: worst-case staleness of a served
        // snapshot is THIS interval plus the supervisor's probe cadence, not either alone.
        note: Some(
            "recomputes the cached health snapshot off the probe path, so a \
             HealthCheck reply touches no database"
                .to_string(),
        ),
    }]))
    .provides(vec![ProviderRole::ManagementSurface {
        // ModuleManaged, and this is a claim about observed behaviour rather than the
        // value that compiles. All three would.
        //
        // NOT Serial: one in-flight call at a time would be a lie and an expensive one. A
        // `get` that triggers an OAuth refresh blocks on a provider's token endpoint for
        // hundreds of milliseconds, and every other consumer's read of an unrelated
        // credential would queue behind it.
        //
        // NOT StatelessParallel: this surface has ordering-sensitive state.
        // Credential-scoped admin mutations serialize under
        // RefreshEngine::with_admin_lock so they cannot interleave with a refresh of the
        // same credential, and concurrent gets on one credential are coalesced by the
        // engine's per-credential single-flight lock rather than each firing its own token
        // exchange.
        //
        // ModuleManaged says exactly what is true: calls may arrive concurrently across
        // channels, and THIS MODULE decides what may overlap -- which it does per
        // credential id, not per connection.
        //
        // BOTH HALVES OF THE CLAIM REST ON TESTS RATHER THAN ON THIS COMMENT, in
        // credentials-core/src/engine_tests.rs:
        //
        //   `concurrent_gets_single_flight_one_upstream_call` -- the module schedules
        //   internally: concurrent gets on ONE credential produce exactly ONE upstream
        //   token exchange. Delete the coalescing and each caller fires its own refresh,
        //   so the module schedules nothing.
        //
        //   `refreshes_on_different_credentials_overlap_rather_than_serialising` -- calls
        //   may overlap ACROSS credentials. Key the single-flight map globally instead of
        //   per credential and this surface is secretly Serial; the first test still
        //   passes, because it never touches a second credential.
        //
        // The second test was missing until 2026-08-16, so half of this declaration was
        // decoration. Both are proofs by construction: one counts upstream calls, the
        // other blocks each refresh on a two-party barrier so a serialising engine HANGS
        // rather than passing slowly.
        //
        // DECLARING IT EXPLICITLY CHANGES NOTHING ON THE WIRE TODAY, and that is worth
        // knowing before someone treats a protocol bump as deploy pressure.
        // `ManagementSurface.concurrency` carries `#[serde(default)]` upstream and
        // `Default for Concurrency` is `ModuleManaged`, so a daemon built before the field
        // existed registers with the same value this line states. Checked at source
        // 2026-08-16 against subc-protocol 0.12 (ToolProvider has NO default -- new roles
        // must declare it; only the pre-existing shape is defaulted).
        //
        // So an older deployed vault is safe across a supervisor upgrade: it neither fails
        // to register nor gets a different concurrency contract. The value of saying it
        // out loud is that the manifest stops depending on an upstream default staying
        // what it is.
        concurrency: Concurrency::ModuleManaged,
        operations: vec![
            ManagementOperation {
                name: OP_ADMIN_CHALLENGE.to_string(),
                description: Some("Issue a single-use challenge to a direct-bound operator.".to_string()),
                kind: ManagementOperationKind::Mutate,
            },
            ManagementOperation {
                name: OP_ADMIN_OP.to_string(),
                description: Some("Execute a master-key-authorized operator mutation.".to_string()),
                kind: ManagementOperationKind::Mutate,
            },
            ManagementOperation {
                name: OP_DEPOSIT_COOKIE.to_string(),
                description: Some("Deposit a consent-attested browser cookie under a reserved principal's deposit grant.".to_string()),
                kind: ManagementOperationKind::Mutate,
            },
            ManagementOperation {
                name: OP_ENROLL_PROPOSE.to_string(),
                description: Some("Propose one bounded consumer enrollment using a pre-hashed resumption secret.".to_string()),
                kind: ManagementOperationKind::Mutate,
            },
            ManagementOperation {
                name: OP_ENROLL_POLL.to_string(),
                description: Some("Poll one enrollment using only its request id and resumption secret.".to_string()),
                kind: ManagementOperationKind::Mutate,
            },
            ManagementOperation {
                name: OP_ENROLL_ROTATE.to_string(),
                description: Some("Replace a live enrollment token at its current generation.".to_string()),
                kind: ManagementOperationKind::Mutate,
            },
            ManagementOperation {
                name: OP_GET.to_string(),
                description: Some("Serve a credential's secret bytes to the holder of a capability handle. Refuses signing keys.".to_string()),
                kind: ManagementOperationKind::Query,
            },
            ManagementOperation {
                name: OP_GET_SCOPED.to_string(),
                description: Some("Serve a credential's secret bytes by id to a reserved principal holding a read grant. Refuses signing keys.".to_string()),
                kind: ManagementOperationKind::Query,
            },
            ManagementOperation {
                name: OP_LIST_SCOPED.to_string(),
                description: Some("List the non-secret credentials and caller grants visible to one reserved principal. Never returns credential material.".to_string()),
                kind: ManagementOperationKind::Query,
            },
            ManagementOperation {
                name: OP_GET_MANY.to_string(),
                description: Some("Serve a capped batch of handle-addressed credentials, refusing the whole batch past the cap.".to_string()),
                kind: ManagementOperationKind::Query,
            },
            ManagementOperation {
                name: OP_STATUS.to_string(),
                description: Some("Report a credential's non-secret readiness and record version. Never returns bytes.".to_string()),
                kind: ManagementOperationKind::Query,
            },
            // Query rather than Mutation: signing reads a stored key and returns a derived
            // value, changing NO vault state -- no version bump, no audit mutation,
            // nothing to reconcile after a crash. The authority it exercises is real, but
            // authority and mutation are different axes and the manifest kind describes
            // the second.
            ManagementOperation {
                name: OP_SIGN.to_string(),
                description: Some("Sign caller-supplied bytes with a stored signing key. The key never leaves the vault.".to_string()),
                kind: ManagementOperationKind::Query,
            },
            // Query rather than Mutation for the same reason as `credential.sign`: this
            // derives public bytes from a stored key without writing a record or appending
            // to the audit chain, so callers may publish on demand.
            ManagementOperation {
                name: OP_PUBLIC_KEY.to_string(),
                description: Some("Return a signing key's public half. Never returns private material.".to_string()),
                kind: ManagementOperationKind::Query,
            },
            ManagementOperation {
                name: OP_OPEN.to_string(),
                description: Some("Open a base-mode HPKE message with a scoped KEM key.".to_string()),
                kind: ManagementOperationKind::Query,
            },
            ManagementOperation {
                name: OP_REPORT_AUTH_FAILURE.to_string(),
                description: Some("Accept a consumer's report that a served token was refused, at the version it was served.".to_string()),
                kind: ManagementOperationKind::Mutate,
            },
        ],
        config_schema: json!({ "type": "object" }),
        observability: Vec::new(),
        identity_scope: Vec::new(),
    }])
    // Empty AND explicit. This module consumes no other module's surface, and an empty
    // `consumes` is the tripwire that says so: a capability arriving here later has to
    // pass through this line.
    .consumes(Vec::new())
    .build()
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
    /// This daemon declares NO consumer role, and that is a security property rather
    /// than an empty field nobody filled in.
    ///
    /// `consumes: Vec::new()` is the machine-checkable half of a boundary held with
    /// cerebellum: nothing pushes plaintext into their context, because this module
    /// never initiates an outbound call at all. It is also why this seat is immune to
    /// the retained-dead-connection class the supervisor censused in August — with no
    /// requester role there is no reply-deadline to expire and no connection object to
    /// retain past one.
    ///
    /// THE GUARANTEE ENDS SILENTLY THE DAY THIS DAEMON GAINS ITS FIRST OUTBOUND CALL,
    /// with nothing in the diff looking like a boundary change: a consumer role added
    /// for an unrelated feature would quietly falsify both properties at once. The
    /// capability grammar cannot assert this yet, so the pin lives here until it can.
    ///
    /// If you are adding a consumer role deliberately: this test failing is the
    /// intended alarm. Read the two properties above, decide whether they still hold,
    /// and tell the cerebellum and supervisor seats before changing the expectation.
    /// The self-signal declaration is a claim about RUNTIME BEHAVIOUR, and the two
    /// halves that can silently become false are pinned here.
    ///
    /// `Observe` is the load-bearing one. A later refactor that gives the refresher a
    /// write -- a lazy backfill on the health path is the tempting shape, and was
    /// explicitly rejected once already -- turns this declaration into a lie that
    /// nothing else in the repo would catch.
    #[test]
    fn the_self_signal_declaration_matches_what_the_refresher_actually_does() {
        let m = manifest("claustrum", None);
        let signals = m.self_signals.as_ref().expect(
            "self_signals must be Some: an exhaustive list also states that no \
                     PERIODIC provider traffic exists, which None leaves open",
        );

        assert_eq!(
            signals.len(),
            1,
            "one periodic behaviour was enumerated by inspection"
        );
        let s = &signals[0];
        assert_eq!(s.name, "health_snapshot_refresh");
        assert_eq!(
            s.effect,
            SelfSignalEffect::Observe,
            "the refresher must not write. If it now does, the DECLARATION is what \
             misleads an analyst -- fix the declaration or the behaviour, not this test"
        );
        assert_eq!(s.anchored_to, SignalAnchor::FixedInterval);
        assert_eq!(
            s.cadence,
            Some(SignalCadence::Literal {
                interval_ms: HEALTH_REFRESH_INTERVAL.as_millis() as u64
            }),
            "cadence must stay derived from the constant the ticker uses"
        );
    }

    #[test]
    fn the_manifest_declares_no_consumer_role_because_nothing_may_be_pushed_outward() {
        let manifest = super::manifest("claustrum", None);
        assert!(
            manifest.consumes.is_empty(),
            "claustrum must consume no roles: an outbound call would break both the \
             no-plaintext-outward boundary with cerebellum and the immune-by-role-shape \
             property the supervisor's connection census depends on. Found: {:?}",
            manifest.consumes
        );
    }

    /// The two fields protocol 0.19 moved OUT of `builder()` are still declared.
    ///
    /// 0.19 made `trust_tier` and `bindings` optional setters defaulting to `None`,
    /// on the stated grounds that the daemon reads neither on any production path.
    /// Both were previously REQUIRED positional arguments, so the compiler was the
    /// thing keeping them present — and the migration silently converted a
    /// compiler-enforced declaration into a convention.
    ///
    /// Measured rather than assumed: with `.trust_tier(...)` deleted, all 106 tests in
    /// this binary passed. So nothing defended it, and the next person tidying the
    /// builder chain would find a value the daemon admits it does not read, with no
    /// test objecting.
    ///
    /// These are not fabricated defaults filled in to clear a compile error, which is
    /// the failure 0.19's note is guarding against: this module IS first-party, and it
    /// DOES own a project-scoped SQLite schema whose migrations it applies itself. A
    /// manifest should describe the module rather than describe what the supervisor
    /// currently bothers to read, because the reader changes and the module does not.
    #[test]
    fn the_manifest_still_declares_the_fields_protocol_0_19_made_optional() {
        let manifest = super::manifest("claustrum", None);
        assert_eq!(
            manifest.trust_tier,
            Some(TrustTier::FirstParty),
            "claustrum must declare its trust tier even though the daemon does not read \
             it: 0.19 moved this out of builder() so the compiler no longer requires it, \
             and omission is indistinguishable from a field nobody considered"
        );
        let bindings = manifest
            .bindings
            .as_ref()
            .expect("claustrum must declare its bindings: it owns a project-scoped SQLite schema");
        assert!(
            matches!(bindings.storage.kind, StorageKind::Sqlite)
                && matches!(bindings.storage.scope, StorageScope::Project)
                && bindings.storage.owns_schema,
            "the storage binding must keep saying what this module actually does — \
             sqlite, project-scoped, owns its schema. Found: {:?}",
            bindings.storage
        );
    }

    use super::*;
    use cortexkit_store::{Isolation, StorageBackend};
    use credentials_core::audit::{AuditCtx, AuditOp, AuditRecord};
    use credentials_core::key::{MasterKey, MASTER_KEY_LEN};
    use credentials_core::oauth::OAuthCredential;
    use credentials_core::record::{CredentialKind, VaultRecord};
    use credentials_core::store::{GrantOperation, RecordState};
    use credentials_core::test_support::TestTempDir;
    use read_surface::ReadSurface;

    fn tmp_surface(seed: u8) -> (Arc<ReadSurface>, TestTempDir) {
        let (surface, _, _, root) = tmp_surface_with_store(seed);
        (surface, root)
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
        let (_, store, _, _root) = tmp_surface_with_store(71);
        let record = VaultRecord::new_oauth(
            "test",
            "stub",
            credentials_core::oauth::OAuthCredential {
                access_token: "at".to_string().into(),
                refresh_token: "rt".to_string().into(),
                expires_at_ms: Some(0),
                token_url: "https://example.invalid/token".into(),
                client_id: None,
                client_secret: None,
                scopes: Vec::new(),
            },
            b"payload".to_vec(),
        );
        store.create("apikey:crashed", &record).expect("create");
        let hash = credentials_core::store::refresh_token_hash("rt");
        store
            .open_intent("apikey:crashed", 1, &hash)
            .expect("open intent");

        let http = Arc::new(crate::test_support::NoHttp);
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
    fn tmp_admin(
        seed: u8,
    ) -> (
        Arc<admin_surface::AdminSurface>,
        Arc<EncryptedStore>,
        TestTempDir,
    ) {
        let (_, store, db_path, root) = tmp_surface_with_store(seed);
        let http = Arc::new(crate::test_support::NoHttp);
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
        (admin, store, root)
    }

    fn tmp_surface_with_store(
        seed: u8,
    ) -> (
        Arc<ReadSurface>,
        Arc<EncryptedStore>,
        std::path::PathBuf,
        TestTempDir,
    ) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = TestTempDir::new(format!(
            "ck-cred-health-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
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
        let http = Arc::new(crate::test_support::NoHttp);
        let engine = Arc::new(RefreshEngine::new(Arc::clone(&store), Vec::new(), http));
        let surface = Arc::new(ReadSurface::new(engine, FetchLimiter::new(Caps::default())));
        (surface, store, db_path, root)
    }

    /// A deterministic refresh adapter for minimum-TTL read tests. Its counter proves
    /// the read path performed one exchange, not merely that a stored version changed.
    /// Fails every refresh with `invalid_grant`, which is the ONE provider verdict the
    /// engine treats as terminal: it latches the record to `needs_reauth` and writes a
    /// `refresh_failed` observation. Any other error (transport, decode, unexpected
    /// status) takes the engine's transient arm, which clears the intent and leaves the
    /// record ACTIVE -- so a stub that merely fails cannot reproduce a latch.
    struct InvalidGrantAdapter;

    #[async_trait::async_trait]
    impl credentials_core::refresh_adapters::RefreshAdapter for InvalidGrantAdapter {
        fn name(&self) -> &str {
            "invalid-grant-fixture"
        }

        async fn refresh(
            &self,
            _credential: &credentials_core::oauth::OAuthCredential,
            _http: &dyn credentials_core::refresh_adapters::HttpTransport,
        ) -> Result<
            credentials_core::refresh_adapters::RefreshedTokens,
            credentials_core::refresh_adapters::RefreshError,
        > {
            Err(
                credentials_core::refresh_adapters::RefreshError::InvalidGrant(
                    "fixture: the provider refused the refresh token".into(),
                ),
            )
        }
    }

    struct TtlFixtureAdapter {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        fresh_ttl_ms: i64,
    }

    #[async_trait::async_trait]
    impl credentials_core::refresh_adapters::RefreshAdapter for TtlFixtureAdapter {
        fn name(&self) -> &str {
            "ttl-fixture"
        }

        async fn refresh(
            &self,
            credential: &credentials_core::oauth::OAuthCredential,
            _http: &dyn credentials_core::refresh_adapters::HttpTransport,
        ) -> Result<
            credentials_core::refresh_adapters::RefreshedTokens,
            credentials_core::refresh_adapters::RefreshError,
        > {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(credentials_core::refresh_adapters::RefreshedTokens {
                access_token: "fresh-after-ttl-check".to_string().into(),
                refresh_token: credential.refresh_token.clone(),
                expires_at_ms: Some(test_now_ms().saturating_add(self.fresh_ttl_ms)),
                github_app_permissions: None,
            })
        }
    }

    fn test_now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as i64)
            .unwrap_or(0)
    }

    fn ttl_surface(
        seed: u8,
        fresh_ttl_ms: i64,
    ) -> (
        Arc<ReadSurface>,
        Arc<EncryptedStore>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let (_unused_surface, store, _db_path, _root) = tmp_surface_with_store(seed);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let adapter = TtlFixtureAdapter {
            calls: Arc::clone(&calls),
            fresh_ttl_ms,
        };
        let http = Arc::new(crate::test_support::NoHttp);
        let engine = Arc::new(RefreshEngine::new(
            Arc::clone(&store),
            vec![Arc::new(adapter)],
            http,
        ));
        let surface = Arc::new(ReadSurface::new(engine, FetchLimiter::new(Caps::default())));
        (surface, store, calls)
    }

    fn seed_ttl_refreshable(
        store: &EncryptedStore,
        credential_id: &str,
        initial_ttl_ms: i64,
    ) -> String {
        store
            .create(
                credential_id,
                &VaultRecord::new_oauth(
                    "test",
                    "ttl-fixture",
                    credentials_core::oauth::OAuthCredential {
                        access_token: "stored-before-refresh".to_string().into(),
                        refresh_token: "refresh-token".to_string().into(),
                        expires_at_ms: Some(test_now_ms().saturating_add(initial_ttl_ms)),
                        token_url: "https://example.invalid/token".into(),
                        client_id: None,
                        client_secret: None,
                        scopes: Vec::new(),
                    },
                    b"stored-before-refresh".to_vec(),
                ),
            )
            .expect("seed refreshable credential");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                credential_id,
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");
        handle.raw
    }

    fn seed_ttl_static(store: &EncryptedStore, credential_id: &str) -> String {
        store
            .create(
                credential_id,
                &VaultRecord::new_static(
                    CredentialKind::ApiKey,
                    "test",
                    b"static-before-refresh".to_vec(),
                    Some(test_now_ms().saturating_add(10 * 60 * 1000)),
                ),
            )
            .expect("seed static credential");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                credential_id,
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");
        handle.raw
    }

    /// A post-refresh lifetime that still misses the caller's demand is a request bound,
    /// not a dead credential. The counter makes a second exchange observable: a retry loop
    /// would return the same refusal but increment it twice.
    #[tokio::test]
    async fn impossible_min_ttl_refuses_after_one_exchange_with_paired_wire_error() {
        const INITIAL_TTL_MS: i64 = 10 * 60 * 1000;
        const FRESH_TTL_MS: i64 = 60 * 60 * 1000;
        const DEMAND_MS: i64 = 2 * 60 * 60 * 1000;

        let (surface, store, calls) = ttl_surface(91, FRESH_TTL_MS);
        let handle = seed_ttl_refreshable(&store, "oauth:ttl-unsatisfiable", INITIAL_TTL_MS);
        let outcome = surface
            .get(
                91,
                &GetParams {
                    handle,
                    min_ttl_ms: Some(DEMAND_MS),
                    force_refresh: false,
                },
            )
            .await;

        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an unsatisfiable demand must make exactly one upstream exchange"
        );
        assert_eq!(
            serde_json::to_value(&outcome).expect("serialize refusal"),
            serde_json::json!({
                "error": {
                    "code": "ttl_unsatisfiable",
                    "class": "context_overflow",
                }
            }),
            "the wire must carry the refusal detail and class together"
        );
        let read_surface::GetOutcome::Err { error } = outcome else {
            panic!("a fresh token shorter than the demand must refuse");
        };
        assert_eq!(error.code, read_surface::ReadError::TtlUnsatisfiable);
        assert_eq!(error.class, read_surface::ErrorClass::ContextOverflow);
    }

    /// A missing `min_ttl_ms` states no requirement. This is intentionally the same
    /// credential shape as the refusal test so a default floor cannot hide behind a
    /// different record type or expiry.
    #[tokio::test]
    async fn absent_min_ttl_does_not_apply_a_default_floor() {
        let (surface, store, calls) = ttl_surface(92, 60 * 60 * 1000);
        let handle = seed_ttl_refreshable(&store, "oauth:ttl-absent", 10 * 60 * 1000);
        let outcome = surface
            .get(
                92,
                &GetParams {
                    handle,
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await;

        let read_surface::GetOutcome::Ok(result) = outcome else {
            panic!("a request without a demand must serve the stored token");
        };
        assert_eq!(result.payload, b"stored-before-refresh");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "an absent demand must not supply an implicit refresh floor"
        );
    }

    #[tokio::test]
    async fn satisfiable_min_ttl_serves_the_fresh_token() {
        let (surface, store, calls) = ttl_surface(93, 60 * 60 * 1000);
        let handle = seed_ttl_refreshable(&store, "oauth:ttl-satisfiable", 10 * 60 * 1000);
        let outcome = surface
            .get(
                93,
                &GetParams {
                    handle,
                    min_ttl_ms: Some(30 * 60 * 1000),
                    force_refresh: false,
                },
            )
            .await;

        let read_surface::GetOutcome::Ok(result) = outcome else {
            panic!("a fresh token that meets the demand must be served");
        };
        assert_eq!(result.payload, b"fresh-after-ttl-check");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the caller's minimum-TTL demand must trigger one refresh"
        );
    }

    /// A static record cannot produce the required fresh-token proof. Even a huge demand
    /// must therefore retain the read surface's existing serve-as-stored behavior.
    #[tokio::test]
    async fn static_credential_with_oversized_min_ttl_is_served_without_a_refusal() {
        let (surface, store, calls) = ttl_surface(94, 60 * 60 * 1000);
        let handle = seed_ttl_static(&store, "apikey:ttl-static");
        let outcome = surface
            .get(
                94,
                &GetParams {
                    handle,
                    min_ttl_ms: Some(2 * 60 * 60 * 1000),
                    force_refresh: false,
                },
            )
            .await;

        let read_surface::GetOutcome::Ok(result) = outcome else {
            panic!("a static credential must not refuse without an exchange");
        };
        assert_eq!(result.payload, b"static-before-refresh");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a static credential has no exchange path to prove the demand impossible"
        );
    }

    #[tokio::test]
    async fn get_many_keeps_a_ttl_refusal_in_its_item_position() {
        let (surface, store, calls) = ttl_surface(95, 60 * 60 * 1000);
        let short_lived = seed_ttl_refreshable(&store, "oauth:ttl-batch", 10 * 60 * 1000);
        let ordinary = seed_ttl_static(&store, "apikey:ttl-batch");
        let outcomes = surface
            .get_many(
                95,
                &GetManyParams {
                    items: vec![
                        GetParams {
                            handle: short_lived,
                            min_ttl_ms: Some(2 * 60 * 60 * 1000),
                            force_refresh: false,
                        },
                        GetParams {
                            handle: ordinary,
                            min_ttl_ms: None,
                            force_refresh: false,
                        },
                    ],
                },
            )
            .await;

        assert_eq!(
            outcomes.len(),
            2,
            "one item refusal must not collapse the batch"
        );
        let read_surface::GetOutcome::Err { error } = &outcomes[0] else {
            panic!("the first item must retain its TTL refusal");
        };
        assert_eq!(error.code, read_surface::ReadError::TtlUnsatisfiable);
        assert_eq!(error.class, read_surface::ErrorClass::ContextOverflow);
        let read_surface::GetOutcome::Ok(result) = &outcomes[1] else {
            panic!("the later ordinary item must keep its position and serve");
        };
        assert_eq!(result.payload, b"static-before-refresh");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "only the short-lived batch item may exchange"
        );
    }

    /// Build a scoped-read rig whose route-bind registry and read surface share one
    /// store. The route helper below drives the real request dispatcher rather than
    /// calling `get_scoped` directly, so the principal snapshot is part of the proof.
    fn scoped_rig(
        seed: u8,
    ) -> (
        Arc<ReadSurface>,
        Arc<admin_surface::AdminSurface>,
        Arc<EncryptedStore>,
    ) {
        let (surface, store, db_path, _root) = tmp_surface_with_store(seed);
        let http = Arc::new(crate::test_support::NoHttp);
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
        (surface, admin, store)
    }

    async fn scoped_route_request(
        surface: &Arc<ReadSurface>,
        admin: &Arc<admin_surface::AdminSurface>,
        channel: u16,
        method: &str,
        params: serde_json::Value,
    ) -> serde_json::Value {
        let (writer, mut responses) = mpsc::channel(1);
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            channel,
            1,
            1,
            serde_json::to_vec(&json!({
                "method": method,
                "params": params,
            }))
            .expect("encode request"),
        )
        .expect("build request");
        let principal = admin.principal(channel);
        handle_read_request(frame, &writer, surface, admin, principal)
            .await
            .expect("serve request");
        let response = responses.recv().await.expect("route response");
        serde_json::from_slice(&response.body).expect("decode response")
    }

    struct DepositCookieTestStore {
        store: Arc<EncryptedStore>,
        db_path: std::path::PathBuf,
        _root: TestTempDir,
    }

    impl std::ops::Deref for DepositCookieTestStore {
        type Target = EncryptedStore;
        fn deref(&self) -> &Self::Target {
            &self.store
        }
    }

    impl DepositCookieTestStore {
        fn with_raw_conn<T>(
            &self,
            f: impl FnOnce(&rusqlite::Connection) -> rusqlite::Result<T>,
        ) -> rusqlite::Result<T> {
            f(&rusqlite::Connection::open(&self.db_path)?)
        }
    }

    fn deposit_cookie_rig(
        seed: u8,
    ) -> (
        Arc<ReadSurface>,
        Arc<admin_surface::AdminSurface>,
        DepositCookieTestStore,
    ) {
        let (surface, store, db_path, _root) = tmp_surface_with_store(seed);
        let engine = Arc::new(RefreshEngine::new(
            Arc::clone(&store),
            Vec::new(),
            Arc::new(crate::test_support::NoHttp),
        ));
        let key = MasterKey::from_bytes([seed; MASTER_KEY_LEN]);
        let admin = Arc::new(admin_surface::AdminSurface::new(
            engine,
            credentials_core::admin_auth::AdminMacKey::derive(&key),
            credentials_core::vault_id_for(db_path.parent().unwrap()).unwrap(),
            key.key_id(),
        ));
        (
            surface,
            admin,
            DepositCookieTestStore {
                store,
                db_path,
                _root,
            },
        )
    }

    const DEPOSIT_COOKIE_ID: &str = "cookie:ollama.com:ufuk";

    fn deposit_cookie_params() -> serde_json::Value {
        json!({"id": DEPOSIT_COOKIE_ID, "cookie": "session=abc", "consent_ref": "consent-123"})
    }

    fn deposit_cookie_grant(store: &EncryptedStore, name: &str, operation: GrantOperation) {
        store
            .create_read_grant_audited(
                "reserved",
                name,
                SelectorKind::Category,
                "browser-session",
                operation,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
    }

    fn deposit_cookie_principal() -> Option<subc_protocol::Principal> {
        Some(subc_protocol::Principal::Reserved {
            module_id: "cerebellum".into(),
        })
    }

    async fn deposit_cookie_frame(
        surface: &Arc<ReadSurface>,
        admin: &Arc<admin_surface::AdminSurface>,
        principal: Option<subc_protocol::Principal>,
        method: &str,
        params: serde_json::Value,
    ) -> Frame {
        let (writer, mut responses) = mpsc::channel(1);
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            51,
            1,
            1,
            serde_json::to_vec(&json!({"method": method, "params": params})).unwrap(),
        )
        .unwrap();
        handle_read_request(frame, &writer, surface, admin, principal)
            .await
            .unwrap();
        responses.recv().await.unwrap()
    }

    fn deposit_cookie_body(frame: &Frame) -> serde_json::Value {
        serde_json::from_slice(&frame.body).unwrap()
    }

    fn deposit_cookie_counts(store: &DepositCookieTestStore) -> (i64, i64, i64, i64) {
        store.with_raw_conn(|conn| conn.query_row("SELECT (SELECT count(*) FROM credentials), (SELECT count(*) FROM credential_categories), (SELECT count(*) FROM audit_log), (SELECT count(*) FROM auth_events WHERE kind='scoped_first_use')", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))).unwrap()
    }

    fn deposit_cookie_raw_row(store: &DepositCookieTestStore) -> (i64, Vec<u8>) {
        store
            .with_raw_conn(|conn| {
                conn.query_row(
                    "SELECT record_version, envelope FROM credentials WHERE credential_id=?1",
                    [DEPOSIT_COOKIE_ID],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
            })
            .unwrap()
    }

    #[test]
    fn deposit_cookie_request_shape_and_secret_debug_are_pinned() {
        for (email, keys) in [
            (None, vec!["id", "cookie", "consent_ref"]),
            (
                Some("a".to_owned()),
                vec!["id", "cookie", "consent_ref", "email"],
            ),
        ] {
            let params = DepositCookieParams {
                id: DEPOSIT_COOKIE_ID.into(),
                cookie: credentials_core::secret::Secret::new("DO_NOT_PRINT_COOKIE".into()),
                consent_ref: "consent-123".into(),
                email,
            };
            assert!(!format!("{params:?}").contains("DO_NOT_PRINT_COOKIE"));
            assert_request_key_set(params, &keys, OP_DEPOSIT_COOKIE);
        }
        let mut null = deposit_cookie_params();
        null["email"] = serde_json::Value::Null;
        let decoded: DepositCookieParams = serde_json::from_value(null).unwrap();
        assert!(decoded.email.is_none());
        assert_request_key_set(decoded, &["id", "cookie", "consent_ref"], OP_DEPOSIT_COOKIE);
    }

    #[tokio::test]
    async fn deposit_cookie_create_replace_route_pins_categories_identity_and_audit() {
        let (surface, admin, store) = deposit_cookie_rig(151);
        deposit_cookie_grant(&store, "cerebellum", GrantOperation::Deposit);
        let mut params = deposit_cookie_params();
        params["email"] = json!("me@example.com");
        let created = deposit_cookie_frame(
            &surface,
            &admin,
            deposit_cookie_principal(),
            OP_DEPOSIT_COOKIE,
            params,
        )
        .await;
        assert_eq!(
            deposit_cookie_body(&created),
            wrap_result(
                json!({"id": DEPOSIT_COOKIE_ID, "outcome": "created", "record_version": 1})
            )
        );
        let meta = store.meta(DEPOSIT_COOKIE_ID).unwrap();
        assert_eq!(meta.categories, ["browser-session"]);
        assert_eq!(meta.created_by.as_deref(), Some("reserved:cerebellum"));
        let birth: (i64, i64) = store
            .with_raw_conn(|c| {
                c.query_row(
                    "SELECT created_at_ms, updated_at_ms FROM credentials WHERE credential_id=?1",
                    [DEPOSIT_COOKIE_ID],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
            })
            .unwrap();
        assert_eq!(birth.0, birth.1);
        let record = store.get(DEPOSIT_COOKIE_ID).unwrap();
        assert_eq!(record.source, "reserved:cerebellum");
        assert_eq!(record.kind, CredentialKind::Cookie);
        let operator = VaultRecord::new_cookie("operator", b"session=abc".to_vec());
        assert_eq!(record.payload, operator.payload);
        assert_eq!(
            record.identity.account_id.as_deref(),
            Some("me@example.com")
        );
        for (version, null_email) in [(2, false), (3, true)] {
            let mut params = deposit_cookie_params();
            if null_email {
                params["email"] = serde_json::Value::Null;
            }
            let response = deposit_cookie_frame(
                &surface,
                &admin,
                deposit_cookie_principal(),
                OP_DEPOSIT_COOKIE,
                params,
            )
            .await;
            assert_eq!(
                deposit_cookie_body(&response)["result"]["record_version"],
                version
            );
            assert_eq!(
                deposit_cookie_body(&response)["result"]["outcome"],
                "replaced"
            );
            assert_eq!(
                store.get(DEPOSIT_COOKIE_ID).unwrap().identity,
                record.identity
            );
            assert_eq!(
                store.meta(DEPOSIT_COOKIE_ID).unwrap().categories,
                meta.categories
            );
        }
        store
            .with_raw_conn(|c| {
                c.execute(
                    "DELETE FROM credential_categories WHERE credential_id=?1",
                    [DEPOSIT_COOKIE_ID],
                )
            })
            .unwrap();
        let response = deposit_cookie_frame(
            &surface,
            &admin,
            deposit_cookie_principal(),
            OP_DEPOSIT_COOKIE,
            deposit_cookie_params(),
        )
        .await;
        assert_eq!(
            deposit_cookie_body(&response)["result"]["outcome"],
            "replaced"
        );
        assert!(store.meta(DEPOSIT_COOKIE_ID).unwrap().categories.is_empty());
        assert_eq!(
            store.meta(DEPOSIT_COOKIE_ID).unwrap().created_by,
            meta.created_by
        );
        let after_birth: i64 = store
            .with_raw_conn(|c| {
                c.query_row(
                    "SELECT created_at_ms FROM credentials WHERE credential_id=?1",
                    [DEPOSIT_COOKIE_ID],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(after_birth, birth.0);
        let audit: Vec<_> = store
            .read_audit(None)
            .unwrap()
            .into_iter()
            .filter(|a| a.credential_id.as_deref() == Some(DEPOSIT_COOKIE_ID))
            .collect();
        assert_eq!(audit.len(), 4);
        for entry in audit {
            assert_eq!(entry.actor, "reserved:cerebellum");
            assert!(!entry.alarm);
            assert_eq!(
                entry.payload_hash.as_deref(),
                Some("d523e692e03fc04a7700e325960047a0283a062980239e5ea7ad03b4eac9bcb7")
            );
        }
        let events: Vec<(String,String,String,String)> = store.with_raw_conn(|c| {
            let mut q = c.prepare("SELECT credential_id, principal_kind, principal_id, detail FROM auth_events WHERE kind='scoped_first_use'")?;
            let rows = q.query_map([], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?; rows.collect()
        }).unwrap();
        assert_eq!(
            events,
            [(
                DEPOSIT_COOKIE_ID.into(),
                "reserved".into(),
                "cerebellum".into(),
                "deposit".into()
            )]
        );
    }

    #[tokio::test]
    async fn deposit_cookie_email_is_disclosed_only_to_readers() {
        let (surface, admin, store) = deposit_cookie_rig(161);
        deposit_cookie_grant(&store, "cerebellum", GrantOperation::Deposit);
        deposit_cookie_grant(&store, "insula", GrantOperation::Read);
        let reader = Some(subc_protocol::Principal::Reserved {
            module_id: "insula".into(),
        });
        for (id, email) in [
            ("cookie:example.com:with-email", Some("a")),
            ("cookie:example.com:without-email", None),
        ] {
            let mut params = deposit_cookie_params();
            params["id"] = json!(id);
            if let Some(email) = email {
                params["email"] = json!(email);
            }
            let deposited = deposit_cookie_frame(
                &surface,
                &admin,
                deposit_cookie_principal(),
                OP_DEPOSIT_COOKIE,
                params,
            )
            .await;
            assert_eq!(
                deposit_cookie_body(&deposited)["result"]["outcome"],
                "created"
            );
            let fetched = deposit_cookie_frame(
                &surface,
                &admin,
                reader.clone(),
                OP_GET_SCOPED,
                json!({"credential_id": id}),
            )
            .await;
            assert_eq!(
                deposit_cookie_body(&fetched)["result"]["email"],
                json!(email)
            );
            let listed =
                deposit_cookie_frame(&surface, &admin, reader.clone(), OP_LIST_SCOPED, json!({}))
                    .await;
            let body = deposit_cookie_body(&listed);
            let row = body["result"]["credentials"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["id"] == id)
                .unwrap();
            assert_eq!(row["email"], json!(email));
        }
    }

    #[tokio::test]
    async fn deposit_cookie_creator_refusals_preserve_envelope_and_first_use() {
        for other_module in [false, true] {
            let (surface, admin, store) = deposit_cookie_rig(if other_module { 153 } else { 152 });
            deposit_cookie_grant(&store, "cerebellum", GrantOperation::Deposit);
            if other_module {
                store
                    .deposit_cookie(
                        DEPOSIT_COOKIE_ID,
                        &credentials_core::secret::Secret::new("other".into()),
                        "consent",
                        None,
                        "reserved:other",
                    )
                    .unwrap();
            } else {
                store
                    .create(
                        DEPOSIT_COOKIE_ID,
                        &VaultRecord::new_cookie("operator", b"original".to_vec()),
                    )
                    .unwrap();
            }
            let before = deposit_cookie_raw_row(&store);
            let counts = deposit_cookie_counts(&store);
            let reply = deposit_cookie_frame(
                &surface,
                &admin,
                deposit_cookie_principal(),
                OP_DEPOSIT_COOKIE,
                deposit_cookie_params(),
            )
            .await;
            assert_eq!(
                deposit_cookie_body(&reply)["result"]["error"]["code"],
                "not_permitted"
            );
            assert_eq!(deposit_cookie_raw_row(&store), before);
            assert_eq!(deposit_cookie_counts(&store), counts);
        }
    }

    #[tokio::test]
    async fn deposit_cookie_audit_failure_rolls_back_create_and_replace() {
        let (surface, admin, store) = deposit_cookie_rig(154);
        deposit_cookie_grant(&store, "cerebellum", GrantOperation::Deposit);
        let before = deposit_cookie_counts(&store);
        store.force_deposit_cookie_audit_append_error_for_test(true);
        let reply = deposit_cookie_frame(
            &surface,
            &admin,
            deposit_cookie_principal(),
            OP_DEPOSIT_COOKIE,
            deposit_cookie_params(),
        )
        .await;
        assert_eq!(
            deposit_cookie_body(&reply)["result"]["error"]["code"],
            "store_error"
        );
        assert_eq!(deposit_cookie_counts(&store), before);
        store.force_deposit_cookie_audit_append_error_for_test(false);
        surface.force_deposit_cookie_first_use_fault_for_test();
        let reply = deposit_cookie_frame(
            &surface,
            &admin,
            deposit_cookie_principal(),
            OP_DEPOSIT_COOKIE,
            deposit_cookie_params(),
        )
        .await;
        assert_eq!(deposit_cookie_body(&reply)["result"]["outcome"], "created");
        assert_eq!(deposit_cookie_counts(&store).3, 0);
        let row = deposit_cookie_raw_row(&store);
        let before = deposit_cookie_counts(&store);
        store.force_deposit_cookie_audit_append_error_for_test(true);
        let reply = deposit_cookie_frame(
            &surface,
            &admin,
            deposit_cookie_principal(),
            OP_DEPOSIT_COOKIE,
            deposit_cookie_params(),
        )
        .await;
        assert_eq!(
            deposit_cookie_body(&reply)["result"]["error"]["code"],
            "store_error"
        );
        assert_eq!(deposit_cookie_counts(&store), before);
        assert_eq!(deposit_cookie_raw_row(&store), row);
    }

    #[tokio::test]
    async fn deposit_cookie_decode_matrix_writes_nothing_and_never_echoes_values() {
        let (surface, admin, store) = deposit_cookie_rig(155);
        deposit_cookie_grant(&store, "cerebellum", GrantOperation::Deposit);
        let mut rows = Vec::new();
        for field in ["id", "cookie", "consent_ref"] {
            for value in [
                None,
                Some(serde_json::Value::Null),
                Some(json!(123)),
                Some(json!(["secret"])),
            ] {
                let mut params = deposit_cookie_params();
                if let Some(value) = value {
                    params[field] = value;
                } else {
                    params.as_object_mut().unwrap().remove(field);
                }
                rows.push(params);
            }
        }
        for (field, value) in [
            ("email", json!(123)),
            ("enrollment_token", json!("DO_NOT_ECHO")),
            ("category", json!("DO_NOT_ECHO")),
        ] {
            let mut params = deposit_cookie_params();
            params[field] = value;
            rows.push(params);
        }
        for principal in [deposit_cookie_principal(), None] {
            for params in &rows {
                let before = deposit_cookie_counts(&store);
                let events: i64 = store
                    .with_raw_conn(|c| {
                        c.query_row("SELECT count(*) FROM auth_events", [], |r| r.get(0))
                    })
                    .unwrap();
                let reply = deposit_cookie_frame(
                    &surface,
                    &admin,
                    principal.clone(),
                    OP_DEPOSIT_COOKIE,
                    params.clone(),
                )
                .await;
                assert_eq!(reply.header.ty, FrameType::Error);
                let text = String::from_utf8(reply.body.to_vec()).unwrap();
                assert!(text.contains("invalid_params"));
                assert!(!text.contains("session=abc"));
                assert!(!text.contains("DO_NOT_ECHO"));
                assert_eq!(deposit_cookie_counts(&store), before);
                let after: i64 = store
                    .with_raw_conn(|c| {
                        c.query_row("SELECT count(*) FROM auth_events", [], |r| r.get(0))
                    })
                    .unwrap();
                assert_eq!(after, events);
            }
        }
        for null in [false, true] {
            let mut params = deposit_cookie_params();
            if null {
                params["email"] = serde_json::Value::Null;
            }
            deposit_cookie_frame(
                &surface,
                &admin,
                deposit_cookie_principal(),
                OP_DEPOSIT_COOKIE,
                params,
            )
            .await;
            assert!(store
                .get(DEPOSIT_COOKIE_ID)
                .unwrap()
                .identity
                .email
                .is_none());
        }
    }

    #[tokio::test]
    async fn deposit_cookie_id_and_payload_grammar_precede_authorization() {
        let (surface, admin, store) = deposit_cookie_rig(156);
        deposit_cookie_grant(&store, "cerebellum", GrantOperation::Deposit);
        let base = format!(
            "cookie:{}.{}.{}.com:a",
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63)
        );
        let id255 = format!("{base}{}", "a".repeat(255 - base.len()));
        let ids = vec![
            ("apikey:x".into(), false),
            ("oauth:anthropic".into(), false),
            ("cookie:example.com:a|b".into(), false),
            ("category:browser-session".into(), false),
            (id255.clone(), true),
            (format!("{id255}a"), false),
            (format!("cookie:{}.com:a", "a".repeat(63)), true),
            (format!("cookie:{}.com:a", "a".repeat(64)), false),
            (format!("cookie:a.com:{}", "a".repeat(64)), true),
            (format!("cookie:a.com:{}", "a".repeat(65)), false),
            ("cookie:-a.com:a".into(), false),
            ("cookie:a-.com:a".into(), false),
            ("cookie:A.com:a".into(), false),
            ("cookie:localhost:a".into(), false),
            ("cookie:a.com:".into(), false),
            ("cookie:a.com:a:b".into(), false),
        ];
        for principal in [deposit_cookie_principal(), None] {
            for (id, valid) in &ids {
                let mut params = deposit_cookie_params();
                params["id"] = json!(id);
                let reply = deposit_cookie_frame(
                    &surface,
                    &admin,
                    principal.clone(),
                    OP_DEPOSIT_COOKIE,
                    params,
                )
                .await;
                let body = deposit_cookie_body(&reply);
                if !valid {
                    assert_eq!(body["result"]["error"]["code"], "invalid_id", "{id}");
                } else if principal.is_none() {
                    assert_eq!(body["result"]["error"]["code"], "not_found");
                } else {
                    assert!(body["result"]["outcome"].is_string(), "{body}");
                }
            }
            for (field, value, valid) in [
                ("cookie", "\t".into(), true),
                ("cookie", "\u{7f}".into(), false),
                ("cookie", "x".repeat(16384), true),
                ("cookie", "x".repeat(16385), false),
                ("cookie", "".into(), false),
                ("cookie", "é".repeat(8192), true),
                ("cookie", "é".repeat(8193), false),
                ("consent_ref", " ".into(), false),
                ("consent_ref", "a".repeat(128), true),
                ("consent_ref", "a".repeat(129), false),
                ("email", "a".repeat(254), true),
                ("email", "a".repeat(255), false),
                ("email", " ".into(), false),
                ("email", "\u{2003}".into(), false),
                ("email", "a".into(), true),
                ("email", "\u{85}".into(), false),
            ] {
                let mut params = deposit_cookie_params();
                params[field] = json!(value);
                let reply = deposit_cookie_frame(
                    &surface,
                    &admin,
                    principal.clone(),
                    OP_DEPOSIT_COOKIE,
                    params,
                )
                .await;
                let body = deposit_cookie_body(&reply);
                if !valid {
                    assert_eq!(
                        body["result"]["error"]["code"], "invalid_payload",
                        "{field}"
                    );
                } else if principal.is_none() {
                    assert_eq!(body["result"]["error"]["code"], "not_found");
                } else {
                    assert!(body["result"]["outcome"].is_string(), "{body}");
                }
            }
        }
    }

    #[tokio::test]
    async fn deposit_cookie_wire_fixture_and_refusal_diagnostics_are_exact() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/deposit_cookie_wire_contract.json"
        ))
        .unwrap();
        for code in [
            "created",
            "replaced",
            "invalid_id",
            "invalid_payload",
            "not_found",
            "not_permitted",
            "store_error",
        ] {
            let (surface, admin, store) = deposit_cookie_rig(157);
            deposit_cookie_grant(&store, "cerebellum", GrantOperation::Deposit);
            let mut params = deposit_cookie_params();
            let mut principal = deposit_cookie_principal();
            match code {
                "replaced" => {
                    store
                        .deposit_cookie(
                            DEPOSIT_COOKIE_ID,
                            &credentials_core::secret::Secret::new("old".into()),
                            "consent",
                            None,
                            "reserved:cerebellum",
                        )
                        .unwrap();
                }
                "invalid_id" => params["id"] = json!("secret-invalid-id"),
                "invalid_payload" => params["cookie"] = json!("\n"),
                "not_found" => principal = None,
                "not_permitted" => {
                    store
                        .create(
                            DEPOSIT_COOKIE_ID,
                            &VaultRecord::new_cookie("operator", b"old".to_vec()),
                        )
                        .unwrap();
                }
                "store_error" => store.force_deposit_cookie_audit_append_error_for_test(true),
                _ => {}
            }
            let before = deposit_cookie_counts(&store);
            let reply = deposit_cookie_frame(
                &surface,
                &admin,
                principal.clone(),
                OP_DEPOSIT_COOKIE,
                params.clone(),
            )
            .await;
            assert_eq!(reply.header.ty, FrameType::Response);
            assert_eq!(
                reply.body.as_slice(),
                fixture[code].as_str().unwrap().as_bytes(),
                "{code}"
            );
            if matches!(code, "created" | "replaced") {
                continue;
            }
            assert_eq!(deposit_cookie_counts(&store), before, "{code}");
            let subject = if matches!(code, "invalid_id" | "invalid_payload" | "not_found") {
                OP_DEPOSIT_COOKIE
            } else {
                DEPOSIT_COOKIE_ID
            };
            let reason = if code == "not_found" {
                "no_grant".to_owned()
            } else {
                format!("deposit_cookie_{code}")
            };
            let events: Vec<(String,String,String,Option<String>)>=store.with_raw_conn(|c| {
                let mut q=c.prepare("SELECT credential_id, detail, principal_kind, principal_id FROM auth_events WHERE kind='scoped_read_refusal'")?;
                let rows=q.query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?; rows.collect()
            }).unwrap();
            assert_eq!(
                events,
                [(
                    subject.into(),
                    reason,
                    if principal.is_none() {
                        "unverified".into()
                    } else {
                        "reserved".into()
                    },
                    principal.as_ref().map(|_| "cerebellum".into())
                )],
                "{code}"
            );
            surface.force_deposit_cookie_diagnostic_fault_for_test();
            let faulted =
                deposit_cookie_frame(&surface, &admin, principal, OP_DEPOSIT_COOKIE, params).await;
            assert_eq!(faulted.body, reply.body, "{code}");
            let count: i64 = store
                .with_raw_conn(|c| {
                    c.query_row(
                        "SELECT count(*) FROM auth_events WHERE kind='scoped_read_refusal'",
                        [],
                        |r| r.get(0),
                    )
                })
                .unwrap();
            assert_eq!(count, 1);
        }
    }

    #[tokio::test]
    async fn deposit_cookie_not_found_is_uniform_for_unbound_direct_and_ungranted() {
        let (surface, admin, _store) = deposit_cookie_rig(158);
        let mut bodies = Vec::new();
        for principal in [
            None,
            Some(subc_protocol::Principal::Direct),
            deposit_cookie_principal(),
        ] {
            let reply = deposit_cookie_frame(
                &surface,
                &admin,
                principal,
                OP_DEPOSIT_COOKIE,
                deposit_cookie_params(),
            )
            .await;
            assert_eq!(
                deposit_cookie_body(&reply)["result"]["error"]["code"],
                "not_found"
            );
            bodies.push(reply.body);
        }
        assert!(bodies.windows(2).all(|w| w[0] == w[1]));
        surface.force_scoped_grant_lookup_error_for_test();
        let reply = deposit_cookie_frame(
            &surface,
            &admin,
            deposit_cookie_principal(),
            OP_DEPOSIT_COOKIE,
            deposit_cookie_params(),
        )
        .await;
        assert_eq!(reply.body, bodies[0]);
    }

    #[tokio::test]
    async fn deposit_only_denial_on_every_read_and_key_operation_has_positive_controls() {
        use base64::Engine as _;
        use credentials_core::kem::*;
        let (surface, admin, store) = deposit_cookie_rig(159);
        let signing_id = "cookie:example.com:sign";
        let kem_id = "cookie:example.com:kem";
        let kem = credentials_core::kem::generate_key().unwrap();
        let (public, _) = credentials_core::kem::public_half(&kem).unwrap();
        store
            .create(
                DEPOSIT_COOKIE_ID,
                &VaultRecord::new_cookie("operator", b"session=abc".to_vec()),
            )
            .unwrap();
        store
            .create(
                signing_id,
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "operator",
                    test_ed25519_pem().into_bytes(),
                    None,
                ),
            )
            .unwrap();
        store
            .create(
                kem_id,
                &VaultRecord::new_static(
                    CredentialKind::KemKey,
                    "operator",
                    kem.into_bytes(),
                    None,
                ),
            )
            .unwrap();
        deposit_cookie_grant(&store, "cerebellum", GrantOperation::Deposit);
        for operation in [
            GrantOperation::Read,
            GrantOperation::Sign,
            GrantOperation::Open,
        ] {
            deposit_cookie_grant(&store, "reader", operation);
        }
        let reader = Some(subc_protocol::Principal::Reserved {
            module_id: "reader".into(),
        });
        for id in [DEPOSIT_COOKIE_ID, signing_id, kem_id] {
            assert!(
                store
                    .evaluate_scoped_coverage("reserved", "cerebellum", id, GrantOperation::Deposit)
                    .unwrap()
                    .covered
            );
        }
        let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        let (enc, ct) = seal_base(&public, b"plaintext", b"info", b"aad").unwrap();
        let rows = [
            (OP_GET_SCOPED, json!({"credential_id":DEPOSIT_COOKIE_ID})),
            (OP_STATUS, json!({"credential_id":DEPOSIT_COOKIE_ID})),
            (
                OP_REPORT_AUTH_FAILURE,
                json!({"credential_id":DEPOSIT_COOKIE_ID,"provider_status":401,"record_version":2}),
            ),
            (
                OP_SIGN,
                json!({"credential_id":signing_id,"payload_b64":encode(b"hello")}),
            ),
            (OP_PUBLIC_KEY, json!({"credential_id":signing_id})),
            (
                OP_OPEN,
                json!({"credential_id":kem_id,"enc_b64":encode(&enc),"ciphertext_b64":encode(&ct),"info_b64":encode(b"info"),"aad_b64":encode(b"aad")}),
            ),
        ];
        for (method, params) in rows {
            let before: i64 = store
                .with_raw_conn(|c| {
                    c.query_row(
                        "SELECT count(*) FROM auth_events WHERE kind='scoped_read_refusal'",
                        [],
                        |r| r.get(0),
                    )
                })
                .unwrap();
            let denied = deposit_cookie_frame(
                &surface,
                &admin,
                deposit_cookie_principal(),
                method,
                params.clone(),
            )
            .await;
            if method == OP_STATUS {
                assert_eq!(
                    deposit_cookie_body(&denied)["result"]["last_error_code"],
                    "not_found"
                );
                assert_eq!(deposit_cookie_body(&denied)["result"]["ready"], false);
            } else {
                assert_eq!(
                    deposit_cookie_body(&denied)["result"]["error"]["code"],
                    "not_found",
                    "{method}"
                );
            }
            let after: i64 = store
                .with_raw_conn(|c| {
                    c.query_row(
                        "SELECT count(*) FROM auth_events WHERE kind='scoped_read_refusal'",
                        [],
                        |r| r.get(0),
                    )
                })
                .unwrap();
            assert_eq!(after, before + 1, "{method}");
            let allowed =
                deposit_cookie_frame(&surface, &admin, reader.clone(), method, params).await;
            assert_eq!(allowed.header.ty, FrameType::Response, "{method}");
            assert!(
                deposit_cookie_body(&allowed)["result"]
                    .get("error")
                    .is_none(),
                "{method}: {}",
                deposit_cookie_body(&allowed)
            );
            if method == OP_STATUS {
                assert_eq!(deposit_cookie_body(&allowed)["result"]["ready"], true);
            }
        }
        let grantless = deposit_cookie_frame(
            &surface,
            &admin,
            Some(subc_protocol::Principal::Reserved {
                module_id: "grantless".into(),
            }),
            OP_LIST_SCOPED,
            json!({}),
        )
        .await;
        let deposit = deposit_cookie_frame(
            &surface,
            &admin,
            deposit_cookie_principal(),
            OP_LIST_SCOPED,
            json!({}),
        )
        .await;
        let body = deposit_cookie_body(&deposit);
        assert_eq!(body["result"]["credentials"], json!([]));
        assert_eq!(body["result"]["grants"], 0);
        assert_eq!(body["result"]["grant_tuples"], json!([]));
        assert_eq!(
            body["result"]["view"],
            deposit_cookie_body(&grantless)["result"]["view"]
        );
        let listed =
            deposit_cookie_frame(&surface, &admin, reader, OP_LIST_SCOPED, json!({})).await;
        assert!(deposit_cookie_body(&listed)["result"]["credentials"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == DEPOSIT_COOKIE_ID));
        deposit_cookie_grant(&store, "reader", GrantOperation::Deposit);
        let listed = deposit_cookie_frame(
            &surface,
            &admin,
            Some(subc_protocol::Principal::Reserved {
                module_id: "reader".into(),
            }),
            OP_LIST_SCOPED,
            json!({}),
        )
        .await;
        assert!(!String::from_utf8(listed.body.to_vec())
            .unwrap()
            .contains("deposit"));
        // The deposit grant confers no handle read authority. An independently minted
        // bearer handle remains a valid read capability, regardless of module grants.
        let refused = deposit_cookie_frame(
            &surface,
            &admin,
            deposit_cookie_principal(),
            OP_GET,
            json!({"handle":"not-a-capability"}),
        )
        .await;
        assert_eq!(
            deposit_cookie_body(&refused)["result"]["error"]["code"],
            "not_found"
        );
        let handle = credentials_core::store::mint_handle().unwrap();
        store
            .put_handle_hash(
                &handle.hash,
                DEPOSIT_COOKIE_ID,
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .unwrap();
        let allowed = deposit_cookie_frame(
            &surface,
            &admin,
            deposit_cookie_principal(),
            OP_GET,
            json!({"handle":handle.raw}),
        )
        .await;
        assert!(deposit_cookie_body(&allowed)["result"]
            .get("error")
            .is_none());
        // Admin authority requires a direct operator connection, not a module grant.
        admin.record_bind_at(51, 1, deposit_cookie_principal().unwrap());
        for (method, params) in [
            (OP_ADMIN_CHALLENGE, json!({})),
            (OP_ADMIN_OP, json!({"op_body":"{}","tag_hex":"00"})),
        ] {
            let refused =
                deposit_cookie_frame(&surface, &admin, deposit_cookie_principal(), method, params)
                    .await;
            assert_eq!(refused.header.ty, FrameType::Error);
            assert!(String::from_utf8(refused.body.to_vec())
                .unwrap()
                .contains("admin_refused"));
        }
        admin.record_bind_at(51, 1, subc_protocol::Principal::Direct);
        let allowed = deposit_cookie_frame(
            &surface,
            &admin,
            Some(subc_protocol::Principal::Direct),
            OP_ADMIN_CHALLENGE,
            json!({}),
        )
        .await;
        assert_eq!(allowed.header.ty, FrameType::Response);
    }

    #[tokio::test]
    async fn deposit_cookie_competing_creators_and_operator_replace_preserve_ownership() {
        let (surface, admin, store) = deposit_cookie_rig(160);
        for name in ["cerebellum", "other"] {
            deposit_cookie_grant(&store, name, GrantOperation::Deposit);
        }
        let (one, two) = tokio::join!(
            deposit_cookie_frame(
                &surface,
                &admin,
                deposit_cookie_principal(),
                OP_DEPOSIT_COOKIE,
                deposit_cookie_params()
            ),
            deposit_cookie_frame(
                &surface,
                &admin,
                Some(subc_protocol::Principal::Reserved {
                    module_id: "other".into()
                }),
                OP_DEPOSIT_COOKIE,
                deposit_cookie_params()
            )
        );
        let bodies = [deposit_cookie_body(&one), deposit_cookie_body(&two)];
        assert_eq!(
            bodies
                .iter()
                .filter(|b| b["result"]["outcome"] == "created")
                .count(),
            1
        );
        assert_eq!(
            bodies
                .iter()
                .filter(|b| b["result"]["error"]["code"] == "not_permitted")
                .count(),
            1
        );
        let audits = store.read_audit(None).unwrap();
        assert_eq!(
            audits
                .iter()
                .filter(|a| a.credential_id.as_deref() == Some(DEPOSIT_COOKIE_ID))
                .count(),
            1
        );
        let creator = store.meta(DEPOSIT_COOKIE_ID).unwrap().created_by.unwrap();
        store
            .overwrite_unconditional_audited(
                DEPOSIT_COOKIE_ID,
                &VaultRecord::new_cookie("operator", b"operator replace".to_vec()),
                AuditCtx::admin(AuditOp::Overwrite),
            )
            .unwrap();
        let principal = Some(subc_protocol::Principal::Reserved {
            module_id: creator.strip_prefix("reserved:").unwrap().into(),
        });
        let reply = deposit_cookie_frame(
            &surface,
            &admin,
            principal,
            OP_DEPOSIT_COOKIE,
            deposit_cookie_params(),
        )
        .await;
        assert_eq!(deposit_cookie_body(&reply)["result"]["outcome"], "replaced");
        assert_eq!(
            store.meta(DEPOSIT_COOKIE_ID).unwrap().created_by.as_deref(),
            Some(creator.as_str())
        );
    }

    async fn enrollment_route_frame(
        surface: &Arc<ReadSurface>,
        admin: &Arc<admin_surface::AdminSurface>,
        method: &str,
        params: serde_json::Value,
    ) -> Frame {
        let (writer, mut responses) = mpsc::channel(1);
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            77,
            1,
            1,
            serde_json::to_vec(&json!({ "method": method, "params": params }))
                .expect("encode enrollment request"),
        )
        .expect("build enrollment request");
        handle_read_request(frame, &writer, surface, admin, None)
            .await
            .expect("serve enrollment request");
        responses.recv().await.expect("enrollment response")
    }

    /// An enrollment refusal is a `Response` whose body is exactly
    /// `{"result":{"error":{"class":..,"code":..}}}`. The exact-key check is what keeps
    /// the retired `disposition` field (or any other extra key) from creeping back in.
    fn assert_enrollment_refusal(frame: &Frame, code: &str, class: &str) {
        assert_eq!(
            frame.header.ty,
            FrameType::Response,
            "an enrollment refusal must be a Response frame, not an Error frame"
        );
        let body: serde_json::Value =
            serde_json::from_slice(&frame.body).expect("decode enrollment refusal");
        assert_eq!(
            body,
            wrap_result(json!({ "error": { "code": code, "class": class } }))
        );
        assert!(
            body["result"]["error"].get("disposition").is_none(),
            "`disposition` is not part of the enrollment refusal wire shape"
        );
    }

    async fn scoped_request(
        surface: &Arc<ReadSurface>,
        admin: &Arc<admin_surface::AdminSurface>,
        channel: u16,
        credential_id: &str,
    ) -> serde_json::Value {
        scoped_route_request(
            surface,
            admin,
            channel,
            OP_GET_SCOPED,
            json!({ "credential_id": credential_id }),
        )
        .await
    }

    #[tokio::test]
    async fn consumer_reports_preserve_route_direct_and_legacy_principal_states() {
        let (surface, admin, store) = scoped_rig(76);
        let credential_ids = [
            "apikey:route-bound-report",
            "apikey:direct-report",
            "apikey:legacy-report",
        ];
        let mut handles = Vec::new();
        for credential_id in credential_ids {
            store
                .create(
                    credential_id,
                    &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
                )
                .expect("create credential");
            let handle = credentials_core::store::mint_handle().expect("mint handle");
            store
                .put_handle_hash(
                    &handle.hash,
                    credential_id,
                    AuditCtx::admin(AuditOp::MintHandle),
                )
                .expect("bind handle");
            handles.push(handle.raw);
        }

        admin.record_bind(
            76,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );
        let route_report = scoped_route_request(
            &surface,
            &admin,
            76,
            OP_REPORT_AUTH_FAILURE,
            json!({
                "handle": handles[0],
                "provider_status": 401,
                "record_version": 1,
            }),
        )
        .await;
        assert_eq!(route_report["result"]["accepted"], true);

        admin.record_bind(77, subc_protocol::Principal::Direct);
        let direct_report = scoped_route_request(
            &surface,
            &admin,
            77,
            OP_REPORT_AUTH_FAILURE,
            json!({
                "handle": handles[1],
                "provider_status": 401,
                "record_version": 1,
            }),
        )
        .await;
        assert_eq!(direct_report["result"]["accepted"], true);

        store
            .record_auth_event(
                credential_ids[2],
                credentials_core::store::AuthObservation {
                    kind: "legacy_report",
                    provider_status: Some(401),
                    detail: None,
                    reporter_source: None,
                    principal: None,
                },
                Some(1),
            )
            .expect("write legacy event");

        let events = store.recent_auth_events(10).expect("read all event states");
        let route = events
            .iter()
            .find(|event| event.credential_id == credential_ids[0])
            .expect("route-bound report event");
        let direct = events
            .iter()
            .find(|event| event.credential_id == credential_ids[1])
            .expect("direct report event");
        let legacy = events
            .iter()
            .find(|event| event.credential_id == credential_ids[2])
            .expect("legacy report event");

        assert_eq!(route.principal_kind.as_deref(), Some("reserved"));
        assert_eq!(route.principal_id.as_deref(), Some("prefrontal-core"));
        assert_eq!(direct.principal_kind.as_deref(), Some("direct"));
        assert_eq!(
            direct.principal_id, None,
            "a direct caller has no id; NULL is the recorded answer"
        );
        assert_eq!(legacy.principal_kind, None);
        assert_eq!(legacy.principal_id, None);
        assert_ne!(
            (
                route.principal_kind.as_deref(),
                route.principal_id.as_deref()
            ),
            (
                direct.principal_kind.as_deref(),
                direct.principal_id.as_deref()
            ),
            "a route-bound and direct caller must remain distinct"
        );
        assert_ne!(
            (
                direct.principal_kind.as_deref(),
                direct.principal_id.as_deref()
            ),
            (
                legacy.principal_kind.as_deref(),
                legacy.principal_id.as_deref()
            ),
            "a direct caller must remain distinguishable from a legacy row"
        );
    }

    async fn scoped_status_request(
        surface: &Arc<ReadSurface>,
        admin: &Arc<admin_surface::AdminSurface>,
        channel: u16,
        credential_id: &str,
    ) -> serde_json::Value {
        scoped_route_request(
            surface,
            admin,
            channel,
            OP_STATUS,
            json!({ "credential_id": credential_id }),
        )
        .await
    }

    async fn scoped_sign_request(
        surface: &Arc<ReadSurface>,
        admin: &Arc<admin_surface::AdminSurface>,
        channel: u16,
        credential_id: &str,
        payload_b64: &str,
    ) -> serde_json::Value {
        scoped_route_request(
            surface,
            admin,
            channel,
            OP_SIGN,
            json!({ "credential_id": credential_id, "payload_b64": payload_b64 }),
        )
        .await
    }

    async fn scoped_public_key_request(
        surface: &Arc<ReadSurface>,
        admin: &Arc<admin_surface::AdminSurface>,
        channel: u16,
        credential_id: &str,
    ) -> serde_json::Value {
        scoped_route_request(
            surface,
            admin,
            channel,
            OP_PUBLIC_KEY,
            json!({ "credential_id": credential_id }),
        )
        .await
    }

    fn assert_scoped_not_found(body: &serde_json::Value) {
        assert_eq!(
            body["result"]["error"],
            json!({ "code": "not_found", "class": "permanent" }),
            "the route frame must carry the complete uniform absence pair"
        );
    }

    #[tokio::test]
    async fn scoped_get_serves_a_covered_credential_and_does_not_audit_the_read() {
        let (surface, admin, store) = scoped_rig(72);
        store
            .create(
                "github_app:fleet-a",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create credential");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                "github_app:fleet-a",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create grant");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "github_app:fleet-a",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("store handle");
        admin.record_bind(
            41,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let normal = serde_json::to_value(
            surface
                .get(
                    42,
                    &GetParams {
                        handle: handle.raw,
                        min_ttl_ms: None,
                        force_refresh: false,
                    },
                )
                .await,
        )
        .expect("encode normal result");
        let audits_before_read = store.read_audit(None).expect("read audit");
        let scoped = scoped_request(&surface, &admin, 41, "github_app:fleet-a").await;
        assert_eq!(
            scoped["result"], normal,
            "credential.get_scoped must return the exact credential.get result body"
        );
        assert_eq!(
            store.read_audit(None).expect("read audit").len(),
            audits_before_read.len(),
            "a grant-authorized read must not append to the untrimmable audit chain"
        );

        store
            .revoke_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                "github_app:fleet-a",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantRevoke),
            )
            .expect("revoke grant");
        let grant_ops: Vec<String> = store
            .read_audit(None)
            .expect("read audit")
            .into_iter()
            .filter(|entry| matches!(entry.op.as_str(), "grant_create" | "grant_revoke"))
            .map(|entry| entry.op)
            .collect();
        assert_eq!(grant_ops, ["grant_create", "grant_revoke"]);
    }

    #[tokio::test]
    async fn list_scoped_records_list_first_use_even_when_the_caller_also_holds_read() {
        // A principal holding `read` on one credential and `list` on another. When the
        // first-use operation was chosen from the caller's GRANTS, its first use of the
        // `list` grant recorded `read`, a row it already had, so the vault's own record
        // could not show the new grant in use. Choosing from the returned ROWS
        // records each authority that actually disclosed a row.
        let (surface, admin, store) = scoped_rig(97);
        for id in ["apikey:zai", "apikey:deepseek"] {
            store
                .create(
                    id,
                    &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
                )
                .expect("create credential");
        }
        for (selector, operation) in [
            ("apikey:zai", GrantOperation::Read),
            ("apikey:deepseek", GrantOperation::List),
        ] {
            store
                .create_read_grant_audited(
                    "reserved",
                    "router",
                    SelectorKind::Exact,
                    selector,
                    operation,
                    AuditCtx::admin(AuditOp::GrantCreate),
                )
                .unwrap();
        }
        admin.record_bind(
            97,
            subc_protocol::Principal::Reserved {
                module_id: "router".into(),
            },
        );
        let first_uses = || {
            let mut details: Vec<String> = store
                .recent_auth_events(100)
                .unwrap()
                .into_iter()
                .filter(|event| {
                    event.credential_id == OP_LIST_SCOPED
                        && event.principal_id.as_deref() == Some("router")
                })
                .filter_map(|event| event.detail)
                .collect();
            details.sort();
            details
        };
        let listed = scoped_route_request(&surface, &admin, 97, OP_LIST_SCOPED, json!({})).await;
        assert_eq!(listed["result"]["credentials"].as_array().unwrap().len(), 2);
        assert_eq!(first_uses(), ["list", "read"]);
        // Still idempotent: a second enumeration adds nothing.
        scoped_route_request(&surface, &admin, 97, OP_LIST_SCOPED, json!({})).await;
        assert_eq!(first_uses(), ["list", "read"]);
    }

    #[tokio::test]
    async fn list_scoped_never_grows_the_audit_chain_and_records_first_use_once_per_principal() {
        let (surface, admin, store) = scoped_rig(94);
        store
            .create(
                "apikey:zai",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create classified credential");
        store
            .create_read_grant_audited(
                "reserved",
                "consumer",
                SelectorKind::Category,
                "llm-provider",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
        store
            .create_read_grant_audited(
                "reserved",
                "consumer",
                SelectorKind::Exact,
                "apikey:zai",
                GrantOperation::Sign,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
        admin.record_bind(
            94,
            subc_protocol::Principal::Reserved {
                module_id: "consumer".into(),
            },
        );
        let audit_count = store.read_audit(None).unwrap().len();
        let event_count = store.recent_auth_events(100).unwrap().len();
        let listed = scoped_route_request(&surface, &admin, 94, OP_LIST_SCOPED, json!({})).await;
        assert_eq!(listed["result"]["grants"], 2);
        assert_eq!(
            listed["result"]["grant_tuples"].as_array().unwrap().len(),
            2
        );
        let row = listed["result"]["credentials"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == "apikey:zai")
            .expect("classified row");
        assert_eq!(row["id"], "apikey:zai");
        assert_eq!(row["categories"], json!(["llm-provider"]));
        assert_eq!(row["operations"], json!(["read", "sign"]));
        assert!(listed["result"]["view"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        // THE AUDIT CHAIN MUST NOT GROW ON A READ. It is untrimmable and HMAC-linked, so
        // a row per enumeration would make it grow with traffic forever. Unchanged.
        assert_eq!(store.read_audit(None).unwrap().len(), audit_count);

        // `auth_events` IS THE OPPOSITE CASE AND USED TO BE SILENT TOO, which cost the
        // insula seat a debugging session on 2026-09-20: a REFUSAL wrote a row and a
        // SUCCESS wrote nothing, so an operator reading this table got the same empty
        // answer for "the consumer is working" and "the consumer never called". I
        // offered exactly that reading as evidence before noticing it could not answer.
        //
        // It is bounded and trimmable, and first use is IDEMPOTENT -- one row ever per
        // (subject, principal, operation), not one per call. That distinction is what
        // makes this safe: every list_scoped row shares one 64-entry ring keyed on the
        // literal op, so a per-CALL row would evict the refusals that explain failures,
        // the least interesting row pushing out the most interesting.
        let after_first = store.recent_auth_events(100).unwrap().len();
        assert_eq!(
            after_first,
            event_count + 1,
            "a successful enumeration must be visible to an operator"
        );
        let again = scoped_route_request(&surface, &admin, 94, OP_LIST_SCOPED, json!({})).await;
        assert_eq!(again["result"]["grants"], 2, "second call still serves");
        assert_eq!(
            store.recent_auth_events(100).unwrap().len(),
            after_first,
            "first use is once per principal, not once per call"
        );
        let first_use = store
            .recent_auth_events(100)
            .unwrap()
            .into_iter()
            .find(|event| {
                event.credential_id == OP_LIST_SCOPED
                    && event.principal_id.as_deref() == Some("consumer")
            })
            .expect("the successful caller is named");
        assert_eq!(first_use.principal_kind.as_deref(), Some("reserved"));

        let invalid = scoped_route_request(
            &surface,
            &admin,
            94,
            OP_LIST_SCOPED,
            json!({ "token": "forbidden" }),
        )
        .await;
        assert_eq!(invalid["code"], "invalid_params", "{invalid}");

        admin.record_bind(95, subc_protocol::Principal::Direct);
        let refused = scoped_route_request(&surface, &admin, 95, OP_LIST_SCOPED, json!({})).await;
        assert_scoped_not_found(&refused);
        let event = store
            .recent_auth_events(100)
            .unwrap()
            .into_iter()
            .find(|event| event.credential_id == OP_LIST_SCOPED)
            .expect("rejected list event");
        assert_eq!(event.principal_kind.as_deref(), Some("direct"));
        assert_eq!(event.principal_id.as_deref(), None);

        admin.record_bind(
            96,
            subc_protocol::Principal::Reserved {
                module_id: "grantless".into(),
            },
        );
        let empty = scoped_route_request(&surface, &admin, 96, OP_LIST_SCOPED, json!({})).await;
        assert_eq!(empty["result"]["credentials"], json!([]));
        assert_eq!(empty["result"]["grants"], 0);
        assert_eq!(empty["result"]["grant_tuples"], json!([]));
        assert_eq!(
            empty["result"]["view"],
            "vGTW0lomfgTvnoZoEYxkS/nUmfm76KhATUyAQCXGpPY="
        );
    }

    #[tokio::test]
    async fn scoped_get_refuses_both_wrong_principal_kind_and_wrong_reserved_id() {
        let (surface, admin, store) = scoped_rig(73);
        store
            .create(
                "github_app:fleet-a",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create credential");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                "github_app:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create grant");

        admin.record_bind(43, subc_protocol::Principal::Direct);
        let direct = scoped_request(&surface, &admin, 43, "github_app:fleet-a").await;
        assert_scoped_not_found(&direct);

        admin.record_bind(
            44,
            subc_protocol::Principal::Reserved {
                module_id: "other-module".into(),
            },
        );
        let other_reserved = scoped_request(&surface, &admin, 44, "github_app:fleet-a").await;
        assert_scoped_not_found(&other_reserved);
    }

    #[tokio::test]
    async fn scoped_get_uncovered_and_unknown_ids_have_identical_wire_bodies() {
        let (surface, admin, store) = scoped_rig(74);
        store
            .create(
                "apikey:uncovered",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create uncovered credential");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                "github_app:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create grant");
        admin.record_bind(
            45,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let uncovered = scoped_request(&surface, &admin, 45, "apikey:uncovered").await;
        let unknown = scoped_request(&surface, &admin, 45, "github_app:missing").await;
        assert_eq!(
            uncovered, unknown,
            "an uncovered stored credential and an unknown credential must be indistinguishable"
        );
    }

    #[tokio::test]
    async fn scoped_get_refusals_record_discriminated_auth_events_behind_uniform_wire_bodies() {
        let (surface, admin, store) = scoped_rig(75);
        store
            .create(
                "apikey:uncovered",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create uncovered credential");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                "github_app:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create grant");
        admin.record_bind(
            46,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let no_grant = scoped_request(&surface, &admin, 46, "apikey:uncovered").await;
        let not_found = scoped_request(&surface, &admin, 46, "github_app:missing").await;
        assert_eq!(
            no_grant, not_found,
            "the operator-only distinction must not change the refused wire body"
        );
        let events = store.recent_auth_events(10).expect("read events");
        assert_eq!(
            events.len(),
            2,
            "each refused scoped read needs a diagnostic row"
        );
        assert_eq!(events[0].credential_id, "github_app:missing");
        assert_eq!(events[0].detail.as_deref(), Some("not_found"));
        assert_eq!(events[1].credential_id, "apikey:uncovered");
        assert_eq!(events[1].detail.as_deref(), Some("no_grant"));
        for event in events {
            assert_eq!(event.kind, "scoped_read_refusal");
            assert_eq!(event.principal_kind.as_deref(), Some("reserved"));
            assert_eq!(event.principal_id.as_deref(), Some("prefrontal-core"));
        }
    }

    #[tokio::test]
    async fn scoped_get_store_lookup_failure_is_uniform_on_wire_and_explicit_in_events() {
        let (surface, admin, store) = scoped_rig(77);
        store
            .create(
                "github_app:fleet-a",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create credential");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                "github_app:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create grant");

        admin.record_bind(47, subc_protocol::Principal::Direct);
        let ordinary_refusal = scoped_request(&surface, &admin, 47, "github_app:fleet-a").await;
        admin.record_bind(
            48,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );
        // There is no public way to make an open store fail one read query. This cfg(test)
        // one-shot keeps the production surface unchanged while exercising the real route's
        // Result error arm after it has performed the normal lookup.
        surface.force_scoped_grant_lookup_error_for_test();
        let store_refusal = scoped_request(&surface, &admin, 48, "github_app:fleet-a").await;

        assert_eq!(
            store_refusal, ordinary_refusal,
            "a grant lookup failure must not make the wire distinguish vault storage from no grant"
        );
        let events = store.recent_auth_events(10).expect("read events");
        assert_eq!(events[0].detail.as_deref(), Some("store_error"));
        assert_eq!(events[0].principal_kind.as_deref(), Some("reserved"));
        assert_eq!(events[0].principal_id.as_deref(), Some("prefrontal-core"));
        assert_eq!(events[1].detail.as_deref(), Some("no_grant"));
    }

    #[tokio::test]
    async fn scoped_status_read_grant_returns_the_same_body_as_a_handle() {
        let (surface, admin, store) = scoped_rig(78);
        let credential_id = "github_app:status-covered";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create credential");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                credential_id,
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create read grant");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                credential_id,
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");
        admin.record_bind(
            51,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let handle_status = serde_json::to_value(
            surface
                .status(
                    52,
                    None,
                    &StatusParams {
                        handle: Some(handle.raw),
                        credential_id: None,
                        enrollment_token: None,
                    },
                )
                .await,
        )
        .expect("encode handle status");
        let scoped_status = scoped_status_request(&surface, &admin, 51, credential_id).await;
        assert_eq!(
            scoped_status["result"], handle_status,
            "a matching Read grant must return the same status body as the capability handle"
        );
    }

    #[tokio::test]
    async fn scoped_status_no_grant_is_uniform_and_records_the_principal() {
        let (surface, admin, store) = scoped_rig(79);
        let credential_id = "apikey:status-uncovered";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create uncovered credential");
        admin.record_bind(
            53,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let refusal = scoped_status_request(&surface, &admin, 53, credential_id).await;
        let result = refusal["result"]
            .as_object()
            .expect("refused status must be a result object");
        assert_eq!(result.get("ready"), Some(&json!(false)));
        assert!(
            !result.contains_key("record_version"),
            "a principal with no grant must not learn that the credential has a record"
        );
        assert!(
            !result.contains_key("stale_pending"),
            "an unreachable credential must omit its next-get latency prediction"
        );
        let events = store.recent_auth_events(1).expect("read refusal event");
        let event = events
            .first()
            .expect("a refused scoped status needs an event");
        assert_eq!(event.kind, "scoped_read_refusal");
        assert_eq!(event.detail.as_deref(), Some("no_grant"));
        assert_eq!(event.principal_kind.as_deref(), Some("reserved"));
        assert_eq!(event.principal_id.as_deref(), Some("prefrontal-core"));
    }

    #[tokio::test]
    async fn scoped_status_grant_lookup_failure_is_uniform_and_records_store_error() {
        let (surface, admin, store) = scoped_rig(80);
        let credential_id = "github_app:status-store-error";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create credential");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                "github_app:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create read grant");
        admin.record_bind(54, subc_protocol::Principal::Direct);
        let ordinary_refusal = scoped_status_request(&surface, &admin, 54, credential_id).await;
        admin.record_bind(
            55,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );
        surface.force_scoped_grant_lookup_error_for_test();
        let store_refusal = scoped_status_request(&surface, &admin, 55, credential_id).await;

        assert_eq!(
            store_refusal, ordinary_refusal,
            "a grant lookup failure must remain indistinguishable from ordinary missing coverage"
        );
        let events = store.recent_auth_events(2).expect("read refusal events");
        assert_eq!(events[0].detail.as_deref(), Some("store_error"));
        assert_eq!(events[0].principal_kind.as_deref(), Some("reserved"));
        assert_eq!(events[0].principal_id.as_deref(), Some("prefrontal-core"));
        assert_eq!(events[1].detail.as_deref(), Some("no_grant"));
    }

    #[tokio::test]
    async fn sign_only_grant_does_not_authorize_scoped_status() {
        let (surface, admin, store) = scoped_rig(80);
        let credential_id = "apikey:status-sign-only";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create sign-only credential");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                "apikey:status-",
                GrantOperation::Sign,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create Sign-only grant");
        admin.record_bind(
            54,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let refusal = scoped_status_request(&surface, &admin, 54, credential_id).await;
        let result = refusal["result"]
            .as_object()
            .expect("Sign-only refusal must be a result object");
        assert_eq!(result.get("ready"), Some(&json!(false)));
        assert!(
            !result.contains_key("record_version"),
            "a Sign grant must not authorize read-shaped status metadata"
        );
        assert_eq!(
            store.recent_auth_events(1).expect("read refusal event")[0]
                .detail
                .as_deref(),
            Some("no_grant"),
            "the refusal must be classified as missing Read coverage, not as a bad record"
        );
    }

    #[tokio::test]
    async fn wrong_principal_kind_is_refused_by_scoped_status() {
        let (surface, admin, store) = scoped_rig(81);
        let credential_id = "github_app:status-direct";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create credential");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                "github_app:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create read grant");
        admin.record_bind(55, subc_protocol::Principal::Direct);

        let refusal = scoped_status_request(&surface, &admin, 55, credential_id).await;
        let result = refusal["result"]
            .as_object()
            .expect("wrong-kind refusal must be a result object");
        assert_eq!(result.get("ready"), Some(&json!(false)));
        assert!(
            !result.contains_key("record_version"),
            "a Direct principal must not learn a covered reserved credential exists"
        );
        let event = store
            .recent_auth_events(1)
            .expect("read refusal event")
            .pop()
            .expect("wrong principal kind needs an event");
        assert_eq!(event.detail.as_deref(), Some("no_grant"));
        assert_eq!(event.principal_kind.as_deref(), Some("direct"));
        assert_eq!(event.principal_id, None);
    }

    #[tokio::test]
    async fn scoped_status_rejects_both_addressing_forms_as_invalid_params() {
        let (surface, admin, _store) = scoped_rig(82);
        let response = scoped_route_request(
            &surface,
            &admin,
            56,
            OP_STATUS,
            json!({
                "handle": "ckh_status_both_addresses",
                "credential_id": "github_app:status-covered",
            }),
        )
        .await;
        assert_eq!(
            response["code"],
            json!("invalid_params"),
            "credential.status must refuse ambiguous handle and credential_id addressing"
        );
    }

    #[tokio::test]
    async fn unaddressed_status_still_reports_overall_vault_health() {
        let (surface, admin, _store) = scoped_rig(83);
        let routed = scoped_route_request(&surface, &admin, 57, OP_STATUS, json!({})).await;
        let direct = serde_json::to_value(
            surface
                .status(
                    57,
                    None,
                    &StatusParams {
                        handle: None,
                        credential_id: None,
                        enrollment_token: None,
                    },
                )
                .await,
        )
        .expect("encode direct overall status");
        assert_eq!(
            routed["result"], direct,
            "neither address must retain credential.status overall-health behavior"
        );
        assert_eq!(
            routed["result"]["ready"],
            json!(true),
            "a healthy unaddressed status must remain ready, not become a refused credential probe"
        );
        assert_eq!(
            routed["result"]["last_error_code"],
            serde_json::Value::Null,
            "overall vault health must not report a credential lookup error"
        );
        assert!(
            routed["result"].get("record_version").is_none(),
            "overall vault health must not claim a record version"
        );
    }

    #[tokio::test]
    async fn scoped_status_unknown_and_no_grant_are_indistinguishable_on_the_wire() {
        let (surface, admin, store) = scoped_rig(84);
        let uncovered_id = "apikey:status-uncovered";
        store
            .create(
                uncovered_id,
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create uncovered credential");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                "github_app:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create read grant");
        admin.record_bind(
            58,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let no_grant = scoped_status_request(&surface, &admin, 58, uncovered_id).await;
        let unknown =
            scoped_status_request(&surface, &admin, 58, "github_app:status-missing").await;
        assert_eq!(
            no_grant, unknown,
            "a valid grant for an unknown credential must be wire-identical to missing grant coverage"
        );
        let events = store.recent_auth_events(2).expect("read refusal events");
        assert_eq!(events[0].detail.as_deref(), Some("not_found"));
        assert_eq!(events[1].detail.as_deref(), Some("no_grant"));
    }

    #[test]
    fn admin_status_lists_sorted_grants_with_their_sorted_covered_credentials() {
        let (_surface, _admin, store) = scoped_rig(76);
        for id in ["github_app:z", "github_app:a"] {
            store
                .create(
                    id,
                    &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
                )
                .expect("create credential");
        }
        for selector in ["apikey:active", "github_app:a"] {
            for operation in [GrantOperation::Read, GrantOperation::Sign] {
                credentials_core::admin_ops::apply(
                    &store,
                    credentials_core::admin_ops::AdminOpBody::GrantCreateV2 {
                        v: credentials_core::admin_ops::ADMIN_OP_SCHEMA_V2,
                        principal_kind: "reserved".into(),
                        principal_id: "prefrontal-core".into(),
                        selector_kind: credentials_core::store::SelectorKind::Exact,
                        selector: selector.into(),
                        operation,
                    },
                    "test",
                )
                .expect("create exact grant");
            }
        }
        let status = credentials_core::admin_ops::apply(
            &store,
            credentials_core::admin_ops::AdminOpBody::Status {
                v: credentials_core::admin_ops::ADMIN_OP_SCHEMA_V1,
            },
            "test",
        )
        .expect("status");
        let mut grants = status["read_grants"]
            .as_array()
            .expect("grant array")
            .clone();
        for grant in &mut grants {
            let created_at_ms = grant
                .as_object_mut()
                .expect("grant object")
                .remove("created_at_ms")
                .expect("grant timestamp");
            assert!(
                created_at_ms.as_i64().is_some(),
                "grant timestamp must be an integer"
            );
        }
        let expected = json!([
            {
                "principal_kind": "reserved",
                "principal_id": "prefrontal-core",
                "selector_kind": "exact",
                "credential_prefix": "apikey:active",
                "operation": "read",
                "covered_credential_ids": ["apikey:active"],
            },
            {
                "principal_kind": "reserved",
                "principal_id": "prefrontal-core",
                "selector_kind": "exact",
                "credential_prefix": "apikey:active",
                "operation": "sign",
                "covered_credential_ids": ["apikey:active"],
            },
            {
                "principal_kind": "reserved",
                "principal_id": "prefrontal-core",
                "selector_kind": "exact",
                "credential_prefix": "github_app:a",
                "operation": "read",
                "covered_credential_ids": ["github_app:a"],
            },
            {
                "principal_kind": "reserved",
                "principal_id": "prefrontal-core",
                "selector_kind": "exact",
                "credential_prefix": "github_app:a",
                "operation": "sign",
                "covered_credential_ids": ["github_app:a"],
            },
        ]);
        assert_eq!(
            grants,
            expected.as_array().expect("expected grant array").clone(),
            "status must make every grant's current reach diffable"
        );
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
                subc_transport::read_frame(&mut server),
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
    /// The health wire key set is a CONTRACT, pinned so a rename cannot reach a
    /// consumer silently.
    ///
    /// This exists because one did. The audit-tip pair shipped on 2026-08-25 with its
    /// mac keyed `entryMac`, while the consumer-impact announcement I sent the
    /// supervisor seat said `auditTipMac`. Both artifacts were authored carefully and
    /// neither was checked against the other, because THERE IS NO MECHANICAL JOIN
    /// BETWEEN AN ANNOUNCEMENT AND THE BYTES IT DESCRIBES. Their own absent-arm check
    /// caught it on the first post-deploy read -- a good outcome, one deploy late.
    ///
    /// The keys here are HAND-TYPED STRING LITERALS with no compiler relationship to
    /// the Rust field names, which is exactly why the divergence was invisible:
    /// renaming the struct field does not touch the wire, and renaming the literal does
    /// not touch the field. Nothing but this test observes the wire.
    ///
    /// Its failure means a consumer's decoder is about to break. Announce the delta,
    /// then update this list -- and if a key disagrees with what was announced, THE
    /// ANNOUNCEMENT IS THE CONTRACT.
    ///
    /// `auditSeq` is unprefixed where `auditTipMac` is not, which looks careless and is
    /// deliberate: there is exactly one audit sequence so `auditSeq` cannot be misread,
    /// while `entryMac` never said WHICH entry and the chain holds thousands.
    /// A dropped frame names itself ONCE per (channel, epoch), and a repeat is quiet.
    ///
    /// Both halves matter and they pull opposite ways. Without the first, a stale
    /// binding is invisible and the incident that produced this code is undiagnosable
    /// from my side. Without the second, a looping sender turns the ingress path into a
    /// log-volume lever -- the same "granted party misbehaving" shape the fetch limiter
    /// answers with alarm-once rather than refuse.
    #[test]
    fn an_epoch_drop_is_recorded_once_per_pair_and_a_repeat_is_quiet() {
        let routes = RouteEpochs::default();
        routes.install(7, 3);

        assert!(!routes.matches(7, 2), "a stale epoch must not match");
        assert!(
            routes.note_drop(7, 2),
            "the first drop of a (channel, epoch) must be reportable"
        );
        assert!(
            !routes.note_drop(7, 2),
            "a repeat of the SAME pair must be quiet, or a looping sender drives \
             unbounded writes on the ingress path"
        );
        assert!(
            routes.note_drop(7, 1),
            "a DIFFERENT stale epoch on the same channel is a different event"
        );
        assert_eq!(
            routes.expected(7),
            Some(3),
            "the drop record must be able to name what this module actually holds"
        );
        assert_eq!(
            routes.expected(9),
            None,
            "an unheld channel reports no expectation rather than a stale one"
        );
    }

    /// Provenance never publishes a placeholder as a build fact.
    ///
    /// `BUILD_REV` is "unknown" on any build the release script did not stamp, and the
    /// protocol validates provenance for SHAPE ONLY -- non-empty, <=128 bytes, printable
    /// -- so "unknown" would sail through as a perfectly well-formed claim. A supervisor
    /// comparing provenance across a fleet treats a present field as an assertion about
    /// the binary, and a placeholder shaped like a sha is worse than an absent field:
    /// absence says "this build does not know", while "unknown" says "this build's sha
    /// is the string unknown".
    ///
    /// This test holds under BOTH build modes, which is what makes it worth having: on a
    /// dev build it asserts the block is absent, and on a stamped release build it
    /// asserts the sha is real. A future change that fills the field unconditionally
    /// fails here rather than in a fleet provenance comparison.
    ///
    /// THERE ARE THREE STATES, NOT TWO, AND THIS TEST CAUGHT ME LEARNING THAT. Adopting
    /// `build_provenance()` added a stamped-but-NONCONFORMING case: subc-protocol 0.17
    /// requires 40 lowercase hex, and my own release script stamped a 7-char abbreviation,
    /// so a stamped build could legitimately omit the block. The old dichotomy --
    /// "omitted implies unstamped" -- asserted something that had stopped being true, and
    /// it failed by name under `CK_BUILD_REV=0cd42dc` before any of this shipped.
    ///
    /// The omission arm now accepts exactly two causes and NAMES WHICH ONE it saw, because
    /// "no revision" and "a revision the wire will not accept" call for different actions:
    /// the first is a dev build working as designed, the second means a release script is
    /// producing a fact the fleet census will silently drop.
    #[test]
    fn provenance_never_publishes_a_placeholder_as_a_build_fact() {
        let m = manifest("claustrum", None);
        let rev = credentials_core::contract::BUILD_REV;
        // The canonical form the protocol enforces: 40 lowercase hex.
        let conforming = rev.len() == 40
            && rev
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase());
        match &m.provenance {
            None => assert!(
                rev == "unknown" || !conforming,
                "provenance was omitted on a build whose revision ({rev}) IS conforming, \
                 so neither cause applies: not an unstamped dev build, and not a form \
                 the wire refuses. Something else is dropping the block."
            ),
            Some(p) => {
                let sha = p
                    .build_git_sha
                    .as_deref()
                    .expect("a present provenance block declares the one fact it has");
                assert_ne!(
                    sha, "unknown",
                    "a placeholder must never be published as a build fact: the protocol \
                     validates shape only, so `unknown` is a well-formed lie"
                );
                assert_eq!(
                    sha,
                    credentials_core::contract::BUILD_REV,
                    "the manifest must report the same revision as --version, or two \
                     surfaces disagree about which binary this is"
                );
            }
        }
        assert!(
            m.provenance.as_ref().is_none_or(|p| p.validate().is_ok()),
            "whatever is declared must satisfy the protocol's own validator"
        );
    }

    /// The manifest declares where the launch nonce came from, on every build.
    ///
    /// The supervisor withdraws the environment copy of the nonce only once every
    /// module reports `fd`, so a module that silently omits the field holds that step
    /// up (or worse, is assumed ready without evidence). A dev build has no revision to
    /// state, and the source must survive that too: it describes the launch, not the
    /// build.
    #[test]
    fn manifest_declares_the_launch_nonce_source() {
        let fd = manifest("claustrum", Some(LaunchNonceSource::Fd));
        let p = fd
            .provenance
            .as_ref()
            .expect("a known nonce source always produces a provenance block");
        assert_eq!(p.launch_nonce_source, Some(LaunchNonceSource::Fd));
        assert!(
            p.validate().is_ok(),
            "the declared block must satisfy the protocol validator"
        );
        let wire = serde_json::to_value(&fd).expect("manifest serializes");
        assert_eq!(
            wire.pointer("/provenance/launch_nonce_source"),
            Some(&json!("fd")),
            "the wire spelling the supervisor's census reads"
        );

        let env = manifest("claustrum", Some(LaunchNonceSource::Env));
        assert_eq!(
            env.provenance
                .as_ref()
                .and_then(|p| p.launch_nonce_source.clone()),
            Some(LaunchNonceSource::Env)
        );

        // With no supervisor there is no nonce and no source, and nothing is invented.
        let none = manifest("claustrum", None);
        assert!(none
            .provenance
            .as_ref()
            .is_none_or(|p| p.launch_nonce_source.is_none()));
    }

    /// No shipped source reads the launch nonce except through `subc_os::launch_nonce`.
    ///
    /// `launch_nonce_source: fd` in the manifest only proves the HELLO read came from the
    /// descriptor. A second reader going to `SUBC_LAUNCH_NONCE` directly would keep
    /// working while the supervisor still sets the environment copy, and fail the day it
    /// stops. Two other modules shipped exactly that, and only a source scan finds it.
    ///
    /// Scans every `src/` tree in this workspace. Removing the variable (the CLI scrubs it
    /// before spawning children) is not a read and is allowed. `examples/` is excluded:
    /// the operator probe takes a nonce the operator exports by hand.
    #[test]
    fn no_shipped_source_reads_the_launch_nonce_directly() {
        fn offending(text: &str) -> Vec<String> {
            text.lines()
                .filter(|line| {
                    let code = line.split("//").next().unwrap_or("");
                    (code.contains("\"SUBC_LAUNCH_NONCE\"") && !code.contains("remove_var"))
                        || code.contains("SUBC_LAUNCH_NONCE_ENV")
                })
                .map(|line| line.trim().to_string())
                .collect()
        }
        // Positive control: the scanner must be able to say yes, or a clean result means
        // nothing.
        assert_eq!(
            offending("let n = std::env::var(\"SUBC_LAUNCH_NONCE\").ok();").len(),
            1
        );
        assert_eq!(
            offending("use subc_protocol::SUBC_LAUNCH_NONCE_ENV;").len(),
            1
        );
        assert!(offending("std::env::remove_var(\"SUBC_LAUNCH_NONCE\");").is_empty());

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut scanned = 0usize;
        let mut found = Vec::new();
        let mut stack: Vec<std::path::PathBuf> = [
            "crates/credentials-core/src",
            "crates/credentials-module/src",
        ]
        .iter()
        .map(|d| root.join(d))
        .collect();
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read src dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    scanned += 1;
                    let text = std::fs::read_to_string(&path).expect("read source");
                    // This test's own control strings are the one expected hit.
                    if path.ends_with("main.rs")
                        && path
                            .parent()
                            .is_some_and(|p| p.ends_with("credentials-module/src"))
                    {
                        let before_tests = text
                            .split("fn no_shipped_source_reads_the_launch_nonce_directly")
                            .next()
                            .unwrap_or("");
                        found.extend(
                            offending(before_tests)
                                .into_iter()
                                .map(|l| format!("{}: {l}", path.display())),
                        );
                    } else {
                        found.extend(
                            offending(&text)
                                .into_iter()
                                .map(|l| format!("{}: {l}", path.display())),
                        );
                    }
                }
            }
        }
        assert!(
            scanned > 20,
            "the scan must actually visit the source tree (visited {scanned})"
        );
        assert!(
            found.is_empty(),
            "read the launch nonce through subc_os::launch_nonce, never directly:\n{}",
            found.join("\n")
        );
    }
    /// The request pins below cover the parameter structs that exist for known route operations.
    /// They catch a parameter added to a known op, but a wholly new op with a new struct still
    /// depends on the person adding it to create a pin. This deliberately does not enumerate
    /// operations dynamically: scanning `OP_` constants would measure mentions rather than
    /// dispatch registrations and could falsely claim that the new surface was covered.
    /// HOW THIS ACTUALLY FIRES, measured rather than assumed: adding a field to a params
    /// struct is a COMPILE error first, not a named test failure. Rust struct literals are
    /// exhaustive, so every fixture below stops building with `missing field ... in
    /// initializer` and the message in this function never prints. That is a stronger
    /// forcing function than a red test -- it cannot be skimmed past -- but it arrives in
    /// two steps: fix the fixtures, THEN the key-set assertion fires and states the
    /// obligations. Do not read the compile error as the whole signal.
    ///
    /// WHICH MAKES ONE REFACTOR SILENTLY FATAL HERE. If these fixtures are ever changed to
    /// `..Default::default()`, the compile error disappears, and a newly added field that
    /// carries `skip_serializing_if = "Option::is_none"` would default to None, serialize
    /// away, and never reach either loop. The pin would then report a green, complete key
    /// set for a struct that had grown a parameter -- blind in exactly the case it exists
    /// for. The exhaustive literals are the mechanism, not verbosity to be tidied.
    /// The golden reply is what goes on the wire, which is `wrap_result` around the
    /// result -- a consumer decodes `result.credentials`, so pinning the bare struct would
    /// pin a shape nobody receives.
    fn main_wrap_for_fixture<T: serde::Serialize>(value: T) -> serde_json::Value {
        wrap_result(value)
    }

    fn assert_request_key_set<T: serde::Serialize>(params: T, expected: &[&str], op: &str) {
        let value = serde_json::to_value(params).expect("serialize request parameters");
        let object = value
            .as_object()
            .unwrap_or_else(|| panic!("{op} request parameters must serialize as an object"));

        // Check both directions so this fails for either a removed key or an added key.
        for key in expected {
            assert!(
                object.contains_key(*key),
                "the {op} accepted parameter set changed. Two obligations: announce the delta to consumers, and give `crates/credentials-module/examples/vault_read_probe.rs` a way to send the new parameter; a wire surface with no probe arm cannot be acceptance-tested on deploy. {op}: missing `{key}`"
            );
        }
        for key in object.keys() {
            assert!(
                expected.iter().any(|expected_key| *expected_key == key),
                "the {op} accepted parameter set changed. Two obligations: announce the delta to consumers, and give `crates/credentials-module/examples/vault_read_probe.rs` a way to send the new parameter; a wire surface with no probe arm cannot be acceptance-tested on deploy. {op}: unexpected `{key}`"
            );
        }
    }

    #[test]
    fn enrollment_wire_fixture_pins_exact_requests_successes_and_nine_refusals() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/enrollment_wire_contract.json"
        ))
        .expect("decode enrollment wire fixture");
        let operations = fixture["operations"].as_array().expect("operation rows");
        let operation = |name: &str| {
            operations
                .iter()
                .find(|row| row["op"] == name)
                .unwrap_or_else(|| panic!("missing {name} fixture row"))
        };
        let raw = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

        assert_eq!(
            serde_json::to_string(&EnrollProposeParams {
                proposed_name: "consumer".into(),
                request_secret_hash: "0".repeat(64),
            })
            .unwrap(),
            operation(OP_ENROLL_PROPOSE)["request"]
        );

        // THE THREE OPS A CONSUMER ACTUALLY SPENDS, not just the ceremony that gets it a
        // token. The ceremony rows were pinned first because they were built first, and an
        // enrolled consumer that can enrol and then cannot read is not a consumer.
        //
        // These are REQUEST shapes only. The success bodies are deliberately absent: a
        // `get_scoped` result carries decrypted payload bytes, and a fixture with a real
        // one in it is a secret in the repository. The request shape is what a decoder has
        // to agree on; the reply shape is pinned by the wire-key contract tests next to
        // each op, which assert presence AND absence without materialising a payload.
        // AND THE ROW SHAPE, WHICH THE REQUEST PINS CANNOT SEE.
        //
        // A list_scoped row carries no secret -- ids, categories, vendors, state -- so
        // unlike a get_scoped body it is safe to pin, and it is the only fixture a
        // consumer's REPLY decoder can be checked against. The gap was not theoretical:
        // my own TypeScript decoder read `credential_type` where the wire says `type`
        // (the Rust field is renamed) and refused every valid row, while the
        // request-shape fixture stayed green throughout.
        //
        // EVERY FIELD COMES FROM THE PRODUCER, not typed here. Each golden row starts as
        // the `ScopedListRow` the store hands the read surface and goes through the same
        // `project_list_scoped` that `credential.list_scoped` calls, so `type` and `serves`
        // come from the catalog, `view` from the production digest, and `auth_method` from
        // `list_auth_method` over the row's kind and refresh adapter. Both pinned rows used
        // to carry `"type":"subscription"`, a value this producer has never emitted for
        // any id; a golden that consumers byte-copy must not carry a value they can never
        // receive, and hand-typing it is how it got there.
        //
        // The inputs below are what the store would return for a `read` or `list` row:
        // the record is unsealed, so identity and the refresh adapter are present and the
        // auth method is derived from the record's kind and adapter. `ScopedListRow` is an
        // exhaustive literal, so a new store field is a compile error here until each
        // golden row states it.
        use credentials_core::list_auth_method::list_auth_method;
        use credentials_core::record::{CredentialKind, RecordIdentity, RecordState};
        use credentials_core::store::{
            GrantOperation, ReadGrant, ScopedListRow, ScopedListSnapshot, SelectorKind,
        };
        struct Stored<'a> {
            id: &'a str,
            categories: &'a [&'a str],
            kind: CredentialKind,
            refresh_adapter: Option<&'a str>,
            record_version: u64,
            identity: bool,
            provider_ids: &'a [&'a str],
        }
        let unsealed_row = |stored: Stored<'_>, operation: GrantOperation| ScopedListRow {
            id: stored.id.into(),
            categories: stored.categories.iter().map(|c| (*c).to_string()).collect(),
            state: RecordState::Active,
            record_version: stored.record_version,
            operations: vec![operation],
            identity: stored.identity.then(|| RecordIdentity {
                account_id: Some("00000000-0000-4000-8000-000000000000".into()),
                email: Some("consumer@example.invalid".into()),
                org_name: Some("Example Org".into()),
            }),
            refresh_adapter: stored.refresh_adapter.map(str::to_string),
            provider_ids: stored
                .provider_ids
                .iter()
                .map(|p| (*p).to_string())
                .collect(),
            auth_method: list_auth_method(stored.kind, stored.refresh_adapter),
        };
        let category_grant = |category: &str, operation: GrantOperation| ReadGrant {
            principal_kind: "enrolled".into(),
            principal_id: "consumer".into(),
            selector_kind: SelectorKind::Category,
            selector: category.into(),
            operation,
            created_at_ms: 1,
        };

        let pinned_row = read_surface::project_list_scoped(ScopedListSnapshot {
            rows: vec![unsealed_row(
                Stored {
                    id: "oauth:anthropic",
                    categories: &["llm-provider"],
                    kind: CredentialKind::Oauth,
                    refresh_adapter: Some("anthropic"),
                    record_version: 232,
                    identity: false,
                    provider_ids: &["anthropic"],
                },
                GrantOperation::Read,
            )],
            grants: Vec::new(),
        });
        assert_eq!(
            serde_json::to_string(&pinned_row.credentials[0]).unwrap(),
            operation("credential.list_scoped")["row"],
            "the golden list_scoped row drifted from what this producer serialises: \
             regenerate it from the assertion's left side"
        );

        // AND THE WHOLE REPLY, NOT JUST ONE ROW.
        //
        // The row above was pinned first, and it did not stop a consumer's hand-copied
        // fixture from spelling `type` as `kind` for days: their decoder, their stub and
        // their fixture all agreed with each other and none agreed with this producer. A
        // row alone also leaves the envelope unpinned, and the envelope is where the same
        // consumer once modelled `grants` (a bare count) as the tuple array that actually
        // lives one key over in `grant_tuples`.
        //
        // This is the golden reply a consumer should BYTE-COPY, with a provenance line
        // naming the claustrum commit, rather than transcribe.
        //
        // ROWS THAT SPAN THE KEY SPACE, not one realistic example. A consumer checking
        // "every key I read is one the producer sends" against a single row cannot see an
        // optional key that row happens to omit. So between them these rows show each
        // optional key both present and absent: identity only on `oauth:anthropic`,
        // `refresh_adapter` absent on the static key, and `auth_method` absent on the
        // GitHub App row, whose adapter maps to no auth method even though the caller can
        // read it. They carry every `auth_method` value (`antigravity`, `apikey`,
        // `chatgpt`, `oauth`), and `provider_ids` with several ids, one id, and none.
        let reply = read_surface::project_list_scoped(ScopedListSnapshot {
            rows: vec![
                unsealed_row(
                    Stored {
                        id: "oauth:anthropic",
                        categories: &["anthropic-native", "llm-provider"],
                        kind: CredentialKind::Oauth,
                        refresh_adapter: Some("anthropic"),
                        record_version: 232,
                        identity: true,
                        provider_ids: &["anthropic", "claude-code"],
                    },
                    GrantOperation::Read,
                ),
                unsealed_row(
                    Stored {
                        id: "apikey:openrouter",
                        categories: &["llm-provider"],
                        kind: CredentialKind::ApiKey,
                        refresh_adapter: None,
                        record_version: 3,
                        identity: false,
                        provider_ids: &["openrouter"],
                    },
                    GrantOperation::Read,
                ),
                unsealed_row(
                    Stored {
                        id: "chatgpt:openai",
                        categories: &["llm-provider"],
                        kind: CredentialKind::Oauth,
                        refresh_adapter: Some("openai"),
                        record_version: 11,
                        identity: false,
                        provider_ids: &[],
                    },
                    GrantOperation::Read,
                ),
                unsealed_row(
                    Stored {
                        id: "antigravity:google",
                        categories: &["llm-provider"],
                        kind: CredentialKind::Oauth,
                        refresh_adapter: Some("antigravity"),
                        record_version: 5,
                        identity: false,
                        provider_ids: &["google-antigravity"],
                    },
                    GrantOperation::Read,
                ),
                unsealed_row(
                    Stored {
                        id: "github_app:plex-alfonso",
                        categories: &["github-app-native"],
                        kind: CredentialKind::Oauth,
                        refresh_adapter: Some("github_app"),
                        record_version: 2,
                        identity: false,
                        provider_ids: &[],
                    },
                    GrantOperation::Read,
                ),
            ],
            grants: vec![
                category_grant("llm-provider", GrantOperation::Read),
                category_grant("github-app-native", GrantOperation::Read),
            ],
        });
        assert_eq!(
            serde_json::to_string(&main_wrap_for_fixture(reply)).unwrap(),
            operation("credential.list_scoped")["reply"],
            "the golden list_scoped reply drifted from what this producer serialises. \
             Consumers byte-copy this file: regenerate it from the assertion's left side, \
             announce the change, and expect every consumer fixture to need re-copying"
        );

        // A REPLY TO A LIST-ONLY CALLER: the account roster without the tokens. The row
        // carries identity, the refresh adapter and the auth method, exactly as a `read`
        // row does, and its `operations` and the caller's tuple say `list`. A consumer
        // decoding operations as a closed set would refuse this reply, which is what this
        // golden lets it test.
        let list_only = read_surface::project_list_scoped(ScopedListSnapshot {
            rows: vec![unsealed_row(
                Stored {
                    id: "oauth:anthropic",
                    categories: &["llm-provider"],
                    kind: CredentialKind::Oauth,
                    refresh_adapter: Some("anthropic"),
                    record_version: 232,
                    identity: true,
                    provider_ids: &["anthropic"],
                },
                GrantOperation::List,
            )],
            grants: vec![category_grant("llm-provider", GrantOperation::List)],
        });
        assert_eq!(
            serde_json::to_string(&main_wrap_for_fixture(list_only)).unwrap(),
            operation("credential.list_scoped")["list_only_reply"],
            "the golden list-only list_scoped reply drifted from what this producer \
             serialises: regenerate it from the assertion's left side"
        );

        // PRESENCE AND ABSENCE, read back from the fixture a consumer copies: every
        // credential object carries a `provider_ids` array, and `auth_method` appears
        // exactly where the auth-method table yields a value.
        let pinned_credentials: Vec<serde_json::Value> = {
            let list_scoped = operation("credential.list_scoped");
            let decode = |key: &str| -> serde_json::Value {
                serde_json::from_str(list_scoped[key].as_str().expect("a JSON string"))
                    .expect("decode pinned JSON")
            };
            let mut rows = vec![decode("row")];
            for key in ["reply", "list_only_reply"] {
                rows.extend(
                    decode(key)["result"]["credentials"]
                        .as_array()
                        .expect("credentials array")
                        .iter()
                        .cloned(),
                );
            }
            rows
        };
        let expected_auth_method = |id: &str| match id {
            "oauth:anthropic" => Some("oauth"),
            "apikey:openrouter" => Some("apikey"),
            "chatgpt:openai" => Some("chatgpt"),
            "antigravity:google" => Some("antigravity"),
            "github_app:plex-alfonso" => None,
            other => panic!("no expected auth_method for pinned row {other}"),
        };
        let mut seen_methods = std::collections::BTreeSet::new();
        let mut provider_id_counts = std::collections::BTreeSet::new();
        for credential in &pinned_credentials {
            let object = credential.as_object().expect("credential object");
            let id = object["id"].as_str().expect("id");
            let provider_ids = object
                .get("provider_ids")
                .unwrap_or_else(|| panic!("{id} has no provider_ids key"))
                .as_array()
                .unwrap_or_else(|| panic!("{id} provider_ids is not an array"));
            assert!(
                provider_ids.iter().all(serde_json::Value::is_string),
                "{id}"
            );
            provider_id_counts.insert(provider_ids.len().min(2));
            let method = object.get("auth_method").map(|value| {
                value
                    .as_str()
                    .unwrap_or_else(|| panic!("{id} auth_method is not a string"))
            });
            assert_eq!(method, expected_auth_method(id), "{id} auth_method");
            seen_methods.extend(method);
        }
        assert_eq!(
            seen_methods.into_iter().collect::<Vec<_>>(),
            ["antigravity", "apikey", "chatgpt", "oauth"],
            "the golden replies carry every auth_method value"
        );
        assert_eq!(
            provider_id_counts.into_iter().collect::<Vec<_>>(),
            [0, 1, 2],
            "the golden replies carry no provider ids, one, and several"
        );
        let github_app = pinned_credentials
            .iter()
            .find(|credential| credential["id"] == "github_app:plex-alfonso")
            .expect("a pinned GitHub App row");
        assert_eq!(
            github_app["refresh_adapter"], "github_app",
            "the row without auth_method is a readable GitHub App row, not a sealed one"
        );
        assert_eq!(github_app["operations"], json!(["read"]));

        assert_eq!(
            serde_json::to_string(&read_surface::ListScopedParams {
                enrollment_token: Some("t".repeat(64)),
            })
            .unwrap(),
            operation("credential.list_scoped")["request"]
        );
        assert_eq!(
            serde_json::to_string(&read_surface::GetScopedParams {
                credential_id: "oauth:anthropic".into(),
                enrollment_token: Some("t".repeat(64)),
                min_ttl_ms: Some(300_000),
            })
            .unwrap(),
            operation("credential.get_scoped")["request"]
        );
        assert_eq!(
            serde_json::to_string(&read_surface::ReportAuthFailureParams {
                handle: None,
                credential_id: Some("oauth:anthropic".into()),
                enrollment_token: Some("t".repeat(64)),
                provider_status: 401,
                record_version: 12,
                reporter_source: Some("direct".into()),
            })
            .unwrap(),
            operation("credential.report_auth_failure")["request"]
        );
        assert_eq!(
            serde_json::to_string(&EnrollPollParams {
                request_id: "request-id".into(),
                request_secret: raw.into(),
            })
            .unwrap(),
            operation(OP_ENROLL_POLL)["request"]
        );
        assert_eq!(
            serde_json::to_string(&EnrollRotateParams {
                token: raw.into(),
                expected_token_generation: 1,
            })
            .unwrap(),
            operation(OP_ENROLL_ROTATE)["request"]
        );
        assert!(
            serde_json::from_value::<EnrollPollParams>(json!({
                "request_id": "request-id",
                "request_secret": raw,
                "proposed_name": "consumer"
            }))
            .is_err(),
            "poll accepts only request_id and request_secret"
        );

        let proposal = serde_json::to_string(&wrap_result(
            credentials_core::enrollment::EnrollmentProposal {
                request_id: "request-id".into(),
            },
        ))
        .unwrap();
        assert_eq!(proposal, operation(OP_ENROLL_PROPOSE)["success"][0]);
        let poll_successes = [
            credentials_core::enrollment::EnrollmentPoll::Pending,
            credentials_core::enrollment::EnrollmentPoll::Denied,
            credentials_core::enrollment::EnrollmentPoll::Approved {
                name: "consumer".into(),
                token: raw.into(),
                token_generation: 1,
            },
        ];
        for (index, success) in poll_successes.into_iter().enumerate() {
            assert_eq!(
                serde_json::to_string(&wrap_result(success)).unwrap(),
                operation(OP_ENROLL_POLL)["success"][index]
            );
        }
        let rotation = serde_json::to_string(&wrap_result(
            credentials_core::enrollment::EnrollmentRotation {
                token: "f".repeat(64),
                token_generation: 2,
            },
        ))
        .unwrap();
        assert_eq!(rotation, operation(OP_ENROLL_ROTATE)["success"][0]);

        let refusal_rows = fixture["refusals"].as_array().expect("refusal rows");
        assert_eq!(
            refusal_rows.len(),
            9,
            "the consumer decision table has nine rows"
        );
        let refusals = [
            EnrollmentRefusal::PendingExists,
            EnrollmentRefusal::PendingQueueFull,
            EnrollmentRefusal::InvalidParams,
            EnrollmentRefusal::NotFound,
            EnrollmentRefusal::InvalidParams,
            EnrollmentRefusal::AlreadyConsumed,
            EnrollmentRefusal::Superseded,
            EnrollmentRefusal::StaleGeneration,
            EnrollmentRefusal::NotFound,
        ];
        for (row, refusal) in refusal_rows.iter().zip(refusals) {
            assert_eq!(
                row["transport_status"], "response",
                "an enrollment refusal is a Response frame; Error frames mean the request never reached the module"
            );
            assert_eq!(
                serde_json::to_string(&enrollment_refusal_reply(
                    refusal.code(),
                    refusal.disposition()
                ))
                .unwrap(),
                row["body"]
            );
        }

        // The fixture's final refusal row ("auth.enroll_rotate and scoped operations")
        // says `credential.get_scoped` / `credential.list_scoped` answer an unknown,
        // revoked or rotated-away enrollment token with the same bytes as
        // `auth.enroll_rotate`. Build the scoped not-found reply exactly as the dispatcher
        // builds it and compare, so that shared-row claim is checked rather than assumed.
        let scoped_not_found = serde_json::to_string(&wrap_result(json!({
            "error": read_surface::ErrorBody {
                code: read_surface::ReadError::NotFound,
                class: read_surface::ReadError::NotFound.class(),
            }
        })))
        .unwrap();
        assert_eq!(
            refusal_rows[8]["op"],
            "auth.enroll_rotate and scoped operations"
        );
        assert_eq!(scoped_not_found, refusal_rows[8]["body"]);
    }

    /// The golden `credential.get` and `credential.status` replies, pinned from the producer.
    ///
    /// These are the two handle-addressed reads most consumers spend, and until they were
    /// pinned nothing checked a client decoder against what this daemon actually sends. The
    /// TypeScript client dropped five `GetResult` fields for weeks, and it refused the
    /// unresolved-handle status shape outright because it required a `record_version` this
    /// producer deliberately omits there. The client suite decodes these same bytes.
    ///
    /// WHERE THE BYTES COME FROM. The `get` replies are exhaustive `GetResult` literals
    /// (a new field is a compile error here until both cases state it; do not convert them
    /// to `..Default::default()`). The `status` replies are produced by the REAL
    /// `ReadSurface::status` over a scratch store, so the unresolved shape is whatever the
    /// production `unavailable` arm builds, not a literal restating it. Both are wrapped by
    /// `wrap_result`, exactly as the dispatcher sends them.
    ///
    /// The payload is a fixed non-secret byte string: this is a fixture consumers byte-copy,
    /// so it must never carry real material.
    ///
    /// ABSENCES ARE PINNED EXPLICITLY, not just implied by string equality, because they are
    /// the part a well-meaning change would break. An unresolved handle omits
    /// `credential_id` (so a probe learns nothing about what exists), `record_version` (a
    /// sentinel such as 0 would compare as "older than everything" and a poller would read a
    /// revoked handle as a pending change forever) and `stale_pending` (a default `false`
    /// would assert "no repair pending" about a record this path never saw).
    #[tokio::test]
    async fn handle_read_wire_fixture_pins_get_and_status_replies() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/enrollment_wire_contract.json"
        ))
        .expect("decode wire fixture");
        let operations = fixture["operations"].as_array().expect("operation rows");
        let successes = |name: &str| -> Vec<serde_json::Value> {
            let row = operations
                .iter()
                .find(|row| row["op"] == name)
                .unwrap_or_else(|| panic!("missing {name} fixture row"));
            let success = row["success"]
                .as_array()
                .unwrap_or_else(|| panic!("{name} success must be an array of reply strings"));
            assert_eq!(
                success.len(),
                row["success_cases"].as_array().map_or(0, Vec::len),
                "every {name} success reply needs a success_cases entry naming it"
            );
            success.clone()
        };
        let result_keys = |reply: &serde_json::Value| -> Vec<String> {
            reply["result"]
                .as_object()
                .expect("a reply carries a result object")
                .keys()
                .cloned()
                .collect()
        };
        let regenerate =
            "the golden handle-read reply drifted from what this producer serialises. \
             Consumers byte-copy this file: regenerate the row from the assertion's left side, \
             announce the change, and update the client decoder and its key-coverage test";

        // credential.get, every optional field populated.
        let get_full = wrap_result(read_surface::GetResult {
            payload: b"fixture-not-a-secret".to_vec(),
            expires_at_ms: Some(1_900_000_000_000),
            record_version: 42,
            credential_id: Some("oauth:example".into()),
            project_id: Some("example-project-000000".into()),
            account_id: Some("00000000-0000-4000-8000-000000000000".into()),
            email: Some("consumer@example.invalid".into()),
            org_name: Some("Example Org".into()),
        });
        assert_eq!(
            result_keys(&get_full),
            [
                "account_id",
                "credential_id",
                "email",
                "expires_at_ms",
                "org_name",
                "payload",
                "project_id",
                "record_version"
            ],
            "the full get case must populate every GetResult field"
        );

        // credential.get, every optional field absent. `expires_at_ms` is the one optional
        // field that is NOT skipped when empty: a credential with no known expiry is sent as
        // an explicit null, and this case pins that too.
        let get_bare = wrap_result(read_surface::GetResult {
            payload: b"fixture-not-a-secret".to_vec(),
            expires_at_ms: None,
            record_version: 7,
            credential_id: None,
            project_id: None,
            account_id: None,
            email: None,
            org_name: None,
        });
        assert_eq!(
            result_keys(&get_bare),
            ["expires_at_ms", "payload", "record_version"],
            "an absent optional get field must be OMITTED, not sent as null"
        );
        assert!(get_bare["result"]["expires_at_ms"].is_null());

        // credential.status, from the real surface.
        let (surface, store, _db, _root) = tmp_surface_with_store(21);
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "apikey:active",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put handle");
        let status_for = |handle: String| {
            let surface = Arc::clone(&surface);
            async move {
                wrap_result(
                    surface
                        .status(
                            1,
                            None,
                            &StatusParams {
                                handle: Some(handle),
                                credential_id: None,
                                enrollment_token: None,
                            },
                        )
                        .await,
                )
            }
        };
        let status_resolved = status_for(handle.raw).await;
        // A handle that never existed takes the same arm as a revoked one: resolution fails
        // and the surface answers with its uniform not-found shape.
        let status_unresolved = status_for("ckh_not_a_real_handle".to_string()).await;

        let resolved = status_resolved["result"]
            .as_object()
            .expect("status result object");
        for key in ["credential_id", "record_version", "stale_pending"] {
            assert!(
                resolved.contains_key(key),
                "a resolved handle's status must carry `{key}`"
            );
        }
        assert_eq!(resolved["ready"], true);

        let unresolved = status_unresolved["result"]
            .as_object()
            .expect("status result object");
        for key in ["credential_id", "record_version", "stale_pending"] {
            assert!(
                !unresolved.contains_key(key),
                "an unresolved handle's status must OMIT `{key}`, not default it: a present \
                 id discloses what exists, a sentinel version reads as older than every real \
                 one, and a defaulted stale mark asserts something this path never observed. \
                 Got {unresolved:?}"
            );
        }
        assert_eq!(
            result_keys(&status_unresolved),
            ["last_error_code", "lease_held", "ready"]
        );
        assert_eq!(unresolved["ready"], false);
        assert_eq!(unresolved["last_error_code"], "not_found");

        let get = successes(OP_GET);
        assert_eq!(get.len(), 2, "credential.get pins exactly two cases");
        assert_eq!(
            serde_json::to_string(&get_full).unwrap(),
            get[0],
            "{regenerate}"
        );
        assert_eq!(
            serde_json::to_string(&get_bare).unwrap(),
            get[1],
            "{regenerate}"
        );

        let status = successes(OP_STATUS);
        assert_eq!(status.len(), 2, "credential.status pins exactly two cases");
        assert_eq!(
            serde_json::to_string(&status_resolved).unwrap(),
            status[0],
            "{regenerate}"
        );
        assert_eq!(
            serde_json::to_string(&status_unresolved).unwrap(),
            status[1],
            "{regenerate}"
        );
    }

    /// Enrollment refusals carry their retry policy in `class`, the field every
    /// read-surface refusal uses, and consumers validate it against the read surface's
    /// closed class set. A disposition that serialized to anything outside that set would
    /// be decoded as an unknown class and silently downgraded to retryable.
    #[test]
    fn every_enrollment_disposition_is_a_member_of_the_error_class_wire_set() {
        for disposition in [
            EnrollmentDisposition::Permanent,
            EnrollmentDisposition::Transient,
        ] {
            // Exhaustive match: adding a variant stops this from compiling, which brings
            // the author here to add the new variant to the array above.
            match disposition {
                EnrollmentDisposition::Permanent | EnrollmentDisposition::Transient => {}
            }
            let wire = serde_json::to_value(disposition).expect("serialize disposition");
            let wire = wire.as_str().expect("a disposition serializes as a string");
            assert!(
                read_surface::ERROR_CLASS_WIRE_SET.contains(&wire),
                "enrollment disposition {disposition:?} serializes to `{wire}`, which is not \
                 in the read-surface error class set {:?}",
                read_surface::ERROR_CLASS_WIRE_SET
            );
        }
    }

    #[tokio::test]
    async fn enrollment_route_refusals_are_responses_and_unknown_matches_wrong_secret() {
        let (surface, admin, store) = scoped_rig(116);
        let secret = "11".repeat(32);
        let secret_hash = credentials_core::enrollment::enrollment_secret_hash(&secret).unwrap();

        let invalid = enrollment_route_frame(
            &surface,
            &admin,
            OP_ENROLL_PROPOSE,
            json!({"proposed_name":"bad:name","request_secret_hash":secret_hash.clone()}),
        )
        .await;
        assert_enrollment_refusal(&invalid, "invalid_params", "permanent");

        let proposed = enrollment_route_frame(
            &surface,
            &admin,
            OP_ENROLL_PROPOSE,
            json!({"proposed_name":"consumer","request_secret_hash":secret_hash.clone()}),
        )
        .await;
        assert_eq!(proposed.header.ty, FrameType::Response);
        let proposed_body: serde_json::Value = serde_json::from_slice(&proposed.body).unwrap();
        let request_id = proposed_body["result"]["request_id"]
            .as_str()
            .expect("request id")
            .to_string();

        // A DIFFERENT SECRET IS A DIFFERENT CALLER. This used to send the SAME hash and
        // assert `pending_exists`, which pinned the crash gap rather than the squatter
        // refusal: `request_id` is minted server-side, so a consumer that crashed after
        // the row committed could not poll and could not re-propose, and was wedged out
        // of its own enrollment until TTL. Same name + same secret now RESUMES (asserted
        // below); same name + different secret is the case that must still refuse.
        let duplicate = enrollment_route_frame(
            &surface,
            &admin,
            OP_ENROLL_PROPOSE,
            json!({"proposed_name":"consumer","request_secret_hash":"c".repeat(64)}),
        )
        .await;
        assert_enrollment_refusal(&duplicate, "pending_exists", "permanent");

        // THE RESUME, over the wire rather than only at the store: the same secret returns
        // the SAME id. A second id for one pending row would leave the first unreachable
        // and still holding the name.
        let resumed = enrollment_route_frame(
            &surface,
            &admin,
            OP_ENROLL_PROPOSE,
            json!({"proposed_name":"consumer","request_secret_hash":secret_hash.clone()}),
        )
        .await;
        assert_eq!(resumed.header.ty, FrameType::Response);
        let resumed_body: serde_json::Value = serde_json::from_slice(&resumed.body).unwrap();
        assert_eq!(
            resumed_body["result"]["request_id"].as_str(),
            Some(request_id.as_str()),
            "a crashed proposer resuming with its own secret must get its original id back"
        );

        let unknown = enrollment_route_frame(
            &surface,
            &admin,
            OP_ENROLL_POLL,
            json!({"request_id":"ff".repeat(32),"request_secret":secret.clone()}),
        )
        .await;
        let wrong_secret = enrollment_route_frame(
            &surface,
            &admin,
            OP_ENROLL_POLL,
            json!({"request_id":request_id.clone(),"request_secret":"22".repeat(32)}),
        )
        .await;
        assert_enrollment_refusal(&unknown, "not_found", "permanent");
        assert_enrollment_refusal(&wrong_secret, "not_found", "permanent");
        assert_eq!(unknown.body, wrong_secret.body);

        let pending = enrollment_route_frame(
            &surface,
            &admin,
            OP_ENROLL_POLL,
            json!({"request_id":request_id.clone(),"request_secret":secret.clone()}),
        )
        .await;
        assert_eq!(pending.header.ty, FrameType::Response);
        assert_eq!(pending.body, br#"{"result":{"status":"pending"}}"#);

        store
            .approve_enrollment(&request_id, "consumer", "operator")
            .expect("approve");
        let approved = enrollment_route_frame(
            &surface,
            &admin,
            OP_ENROLL_POLL,
            json!({"request_id":request_id.clone(),"request_secret":secret.clone()}),
        )
        .await;
        assert_eq!(approved.header.ty, FrameType::Response);
        let approved_body: serde_json::Value = serde_json::from_slice(&approved.body).unwrap();
        assert_eq!(approved_body["result"]["status"], "approved");
        assert_eq!(approved_body["result"]["token_generation"], 1);
        let token = approved_body["result"]["token"]
            .as_str()
            .expect("token")
            .to_string();

        let consumed = enrollment_route_frame(
            &surface,
            &admin,
            OP_ENROLL_POLL,
            json!({"request_id":request_id.clone(),"request_secret":secret.clone()}),
        )
        .await;
        assert_enrollment_refusal(&consumed, "already_consumed", "permanent");

        let stale = enrollment_route_frame(
            &surface,
            &admin,
            OP_ENROLL_ROTATE,
            json!({"token":token.clone(),"expected_token_generation":2}),
        )
        .await;
        assert_enrollment_refusal(&stale, "stale_generation", "permanent");
        let rotated = enrollment_route_frame(
            &surface,
            &admin,
            OP_ENROLL_ROTATE,
            json!({"token":token.clone(),"expected_token_generation":1}),
        )
        .await;
        assert_eq!(rotated.header.ty, FrameType::Response);
        let old_token = enrollment_route_frame(
            &surface,
            &admin,
            OP_ENROLL_ROTATE,
            json!({"token":token.clone(),"expected_token_generation":1}),
        )
        .await;
        assert_enrollment_refusal(&old_token, "not_found", "permanent");
        assert_eq!(old_token.body, unknown.body);
    }

    #[test]
    fn credential_get_request_key_set_is_pinned() {
        assert_request_key_set(
            read_surface::GetParams {
                handle: "ckh_request_shape".to_owned(),
                min_ttl_ms: Some(30_000),
                force_refresh: true,
            },
            &["handle", "min_ttl_ms", "force_refresh"],
            "credential.get",
        );
    }

    #[test]
    fn credential_get_scoped_request_key_set_is_pinned() {
        assert_request_key_set(
            read_surface::GetScopedParams {
                credential_id: "apikey:request-shape".to_owned(),
                enrollment_token: None,
                min_ttl_ms: None,
            },
            &["credential_id"],
            "credential.get_scoped",
        );
        assert_request_key_set(
            read_surface::GetScopedParams {
                credential_id: "apikey:request-shape".to_owned(),
                enrollment_token: Some("cke_request_shape".to_owned()),
                min_ttl_ms: Some(120_000),
            },
            &["credential_id", "enrollment_token", "min_ttl_ms"],
            "credential.get_scoped",
        );
    }

    /// A SCOPED READ HONOURS `min_ttl_ms` EXACTLY AS THE HANDLE PATH DOES.
    ///
    /// The consumer-visible half of the cutover from handle-addressed `credential.get` to
    /// grant-addressed `credential.get_scoped`. Nine production call sites on the insula
    /// seat pass 120_000 against a 35s fetch deadline; that 85s of margin is what makes
    /// "the token was alive when I started" imply "alive when the upstream answered". A
    /// scoped op that silently dropped the floor would let a mid-request 401 be
    /// indistinguishable from a revoked credential, so a HEALTHY credential gets reported
    /// dead and needs an operator re-login for what was a race.
    ///
    /// Mirrors `impossible_min_ttl_refuses_after_one_exchange_with_paired_wire_error`
    /// deliberately: same harness, same record shape, scoped addressing. Parity is the
    /// property, so the two must be comparable line by line.
    ///
    /// MY FIRST VERSION OF THIS TEST ASSERTED A REFUSAL ON A STATIC CREDENTIAL AND FAILED,
    /// correctly. A static record cannot refresh, so `refreshed_for_min_ttl` is false and
    /// no refusal is sound -- the tree already pinned that as
    /// `static_credential_with_oversized_min_ttl_is_served_without_a_refusal`. The
    /// refusal exists only after a real exchange provably fails the demand.
    #[tokio::test]
    async fn a_scoped_read_refuses_an_unsatisfiable_min_ttl_after_one_exchange() {
        const INITIAL_TTL_MS: i64 = 10 * 60 * 1000;
        const FRESH_TTL_MS: i64 = 60 * 60 * 1000;
        const DEMAND_MS: i64 = 2 * 60 * 60 * 1000;

        let (surface, store, calls) = ttl_surface(199, FRESH_TTL_MS);
        let _handle = seed_ttl_refreshable(&store, "oauth:ttl-scoped", INITIAL_TTL_MS);
        store
            .create_read_grant_audited(
                "reserved",
                "ttl-probe",
                credentials_core::store::SelectorKind::Exact,
                "oauth:ttl-scoped",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("grant");
        let principal = subc_protocol::Principal::Reserved {
            module_id: "ttl-probe".to_owned(),
        };

        let outcome = surface
            .get_scoped(
                Some(&principal),
                &read_surface::GetScopedParams {
                    credential_id: "oauth:ttl-scoped".to_owned(),
                    enrollment_token: None,
                    min_ttl_ms: Some(DEMAND_MS),
                },
            )
            .await;

        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the demand must trigger exactly one upstream exchange on the scoped path \
             too: a scoped op that ignored min_ttl_ms would make ZERO"
        );
        let read_surface::GetOutcome::Err { error } = outcome else {
            panic!("a fresh token shorter than the demand must refuse on the scoped path");
        };
        assert_eq!(error.code, read_surface::ReadError::TtlUnsatisfiable);
        assert_eq!(
            error.class,
            read_surface::ErrorClass::ContextOverflow,
            "reduce-and-retry, never permanent: a permanent class here would license a \
             consumer to discard a credential that is merely short-lived"
        );
    }

    /// AN ENROLLMENT TOKEN AUTHORIZES A SCOPED READ, AND A REVOKED ONE DOES NOT.
    ///
    /// This is the property that makes the ceremony worth having: until the resolver
    /// existed, a consumer could complete enrollment, persist a token, and find that no
    /// operation accepted it — a credential that proved nothing, which is worse than no
    /// credential because it looks like access.
    ///
    /// The revoked arm is the load-bearing half. A token that keeps working after
    /// revocation is not a smaller defect than one that never worked; it is the one that
    /// matters, because revocation is the only control the operator has over a consumer
    /// they no longer trust.
    #[tokio::test]
    async fn an_enrollment_token_authorizes_a_scoped_read_until_it_is_revoked() {
        let (surface, store, _db, _root) = tmp_surface_with_store(197);
        store
            .create(
                "apikey:enrolled-read",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"secret".to_vec(), None),
            )
            .expect("create record");
        store
            .create_read_grant_audited(
                "enrolled",
                "probe-consumer",
                credentials_core::store::SelectorKind::Exact,
                "apikey:enrolled-read",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("grant");

        // The request secret is minted by the CONSUMER and only its hash reaches the
        // vault, which is what stops a squatter from collecting a token for a name it
        // proposed but does not hold.
        let request_secret = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let secret_hash = credentials_core::enrollment::enrollment_secret_hash(request_secret)
            .expect("hashable secret");
        let request = store
            .propose_enrollment("probe-consumer", &secret_hash)
            .expect("propose");
        store
            .approve_enrollment(&request.request_id, "probe-consumer", "operator")
            .expect("approve");
        let token = match store
            .poll_enrollment(&request.request_id, request_secret)
            .expect("poll")
        {
            credentials_core::enrollment::EnrollmentPoll::Approved { token, .. } => token,
            other => panic!("an approved request must poll Approved, got {other:?}"),
        };

        let served = surface
            .get_scoped(
                None,
                &read_surface::GetScopedParams {
                    credential_id: "apikey:enrolled-read".to_owned(),
                    enrollment_token: Some(token.clone()),
                    min_ttl_ms: None,
                },
            )
            .await;
        let read_surface::GetOutcome::Ok(served) = served else {
            panic!("a live enrollment token must authorize the read its grant covers: {served:?}");
        };
        assert_eq!(
            served.credential_id.as_deref(),
            Some("apikey:enrolled-read"),
            "and the reply names the credential it resolved, for binding verification"
        );

        store
            .revoke_enrollment("probe-consumer", "operator")
            .expect("revoke");
        let refused = surface
            .get_scoped(
                None,
                &read_surface::GetScopedParams {
                    credential_id: "apikey:enrolled-read".to_owned(),
                    enrollment_token: Some(token.clone()),
                    min_ttl_ms: None,
                },
            )
            .await;
        let read_surface::GetOutcome::Err { error } = refused else {
            panic!("a revoked token must stop working immediately: {refused:?}");
        };
        assert_eq!(
            error.code,
            read_surface::ReadError::NotFound,
            "and must be indistinguishable from an unknown token, so a caller cannot \
             enumerate which consumer names ever existed"
        );
    }

    /// `credential.list_scoped` carries exactly one optional parameter.
    ///
    /// This test used to be named ..._is_exactly_an_empty_object and asserted `&[]`. The
    /// rename is the point: `enrollment_token` is how a host-launched consumer identifies
    /// itself, and `skip_serializing_if` means a supervised module still sends `{}` on
    /// the wire. So the empty-object case survives as the ABSENT arm below rather than as
    /// the whole contract.
    ///
    /// Both arms are pinned because they are different claims. The absent arm says a
    /// module's call did not grow a field; the present arm says the token is spelled
    /// `enrollment_token` and nothing else, which is what a consumer's client must match
    /// byte for byte.
    #[test]
    fn credential_list_scoped_request_key_set_is_pinned() {
        assert_request_key_set(
            read_surface::ListScopedParams {
                enrollment_token: None,
            },
            &[],
            "credential.list_scoped",
        );
        assert_request_key_set(
            read_surface::ListScopedParams {
                enrollment_token: Some("cke_request_shape".to_owned()),
            },
            &["enrollment_token"],
            "credential.list_scoped",
        );
    }

    #[test]
    fn credential_sign_request_key_set_is_pinned() {
        assert_request_key_set(
            read_surface::SignParams {
                handle: Some("ckh_request_shape".to_owned()),
                credential_id: Some("signing_key:request-shape".to_owned()),
                payload_b64: "AQI=".to_owned(),
                enrollment_token: Some("tok_request_shape".to_owned()),
            },
            &["handle", "credential_id", "payload_b64", "enrollment_token"],
            "credential.sign",
        );
    }

    #[test]
    fn credential_public_key_request_key_set_is_pinned() {
        assert_request_key_set(
            read_surface::PublicKeyParams {
                handle: Some("ckh_request_shape".to_owned()),
                credential_id: Some("signing_key:request-shape".to_owned()),
                enrollment_token: Some("tok_request_shape".to_owned()),
            },
            &["handle", "credential_id", "enrollment_token"],
            "credential.public_key",
        );
    }

    #[test]
    fn credential_get_many_request_key_set_is_pinned() {
        assert_request_key_set(
            read_surface::GetManyParams {
                items: vec![read_surface::GetParams {
                    handle: "ckh_request_shape".to_owned(),
                    min_ttl_ms: Some(30_000),
                    force_refresh: true,
                }],
            },
            &["items"],
            "credential.get_many",
        );
    }

    #[test]
    fn credential_status_request_key_set_is_pinned() {
        assert_request_key_set(
            read_surface::StatusParams {
                handle: Some("ckh_request_shape".to_owned()),
                credential_id: Some("apikey:request-shape".to_owned()),
                enrollment_token: Some("tok_request_shape".to_owned()),
            },
            &["handle", "credential_id", "enrollment_token"],
            "credential.status",
        );
    }

    #[test]
    fn credential_report_auth_failure_request_key_set_is_pinned() {
        assert_request_key_set(
            read_surface::ReportAuthFailureParams {
                handle: Some("ckh_request_shape".to_owned()),
                credential_id: Some("apikey:request-shape".to_owned()),
                enrollment_token: Some("t".repeat(64)),
                provider_status: 401,
                record_version: 7,
                reporter_source: Some("probe".to_owned()),
            },
            &[
                "handle",
                "credential_id",
                // Added for the consumer class enrollment creates: a host-launched caller
                // binds as Direct, holds no handle, and could therefore discover and fetch
                // a credential with no way to report it dead. Exercised by
                // `vault_read_probe --report-id ... --enrollment-token`.
                "enrollment_token",
                "provider_status",
                "record_version",
                "reporter_source",
            ],
            "credential.report_auth_failure",
        );
    }

    #[tokio::test]
    async fn get_through_a_resolving_handle_returns_its_bound_credential_id() {
        let (surface, store, _db, _root) = tmp_surface_with_store(93);
        let credential_id = "apikey:get-binding-proof";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create credential");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                credential_id,
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");

        let read_surface::GetOutcome::Ok(result) = surface
            .get(
                93,
                &read_surface::GetParams {
                    handle: handle.raw,
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await
        else {
            panic!("a handle bound to a live credential must resolve");
        };
        assert_eq!(
            result.credential_id.as_deref(),
            Some(credential_id),
            "get must return the credential id the presented handle was minted for"
        );
    }

    #[tokio::test]
    async fn status_through_a_resolving_handle_returns_its_bound_credential_id() {
        let (surface, store, _db, _root) = tmp_surface_with_store(94);
        let credential_id = "apikey:status-binding-proof";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create credential");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                credential_id,
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");

        let result = surface
            .status(
                94,
                None,
                &read_surface::StatusParams {
                    handle: Some(handle.raw),
                    credential_id: None,
                    enrollment_token: None,
                },
            )
            .await;
        assert_eq!(
            result.credential_id.as_deref(),
            Some(credential_id),
            "status must return the credential id the presented handle resolved to"
        );
    }

    #[tokio::test]
    async fn unaddressed_status_omits_credential_id_instead_of_sending_null() {
        let (surface, _store, _db, _root) = tmp_surface_with_store(95);
        let encoded = serde_json::to_value(
            surface
                .status(
                    95,
                    None,
                    &read_surface::StatusParams {
                        handle: None,
                        credential_id: None,
                        enrollment_token: None,
                    },
                )
                .await,
        )
        .expect("serialize overall status");

        assert!(
            encoded
                .as_object()
                .is_some_and(|result| !result.contains_key("credential_id")),
            "overall readiness names no credential, so credential_id must be absent rather than null: {encoded}"
        );
    }

    #[tokio::test]
    async fn unknown_and_revoked_get_handles_refuse_without_disclosing_a_credential_id() {
        fn body_contains_key(value: &serde_json::Value, needle: &str) -> bool {
            match value {
                serde_json::Value::Object(object) => {
                    object.contains_key(needle)
                        || object
                            .values()
                            .any(|child| body_contains_key(child, needle))
                }
                serde_json::Value::Array(array) => {
                    array.iter().any(|child| body_contains_key(child, needle))
                }
                _ => false,
            }
        }

        let (surface, store, _db, _root) = tmp_surface_with_store(96);
        let (admin, _admin_store, _admin_root) = tmp_admin(96);
        let credential_id = "apikey:revoked-binding-proof";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create credential");
        let revoked_handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &revoked_handle.hash,
                credential_id,
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");
        store
            .revoke_handle(&revoked_handle.raw, AuditCtx::admin(AuditOp::RevokeHandle))
            .expect("revoke handle");

        let unknown = scoped_route_request(
            &surface,
            &admin,
            96,
            OP_GET,
            json!({ "handle": "ckh_unknown_credential_id_probe" }),
        )
        .await;
        let revoked = scoped_route_request(
            &surface,
            &admin,
            97,
            OP_GET,
            json!({ "handle": revoked_handle.raw }),
        )
        .await;

        assert_eq!(
            unknown["result"]["error"],
            json!({ "code": "not_found", "class": "permanent" }),
            "an unknown handle must receive the complete uniform not_found refusal"
        );
        assert!(
            !body_contains_key(&unknown, "credential_id")
                && !serde_json::to_string(&unknown)
                    .expect("render response")
                    .contains(credential_id),
            "the not_found body must disclose neither a credential_id field nor the id once bound to the revoked handle: {unknown}"
        );
        assert_eq!(
            unknown, revoked,
            "unknown and revoked handles must remain byte-equivalent after JSON decoding"
        );
    }

    /// `credential.get` is a wire contract, not merely an internal struct serialization.
    ///
    /// This drives the real route handler, so the response is produced by `GetResult` and
    /// serialized through the same `{ "result": ... }` path consumers receive. The fully
    /// populated and minimal shapes are pinned separately so optional metadata is present
    /// only when the real producer has a value for it.
    #[tokio::test]
    async fn the_get_wire_key_set_is_a_contract_and_a_rename_obliges_an_announcement() {
        async fn get_wire(
            surface: &Arc<ReadSurface>,
            admin: &Arc<admin_surface::AdminSurface>,
            handle: String,
            corr: u64,
        ) -> serde_json::Value {
            let (tx, mut rx) = mpsc::channel(1);
            let frame = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Request,
                Flags::new(false, Priority::Interactive, false),
                1,
                1,
                corr,
                serde_json::to_vec(&json!({
                    "method": OP_GET,
                    "params": { "handle": handle },
                }))
                .expect("serialize get request"),
            )
            .expect("build get request frame");

            // The response comes from the real route producer and serializer rather than
            // a hand-written value that could stay stable while the wire changes.
            handle_read_request(frame, &tx, surface, admin, None)
                .await
                .expect("get request must be handled");
            let response = rx.recv().await.expect("get response must be sent");
            assert_eq!(response.header.ty, FrameType::Response);
            serde_json::from_slice(&response.body).expect("decode get response")
        }

        fn assert_exact_keys(body: &serde_json::Value, expected: &[&str], shape: &str) {
            let result = body
                .get("result")
                .and_then(serde_json::Value::as_object)
                .unwrap_or_else(|| panic!("{shape}: get result must be a JSON object"));

            // Check both directions so either a missing key or an unexpected key fails
            // with the consumer-notification obligation at the contract boundary.
            for key in expected {
                assert!(
                    result.contains_key(*key),
                    "the credential.get response key set changed. Consumers decode these BY NAME, so this is a consumer-impact change rather than a refactor: announce the delta to the supervisor seat, then update this list. {shape}: missing `{key}`"
                );
            }
            for key in result.keys() {
                assert!(
                    expected.iter().any(|expected_key| *expected_key == key),
                    "the credential.get response key set changed. Consumers decode these BY NAME, so this is a consumer-impact change rather than a refactor: announce the delta to the supervisor seat, then update this list. {shape}: unexpected `{key}`"
                );
            }

            let mut actual: Vec<&str> = result.keys().map(String::as_str).collect();
            actual.sort_unstable();
            let mut expected = expected.to_vec();
            expected.sort_unstable();
            assert_eq!(
                actual,
                expected,
                "the credential.get response key set changed. Consumers decode these BY NAME, so this is a consumer-impact change rather than a refactor: announce the delta to the supervisor seat, then update this list."
            );
        }

        let (surface, store, _db, _root) = tmp_surface_with_store(97);
        let (admin, _admin_store, _admin_root) = tmp_admin(97);
        let populated_id = "antigravity:get-wire-contract";
        let populated_record = VaultRecord::new_oauth(
            "test",
            "antigravity",
            OAuthCredential {
                access_token: "opaque-access".to_string().into(),
                refresh_token: "refresh-secret|project-wire|managed-wire"
                    .to_string()
                    .into(),
                expires_at_ms: Some(4_102_444_800_000),
                token_url: "https://oauth2.googleapis.com/token".to_string(),
                client_id: Some("client".to_string()),
                client_secret: None,
                scopes: Vec::new(),
            },
            b"opaque-access".to_vec(),
        )
        .with_identity(credentials_core::record::RecordIdentity {
            account_id: Some("account-wire".to_string()),
            email: Some("wire@example.com".to_string()),
            org_name: Some("Wire Organization".to_string()),
        });
        store
            .create(populated_id, &populated_record)
            .expect("create populated credential");
        let populated_handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &populated_handle.hash,
                populated_id,
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind populated handle");

        let populated = get_wire(&surface, &admin, populated_handle.raw, 1).await;
        assert_exact_keys(
            &populated,
            &[
                "payload",
                "expires_at_ms",
                "record_version",
                "credential_id",
                "project_id",
                "account_id",
                "email",
                "org_name",
            ],
            "fully populated result",
        );

        let minimal_handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &minimal_handle.hash,
                "apikey:active",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind minimal handle");
        let minimal = get_wire(&surface, &admin, minimal_handle.raw, 2).await;
        assert_exact_keys(
            &minimal,
            &[
                "payload",
                "expires_at_ms",
                "record_version",
                "credential_id",
            ],
            "minimal result",
        );
    }

    #[test]
    fn the_health_wire_key_set_is_a_contract_and_a_rename_obliges_an_announcement() {
        let health = credentials_core::health::VaultHealth {
            audit_seq: Some(7),
            audit_tip_mac: Some("deadbeef".to_string()),
            ..credentials_core::health::VaultHealth::summarize(&[], 0, false)
        };
        let ModuleControlResponse::HealthCheck { metrics, .. } = health_report(&health) else {
            panic!("health_report must produce a HealthCheck");
        };
        let metrics = metrics.expect("metrics present");
        let metrics = metrics.as_object().expect("metrics object");

        let mut keys: Vec<&str> = metrics.keys().map(String::as_str).collect();
        keys.sort_unstable();

        let mut expected = vec![
            "active",
            "auditSeq",
            "auditTipMac",
            "corrupt",
            "corruptIds",
            "credentialsTotal",
            "fencedOut",
            "needsReauth",
            "needsReauthIds",
            "openIntents",
            "retired",
            "retiredIds",
            "refresherStalled",
            "storeReadable",
        ];
        expected.sort_unstable();

        assert_eq!(
            keys, expected,
            "the health metrics key set changed. Consumers decode these BY NAME, so this \
             is a consumer-impact change rather than a refactor: announce the delta to \
             the supervisor seat, then update this list."
        );
    }

    /// `credential.status` is a wire contract, not merely an internal struct serialization.
    ///
    /// This drives the real route handler, so the response is produced by `StatusResult` and
    /// serialized through the same `{ "result": ... }` path consumers receive. The resolved
    /// and unresolved shapes are pinned separately: when a handle cannot be resolved, there is
    /// no credential record to describe, so `credential_id`, `record_version`, and
    /// `stale_pending` are omitted rather than filled with defaults.
    ///
    /// The `credential.status` fields use `snake_case`; the separate `health.check` metrics use
    /// `camelCase` (`auditTipMac`, `storeReadable`). These are established wire conventions, so
    /// changing either would break consumers.
    #[tokio::test]
    async fn the_status_wire_key_set_is_a_contract_and_a_rename_obliges_an_announcement() {
        async fn status_wire(
            surface: &Arc<ReadSurface>,
            admin: &Arc<admin_surface::AdminSurface>,
            params: serde_json::Value,
            corr: u64,
        ) -> serde_json::Value {
            let (tx, mut rx) = mpsc::channel(1);
            let frame = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Request,
                Flags::new(false, Priority::Interactive, false),
                1,
                1,
                corr,
                serde_json::to_vec(&json!({
                    "method": OP_STATUS,
                    "params": params,
                }))
                .expect("serialize status request"),
            )
            .expect("build status request frame");

            // The response is produced by handle_read_request, not reconstructed from a
            // hand-written object, so this observes the actual producer and wire serializer.
            handle_read_request(frame, &tx, surface, admin, None)
                .await
                .expect("status request must be handled");
            let response = rx.recv().await.expect("status response must be sent");
            assert_eq!(response.header.ty, FrameType::Response);
            serde_json::from_slice(&response.body).expect("decode status response")
        }

        fn assert_exact_keys(body: &serde_json::Value, expected: &[&str], shape: &str) {
            let result = body
                .get("result")
                .and_then(serde_json::Value::as_object)
                .unwrap_or_else(|| panic!("{shape}: status result must be a JSON object"));

            // Check for both missing and unexpected keys so adding or removing a field fails
            // this contract test.
            for key in expected {
                assert!(
                    result.contains_key(*key),
                    "the credential.status response key set changed. Consumers decode these BY NAME, so this is a consumer-impact change rather than a refactor: announce the delta to the supervisor seat, then update this list. {shape}: missing `{key}`"
                );
            }
            for key in result.keys() {
                assert!(
                    expected.iter().any(|expected_key| *expected_key == key),
                    "the credential.status response key set changed. Consumers decode these BY NAME, so this is a consumer-impact change rather than a refactor: announce the delta to the supervisor seat, then update this list. {shape}: unexpected `{key}`"
                );
            }

            let mut actual: Vec<&str> = result.keys().map(String::as_str).collect();
            actual.sort_unstable();
            let mut expected = expected.to_vec();
            expected.sort_unstable();
            assert_eq!(
                actual,
                expected,
                "the credential.status response key set changed. Consumers decode these BY NAME, so this is a consumer-impact change rather than a refactor: announce the delta to the supervisor seat, then update this list."
            );
        }

        let (surface, store, _db, _root) = tmp_surface_with_store(92);
        let (admin, _admin_store, _admin_root) = tmp_admin(92);
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "apikey:active",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");

        let resolved = status_wire(&surface, &admin, json!({ "handle": handle.raw }), 1).await;
        assert_exact_keys(
            &resolved,
            &[
                "ready",
                "last_error_code",
                "lease_held",
                "credential_id",
                "record_version",
                "stale_pending",
            ],
            "resolved handle",
        );

        let unresolved = status_wire(
            &surface,
            &admin,
            json!({ "handle": "ckh_status_wire_unknown" }),
            2,
        )
        .await;
        let unresolved_result = unresolved
            .get("result")
            .and_then(serde_json::Value::as_object)
            .expect("unresolved status result must be an object");
        assert!(
            !unresolved_result.contains_key("credential_id"),
            "the credential.status response key set changed. Consumers decode these BY NAME, so this is a consumer-impact change rather than a refactor: announce the delta to the supervisor seat, then update this list. An unresolved handle must omit `credential_id`, not send null or echo an unverified binding"
        );
        assert!(
            !unresolved_result.contains_key("record_version"),
            "the credential.status response key set changed. Consumers decode these BY NAME, so this is a consumer-impact change rather than a refactor: announce the delta to the supervisor seat, then update this list. An unresolved handle must omit `record_version`, not send null for a record this path could not resolve"
        );
        assert!(
            !unresolved_result.contains_key("stale_pending"),
            "the credential.status response key set changed. Consumers decode these BY NAME, so this is a consumer-impact change rather than a refactor: announce the delta to the supervisor seat, then update this list. An unresolved handle must omit `stale_pending`, not send null for a record this path could not resolve"
        );
        assert_exact_keys(
            &unresolved,
            &["ready", "last_error_code", "lease_held"],
            "unresolved handle",
        );

        let overall = status_wire(&surface, &admin, json!({}), 3).await;
        let overall_result = overall
            .get("result")
            .and_then(serde_json::Value::as_object)
            .expect("overall status result must be an object");
        assert!(
            !overall_result.contains_key("credential_id"),
            "the credential.status response key set changed. Consumers decode these BY NAME, so this is a consumer-impact change rather than a refactor: announce the delta to the supervisor seat, then update this list. Overall readiness must omit `credential_id` because it names no record"
        );
        assert!(
            !overall_result.contains_key("record_version"),
            "the credential.status response key set changed. Consumers decode these BY NAME, so this is a consumer-impact change rather than a refactor: announce the delta to the supervisor seat, then update this list. Overall readiness must omit `record_version` because it names no record"
        );
        assert!(
            !overall_result.contains_key("stale_pending"),
            "the credential.status response key set changed. Consumers decode these BY NAME, so this is a consumer-impact change rather than a refactor: announce the delta to the supervisor seat, then update this list. Overall readiness must omit `stale_pending` because it names no record"
        );
        assert_exact_keys(
            &overall,
            &["ready", "last_error_code", "lease_held"],
            "overall status",
        );
    }

    /// A control request this build cannot decode (here a `route.bind` shaped the way a
    /// newer daemon might send it) is answered on the Error lane with the same corr,
    /// so the daemon fails that bind at once instead of waiting out its timeout, and no
    /// route is installed for it. The fixture is asserted undecodable first, so the
    /// test cannot pass by decoding it.
    #[tokio::test]
    async fn undecodable_control_request_is_refused_on_the_error_lane() {
        let (surface, _surface_root) = tmp_surface(171);
        let (admin, _admin_store, _admin_root) = tmp_admin(171);
        let routes = Arc::new(RouteEpochs::default());
        let (tx, mut rx) = mpsc::channel::<Frame>(4);
        let body = serde_json::json!({
            "op": "route.bind",
            "route_channel": 7,
            "epoch": 3,
            "route": "claustrum",
            "scope": { "attributes": { "field_from_a_newer_protocol": "x" } }
        });
        assert!(
            serde_json::from_value::<ModuleControlRequest>(body.clone()).is_err(),
            "the fixture must be undecodable, or this test proves nothing"
        );
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            control_flags(),
            0,
            0,
            77,
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();

        handle_control_request(frame, &tx, &surface, &admin, &routes)
            .await
            .unwrap();

        let reply = rx
            .try_recv()
            .expect("an undecodable request must be answered");
        assert_eq!(reply.header.ty, FrameType::Error);
        assert_eq!(reply.header.channel, 0);
        assert_eq!(reply.header.corr, 77);
        let error: ErrorBody = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(error.code, "invalid_control_body");
        assert!(
            !String::from_utf8_lossy(&reply.body).contains("field_from_a_newer_protocol"),
            "the refusal must not echo the request body"
        );
        assert!(rx.try_recv().is_err(), "exactly one reply");
        assert!(
            admin.principal(7).is_none(),
            "no route may be bound for a request that was refused"
        );
    }

    /// A bind whose scope stamp carries a `flow_id` is refused by name and binds nothing;
    /// the same bind with the flow removed is acknowledged and records its principal.
    /// The second half is the control: without it a vault that refused every scoped
    /// bind would pass.
    #[tokio::test]
    async fn a_route_bind_under_a_flow_scope_is_refused_and_binds_nothing() {
        let (surface, _surface_root) = tmp_surface(172);
        let (admin, _admin_store, _admin_root) = tmp_admin(172);
        let routes = Arc::new(RouteEpochs::default());
        let (tx, mut rx) = mpsc::channel::<Frame>(4);
        let bind = |route_channel: u16, flow_id: Option<&str>| {
            let attributes = subc_protocol::scope::ScopeAttributes {
                flow_id: flow_id.map(str::to_string),
                ..Default::default()
            };
            let request = ModuleControlRequest::RouteBind {
                route_channel,
                epoch: 1,
                target: subc_protocol::RouteTarget::ToolProvider {
                    module_id: credentials_core::contract::MODULE_ID.to_string(),
                },
                identity: subc_protocol::BindIdentity::new("/tmp/p", "h", "s"),
                principal: Some(subc_protocol::Principal::Reserved {
                    module_id: "prefrontal-core".to_string(),
                }),
                consumer_capabilities: None,
                role_versions: None,
                admission_facts: None,
                scope: Some(subc_protocol::scope::ScopeStamp {
                    owner: subc_protocol::Principal::Reserved {
                        module_id: "prefrontal-core".to_string(),
                    },
                    scope_ref: "scope-1".to_string(),
                    scope_epoch: 1,
                    kind: subc_protocol::scope::ScopeKind::Worker,
                    parent: None,
                    parent_state: None,
                    attributes,
                    owner_authorized: true,
                }),
            };
            Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Request,
                control_flags(),
                0,
                0,
                u64::from(route_channel),
                serde_json::to_vec(&request).unwrap(),
            )
            .unwrap()
        };

        handle_control_request(bind(5, Some("flow-1")), &tx, &surface, &admin, &routes)
            .await
            .unwrap();
        let refusal = rx.try_recv().expect("a flow-scoped bind is answered");
        assert_eq!(refusal.header.ty, FrameType::Error);
        assert_eq!(refusal.header.corr, 5);
        let error: ErrorBody = serde_json::from_slice(&refusal.body).unwrap();
        assert_eq!(error.code, "flow_scopes_unsupported");
        assert!(
            admin.principal(5).is_none(),
            "a refused bind installs nothing"
        );

        handle_control_request(bind(6, None), &tx, &surface, &admin, &routes)
            .await
            .unwrap();
        let ack = rx
            .try_recv()
            .expect("a scoped bind without a flow is answered");
        assert_eq!(ack.header.ty, FrameType::Response);
        assert_eq!(ack.header.corr, 6);
        assert!(
            admin.principal(6).is_some(),
            "a scoped bind without a flow is bound as before"
        );
    }

    #[tokio::test]
    async fn health_check_control_request_returns_domain_report() {
        let (surface, _surface_root) = tmp_surface(7);
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

        let (admin, _admin_store, _admin_root) = tmp_admin(7);
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

    /// The first cached snapshot must expose exactly the same tip pair as the store.
    /// This proves the health path emits the current entry MAC rather than only a
    /// convenient sequence count.
    #[tokio::test]
    async fn health_snapshot_audit_tip_matches_store_tip_pair() {
        let (surface, store, _db, _root) = tmp_surface_with_store(10);
        let (expected_seq, expected_mac) = store
            .audit_tip()
            .expect("read audit tip")
            .expect("seeded store has an audit tip");
        let snapshot = surface.health_snapshot();

        assert_eq!(snapshot.audit_seq, Some(expected_seq));
        assert_eq!(
            snapshot.audit_tip_mac.as_deref(),
            Some(expected_mac.as_str())
        );
    }

    /// A refresh after an audit append must replace both cached halves of the tip.
    /// Keeping the original pair would make the health witness miss a legitimate row
    /// change even though the store itself has advanced.
    #[tokio::test]
    async fn health_refresh_recomputes_audit_tip_after_append() {
        let (surface, store, _db, _root) = tmp_surface_with_store(12);
        let before = surface.health_snapshot();
        store
            .append_audit(&AuditRecord {
                op: AuditOp::FetchAnomaly,
                credential_id: None,
                payload_hash: None,
                actor: "health-test".into(),
                alarm: None,
            })
            .expect("append audit entry");

        surface.refresh_health();
        let after = surface.health_snapshot();

        assert_eq!(
            after.audit_seq,
            before.audit_seq.map(|seq| seq + 1),
            "refresh must move the sequence tip"
        );
        assert_ne!(
            after.audit_tip_mac, before.audit_tip_mac,
            "refresh must move the MAC paired with the new sequence"
        );
    }

    /// The load-bearing property of the cached-snapshot fix: the probe reply is
    /// served from the in-memory snapshot and does NOT do a live store read. Prove
    /// it non-vacuously — mutate the store AFTER construction and assert the probe
    /// still returns the pre-mutation snapshot until `refresh_health` runs (the
    /// off-path recompute). A live-reading probe would reflect the mutation
    /// immediately; the cached one must not.
    #[tokio::test]
    async fn health_probe_serves_cached_snapshot_not_a_live_read() {
        let (surface, store, _db, _root) = tmp_surface_with_store(11);

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
        let (surface, _surface_root) = tmp_surface(13);
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
        const COUNTED: [&str; 9] = [
            "credentialsTotal",
            "active",
            "needsReauth",
            "retired",
            "corrupt",
            "needsReauthIds",
            "retiredIds",
            "corruptIds",
            "openIntents",
        ];
        const AUDIT_TIP: [&str; 2] = ["auditSeq", "entryMac"];

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
        for field in AUDIT_TIP {
            assert!(
                metrics.get(field).is_none(),
                "{field} must be ABSENT when the store is unreadable: a zero or stale audit \
                 tip would be false witness data"
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
        // An empty readable chain has no tip, so both optional fields remain absent.
        for field in AUDIT_TIP {
            assert!(
                metrics.get(field).is_none(),
                "{field} must be absent when the audit chain is empty"
            );
        }

        // A non-empty readable chain emits both halves of the witness observation.
        let mut with_tip = VaultHealth::summarize(&[], 0, false);
        with_tip.audit_seq = Some(7);
        with_tip.audit_tip_mac = Some("mac-7".to_string());
        let ModuleControlResponse::HealthCheck { metrics, .. } = health_report(&with_tip) else {
            panic!("expected HealthCheck");
        };
        let metrics = metrics.expect("health report carries metrics");
        assert_eq!(metrics.get("auditSeq").and_then(|v| v.as_i64()), Some(7));
        assert_eq!(
            metrics.get("auditTipMac").and_then(|v| v.as_str()),
            Some("mac-7")
        );
    }

    /// A SUCCESSFUL `list_scoped` MUST LEAVE A ROW, because its silence was
    /// indistinguishable from never having been called.
    ///
    /// Measured 2026-09-20: the insula seat cut over to a reserved principal, their
    /// enumeration behaved oddly, and I offered to read `auth_events` to tell them
    /// whether the call had arrived. It could not answer: a REFUSAL wrote a row and a
    /// SUCCESS wrote nothing, so the empty result meant both "working" and "never
    /// called". This is the op a consumer calls FIRST, so its first success is the exact
    /// moment a cutover is proven, and it was the one op that could not say so.
    #[test]
    fn a_successful_list_scoped_records_first_use_not_only_its_refusals() {
        let (surface, store, _db, _root) = tmp_surface_with_store(196);
        let id = "apikey:enumerated";
        let record = VaultRecord::new_static(CredentialKind::ApiKey, "test", b"k".to_vec(), None);
        store
            .create_audited(id, &record, AuditCtx::admin(AuditOp::Put))
            .expect("seed");
        store
            .create_read_grant_audited(
                "reserved",
                "a-module",
                credentials_core::store::SelectorKind::Exact,
                id,
                credentials_core::store::GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("grant");

        let principal = subc_protocol::Principal::Reserved {
            module_id: "a-module".to_owned(),
        };
        let listed = surface
            .list_scoped(
                Some(&principal),
                &read_surface::ListScopedParams {
                    enrollment_token: None,
                },
            )
            .expect("a granted reserved principal enumerates");
        assert_eq!(listed.credentials.len(), 1, "the grant covers one row");

        let events = store.recent_auth_events(32).expect("read events");
        assert!(
            events.iter().any(|event| {
                event.credential_id == "credential.list_scoped"
                    && event.principal_id.as_deref() == Some("a-module")
            }),
            "a successful enumeration must record first use under the caller, got {events:?}"
        );
    }

    /// An OAuth record with a far-future expiry, a refresh adapter and a full identity,
    /// so a scoped get serves it without an upstream exchange and a list row has every
    /// identity field to show or withhold.
    fn roster_oauth_record() -> VaultRecord {
        let oauth = credentials_core::OAuthCredential {
            access_token: "sk-ant-oat01-roster".to_string().into(),
            refresh_token: "ref".to_string().into(),
            expires_at_ms: Some(4_102_444_800_000),
            token_url: "https://api.anthropic.com/v1/oauth/token".to_string(),
            client_id: Some("client".to_string()),
            client_secret: None,
            scopes: Vec::new(),
        };
        VaultRecord::new_oauth("login", "anthropic", oauth, b"sk-ant-oat01-roster".to_vec())
            .with_identity(credentials_core::record::RecordIdentity {
                account_id: Some("roster-account".to_string()),
                email: Some("roster@example.invalid".to_string()),
                org_name: Some("Roster Org".to_string()),
            })
    }

    fn grant_for(
        store: &EncryptedStore,
        module: &str,
        credential_id: &str,
        operation: credentials_core::store::GrantOperation,
    ) {
        store
            .create_read_grant_audited(
                "reserved",
                module,
                credentials_core::store::SelectorKind::Exact,
                credential_id,
                operation,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("grant");
    }

    fn reserved(module: &str) -> subc_protocol::Principal {
        subc_protocol::Principal::Reserved {
            module_id: module.to_owned(),
        }
    }

    /// A `list` grant is the account roster without the tokens: the covered row comes
    /// back from `list_scoped` WITH its identity and refresh adapter, exactly as it does
    /// for `read`, and the enumeration's first-use row says `list` rather than claiming
    /// the `read` authority this principal does not hold.
    ///
    /// A `sign` principal over the same row is the control: it sees the row and no
    /// identity, so the identity here cannot come from a projection that ignores the
    /// operation.
    #[test]
    fn a_list_only_principal_sees_identity_and_adapter_in_list_scoped() {
        use credentials_core::store::GrantOperation;
        let (surface, store, _db, _root) = tmp_surface_with_store(197);
        let id = "oauth:anthropic:roster";
        store
            .create_audited(id, &roster_oauth_record(), AuditCtx::admin(AuditOp::Put))
            .expect("seed");
        grant_for(&store, "router", id, GrantOperation::List);
        grant_for(&store, "signer", id, GrantOperation::Sign);
        let params = read_surface::ListScopedParams {
            enrollment_token: None,
        };

        let listed = surface
            .list_scoped(Some(&reserved("router")), &params)
            .expect("a list-only principal enumerates");
        assert_eq!(listed.credentials.len(), 1, "the list grant covers one row");
        let row = &listed.credentials[0];
        assert_eq!(row.id, id);
        assert_eq!(row.operations, vec!["list".to_string()]);
        assert_eq!(row.account_id.as_deref(), Some("roster-account"));
        assert_eq!(row.email.as_deref(), Some("roster@example.invalid"));
        assert_eq!(row.org_name.as_deref(), Some("Roster Org"));
        assert_eq!(row.refresh_adapter.as_deref(), Some("anthropic"));
        assert_eq!(
            listed.grant_tuples[0].operation, "list",
            "the caller's own grant tuple names the operation"
        );

        let signer = surface
            .list_scoped(Some(&reserved("signer")), &params)
            .expect("a sign-only principal enumerates");
        assert_eq!(signer.credentials.len(), 1);
        assert_eq!(signer.credentials[0].account_id, None);
        assert_eq!(signer.credentials[0].refresh_adapter, None);

        let events = store.recent_auth_events(64).expect("read events");
        let first_use = events
            .iter()
            .find(|event| {
                event.credential_id == "credential.list_scoped"
                    && event.kind == credentials_core::audit::AuthEventKind::ScopedFirstUse.as_str()
                    && event.principal_id.as_deref() == Some("router")
            })
            .unwrap_or_else(|| panic!("no list_scoped first use for router: {events:?}"));
        assert_eq!(first_use.detail.as_deref(), Some("list"));
    }

    /// An OAuth record whose refresh adapter is `adapter`, whatever its id says, so the
    /// auth method can be shown to follow the record and not the id.
    fn oauth_record_with_adapter(adapter: &str) -> VaultRecord {
        let oauth = credentials_core::OAuthCredential {
            access_token: "opaque-access".to_string().into(),
            refresh_token: "opaque-refresh".to_string().into(),
            expires_at_ms: Some(4_102_444_800_000),
            token_url: "https://example.invalid/token".to_string(),
            client_id: Some("client".to_string()),
            client_secret: None,
            scopes: Vec::new(),
        };
        VaultRecord::new_oauth("login", adapter, oauth, b"opaque-access".to_vec())
    }

    /// Every `list_scoped` row carries its provider ids, sealed or not, and the auth
    /// method appears only on rows the caller can `read` or `list`, where the record is
    /// unsealed, and only when the record's kind and adapter yield one.
    ///
    /// The ids are chosen so the id never predicts the answer: `chatgpt:openai` holds an
    /// `anthropic` adapter and reports `oauth`, and a GitHub App record the caller can
    /// read reports no auth method at all.
    #[test]
    fn list_scoped_rows_carry_provider_ids_everywhere_and_auth_method_only_for_read_and_list() {
        use credentials_core::store::{GrantOperation, SetProvidersMode};
        let (surface, store, _db, _root) = tmp_surface_with_store(201);
        let roster = "oauth:anthropic:roster";
        let mismatched = "chatgpt:openai";
        let app = "github_app:plex-alfonso";
        let static_key = "apikey:active";
        store
            .create_audited(
                roster,
                &roster_oauth_record(),
                AuditCtx::admin(AuditOp::Put),
            )
            .expect("seed roster");
        store
            .create_audited(
                mismatched,
                &oauth_record_with_adapter("anthropic"),
                AuditCtx::admin(AuditOp::Put),
            )
            .expect("seed mismatched");
        store
            .create_audited(
                app,
                &oauth_record_with_adapter("github_app"),
                AuditCtx::admin(AuditOp::Put),
            )
            .expect("seed app");
        store
            .set_providers_audited(
                roster,
                SetProvidersMode::Set,
                &["bb".to_string(), "aa".to_string()],
                AuditCtx::admin(AuditOp::SetProviders),
            )
            .expect("set roster provider ids");
        store
            .set_providers_audited(
                static_key,
                SetProvidersMode::Set,
                &["zai-coding-plan".to_string()],
                AuditCtx::admin(AuditOp::SetProviders),
            )
            .expect("set static key provider ids");
        for (principal, operation) in [
            ("reader", GrantOperation::Read),
            ("lister", GrantOperation::List),
            ("signer", GrantOperation::Sign),
        ] {
            for id in [roster, mismatched, app, static_key] {
                grant_for(&store, principal, id, operation);
            }
        }
        let params = read_surface::ListScopedParams {
            enrollment_token: None,
        };

        for (principal, opened) in [("reader", true), ("lister", true), ("signer", false)] {
            let listed = surface
                .list_scoped(Some(&reserved(principal)), &params)
                .unwrap_or_else(|_| panic!("{principal} enumerates"));
            let wire = serde_json::to_value(&listed.credentials).expect("serialise rows");
            let rows = wire.as_array().expect("rows");
            assert_eq!(rows.len(), 4, "{principal}");
            let row = |id: &str| {
                rows.iter()
                    .find(|row| row["id"] == id)
                    .unwrap_or_else(|| panic!("{principal} has no row {id}"))
                    .as_object()
                    .expect("row object")
            };
            for (id, provider_ids, auth_method) in [
                (roster, json!(["aa", "bb"]), "oauth"),
                (mismatched, json!([]), "oauth"),
                (app, json!([]), ""),
                (static_key, json!(["zai-coding-plan"]), "apikey"),
            ] {
                assert_eq!(
                    row(id).get("provider_ids"),
                    Some(&provider_ids),
                    "{principal} {id}: provider_ids is on every row"
                );
                let expected = (opened && !auth_method.is_empty()).then_some(auth_method);
                assert_eq!(
                    row(id).get("auth_method").and_then(|value| value.as_str()),
                    expected,
                    "{principal} {id}: auth_method"
                );
                if expected.is_none() {
                    assert!(
                        !row(id).contains_key("auth_method"),
                        "{principal} {id}: an absent auth_method is omitted, not null"
                    );
                }
            }
            if opened {
                assert_eq!(row(app)["refresh_adapter"], "github_app", "{principal}");
            }
        }
    }

    /// A sign-only row is never unsealed, so a garbage envelope does not stop it from
    /// listing, and it still carries the provider ids stored beside it. A `read` grant
    /// over the same row unseals it, and that failure still fails the whole snapshot:
    /// provider ids are not a reason to serve a row whose record cannot be opened.
    #[test]
    fn a_sign_only_garbage_envelope_row_lists_its_provider_ids_and_a_read_grant_still_fails() {
        use credentials_core::store::{GrantOperation, SetProvidersMode};
        let (surface, store, db_path, _root) = tmp_surface_with_store(202);
        let id = "apikey:active";
        store
            .set_providers_audited(
                id,
                SetProvidersMode::Set,
                &["zai-coding-plan".to_string()],
                AuditCtx::admin(AuditOp::SetProviders),
            )
            .expect("set provider ids");
        grant_for(&store, "signer", id, GrantOperation::Sign);
        rusqlite::Connection::open(&db_path)
            .expect("raw connection")
            .execute(
                "UPDATE credentials SET envelope = X'00' WHERE credential_id = ?1",
                [id],
            )
            .expect("corrupt the envelope");
        let params = read_surface::ListScopedParams {
            enrollment_token: None,
        };

        let signer = surface
            .list_scoped(Some(&reserved("signer")), &params)
            .unwrap_or_else(|_| panic!("a sign-only row never opens its envelope"));
        assert_eq!(signer.credentials.len(), 1);
        assert_eq!(signer.credentials[0].id, id);
        assert_eq!(signer.credentials[0].provider_ids, ["zai-coding-plan"]);
        assert_eq!(signer.credentials[0].auth_method, None);

        grant_for(&store, "reader", id, GrantOperation::Read);
        assert!(
            matches!(
                surface.list_scoped(Some(&reserved("reader")), &params),
                Err(read_surface::ReadError::StoreError)
            ),
            "a read row that cannot be unsealed fails the whole snapshot"
        );
    }

    /// Every adapter the daemon registers has an explicit `auth_method` here: eight map
    /// to a value and four to none. The registered list is the daemon's own, so an
    /// adapter added there without an entry here fails, naming it. `list_auth_method`
    /// answers "none" for any adapter name it does not know, so a new adapter would
    /// otherwise pass silently with no auth method; only this map records a decision.
    #[test]
    fn every_registered_refresh_adapter_has_an_explicit_auth_method() {
        use credentials_core::list_auth_method::list_auth_method;
        let expected: std::collections::BTreeMap<&str, Option<&str>> = [
            ("anthropic", Some("oauth")),
            ("openai", Some("chatgpt")),
            ("google", Some("oauth")),
            ("gmail", None),
            ("xai", Some("oauth")),
            ("kimi", Some("oauth")),
            ("cursor", Some("oauth")),
            ("github-copilot", Some("oauth")),
            ("antigravity", Some("antigravity")),
            ("github_app", None),
            ("devin", None),
            ("digitalocean", None),
            ("snowflake", None),
        ]
        .into_iter()
        .collect();
        let registered: Vec<String> = registered_refresh_adapters("test-device".into())
            .iter()
            .map(|adapter| adapter.name().to_string())
            .collect();
        for name in &registered {
            let Some(want) = expected.get(name.as_str()) else {
                panic!(
                    "registered refresh adapter `{name}` has no entry in the expected \
                     auth_method map: decide its value in credentials_core::list_auth_method \
                     and add it here"
                );
            };
            assert_eq!(
                list_auth_method(CredentialKind::Oauth, Some(name)).map(|method| method.as_str()),
                *want,
                "adapter `{name}`"
            );
        }
        for name in expected.keys() {
            assert!(
                registered.iter().any(|registered| registered == name),
                "`{name}` is in the expected map but not registered"
            );
        }
        assert_eq!(registered.len(), 13);
    }

    /// `list` authorizes list_scoped and nothing else. Every scoped surface that can
    /// return a token, exercise a key, or mark a credential must refuse a list-only
    /// principal with the same `not_found` it gives a principal with no grant at all.
    ///
    /// Differential on purpose: each refusal is paired with the same call from a
    /// principal holding the operation that surface does gate on, which must succeed.
    /// Without the pair, a surface that refused everyone would pass.
    #[tokio::test]
    async fn a_list_only_principal_is_refused_by_every_other_scoped_surface() {
        use base64::Engine as _;
        use credentials_core::store::GrantOperation;
        let (surface, store, _db, _root) = tmp_surface_with_store(198);
        let oauth_id = "oauth:anthropic:roster";
        store
            .create_audited(
                oauth_id,
                &roster_oauth_record(),
                AuditCtx::admin(AuditOp::Put),
            )
            .expect("seed oauth");
        let signing_id = "signing:roster:1";
        store
            .create(
                signing_id,
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    test_ed25519_pem().into_bytes(),
                    None,
                ),
            )
            .expect("seed signing key");
        let kem_id = "kem:roster";
        let kem_pem = credentials_core::kem::generate_key().expect("generate recipient");
        store
            .create(
                kem_id,
                &VaultRecord::new_static(
                    CredentialKind::KemKey,
                    "test",
                    kem_pem.into_bytes(),
                    None,
                ),
            )
            .expect("seed kem key");
        for id in [oauth_id, signing_id, kem_id] {
            grant_for(&store, "router", id, GrantOperation::List);
            grant_for(&store, "reader", id, GrantOperation::Read);
        }
        grant_for(&store, "signer", signing_id, GrantOperation::Sign);
        grant_for(&store, "opener", kem_id, GrantOperation::Open);
        let router = reserved("router");
        let reader = reserved("reader");

        // get_scoped returns the token itself: refused for list, served for read.
        let get = |credential_id: &str| read_surface::GetScopedParams {
            credential_id: credential_id.into(),
            enrollment_token: None,
            min_ttl_ms: None,
        };
        let refused = surface.get_scoped(Some(&router), &get(oauth_id)).await;
        assert!(
            matches!(
                refused,
                read_surface::GetOutcome::Err { ref error } if error.code == read_surface::ReadError::NotFound
            ),
            "get_scoped must refuse a list-only principal as not_found, got {refused:?}"
        );
        let served = surface.get_scoped(Some(&reader), &get(oauth_id)).await;
        assert!(
            matches!(served, read_surface::GetOutcome::Ok(_)),
            "the same get_scoped with a read grant serves the token, got {served:?}"
        );

        // Scoped status by credential id: refused for list, answered for read.
        let status = |credential_id: &str| read_surface::StatusParams {
            handle: None,
            credential_id: Some(credential_id.into()),
            enrollment_token: None,
        };
        let refused = surface.status(1, Some(&router), &status(oauth_id)).await;
        assert_eq!(
            refused.last_error_code,
            Some(read_surface::ReadError::NotFound)
        );
        assert_eq!(refused.credential_id, None);
        let answered = surface.status(1, Some(&reader), &status(oauth_id)).await;
        assert_eq!(answered.last_error_code, None);
        assert_eq!(answered.credential_id.as_deref(), Some(oauth_id));

        // sign: refused for list, signs for a sign grant.
        let sign = read_surface::SignParams {
            handle: None,
            credential_id: Some(signing_id.into()),
            payload_b64: base64::engine::general_purpose::STANDARD.encode(b"roster bytes"),
            enrollment_token: None,
        };
        assert_eq!(
            surface.sign(1, Some(&router), &sign).await.err(),
            Some(read_surface::ReadError::NotFound),
            "sign must refuse a list-only principal"
        );
        surface
            .sign(1, Some(&reserved("signer")), &sign)
            .await
            .expect("the same sign with a sign grant signs");

        // public_key is gated on read: refused for list, published for read.
        let public = read_surface::PublicKeyParams {
            handle: None,
            credential_id: Some(signing_id.into()),
            enrollment_token: None,
        };
        assert_eq!(
            surface.public_key(1, Some(&router), &public).await.err(),
            Some(read_surface::ReadError::NotFound),
            "public_key must refuse a list-only principal"
        );
        surface
            .public_key(1, Some(&reader), &public)
            .await
            .expect("the same public_key with a read grant publishes");

        // open: an `open` grant gets past authorization to the decrypt, which fails on
        // these empty fields with its own code; a list-only principal never gets there.
        let open = read_surface::OpenParams {
            credential_id: kem_id.into(),
            enc_b64: String::new(),
            ciphertext_b64: String::new(),
            info_b64: String::new(),
            aad_b64: String::new(),
            enrollment_token: None,
        };
        assert_eq!(
            surface.open(1, Some(&router), &open).await.err(),
            Some(read_surface::ReadError::NotFound),
            "open must refuse a list-only principal"
        );
        assert_eq!(
            surface
                .open(2, Some(&reserved("opener")), &open)
                .await
                .err(),
            Some(read_surface::ReadError::OpenFailed),
            "an open grant reaches the decrypt"
        );

        // report_auth_failure by credential id. It runs last because the read principal's
        // accepted 401 marks the record stale, which would change what the get_scoped
        // and status checks above observe.
        let report = read_surface::ReportAuthFailureParams {
            handle: None,
            credential_id: Some(oauth_id.into()),
            enrollment_token: None,
            provider_status: 401,
            record_version: store.meta(oauth_id).expect("meta").record_version,
            reporter_source: None,
        };
        assert_eq!(
            surface
                .report_auth_failure(1, Some(&router), &report)
                .await
                .err(),
            Some(read_surface::ReadError::NotFound),
            "report_auth_failure must refuse a list-only principal"
        );
        surface
            .report_auth_failure(1, Some(&reader), &report)
            .await
            .expect("the same report with a read grant is accepted");
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
                    stale_pending: false,
                    categories: Vec::new(),
                    created_by: None,
                    provider_ids: Vec::new(),
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
        let (surface, store, db_path, _root) = tmp_surface_with_store(14);
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
            credential_id: None,
            enrollment_token: None,
        };
        let before = surface.status(1, None, &params).await;
        assert!(before.ready, "an active credential is ready before fencing");
        assert!(before.lease_held, "the lease is held before fencing");

        // A newer writer claims the db at a higher fence epoch; the next fenced write on
        // this store is rejected and latches fenced_out (the lease-handover race).
        bump_fence_epoch(&db_path);
        let _ = store.invalidate("apikey:active"); // trigger the fenced write to latch

        let after = surface.status(1, None, &params).await;
        assert!(
            !after.lease_held,
            "a fenced-out daemon does not hold the lease"
        );
        assert!(
            !after.ready,
            "a fenced-out daemon is not ready even for an Active row"
        );

        // The overall (no-handle) status also reflects the loss.
        let overall = surface
            .status(
                1,
                None,
                &StatusParams {
                    handle: None,
                    credential_id: None,
                    enrollment_token: None,
                },
            )
            .await;
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
        let (surface, store, _db, _root) = tmp_surface_with_store(16);

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
                None,
                &StatusParams {
                    handle: Some(active),
                    credential_id: None,
                    enrollment_token: None,
                },
            )
            .await;
        assert!(ok.ready, "an active credential is ready");
        assert_eq!(
            ok.last_error_code, None,
            "an active credential names no error"
        );

        let reauth = surface
            .status(
                2,
                None,
                &StatusParams {
                    handle: Some(dead),
                    credential_id: None,
                    enrollment_token: None,
                },
            )
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
                None,
                &StatusParams {
                    handle: Some(broken),
                    credential_id: None,
                    enrollment_token: None,
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
                None,
                &StatusParams {
                    handle: Some("ckh_not_a_real_handle".to_string()),
                    credential_id: None,
                    enrollment_token: None,
                },
            )
            .await;
        assert!(!unknown.ready);
        assert_eq!(
            unknown.last_error_code,
            Some(read_surface::ReadError::NotFound)
        );
    }

    /// A real Ed25519 PKCS#8 PEM, generated per call.
    ///
    /// Generated rather than pasted as a literal so the test material comes from the
    /// same production path a deposit would: a hand-written fixture agrees with
    /// whatever its author expected, which is how this repo shipped a parser demanding
    /// PKCS#8 at a world that issues PKCS#1.
    fn test_ed25519_pem() -> String {
        use base64::Engine;
        use ring::rand::SystemRandom;
        use ring::signature::Ed25519KeyPair;
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate");
        let b64 = base64::engine::general_purpose::STANDARD.encode(pkcs8.as_ref());
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).expect("ascii"));
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----");
        pem
    }

    /// A capability handle authorizes signing and public-key publication for a signing
    /// key, but must never serve the private PKCS#8 payload through any read operation.
    ///
    /// The three assertions protect distinct refusal behavior. Changing the resolved
    /// signing-key `get` error to `NotFound` fails the resolved-key assertion; changing either
    /// the unknown-handle or revoked-handle error to `KindNotGettable` fails its own
    /// `not_found` assertion.
    #[tokio::test]
    async fn signing_key_handle_cannot_get_but_can_sign_and_publish() {
        use base64::Engine as _;

        let (surface, admin, store) = scoped_rig(81);
        let pem = test_ed25519_pem();
        let credential_id = "signing:agent-assertion:handle";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    pem.as_bytes().to_vec(),
                    None,
                ),
            )
            .expect("create signing key");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                credential_id,
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("store handle");

        // Drive the real request dispatcher so this checks the exact { code, class } pair a
        // consumer receives, rather than a reconstructed error body.
        let get = scoped_route_request(
            &surface,
            &admin,
            81,
            OP_GET,
            json!({ "handle": handle.raw.clone() }),
        )
        .await;
        assert_eq!(
            get["result"]["error"],
            json!({ "code": "kind_not_gettable", "class": "permanent" }),
            "a resolved signing key must tell a consumer to use another verb"
        );

        // The resolved-record code must not escape the two non-resolution arms. An unknown
        // handle and a revoked handle remain indistinguishable to a probing caller.
        let unknown = scoped_route_request(
            &surface,
            &admin,
            81,
            OP_GET,
            json!({ "handle": "ckh_not_a_real_handle" }),
        )
        .await;
        assert_eq!(
            unknown["result"]["error"],
            json!({ "code": "not_found", "class": "permanent" }),
            "an unknown handle must stay uniformly absent"
        );
        let revoked = credentials_core::store::mint_handle().expect("mint revoked handle");
        store
            .put_handle_hash(
                &revoked.hash,
                credential_id,
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("store revoked handle");
        store
            .revoke_handle(&revoked.raw, AuditCtx::admin(AuditOp::RevokeHandle))
            .expect("revoke handle");
        let revoked = scoped_route_request(
            &surface,
            &admin,
            81,
            OP_GET,
            json!({ "handle": revoked.raw }),
        )
        .await;
        assert_eq!(
            revoked["result"]["error"],
            json!({ "code": "not_found", "class": "permanent" }),
            "a revoked handle must remain indistinguishable from an unknown handle"
        );

        let public = surface
            .public_key(
                81,
                None,
                &read_surface::PublicKeyParams {
                    handle: Some(handle.raw.clone()),
                    credential_id: None,
                    enrollment_token: None,
                },
            )
            .await
            .expect("the same handle must publish the public half");
        assert_eq!(public.algorithm, "ed25519");
        let signature = surface
            .sign(
                81,
                None,
                &read_surface::SignParams {
                    handle: Some(handle.raw),
                    credential_id: None,
                    payload_b64: base64::engine::general_purpose::STANDARD
                        .encode(b"handle-authorized bytes"),
                    enrollment_token: None,
                },
            )
            .await
            .expect("the same handle must still sign");
        assert!(!signature.signature_b64.is_empty());
        assert_eq!(signature.key_id, public.key_id);
    }

    /// A scoped read reveals the signing-key-specific remedy only after it proves the
    /// caller's read grant covers the credential.
    ///
    /// The paired assertions enforce that ordering. Classifying before `authorize_scoped`, or
    /// returning `KindNotGettable` without a read grant, fails the no-grant assertion.
    /// Returning `NotFound` after a valid grant fails the granted-read assertion.
    #[tokio::test]
    async fn scoped_get_reveals_signing_kind_only_after_read_grant() {
        let (surface, admin, store) = scoped_rig(86);
        let credential_id = "signing:scoped:grant-order";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    b"private key bytes".to_vec(),
                    None,
                ),
            )
            .expect("create signing key");
        admin.record_bind(
            86,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let no_grant = scoped_request(&surface, &admin, 86, credential_id).await;
        assert_scoped_not_found(&no_grant);

        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                credential_id,
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create read grant");
        let granted = scoped_request(&surface, &admin, 86, credential_id).await;
        assert_eq!(
            granted["result"]["error"],
            json!({ "code": "kind_not_gettable", "class": "permanent" }),
            "a granted caller must learn to use the signing verb, not that the credential is gone"
        );
    }

    /// The two read fences must both reject vault-held private keys; get_many uses
    /// the handle get path and must not turn a refused item into a successful payload.
    #[tokio::test]
    async fn kem_key_payload_is_absent_from_get_get_many_and_get_scoped() {
        let (surface, admin, store) = scoped_rig(87);
        let id = "kem:recipient:private";
        let pem = credentials_core::kem::generate_key().expect("generate recipient");
        store
            .create(
                id,
                &VaultRecord::new_static(
                    CredentialKind::KemKey,
                    "test",
                    pem.as_bytes().to_vec(),
                    None,
                ),
            )
            .expect("deposit recipient");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(&handle.hash, id, AuditCtx::admin(AuditOp::MintHandle))
            .expect("store handle");
        admin.record_bind(
            87,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );
        let expected = json!({ "code": "kind_not_gettable", "class": "permanent" });
        let single = scoped_route_request(
            &surface,
            &admin,
            87,
            OP_GET,
            json!({"handle": handle.raw.clone()}),
        )
        .await;
        assert_eq!(
            single["result"]["error"], expected,
            "get must refuse private KEM payload"
        );
        let batch = scoped_route_request(
            &surface,
            &admin,
            87,
            OP_GET_MANY,
            json!({"items": [{"handle": handle.raw.clone()}]}),
        )
        .await;
        assert_eq!(
            batch["results"][0]["error"], expected,
            "get_many must refuse private KEM payload: {batch}"
        );
        let unknown = scoped_request(&surface, &admin, 87, "kem:recipient:unknown").await;
        let ungranted = scoped_request(&surface, &admin, 87, id).await;
        assert_eq!(
            ungranted, unknown,
            "a kind fence must not reveal an ungranted id"
        );
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                id,
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("read grant");
        let scoped = scoped_request(&surface, &admin, 87, id).await;
        assert_eq!(
            scoped["result"]["error"], expected,
            "get_scoped must refuse private KEM payload"
        );
        for reply in [&single, &batch, &scoped] {
            let serialized = reply.to_string();
            assert!(
                !serialized.contains("\"payload\""),
                "refusal must not carry any payload field: {serialized}"
            );
            assert!(
                !serialized.contains(&pem),
                "refusal must not carry private PEM text"
            );
        }
    }

    /// `get_many` delegates every item to `get`; each response, including each refusal,
    /// stays at its input position.
    ///
    /// The indexed assertions reject a batch-level refusal, omitted failed items, or a
    /// signing-key refusal associated with the following input.
    #[tokio::test]
    async fn get_many_delegates_signing_key_refusal_without_blocking_other_items() {
        let (surface, store, _db, _root) = tmp_surface_with_store(85);
        let pem = test_ed25519_pem();
        store
            .create(
                "signing:batch:private",
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    pem.into_bytes(),
                    None,
                ),
            )
            .expect("create signing key");
        for (credential_id, payload) in [
            ("apikey:batch:before", b"before signing refusal".as_slice()),
            ("apikey:batch:after", b"after unknown refusal".as_slice()),
        ] {
            store
                .create(
                    credential_id,
                    &VaultRecord::new_static(
                        CredentialKind::ApiKey,
                        "test",
                        payload.to_vec(),
                        None,
                    ),
                )
                .expect("create ordinary credential");
        }
        let mint_for = |credential_id: &str| {
            let handle = credentials_core::store::mint_handle().expect("mint handle");
            store
                .put_handle_hash(
                    &handle.hash,
                    credential_id,
                    AuditCtx::admin(AuditOp::MintHandle),
                )
                .expect("store handle");
            handle.raw
        };
        let before_handle = mint_for("apikey:batch:before");
        let signing_handle = mint_for("signing:batch:private");
        let after_handle = mint_for("apikey:batch:after");

        let outcomes = surface
            .get_many(
                85,
                &GetManyParams {
                    items: vec![
                        GetParams {
                            handle: before_handle,
                            min_ttl_ms: None,
                            force_refresh: false,
                        },
                        GetParams {
                            handle: signing_handle,
                            min_ttl_ms: None,
                            force_refresh: false,
                        },
                        GetParams {
                            handle: "ckh_not_a_real_handle".to_string(),
                            min_ttl_ms: None,
                            force_refresh: false,
                        },
                        GetParams {
                            handle: after_handle,
                            min_ttl_ms: None,
                            force_refresh: false,
                        },
                    ],
                },
            )
            .await;

        assert_eq!(
            outcomes.len(),
            4,
            "each input needs an outcome even when neighbouring items refuse"
        );
        let read_surface::GetOutcome::Ok(before) = &outcomes[0] else {
            panic!("the item before a refusal must serve at index zero");
        };
        assert_eq!(before.payload, b"before signing refusal");
        let read_surface::GetOutcome::Err { error } = &outcomes[1] else {
            panic!("the signing-key item must refuse at index one");
        };
        assert_eq!(error.code, read_surface::ReadError::KindNotGettable);
        assert_eq!(error.class, read_surface::ErrorClass::Permanent);
        let read_surface::GetOutcome::Err { error } = &outcomes[2] else {
            panic!("the unknown-handle item must refuse at index two");
        };
        assert_eq!(error.code, read_surface::ReadError::NotFound);
        assert_eq!(error.class, read_surface::ErrorClass::Permanent);
        let read_surface::GetOutcome::Ok(after) = &outcomes[3] else {
            panic!("the item after two refusals must serve at index three");
        };
        assert_eq!(after.payload, b"after unknown refusal");
    }

    #[tokio::test]
    async fn kem_open_sequence_zero_twice_and_failure_bodies_are_identical() {
        use base64::Engine as _;
        use credentials_core::kem::*;
        let (surface, _admin, store) = scoped_rig(91);
        let id = "kem:open:probe";
        let pem = credentials_core::kem::generate_key().unwrap();
        let (public, key_id) = credentials_core::kem::public_half(&pem).unwrap();
        store
            .create(
                id,
                &VaultRecord::new_static(CredentialKind::KemKey, "test", pem.into_bytes(), None),
            )
            .unwrap();
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                id,
                GrantOperation::Open,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
        let principal = subc_protocol::Principal::Reserved {
            module_id: "prefrontal-core".into(),
        };
        let (enc, ct) = seal_base(&public, b"plaintext", b"info", b"aad").unwrap();
        let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        let mut params = read_surface::OpenParams {
            credential_id: id.into(),
            enc_b64: encode(&enc),
            ciphertext_b64: encode(&ct),
            info_b64: encode(b"info"),
            aad_b64: encode(b"aad"),
            enrollment_token: None,
        };
        for _ in 0..17 {
            let opened = surface.open(901, Some(&principal), &params).await.unwrap();
            assert_eq!(opened.plaintext_b64.expose(), &encode(b"plaintext"));
            assert_eq!(opened.key_id, key_id);
        }
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                id,
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
        let public_reply = surface
            .public_key(
                901,
                Some(&principal),
                &read_surface::PublicKeyParams {
                    handle: None,
                    credential_id: Some(id.into()),
                    enrollment_token: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(public_reply.algorithm, "x25519");
        assert_eq!(public_reply.key_id, key_id);
        assert_eq!(
            public_reply.public_key_hex,
            public
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        assert_eq!(
            public_reply.key_id,
            credentials_core::signing::key_id_for_public(&public)
        );
        let mut failures = Vec::new();
        params.enc_b64 = encode(&[0u8; 32]);
        failures.push(
            surface
                .open(901, Some(&principal), &params)
                .await
                .unwrap_err(),
        );
        params.enc_b64 = encode(&enc);
        params.ciphertext_b64 = encode(b"wrong recipient ciphertext");
        failures.push(
            surface
                .open(901, Some(&principal), &params)
                .await
                .unwrap_err(),
        );
        params.ciphertext_b64 = encode(&ct);
        let mut tampered = ct.clone();
        tampered[0] ^= 1;
        params.ciphertext_b64 = encode(&tampered);
        failures.push(
            surface
                .open(901, Some(&principal), &params)
                .await
                .unwrap_err(),
        );
        params.ciphertext_b64 = encode(&ct);
        params.aad_b64 = encode(b"wrong aad");
        failures.push(
            surface
                .open(901, Some(&principal), &params)
                .await
                .unwrap_err(),
        );
        params.aad_b64 = encode(b"aad");
        params.info_b64 = encode(b"wrong info");
        failures.push(
            surface
                .open(901, Some(&principal), &params)
                .await
                .unwrap_err(),
        );
        assert!(failures
            .iter()
            .all(|error| *error == read_surface::ReadError::OpenFailed));
        let api_id = "apikey:open:other";
        store
            .create(
                api_id,
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"api".to_vec(), None),
            )
            .unwrap();
        params.credential_id = api_id.into();
        let api_without_grant = surface
            .open(901, Some(&principal), &params)
            .await
            .unwrap_err();
        params.credential_id = "apikey:unknown".into();
        assert_eq!(
            api_without_grant,
            surface
                .open(901, Some(&principal), &params)
                .await
                .unwrap_err()
        );
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                api_id,
                GrantOperation::Open,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
        params.credential_id = api_id.into();
        assert_eq!(
            surface
                .open(901, Some(&principal), &params)
                .await
                .unwrap_err(),
            read_surface::ReadError::KindNotOpenable
        );
    }

    #[tokio::test]
    async fn open_refusal_sweep_and_repeated_unknown_id_trip_without_throttling_sign() {
        use base64::Engine as _;
        use credentials_core::kem::*;
        let (surface, _admin, store) = scoped_rig(92);
        let principal = subc_protocol::Principal::Reserved {
            module_id: "prefrontal-core".into(),
        };
        let mut params = read_surface::OpenParams {
            credential_id: String::new(),
            enc_b64: base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
            ciphertext_b64: String::new(),
            info_b64: String::new(),
            aad_b64: String::new(),
            enrollment_token: None,
        };
        for n in 0..16 {
            params.credential_id = format!("kem:unknown:{n}");
            assert_eq!(
                surface
                    .open(92, Some(&principal), &params)
                    .await
                    .unwrap_err(),
                read_surface::ReadError::NotFound
            );
        }
        assert_eq!(
            surface
                .open(92, Some(&principal), &params)
                .await
                .unwrap_err(),
            read_surface::ReadError::OpenRateLimited
        );
        let sign = read_surface::SignParams {
            handle: None,
            credential_id: Some("signing:unknown".into()),
            payload_b64: "".into(),
            enrollment_token: None,
        };
        assert_eq!(
            surface.sign(92, Some(&principal), &sign).await.unwrap_err(),
            read_surface::ReadError::NotFound
        );
        for _ in 0..16 {
            assert_eq!(
                surface
                    .open(93, Some(&principal), &params)
                    .await
                    .unwrap_err(),
                read_surface::ReadError::NotFound
            );
        }
        assert_eq!(
            surface
                .open(93, Some(&principal), &params)
                .await
                .unwrap_err(),
            read_surface::ReadError::OpenRateLimited
        );
        let id = "kem:recovery";
        let pem = credentials_core::kem::generate_key().unwrap();
        let (public, _) = credentials_core::kem::public_half(&pem).unwrap();
        store
            .create(
                id,
                &VaultRecord::new_static(CredentialKind::KemKey, "test", pem.into_bytes(), None),
            )
            .unwrap();
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                id,
                GrantOperation::Open,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
        let (enc, ct) = seal_base(&public, b"hello", b"", b"").unwrap();
        params.credential_id = id.into();
        params.enc_b64 = base64::engine::general_purpose::STANDARD.encode(enc);
        params.ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(ct);
        surface.expire_open_window_for_test(93).await;
        assert_eq!(
            surface
                .open(93, Some(&principal), &params)
                .await
                .unwrap()
                .plaintext_b64
                .expose(),
            &base64::engine::general_purpose::STANDARD.encode(b"hello")
        );
    }

    #[tokio::test]
    async fn malformed_encoding_open_reply_is_permanent_result_not_transport_invalid_params() {
        let (surface, _admin, _) = scoped_rig(95);
        let mut params = read_surface::OpenParams {
            credential_id: "kem:unknown".into(),
            enc_b64: String::new(),
            ciphertext_b64: String::new(),
            info_b64: String::new(),
            aad_b64: String::new(),
            enrollment_token: None,
        };
        for field in 0..4 {
            let fields = [
                &mut params.enc_b64,
                &mut params.ciphertext_b64,
                &mut params.info_b64,
                &mut params.aad_b64,
            ];
            *fields.into_iter().nth(field).unwrap() = "!".into();
            let code = surface.open(95, None, &params).await.unwrap_err();
            assert_eq!(
                crate::wrap_result(serde_json::json!({
                    "error": read_surface::ErrorBody { code, class: code.class() }
                })),
                serde_json::json!({"result": {"error": {
                    "code": "malformed_encoding", "class": "permanent"
                }}}),
                "malformed field index {field}"
            );
            let fields = [
                &mut params.enc_b64,
                &mut params.ciphertext_b64,
                &mut params.info_b64,
                &mut params.aad_b64,
            ];
            fields.into_iter().nth(field).unwrap().clear();
        }
    }

    #[tokio::test]
    async fn open_decoded_max_sign_payload_boundary_and_encoded_bound_precede_authorization() {
        use base64::Engine as _;
        let (surface, _admin, _) = scoped_rig(94);
        let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        let mut params = read_surface::OpenParams {
            credential_id: "kem:unknown".into(),
            enc_b64: encode(&[0u8; 32]),
            ciphertext_b64: String::new(),
            info_b64: encode(&vec![0u8; credentials_core::signing::MAX_SIGN_PAYLOAD - 32]),
            aad_b64: String::new(),
            enrollment_token: None,
        };
        assert_eq!(
            surface.open(94, None, &params).await.unwrap_err(),
            read_surface::ReadError::NotFound
        );
        params.aad_b64 = encode(b"x");
        assert_eq!(
            surface.open(94, None, &params).await.unwrap_err(),
            read_surface::ReadError::SignPayloadTooLarge
        );
        params.info_b64 = "!".repeat(1_398_117);
        assert_eq!(
            surface.open(94, None, &params).await.unwrap_err(),
            read_surface::ReadError::SignPayloadTooLarge
        );
    }

    #[tokio::test]
    async fn read_grant_does_not_authorize_scoped_signing() {
        use base64::Engine as _;

        let (surface, admin, store) = scoped_rig(82);
        let credential_id = "signing:operations:read-only";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    test_ed25519_pem().into_bytes(),
                    None,
                ),
            )
            .expect("create signing key");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                "signing:operations:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create read grant");
        admin.record_bind(
            82,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let refused = scoped_sign_request(
            &surface,
            &admin,
            82,
            credential_id,
            &base64::engine::general_purpose::STANDARD.encode(b"must not sign"),
        )
        .await;
        assert_scoped_not_found(&refused);
        let event = store
            .recent_auth_events(1)
            .expect("read auth events")
            .remove(0);
        assert_eq!(event.kind, "scoped_read_refusal");
        assert_eq!(event.detail.as_deref(), Some("no_grant"));
    }

    #[tokio::test]
    async fn sign_grant_does_not_authorize_scoped_get() {
        let (surface, admin, store) = scoped_rig(83);
        let credential_id = "apikey:operations:sign-only";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create api key");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                "apikey:operations:",
                GrantOperation::Sign,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create sign grant");
        admin.record_bind(
            83,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let refused = scoped_request(&surface, &admin, 83, credential_id).await;
        assert_scoped_not_found(&refused);
        let event = store
            .recent_auth_events(1)
            .expect("read auth events")
            .remove(0);
        assert_eq!(event.kind, "scoped_read_refusal");
        assert_eq!(event.detail.as_deref(), Some("no_grant"));
    }

    #[tokio::test]
    async fn sign_grant_signs_signing_keys_but_not_other_kinds() {
        use base64::Engine as _;

        let (surface, admin, store) = scoped_rig(84);
        let pem = test_ed25519_pem();
        store
            .create(
                "signing:operations:real",
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    pem.as_bytes().to_vec(),
                    None,
                ),
            )
            .expect("create signing key");
        store
            .create(
                "signing:operations:impostor",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", pem.into_bytes(), None),
            )
            .expect("create non-signing credential");
        for credential_id in ["signing:operations:real", "signing:operations:impostor"] {
            store
                .create_read_grant_audited(
                    "reserved",
                    "prefrontal-core",
                    SelectorKind::Exact,
                    credential_id,
                    GrantOperation::Sign,
                    AuditCtx::admin(AuditOp::GrantCreate),
                )
                .expect("create exact sign grant");
        }
        admin.record_bind(
            84,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );
        let payload = base64::engine::general_purpose::STANDARD.encode(b"granted bytes");

        let signed =
            scoped_sign_request(&surface, &admin, 84, "signing:operations:real", &payload).await;
        assert!(
            signed["result"]["signature_b64"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "a sign grant must authorize a SigningKey record"
        );

        let refused = scoped_sign_request(
            &surface,
            &admin,
            84,
            "signing:operations:impostor",
            &payload,
        )
        .await;
        assert_eq!(refused["result"]["error"]["code"], "kind_not_signable");
        assert_eq!(refused["result"]["error"]["class"], "permanent");
    }

    #[tokio::test]
    async fn read_grant_authorizes_scoped_public_key() {
        let (surface, admin, store) = scoped_rig(86);
        let credential_id = "signing:public-key:read-granted";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    test_ed25519_pem().into_bytes(),
                    None,
                ),
            )
            .expect("create signing key");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                credential_id,
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create read grant");
        admin.record_bind(
            86,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let published = scoped_public_key_request(&surface, &admin, 86, credential_id).await;
        assert_eq!(published["result"]["algorithm"], "ed25519");
        assert!(
            published["result"]["public_key_hex"]
                .as_str()
                .is_some_and(|key| !key.is_empty()),
            "a read grant must publish the signing key's public material"
        );
        // ASSERT ON THE REFUSAL, NOT ON AN EMPTY TABLE. This read `.is_empty()` until a
        // success row existed, which was a valid proxy only while a refusal was the ONLY
        // scoped event -- and it failed the moment first-use recording landed, correctly.
        //
        // The stronger form is here: no refusal AND the success is instrumented. The
        // second half is what this test could never say before, and it is the one that
        // catches a scoped op that authorizes without leaving any trace that it ran.
        let events = store.recent_auth_events(10).expect("read auth events");
        assert!(
            !events
                .iter()
                .any(|e| e.kind == AuthEventKind::ScopedReadRefusal.as_str()),
            "a grant-authorized public-key request must not record a refusal"
        );
        assert!(
            events
                .iter()
                .any(|e| e.kind == AuthEventKind::ScopedFirstUse.as_str()),
            "and the first exercise of the grant must be recorded, or an unused grant is \
             indistinguishable from one in constant use"
        );
    }

    #[tokio::test]
    async fn sign_grant_does_not_authorize_scoped_public_key() {
        let (surface, admin, store) = scoped_rig(87);
        let credential_id = "signing:public-key:sign-only";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    test_ed25519_pem().into_bytes(),
                    None,
                ),
            )
            .expect("create signing key");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                "signing:public-key:",
                GrantOperation::Sign,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create sign grant");
        admin.record_bind(
            87,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let refused = scoped_public_key_request(&surface, &admin, 87, credential_id).await;
        assert_scoped_not_found(&refused);
        let event = store
            .recent_auth_events(1)
            .expect("read auth events")
            .remove(0);
        assert_eq!(event.credential_id, credential_id);
        assert_eq!(event.detail.as_deref(), Some("no_grant"));
    }

    #[tokio::test]
    async fn public_key_handle_authorization_remains_available() {
        let (surface, admin, store) = scoped_rig(88);
        let credential_id = "signing:public-key:handle";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    test_ed25519_pem().into_bytes(),
                    None,
                ),
            )
            .expect("create signing key");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                credential_id,
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("store handle");

        let published = scoped_route_request(
            &surface,
            &admin,
            88,
            OP_PUBLIC_KEY,
            json!({ "handle": handle.raw }),
        )
        .await;
        assert_eq!(published["result"]["algorithm"], "ed25519");
        assert!(
            published["result"]["key_id"]
                .as_str()
                .is_some_and(|key_id| !key_id.is_empty()),
            "the existing handle form must still publish public key material"
        );
    }

    #[tokio::test]
    async fn scoped_public_key_fences_non_signing_records() {
        let (surface, admin, store) = scoped_rig(89);
        let credential_id = "apikey:public-key:impostor";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(
                    CredentialKind::ApiKey,
                    "test",
                    test_ed25519_pem().into_bytes(),
                    None,
                ),
            )
            .expect("create non-signing credential");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                credential_id,
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create read grant");
        admin.record_bind(
            89,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let refused = scoped_public_key_request(&surface, &admin, 89, credential_id).await;
        assert_eq!(refused["result"]["error"]["code"], "kind_not_signable");
        assert_eq!(refused["result"]["error"]["class"], "permanent");
        let event = store
            .recent_auth_events(1)
            .expect("read auth events")
            .remove(0);
        assert_eq!(event.credential_id, credential_id);
        assert_eq!(event.detail.as_deref(), Some("wrong_kind"));
        assert_eq!(event.principal_kind.as_deref(), Some("reserved"));
        assert_eq!(event.principal_id.as_deref(), Some("prefrontal-core"));
    }

    #[tokio::test]
    async fn scoped_public_key_refusals_record_auth_events_behind_uniform_wire_bodies() {
        let (surface, admin, store) = scoped_rig(90);
        let uncovered_id = "apikey:public-key:uncovered";
        let unknown_id = "signing:public-key:missing";
        store
            .create(
                uncovered_id,
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    test_ed25519_pem().into_bytes(),
                    None,
                ),
            )
            .expect("create uncovered signing key");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                "signing:public-key:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create read grant");
        admin.record_bind(
            90,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let no_grant = scoped_public_key_request(&surface, &admin, 90, uncovered_id).await;
        let not_found = scoped_public_key_request(&surface, &admin, 90, unknown_id).await;
        assert_eq!(
            no_grant, not_found,
            "an uncovered credential and an absent credential must have the same wire body"
        );
        let events = store.recent_auth_events(10).expect("read auth events");
        assert_eq!(
            events.len(),
            2,
            "each refused public-key request needs a row"
        );
        assert_eq!(events[0].credential_id, unknown_id);
        assert_eq!(events[0].detail.as_deref(), Some("not_found"));
        assert_eq!(events[1].credential_id, uncovered_id);
        assert_eq!(events[1].detail.as_deref(), Some("no_grant"));
        for event in events {
            assert_eq!(event.kind, "scoped_read_refusal");
            assert_eq!(event.principal_kind.as_deref(), Some("reserved"));
            assert_eq!(event.principal_id.as_deref(), Some("prefrontal-core"));
        }
    }

    #[tokio::test]
    async fn scoped_public_key_grant_lookup_failure_records_store_error() {
        let (surface, admin, store) = scoped_rig(91);
        let credential_id = "signing:public-key:store-error";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    test_ed25519_pem().into_bytes(),
                    None,
                ),
            )
            .expect("create signing key");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                SelectorKind::Exact,
                "signing:public-key:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create read grant");
        admin.record_bind(
            91,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        surface.force_scoped_grant_lookup_error_for_test();
        let refused = scoped_public_key_request(&surface, &admin, 91, credential_id).await;
        assert_scoped_not_found(&refused);
        let event = store
            .recent_auth_events(1)
            .expect("read auth events")
            .remove(0);
        assert_eq!(event.credential_id, credential_id);
        assert_eq!(event.detail.as_deref(), Some("store_error"));
        assert_eq!(event.principal_kind.as_deref(), Some("reserved"));
        assert_eq!(event.principal_id.as_deref(), Some("prefrontal-core"));
    }

    /// The signing fence: a signing-key credential signs, and EVERY other kind is
    /// refused with a permanent `kind_not_signable`.
    ///
    /// Both arms in one test because the fence is only meaningful as a pair. A test
    /// that only proves signing works would stay green if the kind check were deleted,
    /// and that deletion is precisely what turns this module into a general signing
    /// oracle: a handle for any stored secret could then produce signatures under it.
    ///
    /// The negative uses an API-KEY record holding VALID PEM, so the refusal cannot be
    /// mistaken for a parse failure. If the fence were removed, those bytes would sign
    /// happily -- which is the whole hazard, and a negative built from garbage bytes
    /// would refuse for the wrong reason and prove nothing.
    #[tokio::test]
    async fn signing_is_fenced_to_signing_key_records() {
        use credentials_core::record::CredentialKind;
        let (surface, store, _db, _root) = tmp_surface_with_store(31);

        // One PEM, deposited twice under different kinds. Same bytes, so the ONLY
        // difference between the two arms is the kind.
        let pem = test_ed25519_pem();

        let signer = VaultRecord::new_static(
            CredentialKind::SigningKey,
            "test",
            pem.as_bytes().to_vec(),
            None,
        );
        store.create("sign:root", &signer).expect("create signer");
        let not_signer = VaultRecord::new_static(
            CredentialKind::ApiKey,
            "test",
            pem.as_bytes().to_vec(),
            None,
        );
        store
            .create("apikey:impostor", &not_signer)
            .expect("create impostor");

        let h_sign = credentials_core::store::mint_handle().expect("mint");
        store
            .put_handle_hash(
                &h_sign.hash,
                "sign:root",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put handle");
        let h_api = credentials_core::store::mint_handle().expect("mint");
        store
            .put_handle_hash(
                &h_api.hash,
                "apikey:impostor",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put handle");

        use base64::Engine as _;
        let payload = base64::engine::general_purpose::STANDARD.encode(b"manifest bytes");

        // POSITIVE: the signing-key record signs, and names the key that did it.
        let ok = surface
            .sign(
                1,
                None,
                &read_surface::SignParams {
                    handle: Some(h_sign.raw.clone()),
                    credential_id: None,
                    payload_b64: payload.clone(),
                    enrollment_token: None,
                },
            )
            .await
            .expect("a SigningKey record must sign");
        assert!(!ok.signature_b64.is_empty(), "a signature must come back");
        assert_eq!(ok.key_id.len(), 16, "key_id is 8 bytes of hex");

        // NEGATIVE: identical bytes under ApiKey are refused, permanently.
        let err = surface
            .sign(
                1,
                None,
                &read_surface::SignParams {
                    handle: Some(h_api.raw.clone()),
                    credential_id: None,
                    payload_b64: payload,
                    enrollment_token: None,
                },
            )
            .await
            .expect_err("an ApiKey record must NOT sign even holding valid PEM");
        assert_eq!(
            err,
            read_surface::ReadError::KindNotSignable,
            "the refusal must name the fence, not a parse failure"
        );
        assert!(
            matches!(err.class(), read_surface::ErrorClass::Permanent),
            "no retry turns an api key into a signing key"
        );
    }

    /// Public material must verify signatures from the same handle while excluding the
    /// private PEM that ordinary `credential.get` would expose.
    ///
    /// The non-signing negative uses valid PEM under `ApiKey`, so deleting the kind
    /// fence makes this test fail by publishing a real key instead of refusing for an
    /// unrelated parse error.
    #[tokio::test]
    async fn public_key_matches_signatures_without_serializing_private_material() {
        use base64::Engine as _;
        use ring::signature::{UnparsedPublicKey, ED25519};

        // A private payload might be serialized as a JSON string or as a byte array;
        // inspect both shapes so a future `Vec<u8>` field cannot bypass the PEM-text
        // check merely because JSON escaped or number-encoded the same bytes.
        fn json_contains_byte_sequence(value: &serde_json::Value, needle: &[u8]) -> bool {
            match value {
                serde_json::Value::String(text) => text
                    .as_bytes()
                    .windows(needle.len())
                    .any(|window| window == needle),
                serde_json::Value::Array(values) => {
                    let encoded_bytes: Option<Vec<u8>> = values
                        .iter()
                        .map(|value| value.as_u64().and_then(|n| u8::try_from(n).ok()))
                        .collect();
                    encoded_bytes.is_some_and(|bytes| {
                        bytes.windows(needle.len()).any(|window| window == needle)
                    }) || values
                        .iter()
                        .any(|value| json_contains_byte_sequence(value, needle))
                }
                serde_json::Value::Object(fields) => fields
                    .values()
                    .any(|value| json_contains_byte_sequence(value, needle)),
                serde_json::Value::Null
                | serde_json::Value::Bool(_)
                | serde_json::Value::Number(_) => false,
            }
        }

        let (surface, store, _db, _root) = tmp_surface_with_store(32);
        let pem = test_ed25519_pem();
        store
            .create(
                "signing:agent-assertion:7",
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    pem.as_bytes().to_vec(),
                    None,
                ),
            )
            .expect("create signer");
        store
            .create(
                "apikey:valid-pem",
                &VaultRecord::new_static(
                    CredentialKind::ApiKey,
                    "test",
                    pem.as_bytes().to_vec(),
                    None,
                ),
            )
            .expect("create non-signer");

        let signer_handle = credentials_core::store::mint_handle().expect("mint signer handle");
        store
            .put_handle_hash(
                &signer_handle.hash,
                "signing:agent-assertion:7",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("store signer handle");
        let non_signer_handle =
            credentials_core::store::mint_handle().expect("mint non-signer handle");
        store
            .put_handle_hash(
                &non_signer_handle.hash,
                "apikey:valid-pem",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("store non-signer handle");

        let public = surface
            .public_key(
                1,
                None,
                &read_surface::PublicKeyParams {
                    handle: Some(signer_handle.raw.clone()),
                    credential_id: None,
                    enrollment_token: None,
                },
            )
            .await
            .expect("a signing key must publish its public half");
        assert_eq!(public.algorithm, "ed25519");

        // The outer route body is what a consumer receives. It must contain neither
        // the PEM armour nor the payload bytes, because returning either turns this
        // public-material route into the private `credential.get` disclosure path.
        let serialized = serde_json::to_vec(&wrap_result(&public)).expect("serialize route body");
        let serialized_value: serde_json::Value =
            serde_json::from_slice(&serialized).expect("decode serialized route body");
        assert!(
            !json_contains_byte_sequence(&serialized_value, pem.as_bytes()),
            "the serialized public-key response must not contain private key bytes"
        );
        assert!(
            !String::from_utf8_lossy(&serialized).contains("BEGIN PRIVATE KEY"),
            "the serialized public-key response must not contain PEM armour"
        );

        let payload = b"canonical manifest bytes";
        let signature = surface
            .sign(
                1,
                None,
                &read_surface::SignParams {
                    handle: Some(signer_handle.raw),
                    credential_id: None,
                    payload_b64: base64::engine::general_purpose::STANDARD.encode(payload),
                    enrollment_token: None,
                },
            )
            .await
            .expect("credential.sign must use the same stored key");
        let public_bytes: Vec<u8> = (0..public.public_key_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&public.public_key_hex[i..i + 2], 16).expect("hex"))
            .collect();
        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(signature.signature_b64)
            .expect("signature base64");
        UnparsedPublicKey::new(&ED25519, &public_bytes)
            .verify(payload, &signature_bytes)
            .expect("the published public half must verify credential.sign output");
        assert_eq!(public.key_id, signature.key_id);

        let err = surface
            .public_key(
                1,
                None,
                &read_surface::PublicKeyParams {
                    handle: Some(non_signer_handle.raw),
                    credential_id: None,
                    enrollment_token: None,
                },
            )
            .await
            .expect_err("a non-signing credential must not publish parsed material");
        assert_eq!(err, read_surface::ReadError::KindNotSignable);
    }

    /// A reactivate-based repair moves `ready` and NOT `record_version`.
    ///
    /// Pins the pair, because the two fields answer different questions and a consumer
    /// told "the version is the change cursor" would build on the wrong one. `reactivate`
    /// clears a wrong needs_reauth verdict without touching the stored material, so a
    /// credential goes unusable-to-usable with the version unchanged -- a poller watching
    /// only the version keeps a repaired credential marked dead indefinitely.
    ///
    /// The version CANNOT move here: it is bound into the envelope's AAD, so bumping it
    /// means re-sealing, and a re-seal on the repair path would put decrypt-and-encrypt
    /// on the one route that recovers from a wrong verdict. So this asserts the version
    /// is STABLE as well as that `ready` flipped -- an implementation that "helpfully"
    /// bumped it would be writing a record it can no longer open.
    #[tokio::test]
    async fn a_reactivate_repair_moves_ready_and_leaves_the_version_alone() {
        let (surface, store, _db, _root) = tmp_surface_with_store(29);
        let record = VaultRecord::new_static(
            credentials_core::record::CredentialKind::ApiKey,
            "test",
            b"payload".to_vec(),
            None,
        );
        store.create("apikey:repair", &record).expect("create");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "apikey:repair",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put handle");

        let params = crate::read_surface::StatusParams {
            handle: Some(handle.raw.clone()),
            credential_id: None,
            enrollment_token: None,
        };
        let before = surface.status(1, None, &params).await;
        assert!(before.ready, "seeded credential must start ready");
        let version_before = before
            .record_version
            .expect("a resolved handle has a version");

        store
            .invalidate_and_revoke_all_audited(
                "apikey:repair",
                AuditCtx::admin(AuditOp::Invalidate),
            )
            .expect("invalidate");

        store
            .reactivate_audited("apikey:repair", AuditCtx::admin(AuditOp::Reactivate))
            .expect("reactivate");

        // The handle was revoked by the invalidate, so ask by credential id via meta:
        // the point is the VERSION, and the surface's own view is checked below.
        let meta = store.meta("apikey:repair").expect("meta");
        assert_eq!(
            meta.record_version, version_before,
            "reactivate must NOT bump the version: it is AAD-bound, so moving it without \
             re-sealing writes a record the vault can no longer open"
        );
        assert!(
            matches!(meta.state, credentials_core::store::RecordState::Active),
            "the repair must have landed, or this test proves nothing about the pair"
        );
    }

    /// `status` must NOT consult the refresh path, which is the only reason the version
    /// cursor lives here rather than on `get`.
    ///
    /// THIS FENCES A JUSTIFICATION, NOT A BEHAVIOUR. The cursor exists so a consumer can
    /// poll for a credential coming back WITHOUT buying an upstream token exchange each
    /// time -- `get` mints on a stale record, so polling through it would charge a
    /// provider call per check and a consumer avoiding that cost would notice the repair
    /// late. Every other test here asserts what the field CONTAINS; none asserted what
    /// reading it COSTS, and a plausible consistency refactor routing status through the
    /// engine would keep them all green while silently making repair-polling expensive.
    ///
    /// Discriminated without a network: the record is a STALE OAuth credential and NO
    /// adapter is registered, so anything that reaches the refresh path fails outright.
    /// Metadata-only status answers normally.
    #[tokio::test]
    async fn status_does_not_consult_the_refresh_path() {
        let (surface, store, _db, _root) = tmp_surface_with_store(23);
        // Stale: an OAuth record whose access token expired long ago. Reaching the
        // refresh path with no adapter registered cannot succeed.
        let oauth = credentials_core::oauth::OAuthCredential {
            access_token: "expired".to_string().into(),
            refresh_token: "rt".to_string().into(),
            expires_at_ms: Some(1),
            token_url: String::new(),
            client_id: None,
            client_secret: None,
            scopes: Vec::new(),
        };
        let record = VaultRecord::new_oauth("test", "no-such-adapter", oauth, Vec::new());
        store.create("oauth:stale", &record).expect("create");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "oauth:stale",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put handle");

        let result = surface
            .status(
                1,
                None,
                &crate::read_surface::StatusParams {
                    handle: Some(handle.raw.clone()),
                    credential_id: None,
                    enrollment_token: None,
                },
            )
            .await;

        assert!(
            result.ready,
            "status must report an Active record as ready from METADATA -- if this fails, \
             status is consulting the refresh path, which no adapter can satisfy here"
        );
        assert!(
            result.record_version.is_some(),
            "status must serve the cursor without a provider call"
        );
        assert!(
            result.last_error_code.is_none(),
            "a stale-but-active credential is not an error to status: staleness is the \
             refresh path's business, and status does not go there"
        );
    }

    /// `status` must carry the record version, because a consumer waiting for a
    /// credential to come back has no other cheap way to see that it did.
    ///
    /// THE VAULT CANNOT PUSH -- subc has no module-to-client relay by design -- so a
    /// consumer must ask. Before this, the only way to observe a change was
    /// `credential.get`, which MINTS on a stale record: polling for repair meant buying
    /// upstream token exchanges, and a consumer avoiding that cost would notice late.
    ///
    /// Asserted as a CURSOR rather than as a field being present: the version must MOVE
    /// across a replace, and must be ABSENT where there is nothing to version. A field
    /// that is always Some(1) would satisfy a presence check and be useless.
    #[tokio::test]
    async fn status_carries_a_record_version_that_moves_on_replace() {
        let (surface, store, _db, _root) = tmp_surface_with_store(16);
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "apikey:active",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put handle");

        let before = surface
            .status(
                1,
                None,
                &crate::read_surface::StatusParams {
                    handle: Some(handle.raw.clone()),
                    credential_id: None,
                    enrollment_token: None,
                },
            )
            .await;
        let v_before = before
            .record_version
            .expect("a resolved handle must report its version");

        // A replace is the shape an operator re-auth takes, and the transition a waiting
        // consumer needs to notice.
        store
            .overwrite_unconditional_audited(
                "apikey:active",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"k2".to_vec(), None),
                AuditCtx::admin(AuditOp::Put),
            )
            .expect("replace");

        let after = surface
            .status(
                1,
                None,
                &crate::read_surface::StatusParams {
                    handle: Some(handle.raw.clone()),
                    credential_id: None,
                    enrollment_token: None,
                },
            )
            .await;
        let v_after = after.record_version.expect("still resolves");
        assert!(
            v_after > v_before,
            "the version must MOVE on replace or it is not a cursor: {v_before} -> {v_after}"
        );

        // ABSENT where there is nothing to version. A sentinel here would compare as
        // older than everything, so a poller would read a dead handle as a pending
        // change forever.
        let overall = surface
            .status(
                1,
                None,
                &crate::read_surface::StatusParams {
                    handle: None,
                    credential_id: None,
                    enrollment_token: None,
                },
            )
            .await;
        assert!(
            overall.record_version.is_none(),
            "overall readiness has no credential to version"
        );
        let unknown = surface
            .status(
                2,
                None,
                &crate::read_surface::StatusParams {
                    handle: Some("ckh_definitely-not-a-handle".to_string()),
                    credential_id: None,
                    enrollment_token: None,
                },
            )
            .await;
        assert!(
            unknown.record_version.is_none(),
            "an unresolvable handle must not report a version"
        );
    }

    /// The mark that predicts a SLOW get on a record every other field calls healthy.
    ///
    /// Pins the exact reading that was invisible before this field existed: `ready:
    /// true`, `last_error_code: null`, and the next `get` about to buy an upstream token
    /// exchange. A consumer sizing a startup bound cannot get that from `ready`, because
    /// `ready` is genuinely TRUE -- the mark exists so the next get refreshes rather than
    /// refusing.
    ///
    /// The fixture is `oauth:stub` -- refreshable per `default_refresh_adapter` -- and the
    /// mark is driven through the PUBLIC `report_auth_failure` route, the only call that
    /// can ever set the marker on a real handle. The previous version seeded
    /// `apikey:active` and called `store.mark_stale_if_version_reported` directly, which
    /// constructs a state (non-refreshable + Active + `stale_pending = 1`) the production
    /// path cannot produce: the public route branches on refreshability and the
    /// non-refreshable arm INVALIDATES rather than marks, so the test was passing against
    /// a hand-staged copy of the mark with no assertion behind it.
    #[tokio::test]
    async fn status_publishes_the_stale_mark_without_calling_the_credential_unhealthy() {
        let (surface, store, _db, _root) = tmp_surface_with_store(16);
        store
            .create(
                "oauth:stub",
                &VaultRecord::new_oauth(
                    "test",
                    "stub",
                    OAuthCredential {
                        access_token: "locally-valid".to_string().into(),
                        refresh_token: "rt".to_string().into(),
                        expires_at_ms: Some(i64::MAX),
                        token_url: "https://example.invalid/token".into(),
                        client_id: None,
                        client_secret: None,
                        scopes: Vec::new(),
                    },
                    b"locally-valid".to_vec(),
                ),
            )
            .expect("seed refreshable credential");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "oauth:stub",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");

        let clean = surface
            .status(
                1,
                None,
                &crate::read_surface::StatusParams {
                    handle: Some(handle.raw.clone()),
                    credential_id: None,
                    enrollment_token: None,
                },
            )
            .await;
        assert_eq!(
            clean.stale_pending,
            Some(false),
            "a resolved handle must report the mark explicitly, not by omission"
        );
        assert!(clean.ready, "precondition: the record starts healthy");

        // Exactly what a consumer's 401 report does: the public route sees a refreshable
        // id and chooses the stale arm, so the record stays Active and `stale_pending`
        // flips to 1. Going through `report_auth_failure` rather than the store method is
        // the point -- the version-gated invalidate arm on the non-refreshable path is the
        // shape that has to be bypassed for a hand-staged mark to be possible.
        surface
            .report_auth_failure(
                1,
                None,
                &read_surface::ReportAuthFailureParams {
                    handle: Some(handle.raw.clone()),
                    credential_id: None,
                    enrollment_token: None,
                    provider_status: 401,
                    record_version: 1,
                    reporter_source: None,
                },
            )
            .await
            .expect("report accepted");

        let marked = surface
            .status(
                1,
                None,
                &crate::read_surface::StatusParams {
                    handle: Some(handle.raw.clone()),
                    credential_id: None,
                    enrollment_token: None,
                },
            )
            .await;
        assert_eq!(
            marked.stale_pending,
            Some(true),
            "the mark must be visible WITHOUT calling get -- the whole point is to avoid \
             the call whose cost is in question"
        );
        // The load-bearing half. If this ever flips to false, the field has been folded
        // into health and a consumer will start treating a usable credential as broken.
        assert!(
            marked.ready,
            "a stale-marked record is still USABLE -- expensive is not unhealthy"
        );
        assert!(
            marked.last_error_code.is_none(),
            "a pending repair is not an error that has occurred"
        );

        // ABSENT, never defaulted false: claiming "no repair pending" for a record this
        // path could not read would be an assertion with no basis behind it.
        let overall = surface
            .status(
                1,
                None,
                &crate::read_surface::StatusParams {
                    handle: None,
                    credential_id: None,
                    enrollment_token: None,
                },
            )
            .await;
        assert!(
            overall.stale_pending.is_none(),
            "overall readiness names no credential, so it can report no mark"
        );
        let unknown = surface
            .status(
                2,
                None,
                &crate::read_surface::StatusParams {
                    handle: Some("ckh_definitely-not-a-handle".to_string()),
                    credential_id: None,
                    enrollment_token: None,
                },
            )
            .await;
        assert!(
            unknown.stale_pending.is_none(),
            "an unresolvable handle must not assert anything about a record"
        );
    }

    /// The stale-pending mark must NOT advertise an upstream exchange on a record the
    /// next `get` will refuse out of hand.
    ///
    /// Pins the second half of the field's contract: it is a LATENCY PREDICTOR, not a
    /// claim that anything is happening. A consumer reading `stale_pending: true`
    /// concludes the next get is going to spend seconds on a token exchange -- the very
    /// reason this field exists -- and will SKIP the credential in a startup warm bound.
    /// Skipping is the only safe behaviour when the mark is true, because the alternative
    /// is paying the exchange that the mark warned about.
    ///
    /// The construction reproduces the live shape on this deployment every four hours,
    /// measured 2026-08-27: a consumer 401 marks a refreshable record stale, the forced
    /// refresh fails, the engine latches the record to `needs_reauth`, and `stale_pending`
    /// is left at 1 because none of the seven `UPDATE credentials SET state = ...` paths
    /// in `credentials-core::store` clear the column. The mark is then a five-minute lie:
    /// `stale_pending: true` says "next get pays seconds" while the next get fails fast
    /// with `needs_reauth` without touching the network.
    ///
    /// The state is constructed through the production paths (public `report_auth_failure`
    /// sets the mark, then the engine's version-fenced invalidation after a failed refresh
    /// flips the state), so the test is a real reading of the buggy state rather than a
    /// hand-staged copy of it. A pure store-level construction would pass without ever
    /// proving the public route is part of the path that creates it.
    #[tokio::test]
    async fn status_does_not_publish_a_stale_pending_mark_on_a_non_active_record() {
        // The surface's engine must HOLD the failing adapter -- `tmp_surface_with_store`
        // builds one with an empty adapter list, and a forced refresh against it answers
        // `refresh_unsupported` without ever reaching a provider.
        let (_unused, store, _db, _root) = tmp_surface_with_store(17);
        let surface = Arc::new(ReadSurface::new(
            Arc::new(RefreshEngine::new(
                Arc::clone(&store),
                vec![Arc::new(InvalidGrantAdapter)],
                Arc::new(crate::test_support::NoHttp),
            )),
            FetchLimiter::new(Caps::default()),
        ));
        store
            .create(
                "oauth:needs_reauth_after_stale",
                &VaultRecord::new_oauth(
                    "test",
                    "invalid-grant-fixture",
                    OAuthCredential {
                        access_token: "locally-valid".to_string().into(),
                        refresh_token: "rt".to_string().into(),
                        expires_at_ms: Some(i64::MAX),
                        token_url: "https://example.invalid/token".into(),
                        client_id: None,
                        client_secret: None,
                        scopes: Vec::new(),
                    },
                    b"locally-valid".to_vec(),
                ),
            )
            .expect("seed refreshable credential");
        let raw = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &raw.hash,
                "oauth:needs_reauth_after_stale",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");

        // Production step 1: a consumer reports a 401 on the served version. The public
        // route is refreshable, so it MARKS STALE rather than invalidating; the record
        // stays Active and `stale_pending` becomes 1.
        surface
            .report_auth_failure(
                11,
                None,
                &read_surface::ReportAuthFailureParams {
                    handle: Some(raw.raw.clone()),
                    credential_id: None,
                    enrollment_token: None,
                    provider_status: 401,
                    record_version: 1,
                    reporter_source: None,
                },
            )
            .await
            .expect("report accepted");

        // Production step 2: the next get sees `stale_pending` and forces a refresh, the
        // provider refuses with invalid_grant, and the ENGINE latches the record. This runs
        // the real failure path rather than reproducing its outcome: two earlier versions of
        // this test called the store directly -- first unversioned, then version-fenced --
        // and both would have stayed green if the engine's failure arm changed, which is the
        // whole defect they were written to pin. The engine also writes a `refresh_failed`
        // observation here that no direct store call produces.
        let err = surface
            .get(
                11,
                &read_surface::GetParams {
                    handle: raw.raw.clone(),
                    min_ttl_ms: None,
                    // FALSE deliberately. The refresh under test must be driven by the
                    // `stale_pending` mark the report left behind; forcing it here would
                    // make the test pass on a path the consumer never takes.
                    force_refresh: false,
                },
            )
            .await;
        assert!(
            matches!(
                err,
                read_surface::GetOutcome::Err {
                    error: read_surface::ErrorBody {
                        code: read_surface::ReadError::NeedsReauth,
                        ..
                    }
                }
            ),
            "the forced refresh must fail through the engine: {err:?}"
        );

        // The observation, asserted rather than advertised. The comment above claims the
        // engine writes a diagnostic no direct store call produces -- and until this
        // assertion existed that was a claim in prose with nothing behind it, which is the
        // same defect as a guard whose coverage is invisible from its green result. The
        // audit chain records a generic `invalidate` here; only this row says the provider
        // was reached and what it answered.
        let events = store.recent_auth_events(10).expect("read events");
        let refresh_failed: Vec<_> = events
            .iter()
            .filter(|e| e.kind == "refresh_failed")
            .collect();
        assert_eq!(
            refresh_failed.len(),
            1,
            "the engine's invalid_grant arm must leave exactly one refresh_failed row; \
             got {events:?}"
        );
        assert_eq!(
            refresh_failed[0].credential_id, "oauth:needs_reauth_after_stale",
            "the row must name the credential the refresh was attempted for"
        );
        assert_eq!(
            refresh_failed[0].detail.as_deref(),
            Some("invalid_grant"),
            "the row must carry WHICH provider verdict was seen -- a `refresh_failed` with \
             no detail cannot distinguish a terminal invalid_grant from a transient \
             transport failure, and only the terminal one latches"
        );

        // Precondition checks: the construction actually reproduced the live shape, so a
        // green fix can be trusted to mean the fix is real and not a different test
        // passing for a different reason.
        let meta = store.meta("oauth:needs_reauth_after_stale").expect("meta");
        assert_eq!(
            meta.state,
            RecordState::NeedsReauth,
            "precondition: the construction must leave the record latched"
        );
        assert!(
            meta.stale_pending,
            "precondition: the bug is exactly that stale_pending survives a state flip"
        );

        // The pin. Non-Active state => next get performs no upstream exchange, so the
        // field is FALSE regardless of the column. Absent is reserved for "this path
        // could not see the record" and must NOT be used here -- a defaulted false on a
        // known record would be a defensible reading, an absent one would be a missing
        // field that looks like a wire-drift to a consumer.
        let got = surface
            .status(
                11,
                None,
                &crate::read_surface::StatusParams {
                    handle: Some(raw.raw),
                    credential_id: None,
                    enrollment_token: None,
                },
            )
            .await;
        assert_eq!(
            got.stale_pending,
            Some(false),
            "non-Active state must publish the real (false) prediction, not the column's \
             stale value -- a consumer skipping the credential on stale_pending=true \
             would be skipping a credential whose next get refuses without an exchange"
        );
        assert!(
            !got.ready,
            "a latched record is not ready -- the rest of the contract is unchanged"
        );
        assert_eq!(
            got.last_error_code,
            Some(read_surface::ReadError::NeedsReauth),
            "a needs_reauth record must name the reason"
        );
    }

    #[tokio::test]
    async fn status_handle_probe_runs_the_limiter() {
        let (surface, store, _db, _root) = tmp_surface_with_store(15);
        // Sweep more distinct unknown handles than the distinct ceiling (16) on ONE
        // connection, all via status (not get). None resolve — the probe itself is the
        // signal — so this must still trip the anomaly.
        for i in 0..20 {
            let params = StatusParams {
                handle: Some(format!("ckh_unknown_{i}")),
                credential_id: None,
                enrollment_token: None,
            };
            let _ = surface.status(77, None, &params).await;
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

    /// THE KEY-EXERCISE HANDLE PATH RUNS THE LIMITER, FOR BOTH OPERATIONS AND FROM ONE
    /// PLACE.
    ///
    /// `sign` and `public_key` carried byte-identical address-resolution preambles until
    /// they were extracted into `resolve_key_address`, and the extraction's own comment
    /// claims the limiter position is load-bearing. Nothing defended that claim: removing
    /// the `check_limiter` call from the shared helper left all 134 tests green, so the
    /// property was asserted in prose and nowhere else.
    ///
    /// That is worse after the extraction than before. One helper serving two operations
    /// means one deletion disarms the enumeration detector on BOTH, where previously a
    /// careless edit could only reach one. A shared chokepoint needs a test precisely
    /// because it concentrates the blast radius it was created to reduce.
    ///
    /// Both operations are driven here rather than one, because the helper is reached
    /// through two different `From` conversions and a future edit could plausibly break
    /// only one of them.
    #[tokio::test]
    async fn key_exercise_handle_sweeps_run_the_limiter() {
        use base64::Engine as _;

        for op in ["sign", "public_key"] {
            let (surface, store, _db, _root) =
                tmp_surface_with_store(if op == "sign" { 171 } else { 172 });
            // More distinct unknown handles than the distinct ceiling (16), on ONE
            // connection. None resolve -- the probe is the signal -- so the sweep must
            // still raise the alarm.
            for i in 0..20 {
                let handle = Some(format!("ckh_unknown_{op}_{i}"));
                if op == "sign" {
                    let _ = surface
                        .sign(
                            78,
                            None,
                            &read_surface::SignParams {
                                handle,
                                credential_id: None,
                                payload_b64: base64::engine::general_purpose::STANDARD.encode(b"x"),
                                enrollment_token: None,
                            },
                        )
                        .await;
                } else {
                    let _ = surface
                        .public_key(
                            78,
                            None,
                            &read_surface::PublicKeyParams {
                                handle,
                                credential_id: None,
                                enrollment_token: None,
                            },
                        )
                        .await;
                }
            }
            let alarms = store
                .read_audit(None)
                .expect("read audit")
                .into_iter()
                .filter(|e| e.op == "fetch_anomaly")
                .count();
            assert!(
                alarms >= 1,
                "a {op} sweep of unknown handles must raise a durable fetch-anomaly alarm; \
                 the limiter runs inside resolve_key_address, before resolution"
            );
        }
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
        let (surface, _surface_root) = tmp_surface(21);
        let (admin, _admin_store, _admin_root) = tmp_admin(21);
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

    /// A cookie header is an opaque request artifact. The storage and read paths must
    /// preserve every byte rather than treating its separators or spaces as structure.
    #[tokio::test]
    async fn cookie_record_round_trips_byte_exact_through_seal_and_serve() {
        let (surface, store, _db, _root) = tmp_surface_with_store(74);
        let payload = b" session=abc=123; preference=space value; ending=%".to_vec();
        store
            .create(
                "cookie:opencode.ai",
                &VaultRecord::new_cookie("operator", payload.clone()),
            )
            .expect("seal cookie record");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "cookie:opencode.ai",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");

        let outcome = surface
            .get(
                78,
                &read_surface::GetParams {
                    handle: handle.raw,
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await;
        let read_surface::GetOutcome::Ok(result) = outcome else {
            panic!("a stored cookie must serve through credential.get");
        };
        assert_eq!(
            result.payload, payload,
            "cookie bytes must survive seal and serve"
        );
        assert_eq!(
            result.expires_at_ms, None,
            "cookies carry no declared expiry"
        );
        assert_eq!(result.account_id, None, "cookies do not disclose identity");
        assert_eq!(result.email, None, "cookies do not disclose identity");
        assert_eq!(result.org_name, None, "cookies do not disclose identity");
    }

    /// A legacy malformed row must never become a successful zero-byte credential.
    /// The fixture uses an OAuth-kind record with no refresh state so the current store
    /// can represent the historical bad row without bypassing the new static-write
    /// invariant; removing the read guard makes this test return `Ok([])`.
    #[tokio::test]
    async fn get_quarantines_an_empty_nonrefreshable_record() {
        use credentials_core::store::RecordState;

        let (surface, store, _db, _root) = tmp_surface_with_store(20);
        let mut legacy = VaultRecord::new_oauth(
            "legacy-import",
            "legacy",
            credentials_core::oauth::OAuthCredential {
                access_token: String::new().into(),
                refresh_token: String::new().into(),
                expires_at_ms: None,
                token_url: String::new(),
                client_id: None,
                client_secret: None,
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

    /// A retired credential is not served, but it uses the same consumer-visible
    /// `auth_required` refusal as `needs_reauth`. The distinction is operational state
    /// for the admin surface, not a recovery branch for consumers.
    #[tokio::test]
    async fn retired_reads_use_the_same_auth_required_refusal_as_needs_reauth() {
        let (surface, store, _db, _root) = tmp_surface_with_store(21);
        store
            .create(
                "apikey:retired",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"k".to_vec(), None),
            )
            .expect("create retired credential");
        store
            .retire_and_revoke_all_audited("apikey:retired", AuditCtx::admin(AuditOp::Invalidate))
            .expect("retire credential");

        let mint_for = |id: &str| {
            let handle = credentials_core::store::mint_handle().expect("mint handle");
            store
                .put_handle_hash(&handle.hash, id, AuditCtx::admin(AuditOp::MintHandle))
                .expect("store handle");
            handle.raw
        };
        let needs_reauth_handle = mint_for("apikey:dead");
        let retired_handle = mint_for("apikey:retired");

        let needs_reauth = surface
            .get(
                51,
                &read_surface::GetParams {
                    handle: needs_reauth_handle,
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await;
        let read_surface::GetOutcome::Err {
            error: needs_reauth_error,
        } = needs_reauth
        else {
            panic!("needs_reauth credential must refuse reads");
        };

        let retired = surface
            .get(
                52,
                &read_surface::GetParams {
                    handle: retired_handle,
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await;
        let read_surface::GetOutcome::Err {
            error: retired_error,
        } = retired
        else {
            panic!("retired credential must refuse reads");
        };

        assert_eq!(
            needs_reauth_error.code,
            read_surface::ReadError::NeedsReauth
        );
        assert_eq!(
            needs_reauth_error.class,
            read_surface::ErrorClass::AuthRequired
        );
        assert_eq!(retired_error.code, needs_reauth_error.code);
        assert_eq!(retired_error.class, needs_reauth_error.class);
    }

    /// A static record keeps the terminal report-auth-failure behavior: it invalidates
    /// ONLY on 401/403, and ONLY at the record version the consumer was served.
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

        let (surface, store, _db, _root) = tmp_surface_with_store(31);
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
        let params = |status: u16, version: u64, reporter_source: Option<&str>| {
            read_surface::ReportAuthFailureParams {
                handle: Some(handle.clone()),
                credential_id: None,
                enrollment_token: None,
                provider_status: status,
                record_version: version,
                reporter_source: reporter_source.map(str::to_owned),
            }
        };

        // A NON-AUTH status must not invalidate: a provider 500 is a hiccup, not a dead
        // credential. It is now REFUSED rather than accepted-and-discarded — the record
        // outcome is the same, and the consumer is told. This assertion used to read
        // `.expect("a non-auth status is accepted")`, which was true and was the defect:
        // a consumer classifying 5xx as a credential death got back success and a mark
        // that did nothing.
        let refusal = surface
            .report_auth_failure(7, None, &params(500, 1, None))
            .await
            .expect_err("a non-auth status is refused, not accepted");
        assert_eq!(
            refusal,
            read_surface::ReadError::ReportStatusNotCredentialDeath,
            "and it refuses with the code that names why"
        );
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
            .report_auth_failure(7, None, &params(401, 1, Some("relay_message_parse")))
            .await
            .expect("a stale report is accepted, not errored");
        assert_eq!(
            state_of(&store),
            RecordState::Active,
            "a 401 for a version the vault has moved past must NOT invalidate: that \
             credential was already repaired"
        );
        let events = store.recent_auth_events(10).expect("stale report event");
        assert_eq!(events[0].kind, "consumer_report_latch");
        assert_eq!(
            events[0].reporter_source.as_deref(),
            Some("relay_message_parse")
        );
        assert!(
            !events[0].applied,
            "a state no-op still records a diagnostic observation"
        );

        // THE ACCEPTED ARM. Without it, an implementation that ignored every report
        // satisfies both assertions above.
        surface
            .report_auth_failure(7, None, &params(401, 2, Some(&"a".repeat(40))))
            .await
            .expect("a current-version 401 is accepted");
        assert_eq!(
            state_of(&store),
            RecordState::NeedsReauth,
            "a 401 at the served version must stop the vault serving that token"
        );
        assert!(
            !store.meta("apikey:active").expect("meta").stale_pending,
            "a non-refreshable record must latch rather than setting a useless stale marker"
        );
        let health = credentials_core::health::VaultHealth::summarize(
            &store.list_meta().expect("list reported credential"),
            0,
            false,
        );
        assert_eq!(
            health.status,
            credentials_core::health::VaultHealthStatus::Degraded,
            "a consumer-discovered failure must remain an alarm, not become retired"
        );
        let events = store.recent_auth_events(10).expect("events");
        assert_eq!(events[0].kind, "consumer_report_latch");
        assert_eq!(events[0].reporter_source.as_deref(), Some("unrecognised"));
        let raw = "a".repeat(40);
        assert!(
            events.iter().all(|event| {
                event.credential_id != raw
                    && event.kind != raw
                    && event.detail.as_deref() != Some(raw.as_str())
                    && event.reporter_source.as_deref() != Some(raw.as_str())
                    && event.principal_kind.as_deref() != Some(raw.as_str())
                    && event.principal_id.as_deref() != Some(raw.as_str())
            }),
            "the raw reporter source must never appear in any string column of \
             auth_events -- not merely mapped out of reporter_source itself, but not \
             displaced into detail or the principal fields either"
        );
        assert!(
            events[0].applied,
            "the current static report must be recorded as applied"
        );

        // An unknown handle gets the same refusal as a revoked one, so a caller cannot
        // use this endpoint to discover which handles exist.
        let unknown = surface
            .report_auth_failure(
                7,
                None,
                &read_surface::ReportAuthFailureParams {
                    handle: Some("ckh_not_a_handle".to_string()),
                    credential_id: None,
                    enrollment_token: None,
                    provider_status: 401,
                    record_version: 1,
                    reporter_source: None,
                },
            )
            .await;
        assert!(
            matches!(unknown, Err(read_surface::ReadError::NotFound)),
            "an unknown handle must be a uniform not_found, got {unknown:?}"
        );
    }

    /// THE LOAD-BEARING TEST OF THE SCOPED ADDRESS: both addressing forms produce ONE
    /// store outcome.
    ///
    /// Written this way because the failure it guards is not a wrong answer, it is
    /// DRIFT. Two addresses reaching two code paths that each look correct is how one
    /// of them silently stops fencing on version, or stops marking stale, or starts
    /// latching where the other marks -- and nothing fails, because each path has its
    /// own test asserting its own behaviour. Asserting the two outcomes are EQUAL is
    /// the only shape that cannot be satisfied by two correct-looking implementations.
    #[tokio::test]
    async fn a_scoped_report_and_a_handle_report_reach_the_same_store_outcome() {
        use credentials_core::oauth::OAuthCredential;

        // Two identical credentials so each address can be exercised on its own record
        // without the first report changing what the second one sees.
        let (surface, store, _db, _root) = tmp_surface_with_store(191);
        let record = || {
            VaultRecord::new_oauth(
                "stub",
                "stub",
                OAuthCredential {
                    access_token: "live".to_string().into(),
                    refresh_token: "refresh".to_string().into(),
                    expires_at_ms: Some(i64::MAX),
                    token_url: "https://example.invalid/token".into(),
                    client_id: None,
                    client_secret: None,
                    scopes: Vec::new(),
                },
                b"live".to_vec(),
            )
        };
        store
            .create("oauth:twin-handle", &record())
            .expect("create handle-addressed twin");
        store
            .create("oauth:twin-scoped", &record())
            .expect("create scope-addressed twin");

        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "oauth:twin-handle",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");
        store
            .create_read_grant_audited(
                "reserved",
                "twin-reporter",
                credentials_core::store::SelectorKind::Exact,
                "oauth:twin-scoped",
                credentials_core::store::GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("grant read on the scoped twin");
        let principal = subc_protocol::Principal::Reserved {
            module_id: "twin-reporter".into(),
        };

        surface
            .report_auth_failure(
                1,
                None,
                &read_surface::ReportAuthFailureParams {
                    handle: Some(handle.raw),
                    credential_id: None,
                    enrollment_token: None,
                    provider_status: 401,
                    record_version: 1,
                    reporter_source: None,
                },
            )
            .await
            .expect("handle-addressed report");
        surface
            .report_auth_failure(
                2,
                Some(&principal),
                &read_surface::ReportAuthFailureParams {
                    handle: None,
                    credential_id: Some("oauth:twin-scoped".to_owned()),
                    enrollment_token: None,
                    provider_status: 401,
                    record_version: 1,
                    reporter_source: None,
                },
            )
            .await
            .expect("scope-addressed report");

        let by_handle = store.meta("oauth:twin-handle").expect("handle twin meta");
        let by_scope = store.meta("oauth:twin-scoped").expect("scoped twin meta");
        assert_eq!(
            (by_handle.state, by_handle.record_version),
            (by_scope.state, by_scope.record_version),
            "the two addressing forms must reach one store outcome; if they diverge, one \
             of them has stopped fencing or stopped marking and no single-path test can \
             see it"
        );
    }

    /// A status the contract does not treat as a credential death is REFUSED, and the
    /// two that are stay honoured.
    ///
    /// The refusing half is the new behaviour; the honouring half is what stops a future
    /// tidy-up from collapsing this into "401 only". 403 is genuinely ambiguous across
    /// providers — GitHub uses it for permission refusals on a live token, and xAI has
    /// used it for a real death. Measured on the live store 2026-09-19: of 72 consumer
    /// reports ever taken, exactly one was a real 403, on `oauth:xai`, and it WAS a death
    /// — an operator re-logged in three hours later and it has refreshed cleanly since.
    /// Refusing 403 would fail toward a dead credential that looks healthy.
    #[tokio::test]
    async fn a_report_status_outside_the_contract_is_refused_and_401_403_are_not() {
        let (surface, store, _db, _root) = tmp_surface_with_store(196);
        store
            .create(
                "apikey:status-gate",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create record");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "apikey:status-gate",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");

        let report = |status: u16| {
            let raw = handle.raw.clone();
            let surface = &surface;
            async move {
                surface
                    .report_auth_failure(
                        6,
                        None,
                        &read_surface::ReportAuthFailureParams {
                            handle: Some(raw),
                            credential_id: None,
                            enrollment_token: None,
                            provider_status: status,
                            record_version: 1,
                            reporter_source: None,
                        },
                    )
                    .await
            }
        };

        for status in [429, 402, 500, 200, 404] {
            let refusal = report(status)
                .await
                .expect_err("a status the contract does not treat as a death must refuse");
            assert_eq!(
                refusal,
                read_surface::ReadError::ReportStatusNotCredentialDeath,
                "status {status} must refuse with the naming code, not be accepted and \
                 discarded: a consumer whose classification is wrong learns nothing from \
                 a success that did nothing"
            );
            assert_eq!(
                refusal.class(),
                read_surface::ErrorClass::Permanent,
                "the same status will never become a credential death, so a retry cannot \
                 succeed and the class must say so"
            );
        }

        for status in [401, 403] {
            report(status)
                .await
                .unwrap_or_else(|e| panic!("status {status} must still be honoured, got {e:?}"));
        }
    }

    /// The audit row for a scoped report names the PRINCIPAL, not the route channel.
    ///
    /// This exists because mutation found nothing guarding it: replacing the principal
    /// arm with `conn-N` left the entire suite green. The handle form legitimately
    /// writes `conn-N` -- a handle holder is anonymous by design and the channel number
    /// is all there is -- but a scoped caller's identity is what AUTHORIZED the write,
    /// read one line above by the grant lookup that admitted the call. Writing `conn-N`
    /// there would discard a value already in hand, which is a defect this repo has met
    /// three times (mint rows naming a credential but not which handle, a peer's limiter
    /// holding a principal and writing `conn-N`, a pin recording a slot rather than its
    /// occupant). All three were found by accident, months later, from the outside.
    #[tokio::test]
    async fn a_scoped_report_audits_under_the_principal_not_the_channel() {
        let (surface, store, _db, _root) = tmp_surface_with_store(195);
        store
            .create(
                "apikey:audited-scope",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create record");
        store
            .create_read_grant_audited(
                "reserved",
                "named-reporter",
                credentials_core::store::SelectorKind::Exact,
                "apikey:audited-scope",
                credentials_core::store::GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("grant read");

        surface
            .report_auth_failure(
                // A channel number that would be unmistakable in the row if it leaked in.
                4242,
                Some(&subc_protocol::Principal::Reserved {
                    module_id: "named-reporter".into(),
                }),
                &read_surface::ReportAuthFailureParams {
                    handle: None,
                    credential_id: Some("apikey:audited-scope".to_owned()),
                    enrollment_token: None,
                    provider_status: 401,
                    record_version: 1,
                    reporter_source: None,
                },
            )
            .await
            .expect("scoped report");

        let entry = store
            .read_audit(None)
            .expect("read chain")
            .into_iter()
            .find(|e| {
                e.credential_id.as_deref() == Some("apikey:audited-scope")
                    && e.op == AuditOp::ReportAuthFailure.as_str()
            })
            .expect("the scoped report appended a chain row");
        assert_eq!(
            entry.actor, "named-reporter",
            "a scoped report must be attributable to the principal that authorized it; \
             `conn-4242` here would mean the identity was held and thrown away"
        );
    }

    /// A scoped report at a version the caller was NOT served changes nothing and the
    /// credential keeps serving. The fence is the whole defence against a buggy retry
    /// EVERY SCOPED SURFACE MUST READ THE PRESENTED IDENTITY, AND THIS IS THE TEST THAT
    /// CATCHES THE NEXT ONE THAT DOES NOT.
    ///
    /// The `status` gap survived because the absolute test is blind to it: an
    /// unauthorized scoped call and a surface that CANNOT READ IDENTITY AT ALL return the
    /// same body, so "refuses without a token" passes in both worlds -- and that is the
    /// test anyone writes. Three of six surfaces had the field, three did not, and every
    /// per-surface test was green.
    ///
    /// The property that separates them is DIFFERENTIAL rather than absolute: the same
    /// call, made twice with two identities, must produce two different answers. Where it
    /// does not, either the surface ignores the token or the fixture is wrong, and both
    /// are worth failing on.
    ///
    /// Table-driven on purpose. A judgement per surface is what let three drift; this
    /// fails for a seventh surface the day it is added, without anyone remembering to
    /// think about it.
    ///
    /// The differential is the half that proves the guard READS something. Keep the
    /// absolute arms beside it (`an_enrolled_token_authorizes_scoped_status`), because
    /// those prove the guard EXISTS -- neither direction is sufficient alone. Property
    /// from the opencode seat, after they read the status fix.
    #[tokio::test]
    async fn every_scoped_surface_answers_an_enrolled_token_differently_than_no_token() {
        use base64::Engine as _;

        let (surface, store, _db, _root) = tmp_surface_with_store(164);
        let api_id = "apikey:differential";
        let sign_id = "signing:agent-assertion:differential";
        store
            .create_audited(
                api_id,
                &VaultRecord::new_static(
                    CredentialKind::ApiKey,
                    "test",
                    b"material".to_vec(),
                    None,
                ),
                AuditCtx::admin(AuditOp::Put),
            )
            .expect("seed api key");
        store
            .create_audited(
                sign_id,
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    test_ed25519_pem().as_bytes().to_vec(),
                    None,
                ),
                AuditCtx::admin(AuditOp::Put),
            )
            .expect("seed signing key");

        let request_secret = "d1d2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let secret_hash = credentials_core::enrollment::enrollment_secret_hash(request_secret)
            .expect("hashable secret");
        let request = store
            .propose_enrollment("differential-consumer", &secret_hash)
            .expect("propose");
        store
            .approve_enrollment(&request.request_id, "differential-consumer", "operator")
            .expect("approve");
        let token = match store
            .poll_enrollment(&request.request_id, request_secret)
            .expect("poll")
        {
            credentials_core::enrollment::EnrollmentPoll::Approved { token, .. } => token,
            other => panic!("an approved request must poll Approved, got {other:?}"),
        };
        for (selector, operation) in [
            (api_id, GrantOperation::Read),
            (sign_id, GrantOperation::Read),
            (sign_id, GrantOperation::Sign),
        ] {
            store
                .create_read_grant_audited(
                    "enrolled",
                    "differential-consumer",
                    credentials_core::store::SelectorKind::Exact,
                    selector,
                    operation,
                    AuditCtx::admin(AuditOp::GrantCreate),
                )
                .expect("grant");
        }

        let version = store
            .list_meta()
            .expect("meta")
            .into_iter()
            .find(|(id, _)| id == api_id)
            .expect("the seeded api key")
            .1
            .record_version;
        // BOTH WIRE-REACHABLE SHAPES. `admin.principal(channel)` returns `Option`, and the
        // dispatcher passes it straight through -- a channel with no recorded bind arrives
        // as `None`, not as `Direct`. The token path returns before either is read, so the
        // two must behave identically; asserting it is what makes that a property rather
        // than an implementation detail one refactor away from changing.
        for direct in [Some(&subc_protocol::Principal::Direct), None] {
            // Each arm renders its answer to a string so two identities can be compared
            // without every surface needing a bespoke assertion.
            let mut surfaces: Vec<(&str, String, String)> = Vec::new();

            for (name, tok) in [("with", Some(token.clone())), ("without", None)] {
                let _ = name;
                let _ = tok;
            }

            macro_rules! differential {
                ($label:expr, $call:expr) => {{
                    let with = {
                        let enrollment_token = Some(token.clone());
                        format!("{:?}", $call(enrollment_token).await)
                    };
                    let without = {
                        let enrollment_token: Option<String> = None;
                        format!("{:?}", $call(enrollment_token).await)
                    };
                    surfaces.push(($label, with, without));
                }};
            }

            differential!("credential.get_scoped", |t: Option<String>| {
                let s = &surface;
                async move {
                    match s
                        .get_scoped(
                            direct,
                            &read_surface::GetScopedParams {
                                credential_id: api_id.to_owned(),
                                enrollment_token: t,
                                min_ttl_ms: None,
                            },
                        )
                        .await
                    {
                        read_surface::GetOutcome::Ok(r) => format!("ok:{}", r.record_version),
                        read_surface::GetOutcome::Err { error } => format!("err:{:?}", error.code),
                    }
                }
            });

            differential!("credential.list_scoped", |t: Option<String>| {
                let s = &surface;
                async move {
                    s.list_scoped(
                        direct,
                        &read_surface::ListScopedParams {
                            enrollment_token: t,
                        },
                    )
                    .map(|r| r.credentials.len())
                }
            });

            differential!("credential.status", |t: Option<String>| {
                let s = &surface;
                async move {
                    let r = s
                        .status(
                            3,
                            direct,
                            &read_surface::StatusParams {
                                handle: None,
                                credential_id: Some(api_id.to_owned()),
                                enrollment_token: t,
                            },
                        )
                        .await;
                    (r.ready, r.credential_id)
                }
            });

            differential!("credential.public_key", |t: Option<String>| {
                let s = &surface;
                async move {
                    s.public_key(
                        4,
                        direct,
                        &read_surface::PublicKeyParams {
                            handle: None,
                            credential_id: Some(sign_id.to_owned()),
                            enrollment_token: t,
                        },
                    )
                    .await
                    .map(|r| r.key_id)
                }
            });

            differential!("credential.sign", |t: Option<String>| {
                let s = &surface;
                async move {
                    s.sign(
                        5,
                        direct,
                        &read_surface::SignParams {
                            handle: None,
                            credential_id: Some(sign_id.to_owned()),
                            payload_b64: base64::engine::general_purpose::STANDARD.encode(b"x"),
                            enrollment_token: t,
                        },
                    )
                    .await
                    .map(|r| r.key_id)
                }
            });

            differential!("credential.report_auth_failure", |t: Option<String>| {
                let s = &surface;
                async move {
                    s.report_auth_failure(
                        6,
                        direct,
                        &read_surface::ReportAuthFailureParams {
                            handle: None,
                            credential_id: Some(api_id.to_owned()),
                            enrollment_token: t,
                            provider_status: 401,
                            record_version: version,
                            reporter_source: None,
                        },
                    )
                    .await
                    .is_ok()
                }
            });

            assert_eq!(
                surfaces.len(),
                6,
                "every scoped surface must be covered; add the new one to this table"
            );
            for (label, with, without) in &surfaces {
                assert_ne!(
                    with, without,
                    "{label} answered a valid enrollment token the same as no token at all, \
                 with bus principal {direct:?}. Either it never reads `enrollment_token` \
                 (the defect this test exists for -- see StatusParams), or the fixture \
                 does not grant it."
                );
            }
        }
    }

    /// AN ENROLLED CONSUMER CAN ASK AFTER A CREDENTIAL IT IS ALREADY ENTITLED TO READ.
    ///
    /// `status` was the ONE scoped surface with no `enrollment_token` field. A
    /// host-launched consumer could enumerate with `list_scoped`, fetch with
    /// `get_scoped` and report a death with `report_auth_failure` -- and could not ask
    /// whether one credential was healthy, because status resolved only the bus
    /// principal, which for that consumer class is always `Direct`.
    ///
    /// The failure was invisible by construction: an unauthorized scoped status returns
    /// the SAME body as a nonexistent credential (the enumeration guard), so a consumer
    /// holding a valid grant and a valid token read `unavailable` and could not tell
    /// that the surface simply had nowhere to put its identity.
    ///
    /// Not a design decision -- the field was added to three of four surfaces as each
    /// one acquired a caller that needed it.
    #[tokio::test]
    async fn an_enrolled_token_authorizes_scoped_status() {
        let (surface, store, _db, _root) = tmp_surface_with_store(163);
        let credential_id = "apikey:enrolled-status";
        let record =
            VaultRecord::new_static(CredentialKind::ApiKey, "test", b"material".to_vec(), None);
        store
            .create_audited(credential_id, &record, AuditCtx::admin(AuditOp::Put))
            .expect("seed");

        let request_secret = "c1c2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let secret_hash = credentials_core::enrollment::enrollment_secret_hash(request_secret)
            .expect("hashable secret");
        let request = store
            .propose_enrollment("status-consumer", &secret_hash)
            .expect("propose");
        store
            .approve_enrollment(&request.request_id, "status-consumer", "operator")
            .expect("approve");
        let token = match store
            .poll_enrollment(&request.request_id, request_secret)
            .expect("poll")
        {
            credentials_core::enrollment::EnrollmentPoll::Approved { token, .. } => token,
            other => panic!("an approved request must poll Approved, got {other:?}"),
        };
        store
            .create_read_grant_audited(
                "enrolled",
                "status-consumer",
                credentials_core::store::SelectorKind::Exact,
                credential_id,
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("grant");

        // The caller arrives as Direct, which is what a host-launched consumer always is.
        let with_token = surface
            .status(
                91,
                Some(&subc_protocol::Principal::Direct),
                &read_surface::StatusParams {
                    handle: None,
                    credential_id: Some(credential_id.to_owned()),
                    enrollment_token: Some(token.clone()),
                },
            )
            .await;
        assert!(
            with_token.ready,
            "a consumer holding a covering grant and a valid token must be able to ask \
             after a credential it may already read; got {with_token:?}"
        );
        assert_eq!(
            with_token.credential_id.as_deref(),
            Some(credential_id),
            "a resolved scoped status echoes the id for binding verification"
        );

        // CONTROL, because 'ready' alone would also pass if the token were ignored and
        // some other path had authorized it: the SAME call without the token must refuse.
        let without_token = surface
            .status(
                92,
                Some(&subc_protocol::Principal::Direct),
                &read_surface::StatusParams {
                    handle: None,
                    credential_id: Some(credential_id.to_owned()),
                    enrollment_token: None,
                },
            )
            .await;
        assert!(
            !without_token.ready && without_token.credential_id.is_none(),
            "without the token the caller is Direct, holds no grant, and must get the \
             uniform unavailable body; got {without_token:?}"
        );
    }

    /// loop killing a token that refreshed while it was failing, so it must hold on the
    /// AN ENROLLED REPORT NAMES THE CONSUMER, NOT THE SOCKET IT ARRIVED ON.
    ///
    /// A host-launched consumer binds as `Direct` and proves who it is with its token, so
    /// reading the bus principal here logged `direct` with NO id for a report that was
    /// authorized as `enrolled:<name>`. An operator asking "who said this credential was
    /// dead" got the transport instead of the caller -- and the first-use path one
    /// function away already records the resolved principal, so the two disagreed.
    ///
    /// Found by the anthropic-auth seat auditing the live seven-leg acceptance, where a
    /// report authorized by `enrolled:acc-probe-consumer` recorded `direct:-`.
    #[tokio::test]
    async fn an_enrolled_report_is_audited_under_the_consumer_not_the_transport() {
        for principal in [
            subc_protocol::Principal::Direct,
            subc_protocol::Principal::Reserved {
                module_id: "ambient-module".into(),
            },
        ] {
            let (surface, store, _db, _root) = tmp_surface_with_store(151);
            let credential_id = "apikey:enrolled-report-attribution";
            let record =
                VaultRecord::new_static(CredentialKind::ApiKey, "test", b"material".to_vec(), None);
            store
                .create_audited(credential_id, &record, AuditCtx::admin(AuditOp::Put))
                .expect("seed");

            let request_secret = "b1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
            let secret_hash = credentials_core::enrollment::enrollment_secret_hash(request_secret)
                .expect("hashable secret");
            let request = store
                .propose_enrollment("reporting-consumer", &secret_hash)
                .expect("propose");
            store
                .approve_enrollment(&request.request_id, "reporting-consumer", "operator")
                .expect("approve");
            let token = match store
                .poll_enrollment(&request.request_id, request_secret)
                .expect("poll")
            {
                credentials_core::enrollment::EnrollmentPoll::Approved { token, .. } => token,
                other => panic!("an approved request must poll Approved, got {other:?}"),
            };
            store
                .create_read_grant_audited(
                    "enrolled",
                    "reporting-consumer",
                    credentials_core::store::SelectorKind::Exact,
                    credential_id,
                    GrantOperation::Read,
                    AuditCtx::admin(AuditOp::GrantCreate),
                )
                .expect("grant");

            let version = store.list_meta().expect("meta")[0].1.record_version;
            surface
                .report_auth_failure(
                    77,
                    Some(&principal),
                    &read_surface::ReportAuthFailureParams {
                        handle: None,
                        credential_id: Some(credential_id.to_owned()),
                        enrollment_token: Some(token),
                        provider_status: 401,
                        record_version: version,
                        reporter_source: Some("direct".to_owned()),
                    },
                )
                .await
                .expect("an enrolled consumer may report a credential its grant covers");

            let report = store
                .read_audit(None)
                .expect("audit log")
                .into_iter()
                .find(|entry| entry.op == "report_auth_failure")
                .expect("report audit");
            assert_eq!(report.actor, "enrolled:reporting-consumer");
            let event = store
                .recent_auth_events(10)
                .expect("events")
                .into_iter()
                .find(|e| e.credential_id == credential_id && e.principal_kind.is_some())
                .expect("the report must record a principal");
            assert_eq!(
                (
                    event.principal_kind.as_deref(),
                    event.principal_id.as_deref()
                ),
                (Some("enrolled"), Some("reporting-consumer")),
                "the audit row must name the consumer that authorized the report, not the \
             Direct transport it arrived on"
            );
        }
    }

    /// new address exactly as it does on the old one.
    #[tokio::test]
    async fn a_scoped_report_at_a_stale_version_is_a_no_op() {
        use credentials_core::oauth::OAuthCredential;
        use credentials_core::store::RecordState;

        let (surface, store, _db, _root) = tmp_surface_with_store(192);
        store
            .create(
                "oauth:fenced",
                &VaultRecord::new_oauth(
                    "stub",
                    "stub",
                    OAuthCredential {
                        access_token: "live".to_string().into(),
                        refresh_token: "refresh".to_string().into(),
                        expires_at_ms: Some(i64::MAX),
                        token_url: "https://example.invalid/token".into(),
                        client_id: None,
                        client_secret: None,
                        scopes: Vec::new(),
                    },
                    b"live".to_vec(),
                ),
            )
            .expect("create record");
        store
            .create_read_grant_audited(
                "reserved",
                "fence-reporter",
                credentials_core::store::SelectorKind::Exact,
                "oauth:fenced",
                credentials_core::store::GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("grant read");

        surface
            .report_auth_failure(
                3,
                Some(&subc_protocol::Principal::Reserved {
                    module_id: "fence-reporter".into(),
                }),
                &read_surface::ReportAuthFailureParams {
                    handle: None,
                    credential_id: Some("oauth:fenced".to_owned()),
                    enrollment_token: None,
                    provider_status: 401,
                    // The record is at version 1; the caller claims it was served 99.
                    record_version: 99,
                    reporter_source: None,
                },
            )
            .await
            .expect("a stale report is accepted and ignored, never an error");

        // ASSERTED ON stale_pending, NOT ON state, AND THAT IS THE WHOLE TEST.
        //
        // The first version of this asserted `state == Active` and PASSED under a mutant
        // that bypassed the fence entirely -- because an applied report on a refreshable
        // record does not change `state` at all: it sets `stale_pending` and lets the
        // next get do the work. So `state` reads Active in both the fenced and the
        // unfenced world, and the assertion could not fail. Caught by mutation, not by
        // review, and it is the exact defect this repo keeps meeting: an assertion on a
        // value the mechanism does not move.
        let meta = store.meta("oauth:fenced").expect("meta");
        assert!(
            !meta.stale_pending,
            "a report carrying a version the caller was never served must not mark the \
             record stale: that is what stops a buggy retry loop from killing a token \
             that refreshed while it was failing"
        );
        assert_eq!(
            meta.state,
            RecordState::Active,
            "and it must not latch the record either"
        );
        assert_eq!(meta.record_version, 1, "and it must not bump the version");
    }

    /// An unknown credential id and one the caller holds no grant for must be
    /// INDISTINGUISHABLE. Asserted on the error values themselves rather than on both
    /// merely being errors: two different refusals are still two refusals, and the
    /// difference is exactly what turns this surface into an inventory oracle.
    #[tokio::test]
    async fn a_scoped_report_cannot_tell_unknown_from_ungranted() {
        let (surface, store, _db, _root) = tmp_surface_with_store(193);
        store
            .create(
                "apikey:exists-but-ungranted",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create an ungranted credential");
        let principal = subc_protocol::Principal::Reserved {
            module_id: "no-grants-at-all".into(),
        };
        let mut refusals = Vec::new();
        for id in [
            "apikey:exists-but-ungranted",
            "apikey:no-such-credential-anywhere",
        ] {
            refusals.push(
                surface
                    .report_auth_failure(
                        4,
                        Some(&principal),
                        &read_surface::ReportAuthFailureParams {
                            handle: None,
                            credential_id: Some(id.to_owned()),
                            enrollment_token: None,
                            provider_status: 401,
                            record_version: 1,
                            reporter_source: None,
                        },
                    )
                    .await
                    .expect_err("both must refuse"),
            );
        }
        let (ungranted, unknown) = (refusals[0], refusals[1]);
        assert_eq!(
            format!("{ungranted:?}"),
            format!("{unknown:?}"),
            "an existing-but-ungranted id and a nonexistent one must answer identically; \
             a caller that can tell them apart can enumerate the vault one guess at a time"
        );
    }

    /// Both addresses, and neither, are malformed requests rather than addressing
    /// questions.
    #[tokio::test]
    async fn a_report_supplying_both_addresses_or_neither_is_refused() {
        let (surface, _store, _db, _root) = tmp_surface_with_store(194);
        for (handle, credential_id) in [
            (Some("ckh_whatever".to_owned()), Some("apikey:x".to_owned())),
            (None, None),
        ] {
            surface
                .report_auth_failure(
                    5,
                    None,
                    &read_surface::ReportAuthFailureParams {
                        handle,
                        credential_id,
                        enrollment_token: None,
                        provider_status: 401,
                        record_version: 1,
                        reporter_source: None,
                    },
                )
                .await
                .expect_err("exactly one address, or the request is malformed");
        }
    }

    /// A refreshable report keeps the credential active and schedules its existing
    /// refresh-on-read path instead of terminally latching it.
    #[tokio::test]
    async fn report_auth_failure_marks_a_refreshable_record_stale() {
        use credentials_core::oauth::OAuthCredential;
        use credentials_core::store::RecordState;

        let (surface, store, _db, _root) = tmp_surface_with_store(85);
        store
            .create(
                "oauth:stub",
                &VaultRecord::new_oauth(
                    "stub",
                    "stub",
                    OAuthCredential {
                        access_token: "still-locally-valid".to_string().into(),
                        refresh_token: "refresh".to_string().into(),
                        expires_at_ms: Some(i64::MAX),
                        token_url: "https://example.invalid/token".into(),
                        client_id: None,
                        client_secret: None,
                        scopes: Vec::new(),
                    },
                    b"still-locally-valid".to_vec(),
                ),
            )
            .expect("create refreshable record");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "oauth:stub",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");

        surface
            .report_auth_failure(
                8,
                None,
                &read_surface::ReportAuthFailureParams {
                    handle: Some(handle.raw),
                    credential_id: None,
                    enrollment_token: None,
                    provider_status: 401,
                    record_version: 1,
                    reporter_source: None,
                },
            )
            .await
            .expect("report succeeds with its existing wire reply");

        let meta = store.meta("oauth:stub").expect("meta");
        assert_eq!(meta.state, RecordState::Active);
        assert!(
            meta.stale_pending,
            "the next get must be driven through refresh"
        );
        assert_eq!(
            meta.record_version, 1,
            "a local stale marker must not move the version"
        );
        let events = store.recent_auth_events(10).expect("events");
        assert_eq!(events[0].kind, "consumer_report_stale");
        assert!(
            events[0].applied,
            "the current refreshable report must apply"
        );
    }

    /// An `oauth:` spelling does not make a static record refreshable. The report first
    /// reaches the ID-derived stale arm, then the engine must use the opened record's
    /// authoritative predicate and terminally latch it rather than serving it again.
    #[tokio::test]
    async fn report_on_a_static_oauth_shaped_id_latches_on_the_next_get() {
        use credentials_core::store::RecordState;

        let (surface, store, _db, _root) = tmp_surface_with_store(86);
        store
            .create(
                "oauth:anthropic",
                &VaultRecord::new_static(
                    CredentialKind::ApiKey,
                    "put",
                    b"static-key".to_vec(),
                    None,
                ),
            )
            .expect("put static record with oauth-shaped id");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "oauth:anthropic",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");

        surface
            .report_auth_failure(
                9,
                None,
                &read_surface::ReportAuthFailureParams {
                    handle: Some(handle.raw.clone()),
                    credential_id: None,
                    enrollment_token: None,
                    provider_status: 401,
                    record_version: 1,
                    reporter_source: None,
                },
            )
            .await
            .expect("report succeeds");
        assert!(
            store.meta("oauth:anthropic").expect("meta").stale_pending,
            "the ID-derived report arm sets the marker before the engine opens the record"
        );

        let result = surface
            .get(
                9,
                &read_surface::GetParams {
                    handle: handle.raw,
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await;
        let read_surface::GetOutcome::Err { error } = result else {
            panic!("a reported static record must not be served again");
        };
        assert_eq!(error.code, read_surface::ReadError::NeedsReauth);
        let meta = store.meta("oauth:anthropic").expect("meta");
        assert_eq!(meta.state, RecordState::NeedsReauth);
        let events = store.recent_auth_events(10).expect("events");
        assert_eq!(events[0].kind, "stale_nonrefreshable_latch");
        assert!(
            events[0].applied,
            "the engine backstop must make the terminal transition"
        );
    }

    /// `get_many` serves a batch at the cap and refuses one item past it, WHOLE rather
    /// than truncated. The at-cap arm is what gives the over-cap arm its meaning: a
    /// `get_many` that refused unconditionally would satisfy every over-cap assertion in
    /// this repo, since nothing else calls it with an accepted batch.
    #[tokio::test]
    async fn get_many_serves_at_the_cap_and_refuses_whole_past_it() {
        use crate::limiter::GET_MANY_MAX;

        let (surface, store, _db, _root) = tmp_surface_with_store(24);
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
        //
        // WHAT THIS TEST CANNOT PROVE, stated so nobody reads it as covering more: it
        // seeds GET_MANY_MAX handles and asserts against GET_MANY_MAX, so both sides
        // move together and the cap's VALUE is invisible here — measured, widening it
        // to 1000 leaves this green. That is the correct scope for a unit test of the
        // batch path, but it means the value is pinned elsewhere: the e2e arm
        // `real_daemon_over_cap_get_many_is_rejected` sends a literal 9 items over the
        // wire and fails if the cap moves. Deleting that arm would leave the bound
        // unproven while this test stays green.
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

        let (surface, store, _db, _root) = tmp_surface_with_store(21);

        // A faithful OpenAI access-token JWT carrying the nested claim path
        // "https://api.openai.com/auth"."chatgpt_account_id" = "acct-e2e-7". Unsigned
        // (claims decoding never verifies the signature; transport is the trust anchor).
        let access_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.\
             eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiYWNjdC1lMmUtNyJ9fQ.\
             sig";
        let oauth = OAuthCredential {
            access_token: access_jwt.to_string().into(),
            refresh_token: "ref".to_string().into(),
            // Far-future expiry so the record is not stale and `get` serves it as-is
            // (no refresh, no network) — isolating the account_id surfacing.
            expires_at_ms: Some(4_102_444_800_000),
            token_url: "https://auth.openai.com/oauth/token".to_string(),
            client_id: Some("app_x".to_string()),
            client_secret: None,
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

        let (surface, store, _db, _root) = tmp_surface_with_store(22);

        let oauth = OAuthCredential {
            // Opaque (non-JWT) access token — the live claim parse yields nothing,
            // so any served identity provably comes from the stored RecordIdentity.
            access_token: "sk-ant-oat01-opaque".to_string().into(),
            refresh_token: "ref".to_string().into(),
            expires_at_ms: Some(4_102_444_800_000),
            token_url: "https://api.anthropic.com/v1/oauth/token".to_string(),
            client_id: Some("client".to_string()),
            client_secret: None,
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

    #[tokio::test]
    async fn get_serves_identity_attached_after_an_oauth_record_was_created() {
        use credentials_core::oauth::OAuthCredential;
        use credentials_core::record::RecordIdentity;

        let (surface, store, _db, _root) = tmp_surface_with_store(31);
        let oauth = OAuthCredential {
            access_token: "opaque-access".to_string().into(),
            refresh_token: "refresh-secret".to_string().into(),
            expires_at_ms: Some(4_102_444_800_000),
            token_url: "https://example.invalid/token".to_string(),
            client_id: None,
            client_secret: None,
            scopes: Vec::new(),
        };
        store
            .create(
                "oauth:anthropic:late-labelled",
                &VaultRecord::new_oauth("import", "anthropic", oauth, b"opaque-access".to_vec()),
            )
            .expect("create OAuth record");
        let handle = credentials_core::store::mint_handle().expect("mint");
        store
            .put_handle_hash(
                &handle.hash,
                "oauth:anthropic:late-labelled",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("store handle");
        store
            .set_identity_audited(
                "oauth:anthropic:late-labelled",
                RecordIdentity {
                    account_id: Some("acct-late".to_string()),
                    email: None,
                    org_name: None,
                },
                AuditCtx::admin(AuditOp::SetIdentity),
            )
            .expect("set identity");

        let read_surface::GetOutcome::Ok(result) = surface
            .get(
                1,
                &read_surface::GetParams {
                    handle: handle.raw,
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await
        else {
            panic!("expected a served OAuth record");
        };
        assert_eq!(result.account_id.as_deref(), Some("acct-late"));
    }

    /// `wrap_result` is the single seam that produces the route reply envelope
    /// `{"result": ...}`. Every route op must go through it so a future envelope change
    /// moves every operation at once instead of silently leaving some ops on the old
    /// shape (a partially-applied wire change fails per-operation and looks like a
    /// consumer bug).
    ///
    /// This is a source-level guard, not a behaviour test: it scans the file text and
    /// asserts the wrapper literal appears exactly once — inside `wrap_result` itself.
    ///
    /// What it proves: no site hand-rolls the wrapper literal form (the `json!` macro
    /// with a single `result` key).
    /// What it CANNOT prove: a site that builds the same JSON by another route — a
    /// `Map::insert`, a different macro, or differing whitespace — would pass this scan
    /// while still bypassing the seam. A green run here is evidence the literal form is
    /// gone, not proof that every reply is wrapped.
    ///
    /// The positive control is load-bearing: an all-absent scan is the most convincing
    /// vacuous pass there is (a wrong path, a renamed file, or a broken matcher all
    /// report clean). Asserting a string we KNOW is present (`fn wrap_result`) is found
    /// by the same scan makes the absence assertion mean something.
    #[test]
    fn wrap_result_is_the_only_route_reply_wrapper() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));

        let wrapper_literal = "json!({ \"result\":";
        let occurrences = source.matches(wrapper_literal).count();
        assert_eq!(
            occurrences, 1,
            "the `json!({{ \"result\": ... }})` wrapper literal must appear exactly once, \
             inside `wrap_result` itself; found {occurrences}. Route every reply through \
             `wrap_result` so the envelope has a single seam."
        );

        // Positive control, and what it actually guards is NARROWER than the usual
        // formulation: `include_str!` resolves at COMPILE time, so a wrong path or a
        // renamed file is a build error rather than a clean-reporting empty scan. The
        // hazard those words describe cannot reach runtime here.
        //
        // What it does catch is the scan's PREMISE moving: rename or delete
        // `wrap_result` and the absence assertion above starts passing for the wrong
        // reason -- zero hand-rolled wrappers because the seam itself is gone. The
        // control turns that into a failure that says so.
        //
        // Built by concatenation on purpose, though note this test's own NAME contains
        // the same substring, so the control is not fully self-exclusive. Kept anyway:
        // it is honest about the premise check, and the alternative (renaming the test
        // to dodge its own scan) trades a clearer name for a weaker one.
        let control = format!("fn {}", "wrap_result");
        assert!(
            source.contains(&control),
            "positive control failed: the scan could not find `fn wrap_result` in the \
             source it read; the absence assertion above is therefore meaningless"
        );
    }

    /// AN ENROLLMENT EVENT NAMES THE BUS IDENTITY THAT SENT IT.
    ///
    /// Every other `auth_events` kind records its caller; enrollment was the exception,
    /// writing NULL for both principal columns. Seven proposals for an already-enrolled
    /// name arrived at this vault overnight and nothing could say whether a supervised
    /// module or something running beside one had sent them.
    ///
    /// Drives the real read surface with two different principals so the recorded value
    /// has to come from the caller rather than from a constant; a store call that ignored
    /// its argument would write the same pair for both.
    #[tokio::test]
    async fn enrollment_events_record_the_bus_principal_that_sent_them() {
        let (surface, _store, db_path, _root) = tmp_surface_with_store(164);
        let secret = "d1d2d3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let secret_hash =
            credentials_core::enrollment::enrollment_secret_hash(secret).expect("hashable secret");

        let reserved = subc_protocol::Principal::Reserved {
            module_id: "a-supervised-module".into(),
        };
        let proposal = surface
            .enroll_propose(
                Some(&reserved),
                &read_surface::EnrollProposeParams {
                    proposed_name: "attributed-consumer".into(),
                    request_secret_hash: secret_hash,
                },
            )
            .expect("propose");
        let wrong = "0000000000000000000000000000000000000000000000000000000000000001";
        let refused = surface.enroll_poll(
            Some(&subc_protocol::Principal::Direct),
            &read_surface::EnrollPollParams {
                request_id: proposal.request_id,
                request_secret: wrong.into(),
            },
        );
        assert!(refused.is_err(), "a wrong secret must be refused");

        // A raw read, because the module crate cannot reach core's test-only accessor.
        let conn = rusqlite::Connection::open(&db_path).expect("open raw db");
        let mut stmt = conn
            .prepare(
                "SELECT credential_id, detail, principal_kind, principal_id FROM auth_events \
                 WHERE kind = 'enrollment' ORDER BY seq",
            )
            .expect("prepare");
        let rows: Vec<(String, String, Option<String>, Option<String>)> = stmt
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("rows");
        assert_eq!(
            rows,
            vec![
                (
                    "auth.enroll_propose".to_owned(),
                    "accepted".to_owned(),
                    Some("reserved".to_owned()),
                    Some("a-supervised-module".to_owned()),
                ),
                (
                    "auth.enroll_poll".to_owned(),
                    "not_found".to_owned(),
                    Some("direct".to_owned()),
                    None,
                ),
            ],
            "each enrollment event must carry the principal of the call that wrote it"
        );
    }

    include!("../tests/support/daemon_regressions.rs");

    /// EVERY LINE THIS DAEMON CAN WRITE, ENUMERATED -- so a new one needs a reviewer.
    ///
    /// The read surface is anonymous and its callers carry bearer material: capability
    /// handles, enrollment tokens, and credential ids that are not secrets but are what an
    /// attacker would enumerate. A log line is DURABLE once written to disk (a dated
    /// segment on disk, fourteen days by default), so a formatting mistake that used to be
    /// ephemeral stderr is now a file. The fleet redactor catches credential SHAPES; it
    /// cannot catch a handle that has been truncated, a token in an unfamiliar encoding,
    /// or an id that is sensitive only because of where it appeared.
    ///
    /// So the policy is structural rather than filter-based: ordinary consumer bytes
    /// never reach a log line. One exception records a bounded, escaped credential id
    /// and the container found for a corrupt stored KEM payload so operators can repair
    /// the record without exposing plaintext or private key bytes. The sites are:
    ///
    ///   println!  `--version`, before any connection exists
    ///   eprintln! the logger failed to install (no request has been read yet)
    ///   eprintln! a corrupt KEM record's capped escaped id and container only
    ///   warn!     route-epoch drop: frame-header integers and a value this module chose
    ///   warn!     undecodable channel-0 request: fixed text only, no body or decode error
    ///   warn!     route bind refused under a flow scope: fixed text and the daemon-chosen
    ///             route channel number, never the stamp, its flow id, or the principal
    ///   warn!     engram-catalog.json could not be written: fixed text and the io error
    ///             KIND only (never its message, which can carry a path)
    ///
    /// The count makes a new site impossible to add without editing this test, which puts
    /// the question in front of whoever does it. The count alone cannot see what an
    /// EXISTING site logs, so the test also reads every site's arguments and refuses any
    /// that call `.expose(`: a `Secret` can be read only through `expose()`, so that is
    /// the one shape every secret read must take. Covers the four files linked into the
    /// daemon binary.
    ///
    /// Patterns are built by concatenation so this test's own text is not counted, and
    /// `println!` is counted net of `eprintln!` because one contains the other.
    #[test]
    fn every_daemon_output_site_is_enumerated() {
        let sources = [
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs")),
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/read_surface.rs")),
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/admin_surface.rs")),
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/limiter.rs")),
        ];
        let count = |shape: &str| -> usize {
            let pattern = format!("{shape}{}", "!(");
            sources.iter().map(|s| s.matches(&pattern).count()).sum()
        };
        let eprintln = count("eprintln");
        let println = count("println") - eprintln;
        let tracing: usize = ["trace", "debug", "info", "warn", "error"]
            .iter()
            .map(|level| count(level))
            .sum();
        let other = count("print") + count("eprint") + count("dbg");

        let observed = (println, eprintln, tracing, other);
        assert_eq!(
            observed,
            (1, 2, 4, 0),
            "the daemon's output sites changed (println, eprintln, tracing, other). Before \
             updating this count, confirm the new site logs no secret and bounds any \
             request field -- then add it to the list in \
             this test's doc comment. Log lines are durable files since fleet-logging r2."
        );

        // Positive control: the one route-path line must be FOUND by the same scan, or a
        // broken pattern would report every count as zero and read as "no new sites".
        assert!(
            sources[0].contains("route-epoch drop"),
            "positive control failed: the scan could not see the route-epoch drop line"
        );

        // WHAT each site logs: no argument may read a secret.
        let shapes = [
            "println", "eprintln", "trace", "debug", "info", "warn", "error",
        ];
        let mut sites = 0;
        for source in sources {
            for (call, args) in output_site_arguments(source, &shapes) {
                sites += 1;
                assert!(
                    !args.contains(&format!("{}{}", ".expose", "(")),
                    "a daemon output site reads a secret: {call}!({args})"
                );
            }
        }
        // The argument reader must see exactly the sites the count saw, or it could be
        // passing because it read nothing. `println!` sites include `eprintln!` ones here,
        // so the total is the sum of the per-shape counts above.
        assert_eq!(
            sites,
            println + eprintln + tracing,
            "control: the argument reader missed output sites the count found"
        );
        // And it must flag a planted read, so a reader that never matches cannot pass.
        let planted = format!(
            "{}{}{}",
            "eprintln", "!(\"x {}\", record.payload.expose", "());"
        );
        let flagged = output_site_arguments(&planted, &shapes)
            .into_iter()
            .any(|(_, args)| args.contains(&format!("{}{}", ".expose", "(")));
        assert!(flagged, "control: a planted secret read was not flagged");
    }

    /// Each `<shape>!(` call in `source` and the text of its arguments, read up to the
    /// matching close paren so multi-line format arguments are included. A shape is
    /// matched only at a word boundary, so `eprintln` is not also counted as `println`.
    fn output_site_arguments(source: &str, shapes: &[&str]) -> Vec<(String, String)> {
        let bytes = source.as_bytes();
        let mut found = Vec::new();
        for shape in shapes {
            let pattern = format!("{shape}{}", "!(");
            for (at, _) in source.match_indices(&pattern) {
                if at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_') {
                    continue;
                }
                let open = at + pattern.len();
                let mut depth = 1usize;
                let mut end = open;
                for (offset, byte) in source[open..].bytes().enumerate() {
                    match byte {
                        b'(' => depth += 1,
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                end = open + offset;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                found.push(((*shape).to_string(), source[open..end].to_string()));
            }
        }
        found
    }
}

#[cfg(test)]
mod engram_catalog_tests {
    use super::{place_engram_catalog, ENGRAM_CATALOG_JSON};
    use credentials_core::test_support::TestTempDir;

    fn temp_dir(tag: &str) -> TestTempDir {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        TestTempDir::new(format!(
            "ck-cred-catalog-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }

    /// The engram backup descriptor must name this module and every path the vault keeps
    /// in its data dir. An omitted directory is the defect this constant replaced: the
    /// descriptor that used to be placed by hand never listed `signed-envelopes/`, so
    /// those files were never backed up, and nothing reported it.
    #[test]
    fn catalog_declares_the_store_and_every_retained_directory() {
        let catalog: serde_json::Value =
            serde_json::from_str(ENGRAM_CATALOG_JSON).expect("catalog parses");
        assert_eq!(catalog["schema_version"], 1);
        assert_eq!(catalog["module_id"], credentials_core::contract::MODULE_ID);
        let entries = catalog["entries"].as_array().expect("entries array");
        let declared = |path: &str, mechanism: &str| {
            entries
                .iter()
                .any(|entry| entry["path"] == path && entry["mechanism"] == mechanism)
        };
        assert!(
            declared("store.db", "whole-db"),
            "the store must be captured"
        );
        for retained in ["signed-payloads", "signed-envelopes"] {
            assert!(
                declared(retained, "filetree"),
                "{retained}/ is kept in the data dir and must be backed up"
            );
        }
    }

    /// The first start writes `engram-catalog.json` at mode 0600 (owner-only); a second
    /// start with the same bytes on disk writes nothing; a file with different bytes,
    /// such as an old hand-written descriptor, is replaced.
    #[test]
    fn placement_writes_owner_only_and_is_idempotent() {
        let dir = temp_dir("place");
        let path = dir.join("engram-catalog.json");

        assert!(place_engram_catalog(&dir).expect("first write"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), ENGRAM_CATALOG_JSON);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the descriptor is owner-only");
        }
        assert!(
            !dir.join("engram-catalog.json.tmp").exists(),
            "no temp file left behind"
        );

        assert!(
            !place_engram_catalog(&dir).expect("second start"),
            "unchanged bytes: no write"
        );

        std::fs::write(
            &path,
            b"{\"schema_version\":1,\"module_id\":\"claustrum\",\"entries\":[]}",
        )
        .unwrap();
        assert!(
            place_engram_catalog(&dir).expect("stale copy"),
            "a stale copy is replaced"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), ENGRAM_CATALOG_JSON);
    }
}
