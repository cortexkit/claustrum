//! The remote read: how this vault serves its own consumers a rotating login whose
//! home is another member's vault.
//!
//! A remote record (`remote_records`) holds no token and no refresh token. When a
//! consumer reads one, this vault asks the home for a short-lived access token over
//! `federation.remote_token`, opens the sealed reply with its own transfer key, checks
//! it, and serves it. The token lives only in memory, in a small cache whose every
//! decision runs on this machine's monotonic clock: two machines' wall clocks are
//! never compared.
//!
//! What is here, in the order a read meets it:
//!
//! - **Cache residence and token lifetime.** A cached token is reused only while
//!   monotonic time is before `t0 + min(300 s, recheck_in_ms)`, where `t0` is when the
//!   fetch was sent, and only while its conservative remaining life
//!   (`expires_in_ms − 60 s − (now − t0)`) is positive and covers the caller's
//!   `min_ttl_ms`. Measuring from the send time errs early, never late.
//! - **Home demand.** The home is asked for the caller's `min_ttl_ms` plus 62.5 s (the
//!   60 s skew and this vault's 2.5 s budget), saturating rather than wrapping, so a
//!   reply the home considers fresh also passes the lifetime test here.
//! - **Single-flight.** Concurrent reads of one id share one fetch when their demand is
//!   no larger than the fetch's, keyed on (id, incarnation, cache generation). The
//!   generation moves on every failure report and every applied verdict that is not
//!   `active`, so no read joins a fetch started before either.
//! - **Result ordering.** Each fetch takes a sequence number when it is sent. The last
//!   fetch outcome moves only forward in sequence; the authoritative fields (the
//!   home's description, the state, the unresolved report and the cache) move only for
//!   a result with an authoritative effect whose sequence is above the last such one
//!   applied. A later transport failure therefore cannot hide an earlier verdict.
//! - **Reply validation.** A reply that fails validation changes nothing but the last
//!   fetch outcome and one diagnostic row: a cached token is still served until its
//!   normal expiry, and the record's state and description stay as they were.
//!
//! The consumer-facing answers and their stored effects follow the federation spec's
//! table, one [`Failure`] constructor per row. Every forwarded call finishes inside
//! [`CONSUMER_FACING_DEADLINE`], because the Rust consumer client waits 3 s for the
//! reply.
//!
//! The other surfaces on a remote id (`list_scoped`, `watch_scoped`, `status`) read only
//! this vault's own storage and never call the home.
//!
//! This file is compiled into the daemon and into the test-only library, so it depends
//! on nothing in the daemon outside `federation`.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use base64::Engine as _;
use credentials_core::audit::{AuthEventKind, ReporterSource};
use credentials_core::federation::{
    valid_member_id, NewRemoteRecord, RemoteHomeState, RemoteHomeSuccess, RemoteRecord,
    RemoteRecordWrite, MEMBER_ID_PREFIX, VAULT_TRANSFER_ID,
};
use credentials_core::plan_detection::DetectedPlan;
use credentials_core::record::{CredentialKind, RecordIdentity, RecordState};
use credentials_core::store::{
    AuthEventPrincipal, AuthObservation, EncryptedStore, GrantOperation, ReadGrant, ScopedListRow,
    SelectorKind, StoreOpError,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::watch;

use super::ingress::{
    decode_peer_transfer_key, Lookup, CALLOSUM_MODULE_ID, OP_REMOTE_TOKEN, OP_REPORT_AUTH_FAILURE,
    REMOTE_TOKEN_INFO,
};
use super::outbound::{
    is_permanent_callosum_class, management_surface, OutboundClient, OutboundError, RouteCall,
    CONSUMER_FACING_DEADLINE,
};

/// The skew allowance: a token is treated as expired this long before the home said.
pub const EXPIRY_SKEW_MS: i64 = 60_000;

/// What the home is asked for on top of the caller's own `min_ttl_ms`: the skew plus
/// this vault's end-to-end budget, so a token the home considers fresh enough also
/// passes this vault's lifetime test when it arrives.
pub const HOME_DEMAND_MARGIN_MS: i64 = EXPIRY_SKEW_MS + 2_500;

/// The longest a cached token is reused, on this vault's monotonic clock. It bounds a
/// token with no expiry, and it bounds how long a revoked grant on the home can still
/// be served from here.
pub const CACHE_RESIDENCE_CAP_MS: u64 = 300_000;

/// How much earlier than its leader's deadline a fetch gives up. The fetch then
/// records its own outcome and publishes it before any waiter's deadline fires, so a
/// call that runs out of time still leaves `last_fetch_outcome` saying why, and a read
/// arriving right after never joins a fetch that is about to fail.
const FLIGHT_PUBLISH_MARGIN: Duration = Duration::from_millis(50);

/// The outbound client's binding-cache key for callosum. The same key the home side
/// uses, so both reuse one route to callosum.
const CALLOSUM_ROUTE_KEY: &str = "callosum";

/// The longest home `Error` frame code copied into a diagnostic row. A longer or
/// stranger code is recorded as `unrecognised`, so a peer cannot write text here.
const MAX_DIAGNOSTIC_CODE_LEN: usize = 48;

/// The demand this vault forwards to the home for a caller's `min_ttl_ms`: zero for an
/// absent or negative value, plus [`HOME_DEMAND_MARGIN_MS`], saturating at `i64::MAX`
/// so no wrapped (negative) demand can reach the home.
pub fn home_demand(min_ttl_ms: Option<i64>) -> i64 {
    min_ttl_ms
        .unwrap_or(0)
        .max(0)
        .saturating_add(HOME_DEMAND_MARGIN_MS)
}

/// The management-surface module a member's vault is reached at through callosum:
/// `fed:<fp>:claustrum`, with the fingerprint from the member id.
pub fn fed_provider_module(member_id: &str) -> String {
    let fingerprint = member_id
        .strip_prefix(MEMBER_ID_PREFIX)
        .unwrap_or(member_id);
    format!("fed:{fingerprint}:claustrum")
}

// ---------------------------------------------------------------------------------
// Answers
// ---------------------------------------------------------------------------------

/// A refusal this vault answers its consumer with: the `{code, class}` every read
/// refusal carries, plus `remedy_member` when a setup fault names the member whose
/// operator must fix it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRefusal {
    pub code: &'static str,
    pub class: &'static str,
    pub remedy_member: Option<String>,
}

#[derive(Serialize)]
struct RefusalBody<'a> {
    code: &'a str,
    class: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    remedy_member: Option<&'a str>,
}

impl RemoteRefusal {
    fn new(code: &'static str, class: &'static str) -> Self {
        Self {
            code,
            class,
            remedy_member: None,
        }
    }

    fn remedy(mut self, member: Option<String>) -> Self {
        self.remedy_member = member;
        self
    }

    /// The `error` member of a refusal reply. Built from a struct in the field order
    /// the local read surface uses, so a `not_found` here is the same bytes as a local
    /// one.
    pub fn body(&self) -> Value {
        serde_json::to_value(RefusalBody {
            code: self.code,
            class: self.class,
            remedy_member: self.remedy_member.as_deref(),
        })
        .unwrap_or_else(|_| json!({ "code": self.code, "class": self.class }))
    }
}

/// A token this vault serves its consumer, in the local `get_scoped` shape.
#[derive(Clone, PartialEq, Eq)]
pub struct RemoteGet {
    pub payload: Vec<u8>,
    /// This vault's wall clock when the fetch was sent, plus the home's
    /// `expires_in_ms`; absent for a token with no expiry.
    pub expires_at_ms: Option<i64>,
    /// The home's `record_version`.
    pub record_version: u64,
    pub project_id: Option<String>,
    pub account_id: Option<String>,
    pub email: Option<String>,
    pub org_name: Option<String>,
}

impl std::fmt::Debug for RemoteGet {
    // The payload is the access token; it never belongs in a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteGet")
            .field("payload", &"<redacted>")
            .field("expires_at_ms", &self.expires_at_ms)
            .field("record_version", &self.record_version)
            .field("project_id", &self.project_id)
            .field("account_id", &self.account_id)
            .finish_non_exhaustive()
    }
}

/// What a remote read answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteAnswer {
    Served(RemoteGet),
    Refused(RemoteRefusal),
}

// ---------------------------------------------------------------------------------
// The consumer table
// ---------------------------------------------------------------------------------

/// What a fetch outcome does to the stored record besides `last_fetch_outcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    /// Changes nothing but `last_fetch_outcome`.
    OutcomeOnly,
    /// Sets `last_home_state` to this state and `last_home_error` to the code, drops
    /// the cache and moves the generation.
    State(RemoteHomeState),
}

/// A failed fetch: the consumer's answer, its stored effect, and the diagnostic row it
/// writes on this vault, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Failure {
    refusal: RemoteRefusal,
    effect: Effect,
    diagnostic: Option<String>,
    /// A control refusal keeps its wire code in status without exposing it to consumers.
    wire_outcome: Option<String>,
}

impl Failure {
    fn outcome_only(refusal: RemoteRefusal) -> Self {
        Self {
            refusal,
            effect: Effect::OutcomeOnly,
            diagnostic: None,
            wire_outcome: None,
        }
    }

    fn state(refusal: RemoteRefusal, state: RemoteHomeState) -> Self {
        Self {
            refusal,
            effect: Effect::State(state),
            diagnostic: None,
            wire_outcome: None,
        }
    }

    fn noting(mut self, diagnostic: impl Into<String>) -> Self {
        self.diagnostic = Some(diagnostic.into());
        self
    }

    /// Unreachable, partition, deadline, the end-to-end budget spent, or a retry-safe
    /// or outcome-unknown callosum class.
    fn home_unreachable() -> Self {
        Self::outcome_only(RemoteRefusal::new("home_unreachable", "transient"))
    }

    /// The home could not finish (its pairing lookup failed, or its refresh is still
    /// running past its budget), or answered with an `Error` frame.
    fn home_unavailable() -> Self {
        Self::outcome_only(RemoteRefusal::new("home_unavailable", "transient"))
    }

    /// A permanent callosum class: the route itself is misconfigured.
    fn federation_setup_invalid() -> Self {
        Self::outcome_only(RemoteRefusal::new("federation_setup_invalid", "permanent"))
    }

    /// This vault's own transfer key or self id is absent.
    fn transfer_key_missing(self_id: Option<String>) -> Self {
        Self::outcome_only(RemoteRefusal::new("transfer_key_missing", "permanent").remedy(self_id))
    }

    /// This vault has no announced key for the home.
    fn home_key_missing(home: &str) -> Self {
        Self::outcome_only(
            RemoteRefusal::new("remote_setup_incomplete", "permanent").remedy(Some(home.into())),
        )
    }

    /// The sealed reply would not open: aad, key or info mismatch.
    fn seal_invalid() -> Self {
        Self::state(
            RemoteRefusal::new("remote_seal_invalid", "permanent"),
            RemoteHomeState::NeedsReauth,
        )
        .noting("remote_seal_invalid")
    }

    /// The opened reply failed validation. Outcome only, by design: one bad reply must
    /// not change the record's state, its description or the cache.
    fn reply_invalid(why: &str) -> Self {
        Self::outcome_only(RemoteRefusal::new("remote_reply_invalid", "permanent"))
            .noting(format!("remote_reply_invalid:{why}"))
    }

    fn store_error() -> Self {
        Self::outcome_only(RemoteRefusal::new("store_error", "transient"))
    }
}

/// The code a fetch outcome is stored under in `last_fetch_outcome`.
fn outcome_code(fetched: &Fetched) -> &str {
    match fetched {
        Fetched::Token(_) => "ok",
        Fetched::Failed(failure) => failure
            .wire_outcome
            .as_deref()
            .unwrap_or(failure.refusal.code),
    }
}

/// A peer-chosen code, reduced to something safe to store: lowercase ASCII, digits and
/// `_` only, bounded, else `unrecognised`.
fn diagnostic_code(code: &str) -> &str {
    let safe = !code.is_empty()
        && code.len() <= MAX_DIAGNOSTIC_CODE_LEN
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    if safe {
        code
    } else {
        "unrecognised"
    }
}

fn map_outbound_error(error: OutboundError) -> Failure {
    match error {
        OutboundError::Refused { code, .. } => {
            let mut failure = map_frame_code(&code);
            failure.wire_outcome = Some(diagnostic_code(&code).to_string());
            failure
        }
        OutboundError::Unavailable(_) => Failure::home_unreachable(),
    }
}

/// Map the home's `{code, class, remedy_member?}` refusal of a token fetch to this
/// vault's answer and stored effect.
fn map_home_refusal(error: &Value, home: &str, self_id: &str) -> Failure {
    let code = error.get("code").and_then(Value::as_str).unwrap_or("");
    match code {
        // Unknown id, no current-pairing grant, ineligible, projection refused, a home
        // id that is not the home's, or a refused harness on a gate-off home.
        "not_found" => Failure::state(
            RemoteRefusal::new("not_found", "permanent"),
            RemoteHomeState::NeedsReauth,
        ),
        // Every read while the home record stays `needs_reauth`.
        "needs_reauth" => Failure::state(
            RemoteRefusal::new("needs_reauth", "auth_required").remedy(Some(home.into())),
            RemoteHomeState::NeedsReauth,
        ),
        "corrupt" => Failure::state(
            RemoteRefusal::new("corrupt", "permanent"),
            RemoteHomeState::Corrupt,
        ),
        // The same code and class a local read answers; nothing authoritative.
        "refresh_failed" => {
            Failure::outcome_only(RemoteRefusal::new("refresh_failed", "transient"))
        }
        "refresh_unsupported" => {
            Failure::outcome_only(RemoteRefusal::new("refresh_unsupported", "permanent"))
        }
        "vault_locked" => Failure::outcome_only(RemoteRefusal::new("vault_locked", "transient")),
        "store_error" => Failure::outcome_only(RemoteRefusal::new("store_error", "transient")),
        "ttl_unsatisfiable" => {
            Failure::outcome_only(RemoteRefusal::new("ttl_unsatisfiable", "context_overflow"))
        }
        "home_unavailable" => Failure::home_unavailable(),
        // A setup fault names who must fix it. The home names itself (no transfer key
        // or self id) or names the requester as it attested it, which is this vault's
        // real member id even when this vault's own self id is wrong, so anything
        // other than the home is this vault's to fix.
        "remote_setup_incomplete" => {
            let named = error
                .get("remedy_member")
                .and_then(Value::as_str)
                .filter(|member| valid_member_id(member));
            let remedy = match named {
                Some(member) if member == home => home.to_string(),
                Some(member) => member.to_string(),
                None => self_id.to_string(),
            };
            Failure::state(
                RemoteRefusal::new("remote_setup_incomplete", "permanent").remedy(Some(remedy)),
                RemoteHomeState::NeedsReauth,
            )
        }
        // A code this vault does not know is never a credential verdict.
        other => {
            Failure::home_unavailable().noting(format!("home_refusal:{}", diagnostic_code(other)))
        }
    }
}

/// Classify a frame-level answer that is not the home's own reply: a callosum refusal
/// (`fed_*`) or an `Error` frame from the home (for example `unknown_method` from a
/// home that predates federation).
fn map_frame_code(code: &str) -> Failure {
    if code.starts_with("fed_") {
        if is_permanent_callosum_class(code) {
            Failure::federation_setup_invalid()
        } else {
            Failure::home_unreachable()
        }
    } else {
        Failure::home_unavailable().noting(format!("home_error_frame:{}", diagnostic_code(code)))
    }
}

// ---------------------------------------------------------------------------------
// Wire bodies
// ---------------------------------------------------------------------------------

/// The token `aad`, serialized once by this vault, fields in this order. The exact
/// bytes travel with the request and the reply is opened over the same bytes.
#[derive(Serialize)]
struct TokenAad<'a> {
    credential_id: &'a str,
    requester: &'a str,
    home: &'a str,
    nonce: &'a str,
    recipient_key_id: &'a str,
}

/// The sealed plaintext of a home reply. Unknown fields are refused: a field this
/// vault does not expect (a refresh token, an `oauth` struct) is a reply it must not
/// trust, whatever else it carries.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTokenReply {
    payload: String,
    #[serde(default)]
    expires_in_ms: Option<i64>,
    #[serde(default)]
    recheck_in_ms: Option<i64>,
    record_version: u64,
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    identity: RecordIdentity,
    // Seeds this vault's own category set for the id once, at `remote add`; a read
    // ignores it.
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    refresh_adapter: Option<String>,
    #[serde(default)]
    detected_plan: Option<DetectedPlan>,
}

/// A validated home reply, held in memory only.
#[derive(Clone, PartialEq, Eq)]
struct TokenReply {
    payload: String,
    expires_in_ms: Option<i64>,
    recheck_in_ms: Option<i64>,
    record_version: u64,
    project_id: Option<String>,
    account_id: Option<String>,
    identity: RecordIdentity,
    /// The home's categories, kept only to seed `remote add`.
    categories: Vec<String>,
    refresh_adapter: Option<String>,
    detected_plan: Option<DetectedPlan>,
}

impl std::fmt::Debug for TokenReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenReply")
            .field("payload", &"<redacted>")
            .field("expires_in_ms", &self.expires_in_ms)
            .field("recheck_in_ms", &self.recheck_in_ms)
            .field("record_version", &self.record_version)
            .finish_non_exhaustive()
    }
}

/// A get-projection value (`project_id`, `account_id`) is display metadata a consumer
/// copies into its own config, so it gets the same bounds as a stored identity label.
fn valid_projection_value(value: &str) -> bool {
    RecordIdentity {
        account_id: Some(value.to_string()),
        email: None,
        org_name: None,
    }
    .validate()
    .is_ok()
}

/// Check one opened reply before anything is stored, cached or served from it: a
/// non-empty payload, a valid identity and get projection, a valid plan tier, an
/// adapter this vault registers, and non-negative durations.
fn validate_reply(
    reply: WireTokenReply,
    adapters: &BTreeSet<String>,
) -> Result<TokenReply, &'static str> {
    if reply.payload.is_empty() {
        return Err("empty_payload");
    }
    if reply.identity.validate().is_err() {
        return Err("identity");
    }
    if reply
        .project_id
        .iter()
        .chain(reply.account_id.iter())
        .any(|value| !valid_projection_value(value))
    {
        return Err("projection");
    }
    if reply
        .detected_plan
        .as_ref()
        .and_then(|plan| plan.tier.as_deref())
        .is_some_and(|tier| !credentials_core::plan_tier::valid_plan_tier(tier))
    {
        return Err("plan_tier");
    }
    match reply.refresh_adapter.as_deref() {
        Some(adapter) if adapters.contains(adapter) => {}
        _ => return Err("refresh_adapter"),
    }
    if reply.expires_in_ms.is_some_and(|ms| ms < 0) || reply.recheck_in_ms.is_some_and(|ms| ms < 0)
    {
        return Err("duration");
    }
    Ok(TokenReply {
        payload: reply.payload,
        expires_in_ms: reply.expires_in_ms,
        recheck_in_ms: reply.recheck_in_ms,
        record_version: reply.record_version,
        project_id: reply.project_id,
        account_id: reply.account_id,
        identity: reply.identity,
        categories: reply.categories,
        refresh_adapter: reply.refresh_adapter,
        detected_plan: reply.detected_plan,
    })
}

/// The outcome of one fetch.
#[derive(Debug, Clone)]
enum Fetched {
    Token(Arc<TokenReply>),
    Failed(Failure),
}

// ---------------------------------------------------------------------------------
// Per-id state
// ---------------------------------------------------------------------------------

/// A cached token and the instants its fetch was sent at.
#[derive(Debug, Clone)]
struct CacheEntry {
    reply: Arc<TokenReply>,
    t0_mono: u64,
    t0_wall: i64,
}

/// Whether a reply fetched at `t0_mono` may be served now to a caller demanding
/// `min_ttl_ms`: its conservative remaining life, `expires_in_ms − skew − (now − t0)`,
/// must be positive and at least the demand. A token with no expiry passes.
fn lifetime_ok(reply: &TokenReply, t0_mono: u64, now_mono: u64, min_ttl_ms: i64) -> bool {
    let Some(expires_in_ms) = reply.expires_in_ms else {
        return true;
    };
    let elapsed = i64::try_from(now_mono.saturating_sub(t0_mono)).unwrap_or(i64::MAX);
    let left = expires_in_ms
        .saturating_sub(EXPIRY_SKEW_MS)
        .saturating_sub(elapsed);
    left > 0 && left >= min_ttl_ms
}

impl CacheEntry {
    /// Whether the entry may still be reused: before `t0 + min(300 s, recheck_in_ms)`.
    fn resident(&self, now_mono: u64) -> bool {
        let window = self
            .reply
            .recheck_in_ms
            .map_or(CACHE_RESIDENCE_CAP_MS, |recheck| {
                u64::try_from(recheck)
                    .unwrap_or(0)
                    .min(CACHE_RESIDENCE_CAP_MS)
            });
        now_mono < self.t0_mono.saturating_add(window)
    }
}

fn served(reply: &TokenReply, t0_wall: i64) -> RemoteGet {
    RemoteGet {
        payload: reply.payload.as_bytes().to_vec(),
        expires_at_ms: reply
            .expires_in_ms
            .map(|expires_in_ms| t0_wall.saturating_add(expires_in_ms)),
        record_version: reply.record_version,
        project_id: reply.project_id.clone(),
        account_id: reply.account_id.clone(),
        email: reply.identity.email.clone(),
        org_name: reply.identity.org_name.clone(),
    }
}

/// One finished fetch, as its waiters see it.
#[derive(Debug)]
struct FlightResult {
    fetched: Fetched,
    t0_mono: u64,
    t0_wall: i64,
}

/// A fetch in progress that later readers may join.
struct Flight {
    seq: u64,
    generation: u64,
    demand: i64,
    done: watch::Receiver<Option<Arc<FlightResult>>>,
}

/// Everything this vault keeps in memory for one remote id. Reset when the stored
/// incarnation changes (the id was removed and added again).
struct IdState {
    incarnation: String,
    generation: u64,
    next_seq: u64,
    /// The sequence of the last fetch whose outcome was recorded.
    last_outcome_seq: u64,
    /// The sequence of the last fetch whose authoritative effect was applied.
    last_auth_seq: u64,
    cache: Option<CacheEntry>,
    flights: Vec<Flight>,
    /// How many verdicts other than `active` have been applied, and the last one. A
    /// waiter compares the count with the one it saw when it joined, so a verdict
    /// applied while it waited wins over the result it was waiting for.
    verdicts: u64,
    last_verdict: Option<RemoteRefusal>,
}

impl IdState {
    fn new(incarnation: &str) -> Self {
        Self {
            incarnation: incarnation.to_string(),
            generation: 0,
            next_seq: 1,
            last_outcome_seq: 0,
            last_auth_seq: 0,
            cache: None,
            flights: Vec::new(),
            verdicts: 0,
            last_verdict: None,
        }
    }
}

// ---------------------------------------------------------------------------------
// The reader
// ---------------------------------------------------------------------------------

/// A wall clock in milliseconds since the epoch.
pub type WallClock = Arc<dyn Fn() -> i64 + Send + Sync>;
/// A monotonic clock in milliseconds from an arbitrary origin.
pub type MonoClock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn real_wall() -> WallClock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as i64)
            .unwrap_or(0)
    })
}

fn real_mono() -> MonoClock {
    let origin = std::time::Instant::now();
    Arc::new(move || u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX))
}

/// This vault in its role as requester: it serves its consumers the remote records
/// it holds, fetching tokens from their home vaults.
pub struct RemoteReader {
    store: Arc<EncryptedStore>,
    outbound: OnceLock<OutboundClient>,
    /// The refresh adapters this vault itself registers. A home reply naming any other
    /// adapter is refused: this vault would list a protocol it cannot describe.
    adapters: BTreeSet<String>,
    wall: WallClock,
    mono: MonoClock,
    deadline: Duration,
    ids: Mutex<HashMap<String, IdState>>,
}

impl std::fmt::Debug for RemoteReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteReader")
            .field("outbound", &self.outbound.get())
            .field("adapters", &self.adapters)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl RemoteReader {
    pub fn new(store: Arc<EncryptedStore>, adapters: impl IntoIterator<Item = String>) -> Self {
        Self {
            store,
            outbound: OnceLock::new(),
            adapters: adapters.into_iter().collect(),
            wall: real_wall(),
            mono: real_mono(),
            deadline: CONSUMER_FACING_DEADLINE,
            ids: Mutex::new(HashMap::new()),
        }
    }

    /// Run the cache and the consumer's `expires_at_ms` on these clocks instead of the
    /// machine's. Only tests change them.
    pub fn with_clocks(mut self, wall: WallClock, mono: MonoClock) -> Self {
        self.wall = wall;
        self.mono = mono;
        self
    }

    /// Attach the outbound client home calls go through. Only the first call takes
    /// effect; returns whether this one did.
    pub fn attach_outbound(&self, client: OutboundClient) -> bool {
        self.outbound.set(client).is_ok()
    }

    /// The remote record stored under `credential_id`, or `None` when the id is not a
    /// remote record.
    pub fn remote_record(&self, credential_id: &str) -> Result<Option<RemoteRecord>, StoreOpError> {
        self.store.remote_record(credential_id)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, IdState>> {
        self.ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The in-memory state for `record`, reset when the stored incarnation is not the
    /// one the state was built for.
    fn state_for<'a>(
        ids: &'a mut HashMap<String, IdState>,
        record: &RemoteRecord,
    ) -> &'a mut IdState {
        let state = ids
            .entry(record.credential_id.clone())
            .or_insert_with(|| IdState::new(&record.incarnation));
        if state.incarnation != record.incarnation {
            *state = IdState::new(&record.incarnation);
        }
        state
    }

    /// Serve a consumer's read of the remote record `record`, already authorized by
    /// the caller's grants. At most one home fetch is made for this call, and the call
    /// finishes inside the consumer-facing deadline.
    pub async fn get(
        self: &Arc<Self>,
        record: &RemoteRecord,
        min_ttl_ms: Option<i64>,
    ) -> RemoteAnswer {
        let budget = tokio::time::Instant::now() + self.deadline;
        let min_ttl = min_ttl_ms.unwrap_or(0).max(0);
        let demand = home_demand(min_ttl_ms);
        let (mut done, joined_at) = {
            let mut ids = self.lock();
            let state = Self::state_for(&mut ids, record);
            let now = (self.mono)();
            if let Some(entry) = state.cache.as_ref() {
                if entry.resident(now) && lifetime_ok(&entry.reply, entry.t0_mono, now, min_ttl) {
                    return RemoteAnswer::Served(served(&entry.reply, entry.t0_wall));
                }
            }
            let generation = state.generation;
            let joinable = state
                .flights
                .iter()
                .find(|flight| flight.generation == generation && flight.demand >= demand);
            let done = match joinable {
                Some(flight) => flight.done.clone(),
                None => {
                    let seq = state.next_seq;
                    state.next_seq += 1;
                    let (publish, done) = watch::channel(None);
                    state.flights.push(Flight {
                        seq,
                        generation,
                        demand,
                        done: done.clone(),
                    });
                    // The fetch runs on its own task so a caller that goes away does
                    // not cancel it for everyone who joined.
                    let flight_budget = budget.checked_sub(FLIGHT_PUBLISH_MARGIN).unwrap_or(budget);
                    tokio::spawn(Arc::clone(self).run_flight(
                        record.clone(),
                        seq,
                        generation,
                        demand,
                        flight_budget,
                        publish,
                    ));
                    done
                }
            };
            (done, state.verdicts)
        };

        let result = match tokio::time::timeout_at(budget, done.wait_for(Option::is_some)).await {
            Ok(Ok(result)) => result.clone(),
            // The flight task ended without publishing, or this caller's own budget
            // ran out first: either way nothing definite arrived in time.
            Ok(Err(_)) | Err(_) => None,
        };
        let Some(result) = result else {
            return RemoteAnswer::Refused(Failure::home_unreachable().refusal);
        };

        let ids = self.lock();
        let Some(state) = ids
            .get(&record.credential_id)
            .filter(|state| state.incarnation == record.incarnation)
        else {
            // The record was removed (and perhaps added again) while this call waited.
            return RemoteAnswer::Refused(RemoteRefusal::new("not_found", "permanent"));
        };
        if state.verdicts > joined_at {
            if let Some(verdict) = state.last_verdict.clone() {
                return RemoteAnswer::Refused(verdict);
            }
        }
        match &result.fetched {
            Fetched::Token(reply) => {
                if lifetime_ok(reply, result.t0_mono, (self.mono)(), min_ttl) {
                    RemoteAnswer::Served(served(reply, result.t0_wall))
                } else {
                    // A fresh reply from this call's own fetch still misses the
                    // demand: the local read surface's answer, with its class.
                    RemoteAnswer::Refused(RemoteRefusal::new(
                        "ttl_unsatisfiable",
                        "context_overflow",
                    ))
                }
            }
            Fetched::Failed(failure) => RemoteAnswer::Refused(failure.refusal.clone()),
        }
    }

    /// One fetch, start to finish: fetch, write its diagnostic, apply it under the two
    /// watermarks, retire the flight, then publish to every waiter.
    async fn run_flight(
        self: Arc<Self>,
        record: RemoteRecord,
        seq: u64,
        generation: u64,
        demand: i64,
        budget: tokio::time::Instant,
        publish: watch::Sender<Option<Arc<FlightResult>>>,
    ) {
        let t0_mono = (self.mono)();
        let t0_wall = (self.wall)();
        let fetched =
            match tokio::time::timeout_at(budget, self.fetch(&record, demand, budget)).await {
                Ok(fetched) => fetched,
                Err(_) => Fetched::Failed(Failure::home_unreachable()),
            };
        if let Fetched::Failed(Failure {
            diagnostic: Some(detail),
            ..
        }) = &fetched
        {
            self.note_event(&record.credential_id, &record.home_member, detail);
        }
        let result = Arc::new(FlightResult {
            fetched,
            t0_mono,
            t0_wall,
        });
        let mut ids = self.lock();
        if let Some(state) = ids
            .get_mut(&record.credential_id)
            .filter(|state| state.incarnation == record.incarnation)
        {
            self.apply(state, &record, seq, generation, &result);
            state.flights.retain(|flight| flight.seq != seq);
        }
        drop(ids);
        publish.send_replace(Some(result));
    }

    /// Apply one fetch result under the two watermarks. Called with the id's state
    /// locked, so applies for one id are serialized; the store writes are conditioned
    /// on the incarnation, so a record removed (or re-added) underneath is untouched.
    fn apply(
        &self,
        state: &mut IdState,
        record: &RemoteRecord,
        seq: u64,
        generation: u64,
        result: &FlightResult,
    ) {
        let id = record.credential_id.as_str();
        let incarnation = record.incarnation.as_str();
        if seq > state.last_outcome_seq {
            state.last_outcome_seq = seq;
            if let Ok(RemoteRecordWrite::StaleIncarnation) = self
                .store
                .remote_record_note_fetch_outcome(id, incarnation, outcome_code(&result.fetched))
            {
                return;
            }
        }
        // Authoritative effects: a success, or a row that sets a state. A fetch
        // started before a report or a verdict (an older generation) never applies
        // one, and neither does a result older than the last one applied.
        let authoritative = match &result.fetched {
            Fetched::Token(_) => true,
            Fetched::Failed(failure) => matches!(failure.effect, Effect::State(_)),
        };
        if !authoritative || seq <= state.last_auth_seq || generation != state.generation {
            return;
        }
        match &result.fetched {
            Fetched::Token(reply) => {
                let success = RemoteHomeSuccess {
                    home_version: reply.record_version,
                    refresh_adapter: reply.refresh_adapter.clone(),
                    detected_plan: reply.detected_plan.clone(),
                    identity: reply.identity.clone(),
                    recheck_pending: reply.recheck_in_ms.is_some(),
                };
                match self
                    .store
                    .remote_record_apply_success(id, incarnation, &success)
                {
                    Ok(RemoteRecordWrite::Changed | RemoteRecordWrite::Unchanged) => {}
                    Ok(RemoteRecordWrite::StaleIncarnation) | Err(_) => return,
                }
                state.last_auth_seq = seq;
                state.cache = Some(CacheEntry {
                    reply: Arc::clone(reply),
                    t0_mono: result.t0_mono,
                    t0_wall: result.t0_wall,
                });
            }
            Fetched::Failed(failure) => {
                let Effect::State(home_state) = failure.effect else {
                    return;
                };
                match self.store.remote_record_apply_home_state(
                    id,
                    incarnation,
                    home_state,
                    failure.refusal.code,
                ) {
                    Ok(RemoteRecordWrite::Changed | RemoteRecordWrite::Unchanged) => {}
                    Ok(RemoteRecordWrite::StaleIncarnation) | Err(_) => return,
                }
                state.last_auth_seq = seq;
                state.cache = None;
                state.generation += 1;
                state.verdicts += 1;
                state.last_verdict = Some(failure.refusal.clone());
            }
        }
    }

    /// One diagnostic row on this vault naming the home. Best effort: a diagnostic
    /// that could fail the read would be worse than the gap it leaves.
    fn note_event(&self, credential_id: &str, home: &str, detail: &str) {
        let _ = self.store.record_auth_event(
            credential_id,
            AuthObservation {
                kind: AuthEventKind::ScopedReadRefusal.as_str(),
                provider_status: None,
                detail: Some(detail),
                reporter_source: None,
                principal: Some(AuthEventPrincipal::Member(home)),
            },
            None,
        );
    }

    /// This vault's own requester setup: its self id and its transfer key's private
    /// half and key id.
    fn own_setup(&self) -> Result<(String, String, String), Failure> {
        let self_id = match self.store.federation_self_member() {
            Ok(Some(self_id)) => self_id,
            Ok(None) => return Err(Failure::transfer_key_missing(None)),
            Err(_) => return Err(Failure::store_error()),
        };
        let pem = match self.store.get(VAULT_TRANSFER_ID) {
            Ok(record) if record.kind == CredentialKind::KemKey => {
                match std::str::from_utf8(record.payload.expose()) {
                    Ok(pem) => pem.to_string(),
                    Err(_) => return Err(Failure::transfer_key_missing(Some(self_id))),
                }
            }
            Ok(_)
            | Err(StoreOpError::NotFound)
            | Err(StoreOpError::NeedsReauth)
            | Err(StoreOpError::Quarantined)
            | Err(StoreOpError::Corrupt(_))
            | Err(StoreOpError::Decrypt(_)) => {
                return Err(Failure::transfer_key_missing(Some(self_id)))
            }
            Err(_) => return Err(Failure::store_error()),
        };
        let key_id = match credentials_core::kem::public_half(&pem) {
            Ok((_, key_id)) => key_id,
            Err(_) => return Err(Failure::transfer_key_missing(Some(self_id))),
        };
        Ok((self_id, pem, key_id))
    }

    /// The time left before `budget`, or `None` when it is spent.
    fn left(budget: tokio::time::Instant) -> Option<Duration> {
        budget
            .checked_duration_since(tokio::time::Instant::now())
            .filter(|left| !left.is_zero())
    }

    /// The home's announced transfer key, looked up for the record's stored home and
    /// never for a member named anywhere in a request or a reply.
    async fn home_key(
        &self,
        client: &OutboundClient,
        home: &str,
        budget: tokio::time::Instant,
    ) -> Result<super::ingress::PeerKey, Failure> {
        let left = Self::left(budget).ok_or_else(Failure::home_unreachable)?;
        let body = client
            .call(
                CALLOSUM_ROUTE_KEY,
                RouteCall {
                    target: management_surface(CALLOSUM_MODULE_ID),
                    prelude: None,
                    request: json!({ "method": "callosum.peer_keys_read", "params": {} }),
                },
                left,
            )
            .await
            .map_err(map_outbound_error)?;
        match decode_peer_transfer_key(&body, home) {
            Lookup::Found(key) => Ok(key),
            Lookup::Absent => Err(Failure::home_key_missing(home)),
            Lookup::Unavailable => Err(Failure::home_unreachable()),
        }
    }

    /// Fetch a token for `record` from its home.
    async fn fetch(
        &self,
        record: &RemoteRecord,
        demand: i64,
        budget: tokio::time::Instant,
    ) -> Fetched {
        match self
            .fetch_inner(&record.credential_id, &record.home_member, demand, budget)
            .await
        {
            Ok(reply) => Fetched::Token(Arc::new(reply)),
            Err(failure) => Fetched::Failed(failure),
        }
    }

    /// `remote add`'s one home fetch, for an id this vault does not hold yet: the same
    /// request, opening and reply validation a read makes, against `home`'s announced
    /// key, within `budget`. Writes nothing (no record, no outcome, no diagnostic); the
    /// caller stores the returned description only once it has it. The token in the
    /// reply is dropped here and never leaves this function.
    pub async fn fetch_for_add(
        &self,
        credential_id: &str,
        home: &str,
        budget: tokio::time::Instant,
    ) -> Result<NewRemoteRecord, RemoteRefusal> {
        if credential_id.is_empty() || !valid_member_id(home) {
            return Err(RemoteRefusal::new("invalid_params", "permanent"));
        }
        let reply = self
            .fetch_inner(credential_id, home, home_demand(None), budget)
            .await
            .map_err(|failure| failure.refusal)?;
        Ok(NewRemoteRecord {
            credential_id: credential_id.to_string(),
            home_member: home.to_string(),
            refresh_adapter: reply.refresh_adapter.clone(),
            detected_plan: reply.detected_plan.clone(),
            identity: reply.identity.clone(),
            home_version: reply.record_version,
            categories: reply.categories.clone(),
        })
    }

    async fn fetch_inner(
        &self,
        credential_id: &str,
        home: &str,
        demand: i64,
        budget: tokio::time::Instant,
    ) -> Result<TokenReply, Failure> {
        let (self_id, pem, key_id) = self.own_setup()?;
        let client = self.outbound.get().ok_or_else(Failure::home_unreachable)?;
        let home_key = self.home_key(client, home, budget).await?;
        let nonce = random_nonce().ok_or_else(Failure::store_error)?;
        let aad = serde_json::to_string(&TokenAad {
            credential_id,
            requester: &self_id,
            home,
            nonce: &nonce,
            recipient_key_id: &key_id,
        })
        .map_err(|_| Failure::store_error())?;
        let left = Self::left(budget).ok_or_else(Failure::home_unreachable)?;
        let reply = client
            .call(
                &home_route_key(home),
                RouteCall {
                    target: management_surface(&fed_provider_module(home)),
                    prelude: None,
                    request: json!({
                        "method": OP_REMOTE_TOKEN,
                        "params": { "aad": aad, "min_ttl_ms": demand },
                    }),
                },
                left,
            )
            .await
            .map_err(map_outbound_error)?;
        self.classify_reply(&reply, &aad, &pem, &home_key.public, home, &self_id)
    }

    /// Turn the home's answer into a validated reply or a consumer-table row.
    fn classify_reply(
        &self,
        reply: &Value,
        aad: &str,
        pem: &str,
        home_public: &[u8],
        home: &str,
        self_id: &str,
    ) -> Result<TokenReply, Failure> {
        if let (Some(enc), Some(ciphertext)) = (
            reply.get("enc").and_then(Value::as_str),
            reply.get("ciphertext").and_then(Value::as_str),
        ) {
            let b64 = base64::engine::general_purpose::STANDARD;
            let (Ok(enc), Ok(ciphertext)) = (b64.decode(enc), b64.decode(ciphertext)) else {
                return Err(Failure::seal_invalid());
            };
            // Opened only over the aad bytes this vault sent, with the stored home's
            // announced key and the token-reply info: a reply sealed for another
            // request, by another member or for another purpose does not open.
            let plaintext = credentials_core::kem::open_auth(
                pem,
                home_public,
                &enc,
                &ciphertext,
                REMOTE_TOKEN_INFO,
                aad.as_bytes(),
            )
            .map_err(|_| Failure::seal_invalid())?;
            let wire: WireTokenReply =
                serde_json::from_slice(&plaintext).map_err(|_| Failure::reply_invalid("shape"))?;
            return validate_reply(wire, &self.adapters).map_err(Failure::reply_invalid);
        }
        if let Some(error) = reply.get("error").filter(|error| error.is_object()) {
            return Err(map_home_refusal(error, home, self_id));
        }
        if let Some(code) = reply.get("code").and_then(Value::as_str) {
            return Err(map_frame_code(code));
        }
        Err(Failure::home_unavailable().noting("home_reply_unrecognised"))
    }
}

/// The outbound client's binding-cache key for one home's route.
fn home_route_key(home: &str) -> String {
    format!("home:{home}")
}

/// 16 random bytes as 32 lowercase hex: the per-fetch token nonce.
fn random_nonce() -> Option<String> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new().fill(&mut bytes).ok()?;
    Some(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

// ---------------------------------------------------------------------------------
// Failure reports
// ---------------------------------------------------------------------------------

/// Map the home's answer to a forwarded failure report.
fn map_report_reply(reply: &Value, home: &str) -> Result<(), RemoteRefusal> {
    if reply.get("accepted").and_then(Value::as_bool) == Some(true) {
        return Ok(());
    }
    if let Some(error) = reply.get("error").filter(|error| error.is_object()) {
        let code = error.get("code").and_then(Value::as_str).unwrap_or("");
        return Err(match code {
            "not_found" => RemoteRefusal::new("not_found", "permanent"),
            "report_status_not_credential_death" => {
                RemoteRefusal::new("report_status_not_credential_death", "permanent")
            }
            "needs_reauth" => {
                RemoteRefusal::new("needs_reauth", "auth_required").remedy(Some(home.into()))
            }
            "corrupt" => RemoteRefusal::new("corrupt", "permanent"),
            // The home could not finish (a pairing lookup, its store): nothing about
            // the credential, and a retry may succeed.
            _ => Failure::home_unavailable().refusal,
        });
    }
    if let Some(code) = reply.get("code").and_then(Value::as_str) {
        return Err(map_frame_code(code).refusal);
    }
    Err(Failure::home_unavailable().refusal)
}

impl RemoteReader {
    /// Forward a consumer's failure report on the remote record `record`, already
    /// authorized by the caller's grants.
    ///
    /// A status other than 401/403 is refused here, before anything else, as locally.
    /// Then, whatever the home answers: the cache entry is dropped if it holds the
    /// reported version (a newer one is kept), the generation moves so no later read
    /// joins a fetch started before the report, and the stored unresolved report is
    /// raised to the reported version, never lowered. Only then is the report sent.
    pub async fn report(
        self: &Arc<Self>,
        record: &RemoteRecord,
        record_version: u64,
        provider_status: u16,
        reporter_source: Option<&str>,
        principal: Option<AuthEventPrincipal<'_>>,
    ) -> Result<(), RemoteRefusal> {
        if !matches!(provider_status, 401 | 403) {
            return Err(RemoteRefusal::new(
                "report_status_not_credential_death",
                "permanent",
            ));
        }
        let budget = tokio::time::Instant::now() + self.deadline;
        {
            let mut ids = self.lock();
            let state = Self::state_for(&mut ids, record);
            if state
                .cache
                .as_ref()
                .is_some_and(|entry| entry.reply.record_version == record_version)
            {
                state.cache = None;
            }
            state.generation += 1;
        }
        let id = record.credential_id.as_str();
        match self.store.remote_record_raise_reported_version(
            id,
            &record.incarnation,
            record_version,
        ) {
            Ok(RemoteRecordWrite::Changed | RemoteRecordWrite::Unchanged) => {}
            Ok(RemoteRecordWrite::StaleIncarnation) => {
                return Err(RemoteRefusal::new("not_found", "permanent"))
            }
            Err(_) => return Err(Failure::store_error().refusal),
        }
        // This vault records its forward in its own diagnostics only; the home writes
        // the chain row when its stale mark lands.
        let _ = self.store.record_auth_event(
            id,
            AuthObservation {
                kind: AuthEventKind::ConsumerReportStale.as_str(),
                provider_status: Some(provider_status),
                detail: Some("forwarded_to_home"),
                reporter_source: reporter_source.map(ReporterSource::from_wire),
                principal,
            },
            Some(record_version),
        );
        let Some(client) = self.outbound.get() else {
            return Err(Failure::home_unreachable().refusal);
        };
        let Some(left) = Self::left(budget) else {
            return Err(Failure::home_unreachable().refusal);
        };
        let mut params = json!({
            "credential_id": id,
            "record_version": record_version,
            "provider_status": provider_status,
        });
        if let Some(source) = reporter_source {
            params["reporter_source"] = json!(source);
        }
        let home = record.home_member.as_str();
        let reply = client
            .call(
                &home_route_key(home),
                RouteCall {
                    target: management_surface(&fed_provider_module(home)),
                    prelude: None,
                    request: json!({ "method": OP_REPORT_AUTH_FAILURE, "params": params }),
                },
                left,
            )
            .await
            .map_err(|error| map_outbound_error(error).refusal)?;
        map_report_reply(&reply, home)
    }
}

// ---------------------------------------------------------------------------------
// Status and list
// ---------------------------------------------------------------------------------

/// The `credential.status` body for a remote record: the local fields, read from
/// this vault's storage only, plus `remote_home` and `last_fetch_outcome`.
///
/// `ready` follows the local rule (`!fenced_out && state == active`).
/// `last_error_code` is the code behind the last authoritative home answer, which
/// survives later transport failures, invalid replies and restarts. `stale_pending` is
/// true while a forwarded report is unresolved. Status never calls the home, so it
/// cannot see a repair made only there: a consumer waiting for one polls `get_scoped`.
pub fn status_body(record: &RemoteRecord, fenced_out: bool) -> Value {
    let mut body = json!({
        "ready": !fenced_out && record.last_home_state == RemoteHomeState::Active,
        "last_error_code": record.last_home_error,
        "lease_held": !fenced_out,
        "credential_id": record.credential_id,
        "record_version": record.last_home_version,
        "stale_pending": record.reported_version.is_some(),
        "remote_home": record.home_member,
    });
    if let Some(outcome) = record.last_fetch_outcome.as_deref() {
        body["last_fetch_outcome"] = json!(outcome);
    }
    body
}

fn record_state(state: RemoteHomeState) -> RecordState {
    match state {
        RemoteHomeState::Active => RecordState::Active,
        RemoteHomeState::NeedsReauth => RecordState::NeedsReauth,
        RemoteHomeState::Corrupt => RecordState::Corrupt,
    }
}

impl RemoteReader {
    /// The scoped-listing rows for every remote record `grants` reach, built from this
    /// vault's storage alone, exactly as the local listing builds a row: operations
    /// from the matching grants (deposit never lists), identity, adapter, auth method
    /// and plan disclosed only to `read` or `list`, categories, provider ids and the
    /// operator tier from this vault's own tables, `record_version` the last home
    /// version and `state` the last authoritative home state.
    pub fn scoped_rows(&self, grants: &[ReadGrant]) -> Result<Vec<ScopedListRow>, StoreOpError> {
        let mut rows = Vec::new();
        for entry in self.store.remote_inventory()? {
            let record = entry.record;
            let operations: BTreeSet<GrantOperation> = grants
                .iter()
                .filter(|grant| grant.operation != GrantOperation::Deposit)
                .filter(|grant| match grant.selector_kind {
                    SelectorKind::Exact => grant.selector == record.credential_id,
                    SelectorKind::Audience => false,
                    SelectorKind::Category => entry.categories.contains(&grant.selector),
                })
                .map(|grant| grant.operation)
                .collect();
            if operations.is_empty() {
                continue;
            }
            let disclose = operations.contains(&GrantOperation::Read)
                || operations.contains(&GrantOperation::List);
            let (identity, refresh_adapter, auth_method, detected_plan) = if disclose {
                let auth_method = credentials_core::list_auth_method::list_auth_method(
                    CredentialKind::Oauth,
                    record.refresh_adapter.as_deref(),
                );
                (
                    Some(record.identity.clone()),
                    record.refresh_adapter.clone(),
                    auth_method,
                    record.detected_plan.clone(),
                )
            } else {
                (None, None, None, None)
            };
            let (plan_tier, plan_tier_source) = credentials_core::plan_detection::effective_plan(
                identity.as_ref().and(entry.plan_tier),
                detected_plan.as_ref(),
            );
            rows.push(ScopedListRow {
                id: record.credential_id.clone(),
                categories: entry.categories,
                state: record_state(record.last_home_state),
                record_version: record.last_home_version,
                operations: operations.into_iter().collect(),
                identity,
                refresh_adapter,
                provider_ids: entry.provider_ids,
                plan_tier,
                plan_tier_source,
                auth_method,
            });
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_home_demand_adds_the_margin_and_saturates_instead_of_wrapping() {
        assert_eq!(home_demand(None), 62_500);
        assert_eq!(home_demand(Some(-5)), 62_500);
        assert_eq!(home_demand(Some(600_000)), 662_500);
        assert_eq!(home_demand(Some(i64::MAX - 1)), i64::MAX);
        assert_eq!(home_demand(Some(i64::MAX)), i64::MAX);
    }

    fn reply(expires_in_ms: Option<i64>, recheck_in_ms: Option<i64>) -> TokenReply {
        TokenReply {
            payload: "token".into(),
            expires_in_ms,
            recheck_in_ms,
            record_version: 1,
            project_id: None,
            account_id: None,
            identity: RecordIdentity::default(),
            categories: Vec::new(),
            refresh_adapter: Some("anthropic".into()),
            detected_plan: None,
        }
    }

    #[test]
    fn the_lifetime_test_measures_from_the_send_time_and_subtracts_the_skew() {
        let hour = reply(Some(3_600_000), None);
        assert!(lifetime_ok(&hour, 1_000, 1_000, 600_000));
        // 3600 s − 60 s skew − 2940 s elapsed = 600 s left: exactly the demand.
        assert!(lifetime_ok(&hour, 0, 2_940_000, 600_000));
        assert!(!lifetime_ok(&hour, 0, 2_940_001, 600_000));
        // Nothing left past the skew is never served, whatever the demand.
        assert!(!lifetime_ok(&reply(Some(60_000), None), 0, 0, 0));
        // No expiry: no lifetime bound (the residence cap bounds it instead).
        assert!(lifetime_ok(&reply(None, None), 0, u64::MAX, i64::MAX));
    }

    #[test]
    fn residence_is_capped_at_300_s_and_by_recheck_in_ms() {
        let entry = |recheck| CacheEntry {
            reply: Arc::new(reply(None, recheck)),
            t0_mono: 10_000,
            t0_wall: 0,
        };
        assert!(entry(None).resident(10_000 + 299_999));
        assert!(!entry(None).resident(10_000 + 300_000));
        assert!(entry(Some(40_000)).resident(10_000 + 39_999));
        assert!(!entry(Some(40_000)).resident(10_000 + 40_000));
        assert!(!entry(Some(900_000)).resident(10_000 + 300_000));
        assert!(!entry(Some(0)).resident(10_000));
    }

    const HOME: &str = "fed-computer:aa11bb22cc33dd44ee55ff6600112233";
    const SELF: &str = "fed-computer:11223344556677889900112233445566";

    fn row(error: Value) -> (String, &'static str, Option<String>, Effect) {
        let failure = map_home_refusal(&error, HOME, SELF);
        (
            failure.refusal.code.to_string(),
            failure.refusal.class,
            failure.refusal.remedy_member,
            failure.effect,
        )
    }

    /// One assertion per home-outcome row of the consumer table: code, class,
    /// `remedy_member` and stored effect.
    #[test]
    fn every_home_refusal_row_maps_to_its_answer_and_stored_effect() {
        use RemoteHomeState::{Corrupt, NeedsReauth};
        let state = Effect::State;
        assert_eq!(
            row(json!({"code": "not_found", "class": "permanent"})),
            ("not_found".into(), "permanent", None, state(NeedsReauth))
        );
        assert_eq!(
            row(json!({"code": "needs_reauth", "class": "auth_required"})),
            (
                "needs_reauth".into(),
                "auth_required",
                Some(HOME.into()),
                state(NeedsReauth)
            )
        );
        assert_eq!(
            row(json!({"code": "corrupt", "class": "permanent"})),
            ("corrupt".into(), "permanent", None, state(Corrupt))
        );
        for (code, class) in [
            ("refresh_failed", "transient"),
            ("refresh_unsupported", "permanent"),
            ("vault_locked", "transient"),
            ("store_error", "transient"),
            ("ttl_unsatisfiable", "context_overflow"),
        ] {
            assert_eq!(
                row(json!({"code": code, "class": class})),
                (code.to_string(), class, None, Effect::OutcomeOnly),
                "{code}"
            );
        }
        assert_eq!(
            row(
                json!({"code": "remote_setup_incomplete", "class": "permanent", "remedy_member": HOME})
            ),
            (
                "remote_setup_incomplete".into(),
                "permanent",
                Some(HOME.into()),
                state(NeedsReauth)
            )
        );
        // The home names the requester as it attested it, which may differ from this
        // vault's (wrong) self id; either way it is this vault's to fix.
        let attested = "fed-computer:99999999999999999999999999999999";
        assert_eq!(
            row(
                json!({"code": "remote_setup_incomplete", "class": "permanent", "remedy_member": attested})
            ),
            (
                "remote_setup_incomplete".into(),
                "permanent",
                Some(attested.into()),
                state(NeedsReauth)
            )
        );
        assert_eq!(
            row(json!({"code": "home_unavailable", "class": "transient"})),
            (
                "home_unavailable".into(),
                "transient",
                None,
                Effect::OutcomeOnly
            )
        );
        let unknown = map_home_refusal(&json!({"code": "Weird Code!"}), HOME, SELF);
        assert_eq!(unknown.refusal.code, "home_unavailable");
        assert_eq!(unknown.effect, Effect::OutcomeOnly);
        assert_eq!(
            unknown.diagnostic.as_deref(),
            Some("home_refusal:unrecognised")
        );
    }

    #[test]
    fn frame_codes_split_into_callosum_classes_and_home_error_frames() {
        for code in [
            "fed_not_exposed",
            "fed_unknown_module",
            "fed_bad_call",
            "fed_payload_too_big",
        ] {
            let failure = map_frame_code(code);
            assert_eq!(failure.refusal.code, "federation_setup_invalid", "{code}");
            assert_eq!(failure.refusal.class, "permanent");
            assert_eq!(failure.effect, Effect::OutcomeOnly);
        }
        for code in [
            "fed_busy",
            "fed_ledger_full",
            "fed_target_unavailable",
            "fed_internal",
            "fed_partition",
            "fed_deadline",
            "fed_shutdown",
            "fed_internal [effect:applied]",
            "fed_something_new",
        ] {
            let failure = map_frame_code(code);
            assert_eq!(failure.refusal.code, "home_unreachable", "{code}");
            assert_eq!(failure.refusal.class, "transient");
        }
        let frame = map_frame_code("unknown_method");
        assert_eq!(frame.refusal.code, "home_unavailable");
        assert_eq!(
            frame.diagnostic.as_deref(),
            Some("home_error_frame:unknown_method")
        );
    }

    fn wire(adapter: Option<&str>) -> WireTokenReply {
        serde_json::from_value(json!({
            "payload": "token",
            "expires_in_ms": 1000,
            "record_version": 2,
            "identity": {"account_id": "acct"},
            "categories": ["llm-provider"],
            "refresh_adapter": adapter,
            "detected_plan": {"tier": "max_20x", "raw": null, "observed_at_ms": 1},
        }))
        .expect("wire reply")
    }

    #[test]
    fn reply_validation_refuses_each_listed_fault() {
        let adapters: BTreeSet<String> = ["anthropic".to_string()].into();
        assert!(validate_reply(wire(Some("anthropic")), &adapters).is_ok());
        assert_eq!(
            validate_reply(wire(Some("unregistered")), &adapters).err(),
            Some("refresh_adapter")
        );
        assert_eq!(
            validate_reply(wire(None), &adapters).err(),
            Some("refresh_adapter")
        );
        let mut empty = wire(Some("anthropic"));
        empty.payload.clear();
        assert_eq!(
            validate_reply(empty, &adapters).err(),
            Some("empty_payload")
        );
        let mut control = wire(Some("anthropic"));
        control.identity.email = Some("me\u{7}@example.com".into());
        assert_eq!(validate_reply(control, &adapters).err(), Some("identity"));
        let mut tier = wire(Some("anthropic"));
        tier.detected_plan.as_mut().unwrap().tier = Some("MAX!".into());
        assert_eq!(validate_reply(tier, &adapters).err(), Some("plan_tier"));
        assert!(
            serde_json::from_value::<WireTokenReply>(json!({
                "payload": "token",
                "record_version": 1,
                "refresh_token": "never",
            }))
            .is_err(),
            "a field outside the list refuses the whole reply"
        );
    }
}
