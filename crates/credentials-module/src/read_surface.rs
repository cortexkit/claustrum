//! The anonymous read surface: the four route-channel operations a consumer calls.
//!
//! This is READ-ONLY — there is deliberately no write op here (writes live in the
//! separate offline admin CLI). Each op takes a capability HANDLE, never a public
//! alias, and the handle is resolved to a credential id before anything else; an
//! unknown or revoked handle is a uniform `not_found` so a probe cannot enumerate.
//!
//! Operations:
//! - `credential.get { handle, min_ttl_ms?, force_refresh? }` → the opaque payload,
//!   refreshed first if stale (single-flight, vault-owned).
//! - `credential.get_many { items: [...] }` → capped at [`limiter::GET_MANY_MAX`].
//! - `credential.status { handle? }` → non-secret health, never bytes.
//! - `credential.report_auth_failure { handle, provider_status, record_version }` →
//!   marks the credential needs_reauth so the next get does not serve a dead token.
//!   `record_version` is the version the consumer was SERVED, and the mark only lands
//!   if the store still holds it: a report about a version the vault has already
//!   replaced is a silent no-op, so a slow consumer's stale 401 cannot invalidate a
//!   credential that has since been repaired.
//!
//!   For a STATIC api-key record this call is not an accelerator, it is the only
//!   automatic path to `needs_reauth` — see [`credentials_core::credential_id`].
//!
//! Every fetch passes through the per-connection [`FetchLimiter`]; an anomaly raises
//! a durable audit alarm (the first crossing per connection). Refresh-triggering
//! reads (`force_refresh` / a tight `min_ttl_ms`) and `report_auth_failure` are the
//! rate-sensitive paths the limiter watches.

use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use credentials_core::audit::{AlarmReason, AuditCtx, AuditOp, AuditRecord};
use credentials_core::engine::{EngineError, RefreshEngine};
use credentials_core::health::VaultHealth;
use credentials_core::refresh_adapters::RefreshError;
use credentials_core::store::StoreOpError;

use crate::limiter::{Admission, FetchLimiter, GET_MANY_MAX};

/// A `credential.get` request.
#[derive(Debug, Deserialize)]
pub struct GetParams {
    pub handle: String,
    #[serde(default)]
    pub min_ttl_ms: Option<i64>,
    #[serde(default)]
    pub force_refresh: bool,
}

/// A `credential.get_many` request: a capped batch of get items.
#[derive(Debug, Deserialize)]
pub struct GetManyParams {
    pub items: Vec<GetParams>,
}

/// A `credential.status` request (an absent handle = overall vault health).
#[derive(Debug, Deserialize)]
pub struct StatusParams {
    #[serde(default)]
    pub handle: Option<String>,
}

/// A `credential.report_auth_failure` request.
#[derive(Debug, Deserialize)]
pub struct ReportAuthFailureParams {
    pub handle: String,
    pub provider_status: u16,
    /// The `record_version` the consumer was SERVED for this handle (from the `get`
    /// result it acted on). Required: the vault invalidates only if this still matches
    /// the current version, so a stale report for a since-refreshed credential is a
    /// no-op instead of falsely killing the fresh token. A consumer that omits it is
    /// rejected (`invalid_params`) rather than silently invalidating whatever is current.
    pub record_version: u64,
}

/// A successful `get` result. `payload` is opaque to the consumer.
#[derive(Debug, Serialize)]
pub struct GetResult {
    pub payload: Vec<u8>,
    pub expires_at_ms: Option<i64>,
    pub record_version: u64,
    /// The Code-Assist project id for an antigravity credential, a NON-secret value
    /// the consumer freezes into its render config (it is in the request path).
    /// Absent for every non-antigravity credential. Never the refresh token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// The provider account identity the served token executes under (e.g. the OpenAI
    /// ChatGPT-Account-Id), a NON-secret value parsed live from the served access token
    /// via the per-provider claim table. It answers "which account would a send through
    /// this handle execute under" — the binding key an account-scoped router joins on,
    /// paired with `record_version` (which bumps on every replace, so the router
    /// re-resolves when a handle is re-pointed at a different account). Absent when the
    /// provider has no known account claim or the token does not carry one. Never a
    /// secret and never the credential id / handle (handles survive replace by design).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    /// The account email, when captured at login (Anthropic discloses it in the token
    /// exchange; opaque-token providers have no live-parse path, so this is stored
    /// identity). NON-secret display metadata for account-labeled consumers (ck-quota
    /// usage panels). Absent for records minted before identity capture existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Human-readable organization/workspace name (the subscription the token draws
    /// limits from), when captured at login. NON-secret display metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,
}

/// A non-secret error code returned to a consumer (never leaks why beyond the
/// fail-closed category).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadError {
    NotFound,
    NeedsReauth,
    RefreshUnsupported,
    RefreshFailed,
    VaultLocked,
    Corrupt,
    /// `get_many` exceeded the cap.
    TooManyItems,
}

/// The fleet-wide error-class vocabulary (error-class contract, ratified 2026-07-08;
/// normative doc: llm-runner/docs/error-class-contract.md). Classification is PRODUCED
/// here at the source —
/// a consumer branches on this tag, never on which `ReadError` code it happens to know
/// is permanent. The wire set is closed and pinned: see `ERROR_CLASS_WIRE_SET`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// Retry may succeed (upstream may recover, lock may release).
    Transient,
    /// Retrying this credential with this request is futile until out-of-band action.
    Permanent,
    /// A human/admin must re-establish the credential (`login --replace`); consumers
    /// should surface an actionable auth prompt, not retry.
    AuthRequired,
    /// The request exceeds a bound (`get_many` cap); remedy is to reduce the request
    /// and retry — retrying the same request is futile.
    ContextOverflow,
}

/// The pinned wire strings of the closed class set. Golden-tested below so this
/// producer cannot drift from the contract's canonical block. Referenced only by the
/// golden test (this is a bin target, so that reads as dead code to rustc).
#[allow(dead_code)]
pub const ERROR_CLASS_WIRE_SET: [&str; 4] = [
    "transient",
    "permanent",
    "auth_required",
    "context_overflow",
];

impl ReadError {
    /// The produced classification for each fail-closed category.
    ///
    /// NO REFUSAL HERE EVER MEANS "GONE FOREVER, DESTROY YOUR STATE", and a consumer
    /// must not invent one. Neighbouring fleet surfaces split permanent refusals two
    /// ways -- refuse-but-keep-state, versus proof-of-death that authorises deleting a
    /// route or registration (callosum's push submit does exactly this: 400
    /// BadDeviceToken keeps the route, 410 destroys it). THIS SURFACE HAS ONLY THE
    /// FIRST KIND.
    ///
    /// It is forced rather than unfinished. Handle resolution answers identically for
    /// a REVOKED handle and one that never existed, because distinguishing them is an
    /// enumeration oracle. That same indistinguishability denies the consumer the
    /// difference between "my grant was withdrawn" and "my config holds the wrong
    /// string" -- so no refusal can license destroying configuration, since the typo
    /// case would turn one bad character into a self-sustaining outage.
    ///
    /// Consumer rule: on `permanent`, refuse the operation, account it, surface it to
    /// an operator, and CHANGE NOTHING. Do not retry (nothing about the world changed)
    /// and do not reap (you cannot tell which case you are in).
    pub fn class(self) -> ErrorClass {
        match self {
            // Handle revoked/unknown, record quarantined, or a static credential with
            // no refresh path: nothing a retry can change.
            ReadError::NotFound | ReadError::Corrupt | ReadError::RefreshUnsupported => {
                ErrorClass::Permanent
            }
            // The refresh token is dead; a human must run a fresh login.
            ReadError::NeedsReauth => ErrorClass::AuthRequired,
            // A refresh attempt failed (provider may recover) or the master key is
            // unresolvable right now (keychain/lease may recover).
            ReadError::RefreshFailed | ReadError::VaultLocked => ErrorClass::Transient,
            // Over the `get_many` cap: reduce the batch and retry.
            ReadError::TooManyItems => ErrorClass::ContextOverflow,
        }
    }
}

/// One item's outcome in a `get`/`get_many`: the payload or a non-secret code.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum GetOutcome {
    Ok(GetResult),
    Err { error: ErrorBody },
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: ReadError,
    /// The produced error class (error-class contract). Always consistent with
    /// `code.class()`; consumers branch on this, `code` is the producer detail.
    pub class: ErrorClass,
}

/// Non-secret per-credential health.
#[derive(Debug, Serialize)]
pub struct StatusResult {
    pub ready: bool,
    pub last_error_code: Option<ReadError>,
    pub lease_held: bool,
}

/// The read surface: the engine (for refresh-on-read), the per-connection limiter,
/// and the actor used in audit entries this surface writes (refresh commits and
/// report_auth_failure go in the same chain as admin writes).
pub struct ReadSurface {
    engine: Arc<RefreshEngine>,
    limiter: Mutex<FetchLimiter>,
    // A PRECOMPUTED health snapshot, refreshed off the probe path on a cadence (see
    // the daemon's health refresher). The subc health.check reply MUST be cheap and
    // in-memory (spec §2): a live store read on the probe path can queue behind a
    // busy writer under load and miss the prober's deadline, which for the vault
    // triggers a restart (lease churn + a fenced-out window). So the probe serves
    // this cached snapshot, never a fresh store scan. std::sync::Mutex (not the
    // tokio one) because every critical section here is a trivial clone/swap with
    // no await held across the lock.
    health: std::sync::Mutex<VaultHealth>,
    // Wall-clock ms of the last SUCCESSFUL health refresh. Read LIVE on the probe path
    // (never frozen into the snapshot — the QTA rule: an age baked into the cached
    // content would let a wedged refresher keep reporting a healthy-but-stale snapshot
    // and mask its own death). If the refresher task wedges (a scan that blocks) OR dies
    // (a panic), this stops advancing; the probe computes the age live and fails closed.
    // One atomic covers both failure modes uniformly, so no separate task-watch is needed.
    last_refresh_ms: std::sync::atomic::AtomicI64,
}

/// If the cached health snapshot has not been refreshed within this window, the probe
/// treats the refresher as wedged/dead and reports `Failing` (fail-closed) instead of
/// serving a stale snapshot as healthy. A small multiple of `HEALTH_REFRESH_INTERVAL`
/// (5s) so a single slow scan does not false-trigger, but a genuinely stuck refresher is
/// caught within a few probe cycles.
///
/// THE HEADROOM IS ENORMOUS AND THAT IS THE POINT, because the two quantities are not
/// the same kind of thing. Measured against the live vault (23 credentials), the scan
/// this must not false-trigger on runs in UNDER 2ms — four orders of magnitude inside
/// the limit. The window is not sized to cover a slow scan; it is sized so that a
/// refresher which has STOPPED is caught within a few probe cycles, and a scan taking
/// anywhere near 20s would mean the store is wedged, which is a genuine `Failing`
/// rather than a false trigger.
///
/// The 2ms figure is one vault's worth, which is a floor rather than a distribution.
/// The scan is a full table read, so its tail is a LARGER VAULT rather than a slower
/// machine — measured at 10,000 credentials it is 2.5ms, still ~7900x inside the
/// limit. A vault would have to hold on the order of a hundred million credentials to
/// approach it, so the bound is safe across any size this will ever see.
///
/// Note this bound's governing quantity is not stored anywhere: `last_refresh_ms`
/// records the completion INSTANT, never the duration, so nothing in the vault can
/// answer "how long do scans take" after the fact. It has to be measured directly, as
/// above. That is fine while the work is a local table read; it would stop being fine
/// if the scan ever grew a network or keychain dependency, whose tail is unbounded in
/// a way row count is not — whoever adds one should re-measure rather than trust this
/// note.
const HEALTH_STALE_LIMIT_MS: i64 = 20_000;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl ReadSurface {
    pub fn new(engine: Arc<RefreshEngine>, limiter: FetchLimiter) -> Self {
        // Compute the initial snapshot once at construction (boot time, off any
        // probe path) so the very first health.check has real data, not a
        // placeholder. The background refresher keeps it fresh thereafter.
        let initial = Self::compute_health(&engine);
        ReadSurface {
            engine,
            limiter: Mutex::new(limiter),
            health: std::sync::Mutex::new(initial),
            last_refresh_ms: std::sync::atomic::AtomicI64::new(now_ms()),
        }
    }

    /// Serve a single `get`. Resolves the handle, runs the limiter (raising a
    /// durable alarm on a first anomaly), then refreshes-if-stale and returns the
    /// payload. All failures are fail-closed non-secret codes.
    pub async fn get(&self, connection_id: u64, params: &GetParams) -> GetOutcome {
        // The limiter runs on EVERY probe, keyed by the handle, BEFORE resolution —
        // so an enumeration sweep of UNKNOWN handles (the probe itself is the attack
        // signal) trips the anomaly detector too, not only sweeps of resolvable
        // credentials. A resolved-only check would miss enumeration entirely.
        self.check_limiter(connection_id, &params.handle).await;

        let credential_id = match self.engine.store().resolve_handle(&params.handle) {
            Ok(id) => id,
            // Unknown or revoked handle → uniform not_found.
            Err(StoreOpError::NotFound) => return err(ReadError::NotFound),
            Err(e) => return err(map_store_error(&e)),
        };

        match self
            .engine
            .get(&credential_id, params.min_ttl_ms, params.force_refresh)
            .await
        {
            Ok(record) => {
                if record.payload.is_empty() {
                    // A successful zero-byte credential is a corrupt producer state, not
                    // an authentication token. Quarantine only the version we inspected:
                    // a concurrent refresh/login may already have repaired the record.
                    match self
                        .engine
                        .store()
                        .quarantine_if_version(&credential_id, record.record_version)
                    {
                        Ok(true) => return err(ReadError::Corrupt),
                        // The record changed under us. Do not poison the fresh version or
                        // misclassify it as corrupt; a retry will read the replacement.
                        Ok(false) => return err(ReadError::RefreshFailed),
                        Err(e) => return err(map_store_error(&e)),
                    }
                }

                // For an antigravity credential, surface the non-secret Code-Assist
                // project id (split from the packed refresh token) so the consumer can
                // freeze it into its render config. Never exposes the refresh token.
                let is_antigravity = record.refresh_adapter.as_deref()
                    == Some(credentials_core::refresh_adapters::antigravity::ADAPTER_NAME);
                let project_id = if is_antigravity {
                    record.oauth.as_ref().and_then(|o| {
                        credentials_core::refresh_adapters::antigravity::effective_project_id(
                            &o.refresh_token,
                        )
                    })
                } else {
                    None
                };
                // The non-secret provider account identity the served token executes
                // under, parsed live from the served access token via the per-provider
                // claim table (keyed by the record's stored refresh adapter). Absent for
                // a static api-key record (no adapter) or a provider with no account
                // claim. This is the binding key an account-scoped router joins on.
                // Live claim parse first (self-correcting across refreshes for JWT
                // providers), stored login-time identity as the fallback for opaque-token
                // providers (Anthropic). QTA invariant: email never ships without
                // account_id — both come from the same stored identity when the live
                // parse has nothing.
                let account_id = match (&record.refresh_adapter, &record.oauth) {
                    (Some(adapter), Some(o)) => {
                        credentials_core::oauth_login::account_id_for_adapter(
                            adapter,
                            &o.access_token,
                        )
                    }
                    _ => None,
                }
                .or_else(|| record.identity.account_id.clone());
                GetOutcome::Ok(GetResult {
                    payload: record.payload,
                    expires_at_ms: record.expires_at_ms,
                    record_version: record.record_version,
                    project_id,
                    account_id,
                    email: record.identity.email.clone(),
                    org_name: record.identity.org_name.clone(),
                })
            }
            Err(e) => err(map_engine_error(&e)),
        }
    }

    /// Serve a `get_many`: reject over-cap, else serve each item (independent
    /// outcomes — one failing credential does not fail the batch).
    pub async fn get_many(&self, connection_id: u64, params: &GetManyParams) -> Vec<GetOutcome> {
        if params.items.len() > GET_MANY_MAX {
            return vec![err(ReadError::TooManyItems)];
        }
        let mut out = Vec::with_capacity(params.items.len());
        for item in &params.items {
            out.push(self.get(connection_id, item).await);
        }
        out
    }

    /// Report a consumer-observed auth failure: mark the credential needs_reauth so
    /// the next get does not serve the dead token. Rate-limited via the same
    /// limiter (a flood of reports is itself an anomaly). A 401/403 is the
    /// meaningful signal; other statuses are accepted but only a clear auth failure
    /// invalidates.
    pub async fn report_auth_failure(
        &self,
        connection_id: u64,
        params: &ReportAuthFailureParams,
    ) -> Result<(), ReadError> {
        // Rate-limit on the presented handle (before resolution), like get — a flood
        // of report_auth_failure (malicious invalidation DoS) is itself an anomaly.
        self.check_limiter(connection_id, &params.handle).await;

        let credential_id = match self.engine.store().resolve_handle(&params.handle) {
            Ok(id) => id,
            Err(StoreOpError::NotFound) => return Err(ReadError::NotFound),
            Err(e) => return Err(map_store_error(&e)),
        };

        // Only an authentication failure (401/403) invalidates; a 5xx/429 is a
        // provider hiccup, not a dead credential. The invalidate is VERSION-GATED: it
        // fires only if the credential is still at the record_version the consumer was
        // served, so a stale report for a since-refreshed credential is a silent no-op
        // (and a consumer can only ever kill the exact version it saw, not whatever is
        // current). The invalidate audits the revocation feedback in the chain atomically
        // (actor = the route channel; see below for why that is not a caller identity).
        if params.provider_status == 401 || params.provider_status == 403 {
            // The actor names the ROUTE CHANNEL, not the consumer. The number is
            // assigned to a route binding and reused as bindings come and go, so two
            // entries sharing `conn-1` are not evidence of the same reporter, and one
            // reporter across reconnects may appear under several numbers.
            //
            // Recorded because the chain reads like an identity and is not one: an
            // incident review asking WHO invalidated a credential gets a plausible
            // answer from this field and no warning that it cannot support the
            // question. A capability handle authorizes a read without identifying who
            // presented it, so for a caller that opens a bare connection there is
            // genuinely nothing better to write.
            //
            // NOT a claim that the identity is unavailable in general, which would be
            // too strong: `Principal::Reserved` carries a `module_id`, the daemon
            // stamps it at route-bind time, and this module already keeps it per
            // channel for the admin gate. This is reachable in production rather than
            // hypothetical -- the main consumer confirmed its client attaches
            // consumer_identity on every route.open, so the vault sees a named module
            // for real reports today and this code simply does not look.
            //
            // Whether it SHOULD look is a live question: recording a consumer's
            // identity against a credential failure is a different decision from
            // recording the failure. Until it is settled, establishing the reporter
            // needs a source outside this record.
            //
            // If it is ever wired: the launch nonce is NOT the value to store. It is
            // the secret a module echoes to prove it is the process entitled to claim
            // its id, and this store's plaintext columns are non-secret by
            // construction. A per-bind incarnation tag (derived, non-secret)
            // distinguishes a restarted process from a long-lived one without putting
            // an authentication token in a readable column.
            let actor = format!("conn-{connection_id}");
            self.engine
                .store()
                .invalidate_if_version_reported(
                    &credential_id,
                    params.record_version,
                    AuditCtx {
                        op: AuditOp::ReportAuthFailure,
                        actor: &actor,
                        alarm: None,
                    },
                    // The status is recorded because 401 and 403 mean different things
                    // -- a rejected token versus a forbidden request -- and the audit
                    // chain has no field for it, so previously both arrived here and
                    // were discarded, leaving an incident with no way to tell them
                    // apart afterwards.
                    Some(credentials_core::store::AuthObservation {
                        kind: "consumer_report",
                        provider_status: Some(params.provider_status),
                        detail: None,
                    }),
                )
                .map_err(|e| map_store_error(&e))?;
        }
        Ok(())
    }

    /// Non-secret status: per-handle health, or overall readiness when no handle.
    ///
    /// `lease_held`/`ready` reflect the fenced-out latch: a daemon that has lost the
    /// single-writer lease to a newer instance (`is_fenced_out`) reports `lease_held =
    /// false` and is never `ready`, so this status agrees with the health probe instead
    /// of always claiming a healthy lease. A handle probe runs the per-connection limiter
    /// FIRST (keyed by the presented handle, like `get`), so a status-based enumeration
    /// sweep of unknown handles trips the same anomaly alarm rather than slipping past it.
    pub async fn status(&self, connection_id: u64, params: &StatusParams) -> StatusResult {
        let fenced_out = self.engine.store().is_fenced_out();
        let lease_held = !fenced_out;

        let handle = match &params.handle {
            // Overall readiness: ready iff we still hold write authority. No handle to
            // key the limiter on, and nothing to enumerate, so no limiter run here.
            None => {
                return StatusResult {
                    ready: !fenced_out,
                    last_error_code: None,
                    lease_held,
                };
            }
            Some(h) => h,
        };

        // Rate-limit the handle probe before resolution (enumeration-sweep guard).
        self.check_limiter(connection_id, handle).await;

        match self.engine.store().resolve_handle(handle) {
            Ok(credential_id) => match self.engine.store().meta(&credential_id) {
                Ok(meta) => StatusResult {
                    // A fenced-out daemon is not ready even for an Active credential.
                    ready: !fenced_out
                        && matches!(meta.state, credentials_core::store::RecordState::Active),
                    last_error_code: match meta.state {
                        credentials_core::store::RecordState::NeedsReauth => {
                            Some(ReadError::NeedsReauth)
                        }
                        credentials_core::store::RecordState::Corrupt => Some(ReadError::Corrupt),
                        credentials_core::store::RecordState::Active => None,
                    },
                    lease_held,
                },
                Err(_) => StatusResult {
                    ready: false,
                    last_error_code: Some(ReadError::NotFound),
                    lease_held,
                },
            },
            Err(_) => StatusResult {
                ready: false,
                last_error_code: Some(ReadError::NotFound),
                lease_held,
            },
        }
    }

    /// The subc L3 health reply: return the PRECOMPUTED snapshot. This is the
    /// probe path, so it must be cheap and in-memory (spec §2) — it does NOT touch
    /// the store, keychain, or lease. The snapshot is kept current by
    /// [`Self::refresh_health`] on a background cadence off this path.
    pub fn health_snapshot(&self) -> VaultHealth {
        // The lock guards a trivial clone with no await held; poisoning can only
        // happen if a refresher panicked mid-write, in which case the last-good
        // snapshot under the guard is still a valid read.
        let mut snapshot = self
            .health
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        // Liveness gate, computed LIVE here (never stored in the snapshot): if the
        // refresher has not completed a scan within the stale limit, it has wedged or
        // died, and the cached snapshot is no longer trustworthy — fail closed to
        // `Failing` rather than keep reporting a possibly-healthy frozen snapshot. This
        // is what turns a silent refresher death into an alert instead of a mask.
        let age = now_ms().saturating_sub(
            self.last_refresh_ms
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        if age > HEALTH_STALE_LIMIT_MS {
            snapshot.mark_refresher_stalled();
        }
        snapshot
    }

    /// Test seam: backdate the last-refresh clock so the probe's liveness gate treats
    /// the refresher as stalled, without a real 20s wait. Mirrors the `with_raw_conn`
    /// test-only discipline — not part of the production surface.
    #[cfg(test)]
    pub(crate) fn force_stale_refresher_for_test(&self) {
        self.last_refresh_ms.store(
            now_ms() - (HEALTH_STALE_LIMIT_MS * 2),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Recompute the domain health from the store and store it as the new cached
    /// snapshot. Called OFF the probe path — at boot and on the background cadence —
    /// so the live store reads here never block a health.check reply. Stamps the
    /// last-refresh clock on success so the probe can detect a wedged/dead refresher.
    pub fn refresh_health(&self) {
        let fresh = Self::compute_health(&self.engine);
        *self.health.lock().unwrap_or_else(|p| p.into_inner()) = fresh;
        self.last_refresh_ms
            .store(now_ms(), std::sync::atomic::Ordering::Relaxed);
    }

    /// The actual domain-health computation: a no-decrypt `list_meta` scan plus the
    /// open-intent count and the fenced-out latch. A failed scan means the store is
    /// unreadable (lost lease / gone db) — the vault's real serving-inability signal
    /// and the only read-derived `Failing` trigger. Runs off the probe path only.
    fn compute_health(engine: &RefreshEngine) -> VaultHealth {
        let store = engine.store();
        let metas = match store.list_meta() {
            Ok(metas) => metas,
            Err(_) => return VaultHealth::unreadable(),
        };
        // Open intents are carried as an opaque metric only (a transient in-flight
        // refresh holds one open), so a scan failure here must not flip serving
        // health — default to 0 rather than masking a readable store as failing.
        let open_intents = store.list_intents().map(|i| i.len()).unwrap_or(0);
        VaultHealth::summarize(&metas, open_intents, store.is_fenced_out())
    }

    /// Run the per-connection limiter for one probe, keyed by `probe_key` (the
    /// presented handle — so the distinct-spread counts distinct handles probed,
    /// resolvable or not). On the FIRST anomaly crossing for a connection, raise a
    /// durable rate-anomaly audit alarm. The alarm is connection-scoped
    /// (`credential_id: None`): an enumeration sweep is about the CONNECTION's
    /// behavior, and the probed handles may not map to any real credential.
    async fn check_limiter(&self, connection_id: u64, probe_key: &str) {
        let admission = {
            let mut limiter = self.limiter.lock().await;
            limiter.admit(connection_id, probe_key, Instant::now())
        };
        // This writes an EVENT to the audit chain, not a state transition, and it is
        // correct that it does -- which is worth stating, because the sibling rule on
        // the invalidate path is the opposite and someone applying it here would break
        // this.
        //
        // There, a consumer repeating a report about an unchanged credential was
        // restating one fact, and each restatement appended to a log that can never be
        // trimmed; the fix was to require an actual state change. Here `first` is
        // per-connection and resets when the connection drops, so a reconnecting
        // sweeper does append a fresh entry per session -- deliberately. Two anomalous
        // sessions are two events, not one fact stated twice, and collapsing them
        // would hide exactly the pattern this detects: someone reconnecting to evade a
        // per-connection ceiling.
        //
        // The bound is that reaching it costs a real sweep (the ceilings are distinct
        // handles and fetch rate within a window), so entries track attacker effort
        // rather than being free to emit.
        if let Admission::Anomaly { first: true } = admission {
            let _ = self.engine.store().append_audit(&AuditRecord {
                op: AuditOp::FetchAnomaly,
                credential_id: None,
                payload_hash: None,
                actor: format!("conn-{connection_id}"),
                alarm: Some(AlarmReason::FetchRateAnomaly),
            });
        }
    }

    /// Forget a closed connection's limiter state.
    pub async fn drop_connection(&self, connection_id: u64) {
        self.limiter.lock().await.drop_connection(connection_id);
    }
}

fn err(code: ReadError) -> GetOutcome {
    GetOutcome::Err {
        error: ErrorBody {
            code,
            class: code.class(),
        },
    }
}

/// Map a store error to a non-secret read code (fail-closed; never leaks detail).
///
/// WIDENING WHAT MAPS TO `NotFound` DELETES LIVE CONSUMER CONFIGURATION. A
/// consumer told `permanent` + `not_found` is entitled to conclude the credential
/// is gone and act on it: ck-quota reaps a dangling handle out of its own config
/// file on exactly that answer, on the strength of a guarantee this vault gave
/// them — that a vault OUTAGE can never produce it, because `resolve_handle`
/// returns `NotFound` only on a clean zero-row read.
///
/// So the catch-all's direction is load-bearing, and the edit that breaks it is a
/// tidy-up rather than a blunder: rewriting this match toward "an unknown id means
/// not found" is a reasonable simplification that silently inverts a cross-repo
/// promise. It is pinned by `an_unmapped_store_error_is_never_permanent`, which
/// exists because that mutation once left the entire workspace green.
fn map_store_error(e: &StoreOpError) -> ReadError {
    use credentials_core::envelope::EnvelopeError;
    match e {
        StoreOpError::NotFound => ReadError::NotFound,
        StoreOpError::NeedsReauth => ReadError::NeedsReauth,
        // A key-mismatch decrypt failure means the daemon's loaded master key no
        // longer matches this record — a master-key rotation landed (via the offline
        // CLI) while the daemon was running, so the daemon's key is stale. That is a
        // vault-locked condition from the consumer's view (back off; the daemon must
        // restart to pick up the new key), distinct from genuine record corruption.
        StoreOpError::Decrypt(EnvelopeError::KeyMismatch { .. }) => ReadError::VaultLocked,
        StoreOpError::Quarantined | StoreOpError::Corrupt(_) | StoreOpError::Decrypt(_) => {
            ReadError::Corrupt
        }
        _ => ReadError::RefreshFailed,
    }
}

/// Map an engine error to a non-secret read code.
fn map_engine_error(e: &EngineError) -> ReadError {
    match e {
        EngineError::Store(se) => map_store_error(se),
        EngineError::UnknownAdapter(_) => ReadError::RefreshUnsupported,
        // A definitively dead refresh token: the adapter already marked the record
        // needs_reauth (no rotation can recover it), so this is the AUTHORITATIVE
        // needs-reauth signal — surface it on THIS call, not the next. Returning a
        // transient RefreshFailed here would cost the consumer a wasted retry and
        // mislabel the signal; needs_reauth lets it pause for re-auth immediately.
        EngineError::RefreshFailed(RefreshError::InvalidGrant(_)) => ReadError::NeedsReauth,
        // Every other refresh failure (transport, decode, unexpected status,
        // entitlement) is transient/ambiguous and the record is left active ⇒ retry.
        EngineError::RefreshFailed(_) => ReadError::RefreshFailed,
    }
}

#[cfg(test)]
mod error_class_tests {
    use super::*;

    /// Golden conformance: this producer's serde wire strings for `ErrorClass` match
    /// the pinned contract set exactly (order-independent, no extras, no misses). If a
    /// contract change ever alters the set, this fails loudly instead of drifting.
    #[test]
    fn error_class_wire_strings_match_pinned_set() {
        let all = [
            ErrorClass::Transient,
            ErrorClass::Permanent,
            ErrorClass::AuthRequired,
            ErrorClass::ContextOverflow,
        ];
        let mut emitted: Vec<String> = all
            .iter()
            .map(|c| {
                let s = serde_json::to_string(c).expect("serialize class");
                s.trim_matches('"').to_string()
            })
            .collect();
        emitted.sort_unstable();
        let mut pinned: Vec<String> = ERROR_CLASS_WIRE_SET.iter().map(|s| s.to_string()).collect();
        pinned.sort_unstable();
        assert_eq!(
            emitted, pinned,
            "ErrorClass wire strings drifted from the pinned contract set"
        );
    }

    /// An UNMAPPED store error degrades to a TRANSIENT code, never a permanent one.
    ///
    /// This is the property a cross-repo consumer's destructive behaviour rests on,
    /// which is why it is pinned separately from the classification table. A vault
    /// outage must not be able to surface as `not_found`: `resolve_handle` returns
    /// `NotFound` only on a clean zero-row read, and every other store failure has to
    /// land somewhere retryable. A consumer told `permanent` + `not_found` is entitled
    /// to conclude the credential is GONE and act on it -- ck-quota reaps a dangling
    /// handle from its config on exactly that answer.
    ///
    /// So the catch-all arm's DIRECTION is load-bearing. Measured: changing
    /// `_ => RefreshFailed` to `_ => NotFound` left the entire workspace green, and
    /// would have turned every unmapped store error into a permanent verdict that
    /// deletes live consumer configuration.
    ///
    /// The test asserts the direction rather than the specific code, because the
    /// contract that matters is "unknown failures are retryable", not which retryable
    /// arm they pick.
    #[test]
    fn an_unmapped_store_error_is_never_permanent() {
        // A store error with no explicit arm in `map_store_error`. Chosen because it is
        // an infrastructure failure -- exactly the outage shape a consumer must not read
        // as an absent credential.
        // `Store` is the underlying storage/backend error -- the actual outage shape,
        // and it has no explicit arm in `map_store_error`.
        let unmapped = StoreOpError::Store("disk went away".into());
        let code = map_store_error(&unmapped);
        assert_eq!(
            code.class(),
            ErrorClass::Transient,
            "an unmapped store error surfaced as {code:?} ({:?}). A consumer treats \
             permanent as 'this credential is gone' and acts destructively on it, so \
             the catch-all must degrade toward RETRY, never toward a verdict.",
            code.class()
        );

        // The positive control: a genuine zero-row read IS permanent, so the assertion
        // above is about the catch-all rather than about classification refusing
        // everything.
        assert_eq!(
            map_store_error(&StoreOpError::NotFound).class(),
            ErrorClass::Permanent,
            "a real not-found must stay permanent, or the guard above proves nothing"
        );
    }

    /// Every ReadError code maps to the contract class the vault produced it as.
    /// This is the vault-side classification table, asserted so a new ReadError arm
    /// cannot ship without a deliberate class decision (match is exhaustive) and an
    /// existing arm cannot silently change class.
    #[test]
    fn read_error_classification_table() {
        assert_eq!(ReadError::NotFound.class(), ErrorClass::Permanent);
        assert_eq!(ReadError::Corrupt.class(), ErrorClass::Permanent);
        assert_eq!(ReadError::RefreshUnsupported.class(), ErrorClass::Permanent);
        assert_eq!(ReadError::NeedsReauth.class(), ErrorClass::AuthRequired);
        assert_eq!(ReadError::RefreshFailed.class(), ErrorClass::Transient);
        assert_eq!(ReadError::VaultLocked.class(), ErrorClass::Transient);
        assert_eq!(ReadError::TooManyItems.class(), ErrorClass::ContextOverflow);
    }

    /// The wire body carries BOTH the producer detail (`code`) and the produced class,
    /// and they are consistent — a consumer branching on `class` alone gets the same
    /// decision the vault would make.
    #[test]
    fn error_body_carries_consistent_class() {
        let out = err(ReadError::NeedsReauth);
        let json = serde_json::to_string(&out).expect("serialize outcome");
        assert!(
            json.contains("\"code\":\"needs_reauth\""),
            "detail code missing: {json}"
        );
        assert!(
            json.contains("\"class\":\"auth_required\""),
            "class tag missing: {json}"
        );
    }
}
