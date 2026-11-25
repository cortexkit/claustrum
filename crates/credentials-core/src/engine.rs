//! The crash-safe OAuth refresh engine: single-flight refresh-on-read and startup
//! reconciliation, built on the store's durable intent log.
//!
//! ## The refresh state machine (per credential)
//!
//! 1. **Intent (txn1, fsynced):** before calling the provider, durably record a
//!    `refresh_intent` (the version refreshed from + a hash of the refresh token).
//! 2. **Call:** the adapter exchanges the refresh token at the provider; the new
//!    tokens are staged in memory only.
//! 3. **Commit (txn2, fenced + fsynced):** write the new tokens at `version + 1`
//!    and clear the intent in ONE transaction. Only post-commit is the new payload
//!    visible to a `get`.
//!
//! A crash between step 1 and step 3 leaves a dangling intent that reconciliation
//! resolves fail-safe. A lease handover that fences step 3 (`StoreError::Fenced`)
//! leaves the EXACT same durable state as that crash — a dangling intent + the old
//! tokens — so a single reconciliation path covers both (the convergence property).
//! A failed commit in a live engine leaves the same uncertainty. Reads that observe
//! an intent recheck it under the single-flight lock and refuse until reconciliation
//! or an admin replacement resolves it, even if the access token has not expired.
//!
//! ## Single-flight
//!
//! Per `credential_id`, an in-process async lock ensures N concurrent `get`s that
//! all see a stale token trigger EXACTLY ONE upstream refresh: the first holder
//! refreshes and commits `version + 1`; every waiter then observes the bumped
//! version and returns the fresh record without a second upstream call.
//!
//! ## Startup reconciliation (boot gate)
//!
//! On boot, before the read surface serves any `get`, reconciliation scans the
//! intent log and resolves every dangling intent. This is safe because the vault's
//! single-writer lease means a replacement instance cannot acquire the database
//! (and thus cannot serve) until the previous instance has released it — so every
//! intent a crashed/superseded instance left is on disk before this scan runs, and
//! no `get` is served until each is resolved. Runtime intents (a refresh in flight
//! right now) are never touched by reconciliation; they are governed purely by
//! single-flight.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use crate::audit::{AlarmReason, AuditCtx, AuditOp, AuthEventKind};
use crate::oauth::OAuthCredential;
use crate::record::VaultRecord;
use crate::refresh_adapters::{HttpTransport, RefreshAdapter, RefreshError, ValidityOutcome};
use crate::store::{
    refresh_token_hash, AuthObservation, EncryptedStore, RefreshIntent, StoreOpError,
};

/// Default clock skew (ms) treated as "about to expire": a token within this of
/// its expiry is refreshed proactively so a call does not start on a token that
/// expires mid-flight.
pub const DEFAULT_EXPIRY_SKEW_MS: i64 = 60_000;

/// How long after a credential's current version was written a consumer's stale
/// report may NOT force a refresh.
///
/// A report (`credential.report_auth_failure`) marks the token `stale_pending`, and
/// the next read would refresh it. A consumer that misreads provider refusals as bad
/// tokens reports every one, and each report used to cost an upstream exchange:
/// measured, 43 refreshes of one ChatGPT login in a day, 11 of them in 22 seconds.
/// OpenAI, Anthropic and antigravity rotate the refresh token on every exchange and
/// revoke the whole token family on reuse, so a burst endangers the login itself.
///
/// Inside the window a stale-marked read serves the current token and makes no
/// upstream call; the mark is kept, so the first read after the window refreshes
/// without the consumer reporting again. Only the report path is held back: a token
/// that is expiring, empty, or shorter than the caller's `min_ttl_ms` refreshes as
/// before. The window is half-open: a version written exactly this long ago
/// refreshes.
pub const REPORT_REFRESH_COOLDOWN_MS: i64 = 60_000;

/// How a dangling intent was resolved by reconciliation. Returned so the caller
/// (the module) can drive the audit log / alarms; the resolution itself is already
/// applied to the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconciliation {
    /// A non-mutating validity check proved the stored refresh state still valid;
    /// the intent was cleared and the record left active.
    ClearedValid { credential_id: String },
    /// Resolved to `needs_reauth` and the intent cleared (the default for the v1
    /// adapters, which expose no non-mutating check; also an invalid check result
    /// or a corruption-guard hash mismatch). Carries why, for the audit alarm.
    NeedsReauth {
        credential_id: String,
        reason: ReauthReason,
    },
    /// A non-mutating check existed but could not be RUN (transient network); the
    /// record was marked `needs_reauth` to fail closed now, but the intent was
    /// RETAINED so a later retry can re-check and restore it. Dormant in v1 (no
    /// adapter has a check).
    Retained { credential_id: String },
    /// The intent referenced a credential that no longer exists (or was already
    /// resolved); the orphan intent was cleared, nothing else to do.
    OrphanCleared { credential_id: String },
}

/// Why a dangling intent resolved to `needs_reauth` (for the audit alarm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReauthReason {
    // Note for anyone adding a variant: [`ReauthReason::as_str`] is written to a
    // durable diagnostics row, so a name here becomes a stored value an operator
    // reads after an incident. Keep them short and descriptive of the CAUSE.
    /// No non-mutating validity check exists for this adapter (the v1 default): an
    /// interrupted rotation is INDETERMINATE, so fail safe to re-login.
    NoValidityCheck,
    /// A non-mutating check ran and proved the stored refresh state invalid.
    CheckInvalid,
    /// The stored refresh token's hash did not match the intent's — a write
    /// occurred without clearing the intent (rogue / corruption guard).
    HashMismatch,
}

impl ReauthReason {
    /// The stable string recorded for this reason.
    ///
    /// Distinct from `Debug` because this value is persisted: a rename of the variant
    /// must not silently change what past rows meant.
    pub fn as_str(self) -> &'static str {
        match self {
            ReauthReason::NoValidityCheck => "no_validity_check",
            ReauthReason::CheckInvalid => "check_invalid",
            ReauthReason::HashMismatch => "hash_mismatch",
        }
    }
}

/// A refresh-on-read failure surfaced to the read surface.
#[derive(Debug)]
pub enum EngineError {
    /// The underlying store failed (typed; includes `Fenced`, `NeedsReauth`, ...).
    Store(StoreOpError),
    /// The refresh adapter named by the record is not registered.
    UnknownAdapter(String),
    /// The provider refused or the refresh could not complete. The stored record
    /// is unchanged (or marked `needs_reauth` on a definitively dead token).
    RefreshFailed(RefreshError),
}

/// A credential served by [`RefreshEngine::get_with_refresh_status`].
///
/// `refreshed_for_min_ttl` lets the caller check its floor against a freshly
/// exchanged token. A read can perform that exchange or join another reader's
/// exchange. A higher record version alone does not establish that one occurred.
#[derive(Debug)]
pub struct GetWithRefreshStatus {
    /// Internal lifetime of the row read; never projected onto consumer replies.
    pub incarnation: String,
    pub record: VaultRecord,
    pub refreshed_for_min_ttl: bool,
    /// An unmapped plan stored by this read's successful refresh commit. Diagnostic
    /// data for the daemon only; never projected onto consumer replies.
    pub unmapped_plan: Option<UnmappedPlanObservation>,
    /// On the engine clock, when a refresh this read wanted becomes allowed: set only
    /// when the report cooldown held that refresh back. A caller that can only answer
    /// with durations subtracts engine-clock now to get the time left.
    pub refresh_deferred_until_ms: Option<i64>,
    /// Lowercase-hex SHA-256 of the exact encrypted bytes this read served, taken from
    /// the same row read as `record`.
    ///
    /// It identifies one stored VERSION of the material, not just a version number: a
    /// delete and re-create of the id restarts `record_version` at 1, so a caller that
    /// must recognise "the same bytes I already accounted for" needs this digest. Read
    /// beside the record and never recomputed from it, so the two cannot describe
    /// different rows.
    pub stored_digest_hex: String,
}

/// Provider plan metadata only: no tokens, headers or account identity. The raw
/// string is untrusted provider text; the daemon must escape and bound its output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmappedPlanObservation {
    pub credential_id: String,
    pub provider: &'static str,
    pub raw: String,
}

impl UnmappedPlanObservation {
    fn committed(credential_id: &str, record: &VaultRecord) -> Option<Self> {
        let provider = match record.refresh_adapter.as_deref()? {
            "anthropic" => "anthropic",
            "openai" => "chatgpt",
            _ => return None,
        };
        let plan = record.detected_plan.as_ref()?;
        if plan.tier.is_some() {
            return None;
        }
        Some(Self {
            credential_id: credential_id.to_owned(),
            provider,
            raw: plan.raw.clone()?,
        })
    }
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Store(e) => write!(f, "{e}"),
            EngineError::UnknownAdapter(n) => write!(f, "no refresh adapter named '{n}'"),
            EngineError::RefreshFailed(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<StoreOpError> for EngineError {
    fn from(e: StoreOpError) -> Self {
        EngineError::Store(e)
    }
}

/// The refresh engine: owns the encrypted store, the adapter registry, the HTTP
/// transport, and the per-credential single-flight locks.
#[derive(Clone)]
pub struct RefreshEngine {
    store: Arc<EncryptedStore>,
    adapters: Arc<HashMap<String, Arc<dyn RefreshAdapter>>>,
    http: Arc<dyn HttpTransport>,
    skew_ms: i64,
    // The wall clock the report cooldown is measured against. Real time in
    // production; replaceable through `with_clock` so a test can stand at an exact
    // offset from a record's write time. Only the cooldown reads it: expiry checks
    // keep the real clock, so a test pinning the cooldown cannot move expiry.
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    // Per-credential single-flight locks, created on demand. The map mutex is held
    // only to prune/look up/insert a lock handle (never across an await); the per-id
    // tokio mutex is the one held across the refresh await. Weak entries let unused
    // ids be reclaimed without evicting locks still owned by holders or waiters.
    inflight: Arc<Mutex<HashMap<String, InflightEntry>>>,
    // Test-only crash seam: fired AFTER the intent is durably committed and the new
    // tokens are staged, but BEFORE the commit transaction. The kill-9 conformance
    // helper sets this to a closure that signals readiness and parks forever, so a
    // parent test can SIGKILL it at exactly the response->commit gap. Compiled in
    // ONLY under the `kill9-test-seam` feature, so the release vault has no
    // block-before-commit path at all.
    #[cfg(feature = "kill9-test-seam")]
    pre_commit: Arc<Mutex<Option<PreCommitHook>>>,
    #[cfg(test)]
    after_snapshot: Arc<Mutex<Option<AfterSnapshotHook>>>,
    #[cfg(any(test, feature = "test-support"))]
    before_flight_wait: Arc<Mutex<Option<BeforeFlightWaitHook>>>,
    #[cfg(test)]
    credential_opens: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    plan_observation_finished: Arc<tokio::sync::Notify>,
}

#[cfg(feature = "kill9-test-seam")]
type PreCommitHook = Box<dyn Fn() + Send + Sync>;
#[cfg(test)]
type AfterSnapshotHook = Box<dyn FnOnce() + Send>;
#[cfg(any(test, feature = "test-support"))]
type BeforeFlightWaitHook = Box<dyn FnOnce() + Send>;

struct InflightEntry {
    lock: Weak<tokio::sync::Mutex<()>>,
    last_refresh: Option<(String, u64)>,
}

impl RefreshEngine {
    /// Build an engine over a store, an adapter registry, and an HTTP transport.
    pub fn new(
        store: Arc<EncryptedStore>,
        adapters: Vec<Arc<dyn RefreshAdapter>>,
        http: Arc<dyn HttpTransport>,
    ) -> Self {
        let adapters = adapters
            .into_iter()
            .map(|a| (a.name().to_string(), a))
            .collect();
        RefreshEngine {
            store,
            adapters: Arc::new(adapters),
            http,
            skew_ms: DEFAULT_EXPIRY_SKEW_MS,
            clock: Arc::new(now_ms),
            inflight: Arc::default(),
            #[cfg(feature = "kill9-test-seam")]
            pre_commit: Arc::default(),
            #[cfg(test)]
            after_snapshot: Arc::default(),
            #[cfg(any(test, feature = "test-support"))]
            before_flight_wait: Arc::default(),
            #[cfg(test)]
            credential_opens: Arc::default(),
            #[cfg(test)]
            plan_observation_finished: Arc::default(),
        }
    }

    /// Install the test-only pre-commit hook (see the field docs). Available only
    /// under the `kill9-test-seam` feature; the kill-9 helper uses it to park.
    #[cfg(feature = "kill9-test-seam")]
    pub fn set_pre_commit_hook(&self, hook: Box<dyn Fn() + Send + Sync>) {
        *self.pre_commit.lock().unwrap_or_else(|p| p.into_inner()) = Some(hook);
    }

    #[cfg(test)]
    pub(crate) fn set_after_snapshot_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.after_snapshot.lock().unwrap() = Some(Box::new(hook));
    }

    #[cfg(test)]
    pub(crate) fn credential_opens_for_test(&self) -> usize {
        self.credential_opens
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) async fn wait_for_plan_observation_for_test(&self) {
        self.plan_observation_finished.notified().await;
    }

    /// Signal when a get queues for a held single-flight lock.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_before_flight_wait_hook_for_test(&self, hook: impl FnOnce() + Send + 'static) {
        *self.before_flight_wait.lock().unwrap() = Some(Box::new(hook));
    }

    /// Override the expiry skew (mostly for tests).
    pub fn with_skew_ms(mut self, skew_ms: i64) -> Self {
        self.skew_ms = skew_ms;
        self
    }

    /// Replace the clock the report cooldown is measured against (for tests). It
    /// returns Unix milliseconds, the unit of the store's `updated_at_ms`.
    pub fn with_clock(mut self, clock: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// The underlying store (for the module's read/admin surfaces).
    pub fn store(&self) -> &Arc<EncryptedStore> {
        &self.store
    }

    async fn blocking_store<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&EncryptedStore) -> Result<T, StoreOpError> + Send + 'static,
    ) -> Result<T, StoreOpError> {
        let store = Arc::clone(&self.store);
        #[cfg(test)]
        let credential_opens = Arc::clone(&self.credential_opens);
        tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            let before = crate::store::CREDENTIAL_OPEN_COUNT.get();
            let result = operation(&store);
            #[cfg(test)]
            credential_opens.fetch_add(
                crate::store::CREDENTIAL_OPEN_COUNT.get() - before,
                std::sync::atomic::Ordering::Relaxed,
            );
            result
        })
        .await
        .map_err(|_| StoreOpError::Store("vault store task failed".into()))?
    }

    /// Read a credential, refreshing first if it is stale (or `force_refresh`).
    ///
    /// `min_ttl_ms`: if set, a token with less than this remaining is refreshed.
    /// Refresh is single-flight per credential. A non-refreshable record is served
    /// as-is unless it carries a consumer report marker, which must terminally latch
    /// because no refresh path can recover it. A refreshable record carrying that
    /// marker refreshes unless its current version was written inside
    /// [`REPORT_REFRESH_COOLDOWN_MS`]; then it is served as-is until the window passes.
    /// Fails closed on a
    /// `needs_reauth`/quarantined record (the store's typed errors propagate).
    pub async fn get(
        &self,
        credential_id: &str,
        min_ttl_ms: Option<i64>,
        force_refresh: bool,
    ) -> Result<VaultRecord, EngineError> {
        self.get_with_refresh_status(credential_id, min_ttl_ms, force_refresh)
            .await
            .map(|result| result.record)
    }

    /// Read a credential and report whether its minimum-TTL demand was evaluated
    /// against an exchange, including one shared with another reader. An admin
    /// replacement is not an exchange.
    pub async fn get_with_refresh_status(
        &self,
        credential_id: &str,
        min_ttl_ms: Option<i64>,
        force_refresh: bool,
    ) -> Result<GetWithRefreshStatus, EngineError> {
        self.get_for_incarnation(credential_id, None, min_ttl_ms, force_refresh)
            .await
    }

    /// Serve only the row lifetime admitted by handle resolution or authorization.
    pub async fn get_in_incarnation(
        &self,
        credential_id: &str,
        incarnation: &str,
        min_ttl_ms: Option<i64>,
        force_refresh: bool,
    ) -> Result<GetWithRefreshStatus, EngineError> {
        self.get_for_incarnation(credential_id, Some(incarnation), min_ttl_ms, force_refresh)
            .await
    }

    async fn get_for_incarnation(
        &self,
        credential_id: &str,
        expected_incarnation: Option<&str>,
        min_ttl_ms: Option<i64>,
        force_refresh: bool,
    ) -> Result<GetWithRefreshStatus, EngineError> {
        // Retain the entry before reading SQLite so a refresh that finishes
        // before we can wait still leaves its committed version for us to check.
        let lock = self.inflight_lock(credential_id);
        let id = credential_id.to_owned();
        let expected = expected_incarnation.map(str::to_owned);
        #[cfg(test)]
        let after_snapshot = Arc::clone(&self.after_snapshot);
        let initial = self
            .blocking_store(move |store| {
                let snapshot = match expected {
                    Some(incarnation) => store.get_snapshot(&id, &incarnation)?,
                    None => store.get_with_stale_pending_and_digest(&id)?,
                };
                #[cfg(test)]
                {
                    let hook = after_snapshot.lock().unwrap().take();
                    if let Some(hook) = hook {
                        hook();
                    }
                }
                Ok(snapshot)
            })
            .await?;
        let incarnation = initial.incarnation.clone();
        // Use the intent from the record snapshot: a later lookup could observe it
        // cleared by a refresh that just invalidated the record we read.
        let wants_refresh =
            force_refresh || initial.mark.pending || self.is_stale(&initial.record, min_ttl_ms);
        if !initial.has_refresh_intent && !wants_refresh {
            return Ok(GetWithRefreshStatus {
                incarnation,
                record: initial.record,
                refreshed_for_min_ttl: false,
                unmapped_plan: None,
                refresh_deferred_until_ms: None,
                stored_digest_hex: initial.stored_digest_hex,
            });
        }
        let initial_version = initial.record.record_version;
        let waiting = lock.lock_owned();
        #[cfg(any(test, feature = "test-support"))]
        let waiting = async move {
            use std::future::Future;
            tokio::pin!(waiting);
            std::future::poll_fn(|cx| {
                let result = waiting.as_mut().poll(cx);
                if result.is_pending() {
                    let hook = self.before_flight_wait.lock().unwrap().take();
                    if let Some(hook) = hook {
                        hook();
                    }
                }
                result
            })
            .await
        };
        let guard = waiting.await;
        let engine = self.clone();
        let id = credential_id.to_owned();
        // An admitted exchange owns the lock through the intent, provider call,
        // commit and version stamp. Dropping the reader must not drop that flight.
        tokio::spawn(async move {
            let _guard = guard;
            engine
                .get_locked(&id, incarnation, initial_version, min_ttl_ms, force_refresh)
                .await
        })
        .await
        .map_err(|_| StoreOpError::Store("vault refresh task failed".into()))?
    }

    async fn get_locked(
        &self,
        credential_id: &str,
        incarnation: String,
        initial_version: u64,
        min_ttl_ms: Option<i64>,
        force_refresh: bool,
    ) -> Result<GetWithRefreshStatus, EngineError> {
        let id = credential_id.to_owned();
        let admitted = incarnation.clone();
        let initial = self
            .blocking_store(move |store| store.get_snapshot(&id, &admitted))
            .await?;
        // An intent surviving the prior holder is unresolved just as it would be
        // at boot; a fresh access token cannot prove its refresh token survived.
        if initial.has_refresh_intent {
            return Err(StoreOpError::NeedsReauth.into());
        }
        // Only the exact record committed by a prior refresh can share its
        // exchange. An admin replacement must be evaluated on its own merits.
        if initial.record.record_version != initial_version
            && self.is_last_refresh(credential_id, &incarnation, initial.record.record_version)
        {
            return Ok(GetWithRefreshStatus {
                incarnation,
                record: initial.record,
                refreshed_for_min_ttl: min_ttl_ms.is_some(),
                unmapped_plan: None,
                refresh_deferred_until_ms: None,
                stored_digest_hex: initial.stored_digest_hex,
            });
        }
        let stale_pending = initial.mark.pending;
        if stale_pending && !initial.record.is_refreshable() {
            // A stale marker means a consumer already refused this exact token. A
            // non-refreshable record cannot replace it, so defer to the existing
            // version-fenced terminal transition rather than serving it again.
            let id = credential_id.to_owned();
            let admitted = incarnation.clone();
            let version = initial.record.record_version;
            let replacement = self
                .blocking_store(move |store| {
                    store.invalidate_in_incarnation(
                        &id,
                        version,
                        &admitted,
                        AuditCtx::vault(AuditOp::Invalidate),
                        Some(AuthObservation {
                            kind: AuthEventKind::StaleNonrefreshableLatch.as_str(),
                            provider_status: None,
                            detail: None,
                            reporter_source: None,
                            principal: None,
                        }),
                    )?;
                    // If a concurrent write moved the version, return the replacement.
                    store.get_snapshot(&id, &admitted)
                })
                .await?;
            return Ok(GetWithRefreshStatus {
                incarnation,
                record: replacement.record,
                refreshed_for_min_ttl: false,
                unmapped_plan: None,
                refresh_deferred_until_ms: None,
                stored_digest_hex: replacement.stored_digest_hex,
            });
        }
        let record_written_at_ms = initial.mark.record_written_at_ms;
        let served = initial;

        let refresh_requested_by_min_ttl = self.is_below_min_ttl(&served.record, min_ttl_ms);
        let wants_refresh =
            force_refresh || stale_pending || self.is_stale(&served.record, min_ttl_ms);
        if !wants_refresh || !served.record.is_refreshable() {
            return Ok(GetWithRefreshStatus {
                incarnation,
                record: served.record,
                refreshed_for_min_ttl: false,
                unmapped_plan: None,
                refresh_deferred_until_ms: None,
                stored_digest_hex: served.stored_digest_hex,
            });
        }

        // The report cooldown holds back ONLY a refresh the stale mark alone asks for:
        // never a forced read, and never a token that is empty, expiring, or short of
        // the caller's `min_ttl_ms`. The mark stays set, so the first read after the
        // window refreshes.
        if stale_pending
            && !force_refresh
            && !self.is_stale(&served.record, min_ttl_ms)
            && self.within_report_cooldown(record_written_at_ms)
        {
            // Best-effort: a diagnostic write must never fail the read it explains.
            let id = credential_id.to_owned();
            let version = served.record.record_version;
            let _ = self
                .blocking_store(move |store| store.record_stale_refresh_deferred(&id, version))
                .await;
            // The deferral ends exactly when the cooldown does, computed on the same
            // clock the cooldown test just ran on, so a caller that reports it as a
            // duration cannot drift from this read's own decision by clock skew.
            let deferred_until_ms = record_written_at_ms + REPORT_REFRESH_COOLDOWN_MS;
            return Ok(GetWithRefreshStatus {
                incarnation,
                record: served.record,
                refreshed_for_min_ttl: false,
                unmapped_plan: None,
                refresh_deferred_until_ms: Some(deferred_until_ms),
                stored_digest_hex: served.stored_digest_hex,
            });
        }

        let (record, stored_digest_hex) = self
            .do_refresh(credential_id, &incarnation, &served.record)
            .await?;
        self.stamp_refresh(credential_id, &incarnation, record.record_version);
        let unmapped_plan = UnmappedPlanObservation::committed(credential_id, &record);
        Ok(GetWithRefreshStatus {
            incarnation,
            record,
            refreshed_for_min_ttl: refresh_requested_by_min_ttl,
            unmapped_plan,
            refresh_deferred_until_ms: None,
            stored_digest_hex,
        })
    }

    /// Whether a record written at `written_at_ms` is still inside
    /// [`REPORT_REFRESH_COOLDOWN_MS`]. Half-open: exactly the cooldown later is outside.
    ///
    /// A write time AHEAD of the clock (the clock stepped backwards) counts as outside,
    /// so the read refreshes as it did before the cooldown existed. Counting it as
    /// inside would hold every reported token for as long as the clock was wrong.
    fn within_report_cooldown(&self, written_at_ms: i64) -> bool {
        let elapsed = (self.clock)().saturating_sub(written_at_ms);
        (0..REPORT_REFRESH_COOLDOWN_MS).contains(&elapsed)
    }

    /// Whether a record's access token is stale: empty, expired (within skew), or
    /// below the caller's `min_ttl_ms`.
    fn is_stale(&self, record: &VaultRecord, min_ttl_ms: Option<i64>) -> bool {
        let Some(oauth) = record.oauth.as_ref() else {
            return false;
        };
        // An empty access token is ALWAYS stale: a zero-byte token can never be served,
        // so it must trigger a refresh regardless of expiry. This is the first-get case
        // for a refresh-only login artifact (e.g. an antigravity account that stores
        // only the refresh token + lets the client mint the access token on first use).
        // Without this, a record with an empty access token AND no recorded expiry
        // falls through both checks below (is_access_expired treats no-expiry as
        // not-expired; the min_ttl branch needs Some(expires_at_ms)) and the empty
        // token is served as-is. `get` still gates the actual refresh on
        // `is_refreshable()`. The read surface quarantines a legacy non-refreshable
        // empty record rather than returning a successful zero-byte credential.
        if oauth.access_token.expose().is_empty() {
            return true;
        }
        let now = now_ms();
        if oauth.is_access_expired(now, self.skew_ms) {
            return true;
        }
        self.is_below_min_ttl(record, min_ttl_ms)
    }

    /// Whether a known expiry is at or below the caller's stated minimum. Credentials
    /// without an expiry do not make this claim: their lifetime is unknown, not proven
    /// too short.
    fn is_below_min_ttl(&self, record: &VaultRecord, min_ttl_ms: Option<i64>) -> bool {
        let Some(oauth) = record.oauth.as_ref() else {
            return false;
        };
        let (Some(min_ttl), Some(expires_at_ms)) = (min_ttl_ms, oauth.expires_at_ms) else {
            return false;
        };
        now_ms().saturating_add(min_ttl) >= expires_at_ms
    }

    /// Run ONE refresh (the leader path): txn1 intent → adapter call → txn2 commit.
    /// The caller holds the single-flight lock.
    async fn do_refresh(
        &self,
        credential_id: &str,
        incarnation: &str,
        record: &VaultRecord,
    ) -> Result<(VaultRecord, String), EngineError> {
        let oauth = record
            .oauth
            .as_ref()
            .expect("is_refreshable guaranteed oauth is present");
        let adapter_name = record
            .refresh_adapter
            .as_deref()
            .expect("is_refreshable guaranteed an adapter name");
        let adapter = self
            .adapters
            .get(adapter_name)
            .ok_or_else(|| EngineError::UnknownAdapter(adapter_name.to_string()))?;

        // txn1: durably record the intent BEFORE any network call.
        let old_hash = refresh_token_hash(oauth.refresh_token.expose());
        let id = credential_id.to_owned();
        let version = record.record_version;
        self.blocking_store(move |store| store.open_intent(&id, version, &old_hash))
            .await?;

        // The provider call (rotating). Tokens are staged in memory only.
        match adapter
            .refresh_for_record_with_metadata(credential_id, oauth, &*self.http)
            .await
        {
            Ok((tokens, _)) if tokens.access_token.expose().is_empty() => {
                // A successful provider response with no access token is not a valid
                // rotation. Clear the intent while preserving the old record and version; otherwise
                // the sealed record would later decrypt to a successful zero-byte read.
                let id = credential_id.to_owned();
                self.blocking_store(move |store| store.clear_intent(&id))
                    .await?;
                Err(EngineError::RefreshFailed(RefreshError::Decode(
                    "provider returned an empty access token".into(),
                )))
            }
            Ok((tokens, github_app)) => {
                // Only GitHub App mints return this vendor-specific diagnostic. Keep the
                // field out of every other refresh path even if an adapter is miswired.
                let is_github_app =
                    adapter_name == crate::refresh_adapters::github_app::ADAPTER_NAME;
                let github_app_permissions = is_github_app
                    .then(|| tokens.github_app_permissions.clone())
                    .flatten();
                let new_record = apply_refreshed(record, oauth, tokens);
                let is_anthropic = adapter_name == "anthropic";
                let id = credential_id.to_owned();
                let admitted = incarnation.to_owned();
                let previous = record.clone();
                #[cfg(feature = "kill9-test-seam")]
                let pre_commit = Arc::clone(&self.pre_commit);
                let (new_record, digest) = self
                    .blocking_store(move |store| {
                        let mut new_record = new_record;
                        if is_anthropic {
                            // Profiles survive a restart in a side table, but still ride the
                            // next token commit: a separate sealed write would invalidate a
                            // consumer's report_auth_failure version for the just-served token.
                            match store.held_detected_plan(&id, &previous) {
                                Ok(Some(plan)) => new_record.detected_plan = Some(plan),
                                Ok(None) => {}
                                Err(error) => {
                                    eprintln!(
                                "credential vault: could not read held detected plan: {error}"
                            );
                                }
                            }
                        }

                        // Test-only crash seam: the intent is durably committed and the new
                        // tokens are staged, but the commit transaction has NOT run. The
                        // kill-9 helper parks here so a parent test can SIGKILL it at exactly
                        // this point. No-op (and absent entirely) in a release build.
                        #[cfg(feature = "kill9-test-seam")]
                        {
                            let hook = pre_commit.lock().unwrap_or_else(|p| p.into_inner());
                            if let Some(hook) = hook.as_ref() {
                                hook();
                            }
                        }

                        // A failed fence or version check discards the staged tokens and leaves the current row alone.
                        store.commit_refresh_with_previous(
                            &id,
                            version,
                            &admitted,
                            Some(&previous),
                            new_record,
                            github_app.as_ref().filter(|_| is_github_app),
                        )
                    })
                    .await?;
                let record_version = new_record.record_version;
                if let ("anthropic", Some(new_oauth)) = (adapter_name, new_record.oauth.as_ref()) {
                    let http = self.http.clone();
                    let store = self.store.clone();
                    let id = credential_id.to_owned();
                    let access = new_oauth.access_token.clone();
                    let identity = new_record.identity.clone();
                    #[cfg(test)]
                    let finished = Arc::clone(&self.plan_observation_finished);
                    tokio::spawn(async move {
                        if let Ok(plan) =
                            crate::plan_detection::fetch_anthropic_plan(&*http, access.expose())
                                .await
                        {
                            let _ = tokio::task::spawn_blocking(move || {
                                if let Err(error) = store.hold_detected_plan(
                                    &id,
                                    record_version,
                                    &refresh_token_hash(access.expose()),
                                    &identity,
                                    &plan,
                                ) {
                                    eprintln!("credential vault: could not persist held detected plan: {error}");
                                }
                            }).await;
                        }
                        #[cfg(test)]
                        finished.notify_one();
                    });
                }
                if let Some(permissions) = github_app_permissions {
                    // Diagnostic persistence is deliberately non-fallible: a valid
                    // token has already committed and must be served even if this
                    // extra observation cannot be recorded.
                    let id = credential_id.to_owned();
                    let _ = self
                        .blocking_store(move |store| {
                            store.observe_github_app_permissions(&id, record_version, &permissions);
                            Ok(())
                        })
                        .await;
                }
                Ok((new_record, digest))
            }
            // The provider's verdict applies only to the version and incarnation it
            // saw. The admin lock prevents route admin writes during an exchange;
            // the store guard also protects replacements made without that lock.
            Err(e @ (RefreshError::InvalidGrant(_) | RefreshError::SubscriptionRequired)) => {
                let id = credential_id.to_owned();
                let admitted = incarnation.to_owned();
                let detail = e.variant_name();
                self.blocking_store(move |store| {
                    store.invalidate_in_incarnation(
                        &id,
                        version,
                        &admitted,
                        AuditCtx::vault(AuditOp::Invalidate),
                        Some(AuthObservation {
                            kind: AuthEventKind::RefreshFailed.as_str(),
                            provider_status: None,
                            detail: Some(detail),
                            reporter_source: None,
                            principal: None,
                        }),
                    )
                })
                .await?;
                Err(EngineError::RefreshFailed(e))
            }
            // A transient/ambiguous failure (transport, decode, unexpected status):
            // No usable tokens were received. Clear the intent so a later exchange
            // can recover if the provider did not consume the stored token. If the
            // provider rotated it and the reply was lost, the stored token is dead.
            // Even if reuse revokes the whole token family, its only live member is
            // the new refresh token the vault never received.
            Err(other) => {
                let id = credential_id.to_owned();
                let provider_status = other.provider_status();
                let detail = other.variant_name();
                self.blocking_store(move |store| {
                    store.clear_intent(&id)?;
                    // Record that the provider WAS called and refused, which nothing else
                    // does on this arm: the intent is cleared and the record left active,
                    // so a credential failing every refresh looked untouched from outside.
                    // Best-effort by construction -- a diagnostics write must never mask
                    // the provider failure being returned.
                    let _ = store.record_auth_event(
                        &id,
                        AuthObservation {
                            kind: AuthEventKind::RefreshFailed.as_str(),
                            provider_status,
                            detail: Some(detail),
                            reporter_source: None,
                            principal: None,
                        },
                        Some(version),
                    );
                    Ok(())
                })
                .await?;
                Err(EngineError::RefreshFailed(other))
            }
        }
    }

    /// Reconcile all dangling intents at boot (the boot gate). Resolves each per
    /// the decision table and returns the outcomes for the audit log. Call once,
    /// before the read surface serves any `get`.
    pub async fn reconcile(&self) -> Result<Vec<Reconciliation>, EngineError> {
        let intents = self.blocking_store(EncryptedStore::list_intents).await?;
        let mut outcomes = Vec::with_capacity(intents.len());
        for intent in intents {
            outcomes.push(self.reconcile_one(&intent).await?);
        }
        Ok(outcomes)
    }

    async fn reconcile_one(&self, intent: &RefreshIntent) -> Result<Reconciliation, EngineError> {
        let id = intent.credential_id.as_str();

        // A pending intent on the same needs_reauth version means an earlier
        // validity check did not complete. It remains eligible for reconciliation.
        let candidate = intent.clone();
        let (record, incarnation) = match self
            .blocking_store(move |store| store.get_for_reconciliation(&candidate))
            .await
        {
            Ok(snapshot) => snapshot,
            Err(StoreOpError::NotFound)
            | Err(StoreOpError::NeedsReauth)
            | Err(StoreOpError::Quarantined)
            | Err(StoreOpError::Decrypt(_))
            | Err(StoreOpError::Corrupt(_)) => {
                let orphan = id.to_owned();
                self.blocking_store(move |store| store.clear_intent(&orphan))
                    .await?;
                return Ok(Reconciliation::OrphanCleared {
                    credential_id: id.to_string(),
                });
            }
            Err(e) => return Err(EngineError::Store(e)),
        };

        // Corruption guard: a normal interrupted rotation leaves the stored record
        // unchanged (still the old refresh token), so its hash MUST match the
        // intent's. A mismatch means a write landed without clearing the intent —
        // fail closed regardless of any adapter check.
        if let Some(oauth) = record.oauth.as_ref() {
            let stored_hash = refresh_token_hash(oauth.refresh_token.expose());
            if stored_hash != intent.old_refresh_hash {
                // A write landed without clearing the intent — the rogue-write /
                // interrupted-rotation corruption guard. Invalidate AND record a loud,
                // durable alarm entry (ReconcileHashMismatch) atomically, so this tamper
                // signal survives in the audit chain rather than reading as a silent
                // generic invalidate.
                let damaged = id.to_owned();
                self.blocking_store(move |store| {
                    store.invalidate_audited(
                        &damaged,
                        AuditCtx {
                            op: AuditOp::Invalidate,
                            actor: "vault-reconcile",
                            alarm: Some(AlarmReason::ReconcileHashMismatch),
                        },
                    )
                })
                .await?;
                return Ok(Reconciliation::NeedsReauth {
                    credential_id: id.to_string(),
                    reason: ReauthReason::HashMismatch,
                });
            }
        }

        // The resolution NEVER calls the rotating refresh endpoint — recovery has
        // access only to the adapter's optional non-mutating check.
        let adapter = record
            .refresh_adapter
            .as_deref()
            .and_then(|n| self.adapters.get(n));
        let check = match (adapter, record.oauth.as_ref()) {
            (Some(adapter), Some(oauth)) => adapter.non_mutating_check(oauth, &*self.http).await,
            _ => None,
        };

        let intent = intent.clone();
        self.blocking_store(move |store| {
            let id = intent.credential_id.as_str();
            match check {
                    // Without a non-mutating check, treat the result as indeterminate and fail safe.
                None => {
                    store.invalidate(id)?;
                    Ok(Reconciliation::NeedsReauth {
                        credential_id: id.to_string(),
                        reason: ReauthReason::NoValidityCheck,
                    })
                }
                // The check proved the stored grant still valid, including if an
                // earlier check left it in needs_reauth.
                Some(Ok(ValidityOutcome::Valid)) => {
                    store.confirm_refresh_intent_valid(
                        &intent,
                        &incarnation,
                        record.record_version,
                    )?;
                    Ok(Reconciliation::ClearedValid {
                        credential_id: id.to_string(),
                    })
                }
                // The check proved it invalid: needs_reauth.
                Some(Ok(ValidityOutcome::Invalid)) => {
                    store.invalidate(id)?;
                    Ok(Reconciliation::NeedsReauth {
                        credential_id: id.to_string(),
                        reason: ReauthReason::CheckInvalid,
                    })
                }
                // The check could not run (transient): mark needs_reauth to fail closed
                // NOW, but RETAIN the intent so a later retry can re-check and restore.
                Some(Err(_transient)) => {
                    store.mark_needs_reauth_retaining_intent(id)?;
                    Ok(Reconciliation::Retained {
                        credential_id: id.to_string(),
                    })
                }
            }
        })
        .await
        .map_err(EngineError::from)
    }

    /// Run an admin mutation for one credential UNDER that credential's single-flight
    /// lock — the same lock a refresh holds across its network call and commit.
    ///
    /// This is the load-bearing serializer for module-driven admin ops. The store's
    /// connection mutex only serializes individual transactions, not the
    /// read-modify-write sequence an admin op and a refresh each perform; taking the
    /// per-id lock makes admin-write and refresh-for-the-same-credential strictly
    /// mutually exclusive end-to-end, so an admin replace can never interleave with a
    /// refresh's commit. Gets that observe an intent also take this lock before
    /// serving, so they cannot bypass an unresolved intent from a failed commit.
    /// Fresh reads with no intent do not wait for admin operations on the same id.
    ///
    /// The closure receives the store; it must perform exactly one credential-scoped
    /// admin mutation. Different credential ids use different locks, so admin ops for
    /// distinct credentials still run concurrently.
    pub async fn with_admin_lock<T>(
        &self,
        credential_id: &str,
        f: impl FnOnce(&EncryptedStore) -> Result<T, StoreOpError>,
    ) -> Result<T, StoreOpError> {
        let _guard = self.acquire_admin_lock(credential_id).await;
        f(&self.store)
    }

    /// Hold the same lock across a store mutation and its outbound follow-up.
    /// The caller must bound the wait and keep the guard until that follow-up ends.
    pub async fn acquire_admin_lock(
        &self,
        credential_id: &str,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        self.inflight_lock(credential_id).lock_owned().await
    }

    /// Look up or create the single-flight lock for a credential.
    fn inflight_lock(&self, credential_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self.inflight.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(lock) = map
            .get(credential_id)
            .and_then(|entry| entry.lock.upgrade())
        {
            return lock;
        }
        map.retain(|_, entry| entry.lock.strong_count() != 0);
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        map.insert(
            credential_id.to_string(),
            InflightEntry {
                lock: Arc::downgrade(&lock),
                last_refresh: None,
            },
        );
        lock
    }

    fn is_last_refresh(&self, id: &str, incarnation: &str, version: u64) -> bool {
        self.inflight
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(id)
            .and_then(|entry| entry.last_refresh.as_ref())
            .is_some_and(|(committed_incarnation, committed_version)| {
                committed_incarnation == incarnation && *committed_version == version
            })
    }

    fn stamp_refresh(&self, id: &str, incarnation: &str, version: u64) {
        let mut map = self.inflight.lock().unwrap_or_else(|p| p.into_inner());
        let entry = map.get_mut(id).expect("a held flight cannot be pruned");
        entry.last_refresh = Some((incarnation.to_owned(), version));
    }
}

/// Build the new record to commit from a successful refresh, carrying forward the
/// canonical OAuth metadata and replacing only the rotated token fields + expiry.
/// The new payload is the new access token bytes (what a consumer receives).
fn apply_refreshed(
    record: &VaultRecord,
    old_oauth: &OAuthCredential,
    tokens: crate::refresh_adapters::RefreshedTokens,
) -> VaultRecord {
    let payload = crate::secret::SecretBytes::new(tokens.access_token.expose().as_bytes().to_vec());
    let new_oauth = OAuthCredential {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_at_ms: tokens.expires_at_ms,
        token_url: old_oauth.token_url.clone(),
        client_id: old_oauth.client_id.clone(),
        client_secret: old_oauth.client_secret.clone(),
        scopes: old_oauth.scopes.clone(),
    };
    let mut new_record = record.clone();
    if record.refresh_adapter.as_deref() == Some("openai") {
        new_record.detected_plan = Some(crate::plan_detection::chatgpt_plan(
            new_oauth.access_token.expose(),
        ));
    }
    new_record.expires_at_ms = tokens.expires_at_ms;
    new_record.payload = payload;
    new_record.oauth = Some(new_oauth);
    new_record
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod lock_registry_tests {
    use super::*;
    use crate::{
        key::MasterKey, refresh_adapters::fixture::FixtureTransport, test_support::TestTempDir,
    };
    use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn engine() -> (TestTempDir, RefreshEngine) {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let dir = TestTempDir::new(format!(
            "lock-registry-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let raw = open_sqlite(&StorageDescriptor {
            module_id: "lock-registry".into(),
            storage_namespace: "default".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: dir.join("store.db").to_string_lossy().into_owned(),
            },
        })
        .unwrap();
        EncryptedStore::migrate(&raw).unwrap();
        let store = EncryptedStore::open(raw, MasterKey::from_bytes([23; 32])).unwrap();
        (
            dir,
            RefreshEngine::new(
                Arc::new(store),
                vec![],
                Arc::new(FixtureTransport::new(vec![])),
            ),
        )
    }

    #[test]
    fn single_flight_registry_prunes_removed_credential_ids() {
        let (_dir, engine) = engine();
        for index in 0..128 {
            let id = format!("test:{index}");
            let record = VaultRecord::new_static(
                crate::record::CredentialKind::ApiKey,
                "test",
                b"key".to_vec(),
                None,
            );
            engine.store.create(&id, &record).unwrap();
            let lock = engine.inflight_lock(&id);
            engine
                .store
                .remove_audited(&id, AuditCtx::vault(AuditOp::Remove))
                .unwrap();
            drop(lock);
        }
        assert!(engine.inflight.lock().unwrap().len() <= 1);
    }

    #[tokio::test]
    async fn single_flight_pruning_preserves_holders_and_queued_waiters() {
        let (_dir, engine) = engine();
        let holder = engine.inflight_lock("same").lock_owned().await;
        let waiting_lock = engine.inflight_lock("same");
        let waiter = waiting_lock.clone().lock_owned();
        tokio::pin!(waiter);
        // Poll once to establish a queued waiter without relying on scheduling or time.
        std::future::poll_fn(|cx| {
            assert!(waiter.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(engine.inflight_lock("churn"));
        assert!(Arc::ptr_eq(&waiting_lock, &engine.inflight_lock("same")));
        drop(waiting_lock);
        drop(holder);
        // Only the pending lock future now owns the original lock.
        drop(engine.inflight_lock("churn"));
        assert!(engine.inflight_lock("same").try_lock().is_err());
        let waiter_guard = waiter.await;
        drop(engine.inflight_lock("churn"));
        assert!(engine.inflight_lock("same").try_lock().is_err());
        drop(waiter_guard);
    }

    #[tokio::test]
    async fn engine_snapshot_work_does_not_park_the_executor() {
        let (_dir, engine) = engine();
        engine
            .store
            .create(
                "apikey:test",
                &VaultRecord::new_static(
                    crate::record::CredentialKind::ApiKey,
                    "test",
                    b"test-key".to_vec(),
                    None,
                ),
            )
            .unwrap();
        let (entered, worker) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let executor = std::thread::current().id();
        engine.set_after_snapshot_hook(move || {
            let blocking_worker = std::thread::current().id() != executor;
            entered.send(blocking_worker).unwrap();
            // If the snapshot ran inline, report the failure without deadlocking
            // the only runtime thread that can release the gate.
            if blocking_worker {
                released.recv().unwrap();
            }
        });
        let get = tokio::spawn(async move { engine.get("apikey:test", None, false).await });
        assert!(
            worker.await.unwrap(),
            "snapshot work ran on the async executor"
        );
        assert!(!get.is_finished());
        release.send(()).unwrap();
        assert_eq!(get.await.unwrap().unwrap().payload.expose(), b"test-key");
    }

    #[tokio::test]
    async fn aborted_waiter_does_not_cancel_admitted_refresh() {
        use crate::refresh_adapters::RefreshedTokens;
        use tokio::sync::Notify;

        struct PausedProvider {
            entered: Notify,
            release: Notify,
        }

        #[async_trait::async_trait]
        impl RefreshAdapter for PausedProvider {
            fn name(&self) -> &str {
                "paused-provider"
            }

            async fn refresh(
                &self,
                _: &OAuthCredential,
                _: &dyn HttpTransport,
            ) -> Result<RefreshedTokens, RefreshError> {
                self.entered.notify_one();
                self.release.notified().await;
                Ok(RefreshedTokens {
                    access_token: "new-access".to_string().into(),
                    refresh_token: "new-refresh".to_string().into(),
                    expires_at_ms: Some(i64::MAX),
                    github_app_permissions: None,
                })
            }
        }

        let (_dir, engine) = engine();
        let provider = Arc::new(PausedProvider {
            entered: Notify::new(),
            release: Notify::new(),
        });
        let engine = Arc::new(RefreshEngine::new(
            Arc::clone(engine.store()),
            vec![provider.clone()],
            Arc::new(FixtureTransport::new(vec![])),
        ));
        let id = "oauth:cancel-test";
        engine
            .store
            .create(
                id,
                &VaultRecord::new_oauth(
                    "test",
                    provider.name(),
                    OAuthCredential {
                        access_token: "old-access".to_string().into(),
                        refresh_token: "old-refresh".to_string().into(),
                        expires_at_ms: Some(0),
                        token_url: crate::refresh_adapters::xai::TOKEN_URL.into(),
                        client_id: None,
                        client_secret: None,
                        scopes: vec![],
                    },
                    b"old-access".to_vec(),
                ),
            )
            .unwrap();
        let reader = Arc::clone(&engine);
        let waiter = tokio::spawn(async move { reader.get(id, None, false).await });
        provider.entered.notified().await;
        assert!(engine.store.read_intent(id).unwrap().is_some());
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        provider.release.notify_one();
        // The same lock serializes the refresh commit and any following admin write.
        let _after_refresh = engine.acquire_admin_lock(id).await;
        assert!(
            engine.store.read_intent(id).unwrap().is_none(),
            "aborted reader left a dangling intent"
        );
        let record = engine.store.get(id).unwrap();
        assert_eq!(record.payload.expose(), b"new-access");
        assert_eq!(record.oauth.unwrap().refresh_token.expose(), "new-refresh");
    }

    #[tokio::test]
    async fn fresh_read_does_not_wait_for_a_lock_without_an_intent() {
        let (_dir, engine) = engine();
        let record = VaultRecord::new_oauth(
            "test",
            "unused",
            OAuthCredential {
                access_token: "fresh-access".to_string().into(),
                refresh_token: "fresh-refresh".to_string().into(),
                expires_at_ms: Some(i64::MAX),
                token_url: crate::refresh_adapters::xai::TOKEN_URL.into(),
                client_id: None,
                client_secret: None,
                scopes: vec![],
            },
            b"fresh-access".to_vec(),
        );
        engine.store.create("oauth:fresh", &record).unwrap();
        let lock = engine.inflight_lock("oauth:fresh");
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let holder = tokio::spawn(async move {
            let _guard = lock.lock_owned().await;
            entered_tx.send(()).unwrap();
            let _ = release_rx.await;
        });
        entered_rx.await.unwrap();
        assert!(engine.store.read_intent("oauth:fresh").unwrap().is_none());
        // The read can await its blocking snapshot, but must finish before the
        // other operation releases this credential's single-flight lock.
        let served = engine.get("oauth:fresh", None, false).await.unwrap();
        assert_eq!(served.payload.expose(), b"fresh-access");
        release_tx.send(()).unwrap();
        holder.await.unwrap();
    }
}
