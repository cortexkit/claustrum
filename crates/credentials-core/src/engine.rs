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
use std::sync::{Arc, Mutex};

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
/// `refreshed_for_min_ttl` is true only when THIS read completed one upstream exchange
/// after its supplied minimum-TTL demand found the old token too short. A caller must not
/// infer a fresh mint from a record version alone: another request or an admin write can
/// move the version without this read proving why the replacement exists.
#[derive(Debug)]
pub struct GetWithRefreshStatus {
    pub record: VaultRecord,
    pub refreshed_for_min_ttl: bool,
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
pub struct RefreshEngine {
    store: Arc<EncryptedStore>,
    adapters: HashMap<String, Arc<dyn RefreshAdapter>>,
    http: Arc<dyn HttpTransport>,
    skew_ms: i64,
    // Per-credential single-flight locks, created on demand. The map mutex is held
    // only to look up/insert a lock handle (never across an await); the per-id
    // tokio mutex is the one held across the refresh await.
    inflight: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    // Test-only crash seam: fired AFTER the intent is durably committed and the new
    // tokens are staged, but BEFORE the commit transaction. The kill-9 conformance
    // helper sets this to a closure that signals readiness and parks forever, so a
    // parent test can SIGKILL it at exactly the response->commit gap. Compiled in
    // ONLY under the `kill9-test-seam` feature, so the release vault has no
    // block-before-commit path at all.
    #[cfg(feature = "kill9-test-seam")]
    pre_commit: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
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
            adapters,
            http,
            skew_ms: DEFAULT_EXPIRY_SKEW_MS,
            inflight: Mutex::new(HashMap::new()),
            #[cfg(feature = "kill9-test-seam")]
            pre_commit: Mutex::new(None),
        }
    }

    /// Install the test-only pre-commit hook (see the field docs). Available only
    /// under the `kill9-test-seam` feature; the kill-9 helper uses it to park.
    #[cfg(feature = "kill9-test-seam")]
    pub fn set_pre_commit_hook(&self, hook: Box<dyn Fn() + Send + Sync>) {
        *self.pre_commit.lock().unwrap_or_else(|p| p.into_inner()) = Some(hook);
    }

    /// Override the expiry skew (mostly for tests).
    pub fn with_skew_ms(mut self, skew_ms: i64) -> Self {
        self.skew_ms = skew_ms;
        self
    }

    /// The underlying store (for the module's read/admin surfaces).
    pub fn store(&self) -> &Arc<EncryptedStore> {
        &self.store
    }

    /// Read a credential, refreshing first if it is stale (or `force_refresh`).
    ///
    /// `min_ttl_ms`: if set, a token with less than this remaining is refreshed.
    /// Refresh is single-flight per credential. A non-refreshable record is served
    /// as-is unless it carries a consumer report marker, which must terminally latch
    /// because no refresh path can recover it. Fails closed on a
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

    /// Read a credential and report whether this read itself completed an exchange for
    /// its minimum-TTL demand. The status is deliberately narrower than "the version
    /// changed": a concurrent refresh or admin write is not proof that this request
    /// minted a token against its demand.
    pub async fn get_with_refresh_status(
        &self,
        credential_id: &str,
        min_ttl_ms: Option<i64>,
        force_refresh: bool,
    ) -> Result<GetWithRefreshStatus, EngineError> {
        let (initial, stale_pending) = self.store.get_with_stale_pending(credential_id)?;
        if stale_pending && !initial.is_refreshable() {
            // A stale marker means a consumer already refused this exact token. A
            // non-refreshable record cannot replace it, so defer to the existing
            // version-fenced terminal transition rather than serving it again.
            self.store.invalidate_if_version_reported(
                credential_id,
                initial.record_version,
                AuditCtx::vault(AuditOp::Invalidate),
                Some(AuthObservation {
                    kind: AuthEventKind::StaleNonrefreshableLatch.as_str(),
                    provider_status: None,
                    detail: None,
                }),
            )?;
            // If a concurrent write moved the version, return the replacement rather
            // than incorrectly refusing the record this get did not inspect.
            return Ok(GetWithRefreshStatus {
                record: self.store.get(credential_id)?,
                refreshed_for_min_ttl: false,
            });
        }

        let refresh_requested_by_min_ttl = self.is_below_min_ttl(&initial, min_ttl_ms);
        let wants_refresh = force_refresh || stale_pending || self.is_stale(&initial, min_ttl_ms);
        if !wants_refresh || !initial.is_refreshable() {
            return Ok(GetWithRefreshStatus {
                record: initial,
                refreshed_for_min_ttl: false,
            });
        }

        // Single-flight: serialize refreshes for this credential.
        let lock = self.inflight_lock(credential_id);
        let _guard = lock.lock().await;

        // Re-read under the lock: a prior holder may have already refreshed. If the
        // version moved, that holder did the upstream call — return their result
        // without a second one (this is what makes N concurrent gets ⇒ 1 call, and
        // it is correct even under force_refresh). It also means this request has no
        // exchange proof of its own for a later TTL refusal.
        let (current, _) = self.store.get_with_stale_pending(credential_id)?;
        if current.record_version != initial.record_version {
            return Ok(GetWithRefreshStatus {
                record: current,
                refreshed_for_min_ttl: false,
            });
        }

        self.do_refresh(credential_id, &current).await?;
        Ok(GetWithRefreshStatus {
            record: self.store.get(credential_id)?,
            refreshed_for_min_ttl: refresh_requested_by_min_ttl,
        })
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
        if oauth.access_token.is_empty() {
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
        record: &VaultRecord,
    ) -> Result<(), EngineError> {
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
        let old_hash = refresh_token_hash(&oauth.refresh_token);
        self.store
            .open_intent(credential_id, record.record_version, &old_hash)?;

        // The provider call (rotating). Tokens are staged in memory only.
        match adapter.refresh(oauth, &*self.http).await {
            Ok(tokens) if tokens.access_token.is_empty() => {
                // A successful provider response with no access token is not a valid
                // rotation. Clear txn1 while preserving the old record/version; otherwise
                // the sealed record would later decrypt to a successful zero-byte read.
                self.store.clear_intent(credential_id)?;
                Err(EngineError::RefreshFailed(RefreshError::Decode(
                    "provider returned an empty access token".into(),
                )))
            }
            Ok(tokens) => {
                // Only GitHub App mints return this vendor-specific diagnostic. Keep the
                // field out of every other refresh path even if an adapter is miswired.
                let github_app_permissions = (adapter_name
                    == crate::refresh_adapters::github_app::ADAPTER_NAME)
                    .then(|| tokens.github_app_permissions.clone())
                    .flatten();
                let new_record = apply_refreshed(record, oauth, tokens);

                // Test-only crash seam: the intent is durably committed and the new
                // tokens are staged, but the commit transaction has NOT run. The
                // kill-9 helper parks here so a parent test can SIGKILL it at exactly
                // this point. No-op (and absent entirely) in a release build.
                #[cfg(feature = "kill9-test-seam")]
                {
                    let hook = self.pre_commit.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some(hook) = hook.as_ref() {
                        hook();
                    }
                }

                match self
                    .store
                    .commit_refresh(credential_id, record.record_version, &new_record)
                {
                    Ok(record_version) => {
                        if let Some(permissions) = github_app_permissions.as_ref() {
                            // Diagnostic persistence is deliberately non-fallible: a valid
                            // token has already committed and must be served even if this
                            // extra observation cannot be recorded.
                            self.store.observe_github_app_permissions(
                                credential_id,
                                record_version,
                                permissions,
                            );
                        }
                        Ok(())
                    }
                    // Lease handover fenced our commit: the new lease owner will
                    // reconcile the still-dangling intent. Discard the staged tokens,
                    // do NOT retry, do NOT serve them. (The staged `new_record` drops
                    // here, scrubbing the token strings it owns.)
                    Err(e @ StoreOpError::Fenced { .. }) => Err(EngineError::Store(e)),
                    // A concurrent admin write moved the version (and, per the
                    // admin-clears-intent rule, already cleared our intent). Our
                    // refresh is moot; surface it without touching state.
                    Err(StoreOpError::CasMismatch) => {
                        Err(EngineError::Store(StoreOpError::CasMismatch))
                    }
                    Err(other) => Err(EngineError::Store(other)),
                }
            }
            // A definitively dead refresh token: mark needs_reauth and clear the
            // intent (no rotation can recover it). VERSION-GATED on the version this
            // refresh actually observed: if an admin replaced the credential while
            // the provider call was in flight (bumping the version), the invalid_grant
            // verdict is about the OLD record's token, and invalidating the fresh
            // replacement would kill a healthy credential the verdict never saw. The
            // stale invalidation then no-ops silently; the replacement stands.
            Err(e @ RefreshError::InvalidGrant(_)) => {
                self.store.invalidate_if_version_reported(
                    credential_id,
                    record.record_version,
                    AuditCtx::vault(AuditOp::Invalidate),
                    Some(AuthObservation {
                        kind: AuthEventKind::RefreshFailed.as_str(),
                        provider_status: None,
                        detail: Some(e.variant_name()),
                    }),
                )?;
                Err(EngineError::RefreshFailed(e))
            }
            // A transient/ambiguous failure (transport, decode, unexpected status):
            // no committable tokens were produced. Clear the intent and leave the
            // record active — the engine is alive and handling this synchronously,
            // so this is NOT the indeterminate crash window. If the provider DID
            // rotate server-side and we missed the response, the stored refresh
            // token is now dead and the NEXT refresh attempt fails with invalid_grant
            // ⇒ needs_reauth then (self-healing), never a silent dead token.
            Err(other) => {
                self.store.clear_intent(credential_id)?;
                // Record that the provider WAS called and refused, which nothing else
                // does on this arm: the intent is cleared and the record left active,
                // so a credential failing every refresh looked untouched from outside.
                // Best-effort by construction -- a diagnostics write must never mask
                // the provider failure being returned.
                let _ = self.store.record_auth_event(
                    credential_id,
                    AuthObservation {
                        kind: AuthEventKind::RefreshFailed.as_str(),
                        provider_status: other.provider_status(),
                        detail: Some(other.variant_name()),
                    },
                    Some(record.record_version),
                );
                Err(EngineError::RefreshFailed(other))
            }
        }
    }

    /// Reconcile all dangling intents at boot (the boot gate). Resolves each per
    /// the decision table and returns the outcomes for the audit log. Call once,
    /// before the read surface serves any `get`.
    pub async fn reconcile(&self) -> Result<Vec<Reconciliation>, EngineError> {
        let intents = self.store.list_intents()?;
        let mut outcomes = Vec::with_capacity(intents.len());
        for intent in intents {
            outcomes.push(self.reconcile_one(&intent).await?);
        }
        Ok(outcomes)
    }

    async fn reconcile_one(&self, intent: &RefreshIntent) -> Result<Reconciliation, EngineError> {
        let id = intent.credential_id.as_str();

        // Read the stored record. Absent / already-needs_reauth / quarantined =>
        // there is nothing live to protect; clear the orphan intent.
        let record = match self.store.get(id) {
            Ok(r) => r,
            Err(StoreOpError::NotFound)
            | Err(StoreOpError::NeedsReauth)
            | Err(StoreOpError::Quarantined) => {
                self.store.clear_intent(id)?;
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
            let stored_hash = refresh_token_hash(&oauth.refresh_token);
            if stored_hash != intent.old_refresh_hash {
                // A write landed without clearing the intent — the rogue-write /
                // interrupted-rotation corruption guard. Invalidate AND record a loud,
                // durable alarm entry (ReconcileHashMismatch) atomically, so this tamper
                // signal survives in the audit chain rather than reading as a silent
                // generic invalidate.
                self.store.invalidate_audited(
                    id,
                    AuditCtx {
                        op: AuditOp::Invalidate,
                        actor: "vault-reconcile",
                        alarm: Some(AlarmReason::ReconcileHashMismatch),
                    },
                )?;
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

        match check {
            // No non-mutating check (the v1 default): INDETERMINATE ⇒ fail safe.
            None => {
                self.store.invalidate(id)?;
                Ok(Reconciliation::NeedsReauth {
                    credential_id: id.to_string(),
                    reason: ReauthReason::NoValidityCheck,
                })
            }
            // The check proved the stored refresh state still valid: clear the
            // intent, leave the record active (no re-login).
            Some(Ok(ValidityOutcome::Valid)) => {
                self.store.clear_intent(id)?;
                Ok(Reconciliation::ClearedValid {
                    credential_id: id.to_string(),
                })
            }
            // The check proved it invalid: needs_reauth.
            Some(Ok(ValidityOutcome::Invalid)) => {
                self.store.invalidate(id)?;
                Ok(Reconciliation::NeedsReauth {
                    credential_id: id.to_string(),
                    reason: ReauthReason::CheckInvalid,
                })
            }
            // The check could not run (transient): mark needs_reauth to fail closed
            // NOW, but RETAIN the intent so a later retry can re-check and restore.
            Some(Err(_transient)) => {
                self.store.mark_needs_reauth_retaining_intent(id)?;
                Ok(Reconciliation::Retained {
                    credential_id: id.to_string(),
                })
            }
        }
    }

    /// Run an admin mutation for one credential UNDER that credential's single-flight
    /// lock — the same lock a refresh holds across its network call and commit.
    ///
    /// This is the load-bearing serializer for module-driven admin ops. The store's
    /// connection mutex only serializes individual transactions, not the
    /// read-modify-write sequence an admin op and a refresh each perform; taking the
    /// per-id lock makes admin-write and refresh-for-the-same-credential strictly
    /// mutually exclusive end-to-end, so an admin replace can never interleave with a
    /// refresh's commit (Oracle finding 5), and a get arriving during a live refresh
    /// that also needs to write waits for the intent to resolve rather than acting on
    /// a mid-refresh view (Oracle finding 6). Reads (`get`) that only SERVE are
    /// unaffected — they still take the lock only when they themselves refresh.
    ///
    /// The closure receives the store; it must perform exactly one credential-scoped
    /// admin mutation. Different credential ids use different locks, so admin ops for
    /// distinct credentials still run concurrently.
    pub async fn with_admin_lock<T>(
        &self,
        credential_id: &str,
        f: impl FnOnce(&EncryptedStore) -> Result<T, StoreOpError>,
    ) -> Result<T, StoreOpError> {
        let lock = self.inflight_lock(credential_id);
        let _guard = lock.lock().await;
        f(&self.store)
    }

    /// Look up or create the single-flight lock for a credential.
    fn inflight_lock(&self, credential_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self.inflight.lock().unwrap_or_else(|p| p.into_inner());
        map.entry(credential_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
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
    let new_oauth = OAuthCredential {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token,
        expires_at_ms: tokens.expires_at_ms,
        token_url: old_oauth.token_url.clone(),
        client_id: old_oauth.client_id.clone(),
        scopes: old_oauth.scopes.clone(),
    };
    let mut new_record = record.clone();
    new_record.expires_at_ms = tokens.expires_at_ms;
    new_record.payload = tokens.access_token.into_bytes();
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
