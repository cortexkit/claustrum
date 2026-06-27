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
//! - `credential.report_auth_failure { handle, provider_status }` → marks the
//!   credential needs_reauth so the next get does not serve a dead token.
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
}

impl ReadSurface {
    pub fn new(engine: Arc<RefreshEngine>, limiter: FetchLimiter) -> Self {
        ReadSurface {
            engine,
            limiter: Mutex::new(limiter),
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
                GetOutcome::Ok(GetResult {
                    payload: record.payload,
                    expires_at_ms: record.expires_at_ms,
                    record_version: record.record_version,
                    project_id,
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
        // provider hiccup, not a dead credential. The invalidate audits the
        // revocation feedback in the chain atomically (actor = the connection).
        if params.provider_status == 401 || params.provider_status == 403 {
            let actor = format!("conn-{connection_id}");
            self.engine
                .store()
                .invalidate_audited(
                    &credential_id,
                    AuditCtx {
                        op: AuditOp::ReportAuthFailure,
                        actor: &actor,
                        alarm: None,
                    },
                )
                .map_err(|e| map_store_error(&e))?;
        }
        Ok(())
    }

    /// Non-secret status: per-handle health, or overall readiness when no handle.
    pub fn status(&self, params: &StatusParams) -> StatusResult {
        let lease_held = true; // the daemon holds the lease for its lifetime
        match &params.handle {
            None => StatusResult {
                ready: true,
                last_error_code: None,
                lease_held,
            },
            Some(handle) => match self.engine.store().resolve_handle(handle) {
                Ok(credential_id) => match self.engine.store().meta(&credential_id) {
                    Ok(meta) => StatusResult {
                        ready: matches!(meta.state, credentials_core::store::RecordState::Active),
                        last_error_code: match meta.state {
                            credentials_core::store::RecordState::NeedsReauth => {
                                Some(ReadError::NeedsReauth)
                            }
                            credentials_core::store::RecordState::Corrupt => {
                                Some(ReadError::Corrupt)
                            }
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
            },
        }
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
        error: ErrorBody { code },
    }
}

/// Map a store error to a non-secret read code (fail-closed; never leaks detail).
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
