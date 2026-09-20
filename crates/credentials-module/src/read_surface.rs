//! The capability-handle read surface plus its separate principal-scoped operation.
//!
//! Credential reads remain read-only. The enrollment proposal, poll, and rotation
//! operations are the narrow exceptions: they write only bounded enrollment state and
//! are kept out of the untrimmable audit chain except for successful token rotation.
//! Handle operations take a capability HANDLE, never a
//! public alias, and resolve it to a credential id before anything else; an unknown or
//! revoked handle is a uniform `not_found` so a probe cannot enumerate.
//!
//! Operations:
//! - `credential.get { handle, min_ttl_ms?, force_refresh? }` → the opaque payload,
//!   refreshed first if stale (single-flight, vault-owned).
//! - `credential.public_key { handle }` or `{ credential_id }` → public Ed25519 material
//!   for a signing key; a credential id requires a route-bound principal's read grant and
//!   never serves the private payload.
//! - `credential.get_scoped { credential_id }` → the same ordinary payload body, only
//!   for a route-bound reserved principal with a literal-prefix read grant.
//! - `credential.get_many { items: [...] }` → capped at [`limiter::GET_MANY_MAX`].
//! - `credential.status { handle? | credential_id? }` → non-secret health, never bytes.
//! - `credential.report_auth_failure { handle, provider_status, record_version, reporter_source? }` →
//!   marks the token STALE on a refreshable credential so the next get REFRESHES it,
//!   and latches `needs_reauth` only for a non-refreshable one. A refresh that then
//!   returns `invalid_grant` latches through the path that already existed. Measured
//!   in production 2026-08-24: a report declined to kill a live credential, the vault
//!   attempted recovery, the provider refused, and only then did it latch.
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

use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use credentials_core::audit::{
    AlarmReason, AuditCtx, AuditOp, AuditRecord, AuthEventKind, ReporterSource,
};
use credentials_core::credential_id::{default_refresh_adapter, parse_credential_id};
use credentials_core::engine::{EngineError, RefreshEngine};
use credentials_core::enrollment::{
    EnrollmentError, EnrollmentPoll, EnrollmentProposal, EnrollmentRotation,
};
use credentials_core::health::VaultHealth;
use credentials_core::refresh_adapters::RefreshError;
use credentials_core::store::{
    AuthEventPrincipal, GrantOperation, ScopedCoverage, ScopedListSnapshot, ScopedReadRefusal,
    StoreOpError,
};
use subc_protocol::Principal;

use crate::limiter::{Admission, FetchLimiter, GET_MANY_MAX};

/// Exact parameters for `auth.enroll_propose`.
#[cfg_attr(test, derive(Serialize))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollProposeParams {
    pub proposed_name: String,
    pub request_secret_hash: String,
}

/// Exact parameters for `auth.enroll_poll`. The request secret is the only resumption
/// value besides the request id; neither the proposed name nor any host identity belongs here.
#[cfg_attr(test, derive(Serialize))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollPollParams {
    pub request_id: String,
    pub request_secret: String,
}

/// Exact parameters for `auth.enroll_rotate`.
#[cfg_attr(test, derive(Serialize))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollRotateParams {
    pub token: String,
    pub expected_token_generation: u64,
}

/// A `credential.get` request.
///
/// `force_refresh` and `min_ttl_ms` can both reach the upstream exchange. The latter is
/// caller-supplied and deliberately unclamped: a demand larger than a token's lifetime
/// otherwise behaves like `force_refresh` on every get, silently consuming a shared
/// provider budget.
///
/// A pre-refresh lifetime clamp is unsound. The only available proxy,
/// `expires_at_ms - updated_at_ms`, mistakes the last record write for the token issue
/// time. Imported tokens can have lived for a while before that write, so the proxy
/// underestimates their lifetime and can refuse satisfiable requests.
///
/// Shipped behavior is therefore post-refresh. When this request's supplied
/// `min_ttl_ms` performs one exchange and the fresh token still misses that demand,
/// `credential.get` returns `ttl_unsatisfiable` / `context_overflow`. It evaluates once
/// after the exchange, never before it or in a retry loop. If no exchange occurred,
/// including for a static credential, there is no fresh-token proof and the read is
/// served as before.
///
/// TWO CONSULTATION RESULTS ARE BINDING ON THE WIRE SHAPE:
///
/// 1. The refusal fires only when `min_ttl_ms` is present. There is no default or
///    implicit floor: a caller without a demand cannot have one unsatisfied. In
///    particular, `github_app` installation tokens live one hour, so an implicit
///    30-minute floor would make otherwise ordinary gets timing-dependent.
///
/// 2. The class is `context_overflow`, not `permanent`. `permanent` describes a
///    credential that cannot serve, while this credential remains usable for callers
///    with a smaller demand. The wrong value is one request field, so retrying the
///    identical request is futile but re-login or handle reaping is the wrong remedy.
///
/// WHAT THIS REFUSAL STILL CANNOT SEE, recorded because a consumer named it and the
/// boundary is not obvious. A demand that is SATISFIABLE but tight -- say 9 minutes
/// against a 10-minute token -- refreshes on almost every get while never once being
/// unsatisfiable, so it never reaches this arm. That is the same upstream cost as the
/// pathology this refuses, wearing a legal demand.
///
/// The split on who could detect it, since neither side can alone:
///   VISIBLE HERE      the numerator. A credential refreshing far above its own token
///                     lifetime shows as an elevated `refresh_commit` rate in the chain.
///   NOT VISIBLE HERE  the denominator. THIS VAULT DOES NOT RECORD READS, only
///                     refreshes, so refreshes-per-read -- the ratio that actually names
///                     the pathology -- is not computable from this side at any cost
///                     short of writing a row per read on the hot path.
///   NOT VISIBLE HERE  attribution. `refresh_commit` records `actor=vault` because the
///                     vault performs the refresh; nothing names the triggering caller.
///
/// So it is detectable per-credential as a rate anomaly and not attributable to a
/// consumer. Deliberately not built: no consumer has exhibited it (the one with the
/// highest volume -- 1,114 admissions in 24h, one get each -- passes a 10-minute const
/// against multi-hour tokens), and building a detector whose denominator does not exist
/// would mean deciding to log every read first. That is a different argument.
///
/// Reachable only through a capability handle. [`GetScopedParams`] deliberately carries
/// no refresh controls, so the principal-scoped grant path cannot express either lever.
#[cfg_attr(test, derive(Serialize))]
#[derive(Debug, Deserialize)]
pub struct GetParams {
    pub handle: String,
    #[serde(default)]
    pub min_ttl_ms: Option<i64>,
    #[serde(default)]
    pub force_refresh: bool,
}

/// A principal-scoped credential-id read. This deliberately has no refresh controls:
/// a grant authorizes the same ordinary serving path as `credential.get`, not a mint
/// or force-refresh capability.
#[cfg_attr(test, derive(Serialize))]
#[derive(Debug, Deserialize)]
pub struct GetScopedParams {
    /// Present for a host-launched consumer; absent for a supervised module, which is
    /// identified by its bus principal instead. See `scoped_principal` for why a
    /// presented token wins over the ambient identity and why a bad one does not fall
    /// back to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_token: Option<String>,
    /// The caller's guaranteed-life demand, identical in meaning to `credential.get`'s.
    ///
    /// NOT A NICETY, AND THE REASON IS A CONSUMER'S, NOT MINE. A caller that treats a
    /// served-bearer 401 as evidence the credential is dead needs "alive when I started"
    /// to imply "alive when the upstream answered". The insula seat fences that with
    /// `min_ttl_ms` 120s against a 35s fetch deadline: 85s of margin is what makes the
    /// implication hold. Without a floor, a token with a second left is servable, the
    /// upstream answers 401 mid-request, and the consumer cannot distinguish that from a
    /// revoked credential -- so it reports a HEALTHY credential dead and the account
    /// needs an operator re-login for what was a race.
    ///
    /// That failure is self-concealing: it presents as "this account randomly needs
    /// re-auth", which is the shape people blame on the provider for months.
    ///
    /// This op shipped WITHOUT it (hardcoded `None`) and the omission was invisible from
    /// in here: nine of their call sites pass 120s and none of them could reach this op
    /// yet. It was found by the consumer pricing a cutover, not by any test.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_ttl_ms: Option<i64>,
    pub credential_id: String,
}

/// `credential.list_scoped` lists every row covered by the caller's grants.
///
/// `enrollment_token` is how a host-launched consumer says who it is. A supervised module
/// omits it and is identified by its bus principal; a consumer that holds a token presents
/// it and is identified by that. There is no third way in.
///
/// `deny_unknown_fields` does real work on the compatibility edge: a daemon predating this
/// field REFUSES a token-bearing call rather than ignoring the token and answering from
/// whatever ambient principal the connection carries. A silently ignored token would
/// return a list computed for the wrong grants, which reads as "my grants are wrong"
/// rather than "this daemon is too old".
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListScopedParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ListScopedCredential {
    pub id: String,
    pub categories: Vec<String>,
    #[serde(rename = "type")]
    pub credential_type: String,
    pub serves: Vec<String>,
    /// Which provider protocol this credential speaks, from the record itself.
    ///
    /// `serves` AND `refresh_adapter` ANSWER DIFFERENT QUESTIONS AND A CONSUMER NEEDS
    /// BOTH. `serves` names the model vendors reachable through a credential; the adapter
    /// names the protocol it speaks. On this vault eight rows serve Anthropic models and
    /// only five are Claude OAuth: `apikey:openrouter`, `antigravity:google` and
    /// `oauth:cursor` reach Anthropic models through their own APIs. A consumer sending a
    /// token to Anthropic's native endpoints must select on the adapter; one choosing
    /// where a model can be reached selects on `serves`.
    ///
    /// Absent for static credentials, which have no refresh protocol at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_adapter: Option<String>,
    pub state: String,
    pub record_version: u64,
    pub operations: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GrantTuple {
    pub selector_kind: String,
    pub selector: String,
    pub operation: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ListScopedResult {
    pub credentials: Vec<ListScopedCredential>,
    pub grants: usize,
    pub grant_tuples: Vec<GrantTuple>,
    pub view: String,
}

/// A `credential.sign` request: sign exact bytes with a signing-key credential.
///
/// A capability handle and a principal-scoped credential id are deliberately
/// separate authorization forms. Exactly one must be present: a handle keeps the
/// operator ceremony intact, while a credential id is authorized by a route-bound
/// principal's sign grant.
///
/// The payload is base64 because JSON cannot carry raw bytes, and the SIGNATURE
/// COVERS THE DECODED BYTES -- not the base64 text. A verifier that signed the
/// encoded form would break the moment a caller re-encoded with a different
/// alphabet or padding, which is the canonicalization mismatch this whole design
/// avoids by carrying exact bytes.
#[cfg_attr(test, derive(Serialize))]
#[derive(Debug, Deserialize)]
pub struct SignParams {
    #[serde(default)]
    pub handle: Option<String>,
    #[serde(default)]
    pub credential_id: Option<String>,
    /// The exact bytes to sign, base64 (standard alphabet).
    pub payload_b64: String,
    /// An enrollment token, for the consumer class that holds no handle. See the note on
    /// [`StatusParams::enrollment_token`]: this field arrived on the scoped surfaces one
    /// caller at a time, and the ones that lagged were the ones nobody had asked from yet.
    #[serde(default)]
    pub enrollment_token: Option<String>,
}

enum SignAuthorization<'a> {
    Handle(&'a str),
    Scoped(&'a str),
}

impl SignParams {
    pub(crate) fn has_exactly_one_authorization(&self) -> bool {
        self.authorization().is_some()
    }

    fn authorization(&self) -> Option<SignAuthorization<'_>> {
        match (self.handle.as_deref(), self.credential_id.as_deref()) {
            (Some(handle), None) => Some(SignAuthorization::Handle(handle)),
            (None, Some(credential_id)) => Some(SignAuthorization::Scoped(credential_id)),
            (None, None) | (Some(_), Some(_)) => None,
        }
    }
}

/// A `credential.sign` result: a detached signature and the key that made it.
#[derive(Debug, Serialize)]
pub struct SignResult {
    pub signature_b64: String,
    /// Derived from the public key, so a holder of the public half can recompute it
    /// and check that an envelope names the key that actually signed.
    pub key_id: String,
}

/// A `credential.public_key` request.
///
/// A capability handle and a principal-scoped credential id are deliberately separate
/// authorization forms. Exactly one must be present: a handle retains the operator
/// ceremony, while a credential id is authorized by a route-bound principal's read
/// grant because the returned material is public.
#[cfg_attr(test, derive(Serialize))]
#[derive(Debug, Deserialize)]
pub struct PublicKeyParams {
    #[serde(default)]
    pub handle: Option<String>,
    #[serde(default)]
    pub credential_id: Option<String>,
    /// An enrollment token, for the consumer class that holds no handle. See the note on
    /// [`StatusParams::enrollment_token`]: this field arrived on the scoped surfaces one
    /// caller at a time, and the ones that lagged were the ones nobody had asked from yet.
    #[serde(default)]
    pub enrollment_token: Option<String>,
}

enum PublicKeyAuthorization<'a> {
    Handle(&'a str),
    Scoped(&'a str),
}

impl PublicKeyParams {
    pub(crate) fn has_exactly_one_authorization(&self) -> bool {
        self.authorization().is_some()
    }

    fn authorization(&self) -> Option<PublicKeyAuthorization<'_>> {
        match (self.handle.as_deref(), self.credential_id.as_deref()) {
            (Some(handle), None) => Some(PublicKeyAuthorization::Handle(handle)),
            (None, Some(credential_id)) => Some(PublicKeyAuthorization::Scoped(credential_id)),
            (None, None) | (Some(_), Some(_)) => None,
        }
    }
}

/// The public material of an Ed25519 signing key.
///
/// `credential.get` returns a record payload verbatim, and a signing-key payload is
/// PKCS#8 private material. This separate response exists so publishing a verifier's
/// key cannot accidentally publish the signing key to every ordinary read consumer.
#[derive(Debug, Serialize)]
pub struct PublicKeyResult {
    pub public_key_hex: String,
    pub key_id: String,
    pub algorithm: &'static str,
}

/// A `credential.get_many` request: a capped batch of get items.
#[cfg_attr(test, derive(Serialize))]
#[derive(Debug, Deserialize)]
pub struct GetManyParams {
    pub items: Vec<GetParams>,
}

/// A `credential.status` request. An absent address means overall vault health.
///
/// A capability handle and a principal-scoped credential id are separate addressing forms.
/// They must not be combined because the two forms use different authorization paths.
#[cfg_attr(test, derive(Serialize))]
#[derive(Debug, Deserialize)]
pub struct StatusParams {
    #[serde(default)]
    pub handle: Option<String>,
    #[serde(default)]
    pub credential_id: Option<String>,
    /// An enrollment token, for the consumer class that holds no handle.
    ///
    /// WITHOUT THIS, STATUS WAS THE ONE SCOPED SURFACE AN ENROLLED CONSUMER COULD NOT
    /// REACH. `get_scoped`, `list_scoped` and `report_auth_failure` all take a token, so
    /// a host-launched consumer could discover credentials, fetch them, and say one was
    /// dead -- and could not ask after the health of a single credential it already held
    /// and was already entitled to read. The asymmetry was an oversight rather than a
    /// decision: the field was added to three of four surfaces as each one needed it.
    ///
    /// Ignored when `handle` is used, for the same reason as on the failure report: a
    /// handle holder is anonymous by design, and presenting both claims two identities
    /// for one question.
    #[serde(default)]
    pub enrollment_token: Option<String>,
}

impl StatusParams {
    pub(crate) fn has_mutually_exclusive_addressing(&self) -> bool {
        self.handle.is_none() || self.credential_id.is_none()
    }
}

/// A `credential.report_auth_failure` request.
#[cfg_attr(test, derive(Serialize))]
#[derive(Debug, Deserialize)]
pub struct ReportAuthFailureParams {
    /// The capability handle the consumer was served through. Anonymous addressing,
    /// unchanged. Exactly one of this and [`Self::credential_id`] must be present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// The credential id, for a caller holding a `Read` grant covering it and no
    /// handle at all.
    ///
    /// WHY THIS EXISTS. Enrollment creates a consumer that holds a bearer token and a
    /// category grant and ZERO capability handles. Without this address it could
    /// discover credentials and fetch them and then had no way to say one was dead --
    /// the recovery loop broken for exactly the consumer class enrollment creates, with
    /// the credential looking healthy until a background refresh happened to fail. The
    /// gap was found by the anthropic-auth seat tracing one consumer through its whole
    /// lifecycle INCLUDING failure; enrollment, discovery and fetch each look complete
    /// on their own.
    ///
    /// The gate is `GrantOperation::Read`, not a new operation: reporting that a
    /// credential you may read was refused upstream is strictly LESS authority than
    /// reading it, because the report is version-fenced and can only mark stale
    /// something the caller was already entitled to fetch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    /// An enrollment token, for the consumer class that holds no handle.
    ///
    /// WITHOUT THIS THE RECOVERY LOOP IS BROKEN FOR EXACTLY THE CALLER ENROLLMENT
    /// CREATES. A host-launched consumer binds as `Principal::Direct`, so the
    /// `credential_id` path's grant check cannot authorize it, and it holds no handle
    /// because not needing one is the entire point. It could discover credentials with
    /// `list_scoped`, fetch them with `get_scoped`, and then had no way to say "this one
    /// is dead" -- a revoked credential retried until an operator noticed.
    ///
    /// Reported by the openai-auth seat while reading the contract, before writing a line
    /// against it. Ignored when `handle` is used: a handle holder is anonymous by design,
    /// and presenting both would be claiming two identities for one report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_token: Option<String>,
    pub provider_status: u16,
    /// The `record_version` the consumer was SERVED for this handle (from the `get`
    /// result it acted on). Required: the vault invalidates only if this still matches
    /// the current version, so a stale report for a since-refreshed credential is a
    /// no-op instead of falsely killing the fresh token. A consumer that omits it is
    /// rejected (`invalid_params`) rather than silently invalidating whatever is current.
    pub record_version: u64,
    /// Optional consumer-asserted observation-path label from the closed [`ReporterSource`]
    /// vocabulary. Unknown labels are recorded as `unrecognised`, never stored raw; older
    /// consumers may omit this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reporter_source: Option<String>,
}

/// A successful `get` result. `payload` is opaque to the consumer.
#[derive(Debug, Serialize)]
pub struct GetResult {
    pub payload: Vec<u8>,
    pub expires_at_ms: Option<i64>,
    pub record_version: u64,
    /// The credential id this request resolved to. This field is FOR VERIFYING A BINDING
    /// the caller already holds: a consumer that stored `{label, handle, credential_id}`
    /// in its own manifest can refuse the handle when this vault-side id disagrees with
    /// that row.
    ///
    /// IT IS NOT A ROUTING KEY. Account-scoped routing joins on `account_id` plus
    /// `record_version`. A credential id is an OPERATOR-CHOSEN LABEL: it is hand-written,
    /// can differ between two records holding the same provider account, and means
    /// nothing to the provider. A consumer routing on it will drift silently.
    ///
    /// This discloses nothing new. A handle holder already receives the payload itself,
    /// plus `account_id`, `email`, and `org_name` where captured. The id is only the
    /// operator's name for material the caller is already being given.
    ///
    /// A principal-scoped `get_scoped` caller supplied the id, so echoing it adds no
    /// information. It is populated there too so successful get shapes stay consistent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
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
    /// provider has no known account claim or the token does not carry one. This field
    /// never contains the operator's credential id or the bearer handle; it contains only
    /// the provider's account identity.
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
    StoreError,
    VaultLocked,
    Corrupt,
    /// `get_many` exceeded the cap.
    TooManyItems,
    /// `report_auth_failure` carried a `provider_status` the contract does not treat as
    /// evidence the credential is dead. Refused rather than accepted-and-discarded, so a
    /// consumer whose classification is wrong is told on its first wrong report instead
    /// of at a mark that silently does nothing. `permanent`: the same status will never
    /// become a credential death, so a retry cannot succeed. The consumer's repair is to
    /// stop reporting that status, not to send it again.
    ReportStatusNotCredentialDeath,
    /// A fresh token minted for this request still misses its supplied `min_ttl_ms`.
    /// The credential remains usable for callers that ask for less time.
    TtlUnsatisfiable,
    /// `credential.get` resolved a signing key. Use `credential.sign` for private-key
    /// operations or `credential.public_key` for its public half; no retry can make the
    /// private PKCS#8 payload safe to return through `get`.
    ///
    /// This is emitted only after a handle resolves or a scoped read grant authorizes the
    /// credential, so it cannot distinguish an unknown or unauthorized capability.
    KindNotGettable,
    /// `credential.sign` was asked to sign with a credential that is not a signing
    /// key. THE FENCE, not a diagnostic: without it a handle for any stored secret
    /// could produce signatures under it and this module would be a general signing
    /// oracle. Permanent, because no retry makes an API key into a signing key.
    KindNotSignable,
    /// `credential.sign` was asked to sign more bytes than the cap allows.
    SignPayloadTooLarge,
}

/// The fleet-wide error-class vocabulary (error-class contract, ratified 2026-07-08;
/// normative doc: llm-runner/docs/error-class-contract.md). Classification is produced
/// here at the source. The class carries retry policy; the `ReadError` code carries the
/// request-specific remedy. The wire set is closed and pinned: see `ERROR_CLASS_WIRE_SET`.
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
    /// The produced retry classification for each fail-closed category.
    ///
    /// The class answers whether repeating this request can succeed; the code names the
    /// request-specific remedy. A resolved signing key rejected by `credential.get` is
    /// therefore `KindNotGettable`/`permanent`: retrying cannot reveal its private material,
    /// but `credential.sign` still serves the credential.
    ///
    /// This distinction does not weaken anti-enumeration. `get` reaches the signing-key
    /// guard only after resolving the handle, and `get_scoped` checks the caller's grant
    /// before looking up the record. Unknown or revoked handles and uncovered scoped callers
    /// still receive the uniform `NotFound` refusal.
    pub fn class(self) -> ErrorClass {
        match self {
            // A missing/revoked handle, corrupt record, unsupported refresh, a signing key
            // addressed through `get`, or a non-signing record addressed through `sign`:
            // nothing a retry can change.
            ReadError::NotFound
            | ReadError::Corrupt
            | ReadError::RefreshUnsupported
            | ReadError::KindNotGettable
            | ReadError::KindNotSignable
            | ReadError::ReportStatusNotCredentialDeath => ErrorClass::Permanent,
            // The refresh token is dead; a human must run a fresh login.
            ReadError::NeedsReauth => ErrorClass::AuthRequired,
            // A refresh attempt failed (provider may recover) or the master key is
            // unresolvable right now (keychain/lease may recover).
            ReadError::RefreshFailed | ReadError::StoreError | ReadError::VaultLocked => {
                ErrorClass::Transient
            }
            // Over the `get_many` cap, over the signing-payload cap, or a minimum-TTL
            // demand a fresh token cannot meet: reduce the request and retry. All are
            // bounds on ONE request rather than statements about the credential, which
            // separates them from the permanent arm.
            //
            // REDUCE-AND-RETRY, NEVER WAIT-AND-RETRY, and consumers do file this in the
            // transient family by reflex. Measured 2026-08-25: a careful consumer
            // mapped `context_overflow` into a retry-with-backoff arm, describing both
            // codes below as "transient load shapes". They are not -- each is a
            // compile-time constant, so an identical request retried after any backoff
            // fails identically forever. The name invites the misreading; the contract
            // ("exceeds request bounds, requiring a reduced batch size before retrying")
            // does not.
            //
            // It stops being merely a spin the moment a code under this class costs
            // something to evaluate. `ttl_unsatisfiable` refuses only after a real token
            // exchange has PROVEN the demand unsatisfiable, so a backoff loop on it buys
            // one upstream mint per attempt -- reproducing the exact amplification the
            // refusal exists to prevent, against a vendor budget shared with every other
            // holder of that App.
            ReadError::TooManyItems
            | ReadError::SignPayloadTooLarge
            | ReadError::TtlUnsatisfiable => ErrorClass::ContextOverflow,
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
    /// `code.class()`; it gives retry policy while `code` gives the remedy.
    pub class: ErrorClass,
}

/// Non-secret per-credential health.
#[derive(Debug, Serialize)]
pub struct StatusResult {
    pub ready: bool,
    pub last_error_code: Option<ReadError>,
    pub lease_held: bool,
    /// The credential id this status address resolved to. This field is FOR VERIFYING A
    /// BINDING the caller already holds: a consumer that stored
    /// `{label, handle, credential_id}` in its own manifest can refuse the handle when
    /// this vault-side id disagrees with that row.
    ///
    /// IT IS NOT A ROUTING KEY. Account-scoped routing joins on `account_id` plus
    /// `record_version`. A credential id is an OPERATOR-CHOSEN LABEL: it is hand-written,
    /// can differ between two records holding the same provider account, and means
    /// nothing to the provider. A consumer routing on it will drift silently.
    ///
    /// This discloses nothing new. A handle holder already receives the payload itself on
    /// `get`, plus `account_id`, `email`, and `org_name` where captured. The id is only the
    /// operator's name for material the caller is already entitled to receive.
    ///
    /// Absent for overall readiness (neither addressing form) or when the presented
    /// address did not resolve. A principal-scoped caller supplied the id, so echoing it
    /// adds no information; it is populated after the scoped lookup succeeds so both
    /// addressed status shapes agree.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    /// The record's current version, when a handle resolved to one.
    ///
    /// THE CHANGE CURSOR FOR A CONSUMER THAT MUST NOTICE A CREDENTIAL COMING BACK.
    /// `ready` answers "is it usable now"; this answers "has anything happened since I
    /// last looked", and together they let a poller distinguish a credential that was
    /// repaired from one that merely never broke.
    ///
    /// It matters because the vault CANNOT PUSH. subc has no module-to-client relay by
    /// deliberate design, so a consumer waiting on an unusable-to-usable transition has
    /// to ask. Before this field the only way to observe a change was `credential.get`,
    /// which MINTS on a stale record -- so polling for repair meant repeatedly buying
    /// upstream token exchanges, and a consumer holding off to avoid that cost would
    /// notice the repair late. `status` reads metadata only and never decrypts.
    ///
    /// Absent rather than zero when there is no handle (overall readiness) or the handle
    /// does not resolve: a sentinel version would compare as "older than everything" and
    /// a poller would read a revoked handle as a pending change forever.
    ///
    /// Free to serve: `meta()` already reads it on this path and it was being discarded.
    /// No new disclosure either -- `get` has always returned it.
    ///
    /// ONE DIRECTION ONLY: the version bumps on refresh and on replace. It does NOT bump
    /// when a credential is invalidated (that is a version-GATED compare-and-set, which
    /// would defeat itself by moving the version it matched on). So a stable version
    /// with `ready: false` is a normal reading, not a stuck cursor.
    ///
    /// See [`StatusResult::stale_pending`] for the mark that predicts a SLOW get on an
    /// otherwise healthy record -- the two fields answer different questions and a
    /// consumer sizing a timeout needs the other one.
    ///
    /// AND IT DOES NOT CATCH EVERY REPAIR -- read `ready`, not this, to answer "is it
    /// usable now". `reactivate` clears a wrong `needs_reauth` verdict WITHOUT touching
    /// the stored material, so a credential goes unusable-to-usable with this field
    /// unchanged. A consumer polling only the version would keep a repaired credential
    /// marked dead indefinitely.
    ///
    /// That is forced rather than an oversight: `record_version` is bound into the
    /// envelope's AAD (see `RecordBinding` in the store), so moving it means re-sealing
    /// the record. Re-sealing on the repair path would put a decrypt-and-encrypt cycle
    /// on the one route that exists to recover from a wrong verdict, and a failure
    /// halfway would leave a corrupt record where a recoverable one stood. The version
    /// tracks the MATERIAL; `ready` tracks the VERDICT; a repair can move either alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_version: Option<u64>,

    /// A consumer reported the current token refused, so the NEXT `get` must refresh
    /// before serving. Present only when a handle resolved.
    ///
    /// THIS IS A LATENCY PREDICTOR, NOT A HEALTH FIELD, and it exists because the two
    /// are not the same question. `ready` answers "would a get succeed" -- and on a
    /// stale-marked record the honest answer is YES, because the mark exists precisely
    /// so the next get refreshes rather than refusing. What `ready` cannot say is what
    /// that get will COST:
    ///
    ///   state=active, stale_pending=false  -> local read, sub-millisecond
    ///   state=active, stale_pending=TRUE   -> forces an upstream exchange, seconds
    ///   state=needs_reauth                 -> fails fast, no upstream call
    ///
    /// So a record can read healthy on every other field while the next call is three
    /// orders of magnitude slower than the one before it. Measured 2026-08-25 before
    /// this field existed: twelve status samples over five minutes, every one
    /// `ready: true, last_error_code: null`, with the mark already written to the store
    /// and its chain row committed. Nothing on the wire distinguished them.
    ///
    /// WHY IT IS PUBLISHED NOW rather than earlier: the field was withheld deliberately
    /// while no consumer polled this surface, on the grounds that a field added for a
    /// hypothetical caller is machinery nobody can test against a real requirement. That
    /// condition ended -- the first vault consumer warms a credential cache at startup
    /// and needs to SKIP the accounts that would overrun its bound, rather than
    /// discovering them by timing out. Skipping requires seeing the mark; the only other
    /// way to observe it was `credential.get`, which is the very call whose cost is in
    /// question.
    ///
    /// FREE TO SERVE, which is the whole reason this is a field and not a new verb:
    /// `stale_pending` is a PLAINTEXT column, `store::meta()` already selects it, and
    /// [`RecordMeta`] already carries it. This path was fetching the value and
    /// discarding it before serialization -- exactly the state `record_version` was in
    /// before it was published. No decrypt, no master key, no extra query.
    ///
    /// NO NEW DISCLOSURE: `ready: false` already tells a handle holder that someone
    /// observed a failure on this credential. This says only that a repair is pending on
    /// one that still works.
    ///
    /// ABSENT rather than `false` when no handle was presented or the handle did not
    /// resolve -- a defaulted `false` would read as "no repair pending" for a revoked
    /// handle, which is an assertion this path has no basis to make.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_pending: Option<bool>,
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
    // The store exposes no public way to make one read query fail. This test-only
    // switch injects that Result after the real lookup so route tests can prove the
    // diagnostic keeps a lookup failure distinct without shipping a test capability.
    #[cfg(test)]
    scoped_grant_lookup_error_for_test: std::sync::atomic::AtomicBool,
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

fn push_u32(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u32).to_be_bytes());
}

fn push_string(out: &mut Vec<u8>, value: &str) {
    push_u32(out, value.len());
    out.extend_from_slice(value.as_bytes());
}

fn push_optional_string(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            out.push(1);
            push_string(out, value);
        }
        None => out.push(0),
    }
}

fn encoded_grant_tuple(tuple: &GrantTuple) -> Vec<u8> {
    let mut encoded = Vec::new();
    push_string(&mut encoded, &tuple.selector_kind);
    push_string(&mut encoded, &tuple.selector);
    push_string(&mut encoded, &tuple.operation);
    encoded
}

fn list_scoped_view(credentials: &[ListScopedCredential], grants: &[GrantTuple]) -> String {
    let mut digest_input = b"claustrum.list_scoped.view.v1".to_vec();
    digest_input.push(1);
    push_u32(&mut digest_input, credentials.len());
    for credential in credentials {
        push_string(&mut digest_input, &credential.id);
        push_u32(&mut digest_input, credential.categories.len());
        for category in &credential.categories {
            push_string(&mut digest_input, category);
        }
        push_string(&mut digest_input, &credential.state);
        push_u32(&mut digest_input, credential.operations.len());
        for operation in &credential.operations {
            push_string(&mut digest_input, operation);
        }
        push_optional_string(&mut digest_input, credential.account_id.as_deref());
        push_optional_string(&mut digest_input, credential.email.as_deref());
        push_optional_string(&mut digest_input, credential.org_name.as_deref());
    }
    digest_input.push(2);
    push_u32(&mut digest_input, grants.len());
    for grant in grants {
        digest_input.extend_from_slice(&encoded_grant_tuple(grant));
    }
    let digest = ring::digest::digest(&ring::digest::SHA256, &digest_input);
    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
}

fn project_list_scoped(snapshot: ScopedListSnapshot) -> ListScopedResult {
    let mut grant_tuples: Vec<GrantTuple> = snapshot
        .grants
        .into_iter()
        .map(|grant| GrantTuple {
            selector_kind: grant.selector_kind.as_str().to_string(),
            selector: grant.selector,
            operation: grant.operation.as_str().to_string(),
        })
        .collect();
    grant_tuples.sort_by_key(encoded_grant_tuple);

    let mut credentials: Vec<ListScopedCredential> = snapshot
        .rows
        .into_iter()
        .map(|row| {
            let (account_id, email, org_name) = row
                .identity
                .map(|identity| (identity.account_id, identity.email, identity.org_name))
                .unwrap_or((None, None, None));
            ListScopedCredential {
                credential_type: credentials_core::catalog::credential_type(&row.id).to_string(),
                serves: credentials_core::catalog::serves_for(&row.id)
                    .iter()
                    .map(|vendor| vendor.as_str().to_string())
                    .collect(),
                refresh_adapter: row.refresh_adapter.clone(),
                id: row.id,
                categories: row.categories,
                state: row.state.as_str().to_string(),
                record_version: row.record_version,
                operations: row
                    .operations
                    .iter()
                    .map(|operation| operation.as_str().to_string())
                    .collect(),
                account_id,
                email,
                org_name,
            }
        })
        .collect();
    credentials.sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
    let view = list_scoped_view(&credentials, &grant_tuples);
    ListScopedResult {
        credentials,
        grants: grant_tuples.len(),
        grant_tuples,
        view,
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A known expiry meets the caller's demand only when its remaining lifetime is strictly
/// greater than the threshold. An absent expiry is not proof of a short lifetime, so it
/// cannot prove the demand unsatisfiable.
fn meets_min_ttl(record: &credentials_core::record::VaultRecord, min_ttl_ms: i64) -> bool {
    record
        .expires_at_ms
        .map(|expires_at_ms| now_ms().saturating_add(min_ttl_ms) < expires_at_ms)
        .unwrap_or(true)
}

fn classify_scoped_coverage(coverage: ScopedCoverage) -> Option<ScopedReadRefusal> {
    match coverage {
        ScopedCoverage {
            caller_active_grants: 0,
            ..
        } => Some(ScopedReadRefusal::NoGrant),
        ScopedCoverage { covered: true, .. } => None,
        ScopedCoverage {
            id_exists: false, ..
        } => Some(ScopedReadRefusal::NotFound),
        ScopedCoverage {
            holds_category_selector: true,
            id_category_count: Some(0),
            ..
        } => Some(ScopedReadRefusal::Uncategorized),
        _ => Some(ScopedReadRefusal::NoGrant),
    }
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
            #[cfg(test)]
            scoped_grant_lookup_error_for_test: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn enroll_propose(
        &self,
        params: &EnrollProposeParams,
    ) -> Result<EnrollmentProposal, EnrollmentError> {
        self.engine
            .store()
            .propose_enrollment(&params.proposed_name, &params.request_secret_hash)
    }

    pub fn enroll_poll(
        &self,
        params: &EnrollPollParams,
    ) -> Result<EnrollmentPoll, EnrollmentError> {
        self.engine
            .store()
            .poll_enrollment(&params.request_id, &params.request_secret)
    }

    pub fn enroll_rotate(
        &self,
        params: &EnrollRotateParams,
    ) -> Result<EnrollmentRotation, EnrollmentError> {
        self.engine
            .store()
            .rotate_enrollment(&params.token, params.expected_token_generation)
    }

    /// Sign exact bytes with a signing-key credential. THE KEY NEVER LEAVES THIS
    /// PROCESS.
    ///
    /// A handle retains the operator-driven signing ceremony. A principal-scoped
    /// credential id instead requires an operation-specific sign grant; a read grant
    /// never reaches this path as signing authority.
    ///
    /// FENCED ON KIND. Only `CredentialKind::SigningKey` records are signable;
    /// everything else refuses `KindNotSignable`. Without that fence a grant or handle
    /// for any stored secret could produce signatures under it.
    ///
    /// Deliberately does NOT force-refresh: a signing key is static material with no
    /// refresh adapter, so a get here reads what is stored and nothing is minted.
    pub async fn sign(
        &self,
        connection_id: u64,
        principal: Option<&Principal>,
        params: &SignParams,
    ) -> Result<SignResult, ReadError> {
        let authorization = params.authorization().ok_or(ReadError::NotFound)?;
        let credential_id = match authorization {
            SignAuthorization::Handle(handle) => {
                // Same limiter, same position as `get`: BEFORE resolution and keyed by the
                // presented handle, so a sweep of unknown handles trips the detector here too
                // rather than only on the get path.
                self.check_limiter(connection_id, handle).await;
                match self.engine.store().resolve_handle(handle) {
                    Ok(id) => id,
                    Err(StoreOpError::NotFound) => return Err(ReadError::NotFound),
                    Err(e) => return Err(map_store_error(&e)),
                }
            }
            SignAuthorization::Scoped(credential_id) => {
                self.authorize_scoped_as(
                    principal,
                    params.enrollment_token.as_deref(),
                    credential_id,
                    GrantOperation::Sign,
                )?;
                credential_id.to_string()
            }
        };

        let record = match self.engine.store().get(&credential_id) {
            Ok(r) => r,
            Err(StoreOpError::NotFound) if params.credential_id.is_some() => {
                self.record_scoped_refusal(principal, &credential_id, ScopedReadRefusal::NotFound);
                return Err(ReadError::NotFound);
            }
            Err(e) => return Err(map_store_error(&e)),
        };

        // The fence is checked before the payload is decoded, so a non-signing
        // credential refuses identically whatever bytes were presented.
        if record.kind != credentials_core::record::CredentialKind::SigningKey {
            return Err(ReadError::KindNotSignable);
        }

        let payload = base64::engine::general_purpose::STANDARD
            .decode(params.payload_b64.as_bytes())
            .map_err(|_| ReadError::SignPayloadTooLarge)?;
        let pem = std::str::from_utf8(record.payload.expose()).map_err(|_| ReadError::Corrupt)?;
        match credentials_core::signing::sign_ed25519(pem, &payload) {
            Ok(sig) => Ok(SignResult {
                signature_b64: sig.signature_b64,
                key_id: sig.key_id,
            }),
            Err(credentials_core::signing::SignError::TooLarge { .. }) => {
                Err(ReadError::SignPayloadTooLarge)
            }
            // An unusable key is OUR bytes failing, not the caller's request: the
            // record holds something that is not a signing key despite being typed as
            // one, which is the same class as a record that will not decrypt.
            Err(credentials_core::signing::SignError::UnusableKey(_)) => Err(ReadError::Corrupt),
        }
    }

    /// Return the public half of a signing-key record without ever serving its private
    /// payload.
    ///
    /// A handle retains the existing limiter placement. A credential id instead uses a
    /// route-bound principal's read grant: publishing a verifier key must not require the
    /// authority to create signatures. Both forms retain the signing-key kind fence, and
    /// credential-id refusals leave trimmable operator diagnostics without changing their
    /// wire bodies or appending to the untrimmable audit chain.
    pub async fn public_key(
        &self,
        connection_id: u64,
        principal: Option<&Principal>,
        params: &PublicKeyParams,
    ) -> Result<PublicKeyResult, ReadError> {
        let authorization = params.authorization().ok_or(ReadError::NotFound)?;
        let credential_id = match authorization {
            PublicKeyAuthorization::Handle(handle) => {
                // Match `get` and `sign`: rate-limit the presented handle before resolving
                // it, so unknown-handle sweeps reach the same detector as valid traffic.
                self.check_limiter(connection_id, handle).await;
                match self.engine.store().resolve_handle(handle) {
                    Ok(id) => id,
                    Err(StoreOpError::NotFound) => return Err(ReadError::NotFound),
                    Err(e) => return Err(map_store_error(&e)),
                }
            }
            PublicKeyAuthorization::Scoped(credential_id) => {
                self.authorize_scoped_as(
                    principal,
                    params.enrollment_token.as_deref(),
                    credential_id,
                    GrantOperation::Read,
                )?;
                credential_id.to_string()
            }
        };

        let record = match self.engine.store().get(&credential_id) {
            Ok(record) => record,
            Err(StoreOpError::NotFound) if params.credential_id.is_some() => {
                self.record_scoped_refusal(principal, &credential_id, ScopedReadRefusal::NotFound);
                return Err(ReadError::NotFound);
            }
            Err(e) if params.credential_id.is_some() => {
                self.record_scoped_refusal(
                    principal,
                    &credential_id,
                    ScopedReadRefusal::StoreError,
                );
                return Err(map_store_error(&e));
            }
            Err(e) => return Err(map_store_error(&e)),
        };

        // Check the kind before parsing bytes so non-signing records receive the
        // same permanent refusal regardless of the secret they carry.
        if record.kind != credentials_core::record::CredentialKind::SigningKey {
            if params.credential_id.is_some() {
                self.record_scoped_refusal(principal, &credential_id, ScopedReadRefusal::WrongKind);
            }
            return Err(ReadError::KindNotSignable);
        }

        let pem = std::str::from_utf8(record.payload.expose()).map_err(|_| ReadError::Corrupt)?;
        let public = credentials_core::signing::public_key_ed25519(pem).map_err(|_| {
            // A record typed as a signing key but holding unusable bytes is vault
            // corruption, not a caller request error, just as it is for `sign`.
            ReadError::Corrupt
        })?;
        Ok(PublicKeyResult {
            public_key_hex: public.public_key_hex,
            key_id: public.key_id,
            algorithm: "ed25519",
        })
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
            .get_with_refresh_status(&credential_id, params.min_ttl_ms, params.force_refresh)
            .await
        {
            Ok(refreshed) => {
                // A refusal is sound only after THIS request minted once for its stated
                // demand. The status excludes static reads and a single-flight follower
                // that merely observed another writer's newer version, neither of which
                // can prove a fresh token fails this caller's request.
                if refreshed.refreshed_for_min_ttl
                    && params
                        .min_ttl_ms
                        .is_some_and(|min_ttl_ms| !meets_min_ttl(&refreshed.record, min_ttl_ms))
                {
                    return err(ReadError::TtlUnsatisfiable);
                }
                let record = refreshed.record;
                if record.kind == credentials_core::record::CredentialKind::SigningKey {
                    // The handle resolved, so this is not an absence verdict: the signing key
                    // remains serviceable through `sign` and `public_key`, but its private
                    // PKCS#8 payload must never be served through `get`.
                    return err(ReadError::KindNotGettable);
                }
                if record.payload.expose().is_empty() {
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
                            o.refresh_token.expose(),
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
                            o.access_token.expose(),
                        )
                    }
                    _ => None,
                }
                .or_else(|| record.identity.account_id.clone());
                GetOutcome::Ok(GetResult {
                    payload: record.payload.into_inner().to_vec(),
                    expires_at_ms: record.expires_at_ms,
                    record_version: record.record_version,
                    credential_id: Some(credential_id),
                    project_id,
                    account_id,
                    email: record.identity.email.clone(),
                    org_name: record.identity.org_name.clone(),
                })
            }
            Err(e) => err(map_engine_error(&e)),
        }
    }

    /// Test-only: make the next scoped grant lookup take its store-error refusal arm.
    #[cfg(test)]
    pub(crate) fn force_scoped_grant_lookup_error_for_test(&self) {
        self.scoped_grant_lookup_error_for_test
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn scoped_principal_identity(principal: Option<&Principal>) -> (&str, Option<&str>) {
        match principal {
            Some(Principal::Reserved { module_id }) => ("reserved", Some(module_id.as_str())),
            Some(Principal::Direct) => ("direct", None),
            Some(Principal::Unverified) | None => ("unverified", None),
        }
    }

    fn observed_principal(principal: Option<&Principal>) -> Option<AuthEventPrincipal<'_>> {
        match principal {
            Some(Principal::Reserved { module_id }) => {
                Some(AuthEventPrincipal::Reserved(module_id.as_str()))
            }
            Some(Principal::Direct) => Some(AuthEventPrincipal::Direct),
            Some(Principal::Unverified) => Some(AuthEventPrincipal::Unverified),
            None => None,
        }
    }

    fn record_scoped_refusal(
        &self,
        principal: Option<&Principal>,
        credential_id: &str,
        refusal: ScopedReadRefusal,
    ) {
        let (principal_kind, principal_id) = Self::scoped_principal_identity(principal);
        let _ = self.engine.store().record_scoped_read_refusal(
            credential_id,
            principal_kind,
            principal_id,
            refusal,
        );
    }

    /// Resolve who is asking: a supervised module, or a consumer holding an enrollment
    /// token.
    ///
    /// TWO PRINCIPAL SOURCES, AND THEY ARE NOT EQUIVALENT. `Principal::Reserved` is the
    /// supervisor's attestation, delivered as a launch nonce in the module's environment
    /// — the vault trusts it because the daemon stamps it at route-bind. An enrollment
    /// token is the vault's OWN attestation: it minted it, hashed it, and can revoke it.
    /// Neither derives from the other, which is the point — a host-launched plugin has no
    /// launch nonce and can never have one, so without this arm it could hold a category
    /// grant and still be refused for not being a supervised module.
    ///
    /// THE TOKEN IS CHECKED BEFORE THE BUS PRINCIPAL, and deliberately. Presenting a
    /// token is an explicit claim about identity; the bus principal is ambient. A
    /// supervised module that also presents a token means it, and honouring the ambient
    /// identity instead would silently route the operation to different grants than the
    /// caller named.
    ///
    /// A BAD TOKEN IS NOT A FALLBACK TO THE BUS PRINCIPAL. If a token is presented and
    /// does not resolve, the call refuses. Falling back would mean a consumer whose token
    /// was revoked keeps working from whatever ambient identity it happens to have, which
    /// makes revocation conditional on the caller's transport rather than on the vault.
    fn scoped_principal(
        &self,
        principal: Option<&Principal>,
        enrollment_token: Option<&str>,
    ) -> Option<(&'static str, String)> {
        if let Some(token) = enrollment_token {
            return match self.engine.store().resolve_enrollment_token(token) {
                Ok(Some((name, _generation))) => Some(("enrolled", name)),
                // An unresolvable token and a store failure are the same answer to the
                // caller. They differ in `auth_events`, which is where the operator can
                // tell a revoked consumer from a broken store.
                Ok(None) | Err(_) => None,
            };
        }
        match principal {
            Some(Principal::Reserved { module_id }) => Some(("reserved", module_id.clone())),
            Some(Principal::Direct) | Some(Principal::Unverified) | None => None,
        }
    }

    /// Evaluate the one operation-scoped coverage predicate before loading sealed data,
    /// with an optional enrollment token — the only way a host-launched consumer can be
    /// authorized at all.
    ///
    /// THERE IS DELIBERATELY NO TOKEN-LESS WRAPPER. One existed, and its only effect was
    /// to let a call site skip the caller's identity without saying so: three of six
    /// scoped surfaces used it and were unreachable by enrolled consumers, each looking
    /// correct in isolation because an unauthorized scoped call and a surface that cannot
    /// read identity return the SAME body. Passing `None` explicitly is the same code and
    /// says what it does.
    fn authorize_scoped_as(
        &self,
        principal: Option<&Principal>,
        enrollment_token: Option<&str>,
        credential_id: &str,
        operation: GrantOperation,
    ) -> Result<(), ReadError> {
        let Some((kind, id)) = self.scoped_principal(principal, enrollment_token) else {
            self.record_scoped_refusal(principal, credential_id, ScopedReadRefusal::NoGrant);
            return Err(ReadError::NotFound);
        };
        let coverage =
            self.engine
                .store()
                .evaluate_scoped_coverage(kind, &id, credential_id, operation);
        #[cfg(test)]
        let coverage = if self
            .scoped_grant_lookup_error_for_test
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            Err(StoreOpError::Store(
                "test scoped grant lookup failure".into(),
            ))
        } else {
            coverage
        };

        let refusal = match coverage {
            Err(_) => Some(ScopedReadRefusal::StoreError),
            Ok(coverage) => classify_scoped_coverage(coverage),
        };
        if let Some(refusal) = refusal {
            self.record_scoped_refusal(principal, credential_id, refusal);
            return Err(ReadError::NotFound);
        }
        // THE ONE CHOKEPOINT EVERY SCOPED OP PASSES THROUGH, which is why the record sits
        // here rather than at `get_scoped`, `sign` and `public_key` separately: three
        // call sites is three chances for the next scoped op to be added without one.
        //
        // Records the RESOLVED principal (`kind`, `id`) rather than the bus principal the
        // refusal path logs. For an enrollment token those differ -- the bus says
        // `direct` and the grant was matched against `enrolled:<name>` -- and the useful
        // answer is which principal's grant was exercised, not which socket it arrived on.
        //
        // Best-effort, deliberately: a diagnostic that could fail an authorized read
        // would be worse than the blindness it cures. The store call is idempotent, so
        // this is one INSERT ever and a cheap NOT EXISTS thereafter.
        let _ =
            self.engine
                .store()
                .record_scoped_first_use(credential_id, kind, Some(&id), operation);
        Ok(())
    }

    /// Enumerate every row covered by the caller's own grants from one store snapshot.
    ///
    /// *** NO OPERATOR TOOL CAN CALL THIS, SO ITS LIVE EXERCISE IS NOT OURS. ***
    /// The match below accepts `Principal::Reserved` only, and that principal requires a
    /// supervisor-issued launch nonce. `ck-auth` and `vault_read_probe` both bind as
    /// `Direct`, so neither the CLI nor the acceptance ladder in `scripts/accept-deploy.sh`
    /// can reach this op at all — the ladder is not missing a leg someone forgot to write,
    /// it is structurally incapable of proving this one. A reader who assumes otherwise
    /// will write an acceptance step that cannot exist; that mistake has already been made
    /// here once.
    ///
    /// WHAT THAT LEAVES. This op shipped in v0.1.3 and, as of 2026-09-19, has never served
    /// a live request on any vault: the only consumer that wants it is BROCA's credential
    /// audit, and it needs category grants that are not migrated in yet. Its correctness
    /// is therefore warranted by a SUPERVISED CONSUMER IN ANOTHER REPOSITORY, running on a
    /// schedule this repository does not control. That is invisible from inside this tree
    /// no matter how carefully it is read — the tests below look like the evidence and are
    /// not, because they were written against the behaviour their author imagined.
    ///
    /// So: if BROCA's audit stops running, this op silently returns to never-called, and
    /// nothing here will say so. Their detector failing is the signal for both seats, which
    /// is why it must not be disabled at either end as a local cleanup.
    pub fn list_scoped(
        &self,
        principal: Option<&Principal>,
        params: &ListScopedParams,
    ) -> Result<ListScopedResult, ReadError> {
        let Some((principal_kind, principal_id)) =
            self.scoped_principal(principal, params.enrollment_token.as_deref())
        else {
            self.record_scoped_refusal(
                principal,
                "credential.list_scoped",
                ScopedReadRefusal::NoGrant,
            );
            return Err(ReadError::NotFound);
        };
        // PASS THE RESOLVED KIND, NOT A LITERAL. This read `list_scoped_snapshot("reserved",
        // ...)` with `let _ = principal_kind;` one line above -- the resolved kind computed
        // and then explicitly discarded. An enrollment token resolves to `enrolled`, so an
        // enrolled consumer's grants were looked up under a principal kind it does not
        // have: every row filtered out, an empty inventory, and NO REFUSAL EVENT, because
        // authorization succeeded and the query simply matched nothing.
        //
        // That is the worst available shape. An empty list is a legitimate answer for a
        // caller whose grants cover nothing, so the consumer sees "you have access to
        // nothing" and the vault sees a successful call. Nothing on either side is wrong.
        //
        // It survived because the token path was tested on `get_scoped` and not on
        // `list_scoped`, and the two resolve their principal through the same helper --
        // so reading either one in isolation shows correct code. Found by the consumer
        // that would have hit it, before they wrote a line against it.
        let result = self
            .engine
            .store()
            .list_scoped_snapshot(principal_kind, &principal_id)
            .map(project_list_scoped)
            .map_err(|_| ReadError::StoreError)?;
        // RECORD THE SUCCESS, because this op's SILENCE WAS INDISTINGUISHABLE FROM ITS
        // ABSENCE, and that cost a consumer a debugging session on 2026-09-20.
        //
        // Every other scoped op records first use through `authorize_scoped`. This one
        // does not go through it, so a successful enumeration wrote NOTHING while a
        // refusal wrote a row. An operator reading `auth_events` therefore got the same
        // empty result for "the consumer is working" and "the consumer never called" --
        // and I offered exactly that reading to the insula seat as evidence, which is
        // how a null instrument nearly sent them hunting an ordering bug that did not
        // exist.
        //
        // It is the worst op to leave silent: it is the one a consumer calls FIRST, so
        // its first success is the moment a cutover is proven.
        //
        // Subject is the OP rather than a credential id, matching the refusal rows and
        // for the same reason -- the answer is "this principal enumerated", not "this
        // principal touched row X". Best-effort and idempotent like the other site: a
        // diagnostic that could fail an authorized read would be worse than blindness.
        let _ = self.engine.store().record_scoped_first_use(
            "credential.list_scoped",
            principal_kind,
            Some(&principal_id),
            GrantOperation::Read,
        );
        Ok(result)
    }

    /// Serve a credential-id read after the route layer captures the bind's principal.
    /// An uncovered principal is rejected before the credential lookup, so it cannot
    /// turn this operation into a vault inventory oracle.
    pub async fn get_scoped(
        &self,
        principal: Option<&Principal>,
        params: &GetScopedParams,
    ) -> GetOutcome {
        if let Err(code) = self.authorize_scoped_as(
            principal,
            params.enrollment_token.as_deref(),
            &params.credential_id,
            GrantOperation::Read,
        ) {
            return err(code);
        }

        match self
            .engine
            // `force_refresh` stays hardcoded off: no scoped caller can ask for it, and
            // it is a lever that spends an upstream mint on demand. It is a deliberate
            // omission rather than an oversight -- the same consumer that needs
            // `min_ttl_ms` confirmed its own trait cannot express force_refresh at all.
            .get_with_refresh_status(&params.credential_id, params.min_ttl_ms, false)
            .await
        {
            Ok(refreshed) => {
                // Identical to the handle path: a refusal is sound only after THIS
                // request minted once for its stated demand. Static reads and
                // single-flight followers are excluded, because neither proves a fresh
                // token fails this caller.
                if refreshed.refreshed_for_min_ttl
                    && params
                        .min_ttl_ms
                        .is_some_and(|min_ttl_ms| !meets_min_ttl(&refreshed.record, min_ttl_ms))
                {
                    return err(ReadError::TtlUnsatisfiable);
                }
                let record = refreshed.record;
                if record.kind == credentials_core::record::CredentialKind::SigningKey {
                    // The caller's read grant already authorized this record, so this is not
                    // an absence verdict: the signing key remains serviceable through `sign`
                    // and `public_key`, but its private PKCS#8 payload never leaves `get`.
                    return err(ReadError::KindNotGettable);
                }
                if record.payload.expose().is_empty() {
                    match self
                        .engine
                        .store()
                        .quarantine_if_version(&params.credential_id, record.record_version)
                    {
                        Ok(true) => return err(ReadError::Corrupt),
                        Ok(false) => return err(ReadError::RefreshFailed),
                        Err(e) => return err(map_store_error(&e)),
                    }
                }

                let is_antigravity = record.refresh_adapter.as_deref()
                    == Some(credentials_core::refresh_adapters::antigravity::ADAPTER_NAME);
                let project_id = if is_antigravity {
                    record.oauth.as_ref().and_then(|o| {
                        credentials_core::refresh_adapters::antigravity::effective_project_id(
                            o.refresh_token.expose(),
                        )
                    })
                } else {
                    None
                };
                let account_id = match (&record.refresh_adapter, &record.oauth) {
                    (Some(adapter), Some(o)) => {
                        credentials_core::oauth_login::account_id_for_adapter(
                            adapter,
                            o.access_token.expose(),
                        )
                    }
                    _ => None,
                }
                .or_else(|| record.identity.account_id.clone());
                GetOutcome::Ok(GetResult {
                    payload: record.payload.into_inner().to_vec(),
                    expires_at_ms: record.expires_at_ms,
                    record_version: record.record_version,
                    // The principal supplied this id; echo it after the successful read so
                    // scoped and handle-authorized success bodies keep one shape.
                    credential_id: Some(params.credential_id.clone()),
                    project_id,
                    account_id,
                    email: record.identity.email.clone(),
                    org_name: record.identity.org_name.clone(),
                })
            }
            Err(EngineError::Store(StoreOpError::NotFound)) => {
                self.record_scoped_refusal(
                    principal,
                    &params.credential_id,
                    ScopedReadRefusal::NotFound,
                );
                err(ReadError::NotFound)
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

    /// Report a consumer-observed auth failure. Refreshable credentials are marked
    /// stale so their next get attempts recovery; static credentials still latch
    /// needs_reauth. Rate-limited via the same
    /// limiter (a flood of reports is itself an anomaly). A 401/403 is the
    /// meaningful signal; other statuses are accepted but only a clear auth failure
    /// invalidates.
    pub async fn report_auth_failure(
        &self,
        connection_id: u64,
        principal: Option<&Principal>,
        params: &ReportAuthFailureParams,
    ) -> Result<(), ReadError> {
        // TWO ADDRESSES, EXACTLY ONE OF THEM, mirroring `status` above rather than
        // inventing a second dispatch shape. `scoped` is carried forward because it
        // decides the audit actor: a handle holder is anonymous and the channel number is
        // all there is, while a scoped caller has a principal that is KNOWN HERE and must
        // not be discarded.
        let (credential_id, scoped) = match (&params.handle, &params.credential_id) {
            (Some(handle), None) => {
                // Rate-limit on the presented handle (before resolution), like get — a
                // flood of report_auth_failure (malicious invalidation DoS) is itself an
                // anomaly.
                self.check_limiter(connection_id, handle).await;
                match self.engine.store().resolve_handle(handle) {
                    Ok(id) => (id, false),
                    Err(StoreOpError::NotFound) => return Err(ReadError::NotFound),
                    Err(e) => return Err(map_store_error(&e)),
                }
            }
            (None, Some(credential_id)) => {
                // An unknown id and an ungranted id must be INDISTINGUISHABLE here, for
                // the same reason they are on `get_scoped` and `status`: telling them
                // apart turns this into an inventory oracle. `authorize_scoped` records
                // the discriminated reason in `auth_events` locally and returns one code.
                self.authorize_scoped_as(
                    principal,
                    params.enrollment_token.as_deref(),
                    credential_id,
                    GrantOperation::Read,
                )?;
                (credential_id.clone(), true)
            }
            // Both or neither is a malformed request, not an addressing question. It
            // answers as `NotFound` rather than a distinct code so that a caller cannot
            // use the difference to probe which of two ids exists by pairing them.
            (Some(_), Some(_)) | (None, None) => return Err(ReadError::NotFound),
        };

        // Only an authentication failure (401/403) invalidates; a 5xx/429 is a
        // provider hiccup, not a dead credential.
        //
        // THE STATUS IS THE TRIGGER AND THAT IS A DESIGN DEFECT, recorded here because
        // it cost a real incident on 2026-08-17. A consumer took GitHub's 403 on a
        // reactions call -- "this token is valid and lacks one permission" -- and
        // reported it, which marked a seconds-old, perfectly good App credential
        // needs-reauth. Every later call then refused at RESOLUTION, before dispatch, so
        // the response-body logging built to diagnose the 403 could never fire: the
        // consequence of the failure disabled the path to its own explanation.
        //
        // The vault CANNOT interpret a status code. Whether 403 means "credential dead"
        // or "credential fine, endpoint forbidden" is provider-specific knowledge only
        // the consumer holds -- GitHub uses it for permissions and rate limits, xAI for
        // an entitlement lapse. Same number, opposite meanings, and this surface sees
        // only the number.
        //
        // So the honest input would be the consumer's JUDGEMENT ("I believe this
        // credential is invalid") with the status carried as diagnostic detail. The
        // field being NAMED `provider_status` actively invites the wrong behaviour: a
        // parameter named after a wire value asks to be filled with the wire value, and
        // a competent implementation read it exactly that way.
        //
        // Not changed unilaterally -- other consumers report against this shape today,
        // and BROCA's providers may well use 403 as a genuine credential signal. The
        // CONTRACT rule is the fix available without breaking them: REPORT ONLY WHEN YOU
        // BELIEVE THE CREDENTIAL IS INVALID, NEVER MERELY BECAUSE A CALL WAS REFUSED. The invalidate is VERSION-GATED: it
        // fires only if the credential is still at the record_version the consumer was
        // served, so a stale report for a since-refreshed credential is a silent no-op
        // (and a consumer can only ever kill the exact version it saw, not whatever is
        // current). The invalidate audits the revocation feedback in the chain atomically
        // (actor = the route channel; see below for why that is not a caller identity).
        // A STATUS THE CONTRACT SAYS IS NOT A CREDENTIAL DEATH IS REFUSED, NOT IGNORED.
        //
        // This handler has only ever acted on 401 and 403, so a consumer reporting a 429
        // quota refusal or a 5xx provider hiccup was already having its report discarded
        // -- correctly, and INVISIBLY. A consumer whose classification is wrong got back
        // success and a mark that silently did nothing, so the defect survived in the
        // only place it could not be seen.
        //
        // Refusing costs the consumer nothing it can observe: it already holds the
        // credential, and the report is advisory. That asymmetry is why this is not the
        // same decision as the limiter's alarm-and-serve on the fetch path -- refusing a
        // FETCH is an outage, refusing a redundant REPORT denies nothing. I had both
        // under one rule because they share a limiter call, not because the argument
        // carried across.
        //
        // 403 STAYS HONOURED, and this is the part measured rather than reasoned. Across
        // every report this vault has taken (72 on 2026-09-19), exactly one real
        // consumer 403 exists: `oauth:xai` at 2026-08-21 08:05, v156, applied. It was a
        // GENUINE DEATH -- an operator re-logged in at 14:54 and it has refreshed cleanly
        // every six hours since, and nothing repairs a misclassification. So xAI does use
        // 403 as a credential signal while GitHub uses it for permission refusals, and
        // this surface sees only the number. Refusing 403 would fail toward a dead
        // credential that looks healthy, which is the worse direction.
        //
        // The resolution when a SECOND provider turns up using 403: a per-adapter
        // declared policy rather than one global list, with a PERMISSIVE default so an
        // adapter that has not spoken behaves exactly as today. One 403 in seventy-two
        // does not justify that table yet.
        if !matches!(params.provider_status, 401 | 403) {
            return Err(ReadError::ReportStatusNotCredentialDeath);
        }
        {
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
            //
            // AND FOR THE SCOPED ARM THAT QUESTION IS NOW SETTLED, which is why `scoped`
            // is carried down here. A scoped report is authorized BY the principal: the
            // grant lookup that admitted this call already read the name, so recording it
            // discloses nothing the write did not already depend on, and it is not the
            // "should we identify anonymous reporters" question above. Writing `conn-N`
            // for a caller whose identity authorized the write would discard a value held
            // one line up -- this repo has three separate instances of that defect on
            // record (`mint_handle` naming a credential but not which handle, a peer's
            // limiter holding a principal and writing `conn-N`, a slot pin recording the
            // slot rather than its occupant) and is not adding a fourth.
            let actor = match (scoped, principal) {
                (true, Some(Principal::Reserved { module_id })) => module_id.clone(),
                // Scoped with no reserved principal cannot happen -- `authorize_scoped`
                // refused above -- but the actor must stay a total function rather than
                // panicking on a route-plane input, so it degrades to the channel form.
                _ => format!("conn-{connection_id}"),
            };
            let parsed = parse_credential_id(&credential_id);
            let refreshable = default_refresh_adapter(parsed.method, &parsed.provider).is_some();
            let audit = AuditCtx {
                op: AuditOp::ReportAuthFailure,
                actor: &actor,
                alarm: None,
            };
            // `kind` names the chosen state-machine arm because `applied` alone
            // cannot distinguish a stale marker from a terminal latch. The status
            // remains diagnostic detail: 401 and 403 carry different provider facts.
            // Resolved with the SAME helper the authorization used, so the audit line
            // cannot disagree with the decision that let the report through.
            let enrolled_reporter = self
                .scoped_principal(principal, params.enrollment_token.as_deref())
                .and_then(|(kind, id)| (kind == "enrolled").then_some(id));
            let observation = credentials_core::store::AuthObservation {
                kind: if refreshable {
                    AuthEventKind::ConsumerReportStale.as_str()
                } else {
                    AuthEventKind::ConsumerReportLatch.as_str()
                },
                provider_status: Some(params.provider_status),
                detail: None,
                reporter_source: params
                    .reporter_source
                    .as_deref()
                    .map(ReporterSource::from_wire),
                // NAME THE REPORTER, NOT THE TRANSPORT. An enrolled consumer binds as
                // Direct and proves who it is with its token, so reading the bus
                // principal here logged `direct` with no id for a report that was
                // authorized as `enrolled:<name>` -- the operator saw the socket instead
                // of the caller. Resolved the same way the authorization was.
                principal: match enrolled_reporter.as_deref() {
                    Some(name) => Some(AuthEventPrincipal::Enrolled(name)),
                    None => Self::observed_principal(principal),
                },
            };
            if refreshable {
                self.engine
                    .store()
                    .mark_stale_if_version_reported(
                        &credential_id,
                        params.record_version,
                        audit,
                        observation,
                    )
                    .map_err(|e| map_store_error(&e))?;
            } else {
                self.engine
                    .store()
                    .invalidate_if_version_reported(
                        &credential_id,
                        params.record_version,
                        audit,
                        Some(observation),
                    )
                    .map_err(|e| map_store_error(&e))?;
            }
        }
        Ok(())
    }

    /// Non-secret status: per-credential health, or overall readiness when unaddressed.
    ///
    /// `lease_held`/`ready` reflect the fenced-out latch: a daemon that has lost the
    /// single-writer lease to a newer instance (`is_fenced_out`) reports `lease_held =
    /// false` and is never `ready`, so this status agrees with the health probe instead
    /// of always claiming a healthy lease. A handle probe runs the per-connection limiter
    /// FIRST (keyed by the presented handle, like `get`), so a status-based enumeration
    /// sweep of unknown handles trips the same anomaly alarm rather than slipping past it.
    /// A credential-id probe instead requires a route-bound principal's read grant.
    /// KNOWN DIVERGENCE FROM THE VERB IT DESCRIBES, measured 2026-08-27 and not yet
    /// fixed. On a `SigningKey` record this reports `ready: true` while `credential.get`
    /// on the SAME HANDLE at the same instant refuses:
    ///
    ///   status -> {"ready":true,"last_error_code":null,"record_version":1}
    ///   get    -> {"class":"permanent","code":"not_found"}
    ///
    /// `ready` is computed from `meta.state` alone. The kind fence that makes `get`
    /// refuse a signing key lives on the DECRYPTED record, and `kind` is not a plaintext
    /// column — it is inside the sealed envelope. So this no-decrypt path cannot see it,
    /// and a status surface that decrypted would stop being the cheap read it exists to
    /// be.
    ///
    /// THE CLASS, named by the supervisor seat the same day after their own status
    /// surface reported a manifest valid seconds before the governed verb refused its
    /// key: A STATUS FIELD MUST DERIVE FROM THE ENFORCEMENT PATH, NOT A PARALLEL ARM.
    /// Two readers of one field is better than two validators and still not the same
    /// predicate — `get` gates on state AND kind, this gates on state.
    ///
    /// NOT FIXED YET, and the reason is scope rather than judgement: the honest fix is a
    /// plaintext `kind` column (migration + a backfill that must decrypt every existing
    /// envelope with the master key, so an offline pass). Deriving kind from the
    /// credential-id prefix is NOT acceptable — the same reasoning that made the
    /// refresh-adapter prefix non-authoritative applies, a record's stored kind is the
    /// only truth.
    ///
    /// Blast radius today is zero and that is measured, not assumed: no consumer reads
    /// `credential.status` at all (all three answered at source on 2026-08-25). It is
    /// recorded here so the first consumer to poll status does not discover it.
    pub async fn status(
        &self,
        connection_id: u64,
        principal: Option<&Principal>,
        params: &StatusParams,
    ) -> StatusResult {
        let fenced_out = self.engine.store().is_fenced_out();
        let lease_held = !fenced_out;
        let unavailable = |credential_id| StatusResult {
            ready: false,
            last_error_code: Some(ReadError::NotFound),
            lease_held,
            credential_id,
            record_version: None,
            stale_pending: None,
        };

        let (credential_id, scoped) = match (&params.handle, &params.credential_id) {
            // Overall readiness: ready iff we still hold write authority. No address to
            // authorize or rate-limit, and nothing to enumerate, so no lookup runs here.
            (None, None) => {
                return StatusResult {
                    ready: !fenced_out,
                    last_error_code: None,
                    lease_held,
                    credential_id: None,
                    record_version: None,
                    // No address means no record, so there is no mark to report. Absent
                    // rather than false: this is overall daemon readiness, not a claim
                    // about any credential.
                    stale_pending: None,
                };
            }
            (Some(handle), None) => {
                // Rate-limit the handle probe before resolution (enumeration-sweep guard).
                self.check_limiter(connection_id, handle).await;
                let Ok(credential_id) = self.engine.store().resolve_handle(handle) else {
                    return unavailable(None);
                };
                (credential_id, false)
            }
            (None, Some(credential_id)) => {
                // `_as` rather than the token-less helper: an enrolled consumer presents a
                // bearer token and no principal the bus can vouch for, so without this it
                // resolves to `Direct`, fails coverage, and gets the same `unavailable`
                // body as a credential that does not exist -- indistinguishable from the
                // enumeration guard doing its job.
                if self
                    .authorize_scoped_as(
                        principal,
                        params.enrollment_token.as_deref(),
                        credential_id,
                        GrantOperation::Read,
                    )
                    .is_err()
                {
                    return unavailable(None);
                }
                (credential_id.clone(), true)
            }
            // The route rejects a request with both addressing forms as `invalid_params`.
            // Preserve the non-enumerating status shape for direct callers of this surface.
            (Some(_), Some(_)) => return unavailable(None),
        };

        match self.engine.store().meta(&credential_id) {
            Ok(meta) => {
                // The field is a LATENCY PREDICTOR for the next get, and the prediction
                // only has meaning when the next get will actually run. None of the seven
                // `UPDATE credentials SET state = ...` paths in the store clear
                // `stale_pending`, so a record that was marked stale by a consumer 401 and
                // then latched to `needs_reauth` (or quarantined) by a failed refresh still
                // carries `stale_pending = 1` on the column. Publishing that as the
                // prediction would say "next get pays seconds" for a call that fails fast
                // without an upstream exchange -- measured live on 2026-08-27, every four
                // hours for ~five minutes, until the re-seal writes state = 'active' and
                // stale_pending = 0 together.
                //
                // Non-Active => the next get performs no upstream exchange => FALSE.
                // Absent stays reserved for "this path could not see the record" and is
                // unchanged on the resolve and meta-fail arms below.
                let is_active = matches!(meta.state, credentials_core::store::RecordState::Active);
                StatusResult {
                    // A fenced-out daemon is not ready even for an Active credential.
                    ready: !fenced_out && is_active,
                    // Deliberately NOT folded into `ready`: a stale-marked record is still
                    // usable, it is merely expensive on the next read. Published only when
                    // Active; see the comment above for the bug this gates.
                    stale_pending: Some(if is_active { meta.stale_pending } else { false }),
                    last_error_code: match meta.state {
                        credentials_core::store::RecordState::NeedsReauth
                        | credentials_core::store::RecordState::Retired => {
                            Some(ReadError::NeedsReauth)
                        }
                        credentials_core::store::RecordState::Corrupt => Some(ReadError::Corrupt),
                        credentials_core::store::RecordState::Active => None,
                    },
                    lease_held,
                    credential_id: Some(credential_id.clone()),
                    record_version: Some(meta.record_version),
                }
            }
            // A credential-id request records the local reason while keeping its reply
            // indistinguishable from an uncovered principal's request.
            Err(error) => {
                if scoped {
                    self.record_scoped_refusal(
                        principal,
                        &credential_id,
                        match error {
                            StoreOpError::NotFound => ScopedReadRefusal::NotFound,
                            _ => ScopedReadRefusal::StoreError,
                        },
                    );
                }
                // A handle lookup already resolved the credential, so a later metadata
                // failure may safely include its id. For scoped lookups, omit the id on
                // failure so callers cannot distinguish a nonexistent credential from one
                // that exists but is outside their authorization scope.
                unavailable((!scoped).then_some(credential_id))
            }
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
        let audit_tip = store.audit_tip().ok().flatten();
        let mut health = VaultHealth::summarize(&metas, open_intents, store.is_fenced_out());
        // The tip is optional because a failed tip query cannot provide a truthful
        // observation. Never substitute zero or a previously cached value: either would
        // turn an unreadable audit table into false witness data.
        if let Some((seq, entry_mac)) = audit_tip {
            health.audit_seq = Some(seq);
            health.audit_tip_mac = Some(entry_mac);
        }
        health
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
        // IT ALARMS AND DOES NOT REFUSE, and that is a decision rather than an omission.
        //
        // A flagged connection keeps being served. Refusing would make this surface a
        // denial-of-service lever pointed at a live consumer: the ceilings are heuristic,
        // a legitimate burst during an incident looks exactly like a sweep, and the
        // moment a consumer most needs credentials is the moment it fetches unusually.
        // An alarm a human can read is recoverable; a refusal is an outage.
        //
        // WHAT THAT LEAVES UNBOUNDED, so nobody meets it as a surprise: a GRANTED
        // consumer can drive `force_refresh` -- OR an oversized `min_ttl_ms`, which
        // reaches the same exchange through `is_stale` and is documented at
        // [`GetParams`] -- without limit, and each one is a real
        // upstream token exchange. For a `github_app` record that is a mint against a
        // vendor with its own rate limits, so one looping consumer can exhaust a budget
        // shared by every other holder of that App. The only bound today is an audit
        // entry nobody reads in real time.
        //
        // NOT the same hazard as an UNGRANTED caller reaching a mint, which cannot
        // happen here: a capability handle IS the grant, and resolution precedes every
        // fetch. This is a granted party misbehaving -- a different threat with a
        // different answer (revoke the handle), which is why the trade above still holds.
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

    #[test]
    fn report_auth_failure_params_default_missing_reporter_source() {
        let params: ReportAuthFailureParams = serde_json::from_value(serde_json::json!({
            "handle": "ckh_example",
            "provider_status": 401,
            "record_version": 1
        }))
        .expect("legacy report payload remains valid");
        assert_eq!(params.reporter_source, None);
    }

    /// The consumer-facing wire contract names EVERY error class, and no others.
    ///
    /// A document describing a wire surface is a claim that drifts silently: the class
    /// set is pinned in source by the test below, but a doc naming three of four
    /// classes reads as complete to the consumer who vendors it, and nothing fails.
    /// This joins the two — the doc's table cannot fall behind the enum, and a class
    /// deleted from the enum cannot linger in the doc.
    ///
    /// It does NOT check the prose, the remedies, or the code table; those are
    /// documentation and are checked by reading. It checks the one thing a consumer
    /// branches on.
    #[test]
    fn the_wire_contract_doc_names_every_error_class() {
        let doc = include_str!("../../../docs/wire-contract-v1.md");
        for class in ERROR_CLASS_WIRE_SET {
            assert!(
                doc.contains(class),
                "the wire contract doc does not name the `{class}` class, so a consumer \
                 vendoring it would branch on an incomplete set"
            );
        }
        // And the reverse: a class the doc names that the enum no longer emits would be
        // a consumer branching on something that can never arrive.
        for candidate in [
            "transient",
            "permanent",
            "auth_required",
            "context_overflow",
        ] {
            if doc.contains(&format!("| `{candidate}` |")) {
                assert!(
                    ERROR_CLASS_WIRE_SET.contains(&candidate),
                    "the doc's table names `{candidate}`, which this producer no longer \
                     emits — a consumer would carry a dead branch"
                );
            }
        }
    }

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
            "ErrorClass wire strings drifted from the pinned contract set.\n\
             THIS CHANGE OBLIGES A CONSUMER-IMPACT ANNOUNCEMENT BEFORE IT SHIPS, for the \
             same reason the wire-key pins do, and the reason is sharper here: consumers \
             branch on CLASS and not on code, so the class set IS their control flow. A \
             conforming client handles an unknown class conservatively -- pausing rather \
             than rejecting -- which is the right failure but the WRONG BEHAVIOUR for any \
             new class whose remedy is reject-fast. They stay wrong until told. Announce \
             the class, its remedy, and whether it is retryable, THEN update this set."
        );
    }

    /// Golden conformance for the FRAME SHAPE, which the class-string test above does
    /// not cover and cannot: it pins the four `class` values while saying nothing about
    /// the envelope they arrive in. Rename `class` to `error_class`, move the error a
    /// level, drop `class` from the body, rename the outer `result` key, or wrap the
    /// body in a second envelope, and the class-string test stays green while every
    /// consumer breaks.
    ///
    /// WHY THIS EXISTS AT ALL: a consumer typed a decoder from the published contract,
    /// parsed a real error frame SUCCESSFULLY, and silently discarded `class` — serde
    /// drops unknown fields without complaint, so a decoder that ignores the field it
    /// was told to branch on looks identical to one that honours it. They then branched
    /// on `code` through a closed enum, which turns the first added code into a parse
    /// failure rather than an unknown-code branch. The outer `result` wrapper is the
    /// field they actually depend on for routing their decoder to the body, and neither
    /// their fixture nor this test pinned it before — it had two owners and no
    /// assertion. Neither is reachable from this side; what IS reachable is guaranteeing
    /// the bytes never move under them.
    ///
    /// Serialized through the REAL producer type rather than a hand-built `json!`, then
    /// wrapped through the same route-serialization helper used by `handle_read_request`
    /// for `credential.get` replies — so this pins the full on-wire frame
    /// `{"result":{"error":{...}}}`, not just the inner body.
    ///
    /// The literal below is the on-wire frame captured from a live daemon and handed to
    /// that consumer, who pinned it in their tree. Both directions now go red on drift.
    /// Written as a single JSON literal so the byte sequence can be quoted verbatim into
    /// the consumer's fixture rather than re-derived from a producer.
    #[test]
    fn error_frame_shape_is_pinned() {
        let inner = GetOutcome::Err {
            error: ErrorBody {
                code: ReadError::NotFound,
                class: ErrorClass::Permanent,
            },
        };
        let inner_value = serde_json::to_value(&inner).expect("serialize the error outcome");
        let got = crate::wrap_result(inner_value);

        // ORDER IS LOAD-BEARING, and this is the second version. Written with the
        // equality first, the specific checks below never ran: `assert_eq!` panics on any
        // difference, so dropping `class` reported "the frame shape drifted" and left the
        // reader to diff two blobs. The diagnostics existed only for the cases they could
        // not reach. Cheap, specific assertions must precede a broad one that subsumes
        // them, or they are decoration.
        assert!(
            got.get("result").is_some(),
            "the outer `result` wrapper vanished — every route reply in `handle_read_request` \
             is wrapped in `{{\"result\": ...}}`, so a consumer that decodes straight into \
             the inner shape would start receiving a different envelope than the one their \
             fixture pinned"
        );
        assert!(
            got["result"].get("error").is_some(),
            "the `error` body vanished from inside the wrapper — consumers route on this key"
        );
        assert!(
            got["result"]["error"].get("class").is_some(),
            "`class` vanished from the error body — the contract's branch-on-class rule \
             becomes unfollowable and consumers silently fall back to branching on `code`"
        );

        // The full on-wire frame, written as a single JSON literal so it is quotable
        // verbatim into a consumer's fixture. Keys and order are part of the contract —
        // serde serializes structs in field-declaration order, so `error`/`code`/`class`
        // appear in the order written here, and the route builder adds `result` last.
        // Renaming any of these keys, reordering them, or nesting deeper than this is a
        // contract change, not a refactor.
        let want = serde_json::json!({
            "result": {
                "error": {
                    "class": "permanent",
                    "code": "not_found"
                }
            }
        });

        assert_eq!(
            got, want,
            "the error frame shape drifted — consumers route on the outer `result` key, \
             branch on the inner `class`, and pin both. The whole frame is the contract."
        );

        // THE BYTES, pinned separately, because the assertion above cannot see them.
        //
        // `Value` equality is order-independent, which is correct for a SHAPE pin — a key
        // moving should not turn this red. But it means the test above is green for either
        // field order, and a consumer holding a byte-string fixture is not covered by it.
        //
        // The wire order is NOT this struct's declaration order. `ErrorBody` declares
        // `code` then `class`; the wire emits `class` then `code`, because the reply is
        // built through a `serde_json::Value` and `serde_json::Map` is a `BTreeMap` unless
        // the `preserve_order` feature is on — so keys ship alphabetically. Verified
        // against the running daemon from both sides of the wire, and reproduced in
        // isolation: the same struct serialized directly yields `code` first.
        //
        // That makes the current byte order ACCIDENTAL — it holds only while the reply
        // goes through a `Value`. Serializing the struct straight to bytes would flip it
        // with nothing to notice, so this assertion is what converts the accident into a
        // decision someone has to make deliberately.
        //
        // WHY IT IS WORTH A TEST AT ALL: the first consumer of this surface was handed a
        // literal transcribed from the struct declaration and told to quote it verbatim.
        // It did not match production. Deserialization did not care; a byte-comparing
        // fixture or a frame digest would have. The canonical bytes now live where someone
        // reading this test will copy the right ones.
        assert_eq!(
            serde_json::to_string(&got).expect("serialize the pinned frame"),
            r#"{"result":{"error":{"class":"permanent","code":"not_found"}}}"#,
            "the on-wire BYTES changed. Deserializing consumers are unaffected; any \
             consumer holding a byte-string fixture or hashing a frame is not. If this is \
             intentional, the canonical literal published to consumers has to move with it."
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
        assert_eq!(ReadError::KindNotGettable.class(), ErrorClass::Permanent);
        assert_eq!(ReadError::NeedsReauth.class(), ErrorClass::AuthRequired);
        assert_eq!(ReadError::RefreshFailed.class(), ErrorClass::Transient);
        assert_eq!(ReadError::VaultLocked.class(), ErrorClass::Transient);
        assert_eq!(ReadError::TooManyItems.class(), ErrorClass::ContextOverflow);
        assert_eq!(
            ReadError::TtlUnsatisfiable.class(),
            ErrorClass::ContextOverflow
        );
    }

    /// The wire body carries BOTH the producer detail (`code`) and the produced class.
    /// The class gives retry policy; the code remains available for the request-specific remedy.
    #[test]
    fn error_body_carries_consistent_class() {
        let out = err(ReadError::TtlUnsatisfiable);
        let json = serde_json::to_string(&out).expect("serialize outcome");
        assert!(
            json.contains("\"code\":\"ttl_unsatisfiable\""),
            "detail code missing: {json}"
        );
        assert!(
            json.contains("\"class\":\"context_overflow\""),
            "class tag missing: {json}"
        );
    }
}

#[cfg(test)]
mod list_scoped_tests {
    use super::*;
    use credentials_core::record::{RecordIdentity, RecordState};
    use credentials_core::store::{ReadGrant, ScopedListRow, SelectorKind};

    fn row(
        id: &str,
        categories: &[&str],
        state: RecordState,
        operations: &[GrantOperation],
        identity: Option<RecordIdentity>,
    ) -> ScopedListRow {
        ScopedListRow {
            id: id.into(),
            categories: categories
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            state,
            record_version: 7,
            operations: operations.to_vec(),
            identity,
            // The fixture mirrors a native Claude OAuth record, which is the case the
            // adapter field exists to separate from the three rows that merely SERVE
            // Anthropic models through their own protocols.
            refresh_adapter: Some("anthropic".to_owned()),
        }
    }

    fn grant(kind: SelectorKind, selector: &str, operation: GrantOperation) -> ReadGrant {
        ReadGrant {
            principal_kind: "reserved".into(),
            principal_id: "consumer".into(),
            selector_kind: kind,
            selector: selector.into(),
            operation,
            created_at_ms: 1,
        }
    }

    #[test]
    fn five_clause_scoped_coverage_table_is_total_and_ordered() {
        let row = |caller_active_grants,
                   covered,
                   id_exists,
                   holds_category_selector,
                   id_category_count| ScopedCoverage {
            caller_active_grants,
            covered,
            id_exists,
            holds_category_selector,
            id_category_count,
        };
        assert_eq!(
            classify_scoped_coverage(row(0, false, false, false, None)),
            Some(ScopedReadRefusal::NoGrant),
            "clause 1"
        );
        assert_eq!(
            classify_scoped_coverage(row(1, true, true, true, Some(1))),
            None,
            "clause 2"
        );
        assert_eq!(
            classify_scoped_coverage(row(1, false, false, true, Some(0))),
            Some(ScopedReadRefusal::NotFound),
            "clause 3 precedes uncategorized"
        );
        assert_eq!(
            classify_scoped_coverage(row(1, false, true, true, Some(0))),
            Some(ScopedReadRefusal::Uncategorized),
            "clause 4"
        );
        assert_eq!(
            classify_scoped_coverage(row(1, false, true, false, None)),
            Some(ScopedReadRefusal::NoGrant),
            "clause 5"
        );
    }

    fn scoped_row_with_adapter(id: &str, adapter: Option<&str>) -> ScopedListRow {
        ScopedListRow {
            id: id.to_owned(),
            categories: vec!["llm-provider".to_owned()],
            state: RecordState::Active,
            record_version: 1,
            operations: vec![GrantOperation::Read],
            identity: None,
            refresh_adapter: adapter.map(str::to_owned),
        }
    }

    /// SERVES AND THE ADAPTER ANSWER DIFFERENT QUESTIONS, AND A CONSUMER NEEDS BOTH.
    ///
    /// Measured on the live vault: filtering `serves` for "anthropic" returns EIGHT rows,
    /// of which only five are Claude OAuth. `apikey:openrouter`, `antigravity:google` and
    /// `oauth:cursor` reach Anthropic models through their own APIs, so a consumer that
    /// sends one of those tokens to Anthropic's native endpoints sends a credential the
    /// endpoint cannot accept.
    ///
    /// The id spelling cannot substitute either, in BOTH directions: two of those three
    /// contain no "anthropic" anywhere, and `type == "oauth"` does not separate them
    /// because Antigravity and Cursor are OAuth too.
    ///
    /// Reported by the anthropic-auth seat after reading leg 5 of the live acceptance,
    /// where my own probe printed all eight under an "anthropic" filter.
    #[test]
    fn the_adapter_separates_native_anthropic_from_rows_that_merely_serve_anthropic() {
        let rows = project_list_scoped(ScopedListSnapshot {
            rows: vec![
                scoped_row_with_adapter("oauth:anthropic", Some("anthropic")),
                scoped_row_with_adapter("oauth:cursor", Some("cursor")),
                scoped_row_with_adapter("antigravity:google", Some("antigravity")),
                scoped_row_with_adapter("apikey:openrouter", None),
            ],
            grants: Vec::new(),
        });

        let adapter = |id: &str| -> Option<String> {
            rows.credentials
                .iter()
                .find(|row| row.id == id)
                .unwrap_or_else(|| panic!("no row for {id}"))
                .refresh_adapter
                .clone()
        };

        assert_eq!(adapter("oauth:anthropic").as_deref(), Some("anthropic"));
        // The three that serve Anthropic models and are NOT Claude OAuth.
        assert_eq!(adapter("oauth:cursor").as_deref(), Some("cursor"));
        assert_eq!(
            adapter("antigravity:google").as_deref(),
            Some("antigravity")
        );
        assert_eq!(
            adapter("apikey:openrouter"),
            None,
            "a static key speaks no refresh protocol, and absent is the honest answer"
        );

        let native: Vec<&str> = rows
            .credentials
            .iter()
            .filter(|row| row.refresh_adapter.as_deref() == Some("anthropic"))
            .map(|row| row.id.as_str())
            .collect();
        assert_eq!(
            native,
            vec!["oauth:anthropic"],
            "selecting on the adapter must yield ONLY native Claude OAuth"
        );
    }

    #[test]
    fn list_scoped_view_golden_vector_pins_every_framing_rule() {
        let snapshot = ScopedListSnapshot {
            rows: vec![
                row(
                    "d-retired",
                    &[],
                    RecordState::Retired,
                    &[GrantOperation::Read],
                    None,
                ),
                row(
                    "a-active",
                    &["llm-provider", "monitoring"],
                    RecordState::Active,
                    &[GrantOperation::Read, GrantOperation::Sign],
                    Some(RecordIdentity {
                        account_id: Some("acct".into()),
                        email: Some("a@example.test".into()),
                        org_name: Some("Example".into()),
                    }),
                ),
                row(
                    "e-non-opening-active",
                    &["llm-provider"],
                    RecordState::Active,
                    &[GrantOperation::Read],
                    None,
                ),
                row(
                    "b-needs-reauth",
                    &["llm-provider"],
                    RecordState::NeedsReauth,
                    &[GrantOperation::Sign],
                    None,
                ),
                row(
                    "c-corrupt",
                    &["llm-provider"],
                    RecordState::Corrupt,
                    &[GrantOperation::Read],
                    None,
                ),
            ],
            grants: vec![
                grant(SelectorKind::Category, "llm-provider", GrantOperation::Sign),
                grant(SelectorKind::Exact, "", GrantOperation::Read),
            ],
        };
        let result = project_list_scoped(snapshot);
        assert_eq!(result.grants, result.grant_tuples.len());
        assert_eq!(
            result.view,
            "ymfBXY4hu+RcsKhEzW2CExWRK1mhqCplTSWkJqcagSA=",
            "state/operation/selector enums are length-prefixed strings; lists carry counts; optionals carry presence bytes"
        );
        assert_eq!(result.credentials[0].id, "a-active");
        assert!(result
            .credentials
            .iter()
            .all(|row| !row.operations.is_empty()));
    }

    #[test]
    fn list_scoped_view_is_injective_for_strings_and_optional_presence() {
        let base_grants = vec![grant(SelectorKind::Exact, "", GrantOperation::Read)];
        let left = project_list_scoped(ScopedListSnapshot {
            rows: vec![row(
                "a",
                &["bc"],
                RecordState::Active,
                &[GrantOperation::Read],
                None,
            )],
            grants: base_grants.clone(),
        });
        let right = project_list_scoped(ScopedListSnapshot {
            rows: vec![row(
                "ab",
                &["c"],
                RecordState::Active,
                &[GrantOperation::Read],
                None,
            )],
            grants: base_grants.clone(),
        });
        assert_ne!(left.view, right.view);

        let absent_then_empty = project_list_scoped(ScopedListSnapshot {
            rows: vec![row(
                "same",
                &[],
                RecordState::Active,
                &[GrantOperation::Read],
                Some(RecordIdentity {
                    account_id: None,
                    email: Some(String::new()),
                    org_name: None,
                }),
            )],
            grants: base_grants.clone(),
        });
        let empty_then_absent = project_list_scoped(ScopedListSnapshot {
            rows: vec![row(
                "same",
                &[],
                RecordState::Active,
                &[GrantOperation::Read],
                Some(RecordIdentity {
                    account_id: Some(String::new()),
                    email: None,
                    org_name: None,
                }),
            )],
            grants: base_grants,
        });
        assert_ne!(absent_then_empty.view, empty_then_absent.view);
    }

    #[test]
    fn grantless_view_is_the_constant_digest_of_two_empty_blocks() {
        let result = project_list_scoped(ScopedListSnapshot {
            rows: Vec::new(),
            grants: Vec::new(),
        });
        assert_eq!(result.credentials, []);
        assert_eq!(result.grants, 0);
        assert_eq!(result.grant_tuples, []);
        assert_eq!(result.view, "vGTW0lomfgTvnoZoEYxkS/nUmfm76KhATUyAQCXGpPY=");
    }
}
