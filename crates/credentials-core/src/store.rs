//! The encrypted credential store: durable custody of [`VaultRecord`]s, each
//! sealed value-level and written through the epoch-fenced path.
//!
//! This layer owns persistence and the at-rest crypto wiring; it does NOT own the
//! wire surfaces, the audit chain, or the refresh state machine (those live above
//! it). Credential mutations go through `cortexkit-store`'s `with_conn_fenced`
//! so a superseded writer (an old instance still draining after a lease handover)
//! is rejected at the database layer rather than silently clobbering a fresh write.
//!
//! ## Row layout
//!
//! One row per credential in the `credentials` table:
//! - `credential_id` (PK) — the stable id (e.g. `opencode:anthropic`).
//! - `record_version` (plaintext) — monotonic, bumped every write. Mirrored from
//!   the encrypted body and bound into the cipher AAD, so the column and the
//!   ciphertext always move together in one fenced transaction.
//! - `key_id` (plaintext hex) — which master key sealed this row, so a rotation
//!   scan finds old-key rows without decrypting them.
//! - `state` (plaintext) — `active` | `needs_reauth` | `retired` | `corrupt`. A row
//!   that fails to decrypt is quarantined here (per-record), never panics, and never takes
//!   down the rest of the vault.
//! - `stale_pending` (plaintext) — a consumer-reported refusal that forces the next
//!   refreshable read to exchange the token before serving it; it is not provider TTL.
//! - `envelope` (BLOB) — the sealed record (the only place plaintext fields live,
//!   and only in encrypted form).
//! - `updated_at_ms` — last-write wall clock (diagnostics only).
//! - `last_github_app_permissions` (plaintext) — the most recent canonical GitHub App
//!   installation grant. It is diagnostic metadata, not a token claim, and is only
//!   updated after a successful GitHub App mint.
//!
//! ## Fail-closed, never-panic
//!
//! A decrypt/parse failure on read marks that single id `corrupt` and returns a
//! typed [`StoreOpError`]; the vault keeps serving every other credential. This is
//! the per-record quarantine the availability contract requires (NOT a whole-DB
//! reset — auto-wiping on perceived corruption is itself a data-loss/DoS vector).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use cortexkit_store::{Migration, SqliteStore, StoreError};
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::audit::{
    self, AlarmReason, AuditCtx, AuditEntry, AuditOp, AuditRecord, AuthEventKind, ReporterSource,
};
pub use crate::deposit_cookie::DepositCookieOutcome;
use crate::enrollment::{
    constant_time_hash_eq, enrollment_secret_hash, is_lower_hex_32, mint_hex_32,
    valid_enrollment_name, EnrollmentError, EnrollmentPoll, EnrollmentProposal, EnrollmentRefusal,
    EnrollmentRotation, ENROLLMENT_LIVE_LIMIT, ENROLLMENT_PENDING_TTL_MS,
    ENROLLMENT_TERMINAL_MAX_ROWS, ENROLLMENT_TERMINAL_RETENTION_MS, ENROLL_EXPIRE_SUBJECT,
    ENROLL_POLL_SUBJECT, ENROLL_PROPOSE_SUBJECT,
};
use crate::envelope::{self, EnvelopeError, RecordBinding};
use crate::key::{KeyId, MasterKey};
use crate::oauth::{is_custody_tombstone, CUSTODY_TOMBSTONE_PREFIX};
pub use crate::record::RecordState;
use crate::record::{CredentialKind, RecordIdentity, VaultRecord};

#[path = "store_migrations.rs"]
mod migrations;

#[path = "store_enrollment.rs"]
mod enrollment;

#[path = "store_grants.rs"]
mod grants;

#[path = "store_credentials.rs"]
mod credentials;

#[cfg(test)]
#[path = "store_condition_tests.rs"]
mod condition_tests;
#[path = "store_conditions.rs"]
mod conditions;

use conditions::delete_local_condition_tx;
pub use conditions::{
    check_condition_link, check_condition_report, condition_read_only, Condition, ConditionReport,
    MAX_CONDITION_ACTION_URL_BYTES, MAX_CONDITION_SINCE_MS,
};

#[path = "store_refresh.rs"]
mod refresh;

#[path = "store_handles.rs"]
mod handles;

#[path = "store_audit.rs"]
mod audit_store;

#[path = "store_metadata.rs"]
mod metadata;

#[cfg(test)]
use audit_store::row_to_audit;
pub(crate) use audit_store::{append_audit_tx, append_auth_event_tx};
use audit_store::{append_secret_auth_event_tx, load_or_create_audit_key, trim_auth_events_tx};
pub use audit_store::{
    auth_events_at_cap_read_only, read_audit_read_only, read_auth_events_read_only,
    verify_audit_chain_read_only,
};
use credentials::{
    derived_account_id, normalize_record_identity, refuse_incoming_agent_ssh,
    refuse_short_term_bedrock_key, retain_detected_plan, validate_record_identity,
};
pub use enrollment::{list_enrollments_read_only, list_enrollments_read_only_with_schema};
use grants::{
    bump_grants_generation_tx, create_read_grant_audited_tx, read_grants_from_conn,
    revoke_read_grant_audited_tx, validate_read_grant,
};
pub use grants::{list_read_grants_read_only, list_read_grants_read_only_with_schema};
use handles::vault_transfer_key_fence_holds_tx;
pub use handles::{handle_hash, mint_handle, other_live_handles_read_only};
pub use metadata::{
    auth_methods_read_only, count_refresh_intents_read_only, detected_plans_read_only,
    list_meta_read_only, list_meta_read_only_with_schema, restore_resurrection_read_only,
};
use metadata::{
    detected_plans_from_conn, home_watch_candidates_from_conn, metadata_tables_for,
    plan_tier_column, plan_tier_observed_column, plan_tier_since_column, provider_ids_column,
    provider_ids_from_conn, split_categories, split_provider_ids, table_exists,
    write_plan_tier_in_tx, write_plan_tier_tx, MetadataTables,
};
#[cfg(any(test, feature = "test-support"))]
pub use migrations::migrate_through_for_test;
pub use migrations::newest_migration_version;
use migrations::read_schema_version;
#[cfg(test)]
use migrations::{
    migration_category_targets, refuse_store_ahead_of_binary, MIGRATIONS,
    MIGRATION_10_CONVERSION_TABLE,
};
use refresh::clear_intent_tx;

/// The schema namespace for the credential vault's migrations (independent of any
/// other domain chain in the same database).
const SCHEMA_NAMESPACE: &str = "credentials";

/// The migration that added `credential_categories` and the `selector_kind` column on
/// `read_grants`.
///
/// The lease-free readers branch on it, because they must read a store that is BEHIND
/// this binary: a CLI-only change is placed first and the daemon, which migrates, is
/// restarted later, so between the two every offline read meets a store one migration
/// behind. At or above this version the new shape is read; below it the pre-9 shape is.
///
/// Published because the CLI's behind-store note names this migration as the one that
/// brings categories, which stays true after a later migration raises the binary's own
/// version.
pub const CATEGORY_SCHEMA_VERSION: u32 = 9;

/// Private module-owned values, stored outside the credential and grant tables.
pub const MODULE_SECRET_SCHEMA_VERSION: u32 = 48;

/// Provider login conditions, stored separately from local and remote record state.
pub const CONDITION_SCHEMA_VERSION: u32 = 49;

/// Operator defaults for API-key services absent from the fixed catalog.
pub const REGISTERED_PROVIDERS_SCHEMA_VERSION: u32 = 37;

/// The migration that distinguishes operator grants from Callosum sharing switches.
pub const MEMBER_GRANT_SOURCE_SCHEMA_VERSION: u32 = 38;

/// The migration that distinguishes manually added remote records from records
/// kept in sync by a subscription to their home vault's login list.
pub const REMOTE_RECORD_SOURCE_SCHEMA_VERSION: u32 = 39;

/// The migration that renamed `read_grants.credential_prefix` to `selector`, narrowed
/// the selector vocabulary, and added the enrollment and grant-generation tables.
///
/// The readers that open the store file without the write lease (`grants`, `list`,
/// `status`) branch on it for the same reason they branch on
/// [`CATEGORY_SCHEMA_VERSION`]: a new CLI is placed before the daemon that migrates is
/// restarted, so between the two every such read meets a store one migration behind,
/// where the grant table still carries the old column name.
pub const SELECTOR_SCHEMA_VERSION: u32 = 10;

/// The migration that records who proposed each pending enrollment.
///
/// The lease-free enrollment reader branches on it because a newer CLI can read the store
/// before the daemon has restarted and applied this migration. Below it
/// `pending_enrollments` has no proposer columns, so every row there is read with an
/// unknown proposer rather than failing the listing.
pub const ENROLLMENT_PROPOSER_SCHEMA_VERSION: u32 = 12;

/// The migration that records proposed and approved enrollment display names.
pub const ENROLLMENT_DISPLAY_NAME_SCHEMA_VERSION: u32 = 34;

/// The migration that records the immutable permissions proposed for enrollment.
pub const ENROLLMENT_REQUESTED_GRANTS_SCHEMA_VERSION: u32 = 40;

/// Retained GitHub manifests, binding proposals and per-computer activation reports.
pub const GH_MANIFEST_SCHEMA_VERSION: u32 = 41;

/// Read-time host and authentication descriptors for registered providers.
pub const REGISTERED_PROVIDER_DESCRIPTOR_SCHEMA_VERSION: u32 = 42;

/// Per-credential gateway settings, bound to the credential's incarnation.
pub const GATEWAY_SETTINGS_SCHEMA_VERSION: u32 = 43;

/// Optional operator-supplied effective starts for local and remote plan tiers.
pub const PLAN_TIER_SINCE_SCHEMA_VERSION: u32 = 44;

/// Last-seen approved module declarations, retained for operator inspection only.
pub const DECLARED_GRANTS_SCHEMA_VERSION: u32 = 45;

pub const LOCAL_PROGRAM_SECRET_SCHEMA_VERSION: u32 = 46;

pub const FLEET_SCHEMA_VERSION: u32 = 47;

/// The migration that added `credential_provider_ids`, the operator's record of which
/// catalog provider ids each credential serves.
///
/// The lease-free readers branch on it for the same reason they branch on
/// [`CATEGORY_SCHEMA_VERSION`]: a new CLI can read the store before the daemon that
/// migrates has restarted. Below it the table does not exist, and every credential is
/// read with no provider ids, which is the true reading of that store.
///
/// Published because the CLI's behind-store note names this migration as the one that
/// brings provider ids.
pub const PROVIDER_ID_SCHEMA_VERSION: u32 = 15;

/// The newest migration a vault release-1 binary carries. Every migration above it
/// belongs to vault release 2 (home-vault federation), so a release-1 binary meeting a
/// store at or above [`FEDERATION_SCHEMA_VERSION`] refuses to open it.
pub const VAULT_RELEASE_1_SCHEMA_VERSION: u32 = 18;

/// The first vault release-2 migration: `remote_records`. Every federation table
/// arrives at or above it, so a reader that may meet an older store branches on it
/// before touching any of them.
pub const FEDERATION_SCHEMA_VERSION: u32 = 19;

/// The migration that added the remote-record category, provider-id and plan-tier
/// tables. Readers that may meet an older store skip them below it.
const REMOTE_METADATA_SCHEMA_VERSION: u32 = 20;

/// The migration that added `member_grants`.
const MEMBER_GRANTS_SCHEMA_VERSION: u32 = 22;

/// The migration that added the `settings` table holding the federation gate and the
/// vault's own member id. Below it both read as unset.
const SETTINGS_SCHEMA_VERSION: u32 = 26;

/// Agent-secret storage is independent of the credential and federation tables.
pub const AGENT_SECRET_SCHEMA_VERSION: u32 = 27;

/// Flow grants have their own holder and never satisfy an agent-session request.
pub const FLOW_SECRET_SCHEMA_VERSION: u32 = 28;

/// The migration that lets `member_grants` hold the selector-free `secret_use`
/// operation, which allows a paired computer to forward agent-secret calls here.
const SECRET_USE_MEMBER_GRANT_SCHEMA_VERSION: u32 = 29;

/// The migration that records which computer asked for each agent-secret grant, flow
/// grant and pending approval request. Below it every row is this vault's own (`''`).
pub const SECRET_ASKING_MEMBER_SCHEMA_VERSION: u32 = 30;

/// The migration that added `secret_release_receipts`, which lets a paired computer
/// retry a forwarded secret release and receive the same sealed reply.
pub const SECRET_RELEASE_RECEIPT_SCHEMA_VERSION: u32 = 31;

/// The migration that adds extended scopes while preserving legacy scope columns.
pub const SECRET_SCOPE_SCHEMA_VERSION: u32 = 35;

/// The migration that records when each plan tier first took effect, so a
/// listing can say how long the current tier has applied. Existing rows stay
/// unknown rather than guessed.
pub const PLAN_TIER_OBSERVED_SCHEMA_VERSION: u32 = 36;

/// The audit ops that DEPOSIT a credential, so the earliest entry carrying one of
/// them is that credential's birth instant.
///
/// Migration 10 dates every existing credential from this set and the guard in
/// [`EncryptedStore::migrate`] refuses a credential the set cannot date. The literals
/// are repeated verbatim inside that migration's own `UPDATE`, and a test pins the two
/// lists together: a set that drifted apart would refuse rows the migration can date,
/// or date rows the guard never checked.
///
/// Two of them (`create`, `store`) are not written by this binary's op vocabulary. They
/// stay in the set because the chain is historical data written by every version that
/// has ever held the store, and a narrower set would refuse a credential whose birth
/// entry an older writer spelled differently.
const CHAIN_BIRTH_OPS: [&str; 5] = ["put", "import", "login", "create", "store"];

/// Schema-9 grants whose old and replacement selectors were verified to cover the
/// same credential ids when migration 10 was designed. The migration recomputes both
/// covered sets from the store it opens and converts only when they remain identical.
#[derive(Clone, Copy)]
struct Migration10Conversion {
    principal_kind: &'static str,
    principal_id: &'static str,
    old_selector: &'static str,
    operation: GrantOperation,
    replacement: Migration10Replacement,
}

#[derive(Clone, Copy)]
enum Migration10Replacement {
    Exact {
        selector: &'static str,
    },
    Category {
        selector: &'static str,
        assignments: &'static [&'static str],
    },
}

/// The `vault_secrets` row name for the audit-chain HMAC key. The audit key is a
/// CSPRNG secret created once and SEALED under the master key (so the audit log is
/// unforgeable without the master key), re-sealed on master-key rotation but never
/// regenerated — keeping one continuously-verifiable chain across rotations. Its
/// envelope uses this fixed pseudo-id and version 0 as the AAD binding.
pub const AUDIT_KEY_SECRET_NAME: &str = "__vault_audit_key__";

const AUDIT_KEY_RECORD_VERSION: u64 = 0;

/// The local refresh instruction read in the same row as a record, for the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StaleMark {
    /// A consumer reported the served token as refused (`stale_pending`).
    pub(crate) pending: bool,
    /// When the row was last written (`updated_at_ms`). Every write that produces a
    /// new `record_version` sets it, refresh commits included, so for a live record
    /// this is when its current token was stored. The engine's report cooldown
    /// measures from it.
    pub(crate) record_written_at_ms: i64,
}

/// One decrypted read of a credential row: the record, the stale mark observed beside
/// it, and the digest of the exact encrypted bytes it was decrypted from.
#[derive(Debug)]
pub struct StoredRead {
    pub record: VaultRecord,
    /// Internal row identity, stable across refresh and replacement but not removal.
    pub incarnation: String,
    pub(crate) mark: StaleMark,
    /// Lowercase-hex SHA-256 of the stored envelope bytes this read decrypted.
    pub(crate) stored_digest_hex: String,
}

/// Lowercase-hex SHA-256 of arbitrary bytes, the encoding every digest this store and
/// its callers compare uses.
pub(crate) fn sha256_hex_of_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn credential_incarnation_matches(
    conn: &rusqlite::Connection,
    credential_id: &str,
    incarnation: &str,
) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM credentials WHERE credential_id = ?1 AND incarnation = ?2)",
        rusqlite::params![credential_id, incarnation],
        |row| row.get(0),
    )
}

/// The non-secret metadata of a stored record, readable WITHOUT decrypting (the
/// plaintext columns). Used by rotation scans, status, and CAS pre-checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordMeta {
    pub incarnation: Option<String>,
    /// Commit time of the current operator assertion; absent on older rows.
    pub plan_tier_observed_at_ms: Option<i64>,
    pub plan_tier_since_ms: Option<i64>,
    /// The stored record's monotonic version.
    pub record_version: u64,
    /// Hex fingerprint of the master key this row is sealed under.
    pub key_id_hex: String,
    /// The row's lifecycle state.
    pub state: RecordState,
    /// A consumer reported the current access token as refused, so the next read must
    /// refresh before serving it. This local assertion is not a provider expiry fact.
    pub stale_pending: bool,
    /// Sorted non-secret authorization categories.
    pub categories: Vec<String>,
    /// Write-once creator; rows predating migration 14 have no known creator.
    pub created_by: Option<String>,
    /// The catalog provider ids the operator says this credential serves, in ascending
    /// byte order. Empty on a store below [`PROVIDER_ID_SCHEMA_VERSION`].
    pub provider_ids: Vec<String>,
    /// Operator-asserted subscription tier, unknown when absent.
    pub plan_tier: Option<String>,
    /// Fixed gateway settings, absent before [`GATEWAY_SETTINGS_SCHEMA_VERSION`]
    /// or on an ordinary credential, regardless of its categories.
    pub gateway: Option<StoredGatewaySettings>,
}

pub type DetectedPlanListing =
    std::collections::BTreeMap<String, (u64, crate::plan_detection::DetectedPlan, Option<i64>)>;

/// Non-secret metadata opened for the home-watch projection. Decrypted credential
/// material stays inside the store read, including for logins needing reauthentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeWatchCandidate {
    pub credential_id: String,
    pub state: RecordState,
    pub record_version: u64,
    pub kind: CredentialKind,
    pub refresh_adapter: Option<String>,
    pub identity: RecordIdentity,
    pub detected_plan: Option<crate::plan_detection::DetectedPlan>,
    pub condition: Option<Condition>,
    is_refreshable: bool,
}

impl HomeWatchCandidate {
    pub fn is_refreshable(&self) -> bool {
        self.is_refreshable
    }
}

/// The operation a principal-scoped credential-prefix grant permits.
///
/// Each operation authorizes only its own surfaces; none implies another. `List` is the
/// metadata-only one: it makes a covered row visible in `credential.list_scoped` with
/// its identity and refresh adapter, and authorizes nothing that can return a token or
/// exercise a key. It exists so a module can be given the account roster without also
/// being given every token, which `Read` would do.
///
/// `Deposit` is declared after the older operations so derived ordering preserves their
/// order in list_scoped responses. It permits cookie creation and replacement only
/// when the stored creator is the same depositing principal.
///
/// `Seal` is declared last for the same reason. It permits `credential.seal`: an
/// auth-mode HPKE seal under one vault-held KEM key, to a caller-chosen recipient. It
/// takes an exact selector only, because it lets the caller send messages that the
/// recipient will attribute to that key, and a category grant would extend that to
/// every key later put in the category without anyone choosing it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum GrantOperation {
    Read,
    Sign,
    Open,
    List,
    Deposit,
    AccountToken,
    Seal,
}

impl GrantOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Sign => "sign",
            Self::Open => "open",
            Self::List => "list",
            Self::Deposit => "deposit",
            Self::AccountToken => "account_token",
            Self::Seal => "seal",
        }
    }
}

impl std::str::FromStr for GrantOperation {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "read" => Ok(Self::Read),
            "sign" => Ok(Self::Sign),
            "open" => Ok(Self::Open),
            "list" => Ok(Self::List),
            "deposit" => Ok(Self::Deposit),
            "account_token" => Ok(Self::AccountToken),
            "seal" => Ok(Self::Seal),
            _ => Err(format!(
                "unknown grant operation '{value}' (expected read, sign, open, list, deposit, account_token, or seal)"
            )),
        }
    }
}

/// How a grant selector is evaluated: against one credential id, or against the
/// categories a credential carries.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SelectorKind {
    Exact,
    Category,
    Audience,
}

impl SelectorKind {
    pub fn validate_operation(self, operation: GrantOperation) -> Result<(), String> {
        if (self == Self::Audience) != (operation == GrantOperation::AccountToken) {
            return Err("account_token requires selector-kind audience, and audience requires operation account_token".into());
        }
        // A seal grant names one key. Migration 18 enforces the same rule in the schema,
        // so a row written around this check is refused by SQLite as well.
        if operation == GrantOperation::Seal && self != Self::Exact {
            return Err(
                "seal requires selector-kind exact: it names one KEM key, never a category".into(),
            );
        }
        Ok(())
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Category => "category",
            Self::Audience => "audience",
        }
    }
}

impl std::str::FromStr for SelectorKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "exact" => Ok(Self::Exact),
            "category" => Ok(Self::Category),
            "audience" => Ok(Self::Audience),
            _ => Err(format!(
                "unknown selector kind '{value}' (expected exact, category, or audience)"
            )),
        }
    }
}

/// One durable principal-scoped operation grant. `selector` holds the selector text
/// for both selector kinds, and `selector_kind` says how to read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadGrant {
    pub principal_kind: String,
    pub principal_id: String,
    pub selector_kind: SelectorKind,
    pub selector: String,
    pub operation: GrantOperation,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Schema9GrantRow {
    principal_kind: String,
    principal_id: String,
    selector_kind: String,
    selector: String,
    operation: String,
    created_at_ms: i64,
}

impl Schema9GrantRow {
    fn label(&self) -> String {
        format!(
            "(principal_kind={}, principal_id={}, selector_kind={}, selector={}, operation={})",
            self.principal_kind,
            self.principal_id,
            self.selector_kind,
            self.selector,
            self.operation
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Migration10GrantPlanRow {
    principal_kind: String,
    principal_id: String,
    selector_kind: String,
    selector: String,
    operation: String,
    created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Migration10Plan {
    grants: Vec<Migration10GrantPlanRow>,
    assignments: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Migration10State {
    credential_ids: BTreeSet<String>,
    categories: BTreeMap<String, BTreeSet<String>>,
    grants: Vec<Schema9GrantRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedCoverage {
    pub covered: bool,
    pub caller_active_grants: u32,
    pub holds_category_selector: bool,
    pub id_exists: bool,
    pub id_category_count: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedListRow {
    pub provider: Option<String>,
    pub incarnation: String,
    pub plan_tier_observed_at_ms: Option<i64>,
    pub plan_tier_since_ms: Option<i64>,
    pub id: String,
    pub categories: Vec<String>,
    pub state: RecordState,
    pub record_version: u64,
    pub operations: Vec<GrantOperation>,
    pub identity: Option<crate::record::RecordIdentity>,
    /// The record's OWN refresh adapter, read from the sealed record rather than parsed
    /// from the id.
    ///
    /// It is the only exact answer to "which provider protocol does this credential
    /// speak", and `serves` cannot substitute for it: `serves` names the model vendors a
    /// credential can reach, so `apikey:openrouter`, `antigravity:google` and
    /// `oauth:cursor` all serve Anthropic models while speaking three protocols that are
    /// not Anthropic's. A consumer that sends a Claude OAuth token to a native Anthropic
    /// endpoint needs the adapter, not the vendor list.
    ///
    /// Non-secret: it is a short protocol label, already published on `credential.get`
    /// indirectly through behaviour, and it names no account and no material. Reading it
    /// costs nothing here because the row is already unsealed for identity.
    pub refresh_adapter: Option<String>,
    /// The catalog provider ids the operator assigned, in ascending byte order. Read
    /// from their own table without unsealing, so a row reached only through `sign` or
    /// `open` carries them too.
    pub provider_ids: Vec<String>,
    /// Effective tier disclosed only to callers with read or list authority.
    pub plan_tier: Option<String>,
    pub plan_tier_source: Option<String>,
    /// Gateway settings take precedence over the unsealed record's kind and refresh
    /// adapter via [`crate::list_auth_method::list_auth_method_with_gateway`].
    /// `None` when the row is reached only through `sign` or `open` (it stays sealed)
    /// or when the table yields nothing.
    pub auth_method: Option<crate::list_auth_method::ListAuthMethod>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedListSnapshot {
    pub rows: Vec<ScopedListRow>,
    pub grants: Vec<ReadGrant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetCategoryMode {
    Set,
    Add,
    Remove,
}

/// How an `admin.set_providers` request combines with the credential's stored provider
/// ids: replace them, add to them, or remove from them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetProvidersMode {
    Set,
    Add,
    Remove,
}

/// A durable refresh-intent row: the fsynced marker that a refresh is in flight
/// for a credential, written before the provider's rotating endpoint is called and
/// cleared in the same transaction that commits the new tokens. A row that
/// survives a restart marks an INDETERMINATE refresh (the provider may or may not
/// have rotated) that startup reconciliation resolves fail-safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshIntent {
    /// The credential being refreshed.
    pub credential_id: String,
    /// The record version the refresh started FROM (the commit's CAS guard).
    pub record_version: u64,
    /// Hash of the refresh token about to be rotated (see [`refresh_token_hash`]).
    /// Reconciliation cross-checks it against the stored record's refresh token so
    /// a legitimate re-login (which clears the intent) is told apart from a rogue
    /// write that left a stale intent.
    pub old_refresh_hash: String,
    /// The store epoch that opened the intent. AUDIT-ONLY: recorded so the audit
    /// log can label a dangling intent as crash-vs-handover, but it is NEVER an
    /// input to the reconciliation resolution (kill-9 and lease-handover must
    /// resolve identically — the convergence property).
    pub lease_epoch: u64,
    /// When the intent was opened (Unix ms). Staleness / audit.
    pub started_at_ms: i64,
}

/// Domain-separated hash of a refresh token, stored in the intent so reconciliation
/// can compare it to the record's current refresh token WITHOUT either being a
/// reversible store of the secret. Hex SHA-256 over a domain label + the token.
pub fn refresh_token_hash(refresh_token: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"cortexkit-credentials/refresh-token-hash/v1");
    h.update(refresh_token.as_bytes());
    let digest = h.finalize();
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A store operation failure. Distinct, typed, fail-closed — never a panic.
#[derive(Debug)]
pub enum StoreOpError {
    /// A module-secret refusal, shared by operator and module-owned operations.
    ModuleSecret(module_secrets::ModuleSecretError),
    /// SSH enrollment is malformed or was supplied through a generic record write.
    InvalidAgentSsh,
    /// The credential id does not exist.
    NotFound,
    /// The record or its provider does not admit the reported condition.
    ConditionNotAdmitted,
    /// The provider status does not admit a condition report.
    ConditionStatusRefused,
    /// The reported action link is not permitted. Never carries the supplied value.
    ConditionLinkRefused,
    /// A remote copy's condition must be cleared at its home vault.
    ConditionHomeOwned,
    /// A create was attempted for an id that already exists (create-only default).
    AlreadyExists,
    /// A CAS overwrite's `expected_payload_hash` did not match the current record.
    CasMismatch,
    /// A credential id begins with `category:` or contains `|`, bytes reserved for category selectors and audit targets.
    InvalidCredentialId,
    /// A category name does not match `^[a-z][a-z0-9-]{1,31}$`.
    InvalidCategoryName,
    /// An API-key service cannot be named by the interactive put flow.
    InvalidServiceName {
        service: String,
    },
    /// The fixed API-key catalog already owns this service's defaults.
    ServiceInProviderCatalog {
        service: String,
    },
    /// A tier is not a lowercase ASCII identifier of 1–32 characters.
    InvalidPlanTier,
    /// An enrollment display name failed the shared person-facing label validation.
    InvalidDisplayName,
    /// A provider-id write broke one of the provider-id rules. `value` is the id the
    /// rule names, which may be empty (an empty id fails `charset`).
    InvalidProviderId {
        rule: crate::provider_ids::ProviderIdRule,
        value: String,
    },
    /// Gateway settings are not in the accepted normal form. No supplied values
    /// are carried here, so a refusal cannot disclose fixed header values.
    InvalidGatewaySettings {
        rule: crate::gateway::GatewaySettingsRule,
    },
    /// The requested change would alter gateway metadata fixed at creation.
    GatewayFixed {
        rule: crate::gateway::GatewayFixedRule,
    },
    /// A grant principal is not a non-empty `reserved` principal id without `|`.
    InvalidPrincipal,
    /// This tuple appears in the module's approved declaration; no manually managed grant was revoked.
    DeclaredGrant {
        module_id: String,
    },
    /// Approval would hand existing name-bound grants to a new consumer without consent.
    EnrollmentNameHasGrants {
        name: String,
    },
    /// Deposit grants are restricted to reserved principals and browser-session categories.
    InvalidDepositGrant,
    /// The existing cookie belongs to another creator, or has no known creator.
    DepositCookieNotPermitted,
    /// Identity preservation would attach an existing account label to incoming material
    /// whose provider claim names a different account.
    AccountIdentityMismatch {
        credential_id: String,
        retained_account_id: String,
        incoming_account_id: String,
    },
    /// An explicit supplied account label contradicts the provider claim in incoming
    /// material. The token claim is authoritative for adapters that expose one.
    SuppliedIdentityContradictsClaim {
        credential_id: String,
        supplied_account_id: String,
        derived_account_id: String,
    },
    /// The payload is a short-term Amazon Bedrock API key, which expires within 12 hours
    /// and cannot be renewed by the vault. `expires_at_ms` is decoded from the key when
    /// its presigned URL carries one.
    ShortTermBedrockKey {
        expires_at_ms: Option<i64>,
    },
    /// The record is quarantined (`corrupt`) and cannot be served.
    Quarantined,
    /// The record is `needs_reauth` and must not be served until re-authenticated.
    NeedsReauth,
    /// The id is held by a remote record (a login whose home is another member's vault),
    /// so no local record may be created under it. Remove the remote record first.
    CredentialIdIsRemote,
    /// The id is held by a local record, so it cannot be registered as a remote record.
    /// There is no replace across the two: remove the local record first.
    CredentialIdIsLocal,
    /// A member id is not `fed-computer:` followed by 32 lowercase hex characters.
    InvalidMemberId,
    /// Callosum owns this grant; a manual revoke would be undone by reconciliation.
    MemberGrantSharingSwitch {
        member_id: String,
    },
    /// The home controls this row and its categories until an operator converts it
    /// with a remote add for the same home.
    RemoteRecordHomeWatch {
        credential_id: String,
        home_member: String,
    },
    /// A grant would reach the vault transfer key (`kem:vault-transfer:*`) with
    /// anything but the one announce read, or a handle was requested for it. The
    /// transfer key signs the federation seals, so the only thing it may be granted is
    /// `credential.public_key`, and no handle may reach it.
    TransferKeyReserved,
    FleetKeyReserved,
    BusKeyReserved,
    /// Hosted message-hub tokens belong only to the supervised ck-bus module.
    HubAudienceReserved,
    /// The vault transfer key is `Active`, so every operation that would change its
    /// state, payload, identity or kind is refused: the federation peers sealed to it
    /// could not open anything signed by a replacement. Recovery is an operator
    /// `ck auth transfer init --replace` once the key is found off `Active`.
    TransferKeyProtected,
    /// The reserved deposit key is absent, inactive, or undecodable. Bootstrap leaves
    /// an existing key untouched so deposits fail closed; no recovery command exists.
    SecretSetupIncomplete,
    /// An API key with multiple host rules or a wildcard, or a login with multiple
    /// origins, requires `secret.multi_host` to be on.
    SecretMultiHostDisabled,
    SecretBasicAuthDisabled,
    SecretLocalProgramsDisabled,
    /// An agent secret already exists under the requested name, live or `corrupt`.
    /// Names are create-only, so the operator must delete before storing again.
    SecretNameExists,
    /// This vault's `secrets.home_member` setting names another member, so agent secrets
    /// live in that member's vault and none may be created here. `home_member` is the
    /// member whose vault the operator should use instead.
    SecretHomeElsewhere {
        home_member: String,
    },
    /// The `secrets.home_member` setting names a member, but this vault's own member id
    /// is unset or equal to it, so the vault cannot tell whether it is the home. The
    /// operator of this vault (`remedy_member`, when its id is known) must fix it.
    SecretRemoteSetupIncomplete {
        remedy_member: Option<String>,
    },
    /// Pointing `secrets.home_member` at another member was refused because this vault
    /// still holds agent secret state that would be stranded there. The counts say what
    /// must be deleted or revoked first.
    SecretHomeNotEmpty {
        agent_secrets: u64,
        grants: u64,
        flow_grants: u64,
        pending_requests: u64,
    },
    /// The cipher envelope failed to decode/decrypt. The id has been quarantined.
    Decrypt(EnvelopeError),
    /// The decrypted body failed to parse as a record. The id has been quarantined.
    Corrupt(String),
    /// A fenced write was rejected because a newer writer holds the database (the
    /// lease-handover race). The write was NOT applied.
    Fenced {
        holder_epoch: u64,
        db_epoch: u64,
    },
    /// A serialization failure building the record body.
    Encode(String),
    /// The vault's sealed audit key is missing on a non-empty vault — a genuinely
    /// corrupt state (it is created once at init and never deleted). Fail-closed:
    /// the audit chain cannot be verified, so the vault refuses to open rather than
    /// silently regenerating the key (which would make all existing entries
    /// unverifiable).
    CorruptVault(String),
    /// An underlying storage/backend error.
    Store(String),
}

enum IdentityPolicyOverwriteOutcome {
    NotFound,
    GatewayFixedKind,
    AccountMismatch {
        retained_account_id: String,
        incoming_account_id: String,
    },
    Updated(usize),
}

impl std::fmt::Display for StoreOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreOpError::ModuleSecret(error) => write!(f, "{}: {error}", error.code()),
            StoreOpError::InvalidAgentSsh => f.write_str("invalid_params: invalid SSH enrollment"),
            StoreOpError::SecretSetupIncomplete => f.write_str("secret_setup_incomplete"),
            StoreOpError::SecretBasicAuthDisabled => f.write_str("secret_basic_auth_disabled: secret.basic_auth is off or unreadable; enable it with ck auth secret basic-auth on"),
            StoreOpError::SecretMultiHostDisabled => f.write_str("secret_multi_host_disabled: secret.multi_host is off or unreadable; enable it with ck auth secret multi-host on"),
            StoreOpError::SecretLocalProgramsDisabled => f.write_str("secret_local_programs_disabled: secret.local_programs is off or unreadable; enable it with ck auth secret local-programs on"),
            StoreOpError::SecretNameExists => f.write_str("name_exists: an agent secret already holds this name; delete it first"),
            // These three print the same `code/class: detail` text the daemon's admin
            // route answers with, so the online and offline `ck auth secret` paths agree.
            StoreOpError::SecretHomeElsewhere { home_member } => write!(
                f,
                "secret_home_elsewhere/permanent: remedy_member={home_member}"
            ),
            StoreOpError::SecretRemoteSetupIncomplete {
                remedy_member: Some(member),
            } => write!(
                f,
                "remote_setup_incomplete/permanent: remedy_member={member}"
            ),
            StoreOpError::SecretRemoteSetupIncomplete {
                remedy_member: None,
            } => f.write_str("remote_setup_incomplete/permanent"),
            StoreOpError::SecretHomeNotEmpty {
                agent_secrets,
                grants,
                flow_grants,
                pending_requests,
            } => write!(
                f,
                "secret_home_not_empty/permanent: agent_secrets={agent_secrets} grants={grants} \
                 flow_grants={flow_grants} pending_requests={pending_requests}; delete the \
                 secrets on this vault before naming another member as the home"
            ),
            StoreOpError::NotFound => f.write_str("credential not found"),
            StoreOpError::ConditionNotAdmitted => f.write_str("condition not admitted"),
            StoreOpError::ConditionStatusRefused => f.write_str("condition provider status refused"),
            StoreOpError::ConditionLinkRefused => f.write_str("condition action link refused"),
            StoreOpError::ConditionHomeOwned => f.write_str("condition is owned by the home vault"),
            StoreOpError::AlreadyExists => {
                f.write_str("credential already exists (create-only; use a CAS overwrite)")
            }
            StoreOpError::CasMismatch => {
                f.write_str("compare-and-set failed: expected payload hash did not match")
            }
            StoreOpError::InvalidCredentialId => f.write_str("invalid_credential_id"),
            StoreOpError::InvalidCategoryName => f.write_str("invalid_category_name"),
            StoreOpError::InvalidServiceName { service } => write!(f, "Provider service {service:?} is invalid; use a non-empty name without colons, whitespace, control characters, '|' or the reserved '-gw-' marker."),
            StoreOpError::ServiceInProviderCatalog { service } => write!(f, "Provider service {service:?} is in the fixed provider catalog and cannot be registered."),
            StoreOpError::InvalidDisplayName => f.write_str("invalid_params/permanent: invalid display_name"),
            StoreOpError::InvalidPlanTier => f.write_str("invalid_plan_tier/permanent: expected [a-z][a-z0-9_]{0,31} and an optional positive, exact-integer since_ms no later than now"),
            // Labelled fields, so a value that happens to spell a rule token (`count`)
            // cannot be read as a second rule.
            StoreOpError::InvalidProviderId { rule, value } => {
                write!(f, "invalid_provider_id/permanent: rule={rule} value={value}")
            }
            StoreOpError::InvalidGatewaySettings { rule } => {
                write!(f, "invalid_gateway_settings/permanent: rule={rule}")
            }
            StoreOpError::GatewayFixed { rule } => {
                write!(f, "gateway_fixed/permanent: rule={rule}")
            }
            StoreOpError::InvalidPrincipal => f.write_str("invalid_principal"),
            StoreOpError::EnrollmentNameHasGrants { name } => write!(
                f,
                "enrollment_name_has_grants/permanent: enrolled:{name} has existing grants; \
                 revoke them with ck auth revoke-grant, or approve with --keep-grants to explicitly inherit them"
            ),
            StoreOpError::InvalidDepositGrant => f.write_str("deposit requires a reserved principal and category browser-session selector"),
            StoreOpError::DepositCookieNotPermitted => f.write_str("not_permitted"),
            StoreOpError::AccountIdentityMismatch {
                credential_id,
                retained_account_id,
                incoming_account_id,
            } => write!(
                f,
                "incoming material names account '{incoming_account_id}', but identity preservation would retain account '{retained_account_id}'; pass `--account-id <new>` with '{incoming_account_id}' or `--clear-identity`; or afterwards: ck auth set-identity {credential_id} --account-id {incoming_account_id}"
            ),
            StoreOpError::SuppliedIdentityContradictsClaim {
                supplied_account_id,
                derived_account_id,
                ..
            } => write!(
                f,
                "supplied identity names account '{supplied_account_id}', but incoming material names account '{derived_account_id}'; drop `--account-id`, or fix the export; the token's own claim is authoritative"
            ),
            StoreOpError::ShortTermBedrockKey { expires_at_ms } => {
                let when = expires_at_ms
                    .and_then(chrono::DateTime::from_timestamp_millis)
                    .map(|at| format!(" (it expires {})", at.format("%Y-%m-%d %H:%M:%SZ")))
                    .unwrap_or_default();
                write!(
                    f,
                    "this is a short-term Amazon Bedrock API key (bedrock-api-key-...){when}; it lives at most 12 hours and the vault cannot renew it. Create a long-term Bedrock API key (it starts ABSK) in the Bedrock console and store that instead"
                )
            }
            StoreOpError::Quarantined => f.write_str("credential is quarantined (corrupt)"),
            StoreOpError::NeedsReauth => f.write_str("credential needs re-authentication"),
            StoreOpError::CredentialIdIsRemote => f.write_str(
                "credential_id_is_remote: this id is a remote record served by its home vault; run `ck auth remote remove` before creating a local record under it",
            ),
            StoreOpError::CredentialIdIsLocal => f.write_str(
                "credential_id_is_local: this id already holds a local record; remove it before adding a remote record under the same id",
            ),
            StoreOpError::InvalidMemberId => f.write_str(
                "invalid_member_id: expected fed-computer: followed by 32 lowercase hex characters",
            ),
            StoreOpError::DeclaredGrant { module_id } => write!(
                f,
                "declared_grant/permanent: change module {module_id}'s approved declaration in the daemon's configuration; the approval change reaches live routes only when the module re-binds (restart the module), and the stored row is replaced at that bind"
            ),
            StoreOpError::MemberGrantSharingSwitch { member_id } => write!(
                f,
                "Turn the vault-sharing switch off with `ck callosum share {} claustrum/vault off`; otherwise the vault would recreate this grant.",
                member_id.trim_start_matches("fed-computer:")
            ),
            StoreOpError::RemoteRecordHomeWatch { credential_id, home_member } => write!(
                f,
                "remote_record_home_watch/permanent: {credential_id} is kept by {home_member}'s vault-sharing switch"
            ),
            StoreOpError::TransferKeyReserved => f.write_str(
                "transfer_key_reserved: the vault transfer key admits one grant only, read to reserved:callosum for the public-key announce; it cannot be opened, sealed, signed or listed, and no other credential may take its id",
            ),
            StoreOpError::FleetKeyReserved => f.write_str("fleet_key_reserved: fleet keys admit only their purpose-specific grants and no handles"),
            StoreOpError::BusKeyReserved => f.write_str("bus_key_reserved: bus signing keys admit only exact read/sign grants to reserved:ckbus and no handles"),
            StoreOpError::HubAudienceReserved => f.write_str("hub_audience_reserved: cortexkit-hub audience admits only account_token grants to reserved:ckbus"),
            StoreOpError::TransferKeyProtected => f.write_str(
                "transfer_key_protected: the vault transfer key is active, so its record cannot be replaced, re-identified, invalidated, retired, reactivated or removed",
            ),
            StoreOpError::Decrypt(e) => write!(f, "envelope decrypt failed: {e}"),
            StoreOpError::Corrupt(m) => write!(f, "record body corrupt: {m}"),
            StoreOpError::Fenced {
                holder_epoch,
                db_epoch,
            } => write!(
                f,
                "fenced write rejected: holder epoch {holder_epoch} < database epoch {db_epoch}"
            ),
            StoreOpError::Encode(m) => write!(f, "record encode failed: {m}"),
            StoreOpError::CorruptVault(m) => write!(f, "vault corrupt: {m}"),
            StoreOpError::Store(m) => write!(f, "storage error: {m}"),
        }
    }
}

impl std::error::Error for StoreOpError {}

impl StoreOpError {
    /// Stable refusal code for typed operator refusals.
    pub fn wire_code(&self) -> Option<&'static str> {
        match self {
            StoreOpError::ModuleSecret(error) => Some(error.code()),
            StoreOpError::InvalidAgentSsh => Some("invalid_params"),
            StoreOpError::ConditionHomeOwned => Some("condition_home_owned"),
            StoreOpError::SecretSetupIncomplete => Some("secret_setup_incomplete"),
            StoreOpError::SecretMultiHostDisabled => Some("secret_multi_host_disabled"),
            StoreOpError::SecretBasicAuthDisabled => Some("secret_basic_auth_disabled"),
            StoreOpError::SecretLocalProgramsDisabled => Some("secret_local_programs_disabled"),
            StoreOpError::SecretNameExists => Some("name_exists"),
            StoreOpError::InvalidCredentialId => Some("invalid_credential_id"),
            StoreOpError::InvalidCategoryName => Some("invalid_category_name"),
            StoreOpError::InvalidServiceName { .. } => Some("invalid_service_name"),
            StoreOpError::ServiceInProviderCatalog { .. } => Some("service_in_provider_catalog"),
            StoreOpError::InvalidDisplayName => Some("invalid_params"),
            StoreOpError::InvalidPlanTier => Some("invalid_plan_tier"),
            StoreOpError::InvalidProviderId { .. } => Some("invalid_provider_id"),
            StoreOpError::InvalidGatewaySettings { .. } => Some("invalid_gateway_settings"),
            StoreOpError::GatewayFixed { .. } => Some("gateway_fixed"),
            StoreOpError::InvalidPrincipal => Some("invalid_principal"),
            StoreOpError::DeclaredGrant { .. } => Some("declared_grant"),
            StoreOpError::EnrollmentNameHasGrants { .. } => Some("enrollment_name_has_grants"),
            StoreOpError::CredentialIdIsRemote => Some("credential_id_is_remote"),
            StoreOpError::CredentialIdIsLocal => Some("credential_id_is_local"),
            StoreOpError::InvalidMemberId => Some("invalid_member_id"),
            StoreOpError::MemberGrantSharingSwitch { .. } => Some("member_grant_sharing_switch"),
            StoreOpError::RemoteRecordHomeWatch { .. } => Some("remote_record_home_watch"),
            StoreOpError::TransferKeyReserved => Some("transfer_key_reserved"),
            StoreOpError::FleetKeyReserved => Some("fleet_key_reserved"),
            StoreOpError::BusKeyReserved => Some("bus_key_reserved"),
            StoreOpError::HubAudienceReserved => Some("hub_audience_reserved"),
            StoreOpError::TransferKeyProtected => Some("transfer_key_protected"),
            _ => None,
        }
    }

    /// Stable class paired with [`Self::wire_code`].
    pub fn wire_class(&self) -> Option<&'static str> {
        match self {
            Self::ModuleSecret(error) => Some(error.class()),
            _ => self.wire_code().map(|_| "permanent"),
        }
    }
}

impl From<StoreError> for StoreOpError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Fenced {
                holder_epoch,
                db_epoch,
            } => StoreOpError::Fenced {
                holder_epoch,
                db_epoch,
            },
            // The id-uniqueness triggers abort with these exact messages. Naming the
            // conflict here covers every creator at once, whichever insert tripped it.
            StoreError::Backend(message) if message.contains("credential_id_is_remote") => {
                StoreOpError::CredentialIdIsRemote
            }
            StoreError::Backend(message) if message.contains("credential_id_is_local") => {
                StoreOpError::CredentialIdIsLocal
            }
            other => StoreOpError::Store(other.to_string()),
        }
    }
}

/// Validate a deposit id. The CLI reuses this check so its prompt and the store
/// refuse exactly the same ids.
pub fn validate_deposit_credential_id(credential_id: &str) -> Result<(), StoreOpError> {
    if !crate::credential_id::is_valid_deposit_credential_id(credential_id) {
        return Err(StoreOpError::InvalidCredentialId);
    }
    Ok(())
}

/// SHA-256 of a record's opaque payload — the value an overwrite CAS compares
/// against. Computed over the payload bytes only (not the whole record), so a
/// caller can prove "I am overwriting the payload I last saw" without holding the
/// rest of the record.
pub fn payload_hash(payload: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(payload);
    h.finalize().into()
}

/// The encrypted credential store over a lease-guarded sqlite database.
///
/// Holds the master key (in its zeroizing newtype) for the store's lifetime so
/// every read/write can seal/open records. The underlying [`SqliteStore`] holds
/// the single-writer lease and carries the fence epoch.
pub struct EncryptedStore {
    store: SqliteStore,
    writes: tokio::sync::watch::Sender<()>,
    mapping_gates: Mutex<MappingGates>,
    mapping_gate_writes: Mutex<()>,
    key: MasterKey,
    key_id: KeyId,
    // The audit-chain HMAC key, held in a zeroizing buffer so it is scrubbed from memory
    // on drop rather than lingering for the process lifetime like a plain `[u8; 32]`.
    // Each per-op copy is also a `Zeroizing` clone (scrubbed when the op returns), so the
    // key material never sits in an un-zeroized local either. Deref-coerces to `&[u8; 32]`
    // at the HMAC call sites, so the callees are unchanged.
    audit_key: Zeroizing<[u8; 32]>,
    // Latched true the first time a fenced write is rejected because a newer writer
    // took the lease. This is PERMANENT for a store instance by construction: the
    // fence epoch only ever rises, so a superseded writer can never win a later
    // fenced write. It gives the health probe a precise "fenced out by a newer
    // writer" signal that an unfenced read scan cannot detect on its own (a
    // superseded daemon still reads its stale rows fine — it has only lost WRITE
    // authority), distinguishing "find the other writer" from a generic read error.
    //
    // THE PERMANENCE IS INHERITED, NOT LOCAL. Nothing here keeps the latch set; it
    // stays set only because the lease epoch underneath it is monotonic and never
    // reused or reset. If `cortexkit-lease` ever permitted an epoch to be reused, a
    // superseded writer could win a later fenced write, this latch would be
    // clearable, and two writers would hold the same store without either observing
    // the other. Epoch monotonicity is therefore load-bearing for write custody here
    // and is not enforced by this crate, so it must be preserved by any change to
    // the lease — which will not be apparent from that crate's own tests.
    //
    // AND NOTHING ON THIS SIDE WOULD CATCH IT EITHER, which is the part worth
    // stating rather than leaving as an exercise. The latch's own test rolls the
    // epoch BACK by hand to make a later write succeed — i.e. it simulates the very
    // reuse this comment forbids, precisely to prove the latch does not clear. So it
    // asserts the local property while deliberately violating the inherited one, and
    // cannot detect its loss.
    //
    // NOR DOES THE E2E, checked rather than assumed: the real-daemon suite proves
    // MUTUAL EXCLUSION (the offline CLI is refused, exit 3, while the daemon holds
    // the lease) and never reads the epoch, so a reused epoch would still exclude
    // correctly and pass. Verifying monotonicity means observing the value rise
    // across a real handover, and nothing in either crate does that today.
    //
    // Stated because a limitation named in prose reads as one that was handled. It
    // was not: this is a dependency on another crate's invariant with no automated
    // test on either side of the boundary. What exists is operational: the runbook's
    // deploy acceptance reads the fence epoch across a restart, so a reused epoch
    // would show up as a value that failed to rise — caught by a human comparing two
    // numbers, if they compare them.
    fenced_out: AtomicBool,
    #[cfg(any(test, feature = "test-support"))]
    deposit_cookie_audit_fault: AtomicBool,
}

// None means the settings query was unreadable. An unreadable phone value on
// its own is represented separately from an explicitly disabled phone gate.
type MappingGates = Option<(bool, Option<bool>)>;

/// One sealed row selected by the account machine-key lookup. Its identity and
/// envelope can be checked against a cached token before opening key material.
pub struct AccountMachineKey {
    credential_id: String,
    incarnation: String,
    record_version: u64,
    envelope_digest: String,
    envelope: Vec<u8>,
}

impl AccountMachineKey {
    pub fn identity(&self) -> (&str, &str, u64, &str) {
        (
            &self.credential_id,
            &self.incarnation,
            self.record_version,
            &self.envelope_digest,
        )
    }
}

fn mint_hex_32_sqlite() -> rusqlite::Result<String> {
    mint_hex_32().map_err(|error| {
        rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(format!(
            "{error:?}"
        ))))
    })
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Wrap a message as a rusqlite error so a non-sql failure inside a transaction
/// closure (e.g. an envelope seal failure during rotation) rolls the txn back.
fn rusqlite_err(msg: &str) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH),
        Some(msg.to_string()),
    )
}

/// Lowercase-hex render of a 32-byte hash (the payload hash, for the audit entry).
fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub(crate) use claustrum_providers::encoding::base64url;

pub struct MintedHandle {
    pub raw: String,
    pub hash: String,
}

/// One row of the enrollment ledger, as an operator reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentRow {
    /// `pending` requests carry their request id; live consumers carry their name.
    pub key: String,
    pub name: String,
    /// Proposed on a pending request, approved on a live enrollment; absent before migration 34.
    pub display_name: Option<String>,
    /// Immutable proposal-time permissions; absent on live rows and before migration 40.
    pub requested_grants: Option<Vec<crate::enrollment::RequestedGrant>>,
    pub state: String,
    pub created_at_ms: i64,
    pub token_generation: i64,
    /// Who proposed a pending request: `direct`, `reserved`, `enrolled` or `unverified`.
    /// `None` for live enrollments, for requests proposed before migration 12, and for
    /// every row of a store that has not reached migration 12 yet.
    pub proposer_kind: Option<String>,
    /// The proposer's id: the module id for `reserved`, the enrollment name for
    /// `enrolled`, and `None` for kinds that carry no id.
    pub proposer_id: Option<String>,
}

impl EnrollmentRow {
    /// Defaults describe approved enrollments, never an unverified pending proposal.
    pub fn effective_display_name(&self) -> Option<&str> {
        if self.state == "pending" {
            self.display_name.as_deref()
        } else {
            crate::display_name::effective_enrollment_display_name(
                &self.name,
                self.display_name.as_deref(),
            )
        }
    }
}

/// What a whole-file restore of this store would bring back.
///
/// Every column read here is plaintext, so this answers on a restored copy sitting
/// ANYWHERE -- which is the point: the copy an operator is about to place is exactly the
/// one whose master key does not resolve yet, because the keychain service is derived
/// from the canonical data-dir path.
///
/// *** A REPORT, NOT A REPAIR. *** Deliberately read-only. The decision to scrub belongs
/// to whoever places the store, and a function that silently mutated a restored file
/// would make the placement unauditable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreResurrection {
    /// Capability handles the copy would serve.
    ///
    /// BEARER TOKENS WITH NO TTL. A handle live at capture comes back live, including one
    /// revoked since -- the revocation is a column on the same row, not a separate event,
    /// so a copy taken before it carries no trace that it happened. The audit chain in
    /// that file ends before the revoke, and nothing in the file can see that its tip is
    /// old.
    ///
    /// *** A SCRUB OF THIS TABLE MUST REVOKE, NOT DELETE. *** Both close the re-arm
    /// hazard identically, because `resolve_handle` gates on `revoked = 0` and a revoked
    /// handle is indistinguishable from an unknown one on the wire. But deleting the rows
    /// severs the only join that makes historical `revoke_handle` audit entries readable:
    /// those rows record the handle HASH and carry no credential id, so
    /// `audit_log.payload_hash = handles.handle_hash` is what names the credential.
    ///
    /// Measured on the live store when this was written: 61 such audit rows, 56 still
    /// joinable, 5 ALREADY unjoinable because `ck auth remove` deletes handle rows for a
    /// removed credential. Those five are the control -- they are what a delete-shaped
    /// scrub would do to the other 56, having already happened for a reason that is
    /// correct in its own context.
    ///
    /// The chain still VERIFIES either way; the MACs are untouched. Integrity and
    /// interpretability are different properties and only one of them has a check.
    pub live_handles: usize,
    /// Dangling refresh intents.
    ///
    /// Each is a crash marker for a crash on the machine that was CAPTURED. Boot
    /// reconciliation on the restoring machine reads it as a local one and marks the
    /// credential needs_reauth on no local evidence.
    pub open_intents: usize,
    /// The fence epoch carried in the file, absent when the table is missing.
    ///
    /// The lease counter is a LOCAL file keyed on (module_id, backend, namespace) and
    /// starts fresh. A restored epoch that outruns it refuses every write while the
    /// health detail says "fenced out by a newer writer" -- with no newer writer
    /// anywhere.
    pub fence_epoch: Option<i64>,
    /// Principal-scoped grants: reported for completeness rather than as a hazard.
    ///
    /// Milder than the rest because a stale grant is visible in `ck auth grants`, which
    /// is a verb an operator actually runs.
    pub read_grants: usize,
}

/// What a compound lifecycle transition and handle revocation actually changed.
///
/// Three separate facts rather than one boolean, because they drive different
/// operator advice: a credential that was already dead needs a DIFFERENT next step
/// (`remove`, or a re-login) from one this call just killed, and "handles revoked"
/// alone cannot distinguish them -- a credential with no handles reports zero in
/// both cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidateOutcome {
    /// The lifecycle state moved. False when it was already at the target or the
    /// transition deliberately refuses its current state.
    pub state_changed: bool,
    /// A dangling refresh intent was cleared.
    pub intent_cleared: bool,
    /// How many live handles were revoked.
    pub handles_revoked: usize,
}

impl InvalidateOutcome {
    /// Whether anything at all changed. A false answer is the one worth surfacing:
    /// it means the command reports success while the vault is exactly as it was.
    pub fn changed_anything(&self) -> bool {
        self.state_changed || self.intent_cleared || self.handles_revoked > 0
    }
}

/// One recorded authentication observation, as read back for diagnostics.
#[derive(Debug, Clone)]
pub struct AuthEvent {
    pub ts_ms: i64,
    pub credential_id: String,
    pub kind: String,
    pub provider_status: Option<u16>,
    pub detail: Option<String>,
    /// Consumer-asserted, unverified; from `ReporterSource::as_str`, never raw consumer input.
    pub reporter_source: Option<String>,
    pub record_version: Option<u64>,
    /// Whether this observation actually changed the credential. False for a report
    /// against a superseded version, and for events that authorise no change.
    pub applied: bool,
    /// The caller's resolved principal kind for a scoped-read refusal. Older events
    /// and anonymous observations have no principal and remain `None`.
    pub principal_kind: Option<String>,
    /// The module id for a reserved principal. Unit principals such as `Direct` carry
    /// their full identity in `principal_kind`, so this remains `None` for them.
    pub principal_id: Option<String>,
}

/// The distinct internal reasons a principal-scoped read was refused. These values
/// are diagnostics only; the wire response remains uniformly `not_found`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopedReadRefusal {
    NoGrant,
    NotFound,
    Uncategorized,
    WrongKind,
    StoreError,
}

impl ScopedReadRefusal {
    fn as_str(self) -> &'static str {
        match self {
            ScopedReadRefusal::NoGrant => "no_grant",
            ScopedReadRefusal::NotFound => "not_found",
            ScopedReadRefusal::Uncategorized => "uncategorized",
            ScopedReadRefusal::WrongKind => "wrong_kind",
            ScopedReadRefusal::StoreError => "store_error",
        }
    }
}

/// How many `auth_events` rows are kept per credential.
///
/// Sized for reading a single incident rather than a history: enough to show a
/// sequence of failures and what preceded them, small enough that a consumer stuck in
/// a retry loop cannot grow the store without bound. Older rows for that credential
/// are dropped as newer ones arrive.
///
/// SO THIS TABLE CANNOT ANSWER "HOW OFTEN DOES THIS CREDENTIAL FAIL", and that is a
/// consequence rather than a decision. The cap bounds ROWS, not TIME, so the window
/// it covers is a function of the failure rate itself: a credential that fails twice
/// a month retains a year, while one in a retry loop retains minutes. Any rate
/// computed from these rows is therefore biased toward whatever was failing most, and
/// a credential whose rows all survive is indistinguishable from one whose earlier
/// rows were evicted.
///
/// The audit chain is the place to ask about frequency: it is append-only, never
/// trimmed, and records every invalidation that actually changed a credential. This
/// table explains an incident; the chain counts them.
pub const AUTH_EVENTS_PER_CREDENTIAL: u32 = 64;

/// What a caller observed about a credential's authentication, for `auth_events`.
///
/// `detail` is either a typed variant name (`invalid_grant`, `transport`, `status`)
/// or a locally rendered diagnostic such as a GitHub grant diff. It must never be
/// provider response text: adapters carry raw bodies in their error values, and an OAuth
/// error body can echo submitted parameters, so writing one here would risk putting token
/// material in a plaintext column.
#[derive(Debug, Clone, Copy)]
pub struct AuthObservation<'a> {
    /// What kind of event this was, normally from [`AuthEventKind::as_str`]. Test
    /// fixtures may use a raw value to model legacy or unknown rows.
    pub kind: &'a str,
    /// The provider's HTTP status, when there was one.
    pub provider_status: Option<u16>,
    /// A typed variant or locally rendered safe metadata. Never response text.
    pub detail: Option<&'a str>,
    /// Consumer-asserted, unverified; raw consumer input is unrepresentable here.
    pub reporter_source: Option<ReporterSource>,
    /// The route principal that submitted this observation. `Some(Direct)` records a
    /// known unnamed caller; `None` is reserved for observations that predate attribution.
    pub principal: Option<AuthEventPrincipal<'a>>,
}

/// A principal carried from a route binding into an `auth_events` observation.
///
/// The closed kind vocabulary prevents callers from writing arbitrary principal kinds,
/// while a reserved module id remains available because it is assigned at route bind.
#[derive(Debug, Clone, Copy)]
pub enum AuthEventPrincipal<'a> {
    Direct,
    Reserved(&'a str),
    /// A consumer holding an enrollment token, named by the enrollment it resolved to.
    ///
    /// WITHOUT THIS VARIANT AN ENROLLED REPORT LOGS `direct` WITH NO ID, because that is
    /// what the bus carries: a host-launched consumer binds as Direct and proves who it
    /// is with the token, not with the socket. An operator reading `auth_events` after a
    /// credential went stale would see the transport and not the reporter.
    Enrolled(&'a str),
    /// Another member's vault, named by its member id (`fed-computer:<fp>`), on a
    /// federation channel. The channel itself is opened by callosum, so without this
    /// variant such a row would name `reserved:callosum` rather than the member that
    /// actually made the call.
    Member(&'a str),
    /// An authenticated phone channel, including its `fed-phone:` prefix.
    Phone(&'a str),
    Unverified,
}

impl<'a> AuthEventPrincipal<'a> {
    const fn kind(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Reserved(_) => "reserved",
            Self::Enrolled(_) => "enrolled",
            Self::Member(_) => "member",
            Self::Phone(_) => "phone",
            Self::Unverified => "unverified",
        }
    }

    const fn id(self) -> Option<&'a str> {
        match self {
            Self::Reserved(module_id) => Some(module_id),
            Self::Enrolled(name) => Some(name),
            Self::Member(member_id) => Some(member_id),
            Self::Phone(phone_id) => Some(phone_id),
            Self::Direct | Self::Unverified => None,
        }
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "store_taxonomy_tests.rs"]
mod taxonomy_tests;

#[cfg(test)]
#[path = "store_admin_apply_taxonomy_tests.rs"]
mod admin_apply_taxonomy_tests;

#[cfg(test)]
#[path = "store_audit_target_delimiter_tests.rs"]
mod audit_target_delimiter_tests;

#[cfg(test)]
#[path = "store_list_scoped_snapshot_tests.rs"]
mod list_scoped_snapshot_tests;

#[cfg(test)]
#[path = "store_coverage_phase_tests.rs"]
mod coverage_phase_tests;

#[cfg(test)]
#[path = "store_migration_10_tests.rs"]
mod migration_10_tests;

#[cfg(test)]
#[path = "deposit_cookie_tests.rs"]
mod deposit_cookie_tests;

#[cfg(test)]
#[path = "enrollment_grant_tests.rs"]
mod enrollment_grant_tests;

#[cfg(test)]
#[path = "provider_ids_store_tests.rs"]
mod provider_ids_store_tests;

#[cfg(test)]
#[path = "plan_tier_store_tests.rs"]
mod plan_tier_store_tests;

#[path = "store_federation.rs"]
mod federation_store;

#[cfg(test)]
#[path = "store_federation_tests.rs"]
mod store_federation_tests;

#[cfg(test)]
#[path = "engine_federation_tests.rs"]
mod engine_federation_tests;

#[cfg(test)]
#[path = "transfer_key_fence_tests.rs"]
mod transfer_key_fence_tests;

#[path = "store_agent_secrets.rs"]
mod store_agent_secrets;

#[path = "store_module_secrets.rs"]
pub mod module_secrets;

#[path = "store_fleet.rs"]
mod fleet_store;

#[path = "store_declared_grants.rs"]
mod declared_grants;

#[cfg(test)]
#[path = "declared_grants_tests.rs"]
mod declared_grants_tests;

#[path = "store_gh_activations.rs"]
mod gh_activations;

#[path = "store_gh_admin.rs"]
mod gh_admin;

#[path = "store_gh_approval.rs"]
mod gh_approval;

#[path = "store_gh_manifests.rs"]
mod gh_manifests;

#[path = "store_gh_proposals.rs"]
mod gh_proposals;

#[path = "store_registered_providers.rs"]
mod registered_providers;

pub use declared_grants::{
    declared_grant_approval_sentence, declared_grant_sets_read_only, parse_declared_grants,
    DeclarationDiagnostics, DeclaredGrant, DeclaredGrantListing, DeclaredGrantRecord,
    DeclaredGrantSet, SkippedDeclaredGrant, ACCOUNT_TOKEN_AUDIENCES,
    DECLARED_GRANT_APPROVAL_TEMPLATES, DECLARED_GRANT_CATEGORY_NAMES, MAX_DECLARED_GRANTS,
};

pub use gh_activations::{
    GhManifestActivationOutcome, GhManifestActivationReport, GhManifestActiveStatus,
    GhManifestComputerStatus, GhManifestHandoffEnvelope, GhManifestLatest,
    GhManifestLowerVersionReported, GhManifestVerdict,
};

pub use gh_manifests::{GhManifestSource, GhManifestVersion, GH_MANIFEST_ROOT_KEY_ID};

pub use gh_proposals::{
    manifest_one_tap_status_read_only, GhManifestProposal, GhManifestProposalError,
    GhManifestProposalInput, PreparedGhManifestProposal, MANIFEST_ONE_TAP_SETTING,
};

#[path = "store_gateway.rs"]
mod gateway;

pub use gateway::StoredGatewaySettings;

#[cfg(test)]
#[path = "gateway_create_tests.rs"]
mod gateway_create_tests;

#[cfg(test)]
#[path = "gateway_fixed_tests.rs"]
mod gateway_fixed_tests;

#[cfg(test)]
#[path = "gateway_readers_tests.rs"]
mod gateway_readers_tests;

pub use registered_providers::{
    api_key_service, registered_providers_read_only, valid_provider_header_name,
    validate_registered_provider_service, validate_registered_provider_settings,
    RegisteredProvider, RegisteredProviderSettings, MAX_REGISTERED_PROVIDER_HOSTS,
};

/// Operator writes for agent secrets and the lease-free `ck auth secret` listing.
pub use store_agent_secrets::{
    list_agent_secret_grants_read_only, list_agent_secrets_read_only, OperatorFlowGrantRow,
    OperatorGrantRow, OperatorPhoneRow, OperatorSecretListing, OperatorSecretRow,
};

/// Where agent secrets live: the `secrets.home_member` setting and the role it resolves to.
pub use store_agent_secrets::{
    resolve_secret_home_role, secret_home_read_only, SecretHomeChange, SecretHomeRole,
    SecretHomeStatus, SECRET_HOME_SELF, SECRET_HOME_SETTING,
};

pub use store_agent_secrets::{
    secret_basic_auth_status_read_only, secret_local_programs_status_read_only,
    secret_multi_host_status_read_only, secret_phone_gate_status_read_only, PhoneDeposit,
    PhoneOperation, SecretDepositPublicKey, SecretUseOutcome,
};

/// Sealed releases to paired computers and the receipts that answer their retries.
pub use store_agent_secrets::{
    ForwardedUse, ReleaseRequest, SealedRelease, SECRET_RELEASE_RECEIPT_LIFETIME_MS,
};

impl EncryptedStore {
    /// Wrap an already-open, migrated [`SqliteStore`] with a master key, loading (or
    /// creating, on a brand-new vault) the sealed audit-chain key.
    ///
    /// The audit key is a secret from the operating system's secure random generator,
    /// created ONCE — when the vault is brand-new (no credentials, no audit entries, no
    /// existing audit_key row) — and SEALED under the master key. On every later open
    /// it is LOADED and decrypted; a wrong master key fails that decrypt the same way
    /// it fails a record decrypt (fail-closed, not a panic). It is NEVER regenerated
    /// for an existing vault: a
    /// missing audit_key row on a non-empty vault is [`StoreOpError::CorruptVault`]
    /// (regenerating would silently make every existing audit entry unverifiable).
    /// The store must have had [`EncryptedStore::migrate`] applied first.
    pub fn open(store: SqliteStore, key: MasterKey) -> Result<Self, StoreOpError> {
        let key_id = key.key_id();
        let audit_key = load_or_create_audit_key(&store, &key)?;
        let gates = store
            .with_conn(store_agent_secrets::mapping_gates_from_conn)
            .ok();
        let encrypted = EncryptedStore {
            store,
            writes: tokio::sync::watch::channel(()).0,
            mapping_gates: Mutex::new(gates),
            mapping_gate_writes: Mutex::new(()),
            key,
            key_id,
            audit_key,
            fenced_out: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-support"))]
            deposit_cookie_audit_fault: AtomicBool::new(false),
        };
        encrypted.sweep_pending_enrollments_on_open(now_ms())?;
        Ok(encrypted)
    }

    /// Whether a fenced write has ever been rejected on this store instance because
    /// a newer writer holds the lease. Once true it stays true (the fence epoch only
    /// rises). The health probe reads it to report a precise fenced-out state.
    pub fn is_fenced_out(&self) -> bool {
        self.fenced_out.load(Ordering::Relaxed)
    }

    /// Run a fenced write, latching [`Self::is_fenced_out`] if it is rejected by a
    /// newer lease holder. The single choke point credential mutations route
    /// through, so the fenced-out signal is set exactly once, at the source, rather
    /// than at each call site. Returns `Result<_, StoreError>` exactly like the
    /// underlying `with_conn_fenced`, so it is a drop-in at every call site (the
    /// existing `?`/`map_err` error tails are unchanged).
    ///
    /// THE LATCH IS ONE-WAY ON PURPOSE, AND NOTHING CLEARS IT SHORT OF A RESTART.
    /// That is normally the signature of a broken gauge — a status that cannot return
    /// to ok is a boot-scoped incident log rather than a health signal, and every
    /// other field of [`crate::health::VaultHealth`] is recomputed from a fresh scan
    /// for exactly that reason. This one is different because THE CONDITION ITSELF
    /// IS IRREVERSIBLE: losing the epoch fence means another writer holds the lease,
    /// and this process cannot take it back. A later write appearing to succeed would
    /// mean the OTHER holder had gone, not that this instance regained authority.
    /// Clearing the latch on such a write would resume serving as the authority on
    /// the strength of a race.
    /// So the honest recovery sequence is: this process exits, and a new one acquires
    /// the lease from scratch. Fail-closed until then. Do not "fix" this by clearing
    /// the flag on a subsequent successful write.
    fn fenced_write<T>(
        &self,
        f: impl FnOnce(&rusqlite::Transaction) -> rusqlite::Result<T>,
    ) -> Result<T, StoreError> {
        self.fenced_write_after_commit(f, |_| {})
    }

    fn fenced_write_after_commit<T>(
        &self,
        f: impl FnOnce(&rusqlite::Transaction) -> rusqlite::Result<T>,
        after_commit: impl FnOnce(&T),
    ) -> Result<T, StoreError> {
        let out = self.store.with_conn_fenced(f);
        if let Ok(value) = &out {
            after_commit(value);
        }
        if matches!(out, Err(StoreError::Fenced { .. })) {
            self.fenced_out.store(true, Ordering::Relaxed);
        }
        self.signal_commit(&out);
        out
    }

    // with_conn_fenced returns only after commit. Runtime mutations pass through
    // fenced_write, except deliberately unfenced diagnostic observations. Permission
    // observations also call this hook; held plans are not reader-visible until the
    // next token commit. Migrations, audit-key bootstrap and the
    // enrollment sweep precede serving. Failed transactions never wake readers;
    // successful no-ops may wake them and are filtered by their projected digests.
    fn signal_commit<T>(&self, result: &Result<T, StoreError>) {
        if result.is_ok() {
            self.writes.send_replace(());
        }
    }

    pub fn subscribe_writes(&self) -> tokio::sync::watch::Receiver<()> {
        self.writes.subscribe()
    }

    /// The fingerprint of the master key this store seals under.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Run a closure against the raw underlying connection. Test-only: the
    /// conformance tests set up lease-handover (a fence-epoch bump) and inspect raw
    /// rows that the public API deliberately does not expose. Not part of the
    /// production surface.
    #[cfg(test)]
    pub(crate) fn with_raw_conn<T>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> rusqlite::Result<T>,
    ) -> Result<T, StoreOpError> {
        self.store.with_conn(f).map_err(StoreOpError::from)
    }

    /// [`Self::fenced_write`], refusing first if the active transfer key's fence forbids
    /// writing to `credential_id`.
    ///
    /// One helper for the writers that choose their SQL from the credential id (the
    /// state writer and the two report writers): each needs the fence read and the write
    /// in the same transaction, and this keeps that shape in one place instead of three
    /// copies of a guard that a later edit could drop from one of them. It stays on the
    /// fenced path on purpose, so these writers still latch a lease handover like every
    /// other durable mutation.
    fn fenced_write_unless_transfer_key_protected<T>(
        &self,
        credential_id: &str,
        work: impl FnOnce(&rusqlite::Transaction) -> rusqlite::Result<T>,
    ) -> Result<T, StoreOpError> {
        let refused = std::cell::Cell::new(false);
        let outcome = self.fenced_write(|tx| {
            if store_agent_secrets::deposit_key_write_protected(tx, credential_id)?
                || crate::federation::is_vault_transfer_id(credential_id)
                    && vault_transfer_key_fence_holds_tx(tx)?
            {
                refused.set(true);
                return Err(rusqlite::Error::InvalidQuery);
            }
            work(tx)
        });
        match outcome {
            Ok(value) => Ok(value),
            Err(_refusal) if refused.get() => Err(StoreOpError::TransferKeyProtected),
            Err(error) => Err(StoreOpError::from(error)),
        }
    }

    // ---- master-key rotation --------------------------------------------

    /// Rotate the master key: re-wrap every record and the sealed audit key under
    /// `new_key`, swap every `key_id` column to the new fingerprint, and append a
    /// `RotateMasterKey` audit entry — ALL in ONE fenced transaction, so it is
    /// atomic (all-or-nothing). A `Fenced`/failed transaction leaves the OLD key
    /// opening everything (fail-closed); only post-commit is the old key dead.
    ///
    /// The caller MUST persist `new_key` to the key store BEFORE calling this, so a
    /// crash right after commit leaves the vault openable by the persisted new key.
    /// The audit_key VALUE is unchanged (only re-sealed), so the chain stays one
    /// continuously-verifiable sequence across the rotation; the `RotateMasterKey`
    /// entry is MAC'd with that stable audit key and chains cleanly.
    ///
    /// A record that fails to decrypt under the OLD key is already corrupt; it cannot be
    /// re-wrapped under the new key, so it is QUARANTINED (state flipped to `corrupt`)
    /// in the same transaction and its id is collected, rather than silently skipped
    /// while the rotation still reports success. Dropping the old key loses nothing
    /// further (the row was already unreadable), but marking it `corrupt` means the
    /// post-rotation health scan and the returned id list SURFACE it instead of leaving a
    /// still-old-key-sealed row behind a "success". The returned `Vec` is the quarantined
    /// ids (empty on a clean rotation) so the CLI can warn the operator.
    ///
    /// On success the store's in-memory key + key_id are swapped to the new key.
    pub fn rotate_master_key(&mut self, new_key: MasterKey) -> Result<Vec<String>, StoreOpError> {
        let old_key = &self.key;
        let new_key_id_hex = new_key.key_id().to_hex();
        let audit_key = self.audit_key.clone();

        // Re-seal the audit-key secret under the new key (value unchanged).
        let audit_binding = RecordBinding {
            credential_id: AUDIT_KEY_SECRET_NAME,
            record_version: AUDIT_KEY_RECORD_VERSION,
        };
        let new_audit_envelope =
            envelope::seal(&new_key, &*audit_key, &audit_binding).map_err(StoreOpError::Decrypt)?;

        let quarantined = self
            .fenced_write(|tx| {
                // Snapshot every record id + version + current envelope.
                let rows: Vec<(String, i64, Vec<u8>)> = {
                    let mut stmt = tx.prepare(
                        "SELECT credential_id, record_version, envelope FROM credentials",
                    )?;
                    let mapped = stmt.query_map([], |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, i64>(1)?,
                            r.get::<_, Vec<u8>>(2)?,
                        ))
                    })?;
                    mapped.collect::<rusqlite::Result<Vec<_>>>()?
                };

                let mut quarantined: Vec<String> = Vec::new();
                for (id, version, old_blob) in rows {
                    let binding = RecordBinding {
                        credential_id: &id,
                        record_version: version as u64,
                    };
                    // Decrypt with the old key; a record that does not decrypt is already
                    // corrupt. It cannot be re-wrapped, so QUARANTINE it (flip to `corrupt`)
                    // in this same transaction and record its id — never leave a still-old-
                    // key row behind a reported success.
                    let plaintext = match envelope::open(old_key, &old_blob, &binding) {
                        Ok(pt) => pt,
                        Err(_) => {
                            tx.execute(
                                "UPDATE credentials SET state = ?2 WHERE credential_id = ?1",
                                rusqlite::params![id, RecordState::Corrupt.as_str()],
                            )?;
                            quarantined.push(id);
                            continue;
                        }
                    };
                    // Re-seal under the new key. The same id and version give the same
                    // additional authenticated data (AAD), so the binding is unchanged.
                    let new_blob = envelope::seal(&new_key, &plaintext, &binding)
                        .map_err(|_| rusqlite_err("re-seal under new key failed"))?;
                    tx.execute(
                        "UPDATE credentials SET envelope = ?2, key_id = ?3 \
                     WHERE credential_id = ?1",
                        rusqlite::params![id, new_blob, new_key_id_hex],
                    )?;
                }

                quarantined.extend(store_agent_secrets::rotate_agent_secrets_tx(
                    tx, old_key, &new_key,
                )?);
                quarantined.extend(module_secrets::rotate_module_secrets_tx(
                    tx, old_key, &new_key,
                )?);
                fleet_store::rotate_fleet_epochs_tx(tx, old_key, &new_key)?;

                // Re-seal the audit-key secret row under the new key.
                tx.execute(
                    "UPDATE vault_secrets SET envelope = ?2, key_id = ?3 WHERE name = ?1",
                    rusqlite::params![AUDIT_KEY_SECRET_NAME, new_audit_envelope, new_key_id_hex],
                )?;

                // Append the vault-global RotateMasterKey entry (no credential_id),
                // MAC'd with the stable audit key so the chain stays continuous.
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: AuditOp::RotateMasterKey,
                        credential_id: None,
                        payload_hash: None,
                        actor: "offline-cli".to_string(),
                        alarm: Some(AlarmReason::AdminWrite),
                    },
                )?;
                Ok(quarantined)
            })
            .map_err(StoreOpError::from)?;

        // Commit succeeded: the new key now opens everything. Swap in-memory state.
        self.key_id = new_key.key_id();
        self.key = new_key;
        Ok(quarantined)
    }

    /// Seal a record into a cipher envelope bound to its id + version.
    ///
    /// Short-term Bedrock keys are refused at the operator deposit sinks (create and
    /// unconditional overwrite), not here. This also re-seals existing records during
    /// master-key rotation, where refusing one stored record would abort the whole
    /// rotation; a dead key already in the store is the operator's to remove.
    fn seal_record(
        &self,
        credential_id: &str,
        record: &VaultRecord,
    ) -> Result<Vec<u8>, StoreOpError> {
        if let Some(enrollment) = &record.agent_ssh {
            if !credential_id.starts_with("signing:")
                || record.kind != CredentialKind::SigningKey
                || std::str::from_utf8(record.payload.expose())
                    .ok()
                    .and_then(|pem| crate::signing::public_key_ed25519(pem).ok())
                    .is_none()
                || enrollment.clone().canonicalized().ok().as_ref() != Some(enrollment)
            {
                return Err(StoreOpError::InvalidAgentSsh);
            }
        }
        // An OAuth record may intentionally contain no access token while retaining a
        // refresh token; first use then refreshes it. Every non-OAuth credential is the
        // served payload itself, so sealing zero bytes would create a successful read
        // that downstreams can misdiagnose as an authentication failure.
        if record.kind != CredentialKind::Oauth && record.payload.expose().is_empty() {
            return Err(StoreOpError::Encode(
                "non-OAuth credential payload must not be empty".into(),
            ));
        }
        // The sentinel is never a credential. Entrance checks enumerate doors, and the door
        // that matters is the one added next. The unattended re-sealer is the live caller that
        // makes this concrete: it re-seals whatever it finds in a consumer store, and that
        // store is exactly where the tombstone gets written.
        if (record.kind != CredentialKind::Oauth
            && record
                .payload
                .expose()
                .starts_with(CUSTODY_TOMBSTONE_PREFIX.as_bytes()))
            || record.oauth.as_ref().is_some_and(|oauth| {
                is_custody_tombstone(oauth.access_token.expose())
                    || is_custody_tombstone(oauth.refresh_token.expose())
            })
        {
            return Err(StoreOpError::Encode(
                "custody-tombstone material is not a credential; storing it would invert custody"
                    .into(),
            ));
        }
        // `Cookie` is a request header captured after the browser consumed Set-Cookie
        // attributes. It cannot disclose an expiry, so accepting a supplied timestamp
        // would persist an invented lifetime rather than an observed fact.
        //
        // IF YOU ARE HERE TO RELAX THIS REFUSAL, READ THE NEXT PARAGRAPH FIRST. There is
        // one capture path that makes a cookie expiry real -- a browser extension, where
        // `chrome.cookies.getAll` returns `expirationDate` uniformly on every platform
        // instead of being refused by App-Bound Encryption on Windows. If the desktop
        // surface adopts it, deleting this check is correct.
        //
        // WHAT MUST NOT FOLLOW: the field reaching a fetch or serve decision. A browser
        // `expirationDate` is an UPPER BOUND -- a session can be revoked server-side long
        // before it, and can outlive a conservative value -- so refusing on a passed
        // declaration takes a possibly-working session dark on the strength of metadata,
        // manufacturing an outage from a hint. The authoritative test is the request and
        // the authoritative answer is the provider's 401.
        //
        // A passed bound is strong evidence of death; a future bound rules re-capture out
        // as the likely fix; NEITHER proves the session is alive. That asymmetry is the
        // whole value, and it is diagnostic value: it sharpens what an operator is told
        // after a 401, and gates nothing. insula holds the mirror of this rule at its
        // consumption site: `quota-core/src/grok.rs::expiry_never_overrides_a_successful_fetch`
        // asserts that a successful fetch keeps its result even when the stated expiry has
        // passed.
        //
        // THE SYMBOL AND NOT A LINE NUMBER, deliberately. A line in a repository this one
        // does not control slides on any edit above it -- theirs, a formatter's, anyone's --
        // and then points confidently at something else with nothing failing. A symbol name
        // survives edits and reordering, and when it does break it breaks LOUDLY: a reader
        // who greps for it and finds nothing knows the citation is stale, which is the
        // signal a wrong line number denies them. Same rule as preferring a version anchor
        // over a date: choose the reference whose failure the reader can detect.
        //
        // A CITATION, NOT AN AGREEMENT. A claim that another repository behaves some way
        // reads exactly the same whether it is true or false, and stays unverifiable until
        // someone opens the other tree. A file and a symbol are openable by anyone with
        // both checkouts; an agreement is not.
        //
        // The drift is a WELL-MEANING one, which is why it is written here rather than
        // left as an unwritten understanding between the two repositories: an implementer
        // sees a stored expiry and a request about to go out with an apparently-dead
        // cookie, and adds the check as an obvious improvement. Nothing fails. The operator quietly loses sessions
        // that were still working.
        if record.kind == CredentialKind::Cookie && record.expires_at_ms.is_some() {
            return Err(StoreOpError::Encode(
                "cookie credentials must not declare an expiry".into(),
            ));
        }
        let body = record
            .encode()
            .map_err(|e| StoreOpError::Encode(e.to_string()))?;
        let binding = RecordBinding {
            credential_id,
            record_version: record.record_version,
        };
        envelope::seal(&self.key, &body, &binding).map_err(StoreOpError::Decrypt)
    }
}
