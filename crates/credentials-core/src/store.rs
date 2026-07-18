//! The encrypted credential store: durable custody of [`VaultRecord`]s, each
//! sealed value-level and written through the epoch-fenced path.
//!
//! This layer owns persistence and the at-rest crypto wiring; it does NOT own the
//! wire surfaces, the audit chain, or the refresh state machine (those live above
//! it). Every durable mutation goes through `cortexkit-store`'s `with_conn_fenced`
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
//! - `state` (plaintext) — `active` | `needs_reauth` | `corrupt`. A row that fails
//!   to decrypt is quarantined here (per-record), never panics, and never takes
//!   down the rest of the vault.
//! - `envelope` (BLOB) — the sealed record (the only place plaintext fields live,
//!   and only in encrypted form).
//! - `updated_at_ms` — last-write wall clock (diagnostics only).
//!
//! ## Fail-closed, never-panic
//!
//! A decrypt/parse failure on read marks that single id `corrupt` and returns a
//! typed [`StoreOpError`]; the vault keeps serving every other credential. This is
//! the per-record quarantine the availability contract requires (NOT a whole-DB
//! reset — auto-wiping on perceived corruption is itself a data-loss/DoS vector).

use std::sync::atomic::{AtomicBool, Ordering};

use cortexkit_store::{Migration, SqliteStore, StoreError};
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::audit::{self, AlarmReason, AuditCtx, AuditEntry, AuditOp, AuditRecord};
use crate::envelope::{self, EnvelopeError, RecordBinding};
use crate::key::{KeyId, MasterKey};
use crate::record::VaultRecord;

/// The schema namespace for the credential vault's migrations (independent of any
/// other domain chain in the same database).
const SCHEMA_NAMESPACE: &str = "credentials";

/// The vault schema. The fence table is created lazily by `with_conn_fenced` on
/// the first fenced write and is not declared here.
///
/// `refresh_intent` is the durable crash-safety log for OAuth refresh: a row is
/// fsynced BEFORE the provider's rotating refresh endpoint is called, and cleared
/// in the same transaction that commits the new tokens. A row that survives a
/// restart means a refresh was interrupted between the provider call and the
/// commit (its outcome is INDETERMINATE — the provider may have rotated), which
/// startup reconciliation resolves fail-safe. At most one intent per credential
/// (the id is the primary key), matching the engine's single-flight.
const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        statements: "CREATE TABLE credentials (\
                         credential_id   TEXT PRIMARY KEY, \
                         record_version  INTEGER NOT NULL, \
                         key_id          TEXT NOT NULL, \
                         state           TEXT NOT NULL, \
                         envelope        BLOB NOT NULL, \
                         updated_at_ms   INTEGER NOT NULL\
                     ); \
                     CREATE TABLE refresh_intent (\
                         credential_id    TEXT PRIMARY KEY, \
                         record_version   INTEGER NOT NULL, \
                         old_refresh_hash TEXT NOT NULL, \
                         lease_epoch      INTEGER NOT NULL, \
                         started_at_ms    INTEGER NOT NULL\
                     );",
    },
    // Capability handles + the tamper-evident audit chain.
    //
    // `handles`: a credential is read by an unguessable 256-bit capability handle,
    // not its public alias. Only the handle's SHA-256 HASH is stored (the raw handle
    // is returned once at mint and written into the consumer's 0600 config), so a
    // database leak yields no usable handle — just which credential_ids exist and
    // how many handles each has (metadata, never a secret), which is why these are
    // plaintext columns while credential payloads stay value-encrypted. Handles are
    // per-credential revocable (revoke one, or all for a credential, and mint a fresh
    // one without re-login).
    //
    // `audit_log`: an append-only, HMAC-chained record of EVERY durable mutation
    // (admin writes, refresh commits, revocations), so every credential version is
    // accounted for and an unexplained version bump is a detectable chain gap. Each
    // entry's `entry_mac` is HMAC(audit_key, prev_mac || fields), keyed by a
    // master-key-derived audit key, so the log cannot be forged or repaired without
    // the master key. `alarm` flags a detected anomaly (overwrite-without-CAS,
    // fetch-rate anomaly, admin write) as a durable, queryable row rather than a live
    // notification.
    Migration {
        version: 2,
        statements: "CREATE TABLE handles (\
                         handle_hash    TEXT PRIMARY KEY, \
                         credential_id  TEXT NOT NULL, \
                         created_at_ms  INTEGER NOT NULL, \
                         revoked        INTEGER NOT NULL DEFAULT 0\
                     ); \
                     CREATE INDEX idx_handles_credential ON handles(credential_id); \
                     CREATE TABLE audit_log (\
                         seq            INTEGER PRIMARY KEY AUTOINCREMENT, \
                         ts_ms          INTEGER NOT NULL, \
                         op             TEXT NOT NULL, \
                         credential_id  TEXT, \
                         payload_hash   TEXT, \
                         actor          TEXT NOT NULL, \
                         alarm          INTEGER NOT NULL DEFAULT 0, \
                         alarm_reason   TEXT, \
                         prev_mac       TEXT NOT NULL, \
                         entry_mac      TEXT NOT NULL\
                     ); \
                     CREATE TABLE vault_secrets (\
                         name      TEXT PRIMARY KEY, \
                         key_id    TEXT NOT NULL, \
                         envelope  BLOB NOT NULL\
                     );",
    },
];

/// The `vault_secrets` row name for the audit-chain HMAC key. The audit key is a
/// CSPRNG secret created once and SEALED under the master key (so the audit log is
/// unforgeable without the master key), re-sealed on master-key rotation but never
/// regenerated — keeping one continuously-verifiable chain across rotations. Its
/// envelope uses this fixed pseudo-id and version 0 as the AAD binding.
const AUDIT_KEY_SECRET_NAME: &str = "__vault_audit_key__";
const AUDIT_KEY_RECORD_VERSION: u64 = 0;

/// The non-secret lifecycle state of a stored record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordState {
    /// Decryptable and serveable.
    Active,
    /// Authoritatively invalidated (logout / revoke / a reported auth failure):
    /// the credential is present but must not be served until re-auth.
    NeedsReauth,
    /// Undecryptable / corrupt: quarantined so a `get` fails closed for this id
    /// while the rest of the vault keeps serving.
    Corrupt,
}

impl RecordState {
    /// The stable lowercase wire/display form (also what the `state` column stores).
    pub fn as_str(self) -> &'static str {
        match self {
            RecordState::Active => "active",
            RecordState::NeedsReauth => "needs_reauth",
            RecordState::Corrupt => "corrupt",
        }
    }

    fn from_str(s: &str) -> RecordState {
        match s {
            "active" => RecordState::Active,
            "needs_reauth" => RecordState::NeedsReauth,
            // `corrupt` and ANY unrecognized value fail closed to Corrupt: an
            // unknown lifecycle string must never be served as if active.
            _ => RecordState::Corrupt,
        }
    }
}

/// The non-secret metadata of a stored record, readable WITHOUT decrypting (the
/// plaintext columns). Used by rotation scans, status, and CAS pre-checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordMeta {
    /// The stored record's monotonic version.
    pub record_version: u64,
    /// Hex fingerprint of the master key this row is sealed under.
    pub key_id_hex: String,
    /// The row's lifecycle state.
    pub state: RecordState,
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
    /// The credential id does not exist.
    NotFound,
    /// A create was attempted for an id that already exists (create-only default).
    AlreadyExists,
    /// A CAS overwrite's `expected_payload_hash` did not match the current record.
    CasMismatch,
    /// The record is quarantined (`corrupt`) and cannot be served.
    Quarantined,
    /// The record is `needs_reauth` and must not be served until re-authenticated.
    NeedsReauth,
    /// The cipher envelope failed to decode/decrypt. The id has been quarantined.
    Decrypt(EnvelopeError),
    /// The decrypted body failed to parse as a record. The id has been quarantined.
    Corrupt(String),
    /// A fenced write was rejected because a newer writer holds the database (the
    /// lease-handover race). The write was NOT applied.
    Fenced { holder_epoch: u64, db_epoch: u64 },
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

impl std::fmt::Display for StoreOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreOpError::NotFound => f.write_str("credential not found"),
            StoreOpError::AlreadyExists => {
                f.write_str("credential already exists (create-only; use a CAS overwrite)")
            }
            StoreOpError::CasMismatch => {
                f.write_str("compare-and-set failed: expected payload hash did not match")
            }
            StoreOpError::Quarantined => f.write_str("credential is quarantined (corrupt)"),
            StoreOpError::NeedsReauth => f.write_str("credential needs re-authentication"),
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
            other => StoreOpError::Store(other.to_string()),
        }
    }
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
    fenced_out: AtomicBool,
}

impl EncryptedStore {
    /// Wrap an already-open, migrated [`SqliteStore`] with a master key, loading (or
    /// creating, on a brand-new vault) the sealed audit-chain key.
    ///
    /// The audit key is a CSPRNG secret created ONCE — when the vault is brand-new
    /// (no credentials, no audit entries, no existing audit_key row) — and SEALED
    /// under the master key. On every later open it is LOADED and decrypted; a wrong
    /// master key fails that decrypt the same way it fails a record decrypt
    /// (fail-closed, not a panic). It is NEVER regenerated for an existing vault: a
    /// missing audit_key row on a non-empty vault is [`StoreOpError::CorruptVault`]
    /// (regenerating would silently make every existing audit entry unverifiable).
    /// The store must have had [`EncryptedStore::migrate`] applied first.
    pub fn open(store: SqliteStore, key: MasterKey) -> Result<Self, StoreOpError> {
        let key_id = key.key_id();
        let audit_key = load_or_create_audit_key(&store, &key)?;
        Ok(EncryptedStore {
            store,
            key,
            key_id,
            audit_key,
            fenced_out: AtomicBool::new(false),
        })
    }

    /// Whether a fenced write has ever been rejected on this store instance because
    /// a newer writer holds the lease. Once true it stays true (the fence epoch only
    /// rises). The health probe reads it to report a precise fenced-out state.
    pub fn is_fenced_out(&self) -> bool {
        self.fenced_out.load(Ordering::Relaxed)
    }

    /// Run a fenced write, latching [`Self::is_fenced_out`] if it is rejected by a
    /// newer lease holder. The single choke point every durable mutation routes
    /// through, so the fenced-out signal is set exactly once, at the source, rather
    /// than at each call site. Returns `Result<_, StoreError>` exactly like the
    /// underlying `with_conn_fenced`, so it is a drop-in at every call site (the
    /// existing `?`/`map_err` error tails are unchanged).
    fn fenced_write<T>(
        &self,
        f: impl FnOnce(&rusqlite::Transaction) -> rusqlite::Result<T>,
    ) -> Result<T, StoreError> {
        let out = self.store.with_conn_fenced(f);
        if matches!(out, Err(StoreError::Fenced { .. })) {
            self.fenced_out.store(true, Ordering::Relaxed);
        }
        out
    }

    /// Apply the vault schema migrations to a freshly opened store and set the
    /// vault's durability level. Idempotent. Call once, right after opening, before
    /// any credential write.
    ///
    /// Sets `PRAGMA synchronous=FULL` on the store's connection: the vault's SQLite
    /// IS its own source of truth (a lost token-rotation commit is unrecoverable),
    /// so it must fsync every commit. This is stronger than WAL's default
    /// `synchronous=NORMAL` (which can lose the last transaction on power loss) and
    /// is set vault-locally rather than in `cortexkit-store`, because the other
    /// consumers hold rebuildable projections that are correct at NORMAL and should
    /// not pay FULL's fsync-per-commit. `SqliteStore` is one connection behind a
    /// mutex, so setting it once here covers every later `with_conn`/
    /// `with_conn_fenced` call.
    /// Read the database's recorded master-key fingerprint WITHOUT the master key:
    /// the plaintext `key_id` of the sealed audit-key row (which always exists from
    /// vault-init). This is the crash-safe-resolve anchor — the resolver compares it
    /// to each key-store slot's fingerprint to pick the slot the database is actually
    /// sealed under (see [`resolver::resolve_for_db`]). `None` on a brand-new vault
    /// whose audit-key row does not exist yet (then `Current` is the only candidate).
    pub fn read_db_key_id(store: &SqliteStore) -> Result<Option<KeyId>, StoreError> {
        let hex: Option<String> = store
            .with_conn(|c| {
                c.query_row(
                    "SELECT key_id FROM vault_secrets WHERE name = ?1",
                    rusqlite::params![AUDIT_KEY_SECRET_NAME],
                    |r| r.get::<_, String>(0),
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })
            })
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        // Distinguish "no row" (a brand-new vault, resolve against `Current`) from "row
        // present but its fingerprint is unparseable" (a corrupt anchor). The old code
        // collapsed both to `None`, which would silently downgrade a corrupt anchor into
        // the bootstrap path and could open a mismatched key. A present-but-invalid
        // fingerprint fails closed as a corrupt store instead.
        match hex {
            None => Ok(None),
            Some(h) => KeyId::from_hex(&h).map(Some).ok_or_else(|| {
                StoreError::Backend(format!(
                    "vault_secrets audit-key row has an invalid key_id fingerprint '{h}' \
                     (corrupt anchor)"
                ))
            }),
        }
    }

    pub fn migrate(store: &SqliteStore) -> Result<(), StoreError> {
        store.migrate(SCHEMA_NAMESPACE, MIGRATIONS)?;
        store
            .with_conn(|c| c.pragma_update(None, "synchronous", "FULL"))
            .map_err(|e| StoreError::Backend(e.to_string()))
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

    /// Read non-secret metadata for an id WITHOUT decrypting (plaintext columns).
    pub fn meta(&self, credential_id: &str) -> Result<RecordMeta, StoreOpError> {
        self.store
            .with_conn(|c| {
                c.query_row(
                    "SELECT record_version, key_id, state FROM credentials WHERE credential_id = ?1",
                    rusqlite::params![credential_id],
                    |row| {
                        let version: i64 = row.get(0)?;
                        let key_id_hex: String = row.get(1)?;
                        let state: String = row.get(2)?;
                        Ok((version, key_id_hex, state))
                    },
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })
            })
            .map_err(StoreOpError::from)?
            .map(|(version, key_id_hex, state)| RecordMeta {
                record_version: version as u64,
                key_id_hex,
                state: RecordState::from_str(&state),
            })
            .ok_or(StoreOpError::NotFound)
    }

    /// List every record's id + non-secret metadata, WITHOUT decrypting. Used by
    /// rotation scans and status.
    pub fn list_meta(&self) -> Result<Vec<(String, RecordMeta)>, StoreOpError> {
        self.store
            .with_conn(|c| {
                let mut stmt = c.prepare(
                    "SELECT credential_id, record_version, key_id, state FROM credentials \
                     ORDER BY credential_id",
                )?;
                let rows = stmt.query_map([], |row| {
                    let id: String = row.get(0)?;
                    let version: i64 = row.get(1)?;
                    let key_id_hex: String = row.get(2)?;
                    let state: String = row.get(3)?;
                    Ok((
                        id,
                        RecordMeta {
                            record_version: version as u64,
                            key_id_hex,
                            state: RecordState::from_str(&state),
                        },
                    ))
                })?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
            })
            .map_err(StoreOpError::from)
    }

    /// Create a record (CREATE-ONLY) with an explicit audit context: fails
    /// [`StoreOpError::AlreadyExists`] if the id is already present. The record is
    /// sealed at `record_version = 1`, the row is written through the epoch-fenced
    /// path, any dangling refresh intent is cleared, AND an audit entry is appended
    /// — all in ONE transaction, so the mutation and its audit record commit
    /// atomically (the audit chain accounts for the new version, tamper-evidently).
    pub fn create_audited(
        &self,
        credential_id: &str,
        record: &VaultRecord,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        let mut record = record.clone();
        record.record_version = 1;
        let blob = self.seal_record(credential_id, &record)?;
        let key_id_hex = self.key_id.to_hex();
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        let payload_hash_hex = hex32(&payload_hash(&record.payload));

        // Create-only via INSERT ... ON CONFLICT DO NOTHING inside the fenced
        // transaction: an existing id leaves zero rows changed (atomic, no separate
        // existence query, no error-string matching). Zero changed => AlreadyExists.
        let changed = self.fenced_write(|tx| {
            let n = tx.execute(
                "INSERT INTO credentials \
                 (credential_id, record_version, key_id, state, envelope, updated_at_ms) \
                 VALUES (?1, ?2, ?3, 'active', ?4, ?5) \
                 ON CONFLICT(credential_id) DO NOTHING",
                rusqlite::params![
                    credential_id,
                    record.record_version as i64,
                    key_id_hex,
                    blob,
                    now
                ],
            )?;
            // An admin write clears any dangling refresh intent for this id in the
            // SAME transaction: a fresh credential must never inherit a stale intent
            // from a prior id reuse (and on overwrite this is what stops a boot
            // reconciliation from undoing a legitimate re-login).
            if n > 0 {
                clear_intent_tx(tx, credential_id)?;
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: Some(payload_hash_hex),
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(n)
        })?;
        if changed == 0 {
            return Err(StoreOpError::AlreadyExists);
        }
        Ok(())
    }

    /// Create a record (CREATE-ONLY), auditing it as a vault-owned `Put`. Convenience
    /// wrapper over [`create_audited`] for callers (and tests) that do not need to
    /// specify the op/actor; production admin writes use `create_audited` with an
    /// admin context.
    pub fn create(&self, credential_id: &str, record: &VaultRecord) -> Result<(), StoreOpError> {
        self.create_audited(credential_id, record, AuditCtx::vault(AuditOp::Put))
    }

    /// Overwrite an existing record under a compare-and-set on its current payload
    /// hash, with an explicit audit context. Fails [`StoreOpError::NotFound`] if
    /// absent, [`StoreOpError::CasMismatch`] if `expected_payload_hash` does not
    /// match. On success the new record is sealed at `current_version + 1`, the
    /// dangling intent is cleared, and the audit entry is appended — all in ONE
    /// transaction.
    pub fn overwrite_cas_audited(
        &self,
        credential_id: &str,
        record: &VaultRecord,
        expected_payload_hash: &[u8; 32],
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        // Read + decrypt the current record to verify the CAS precondition. A
        // decrypt failure here quarantines the id (handled by `get`).
        let current = self.get(credential_id)?;
        if &payload_hash(&current.payload) != expected_payload_hash {
            return Err(StoreOpError::CasMismatch);
        }
        let next_version = current.record_version.saturating_add(1);
        let mut record = record.clone();
        record.record_version = next_version;
        let blob = self.seal_record(credential_id, &record)?;
        let key_id_hex = self.key_id.to_hex();
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        let payload_hash_hex = hex32(&payload_hash(&record.payload));

        // The version in the WHERE makes the UPDATE itself a compare-and-set on the
        // version we read, so a concurrent writer that already bumped it leaves zero
        // rows changed (no error-string matching). Zero changed => CasMismatch.
        let changed = self.fenced_write(|tx| {
            let n = tx.execute(
                "UPDATE credentials \
                 SET record_version = ?2, key_id = ?3, state = 'active', envelope = ?4, \
                     updated_at_ms = ?5 \
                 WHERE credential_id = ?1 AND record_version = ?6",
                rusqlite::params![
                    credential_id,
                    next_version as i64,
                    key_id_hex,
                    blob,
                    now,
                    current.record_version as i64
                ],
            )?;
            // Clear any dangling intent in the same txn (see `create`): an admin
            // overwrite with fresh valid tokens must clear the old intent, or boot
            // reconciliation's hash-mismatch check would later undo this re-login.
            if n > 0 {
                clear_intent_tx(tx, credential_id)?;
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: Some(payload_hash_hex),
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(n)
        })?;
        if changed == 0 {
            return Err(StoreOpError::CasMismatch);
        }
        Ok(())
    }

    /// Overwrite an existing record UNCONDITIONALLY (no CAS), re-sealing it at
    /// `current_version + 1` and resetting its state to `active`, with an explicit
    /// audit context. Fails [`StoreOpError::NotFound`] if the id is absent.
    ///
    /// Unlike [`overwrite_cas_audited`], this reads the current version via `meta`
    /// (plaintext columns, NO decrypt) rather than `get`, so it works even when the
    /// current record is `needs_reauth` or quarantined — which is exactly the
    /// re-import case: an operator imported a credential from the wrong source (its
    /// refresh token is dead → `needs_reauth`) and is replacing it with the correct
    /// one. The handles table is untouched, so existing handles keep resolving to this
    /// id (no re-mint). The version bump + state reset + intent clear + audit entry all
    /// commit in ONE fenced transaction.
    pub fn overwrite_unconditional_audited(
        &self,
        credential_id: &str,
        record: &VaultRecord,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        let key_id_hex = self.key_id.to_hex();
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        let payload_hash_hex = hex32(&payload_hash(&record.payload));

        // Read the current version, seal at version+1, and update — ALL inside the
        // one fenced transaction, gated on `WHERE record_version = <the version we
        // just read>`. On the single writer connection this is atomic: nothing can
        // move the version between the read and the guarded update, so the "+1" can
        // never alias a concurrent refresh's own +1 (the lost-update bug a
        // read-outside-the-txn version + unguarded update would allow). "State-
        // unconditional" (works on needs_reauth/quarantined via the plaintext
        // version read, no decrypt) is preserved; only lost-update tolerance is
        // removed. A CasMismatch here would mean the row vanished mid-txn (a
        // concurrent delete), which cannot happen under the single writer, so the
        // guard is belt-and-suspenders that also documents the invariant.
        let outcome = self.fenced_write(|tx| {
            let current_version: Option<i64> = tx
                .query_row(
                    "SELECT record_version FROM credentials WHERE credential_id = ?1",
                    rusqlite::params![credential_id],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(current_version) = current_version else {
                return Ok(None); // NotFound: signalled to the caller below.
            };
            let next_version = (current_version as u64).saturating_add(1);

            let mut sealed = record.clone();
            sealed.record_version = next_version;
            // seal_record is pure crypto (no DB), safe to call inside the txn.
            let blob = self
                .seal_record(credential_id, &sealed)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            let n = tx.execute(
                "UPDATE credentials \
                 SET record_version = ?2, key_id = ?3, state = 'active', envelope = ?4, \
                     updated_at_ms = ?5 \
                 WHERE credential_id = ?1 AND record_version = ?6",
                rusqlite::params![
                    credential_id,
                    next_version as i64,
                    key_id_hex,
                    blob,
                    now,
                    current_version
                ],
            )?;
            if n > 0 {
                clear_intent_tx(tx, credential_id)?;
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: Some(payload_hash_hex),
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(Some(n))
        })?;
        match outcome {
            None => Err(StoreOpError::NotFound),
            Some(0) => Err(StoreOpError::CasMismatch),
            Some(_) => Ok(()),
        }
    }

    /// Overwrite under CAS, auditing as a vault-owned `Overwrite`. Convenience
    /// wrapper for callers/tests that do not specify an audit context.
    pub fn overwrite_cas(
        &self,
        credential_id: &str,
        record: &VaultRecord,
        expected_payload_hash: &[u8; 32],
    ) -> Result<(), StoreOpError> {
        self.overwrite_cas_audited(
            credential_id,
            record,
            expected_payload_hash,
            AuditCtx::vault(AuditOp::Overwrite),
        )
    }

    /// Read and decrypt a record. Fails closed: a quarantined (`corrupt`) row is
    /// [`StoreOpError::Quarantined`]; a `needs_reauth` row is
    /// [`StoreOpError::NeedsReauth`]; a row that fails to decrypt or parse is
    /// QUARANTINED (its state flipped to `corrupt`) and returned as a typed error.
    /// Never panics, never returns plaintext on failure.
    pub fn get(&self, credential_id: &str) -> Result<VaultRecord, StoreOpError> {
        let row = self
            .store
            .with_conn(|c| {
                c.query_row(
                    "SELECT record_version, state, envelope FROM credentials \
                     WHERE credential_id = ?1",
                    rusqlite::params![credential_id],
                    |r| {
                        let version: i64 = r.get(0)?;
                        let state: String = r.get(1)?;
                        let blob: Vec<u8> = r.get(2)?;
                        Ok((version, state, blob))
                    },
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })
            })
            .map_err(StoreOpError::from)?;

        let (version, state, blob) = row.ok_or(StoreOpError::NotFound)?;
        match RecordState::from_str(&state) {
            RecordState::Corrupt => return Err(StoreOpError::Quarantined),
            RecordState::NeedsReauth => return Err(StoreOpError::NeedsReauth),
            RecordState::Active => {}
        }

        let binding = RecordBinding {
            credential_id,
            record_version: version as u64,
        };
        let plaintext = match envelope::open(&self.key, &blob, &binding) {
            Ok(pt) => pt,
            Err(e) => {
                // Per-record quarantine: a single undecryptable row is isolated so
                // the rest of the vault keeps serving. Best-effort state flip — a
                // failure to mark must not itself panic the read path.
                let _ = self.quarantine(credential_id);
                return Err(StoreOpError::Decrypt(e));
            }
        };
        match VaultRecord::decode(&plaintext) {
            Ok(record) => Ok(record),
            Err(e) => {
                let _ = self.quarantine(credential_id);
                Err(StoreOpError::Corrupt(e.to_string()))
            }
        }
    }

    /// Mark a record `needs_reauth` (authoritative revoke / reported auth failure)
    /// and clear any dangling refresh intent for it, with an explicit audit context —
    /// the state flip, the intent clear, and the audit entry all commit atomically.
    /// A no-op (Ok) if the id is absent.
    ///
    /// Clears the intent because an authoritative revoke supersedes any in-flight
    /// refresh: leaving a stale intent would let boot reconciliation reason about a
    /// credential the operator has already invalidated.
    pub fn invalidate_audited(
        &self,
        credential_id: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        self.set_state(credential_id, RecordState::NeedsReauth, true, Some(ctx))
    }

    /// Version-gated invalidate for a consumer-reported auth failure: mark the
    /// credential `needs_reauth` (and clear any dangling intent) ONLY if its current
    /// `record_version` still equals `expected_version` — the version the consumer was
    /// actually served. Returns `true` if it invalidated, `false` (a silent, successful
    /// no-op) if the version has since moved on.
    ///
    /// This closes a false-invalidation race: a consumer reports a 401 for the token it
    /// held at version N, but the vault has meanwhile refreshed to N+1 (a fresh, working
    /// token); the stale report must NOT kill the healthy N+1 credential. Because every
    /// durable mutation is serialized through the store's single writer connection, this
    /// CAS and a concurrent `commit_refresh` can never interleave: report-first flips
    /// state at version N and the refresh's `WHERE record_version = N` still overwrites it
    /// back to active N+1; refresh-first bumps to N+1 and this CAS matches 0 rows → no-op.
    /// Either ordering converges on the fresh token. It also neuters malicious
    /// invalidation: a consumer can only ever kill the exact version it was served.
    ///
    /// A no-op (Ok(false)) if the id is absent.
    pub fn invalidate_if_version_audited(
        &self,
        credential_id: &str,
        expected_version: u64,
        ctx: AuditCtx<'_>,
    ) -> Result<bool, StoreOpError> {
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        let changed = self
            .fenced_write(|tx| {
                let n = tx.execute(
                    "UPDATE credentials SET state = ?2, updated_at_ms = ?3 \
                 WHERE credential_id = ?1 AND record_version = ?4",
                    rusqlite::params![
                        credential_id,
                        RecordState::NeedsReauth.as_str(),
                        now,
                        expected_version as i64
                    ],
                )?;
                if n > 0 {
                    // Same version still current: this is an authoritative revoke, so clear
                    // any dangling intent and audit it, exactly like invalidate_audited.
                    clear_intent_tx(tx, credential_id)?;
                    append_audit_tx(
                        tx,
                        &audit_key,
                        &AuditRecord {
                            op: ctx.op,
                            credential_id: Some(credential_id.to_string()),
                            payload_hash: None,
                            actor: ctx.actor.to_string(),
                            alarm: ctx.alarm,
                        },
                    )?;
                }
                Ok(n)
            })
            .map_err(StoreOpError::from)?;
        Ok(changed > 0)
    }

    /// Invalidate, auditing as a vault-owned `Invalidate`. Convenience wrapper for
    /// callers/tests that do not specify an audit context.
    pub fn invalidate(&self, credential_id: &str) -> Result<(), StoreOpError> {
        self.invalidate_audited(credential_id, AuditCtx::vault(AuditOp::Invalidate))
    }

    /// The COMPOUND authoritative invalidate: mark `needs_reauth`, clear any
    /// dangling refresh intent, AND revoke every live handle for the credential —
    /// all in ONE fenced transaction, with both audit entries (`Invalidate` and,
    /// when any handles were live, `RevokeHandle`) inside it.
    ///
    /// This exists because invalidate-then-revoke as two calls is crash-partial: a
    /// crash between them leaves a dead credential still resolvable by handle. The
    /// offline CLI performs the same pair; the online admin surface additionally
    /// must not let a relay reorder or split the two halves, so the compound op is
    /// the only online shape. Returns the number of handles revoked.
    pub fn invalidate_and_revoke_all_audited(
        &self,
        credential_id: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<usize, StoreOpError> {
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            tx.execute(
                "UPDATE credentials SET state = ?2, updated_at_ms = ?3 \
                 WHERE credential_id = ?1",
                rusqlite::params![credential_id, RecordState::NeedsReauth.as_str(), now],
            )?;
            clear_intent_tx(tx, credential_id)?;
            let revoked = tx.execute(
                "UPDATE handles SET revoked = 1 \
                 WHERE credential_id = ?1 AND revoked = 0",
                rusqlite::params![credential_id],
            )?;
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: ctx.op,
                    credential_id: Some(credential_id.to_string()),
                    payload_hash: None,
                    actor: ctx.actor.to_string(),
                    alarm: ctx.alarm,
                },
            )?;
            if revoked > 0 {
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: AuditOp::RevokeHandle,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: None,
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(revoked)
        })
        .map_err(StoreOpError::from)
    }

    /// PERMANENTLY remove a credential: delete the row, its refresh intent, and its
    /// handle rows, appending a `Remove` audit entry — all in ONE fenced transaction.
    /// The audit chain keeps the credential's full history (append-only; removal is
    /// itself an entry), so this deletes serving state, never forensics. For retiring
    /// an account or cleaning up a mistaken id; a temporary stop is `logout`
    /// (invalidate + revoke, reversible). Returns [`StoreOpError::NotFound`] when the
    /// id has no row, so a typo'd remove is loud instead of a silent no-op.
    pub fn remove_audited(
        &self,
        credential_id: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        let audit_key = self.audit_key.clone();
        let removed = self.fenced_write(|tx| {
            let n = tx.execute(
                "DELETE FROM credentials WHERE credential_id = ?1",
                rusqlite::params![credential_id],
            )?;
            if n > 0 {
                clear_intent_tx(tx, credential_id)?;
                // Handle rows are deleted outright (not just revoked): the credential
                // is gone, so retaining hash rows would only grow an unusable table.
                // The mint/revoke history stays in the audit chain.
                tx.execute(
                    "DELETE FROM handles WHERE credential_id = ?1",
                    rusqlite::params![credential_id],
                )?;
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: None,
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(n)
        })?;
        if removed == 0 {
            return Err(StoreOpError::NotFound);
        }
        Ok(())
    }

    /// Quarantine a record (`corrupt`). Used by the read path on a decrypt/parse
    /// failure; idempotent. Does NOT clear a refresh intent or audit — quarantine is
    /// an internal integrity flip, not a recorded mutation, and a corrupt record's
    /// intent (if any) is for reconciliation to resolve, not for this path to discard.
    pub fn quarantine(&self, credential_id: &str) -> Result<(), StoreOpError> {
        self.set_state(credential_id, RecordState::Corrupt, false, None)
    }

    /// Mark a record `needs_reauth` but RETAIN its refresh intent. Used by
    /// reconciliation when a non-mutating validity check could not be run (transient
    /// network): the record fails closed now, but the surviving intent lets a later
    /// retry re-check and restore the credential without a forced re-login.
    pub fn mark_needs_reauth_retaining_intent(
        &self,
        credential_id: &str,
    ) -> Result<(), StoreOpError> {
        self.set_state(credential_id, RecordState::NeedsReauth, false, None)
    }

    fn set_state(
        &self,
        credential_id: &str,
        state: RecordState,
        clear_intent: bool,
        ctx: Option<AuditCtx<'_>>,
    ) -> Result<(), StoreOpError> {
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            let n = tx.execute(
                "UPDATE credentials SET state = ?2, updated_at_ms = ?3 \
                 WHERE credential_id = ?1",
                rusqlite::params![credential_id, state.as_str(), now],
            )?;
            if clear_intent {
                clear_intent_tx(tx, credential_id)?;
            }
            // Audit the state change only when it actually hit a row and a
            // context was supplied (quarantine/retain are internal, unaudited).
            if n > 0 {
                if let Some(ctx) = ctx {
                    append_audit_tx(
                        tx,
                        &audit_key,
                        &AuditRecord {
                            op: ctx.op,
                            credential_id: Some(credential_id.to_string()),
                            payload_hash: None,
                            actor: ctx.actor.to_string(),
                            alarm: ctx.alarm,
                        },
                    )?;
                }
            }
            Ok(())
        })
        .map_err(StoreOpError::from)
    }

    // ---- refresh intent log (crash-safe rotation) -----------------------

    /// Durably open a refresh intent (txn1 of the refresh state machine): the
    /// fsynced marker written BEFORE the provider's rotating endpoint is called.
    ///
    /// Goes through the fenced path so a superseded writer cannot open an intent,
    /// and (with `synchronous=FULL`) the row is on disk before this returns —
    /// guaranteeing a crash during the subsequent network call leaves a recoverable
    /// intent. `record_version` is the version being refreshed from (the commit's
    /// CAS guard); `old_refresh_hash` is [`refresh_token_hash`] of the current
    /// refresh token. Replaces any existing intent for the id (single-flight means
    /// there is at most one, but a re-open after a transient failure is idempotent).
    pub fn open_intent(
        &self,
        credential_id: &str,
        record_version: u64,
        old_refresh_hash: &str,
    ) -> Result<(), StoreOpError> {
        let epoch = self.store.epoch();
        let now = now_ms();
        self.fenced_write(|tx| {
            tx.execute(
                "INSERT INTO refresh_intent \
                 (credential_id, record_version, old_refresh_hash, lease_epoch, started_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(credential_id) DO UPDATE SET \
                   record_version = excluded.record_version, \
                   old_refresh_hash = excluded.old_refresh_hash, \
                   lease_epoch = excluded.lease_epoch, \
                   started_at_ms = excluded.started_at_ms",
                rusqlite::params![
                    credential_id,
                    record_version as i64,
                    old_refresh_hash,
                    epoch as i64,
                    now
                ],
            )?;
            Ok(())
        })
        .map_err(StoreOpError::from)
    }

    /// Commit a completed refresh (txn2): seal the new record at
    /// `expected_version + 1`, write it, and clear the intent — in ONE fenced,
    /// fsynced transaction, so the new tokens become visible AND the intent clears
    /// atomically, or neither does.
    ///
    /// Fails [`StoreOpError::CasMismatch`] if the stored version is no longer
    /// `expected_version` (a concurrent write moved it), and
    /// [`StoreOpError::Fenced`] if a newer instance took the lease mid-commit (the
    /// lease-handover race) — in which case NOTHING is applied and the caller must
    /// discard the staged tokens and not retry (reconciliation on the new owner
    /// resolves the still-dangling intent). The new `record_version` is returned.
    pub fn commit_refresh(
        &self,
        credential_id: &str,
        expected_version: u64,
        new_record: &VaultRecord,
    ) -> Result<u64, StoreOpError> {
        let next_version = expected_version.saturating_add(1);
        let mut new_record = new_record.clone();
        new_record.record_version = next_version;
        let blob = self.seal_record(credential_id, &new_record)?;
        let key_id_hex = self.key_id.to_hex();
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        let payload_hash_hex = hex32(&payload_hash(&new_record.payload));

        let changed = self.fenced_write(|tx| {
            let n = tx.execute(
                "UPDATE credentials \
                 SET record_version = ?2, key_id = ?3, state = 'active', envelope = ?4, \
                     updated_at_ms = ?5 \
                 WHERE credential_id = ?1 AND record_version = ?6",
                rusqlite::params![
                    credential_id,
                    next_version as i64,
                    key_id_hex,
                    blob,
                    now,
                    expected_version as i64
                ],
            )?;
            // The new tokens, the intent-clear, and the audit entry commit together
            // or not at all — so the refresh's version bump is accounted for in the
            // chain (a vault-owned RefreshCommit).
            if n > 0 {
                clear_intent_tx(tx, credential_id)?;
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: AuditOp::RefreshCommit,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: Some(payload_hash_hex),
                        actor: "vault".to_string(),
                        alarm: None,
                    },
                )?;
            }
            Ok(n)
        })?;
        if changed == 0 {
            return Err(StoreOpError::CasMismatch);
        }
        Ok(next_version)
    }

    /// Read the dangling intent for one credential, if any (reconciliation + the
    /// boot gate's never-serve-dangling check).
    pub fn read_intent(&self, credential_id: &str) -> Result<Option<RefreshIntent>, StoreOpError> {
        self.store
            .with_conn(|c| {
                c.query_row(
                    "SELECT credential_id, record_version, old_refresh_hash, lease_epoch, \
                            started_at_ms FROM refresh_intent WHERE credential_id = ?1",
                    rusqlite::params![credential_id],
                    row_to_intent,
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })
            })
            .map_err(StoreOpError::from)
    }

    /// List every dangling intent (the boot reconciliation scan).
    pub fn list_intents(&self) -> Result<Vec<RefreshIntent>, StoreOpError> {
        self.store
            .with_conn(|c| {
                let mut stmt = c.prepare(
                    "SELECT credential_id, record_version, old_refresh_hash, lease_epoch, \
                            started_at_ms FROM refresh_intent ORDER BY credential_id",
                )?;
                let rows = stmt.query_map([], row_to_intent)?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
            })
            .map_err(StoreOpError::from)
    }

    /// Clear a dangling intent (reconciliation resolved it). Fenced.
    pub fn clear_intent(&self, credential_id: &str) -> Result<(), StoreOpError> {
        self.fenced_write(|tx| clear_intent_tx(tx, credential_id).map(|_| ()))
            .map_err(StoreOpError::from)
    }

    /// The current refresh token hash stored for a credential, read by decrypting
    /// the record. Used by reconciliation to compare against an intent's
    /// `old_refresh_hash`. `None` for a non-OAuth or absent record.
    pub fn stored_refresh_hash(&self, credential_id: &str) -> Result<Option<String>, StoreOpError> {
        match self.get(credential_id) {
            Ok(record) => Ok(record
                .oauth
                .as_ref()
                .map(|o| refresh_token_hash(&o.refresh_token))),
            Err(StoreOpError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    // ---- capability handles ---------------------------------------------

    /// Resolve a raw capability handle to its credential id. Hashes the presented
    /// handle and looks up a NON-revoked row; returns [`StoreOpError::NotFound`]
    /// when the handle is unknown or revoked (the read surface maps that to a
    /// uniform not-found so a probe cannot tell "wrong handle" from "revoked").
    pub fn resolve_handle(&self, raw_handle: &str) -> Result<String, StoreOpError> {
        let h = handle_hash(raw_handle);
        self.store
            .with_conn(|c| {
                c.query_row(
                    "SELECT credential_id FROM handles \
                     WHERE handle_hash = ?1 AND revoked = 0",
                    rusqlite::params![h],
                    |r| r.get::<_, String>(0),
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })
            })
            .map_err(StoreOpError::from)?
            .ok_or(StoreOpError::NotFound)
    }

    /// Record a freshly minted handle for a credential, storing only its hash, AND
    /// append a `MintHandle` audit entry — both in ONE fenced transaction, so a handle
    /// can never be minted without a tamper-evident audit record (the same atomicity
    /// every other durable mutation uses). Mint is admin-only; the caller's audit
    /// context records WHICH admin origin performed it (offline CLI vs the module's
    /// authenticated route admin surface) so the trail is truthful provenance.
    pub fn put_handle_hash(
        &self,
        handle_hash_hex: &str,
        credential_id: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            tx.execute(
                "INSERT INTO handles (handle_hash, credential_id, created_at_ms, revoked) \
                 VALUES (?1, ?2, ?3, 0)",
                rusqlite::params![handle_hash_hex, credential_id, now],
            )?;
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: AuditOp::MintHandle,
                    credential_id: Some(credential_id.to_string()),
                    payload_hash: None,
                    actor: ctx.actor.to_string(),
                    alarm: ctx.alarm,
                },
            )?;
            Ok(())
        })
        .map_err(StoreOpError::from)
    }

    /// Revoke a single handle by its raw value (idempotent — revoking an unknown or
    /// already-revoked handle is a no-op success). The update AND a `RevokeHandle`
    /// audit entry commit in ONE fenced transaction, so a revocation — the most
    /// security-relevant handle action — is always tamper-evidently recorded. The
    /// audit entry is keyed by the handle hash (the raw handle is never stored), not a
    /// credential id, since revoke-by-handle does not name the credential.
    pub fn revoke_handle(&self, raw_handle: &str, ctx: AuditCtx<'_>) -> Result<(), StoreOpError> {
        let h = handle_hash(raw_handle);
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            tx.execute(
                "UPDATE handles SET revoked = 1 WHERE handle_hash = ?1",
                rusqlite::params![h],
            )?;
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: AuditOp::RevokeHandle,
                    credential_id: None,
                    payload_hash: Some(h.clone()),
                    actor: ctx.actor.to_string(),
                    alarm: ctx.alarm,
                },
            )?;
            Ok(())
        })
        .map_err(StoreOpError::from)
    }

    /// Revoke ALL handles for a credential (e.g. on invalidate / suspected leak).
    /// Returns the number revoked. The update AND a `RevokeHandle` audit entry (naming
    /// the credential) commit in ONE fenced transaction.
    pub fn revoke_all_handles(
        &self,
        credential_id: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<usize, StoreOpError> {
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            let n = tx.execute(
                "UPDATE handles SET revoked = 1 \
                 WHERE credential_id = ?1 AND revoked = 0",
                rusqlite::params![credential_id],
            )?;
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: AuditOp::RevokeHandle,
                    credential_id: Some(credential_id.to_string()),
                    payload_hash: None,
                    actor: ctx.actor.to_string(),
                    alarm: ctx.alarm,
                },
            )?;
            Ok(n)
        })
        .map_err(StoreOpError::from)
    }

    // ---- audit chain ----------------------------------------------------

    /// Append one entry to the tamper-evident audit chain, computing its HMAC over
    /// the previous entry's mac, in a fenced write. Standalone variant; mutation
    /// paths that must audit atomically use [`append_audit_tx`] inside their own
    /// transaction.
    pub fn append_audit(&self, record: &AuditRecord) -> Result<AuditEntry, StoreOpError> {
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| append_audit_tx(tx, &audit_key, record))
            .map_err(StoreOpError::from)
    }

    /// Read the audit chain (oldest first), capped at `limit` most-recent entries
    /// when `limit` is `Some`. Used by status/monitoring to surface alarms and by
    /// the integrity check.
    pub fn read_audit(&self, limit: Option<usize>) -> Result<Vec<AuditEntry>, StoreOpError> {
        self.store
            .with_conn(|c| {
                // Fetch newest-first with the cap, then reverse to chain order.
                let cap: i64 = limit.map(|n| n as i64).unwrap_or(-1); // -1 = no limit
                let mut stmt = c.prepare(
                    "SELECT seq, ts_ms, op, credential_id, payload_hash, actor, alarm, \
                            alarm_reason, prev_mac, entry_mac \
                     FROM audit_log ORDER BY seq DESC LIMIT ?1",
                )?;
                let rows = stmt.query_map(rusqlite::params![cap], row_to_audit)?;
                let mut v = rows.collect::<rusqlite::Result<Vec<_>>>()?;
                v.reverse();
                Ok(v)
            })
            .map_err(StoreOpError::from)
    }

    /// Verify the full audit chain against the master-key-derived audit key.
    /// Returns the seq of the first broken entry, or `None` if it verifies.
    pub fn verify_audit_chain(&self) -> Result<Option<i64>, StoreOpError> {
        let entries = self.read_audit(None)?;
        Ok(audit::verify_chain(&self.audit_key, &entries))
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
                    // Re-seal under the new key (same id + version => same AAD).
                    let new_blob = envelope::seal(&new_key, &plaintext, &binding)
                        .map_err(|_| rusqlite_err("re-seal under new key failed"))?;
                    tx.execute(
                        "UPDATE credentials SET envelope = ?2, key_id = ?3 \
                     WHERE credential_id = ?1",
                        rusqlite::params![id, new_blob, new_key_id_hex],
                    )?;
                }

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
    fn seal_record(
        &self,
        credential_id: &str,
        record: &VaultRecord,
    ) -> Result<Vec<u8>, StoreOpError> {
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

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Delete a credential's refresh intent within an open transaction. Returns the
/// number of rows removed (0 if there was no intent). Used both standalone and as
/// the intent-clearing step folded into admin writes and the refresh commit.
fn clear_intent_tx(tx: &rusqlite::Transaction, credential_id: &str) -> rusqlite::Result<usize> {
    tx.execute(
        "DELETE FROM refresh_intent WHERE credential_id = ?1",
        rusqlite::params![credential_id],
    )
}

/// Load the vault's sealed audit key, or create it on a brand-new vault.
///
/// The audit key lives in `vault_secrets` under [`AUDIT_KEY_SECRET_NAME`], sealed
/// with the master key (AAD bound to that pseudo-id + version 0). On an existing
/// row: decrypt it (a wrong master key fails closed here). On no row: only create a
/// fresh CSPRNG key if the vault is genuinely EMPTY (no credentials, no audit
/// entries); otherwise the row's absence is corruption and we fail closed rather
/// than regenerate (which would orphan every existing audit entry).
fn load_or_create_audit_key(
    store: &SqliteStore,
    key: &MasterKey,
) -> Result<Zeroizing<[u8; 32]>, StoreOpError> {
    let binding = RecordBinding {
        credential_id: AUDIT_KEY_SECRET_NAME,
        record_version: AUDIT_KEY_RECORD_VERSION,
    };

    // Read the existing sealed audit-key envelope, if any.
    let existing: Option<Vec<u8>> = store
        .with_conn(|c| {
            c.query_row(
                "SELECT envelope FROM vault_secrets WHERE name = ?1",
                rusqlite::params![AUDIT_KEY_SECRET_NAME],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })
        })
        .map_err(StoreOpError::from)?;

    if let Some(blob) = existing {
        // Decrypt with the master key — fail-closed on a wrong key (KeyMismatch) or
        // tampering, never a panic.
        let plaintext = envelope::open(key, &blob, &binding).map_err(StoreOpError::Decrypt)?;
        let bytes: [u8; 32] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| StoreOpError::CorruptVault("audit key is not 32 bytes".to_string()))?;
        return Ok(Zeroizing::new(bytes));
    }

    // No audit-key row. Only a brand-new (empty) vault may create one.
    let non_empty: bool = store
        .with_conn(|c| {
            c.query_row(
                "SELECT EXISTS(SELECT 1 FROM credentials) OR EXISTS(SELECT 1 FROM audit_log)",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v != 0)
        })
        .map_err(StoreOpError::from)?;
    if non_empty {
        return Err(StoreOpError::CorruptVault(
            "audit key missing on a non-empty vault (refusing to regenerate)".to_string(),
        ));
    }

    // Brand-new vault: mint a fresh audit key and seal it under the master key.
    let audit_key = Zeroizing::new(
        crate::audit::generate_audit_key()
            .map_err(|_| StoreOpError::Store("csprng".to_string()))?,
    );
    let blob = envelope::seal(key, &*audit_key, &binding).map_err(StoreOpError::Decrypt)?;
    let key_id_hex = key.key_id().to_hex();
    store
        .with_conn_fenced(|tx| {
            tx.execute(
                "INSERT INTO vault_secrets (name, key_id, envelope) VALUES (?1, ?2, ?3)",
                rusqlite::params![AUDIT_KEY_SECRET_NAME, key_id_hex, blob],
            )?;
            Ok(())
        })
        .map_err(StoreOpError::from)?;
    Ok(audit_key)
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

/// Hex SHA-256 of a raw capability handle — the only form of a handle the store
/// persists (a database leak yields no usable handle).
pub fn handle_hash(raw_handle: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"cortexkit-credentials/handle/v1");
    h.update(raw_handle.as_bytes());
    let digest = h.finalize();
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub(crate) fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3F) as usize] as char);
        }
    }
    out
}

pub struct MintedHandle {
    pub raw: String,
    pub hash: String,
}

/// Mint a fresh capability handle: 256 CSPRNG bits as a `ckh_`-prefixed base64url
/// string. The raw value is returned once; only its hash is ever persisted.
pub fn mint_handle() -> Result<MintedHandle, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)?;
    let value = format!("ckh_{}", base64url(&bytes));
    let hash = handle_hash(&value);
    Ok(MintedHandle { raw: value, hash })
}

/// Append an audit entry within an open transaction: read the current tip mac,
/// compute this entry's mac over it, insert it. Used both standalone and folded
/// into a mutation's own transaction so the audit entry and the mutation commit
/// together. The single-writer lease guarantees no concurrent appender, so reading
/// the tip and inserting the next seq is race-free.
pub(crate) fn append_audit_tx(
    tx: &rusqlite::Transaction,
    audit_key: &[u8; 32],
    record: &AuditRecord,
) -> rusqlite::Result<AuditEntry> {
    // An EMPTY audit table is the only reason to start from genesis (QueryReturnedNoRows
    // on the tip read). ANY OTHER query error (a broken/locked/damaged audit_log) must
    // propagate and fail the whole mutation's transaction — silently substituting genesis
    // would let a mutation commit against an unreadable chain, forking it. The
    // COALESCE(MAX(seq),0)+1 query returns a row even on an empty table, so it never hits
    // NoRows; only a real error surfaces there, and that too must propagate.
    let prev_mac: String = match tx.query_row(
        "SELECT entry_mac FROM audit_log ORDER BY seq DESC LIMIT 1",
        [],
        |r| r.get::<_, String>(0),
    ) {
        Ok(mac) => mac,
        Err(rusqlite::Error::QueryReturnedNoRows) => audit::GENESIS_MAC.to_string(),
        Err(e) => return Err(e),
    };

    let next_seq: i64 =
        tx.query_row("SELECT COALESCE(MAX(seq), 0) + 1 FROM audit_log", [], |r| {
            r.get(0)
        })?;

    let ts_ms = now_ms();
    let op = record.op.as_str();
    let alarm = record.alarm.is_some();
    let alarm_reason = record.alarm.map(AlarmReason::as_str);
    let entry_mac = audit::compute_entry_mac(
        audit_key,
        &prev_mac,
        &audit::MacFields {
            seq: next_seq,
            ts_ms,
            op,
            credential_id: record.credential_id.as_deref(),
            payload_hash: record.payload_hash.as_deref(),
            actor: &record.actor,
            alarm,
            alarm_reason,
        },
    );

    tx.execute(
        "INSERT INTO audit_log \
         (seq, ts_ms, op, credential_id, payload_hash, actor, alarm, alarm_reason, prev_mac, entry_mac) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        rusqlite::params![
            next_seq,
            ts_ms,
            op,
            record.credential_id,
            record.payload_hash,
            record.actor,
            alarm as i64,
            alarm_reason,
            prev_mac,
            entry_mac,
        ],
    )?;

    Ok(AuditEntry {
        seq: next_seq,
        ts_ms,
        op: op.to_string(),
        credential_id: record.credential_id.clone(),
        payload_hash: record.payload_hash.clone(),
        actor: record.actor.clone(),
        alarm,
        alarm_reason: alarm_reason.map(String::from),
        prev_mac,
        entry_mac,
    })
}

fn row_to_audit(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEntry> {
    Ok(AuditEntry {
        seq: row.get(0)?,
        ts_ms: row.get(1)?,
        op: row.get(2)?,
        credential_id: row.get(3)?,
        payload_hash: row.get(4)?,
        actor: row.get(5)?,
        alarm: row.get::<_, i64>(6)? != 0,
        alarm_reason: row.get(7)?,
        prev_mac: row.get(8)?,
        entry_mac: row.get(9)?,
    })
}

/// Build a [`RefreshIntent`] from a row of the standard intent column projection.
fn row_to_intent(row: &rusqlite::Row<'_>) -> rusqlite::Result<RefreshIntent> {
    Ok(RefreshIntent {
        credential_id: row.get(0)?,
        record_version: row.get::<_, i64>(1)? as u64,
        old_refresh_hash: row.get(2)?,
        lease_epoch: row.get::<_, i64>(3)? as u64,
        started_at_ms: row.get(4)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::MASTER_KEY_LEN;
    use crate::oauth::OAuthCredential;
    use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};

    fn tmp_store(seed: u8) -> (std::path::PathBuf, EncryptedStore) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "ck-cred-store-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let db = root.join("store.db");
        let descriptor = StorageDescriptor {
            module_id: "cortexkit-credentials".into(),
            storage_namespace: "vault".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: db.to_string_lossy().into_owned(),
            },
        };
        let store = open_sqlite(&descriptor).expect("open");
        EncryptedStore::migrate(&store).expect("migrate");
        let key = MasterKey::from_bytes([seed; MASTER_KEY_LEN]);
        (root, EncryptedStore::open(store, key).expect("open vault"))
    }

    fn oauth_record() -> VaultRecord {
        VaultRecord::new_oauth(
            "opencode",
            "anthropic",
            OAuthCredential {
                access_token: "access".into(),
                refresh_token: "refresh".into(),
                expires_at_ms: Some(9_999),
                token_url: "https://t.test/token".into(),
                client_id: Some("c".into()),
                scopes: vec![],
            },
            b"payload-bytes".to_vec(),
        )
    }

    #[test]
    fn create_then_get_round_trips() {
        let (root, store) = tmp_store(1);
        store
            .create("opencode:anthropic", &oauth_record())
            .expect("create");
        let got = store.get("opencode:anthropic").expect("get");
        assert_eq!(got.payload, b"payload-bytes");
        assert_eq!(got.record_version, 1);
        assert_eq!(got.oauth.unwrap().access_token, "access");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn create_only_rejects_duplicate() {
        let (root, store) = tmp_store(2);
        store.create("id", &oauth_record()).expect("first create");
        match store.create("id", &oauth_record()) {
            Err(StoreOpError::AlreadyExists) => {}
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `remove_audited` permanently deletes the row + intent + handle rows in one
    /// fenced transaction, appends a `remove` audit entry, and frees the id for a
    /// future create. A missing id is a loud NotFound, and removal must not disturb
    /// other credentials.
    #[test]
    fn remove_deletes_row_handles_and_intent_and_frees_the_id() {
        let (root, store) = tmp_store(2);
        store.create("keep", &oauth_record()).expect("create keep");
        store.create("gone", &oauth_record()).expect("create gone");
        store
            .put_handle_hash("deadbeef", "gone", AuditCtx::vault(AuditOp::MintHandle))
            .expect("mint handle");
        store.open_intent("gone", 1, "rhash").expect("open intent");

        // Unknown id: loud NotFound, nothing audited for it.
        match store.remove_audited("nope", AuditCtx::vault(AuditOp::Remove)) {
            Err(StoreOpError::NotFound) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }

        store
            .remove_audited("gone", AuditCtx::vault(AuditOp::Remove))
            .expect("remove");

        // Row gone, intent gone, handle unresolvable; sibling untouched.
        assert!(matches!(store.meta("gone"), Err(StoreOpError::NotFound)));
        assert!(store.read_intent("gone").expect("read intent").is_none());
        assert!(store.meta("keep").is_ok());
        // The audit chain records the removal and still verifies end-to-end.
        let entries = store.read_audit(None).expect("read audit");
        let last = entries.last().expect("has entries");
        assert_eq!(last.op, "remove");
        assert_eq!(last.credential_id.as_deref(), Some("gone"));
        store
            .verify_audit_chain()
            .expect("chain verifies after remove");
        // The id is free for a NEW credential (fresh v1 chain).
        store.create("gone", &oauth_record()).expect("recreate");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unconditional_overwrite_replaces_needs_reauth_record_and_keeps_handle() {
        let (root, store) = tmp_store(20);
        // A credential imported from the wrong source whose refresh token is dead:
        // mark it needs_reauth (as a failed refresh would), and mint a handle for it.
        store.create("opencode:google", &oauth_record()).unwrap();
        let h = mint_handle().unwrap();
        store
            .put_handle_hash(
                &h.hash,
                "opencode:google",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .unwrap();
        store.invalidate("opencode:google").unwrap();
        // A CAS overwrite cannot even read it (get on a needs_reauth row fails closed).
        assert!(matches!(
            store.get("opencode:google"),
            Err(StoreOpError::NeedsReauth)
        ));
        // The unconditional overwrite (the --replace path) replaces it regardless of
        // state, resets it to active, and is immediately gettable again.
        store
            .overwrite_unconditional_audited(
                "opencode:google",
                &oauth_record(),
                AuditCtx::admin(AuditOp::Import),
            )
            .unwrap();
        let rec = store.get("opencode:google").expect("active after replace");
        assert!(rec.record_version >= 2, "version bumped past the original");
        // The pre-existing handle STILL resolves to the same id — no re-mint needed.
        assert_eq!(
            store.resolve_handle(&h.raw).unwrap(),
            "opencode:google",
            "handle survives the replace"
        );
        // Replacing an ABSENT id is NotFound (not a silent create).
        assert!(matches!(
            store.overwrite_unconditional_audited(
                "nope",
                &oauth_record(),
                AuditCtx::admin(AuditOp::Import)
            ),
            Err(StoreOpError::NotFound)
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn get_missing_is_not_found() {
        let (root, store) = tmp_store(3);
        match store.get("absent") {
            Err(StoreOpError::NotFound) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn overwrite_cas_matches_and_bumps_version() {
        let (root, store) = tmp_store(4);
        store.create("id", &oauth_record()).expect("create");
        let cur = store.get("id").expect("get");
        let expect = payload_hash(&cur.payload);
        let mut next = oauth_record();
        next.payload = b"new-payload".to_vec();
        store.overwrite_cas("id", &next, &expect).expect("cas ok");
        let got = store.get("id").expect("get after cas");
        assert_eq!(got.payload, b"new-payload");
        assert_eq!(got.record_version, 2, "version bumped on overwrite");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn overwrite_cas_mismatch_rejected() {
        let (root, store) = tmp_store(5);
        store.create("id", &oauth_record()).expect("create");
        let wrong = payload_hash(b"not the current payload");
        match store.overwrite_cas("id", &oauth_record(), &wrong) {
            Err(StoreOpError::CasMismatch) => {}
            other => panic!("expected CasMismatch, got {other:?}"),
        }
        // The record is unchanged after a rejected CAS.
        assert_eq!(store.get("id").unwrap().record_version, 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn invalidate_marks_needs_reauth() {
        let (root, store) = tmp_store(6);
        store.create("id", &oauth_record()).expect("create");
        store.invalidate("id").expect("invalidate");
        match store.get("id") {
            Err(StoreOpError::NeedsReauth) => {}
            other => panic!("expected NeedsReauth, got {other:?}"),
        }
        assert_eq!(store.meta("id").unwrap().state, RecordState::NeedsReauth);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn corrupt_envelope_quarantines_only_that_record() {
        let (root, store) = tmp_store(7);
        store.create("good", &oauth_record()).expect("create good");
        store.create("bad", &oauth_record()).expect("create bad");
        // Corrupt the 'bad' row's ciphertext directly (simulate at-rest damage).
        store
            .store
            .with_conn(|c| {
                c.execute(
                    "UPDATE credentials SET envelope = X'00010203' WHERE credential_id = 'bad'",
                    [],
                )
            })
            .expect("corrupt bad");
        // 'bad' fails closed and is quarantined; 'good' still serves.
        match store.get("bad") {
            Err(StoreOpError::Decrypt(_)) => {}
            other => panic!("expected Decrypt, got {other:?}"),
        }
        assert_eq!(
            store.meta("bad").unwrap().state,
            RecordState::Corrupt,
            "bad row quarantined"
        );
        // A second get on the now-quarantined row is a clean Quarantined error.
        match store.get("bad") {
            Err(StoreOpError::Quarantined) => {}
            other => panic!("expected Quarantined on re-get, got {other:?}"),
        }
        assert_eq!(
            store.get("good").unwrap().payload,
            b"payload-bytes",
            "good still serves"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn wrong_key_fails_closed_at_open() {
        // A vault sealed under one key, then OPENED with a DIFFERENT key: the wrong
        // key fails to decrypt the sealed audit key, so open() itself fails closed
        // (KeyMismatch) — the vault never opens under the wrong key, and nothing
        // panics. This is stronger than the old per-record check: a wrong key is
        // rejected up front, before any credential is touched.
        let (root, store) = tmp_store(8);
        store.create("id", &oauth_record()).expect("create");
        let db_path = root.join("store.db");

        // Release the first store's single-writer lease before re-opening, then
        // re-open the same database under a different master key.
        drop(store);
        let descriptor = StorageDescriptor {
            module_id: "cortexkit-credentials".into(),
            storage_namespace: "vault".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: db_path.to_string_lossy().into_owned(),
            },
        };
        let reopened = open_sqlite(&descriptor).expect("reopen");
        let result = EncryptedStore::open(reopened, MasterKey::from_bytes([0xEE; MASTER_KEY_LEN]));
        match result {
            Err(StoreOpError::Decrypt(EnvelopeError::KeyMismatch { .. })) => {}
            Err(other) => panic!("expected KeyMismatch at open under wrong key, got {other:?}"),
            Ok(_) => panic!("expected open to fail closed under the wrong key"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn list_meta_reports_without_decrypt() {
        let (root, store) = tmp_store(9);
        store.create("a", &oauth_record()).expect("a");
        store.create("b", &oauth_record()).expect("b");
        store.invalidate("b").expect("invalidate b");
        let metas = store.list_meta().expect("list");
        assert_eq!(metas.len(), 2);
        let by_id: std::collections::HashMap<_, _> = metas.into_iter().collect();
        assert_eq!(by_id["a"].state, RecordState::Active);
        assert_eq!(by_id["b"].state, RecordState::NeedsReauth);
        assert_eq!(by_id["a"].key_id_hex, store.key_id().to_hex());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn handle_mint_resolve_revoke() {
        let (root, store) = tmp_store(10);
        store.create("opencode:anthropic", &oauth_record()).unwrap();
        let h = mint_handle().expect("mint");
        assert!(h.raw.starts_with("ckh_"));
        assert_eq!(h.hash, handle_hash(&h.raw));
        store
            .put_handle_hash(
                &h.hash,
                "opencode:anthropic",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .unwrap();
        // Resolve maps the raw handle to its credential id.
        assert_eq!(store.resolve_handle(&h.raw).unwrap(), "opencode:anthropic");
        // Revoke makes it resolve to NotFound (uniform with an unknown handle).
        store
            .revoke_handle(&h.raw, AuditCtx::admin(AuditOp::RevokeHandle))
            .unwrap();
        assert!(matches!(
            store.resolve_handle(&h.raw),
            Err(StoreOpError::NotFound)
        ));
        // An unknown handle is also NotFound (no distinction leaked).
        assert!(matches!(
            store.resolve_handle("ckh_bogus"),
            Err(StoreOpError::NotFound)
        ));
        // The mint and the revoke are BOTH recorded in the tamper-evident audit chain
        // (atomically, in their own fenced txns), and the chain still verifies.
        let entries = store.read_audit(None).unwrap();
        let ops: Vec<&str> = entries.iter().map(|e| e.op.as_str()).collect();
        assert!(ops.contains(&"mint_handle"), "mint audited: {ops:?}");
        assert!(ops.contains(&"revoke_handle"), "revoke audited: {ops:?}");
        assert_eq!(
            store.verify_audit_chain().unwrap(),
            None,
            "chain intact after mint+revoke"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn revoke_all_handles_for_credential() {
        let (root, store) = tmp_store(11);
        store.create("id", &oauth_record()).unwrap();
        let h1 = mint_handle().unwrap();
        let h2 = mint_handle().unwrap();
        store
            .put_handle_hash(&h1.hash, "id", AuditCtx::admin(AuditOp::MintHandle))
            .unwrap();
        store
            .put_handle_hash(&h2.hash, "id", AuditCtx::admin(AuditOp::MintHandle))
            .unwrap();
        let n = store
            .revoke_all_handles("id", AuditCtx::admin(AuditOp::RevokeHandle))
            .unwrap();
        assert_eq!(n, 2, "both handles revoked");
        assert!(matches!(
            store.resolve_handle(&h1.raw),
            Err(StoreOpError::NotFound)
        ));
        assert!(matches!(
            store.resolve_handle(&h2.raw),
            Err(StoreOpError::NotFound)
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn audit_chain_appends_and_verifies() {
        let (root, store) = tmp_store(12);
        let e1 = store
            .append_audit(&AuditRecord {
                op: crate::audit::AuditOp::Put,
                credential_id: Some("id".into()),
                payload_hash: Some("abcd".into()),
                actor: "offline-cli".into(),
                alarm: None,
            })
            .expect("append 1");
        assert_eq!(e1.seq, 1);
        assert_eq!(e1.prev_mac, crate::audit::GENESIS_MAC);
        let e2 = store
            .append_audit(&AuditRecord {
                op: crate::audit::AuditOp::Overwrite,
                credential_id: Some("id".into()),
                payload_hash: Some("ef01".into()),
                actor: "offline-cli".into(),
                alarm: Some(AlarmReason::OverwriteWithoutCas),
            })
            .expect("append 2");
        assert_eq!(e2.seq, 2);
        assert_eq!(e2.prev_mac, e1.entry_mac, "chain links");
        assert!(e2.alarm);
        // The full chain verifies under the store's master-key-derived audit key.
        assert_eq!(store.verify_audit_chain().unwrap(), None);
        // read_audit returns chain order, oldest first.
        let all = store.read_audit(None).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].seq, 1);
        assert_eq!(all[1].seq, 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rotate_master_key_rewraps_and_chain_stays_verifiable() {
        let (root, mut store) = tmp_store(20);
        store.create("a", &oauth_record()).expect("create a");
        store.create("b", &oauth_record()).expect("create b");
        // The audit chain has two put entries; capture its length.
        let before = store.read_audit(None).unwrap().len();
        assert!(store.verify_audit_chain().unwrap().is_none());

        // Rotate to a new master key.
        let new_key = MasterKey::from_bytes([0x77; MASTER_KEY_LEN]);
        let new_key_id = new_key.key_id();
        store.rotate_master_key(new_key).expect("rotate");

        // Records are still readable (re-wrapped under the new key), unchanged plaintext.
        assert_eq!(store.get("a").unwrap().payload, b"payload-bytes");
        assert_eq!(store.get("b").unwrap().payload, b"payload-bytes");
        // The key_id columns were swapped to the new fingerprint.
        assert_eq!(store.meta("a").unwrap().key_id_hex, new_key_id.to_hex());
        // The chain is STILL one continuously-verifiable sequence (stable audit key)
        // and grew by exactly one RotateMasterKey entry.
        assert_eq!(
            store.verify_audit_chain().unwrap(),
            None,
            "chain spans rotation"
        );
        let after = store.read_audit(None).unwrap();
        assert_eq!(after.len(), before + 1);
        assert_eq!(after.last().unwrap().op, "rotate_master_key");
        assert!(
            after.last().unwrap().credential_id.is_none(),
            "vault-global entry"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rotated_vault_reopens_only_under_new_key() {
        let (root, mut store) = tmp_store(21);
        store.create("a", &oauth_record()).unwrap();
        let db_path = root.join("store.db");
        let new_key = MasterKey::from_bytes([0x88; MASTER_KEY_LEN]);
        store
            .rotate_master_key(MasterKey::from_bytes([0x88; MASTER_KEY_LEN]))
            .unwrap();
        drop(store);

        let descriptor = StorageDescriptor {
            module_id: "cortexkit-credentials".into(),
            storage_namespace: "vault".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: db_path.to_string_lossy().into_owned(),
            },
        };
        // The OLD key no longer opens the vault (audit-key decrypt fails closed).
        let reopened = open_sqlite(&descriptor).unwrap();
        let old_result =
            EncryptedStore::open(reopened, MasterKey::from_bytes([20u8; MASTER_KEY_LEN]));
        assert!(
            old_result.is_err(),
            "old key must not reopen a rotated vault"
        );
        // The NEW key opens it and the records are intact.
        let reopened = open_sqlite(&descriptor).unwrap();
        let store = EncryptedStore::open(reopened, new_key).expect("new key opens");
        assert_eq!(store.get("a").unwrap().payload, b"payload-bytes");
        assert_eq!(store.verify_audit_chain().unwrap(), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn audit_chain_detects_tampering() {
        let (root, store) = tmp_store(13);
        for i in 0..3 {
            store
                .append_audit(&AuditRecord {
                    op: crate::audit::AuditOp::RefreshCommit,
                    credential_id: Some(format!("id{i}")),
                    payload_hash: Some("hh".into()),
                    actor: "conn-1".into(),
                    alarm: None,
                })
                .unwrap();
        }
        assert_eq!(
            store.verify_audit_chain().unwrap(),
            None,
            "clean chain verifies"
        );
        // Tamper with a row's payload_hash directly (a key-less attacker editing the
        // db) — the HMAC no longer matches, so verification flags the broken seq.
        store
            .with_raw_conn(|c| {
                c.execute(
                    "UPDATE audit_log SET payload_hash = 'tampered' WHERE seq = 2",
                    [],
                )
            })
            .unwrap();
        assert_eq!(
            store.verify_audit_chain().unwrap(),
            Some(2),
            "tampered entry detected"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_fenced_write_latches_fenced_out() {
        let (root, store) = tmp_store(21);
        store.create("id", &oauth_record()).expect("create");
        // Not fenced out on a healthy store.
        assert!(!store.is_fenced_out());

        // Simulate a newer writer having claimed the database at a higher epoch, so
        // the next fenced write is rejected — exactly the lease-handover race.
        store
            .with_raw_conn(|c| c.execute("UPDATE cortexkit_fence SET epoch = 999 WHERE id = 0", []))
            .expect("bump fence epoch above the holder");

        // A real durable mutation now: it must be Fenced AND latch the flag.
        match store.invalidate("id") {
            Err(StoreOpError::Fenced { .. }) => {}
            other => panic!("expected Fenced, got {other:?}"),
        }
        assert!(
            store.is_fenced_out(),
            "a rejected fenced write must latch the fenced-out signal"
        );

        // The signal drives the health snapshot to Failing even though the stale
        // read of the row still succeeds (Active).
        let metas = store.list_meta().expect("list_meta still reads");
        let health = crate::health::VaultHealth::summarize(&metas, 0, store.is_fenced_out());
        assert_eq!(health.status, crate::health::VaultHealthStatus::Failing);
        assert!(health.fenced_out);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn version_gated_invalidate_hits_on_matching_version() {
        let (root, store) = tmp_store(30);
        store.create("id", &oauth_record()).expect("create"); // record_version 1
        let ctx = AuditCtx {
            op: AuditOp::ReportAuthFailure,
            actor: "conn-1",
            alarm: None,
        };
        // Reporting the CURRENT version (1) invalidates and returns true.
        let hit = store
            .invalidate_if_version_audited("id", 1, ctx)
            .expect("version-gated invalidate");
        assert!(hit, "a report for the current version must invalidate");
        assert_eq!(store.meta("id").unwrap().state, RecordState::NeedsReauth);
        // And it audited exactly one ReportAuthFailure entry.
        let reports = store
            .read_audit(None)
            .unwrap()
            .into_iter()
            .filter(|e| e.op == "report_auth_failure")
            .count();
        assert_eq!(reports, 1, "a hitting version-CAS audits the invalidation");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn version_gated_invalidate_is_a_silent_noop_on_stale_version() {
        let (root, store) = tmp_store(31);
        store.create("id", &oauth_record()).expect("create"); // record_version 1
                                                              // Simulate the vault having refreshed to a newer version after the consumer was
                                                              // served v1: overwrite unconditionally so the current version moves to 2.
        store
            .overwrite_unconditional_audited(
                "id",
                &oauth_record(),
                AuditCtx::vault(AuditOp::Overwrite),
            )
            .expect("bump to version 2");
        assert_eq!(store.meta("id").unwrap().record_version, 2);

        let ctx = AuditCtx {
            op: AuditOp::ReportAuthFailure,
            actor: "conn-1",
            alarm: None,
        };
        // A stale report for the SERVED version (1) must be a silent no-op: it does NOT
        // invalidate the fresh v2 credential, returns false, and audits nothing.
        let hit = store
            .invalidate_if_version_audited("id", 1, ctx)
            .expect("stale version-gated invalidate");
        assert!(
            !hit,
            "a report for a superseded version must not invalidate"
        );
        assert_eq!(
            store.meta("id").unwrap().state,
            RecordState::Active,
            "the fresh credential is untouched by a stale report"
        );
        let reports = store
            .read_audit(None)
            .unwrap()
            .into_iter()
            .filter(|e| e.op == "report_auth_failure")
            .count();
        assert_eq!(reports, 0, "a stale version-CAS no-op audits nothing");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rotate_quarantines_undecryptable_rows_and_reports_them() {
        let (root, mut store) = tmp_store(40);
        store.create("good", &oauth_record()).expect("create good");
        store.create("bad", &oauth_record()).expect("create bad");
        // Corrupt "bad"'s envelope directly (a key-less db edit): it will fail to decrypt
        // under the OLD key during rotation, so it cannot be re-wrapped.
        store
            .with_raw_conn(|c| {
                c.execute(
                    "UPDATE credentials SET envelope = X'00010203' WHERE credential_id = 'bad'",
                    [],
                )
            })
            .expect("corrupt bad envelope");

        let new_key = MasterKey::from_bytes([0x41; MASTER_KEY_LEN]);
        let quarantined = store.rotate_master_key(new_key).expect("rotate");
        // The undecryptable row is surfaced, not silently skipped behind a success.
        assert_eq!(quarantined, vec!["bad".to_string()]);
        assert_eq!(store.meta("bad").unwrap().state, RecordState::Corrupt);
        // The good record re-wrapped under the new key and still reads.
        assert_eq!(
            store.get("good").expect("good readable").payload,
            b"payload-bytes"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn read_db_key_id_fails_closed_on_a_corrupt_anchor() {
        let (root, store) = tmp_store(50);
        store.create("id", &oauth_record()).expect("create");
        // Corrupt the sealed audit-key row's plaintext key_id fingerprint (the resolve
        // anchor). This must be distinguished from an ABSENT row (a new vault) and fail
        // closed, not silently downgrade to the bootstrap path.
        store
            .with_raw_conn(|c| {
                c.execute(
                    "UPDATE vault_secrets SET key_id = 'not-hex' WHERE name = ?1",
                    rusqlite::params![AUDIT_KEY_SECRET_NAME],
                )
            })
            .expect("corrupt anchor");
        // The test module is inside store.rs, so it can reach the private inner store.
        match EncryptedStore::read_db_key_id(&store.store) {
            Err(StoreError::Backend(m)) => assert!(m.contains("corrupt anchor"), "got: {m}"),
            other => panic!("a corrupt anchor must fail closed, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
