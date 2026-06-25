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

use cortexkit_store::{Migration, SqliteStore, StoreError};
use sha2::{Digest, Sha256};

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
const MIGRATIONS: &[Migration] = &[Migration {
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
}];

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
    fn as_str(self) -> &'static str {
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
}

impl EncryptedStore {
    /// Wrap an already-open, migrated [`SqliteStore`] with a master key. The store
    /// must have had [`EncryptedStore::migrate`] applied (open paths do this).
    pub fn new(store: SqliteStore, key: MasterKey) -> Self {
        let key_id = key.key_id();
        EncryptedStore { store, key, key_id }
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

    /// Create a record (CREATE-ONLY): fails [`StoreOpError::AlreadyExists`] if the
    /// id is already present. The record is sealed at `record_version = 1` and the
    /// row is written through the epoch-fenced path.
    pub fn create(&self, credential_id: &str, record: &VaultRecord) -> Result<(), StoreOpError> {
        let mut record = record.clone();
        record.record_version = 1;
        let blob = self.seal_record(credential_id, &record)?;
        let key_id_hex = self.key_id.to_hex();
        let now = now_ms();

        // Create-only via INSERT ... ON CONFLICT DO NOTHING inside the fenced
        // transaction: an existing id leaves zero rows changed (atomic, no separate
        // existence query, no error-string matching). Zero changed => AlreadyExists.
        let changed = self.store.with_conn_fenced(|tx| {
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
            }
            Ok(n)
        })?;
        if changed == 0 {
            return Err(StoreOpError::AlreadyExists);
        }
        Ok(())
    }

    /// Overwrite an existing record under a compare-and-set on its current payload
    /// hash. Fails [`StoreOpError::NotFound`] if absent, [`StoreOpError::CasMismatch`]
    /// if `expected_payload_hash` does not match the current record's payload. On
    /// success the new record is sealed at `current_version + 1`.
    pub fn overwrite_cas(
        &self,
        credential_id: &str,
        record: &VaultRecord,
        expected_payload_hash: &[u8; 32],
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

        // The version in the WHERE makes the UPDATE itself a compare-and-set on the
        // version we read, so a concurrent writer that already bumped it leaves zero
        // rows changed (no error-string matching). Zero changed => CasMismatch.
        let changed = self.store.with_conn_fenced(|tx| {
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
            }
            Ok(n)
        })?;
        if changed == 0 {
            return Err(StoreOpError::CasMismatch);
        }
        Ok(())
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
    /// and clear any dangling refresh intent for it, atomically. Written through the
    /// fenced path. A no-op (Ok) if the id is absent.
    ///
    /// Clears the intent because an authoritative revoke supersedes any in-flight
    /// refresh: leaving a stale intent would let boot reconciliation reason about a
    /// credential the operator has already invalidated.
    pub fn invalidate(&self, credential_id: &str) -> Result<(), StoreOpError> {
        self.set_state(credential_id, RecordState::NeedsReauth, true)
    }

    /// Quarantine a record (`corrupt`). Used by the read path on a decrypt/parse
    /// failure; idempotent. Does NOT clear a refresh intent — quarantine is an
    /// internal integrity flip, not an admin write, and a corrupt record's intent
    /// (if any) is for reconciliation to resolve, not for this path to discard.
    pub fn quarantine(&self, credential_id: &str) -> Result<(), StoreOpError> {
        self.set_state(credential_id, RecordState::Corrupt, false)
    }

    /// Mark a record `needs_reauth` but RETAIN its refresh intent. Used by
    /// reconciliation when a non-mutating validity check could not be run (transient
    /// network): the record fails closed now, but the surviving intent lets a later
    /// retry re-check and restore the credential without a forced re-login.
    pub fn mark_needs_reauth_retaining_intent(
        &self,
        credential_id: &str,
    ) -> Result<(), StoreOpError> {
        self.set_state(credential_id, RecordState::NeedsReauth, false)
    }

    fn set_state(
        &self,
        credential_id: &str,
        state: RecordState,
        clear_intent: bool,
    ) -> Result<(), StoreOpError> {
        let now = now_ms();
        self.store
            .with_conn_fenced(|tx| {
                tx.execute(
                    "UPDATE credentials SET state = ?2, updated_at_ms = ?3 \
                     WHERE credential_id = ?1",
                    rusqlite::params![credential_id, state.as_str(), now],
                )?;
                if clear_intent {
                    clear_intent_tx(tx, credential_id)?;
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
        self.store
            .with_conn_fenced(|tx| {
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

        let changed = self.store.with_conn_fenced(|tx| {
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
            // The new tokens and the intent-clear commit together or not at all.
            if n > 0 {
                clear_intent_tx(tx, credential_id)?;
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
        self.store
            .with_conn_fenced(|tx| clear_intent_tx(tx, credential_id).map(|_| ()))
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
        (root, EncryptedStore::new(store, key))
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
    fn wrong_key_does_not_decrypt_and_quarantines() {
        // A record sealed under one key, then opened by a store holding a DIFFERENT
        // key: the key_id check inside the envelope catches it, the row is
        // quarantined, and nothing panics.
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
        let wrong = EncryptedStore::new(reopened, MasterKey::from_bytes([0xEE; MASTER_KEY_LEN]));
        match wrong.get("id") {
            Err(StoreOpError::Decrypt(_)) => {}
            other => panic!("expected Decrypt on wrong key, got {other:?}"),
        }
        assert_eq!(wrong.meta("id").unwrap().state, RecordState::Corrupt);
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
}
