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

/// The vault schema. One table; the fence table is created lazily by
/// `with_conn_fenced` on the first fenced write and is not declared here.
const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    statements: "CREATE TABLE credentials (\
                     credential_id   TEXT PRIMARY KEY, \
                     record_version  INTEGER NOT NULL, \
                     key_id          TEXT NOT NULL, \
                     state           TEXT NOT NULL, \
                     envelope        BLOB NOT NULL, \
                     updated_at_ms   INTEGER NOT NULL\
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

    /// Apply the vault schema migrations to a freshly opened store. Idempotent.
    pub fn migrate(store: &SqliteStore) -> Result<(), StoreError> {
        store.migrate(SCHEMA_NAMESPACE, MIGRATIONS)
    }

    /// The fingerprint of the master key this store seals under.
    pub fn key_id(&self) -> KeyId {
        self.key_id
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
            tx.execute(
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
            )
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
            tx.execute(
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
            )
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

    /// Mark a record `needs_reauth` (authoritative revoke / reported auth failure).
    /// Written through the fenced path. A no-op (Ok) if the id is absent.
    pub fn invalidate(&self, credential_id: &str) -> Result<(), StoreOpError> {
        self.set_state(credential_id, RecordState::NeedsReauth)
    }

    /// Quarantine a record (`corrupt`). Used by the read path on a decrypt/parse
    /// failure; idempotent.
    pub fn quarantine(&self, credential_id: &str) -> Result<(), StoreOpError> {
        self.set_state(credential_id, RecordState::Corrupt)
    }

    fn set_state(&self, credential_id: &str, state: RecordState) -> Result<(), StoreOpError> {
        let now = now_ms();
        self.store
            .with_conn_fenced(|tx| {
                tx.execute(
                    "UPDATE credentials SET state = ?2, updated_at_ms = ?3 \
                     WHERE credential_id = ?1",
                    rusqlite::params![credential_id, state.as_str(), now],
                )?;
                Ok(())
            })
            .map_err(StoreOpError::from)
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
