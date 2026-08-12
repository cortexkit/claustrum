//! Whether each credential holds material the engine can actually work with.
//!
//! The health gauge counts records that exist and decrypt, which cannot see inside the
//! sealed envelope. This opens each one and reports the property the gauge structurally
//! cannot: whether a record is STRANDED -- holding neither a usable access token nor any
//! refresh material, so it can never serve again without an operator login.
//!
//! # Expiry is reported but never scored
//!
//! An expired access token is not a fault: [`crate::engine::RefreshEngine`] treats it as
//! the trigger to refresh on the next get, so expired-with-refresh-material is the
//! routine state of a perfectly healthy credential and counting it as degraded would
//! report normal operation as a problem.
//!
//! Nor is remaining TTL evidence of the opposite. Expiry and provider acceptance are
//! independent: a provider can reject a token that was minted an hour ago and still has
//! days of TTL left, and no amount of local inspection can see that coming. The
//! authoritative signal for a rejected credential is the `needs_reauth` state, which a
//! consumer sets through `report_auth_failure` and the health gauge already counts.
//!
//! # Acquires nothing exclusive
//!
//! Opening a vault through [`crate::store::EncryptedStore`] takes the single-writer
//! lease, which fences the running daemon out of its own store. So the envelope is read
//! through a plain read-only SQLite connection and decrypted in memory here. Read-only
//! rather than `immutable=1`: immutable skips the write-ahead log and would answer about
//! a live store's past.
//!
//! # Scan, do not print
//!
//! This returns data and renders nothing, so the same scan can back an operator command
//! and a test assertion without either inheriting the other's formatting.

use crate::envelope::{open as envelope_open, RecordBinding};
use crate::key::{KeyId, MasterKey};
use crate::oauth::OAuthCredential;
use crate::record::VaultRecord;
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

/// What a single record's decrypted contents say about its future.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Usability {
    /// A static key: no expiry and no refresh path. Nothing readable here can tell a
    /// live key from one the provider revoked an hour ago.
    Static,
    /// OAuth with material the engine can serve or refresh from. `expires_at_ms` is
    /// carried for display and deliberately not scored.
    Serviceable { expires_at_ms: Option<i64> },
    /// Neither a usable access token nor refresh material: cannot serve, cannot
    /// recover on its own, and needs an operator login.
    Stranded,
    /// The envelope did not open, or its plaintext did not decode.
    Unreadable { why: String },
}

/// One record's row in the report.
#[derive(Debug, Clone)]
pub struct RecordUsability {
    pub credential_id: String,
    /// The stored lifecycle state (`active` / `needs_reauth` / `corrupt`), carried
    /// verbatim so the caller need not re-read the column.
    pub state: String,
    pub usability: Usability,
    /// True when the record claims an identity that resolves nothing -- an email with
    /// no account id. The sink in [`crate::record::VaultRecord::with_identity`]
    /// normalises this away at WRITE time, but a record sealed BEFORE that landed
    /// deserializes with the shape intact and serves it: `VaultRecord::decode` is plain
    /// serde and does not pass through the sink.
    pub unservable_identity: bool,
}

/// Why a scan could not start. Distinguished from a per-record failure, which is
/// reported as [`Usability::Unreadable`] and never aborts the scan.
#[derive(Debug)]
pub enum ScanError {
    /// The store file could not be opened at all.
    Open(String),
    /// The vault is bootstrapped but holds no schema yet: the tables are created by the
    /// first write, not by `bootstrap`. Its own variant because the raw sqlite "no such
    /// table" reads as a corrupt store when the store is merely empty.
    NoSchema,
    /// The scan started and the query failed partway.
    Read(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(e) => write!(f, "opening the store read-only: {e}"),
            Self::NoSchema => write!(f, "the vault holds no credentials yet"),
            Self::Read(e) => write!(f, "reading the store: {e}"),
        }
    }
}

/// Whether the engine can still do something with this record. `None` is a static key.
///
/// Split out of the scan so the stranded arm is reachable by a test: against a healthy
/// vault every record is serviceable, so a run over real data exercises one arm only,
/// and an all-serviceable report is equally consistent with a function that has no
/// stranded arm at all.
pub fn is_serviceable(oauth: Option<&OAuthCredential>) -> bool {
    match oauth {
        None => true,
        Some(oauth) => !oauth.refresh_token.is_empty() || !oauth.access_token.is_empty(),
    }
}

/// The master-key fingerprint the store records in plaintext.
///
/// [`crate::store::EncryptedStore::read_db_key_id`] needs an opened store, which takes
/// the single-writer lease -- the thing this module must not do. The row is plaintext,
/// so reading it over the same read-only connection costs nothing and keeps the
/// lease-free property.
///
/// `None` covers both a store predating the anchor row and any read failure; the caller
/// then falls back to a plain resolve, which fails closed with its own message.
pub fn read_db_key_id_read_only(conn: &Connection) -> Option<KeyId> {
    let hex: String = conn
        .query_row(
            "SELECT key_id FROM vault_secrets WHERE name = '__vault_audit_key__'",
            [],
            |r| r.get(0),
        )
        .ok()?;
    KeyId::from_hex(&hex)
}

/// Open a vault's store read-only, taking no lease.
pub fn open_store_read_only(store_path: &Path) -> Result<Connection, ScanError> {
    Connection::open_with_flags(
        store_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| ScanError::Open(e.to_string()))
}

/// Decrypt every record and report what each one's contents imply.
///
/// A record that fails to decrypt is reported and the scan continues: one unreadable
/// envelope must not hide the state of the other twenty-two.
pub fn scan(conn: &Connection, key: &MasterKey) -> Result<Vec<RecordUsability>, ScanError> {
    let mut stmt = match conn.prepare(
        "SELECT credential_id, record_version, state, envelope FROM credentials \
         ORDER BY credential_id",
    ) {
        Ok(stmt) => stmt,
        Err(rusqlite::Error::SqliteFailure(_, Some(msg))) if msg.contains("no such table") => {
            return Err(ScanError::NoSchema)
        }
        Err(e) => return Err(ScanError::Read(e.to_string())),
    };
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(|e| ScanError::Read(e.to_string()))?;

    let mut out = Vec::new();
    for row in rows {
        let (id, version, state, blob) = row.map_err(|e| ScanError::Read(e.to_string()))?;
        let binding = RecordBinding {
            credential_id: &id,
            record_version: version,
        };
        let plaintext = match envelope_open(key, &blob, &binding) {
            Ok(p) => p,
            Err(e) => {
                out.push(RecordUsability {
                    credential_id: id,
                    state,
                    usability: Usability::Unreadable {
                        why: format!("{e:?}"),
                    },
                    unservable_identity: false,
                });
                continue;
            }
        };
        let record: VaultRecord = match serde_json::from_slice(&plaintext) {
            Ok(r) => r,
            Err(e) => {
                out.push(RecordUsability {
                    credential_id: id,
                    state,
                    usability: Usability::Unreadable {
                        why: format!("undecodable: {e}"),
                    },
                    unservable_identity: false,
                });
                continue;
            }
        };

        let oauth = record.oauth.as_ref();
        let usability = if !is_serviceable(oauth) {
            Usability::Stranded
        } else {
            match oauth {
                None => Usability::Static,
                Some(oauth) => Usability::Serviceable {
                    expires_at_ms: oauth.expires_at_ms,
                },
            }
        };
        out.push(RecordUsability {
            credential_id: id,
            state,
            usability,
            unservable_identity: !record.identity.is_servable(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{is_serviceable, Usability};
    use crate::oauth::OAuthCredential;

    fn creds(access: &str, refresh: &str) -> OAuthCredential {
        OAuthCredential {
            access_token: access.to_string(),
            refresh_token: refresh.to_string(),
            expires_at_ms: None,
            token_url: "https://example.invalid/token".to_string(),
            client_id: None,
            scopes: Vec::new(),
        }
    }

    #[test]
    fn only_a_record_with_neither_token_is_stranded() {
        // The stranded arm: no access token AND no refresh material.
        assert!(!is_serviceable(Some(&creds("", ""))));

        // DISAMBIGUATORS. A predicate that always returned false would satisfy the
        // assertion above, and against a healthy vault nothing would ever exercise
        // these. Refresh material alone is enough -- the engine mints a new access
        // token on the next get -- and so is an access token alone.
        assert!(is_serviceable(Some(&creds("", "refresh"))));
        assert!(is_serviceable(Some(&creds("access", ""))));
        assert!(is_serviceable(Some(&creds("access", "refresh"))));

        // A static key has no OAuth block at all and is never stranded: nothing
        // readable here distinguishes a live key from a revoked one.
        assert!(is_serviceable(None));
    }

    #[test]
    fn expiry_never_makes_a_record_stranded() {
        // An access token that expired an hour ago, with refresh material beside it, is
        // the ROUTINE state of a healthy credential. Pinned because scoring expiry is
        // the exact mistake this module's doc comment argues against, and a future
        // change that "improves" the predicate by checking expires_at_ms would pass
        // every other test here.
        let mut expired = creds("stale-access", "refresh");
        expired.expires_at_ms = Some(0);
        assert!(is_serviceable(Some(&expired)));
    }

    #[test]
    fn usability_variants_are_distinguishable() {
        // Guards against a future refactor collapsing Stranded into Unreadable: the two
        // need different operator responses (re-login vs investigate the store).
        assert_ne!(Usability::Stranded, Usability::Static);
        assert_ne!(
            Usability::Stranded,
            Usability::Unreadable {
                why: "x".to_string()
            }
        );
    }
}
