//! Report whether each credential holds material the engine can actually work with.
//!
//! The health gauge counts records that exist and decrypt, which cannot see inside the
//! sealed envelope. This opens each one and reports the property the gauge structurally
//! cannot: whether a record is STRANDED -- holding neither a usable access token nor any
//! refresh material, so it can never serve again without an operator login.
//!
//! # Expiry is reported but never scored
//!
//! An expired access token is not a fault: `RefreshEngine::is_stale` treats it as the
//! trigger to refresh on the next get, so expired-with-refresh-material is the routine
//! state of a perfectly healthy credential and counting it as degraded would report
//! normal operation as a problem.
//!
//! Nor is remaining TTL evidence of the opposite. Expiry and provider acceptance are
//! independent: a provider can reject a token that was minted an hour ago and still has
//! days of TTL left, and no amount of local inspection can see that coming. The
//! authoritative signal for a rejected credential is the `needs_reauth` state, which a
//! consumer sets through `report_auth_failure` and the health gauge already counts.
//!
//! # Acquires nothing exclusive
//!
//! Opening a vault through the normal path takes the single-writer lease, which fences the
//! running daemon out of its own store. So the envelope is read through a plain read-only
//! SQLite connection and decrypted in memory here. Read-only rather than `immutable=1`:
//! immutable skips the write-ahead log and would answer about a live store's past.

use credentials_core::envelope::{open as envelope_open, RecordBinding};
use credentials_core::key::KeyId;
use credentials_core::oauth::OAuthCredential;
use credentials_core::record::VaultRecord;
use credentials_core::resolver::{self, KeySource, ResolverConfig};
use rusqlite::{Connection, OpenFlags};
use std::path::PathBuf;

/// The master-key fingerprint the store records in plaintext, read over the same
/// read-only connection.
///
/// `EncryptedStore::read_db_key_id` needs an opened store, which takes the
/// single-writer lease -- the thing this tool must not do. The row is plaintext, so
/// reading it directly costs nothing and keeps the lease-free property.
///
/// `None` covers both a store predating the anchor row and any read failure: the
/// caller then falls back to a plain resolve, which fails closed with its own
/// message if no key matches.
fn read_db_key_id_read_only(conn: &Connection) -> Option<KeyId> {
    let hex: String = conn
        .query_row(
            "SELECT key_id FROM vault_secrets WHERE name = '__vault_audit_key__'",
            [],
            |r| r.get(0),
        )
        .ok()?;
    KeyId::from_hex(&hex)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Whether the engine can still do something with this record, or whether it is stranded
/// and needs an operator login. `None` is a static key.
///
/// Split out of the reporting loop so the stranded arm is reachable by a test: against a
/// healthy vault every record is serviceable, so a run over real data exercises one arm
/// only, and an all-serviceable report is equally consistent with a function that has no
/// stranded arm at all.
fn is_serviceable(oauth: Option<&OAuthCredential>) -> bool {
    match oauth {
        // A static key carries no expiry and no refresh path. Nothing readable here can
        // distinguish a live key from one the provider revoked an hour ago.
        None => true,
        // An OAuth record with neither a usable access token nor refresh material cannot
        // serve and cannot recover on its own. Everything else the engine can handle:
        // with refresh material it mints a new access token on the next get.
        Some(oauth) => !oauth.refresh_token.is_empty() || !oauth.access_token.is_empty(),
    }
}

/// Exit with a diagnostic on stderr rather than a panic. A panic prints a backtrace
/// hint and an "the application panicked" frame around what is an ordinary usage or
/// configuration error, which reads as a tool defect to an operator.
fn fail(msg: &str) -> ! {
    eprintln!("ck_usable_audit: {msg}");
    std::process::exit(2);
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut dir: Option<PathBuf> = None;
    let mut key_path: Option<PathBuf> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            // Mirrors `ck auth --key-path`: an operator-path vault has no keychain
            // item, so without this the tool cannot open the one deployment where a
            // read-only diagnostic matters most -- a headless or CI host.
            "--key-path" => {
                key_path = Some(PathBuf::from(args.next().unwrap_or_else(|| {
                    fail("--key-path needs a file");
                })));
            }
            other if other.starts_with('-') => fail(&format!("unexpected argument {other}")),
            other if dir.is_none() => dir = Some(PathBuf::from(other)),
            other => fail(&format!("unexpected argument {other}")),
        }
    }
    let Some(dir) = dir else {
        fail("usage: ck_usable_audit <DATA_DIR> [--key-path <file>]");
    };

    let source = match key_path {
        Some(path) => KeySource::OperatorPath { path },
        None => KeySource::Keychain,
    };
    // Name the source in the refusal. "No master key at this vault's derived scope"
    // is true for a keychain miss AND for a wrong --key-path, and the two need
    // opposite responses (unlock/bootstrap vs fix the path).
    let label = match &source {
        KeySource::OperatorPath { path } => format!("key file {}", path.display()),
        KeySource::Keychain => "the macOS keychain".to_string(),
    };
    let db = dir.join("store.db");
    let conn = match Connection::open_with_flags(
        &db,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    ) {
        Ok(conn) => conn,
        Err(e) => fail(&format!("opening {} read-only: {e}", db.display())),
    };

    // RESOLVE THE SLOT THE DATABASE NAMES, exactly as the daemon does, rather than
    // assuming `Current`.
    //
    // A rotation that crashed after the rewrap and before the promote leaves the
    // store sealed under `Next` -- the state the two-slot handover exists to survive,
    // and one the daemon recovers from silently via `resolve_for_db`. Loading
    // `Current` here reported every record UNREADABLE with a KeyMismatch on a vault
    // that was serving perfectly well. That is the worst possible answer from a
    // diagnostic: it accuses the store during the one window when an operator is
    // already anxious about a rotation, and the true reading is "healthy, finish the
    // promote". Measured with the shipped rotate_cut_helper at its `rewrap` cut, which
    // is a real SIGKILL rather than a hand-forged slot layout.
    //
    // The db's plaintext key fingerprint is the authority for which slot to use, so
    // read it first and let the resolver pick; fall back to a plain resolve for a
    // store too young to have the anchor row.
    let config = ResolverConfig {
        data_dir: dir.clone(),
        source,
    };
    let key = match read_db_key_id_read_only(&conn) {
        Some(db_key_id) => resolver::resolve_for_db(&config, db_key_id),
        None => resolver::resolve(&config, None),
    };
    let key = match key {
        Ok(key) => key,
        Err(e) => fail(&format!(
            "master key for {} from {label}: {e}",
            dir.display()
        )),
    };

    // A bootstrapped-but-never-written vault has a key and no schema: the tables are
    // created by the first write, not by `bootstrap`. Say that, rather than surfacing
    // "no such table: credentials", which reads as a corrupt store when it is an empty
    // one.
    let mut stmt = match conn
        .prepare("SELECT credential_id, record_version, state, envelope FROM credentials ORDER BY credential_id")
    {
        Ok(stmt) => stmt,
        Err(rusqlite::Error::SqliteFailure(_, Some(msg))) if msg.contains("no such table") => {
            println!();
            println!("  {} holds no credentials yet", dir.display());
            println!("  (the vault is bootstrapped; its schema is created by the first write)");
            println!();
            return;
        }
        Err(e) => fail(&format!("reading {}: {e}", db.display())),
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
        .expect("query");

    let now = now_ms();
    let (mut serviceable, mut stranded, mut unreadable) = (0, 0, 0);
    let mut unservable_identity = 0;

    for row in rows {
        let (id, version, state, blob) = row.expect("row");
        let binding = RecordBinding {
            credential_id: &id,
            record_version: version,
        };
        let plaintext = match envelope_open(&key, &blob, &binding) {
            Ok(p) => p,
            Err(e) => {
                println!("  {id:34} UNREADABLE  {e:?}");
                unreadable += 1;
                continue;
            }
        };
        let record: VaultRecord = match serde_json::from_slice(&plaintext) {
            Ok(r) => r,
            Err(e) => {
                println!("  {id:34} UNDECODABLE {e}");
                unreadable += 1;
                continue;
            }
        };

        // An identity that renders a value while resolving nothing. The sink in
        // `with_identity` now normalises this away at WRITE time, but a record sealed
        // BEFORE that landed deserializes with the shape intact and serves it --
        // `VaultRecord::decode` is plain serde and does not pass through the sink.
        // Reported per record rather than counted, because the repair is per record
        // (a re-login or re-import) and a bare count would not say which.
        if !record.identity.is_servable() {
            println!(
                "  {id:34} IDENTITY    email with no account_id: serves a label that \
                 resolves nothing (re-login or re-import to repair)"
            );
            unservable_identity += 1;
        }

        let oauth = record.oauth.as_ref();
        if !is_serviceable(oauth) {
            println!("  {id:34} oauth   {state}  STRANDED: no access token and no refresh token");
            stranded += 1;
            continue;
        }

        match oauth {
            None => {
                println!("  {id:34} static  {state}");
            }
            Some(oauth) => {
                // Expiry is printed as context and never scored. An expired access token
                // is the ROUTINE state of a healthy credential -- RefreshEngine::is_stale
                // treats it as the trigger to refresh on the next get, not as a fault --
                // so counting it as degraded would report normal operation as a problem.
                let ttl = match oauth.expires_at_ms {
                    Some(exp) => {
                        let mins = (exp - now) / 60_000;
                        if mins < 0 {
                            format!("access expired {}m ago, refreshes on next get", -mins)
                        } else {
                            format!("access good for {mins}m")
                        }
                    }
                    None => "no expiry recorded".to_string(),
                };
                println!("  {id:34} oauth   {state}  {ttl}");
            }
        }
        serviceable += 1;
    }

    println!();
    println!(
        "  serviceable: {serviceable}   stranded: {stranded}   unreadable: {unreadable}   \
         unservable identity: {unservable_identity}"
    );
    println!();
    println!("  Serviceable means the record decrypts under the current master key and");
    println!("  holds material the engine can either serve or refresh from. It is NOT a");
    println!("  claim that the provider will still honour it: only spending a token");
    println!("  answers that, and for rotating providers spending it invalidates the copy");
    println!("  we hold, so no dry run exists even in principle. The authoritative signal");
    println!("  for a provider-rejected credential is the `needs_reauth` state, which a");
    println!("  consumer sets via report_auth_failure and the health gauge already counts.");
}

#[cfg(test)]
mod tests {
    use super::is_serviceable;
    use credentials_core::oauth::OAuthCredential;

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
        // The arm a healthy vault never reaches, which is the whole reason it is asserted
        // here rather than left to a live run.
        assert!(!is_serviceable(Some(&creds("", ""))));

        // All three recoverable shapes, so the check cannot collapse into a constant in
        // either direction without failing this test.
        assert!(is_serviceable(Some(&creds("live-access", ""))));
        assert!(is_serviceable(Some(&creds("", "live-refresh"))));
        assert!(is_serviceable(Some(&creds("live-access", "live-refresh"))));
    }

    #[test]
    fn a_static_key_is_serviceable_because_nothing_local_can_falsify_it() {
        assert!(is_serviceable(None));
    }
}
