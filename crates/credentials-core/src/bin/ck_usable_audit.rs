//! Report which credentials are USABLE, not merely present.
//!
//! The health gauge counts records that exist and decrypt. That is a weaker property than
//! "a consumer asking for this right now would get a working token": an OAuth record whose
//! access token has expired is still `active` and still counted, and only becomes visibly
//! broken when its refresh is attempted. Tonight one credential sat in exactly that state
//! and read as serving until nine runs asked for it at once.
//!
//! This prints, per credential, whether it holds refresh material and how its access token
//! stands against the clock — so the present-versus-usable gap is measurable without
//! waiting for a consumer to trip over it.
//!
//! # Acquires nothing exclusive
//!
//! Opening a vault through the normal path takes the single-writer lease, which fences the
//! running daemon out of its own store. So the envelope is read through a plain read-only
//! SQLite connection and decrypted in memory here. Read-only rather than `immutable=1`:
//! immutable skips the write-ahead log and would answer about a live store's past.
//!
//! What this CANNOT tell you: whether a refresh token is still honoured by the provider.
//! Only spending it answers that, and for rotating providers spending it invalidates the
//! copy we hold. A token that refreshed successfully today is the strongest non-destructive
//! evidence available.

use credentials_core::envelope::{open as envelope_open, RecordBinding};
use credentials_core::record::VaultRecord;
use credentials_core::resolver::{KeySlot, KeySource};
use rusqlite::{Connection, OpenFlags};
use std::path::PathBuf;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn main() {
    let dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: ck_usable_audit <DATA_DIR>"),
    );

    let key = KeySource::Keychain
        .backend()
        .load_slot(&dir, KeySlot::Current)
        .expect("read keychain")
        .expect("no master key at this vault's derived scope");

    let conn = Connection::open_with_flags(
        dir.join("store.db"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .expect("open store.db read-only");

    let mut stmt = conn
        .prepare("SELECT credential_id, record_version, state, envelope FROM credentials ORDER BY credential_id")
        .expect("prepare");
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
    let (mut usable, mut expiring, mut stale, mut unreadable) = (0, 0, 0, 0);

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

        match record.oauth.as_ref() {
            // A static key has no expiry and no refresh path: present IS usable, as far as
            // the vault can tell. Only the provider knows if it has been revoked.
            None => {
                println!("  {id:34} static      {state}");
                usable += 1;
            }
            Some(oauth) => {
                let has_refresh = !oauth.refresh_token.is_empty();
                match oauth.expires_at_ms {
                    None => {
                        println!("  {id:34} oauth       {state}  no expiry recorded  refresh={has_refresh}");
                        usable += 1;
                    }
                    Some(exp) => {
                        let mins = (exp - now) / 60_000;
                        if mins < 0 {
                            // Expired: the NEXT get must refresh. Usable only if the
                            // refresh token is still honoured, which cannot be known here.
                            println!("  {id:34} oauth       {state}  EXPIRED {} min ago  refresh={has_refresh}", -mins);
                            stale += 1;
                        } else if mins < 15 {
                            println!("  {id:34} oauth       {state}  expires in {mins} min  refresh={has_refresh}");
                            expiring += 1;
                        } else {
                            println!("  {id:34} oauth       {state}  expires in {mins} min  refresh={has_refresh}");
                            usable += 1;
                        }
                    }
                }
            }
        }
    }

    println!();
    println!("  usable now: {usable}   expiring<15m: {expiring}   expired-needs-refresh: {stale}   unreadable: {unreadable}");
}
