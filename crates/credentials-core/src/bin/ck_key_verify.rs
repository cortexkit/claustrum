//! Assert that the key resolvable for a vault matches the fingerprint its DATABASE
//! records — rather than merely that a keychain item exists at the derived scope.
//!
//! Existence is not identity: a freshly bootstrapped item and the real migrated key both
//! satisfy "something is there". The database's sealed audit-key row carries the plaintext
//! `key_id` of the key it is sealed under, so comparing against that anchor is the check.
//!
//! # This tool must acquire nothing exclusive
//!
//! An earlier version opened the store through `open_sqlite`, which ACQUIRES THE
//! SINGLE-WRITER LEASE as a side effect of opening. Run against a live vault, that claimed
//! the database at a higher epoch and fenced the running daemon out of its own store —
//! reads kept working while every write was refused, which is the silent-decay failure
//! rather than a loud one. The tool reported success throughout, because taking a lease is
//! not a write and nothing in its output could show it.
//!
//! So the bar here is stricter than "performs no writes": IT ACQUIRES NOTHING EXCLUSIVE.
//! The database is read through a plain read-only SQLite connection that participates in
//! no lease protocol at all.
//!
//! Note the connection is read-only but NOT `immutable=1`. An immutable open tells SQLite
//! the file cannot change, so it skips the write-ahead log — on a live vault that silently
//! returns a PRE-WAL snapshot, answering confidently about the past. Read-only sees
//! committed WAL state; immutable is for a store nobody is writing.

use credentials_core::key::KeyId;
use credentials_core::resolver::{KeySlot, KeySource};
use rusqlite::{Connection, OpenFlags};
use std::path::PathBuf;

/// The plaintext fingerprint the vault's sealed audit-key row records, read without the
/// master key and without opening the store through the leased path.
fn db_key_id(data_dir: &std::path::Path) -> Option<KeyId> {
    let conn = Connection::open_with_flags(
        data_dir.join("store.db"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .expect("open store.db read-only");
    // The row name comes from the store's own constant rather than a literal here:
    // a second copy of it would be free to drift from the schema it names.
    let hex: String = conn
        .query_row(
            "SELECT key_id FROM vault_secrets WHERE name = ?1",
            [credentials_core::store::AUDIT_KEY_SECRET_NAME],
            |r| r.get(0),
        )
        .expect("vault has a sealed audit-key row");
    KeyId::from_hex(&hex)
}

fn main() {
    let dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: ck_key_verify <DATA_DIR>"),
    );

    let anchor = db_key_id(&dir)
        .expect("audit-key row has a valid fingerprint")
        .to_hex();

    // What the resolver would actually reach for this data dir. Reading a keychain slot
    // acquires nothing and mutates nothing.
    let backend = KeySource::Keychain.backend();
    let resolved = backend
        .load_slot(&dir, KeySlot::Current)
        .expect("read keychain Current")
        .expect("no key at the derived scope for this data dir")
        .key_id()
        .to_hex();

    println!("  data dir     {}", dir.display());
    println!("  db anchor    {anchor}");
    println!("  keychain     {resolved}");
    assert_eq!(
        resolved, anchor,
        "the key at this vault's keychain scope is NOT the key its database is sealed under"
    );
    println!("  MATCH");
}
