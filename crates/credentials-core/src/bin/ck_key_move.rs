//! One-shot: move the vault master key from the OLD data-dir keychain scope to the NEW one.
//!
//! Runs in-process through the shipped resolver API so both scopes are derived by the same
//! `keychain_service_for` the daemon uses — a bespoke re-implementation of that hash could
//! write to a scope nothing will ever read, and it would look like success.
//!
//! The key bytes never reach a shell, a file, or a log: `MasterKey` is zeroize-backed and
//! only its fingerprint (`key_id`) is ever printed.

use credentials_core::resolver::{KeySlot, KeySource};
use std::path::PathBuf;

/// The key source for an operator tool, honouring `CK_MASTER_KEY_PATH`.
///
/// Both migration tools hardcoded `KeySource::Keychain`, which made them unusable on an
/// OPERATOR-PATH vault -- a headless or CI host, which is a large part of who runs a
/// migration. The daemon and `ck auth` both honour a key path already; these did not,
/// and the same defect had been fixed in the usable-audit hours earlier without a sweep
/// for siblings, which is why it survived here.
///
/// Reads the DAEMON's variable rather than inventing a second spelling: one concept,
/// one name, and an operator who set it for the daemon does not have to learn another.
fn key_source_from_env() -> KeySource {
    match std::env::var_os("CK_MASTER_KEY_PATH") {
        Some(path) => KeySource::OperatorPath {
            path: PathBuf::from(path),
        },
        None => KeySource::Keychain,
    }
}

/// How the key source will be described in output, so a refusal names WHICH store was
/// consulted. "No key at the derived scope" is equally true of a keychain miss and a
/// wrong key path, and those need opposite responses.
fn key_source_label(source: &KeySource) -> String {
    match source {
        KeySource::OperatorPath { path } => format!("key file {}", path.display()),
        KeySource::Keychain => "the macOS keychain".to_string(),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let old_dir = PathBuf::from(args.next().expect("usage: ck_key_move <OLD_DIR> <NEW_DIR>"));
    let new_dir = PathBuf::from(args.next().expect("usage: ck_key_move <OLD_DIR> <NEW_DIR>"));

    let source = key_source_from_env();
    println!("key store: {}", key_source_label(&source));
    let backend = source.backend();

    println!("old dir: {}", old_dir.display());
    println!("new dir: {}", new_dir.display());

    // OCCUPANCY CHECK FIRST. store_slot is replace-semantics, so a half-applied earlier
    // attempt could be sitting at the destination; overwriting it silently would destroy
    // the only evidence that something else already ran.
    for slot in [KeySlot::Current, KeySlot::Next] {
        match backend.load_slot(&new_dir, slot) {
            Ok(None) => println!("destination {slot:?}: empty (expected)"),
            Ok(Some(k)) => {
                eprintln!(
                    "REFUSING: destination {slot:?} is ALREADY OCCUPIED (key_id {})",
                    k.key_id().to_hex()
                );
                eprintln!("Something wrote here before this run. Investigate before proceeding.");
                std::process::exit(2);
            }
            Err(e) => {
                eprintln!("REFUSING: cannot read destination {slot:?}: {e}");
                std::process::exit(2);
            }
        }
    }

    // Carry BOTH slots. `Next` is normally empty, but an unpromoted `Next` is exactly what a
    // crashed two-slot rotation leaves behind — dropping it here would turn a recoverable
    // pending rotation into an unrecoverable lost key.
    let mut moved = 0usize;
    for slot in [KeySlot::Current, KeySlot::Next] {
        match backend.load_slot(&old_dir, slot) {
            Ok(Some(key)) => {
                let fp = key.key_id().to_hex();
                backend
                    .store_slot(&new_dir, slot, &key)
                    .unwrap_or_else(|e| panic!("write {slot:?} to new scope: {e}"));
                // Read back through the same path: proves the write landed at the scope the
                // daemon will resolve, not merely that store_slot returned Ok.
                let back = backend
                    .load_slot(&new_dir, slot)
                    .unwrap_or_else(|e| panic!("read back {slot:?}: {e}"))
                    .unwrap_or_else(|| panic!("{slot:?} absent after write"));
                assert_eq!(back.key_id().to_hex(), fp, "{slot:?} read-back mismatch");
                println!("moved {slot:?}: key_id {fp} (read-back verified)");
                moved += 1;
            }
            Ok(None) => println!("source {slot:?}: empty, nothing to move"),
            Err(e) => panic!("read source {slot:?}: {e}"),
        }
    }

    assert!(moved >= 1, "no key found in the OLD scope — wrong old dir?");
    println!("OK: {moved} slot(s) moved. Source scope left intact.");
}
