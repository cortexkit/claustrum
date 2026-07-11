//! Cross-binary contract values — the single definition site.
//!
//! Every value here is part of a contract BETWEEN the daemon (`credentials-module`)
//! and the admin CLI (`ck-creds`): both binaries must agree on it
//! exactly, or they operate on different vaults / locks / key-store items without
//! noticing. The class of bug this module exists to kill is a cross-binary contract
//! value copy-pasted as a literal into each binary, free to drift — which has bitten
//! this vault before (a lease-namespace split, and an un-scoped keychain item). The
//! fix is structural: each such value has EXACTLY ONE definition here, and both
//! binaries import it. There are no second copies to drift.
//!
//! The unifying invariant: the keychain master-key item, the single-writer lease,
//! and the `store.db` location are ALL keyed on the same discriminator — the
//! canonical vault data directory. Point both binaries at the same vault and they
//! share one store, one lease, and one keychain item by construction; point them at
//! different vaults and all three differ by construction.

use cortexkit_paths::ProjectRootId;
use std::path::Path;

use sha2::{Digest, Sha256};

/// The vault's module id under subc supervision. The daemon registers under it and
/// the CLI builds the storage descriptor with it; they MUST match.
pub const MODULE_ID: &str = "cortexkit-credentials";

/// The storage namespace the vault is resolved under. subc delivers this to the
/// daemon in `HELLO_ACK.storage`; the CLI must build its descriptor with the SAME
/// value. The single-writer lease key is `(module_id, backend, storage_namespace)`,
/// so a mismatch makes the CLI and daemon take DIFFERENT lease locks — they stop
/// mutually excluding, which breaks the rule that an admin write only succeeds while
/// the daemon is stopped, and fences the daemon's own writes out. subc uses
/// "default"; this is a fixed contract value, not a free choice.
pub const STORAGE_NAMESPACE: &str = "default";

/// The keychain service prefix. The full service string is this, scoped per-vault by
/// the canonical data directory (see [`keychain_service_for`]).
const KEYCHAIN_SERVICE_PREFIX: &str = "cortexkit-credentials";

/// The keychain account for the `Current` master-key slot. The `Next` rotation slot
/// is this with a `-next` suffix (the slot scheme lives in the keychain backend).
pub const KEYCHAIN_ACCOUNT_CURRENT: &str = "master-key";

/// Derive the keychain SERVICE string for a vault, scoped by its data directory.
///
/// The service is `"cortexkit-credentials:<16 hex>"` where the hex is the first 8
/// bytes of `SHA-256(canonical data_dir)`. The canonical form comes from
/// [`cortexkit_paths::ProjectRootId`] — the same path-identity primitive the wire
/// layer uses so two independent binaries agree on a path byte-for-byte (it resolves
/// macOS `/var`→`/private/var`, symlinks, and Windows verbatim/drive-case). So the
/// CLI and the daemon, pointed at the same data directory by any spelling, derive
/// the IDENTICAL service; pointed at different directories, they derive DISTINCT
/// services (per-vault isolation).
///
/// This is why the keychain item gains the same per-vault scoping the lease and the
/// `store.db` path already have. Two vaults on one machine no longer collide on a
/// single fixed keychain item.
///
/// Fails closed: if the data directory cannot be canonicalized (it does not exist,
/// or the OS rejects it), this returns `None`. Callers treat that as "no key
/// resolvable" rather than falling back to an unscoped item — every resolve path
/// runs `ensure_vault_dir` first, so in practice the directory exists by here.
pub fn keychain_service_for(data_dir: &Path) -> Option<String> {
    let id = ProjectRootId::from_path(data_dir).ok()?;
    let mut hasher = Sha256::new();
    // Hash the canonical path's raw OS bytes LOSSLESSLY, so two distinct paths can never
    // alias into the same scope by first passing through a lossy UTF-8 conversion (a
    // `to_string_lossy` would map any non-UTF-8 byte to U+FFFD, collapsing distinct
    // non-UTF-8 paths together). For a normal UTF-8 path the bytes are identical to the
    // UTF-8 encoding, so this does NOT change the derived service for any real vault — it
    // only removes the aliasing edge for exotic byte paths.
    hasher.update(canonical_path_bytes(id.as_path()));
    let digest = hasher.finalize();
    // 8 bytes (32 bits) of scope is ample: a machine holds a handful of vaults, not
    // billions, so a distinct-data_dir collision is astronomically unlikely. And even
    // a hypothetical collision is FAIL-CLOSED, not a wrong-vault open: two vaults that
    // collided to the same keychain service would still have store.db sealed under
    // different master keys, so resolve_for_db's key_id anchor (the sealed audit-key
    // row's fingerprint) rejects the mismatched key as KeyMismatch and never decrypts
    // the other vault. The truncation can only ever degrade to a clean fail-closed.
    let scope: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    Some(format!("{KEYCHAIN_SERVICE_PREFIX}:{scope}"))
}

/// Derive the vault's admin-transcript identity from its data directory: the FULL
/// (untruncated) SHA-256 over the canonical path bytes, domain-separated. Both
/// binaries (module and CLI/app) must derive this from the same canonical form —
/// [`cortexkit_paths::ProjectRootId`], the same identity the keychain scope uses —
/// so the challenge-response transcript binds to the same 32 bytes on both sides.
///
/// Unlike the keychain service (8-byte truncation, cosmetic namespacing), this is
/// full-width because the binding is adversarial: it is what stops an admin-op MAC
/// minted for one vault being spliced onto another. Fails closed (`None`) when the
/// directory cannot be canonicalized.
pub fn vault_id_for(data_dir: &Path) -> Option<[u8; crate::admin_auth::VAULT_ID_LEN]> {
    let id = ProjectRootId::from_path(data_dir).ok()?;
    Some(crate::admin_auth::vault_id_for_canonical_dir(
        &canonical_path_bytes(id.as_path()),
    ))
}

/// The canonical path's raw bytes for hashing, losslessly. On unix the `OsStr` bytes are
/// taken directly (`OsStrExt::as_bytes`), so a non-UTF-8 path hashes to its true bytes
/// rather than a U+FFFD-collapsed approximation. On non-unix (Windows), the OS string is
/// UTF-16-based; `to_string_lossy` there is lossless for real paths (valid UTF-16 → UTF-8)
/// and the whole path family differs anyway, so the string form is used.
fn canonical_path_bytes(path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy().as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(label: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ck-contract-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn same_data_dir_yields_same_keychain_service() {
        let dir = tmp_dir("same");
        let a = keychain_service_for(&dir).expect("service");
        let b = keychain_service_for(&dir).expect("service");
        assert_eq!(
            a, b,
            "the same data dir must derive the same keychain service"
        );
        assert!(a.starts_with("cortexkit-credentials:"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn alternate_spellings_of_one_dir_agree() {
        // The cross-binary property: the CLI and the daemon may hold different
        // SPELLINGS of the same vault dir (a trailing slash, a `.` segment, a
        // symlink). They must still derive the identical service — this is exactly
        // what ProjectRootId canonicalization guarantees.
        let dir = tmp_dir("spellings");
        let canonical = keychain_service_for(&dir).expect("service");

        let with_dot = dir.join(".");
        let via_dot = keychain_service_for(&with_dot).expect("service via .");
        assert_eq!(
            canonical, via_dot,
            "a `.` segment must not change the service"
        );

        let with_trailing = {
            let mut s = dir.clone().into_os_string();
            s.push("/");
            std::path::PathBuf::from(s)
        };
        let via_trailing = keychain_service_for(&with_trailing).expect("service via trailing /");
        assert_eq!(
            canonical, via_trailing,
            "a trailing separator must not change the service"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lossless_path_hashing_matches_utf8_for_a_normal_path() {
        // The lossless-byte switch (crypto audit #10) must NOT change the service for any
        // real (UTF-8) data dir — the prod vault's item must stay stable. For a UTF-8
        // path, the raw OS bytes ARE the UTF-8 bytes, so canonical_path_bytes equals
        // to_string_lossy().as_bytes(); this pins that so the change is provably a no-op
        // for real paths while still removing the aliasing edge for non-UTF-8 byte paths.
        let dir = tmp_dir("lossless");
        let id = ProjectRootId::from_path(&dir).expect("canonicalize");
        let lossless = canonical_path_bytes(id.as_path());
        let lossy = id.as_path().to_string_lossy().as_bytes().to_vec();
        assert_eq!(
            lossless, lossy,
            "for a UTF-8 path the lossless bytes equal the UTF-8 bytes (service unchanged)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn distinct_data_dirs_yield_distinct_services() {
        // The fail-closed direction: a daemon pointed at a DIFFERENT data dir derives
        // a DIFFERENT keychain service, so it finds no key there (NotBootstrapped) —
        // it never silently opens a wrong/empty vault under a shared item.
        let a_dir = tmp_dir("distinct-a");
        let b_dir = tmp_dir("distinct-b");
        let a = keychain_service_for(&a_dir).expect("service a");
        let b = keychain_service_for(&b_dir).expect("service b");
        assert_ne!(
            a, b,
            "two different vaults must NOT collide on one keychain service"
        );
        let _ = std::fs::remove_dir_all(&a_dir);
        let _ = std::fs::remove_dir_all(&b_dir);
    }

    #[test]
    fn nonexistent_data_dir_fails_closed_to_none() {
        let missing = std::env::temp_dir().join("ck-contract-does-not-exist-xyzzy-99999");
        let _ = std::fs::remove_dir_all(&missing);
        assert_eq!(
            keychain_service_for(&missing),
            None,
            "an un-canonicalizable data dir yields no service (fail closed), not a fallback"
        );
    }
}
