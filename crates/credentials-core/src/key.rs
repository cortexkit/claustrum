//! The master key and its fingerprint.
//!
//! [`MasterKey`] is the 32-byte secret that wraps every vault record. It is held
//! in a self-zeroizing buffer, never logged, never serialized, never cloned, and
//! its `Debug` is redacted — the only ways its bytes leave this type are the
//! crate-internal `as_bytes` (so the envelope can build a cipher) and the one-way
//! [`KeyId`] fingerprint.
//!
//! [`KeyId`] is a short, non-secret fingerprint of the key (a key-check value).
//! It is stored in plaintext beside each ciphertext and at the vault level so the
//! vault can (a) detect at load time that the WRONG master key was supplied —
//! fail-closed before any record decrypt, rather than emitting a flood of decrypt
//! failures — and (b) during master-key rotation, find which records are still
//! under the old key without decrypting them. It is a fail-fast optimization, not
//! the security boundary: the AEAD is the boundary, and a fingerprint collision
//! (2^-64) merely falls through to a real authenticated decrypt that then fails.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The master key is 256-bit, matching the XChaCha20-Poly1305 key size.
pub const MASTER_KEY_LEN: usize = 32;

/// The key fingerprint is the first 8 bytes of a domain-separated SHA-256 of the
/// key. Eight bytes is ample for a fail-fast check (see the module docs).
///
/// CHANGING THIS WIDTH BRICKS EVERY EXISTING VAULT, and no test says so, because
/// every assertion about the fingerprint derives its expectation from this same
/// constant and therefore moves with it. Measured on a real vault: bootstrap at 8,
/// rebuild at 4, and the next open fails with `vault_secrets audit-key row has an
/// invalid key_id fingerprint '<16 hex chars>' (corrupt anchor)` -- the store is
/// intact and unreadable, and the operator is told the vault is corrupt rather than
/// that the binary changed.
///
/// The reason is that the fingerprint is PERSISTED as plaintext hex in
/// `vault_secrets` and re-derived on open, so the width is an on-disk format
/// parameter rather than an implementation detail. It is a compatibility constant
/// with no migration path: a rotation cannot help, since resolving the key requires
/// reading the anchor that no longer parses.
pub const KEY_ID_LEN: usize = 8;

/// Domain-separation label for the key fingerprint, so a `KeyId` can never
/// collide with any other SHA-256 use of the same key bytes.
const KEY_ID_DOMAIN: &[u8] = b"cortexkit-credentials/key-id/v1";

/// The 256-bit master key, held in a buffer that scrubs itself on drop.
///
/// No `Clone`, `Display`, `Serialize`, or non-redacted `Debug` is provided on
/// purpose: the key bytes must not be copied loosely, printed, or persisted. Use
/// [`MasterKey::key_id`] to refer to a key in logs/storage.
pub struct MasterKey(Zeroizing<[u8; MASTER_KEY_LEN]>);

impl MasterKey {
    /// Wrap raw key bytes. The caller is responsible for scrubbing whatever it
    /// decoded the bytes from (hold that source in a `Zeroizing` buffer); this
    /// type owns and scrubs its own copy.
    pub fn from_bytes(bytes: [u8; MASTER_KEY_LEN]) -> Self {
        MasterKey(Zeroizing::new(bytes))
    }

    /// Generate a fresh key from the OS CSPRNG. Used for first-run bootstrap.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = Zeroizing::new([0u8; MASTER_KEY_LEN]);
        getrandom::getrandom(bytes.as_mut_slice())?;
        Ok(MasterKey(bytes))
    }

    /// The non-secret fingerprint of this key (see the module docs).
    pub fn key_id(&self) -> KeyId {
        let mut hasher = Sha256::new();
        hasher.update(KEY_ID_DOMAIN);
        hasher.update(self.0.as_slice());
        let digest = hasher.finalize();
        let mut id = [0u8; KEY_ID_LEN];
        id.copy_from_slice(&digest[..KEY_ID_LEN]);
        KeyId(id)
    }

    /// Borrow the raw key bytes to construct a cipher. Crate-internal only — the
    /// bytes must never escape this crate.
    pub(crate) fn as_bytes(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render key bytes — only that a key is present.
        f.write_str("MasterKey(redacted)")
    }
}

/// A short, non-secret key fingerprint stored in plaintext (see the module docs).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyId([u8; KEY_ID_LEN]);

impl KeyId {
    /// Reconstruct a fingerprint from its stored bytes (the plaintext column /
    /// envelope header).
    pub fn from_bytes(bytes: [u8; KEY_ID_LEN]) -> Self {
        KeyId(bytes)
    }

    /// The raw fingerprint bytes (for the envelope header and storage column).
    pub fn as_bytes(&self) -> &[u8; KEY_ID_LEN] {
        &self.0
    }

    /// Parse a fingerprint from its lowercase-hex rendering (the stored plaintext
    /// `key_id` column). `None` if the string is not exactly `KEY_ID_LEN` hex bytes.
    pub fn from_hex(s: &str) -> Option<KeyId> {
        if s.len() != KEY_ID_LEN * 2 {
            return None;
        }
        let mut bytes = [0u8; KEY_ID_LEN];
        // `as_chunks` over `chunks_exact` so the pair is a `[u8; 2]` and the indexing
        // below is checked at compile time. The remainder is provably empty: the length
        // guard above requires an even length.
        let (pairs, _remainder) = s.as_bytes().as_chunks::<2>();
        for (i, chunk) in pairs.iter().enumerate() {
            let hi = (chunk[0] as char).to_digit(16)?;
            let lo = (chunk[1] as char).to_digit(16)?;
            bytes[i] = ((hi << 4) | lo) as u8;
        }
        Some(KeyId(bytes))
    }

    /// Lowercase hex rendering (16 chars). Non-secret; safe to log.
    pub fn to_hex(&self) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(KEY_ID_LEN * 2);
        for b in &self.0 {
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

impl std::fmt::Debug for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyId({})", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_is_deterministic_and_domain_separated() {
        let key = MasterKey::from_bytes([7u8; MASTER_KEY_LEN]);
        let a = key.key_id();
        let b = key.key_id();
        assert_eq!(a, b, "same key yields the same fingerprint");

        // A different key yields a different fingerprint (with overwhelming
        // probability); this also guards against an accidental constant.
        let other = MasterKey::from_bytes([8u8; MASTER_KEY_LEN]);
        assert_ne!(a, other.key_id());

        // The fingerprint is NOT a bare truncation of the key, nor a bare
        // SHA-256 of the key: the domain label must participate.
        let bare: [u8; KEY_ID_LEN] = {
            let d = Sha256::digest([7u8; MASTER_KEY_LEN]);
            let mut o = [0u8; KEY_ID_LEN];
            o.copy_from_slice(&d[..KEY_ID_LEN]);
            o
        };
        assert_ne!(a.as_bytes(), &bare, "fingerprint is domain-separated");
        assert_ne!(a.as_bytes(), &[7u8; KEY_ID_LEN], "not a raw key prefix");
    }

    #[test]
    fn key_id_round_trips_through_bytes_and_hex() {
        let key = MasterKey::from_bytes([42u8; MASTER_KEY_LEN]);
        let id = key.key_id();
        let restored = KeyId::from_bytes(*id.as_bytes());
        assert_eq!(id, restored);
        assert_eq!(id.to_hex().len(), KEY_ID_LEN * 2);
        // AND against a LITERAL, because the assertion above derives both sides from
        // the same constant and so cannot fail when the constant moves. The width is
        // persisted in `vault_secrets` and re-derived on open, so a change to it makes
        // every existing vault unreadable -- measured: an existing store then refuses
        // with "corrupt anchor", telling the operator the vault is broken rather than
        // that the binary changed. This literal is the only thing that reddens.
        assert_eq!(
            id.to_hex().len(),
            16,
            "the on-disk key fingerprint is 16 hex chars; changing it bricks every \
             existing vault with no migration path"
        );
        assert!(id.to_hex().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn debug_never_leaks_key_bytes() {
        let key = MasterKey::from_bytes([0xAB; MASTER_KEY_LEN]);
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "MasterKey(redacted)");
        assert!(!rendered.contains("ab"), "no key bytes in Debug output");
    }

    #[test]
    fn generated_keys_differ() {
        let a = MasterKey::generate().expect("csprng");
        let b = MasterKey::generate().expect("csprng");
        assert_ne!(a.key_id(), b.key_id(), "fresh keys are distinct");
    }
}
