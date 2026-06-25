//! The at-rest cipher envelope: one [`VaultRecord`](crate)'s plaintext encrypted
//! as a single atomic unit with XChaCha20-Poly1305.
//!
//! ## Wire layout (the stored ciphertext BLOB)
//!
//! ```text
//!   byte  0        magic = 0xC7
//!   byte  1        cipher_version = 0x01  (XChaCha20-Poly1305)
//!   bytes 2..10    key_id (8 bytes — which master key wrapped this)
//!   bytes 10..34   nonce  (24 bytes — XChaCha extended nonce, CSPRNG per write)
//!   bytes 34..     ciphertext || Poly1305 tag (the AEAD appends the 16-byte tag)
//! ```
//!
//! The envelope is self-describing (it can be decrypted standalone given the key)
//! and the header is authenticated, not just length-checked: the cipher_version
//! and key_id are folded into the AEAD's additional authenticated data, so a
//! downgrade or key-id edit fails the tag check rather than silently mis-routing.
//!
//! ## The fuzz invariant (a ship-gate requirement)
//!
//! [`open`] is the ONLY decode path and it bounds-checks every field before
//! slicing — any malformed, truncated, or garbage buffer returns a typed
//! [`EnvelopeError`], NEVER a panic and NEVER plaintext. The security-conformance
//! suite fuzzes this directly. The implementation therefore uses only checked
//! slicing (explicit length guards, `try_into` on fixed arrays) — no indexing
//! that could panic on a short buffer.
//!
//! ## Additional authenticated data (AAD)
//!
//! The AAD binds each ciphertext to its identity so it cannot be relocated or
//! rolled back at the storage layer (a complement to, not a replacement for, the
//! write-audit hash-chain). It is a canonical, unambiguous, length-prefixed
//! encoding (every field is a u32-little-endian length followed by its bytes), so
//! a crafted `credential_id` can never shift a field boundary:
//!
//! ```text
//!   AAD = LP(domain) || LP(cipher_version) || LP(key_id)
//!         || LP(credential_id) || LP(record_version)
//! ```
//!
//! `credential_id` binding stops a ciphertext from being moved to a different
//! record; `record_version` binding stops an old ciphertext from being paired
//! with a bumped version column. Because the whole record is re-encrypted and the
//! version is bumped together in one fenced transaction on every write, the column
//! and ciphertext always move together — there is no path that bumps the version
//! without re-encrypting, so this never self-inflicts a decrypt break.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroizing;

use crate::key::{KeyId, MasterKey, KEY_ID_LEN};

/// First envelope byte: a fixed tag so a non-envelope blob is rejected up front.
pub const MAGIC: u8 = 0xC7;

/// `cipher_version` for XChaCha20-Poly1305. New cipher suites take new numbers;
/// the decoder rejects any version it does not implement.
pub const CIPHER_VERSION_XCHACHA20POLY1305: u8 = 0x01;

/// Nonce length for XChaCha20-Poly1305 (the extended 192-bit nonce).
pub const NONCE_LEN: usize = 24;

/// Poly1305 authentication tag length appended by the AEAD.
pub const TAG_LEN: usize = 16;

/// Header length: magic(1) + cipher_version(1) + key_id(8) + nonce(24).
pub const HEADER_LEN: usize = 1 + 1 + KEY_ID_LEN + NONCE_LEN;

/// Smallest possible valid envelope: a full header plus an empty-plaintext
/// ciphertext (which is still TAG_LEN tag bytes). Anything shorter is malformed.
pub const MIN_ENVELOPE_LEN: usize = HEADER_LEN + TAG_LEN;

/// Domain-separation label mixed into every AAD, so this envelope's AAD can never
/// alias another protocol's authenticated data.
const AAD_DOMAIN: &[u8] = b"cortexkit-credentials/envelope-aad/v1";

/// Identity an envelope is cryptographically bound to (folded into the AAD). The
/// same binding must be supplied to [`open`] or the authenticated decrypt fails.
#[derive(Debug, Clone, Copy)]
pub struct RecordBinding<'a> {
    /// The credential's stable identifier (anti-relocation binding).
    pub credential_id: &'a str,
    /// The record's monotonic version at the time it was written (anti-rollback).
    pub record_version: u64,
}

/// A decode/decrypt failure. Every variant is a clean, typed error — the decoder
/// never panics and never returns plaintext on failure.
#[derive(Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Buffer shorter than a minimal envelope, or a field runs past the end.
    Truncated,
    /// First byte is not [`MAGIC`] — not one of our envelopes.
    BadMagic(u8),
    /// `cipher_version` names a suite this build does not implement.
    UnsupportedCipherVersion(u8),
    /// The envelope's key_id does not match the supplied key's fingerprint, so
    /// this key cannot decrypt it (wrong/rotated key). Reported before any
    /// decrypt is attempted, so a wrong key fails fast rather than as a tag error.
    KeyMismatch { envelope: KeyId, key: KeyId },
    /// The AEAD rejected the ciphertext: wrong key, corrupted bytes, a tampered
    /// header, or an AAD (credential_id / record_version) that does not match
    /// what the envelope was sealed with. Indistinguishable by design.
    Decrypt,
    /// Cipher construction failed (e.g. an invalid key length). Not expected for
    /// a correctly sized master key; surfaced rather than unwrapped.
    Cipher,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvelopeError::Truncated => f.write_str("cipher envelope is truncated or malformed"),
            EnvelopeError::BadMagic(b) => {
                write!(f, "cipher envelope has wrong magic byte 0x{b:02x}")
            }
            EnvelopeError::UnsupportedCipherVersion(v) => {
                write!(f, "unsupported cipher version 0x{v:02x}")
            }
            EnvelopeError::KeyMismatch { envelope, key } => write!(
                f,
                "envelope sealed under key {} but loaded key is {}",
                envelope.to_hex(),
                key.to_hex()
            ),
            EnvelopeError::Decrypt => {
                f.write_str("cipher envelope failed authenticated decryption")
            }
            EnvelopeError::Cipher => f.write_str("cipher could not be constructed"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Append a length-prefixed field (u32-LE length, then bytes) to the AAD buffer.
/// The fixed-width length prefix makes field boundaries unambiguous regardless of
/// field contents.
fn push_lp(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u32).to_le_bytes());
    buf.extend_from_slice(field);
}

/// Build the canonical AAD for a record (see the module docs). Deterministic, so
/// seal and open derive byte-identical AAD from the same inputs.
fn build_aad(key_id: &KeyId, binding: &RecordBinding<'_>) -> Vec<u8> {
    let mut aad = Vec::new();
    push_lp(&mut aad, AAD_DOMAIN);
    push_lp(&mut aad, &[CIPHER_VERSION_XCHACHA20POLY1305]);
    push_lp(&mut aad, key_id.as_bytes());
    push_lp(&mut aad, binding.credential_id.as_bytes());
    push_lp(&mut aad, &binding.record_version.to_le_bytes());
    aad
}

/// Encrypt `plaintext` into a complete envelope BLOB, bound to `binding`.
///
/// A fresh 24-byte nonce is drawn from the OS CSPRNG for every call (never
/// reused, never derived), which XChaCha's extended nonce makes collision-safe at
/// any realistic write volume. The returned `Vec` is the exact bytes to persist.
pub fn seal(
    key: &MasterKey,
    plaintext: &[u8],
    binding: &RecordBinding<'_>,
) -> Result<Vec<u8>, EnvelopeError> {
    let key_id = key.key_id();
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| EnvelopeError::Cipher)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|_| EnvelopeError::Cipher)?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    let aad = build_aad(&key_id, binding);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| EnvelopeError::Cipher)?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.push(MAGIC);
    out.push(CIPHER_VERSION_XCHACHA20POLY1305);
    out.extend_from_slice(key_id.as_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decode and authenticate-decrypt an envelope BLOB, returning the plaintext in a
/// self-zeroizing buffer.
///
/// This is the ONLY decode path and the fuzz target: every field is length-checked
/// before it is read, so a malformed/truncated/garbage `blob` returns a typed
/// [`EnvelopeError`] and never panics. The supplied `key` must be the one the
/// envelope was sealed under (checked via the key_id fingerprint before any
/// decrypt) and `binding` must match what it was sealed with (enforced by the
/// AEAD over the AAD), or the call fails closed.
pub fn open(
    key: &MasterKey,
    blob: &[u8],
    binding: &RecordBinding<'_>,
) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    // Length guard first: everything below slices within a validated length.
    if blob.len() < MIN_ENVELOPE_LEN {
        return Err(EnvelopeError::Truncated);
    }

    // Fixed-offset header fields, all within the checked length.
    let magic = blob[0];
    if magic != MAGIC {
        return Err(EnvelopeError::BadMagic(magic));
    }
    let cipher_version = blob[1];
    if cipher_version != CIPHER_VERSION_XCHACHA20POLY1305 {
        return Err(EnvelopeError::UnsupportedCipherVersion(cipher_version));
    }

    let key_id_bytes: [u8; KEY_ID_LEN] = blob[2..2 + KEY_ID_LEN]
        .try_into()
        .map_err(|_| EnvelopeError::Truncated)?;
    let envelope_key_id = KeyId::from_bytes(key_id_bytes);

    // Fail fast on a wrong/rotated key BEFORE attempting decryption, so a key
    // mismatch is a distinct, cheap signal (→ vault_locked) rather than an
    // opaque tag failure indistinguishable from real corruption.
    let key_id = key.key_id();
    if envelope_key_id != key_id {
        return Err(EnvelopeError::KeyMismatch {
            envelope: envelope_key_id,
            key: key_id,
        });
    }

    let nonce_start = 2 + KEY_ID_LEN;
    let nonce_bytes: [u8; NONCE_LEN] = blob[nonce_start..nonce_start + NONCE_LEN]
        .try_into()
        .map_err(|_| EnvelopeError::Truncated)?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    // The remainder is ciphertext || tag. The minimum-length guard already
    // ensured at least TAG_LEN bytes remain.
    let ciphertext = &blob[HEADER_LEN..];

    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| EnvelopeError::Cipher)?;
    let aad = build_aad(&envelope_key_id, binding);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| EnvelopeError::Decrypt)?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::MASTER_KEY_LEN;

    fn key(seed: u8) -> MasterKey {
        MasterKey::from_bytes([seed; MASTER_KEY_LEN])
    }

    fn binding() -> RecordBinding<'static> {
        RecordBinding {
            credential_id: "opencode:anthropic",
            record_version: 7,
        }
    }

    #[test]
    fn round_trips() {
        let k = key(1);
        let pt = b"super-secret-refresh-token";
        let blob = seal(&k, pt, &binding()).expect("seal");
        assert_eq!(blob[0], MAGIC);
        assert_eq!(blob[1], CIPHER_VERSION_XCHACHA20POLY1305);
        assert!(blob.len() >= MIN_ENVELOPE_LEN);
        let out = open(&k, &blob, &binding()).expect("open");
        assert_eq!(out.as_slice(), pt);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let k = key(2);
        let blob = seal(&k, b"", &binding()).expect("seal empty");
        assert_eq!(
            blob.len(),
            MIN_ENVELOPE_LEN,
            "empty plaintext = header + tag"
        );
        let out = open(&k, &blob, &binding()).expect("open empty");
        assert!(out.is_empty());
    }

    #[test]
    fn fresh_nonce_per_seal_makes_ciphertext_unequal() {
        let k = key(3);
        let a = seal(&k, b"same plaintext", &binding()).unwrap();
        let b = seal(&k, b"same plaintext", &binding()).unwrap();
        // Same key + same plaintext must still differ: the nonce is fresh, and it
        // lives in the header, so the whole blob (header + ciphertext) differs.
        assert_ne!(a, b, "nonce reuse would make these equal");
        assert_ne!(a[HEADER_LEN..], b[HEADER_LEN..], "ciphertext differs");
    }

    #[test]
    fn wrong_key_is_key_mismatch_not_panic() {
        let blob = seal(&key(4), b"secret", &binding()).unwrap();
        match open(&key(5), &blob, &binding()) {
            Err(EnvelopeError::KeyMismatch { .. }) => {}
            other => panic!("expected KeyMismatch, got {other:?}"),
        }
    }

    #[test]
    fn tampered_ciphertext_fails_decrypt() {
        let k = key(6);
        let mut blob = seal(&k, b"secret payload", &binding()).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF; // flip a tag bit
        assert_eq!(open(&k, &blob, &binding()), Err(EnvelopeError::Decrypt));
    }

    #[test]
    fn tampered_header_fails_decrypt() {
        let k = key(7);
        let mut blob = seal(&k, b"secret", &binding()).unwrap();
        // Flip a nonce byte (inside the header, authenticated transitively via the
        // tag over the real nonce): the tag no longer matches.
        blob[HEADER_LEN - 1] ^= 0x01;
        assert_eq!(open(&k, &blob, &binding()), Err(EnvelopeError::Decrypt));
    }

    #[test]
    fn wrong_binding_credential_id_fails_decrypt() {
        let k = key(8);
        let blob = seal(&k, b"secret", &binding()).unwrap();
        let relocated = RecordBinding {
            credential_id: "opencode:openai", // moved to a different record
            record_version: 7,
        };
        assert_eq!(open(&k, &blob, &relocated), Err(EnvelopeError::Decrypt));
    }

    #[test]
    fn wrong_binding_record_version_fails_decrypt() {
        let k = key(9);
        let blob = seal(&k, b"secret", &binding()).unwrap();
        let rolled = RecordBinding {
            credential_id: "opencode:anthropic",
            record_version: 8, // bumped column paired with old ciphertext
        };
        assert_eq!(open(&k, &blob, &rolled), Err(EnvelopeError::Decrypt));
    }

    #[test]
    fn bad_magic_rejected() {
        let k = key(10);
        let mut blob = seal(&k, b"x", &binding()).unwrap();
        blob[0] = 0x00;
        assert_eq!(
            open(&k, &blob, &binding()),
            Err(EnvelopeError::BadMagic(0x00))
        );
    }

    #[test]
    fn unsupported_cipher_version_rejected() {
        let k = key(11);
        let mut blob = seal(&k, b"x", &binding()).unwrap();
        blob[1] = 0x02;
        assert_eq!(
            open(&k, &blob, &binding()),
            Err(EnvelopeError::UnsupportedCipherVersion(0x02))
        );
    }

    #[test]
    fn short_buffers_are_truncated_not_panic() {
        let k = key(12);
        let full = seal(&k, b"some bytes", &binding()).unwrap();
        // Every prefix shorter than a minimal envelope must be Truncated, never a
        // panic (slice-before-the-length-check would panic — this guards it).
        for len in 0..MIN_ENVELOPE_LEN {
            assert_eq!(
                open(&k, &full[..len.min(full.len())], &binding()),
                Err(EnvelopeError::Truncated),
                "prefix length {len} must be Truncated"
            );
        }
    }

    // The fuzz invariant: NO byte string, of any length, may panic the decoder.
    proptest::proptest! {
        #[test]
        fn decoder_never_panics_on_arbitrary_bytes(blob in proptest::collection::vec(proptest::num::u8::ANY, 0..512)) {
            let k = key(13);
            // We only assert it returns (Ok or Err) without panicking. A random
            // blob that happened to authenticate is astronomically unlikely, but
            // even an Ok is acceptable here — the invariant under test is "never
            // panics", which the ship-gate fuzz target also asserts.
            let _ = open(&k, &blob, &binding());
        }

        #[test]
        fn round_trips_arbitrary_plaintext(pt in proptest::collection::vec(proptest::num::u8::ANY, 0..1024)) {
            let k = key(14);
            let blob = seal(&k, &pt, &binding()).expect("seal");
            let out = open(&k, &blob, &binding()).expect("open");
            proptest::prop_assert_eq!(out.as_slice(), pt.as_slice());
        }

        #[test]
        fn any_single_byte_flip_is_rejected(idx in 0usize..64, xor in 1u8..=255) {
            let k = key(15);
            let mut blob = seal(&k, b"twenty-four-byte-payload!", &binding()).expect("seal");
            let i = idx % blob.len();
            blob[i] ^= xor;
            // A flip anywhere must be caught: magic/version/key_id/nonce/ciphertext
            // /tag are all either structurally validated or authenticated. It must
            // never decrypt to the original plaintext, and must never panic.
            if let Ok(out) = open(&k, &blob, &binding()) {
                proptest::prop_assert_ne!(out.as_slice(), &b"twenty-four-byte-payload!"[..]);
            }
        }
    }
}
