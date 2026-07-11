//! Master-key challenge-response for module-driven admin ops (contract §4
//! "mechanism 2").
//!
//! An admin op arrives over the subc route plane carrying a MAC over the EXACT
//! operation bytes. The caller proves master-key possession without transmitting
//! the key; the module verifies with the key it already holds. The MAC binds the
//! op to (this vault, this key, this challenge nonce, these exact op bytes), so a
//! captured response cannot authorize a different op (no splice), a different
//! vault (no cross-vault confusion), or a second execution (the nonce is claimed
//! once, atomically, by the caller in the module).
//!
//! Guarantee (precise): at-most-once ACCEPTANCE of an individually key-authorized
//! operation. A hostile relay can drop, delay, or reorder separately authorized
//! ops and can fabricate responses; it cannot create or alter an operation.
//!
//! The op body is treated as an OPAQUE byte string: the caller MACs the exact
//! bytes it sends, the module verifies those exact bytes and only THEN parses
//! them. Nothing is re-serialized or "canonicalized" on either side — JSON is not
//! canonical, so reconstructing bytes for verification would be a
//! canonicalization-mismatch bug class. Parse-after-verify eliminates it.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::key::{KeyId, MasterKey};

type HmacSha256 = Hmac<Sha256>;

/// Domain-separation label for deriving the admin MAC key from the master key.
/// Versioned: a transcript change bumps the label, never reuses it.
const ADMIN_MAC_KEY_DOMAIN: &[u8] = b"cortexkit-credentials/admin-mac-key/v1";

/// Domain-separation prefix for the authenticated transcript itself.
const ADMIN_OP_DOMAIN: &[u8] = b"cortexkit-credentials/admin-op/v1\0";

/// Challenge nonces are 32 bytes from the OS CSPRNG.
pub const ADMIN_NONCE_LEN: usize = 32;

/// The MAC tag is a full HMAC-SHA256 output.
pub const ADMIN_TAG_LEN: usize = 32;

/// The vault identity bound into the transcript: the full (untruncated) SHA-256
/// of the canonical data_dir bytes. Full width, unlike the 32-bit keychain
/// service suffix, because this binding is adversarial (cross-vault splice
/// resistance), not cosmetic namespacing.
pub const VAULT_ID_LEN: usize = 32;

/// The admin MAC key: derived once from the master key, held self-zeroizing.
/// Deriving a purpose key (rather than MACing with the master key directly)
/// keeps the master key's byte exposure confined to `key.rs` and gives the
/// transcript its own revocable domain.
pub struct AdminMacKey(Zeroizing<[u8; 32]>);

impl AdminMacKey {
    /// Derive the admin MAC key from the master key. The only master-key-bytes
    /// consumer outside envelope/audit sealing, and the bytes never leave this
    /// type.
    pub fn derive(master_key: &MasterKey) -> Self {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(master_key.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(ADMIN_MAC_KEY_DOMAIN);
        let digest = mac.finalize().into_bytes();
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&digest);
        AdminMacKey(key)
    }

    fn mac(&self, transcript_parts: &TranscriptParts<'_>) -> HmacSha256 {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.0.as_slice())
            .expect("HMAC accepts any key length");
        mac.update(ADMIN_OP_DOMAIN);
        mac.update(transcript_parts.vault_id);
        mac.update(transcript_parts.key_id.as_bytes());
        mac.update(transcript_parts.nonce);
        mac.update(
            &u32::try_from(transcript_parts.op_body.len())
                .expect("op body length fits u32 (bounded at 1 MiB by admission)")
                .to_be_bytes(),
        );
        mac.update(transcript_parts.op_body);
        mac
    }

    /// Produce the tag for an op (caller side: CLI / CK app).
    pub fn sign(&self, parts: &TranscriptParts<'_>) -> [u8; ADMIN_TAG_LEN] {
        let digest = self.mac(parts).finalize().into_bytes();
        let mut tag = [0u8; ADMIN_TAG_LEN];
        tag.copy_from_slice(&digest);
        tag
    }

    /// Verify a tag (module side). Constant-time via `Mac::verify_slice`; the
    /// tag must be exactly [`ADMIN_TAG_LEN`] bytes (strict, no prefix match).
    pub fn verify(&self, parts: &TranscriptParts<'_>, tag: &[u8]) -> bool {
        if tag.len() != ADMIN_TAG_LEN {
            return false;
        }
        self.mac(parts).verify_slice(tag).is_ok()
    }
}

/// The exact fields bound into the authenticated transcript, in order.
pub struct TranscriptParts<'a> {
    /// Full-width vault identity: sha256(canonical data_dir bytes).
    pub vault_id: &'a [u8; VAULT_ID_LEN],
    /// Fingerprint of the master key the caller resolved (and the module holds).
    pub key_id: KeyId,
    /// The single-use challenge nonce issued by the module on this bind.
    pub nonce: &'a [u8; ADMIN_NONCE_LEN],
    /// The EXACT op body bytes as sent on the wire (opaque here).
    pub op_body: &'a [u8],
}

/// Generate a fresh challenge nonce from the OS CSPRNG.
pub fn generate_admin_nonce() -> Result<[u8; ADMIN_NONCE_LEN], getrandom::Error> {
    let mut nonce = [0u8; ADMIN_NONCE_LEN];
    getrandom::getrandom(&mut nonce)?;
    Ok(nonce)
}

/// Compute the vault identity from the canonical data_dir bytes. The caller is
/// responsible for canonicalizing the path FIRST (`cortexkit-paths` identity,
/// same as the keychain service derivation) so both sides hash identical bytes.
pub fn vault_id_for_canonical_dir(canonical_dir_bytes: &[u8]) -> [u8; VAULT_ID_LEN] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(b"cortexkit-credentials/vault-id/v1");
    hasher.update(canonical_dir_bytes);
    let digest = hasher.finalize();
    let mut id = [0u8; VAULT_ID_LEN];
    id.copy_from_slice(&digest);
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::MASTER_KEY_LEN;

    fn key(seed: u8) -> MasterKey {
        MasterKey::from_bytes([seed; MASTER_KEY_LEN])
    }

    fn parts<'a>(
        vault_id: &'a [u8; VAULT_ID_LEN],
        key: &MasterKey,
        nonce: &'a [u8; ADMIN_NONCE_LEN],
        op_body: &'a [u8],
    ) -> TranscriptParts<'a> {
        TranscriptParts {
            vault_id,
            key_id: key.key_id(),
            nonce,
            op_body,
        }
    }

    #[test]
    fn sign_verify_round_trip() {
        let mk = key(7);
        let mac_key = AdminMacKey::derive(&mk);
        let vault_id = vault_id_for_canonical_dir(b"/data/vault-a");
        let nonce = [9u8; ADMIN_NONCE_LEN];
        let body = br#"{"v":1,"op":"admin.store","id":"apikey:x"}"#;

        let p = parts(&vault_id, &mk, &nonce, body);
        let tag = mac_key.sign(&p);
        assert!(mac_key.verify(&p, &tag));
    }

    #[test]
    fn any_single_field_change_rejects() {
        let mk = key(7);
        let mac_key = AdminMacKey::derive(&mk);
        let vault_id = vault_id_for_canonical_dir(b"/data/vault-a");
        let nonce = [9u8; ADMIN_NONCE_LEN];
        let body: &[u8] = br#"{"v":1,"op":"admin.store","id":"apikey:x"}"#;
        let tag = mac_key.sign(&parts(&vault_id, &mk, &nonce, body));

        // Different op body (single byte).
        let mut other_body = body.to_vec();
        let flip_at = other_body.len() - 3;
        other_body[flip_at] ^= 1;
        assert!(!mac_key.verify(&parts(&vault_id, &mk, &nonce, &other_body), &tag));

        // Different nonce.
        let other_nonce = [10u8; ADMIN_NONCE_LEN];
        assert!(!mac_key.verify(&parts(&vault_id, &mk, &other_nonce, body), &tag));

        // Different vault.
        let other_vault = vault_id_for_canonical_dir(b"/data/vault-b");
        assert!(!mac_key.verify(&parts(&other_vault, &mk, &nonce, body), &tag));

        // Different master key entirely.
        let other_key = key(8);
        let other_mac = AdminMacKey::derive(&other_key);
        assert!(!other_mac.verify(&parts(&vault_id, &other_key, &nonce, body), &tag));

        // Different key_id under the same MAC key (a lying caller).
        let mut p = parts(&vault_id, &mk, &nonce, body);
        p.key_id = other_key.key_id();
        assert!(!mac_key.verify(&p, &tag));
    }

    #[test]
    fn tag_must_be_exact_length() {
        let mk = key(7);
        let mac_key = AdminMacKey::derive(&mk);
        let vault_id = vault_id_for_canonical_dir(b"/data/vault-a");
        let nonce = [9u8; ADMIN_NONCE_LEN];
        let body: &[u8] = b"x";
        let p = parts(&vault_id, &mk, &nonce, body);
        let tag = mac_key.sign(&p);

        assert!(!mac_key.verify(&p, &tag[..31]), "truncated tag must fail");
        let mut long = tag.to_vec();
        long.push(0);
        assert!(!mac_key.verify(&p, &long), "extended tag must fail");
        assert!(!mac_key.verify(&p, b""), "empty tag must fail");
    }

    /// Length-prefix framing: (body "AB", suffix "C") and (body "A", suffix "BC")
    /// must MAC differently even though the concatenation of all transcript bytes
    /// after the fixed-width fields could otherwise collide. The u32 length
    /// prefix is what prevents boundary-shift splices.
    #[test]
    fn length_prefix_prevents_boundary_shift() {
        let mk = key(7);
        let mac_key = AdminMacKey::derive(&mk);
        let vault_id = vault_id_for_canonical_dir(b"/data/vault-a");
        let nonce = [9u8; ADMIN_NONCE_LEN];

        let tag_ab = mac_key.sign(&parts(&vault_id, &mk, &nonce, b"AB"));
        let tag_a = mac_key.sign(&parts(&vault_id, &mk, &nonce, b"A"));
        assert_ne!(tag_ab, tag_a);
        // A tag for body "A" must not verify body "AB" or "" under any framing.
        assert!(!mac_key.verify(&parts(&vault_id, &mk, &nonce, b"AB"), &tag_a));
        assert!(!mac_key.verify(&parts(&vault_id, &mk, &nonce, b""), &tag_a));
    }

    #[test]
    fn admin_mac_key_differs_from_master_and_is_deterministic() {
        let mk = key(7);
        let a = AdminMacKey::derive(&mk);
        let b = AdminMacKey::derive(&mk);
        // Deterministic derivation (same key -> same MAC behavior)...
        let vault_id = vault_id_for_canonical_dir(b"/d");
        let nonce = [0u8; ADMIN_NONCE_LEN];
        let p1 = parts(&vault_id, &mk, &nonce, b"op");
        let p2 = parts(&vault_id, &mk, &nonce, b"op");
        assert_eq!(a.sign(&p1), b.sign(&p2));
        // ...and the derived key is not the master key bytes.
        assert_ne!(a.0.as_slice(), mk.as_bytes().as_slice());
    }

    #[test]
    fn nonce_generation_is_nontrivial() {
        let a = generate_admin_nonce().expect("csprng");
        let b = generate_admin_nonce().expect("csprng");
        assert_ne!(a, b, "two CSPRNG nonces must differ");
        assert_ne!(a, [0u8; ADMIN_NONCE_LEN]);
    }
}
