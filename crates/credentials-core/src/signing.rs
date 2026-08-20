//! Ed25519 signing performed INSIDE the vault, so the private key never leaves the
//! daemon that holds it.
//!
//! # Why the vault signs rather than serving the key
//!
//! This module serves bytes; that is what a custody module does. The precedent for
//! serving a signing key was APNs, where it was FORCED — the signer is an edge Worker
//! with no route to a daemon that has zero inbound network surface, so the key had to
//! travel. **That constraint does not apply to a signer on this machine holding a
//! route**, and the shape outlived the reason until someone asked what forced it.
//!
//! Signing here buys three things:
//!
//! - **No second-process window.** Serving puts the private key in another process's
//!   memory for the duration of a signing.
//! - **Zero new authority.** A handle that can READ a key is already signing power —
//!   whoever holds the bytes can sign with any Ed25519 library. This exercises the
//!   same privilege without copying the material.
//! - **An approval can be a precondition rather than a correlation.** When the vault
//!   performs the signature it can append the approval and the signature in one
//!   transaction, so "no signature exists without its approval" becomes a property
//!   rather than a convention.
//!
//! # The fence
//!
//! Signing is served ONLY for [`CredentialKind::SigningKey`] records. Without that
//! restriction a capability handle for an API key could produce signatures under it
//! and this module would be a general signing oracle over every stored secret.

use base64::Engine;
use ring::signature::{Ed25519KeyPair, KeyPair};

/// Why a signing request was refused. Every variant is fail-closed and carries no
/// key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// The stored payload is not a PKCS#8 Ed25519 private key.
    ///
    /// Names what was FOUND rather than only what was wanted, because a key deposited
    /// in the wrong container is the single most likely cause and a refusal that only
    /// says "bad key" sends an operator to look at the wrong thing. This repo already
    /// paid for that lesson twice: GitHub issues PKCS#1 where the parser wanted
    /// PKCS#8, and Apple issues SEC1 where p256 quoted the OID it EXPECTED rather than
    /// the one it found.
    UnusableKey(String),
    /// The request asked to sign more bytes than the cap allows.
    TooLarge { len: usize, cap: usize },
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignError::UnusableKey(what) => write!(f, "unusable signing key: {what}"),
            SignError::TooLarge { len, cap } => {
                write!(f, "payload {len} bytes exceeds the {cap}-byte signing cap")
            }
        }
    }
}

/// Largest payload the vault will sign in one request.
///
/// A signing request is authenticated by a capability handle and costs CPU, so an
/// unbounded size is a cheap way to make the daemon do arbitrary work on the serve
/// path. 1 MiB is far above any manifest this exists for (the initial routing
/// manifest is under 4 KiB) and far below anything that would stall the loop.
pub const MAX_SIGN_PAYLOAD: usize = 1024 * 1024;

/// A signature plus the id of the key that produced it.
#[derive(Debug, Clone)]
pub struct Signature {
    /// Detached Ed25519 signature, base64 (standard alphabet, padded).
    pub signature_b64: String,
    /// First 8 bytes of SHA-256 over the public key, hex.
    ///
    /// DERIVED rather than assigned, so any holder of the public half can recompute
    /// it and check an envelope's claim. A date-based or operator-chosen id cannot be
    /// verified against the key it names.
    pub key_id: String,
}

/// Parse a PKCS#8 Ed25519 private key out of PEM armour.
///
/// Accepts the `PRIVATE KEY` armour that PKCS#8 uses. Deliberately does NOT accept
/// `OPENSSH PRIVATE KEY` or bare base64: a wrong-container key must be refused with a
/// message naming what it was, not coerced.
fn parse_pkcs8_pem(pem: &str) -> Result<Ed25519KeyPair, SignError> {
    let trimmed = pem.trim();
    let first_line = trimmed.lines().next().unwrap_or("").trim();
    if !first_line.starts_with("-----BEGIN PRIVATE KEY-----") {
        return Err(SignError::UnusableKey(format!(
            "expected PKCS#8 PEM (-----BEGIN PRIVATE KEY-----), found {}",
            if first_line.starts_with("-----BEGIN") {
                first_line
            } else {
                "no PEM armour"
            }
        )));
    }
    let body: String = trimmed
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| SignError::UnusableKey(format!("PEM body is not valid base64: {e}")))?;
    Ed25519KeyPair::from_pkcs8(&der).map_err(|_| {
        SignError::UnusableKey(format!(
            "not a PKCS#8 Ed25519 key ({} DER bytes decoded)",
            der.len()
        ))
    })
}

/// Sign `payload` with the Ed25519 key stored as PKCS#8 PEM in `key_pem`.
///
/// The key material exists only for the duration of this call and is dropped on
/// return; nothing here writes it anywhere or includes it in an error.
pub fn sign_ed25519(key_pem: &str, payload: &[u8]) -> Result<Signature, SignError> {
    if payload.len() > MAX_SIGN_PAYLOAD {
        return Err(SignError::TooLarge {
            len: payload.len(),
            cap: MAX_SIGN_PAYLOAD,
        });
    }
    let kp = parse_pkcs8_pem(key_pem)?;
    let sig = kp.sign(payload);
    let public = kp.public_key().as_ref();
    let digest = ring::digest::digest(&ring::digest::SHA256, public);
    let key_id = hex_lower(&digest.as_ref()[..8]);
    Ok(Signature {
        signature_b64: base64::engine::general_purpose::STANDARD.encode(sig.as_ref()),
        key_id,
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{UnparsedPublicKey, ED25519};

    fn a_key() -> (String, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate");
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse");
        let public = kp.public_key().as_ref().to_vec();
        let b64 = base64::engine::general_purpose::STANDARD.encode(pkcs8.as_ref());
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).expect("ascii"));
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----");
        (pem, public)
    }

    /// The signature must verify under the key's own public half, and the key_id must
    /// be recomputable from that public half alone.
    ///
    /// Both halves matter: a signature nobody can verify is indistinguishable from a
    /// correct one until a consumer tries, and an id a holder cannot recompute cannot
    /// be checked against the key it names -- which is the entire reason it is derived
    /// rather than assigned.
    #[test]
    fn a_signature_verifies_under_the_public_half_and_the_key_id_is_recomputable() {
        let (pem, public) = a_key();
        let sig = sign_ed25519(&pem, b"the exact published bytes").expect("sign");

        let raw = base64::engine::general_purpose::STANDARD
            .decode(&sig.signature_b64)
            .expect("signature is base64");
        UnparsedPublicKey::new(&ED25519, &public)
            .verify(b"the exact published bytes", &raw)
            .expect("the signature must verify under this key's own public half");

        let expect = hex_lower(&ring::digest::digest(&ring::digest::SHA256, &public).as_ref()[..8]);
        assert_eq!(
            sig.key_id, expect,
            "key_id must be derivable from the public key by a holder who has only that"
        );
    }

    /// A signature over one payload must NOT verify over another.
    ///
    /// Guards the arm a refactor can quietly break: signing a constant, a hash of the
    /// payload, or an empty slice all produce a valid-looking signature that passes the
    /// test above.
    #[test]
    fn a_signature_does_not_verify_over_different_bytes() {
        let (pem, public) = a_key();
        let sig = sign_ed25519(&pem, b"manifest version 1").expect("sign");
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&sig.signature_b64)
            .expect("base64");
        assert!(
            UnparsedPublicKey::new(&ED25519, &public)
                .verify(b"manifest version 2", &raw)
                .is_err(),
            "a signature that verifies over bytes it did not cover signs nothing"
        );
    }

    /// A wrong-container key is refused with a message naming WHAT WAS FOUND.
    #[test]
    fn a_wrong_container_key_is_refused_by_name() {
        let err = sign_ed25519(
            "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----",
            b"x",
        )
        .expect_err("PKCS#1 armour must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("RSA PRIVATE KEY"),
            "the refusal must name the armour found, got: {msg}"
        );
        let err = sign_ed25519("not a pem at all", b"x").expect_err("garbage must be refused");
        assert!(
            err.to_string().contains("no PEM armour"),
            "a payload with no armour must say so"
        );
    }

    /// The size cap refuses at the boundary rather than signing unbounded work.
    #[test]
    fn the_signing_cap_refuses_one_byte_over_and_accepts_the_cap() {
        let (pem, _) = a_key();
        let at_cap = vec![0u8; MAX_SIGN_PAYLOAD];
        assert!(
            sign_ed25519(&pem, &at_cap).is_ok(),
            "the cap itself must sign"
        );
        let over = vec![0u8; MAX_SIGN_PAYLOAD + 1];
        assert!(
            matches!(sign_ed25519(&pem, &over), Err(SignError::TooLarge { .. })),
            "one byte over the cap must refuse"
        );
    }
}
