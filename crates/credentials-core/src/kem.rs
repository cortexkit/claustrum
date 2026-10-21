//! Fixed RFC 9180 X25519/HKDF-SHA256/ChaCha20-Poly1305 suite: a base-mode receiver for
//! `credential.open`, and an auth-mode sender for `credential.seal` that seals with the
//! vault-held key as the sender's static key so the recipient can tell who sent it.
//! Stored scalars use PKCS#8 v1 PEM (RFC 8410 OID 1.3.101.110).
use crate::signing::key_id_for_public;
use base64::Engine;
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem as _,
    OpModeR, OpModeS, Serializable,
};

type K = X25519HkdfSha256;
const PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
];

/// Generate a new independent private key, for sealing directly into a vault record.
pub fn generate_key() -> Result<String, String> {
    let mut ikm = [0; 32];
    getrandom::getrandom(&mut ikm).map_err(|_| "recipient randomness unavailable".to_string())?;
    let (sk, _) = K::derive_keypair(&ikm);
    let mut der = PREFIX.to_vec();
    der.extend_from_slice(&sk.to_bytes());
    Ok(format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        base64::engine::general_purpose::STANDARD.encode(der)
    ))
}

/// Reject another container or algorithm by name; this diagnostic must not go on the wire.
pub fn parse_pkcs8_pem(pem: &str) -> Result<<K as hpke::Kem>::PrivateKey, String> {
    let text = pem.trim();
    let first = text.lines().next().unwrap_or("").trim();
    if first != "-----BEGIN PRIVATE KEY-----" || !text.ends_with("-----END PRIVATE KEY-----") {
        return Err(format!(
            "expected X25519 PKCS#8 PRIVATE KEY, found {}",
            if first.starts_with("-----BEGIN") {
                first
            } else {
                "no PEM armour"
            }
        ));
    }
    let body: String = text.lines().filter(|s| !s.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|_| "invalid PKCS#8 PEM base64".to_string())?;
    if der.len() != 48 || der[..16] != PREFIX {
        let found = if der.windows(5).any(|s| s == [6, 3, 43, 101, 112]) {
            "Ed25519 (1.3.101.112)"
        } else {
            "unknown algorithm or PKCS#8 version"
        };
        return Err(format!(
            "expected X25519 PKCS#8 (1.3.101.110), found {found}"
        ));
    }
    <<K as hpke::Kem>::PrivateKey as Deserializable>::from_bytes(&der[16..])
        .map_err(|_| "invalid X25519 scalar".to_string())
}

/// Publish the 32-byte public half and the existing Ed25519-derived key identifier.
pub fn public_half(pem: &str) -> Result<(Vec<u8>, String), String> {
    let public = K::sk_to_pk(&parse_pkcs8_pem(pem)?).to_bytes().to_vec();
    let id = key_id_for_public(&public);
    Ok((public, id))
}

/// Set up a new receiver for each request; open only sequence zero.
pub fn open_base(
    pem: &str,
    enc: &[u8],
    ct: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let sk = parse_pkcs8_pem(pem)?;
    let enc = <<K as hpke::Kem>::EncappedKey as Deserializable>::from_bytes(enc)
        .map_err(|_| "invalid encapsulation".to_string())?;
    let mut ctx =
        hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, K>(&OpModeR::Base, &sk, &enc, info)
            .map_err(|_| "receiver setup failed".to_string())?;
    ctx.open(ct, aad)
        .map_err(|_| "HPKE open failed".to_string())
}

// HPKE accepts a rand_core 0.9 RNG; the workspace CSPRNG is getrandom 0.2.
struct SystemRng;
impl hpke::rand_core::RngCore for SystemRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("OS randomness unavailable");
    }
}
impl hpke::rand_core::CryptoRng for SystemRng {}

/// Seal one message to a public recipient with a fresh encapsulation.
pub fn seal_base(
    public: &[u8],
    pt: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let pk = <<K as hpke::Kem>::PublicKey as Deserializable>::from_bytes(public)
        .map_err(|_| "invalid public key".to_string())?;
    let mut rng = SystemRng;
    let (enc, mut ctx) = hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, K, _>(
        &OpModeS::Base,
        &pk,
        info,
        &mut rng,
    )
    .map_err(|_| "sender setup failed".to_string())?;
    let ct = ctx
        .seal(pt, aad)
        .map_err(|_| "HPKE seal failed".to_string())?;
    Ok((enc.to_bytes().to_vec(), ct))
}

/// The largest plaintext `credential.seal` accepts. A push payload is a few hundred
/// bytes; the cap bounds how much work and memory one request can demand, and it is
/// checked before any key material is touched.
pub const MAX_SEAL_PLAINTEXT: usize = 64 * 1024;
/// The largest HPKE `info` (key-schedule context) `credential.seal` accepts.
pub const MAX_SEAL_INFO: usize = 1024;
/// The largest associated data `credential.seal` accepts.
pub const MAX_SEAL_AAD: usize = 1024;
/// An X25519 public key is exactly this many bytes (RFC 7748).
pub const X25519_PUBLIC_KEY_LEN: usize = 32;

/// Why an auth-mode seal was refused. None of these carry key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// The plaintext, info or aad is over its cap.
    TooLarge,
    /// The recipient key is not 32 bytes, or is a low-order point. A low-order point
    /// makes the Diffie-Hellman output all zeros, so the "shared" secret would be a
    /// constant anyone can compute; RFC 9180 section 7.1.4 requires refusing it.
    InvalidRecipient,
    /// The stored sender key is not a usable X25519 PKCS#8 key: vault-side damage, not
    /// a fault in the request.
    UnusableKey,
    /// The AEAD refused to seal. A fresh context seals sequence zero, which cannot
    /// overflow, so this is unreachable in practice and exists only to avoid a panic.
    Failed,
}

/// Check the request bytes `seal_auth` will accept, without touching any key.
///
/// Exposed separately so the daemon can refuse an oversized or malformed request before
/// it authorizes anything or reads the stored key. `seal_auth` runs the same check
/// itself, so a caller that skips this still cannot seal an over-cap request.
pub fn check_seal_inputs(
    recipient_public_key: &[u8],
    plaintext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<(), SealError> {
    if plaintext.len() > MAX_SEAL_PLAINTEXT
        || info.len() > MAX_SEAL_INFO
        || aad.len() > MAX_SEAL_AAD
    {
        return Err(SealError::TooLarge);
    }
    if recipient_public_key.len() != X25519_PUBLIC_KEY_LEN {
        return Err(SealError::InvalidRecipient);
    }
    Ok(())
}

/// Seal one message in RFC 9180 Auth mode (mode 2): the stored key `sender_pem` is the
/// sender's static key skS, `recipient_public_key` is pkR, and every call uses a fresh
/// ephemeral key and a fresh context, so each reply is sequence zero of its own context.
/// Returns `(enc, ciphertext)`.
///
/// Auth mode binds the sender's static key into the shared secret, so a recipient that
/// opens with the sender's public half learns the message came from the holder of this
/// key. This is the only operation that uses the stored key against a caller-chosen
/// public key, and it returns only AEAD output: never the raw Diffie-Hellman value or
/// any derived secret, which would turn the vault into a key-agreement oracle.
pub fn seal_auth(
    sender_pem: &str,
    recipient_public_key: &[u8],
    plaintext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), SealError> {
    seal_auth_with_rng(
        sender_pem,
        recipient_public_key,
        plaintext,
        info,
        aad,
        &mut SystemRng,
    )
}

fn seal_auth_with_rng<R: hpke::rand_core::CryptoRng + hpke::rand_core::RngCore>(
    sender_pem: &str,
    recipient_public_key: &[u8],
    plaintext: &[u8],
    info: &[u8],
    aad: &[u8],
    rng: &mut R,
) -> Result<(Vec<u8>, Vec<u8>), SealError> {
    check_seal_inputs(recipient_public_key, plaintext, info, aad)?;
    let recipient =
        <<K as hpke::Kem>::PublicKey as Deserializable>::from_bytes(recipient_public_key)
            .map_err(|_| SealError::InvalidRecipient)?;
    let sender_secret = parse_pkcs8_pem(sender_pem).map_err(|_| SealError::UnusableKey)?;
    let sender_public = K::sk_to_pk(&sender_secret);
    // The `hpke` crate refuses an all-zero Diffie-Hellman output during encapsulation
    // (its X25519 `dh` returns an error exactly then), and encapsulation can fail for no
    // other reason, so this error means the recipient is a low-order point.
    // `low_order_recipients_are_refused_by_the_hpke_crate` pins that behaviour.
    let (enc, mut context) = hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, K, _>(
        &OpModeS::Auth((sender_secret, sender_public)),
        &recipient,
        info,
        rng,
    )
    .map_err(|_| SealError::InvalidRecipient)?;
    let ciphertext = context
        .seal(plaintext, aad)
        .map_err(|_| SealError::Failed)?;
    Ok((enc.to_bytes().to_vec(), ciphertext))
}

/// Hands out exactly one fixed 32-byte draw, so a test can choose the ephemeral key.
/// HPKE derives the ephemeral key pair from one Nsk-byte draw (`DeriveKeyPair(ikmE)`),
/// which is how RFC 9180's published vectors fix it.
#[cfg(any(test, feature = "test-support"))]
struct FixedEphemeralRng {
    ikm: [u8; 32],
    used: bool,
}

#[cfg(any(test, feature = "test-support"))]
impl hpke::rand_core::RngCore for FixedEphemeralRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!("the fixed ephemeral source serves one 32-byte draw only")
    }
    fn next_u64(&mut self) -> u64 {
        unimplemented!("the fixed ephemeral source serves one 32-byte draw only")
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // A second draw, or one of another size, means the library changed how it
        // derives the ephemeral key, and a vector comparison would then be meaningless.
        assert!(!self.used && dest.len() == 32, "unexpected ephemeral draw");
        dest.copy_from_slice(&self.ikm);
        self.used = true;
    }
}

#[cfg(any(test, feature = "test-support"))]
impl hpke::rand_core::CryptoRng for FixedEphemeralRng {}

/// Test-only: `seal_auth` with the ephemeral key derived from `ikm_e` instead of fresh
/// randomness, so a test can reproduce a published vector or a pinned wire sample
/// byte for byte. Never compiled into a release build.
#[cfg(any(test, feature = "test-support"))]
pub fn seal_auth_with_ephemeral_ikm(
    sender_pem: &str,
    recipient_public_key: &[u8],
    plaintext: &[u8],
    info: &[u8],
    aad: &[u8],
    ikm_e: [u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), SealError> {
    seal_auth_with_rng(
        sender_pem,
        recipient_public_key,
        plaintext,
        info,
        aad,
        &mut FixedEphemeralRng {
            ikm: ikm_e,
            used: false,
        },
    )
}

/// Test-only: an RFC 9180 Auth-mode receiver, so tests can show what `seal_auth`
/// produced opens for the intended recipient under the sender's public half.
#[cfg(any(test, feature = "test-support"))]
pub fn open_auth(
    recipient_pem: &str,
    sender_public_key: &[u8],
    enc: &[u8],
    ciphertext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let recipient = parse_pkcs8_pem(recipient_pem)?;
    let sender = <<K as hpke::Kem>::PublicKey as Deserializable>::from_bytes(sender_public_key)
        .map_err(|_| "invalid sender public key".to_string())?;
    let enc = <<K as hpke::Kem>::EncappedKey as Deserializable>::from_bytes(enc)
        .map_err(|_| "invalid encapsulation".to_string())?;
    let mut context = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, K>(
        &OpModeR::Auth(sender),
        &recipient,
        &enc,
        info,
    )
    .map_err(|_| "receiver setup failed".to_string())?;
    context
        .open(ciphertext, aad)
        .map_err(|_| "HPKE open failed".to_string())
}

/// Test-only: wrap a raw 32-byte X25519 scalar in the PKCS#8 PEM the vault stores, so a
/// test can install a known key (a published vector's, or a fixed synthetic one).
#[cfg(any(test, feature = "test-support"))]
pub fn pem_from_scalar(scalar: &[u8; 32]) -> String {
    let mut der = PREFIX.to_vec();
    der.extend_from_slice(scalar);
    format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        base64::engine::general_purpose::STANDARD.encode(der)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    fn bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
    #[test]
    fn rfc9180_a2_opens_every_published_encryption_in_one_context() {
        // Source: https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/master/test-vectors.json
        // mode 0, KEM 32, KDF 1, AEAD 3 (RFC 9180 Appendix A.2).
        let v: Value =
            serde_json::from_str(include_str!("../tests/fixtures/rfc9180-a2-base.json")).unwrap();
        assert_eq!(
            (
                v["mode"].as_u64(),
                v["kem_id"].as_u64(),
                v["kdf_id"].as_u64(),
                v["aead_id"].as_u64()
            ),
            (Some(0), Some(32), Some(1), Some(3))
        );
        let get = |field: &str| bytes(v[field].as_str().unwrap());
        let sk =
            <<K as hpke::Kem>::PrivateKey as Deserializable>::from_bytes(&get("skRm")).unwrap();
        assert_eq!(K::sk_to_pk(&sk).to_bytes().as_slice(), get("pkRm"));
        let enc =
            <<K as hpke::Kem>::EncappedKey as Deserializable>::from_bytes(&get("enc")).unwrap();
        assert_eq!(enc.to_bytes().as_slice(), get("enc"));
        let mut receiver = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, K>(
            &OpModeR::Base,
            &sk,
            &enc,
            &get("info"),
        )
        .unwrap();
        let encryptions = v["encryptions"].as_array().unwrap();
        assert_eq!(
            encryptions.len(),
            257,
            "the vendored published set includes seq 0..256"
        );
        for (seq, encryption) in encryptions.iter().enumerate() {
            let aad = bytes(encryption["aad"].as_str().unwrap());
            let ct = bytes(encryption["ct"].as_str().unwrap());
            let pt = bytes(encryption["pt"].as_str().unwrap());
            assert_eq!(
                receiver.open(&ct, &aad).unwrap(),
                pt,
                "published sequence {seq}"
            );
        }
    }
    #[test]
    fn generated_recipient_opens_two_fresh_sequence_zero_requests() {
        let pem = generate_key().unwrap();
        let (public, id) = public_half(&pem).unwrap();
        assert_eq!(public.len(), 32);
        assert_eq!(id, key_id_for_public(&public));
        let (enc, ct) = seal_base(&public, b"hello", b"info", b"aad").unwrap();
        for _ in 0..2 {
            assert_eq!(
                open_base(&pem, &enc, &ct, b"info", b"aad").unwrap(),
                b"hello"
            );
        }
        assert!(open_base(&pem, &enc, &ct, b"wrong", b"aad").is_err());
    }
    #[test]
    fn signing_decoder_uses_padded_strict_standard_base64() {
        assert!(include_str!("../../credentials-module/src/read_surface.rs")
            .contains("let payload = base64::engine::general_purpose::STANDARD"));
        let decoder = base64::engine::general_purpose::STANDARD;
        assert_eq!(decoder.decode("YQ==").unwrap(), b"a");
        assert!(decoder.decode("YQ").is_err(), "unpadded form must refuse");
        assert!(decoder.decode("YQ===").is_err(), "over-padding must refuse");
        assert!(
            decoder.decode("Y_==").is_err(),
            "URL-safe alphabet must refuse"
        );
        assert!(
            decoder.decode("YR==").is_err(),
            "nonzero trailing bits must refuse"
        );
    }

    #[test]
    fn sender_helper_has_no_route_dispatch_or_cli_verb() {
        let daemon = include_str!("../../credentials-module/src/main.rs");
        let cli = include_str!("../../credentials-module/src/bin/credentials_cli.rs");
        let helper = "seal_base";
        assert!(include_str!("kem.rs").contains("pub fn seal_base("));
        for (surface, source) in [("route dispatch", daemon), ("CLI verbs", cli)] {
            assert!(
                !source.contains(&format!("kem::{helper}")),
                "{surface} cannot exercise the public sender helper"
            );
            assert!(
                !source.contains(&format!("::{helper}(")),
                "{surface} cannot call the sender helper via a renamed module"
            );
        }
    }
    #[test]
    fn a_wrong_container_names_what_was_found() {
        assert!(parse_pkcs8_pem("-----BEGIN RSA PRIVATE KEY-----")
            .err()
            .unwrap()
            .contains("RSA PRIVATE KEY"));
        let mut der = PREFIX.to_vec();
        der[11] = 0x70;
        der.extend_from_slice(&[1; 32]);
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            base64::engine::general_purpose::STANDARD.encode(der)
        );
        assert!(parse_pkcs8_pem(&pem).err().unwrap().contains("Ed25519"));
    }

    fn scalar(hex: &str) -> [u8; 32] {
        bytes(hex).try_into().unwrap()
    }

    #[test]
    fn rfc9180_a2_auth_vector_seals_byte_exact_with_the_published_ephemeral_key() {
        // Source: https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/master/test-vectors.json
        // mode 2 (Auth), KEM 32, KDF 1, AEAD 3 (RFC 9180 Appendix A.2.3), copied verbatim
        // from that file (sha256 61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6).
        let v: Value =
            serde_json::from_str(include_str!("../tests/fixtures/rfc9180-a2-auth.json")).unwrap();
        assert_eq!(
            (
                v["mode"].as_u64(),
                v["kem_id"].as_u64(),
                v["kdf_id"].as_u64(),
                v["aead_id"].as_u64()
            ),
            (Some(2), Some(32), Some(1), Some(3))
        );
        let get = |field: &str| bytes(v[field].as_str().unwrap());
        let sender_pem = pem_from_scalar(&scalar(v["skSm"].as_str().unwrap()));
        let recipient_pem = pem_from_scalar(&scalar(v["skRm"].as_str().unwrap()));
        // The stored-key path derives the published sender public half.
        assert_eq!(public_half(&sender_pem).unwrap().0, get("pkSm"));
        assert_eq!(public_half(&recipient_pem).unwrap().0, get("pkRm"));

        // Each vault seal is sequence zero of a fresh context, so it must reproduce the
        // first published encryption exactly when given the published ephemeral seed.
        let first = &v["encryptions"][0];
        let (aad, ct, pt) = (
            bytes(first["aad"].as_str().unwrap()),
            bytes(first["ct"].as_str().unwrap()),
            bytes(first["pt"].as_str().unwrap()),
        );
        let (enc, sealed) = seal_auth_with_ephemeral_ikm(
            &sender_pem,
            &get("pkRm"),
            &pt,
            &get("info"),
            &aad,
            scalar(v["ikmE"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(enc, get("enc"), "published enc");
        assert_eq!(sealed, ct, "published sequence-zero ciphertext");

        // An Auth-mode receiver holding skR and the sender's public half opens it, and
        // opens every published encryption in one context, so the receiver used by the
        // other tests is itself checked against the vector.
        assert_eq!(
            open_auth(
                &recipient_pem,
                &get("pkSm"),
                &enc,
                &sealed,
                &get("info"),
                &aad
            )
            .unwrap(),
            pt
        );
        let sender_public =
            <<K as hpke::Kem>::PublicKey as Deserializable>::from_bytes(&get("pkSm")).unwrap();
        let published_enc =
            <<K as hpke::Kem>::EncappedKey as Deserializable>::from_bytes(&get("enc")).unwrap();
        let mut receiver = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, K>(
            &OpModeR::Auth(sender_public),
            &parse_pkcs8_pem(&recipient_pem).unwrap(),
            &published_enc,
            &get("info"),
        )
        .unwrap();
        let encryptions = v["encryptions"].as_array().unwrap();
        assert_eq!(
            encryptions.len(),
            257,
            "the vendored set includes seq 0..256"
        );
        for (seq, encryption) in encryptions.iter().enumerate() {
            let opened = receiver
                .open(
                    &bytes(encryption["ct"].as_str().unwrap()),
                    &bytes(encryption["aad"].as_str().unwrap()),
                )
                .unwrap();
            assert_eq!(
                opened,
                bytes(encryption["pt"].as_str().unwrap()),
                "published sequence {seq}"
            );
        }
    }

    #[test]
    fn auth_seal_opens_only_under_the_vault_sender_and_never_in_base_mode() {
        let sender = generate_key().unwrap();
        let (sender_public, _) = public_half(&sender).unwrap();
        let recipient = generate_key().unwrap();
        let (recipient_public, _) = public_half(&recipient).unwrap();
        let (enc, ct) = seal_auth(&sender, &recipient_public, b"push", b"info", b"aad").unwrap();
        assert_eq!(
            open_auth(&recipient, &sender_public, &enc, &ct, b"info", b"aad").unwrap(),
            b"push"
        );
        // Another sender's public half does not open it: this is what lets the phone
        // tell a push from this vault apart from one sealed by anyone else.
        let (other_public, _) = public_half(&generate_key().unwrap()).unwrap();
        assert!(open_auth(&recipient, &other_public, &enc, &ct, b"info", b"aad").is_err());
        assert!(open_base(&recipient, &enc, &ct, b"info", b"aad").is_err());
        // A fresh ephemeral key per call: two seals of the same input differ.
        let (enc_again, ct_again) =
            seal_auth(&sender, &recipient_public, b"push", b"info", b"aad").unwrap();
        assert_ne!(enc, enc_again);
        assert_ne!(ct, ct_again);
    }

    #[test]
    fn low_order_recipients_are_refused_by_the_hpke_crate() {
        // Curve25519 points of small order, plus non-canonical encodings of them. With a
        // clamped scalar every one gives an all-zero X25519 output. Hex from the
        // well-known blocklist (libsodium `has_small_order`, Bernstein's curve25519 page).
        let low_order = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ];
        let sender = generate_key().unwrap();
        for point in low_order {
            assert_eq!(
                seal_auth(&sender, &bytes(point), b"push", b"", b""),
                Err(SealError::InvalidRecipient),
                "{point}"
            );
            // The refusal comes from the crate's all-zero check, which runs in every
            // mode: base-mode encapsulation to the same point is refused too.
            assert!(
                seal_base(&bytes(point), b"push", b"", b"").is_err(),
                "{point}"
            );
        }
        // Control: an ordinary recipient through the same call seals.
        let (recipient_public, _) = public_half(&generate_key().unwrap()).unwrap();
        assert!(seal_auth(&sender, &recipient_public, b"push", b"", b"").is_ok());
    }

    #[test]
    fn seal_caps_accept_the_cap_and_refuse_one_byte_over() {
        let sender = generate_key().unwrap();
        let recipient = generate_key().unwrap();
        let (recipient_public, _) = public_half(&recipient).unwrap();
        let (sender_public, _) = public_half(&sender).unwrap();
        let at = |n: usize| vec![7u8; n];
        // Each field exactly at its cap seals and opens; the others stay small so the
        // refusal below can only come from the field under test.
        for (pt, info, aad) in [
            (at(MAX_SEAL_PLAINTEXT), at(0), at(0)),
            (at(0), at(MAX_SEAL_INFO), at(0)),
            (at(0), at(0), at(MAX_SEAL_AAD)),
        ] {
            let (enc, ct) = seal_auth(&sender, &recipient_public, &pt, &info, &aad).unwrap();
            assert_eq!(
                open_auth(&recipient, &sender_public, &enc, &ct, &info, &aad).unwrap(),
                pt
            );
            assert_eq!(
                check_seal_inputs(&recipient_public, &pt, &info, &aad),
                Ok(())
            );
        }
        for (pt, info, aad) in [
            (at(MAX_SEAL_PLAINTEXT + 1), at(0), at(0)),
            (at(0), at(MAX_SEAL_INFO + 1), at(0)),
            (at(0), at(0), at(MAX_SEAL_AAD + 1)),
        ] {
            assert_eq!(
                seal_auth(&sender, &recipient_public, &pt, &info, &aad),
                Err(SealError::TooLarge)
            );
            assert_eq!(
                check_seal_inputs(&recipient_public, &pt, &info, &aad),
                Err(SealError::TooLarge)
            );
        }
        // The recipient key is exactly 32 bytes: one short and one long are refused.
        let doubled = recipient_public.repeat(2);
        for len in [X25519_PUBLIC_KEY_LEN - 1, X25519_PUBLIC_KEY_LEN + 1] {
            assert_eq!(
                seal_auth(&sender, &doubled[..len], b"", b"", b""),
                Err(SealError::InvalidRecipient),
                "{len}-byte recipient"
            );
        }
    }

    #[test]
    fn an_unusable_stored_sender_key_is_reported_as_the_vault_fault_it_is() {
        let (recipient_public, _) = public_half(&generate_key().unwrap()).unwrap();
        assert_eq!(
            seal_auth("not a key", &recipient_public, b"push", b"", b""),
            Err(SealError::UnusableKey)
        );
    }
}
