//! Fixed RFC 9180 base-mode X25519/HKDF-SHA256/ChaCha20-Poly1305 suite.
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
}
