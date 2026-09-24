//! Seal one base-mode message to the public half printed by `ck auth mint-kem-key`.
//! Usage: cargo run -p credentials-module --example kem_seal_probe -- <public_key_hex> <plaintext>
use base64::Engine as _;
use serde_json::json;

fn main() {
    let mut args = std::env::args().skip(1);
    let public_hex = args.next().expect("public_key_hex required");
    let plaintext = args.next().expect("plaintext required");
    assert!(args.next().is_none(), "unexpected argument");
    let public: Vec<u8> = public_hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16).expect("hex"))
        .collect();
    assert_eq!(public_hex.len(), 64, "X25519 public key is 32 bytes");
    let info = b"kem-seal-probe";
    let aad = b"";
    let (enc, ciphertext) =
        credentials_core::kem::seal_base(&public, plaintext.as_bytes(), info, aad)
            .expect("seal message");
    let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    println!(
        "{}",
        json!({
            "enc_b64": encode(&enc),
            "ciphertext_b64": encode(&ciphertext),
            "info_b64": encode(info),
            "aad_b64": encode(aad),
        })
    );
}
