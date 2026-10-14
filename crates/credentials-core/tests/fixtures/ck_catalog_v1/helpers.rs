use base64::Engine as _;
use serde_json::Value;

pub const RECORD_JSON: &[u8] = include_bytes!("record.json");

pub fn fixture() -> Value {
    serde_json::from_slice(RECORD_JSON).expect("published catalog record vectors")
}

pub fn bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex must contain whole bytes");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("fixture hex"))
        .collect()
}

pub fn trusted_key_pem(vectors: &Value) -> String {
    let trusted = &vectors["keys"]["trusted"];
    assert!(trusted["WARNING"].as_str().unwrap().contains("TEST-ONLY"));
    let seed = bytes(trusted["seed_hex"].as_str().unwrap());
    assert_eq!(seed.len(), 32, "Ed25519 seed length");
    // RFC 8410 PKCS#8 v1 wraps the raw Ed25519 seed in a nested OCTET STRING.
    // Load the published test key from the fixture, never from another literal.
    let mut der = bytes("302e020100300506032b657004220420");
    der.extend_from_slice(&seed);
    format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    )
}
