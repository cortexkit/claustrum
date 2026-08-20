//! Prove this vault's signer against the CONSUMER's fixture: their bytes, their key,
//! their expected signature.
//!
//! # Why this test exists in this shape
//!
//! Every other signing test in this repo uses a key this repo generated. That is fine
//! for behaviour and useless for CONTRACT, because a locally produced artifact agrees
//! with whatever the local parser expects, by construction. This repo has shipped that
//! defect twice — a parser demanding PKCS#8 while GitHub issues PKCS#1, and an APNs
//! path assuming PKCS#8 while Apple issues SEC1 — and both times every test was green.
//!
//! Writing this test found the third instance before it shipped: the consumer's dev key
//! is a raw seed, which wraps as PKCS#8 **v1**, and the signer accepted only **v2**
//! because `ring` — the thing generating every local test key — emits v2. `openssl
//! genpkey -algorithm ed25519` emits v1, so an operator-generated signing key would have
//! deposited cleanly and failed at first use.
//!
//! The fixtures are VENDORED with provenance (see `fixtures/gh_shim/VENDORED.md`) rather
//! than read from a sibling checkout, so the proof runs anywhere rather than only on the
//! machine where both repos happen to sit side by side.

use base64::Engine;

/// PKCS#8 v1 prefix for an Ed25519 private key: fixed 16 bytes, then the 32-byte seed.
const PKCS8_V1_ED25519_PREFIX: &str = "302e020100300506032b657004220420";

/// The consumer's published dev seed (RFC 8032 §7.1 test vector 1).
const DEV_SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

fn hex_bytes(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).expect("hex"))
        .collect()
}

fn pem_wrap(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("ascii"));
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----");
    pem
}

fn fixture(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/gh_shim")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("vendored fixture {}: {e}", p.display()))
}

/// This signer reproduces the consumer's expected signature byte for byte.
///
/// If this fails, the signer must NOT be used to mint or sign against a production
/// trust root: a signature that does not match the producer's own vector is one their
/// verifier will refuse, and discovering that after a root is compiled into a release
/// costs a key rotation rather than a code fix.
#[test]
fn the_signer_reproduces_the_consumers_expected_signature() {
    let envelope: serde_json::Value =
        serde_json::from_slice(&fixture("signed-envelope-v2.json")).expect("envelope parses");
    let manifest_bytes = envelope["manifest_bytes"]
        .as_str()
        .expect("envelope carries manifest_bytes");
    let expected_sig = envelope["signature"]
        .as_str()
        .expect("envelope carries a signature");

    let mut der = hex_bytes(PKCS8_V1_ED25519_PREFIX);
    der.extend_from_slice(&hex_bytes(DEV_SEED_HEX));

    let produced =
        credentials_core::signing::sign_ed25519(&pem_wrap(&der), manifest_bytes.as_bytes())
            .expect("the consumer's dev key must sign -- a v1 seed key is the common case");

    assert_eq!(
        produced.signature_b64, expected_sig,
        "signature disagrees with the producer's own vector; this signer must not sign \
         against a production root until it matches"
    );
}

/// The signed bytes are the manifest FILE's bytes, not a re-serialization of them.
///
/// Pins the property the whole envelope design rests on: there is no canonicalization
/// step, so the signature covers exactly what was published. If these ever diverged, a
/// signer could produce a signature over bytes nobody distributes — valid in isolation
/// and refused by every verifier that fetched the real file.
#[test]
fn the_envelope_carries_the_manifest_file_verbatim() {
    let envelope: serde_json::Value =
        serde_json::from_slice(&fixture("signed-envelope-v2.json")).expect("envelope parses");
    let carried = envelope["manifest_bytes"].as_str().expect("manifest_bytes");
    let on_disk = String::from_utf8(fixture("initial-manifest-v1.json")).expect("utf-8");

    assert_eq!(
        carried, on_disk,
        "the envelope's manifest_bytes must be the published file verbatim -- any \
         difference means the signature covers something nobody distributes"
    );
}
