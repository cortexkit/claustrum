use super::*;
use crate::agent_secret::{SecretError, MAX_SECRET_JSON_INTEGER, SECRET_ISSUE_SKEW_LIMIT_MS};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::json;

const FP: &str = "11111111111111111111111111111111";
const NOW: i64 = 1_794_355_300_123;

fn envelope() -> ManifestBindingEnvelope {
    ManifestBindingEnvelope {
        v: String::from_utf8(MANIFEST_BINDING_ENVELOPE_V1_TAG.to_vec()).unwrap(),
        proposal_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
        statement_sha256: "a".repeat(64),
        decision: "allow".into(),
        device_fingerprint: FP.into(),
        issued_at_ms: NOW as u64,
    }
}

#[test]
fn manifest_envelope_strict_parse_checks_domain_and_exact_six_fields_before_crypto() {
    let e = envelope();
    let bytes = e.canonical_bytes().unwrap();
    let expected = format!("{{\"decision\":\"allow\",\"device_fingerprint\":\"{FP}\",\"issued_at_ms\":{NOW},\"proposal_id\":\"01ARZ3NDEKTSV4RRFFQ69G5FAV\",\"statement_sha256\":\"{}\",\"v\":\"ck-manifest-binding-envelope/v1\"}}", "a".repeat(64));
    assert_eq!(bytes, expected.as_bytes());
    assert_eq!(
        ManifestBindingEnvelope::parse_canonical(&bytes, FP).unwrap(),
        e
    );
    let value = serde_json::to_value(&e).unwrap();
    for field in [
        "v",
        "proposal_id",
        "statement_sha256",
        "decision",
        "device_fingerprint",
        "issued_at_ms",
    ] {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert_eq!(
            ManifestBindingEnvelope::parse_canonical(&serde_json::to_vec(&missing).unwrap(), FP),
            Err(SecretError::ApprovalInvalid),
            "missing {field}"
        );
        let mut wrong_type = value.clone();
        wrong_type[field] = json!(false);
        assert_eq!(
            ManifestBindingEnvelope::parse_canonical(&serde_json::to_vec(&wrong_type).unwrap(), FP),
            Err(SecretError::ApprovalInvalid),
            "wrong type {field}"
        );
        let duplicated = format!("{{\"{field}\":{},{}", value[field], &expected[1..]);
        assert_eq!(
            ManifestBindingEnvelope::parse_canonical(duplicated.as_bytes(), FP),
            Err(SecretError::ApprovalInvalid),
            "duplicate {field}"
        );
    }
    for (field, bad) in [
        ("v", json!("ck-secret-use-envelope/v1")),
        ("v", json!("ck-manifest-binding-envelope/v2")),
        ("decision", json!("deny")),
        ("extra", json!(true)),
        ("device_fingerprint", json!("2".repeat(32))),
        ("proposal_id", json!("")),
        ("proposal_id", json!("81ARZ3NDEKTSV4RRFFQ69G5FAV")),
        ("proposal_id", json!("01ARZ3NDEKTSV4RRFFQ69G5FAI")),
        ("statement_sha256", json!("A".repeat(64))),
        ("statement_sha256", json!("a".repeat(63))),
        ("issued_at_ms", json!(-1)),
        ("issued_at_ms", json!(1.5)),
        ("issued_at_ms", json!(MAX_SECRET_JSON_INTEGER + 1)),
    ] {
        let mut bad_value = value.clone();
        bad_value[field] = bad;
        assert_eq!(
            ManifestBindingEnvelope::parse_canonical(&serde_json::to_vec(&bad_value).unwrap(), FP),
            Err(SecretError::ApprovalInvalid),
            "bad {field}"
        );
    }
    for issued in [0, MAX_SECRET_JSON_INTEGER] {
        let mut e = e.clone();
        e.issued_at_ms = issued;
        assert_eq!(
            ManifestBindingEnvelope::parse_canonical(&e.canonical_bytes().unwrap(), FP).unwrap(),
            e
        );
    }
    assert_eq!(
        ManifestBindingEnvelope::parse_canonical(format!("{expected}\n").as_bytes(), FP),
        Err(SecretError::ApprovalInvalid)
    );
}

#[test]
fn manifest_envelope_verifies_der_signature_received_bytes_and_both_skew_boundaries() {
    let key = SigningKey::from_bytes((&[7; 32]).into()).unwrap();
    let public = key.verifying_key().to_encoded_point(false);
    let e = envelope();
    let bytes = e.canonical_bytes().unwrap();
    let signature: Signature = key.sign(&bytes);
    for delta in [-SECRET_ISSUE_SKEW_LIMIT_MS, SECRET_ISSUE_SKEW_LIMIT_MS] {
        assert_eq!(
            ManifestBindingEnvelope::verify(
                &bytes,
                signature.to_der().as_bytes(),
                public.as_bytes(),
                FP,
                NOW + delta
            )
            .unwrap(),
            e
        );
    }
    for delta in [
        -SECRET_ISSUE_SKEW_LIMIT_MS - 1,
        SECRET_ISSUE_SKEW_LIMIT_MS + 1,
    ] {
        assert_eq!(
            ManifestBindingEnvelope::verify(
                &bytes,
                signature.to_der().as_bytes(),
                public.as_bytes(),
                FP,
                NOW + delta
            ),
            Err(SecretError::ApprovalInvalid)
        );
    }
    assert_eq!(
        ManifestBindingEnvelope::verify(&bytes, &signature.to_bytes(), public.as_bytes(), FP, NOW),
        Err(SecretError::ApprovalInvalid)
    );
    let mut changed = e.clone();
    changed.issued_at_ms += 1;
    assert_eq!(
        ManifestBindingEnvelope::verify(
            &changed.canonical_bytes().unwrap(),
            signature.to_der().as_bytes(),
            public.as_bytes(),
            FP,
            NOW
        ),
        Err(SecretError::ApprovalInvalid)
    );
}
