//! The exact signed bytes used by manifest reporters and the Home collector.

use base64::{engine::general_purpose::STANDARD, Engine};
use credentials_core::{
    hub_counters::HubReportSeq,
    signing::{key_id_for_public, sign_ed25519},
    store::{GhManifestVerdict, HubOwnReport, StoreOpError},
};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::hub_binding::HubBinding;
use crate::manifest_active_report::valid_manifest_hash;

const MANIFEST_DOMAIN: &[u8] = b"ck-vault-hub/manifest-active/v1\0";
const REPORTED_INVALID: &str = "reported_invalid";
// The hub's limit. All generated fields have fixed-size bounds well below it.
const MAX_HUB_MANIFEST_VALUE_BYTES: usize = 16 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    v: u8,
    body: String,
    signature_b64: String,
    key_id: String,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Body {
    pub(super) r#box: String,
    pub(super) member: String,
    pub(super) version: i64,
    pub(super) manifest_sha256: String,
    pub(super) verdict: GhManifestVerdict,
    // Value rather than Option: this field is required even when it is null.
    pub(super) reason: Value,
    pub(super) seq: HubReportSeq,
}

fn public_reason(verdict: GhManifestVerdict) -> Value {
    match verdict {
        GhManifestVerdict::Valid => Value::Null,
        GhManifestVerdict::Invalid => Value::String(REPORTED_INVALID.into()),
    }
}

fn signing_input(body: &str) -> Vec<u8> {
    [MANIFEST_DOMAIN, body.as_bytes()].concat()
}

pub(super) fn seal(
    report: &HubOwnReport,
    box_id: &str,
    member: &str,
    seq: HubReportSeq,
    pem: &str,
) -> Result<Vec<u8>, StoreOpError> {
    let body = serde_json::to_string(&Body {
        r#box: box_id.into(),
        member: member.into(),
        version: report.version,
        manifest_sha256: report.payload_sha256.clone(),
        verdict: report.verdict,
        reason: public_reason(report.verdict),
        seq,
    })
    .map_err(|_| StoreOpError::Encode("hub manifest body".into()))?;
    let sig = sign_ed25519(pem, &signing_input(&body))
        .map_err(|_| StoreOpError::Encode("hub manifest signing key".into()))?;
    let bytes = serde_json::to_vec(&Envelope {
        v: 1,
        body,
        signature_b64: sig.signature_b64,
        key_id: sig.key_id,
    })
    .map_err(|_| StoreOpError::Encode("hub manifest envelope".into()))?;
    if bytes.len() > MAX_HUB_MANIFEST_VALUE_BYTES {
        return Err(StoreOpError::Encode(
            "hub manifest envelope exceeds bucket limit".into(),
        ));
    }
    Ok(bytes)
}

pub(super) fn matches_report(
    bytes: &[u8],
    report: &HubOwnReport,
    box_id: &str,
    member: &str,
    key_id: &str,
) -> bool {
    let Some((envelope, body)) = decode(bytes) else {
        return false;
    };
    envelope.key_id == key_id
        && body.r#box == box_id
        && body.member == member
        && body.version == report.version
        && body.manifest_sha256 == report.payload_sha256
        && body.verdict == report.verdict
        && body.reason == public_reason(report.verdict)
}

/// The sequence of a value this vault signed for `box_id` with the key `key_id`,
/// read from its header without checking the signature.
pub(super) fn published_seq(
    bytes: &[u8],
    box_id: &str,
    member: &str,
    key_id: &str,
) -> Option<HubReportSeq> {
    let (envelope, body) = decode(bytes)?;
    (envelope.key_id == key_id && body.r#box == box_id && body.member == member).then_some(body.seq)
}

fn decode(bytes: &[u8]) -> Option<(Envelope, Body)> {
    if bytes.len() > MAX_HUB_MANIFEST_VALUE_BYTES {
        return None;
    }
    let envelope: Envelope = serde_json::from_slice(bytes).ok()?;
    let body: Body = serde_json::from_str(&envelope.body).ok()?;
    (envelope.v == 1
        && body.version > 0
        && valid_manifest_hash(&body.manifest_sha256)
        && body.reason == public_reason(body.verdict))
    .then_some((envelope, body))
}

pub(super) fn verify(bytes: &[u8], binding: &HubBinding) -> Option<Body> {
    let (envelope, body) = decode(bytes)?;
    let key = binding.fleet_record_ed25519.as_ref()?;
    if body.r#box != binding.box_id
        || body.member != binding.member_id
        || envelope.key_id != key_id_for_public(key)
    {
        return None;
    }
    let signature = STANDARD.decode(envelope.signature_b64).ok()?;
    UnparsedPublicKey::new(&ED25519, key)
        .verify(&signing_input(&envelope.body), &signature)
        .ok()?;
    Some(body)
}
