//! Signed consent uses a closed JSON vocabulary and canonical bytes, not JSON equivalence.
use super::{SecretError, USE_ENVELOPE_TAG};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const MAX_ENVELOPE_ITEMS: usize = 16;
pub const SECRET_ISSUE_SKEW_LIMIT_MS: i64 = 120_000;
pub const MAX_SECRET_JSON_INTEGER: u64 = (1 << 53) - 1;

pub fn approval_statement(
    id: &str,
    member: &str,
    incarnation: &str,
    call: &super::SecretUse,
    scope: &super::SecretScope,
    expiry: i64,
) -> serde_json::Value {
    use serde_json::json;
    let use_scope = match scope {
        super::SecretScope::ApiKey {
            host,
            path_prefix,
            location,
        } => {
            json!({"host":host,"path_prefix":path_prefix.as_deref().unwrap_or(""),"location":location})
        }
        super::SecretScope::SiteLogin { origin } => json!({"origin":origin}),
    };
    json!({"v":"ck-secret-use-statement/v1","request_id":id,"member_id":member,"scope":{"owner":call.scope.owner,"kind":call.scope.kind,"ref":call.scope.scope_ref,"epoch":call.scope.epoch},"agent_id":call.agent_id,"coverage":call.coverage,"secret":{"name":call.name,"kind":scope.kind(),"incarnation":incarnation},"use":use_scope,"durations":if call.coverage=="agent_and_workers" {vec!["permanent"]}else{vec!["once","hour","session","permanent"]},"request_expires_at_ms":expiry})
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowIdentity {
    pub flow_id: String,
    pub version: u64,
    pub code_hash: String,
    pub install_id: String,
}

impl FlowIdentity {
    pub fn validate(&self) -> Result<(), super::ValidationError> {
        if self.flow_id.is_empty()
            || !(1..=MAX_SECRET_JSON_INTEGER).contains(&self.version)
            || self.code_hash.len() != 64
            || !self
                .code_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !(1..=256).contains(&self.install_id.len())
            || !self.install_id.bytes().all(|b| (0x20..=0x7e).contains(&b))
        {
            return Err(super::ValidationError::InvalidParams);
        }
        Ok(())
    }
}

pub fn sorted_flow_methods(methods: &[String]) -> Result<Vec<String>, super::ValidationError> {
    if methods.is_empty()
        || methods
            .iter()
            .any(|m| !(1..=16).contains(&m.len()) || !m.bytes().all(|b| b.is_ascii_uppercase()))
    {
        return Err(super::ValidationError::InvalidParams);
    }
    let mut sorted = methods.to_vec();
    sorted.sort();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(super::ValidationError::InvalidParams);
    }
    Ok(sorted)
}

/// The statement tags. A flow id equal to one of them cannot sit in a statement object: the
/// JSON encoder writes a repeated key rather than refusing, and the bytes it produces are not
/// the statement anyone meant to sign.
const STATEMENT_TAGS: &[&str] = &["ck-secret-flow-statement/v1", "ck-secret-use-statement/v1"];

/// Refuses a flow identity that cannot be stored as given. Every flow attribute is checked
/// here, not only at the sender boundary, because approval signs one JSON object whose
/// fields are these values: a value that reproduces the statement's own `v` key would
/// collide with the tag below, and one holding a byte JSON cannot carry would fail to
/// encode. The remaining checks are the ones the store's own grant lookup relies on, so a
/// grant is never created for an identity it could not match later.
fn flow_identity_encodes_unchanged(flow: &FlowIdentity) -> Result<(), super::ValidationError> {
    if flow.flow_id.is_empty()
        || STATEMENT_TAGS.contains(&flow.flow_id.as_str())
        || !(1..=256).contains(&flow.install_id.len())
        || !flow.install_id.bytes().all(|b| (0x20..=0x7e).contains(&b))
        || flow.code_hash.len() != 64
        || !flow
            .code_hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !(1..=MAX_SECRET_JSON_INTEGER).contains(&flow.version)
    {
        return Err(super::ValidationError::InvalidParams);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn flow_approval_statement(
    id: &str,
    member: &str,
    incarnation: &str,
    name: &str,
    flow: &FlowIdentity,
    scope: &super::SecretScope,
    methods: Option<&[String]>,
    expiry: i64,
) -> Result<serde_json::Value, super::ValidationError> {
    use serde_json::json;
    flow.validate()?;
    // Approval grants on the flow identity as given, so the encoder must be handed that
    // identity exactly as it is stored; a value it cannot carry verbatim is refused rather
    // than signed in some other form.
    flow_identity_encodes_unchanged(flow)?;
    let use_scope = match (scope, methods) {
        (
            super::SecretScope::ApiKey {
                host,
                path_prefix,
                location,
            },
            Some(methods),
        ) => {
            json!({"host":host,"path_prefix":path_prefix.as_deref().unwrap_or(""),"location":location,"methods":sorted_flow_methods(methods)?})
        }
        (super::SecretScope::SiteLogin { origin }, None) => json!({"origin":origin}),
        _ => return Err(super::ValidationError::InvalidParams),
    };
    Ok(
        json!({"v":"ck-secret-flow-statement/v1","request_id":id,"member_id":member,"flow":flow,"secret":{"name":name,"kind":scope.kind(),"incarnation":incarnation},"use":use_scope,"durations":["version"],"request_expires_at_ms":expiry}),
    )
}

pub fn delete_statement(
    id: &str,
    member: &str,
    name: &str,
    kind: &str,
    incarnation: &str,
    expiry: i64,
) -> serde_json::Value {
    serde_json::json!({"v":"ck-secret-delete-statement/v1","request_id":id,"member_id":member,"secret":{"name":name,"kind":kind,"incarnation":incarnation},"request_expires_at_ms":expiry})
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalItem {
    pub request_id: String,
    pub statement_sha256: String,
}

/// Whether every element of the envelope's `items` array holds exactly `request_id` and
/// `statement_sha256`. The rebuilt item serializes only those two keys, so each element must
/// be byte-identical to its own canonical form; a key such as `duration` inside an item is
/// not part of the envelope schema and makes the whole envelope `approval_invalid`.
fn envelope_items_carry_only_their_two_keys(bytes: &[u8]) -> bool {
    let parsed = serde_json::from_slice::<serde_json::Value>(bytes);
    let Ok(parsed) = parsed else {
        return false;
    };
    let Some(items) = parsed.get("items").and_then(serde_json::Value::as_array) else {
        return false;
    };
    items.iter().all(|item| {
        let rebuilt = serde_json::to_value(ApprovalItem {
            request_id: item
                .get("request_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            statement_sha256: item
                .get("statement_sha256")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        });
        rebuilt.is_ok_and(|rebuilt| rebuilt == *item)
    })
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalEnvelope {
    pub v: String,
    /// One entry per answered request; `#[serde(deny_unknown_fields)]` on this struct does
    /// not reach an element, so `verify` refuses items carrying extra keys itself. A key
    /// inside an item, `duration` included, never takes part in approval.
    pub items: Vec<ApprovalItem>,
    pub decision: String,
    pub duration: String,
    pub grant_expires_at_ms: u64,
    pub device_fingerprint: String,
    pub issued_at_ms: u64,
}

impl ApprovalEnvelope {
    /// All object keys are fixed ASCII and numbers are exact nonnegative integers.
    /// Sorting those keys and using serde_json's string encoding produces JCS bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SecretError> {
        serde_json::to_value(self)
            .and_then(|v| serde_json::to_vec(&v))
            .map_err(|_| SecretError::ApprovalInvalid)
    }

    pub fn verify(
        bytes: &[u8],
        signature: &[u8],
        public_key: &[u8],
        fingerprint: &str,
    ) -> Result<Self, SecretError> {
        let invalid = SecretError::ApprovalInvalid;
        // Deserializing structs (not Value maps) rejects duplicate keys at every level.
        let envelope: Self = serde_json::from_slice(bytes).map_err(|_| invalid)?;
        let mut ids = HashSet::new();
        if envelope.v.as_bytes() != USE_ENVELOPE_TAG
            || envelope.items.is_empty()
            || envelope.items.len() > MAX_ENVELOPE_ITEMS
            || envelope.device_fingerprint != fingerprint
            || envelope.issued_at_ms > MAX_SECRET_JSON_INTEGER
            || envelope.grant_expires_at_ms > MAX_SECRET_JSON_INTEGER
            || !matches!(envelope.decision.as_str(), "allow" | "delete")
            || !matches!(
                envelope.duration.as_str(),
                "once" | "hour" | "session" | "permanent" | "none" | "version"
            )
            || (envelope.duration == "version"
                && (envelope.decision != "allow" || envelope.grant_expires_at_ms != 0))
            || envelope.items.iter().any(|item| {
                item.request_id.len() != 26
                    || item.request_id.as_bytes()[0] > b'7'
                    || !item
                        .request_id
                        .bytes()
                        .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
                    || item.statement_sha256.len() != 64
                    || !item
                        .statement_sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    || !ids.insert(&item.request_id)
            })
            || !envelope_items_carry_only_their_two_keys(bytes)
            || envelope.canonical_bytes()? != bytes
        {
            return Err(invalid);
        }
        let key = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| invalid)?;
        let signature = Signature::from_der(signature).map_err(|_| invalid)?;
        key.verify(bytes, &signature).map_err(|_| invalid)?;
        Ok(envelope)
    }
}
