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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalEnvelope {
    pub v: String,
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
                "once" | "hour" | "session" | "permanent" | "none"
            )
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
