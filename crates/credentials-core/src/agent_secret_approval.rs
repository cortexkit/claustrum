//! Signed consent uses a closed JSON vocabulary and canonical bytes, not JSON equivalence.
use super::{SecretError, USE_ENVELOPE_TAG};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const MAX_ENVELOPE_ITEMS: usize = 16;
pub const SECRET_ISSUE_SKEW_LIMIT_MS: i64 = 120_000;
pub const MAX_SECRET_JSON_INTEGER: u64 = (1 << 53) - 1;

/// The v2 statement tags. A forwarded request carries the v1 object plus
/// `asking_member_id`, under a v2 tag so a v1-only phone or Cingulate decoder
/// refuses it rather than approving a statement it does not understand.
pub const USE_STATEMENT_V2: &str = "ck-secret-use-statement/v2";
pub const FLOW_STATEMENT_V2: &str = "ck-secret-flow-statement/v2";

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

/// The statement for a request `asking_member` forwarded to this vault. A local
/// request keeps the v1 object byte for byte; a forwarded one carries the v1
/// object plus the required `asking_member_id` key under a v2 tag, encoded
/// with the same canonical bytes as today.
pub fn approval_statement_for_asker(
    id: &str,
    member: &str,
    incarnation: &str,
    call: &super::SecretUse,
    scope: &super::SecretScope,
    expiry: i64,
    asking_member: &str,
) -> serde_json::Value {
    let mut statement = approval_statement(id, member, incarnation, call, scope, expiry);
    if !asking_member.is_empty() {
        statement["asking_member_id"] = serde_json::json!(asking_member);
        statement["v"] = serde_json::json!(USE_STATEMENT_V2);
    }
    statement
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

/// Refuses a flow identity that cannot be stored as given. A flow id equal to the
/// statement's own `v` tag would collide with that key when the statement object is built,
/// so it is refused here as well as at the sender boundary: approval signs that one object.
/// The remaining checks are the identity constraints the store's grant lookup relies on, so
/// a grant is never created for an identity it could not match later.
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

/// Whether `flow_id` equals a v2 statement tag. Only a forwarded flow approval
/// refuses these: the local sender boundary stays v1-only, so a local flow
/// approval whose flow id equals a v2 tag is still accepted and still encodes
/// as a v1 statement.
pub fn flow_id_is_v2_statement_tag(flow_id: &str) -> bool {
    flow_id == USE_STATEMENT_V2 || flow_id == FLOW_STATEMENT_V2
}

/// The flow statement for a request `asking_member` forwarded to this vault.
/// A local request keeps the v1 object byte for byte; a forwarded one carries
/// the v1 object plus the required `asking_member_id` key under a v2 tag. A
/// forwarded request whose flow id equals a v2 tag is refused, since that id
/// would collide with the v2 statement's own `v` key.
#[allow(clippy::too_many_arguments)]
pub fn flow_approval_statement_for_asker(
    id: &str,
    member: &str,
    incarnation: &str,
    name: &str,
    flow: &FlowIdentity,
    scope: &super::SecretScope,
    methods: Option<&[String]>,
    expiry: i64,
    asking_member: &str,
) -> Result<serde_json::Value, super::ValidationError> {
    if asking_member.is_empty() {
        return flow_approval_statement(
            id,
            member,
            incarnation,
            name,
            flow,
            scope,
            methods,
            expiry,
        );
    }
    if flow_id_is_v2_statement_tag(&flow.flow_id) {
        return Err(super::ValidationError::InvalidParams);
    }
    let mut statement =
        flow_approval_statement(id, member, incarnation, name, flow, scope, methods, expiry)?;
    statement["asking_member_id"] = serde_json::json!(asking_member);
    statement["v"] = serde_json::json!(FLOW_STATEMENT_V2);
    Ok(statement)
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
/// `statement_sha256`. Each element is compared with the rebuilt JSON value holding only
/// those two keys; a key such as `duration` inside an item is not part of the envelope
/// schema and makes the whole envelope `approval_invalid`.
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

#[cfg(test)]
mod v2_statement_tests {
    use super::*;
    use crate::agent_secret::{AskingScope, SecretScope, SecretSender, SecretUse};

    const HOME: &str = "fed-computer:22222222222222222222222222222222";
    const ASKER: &str = "fed-computer:11111111111111111111111111111111";
    const NOW: i64 = 1_700_000_000_000;
    const REQUEST_ID: &str = "01HF7YAT000000000000000001";
    const INCARNATION: &str = "00000000000000000000000000000149";

    fn api_scope() -> SecretScope {
        SecretScope::ApiKey {
            host: "x.test".into(),
            path_prefix: Some("/repos/a".into()),
            location: "header:X-Api-Key".into(),
        }
    }

    fn api_call() -> SecretUse {
        SecretUse {
            name: "key".into(),
            sender: SecretSender::Aft,
            scope: AskingScope {
                owner: "reserved:prefrontal-core".into(),
                kind: "head".into(),
                scope_ref: "H".into(),
                epoch: 7,
            },
            worker_parent: None,
            coverage: "scope".into(),
            agent_id: Some("agent-A".into()),
            target: crate::agent_secret::UseTarget::ApiKey {
                scheme: "https".into(),
                host: "x.test".into(),
                port: 443,
                path: "/repos/a/canary-token".into(),
            },
        }
    }

    fn login_scope() -> SecretScope {
        SecretScope::SiteLogin {
            origin: "https://x.test".into(),
        }
    }

    fn flow_identity() -> FlowIdentity {
        FlowIdentity {
            flow_id: "daily-fetch".into(),
            version: 7,
            code_hash: "0123456789abcdef".repeat(4),
            install_id: "install-A".into(),
        }
    }

    #[test]
    fn forwarded_use_statement_is_v1_plus_asker_under_v2_tag() {
        let v1 = approval_statement(
            REQUEST_ID,
            HOME,
            INCARNATION,
            &api_call(),
            &api_scope(),
            NOW + 600_000,
        );
        assert_eq!(v1["v"], "ck-secret-use-statement/v1");
        assert!(v1.get("asking_member_id").is_none());
        let v1_bytes = serde_json::to_vec(&v1).unwrap();
        let v2 = approval_statement_for_asker(
            REQUEST_ID,
            HOME,
            INCARNATION,
            &api_call(),
            &api_scope(),
            NOW + 600_000,
            ASKER,
        );
        assert_eq!(v2["v"], USE_STATEMENT_V2);
        assert_eq!(v2["asking_member_id"], ASKER);
        // Every other key is the v1 object unchanged.
        let mut v2_as_v1 = v2.clone();
        v2_as_v1["v"] = serde_json::json!("ck-secret-use-statement/v1");
        v2_as_v1.as_object_mut().unwrap().remove("asking_member_id");
        assert_eq!(v2_as_v1, v1);
        // Canonical bytes: the same Value re-encoded is identical.
        let v2_bytes = serde_json::to_vec(&v2).unwrap();
        assert_ne!(v1_bytes, v2_bytes);
        let decoded: serde_json::Value = serde_json::from_slice(&v2_bytes).unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), v2_bytes);
    }

    #[test]
    fn local_use_statement_stays_v1_byte_for_byte() {
        let direct = approval_statement(
            REQUEST_ID,
            HOME,
            INCARNATION,
            &api_call(),
            &api_scope(),
            NOW + 600_000,
        );
        let via_asker = approval_statement_for_asker(
            REQUEST_ID,
            HOME,
            INCARNATION,
            &api_call(),
            &api_scope(),
            NOW + 600_000,
            "",
        );
        assert_eq!(via_asker, direct);
        assert_eq!(via_asker["v"], "ck-secret-use-statement/v1");
        assert!(via_asker.get("asking_member_id").is_none());
    }

    #[test]
    fn forwarded_flow_statement_is_v1_plus_asker_under_v2_tag() {
        let v1 = flow_approval_statement(
            REQUEST_ID,
            HOME,
            INCARNATION,
            "key",
            &flow_identity(),
            &api_scope(),
            Some(&["GET".to_string()]),
            NOW + 600_000,
        )
        .unwrap();
        assert_eq!(v1["v"], "ck-secret-flow-statement/v1");
        assert!(v1.get("asking_member_id").is_none());
        let v2 = flow_approval_statement_for_asker(
            REQUEST_ID,
            HOME,
            INCARNATION,
            "key",
            &flow_identity(),
            &api_scope(),
            Some(&["GET".to_string()]),
            NOW + 600_000,
            ASKER,
        )
        .unwrap();
        assert_eq!(v2["v"], FLOW_STATEMENT_V2);
        assert_eq!(v2["asking_member_id"], ASKER);
        let mut v2_as_v1 = v2.clone();
        v2_as_v1["v"] = serde_json::json!("ck-secret-flow-statement/v1");
        v2_as_v1.as_object_mut().unwrap().remove("asking_member_id");
        assert_eq!(v2_as_v1, v1);
        let v2_bytes = serde_json::to_vec(&v2).unwrap();
        let decoded: serde_json::Value = serde_json::from_slice(&v2_bytes).unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), v2_bytes);
    }

    #[test]
    fn local_flow_statement_stays_v1_byte_for_byte() {
        let direct = flow_approval_statement(
            REQUEST_ID,
            HOME,
            INCARNATION,
            "key",
            &flow_identity(),
            &api_scope(),
            Some(&["GET".to_string()]),
            NOW + 600_000,
        )
        .unwrap();
        let via_asker = flow_approval_statement_for_asker(
            REQUEST_ID,
            HOME,
            INCARNATION,
            "key",
            &flow_identity(),
            &api_scope(),
            Some(&["GET".to_string()]),
            NOW + 600_000,
            "",
        )
        .unwrap();
        assert_eq!(via_asker, direct);
    }

    #[test]
    fn only_forwarded_flow_refuses_a_v2_tag_flow_id() {
        for tag in [USE_STATEMENT_V2, FLOW_STATEMENT_V2] {
            let mut identity = flow_identity();
            identity.flow_id = tag.into();
            // Local keeps the v1-only sender check, so a v2 tag still encodes.
            assert!(flow_approval_statement(
                REQUEST_ID,
                HOME,
                INCARNATION,
                "key",
                &identity,
                &api_scope(),
                Some(&["GET".to_string()]),
                NOW + 600_000,
            )
            .is_ok());
            // Forwarded refuses it: the id would collide with the v2 `v` key.
            assert!(flow_approval_statement_for_asker(
                REQUEST_ID,
                HOME,
                INCARNATION,
                "key",
                &identity,
                &api_scope(),
                Some(&["GET".to_string()]),
                NOW + 600_000,
                ASKER,
            )
            .is_err());
            assert!(flow_id_is_v2_statement_tag(tag));
        }
        assert!(!flow_id_is_v2_statement_tag("daily-fetch"));
        assert!(!flow_id_is_v2_statement_tag("ck-secret-flow-statement/v1"));
    }

    fn statement_record(statement: &serde_json::Value) -> serde_json::Value {
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let bytes = serde_json::to_vec(statement).unwrap();
        let digest: Vec<u8> = Sha256::digest(&bytes).to_vec();
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        serde_json::json!({
            "statement": statement,
            "statement_b64url": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes),
            "statement_sha256": hex,
        })
    }

    #[test]
    fn v2_statement_vectors_are_emitted_by_the_real_encoders_and_pinned() {
        let use_v2 = approval_statement_for_asker(
            REQUEST_ID,
            HOME,
            INCARNATION,
            &api_call(),
            &api_scope(),
            NOW + 600_000,
            ASKER,
        );
        let login_incarnation = format!(
            "{:032x}",
            b"login".iter().copied().map(u64::from).sum::<u64>()
        );
        let login_call = SecretUse {
            name: "login".into(),
            sender: SecretSender::Cerebellum,
            scope: AskingScope {
                owner: "reserved:prefrontal-core".into(),
                kind: "head".into(),
                scope_ref: "H".into(),
                epoch: 7,
            },
            worker_parent: None,
            coverage: "scope".into(),
            agent_id: Some("agent-A".into()),
            target: crate::agent_secret::UseTarget::SiteLogin {
                origin: "https://x.test".into(),
            },
        };
        let login_v2 = approval_statement_for_asker(
            "01HF7YAT000000000000000002",
            HOME,
            &login_incarnation,
            &login_call,
            &login_scope(),
            NOW + 600_000,
            ASKER,
        );
        let mut use_vectors = Vec::new();
        for (case, request_id, statement) in [
            ("forwarded-use-api-key", REQUEST_ID, use_v2),
            (
                "forwarded-use-site-login",
                "01HF7YAT000000000000000002",
                login_v2,
            ),
        ] {
            let mut record = statement_record(&statement);
            record["case"] = serde_json::json!(case);
            record["request_id"] = serde_json::json!(request_id);
            record["member_id"] = serde_json::json!(HOME);
            record["asking_member_id"] = serde_json::json!(ASKER);
            use_vectors.push(record);
        }
        let emitted_use = serde_json::json!({"vectors": use_vectors});
        let use_pinned = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors/secret-approval-v2.json");
        if std::env::var_os("CK_EMIT_SECRET_VECTORS").is_some() {
            std::fs::create_dir_all(use_pinned.parent().unwrap()).unwrap();
            std::fs::write(
                &use_pinned,
                serde_json::to_vec_pretty(&emitted_use).unwrap(),
            )
            .unwrap();
            println!("emitted v2 use statement vectors");
        } else {
            let expected: serde_json::Value = serde_json::from_slice(
                &std::fs::read(&use_pinned).expect("pinned v2 use statement vectors"),
            )
            .unwrap();
            assert_eq!(
                emitted_use, expected,
                "vault-emitted v2 use vectors changed"
            );
        }
        let flow_api_v2 = flow_approval_statement_for_asker(
            REQUEST_ID,
            HOME,
            INCARNATION,
            "key",
            &flow_identity(),
            &api_scope(),
            Some(&["GET".to_string()]),
            NOW + 600_000,
            ASKER,
        )
        .unwrap();
        let flow_login_v2 = flow_approval_statement_for_asker(
            "01HF7YAT000000000000000002",
            HOME,
            &login_incarnation,
            "login",
            &flow_identity(),
            &login_scope(),
            None,
            NOW + 600_000,
            ASKER,
        )
        .unwrap();
        let mut flow_vectors = Vec::new();
        for (case, request_id, statement) in [
            ("forwarded-flow-api-key", REQUEST_ID, flow_api_v2),
            (
                "forwarded-flow-site-login",
                "01HF7YAT000000000000000002",
                flow_login_v2,
            ),
        ] {
            let mut record = statement_record(&statement);
            record["case"] = serde_json::json!(case);
            record["request_id"] = serde_json::json!(request_id);
            record["member_id"] = serde_json::json!(HOME);
            record["asking_member_id"] = serde_json::json!(ASKER);
            flow_vectors.push(record);
        }
        let emitted_flow = serde_json::json!({"vectors": flow_vectors});
        let flow_pinned = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors/secret-flow-approval-v2.json");
        if std::env::var_os("CK_EMIT_SECRET_VECTORS").is_some() {
            std::fs::create_dir_all(flow_pinned.parent().unwrap()).unwrap();
            std::fs::write(
                &flow_pinned,
                serde_json::to_vec_pretty(&emitted_flow).unwrap(),
            )
            .unwrap();
            println!("emitted v2 flow statement vectors");
        } else {
            let expected: serde_json::Value = serde_json::from_slice(
                &std::fs::read(&flow_pinned).expect("pinned v2 flow statement vectors"),
            )
            .unwrap();
            assert_eq!(
                emitted_flow, expected,
                "vault-emitted v2 flow vectors changed"
            );
        }
    }
}
