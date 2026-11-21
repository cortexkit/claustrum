//! Canonical statements for one-time broker action approvals.

use std::{borrow::Cow, collections::BTreeMap, fmt};

use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::{
    agent_policy::{valid_app_slug, valid_host, valid_resource},
    federation::is_lower_hex_sha256,
    gh_manifest::{sha256_hex, ManifestValue, MAX_MANIFEST_JSON_INTEGER as MAX_SAFE_INTEGER},
};

const STATEMENT_VERSION: &str = "ck-broker-action-statement/v1";
pub const MAX_STATEMENT_BYTES: usize = 524_288;
pub const MAX_STATEMENT_FIELDS: usize = 16;
pub const MAX_STATEMENT_LEGS: usize = 16;
pub const MAX_CONTEXT_CHARS: usize = 200;
const ENCODING: &str = "statement_b64url";

#[derive(Clone, PartialEq, Eq)]
pub struct BrokerActionStatement {
    pub request_id: String,
    pub agent_id: String,
    pub scope: BrokerActionScope,
    pub service: String,
    pub identity: String,
    pub action: String,
    pub host: String,
    pub resource: String,
    pub policy_version: u64,
    pub policy_sha256: String,
    pub fields: Vec<BrokerActionField>,
    pub shape: BrokerActionShape,
    pub context: Option<String>,
    pub expires_at_ms: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct BrokerActionScope {
    pub owner: String,
    pub kind: String,
    #[serde(rename = "ref")]
    pub scope_ref: String,
    pub epoch: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub enum BrokerActionShape {
    OneLeg {
        kind: String,
        method: String,
        request_sha256: String,
    },
    Legs(Vec<BrokerActionLeg>),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerActionLeg {
    pub kind: String,
    pub method: String,
    pub resource: String,
    pub request_sha256: String,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct BrokerActionField {
    pub name: String,
    pub value: FieldValue,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum FieldValue {
    Null,
    Bool(bool),
    String(String),
    Integer(i64),
    Array(Vec<FieldValue>),
    Object(BTreeMap<String, FieldValue>),
}

impl TryFrom<Value> for FieldValue {
    type Error = StatementError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Ok(match value {
            Value::Null => Self::Null,
            Value::Bool(value) => Self::Bool(value),
            Value::String(value) => Self::String(value),
            Value::Number(number) => Self::Integer(
                number
                    .as_i64()
                    .filter(|value| (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(value))
                    .ok_or_else(|| invalid("fields.value"))?,
            ),
            Value::Array(values) => Self::Array(
                values
                    .into_iter()
                    .map(Self::try_from)
                    .collect::<Result<_, _>>()?,
            ),
            Value::Object(values) => Self::Object(
                values
                    .into_iter()
                    .map(|(key, value)| Ok((key, Self::try_from(value)?)))
                    .collect::<Result<_, _>>()?,
            ),
        })
    }
}

impl fmt::Debug for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FieldValue { .. }")
    }
}

impl BrokerActionStatement {
    /// Preserve the caller-supplied consent-template order; JCS sorts object members, not arrays.
    pub fn encode(&self) -> Result<CheckedStatement, StatementError> {
        let mut value = json!({
            "v": STATEMENT_VERSION,
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "scope": self.scope,
            "service": self.service,
            "identity": self.identity,
            "action": self.action,
            "host": self.host,
            "resource": self.resource,
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
            "fields": self.fields,
            "expires_at_ms": self.expires_at_ms,
        });
        if let Some(context) = &self.context {
            value["context"] = json!(context);
        }
        match &self.shape {
            BrokerActionShape::OneLeg {
                kind,
                method,
                request_sha256,
            } => {
                value["kind"] = json!(kind);
                value["method"] = json!(method);
                value["request_sha256"] = json!(request_sha256);
            }
            BrokerActionShape::Legs(legs) => value["legs"] = json!(legs),
        }
        let bytes = canonical_bytes(value)?;
        if bytes.len() > MAX_STATEMENT_BYTES {
            return Err(invalid(ENCODING));
        }
        check_statement(&BASE64_URL_SAFE_NO_PAD.encode(bytes))
    }
}

impl fmt::Debug for BrokerActionStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BrokerActionStatement { .. }")
    }
}

pub struct CheckedStatement {
    statement: BrokerActionStatement,
    bytes: Vec<u8>,
    b64url: String,
    sha256: String,
}

impl CheckedStatement {
    pub fn statement(&self) -> &BrokerActionStatement {
        &self.statement
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn b64url(&self) -> &str {
        &self.b64url
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

impl fmt::Debug for CheckedStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CheckedStatement { .. }")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct StatementError(Cow<'static, str>);

impl StatementError {
    /// The member is for contract tests; unknown keys may contain untrusted text.
    pub fn member(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StatementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid broker action statement")
    }
}

impl fmt::Debug for StatementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for StatementError {}

fn invalid(member: &'static str) -> StatementError {
    StatementError(Cow::Borrowed(member))
}

/// Check the encoding and grammar, not expiry, policy membership or template fields.
pub fn check_statement(b64url: &str) -> Result<CheckedStatement, StatementError> {
    // Bound the decoder's allocation even for input that is not base64url.
    if b64url.len() > (MAX_STATEMENT_BYTES * 4).div_ceil(3) {
        return Err(invalid(ENCODING));
    }
    let bytes = BASE64_URL_SAFE_NO_PAD
        .decode(b64url)
        .map_err(|_| invalid(ENCODING))?;
    if bytes.len() > MAX_STATEMENT_BYTES || BASE64_URL_SAFE_NO_PAD.encode(&bytes) != b64url {
        return Err(invalid(ENCODING));
    }
    let value = serde_json::from_slice(&bytes).map_err(|_| invalid(ENCODING))?;
    let statement = parse_statement(&value)?;
    // Comparing bytes also rejects duplicate keys discarded by the JSON parser.
    if canonical_bytes(value)? != bytes {
        return Err(invalid(ENCODING));
    }
    Ok(CheckedStatement {
        statement,
        sha256: sha256_hex(&bytes),
        bytes,
        b64url: b64url.to_owned(),
    })
}

fn canonical_bytes(value: Value) -> Result<Vec<u8>, StatementError> {
    // All admitted numbers are exact integers; compact JSON with UTF-16 key order
    // is their RFC 8785 representation, including in nested field objects.
    let mut ordered = ManifestValue::deserialize(value).map_err(|_| invalid(ENCODING))?;
    ordered.sort_jcs_keys();
    serde_json::to_vec(&ordered).map_err(|_| invalid(ENCODING))
}

fn parse_statement(value: &Value) -> Result<BrokerActionStatement, StatementError> {
    let obj = object(value, ENCODING)?;
    const MEMBERS: &[&str] = &[
        "v",
        "request_id",
        "agent_id",
        "scope",
        "service",
        "identity",
        "action",
        "host",
        "resource",
        "policy_version",
        "policy_sha256",
        "fields",
        "expires_at_ms",
        "context",
        "kind",
        "method",
        "request_sha256",
        "legs",
    ];
    if let Some(key) = obj.keys().find(|key| !MEMBERS.contains(&key.as_str())) {
        return Err(StatementError(Cow::Owned(key.clone())));
    }
    text_where(obj, "v", "v", |v| v == STATEMENT_VERSION)?;
    let action = text_where(obj, "action", "action", nonempty)?;
    let shape = if let Some(legs) = obj.get("legs") {
        for member in ["kind", "method", "request_sha256"] {
            if obj.contains_key(member) {
                return Err(invalid(member));
            }
        }
        let legs = legs
            .as_array()
            .filter(|legs| (1..=MAX_STATEMENT_LEGS).contains(&legs.len()))
            .ok_or_else(|| invalid("legs"))?;
        BrokerActionShape::Legs(legs.iter().map(parse_leg).collect::<Result<_, _>>()?)
    } else {
        BrokerActionShape::OneLeg {
            kind: text_where(obj, "kind", "kind", |kind| kind == action)?,
            method: text_where(obj, "method", "method", valid_method)?,
            request_sha256: text_where(
                obj,
                "request_sha256",
                "request_sha256",
                is_lower_hex_sha256,
            )?,
        }
    };
    let fields = obj
        .get("fields")
        .and_then(Value::as_array)
        .filter(|fields| fields.len() <= MAX_STATEMENT_FIELDS)
        .ok_or_else(|| invalid("fields"))?;
    Ok(BrokerActionStatement {
        request_id: text_where(obj, "request_id", "request_id", valid_ulid)?,
        agent_id: text_where(obj, "agent_id", "agent_id", nonempty)?,
        scope: parse_scope(obj.get("scope").ok_or_else(|| invalid("scope"))?)?,
        service: text_where(obj, "service", "service", |service| service == "github")?,
        identity: text_where(obj, "identity", "identity", |identity| {
            identity
                .strip_prefix("github_app:")
                .is_some_and(valid_app_slug)
        })?,
        action,
        host: text_where(obj, "host", "host", valid_statement_host)?,
        resource: text_where(obj, "resource", "resource", valid_resource)?,
        policy_version: safe_counter(obj, "policy_version", "policy_version")?,
        policy_sha256: text_where(obj, "policy_sha256", "policy_sha256", is_lower_hex_sha256)?,
        fields: fields.iter().map(parse_field).collect::<Result<_, _>>()?,
        shape,
        context: obj
            .get("context")
            .map(|_| text_where(obj, "context", "context", valid_context))
            .transpose()?,
        expires_at_ms: safe_counter(obj, "expires_at_ms", "expires_at_ms")?,
    })
}

fn parse_scope(value: &Value) -> Result<BrokerActionScope, StatementError> {
    let obj = closed_object(value, &["owner", "kind", "ref", "epoch"], "scope")?;
    Ok(BrokerActionScope {
        owner: text_where(obj, "owner", "scope.owner", |owner| {
            matches!(owner, "direct" | "unverified")
                || owner.strip_prefix("reserved:").is_some_and(nonempty)
        })?,
        kind: text_where(obj, "kind", "scope.kind", |kind| {
            matches!(kind, "head" | "worker" | "ephemeral")
        })?,
        scope_ref: text_where(obj, "ref", "scope.ref", |_| true)?,
        epoch: safe_counter(obj, "epoch", "scope.epoch")?,
    })
}

fn parse_leg(value: &Value) -> Result<BrokerActionLeg, StatementError> {
    let obj = closed_object(
        value,
        &["kind", "method", "resource", "request_sha256"],
        "legs",
    )?;
    Ok(BrokerActionLeg {
        kind: text_where(obj, "kind", "legs.kind", nonempty)?,
        method: text_where(obj, "method", "legs.method", valid_method)?,
        resource: text_where(obj, "resource", "legs.resource", valid_resource)?,
        request_sha256: text_where(
            obj,
            "request_sha256",
            "legs.request_sha256",
            is_lower_hex_sha256,
        )?,
    })
}

fn parse_field(value: &Value) -> Result<BrokerActionField, StatementError> {
    let obj = closed_object(value, &["name", "value"], "fields")?;
    Ok(BrokerActionField {
        name: text_where(obj, "name", "fields.name", nonempty)?,
        value: FieldValue::try_from(
            obj.get("value")
                .cloned()
                .ok_or_else(|| invalid("fields.value"))?,
        )?,
    })
}

fn object<'a>(
    value: &'a Value,
    member: &'static str,
) -> Result<&'a Map<String, Value>, StatementError> {
    value.as_object().ok_or_else(|| invalid(member))
}

fn closed_object<'a>(
    value: &'a Value,
    members: &[&str],
    member: &'static str,
) -> Result<&'a Map<String, Value>, StatementError> {
    let obj = object(value, member)?;
    if obj.keys().any(|key| !members.contains(&key.as_str())) {
        return Err(invalid(member));
    }
    Ok(obj)
}

fn text_where(
    obj: &Map<String, Value>,
    key: &str,
    member: &'static str,
    valid: impl FnOnce(&str) -> bool,
) -> Result<String, StatementError> {
    let text = obj
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(member))?;
    if !valid(text) {
        return Err(invalid(member));
    }
    Ok(text.to_owned())
}

fn safe_counter(
    obj: &Map<String, Value>,
    key: &str,
    member: &'static str,
) -> Result<u64, StatementError> {
    obj.get(key)
        .and_then(Value::as_u64)
        .filter(|n| *n <= MAX_SAFE_INTEGER as u64)
        .ok_or_else(|| invalid(member))
}

fn nonempty(text: &str) -> bool {
    !text.is_empty()
}

/// The canonical uppercase Crockford representation of a 128-bit ULID.
pub fn valid_ulid(value: &str) -> bool {
    value.len() == 26
        && value.as_bytes()[0] <= b'7'
        && value
            .bytes()
            .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
}

pub fn valid_method(method: &str) -> bool {
    !method.is_empty() && method.bytes().all(|b| b.is_ascii_uppercase())
}

/// A policy host can include a port only when it is not the default HTTPS port.
pub fn valid_statement_host(host: &str) -> bool {
    match host.split_once(':') {
        Some((host, port)) => {
            valid_host(host)
                && !port.starts_with('0')
                && port.bytes().all(|b| b.is_ascii_digit())
                && port.parse::<u16>().is_ok_and(|n| !matches!(n, 0 | 443))
        }
        None => valid_host(host),
    }
}

pub fn valid_context(context: &str) -> bool {
    !context.is_empty()
        && context.chars().count() <= MAX_CONTEXT_CHARS
        && !context.chars().any(unreadable_context_character)
}

fn unreadable_context_character(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{2028}' | '\u{2029}')
        // Unicode General_Category=Cf, including supplementary-plane format controls.
        || matches!(
            c,
            '\u{ad}' | '\u{600}'..='\u{605}' | '\u{61c}' | '\u{6dd}' | '\u{70f}'
                | '\u{890}'..='\u{891}' | '\u{8e2}' | '\u{180e}' | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206f}'
                | '\u{feff}' | '\u{fff9}'..='\u{fffb}' | '\u{110bd}' | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}' | '\u{1bca0}'..='\u{1bca3}' | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}' | '\u{e0020}'..='\u{e007f}'
        )
}

#[cfg(test)]
#[path = "broker_action_tests.rs"]
mod tests;
