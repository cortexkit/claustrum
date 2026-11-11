//! Byte-reproducible GitHub routing manifests and phone approval statements.
//!
//! Manifest objects retain insertion order without changing serde_json's map
//! representation: enabling its preserve_order feature would change existing
//! phone approval statement bytes for agent secrets throughout the workspace.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

/// JSON whose object entries retain their input order, including nested objects.
#[derive(Debug, Clone, PartialEq)]
pub enum ManifestValue {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<ManifestValue>),
    Object(Vec<(String, ManifestValue)>),
}

impl ManifestValue {
    pub fn get(&self, name: &str) -> Option<&Self> {
        match self {
            Self::Object(entries) => entries.iter().find(|(key, _)| key == name).map(|(_, v)| v),
            _ => None,
        }
    }

    fn get_mut(&mut self, name: &str) -> Option<&mut Self> {
        match self {
            Self::Object(entries) => entries
                .iter_mut()
                .find(|(key, _)| key == name)
                .map(|(_, v)| v),
            _ => None,
        }
    }

    fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(number) => number.as_i64(),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    fn sort_jcs_keys(&mut self) {
        match self {
            Self::Object(entries) => {
                entries.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
                for (_, value) in entries {
                    value.sort_jcs_keys();
                }
            }
            Self::Array(values) => {
                for value in values {
                    value.sort_jcs_keys();
                }
            }
            _ => {}
        }
    }
}

impl Serialize for ManifestValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Number(value) => value.serialize(serializer),
            Self::String(value) => serializer.serialize_str(value),
            Self::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(value)?;
                }
                sequence.end()
            }
            Self::Object(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for ManifestValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct OrderedVisitor;

        impl<'de> Visitor<'de> for OrderedVisitor {
            type Value = ManifestValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value with unique object keys")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(ManifestValue::Null)
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(ManifestValue::Bool(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(ManifestValue::Number(value.into()))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(ManifestValue::Number(value.into()))
            }

            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(ManifestValue::Number)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(ManifestValue::String(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(ManifestValue::String(value))
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(ManifestValue::Array(values))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut entries = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, ManifestValue>()? {
                    if entries.iter().any(|(prior, _)| prior == &key) {
                        return Err(serde::de::Error::custom("duplicate JSON object key"));
                    }
                    entries.push((key, value));
                }
                Ok(ManifestValue::Object(entries))
            }
        }

        deserializer.deserialize_any(OrderedVisitor)
    }
}

#[derive(Debug)]
pub enum ManifestError {
    InvalidJson(serde_json::Error),
    /// The stored bytes cannot be rebuilt exactly by the manifest serializer.
    NotReproducible,
    InvalidManifest(&'static str),
    InvalidStatementInteger(&'static str),
    InvalidInstallationPermissions,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson(error) => write!(formatter, "invalid manifest JSON: {error}"),
            Self::NotReproducible => formatter.write_str("not_reproducible"),
            Self::InvalidManifest(reason) => write!(formatter, "invalid manifest: {reason}"),
            Self::InvalidStatementInteger(field) => {
                write!(formatter, "invalid statement integer: {field}")
            }
            Self::InvalidInstallationPermissions => {
                formatter.write_str("invalid installation permissions")
            }
        }
    }
}

impl std::error::Error for ManifestError {}

/// A reproducible manifest from which one repository binding can be added.
#[derive(Debug, Clone, PartialEq)]
pub struct GhManifest {
    value: ManifestValue,
}

impl GhManifest {
    pub fn parse_reproducible(bytes: &[u8]) -> Result<Self, ManifestError> {
        let value = serde_json::from_slice(bytes).map_err(ManifestError::InvalidJson)?;
        let manifest = Self { value };
        if manifest.to_bytes() != bytes {
            return Err(ManifestError::NotReproducible);
        }
        if manifest
            .value
            .get("manifest_version")
            .and_then(ManifestValue::as_i64)
            .filter(|version| *version > 0)
            .is_none()
        {
            return Err(ManifestError::InvalidManifest(
                "manifest_version must be a positive integer",
            ));
        }
        if manifest
            .value
            .get("issued_at_unix_secs")
            .and_then(ManifestValue::as_i64)
            .is_none()
        {
            return Err(ManifestError::InvalidManifest(
                "issued_at_unix_secs must be an integer",
            ));
        }
        match manifest.value.get("bindings") {
            Some(ManifestValue::Object(entries))
                if entries.iter().all(|(_, value)| value.as_str().is_some()) => {}
            _ => {
                return Err(ManifestError::InvalidManifest(
                    "bindings must be an object of strings",
                ))
            }
        }
        Ok(manifest)
    }

    /// Two-space indentation, literal UTF-8, and exactly one trailing newline.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes =
            serde_json::to_vec_pretty(&self.value).expect("manifest JSON serialization");
        bytes.push(b'\n');
        bytes
    }

    pub fn value(&self) -> &ManifestValue {
        &self.value
    }

    pub fn version(&self) -> i64 {
        self.value
            .get("manifest_version")
            .and_then(ManifestValue::as_i64)
            .expect("validated version")
    }

    pub fn issued_at_unix_secs(&self) -> i64 {
        self.value
            .get("issued_at_unix_secs")
            .and_then(ManifestValue::as_i64)
            .expect("validated issue time")
    }

    pub fn bindings(&self) -> impl Iterator<Item = (&str, &str)> {
        let Some(ManifestValue::Object(entries)) = self.value.get("bindings") else {
            unreachable!("validated bindings");
        };
        entries
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str().expect("validated binding")))
    }

    /// The caller supplies GitHub's full_name casing, not the proposed spelling.
    pub fn build_next(
        &self,
        full_name: &str,
        agent_id: &str,
        now_unix_secs: i64,
    ) -> Result<Self, ManifestError> {
        if self
            .bindings()
            .any(|(repo, _)| repo.eq_ignore_ascii_case(full_name))
        {
            return Err(ManifestError::InvalidManifest(
                "repository is already bound",
            ));
        }
        let version = self
            .version()
            .checked_add(1)
            .ok_or(ManifestError::InvalidManifest("manifest_version overflow"))?;
        let mut next = self.clone();
        *next
            .value
            .get_mut("manifest_version")
            .expect("validated version") = ManifestValue::Number(version.into());
        *next
            .value
            .get_mut("issued_at_unix_secs")
            .expect("validated issue time") = ManifestValue::Number(now_unix_secs.into());
        let Some(ManifestValue::Object(bindings)) = next.value.get_mut("bindings") else {
            unreachable!("validated bindings");
        };
        bindings.push((
            full_name.to_owned(),
            ManifestValue::String(agent_id.to_owned()),
        ));
        Ok(next)
    }

    pub fn manifest_sha256(&self) -> String {
        sha256_hex(&self.to_bytes())
    }
}

pub const MANIFEST_BINDING_STATEMENT_V1: &str = "ck-manifest-binding-statement/v1";
pub const MANIFEST_BINDING_STATEMENT_V1_TAG: &[u8] = b"ck-manifest-binding-statement/v1";
/// Statement counters and times must survive the phone's JSON number parsing
/// without rounding; use the same exact-integer bound as agent-secret approvals.
pub const MAX_MANIFEST_JSON_INTEGER: i64 = crate::agent_secret::MAX_SECRET_JSON_INTEGER as i64;
pub const MIN_MANIFEST_INSTALLATION_PERMISSIONS: usize = 1;
pub const MAX_MANIFEST_INSTALLATION_PERMISSIONS: usize = 64;
pub const MAX_MANIFEST_PERMISSION_NAME_BYTES: usize = 64;

/// Keep the phone's permission card unambiguous: names are bounded ASCII
/// identifiers, and every entry describes one of GitHub's three permission levels.
pub fn validate_installation_permissions(
    permissions: &BTreeMap<String, String>,
) -> Result<(), ManifestError> {
    if !(MIN_MANIFEST_INSTALLATION_PERMISSIONS..=MAX_MANIFEST_INSTALLATION_PERMISSIONS)
        .contains(&permissions.len())
        || permissions.iter().any(|(name, level)| {
            let bytes = name.as_bytes();
            bytes.len() > MAX_MANIFEST_PERMISSION_NAME_BYTES
                || !bytes.first().is_some_and(u8::is_ascii_lowercase)
                || !bytes
                    .iter()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
                || !matches!(level.as_str(), "read" | "write" | "admin")
        })
    {
        return Err(ManifestError::InvalidInstallationPermissions);
    }
    Ok(())
}

/// The exact phone-visible commitment; no agent display name is included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestBindingStatement {
    pub v: String,
    pub proposal_id: String,
    pub agent_id: String,
    pub app_slug: String,
    pub repo: String,
    pub installation_permissions: BTreeMap<String, String>,
    pub manifest_version: i64,
    pub manifest_sha256: String,
    pub prior_version: i64,
    pub prior_sha256: String,
    pub expires_at_ms: i64,
}

impl ManifestBindingStatement {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposal_id: String,
        agent_id: String,
        app_slug: String,
        full_name: String,
        installation_permissions: BTreeMap<String, String>,
        manifest: &GhManifest,
        prior: &GhManifest,
        expires_at_ms: i64,
    ) -> Result<Self, ManifestError> {
        validate_installation_permissions(&installation_permissions)?;
        let statement = Self {
            v: MANIFEST_BINDING_STATEMENT_V1.to_owned(),
            proposal_id,
            agent_id,
            app_slug,
            repo: full_name,
            installation_permissions,
            manifest_version: manifest.version(),
            manifest_sha256: manifest.manifest_sha256(),
            prior_version: prior.version(),
            prior_sha256: prior.manifest_sha256(),
            expires_at_ms,
        };
        statement.validate_jcs_integers()?;
        Ok(statement)
    }

    fn validate_jcs_integers(&self) -> Result<(), ManifestError> {
        for (field, value) in [
            ("manifest_version", self.manifest_version),
            ("prior_version", self.prior_version),
            ("expires_at_ms", self.expires_at_ms),
        ] {
            if !(0..=MAX_MANIFEST_JSON_INTEGER).contains(&value) {
                return Err(ManifestError::InvalidStatementInteger(field));
            }
        }
        Ok(())
    }

    /// The statement has only strings, exact integer counters/times and permission
    /// objects. Compact JSON plus UTF-16 object-key sorting gives its JSON
    /// Canonicalization Scheme (RFC 8785) form; manifest objects themselves must
    /// never be sorted this way.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ManifestError> {
        validate_installation_permissions(&self.installation_permissions)?;
        self.validate_jcs_integers()?;
        let mut value =
            ManifestValue::deserialize(serde_json::to_value(self).expect("statement JSON value"))
                .expect("statement contains JSON values");
        value.sort_jcs_keys();
        Ok(serde_json::to_vec(&value).expect("statement JSON serialization"))
    }

    pub fn statement_sha256(&self) -> Result<String, ManifestError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }
}

pub const MANIFEST_BINDING_ENVELOPE_V1_TAG: &[u8] = b"ck-manifest-binding-envelope/v1";

/// The phone authorizes one stored proposal, not caller-supplied manifest bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestBindingEnvelope {
    pub v: String,
    pub proposal_id: String,
    pub statement_sha256: String,
    pub decision: String,
    pub device_fingerprint: String,
    pub issued_at_ms: u64,
}

impl ManifestBindingEnvelope {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, crate::agent_secret::SecretError> {
        serde_json::to_value(self)
            .and_then(|value| serde_json::to_vec(&value))
            .map_err(|_| crate::agent_secret::SecretError::ApprovalInvalid)
    }

    fn parse_canonical(
        bytes: &[u8],
        fingerprint: &str,
    ) -> Result<Self, crate::agent_secret::SecretError> {
        use crate::agent_secret::{SecretError, MAX_SECRET_JSON_INTEGER};
        let invalid = SecretError::ApprovalInvalid;
        // Struct decoding rejects missing, duplicate and unknown fields. Check the
        // domain tag here, before constructing a verification key or signature.
        let envelope: Self = serde_json::from_slice(bytes).map_err(|_| invalid)?;
        if envelope.v.as_bytes() != MANIFEST_BINDING_ENVELOPE_V1_TAG
            || envelope.decision != "allow"
            || envelope.device_fingerprint != fingerprint
            || envelope.issued_at_ms > MAX_SECRET_JSON_INTEGER
            || envelope.proposal_id.len() != 26
            || envelope.proposal_id.as_bytes()[0] > b'7'
            || !envelope
                .proposal_id
                .bytes()
                .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
            || envelope.statement_sha256.len() != 64
            || !envelope
                .statement_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || envelope.canonical_bytes()? != bytes
        {
            return Err(invalid);
        }
        Ok(envelope)
    }

    pub fn verify(
        bytes: &[u8],
        signature: &[u8],
        public_key: &[u8],
        fingerprint: &str,
        now: i64,
    ) -> Result<Self, crate::agent_secret::SecretError> {
        use crate::agent_secret::{SecretError, SECRET_ISSUE_SKEW_LIMIT_MS};
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        let invalid = SecretError::ApprovalInvalid;
        let envelope = Self::parse_canonical(bytes, fingerprint)?;
        let key = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| invalid)?;
        let signature = Signature::from_der(signature).map_err(|_| invalid)?;
        key.verify(bytes, &signature).map_err(|_| invalid)?;
        if now.abs_diff(envelope.issued_at_ms as i64) > SECRET_ISSUE_SKEW_LIMIT_MS as u64 {
            return Err(invalid);
        }
        Ok(envelope)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
#[path = "gh_manifest_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "gh_manifest_envelope_tests.rs"]
mod envelope_tests;
