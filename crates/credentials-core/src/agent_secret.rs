//! Agent-secret storage formats, separate from the credential record vocabulary.
use crate::{envelope, key::MasterKey, secret::Secret, RecordBinding};
use sha2::{Digest, Sha256};

pub const DEPOSIT_KEY_ID: &str = "kem:secret-deposit:1";
pub const DEPOSIT_KEY_PREFIX: &str = "kem:secret-deposit:";
pub const DEPOSIT_INFO: &[u8] = b"cortexkit/claustrum/secret-deposit/v1";
pub const DEPOSIT_AAD_TAG: &[u8] = b"ck-secret-deposit-aad/v1";
pub const DEPOSIT_PLAINTEXT_TAG: &[u8] = b"ck-secret-deposit-plaintext/v1";
pub const SEALED_BODY_TAG: &[u8] = b"ck-secret-sealed-body/v1";
pub const USE_STATEMENT_TAG: &[u8] = b"ck-secret-use-statement/v1";
pub const FLOW_STATEMENT_TAG: &[u8] = b"ck-secret-flow-statement/v1";
pub const DELETE_STATEMENT_TAG: &[u8] = b"ck-secret-delete-statement/v1";
pub const USE_ENVELOPE_TAG: &[u8] = b"ck-secret-use-envelope/v1";
pub const MAX_SECRET_NAME_BYTES: usize = 64;
pub const SECRET_RECORD_VERSION: u64 = 1;

#[path = "agent_secret_totp.rs"]
mod totp;
#[path = "agent_secret_validation.rs"]
mod validation;
pub use totp::totp;
#[path = "agent_secret_use.rs"]
mod use_types;
pub use use_types::*;
pub use validation::*;
#[path = "agent_secret_approval.rs"]
mod approval;
pub use approval::*;

pub fn validate_phone_approval_key(bytes: &[u8]) -> Result<(), ValidationError> {
    if bytes.len() != 65 || bytes.first() != Some(&4) {
        return Err(ValidationError::InvalidParams);
    }
    p256::PublicKey::from_sec1_bytes(bytes).map_err(|_| ValidationError::InvalidParams)?;
    Ok(())
}

/// Stable refusal vocabulary shared by the phone transport and its store transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretError {
    InvalidParams,
    LimitExceeded,
    NotFound,
    PairingUnavailable,
    PhoneNotRegistered,
    PhoneKeyConflict,
    DepositConflict,
    NameExists,
    SecretSetupIncomplete,
    ApprovalInvalid,
    PendingLimit,
    StoreError,
}

impl SecretError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidParams => "invalid_params",
            Self::LimitExceeded => "limit_exceeded",
            Self::NotFound => "not_found",
            Self::PairingUnavailable => "pairing_unavailable",
            Self::PhoneNotRegistered => "phone_not_registered",
            Self::PhoneKeyConflict => "phone_key_conflict",
            Self::DepositConflict => "deposit_conflict",
            Self::NameExists => "name_exists",
            Self::SecretSetupIncomplete => "secret_setup_incomplete",
            Self::ApprovalInvalid => "approval_invalid",
            Self::PendingLimit => "pending_limit",
            Self::StoreError => "store_error",
        }
    }

    pub const fn class(self) -> &'static str {
        match self {
            Self::LimitExceeded => "context_overflow",
            Self::PairingUnavailable | Self::PendingLimit | Self::StoreError => "transient",
            _ => "permanent",
        }
    }

    pub fn body(self) -> serde_json::Value {
        serde_json::json!({"error":{"code":self.code(),"class":self.class()}})
    }
}

impl From<ValidationError> for SecretError {
    fn from(value: ValidationError) -> Self {
        match value {
            ValidationError::InvalidParams => Self::InvalidParams,
            ValidationError::LimitExceeded => Self::LimitExceeded,
        }
    }
}

/// Reserved deposit-key namespace. The suffix may not contain `|`, because a secret name
/// cannot either: that keeps `kem:secret-deposit:|` out of this predicate and out of the
/// `secret|<name>` target form the operator delete uses, so the two namespaces stay
/// disjoint and an operator delete can never address the vault's own deposit key.
pub fn is_deposit_key(id: &str) -> bool {
    if !id.starts_with(DEPOSIT_KEY_PREFIX) || id.contains('|') {
        return false;
    }
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationError {
    InvalidParams,
    LimitExceeded,
}

impl ValidationError {
    pub fn wire_code(self) -> &'static str {
        match self {
            Self::InvalidParams => "invalid_params",
            Self::LimitExceeded => "limit_exceeded",
        }
    }
}

pub fn validate_name(name: &str) -> Result<(), ValidationError> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(b))
    {
        return Err(ValidationError::InvalidParams);
    }
    if bytes.len() > MAX_SECRET_NAME_BYTES {
        return Err(ValidationError::LimitExceeded);
    }
    Ok(())
}

/// Release-governing metadata. An API key cannot be represented without a location.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretScope {
    ApiKey {
        host: String,
        path_prefix: Option<String>,
        location: String,
    },
    SiteLogin {
        origin: String,
    },
}

impl SecretScope {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ApiKey { .. } => "agent_api_key",
            Self::SiteLogin { .. } => "site_login",
        }
    }

    fn encode_fields(&self, out: &mut Vec<u8>) -> Result<(), ValidationError> {
        match self {
            Self::ApiKey {
                host,
                path_prefix,
                location,
            } => {
                if location.is_empty() {
                    return Err(ValidationError::InvalidParams);
                }
                push_field(out, host.as_bytes());
                push_field(out, path_prefix.as_deref().unwrap_or("").as_bytes());
                push_field(out, location.as_bytes());
            }
            Self::SiteLogin { origin } => push_field(out, origin.as_bytes()),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretMaterial {
    ApiKey(Secret<Vec<u8>>),
    SiteLogin {
        username: Secret<String>,
        password: Secret<String>,
        otpauth: Option<Secret<String>>,
    },
}

impl SecretMaterial {
    fn encode_fields(&self, out: &mut Vec<u8>) {
        match self {
            Self::ApiKey(key) => push_field(out, key.expose()),
            Self::SiteLogin {
                username,
                password,
                otpauth,
            } => {
                push_field(out, username.expose().as_bytes());
                push_field(out, password.expose().as_bytes());
                push_field(
                    out,
                    otpauth
                        .as_ref()
                        .map(|s| s.expose().as_bytes())
                        .unwrap_or(b""),
                );
            }
        }
    }

    fn matches(&self, scope: &SecretScope) -> bool {
        matches!(
            (self, scope),
            (Self::ApiKey(_), SecretScope::ApiKey { .. })
                | (Self::SiteLogin { .. }, SecretScope::SiteLogin { .. })
        )
    }
}

pub fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u64).to_le_bytes());
    out.extend_from_slice(field);
}

pub fn deposit_aad(
    deposit_id: &str,
    member_id: &str,
    name: &str,
    scope: &SecretScope,
) -> Result<Vec<u8>, ValidationError> {
    validate_name(name)?;
    let mut out = Vec::new();
    for field in [
        DEPOSIT_AAD_TAG,
        deposit_id.as_bytes(),
        member_id.as_bytes(),
        name.as_bytes(),
        scope.kind().as_bytes(),
    ] {
        push_field(&mut out, field);
    }
    scope.encode_fields(&mut out)?;
    Ok(out)
}

pub fn deposit_plaintext(material: &SecretMaterial) -> Secret<Vec<u8>> {
    let mut out = Secret::new(Vec::new()).into_inner();
    push_field(&mut out, DEPOSIT_PLAINTEXT_TAG);
    material.encode_fields(&mut out);
    Secret::new(std::mem::take(&mut *out))
}

pub fn sealed_body(
    scope: &SecretScope,
    material: &SecretMaterial,
) -> Result<Secret<Vec<u8>>, ValidationError> {
    if !material.matches(scope) {
        return Err(ValidationError::InvalidParams);
    }
    let mut out = Secret::new(Vec::new()).into_inner();
    push_field(&mut out, SEALED_BODY_TAG);
    push_field(&mut out, scope.kind().as_bytes());
    scope.encode_fields(&mut out)?;
    material.encode_fields(&mut out);
    Ok(Secret::new(std::mem::take(&mut *out)))
}

pub fn record_binding(
    kind: &str,
    incarnation: &str,
    name: &str,
) -> Result<String, ValidationError> {
    validate_name(name)?;
    if !matches!(kind, "agent_api_key" | "site_login")
        || incarnation.len() != 32
        || !incarnation
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ValidationError::InvalidParams);
    }
    Ok(format!("secret|{kind}|{incarnation}|{name}"))
}

pub fn seal(
    key: &MasterKey,
    incarnation: &str,
    name: &str,
    scope: &SecretScope,
    material: &SecretMaterial,
) -> Result<Vec<u8>, ValidationError> {
    let id = record_binding(scope.kind(), incarnation, name)?;
    let body = sealed_body(scope, material)?;
    envelope::seal(
        key,
        body.expose(),
        &RecordBinding {
            credential_id: &id,
            record_version: SECRET_RECORD_VERSION,
        },
    )
    .map_err(|_| ValidationError::InvalidParams)
}

/// Open and compare the authenticated scope before allowing any material to escape.
pub fn open(
    key: &MasterKey,
    incarnation: &str,
    name: &str,
    scope: &SecretScope,
    blob: &[u8],
) -> Result<SecretMaterial, ValidationError> {
    let id = record_binding(scope.kind(), incarnation, name)?;
    let body = envelope::open(
        key,
        blob,
        &RecordBinding {
            credential_id: &id,
            record_version: SECRET_RECORD_VERSION,
        },
    )
    .map_err(|_| ValidationError::InvalidParams)?;
    let mut reader = Fields(&body);
    reader.expect(SEALED_BODY_TAG)?;
    reader.expect(scope.kind().as_bytes())?;
    let mut expected = Vec::new();
    scope.encode_fields(&mut expected)?;
    if !reader.0.starts_with(&expected) {
        return Err(ValidationError::InvalidParams);
    }
    reader.0 = &reader.0[expected.len()..];
    let material = reader.material(scope.kind())?;
    reader.end()?;
    Ok(material)
}

pub fn decode_deposit_plaintext(
    kind: &str,
    bytes: &Secret<Vec<u8>>,
) -> Result<SecretMaterial, ValidationError> {
    let mut reader = Fields(bytes.expose());
    reader.expect(DEPOSIT_PLAINTEXT_TAG)?;
    let material = reader.material(kind)?;
    reader.end()?;
    Ok(material)
}

struct Fields<'a>(&'a [u8]);
impl<'a> Fields<'a> {
    fn next(&mut self) -> Result<&'a [u8], ValidationError> {
        let len = self.0.get(..8).ok_or(ValidationError::InvalidParams)?;
        let len = usize::try_from(u64::from_le_bytes(len.try_into().unwrap()))
            .map_err(|_| ValidationError::InvalidParams)?;
        self.0 = &self.0[8..];
        let value = self.0.get(..len).ok_or(ValidationError::InvalidParams)?;
        self.0 = &self.0[len..];
        Ok(value)
    }
    fn expect(&mut self, expected: &[u8]) -> Result<(), ValidationError> {
        if self.next()? == expected {
            Ok(())
        } else {
            Err(ValidationError::InvalidParams)
        }
    }
    fn text(&mut self) -> Result<Secret<String>, ValidationError> {
        let value =
            std::str::from_utf8(self.next()?).map_err(|_| ValidationError::InvalidParams)?;
        Ok(Secret::new(value.to_owned()))
    }
    fn material(&mut self, kind: &str) -> Result<SecretMaterial, ValidationError> {
        match kind {
            "agent_api_key" => Ok(SecretMaterial::ApiKey(Secret::new(self.next()?.to_vec()))),
            "site_login" => {
                let username = self.text()?;
                let password = self.text()?;
                let uri = self.text()?;
                let otpauth = if uri.expose().is_empty() {
                    None
                } else {
                    Some(uri)
                };
                Ok(SecretMaterial::SiteLogin {
                    username,
                    password,
                    otpauth,
                })
            }
            _ => Err(ValidationError::InvalidParams),
        }
    }
    fn end(self) -> Result<(), ValidationError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::InvalidParams)
        }
    }
}

pub fn deposit_digest(deposit_id: &str, enc: &[u8], ciphertext: &[u8], aad: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for field in [deposit_id.as_bytes(), enc, ciphertext, aad] {
        hash.update((field.len() as u64).to_le_bytes());
        hash.update(field);
    }
    hash.finalize().into()
}

#[cfg(test)]
#[path = "agent_secret_tests.rs"]
mod tests;
