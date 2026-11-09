use super::{SecretMaterial, SecretRule, SecretScope, ValidationError};
use secret_rules::scope as rules;
use serde_json::{json, Value};
use ValidationError::{InvalidParams, LimitExceeded};

pub const MAX_SECRET_HOST_BYTES: usize = rules::MAX_HOST_BYTES;
pub const MAX_SECRET_PATH_PREFIX_BYTES: usize = rules::MAX_PREFIX_BYTES;
// Contract caps enforced by the shared parser and pinned by vault boundary tests.
pub const MAX_SECRET_RULES: usize = 8;
pub const MAX_SECRET_ORIGINS: usize = 4;
pub const MAX_SECRET_HEADER_BYTES: usize = 64;
pub const MAX_SECRET_QUERY_BYTES: usize = 64;
pub const MAX_SECRET_POINTER_BYTES: usize = 256;
pub const MAX_SECRET_USERNAME_BYTES: usize = 256;
pub const MAX_SECRET_PASSWORD_BYTES: usize = 1024;
pub const MAX_SECRET_API_KEY_BYTES: usize = 8192;
pub const MIN_SECRET_TOTP_PERIOD: u64 = 15;
pub const MAX_SECRET_TOTP_PERIOD: u64 = 120;

pub fn validate_host(host: &str) -> Result<(), ValidationError> {
    rules::SecretScope::parse_input("agent_api_key", &json!({"host": host}))
        .map(|_| ())
        .map_err(Into::into)
}

/// Compare origins without URL path normalization or accepting user information.
pub fn canonical_origin(origin: &str) -> Result<String, ValidationError> {
    rules::canonical_origin(origin)
        .map(str::to_owned)
        .map_err(Into::into)
}

impl From<rules::ScopeRefusal> for ValidationError {
    fn from(refusal: rules::ScopeRefusal) -> Self {
        match refusal {
            rules::ScopeRefusal::InvalidParams => InvalidParams,
            rules::ScopeRefusal::LimitExceeded => LimitExceeded,
        }
    }
}

impl SecretScope {
    /// The shared parser owns scope grammar; location remains vault-only metadata.
    pub(super) fn rule_fields(&self) -> Value {
        match self {
            Self::ApiKey {
                host, path_prefix, ..
            } => {
                let mut fields = json!({"host": host});
                if let Some(prefix) = path_prefix {
                    fields["path_prefix"] = json!(prefix);
                }
                fields
            }
            Self::SiteLogin { origin } => json!({"origin": origin}),
            Self::ApiKeyRules { rules, .. } => json!({"rules": rules}),
            Self::SiteLoginOrigins { origins } => json!({"origins": origins}),
        }
    }

    pub(super) fn stored_rule_fields(&self) -> Value {
        if !self.is_extended() {
            return self.rule_fields();
        }
        let mut fields = self.use_fields();
        if let Some(object) = fields.as_object_mut() {
            object.remove("location");
        }
        fields
    }

    /// Validate input without reordering it: the deposit's additional authenticated
    /// data authenticates the sent order.
    /// `fields` contains only the shared scope fields; location is vault metadata.
    pub fn from_input(
        kind: &str,
        fields: &Value,
        location: Option<&str>,
    ) -> Result<Self, ValidationError> {
        rules::SecretScope::parse_input(kind, fields)?;
        let scope = Self::from_rule_fields(kind, fields, location)?;
        scope.validate_location()?;
        Ok(scope)
    }

    fn from_rule_fields(
        kind: &str,
        fields: &Value,
        location: Option<&str>,
    ) -> Result<Self, ValidationError> {
        let text = |key| {
            fields
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(InvalidParams)
        };
        match kind {
            "agent_api_key" => {
                let location = location.ok_or(InvalidParams)?.to_owned();
                if let Some(entries) = fields.get("rules") {
                    let mut rules: Vec<SecretRule> =
                        serde_json::from_value(entries.clone()).map_err(|_| InvalidParams)?;
                    for rule in &mut rules {
                        if rule.path_prefix.as_deref() == Some("") {
                            rule.path_prefix = None;
                        }
                    }
                    Ok(Self::ApiKeyRules { rules, location })
                } else {
                    Ok(Self::ApiKey {
                        host: text("host")?,
                        path_prefix: fields
                            .get("path_prefix")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned),
                        location,
                    })
                }
            }
            "site_login" if location.is_none() => {
                if let Some(entries) = fields.get("origins") {
                    Ok(Self::SiteLoginOrigins {
                        origins: serde_json::from_value(entries.clone())
                            .map_err(|_| InvalidParams)?,
                    })
                } else {
                    Ok(Self::SiteLogin {
                        origin: text("origin")?,
                    })
                }
            }
            _ => Err(InvalidParams),
        }
    }

    fn validate_location(&self) -> Result<(), ValidationError> {
        match self {
            Self::ApiKey { location, .. } | Self::ApiKeyRules { location, .. } => {
                validate_location(location)
            }
            Self::SiteLogin { .. } | Self::SiteLoginOrigins { .. } => Ok(()),
        }
    }

    /// Stored scopes obey grammar and limits, but never recheck the public suffix list.
    pub fn canonicalized(&self) -> Result<Self, ValidationError> {
        rules::SecretScope::decode_stored(self.kind(), &self.stored_rule_fields())?;
        self.validate_location()?;
        let mut scope = self.clone();
        match &mut scope {
            Self::ApiKeyRules { rules, .. } => rules.sort_by(|a, b| {
                (&a.host, a.path_prefix.as_deref().unwrap_or(""))
                    .cmp(&(&b.host, b.path_prefix.as_deref().unwrap_or("")))
            }),
            Self::SiteLoginOrigins { origins } => origins.sort(),
            _ => {}
        }
        Ok(scope)
    }

    /// Vault-emitted scope fields always include an empty prefix when it is absent.
    pub fn use_fields(&self) -> Value {
        match self {
            Self::ApiKey {
                host,
                path_prefix,
                location,
            } => {
                json!({"host": host, "path_prefix": path_prefix.as_deref().unwrap_or(""), "location": location})
            }
            Self::ApiKeyRules { rules, location } => {
                let mut rules = rules.clone();
                rules.sort_by(|a, b| {
                    (&a.host, a.path_prefix.as_deref().unwrap_or(""))
                        .cmp(&(&b.host, b.path_prefix.as_deref().unwrap_or("")))
                });
                let rules: Vec<_> = rules.iter().map(|r| json!({"host": r.host, "path_prefix": r.path_prefix.as_deref().unwrap_or("")})).collect();
                json!({"rules": rules, "location": location})
            }
            Self::SiteLoginOrigins { origins } => {
                let mut origins = origins.clone();
                origins.sort();
                json!({"origins": origins})
            }
            Self::SiteLogin { origin } => json!({"origin": origin}),
        }
    }

    /// The last table column contains only the canonical array, not location.
    pub fn scope_json(&self) -> Result<Option<String>, ValidationError> {
        if !self.is_extended() {
            return Ok(None);
        }
        let canonical = self.canonicalized()?.use_fields();
        let array = if self.kind() == "agent_api_key" {
            &canonical["rules"]
        } else {
            &canonical["origins"]
        };
        // These arrays contain strings and ASCII-keyed objects only. serde_json's
        // sorted map keys and string escaping give their RFC 8785 canonical JSON bytes.
        serde_json::to_string(array)
            .map(Some)
            .map_err(|_| InvalidParams)
    }

    /// Refuse even parseable JSON if its bytes differ from the canonical stored form.
    pub fn from_scope_json(
        kind: &str,
        location: Option<&str>,
        raw: &str,
    ) -> Result<Self, ValidationError> {
        let array: Value = serde_json::from_str(raw).map_err(|_| InvalidParams)?;
        let fields = match kind {
            "agent_api_key" => json!({"rules": array}),
            "site_login" => json!({"origins": array}),
            _ => return Err(InvalidParams),
        };
        rules::SecretScope::decode_stored(kind, &fields)?;
        let scope = Self::from_rule_fields(kind, &fields, location)?.canonicalized()?;
        if scope.scope_json()?.as_deref() != Some(raw) {
            return Err(InvalidParams);
        }
        Ok(scope)
    }

    /// Decode the mutually exclusive legacy columns or the extended scope column.
    pub fn from_columns(
        kind: &str,
        host: Option<&str>,
        path_prefix: Option<&str>,
        location: Option<&str>,
        origin: Option<&str>,
        scope_json: Option<&str>,
    ) -> Result<Self, ValidationError> {
        match (kind, host, path_prefix, location, origin, scope_json) {
            ("agent_api_key", None, None, Some(location), None, Some(raw)) => {
                Self::from_scope_json(kind, Some(location), raw)
            }
            ("site_login", None, None, None, None, Some(raw)) => {
                Self::from_scope_json(kind, None, raw)
            }
            ("agent_api_key", Some(host), prefix, Some(location), None, None) => {
                let scope = Self::ApiKey {
                    host: host.to_owned(),
                    path_prefix: prefix.map(str::to_owned),
                    location: location.to_owned(),
                };
                scope.canonicalized()
            }
            ("site_login", None, None, None, Some(origin), None) => Self::SiteLogin {
                origin: origin.to_owned(),
            }
            .canonicalized(),
            _ => Err(InvalidParams),
        }
    }
}

pub fn validate_scope(scope: &SecretScope) -> Result<(), ValidationError> {
    rules::SecretScope::parse_input(scope.kind(), &scope.rule_fields())?;
    scope.validate_location()
}

/// Scope prefixes use the request-path grammar but cannot end with a slash.
pub fn validate_path_prefix(prefix: &str) -> Result<(), ValidationError> {
    // The crate exposes scope parsing rather than a standalone prefix validator.
    rules::SecretScope::parse_input(
        "agent_api_key",
        &json!({"host": "scope", "path_prefix": prefix}),
    )
    .map(|_| ())
    .map_err(Into::into)
}

/// Validate concrete request paths, which unlike scope prefixes may end in `/`.
pub fn validate_path(path: &str) -> Result<(), ValidationError> {
    if !path.starts_with('/')
        || path.contains("//")
        || path
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/%".contains(&b)))
    {
        return Err(InvalidParams);
    }
    let bytes = path.as_bytes();
    let mut decoded = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let pair = bytes.get(i + 1..i + 3).ok_or(InvalidParams)?;
            let pair = std::str::from_utf8(pair).map_err(|_| InvalidParams)?;
            let b = u8::from_str_radix(pair, 16).map_err(|_| InvalidParams)?;
            if b"/.%\\;".contains(&b) || !(0x21..=0x7e).contains(&b) {
                return Err(InvalidParams);
            }
            decoded.push(b);
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    if decoded
        .split(|b| *b == b'/')
        .any(|segment| matches!(segment.split(|b| *b == b';').next(), Some(b"." | b"..")))
    {
        return Err(InvalidParams);
    }
    Ok(())
}

pub fn validate_location(location: &str) -> Result<(), ValidationError> {
    if location == "authorization_bearer" {
        return Ok(());
    }
    let (kind, value) = location.split_once(':').ok_or(InvalidParams)?;
    if value.is_empty() {
        return Err(InvalidParams);
    }
    match kind {
        "header" => {
            if !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                || ["host", "cookie", "content-length", "authorization"]
                    .iter()
                    .any(|h| value.eq_ignore_ascii_case(h))
            {
                return Err(InvalidParams);
            }
            if value.len() > MAX_SECRET_HEADER_BYTES {
                return Err(LimitExceeded);
            }
        }
        "query" => {
            if !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                return Err(InvalidParams);
            }
            if value.len() > MAX_SECRET_QUERY_BYTES {
                return Err(LimitExceeded);
            }
        }
        "json_pointer" => {
            if !value.starts_with('/') || !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
                return Err(InvalidParams);
            }
            let mut chars = value.chars();
            while let Some(c) = chars.next() {
                if c == '~' && !matches!(chars.next(), Some('0' | '1')) {
                    return Err(InvalidParams);
                }
            }
            if value.len() > MAX_SECRET_POINTER_BYTES {
                return Err(LimitExceeded);
            }
        }
        _ => return Err(InvalidParams),
    }
    Ok(())
}

/// Validate opened deposit material and operator input with identical, content-free errors.
pub fn validate_material(material: &SecretMaterial) -> Result<(), ValidationError> {
    match material {
        SecretMaterial::ApiKey(key) => {
            if key.expose().is_empty() {
                return Err(InvalidParams);
            }
            if key.expose().len() > MAX_SECRET_API_KEY_BYTES {
                return Err(LimitExceeded);
            }
        }
        SecretMaterial::SiteLogin {
            username,
            password,
            otpauth,
        } => {
            if username.expose().len() > MAX_SECRET_USERNAME_BYTES
                || password.expose().len() > MAX_SECRET_PASSWORD_BYTES
            {
                return Err(LimitExceeded);
            }
            if let Some(uri) = otpauth {
                validate_otpauth(uri.expose())?;
            }
        }
    }
    Ok(())
}

pub(super) fn validate_otpauth(uri: &str) -> Result<(), ValidationError> {
    let url = url::Url::parse(uri).map_err(|_| InvalidParams)?;
    if url.scheme() != "otpauth"
        || url.host_str() != Some("totp")
        || url.path().len() <= 1
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.fragment().is_some()
    {
        return Err(InvalidParams);
    }
    let mut seen = std::collections::HashSet::new();
    let mut secret = false;
    for (key, value) in url.query_pairs() {
        if !seen.insert(key.to_string()) {
            return Err(InvalidParams);
        }
        match key.as_ref() {
            "secret" => {
                let unpadded = value.trim_end_matches('=');
                if unpadded.is_empty()
                    || !unpadded
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
                    || !matches!(unpadded.len() % 8, 0 | 2 | 4 | 5 | 7)
                {
                    return Err(InvalidParams);
                }
                secret = true;
            }
            "algorithm" if !matches!(value.as_ref(), "SHA1" | "SHA256" | "SHA512") => {
                return Err(InvalidParams)
            }
            "digits" if !matches!(value.as_ref(), "6" | "8") => return Err(InvalidParams),
            "period" => {
                let period = value.parse::<u64>().map_err(|_| InvalidParams)?;
                if !(MIN_SECRET_TOTP_PERIOD..=MAX_SECRET_TOTP_PERIOD).contains(&period) {
                    return Err(InvalidParams);
                }
            }
            "algorithm" | "digits" | "issuer" => {}
            _ => return Err(InvalidParams),
        }
    }
    if !secret {
        return Err(InvalidParams);
    }
    Ok(())
}

/// The operator `ck auth secret put` request, as the admin op hands it to the store.
///
/// The fields crossed a JSON admin op, so this type exists to turn its scope metadata
/// and base64 material back into the validated `SecretScope` and
/// `SecretMaterial` a phone deposit would have produced. Putting the conversion here
/// keeps one validator for both doors: a scope that a phone deposit refuses must be
/// refused by `put` as well, or the two would slowly accept different shapes.
///
/// `Debug` is hand-written to redact the material, exactly like `AdminOpBody`. A put
/// request is created by the CLI just before the admin op is serialized, and the most
/// likely place a panic message shows a local value is right there -- so the base64 text,
/// which decodes straight back to the password or key, must not render. The scope fields
/// stay visible because they are the metadata an operator needs to diagnose a refusal.
#[derive(Clone)]
pub struct SecretPut {
    pub kind: String,
    pub name: String,
    pub host: Option<String>,
    pub path_prefix: Option<String>,
    pub location: Option<String>,
    pub origin: Option<String>,
    /// Keep the input JSON intact so the shared parser owns shape and refusal order.
    pub rules: Option<Value>,
    pub origins: Option<Value>,
    /// Unpadded base64url of the deposit-plaintext bytes for `kind`.
    pub material_b64url: String,
}

impl SecretPut {
    /// Decode and validate everything but the name, which the store checks first so a
    /// bad name is reported before any other field.
    ///
    /// The returned errors deliberately carry no field of the request: `invalid_params`
    /// names no value, and the caller decides which rule to print for a human.
    pub fn scope_and_material(&self) -> Result<(SecretScope, SecretMaterial), ValidationError> {
        match self.kind.as_str() {
            "agent_api_key" if self.location.is_some() => {}
            "site_login" if self.location.is_none() => {}
            _ => return Err(InvalidParams),
        }
        let mut fields = serde_json::Map::new();
        for (key, value) in [
            ("host", &self.host),
            ("path_prefix", &self.path_prefix),
            ("origin", &self.origin),
        ] {
            if let Some(value) = value {
                fields.insert(key.into(), json!(value));
            }
        }
        for (key, value) in [("rules", &self.rules), ("origins", &self.origins)] {
            if let Some(value) = value {
                fields.insert(key.into(), value.clone());
            }
        }
        let scope =
            SecretScope::from_input(&self.kind, &Value::Object(fields), self.location.as_deref())?
                .canonicalized()?;
        let bytes = base64_url_no_pad(&self.material_b64url)?;
        let framed = super::Secret::new(bytes);
        let material = super::decode_deposit_plaintext(scope.kind(), &framed)?;
        validate_material(&material)?;
        Ok((scope, material))
    }
}

/// Strict unpadded base64url: trailing bits must be zero and no padding character may
/// appear, so one plaintext has exactly one encoding.
fn base64_url_no_pad(text: &str) -> Result<Vec<u8>, ValidationError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let bytes = URL_SAFE_NO_PAD
        .decode(text.as_bytes())
        .map_err(|_| InvalidParams)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != text {
        return Err(InvalidParams);
    }
    Ok(bytes)
}

impl std::fmt::Debug for SecretPut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretPut")
            .field("kind", &self.kind)
            .field("name", &self.name)
            .field("host", &self.host)
            .field("path_prefix", &self.path_prefix)
            .field("location", &self.location)
            .field("origin", &self.origin)
            .field("rules", &self.rules)
            .field("origins", &self.origins)
            .field("material_b64url", &"<redacted>")
            .finish()
    }
}
