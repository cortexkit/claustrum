use super::{SecretMaterial, SecretScope, ValidationError};
use ValidationError::{InvalidParams, LimitExceeded};

pub const MAX_SECRET_HOST_BYTES: usize = 253;
pub const MAX_SECRET_PATH_PREFIX_BYTES: usize = 1024;
pub const MAX_SECRET_HEADER_BYTES: usize = 64;
pub const MAX_SECRET_QUERY_BYTES: usize = 64;
pub const MAX_SECRET_POINTER_BYTES: usize = 256;
pub const MAX_SECRET_USERNAME_BYTES: usize = 256;
pub const MAX_SECRET_PASSWORD_BYTES: usize = 1024;
pub const MAX_SECRET_API_KEY_BYTES: usize = 8192;
pub const MIN_SECRET_TOTP_PERIOD: u64 = 15;
pub const MAX_SECRET_TOTP_PERIOD: u64 = 120;
pub const MAX_SECRET_DISPLAY_NAME_BYTES: usize = 128;

pub fn validate_display_name(name: &str) -> Result<(), ValidationError> {
    use unicode_general_category::{get_general_category, GeneralCategory};
    if name.is_empty()
        || name.chars().any(|c| {
            matches!(
                get_general_category(c),
                GeneralCategory::Control
                    | GeneralCategory::Format
                    | GeneralCategory::LineSeparator
                    | GeneralCategory::ParagraphSeparator
            )
        })
    {
        return Err(InvalidParams);
    }
    if name.len() > MAX_SECRET_DISPLAY_NAME_BYTES {
        return Err(LimitExceeded);
    }
    Ok(())
}

pub fn validate_host(host: &str) -> Result<(), ValidationError> {
    if host.is_empty()
        || host.ends_with('.')
        || host.parse::<std::net::IpAddr>().is_ok()
        || !host.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    {
        return Err(InvalidParams);
    }
    if host.len() > MAX_SECRET_HOST_BYTES {
        return Err(LimitExceeded);
    }
    Ok(())
}

/// Compare origins without URL path normalization or accepting user information.
pub fn canonical_origin(origin: &str) -> Result<String, ValidationError> {
    let authority = origin.strip_prefix("https://").ok_or(InvalidParams)?;
    let host = authority.strip_suffix(":443").unwrap_or(authority);
    validate_host(host)?;
    Ok(format!("https://{host}"))
}

pub fn validate_scope(scope: &SecretScope) -> Result<(), ValidationError> {
    match scope {
        SecretScope::ApiKey {
            host,
            path_prefix,
            location,
        } => {
            validate_host(host)?;
            if let Some(prefix) = path_prefix {
                validate_path(prefix)?;
                if prefix.ends_with('/') {
                    return Err(InvalidParams);
                }
                if prefix.len() > MAX_SECRET_PATH_PREFIX_BYTES {
                    return Err(LimitExceeded);
                }
            }
            validate_location(location)
        }
        SecretScope::SiteLogin { origin } => {
            canonical_origin(origin)?;
            Ok(())
        }
    }
}

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

fn validate_location(location: &str) -> Result<(), ValidationError> {
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
