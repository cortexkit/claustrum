//! Validated release inputs. None of these types format the requested target path.
use super::{SecretScope, ValidationError};

pub const SECRET_PENDING_LIFETIME_LIMIT_MS: i64 = 600_000;
pub const MAX_SECRET_PENDING_PER_SCOPE: usize = 8;
pub const MAX_SECRET_PENDING_TOTAL: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SecretSender {
    Aft,
    Cerebellum,
}
impl SecretSender {
    pub fn actor(self) -> &'static str {
        match self {
            Self::Aft => "reserved:aft",
            Self::Cerebellum => "reserved:cerebellum",
        }
    }
    pub fn admits(self, scope: &SecretScope) -> bool {
        matches!(
            (self, scope),
            (Self::Aft, SecretScope::ApiKey { .. })
                | (Self::Cerebellum, SecretScope::SiteLogin { .. })
        )
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AskingScope {
    pub owner: String,
    pub kind: String,
    pub scope_ref: String,
    pub epoch: u64,
}

/// The module's `secret_use::serve` derives scope and parent only from a decoded
/// `subc_protocol::scope::ScopeStamp`, never from separate caller parameters.
pub struct SecretUse {
    pub name: String,
    pub sender: SecretSender,
    pub scope: AskingScope,
    pub worker_parent: Option<AskingScope>,
    pub coverage: String,
    pub agent_id: Option<String>,
    pub target: UseTarget,
}

pub enum UseTarget {
    ApiKey {
        scheme: String,
        host: String,
        port: u16,
        path: String,
    },
    SiteLogin {
        origin: String,
    },
}

impl UseTarget {
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::ApiKey {
                scheme, host, path, ..
            } => {
                if scheme.is_empty()
                    || !scheme.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b"+-.".contains(&b)
                    })
                {
                    return Err(ValidationError::InvalidParams);
                }
                super::validate_host(host)?;
                super::validate_path(path)
            }
            Self::SiteLogin { origin } => origin_parts(origin).map(|_| ()),
        }
    }

    pub fn matches(&self, scope: &SecretScope) -> bool {
        match (self, scope) {
            (
                Self::ApiKey {
                    scheme,
                    host,
                    port,
                    path,
                },
                SecretScope::ApiKey {
                    host: expected,
                    path_prefix,
                    ..
                },
            ) => {
                scheme == "https"
                    && *port == 443
                    && host == expected
                    && path_prefix.as_ref().is_none_or(|prefix| {
                        path == prefix
                            || path
                                .strip_prefix(prefix)
                                .is_some_and(|rest| rest.starts_with('/'))
                    })
            }
            (Self::SiteLogin { origin }, SecretScope::SiteLogin { origin: expected }) => {
                origin_parts(origin)
                    .ok()
                    .is_some_and(|(scheme, host, port)| {
                        scheme == "https"
                            && port == 443
                            && super::canonical_origin(expected).ok().as_deref()
                                == Some(format!("https://{host}").as_str())
                    })
            }
            _ => false,
        }
    }
}

fn origin_parts(origin: &str) -> Result<(&str, &str, u16), ValidationError> {
    let (scheme, authority) = origin
        .split_once("://")
        .ok_or(ValidationError::InvalidParams)?;
    if scheme.is_empty() || !scheme.bytes().all(|b| b.is_ascii_lowercase()) {
        return Err(ValidationError::InvalidParams);
    }
    let (host, port) = if let Some((host, port)) = authority.split_once(':') {
        (
            host,
            port.parse::<u16>()
                .map_err(|_| ValidationError::InvalidParams)?,
        )
    } else {
        (authority, if scheme == "https" { 443 } else { 80 })
    };
    super::validate_host(host)?;
    Ok((scheme, host, port))
}

/// Canonical ULID encoding with a cryptographically random 80-bit suffix.
pub fn request_id(now_ms: i64) -> Result<String, ValidationError> {
    let time = u64::try_from(now_ms).map_err(|_| ValidationError::InvalidParams)?;
    if time >= 1 << 48 {
        return Err(ValidationError::InvalidParams);
    }
    let mut random = [0u8; 10];
    getrandom::getrandom(&mut random).map_err(|_| ValidationError::InvalidParams)?;
    let mut value = u128::from(time) << 80;
    for (i, b) in random.iter().enumerate() {
        value |= u128::from(*b) << (8 * (9 - i));
    }
    let alphabet = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut text = [b'0'; 26];
    for c in text.iter_mut().rev() {
        *c = alphabet[(value & 31) as usize];
        value >>= 5;
    }
    String::from_utf8(text.to_vec()).map_err(|_| ValidationError::InvalidParams)
}
