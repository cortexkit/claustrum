//! Consumer enrollment wire primitives shared by the store and route surface.
//!
//! Enrollment secrets and tokens deliberately use one grammar and one digest
//! construction: 32 bytes encoded as 64 lowercase hexadecimal characters, with the
//! persisted value being SHA-256 over the decoded bytes. Keeping that construction in
//! one module prevents request-secret verification and bearer-token verification from
//! drifting apart.

use serde::Serialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::store::StoreOpError;

pub const ENROLLMENT_LIVE_LIMIT: i64 = 16;
pub const ENROLLMENT_PENDING_TTL_MS: i64 = 15 * 60 * 1_000;
pub const ENROLLMENT_TERMINAL_MAX_ROWS: i64 = 256;
pub const ENROLLMENT_TERMINAL_RETENTION_MS: i64 = 24 * 60 * 60 * 1_000;

pub const ENROLL_PROPOSE_SUBJECT: &str = "auth.enroll_propose";
pub const ENROLL_POLL_SUBJECT: &str = "auth.enroll_poll";
pub const ENROLL_EXPIRE_SUBJECT: &str = "auth.enroll_expire";

/// Retry policy carried by enrollment transport errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentDisposition {
    Permanent,
    Transient,
}

/// The closed consumer-visible refusal vocabulary for enrollment operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentRefusal {
    InvalidParams,
    PendingExists,
    PendingQueueFull,
    NotFound,
    AlreadyConsumed,
    Superseded,
    StaleGeneration,
}

impl EnrollmentRefusal {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidParams => "invalid_params",
            Self::PendingExists => "pending_exists",
            Self::PendingQueueFull => "pending_queue_full",
            Self::NotFound => "not_found",
            Self::AlreadyConsumed => "already_consumed",
            Self::Superseded => "superseded",
            Self::StaleGeneration => "stale_generation",
        }
    }

    pub const fn disposition(self) -> EnrollmentDisposition {
        match self {
            Self::PendingQueueFull => EnrollmentDisposition::Transient,
            Self::InvalidParams
            | Self::PendingExists
            | Self::NotFound
            | Self::AlreadyConsumed
            | Self::Superseded
            | Self::StaleGeneration => EnrollmentDisposition::Permanent,
        }
    }
}

/// A ceremony failure. Store failures remain transport errors but are intentionally
/// collapsed to one transient code so database detail never reaches an anonymous caller.
#[derive(Debug)]
pub enum EnrollmentError {
    Refused(EnrollmentRefusal),
    Store(StoreOpError),
}

impl EnrollmentError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Refused(refusal) => refusal.code(),
            Self::Store(_) => "store_error",
        }
    }

    pub const fn disposition(&self) -> EnrollmentDisposition {
        match self {
            Self::Refused(refusal) => refusal.disposition(),
            Self::Store(_) => EnrollmentDisposition::Transient,
        }
    }
}

impl From<StoreOpError> for EnrollmentError {
    fn from(value: StoreOpError) -> Self {
        Self::Store(value)
    }
}

/// The successful result of an enrollment proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnrollmentProposal {
    pub request_id: String,
}

/// A successful poll is one of the three states a consumer may continue from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EnrollmentPoll {
    Pending,
    Denied,
    Approved {
        name: String,
        token: String,
        token_generation: u64,
    },
}

/// The successful result of rotating a live enrollment token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnrollmentRotation {
    pub token: String,
    pub token_generation: u64,
}

/// Names use the same 2–32 byte lowercase label grammar as categories.
pub fn valid_enrollment_name(name: &str) -> bool {
    crate::catalog::valid_category_name(name)
}

/// True only for the exact secret/token/hash wire grammar.
pub fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Decode the exact 32-byte lowercase-hex grammar.
pub fn decode_lower_hex_32(value: &str) -> Option<[u8; 32]> {
    if !is_lower_hex_32(value) {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(decoded)
}

/// Hash decoded secret/token bytes and return the persisted lowercase-hex digest.
pub fn enrollment_secret_hash(value: &str) -> Option<String> {
    let decoded = decode_lower_hex_32(value)?;
    let digest: [u8; 32] = Sha256::digest(decoded).into();
    Some(hex32(&digest))
}

/// Compare fixed-size lowercase-hex digests without data-dependent early exit.
pub fn constant_time_hash_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    left.len() == 64 && right.len() == 64 && bool::from(left.ct_eq(right))
}

/// Mint 32 CSPRNG bytes in the exact token/request-id wire encoding.
pub(crate) fn mint_hex_32() -> Result<String, StoreOpError> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| StoreOpError::Encode(format!("enrollment csprng: {error}")))?;
    Ok(hex32(&bytes))
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_and_token_hash_share_one_fixed_vector() {
        let raw = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let expected =
            "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abC1b8581bd710dd".to_ascii_lowercase();
        assert_eq!(
            enrollment_secret_hash(raw).as_deref(),
            Some(expected.as_str())
        );
    }

    #[test]
    fn exact_lowercase_hex_grammar_rejects_near_misses() {
        let valid = "ab".repeat(32);
        assert!(is_lower_hex_32(&valid));
        for invalid in [
            "a".repeat(63),
            "a".repeat(65),
            "AB".repeat(32),
            format!("{}g", "a".repeat(63)),
        ] {
            assert!(!is_lower_hex_32(&invalid), "accepted {invalid}");
            assert!(enrollment_secret_hash(&invalid).is_none());
        }
    }
}
