//! Fleet epoch vocabulary. Epoch secrets never cross the store API in plaintext.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

// Byte literals feed the generated domain-separator inventory; JSON uses their
// UTF-8 form. Both representations derive from the same format constant.
pub const WRAP_DOMAIN: &str = domain(b"ck-fleet-epoch-wrap/v1");
pub const AAD_DOMAIN: &str = domain(b"ck-fleet-epoch-aad/v1");
pub const PREFRONTAL_AAD_DOMAIN: &str = domain(b"ck-fleet-epoch-aad/prefrontal/v1");
pub const STORE_DOMAIN: &str = domain(b"ck-fleet-epoch-store/v1");
const fn domain(bytes: &[u8]) -> &str {
    match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => panic!("domain separators must be UTF-8"),
    }
}
pub const WRAP_KEY_ID: &str = "kem:fleet-epoch-wrap:1";
pub const RECORD_KEY_ID: &str = "signing:fleet-record:1";
pub const BUS_KEY_ID: &str = "kem:bus-seal:1";
pub const MAX_BYTES: usize = 1024 * 1024;
pub const MAX_BATCH_ITEMS: usize = 256;
pub const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_HOLDERS: usize = 64;
pub const MAX_EPOCHS: usize = 256;

/// The vault selects the authenticated-data domain from the attested caller.
/// This is not a wire value and cannot be supplied in fleet request parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FleetSealer {
    Entorhinal,
    Prefrontal,
}

pub struct FleetSealInput<'a> {
    pub aad: &'a [u8],
    pub plaintext: &'a [u8],
}

pub struct FleetOpenInput<'a> {
    pub epoch: u32,
    pub nonce: &'a [u8],
    pub ciphertext: &'a [u8],
    pub aad: &'a [u8],
}

pub type FleetOpenResult = Result<crate::secret::Secret<Vec<u8>>, FleetError>;

impl FleetSealInput<'_> {
    pub fn validate(&self) -> Result<usize, FleetError> {
        if self.aad.len() > MAX_BYTES || self.plaintext.len() > MAX_BYTES {
            return Err(FleetError::InvalidParams);
        }
        Ok(self.aad.len() + self.plaintext.len())
    }
}

impl FleetOpenInput<'_> {
    pub fn validate(&self) -> Result<usize, FleetError> {
        if self.epoch == 0
            || self.nonce.len() != 24
            || self.ciphertext.len() < 16
            || self.ciphertext.len() > MAX_BYTES + 16
            || self.aad.len() > MAX_BYTES
        {
            return Err(FleetError::InvalidParams);
        }
        Ok(self.aad.len() + self.ciphertext.len())
    }
}

pub fn validate_batch(
    count: usize,
    sizes: impl Iterator<Item = Result<usize, FleetError>>,
) -> Result<(), FleetError> {
    if !(1..=MAX_BATCH_ITEMS).contains(&count) {
        return Err(FleetError::InvalidParams);
    }
    let mut total = 0usize;
    for size in sizes {
        total = total
            .checked_add(size?)
            .filter(|total| *total <= MAX_BATCH_BYTES)
            .ok_or(FleetError::InvalidParams)?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetRemoval {
    pub member_id: String,
    pub removal_id: String,
}

/// The daemon formats refusals; this enum defines their complete code vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FleetError {
    InvalidParams,
    NotFound,
    EpochUnavailable,
    EpochPending,
    PeerKeysUnavailable,
    MembersMismatch,
    EpochNotPending,
    EpochOpenFailed,
    WrapRefused,
    EpochCapacity,
    Corrupt { epoch: u32 },
    StoreError,
}

impl FleetError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidParams => "invalid_params",
            Self::NotFound => "not_found",
            Self::EpochUnavailable => "fleet_epoch_unavailable",
            Self::EpochPending => "fleet_epoch_pending",
            Self::PeerKeysUnavailable => "fleet_peer_keys_unavailable",
            Self::MembersMismatch => "fleet_members_mismatch",
            Self::EpochNotPending => "fleet_epoch_not_pending",
            Self::EpochOpenFailed => "fleet_epoch_open_failed",
            Self::WrapRefused => "fleet_wrap_refused",
            Self::EpochCapacity => "fleet_epoch_capacity",
            Self::Corrupt { .. } => "corrupt",
            Self::StoreError => "store_error",
        }
    }

    pub fn class(self) -> &'static str {
        match self {
            Self::EpochUnavailable
            | Self::EpochPending
            | Self::PeerKeysUnavailable
            | Self::StoreError => "transient",
            _ => "permanent",
        }
    }
}

impl std::fmt::Display for FleetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for FleetError {}
impl From<String> for FleetError {
    fn from(_: String) -> Self {
        Self::StoreError
    }
}
impl From<rusqlite::Error> for FleetError {
    fn from(_: rusqlite::Error) -> Self {
        Self::StoreError
    }
}

/// A checked Callosum computer entry. Construction does not authorize a snapshot;
/// each store operation also rejects duplicates and consults durable removals.
#[derive(Clone, Debug)]
pub struct FleetPeer {
    member_id: String,
    public_key: [u8; 32],
}

impl FleetPeer {
    pub fn new(member_id: String, public_key: [u8; 32]) -> Result<Self, FleetError> {
        if !crate::federation::valid_member_id(&member_id)
            || !crate::kem::valid_recipient_public_key(&public_key)
        {
            return Err(FleetError::PeerKeysUnavailable);
        }
        Ok(Self {
            member_id,
            public_key,
        })
    }
    pub fn member_id(&self) -> &str {
        &self.member_id
    }
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetWrap {
    pub ct: String,
    pub enc: String,
    pub from: String,
    pub to: String,
    pub v: String,
}

#[derive(Serialize)]
pub struct FleetMemberWrap {
    pub member_id: String,
    pub wrap: FleetWrap,
}

#[derive(Serialize)]
pub struct FleetMint {
    pub epoch: u32,
    pub mint_id: String,
    pub wraps: Vec<FleetMemberWrap>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct FleetPending {
    pub epoch: u32,
    pub mint_id: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct FleetStatus {
    pub current: Option<u32>,
    pub held: Vec<u32>,
    pub pending: Option<FleetPending>,
    pub sealing_blocked_by: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct FleetTransition {
    pub epoch: u32,
    pub state: &'static str,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct FleetImport {
    pub epochs: Vec<u32>,
    pub already_held: bool,
}

#[derive(Debug, Serialize)]
pub struct FleetSealed {
    pub epoch: u32,
    pub nonce: String,
    pub ciphertext: String,
}

// Secret-bearing wire structs are deliberately not Debug-derived, including their
// containers: a future field must not accidentally become a logging surface.
macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => { $(
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($ty), "([REDACTED])"))
            }
        }
    )+ };
}
pub(crate) use redacted_debug;
redacted_debug!(
    FleetWrap,
    FleetMemberWrap,
    FleetMint,
    WrapKey,
    WrapPlaintext
);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WrapKey {
    pub epoch: u32,
    pub key: String,
    pub members: Vec<String>,
    pub minter: String,
}
impl Drop for WrapKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WrapPlaintext {
    pub keys: Vec<WrapKey>,
    pub kind: String,
    pub v: String,
}

pub(crate) fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
pub(crate) fn decode(value: &str, max: usize) -> Result<Zeroizing<Vec<u8>>, FleetError> {
    if value.len() > max.div_ceil(3) * 4 {
        return Err(FleetError::InvalidParams);
    }
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| FleetError::InvalidParams)?,
    );
    if bytes.len() > max || encode(&bytes) != value {
        return Err(FleetError::InvalidParams);
    }
    Ok(bytes)
}

pub(crate) fn valid_members(members: &[String]) -> bool {
    !members.is_empty()
        && members.len() <= MAX_HOLDERS
        && members
            .iter()
            .all(|id| crate::federation::valid_member_id(id))
        && members.windows(2).all(|pair| pair[0] < pair[1])
}

pub(crate) fn wrap_info(from: &str, to: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"from": from, "to": to, "v": WRAP_DOMAIN}))
        .expect("string-only JSON")
}

pub(crate) fn record_aad(sealer: FleetSealer, epoch: u32, aad: &[u8]) -> Vec<u8> {
    let domain = match sealer {
        FleetSealer::Entorhinal => AAD_DOMAIN,
        FleetSealer::Prefrontal => PREFRONTAL_AAD_DOMAIN,
    };
    serde_json::to_vec(&serde_json::json!({"aad": encode(aad), "epoch": epoch, "v": domain}))
        .expect("string-only JSON")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fleet_caller_aad_bytes_keep_legacy_and_prefrontal_domains() {
        assert_eq!(
            record_aad(FleetSealer::Entorhinal, 7, b"room"),
            br#"{"aad":"cm9vbQ","epoch":7,"v":"ck-fleet-epoch-aad/v1"}"#
        );
        assert_eq!(
            record_aad(FleetSealer::Prefrontal, 7, b"room"),
            br#"{"aad":"cm9vbQ","epoch":7,"v":"ck-fleet-epoch-aad/prefrontal/v1"}"#
        );
    }

    #[test]
    fn canonical_bytes_and_member_boundaries() {
        assert!(decode(&encode(&vec![1; MAX_BYTES]), MAX_BYTES).is_ok());
        assert!(decode(&encode(&vec![1; MAX_BYTES + 1]), MAX_BYTES).is_err());
        for bad in ["YQ==", "YQ=", "YR", "a+"] {
            assert!(decode(bad, MAX_BYTES).is_err());
        }
        let members: Vec<_> = (0..MAX_HOLDERS)
            .map(|i| format!("fed-computer:{i:032x}"))
            .collect();
        assert!(valid_members(&members));
        let mut too_many = members;
        too_many.push(format!("fed-computer:{:032x}", MAX_HOLDERS));
        assert!(!valid_members(&too_many));
    }

    #[test]
    fn secret_bearing_debug_is_redacted() {
        let wrap = FleetWrap {
            ct: "wrap-ciphertext".into(),
            enc: "wrap-enc".into(),
            from: "sender".into(),
            to: "recipient".into(),
            v: WRAP_DOMAIN.into(),
        };
        assert_eq!(format!("{wrap:?}"), "FleetWrap([REDACTED])");
        let member = FleetMemberWrap {
            member_id: "recipient".into(),
            wrap,
        };
        assert_eq!(format!("{member:?}"), "FleetMemberWrap([REDACTED])");
        let mint = FleetMint {
            epoch: 1,
            mint_id: "id".into(),
            wraps: vec![member],
        };
        assert_eq!(format!("{mint:?}"), "FleetMint([REDACTED])");
        let key = WrapKey {
            epoch: 1,
            key: "epoch-secret".into(),
            members: vec![],
            minter: "sender".into(),
        };
        assert_eq!(format!("{key:?}"), "WrapKey([REDACTED])");
        let plaintext = WrapPlaintext {
            keys: vec![key],
            kind: "join".into(),
            v: WRAP_DOMAIN.into(),
        };
        assert_eq!(format!("{plaintext:?}"), "WrapPlaintext([REDACTED])");
    }
}
