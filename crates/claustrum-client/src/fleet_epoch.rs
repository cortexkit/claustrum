//! Fleet epoch records use the caller domain attested by the vault route.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::{CredentialErrorClass, CredentialResolverError, Secret};

const MAX_BATCH_ITEMS: usize = 256;

/// Bytes to seal under the current fleet epoch. The plaintext remains caller-owned.
#[derive(Debug, Clone, Copy)]
pub struct FleetEpochSealRequest<'a> {
    pub aad: &'a [u8],
    pub plaintext: &'a Secret<Vec<u8>>,
}

/// A sealed record and the exact associated data used to seal it.
#[derive(Debug, Clone, Copy)]
pub struct FleetEpochOpenRequest<'a> {
    pub epoch: u32,
    pub nonce: &'a [u8],
    pub ciphertext: &'a [u8],
    pub aad: &'a [u8],
}

/// Fleet epoch record to persist alongside its associated data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetEpochSeal {
    pub epoch: u32,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// One ordered slot of a successful open batch. The refusal's code and class
/// are those returned by the vault for that item.
pub type FleetEpochOpenResult = Result<Secret<Vec<u8>>, CredentialResolverError>;

#[derive(Deserialize)]
struct Reply<'a> {
    #[serde(borrow)]
    result: &'a RawValue,
}

#[derive(Deserialize)]
struct MaybeRefusal<'a> {
    #[serde(borrow)]
    error: Option<&'a RawValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Refusal<'a> {
    #[serde(borrow)]
    error: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireError<'a> {
    code: &'a str,
    class: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sealed<'a> {
    epoch: std::num::NonZeroU32,
    nonce: &'a str,
    ciphertext: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Opened<'a> {
    #[serde(borrow)]
    plaintext: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchReply<'a> {
    #[serde(borrow)]
    items: Vec<&'a RawValue>,
}

fn invalid_reply() -> CredentialResolverError {
    CredentialResolverError::new(
        CredentialErrorClass::InvalidResponse,
        "invalid fleet epoch reply",
    )
}

fn object<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, CredentialResolverError> {
    if bytes.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return Err(invalid_reply());
    }
    serde_json::from_slice(bytes).map_err(|_| invalid_reply())
}

fn result_body(bytes: &[u8]) -> Result<&RawValue, CredentialResolverError> {
    Ok(object::<Reply<'_>>(bytes)?.result)
}

fn refusal(body: &RawValue) -> Result<Option<CredentialResolverError>, CredentialResolverError> {
    if object::<MaybeRefusal<'_>>(body.get().as_bytes())?
        .error
        .is_none()
    {
        return Ok(None);
    }
    let refusal: Refusal<'_> = object(body.get().as_bytes())?;
    let error: WireError<'_> = object(refusal.error.get().as_bytes())?;
    let class = match error.class {
        "permanent" => CredentialErrorClass::Permanent,
        "transient" => CredentialErrorClass::Transient,
        _ => return Err(invalid_reply()),
    };
    // Fleet not_found is a permanent admission refusal, not an absent credential.
    Ok(Some(CredentialResolverError {
        class,
        code: error.code.to_owned(),
        safe_message: "vault refused the fleet epoch operation".to_owned(),
    }))
}

fn success_body(bytes: &[u8]) -> Result<&RawValue, CredentialResolverError> {
    let body = result_body(bytes)?;
    match refusal(body)? {
        Some(error) => Err(error),
        None => Ok(body),
    }
}

fn decode_sealed(body: &RawValue) -> Result<FleetEpochSeal, CredentialResolverError> {
    let sealed: Sealed<'_> = object(body.get().as_bytes())?;
    let mut nonce = [0; 24];
    let len = URL_SAFE_NO_PAD
        .decode_slice(sealed.nonce, &mut nonce)
        .map_err(|_| invalid_reply())?;
    if len != nonce.len() {
        return Err(invalid_reply());
    }
    Ok(FleetEpochSeal {
        epoch: sealed.epoch.get(),
        nonce,
        ciphertext: URL_SAFE_NO_PAD
            .decode(sealed.ciphertext)
            .map_err(|_| invalid_reply())?,
    })
}

fn decode_opened(body: &RawValue) -> Result<Secret<Vec<u8>>, CredentialResolverError> {
    let opened: Opened<'_> = object(body.get().as_bytes())?;
    // Canonical base64url needs no JSON escapes. Borrow the string's raw bytes
    // so even a malformed escaped value cannot leave a parser-owned copy.
    let encoded = opened
        .plaintext
        .get()
        .as_bytes()
        .strip_prefix(b"\"")
        .and_then(|value| value.strip_suffix(b"\""))
        .ok_or_else(invalid_reply)?;
    let mut plaintext = Secret::new(vec![0; base64::decoded_len_estimate(encoded.len())]);
    let len = URL_SAFE_NO_PAD
        .decode_slice(encoded, plaintext.expose_mut())
        .map_err(|_| invalid_reply())?;
    plaintext.expose_mut().truncate(len);
    Ok(plaintext)
}

fn valid_batch_size(count: usize) -> bool {
    (1..=MAX_BATCH_ITEMS).contains(&count)
}

fn batch_reply(bytes: &[u8]) -> Result<Vec<&RawValue>, CredentialResolverError> {
    let body: BatchReply<'_> = object(success_body(bytes)?.get().as_bytes())?;
    if !valid_batch_size(body.items.len()) {
        return Err(invalid_reply());
    }
    Ok(body.items)
}

/// Decodes the JSON body of a fleet seal Response frame (including a vault refusal).
/// Decode Error frames separately with [`crate::decode_wire_error`].
pub fn decode_fleet_epoch_seal_reply(
    bytes: &[u8],
) -> Result<FleetEpochSeal, CredentialResolverError> {
    decode_sealed(success_body(bytes)?)
}

/// Decodes the JSON body of a fleet open Response frame (including a vault refusal).
/// The input may hold encoded plaintext; keep it in zeroizing storage too.
pub fn decode_fleet_epoch_open_reply(bytes: &[u8]) -> FleetEpochOpenResult {
    decode_opened(success_body(bytes)?)
}

/// Decodes a fleet batch seal Response frame body, in wire order, or fails the whole reply.
pub fn decode_fleet_epoch_seal_batch_reply(
    bytes: &[u8],
) -> Result<Vec<FleetEpochSeal>, CredentialResolverError> {
    batch_reply(bytes)?.into_iter().map(decode_sealed).collect()
}

/// Decodes a fleet batch open Response frame body. An outer error is a whole-call
/// refusal or invalid reply; item refusals preserve their slots in a successful batch.
/// The input may hold encoded plaintext; keep it in zeroizing storage too.
pub fn decode_fleet_epoch_open_batch_reply(
    bytes: &[u8],
) -> Result<Vec<FleetEpochOpenResult>, CredentialResolverError> {
    batch_reply(bytes)?
        .into_iter()
        .map(|item| match refusal(item)? {
            Some(error) => Ok(Err(error)),
            None => decode_opened(item).map(Ok),
        })
        .collect()
}

#[cfg(any(feature = "transport", test))]
mod request;

#[cfg(test)]
mod tests;
