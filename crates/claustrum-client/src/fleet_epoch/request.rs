use super::*;
use serde::{Serialize, Serializer};

const SEAL: &str = "fleet.epoch_seal";
const OPEN: &str = "fleet.epoch_open";
const SEAL_BATCH: &str = "fleet.epoch_seal_batch";
const OPEN_BATCH: &str = "fleet.epoch_open_batch";

#[derive(Serialize)]
struct Seal<'a> {
    #[serde(serialize_with = "encode_bytes")]
    aad: &'a [u8],
    #[serde(serialize_with = "encode_plaintext")]
    plaintext: &'a Secret<Vec<u8>>,
}

#[derive(Serialize)]
struct Open<'a> {
    epoch: u32,
    #[serde(serialize_with = "encode_bytes")]
    nonce: &'a [u8],
    #[serde(serialize_with = "encode_bytes")]
    ciphertext: &'a [u8],
    #[serde(serialize_with = "encode_bytes")]
    aad: &'a [u8],
}

#[derive(Serialize)]
struct Batch<T> {
    items: Vec<T>,
}

fn encode_bytes<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
}

fn encode_plaintext<S: Serializer>(
    plaintext: &Secret<Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let len = base64::encoded_len(plaintext.expose().len(), false)
        .ok_or_else(|| serde::ser::Error::custom("fleet epoch plaintext cannot be encoded"))?;
    let mut encoded = Secret::new(String::with_capacity(len));
    URL_SAFE_NO_PAD.encode_string(plaintext.expose(), encoded.expose_mut());
    serializer.serialize_str(encoded.expose())
}

impl<'a> From<FleetEpochSealRequest<'a>> for Seal<'a> {
    fn from(request: FleetEpochSealRequest<'a>) -> Self {
        Self {
            aad: request.aad,
            plaintext: request.plaintext,
        }
    }
}

impl<'a> From<FleetEpochOpenRequest<'a>> for Open<'a> {
    fn from(request: FleetEpochOpenRequest<'a>) -> Self {
        Self {
            epoch: request.epoch,
            nonce: request.nonce,
            ciphertext: request.ciphertext,
            aad: request.aad,
        }
    }
}

fn encode(
    method: &'static str,
    params: impl Serialize,
) -> Result<Secret<Vec<u8>>, CredentialResolverError> {
    crate::sensitive_wire::encode_request(method, params).map_err(|_| {
        CredentialResolverError::new(
            CredentialErrorClass::Permanent,
            "fleet epoch request encoding failed",
        )
    })
}

fn encode_batch<I: Copy, T: Serialize + From<I>>(
    method: &'static str,
    items: &[I],
) -> Result<Secret<Vec<u8>>, CredentialResolverError> {
    if !valid_batch_size(items.len()) {
        return Err(CredentialResolverError::unclassified(
            "invalid_params",
            "fleet epoch batches require 1 through 256 items",
        ));
    }
    encode(
        method,
        Batch {
            items: items.iter().copied().map(T::from).collect(),
        },
    )
}

pub(super) fn seal(
    request: FleetEpochSealRequest<'_>,
) -> Result<Secret<Vec<u8>>, CredentialResolverError> {
    encode(SEAL, Seal::from(request))
}

pub(super) fn open(
    request: FleetEpochOpenRequest<'_>,
) -> Result<Secret<Vec<u8>>, CredentialResolverError> {
    encode(OPEN, Open::from(request))
}

pub(super) fn seal_batch(
    items: &[FleetEpochSealRequest<'_>],
) -> Result<Secret<Vec<u8>>, CredentialResolverError> {
    encode_batch::<_, Seal<'_>>(SEAL_BATCH, items)
}

pub(super) fn open_batch(
    items: &[FleetEpochOpenRequest<'_>],
) -> Result<Secret<Vec<u8>>, CredentialResolverError> {
    encode_batch::<_, Open<'_>>(OPEN_BATCH, items)
}

#[cfg(feature = "transport")]
impl crate::ClaustrumCredentialResolver {
    /// Seals one record under the current fleet epoch on the caller's attested
    /// route. Sends once; a second seal would produce a new ciphertext.
    pub async fn fleet_epoch_seal(
        &self,
        request: FleetEpochSealRequest<'_>,
    ) -> Result<FleetEpochSeal, CredentialResolverError> {
        let reply = self.fleet_epoch_send(seal(request)?, SEAL).await?;
        decode_fleet_epoch_seal_reply(reply.expose())
    }

    /// Opens a record on the caller's attested route, without retrying.
    pub async fn fleet_epoch_open(
        &self,
        request: FleetEpochOpenRequest<'_>,
    ) -> FleetEpochOpenResult {
        let reply = self.fleet_epoch_send(open(request)?, OPEN).await?;
        decode_fleet_epoch_open_reply(reply.expose())
    }

    /// Seals 1 through 256 records in one attempt. Successful replies preserve input order.
    pub async fn fleet_epoch_seal_batch(
        &self,
        items: &[FleetEpochSealRequest<'_>],
    ) -> Result<Vec<FleetEpochSeal>, CredentialResolverError> {
        let reply = self
            .fleet_epoch_send(seal_batch(items)?, SEAL_BATCH)
            .await?;
        complete_batch(
            decode_fleet_epoch_seal_batch_reply(reply.expose())?,
            items.len(),
        )
    }

    /// Opens 1 through 256 records in one attempt. An item refusal does not fail
    /// its neighbors; a whole-call refusal or malformed reply returns no items.
    pub async fn fleet_epoch_open_batch(
        &self,
        items: &[FleetEpochOpenRequest<'_>],
    ) -> Result<Vec<FleetEpochOpenResult>, CredentialResolverError> {
        let reply = self
            .fleet_epoch_send(open_batch(items)?, OPEN_BATCH)
            .await?;
        complete_batch(
            decode_fleet_epoch_open_batch_reply(reply.expose())?,
            items.len(),
        )
    }

    async fn fleet_epoch_send(
        &self,
        request: Secret<Vec<u8>>,
        method: &str,
    ) -> Result<Secret<Vec<u8>>, CredentialResolverError> {
        let target = self
            .live_target
            .as_ref()
            .ok_or_else(CredentialResolverError::unavailable)?;
        target.sensitive_request(request, method).await
    }
}

#[cfg(feature = "transport")]
fn complete_batch<T>(items: Vec<T>, expected: usize) -> Result<Vec<T>, CredentialResolverError> {
    if items.len() != expected {
        return Err(invalid_reply());
    }
    Ok(items)
}
