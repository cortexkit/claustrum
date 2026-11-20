//! Shared wire fields for Auth-mode login snapshots and end markers.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use credentials_core::{hub_counters::HubGeneration, kem, store::StoreOpError};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoginAad {
    pub(crate) home: String,
    pub(crate) member: String,
    pub(crate) home_box: String,
    pub(crate) member_box: String,
    pub(crate) generation: HubGeneration,
    pub(crate) sender_key_id: String,
    pub(crate) recipient_key_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoginEnvelope {
    pub(crate) v: u8,
    pub(crate) enc_b64: String,
    pub(crate) ciphertext_b64: String,
    pub(crate) aad: String,
}

pub(super) fn seal(
    aad: &LoginAad,
    sender_pem: &str,
    recipient_public: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, StoreOpError> {
    let aad =
        serde_json::to_string(aad).map_err(|_| StoreOpError::Encode("hub login AAD".into()))?;
    let (enc, ciphertext) =
        kem::seal_hub_logins(sender_pem, recipient_public, plaintext, aad.as_bytes())
            .map_err(|_| StoreOpError::Encode("hub login seal".into()))?;
    serde_json::to_vec(&LoginEnvelope {
        v: 1,
        enc_b64: STANDARD.encode(enc),
        ciphertext_b64: STANDARD.encode(ciphertext),
        aad,
    })
    .map_err(|_| StoreOpError::Encode("hub login envelope".into()))
}
