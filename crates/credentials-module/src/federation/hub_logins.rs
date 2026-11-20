//! Shared wire fields for Auth-mode login snapshots and end markers.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use credentials_core::{
    federation::{validate_remote_watch_row, RemoteHomeState, RemoteWatchRow},
    hub_counters::HubGeneration,
    kem,
    plan_detection::DetectedPlan,
    record::RecordIdentity,
    store::{Condition, StoreOpError},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

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

pub(crate) fn seal(
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

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum LoginBody {
    Snapshot { logins: Vec<Login> },
    Ended {},
}

impl LoginEnvelope {
    pub(super) fn open(&self, recipient_pem: &str, sender_public: &[u8; 32]) -> Option<LoginBody> {
        let plaintext = kem::open_hub_logins(
            recipient_pem,
            sender_public,
            &STANDARD.decode(&self.enc_b64).ok()?,
            &STANDARD.decode(&self.ciphertext_b64).ok()?,
            self.aad.as_bytes(),
        )
        .ok()?;
        serde_json::from_slice(&plaintext).ok()
    }
}

#[derive(Deserialize)]
pub(super) struct Login {
    credential_id: String,
    state: RemoteHomeState,
    refresh_adapter: Option<String>,
    identity: RecordIdentity,
    categories: Vec<String>,
    provider_ids: Option<Vec<String>>,
    detected_plan: Option<DetectedPlan>,
    home_version: u64,
    #[serde(default, deserialize_with = "present_condition")]
    condition: Option<Value>,
}

fn present_condition<'de, D: serde::Deserializer<'de>>(de: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(de).map(Some)
}

fn decode_condition(value: Value) -> Result<Condition, StoreOpError> {
    let malformed = || StoreOpError::Encode("malformed home-watch condition".into());
    let value = value.as_object().ok_or_else(malformed)?;
    Ok(Condition {
        reason: value
            .get("reason")
            .and_then(Value::as_str)
            .ok_or_else(malformed)?
            .to_owned(),
        since_ms: value
            .get("since_ms")
            .and_then(Value::as_u64)
            .ok_or_else(malformed)?,
        action_url: value
            .get("action_url")
            .map(|link| link.as_str().map(str::to_owned).ok_or_else(malformed))
            .transpose()?,
    })
}

#[derive(Clone, Debug)]
pub(super) struct Snapshot {
    pub(super) rows: Vec<RemoteWatchRow>,
    pub(super) retained_ids: Vec<String>,
}

pub(super) fn decode_rows(
    home: &str,
    logins: Vec<Login>,
    mut rejected: impl FnMut(&str, &StoreOpError),
) -> Option<Snapshot> {
    let mut ids = BTreeSet::new();
    let mut rows = Vec::new();
    let mut retained_ids = Vec::new();
    for login in logins {
        if login.state == RemoteHomeState::Corrupt || !ids.insert(login.credential_id.clone()) {
            return None;
        }
        let mut row = RemoteWatchRow {
            credential_id: login.credential_id,
            state: login.state,
            refresh_adapter: login.refresh_adapter,
            identity: login.identity,
            categories: login.categories,
            provider_ids: login.provider_ids,
            detected_plan: login.detected_plan,
            home_version: login.home_version,
            condition: None,
        };
        let result = login
            .condition
            .map(decode_condition)
            .transpose()
            .and_then(|condition| {
                row.condition = condition;
                validate_remote_watch_row(home, &row)
            });
        if let Err(error) = result {
            rejected(&row.credential_id, &error);
            retained_ids.push(row.credential_id);
        } else {
            rows.push(row);
        }
    }
    Some(Snapshot { rows, retained_ids })
}
