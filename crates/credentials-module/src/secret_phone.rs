//! The isolated phone channel: grammar, an uncached pairing lookup, then one write.
use crate::federation::{self, Lookup, OutboundClient};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use credentials_core::{
    agent_secret::{self, SecretError, SecretScope},
    store::{EncryptedStore, PhoneDeposit, PhoneOperation},
};
use serde_json::Value;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

pub const PHONE_OP_DEADLINE_LIMIT_MS: u64 = 1500;
pub const PHONE_OP_DEADLINE: std::time::Duration =
    std::time::Duration::from_millis(PHONE_OP_DEADLINE_LIMIT_MS);
pub const MAX_DEPOSIT_CIPHERTEXT: usize = 16384;
pub const MAX_SECRET_CARD_REF_BYTES: usize = 64;
pub const PHONE_OPS: [&str; 7] = [
    "secret.phone_keys_register",
    "secret.deposit_keys",
    "secret.deposit",
    "secret.approve",
    "secret.list",
    "secret.delete",
    "secret.revoke_grant",
];

pub fn is_phone_op(method: &str) -> bool {
    PHONE_OPS.contains(&method)
}

/// The phone-callable query that says where this account's agent secrets live. It is
/// kept apart from [`PHONE_OPS`], the seven ops a vault refuses when the secrets live
/// elsewhere, because this one answers on every vault: it is how the phone finds the
/// home.
pub const HOME_OP: &str = "secret.home";

/// Every op the phone route serves: the seven secret ops and [`HOME_OP`].
pub fn is_phone_route_op(method: &str) -> bool {
    is_phone_op(method) || method == HOME_OP
}

fn before_deadline(now: tokio::time::Instant, deadline: tokio::time::Instant) -> bool {
    now < deadline
}

fn wall_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub enum PhoneAnswer {
    Reply(Value),
    InvalidParams(String),
    PermissionsOperatorRequired,
}

fn answer(result: Result<Value, SecretError>) -> PhoneAnswer {
    match result {
        Ok(body) => PhoneAnswer::Reply(body),
        Err(SecretError::InvalidParams) => {
            PhoneAnswer::InvalidParams("invalid secret params".to_owned())
        }
        Err(error) => PhoneAnswer::Reply(error.body()),
    }
}

pub async fn serve(
    store: Arc<EncryptedStore>,
    client: Option<&OutboundClient>,
    fingerprint: &str,
    method: &str,
    params: &Value,
) -> PhoneAnswer {
    let deadline = tokio::time::Instant::now() + PHONE_OP_DEADLINE;
    serve_with_lookup(
        store,
        fingerprint,
        method,
        params,
        deadline,
        federation::callosum_lookup(client, "callosum.paired_devices_read", deadline),
    )
    .await
}

pub(crate) async fn serve_with_lookup(
    store: Arc<EncryptedStore>,
    fingerprint: &str,
    method: &str,
    params: &Value,
    deadline: tokio::time::Instant,
    lookup: impl std::future::Future<Output = Option<Value>>,
) -> PhoneAnswer {
    if federation::carries_bearer(params) {
        return answer(Err(SecretError::InvalidParams));
    }
    if matches!(method, "permissions.list" | "permissions.revoke") {
        return PhoneAnswer::PermissionsOperatorRequired;
    }
    if !is_phone_route_op(method) {
        return answer(Err(SecretError::NotFound));
    }
    let op = match parse(method, params) {
        Ok(op) => op,
        Err(e) => return answer(Err(e)),
    };
    let pairing = if matches!(op, PhoneOperation::DepositKeys) {
        None
    } else {
        let body = match tokio::time::timeout_at(deadline, lookup).await {
            Ok(Some(body)) => body,
            _ => return answer(Err(SecretError::PairingUnavailable)),
        };
        match federation::decode_paired_devices(&body, &format!("fed-phone:{fingerprint}")) {
            Lookup::Found(pairing) => Some(pairing),
            Lookup::Absent => None,
            Lookup::Unavailable => return answer(Err(SecretError::PairingUnavailable)),
        }
    };
    let now = wall_now_ms();
    let fingerprint = fingerprint.to_owned();
    // Do not timeout the blocking job: it checks admission after acquiring SQLite's
    // write transaction, and an admitted transaction must finish even after the budget.
    answer(
        tokio::task::spawn_blocking(move || {
            store.secret_phone_operation(
                &fingerprint,
                pairing.as_deref(),
                now,
                &op,
                || before_deadline(tokio::time::Instant::now(), deadline),
                wall_now_ms,
            )
        })
        .await
        .unwrap_or(Err(SecretError::StoreError)),
    )
}

fn text<'a>(params: &'a Value, key: &str) -> Result<&'a str, SecretError> {
    params
        .get(key)
        .and_then(Value::as_str)
        .ok_or(SecretError::InvalidParams)
}

fn keys(params: &Value, required: &[&str], optional: &[&str]) -> Result<(), SecretError> {
    let object = params.as_object().ok_or(SecretError::InvalidParams)?;
    if required.iter().any(|key| !object.contains_key(*key))
        || object
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(SecretError::InvalidParams);
    }
    Ok(())
}

fn hex(value: &str, bytes: usize) -> Result<Vec<u8>, SecretError> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(SecretError::InvalidParams);
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| SecretError::InvalidParams))
        .collect()
}

fn base64(value: &str) -> Result<Vec<u8>, SecretError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| SecretError::InvalidParams)
}

pub fn valid_ulid(value: &str) -> bool {
    value.len() == 26
        && value.as_bytes()[0] <= b'7'
        && value
            .bytes()
            .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
}

pub(crate) fn parse(method: &str, params: &Value) -> Result<PhoneOperation, SecretError> {
    match method {
        "secret.deposit_keys" | "secret.list" | HOME_OP => {
            keys(params, &[], &[])?;
            Ok(match method {
                "secret.list" => PhoneOperation::List,
                HOME_OP => PhoneOperation::Home,
                _ => PhoneOperation::DepositKeys,
            })
        }
        "secret.phone_keys_register" => {
            keys(params, &["deposit_pub", "approval_pub"], &[])?;
            let deposit_pub = hex(text(params, "deposit_pub")?, 32)?;
            let approval_pub = hex(text(params, "approval_pub")?, 65)?;
            agent_secret::validate_phone_approval_key(&approval_pub)?;
            Ok(PhoneOperation::Register {
                deposit_pub,
                approval_pub,
            })
        }
        "secret.deposit" => {
            let kind = text(params, "kind")?;
            let scope = match kind {
                "agent_api_key" => {
                    keys(
                        params,
                        &[
                            "deposit_id",
                            "member_id",
                            "name",
                            "kind",
                            "host",
                            "location",
                            "enc_b64url",
                            "ciphertext_b64url",
                        ],
                        &["path_prefix"],
                    )?;
                    SecretScope::ApiKey {
                        host: text(params, "host")?.to_owned(),
                        path_prefix: params
                            .get("path_prefix")
                            .map(|_| text(params, "path_prefix").map(str::to_owned))
                            .transpose()?,
                        location: text(params, "location")?.to_owned(),
                    }
                }
                "site_login" => {
                    keys(
                        params,
                        &[
                            "deposit_id",
                            "member_id",
                            "name",
                            "kind",
                            "origin",
                            "enc_b64url",
                            "ciphertext_b64url",
                        ],
                        &[],
                    )?;
                    SecretScope::SiteLogin {
                        origin: text(params, "origin")?.to_owned(),
                    }
                }
                _ => return Err(SecretError::InvalidParams),
            };
            let name = text(params, "name")?;
            agent_secret::validate_name(name)?;
            agent_secret::validate_scope(&scope)?;
            let deposit_id = text(params, "deposit_id")?;
            if !valid_ulid(deposit_id) {
                return Err(SecretError::InvalidParams);
            }
            let member_id = text(params, "member_id")?;
            if !credentials_core::federation::valid_member_id(member_id) {
                return Err(SecretError::InvalidParams);
            }
            let enc = base64(text(params, "enc_b64url")?)?;
            if enc.len() != 32 {
                return Err(SecretError::InvalidParams);
            }
            let ciphertext = base64(text(params, "ciphertext_b64url")?)?;
            if ciphertext.len() > MAX_DEPOSIT_CIPHERTEXT {
                return Err(SecretError::LimitExceeded);
            }
            Ok(PhoneOperation::Deposit(PhoneDeposit {
                deposit_id: deposit_id.to_owned(),
                member_id: member_id.to_owned(),
                name: name.to_owned(),
                scope,
                enc,
                ciphertext,
            }))
        }
        "secret.approve" | "secret.delete" if params.get("envelope_b64url").is_some() => {
            keys(
                params,
                &["envelope_b64url", "signature_b64url"],
                if method == "secret.approve" {
                    &["card_ref"]
                } else {
                    &[]
                },
            )?;
            let envelope = base64(text(params, "envelope_b64url")?)?;
            let signature = base64(text(params, "signature_b64url")?)?;
            if let Some(card) = params.get("card_ref") {
                let card = card.as_str().ok_or(SecretError::InvalidParams)?;
                if card.is_empty()
                    || card.len() > MAX_SECRET_CARD_REF_BYTES
                    || !card.bytes().all(|b| b.is_ascii_graphic())
                {
                    return Err(SecretError::InvalidParams);
                }
            }
            Ok(if method == "secret.approve" {
                PhoneOperation::Approve {
                    envelope,
                    signature,
                    card_ref: params
                        .get("card_ref")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                }
            } else {
                PhoneOperation::DeleteCommit {
                    envelope,
                    signature,
                }
            })
        }
        "secret.delete" => {
            keys(params, &["name"], &[])?;
            agent_secret::validate_name(text(params, "name")?)?;
            Ok(PhoneOperation::DeleteRequest {
                name: text(params, "name")?.to_owned(),
            })
        }
        "secret.revoke_grant" => {
            keys(params, &["grant_id"], &[])?;
            if !valid_ulid(text(params, "grant_id")?) {
                return Err(SecretError::InvalidParams);
            }
            Ok(PhoneOperation::Revoke {
                grant_id: text(params, "grant_id")?.to_owned(),
            })
        }
        _ => Err(SecretError::InvalidParams),
    }
}

#[cfg(test)]
#[path = "secret_phone_tests.rs"]
mod tests;
