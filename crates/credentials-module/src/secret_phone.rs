//! The isolated phone channel: grammar, an uncached pairing lookup, then one write.
use crate::federation::{self, Lookup, OutboundClient};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use credentials_core::{
    agent_secret::{self, SecretError, SecretScope},
    store::{EncryptedStore, PhoneDeposit, PhoneOperation},
};
use serde_json::{json, Value};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

pub const PHONE_OP_DEADLINE_LIMIT_MS: u64 = 1500;
pub const PHONE_OP_DEADLINE: std::time::Duration =
    std::time::Duration::from_millis(PHONE_OP_DEADLINE_LIMIT_MS);
pub const MAX_DEPOSIT_CIPHERTEXT: usize = 16384;
pub const MAX_SECRET_CARD_REF_BYTES: usize = 64;
pub(crate) const OP_APPROVE_ACTION: &str = "policy.approve_action";
pub const PHONE_OPS: [&str; 9] = [
    "secret.phone_keys_register",
    "secret.deposit_keys",
    "secret.deposit",
    "secret.approve",
    "manifest.approve",
    OP_APPROVE_ACTION,
    "secret.list",
    "secret.delete",
    "secret.revoke_grant",
];

pub fn is_phone_op(method: &str) -> bool {
    PHONE_OPS.contains(&method)
}

/// These operations establish phone signing authority or act on it. Delete's
/// statement request is gated too, so an untrusted build cannot create pending work.
pub const ATTESTED_PHONE_OPS: [&str; 5] = [
    "secret.phone_keys_register",
    "secret.approve",
    "secret.delete",
    "manifest.approve",
    OP_APPROVE_ACTION,
];

/// The phone-callable query that says where this account's agent secrets live. It is
/// kept apart from [`PHONE_OPS`], the ops a vault refuses when the secrets live
/// elsewhere, because this one answers on every vault: it is how the phone finds the
/// home.
pub const HOME_OP: &str = "secret.home";

/// Every op the phone route serves, including [`HOME_OP`].
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

#[cfg(test)]
thread_local! {
    pub(crate) static BROKER_ACTION_TEST_CLOCK_MS: std::cell::Cell<Option<i64>> = const { std::cell::Cell::new(None) };
}

pub(crate) fn broker_action_clock() -> impl Fn() -> i64 {
    // Capture the test override before the transaction moves to the blocking pool.
    #[cfg(test)]
    let fixed = BROKER_ACTION_TEST_CLOCK_MS.get();
    move || {
        #[cfg(test)]
        if let Some(fixed) = fixed {
            return fixed;
        }
        wall_now_ms()
    }
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

fn answer_for_method(method: &str, result: Result<Value, SecretError>) -> PhoneAnswer {
    answer(result.map_err(|error| match (method, error) {
        (OP_APPROVE_ACTION, SecretError::InvalidParams) => SecretError::InvalidParams,
        (OP_APPROVE_ACTION, SecretError::NotFound) => SecretError::NotFound,
        (OP_APPROVE_ACTION, _) => SecretError::ApprovalInvalid,
        (_, error) => error,
    }))
}

pub async fn serve(
    store: Arc<EncryptedStore>,
    client: Option<&OutboundClient>,
    fingerprint: &str,
    peer_build: Option<&str>,
    method: &str,
    params: &Value,
) -> PhoneAnswer {
    let deadline = tokio::time::Instant::now() + PHONE_OP_DEADLINE;
    serve_with_pairing(
        store,
        fingerprint,
        peer_build,
        method,
        params,
        deadline,
        async {
            let reply =
                federation::callosum_lookup(client, "callosum.paired_devices_read", deadline).await;
            federation::lookup_paired_device(&reply, &format!("fed-phone:{fingerprint}"))
        },
    )
    .await
}

/// Development-only unsigned approvals share the phone's transaction checks, not
/// its pairing or signature authority. Remove before the next public release.
pub async fn serve_dev_desktop(
    store: Arc<EncryptedStore>,
    method: &str,
    params: &Value,
) -> PhoneAnswer {
    match store.secret_dev_desktop_approvals_enabled() {
        Ok(true) => {}
        Ok(false) => return answer(Err(SecretError::NotFound)),
        Err(error) => return answer_for_method(method, Err(error)),
    }
    tracing::info!(target: "approvals", "admitted development desktop approval");
    let parsed = (|| {
        keys(params, &["envelope_b64url"], &["card_ref"])?;
        let envelope = base64(text(params, "envelope_b64url")?)?;
        let card_ref = card_ref(params)?.map(str::to_owned);
        Ok((envelope, card_ref))
    })();
    let (envelope, card_ref) = match parsed {
        Ok(parsed) => parsed,
        Err(error) => return answer(Err(error)),
    };
    let manifest = method == "manifest.approve";
    let broker_action = method == OP_APPROVE_ACTION;
    let broker_clock = broker_action_clock();
    answer_for_method(
        method,
        tokio::task::spawn_blocking(move || {
            if broker_action {
                store.broker_action_dev_desktop_approval(&envelope, broker_clock)
            } else {
                store.secret_dev_desktop_approval(
                    &envelope,
                    card_ref.as_deref(),
                    manifest,
                    wall_now_ms,
                )
            }
        })
        .await
        .unwrap_or(Err(SecretError::StoreError)),
    )
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) async fn serve_with_lookup(
    store: Arc<EncryptedStore>,
    fingerprint: &str,
    peer_build: Option<&str>,
    method: &str,
    params: &Value,
    deadline: tokio::time::Instant,
    lookup: impl std::future::Future<Output = Option<Value>>,
) -> PhoneAnswer {
    serve_with_pairing(
        store,
        fingerprint,
        peer_build,
        method,
        params,
        deadline,
        async {
            match lookup.await {
                Some(body) => {
                    federation::decode_paired_devices(&body, &format!("fed-phone:{fingerprint}"))
                }
                None => Lookup::Unavailable,
            }
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn serve_with_pairing(
    store: Arc<EncryptedStore>,
    fingerprint: &str,
    peer_build: Option<&str>,
    method: &str,
    params: &Value,
    deadline: tokio::time::Instant,
    pairing: impl std::future::Future<Output = Lookup<String>>,
) -> PhoneAnswer {
    if ATTESTED_PHONE_OPS.contains(&method) && peer_build != Some("production") {
        return answer(Err(if method == OP_APPROVE_ACTION {
            SecretError::NotFound
        } else {
            SecretError::PhoneNotAttested
        }));
    }
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
        match tokio::time::timeout_at(deadline, pairing).await {
            Ok(Lookup::Found(pairing)) => Some(pairing),
            Ok(Lookup::Absent) => None,
            Ok(Lookup::Unavailable) | Err(_) => {
                return answer_for_method(method, Err(SecretError::PairingUnavailable));
            }
        }
    };
    let broker_clock = broker_action_clock();
    let broker_action = method == OP_APPROVE_ACTION;
    let clock = move || {
        if broker_action {
            broker_clock()
        } else {
            wall_now_ms()
        }
    };
    let now = clock();
    let fingerprint = fingerprint.to_owned();
    // Do not timeout the blocking job: it checks admission after acquiring SQLite's
    // write transaction, and an admitted transaction must finish even after the budget.
    answer_for_method(
        method,
        tokio::task::spawn_blocking(move || {
            store.secret_phone_operation(
                &fingerprint,
                pairing.as_deref(),
                now,
                &op,
                || before_deadline(tokio::time::Instant::now(), deadline),
                clock,
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

fn card_ref(params: &Value) -> Result<Option<&str>, SecretError> {
    let Some(value) = params.get("card_ref") else {
        return Ok(None);
    };
    let card = value.as_str().ok_or(SecretError::InvalidParams)?;
    if card.is_empty()
        || card.len() > MAX_SECRET_CARD_REF_BYTES
        || !card.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(SecretError::InvalidParams);
    }
    Ok(Some(card))
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

pub use credentials_core::broker_action::valid_ulid;

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
            let (fields, location) = match kind {
                "local_program" => {
                    keys(
                        params,
                        &[
                            "deposit_id",
                            "member_id",
                            "name",
                            "kind",
                            "program",
                            "use",
                            "targets",
                            "enc_b64url",
                            "ciphertext_b64url",
                        ],
                        &[],
                    )?;
                    (
                        json!({"program": text(params, "program")?, "use": text(params, "use")?, "targets": params["targets"]}),
                        None,
                    )
                }
                "agent_api_key" => {
                    let extended = params.get("rules").is_some();
                    keys(
                        params,
                        &[
                            "deposit_id",
                            "member_id",
                            "name",
                            "kind",
                            if extended { "rules" } else { "host" },
                            "location",
                            "enc_b64url",
                            "ciphertext_b64url",
                        ],
                        if extended { &[] } else { &["path_prefix"] },
                    )?;
                    let fields = if extended {
                        json!({"rules": params["rules"]})
                    } else {
                        let mut fields = json!({"host": text(params, "host")?});
                        if params.get("path_prefix").is_some() {
                            fields["path_prefix"] = json!(text(params, "path_prefix")?);
                        }
                        fields
                    };
                    (fields, Some(text(params, "location")?))
                }
                "site_login" => {
                    let extended = params.get("origins").is_some();
                    keys(
                        params,
                        &[
                            "deposit_id",
                            "member_id",
                            "name",
                            "kind",
                            if extended { "origins" } else { "origin" },
                            "enc_b64url",
                            "ciphertext_b64url",
                        ],
                        &[],
                    )?;
                    (
                        if extended {
                            json!({"origins": params["origins"]})
                        } else {
                            json!({"origin": text(params, "origin")?})
                        },
                        None,
                    )
                }
                _ => return Err(SecretError::InvalidParams),
            };
            let name = text(params, "name")?;
            agent_secret::validate_name(name)?;
            let scope = SecretScope::from_input(kind, &fields, location)?;
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
        "manifest.approve" => {
            keys(params, &["envelope_b64url", "signature_b64url"], &[])?;
            Ok(PhoneOperation::ManifestApprove {
                envelope: base64(text(params, "envelope_b64url")?)?,
                signature: base64(text(params, "signature_b64url")?)?,
            })
        }
        "secret.approve" | OP_APPROVE_ACTION | "secret.delete"
            if params.get("envelope_b64url").is_some() =>
        {
            keys(
                params,
                &["envelope_b64url", "signature_b64url"],
                if method == "secret.delete" {
                    &[]
                } else {
                    &["card_ref"]
                },
            )?;
            let envelope = base64(text(params, "envelope_b64url")?)?;
            let signature = base64(text(params, "signature_b64url")?)?;
            let card_ref = card_ref(params)?;
            Ok(match method {
                "secret.approve" => PhoneOperation::Approve {
                    envelope,
                    signature,
                    card_ref: card_ref.map(str::to_owned),
                },
                OP_APPROVE_ACTION => PhoneOperation::BrokerActionApprove {
                    envelope,
                    signature,
                },
                _ => PhoneOperation::DeleteCommit {
                    envelope,
                    signature,
                },
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
