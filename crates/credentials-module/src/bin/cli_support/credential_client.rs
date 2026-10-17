use std::{fmt, path::Path};

use serde_json::{json, Value};
use subc_protocol::FrameType;
use subc_transport::write_frame;

use crate::route_client;

pub struct ServedCredential {
    pub payload: Vec<u8>,
    pub record_version: u64,
    pub expires_at_ms: Option<i64>,
}

impl fmt::Debug for ServedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServedCredential")
            .field(
                "payload",
                &format_args!("<{} bytes redacted>", self.payload.len()),
            )
            .field("record_version", &self.record_version)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialReadError {
    NeedsReauth,
    NotFound,
    RefreshUnsupported,
    RefreshFailed,
    VaultLocked,
    Corrupt,
    TtlUnsatisfiable,
    Refused,
    Transport(String),
}

impl fmt::Display for CredentialReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::NeedsReauth => "credential needs reauthentication",
            Self::NotFound => "credential capability was not found",
            Self::RefreshUnsupported => "credential refresh is unsupported",
            Self::RefreshFailed => "credential refresh failed",
            Self::VaultLocked => "credential vault is unavailable",
            Self::Corrupt => "credential record is corrupt",
            Self::TtlUnsatisfiable => "credential cannot meet the requested lifetime",
            Self::Refused => "credential read was refused",
            Self::Transport(cause) => return write!(f, "credential route is unavailable: {cause}"),
        };
        f.write_str(message)
    }
}

impl std::error::Error for CredentialReadError {}

pub fn get_online(
    connection_file: &Path,
    project_root: &Path,
    handle: &str,
) -> Result<ServedCredential, CredentialReadError> {
    // No environment handling is needed here. A shell spawned by a supervised module
    // inherits that module's SUBC_MODULE_ID and launch nonce, and subc's own client
    // libraries copy those into `route.open` as a consumer identity when none is
    // given. `route_client::open_route` builds `route.open` itself and never reads
    // them, so `ck auth` opens its route without a consumer identity regardless of
    // the environment (pinned by tests/route_open_identity.rs).
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CredentialReadError::Transport(format!("runtime: {e}")))?;
    runtime.block_on(get_online_async(connection_file, project_root, handle))
}

async fn get_online_async(
    connection_file: &Path,
    project_root: &Path,
    handle: &str,
) -> Result<ServedCredential, CredentialReadError> {
    let stream = route_client::connect(connection_file)
        .await
        .map_err(|e| CredentialReadError::Transport(format!("connect: {e}")))?;
    let mut route = route_client::open_route(stream, project_root, "ck-auth", "opencode-read")
        .await
        .map_err(|e| CredentialReadError::Transport(format!("route.open: {e}")))?;
    let frame = route_client::route_request(
        route.channel,
        route.epoch,
        10,
        json!({
            "method": "credential.get",
            "params": { "handle": handle, "force_refresh": false, "min_ttl_ms": 0 },
        }),
    );
    write_frame(&mut route.stream, &frame)
        .await
        .map_err(|e| CredentialReadError::Transport(format!("write credential.get: {e}")))?;
    let response = route_client::read_route_response(&mut route.stream, 10)
        .await
        .map_err(|e| CredentialReadError::Transport(format!("read credential.get: {e}")))?;
    if response.header.ty == FrameType::Error {
        return Err(CredentialReadError::Refused);
    }
    decode_response(&response.body)
}

fn decode_response(body: &[u8]) -> Result<ServedCredential, CredentialReadError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|e| CredentialReadError::Transport(format!("decode response: {e}")))?;
    let result = value
        .get("result")
        .ok_or_else(|| CredentialReadError::Transport("response omitted result".into()))?;
    if let Some(error) = result.get("error") {
        return Err(map_error(error));
    }
    let payload = result
        .get("payload")
        .and_then(Value::as_array)
        .ok_or_else(|| CredentialReadError::Transport("response omitted payload".into()))?
        .iter()
        .map(|byte| byte.as_u64().and_then(|byte| u8::try_from(byte).ok()))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| CredentialReadError::Transport("response payload was invalid".into()))?;
    let record_version = result
        .get("record_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| CredentialReadError::Transport("response omitted record version".into()))?;
    let expires_at_ms =
        match result.get("expires_at_ms") {
            None | Some(Value::Null) => None,
            Some(value) => Some(value.as_i64().ok_or_else(|| {
                CredentialReadError::Transport("response expiry was invalid".into())
            })?),
        };
    Ok(ServedCredential {
        payload,
        record_version,
        expires_at_ms,
    })
}

fn map_error(error: &Value) -> CredentialReadError {
    match (
        error.get("class").and_then(Value::as_str),
        error.get("code").and_then(Value::as_str),
    ) {
        (Some("auth_required"), Some("needs_reauth")) => CredentialReadError::NeedsReauth,
        (_, Some("not_found")) => CredentialReadError::NotFound,
        (_, Some("refresh_unsupported")) => CredentialReadError::RefreshUnsupported,
        (_, Some("refresh_failed")) => CredentialReadError::RefreshFailed,
        (_, Some("vault_locked")) => CredentialReadError::VaultLocked,
        (_, Some("corrupt")) => CredentialReadError::Corrupt,
        (_, Some("ttl_unsatisfiable")) => CredentialReadError::TtlUnsatisfiable,
        _ => CredentialReadError::Refused,
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_response, map_error, CredentialReadError};
    use serde_json::json;

    /// The read surface's refusal codes as the vault serializes them (pinned on the
    /// producer side by `read_error_wire_codes_are_golden_and_match_the_doc_table`).
    /// A code that stops matching here falls through to the generic `Refused`, which
    /// would turn a typed operator message into "credential read was refused".
    #[test]
    fn map_error_types_every_refusal_code_ck_auth_handles() {
        let cases = [
            (
                "auth_required",
                "needs_reauth",
                CredentialReadError::NeedsReauth,
            ),
            ("permanent", "not_found", CredentialReadError::NotFound),
            (
                "permanent",
                "refresh_unsupported",
                CredentialReadError::RefreshUnsupported,
            ),
            (
                "transient",
                "refresh_failed",
                CredentialReadError::RefreshFailed,
            ),
            (
                "transient",
                "vault_locked",
                CredentialReadError::VaultLocked,
            ),
            ("permanent", "corrupt", CredentialReadError::Corrupt),
            (
                "context_overflow",
                "ttl_unsatisfiable",
                CredentialReadError::TtlUnsatisfiable,
            ),
        ];
        for (class, code, expected) in cases {
            assert_eq!(
                map_error(&json!({ "class": class, "code": code })),
                expected,
                "{code}/{class}"
            );
        }
    }

    #[test]
    fn map_error_refuses_what_it_does_not_recognise() {
        // `needs_reauth` is honoured only with its contract class, so a body that
        // disagrees with itself is not read as "log in again".
        assert_eq!(
            map_error(&json!({ "class": "transient", "code": "needs_reauth" })),
            CredentialReadError::Refused
        );
        for body in [
            json!({ "class": "permanent", "code": "kind_not_gettable" }),
            json!({ "class": "permanent", "code": "some_future_code" }),
            json!({ "class": "permanent" }),
            json!({}),
        ] {
            assert_eq!(map_error(&body), CredentialReadError::Refused, "{body}");
        }
    }

    fn body(value: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&value).expect("encode test body")
    }

    #[test]
    fn decode_response_returns_the_served_credential() {
        let served = decode_response(&body(json!({
            "result": { "payload": [104, 105], "record_version": 4, "expires_at_ms": 77 }
        })))
        .expect("served");
        assert_eq!(served.payload, b"hi");
        assert_eq!(served.record_version, 4);
        assert_eq!(served.expires_at_ms, Some(77));

        let no_expiry = decode_response(&body(json!({
            "result": { "payload": [], "record_version": 1, "expires_at_ms": null }
        })))
        .expect("served without expiry");
        assert_eq!(no_expiry.expires_at_ms, None);
    }

    #[test]
    fn decode_response_maps_refusal_codes() {
        for (class, code, expected) in [
            (
                "auth_required",
                "needs_reauth",
                CredentialReadError::NeedsReauth,
            ),
            (
                "permanent",
                "refresh_unsupported",
                CredentialReadError::RefreshUnsupported,
            ),
            (
                "transient",
                "vault_locked",
                CredentialReadError::VaultLocked,
            ),
            ("permanent", "not_found", CredentialReadError::NotFound),
        ] {
            let err = decode_response(&body(json!({
                "result": { "error": { "class": class, "code": code } }
            })))
            .expect_err("a refusal is not a credential");
            assert_eq!(err, expected, "{code}");
        }
    }

    #[test]
    fn decode_response_rejects_malformed_bodies_as_transport_errors() {
        for raw in [
            b"not json".to_vec(),
            body(json!({ "no_result": true })),
            body(json!({ "result": { "record_version": 1 } })),
            body(json!({ "result": { "payload": [256], "record_version": 1 } })),
            body(json!({ "result": { "payload": [1] } })),
            body(
                json!({ "result": { "payload": [1], "record_version": 1, "expires_at_ms": "soon" } }),
            ),
        ] {
            match decode_response(&raw) {
                Err(CredentialReadError::Transport(_)) => {}
                other => panic!(
                    "{}: expected a transport error, got {other:?}",
                    String::from_utf8_lossy(&raw)
                ),
            }
        }
    }
}
