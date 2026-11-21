use crate::*;
use serde::Deserialize;
use serde_json::value::RawValue;

#[cfg(feature = "transport")]
pub(super) const POLICY_ACTIVE_OP: &str = "policy.active";
#[cfg(feature = "transport")]
pub(super) const POLICY_WATCH_OP: &str = "policy.watch";
#[cfg(feature = "transport")]
const POLICY_TOKEN_OP: &str = "credential.policy_token";

/// The policy the vault reports as active, with its signed JSON text unchanged.
#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct ActivePolicy {
    pub version: u64,
    pub policy_sha256: String,
    pub policy_text: String,
    pub manifest_version: u64,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct PolicyTokenRequest<'a> {
    pub identity: &'a str,
    pub service: &'a str,
    pub kind: &'a str,
    pub resource: &'a str,
    pub policy_version: u64,
}

#[derive(Debug)]
pub struct PolicyToken {
    pub token: Secret<String>,
    pub expires_at_ms: i64,
    pub repositories: Vec<String>,
    pub permissions: BTreeMap<String, String>,
}

pub(super) fn invalid_policy_reply() -> CredentialResolverError {
    CredentialResolverError::new(
        CredentialErrorClass::InvalidResponse,
        "invalid policy reply",
    )
}

#[derive(Deserialize)]
struct PolicyReply<'a> {
    #[serde(borrow)]
    result: &'a RawValue,
}

#[derive(Deserialize)]
struct MaybeRefusal<'a> {
    #[serde(borrow)]
    error: Option<PolicyRefusal<'a>>,
}

#[derive(Deserialize)]
struct PolicyRefusal<'a> {
    code: &'a str,
    class: &'a str,
}

pub(super) fn policy_result(bytes: &[u8]) -> Result<&RawValue, CredentialResolverError> {
    let reply: PolicyReply<'_> =
        serde_json::from_slice(bytes).map_err(|_| invalid_policy_reply())?;
    let result = reply.result;
    if !result.get().starts_with('{') {
        return Err(invalid_policy_reply());
    }
    let refusal: MaybeRefusal<'_> =
        serde_json::from_str(result.get()).map_err(|_| invalid_policy_reply())?;
    if let Some(error) = refusal.error {
        let class = match error.class {
            "permanent" => CredentialErrorClass::Permanent,
            "transient" => CredentialErrorClass::Transient,
            "auth_required" => CredentialErrorClass::AuthRequired,
            _ => return Err(invalid_policy_reply()),
        };
        // A policy not_found can mean the caller or vault role was refused, not
        // that a credential is absent. Keep the producer's code and class intact.
        return Err(CredentialResolverError {
            class,
            code: error.code.to_owned(),
            safe_message: "vault refused the policy operation".to_owned(),
        });
    }
    Ok(result)
}

/// Decodes the active policy, or `None` when the vault serves four explicit nulls.
pub fn decode_policy_active_reply(
    bytes: &[u8],
) -> Result<Option<ActivePolicy>, CredentialResolverError> {
    let result = policy_result(bytes)?;
    let value: Value = serde_json::from_str(result.get()).map_err(|_| invalid_policy_reply())?;
    if [
        "version",
        "policy_sha256",
        "policy_text",
        "manifest_version",
    ]
    .iter()
    .all(|key| value.get(key).is_some_and(Value::is_null))
    {
        return Ok(None);
    }
    let policy: ActivePolicy = serde_json::from_value(value).map_err(|_| invalid_policy_reply())?;
    if policy.version == 0
        || policy.manifest_version == 0
        || !valid_lower_hex(&policy.policy_sha256, 64)
        || policy.policy_text.is_empty()
    {
        return Err(invalid_policy_reply());
    }
    Ok(Some(policy))
}

/// Decodes a narrowed token reply. The input bytes hold the token; keep them private.
pub fn decode_policy_token_reply(bytes: &[u8]) -> Result<PolicyToken, CredentialResolverError> {
    #[derive(Deserialize)]
    struct WireToken<'a> {
        token: &'a str,
        expires_at_ms: i64,
        repositories: Vec<String>,
        permissions: BTreeMap<String, String>,
    }
    let reply: WireToken<'_> =
        serde_json::from_str(policy_result(bytes)?.get()).map_err(|_| invalid_policy_reply())?;
    if reply.token.is_empty() || reply.expires_at_ms < 0 {
        return Err(invalid_policy_reply());
    }
    Ok(PolicyToken {
        token: Secret::new(reply.token.to_owned()),
        expires_at_ms: reply.expires_at_ms,
        repositories: reply.repositories,
        permissions: reply.permissions,
    })
}

#[cfg(feature = "transport")]
impl ClaustrumCredentialResolver {
    /// Reads the active policy on the caller's attested route.
    pub async fn policy_active(&self) -> Result<Option<ActivePolicy>, CredentialResolverError> {
        let reply = self.policy_request(POLICY_ACTIVE_OP, json!({})).await?;
        decode_policy_active_reply(reply.expose())
    }

    /// Requests one policy-narrowed token. Does not retry or fall back to a broad token.
    pub async fn policy_token(
        &self,
        request: PolicyTokenRequest<'_>,
    ) -> Result<PolicyToken, CredentialResolverError> {
        let reply = self.policy_request(POLICY_TOKEN_OP, request).await?;
        decode_policy_token_reply(reply.expose())
    }

    /// Opens a dedicated active-policy watch. Reopening and reads belong to the caller.
    pub async fn policy_watch(&self) -> Result<PolicyWatch, CredentialResolverError> {
        let target = self
            .live_target
            .as_ref()
            .ok_or_else(CredentialResolverError::unavailable)?;
        tokio::time::timeout(target.call_deadline, async {
            target
                .connector
                .connect_policy_watch()
                .await?
                .into_policy_watch()
                .await
        })
        .await
        .unwrap_or_else(|_| Err(LiveCredentialGetTarget::deadline_error(POLICY_WATCH_OP)))
    }

    async fn policy_request(
        &self,
        method: &str,
        params: impl serde::Serialize,
    ) -> Result<Secret<Vec<u8>>, CredentialResolverError> {
        let target = self
            .live_target
            .as_ref()
            .ok_or_else(CredentialResolverError::unavailable)?;
        let bytes = serde_json::to_vec(&json!({ "method": method, "params": params }))
            .map_err(|_| invalid_policy_reply())?;
        target.sensitive_request(Secret::new(bytes), method).await
    }
}
