//! Private, attested module-owned secret operations.

use base64::{engine::general_purpose::STANDARD, Engine};
use credentials_core::secret::Secret;
use credentials_core::store::{module_secrets, EncryptedStore};
use module_secrets::{
    validate_module_secret_name, ModuleSecretOwner, MODULE_SECRET_MAX_VALUE_BYTES,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use subc_protocol::{peer::CallerClaim, Principal};

use crate::federation::{ingress::carries_bearer, RouteCaller};

pub const PUT: &str = "module_secret.put";
pub const GET: &str = "module_secret.get";
pub const DELETE: &str = "module_secret.delete";
pub const LIST: &str = "module_secret.list";

pub fn is_op(method: &str) -> bool {
    matches!(method, PUT | GET | DELETE | LIST)
}

pub fn admit(caller: &RouteCaller, params: &Value) -> Option<ModuleSecretOwner> {
    let RouteCaller::Principal(caller) = caller else {
        return None;
    };
    let Principal::Reserved { module_id } = caller.as_ref()? else {
        return None;
    };
    if caller.attestation.as_ref()?.claim != CallerClaim::Own || carries_bearer(params) {
        return None;
    }
    ModuleSecretOwner::new(module_id).ok()
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleSecretError {
    InvalidParams,
    NotFound,
    ModuleSecretProtected,
    ModuleSecretVersionConflict,
    ModuleSecretLimit,
    Corrupt,
    VaultLocked,
    StoreError,
}

impl ModuleSecretError {
    pub fn class(self) -> &'static str {
        match self {
            Self::VaultLocked | Self::StoreError => "transient",
            Self::InvalidParams
            | Self::NotFound
            | Self::ModuleSecretProtected
            | Self::ModuleSecretVersionConflict
            | Self::ModuleSecretLimit
            | Self::Corrupt => "permanent",
        }
    }

    pub fn reply(self) -> Value {
        json!({"error": {"code": self, "class": self.class()}})
    }
}

impl From<module_secrets::ModuleSecretError> for ModuleSecretError {
    fn from(error: module_secrets::ModuleSecretError) -> Self {
        use module_secrets::ModuleSecretError as StoreError;
        match error {
            StoreError::Protected => Self::ModuleSecretProtected,
            StoreError::VersionConflict => Self::ModuleSecretVersionConflict,
            StoreError::Limit => Self::ModuleSecretLimit,
            StoreError::InvalidParams => Self::InvalidParams,
            StoreError::NotFound => Self::NotFound,
            StoreError::Corrupt => Self::Corrupt,
            StoreError::VaultLocked => Self::VaultLocked,
            StoreError::Store => Self::StoreError,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PutParams {
    name: String,
    value: Secret<String>,
    expected_version: Option<u64>,
    protected: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NameParams {
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteParams {
    name: String,
    expected_version: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListParams {}

fn decode<T: serde::de::DeserializeOwned>(params: &Value) -> Result<T, ModuleSecretError> {
    if !params.is_object() {
        return Err(ModuleSecretError::InvalidParams);
    }
    serde_json::from_value(params.clone()).map_err(|_| ModuleSecretError::InvalidParams)
}

fn validate(name: &str, expected_version: Option<u64>) -> Result<(), ModuleSecretError> {
    validate_module_secret_name(name)?;
    if expected_version == Some(0) {
        return Err(ModuleSecretError::InvalidParams);
    }
    Ok(())
}

pub fn serve(
    store: &EncryptedStore,
    owner: &ModuleSecretOwner,
    method: &str,
    params: &Value,
) -> Value {
    match execute(store, owner, method, params) {
        Ok(reply) => reply,
        Err(error) => error.reply(),
    }
}

fn execute(
    store: &EncryptedStore,
    owner: &ModuleSecretOwner,
    method: &str,
    params: &Value,
) -> Result<Value, ModuleSecretError> {
    match method {
        PUT => {
            let params: PutParams = decode(params)?;
            validate(&params.name, params.expected_version)?;
            let value = Secret::new(
                STANDARD
                    .decode(params.value.expose())
                    .map_err(|_| ModuleSecretError::InvalidParams)?,
            );
            if !(1..=MODULE_SECRET_MAX_VALUE_BYTES).contains(&value.expose().len()) {
                return Err(ModuleSecretError::InvalidParams);
            }
            let written = store.put_module_secret(
                owner,
                &params.name,
                value.expose(),
                params.expected_version,
                params.protected,
            )?;
            Ok(
                json!({"name": written.name, "version": written.version, "created": written.created}),
            )
        }
        GET => {
            let params: NameParams = decode(params)?;
            validate(&params.name, None)?;
            let secret = store.get_module_secret(owner, &params.name)?;
            let value = Secret::new(STANDARD.encode(secret.value.expose()));
            Ok(
                json!({"name": secret.name, "version": secret.version, "value": value,
                "protected": secret.protected}),
            )
        }
        DELETE => {
            let params: DeleteParams = decode(params)?;
            validate(&params.name, params.expected_version)?;
            store.delete_module_secret(owner, &params.name, params.expected_version)?;
            Ok(json!({"deleted": true}))
        }
        LIST => {
            let _: ListParams = decode(params)?;
            let items: Vec<_> = store
                .list_module_secrets(owner)?
                .into_iter()
                .map(|item| {
                    json!({"name": item.name, "version": item.version, "protected": item.protected,
                    "state": item.state.as_str(), "updated_at_ms": item.updated_at_ms})
                })
                .collect();
            Ok(json!({"items": items}))
        }
        _ => Err(ModuleSecretError::NotFound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_secret_request_debug_redacts_values() {
        let params: PutParams = decode(&json!({"name":"key", "value":"c2VjcmV0"})).unwrap();
        let debug = format!("{params:?}");
        assert!(!debug.contains("c2VjcmV0") && !debug.contains("secret"));
    }
}
