//! Module-owned values use typed, zeroizing buffers rather than JSON values.

use super::*;
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

/// An owned buffer that is scrubbed on drop and never rendered by `Debug`.
///
/// Only the buffer owned here is scrubbed. Copies inside SDK request bodies and
/// transport frame buffers are outside the client's control; this is not an
/// end-to-end memory-erasure guarantee.
pub struct Secret<T: Zeroize>(Zeroizing<T>);

impl<T: Zeroize> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn expose(&self) -> &T {
        &self.0
    }

    pub(super) fn expose_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize> std::fmt::Debug for Secret<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleSecretError {
    VersionConflict,
    Protected,
    Limit,
    Other(CredentialResolverError),
}

impl std::fmt::Display for ModuleSecretError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VersionConflict => formatter.write_str("module secret version conflict"),
            Self::Protected => formatter.write_str("module secret is protected"),
            Self::Limit => formatter.write_str("module secret item limit reached"),
            Self::Other(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ModuleSecretError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Other(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CredentialResolverError> for ModuleSecretError {
    fn from(error: CredentialResolverError) -> Self {
        Self::Other(error)
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct ModuleSecretWritten {
    pub name: String,
    pub version: u64,
    pub created: bool,
}

#[derive(Debug)]
pub struct ModuleSecret {
    pub name: String,
    pub version: u64,
    pub value: Secret<Vec<u8>>,
    pub protected: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModuleSecretState {
    Active,
    Corrupt,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct ModuleSecretSummary {
    pub name: String,
    pub version: u64,
    pub protected: bool,
    pub state: ModuleSecretState,
    pub updated_at_ms: i64,
}

#[cfg(any(feature = "transport", test))]
pub(super) mod wire {
    use super::*;
    use serde::Serialize;

    #[derive(Debug, Serialize)]
    struct Put<'a> {
        name: &'a str,
        #[serde(serialize_with = "serialize_value")]
        value: Secret<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        expected_version: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        protected: Option<bool>,
    }

    fn serialize_value<S: serde::Serializer>(
        value: &Secret<String>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value.expose())
    }

    #[derive(Debug, Serialize)]
    struct Named<'a> {
        name: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        expected_version: Option<u64>,
    }

    #[derive(Debug, Serialize)]
    struct Empty {}

    #[derive(Debug, Deserialize)]
    struct Reply<T> {
        result: T,
    }

    #[derive(Deserialize)]
    #[serde(transparent)]
    struct BorrowedValue<'a>(#[serde(borrow)] &'a str);

    impl std::fmt::Debug for BorrowedValue<'_> {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("<redacted>")
        }
    }

    #[derive(Debug, Deserialize)]
    struct Got<'a> {
        name: String,
        version: u64,
        #[serde(borrow)]
        value: BorrowedValue<'a>,
        protected: bool,
    }

    #[derive(Debug, Deserialize)]
    struct Deleted {
        deleted: bool,
    }

    #[derive(Debug, Deserialize)]
    struct Listed {
        items: Vec<ModuleSecretSummary>,
    }

    #[derive(Debug, Deserialize)]
    struct WireError<'a> {
        code: &'a str,
        class: Option<&'a str>,
    }

    #[derive(Debug, Deserialize)]
    struct MaybeError<'a> {
        #[serde(borrow)]
        error: Option<WireError<'a>>,
    }

    fn invalid_response() -> ModuleSecretError {
        CredentialResolverError::new(
            CredentialErrorClass::InvalidResponse,
            "invalid module-secret reply",
        )
        .into()
    }

    fn decode<'a, T: Deserialize<'a>>(bytes: &'a Secret<Vec<u8>>) -> Result<T, ModuleSecretError> {
        let probe: Reply<MaybeError<'_>> =
            serde_json::from_slice(bytes.expose()).map_err(|_| invalid_response())?;
        if let Some(error) = probe.result.error {
            return Err(match error.code {
                "module_secret_version_conflict" => ModuleSecretError::VersionConflict,
                "module_secret_protected" => ModuleSecretError::Protected,
                "module_secret_limit" => ModuleSecretError::Limit,
                _ => classify_error_value(
                    &serde_json::json!({"code": error.code, "class": error.class}),
                )
                .into(),
            });
        }
        let reply: Reply<T> =
            serde_json::from_slice(bytes.expose()).map_err(|_| invalid_response())?;
        Ok(reply.result)
    }

    fn encode(
        params: impl Serialize,
        method: &'static str,
    ) -> Result<Secret<Vec<u8>>, ModuleSecretError> {
        sensitive_wire::encode_request(method, params).map_err(|_| {
            ModuleSecretError::Other(CredentialResolverError::new(
                CredentialErrorClass::Permanent,
                "module-secret request encoding failed",
            ))
        })
    }

    #[cfg(feature = "transport")]
    impl ClaustrumCredentialResolver {
        /// Creates or replaces a value in the attested module's private space.
        /// No attempt is retried, including after a transient refusal or lost reply.
        pub async fn module_secret_put(
            &self,
            name: &str,
            value: Secret<Vec<u8>>,
            expected_version: Option<u64>,
            protected: Option<bool>,
        ) -> Result<ModuleSecretWritten, ModuleSecretError> {
            let mut encoded = Secret::new(String::with_capacity(
                base64::encoded_len(value.expose().len(), true).ok_or_else(invalid_response)?,
            ));
            base64::engine::general_purpose::STANDARD.encode_string(value.expose(), &mut encoded.0);
            let reply = self
                .module_secret_send(encode(
                    Put {
                        name,
                        value: encoded,
                        expected_version,
                        protected,
                    },
                    "module_secret.put",
                )?)
                .await?;
            decode(&reply)
        }

        /// Reads the calling module's value. Requires an `own` SDK consumer claim.
        pub async fn module_secret_get(
            &self,
            name: &str,
        ) -> Result<ModuleSecret, ModuleSecretError> {
            let reply = self
                .module_secret_send(encode(
                    Named {
                        name,
                        expected_version: None,
                    },
                    "module_secret.get",
                )?)
                .await?;
            let got: Got<'_> = decode(&reply)?;
            let mut value = Secret::new(vec![0; base64::decoded_len_estimate(got.value.0.len())]);
            let len = base64::engine::general_purpose::STANDARD
                .decode_slice(got.value.0, &mut value.0)
                .map_err(|_| invalid_response())?;
            value.0.truncate(len);
            Ok(ModuleSecret {
                name: got.name,
                version: got.version,
                value,
                protected: got.protected,
            })
        }

        /// Deletes once; a stale expected version never deletes a newer value.
        pub async fn module_secret_delete(
            &self,
            name: &str,
            expected_version: Option<u64>,
        ) -> Result<(), ModuleSecretError> {
            let reply = self
                .module_secret_send(encode(
                    Named {
                        name,
                        expected_version,
                    },
                    "module_secret.delete",
                )?)
                .await?;
            let deleted: Deleted = decode(&reply)?;
            if !deleted.deleted {
                return Err(invalid_response());
            }
            Ok(())
        }

        /// Lists metadata only, without returning any value bytes.
        pub async fn module_secret_list(
            &self,
        ) -> Result<Vec<ModuleSecretSummary>, ModuleSecretError> {
            let reply = self
                .module_secret_send(encode(Empty {}, "module_secret.list")?)
                .await?;
            Ok(decode::<Listed>(&reply)?.items)
        }

        async fn module_secret_send(
            &self,
            request: Secret<Vec<u8>>,
        ) -> Result<Secret<Vec<u8>>, ModuleSecretError> {
            let target = self
                .module_secret_target
                .as_ref()
                .ok_or_else(CredentialResolverError::unavailable)?;
            target
                .sensitive_request(request, "module_secret")
                .await
                .map_err(Into::into)
        }
    }

    #[cfg(test)]
    mod tests;
}
