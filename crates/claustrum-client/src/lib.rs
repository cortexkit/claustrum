#![forbid(unsafe_code)]

//! Claustrum credential consumer for subc-supervised modules.

#[cfg(test)]
use std::collections::VecDeque;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subc_protocol::{Flags, Frame, FrameType, Priority};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;

const CREDENTIAL_MODULE_ID: &str = "claustrum";
const CREDENTIAL_GET_OP: &str = "credential.get";
const CREDENTIAL_GET_SCOPED_OP: &str = "credential.get_scoped";
const CREDENTIAL_STATUS_OP: &str = "credential.status";
const CREDENTIAL_SIGN_OP: &str = "credential.sign";
const CREDENTIAL_PUBLIC_KEY_OP: &str = "credential.public_key";
const CREDENTIAL_LIST_SCOPED_OP: &str = "credential.list_scoped";
const CREDENTIAL_READ_TIMEOUT: Duration = Duration::from_secs(3);
const CREDENTIAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// A peer daemon restart can leave this daemon holding an outdated routing
/// generation. The peer silently discards requests from that generation instead
/// of returning an error, so the request looks the same as a dead peer; this
/// deadline detects both cases and lets this daemon recover without restarting.
const CREDENTIAL_CALL_DEADLINE: Duration = Duration::from_secs(10);
const DEFAULT_TRANSIENT_RETRIES: usize = 2;

pub type CredentialResolverFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialErrorClass {
    AuthRequired,
    CredentialAbsent,
    Unauthorized,
    Permanent,
    Transient,
    ContextOverflow,
    InvalidResponse,
    Transport,
    Unavailable,
    Unclassified,
}

impl CredentialErrorClass {
    pub fn classifier_code(self) -> &'static str {
        match self {
            Self::AuthRequired => "credential_auth_required",
            Self::CredentialAbsent => "credential_absent",
            Self::Unauthorized => "unauthorized",
            Self::Permanent => "credential_permanent",
            Self::Transient => "credential_transient",
            Self::ContextOverflow => "credential_context_overflow",
            Self::InvalidResponse => "credential_invalid_response",
            Self::Transport => "credential_transport",
            Self::Unavailable => "credential_resolver_unavailable",
            Self::Unclassified => "credential_unclassified",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialResolverError {
    pub class: CredentialErrorClass,
    code: String,
    safe_message: String,
}

impl CredentialResolverError {
    pub fn new(class: CredentialErrorClass, safe_message: impl Into<String>) -> Self {
        let code = class.classifier_code();
        Self {
            class,
            code: code.to_owned(),
            safe_message: safe_message.into(),
        }
    }

    pub fn unavailable() -> Self {
        Self::new(
            CredentialErrorClass::Unavailable,
            "campaign credential resolver is unavailable",
        )
    }

    pub fn transport(message: impl Into<String>) -> Self {
        Self::new(CredentialErrorClass::Transport, message)
    }

    fn unclassified(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            class: CredentialErrorClass::Unclassified,
            code: code.into(),
            safe_message: message.into(),
        }
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn retryable(&self) -> bool {
        matches!(
            self.class,
            CredentialErrorClass::Transient | CredentialErrorClass::Transport
        )
    }

    pub fn is_transport(&self) -> bool {
        matches!(
            self.class,
            CredentialErrorClass::Transport | CredentialErrorClass::Unavailable
        )
    }
}

impl std::fmt::Display for CredentialResolverError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.safe_message)
    }
}

impl std::error::Error for CredentialResolverError {}

pub struct ResolvedCredential {
    payload: Vec<u8>,
    pub record_version: String,
    pub expires_at_ms: Option<i64>,
}

/// Plaintext readiness metadata for a scoped credential. This never contains or
/// mints credential material, so callers can poll repair progress safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialStatus {
    pub ready: bool,
    pub record_version: Option<String>,
    pub stale_pending: bool,
    pub last_error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialSignature {
    pub signature_hex: String,
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialPublicKey {
    pub public_key_hex: String,
    pub key_id: String,
    pub algorithm: String,
}

/// The metadata `credential.list_scoped` returns for the caller's own grants.
/// It carries identity and protocol only, never secret material.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopedCredentialListing {
    pub credentials: Vec<ListedCredential>,
    /// Row-local decode failures; usable rows in the same reply remain available.
    pub undecodable_credentials: Vec<String>,
    pub grant_tuples: Vec<ListedGrant>,
    /// Tuple-local decode failures; malformed tuples never become usable grants.
    pub undecodable_grants: Vec<String>,
    /// Digest over the listed rows and grants. It moves when grants, records,
    /// record states or identities change, but not when a token is refreshed.
    pub view: String,
}

/// One vault row as `credential.list_scoped` describes it. The vault fills in
/// `account_id` and `refresh_adapter` only for rows the caller may list or read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListedCredential {
    /// The vault credential ID, returned verbatim (for example `oauth:anthropic:yiyi`).
    pub id: String,
    pub categories: Vec<String>,
    pub credential_type: String,
    /// Model vendors, not Fusiform provider IDs. Never use these for reachability.
    pub serves: Vec<String>,
    /// Missing on older vaults and empty until the operator maps the credential.
    pub provider_ids: Vec<String>,
    pub auth_method: Option<String>,
    pub refresh_adapter: Option<String>,
    pub state: String,
    pub record_version: u64,
    pub operations: Vec<String>,
    pub account_id: Option<String>,
    pub email: Option<String>,
    pub org_name: Option<String>,
}

/// One grant the caller holds: which selector it names and which operation it allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedGrant {
    pub selector_kind: String,
    pub selector: String,
    pub operation: String,
}

impl ResolvedCredential {
    pub fn new(payload: Vec<u8>, record_version: String, expires_at_ms: Option<i64>) -> Self {
        Self {
            payload,
            record_version,
            expires_at_ms,
        }
    }

    pub fn expose(&self) -> &[u8] {
        &self.payload
    }
}

impl std::fmt::Debug for ResolvedCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResolvedCredential")
            .field("payload", &"[REDACTED]")
            .field("record_version", &self.record_version)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

impl Drop for ResolvedCredential {
    fn drop(&mut self) {
        self.payload.fill(0);
    }
}

pub trait CredentialResolver: Send + Sync {
    /// `raw_handle` is the capability stored only in module configuration. Callers
    /// must use the config's public credential name in reports and diagnostics.
    fn resolve<'a>(
        &'a self,
        raw_handle: &'a str,
        min_ttl_ms: Option<u64>,
        force_refresh: bool,
    ) -> CredentialResolverFuture<'a, Result<ResolvedCredential, CredentialResolverError>>;

    /// Reads a credential by its vault ID under the route's reserved principal.
    /// Unlike `resolve`, this never accepts a raw capability handle.
    fn get_scoped<'a>(
        &'a self,
        credential_id: &'a str,
    ) -> CredentialResolverFuture<'a, Result<ResolvedCredential, CredentialResolverError>>;

    /// Returns status for a vault ID under the reserved principal without minting.
    fn status_scoped<'a>(
        &'a self,
        _credential_id: &'a str,
    ) -> CredentialResolverFuture<'a, Result<CredentialStatus, CredentialResolverError>> {
        Box::pin(async { Err(CredentialResolverError::unavailable()) })
    }

    fn sign<'a>(
        &'a self,
        _handle: &'a str,
        _payload: &'a [u8],
    ) -> CredentialResolverFuture<'a, Result<CredentialSignature, CredentialResolverError>> {
        Box::pin(async { Err(CredentialResolverError::unavailable()) })
    }

    fn public_key<'a>(
        &'a self,
        _handle: &'a str,
    ) -> CredentialResolverFuture<'a, Result<CredentialPublicKey, CredentialResolverError>> {
        Box::pin(async { Err(CredentialResolverError::unavailable()) })
    }

    /// Lists the vault rows covered by this principal's own grants, metadata only.
    fn list_scoped(
        &self,
    ) -> CredentialResolverFuture<'_, Result<ScopedCredentialListing, CredentialResolverError>>
    {
        Box::pin(async { Err(CredentialResolverError::unavailable()) })
    }
}

/// Fail-closed resolver used when no live claustrum route is available.
#[derive(Debug, Default)]
pub struct UnavailableCredentialResolver;

impl CredentialResolver for UnavailableCredentialResolver {
    fn resolve<'a>(
        &'a self,
        _raw_handle: &'a str,
        _min_ttl_ms: Option<u64>,
        _force_refresh: bool,
    ) -> CredentialResolverFuture<'a, Result<ResolvedCredential, CredentialResolverError>> {
        Box::pin(async { Err(CredentialResolverError::unavailable()) })
    }

    fn get_scoped<'a>(
        &'a self,
        _credential_id: &'a str,
    ) -> CredentialResolverFuture<'a, Result<ResolvedCredential, CredentialResolverError>> {
        Box::pin(async { Err(CredentialResolverError::unavailable()) })
    }
}

#[doc(hidden)]
pub trait CredentialGetTarget: Send + Sync {
    fn credential_get<'a>(
        &'a self,
        raw_handle: &'a str,
        min_ttl_ms: Option<u64>,
        force_refresh: bool,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>>;

    fn credential_get_scoped<'a>(
        &'a self,
        _credential_id: &'a str,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(async {
            Err(CredentialResolverError::new(
                CredentialErrorClass::Permanent,
                "credential scoped reads are unavailable",
            ))
        })
    }

    fn credential_status<'a>(
        &'a self,
        _credential_id: &'a str,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(async {
            Err(CredentialResolverError::new(
                CredentialErrorClass::Permanent,
                "credential status reads are unavailable",
            ))
        })
    }

    fn credential_sign<'a>(
        &'a self,
        _handle: &'a str,
        _payload: &'a [u8],
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(async {
            Err(CredentialResolverError::new(
                CredentialErrorClass::Permanent,
                "credential signing is unavailable",
            ))
        })
    }

    fn credential_public_key<'a>(
        &'a self,
        _handle: &'a str,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(async {
            Err(CredentialResolverError::new(
                CredentialErrorClass::Permanent,
                "credential public-key reads are unavailable",
            ))
        })
    }

    fn credential_list_scoped(
        &self,
    ) -> CredentialResolverFuture<'_, Result<Value, CredentialResolverError>> {
        Box::pin(async {
            Err(CredentialResolverError::new(
                CredentialErrorClass::Permanent,
                "credential listing is unavailable",
            ))
        })
    }
}

/// Live claustrum-backed resolver. It lazily opens one soft outbound route and
/// retries transient or transport errors for credential operations;
/// scoped reads return the first error because each consumer owns its one-shot
/// redial bound. Auth and permanent failures always return immediately.
pub struct ClaustrumCredentialResolver {
    target: Arc<dyn CredentialGetTarget>,
    transient_retries: usize,
}

impl std::fmt::Debug for ClaustrumCredentialResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClaustrumCredentialResolver")
            .field("target", &CREDENTIAL_MODULE_ID)
            .field("transient_retries", &self.transient_retries)
            .finish()
    }
}

impl ClaustrumCredentialResolver {
    pub fn new(
        connection_file_path: PathBuf,
        project_root: PathBuf,
        consumer_module_id: impl Into<String>,
    ) -> Self {
        Self {
            target: Arc::new(LiveCredentialGetTarget::new(
                Arc::new(LiveCredentialConnector {
                    connection_file_path,
                    project_root,
                    consumer_module_id: consumer_module_id.into(),
                }),
                CREDENTIAL_CALL_DEADLINE,
            )),
            transient_retries: DEFAULT_TRANSIENT_RETRIES,
        }
    }

    #[doc(hidden)]
    pub fn with_live_consumer_identity(
        connection_file_path: PathBuf,
        project_root: PathBuf,
        consumer_module_id: String,
    ) -> Self {
        Self {
            target: Arc::new(LiveCredentialGetTarget::new(
                Arc::new(LiveCredentialConnector {
                    connection_file_path,
                    project_root,
                    consumer_module_id,
                }),
                CREDENTIAL_CALL_DEADLINE,
            )),
            transient_retries: DEFAULT_TRANSIENT_RETRIES,
        }
    }

    #[doc(hidden)]
    pub fn with_target(target: Arc<dyn CredentialGetTarget>, transient_retries: usize) -> Self {
        Self {
            target,
            transient_retries,
        }
    }
}

impl CredentialResolver for ClaustrumCredentialResolver {
    fn resolve<'a>(
        &'a self,
        raw_handle: &'a str,
        min_ttl_ms: Option<u64>,
        force_refresh: bool,
    ) -> CredentialResolverFuture<'a, Result<ResolvedCredential, CredentialResolverError>> {
        Box::pin(async move {
            let mut retries = 0;
            loop {
                match self
                    .target
                    .credential_get(raw_handle, min_ttl_ms, force_refresh)
                    .await
                {
                    Ok(reply) => return decode_credential_reply(reply),
                    Err(error) if error.retryable() && retries < self.transient_retries => {
                        retries += 1;
                    }
                    Err(error) => return Err(error),
                }
            }
        })
    }

    fn get_scoped<'a>(
        &'a self,
        credential_id: &'a str,
    ) -> CredentialResolverFuture<'a, Result<ResolvedCredential, CredentialResolverError>> {
        Box::pin(async move {
            self.target
                .credential_get_scoped(credential_id)
                .await
                .and_then(decode_credential_reply)
        })
    }

    fn status_scoped<'a>(
        &'a self,
        credential_id: &'a str,
    ) -> CredentialResolverFuture<'a, Result<CredentialStatus, CredentialResolverError>> {
        Box::pin(async move {
            self.target
                .credential_status(credential_id)
                .await
                .and_then(decode_credential_status_reply)
        })
    }

    fn sign<'a>(
        &'a self,
        handle: &'a str,
        payload: &'a [u8],
    ) -> CredentialResolverFuture<'a, Result<CredentialSignature, CredentialResolverError>> {
        Box::pin(async move {
            let mut retries = 0;
            loop {
                match self.target.credential_sign(handle, payload).await {
                    Ok(reply) => return decode_signature_reply(reply),
                    Err(error) if error.retryable() && retries < self.transient_retries => {
                        retries += 1;
                    }
                    Err(error) => return Err(error),
                }
            }
        })
    }

    fn public_key<'a>(
        &'a self,
        handle: &'a str,
    ) -> CredentialResolverFuture<'a, Result<CredentialPublicKey, CredentialResolverError>> {
        Box::pin(async move {
            let mut retries = 0;
            loop {
                match self.target.credential_public_key(handle).await {
                    Ok(reply) => return decode_public_key_reply(reply),
                    Err(error) if error.retryable() && retries < self.transient_retries => {
                        retries += 1;
                    }
                    Err(error) => return Err(error),
                }
            }
        })
    }

    fn list_scoped(
        &self,
    ) -> CredentialResolverFuture<'_, Result<ScopedCredentialListing, CredentialResolverError>>
    {
        // One attempt per call: the caller polls on its own cadence, so a failed
        // listing is simply retried at the next poll.
        Box::pin(async move {
            self.target
                .credential_list_scoped()
                .await
                .and_then(decode_list_scoped_reply)
        })
    }
}

trait CredentialConsumerConnection: Send {
    fn credential_get<'a>(
        &'a mut self,
        raw_handle: &'a str,
        min_ttl_ms: Option<u64>,
        force_refresh: bool,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>>;

    fn credential_get_scoped<'a>(
        &'a mut self,
        credential_id: &'a str,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>>;

    fn credential_status<'a>(
        &'a mut self,
        _credential_id: &'a str,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(async {
            Err(CredentialResolverError::new(
                CredentialErrorClass::Permanent,
                "credential status reads are unavailable",
            ))
        })
    }

    fn credential_sign<'a>(
        &'a mut self,
        credential_id: &'a str,
        payload: &'a [u8],
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>>;

    fn credential_public_key<'a>(
        &'a mut self,
        credential_id: &'a str,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>>;

    fn credential_list_scoped(
        &mut self,
    ) -> CredentialResolverFuture<'_, Result<Value, CredentialResolverError>> {
        Box::pin(async {
            Err(CredentialResolverError::new(
                CredentialErrorClass::Permanent,
                "credential listing is unavailable",
            ))
        })
    }
}

trait CredentialConsumerConnector: Send + Sync {
    fn connect<'a>(
        &'a self,
    ) -> CredentialResolverFuture<
        'a,
        Result<Box<dyn CredentialConsumerConnection>, CredentialResolverError>,
    >;
}

struct LiveCredentialConnector {
    connection_file_path: PathBuf,
    project_root: PathBuf,
    consumer_module_id: String,
}

impl CredentialConsumerConnector for LiveCredentialConnector {
    fn connect<'a>(
        &'a self,
    ) -> CredentialResolverFuture<
        'a,
        Result<Box<dyn CredentialConsumerConnection>, CredentialResolverError>,
    > {
        Box::pin(async move {
            ClaustrumConsumer::connect(
                &self.connection_file_path,
                &self.project_root,
                &self.consumer_module_id,
            )
            .await
            .map(|consumer| Box::new(consumer) as Box<dyn CredentialConsumerConnection>)
        })
    }
}

struct LiveCredentialGetTarget {
    connector: Arc<dyn CredentialConsumerConnector>,
    call_deadline: Duration,
    consumer: AsyncMutex<Option<Box<dyn CredentialConsumerConnection>>>,
}

impl LiveCredentialGetTarget {
    fn new(connector: Arc<dyn CredentialConsumerConnector>, call_deadline: Duration) -> Self {
        Self {
            connector,
            call_deadline,
            consumer: AsyncMutex::new(None),
        }
    }

    async fn connect_if_needed(
        &self,
        consumer: &mut Option<Box<dyn CredentialConsumerConnection>>,
    ) -> Result<(), CredentialResolverError> {
        if consumer.is_none() {
            *consumer = Some(self.connector.connect().await?);
        }
        Ok(())
    }

    fn deadline_error(operation: &str) -> CredentialResolverError {
        CredentialResolverError::transport(format!(
            "{operation} timed out waiting for the credential route"
        ))
    }

    fn clear_failed_transport<T>(
        consumer: &mut Option<Box<dyn CredentialConsumerConnection>>,
        result: &Result<T, CredentialResolverError>,
    ) {
        if result
            .as_ref()
            .is_err_and(CredentialResolverError::is_transport)
        {
            *consumer = None;
        }
    }
}

impl CredentialGetTarget for LiveCredentialGetTarget {
    fn credential_get<'a>(
        &'a self,
        raw_handle: &'a str,
        min_ttl_ms: Option<u64>,
        force_refresh: bool,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(async move {
            let mut consumer = self.consumer.lock().await;
            self.connect_if_needed(&mut consumer).await?;
            let result = tokio::time::timeout(
                self.call_deadline,
                consumer
                    .as_mut()
                    .expect("credential consumer initialized")
                    .credential_get(raw_handle, min_ttl_ms, force_refresh),
            )
            .await
            .unwrap_or_else(|_| Err(Self::deadline_error(CREDENTIAL_GET_OP)));
            Self::clear_failed_transport(&mut consumer, &result);
            result
        })
    }

    fn credential_get_scoped<'a>(
        &'a self,
        credential_id: &'a str,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(async move {
            let mut consumer = self.consumer.lock().await;
            self.connect_if_needed(&mut consumer).await?;
            let result = tokio::time::timeout(
                self.call_deadline,
                consumer
                    .as_mut()
                    .expect("credential consumer initialized")
                    .credential_get_scoped(credential_id),
            )
            .await
            .unwrap_or_else(|_| Err(Self::deadline_error(CREDENTIAL_GET_SCOPED_OP)));
            Self::clear_failed_transport(&mut consumer, &result);
            result
        })
    }

    fn credential_status<'a>(
        &'a self,
        credential_id: &'a str,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(async move {
            let mut consumer = self.consumer.lock().await;
            self.connect_if_needed(&mut consumer).await?;
            let result = tokio::time::timeout(
                self.call_deadline,
                consumer
                    .as_mut()
                    .expect("credential consumer initialized")
                    .credential_status(credential_id),
            )
            .await
            .unwrap_or_else(|_| Err(Self::deadline_error(CREDENTIAL_STATUS_OP)));
            Self::clear_failed_transport(&mut consumer, &result);
            result
        })
    }

    fn credential_sign<'a>(
        &'a self,
        credential_id: &'a str,
        payload: &'a [u8],
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(async move {
            let mut consumer = self.consumer.lock().await;
            self.connect_if_needed(&mut consumer).await?;
            let result = tokio::time::timeout(
                self.call_deadline,
                consumer
                    .as_mut()
                    .expect("credential consumer initialized")
                    .credential_sign(credential_id, payload),
            )
            .await
            .unwrap_or_else(|_| Err(Self::deadline_error(CREDENTIAL_SIGN_OP)));
            Self::clear_failed_transport(&mut consumer, &result);
            result
        })
    }

    fn credential_public_key<'a>(
        &'a self,
        credential_id: &'a str,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(async move {
            let mut consumer = self.consumer.lock().await;
            self.connect_if_needed(&mut consumer).await?;
            let result = tokio::time::timeout(
                self.call_deadline,
                consumer
                    .as_mut()
                    .expect("credential consumer initialized")
                    .credential_public_key(credential_id),
            )
            .await
            .unwrap_or_else(|_| Err(Self::deadline_error(CREDENTIAL_PUBLIC_KEY_OP)));
            Self::clear_failed_transport(&mut consumer, &result);
            result
        })
    }

    fn credential_list_scoped(
        &self,
    ) -> CredentialResolverFuture<'_, Result<Value, CredentialResolverError>> {
        Box::pin(async move {
            let mut consumer = self.consumer.lock().await;
            self.connect_if_needed(&mut consumer).await?;
            let result = tokio::time::timeout(
                self.call_deadline,
                consumer
                    .as_mut()
                    .expect("credential consumer initialized")
                    .credential_list_scoped(),
            )
            .await
            .unwrap_or_else(|_| Err(Self::deadline_error(CREDENTIAL_LIST_SCOPED_OP)));
            Self::clear_failed_transport(&mut consumer, &result);
            result
        })
    }
}

struct ClaustrumConsumer {
    stream: TcpStream,
    route_channel: u16,
    route_epoch: u32,
    next_corr: u64,
}

impl ClaustrumConsumer {
    async fn connect(
        connection_file_path: &Path,
        project_root: &Path,
        consumer_module_id: &str,
    ) -> Result<Self, CredentialResolverError> {
        let connection = connection_file::read(connection_file_path).map_err(|error| {
            CredentialResolverError::transport(format!(
                "credential route connection metadata is unavailable: {error}"
            ))
        })?;
        let endpoint = connection.endpoints.first().ok_or_else(|| {
            CredentialResolverError::transport("credential route has no daemon endpoint")
        })?;
        let address = format!("{}:{}", endpoint.host, endpoint.port);
        let mut stream =
            tokio::time::timeout(CREDENTIAL_CONNECT_TIMEOUT, TcpStream::connect(address))
                .await
                .map_err(|error| {
                    CredentialResolverError::transport(format!(
                        "credential route connection timed out: {error}"
                    ))
                })?
                .map_err(|error| {
                    CredentialResolverError::transport(format!(
                        "credential route connection failed: {error}"
                    ))
                })?;
        authenticate_client(&mut stream, &connection, CREDENTIAL_CONNECT_TIMEOUT)
            .await
            .map_err(|_| {
                CredentialResolverError::new(
                    CredentialErrorClass::AuthRequired,
                    "credential route authentication failed",
                )
            })?;
        let mut consumer = Self {
            stream,
            route_channel: 0,
            route_epoch: 0,
            next_corr: 1,
        };
        (consumer.route_channel, consumer.route_epoch) = consumer
            .route_open(project_root, consumer_module_id)
            .await?;
        Ok(consumer)
    }

    fn next_correlation(&mut self) -> u64 {
        let correlation = self.next_corr;
        self.next_corr += 1;
        correlation
    }

    async fn route_open(
        &mut self,
        project_root: &Path,
        consumer_module_id: &str,
    ) -> Result<(u16, u32), CredentialResolverError> {
        let correlation = self.next_correlation();
        let body = route_open_body(project_root, consumer_module_id);
        self.write_request(0, 0, correlation, Priority::Passive, body)
            .await?;
        let reply = self.read_reply(0, 0, correlation).await?;
        if reply.header.ty == FrameType::Error {
            return Err(decode_wire_error(&reply.body));
        }
        let value: Value = serde_json::from_slice(&reply.body).map_err(|_| {
            CredentialResolverError::new(
                CredentialErrorClass::InvalidResponse,
                "credential route-open reply is not valid JSON",
            )
        })?;
        let channel = value
            .get("route_channel")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| {
                CredentialResolverError::new(
                    CredentialErrorClass::InvalidResponse,
                    "credential route-open reply has no valid channel",
                )
            })?;
        let epoch = value
            .get("route_epoch")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| {
                CredentialResolverError::new(
                    CredentialErrorClass::InvalidResponse,
                    "credential route-open reply has no valid epoch",
                )
            })?;
        Ok((channel, epoch))
    }

    async fn credential_get(
        &mut self,
        raw_handle: &str,
        min_ttl_ms: Option<u64>,
        force_refresh: bool,
    ) -> Result<Value, CredentialResolverError> {
        self.credential_request(
            credential_get_request(raw_handle, min_ttl_ms, force_refresh),
            "credential.get",
        )
        .await
    }

    async fn credential_get_scoped(
        &mut self,
        credential_id: &str,
    ) -> Result<Value, CredentialResolverError> {
        self.credential_request(
            credential_get_scoped_request(credential_id),
            "credential.get_scoped",
        )
        .await
    }

    async fn credential_status(
        &mut self,
        credential_id: &str,
    ) -> Result<Value, CredentialResolverError> {
        self.credential_request(
            credential_status_request(credential_id),
            CREDENTIAL_STATUS_OP,
        )
        .await
    }

    async fn credential_sign(
        &mut self,
        handle: &str,
        payload: &[u8],
    ) -> Result<Value, CredentialResolverError> {
        self.credential_request(credential_sign_request(handle, payload), CREDENTIAL_SIGN_OP)
            .await
    }

    async fn credential_public_key(
        &mut self,
        handle: &str,
    ) -> Result<Value, CredentialResolverError> {
        self.credential_request(
            credential_public_key_request(handle),
            CREDENTIAL_PUBLIC_KEY_OP,
        )
        .await
    }

    async fn credential_request(
        &mut self,
        request: Value,
        operation: &str,
    ) -> Result<Value, CredentialResolverError> {
        let correlation = self.next_correlation();
        self.write_request(
            self.route_channel,
            self.route_epoch,
            correlation,
            Priority::Interactive,
            request,
        )
        .await?;
        let reply = self
            .read_reply(self.route_channel, self.route_epoch, correlation)
            .await?;
        if reply.header.ty == FrameType::Error {
            return Err(decode_wire_error(&reply.body));
        }
        serde_json::from_slice(&reply.body).map_err(|_| {
            CredentialResolverError::new(
                CredentialErrorClass::InvalidResponse,
                format!("{operation} reply is not valid JSON"),
            )
        })
    }

    async fn write_request(
        &mut self,
        channel: u16,
        epoch: u32,
        correlation: u64,
        priority: Priority,
        body: Value,
    ) -> Result<(), CredentialResolverError> {
        let bytes = serde_json::to_vec(&body).map_err(|_| {
            CredentialResolverError::new(
                CredentialErrorClass::Permanent,
                "credential request encoding failed",
            )
        })?;
        let frame = Frame::build(
            FrameType::Request,
            Flags::new(false, priority, false),
            channel,
            epoch,
            correlation,
            bytes,
        )
        .map_err(|_| {
            CredentialResolverError::new(
                CredentialErrorClass::Permanent,
                "credential request framing failed",
            )
        })?;
        write_frame(&mut self.stream, &frame)
            .await
            .map_err(|error| {
                CredentialResolverError::transport(format!(
                    "credential route write failed: {error}"
                ))
            })
    }

    async fn read_reply(
        &mut self,
        channel: u16,
        epoch: u32,
        correlation: u64,
    ) -> Result<Frame, CredentialResolverError> {
        loop {
            let frame = tokio::time::timeout(CREDENTIAL_READ_TIMEOUT, read_frame(&mut self.stream))
                .await
                .map_err(|error| {
                    CredentialResolverError::transport(format!(
                        "credential route reply timed out: {error}"
                    ))
                })?
                .map_err(|error| {
                    CredentialResolverError::transport(format!(
                        "credential route read failed: {error}"
                    ))
                })?
                .ok_or_else(|| {
                    CredentialResolverError::transport("credential route closed before replying")
                })?;
            if frame.header.channel == channel
                && frame.header.epoch == epoch
                && frame.header.corr == correlation
                && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
            {
                return Ok(frame);
            }
        }
    }
}

impl CredentialConsumerConnection for ClaustrumConsumer {
    fn credential_get<'a>(
        &'a mut self,
        raw_handle: &'a str,
        min_ttl_ms: Option<u64>,
        force_refresh: bool,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(ClaustrumConsumer::credential_get(
            self,
            raw_handle,
            min_ttl_ms,
            force_refresh,
        ))
    }

    fn credential_get_scoped<'a>(
        &'a mut self,
        credential_id: &'a str,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(ClaustrumConsumer::credential_get_scoped(
            self,
            credential_id,
        ))
    }

    fn credential_status<'a>(
        &'a mut self,
        credential_id: &'a str,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(ClaustrumConsumer::credential_status(self, credential_id))
    }

    fn credential_sign<'a>(
        &'a mut self,
        credential_id: &'a str,
        payload: &'a [u8],
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(ClaustrumConsumer::credential_sign(
            self,
            credential_id,
            payload,
        ))
    }

    fn credential_public_key<'a>(
        &'a mut self,
        credential_id: &'a str,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(ClaustrumConsumer::credential_public_key(
            self,
            credential_id,
        ))
    }

    fn credential_list_scoped(
        &mut self,
    ) -> CredentialResolverFuture<'_, Result<Value, CredentialResolverError>> {
        Box::pin(
            self.credential_request(credential_list_scoped_request(), CREDENTIAL_LIST_SCOPED_OP),
        )
    }
}

fn credential_list_scoped_request() -> Value {
    // A supervised module is identified by its route's reserved principal, so it
    // sends no enrollment token; the vault refuses unknown parameters.
    json!({
        "method": CREDENTIAL_LIST_SCOPED_OP,
        "params": {},
    })
}

fn optional_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

fn invalid_listing(detail: &str) -> CredentialResolverError {
    CredentialResolverError::new(
        CredentialErrorClass::InvalidResponse,
        format!("credential.list_scoped reply {detail}"),
    )
}

fn listing_strings(row: &Value, key: &str, optional: bool) -> Result<Vec<String>, String> {
    if optional && row.get(key).is_none() {
        return Ok(Vec::new());
    }
    let items = row
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{key} is not an array"))?;
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{key} contains a non-string"))
        })
        .collect()
}

fn listing_string(row: &Value, key: &str) -> Result<String, String> {
    optional_string(row, key).ok_or_else(|| format!("{key} is not a non-empty string"))
}

fn listing_optional_string(row: &Value, key: &str) -> Result<Option<String>, String> {
    match row.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(|s| Some(s.to_owned()))
            .ok_or_else(|| format!("{key} is not a string")),
    }
}

fn decode_listed_credential(row: &Value) -> Result<ListedCredential, String> {
    Ok(ListedCredential {
        id: listing_string(row, "id")?,
        categories: listing_strings(row, "categories", false)?,
        credential_type: listing_string(row, "type")?,
        serves: listing_strings(row, "serves", false)?,
        provider_ids: listing_strings(row, "provider_ids", true)?,
        auth_method: listing_optional_string(row, "auth_method")?,
        refresh_adapter: listing_optional_string(row, "refresh_adapter")?,
        state: listing_string(row, "state")?,
        record_version: row
            .get("record_version")
            .and_then(Value::as_u64)
            .ok_or_else(|| "record_version is not an unsigned integer".to_string())?,
        operations: listing_strings(row, "operations", false)?,
        account_id: listing_optional_string(row, "account_id")?,
        email: listing_optional_string(row, "email")?,
        org_name: listing_optional_string(row, "org_name")?,
    })
}

fn decode_listed_grant(tuple: &Value) -> Result<ListedGrant, String> {
    Ok(ListedGrant {
        selector_kind: listing_string(tuple, "selector_kind")?,
        selector: listing_string(tuple, "selector")?,
        operation: listing_string(tuple, "operation")?,
    })
}

/// Decode metadata row by row: a malformed credential or grant must not discard
/// healthy entries listed alongside it. Envelope failures still reject the listing.
fn decode_list_scoped_reply(
    value: Value,
) -> Result<ScopedCredentialListing, CredentialResolverError> {
    let result = reply_result(value)?;
    let view = result
        .get("view")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_listing("has no view digest"))?
        .to_owned();
    let rows = result
        .get("credentials")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_listing("has no credentials array"))?;
    let mut credentials = Vec::with_capacity(rows.len());
    let mut undecodable_credentials = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        match decode_listed_credential(row) {
            Ok(credential) => credentials.push(credential),
            Err(error) => {
                let id = optional_string(row, "id").unwrap_or_else(|| format!("row {index}"));
                let detail = format!("{id}: {error}");
                undecodable_credentials.push(detail);
            }
        }
    }
    let mut grant_tuples = Vec::new();
    let mut undecodable_grants = Vec::new();
    if let Some(tuples) = result.get("grant_tuples").and_then(Value::as_array) {
        for (index, tuple) in tuples.iter().enumerate() {
            match decode_listed_grant(tuple) {
                Ok(grant) => grant_tuples.push(grant),
                Err(error) => undecodable_grants.push(format!("grant tuple {index}: {error}")),
            }
        }
    }
    Ok(ScopedCredentialListing {
        credentials,
        undecodable_credentials,
        grant_tuples,
        undecodable_grants,
        view,
    })
}

fn credential_get_request(raw_handle: &str, min_ttl_ms: Option<u64>, force_refresh: bool) -> Value {
    let mut params =
        serde_json::Map::from_iter([("handle".to_owned(), Value::String(raw_handle.to_owned()))]);
    if let Some(min_ttl_ms) = min_ttl_ms {
        params.insert("min_ttl_ms".to_owned(), Value::from(min_ttl_ms));
    }
    if force_refresh {
        params.insert("force_refresh".to_owned(), Value::Bool(true));
    }
    json!({
        "method": CREDENTIAL_GET_OP,
        "params": params,
    })
}

fn credential_get_scoped_request(credential_id: &str) -> Value {
    json!({
        "method": CREDENTIAL_GET_SCOPED_OP,
        "params": { "credential_id": credential_id },
    })
}

fn credential_status_request(credential_id: &str) -> Value {
    json!({
        "method": CREDENTIAL_STATUS_OP,
        "params": { "credential_id": credential_id },
    })
}

fn credential_sign_request(credential_id: &str, payload: &[u8]) -> Value {
    // CKCRED 3aaf0e3: sign is handle-less - authorized by the launch-nonce
    // principal against the grant table's sign authority, addressed by the
    // credential NAME. A handle here would be a bearer capability for a
    // signing key, the shape the handle-less revision exists to delete.
    json!({
        "method": CREDENTIAL_SIGN_OP,
        "params": {
            "credential_id": credential_id,
            "payload_b64": base64::engine::general_purpose::STANDARD.encode(payload),
        },
    })
}

fn credential_public_key_request(credential_id: &str) -> Value {
    // The launch-nonce principal authorizes this named credential lookup; a
    // bearer capability handle must never cross the public-key request.
    json!({
        "method": CREDENTIAL_PUBLIC_KEY_OP,
        "params": { "credential_id": credential_id },
    })
}

fn decode_wire_error(bytes: &[u8]) -> CredentialResolverError {
    let value = serde_json::from_slice::<Value>(bytes).unwrap_or(Value::Null);
    classify_error_value(&value)
}

/// Daemon relay refusals: the frame never reached the credential service.
const RELAY_ROUTING_CODES: [&str; 7] = [
    subc_protocol::error_codes::UNKNOWN_MODULE,
    subc_protocol::error_codes::MODULE_RELOADING,
    subc_protocol::error_codes::MODULE_WARMING,
    subc_protocol::error_codes::TARGET_UNAVAILABLE,
    subc_protocol::error_codes::MODULE_TIMEOUT,
    "unknown_channel",
    "stale_route_epoch",
];

/// Classify a refusal that may arrive as an error frame body or as a
/// `result.error` member of a success frame. The broad class drives retry
/// behavior, while preserving the producer's code in the safe message lets an
/// operator distinguish a missing, revoked, or denied credential.
fn classify_error_value(value: &Value) -> CredentialResolverError {
    let class = value
        .get("class")
        .or_else(|| value.pointer("/error/class"))
        .or_else(|| value.pointer("/error/data/class"))
        .and_then(Value::as_str);
    let class = match class {
        Some("auth_required") => Some(CredentialErrorClass::AuthRequired),
        Some("credential_absent") => Some(CredentialErrorClass::CredentialAbsent),
        Some("unauthorized") => Some(CredentialErrorClass::Unauthorized),
        Some("permanent") => Some(CredentialErrorClass::Permanent),
        Some("transient") => Some(CredentialErrorClass::Transient),
        Some("context_overflow") => Some(CredentialErrorClass::ContextOverflow),
        _ => None,
    };
    let code_field = value
        .get("code")
        .or_else(|| value.pointer("/error/code"))
        .and_then(Value::as_str);
    // A missing record or authentication refusal requires operator repair, not
    // another signing attempt, even if a producer supplies a broad retry class.
    let class = match code_field {
        Some("not_found") => Some(CredentialErrorClass::CredentialAbsent),
        Some("auth_required") => Some(CredentialErrorClass::AuthRequired),
        _ => class,
    };
    if let Some(class) = class {
        let message = match code_field {
            Some(code) => format!("credential service rejected the request: {code}"),
            None => "credential service rejected the request".to_string(),
        };
        return CredentialResolverError::new(class, message);
    }
    let code = value
        .get("code")
        .or_else(|| value.pointer("/error/code"))
        .and_then(Value::as_str)
        .unwrap_or("credential_unclassified");
    let message = value
        .get("message")
        .or_else(|| value.pointer("/error/message"))
        .and_then(Value::as_str)
        .unwrap_or("credential service returned an unclassified error");
    // Relay routing refusals mean the DAEMON could not route the frame: the
    // credential service never spoke, so nothing about custody can be concluded
    // from them. Classify these class-less refusals as transport errors so the
    // client can redial a stale channel. The set is named here
    // rather than borrowed from the protocol's retryable route-open list:
    // whether the SDK retries a code is SUBC's policy, and subc-protocol 0.25
    // made `unknown_module` terminal, which silently turned "the credential
    // module is not there" back into a custody verdict. A copied list also
    // missed `module_warming` once (GitHub #48). The two data-path codes cover
    // an established route that died: `unknown_channel` and `stale_route_epoch`
    // (the module restarted under the route; the SDK retries each once in place
    // and surfaces it only when the retry fails the same way, GitHub #59).
    if RELAY_ROUTING_CODES.contains(&code) {
        return CredentialResolverError::new(
            CredentialErrorClass::Transport,
            format!("{code}: {message}"),
        );
    }
    CredentialResolverError::unclassified(code, message)
}

/// The route.open frame for the credential module. Reserved-principal identity
/// is carried in `consumer_identity`, not the bind parameters. The credential
/// service derives that principal by matching the launch nonce; if it is absent,
/// claustrum silently treats the caller as unscoped. Route opening must therefore
/// fail before scoped reads are reduced to an ambiguous `not_found`.
fn route_open_body(project_root: &Path, consumer_module_id: &str) -> Value {
    // The process-wide accessor, never the environment: after the first read
    // closes the pipe the daemon handed over, a second independent reader
    // would read whatever the process opened next at that descriptor number.
    let read = subc_os::launch_nonce()
        .map(|nonce| nonce.map(|nonce| nonce.value().to_owned()))
        .map_err(|error| error.to_string());
    route_open_body_with_nonce(
        project_root,
        consumer_module_id,
        &required_launch_nonce(read),
    )
}

/// The nonce from a read of it, panicking when there is none: without it the
/// route would open unscoped (see [`route_open_body`]).
fn required_launch_nonce(read: Result<Option<String>, String>) -> String {
    match read {
        Ok(Some(nonce)) if !nonce.trim().is_empty() => nonce,
        Ok(_) => panic!(
            "credential consumer requires a non-empty launch nonce for the reserved principal"
        ),
        Err(error) => panic!(
            "credential consumer could not read the launch nonce for the reserved principal: {error}"
        ),
    }
}

fn route_open_body_with_nonce(
    project_root: &Path,
    consumer_module_id: &str,
    launch_nonce: &str,
) -> Value {
    json!({
        "op": "route.open",
        "target": {
            "kind": "management_surface",
            "module_id": CREDENTIAL_MODULE_ID,
        },
        "identity": {
            "project_root": project_root,
            "harness": consumer_module_id,
            "session": "campaign-credential-consumer",
        },
        "consumer_identity": {
            "module_id": consumer_module_id,
            "launch_nonce": launch_nonce,
        },
        "config": [],
    })
}

fn reply_result(value: Value) -> Result<Value, CredentialResolverError> {
    let result = value.get("result").cloned().unwrap_or(value);
    if result.get("error").is_some() {
        return Err(classify_error_value(&result));
    }
    Ok(result)
}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

fn decode_signature_reply(value: Value) -> Result<CredentialSignature, CredentialResolverError> {
    let result = reply_result(value)?;
    let signature_b64 = result
        .get("signature_b64")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CredentialResolverError::new(
                CredentialErrorClass::InvalidResponse,
                "credential signing reply has no signature_b64",
            )
        })?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|_| {
            CredentialResolverError::new(
                CredentialErrorClass::InvalidResponse,
                "credential signing reply has invalid base64",
            )
        })?;
    if signature.len() != 64 {
        return Err(CredentialResolverError::new(
            CredentialErrorClass::InvalidResponse,
            "credential signing reply has a non-Ed25519 signature length",
        ));
    }
    let key_id = result
        .get("key_id")
        .and_then(Value::as_str)
        .filter(|value| valid_lower_hex(value, 16))
        .ok_or_else(|| {
            CredentialResolverError::new(
                CredentialErrorClass::InvalidResponse,
                "credential signing reply has no valid key_id",
            )
        })?;
    Ok(CredentialSignature {
        signature_hex: hex_bytes(&signature),
        key_id: key_id.to_owned(),
    })
}

fn decode_public_key_reply(value: Value) -> Result<CredentialPublicKey, CredentialResolverError> {
    let result = reply_result(value)?;
    let public_key_hex = result
        .get("public_key_hex")
        .and_then(Value::as_str)
        .filter(|value| valid_lower_hex(value, 64))
        .ok_or_else(|| {
            CredentialResolverError::new(
                CredentialErrorClass::InvalidResponse,
                "credential public-key reply has no valid public_key_hex",
            )
        })?;
    let key_id = result
        .get("key_id")
        .and_then(Value::as_str)
        .filter(|value| valid_lower_hex(value, 16))
        .ok_or_else(|| {
            CredentialResolverError::new(
                CredentialErrorClass::InvalidResponse,
                "credential public-key reply has no valid key_id",
            )
        })?;
    let public_key_bytes = (0..public_key_hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&public_key_hex[index..index + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .expect("validated lowercase hex decodes");
    let expected_key_id = hex_bytes(&Sha256::digest(&public_key_bytes)[..8]);
    if key_id != expected_key_id {
        return Err(CredentialResolverError::new(
            CredentialErrorClass::InvalidResponse,
            "credential public-key reply key_id does not identify public_key_hex",
        ));
    }
    let algorithm = result
        .get("algorithm")
        .and_then(Value::as_str)
        .filter(|value| *value == "ed25519")
        .ok_or_else(|| {
            CredentialResolverError::new(
                CredentialErrorClass::InvalidResponse,
                "credential public-key reply is not Ed25519",
            )
        })?;
    Ok(CredentialPublicKey {
        public_key_hex: public_key_hex.to_owned(),
        key_id: key_id.to_owned(),
        algorithm: algorithm.to_owned(),
    })
}

fn decode_credential_status_reply(
    value: Value,
) -> Result<CredentialStatus, CredentialResolverError> {
    let result = reply_result(value)?;
    let ready = result
        .get("ready")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            CredentialResolverError::new(
                CredentialErrorClass::InvalidResponse,
                "credential status reply has no ready flag",
            )
        })?;
    let record_version = result.get("record_version").and_then(|value| match value {
        Value::String(version) if !version.is_empty() => Some(version.clone()),
        Value::Number(version) => Some(version.to_string()),
        _ => None,
    });
    Ok(CredentialStatus {
        ready,
        record_version,
        stale_pending: result
            .get("stale_pending")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        last_error_code: result
            .get("last_error_code")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn decode_credential_reply(value: Value) -> Result<ResolvedCredential, CredentialResolverError> {
    let result = value.get("result").unwrap_or(&value);
    // A refusal arrives as a SUCCESS frame carrying `result.error`; demanding a
    // payload from it would launder the vault's typed answer (class + code)
    // into invalid_response - the first live push fetch reported "no opaque
    // payload" for a reply that said permanent/not_found in plain sight.
    if result.get("error").is_some() {
        return Err(classify_error_value(result));
    }
    let payload = match result.get("payload") {
        Some(Value::String(payload)) => payload.as_bytes().to_vec(),
        Some(Value::Array(payload)) => payload
            .iter()
            .map(|byte| {
                byte.as_u64()
                    .and_then(|byte| u8::try_from(byte).ok())
                    .ok_or_else(|| {
                        CredentialResolverError::new(
                            CredentialErrorClass::InvalidResponse,
                            "credential payload contains a non-byte value",
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(CredentialResolverError::new(
                CredentialErrorClass::InvalidResponse,
                "credential reply has no opaque payload",
            ));
        }
    };
    let version = result
        .get("record_version")
        .map(|version| match version {
            Value::String(version) => version.clone(),
            version => version.to_string(),
        })
        .filter(|version| !version.is_empty())
        .ok_or_else(|| {
            CredentialResolverError::new(
                CredentialErrorClass::InvalidResponse,
                "credential reply has no record version",
            )
        })?;
    let expires_at_ms = result.get("expires_at_ms").and_then(Value::as_i64);
    Ok(ResolvedCredential::new(payload, version, expires_at_ms))
}
#[cfg(test)]
mod contract_tests;

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Debug)]
    struct FakeCkcredTarget {
        script: Mutex<VecDeque<Result<Value, CredentialResolverError>>>,
        requests: Mutex<Vec<(String, Option<u64>, bool)>>,
    }

    impl CredentialGetTarget for FakeCkcredTarget {
        fn credential_get<'a>(
            &'a self,
            raw_handle: &'a str,
            min_ttl_ms: Option<u64>,
            force_refresh: bool,
        ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
            Box::pin(async move {
                self.requests
                    .lock()
                    .expect("fake CKCRED target poisoned")
                    .push((raw_handle.to_owned(), min_ttl_ms, force_refresh));
                self.script
                    .lock()
                    .expect("fake CKCRED target poisoned")
                    .pop_front()
                    .expect("fake CKCRED target script exhausted")
            })
        }

        fn credential_get_scoped<'a>(
            &'a self,
            credential_id: &'a str,
        ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
            Box::pin(async move {
                self.requests
                    .lock()
                    .expect("fake CKCRED target poisoned")
                    .push((credential_id.to_owned(), None, false));
                self.script
                    .lock()
                    .expect("fake CKCRED target poisoned")
                    .pop_front()
                    .expect("fake CKCRED target script exhausted")
            })
        }
    }

    #[derive(Debug)]
    struct DeadlineConnector {
        dials: Arc<AtomicUsize>,
    }

    impl CredentialConsumerConnector for DeadlineConnector {
        fn connect<'a>(
            &'a self,
        ) -> CredentialResolverFuture<
            'a,
            Result<Box<dyn CredentialConsumerConnection>, CredentialResolverError>,
        > {
            Box::pin(async move {
                let dial = self.dials.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(DeadlineConsumer { hangs: dial == 0 })
                    as Box<dyn CredentialConsumerConnection>)
            })
        }
    }

    struct DeadlineConsumer {
        hangs: bool,
    }

    impl CredentialConsumerConnection for DeadlineConsumer {
        fn credential_get<'a>(
            &'a mut self,
            _raw_handle: &'a str,
            _min_ttl_ms: Option<u64>,
            _force_refresh: bool,
        ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
            Box::pin(async { panic!("deadline fixture only supports scoped reads") })
        }

        fn credential_get_scoped<'a>(
            &'a mut self,
            _credential_id: &'a str,
        ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
            Box::pin(async move {
                if self.hangs {
                    std::future::pending().await
                } else {
                    Ok(json!({
                        "payload": "reconnected-secret",
                        "record_version": "2",
                    }))
                }
            })
        }

        fn credential_sign<'a>(
            &'a mut self,
            _credential_id: &'a str,
            _payload: &'a [u8],
        ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
            Box::pin(async { panic!("deadline fixture only supports scoped reads") })
        }

        fn credential_public_key<'a>(
            &'a mut self,
            _credential_id: &'a str,
        ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
            Box::pin(async { panic!("deadline fixture only supports scoped reads") })
        }
    }

    #[tokio::test]
    async fn silent_call_deadline_is_transport_rebuilds_and_releases_mutex_mutation_proof() {
        let dials = Arc::new(AtomicUsize::new(0));
        let deadline = Duration::from_millis(20);
        let target = Arc::new(LiveCredentialGetTarget::new(
            Arc::new(DeadlineConnector {
                dials: Arc::clone(&dials),
            }),
            deadline,
        ));
        let first = tokio::spawn({
            let target = Arc::clone(&target);
            async move { target.credential_get_scoped("github_app:first").await }
        });
        tokio::time::timeout(deadline, async {
            while dials.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first call must dial before the fixture deadline");

        let second = tokio::time::timeout(
            deadline.saturating_mul(3),
            target.credential_get_scoped("github_app:second"),
        )
        .await
        .expect("a timed-out holder must release the consumer mutex")
        .expect("the rebuilt consumer must serve the second caller");
        let first_error = first
            .await
            .expect("deadline task must join")
            .expect_err("the silent first consumer must reach the whole-call deadline");

        assert_eq!(first_error.class, CredentialErrorClass::Transport);
        assert!(first_error.retryable());
        assert_eq!(
            first_error.to_string(),
            "credential_transport: credential.get_scoped timed out waiting for the credential route"
        );
        assert_eq!(second["payload"], json!("reconnected-secret"));
        assert_eq!(
            dials.load(Ordering::SeqCst),
            2,
            "the deadline must clear the stale cached consumer before the next call"
        );
    }

    #[tokio::test]
    async fn live_shape_red_proof_retry_class_and_capability_redaction() {
        let raw_handle = "capability-handle-must-never-leak";
        let target = Arc::new(FakeCkcredTarget {
            script: Mutex::new(VecDeque::from([
                Err(CredentialResolverError::new(
                    CredentialErrorClass::Transient,
                    "credential service is temporarily unavailable",
                )),
                Ok(json!({
                    "result": {
                        "payload": "api-secret",
                        "record_version": 7,
                        "expires_at_ms": 1234,
                    }
                })),
            ])),
            requests: Mutex::new(Vec::new()),
        });
        let resolver = ClaustrumCredentialResolver::with_target(target.clone(), 2);

        let credential = resolver.resolve(raw_handle, Some(500), true).await.unwrap();
        assert_eq!(credential.expose(), b"api-secret");
        assert_eq!(credential.record_version, "7");
        assert_eq!(target.requests.lock().unwrap().len(), 2);
        assert!(!format!("{credential:?}").contains(raw_handle));

        let permanent = CredentialResolverError::new(
            CredentialErrorClass::Permanent,
            "credential service rejected the request",
        );
        assert!(!permanent.retryable());
        assert!(!permanent.to_string().contains(raw_handle));
    }

    #[test]
    fn relay_routing_codes_classify_transport_so_redial_arms_fire() {
        // The live specimen from the 2026-08-26 speech outage: the relay's
        // class-less unknown_channel refusal after a credential-module restart.
        // Without transport classification this class-less routing refusal is
        // treated as a custody refusal. Transport classification permits redial.
        // `module_warming` is the daemon's spelling for the pre-HELLO respawn
        // window since subc #53 (it was `target_unavailable`); a copied two-code
        // list rendered it as a custody verdict again (GitHub #48).
        for code in [
            "unknown_channel",
            "stale_route_epoch",
            "unknown_module",
            "module_warming",
            "module_reloading",
            "target_unavailable",
            "module_timeout",
        ] {
            let error = classify_error_value(&json!({
                "code": code,
                "message": format!("{code} 1"),
            }));
            assert!(
                error.is_transport(),
                "{code} must classify transport (got {:?})",
                error.class
            );
            assert!(error.to_string().contains(code), "verbatim code preserved");
        }
        // The catch-all still exists for genuinely unknown codes.
        let other = classify_error_value(&json!({"code": "weird_new_code"}));
        assert!(!other.is_transport());
    }

    #[test]
    fn ckcred_contract_red_proof_request_shape_and_error_capability_redaction() {
        let raw_handle = "raw-capability-token";
        assert_eq!(
            credential_get_request(raw_handle, Some(250), true),
            json!({
                "method": "credential.get",
                "params": {
                    "handle": raw_handle,
                    "min_ttl_ms": 250,
                    "force_refresh": true,
                }
            })
        );
        let credential_id = "github_app:scoped-agent";
        assert_eq!(
            credential_get_scoped_request(credential_id),
            json!({
                "method": "credential.get_scoped",
                "params": { "credential_id": credential_id },
            })
        );
        assert_eq!(
            credential_status_request(credential_id),
            json!({
                "method": "credential.status",
                "params": { "credential_id": credential_id },
            })
        );
        // CKCRED 3aaf0e3: sign and public_key are handle-less - addressed by
        // credential NAME under principal authority, never a bearer handle
        // (the handle spelling was the pre-cutover wire and now refuses).
        let signing_credential = "signing:agent-assertion:1";
        assert_eq!(
            credential_sign_request(signing_credential, b"abc"),
            json!({
                "method": "credential.sign",
                "params": {
                    "credential_id": signing_credential,
                    "payload_b64": "YWJj",
                },
            })
        );
        assert_eq!(
            credential_public_key_request(signing_credential),
            json!({
                "method": "credential.public_key",
                "params": { "credential_id": signing_credential },
            })
        );
        let error = decode_wire_error(
            json!({
                "class": "auth_required",
                "message": format!("unknown handle {raw_handle}"),
            })
            .to_string()
            .as_bytes(),
        );
        assert_eq!(error.class, CredentialErrorClass::AuthRequired);
        assert_eq!(error.code(), "credential_auth_required");
        assert!(!error.to_string().contains(raw_handle));
    }

    #[test]
    fn signing_replies_decode_exact_ed25519_material_and_reject_wrong_algorithm() {
        let signature = decode_signature_reply(json!({
            "result": {
                "signature_b64": base64::engine::general_purpose::STANDARD.encode([7_u8; 64]),
                "key_id": "0123456789abcdef",
            }
        }))
        .unwrap();
        assert_eq!(signature.signature_hex, "07".repeat(64));
        assert_eq!(signature.key_id, "0123456789abcdef");

        let public_key_hex = "ab".repeat(32);
        let public_key_bytes = [0xab_u8; 32];
        let key_id = hex_bytes(&Sha256::digest(public_key_bytes)[..8]);
        let public_key = decode_public_key_reply(json!({
            "result": {
                "public_key_hex": public_key_hex,
                "key_id": key_id,
                "algorithm": "ed25519",
            }
        }))
        .unwrap();
        assert_eq!(public_key.public_key_hex, "ab".repeat(32));
        assert_eq!(public_key.algorithm, "ed25519");

        let error = decode_public_key_reply(json!({
            "result": {
                "public_key_hex": "ab".repeat(32),
                "key_id": hex_bytes(&Sha256::digest(public_key_bytes)[..8]),
                "algorithm": "rsa",
            }
        }))
        .unwrap_err();
        assert_eq!(error.class, CredentialErrorClass::InvalidResponse);
    }

    #[test]
    fn unknown_method_without_a_class_remains_unclassified_and_preserves_producer_details() {
        let error = decode_wire_error(
            br#"{"code":"unknown_method","message":"unknown method 'credential.put'"}"#,
        );
        assert_eq!(error.class, CredentialErrorClass::Unclassified);
        assert_eq!(error.code(), "unknown_method");
        assert!(!error.retryable());
        assert_ne!(error.class, CredentialErrorClass::Permanent);
        assert_eq!(
            error.to_string(),
            "unknown_method: unknown method 'credential.put'"
        );
    }

    #[test]
    fn error_shaped_success_reply_surfaces_the_typed_class_and_code() {
        // The vault answers a principal-bound handle miss as a SUCCESS frame
        // carrying result.error; demanding a payload from it laundered the
        // typed answer into invalid_response on the first live push fetch.
        let error = decode_credential_reply(json!({
            "result": { "error": { "class": "permanent", "code": "not_found" } }
        }))
        .expect_err("an error reply must not decode as a credential");
        assert_eq!(error.class, CredentialErrorClass::CredentialAbsent);
        assert!(
            error.to_string().contains("not_found"),
            "the producer's code must survive classification: {error}"
        );
        assert!(
            !error.to_string().contains("opaque payload"),
            "a typed refusal must never render as invalid_response: {error}"
        );
    }

    #[tokio::test]
    async fn scoped_transport_failure_returns_without_internal_retry_ladder_mutation_proof() {
        let credential_id = "github_app:bounded-agent";
        let target = Arc::new(FakeCkcredTarget {
            script: Mutex::new(VecDeque::from([
                Err(CredentialResolverError::transport(
                    "connection reset by peer",
                )),
                Ok(json!({
                    "payload": "must-not-be-reached",
                    "record_version": "2",
                })),
            ])),
            requests: Mutex::new(Vec::new()),
        });
        let resolver = ClaustrumCredentialResolver::with_target(target.clone(), 2);

        let error = resolver
            .get_scoped(credential_id)
            .await
            .expect_err("caller owns the scoped redial");

        assert_eq!(error.class, CredentialErrorClass::Transport);
        assert_eq!(target.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn scoped_reads_use_the_credential_id_and_decode_the_record_directly() {
        let credential_id = "github_app:scoped-agent";
        let target = Arc::new(FakeCkcredTarget {
            script: Mutex::new(VecDeque::from([Ok(json!({
                "payload": "-----BEGIN PRIVATE KEY-----\nscoped PEM\n-----END PRIVATE KEY-----",
                "record_version": "7",
            }))])),
            requests: Mutex::new(Vec::new()),
        });
        let resolver = ClaustrumCredentialResolver::with_target(target.clone(), 0);

        let credential = resolver.get_scoped(credential_id).await.unwrap();

        assert_eq!(
            credential.expose(),
            b"-----BEGIN PRIVATE KEY-----\nscoped PEM\n-----END PRIVATE KEY-----"
        );
        assert_eq!(credential.record_version, "7");
        assert_eq!(
            target.requests.lock().unwrap().as_slice(),
            &[(credential_id.to_owned(), None, false)]
        );
    }

    #[test]
    fn route_open_body_carries_the_reserved_consumer_identity_when_the_nonce_is_present() {
        let root = Path::new("/probe/root");
        let body = route_open_body_with_nonce(root, "prefrontal-core", "nonce-under-test");
        assert_eq!(
            body.pointer("/consumer_identity/module_id")
                .and_then(Value::as_str),
            Some("prefrontal-core"),
            "a supervised launch must ride the reserved principal"
        );
        assert_eq!(
            body.pointer("/consumer_identity/launch_nonce")
                .and_then(Value::as_str),
            Some("nonce-under-test")
        );
    }

    #[test]
    fn motor_credential_route_presents_its_launch_nonce() {
        let body =
            route_open_body_with_nonce(Path::new("/motor-project"), "ck-motor", "motor-nonce");
        assert_eq!(body["op"], "route.open");
        assert_eq!(body["target"]["module_id"], "claustrum");
        assert_eq!(
            body["consumer_identity"],
            json!({"module_id":"ck-motor", "launch_nonce":"motor-nonce"})
        );
    }

    #[tokio::test]
    async fn signing_not_found_and_auth_required_are_terminal_without_retries() {
        struct TerminalTarget {
            code: &'static str,
            calls: AtomicUsize,
        }
        impl CredentialGetTarget for TerminalTarget {
            fn credential_get<'a>(
                &'a self,
                _: &'a str,
                _: Option<u64>,
                _: bool,
            ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
                panic!("signing must not read private credentials")
            }
            fn credential_sign<'a>(
                &'a self,
                _: &'a str,
                _: &'a [u8],
            ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
                Box::pin(async move {
                    self.calls.fetch_add(1, Ordering::SeqCst);
                    Err(classify_error_value(
                        &json!({"code":self.code, "class":"transient", "message":"do not log vault material"}),
                    ))
                })
            }
            fn credential_public_key<'a>(
                &'a self,
                _: &'a str,
            ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
                self.credential_sign("unused", b"")
            }
        }
        for (code, class) in [
            ("not_found", CredentialErrorClass::CredentialAbsent),
            ("auth_required", CredentialErrorClass::AuthRequired),
        ] {
            let target = Arc::new(TerminalTarget {
                code,
                calls: AtomicUsize::new(0),
            });
            let resolver = ClaustrumCredentialResolver::with_target(target.clone(), 2);
            assert_eq!(
                resolver
                    .sign("signing:ck-motor-ssh:1", b"challenge")
                    .await
                    .unwrap_err()
                    .class,
                class
            );
            assert_eq!(
                resolver
                    .public_key("signing:ck-motor-ssh:1")
                    .await
                    .unwrap_err()
                    .class,
                class
            );
            assert_eq!(target.calls.load(Ordering::SeqCst), 2);
            for wire in [
                json!({"code":code}),
                json!({"error":{"code":code}}),
                json!({"error":{"code":code,"class":"transient"}}),
            ] {
                let error = classify_error_value(&wire);
                assert_eq!(error.class, class);
                assert!(!error.retryable());
                assert!(!error.is_transport());
                assert!(!error.to_string().contains("do not log vault material"));
            }
        }
    }

    #[test]
    fn route_open_body_carries_prefrontal_routing_as_consumer_id() {
        let body = route_open_body_with_nonce(
            Path::new("/probe/routing"),
            "prefrontal-routing",
            "routing-nonce-under-test",
        );

        assert_eq!(
            body.pointer("/consumer_identity/module_id")
                .and_then(Value::as_str),
            Some("prefrontal-routing")
        );
        assert_eq!(
            body.pointer("/identity/harness").and_then(Value::as_str),
            Some("prefrontal-routing")
        );
    }

    /// An absent, blank or unreadable nonce stops the route open instead of
    /// letting it through unscoped.
    #[test]
    fn route_open_body_requires_the_launch_nonce_for_the_reserved_principal() {
        assert_eq!(
            required_launch_nonce(Ok(Some("nonce".to_string()))),
            "nonce"
        );
        for read in [
            Ok(None),
            Ok(Some("  ".to_string())),
            Err("descriptor 3 is not open".to_string()),
        ] {
            let result = std::panic::catch_unwind(|| required_launch_nonce(read.clone()));
            assert!(result.is_err(), "{read:?} must not yield a nonce");
        }
    }

    #[test]
    fn list_scoped_request_sends_no_enrollment_token() {
        assert_eq!(
            credential_list_scoped_request(),
            json!({ "method": "credential.list_scoped", "params": {} })
        );
    }

    /// The reply shape is claustrum's `ListScopedResult` / `ListScopedCredential`
    /// serialization (credentials-module `read_surface.rs`): optional fields are
    /// omitted when absent, and the id is `id`, not `credential_id`. It is built
    /// from that struct, not captured from a live vault, because no principal of
    /// this repository yet holds a grant that lists Claude rows.
    #[test]
    fn list_scoped_reply_decodes_identity_rows_grants_and_view() {
        let listing = decode_list_scoped_reply(json!({
            "result": {
                "credentials": [
                    {
                        "id": "oauth:anthropic:yiyi",
                        "categories": ["anthropic-native", "llm-provider"],
                        "type": "oauth",
                        "serves": ["anthropic"],
                        "refresh_adapter": "anthropic",
                        "state": "active",
                        "record_version": 227,
                        "operations": ["list"],
                        "account_id": "acct-1",
                        "email": "a@example.test"
                    },
                    {
                        "id": "apikey:artificial-analysis",
                        "categories": [],
                        "type": "apikey",
                        "serves": [],
                        "state": "active",
                        "record_version": 1,
                        "operations": ["read"]
                    }
                ],
                "grants": 1,
                "grant_tuples": [
                    {"selector_kind": "category", "selector": "anthropic-native", "operation": "list"}
                ],
                "view": "digest"
            }
        }))
        .expect("listing decodes");
        assert_eq!(listing.view, "digest");
        assert_eq!(listing.credentials.len(), 2);
        let claude = &listing.credentials[0];
        assert_eq!(claude.id, "oauth:anthropic:yiyi");
        assert_eq!(claude.refresh_adapter.as_deref(), Some("anthropic"));
        assert_eq!(claude.account_id.as_deref(), Some("acct-1"));
        assert_eq!(claude.record_version, 227);
        assert_eq!(listing.credentials[1].account_id, None);
        assert_eq!(listing.credentials[1].refresh_adapter, None);
        assert_eq!(
            listing.grant_tuples,
            vec![ListedGrant {
                selector_kind: "category".into(),
                selector: "anthropic-native".into(),
                operation: "list".into(),
            }]
        );
    }

    #[test]
    fn list_scoped_reply_without_view_is_invalid_and_unreadable_rows_are_local() {
        let no_view = decode_list_scoped_reply(json!({ "result": { "credentials": [] } }))
            .expect_err("no view");
        assert_eq!(no_view.class, CredentialErrorClass::InvalidResponse);
        let no_id = decode_list_scoped_reply(json!({
            "result": { "credentials": [{ "state": "active" }], "view": "v" }
        }))
        .expect("row without id does not reject the listing");
        assert!(no_id.credentials.is_empty());
        assert_eq!(
            no_id.undecodable_credentials,
            ["row 0: id is not a non-empty string"]
        );
    }
}
