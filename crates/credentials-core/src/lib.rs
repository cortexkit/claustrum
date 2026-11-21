//! Credential custody logic for the claustrum subc module (the credential vault).
//!
//! This crate holds the custody logic of the credential vault: the crash-safe
//! refresh state machine and master-key resolution. The bounded per-provider
//! refresh adapters are re-exported from `claustrum-providers`.
//! The typed `VaultRecord`, canonical `OAuthCredential`,
//! and value-level encryption envelope are re-exported from `claustrum-model`.
//! It is wire-agnostic — it never speaks the subc protocol;
//! `credentials-module` is the thin binary that does.
//!
//! See docs/architecture.md for how the parts fit together and the invariants they
//! keep, and SECURITY.md for the threat model. Built behind a security-conformance suite
//! (kill -9 mid-refresh, lease-handover mid-write, fail-closed matrix) that is a ship
//! gate, not a nice-to-have. Envelope decoding is covered by the never-panic proptest
//! in `envelope.rs`, not by a separate fuzz target.
#![forbid(unsafe_code)]

pub mod admin_auth;
pub mod admin_ops;
pub mod agent_policy;
pub use claustrum_model::agent_secret;
pub use claustrum_providers::apns;
pub use claustrum_providers::apns_submit;
pub mod audit;
pub use claustrum_providers::bedrock;
pub mod broker_action;
pub use claustrum_providers::catalog;
pub mod contract;
pub use claustrum_model::credential_id;
pub mod deposit_cookie;
pub use claustrum_providers::device_flow;
pub mod display_name;
pub mod engine;
#[cfg(test)]
mod engine_tests;
pub mod enrollment;
pub use claustrum_model::envelope;
pub mod federation;
pub mod fleet;
pub use claustrum_model::fusiform_providers;
pub mod gateway;
pub mod gh_manifest;
pub use claustrum_providers::google_login;
pub mod health;
pub mod hub_counters;
pub use claustrum_providers::http;
pub mod kem;
pub use claustrum_model::key;
pub use claustrum_providers::list_auth_method;
pub mod login_sharing;
pub use claustrum_model::oauth;
pub use claustrum_providers::oauth_login;
pub use claustrum_providers::plan_detection;
pub mod plan_tier;
mod process_hardening;
pub mod provider_ids;
pub use claustrum_model::record;
pub use claustrum_providers::refresh_adapters;
pub mod resolver;
pub use claustrum_model::secret;
pub mod signing;
pub mod store;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod usable;

pub use process_hardening::harden_process;

pub use admin_auth::{
    generate_admin_nonce, vault_id_for_canonical_dir, AdminMacKey, TranscriptParts,
    ADMIN_NONCE_LEN, ADMIN_TAG_LEN, VAULT_ID_LEN,
};
pub use admin_ops::{AdminAuditOp, AdminOpBody, StoreMode, ADMIN_OP_SCHEMA_V1, ADMIN_OP_SCHEMA_V2};
pub use audit::{AlarmReason, AuditEntry, AuditOp, AuditRecord, AuthEventKind, ReporterSource};
pub use catalog::{
    category_defaults, credential_type, login_provider, serves_for, ApiKeyProvider, AuthDescriptor,
    AuthScheme, CredentialCategory, DeviceKind, ExchangeWire, InvalidKeyEvidence, KeyValidation,
    LoginProvider, ModelVendor, API_KEY_PROVIDERS, LOGIN_PROVIDERS,
};
pub use contract::{keychain_service_for, vault_id_for, MODULE_ID, STORAGE_NAMESPACE};
pub use credential_id::{
    default_refresh_adapter, parse_credential_id, AuthMethod, ParsedCredentialId,
};
pub use device_flow::{
    run_device_flow, run_openai_device_flow, DeviceAuthorization, DeviceBodyEncoding,
    DeviceFlowConfig, DeviceTokens,
};
pub use engine::{EngineError, ReauthReason, Reconciliation, RefreshEngine};
pub use enrollment::{
    constant_time_hash_eq, decode_lower_hex_32, enrollment_secret_hash, is_lower_hex_32,
    valid_enrollment_name, EnrollmentDisposition, EnrollmentError, EnrollmentPoll,
    EnrollmentProposal, EnrollmentRefusal, EnrollmentRotation, ENROLLMENT_LIVE_LIMIT,
    ENROLLMENT_PENDING_TTL_MS,
};
pub use envelope::{open, seal, EnvelopeError, RecordBinding};
pub use gateway::{
    gateway_provider_vendor, gateway_settings_digest, validate_gateway_settings, GatewayAuth,
    GatewayFixedRule, GatewayHeader, GatewaySettings, GatewaySettingsRule, ValidatedGateway,
};
pub use health::{VaultHealth, VaultHealthStatus};
pub use http::ReqwestTransport;
pub use key::{KeyId, MasterKey};
pub use list_auth_method::{list_auth_method, list_auth_method_with_gateway, ListAuthMethod};
pub use oauth::OAuthCredential;
pub use provider_ids::{
    check_provider_ids, ProviderIdRule, MAX_PROVIDER_IDS_PER_CREDENTIAL, MAX_PROVIDER_ID_LEN,
    MIN_PROVIDER_ID_LEN,
};
pub use record::{CredentialKind, VaultRecord, RECORD_SCHEMA_VERSION};

/// Non-secret fields opened for the operator's connectors projection, including
/// lifecycle states for which ordinary credential reads must not return material.
#[derive(Clone, Debug)]
pub struct ConnectorRecordMetadata {
    pub id: String,
    pub incarnation: String,
    pub state: record::RecordState,
    pub categories: Vec<String>,
    pub kind: &'static str,
    pub identity: record::RecordIdentity,
    pub detected_plan: Option<plan_detection::DetectedPlan>,
    pub plan_tier: Option<String>,
}

pub struct ConnectorRow<T> {
    pub record: T,
    pub permissions: Vec<String>,
    pub auth_reason: Option<String>,
    pub condition: Option<store::Condition>,
}

pub struct ConnectorInventory {
    pub local: Vec<ConnectorRow<ConnectorRecordMetadata>>,
    pub remote: Vec<ConnectorRow<federation::RemoteInventoryRow>>,
    pub computer: Option<String>,
}
pub use refresh_adapters::anthropic::AnthropicAdapter;
pub use refresh_adapters::antigravity::AntigravityAdapter;
pub use refresh_adapters::cursor::CursorAdapter;
pub use refresh_adapters::devin::DevinAdapter;
pub use refresh_adapters::digitalocean::DigitalOceanAdapter;
pub use refresh_adapters::github_app::GithubAppAdapter;
pub use refresh_adapters::github_copilot::GithubCopilotAdapter;
pub use refresh_adapters::google::GoogleAdapter;
pub use refresh_adapters::kimi::KimiAdapter;
pub use refresh_adapters::openai::OpenAiAdapter;
pub use refresh_adapters::snowflake::SnowflakeAdapter;
pub use refresh_adapters::xai::XaiAdapter;
pub use refresh_adapters::{
    HttpResponse, HttpTransport, RefreshAdapter, RefreshError, RefreshedTokens, ValidityOutcome,
};
pub use resolver::{
    bootstrap, resolve, CredentialManager, KeySource, KeychainCli, MasterKeyError, MasterKeyStore,
    OperatorPathStore, ResolverConfig, SecretService,
};
pub use store::{
    handle_hash, mint_handle, payload_hash, refresh_token_hash, DepositCookieOutcome,
    EncryptedStore, GrantOperation, MintedHandle, ReadGrant, RecordMeta, RecordState,
    RefreshIntent, ScopedCoverage, ScopedListRow, ScopedListSnapshot, ScopedReadRefusal,
    SelectorKind, SetCategoryMode, SetProvidersMode, StoreOpError, StoredGatewaySettings,
    GATEWAY_SETTINGS_SCHEMA_VERSION, PROVIDER_ID_SCHEMA_VERSION,
};
