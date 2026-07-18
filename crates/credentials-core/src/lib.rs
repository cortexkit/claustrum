//! Credential custody logic for the cortexkit-credentials subc module.
//!
//! This crate holds the format/provider-specific weight of the credential vault
//! (the "Acquisition + Custody" side of the thin-core boundary): the typed
//! `VaultRecord`, the canonical `OAuthCredential`, the value-level encryption
//! envelope, the bounded per-provider refresh adapters, the crash-safe refresh
//! state machine, and master-key resolution. It is wire-agnostic — it never
//! speaks the subc protocol; `credentials-module` is the thin binary that does.
//!
//! See docs/cortexkit-credentials-contract.md for the security contract and
//! docs/charter.md for the build plan. Built behind a security-conformance suite
//! (kill -9 mid-refresh, lease-handover mid-write, fail-closed matrix, envelope
//! fuzz) that is a ship gate, not a nice-to-have.

// Implemented so far: the credential vault's at-rest encryption (the `envelope`
// module) and master-key custody (`key`, `resolver`). Not yet present in this
// crate: the typed VaultRecord, the canonical OAuthCredential, the bounded
// refresh adapters, the crash-safe refresh state machine, and the encrypted
// store.

pub mod admin_auth;
pub mod admin_ops;
pub mod audit;
pub mod contract;
pub mod credential_id;
pub mod engine;
#[cfg(test)]
mod engine_tests;
pub mod envelope;
pub mod google_login;
pub mod health;
pub mod http;
pub mod key;
pub mod oauth;
pub mod oauth_login;
pub mod record;
pub mod refresh_adapters;
pub mod resolver;
pub mod store;

pub use admin_auth::{
    generate_admin_nonce, vault_id_for_canonical_dir, AdminMacKey, TranscriptParts,
    ADMIN_NONCE_LEN, ADMIN_TAG_LEN, VAULT_ID_LEN,
};
pub use admin_ops::{AdminAuditOp, AdminOpBody, StoreMode, ADMIN_OP_SCHEMA_V1};
pub use audit::{AlarmReason, AuditEntry, AuditOp, AuditRecord};
pub use contract::{keychain_service_for, vault_id_for, MODULE_ID, STORAGE_NAMESPACE};
pub use credential_id::{
    default_refresh_adapter, parse_credential_id, AuthMethod, ParsedCredentialId,
};
pub use engine::{EngineError, ReauthReason, Reconciliation, RefreshEngine};
pub use envelope::{open, seal, EnvelopeError, RecordBinding};
pub use health::{VaultHealth, VaultHealthStatus};
pub use http::ReqwestTransport;
pub use key::{KeyId, MasterKey};
pub use oauth::OAuthCredential;
pub use record::{CredentialKind, VaultRecord, RECORD_SCHEMA_VERSION};
pub use refresh_adapters::anthropic::AnthropicAdapter;
pub use refresh_adapters::antigravity::AntigravityAdapter;
pub use refresh_adapters::google::GoogleAdapter;
pub use refresh_adapters::openai::OpenAiAdapter;
pub use refresh_adapters::xai::XaiAdapter;
pub use refresh_adapters::{
    HttpResponse, HttpTransport, RefreshAdapter, RefreshError, RefreshedTokens, ValidityOutcome,
};
pub use resolver::{
    bootstrap, resolve, KeySource, KeychainCli, MasterKeyError, MasterKeyStore, OperatorPathStore,
    ResolverConfig,
};
pub use store::{
    handle_hash, mint_handle, payload_hash, refresh_token_hash, EncryptedStore, MintedHandle,
    RecordMeta, RecordState, RefreshIntent, StoreOpError,
};
