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

pub mod engine;
#[cfg(test)]
mod engine_tests;
pub mod envelope;
pub mod key;
pub mod oauth;
pub mod record;
pub mod refresh_adapters;
pub mod resolver;
pub mod store;

pub use engine::{EngineError, ReauthReason, Reconciliation, RefreshEngine};
pub use envelope::{open, seal, EnvelopeError, RecordBinding};
pub use key::{KeyId, MasterKey};
pub use oauth::OAuthCredential;
pub use record::{CredentialKind, VaultRecord, RECORD_SCHEMA_VERSION};
pub use refresh_adapters::{
    HttpResponse, HttpTransport, RefreshAdapter, RefreshError, RefreshedTokens, ValidityOutcome,
};
pub use resolver::{
    bootstrap, resolve, KeySource, KeychainCli, MasterKeyError, MasterKeyStore, OperatorPathStore,
    ResolverConfig,
};
pub use store::{
    payload_hash, refresh_token_hash, EncryptedStore, RecordMeta, RecordState, RefreshIntent,
    StoreOpError,
};
