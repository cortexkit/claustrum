//! The typed vault record.
//!
//! A [`VaultRecord`] is the vault's INTERNAL, typed view of one credential: enough
//! structure for the vault to reason about freshness and refresh. The consumer
//! never sees this type — a `get` returns only the opaque `payload` bytes. The
//! whole record is encrypted at rest as a single unit, so none of the internal
//! fields (the OAuth tokens, the source, the adapter name) leak to a read.
//!
//! ## Plaintext vs encrypted
//!
//! Two fields are kept ALSO as plaintext columns beside the ciphertext, because
//! the store must read them without decrypting:
//! - `record_version` — the monotonic version, bumped on every write/refresh. It
//!   is bound into the cipher envelope's authenticated data (anti-rollback), so the
//!   plaintext column and the ciphertext are always written together in one fenced
//!   transaction; a read uses it to build the decrypt binding and to power the
//!   consumer's `record_version`-keyed cache.
//! - the key fingerprint — so a master-key rotation scan can find records under the
//!   old key without decrypting every row.
//!
//! Everything else here is part of the encrypted plaintext.

use serde::{Deserialize, Serialize};

use crate::oauth::OAuthCredential;

/// The current schema version of the encrypted record body. Bumped only when the
/// record's PLAINTEXT structure changes in a way a decoder must branch on; it is
/// independent of the cipher envelope's `cipher_version`.
pub const RECORD_SCHEMA_VERSION: u32 = 1;

/// What kind of credential a record holds. Drives whether refresh applies and how
/// the payload is interpreted by its consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// An OAuth credential with refreshable tokens (`oauth` is populated).
    Oauth,
    /// A static API key (no refresh).
    ApiKey,
    /// A database connection string.
    Dsn,
    /// Opaque bytes with no vault-understood structure (no refresh).
    Opaque,
}

/// The vault's typed, at-rest view of one credential. Encrypted as one unit; only
/// `payload` is ever returned to a consumer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultRecord {
    /// Schema version of this record body (see [`RECORD_SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// What kind of credential this is.
    pub kind: CredentialKind,
    /// Where the credential was acquired from: `opencode` | `pi` | `antigravity` |
    /// `operator`. Provenance for audit and import reconciliation.
    pub source: String,
    /// Monotonic version, bumped on every write/refresh. Mirrored to a plaintext
    /// column and bound into the cipher AAD (see the module docs).
    pub record_version: u64,
    /// Access-token / credential expiry as a Unix timestamp in milliseconds, when
    /// known. Drives refresh-on-`get`.
    pub expires_at_ms: Option<i64>,
    /// Names the bounded refresh adapter to use (e.g. `anthropic`), when this
    /// credential is refreshable. `None` for non-refreshable kinds.
    pub refresh_adapter: Option<String>,
    /// The canonical OAuth credential, present when `kind == Oauth`.
    pub oauth: Option<OAuthCredential>,
    /// The opaque bytes returned to a consumer verbatim by a `get`. For an OAuth
    /// credential this is typically the serialized form the consumer expects (e.g.
    /// the access token / an auth header value); the vault does not interpret it.
    pub payload: Vec<u8>,
}

impl VaultRecord {
    /// Construct an OAuth record at version 1 from a canonical credential and the
    /// opaque payload a consumer should receive. `expires_at_ms` is taken from the
    /// credential so freshness logic has it without decrypting `oauth`.
    pub fn new_oauth(
        source: impl Into<String>,
        refresh_adapter: impl Into<String>,
        oauth: OAuthCredential,
        payload: Vec<u8>,
    ) -> Self {
        let expires_at_ms = oauth.expires_at_ms;
        VaultRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            kind: CredentialKind::Oauth,
            source: source.into(),
            record_version: 1,
            expires_at_ms,
            refresh_adapter: Some(refresh_adapter.into()),
            oauth: Some(oauth),
            payload,
        }
    }

    /// Construct a static (non-refreshable) record at version 1: an API key, DSN,
    /// or opaque blob. No OAuth, no refresh adapter.
    pub fn new_static(
        kind: CredentialKind,
        source: impl Into<String>,
        payload: Vec<u8>,
        expires_at_ms: Option<i64>,
    ) -> Self {
        debug_assert!(
            !matches!(kind, CredentialKind::Oauth),
            "new_static is for non-oauth kinds; use new_oauth for oauth"
        );
        VaultRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            kind,
            source: source.into(),
            record_version: 1,
            expires_at_ms,
            refresh_adapter: None,
            oauth: None,
            payload,
        }
    }

    /// Whether this record's credential is refreshable (OAuth with an adapter).
    pub fn is_refreshable(&self) -> bool {
        self.kind == CredentialKind::Oauth && self.refresh_adapter.is_some() && self.oauth.is_some()
    }

    /// Serialize the record body to the bytes that get encrypted. JSON is used for
    /// forward-compatible, self-describing field evolution under `schema_version`.
    pub fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Decode a record body from decrypted plaintext bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oauth_cred() -> OAuthCredential {
        OAuthCredential {
            access_token: "a".into(),
            refresh_token: "r".into(),
            expires_at_ms: Some(123),
            token_url: "https://t.test/token".into(),
            client_id: Some("c".into()),
            scopes: vec![],
        }
    }

    #[test]
    fn oauth_record_round_trips_and_is_refreshable() {
        let r = VaultRecord::new_oauth("opencode", "anthropic", oauth_cred(), b"payload".to_vec());
        assert_eq!(r.schema_version, RECORD_SCHEMA_VERSION);
        assert_eq!(r.record_version, 1);
        assert_eq!(r.expires_at_ms, Some(123), "expiry mirrored from oauth");
        assert!(r.is_refreshable());
        let bytes = r.encode().unwrap();
        let back = VaultRecord::decode(&bytes).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn static_record_is_not_refreshable() {
        let r =
            VaultRecord::new_static(CredentialKind::ApiKey, "operator", b"sk-123".to_vec(), None);
        assert!(!r.is_refreshable());
        assert!(r.oauth.is_none());
        assert!(r.refresh_adapter.is_none());
        let back = VaultRecord::decode(&r.encode().unwrap()).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn kind_serializes_snake_case() {
        let json = serde_json::to_string(&CredentialKind::ApiKey).unwrap();
        assert_eq!(json, "\"api_key\"");
    }
}
