//! The canonical OAuth credential.
//!
//! Every source format (opencode's `auth.json`, pi, antigravity) is parsed by its
//! importer into this ONE canonical shape, and the bounded refresh adapters
//! operate exclusively on it — never on raw provider JSON. That is what keeps
//! per-provider format knowledge at the import boundary instead of leaking it into
//! the refresh path: an adapter is handed a canonical credential and a token
//! endpoint, and it knows how to exchange a refresh token for a new access token.
//!
//! The access and refresh tokens are secrets. This type therefore has a redacted
//! `Debug` (it renders presence and non-secret metadata, never token bytes) and is
//! never logged in the clear. The whole [`VaultRecord`](crate::record::VaultRecord)
//! it lives in is encrypted at rest as one unit.

use serde::{Deserialize, Serialize};

/// A canonical OAuth credential: the provider-agnostic fields a refresh exchange
/// needs, plus the current tokens. Importers map each source format into this;
/// refresh adapters read and update it.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthCredential {
    /// The current access token (bearer credential handed to the provider API).
    /// Secret.
    pub access_token: String,
    /// The current refresh token, exchanged at `token_url` for a new access token.
    /// Secret. Rotated by the provider on refresh for providers that follow
    /// RFC 9700 refresh-token rotation.
    pub refresh_token: String,
    /// Access-token expiry as a Unix timestamp in milliseconds, if the source
    /// provides one. Used to decide when a `get` must trigger a refresh.
    pub expires_at_ms: Option<i64>,
    /// The provider's token endpoint — where a refresh exchange is POSTed. Stored
    /// per-credential (canonicalized at import) so the refresh path never hardcodes
    /// or re-derives provider URLs.
    pub token_url: String,
    /// The OAuth client id, when the provider's refresh grant requires one.
    pub client_id: Option<String>,
    /// The granted scopes, when the source records them (re-sent on refresh by
    /// providers that require it). Empty when not applicable.
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl OAuthCredential {
    /// Whether the access token is expired (or within `skew_ms` of expiring) at
    /// `now_ms`. A credential with no recorded expiry is treated as not-expired
    /// here (freshness is then driven by `report_auth_failure` / `min_ttl_ms`),
    /// so this never forces a refresh it cannot reason about.
    pub fn is_access_expired(&self, now_ms: i64, skew_ms: i64) -> bool {
        match self.expires_at_ms {
            Some(exp) => now_ms.saturating_add(skew_ms) >= exp,
            None => false,
        }
    }

    /// Parse a source format's raw JSON into the canonical credential. This is the
    /// import boundary: per-source field knowledge lives HERE, never in the refresh
    /// path. v1 sources share the `auth.json` shape `{ refresh, access, expires }`
    /// (epoch-ms expiry) that the opencode / pi / antigravity logins write; the
    /// `token_url` / `client_id` an adapter needs are NOT in that file (the adapter
    /// carries the provider defaults), so they are left empty here and the adapter
    /// fills them. Unknown sources are rejected rather than guessed.
    pub fn import(source: &str, raw_json: &[u8]) -> Result<Self, ImportError> {
        match source {
            "opencode" | "pi" | "antigravity" => Self::from_auth_json(raw_json),
            other => Err(ImportError::UnknownSource(other.to_string())),
        }
    }

    /// Parse the shared `auth.json` per-provider entry: `{ "refresh": ..., "access":
    /// ..., "expires": <epoch_ms> }`. `expires` is optional.
    fn from_auth_json(raw_json: &[u8]) -> Result<Self, ImportError> {
        #[derive(Deserialize)]
        struct AuthEntry {
            #[serde(default)]
            refresh: Option<String>,
            #[serde(default)]
            access: Option<String>,
            #[serde(default)]
            expires: Option<i64>,
        }
        let entry: AuthEntry =
            serde_json::from_slice(raw_json).map_err(|e| ImportError::Malformed(e.to_string()))?;
        let refresh_token = entry
            .refresh
            .filter(|s| !s.is_empty())
            .ok_or(ImportError::MissingField("refresh"))?;
        let access_token = entry.access.unwrap_or_default();
        Ok(OAuthCredential {
            access_token,
            refresh_token,
            expires_at_ms: entry.expires,
            // The adapter supplies the provider's token URL / client id; the import
            // file does not carry them.
            token_url: String::new(),
            client_id: None,
            scopes: Vec::new(),
        })
    }
}

/// A credential-import failure.
#[derive(Debug)]
pub enum ImportError {
    /// The source name is not one of the supported importers.
    UnknownSource(String),
    /// The source JSON did not decode.
    Malformed(String),
    /// A required field (a refresh token) was absent.
    MissingField(&'static str),
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::UnknownSource(s) => write!(f, "unknown import source '{s}'"),
            ImportError::Malformed(m) => write!(f, "malformed import json: {m}"),
            ImportError::MissingField(field) => {
                write!(f, "import missing required field '{field}'")
            }
        }
    }
}

impl std::error::Error for ImportError {}

impl std::fmt::Debug for OAuthCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render token bytes. Presence + non-secret metadata only.
        f.debug_struct("OAuthCredential")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("expires_at_ms", &self.expires_at_ms)
            .field("token_url", &self.token_url)
            .field("client_id", &self.client_id)
            .field("scopes", &self.scopes)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> OAuthCredential {
        OAuthCredential {
            access_token: "access-abc".into(),
            refresh_token: "refresh-xyz".into(),
            expires_at_ms: Some(1_000_000),
            token_url: "https://example.test/oauth/token".into(),
            client_id: Some("client-1".into()),
            scopes: vec!["a".into(), "b".into()],
        }
    }

    #[test]
    fn round_trips_through_json() {
        let c = sample();
        let json = serde_json::to_vec(&c).unwrap();
        let back: OAuthCredential = serde_json::from_slice(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn debug_redacts_tokens() {
        let rendered = format!("{:?}", sample());
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("access-abc"), "no access token in Debug");
        assert!(
            !rendered.contains("refresh-xyz"),
            "no refresh token in Debug"
        );
        // Non-secret metadata is fine to show.
        assert!(rendered.contains("example.test"));
    }

    #[test]
    fn imports_auth_json_shape() {
        let raw = br#"{"refresh":"r-tok","access":"a-tok","expires":1700000000000}"#;
        let c = OAuthCredential::import("opencode", raw).expect("import");
        assert_eq!(c.refresh_token, "r-tok");
        assert_eq!(c.access_token, "a-tok");
        assert_eq!(c.expires_at_ms, Some(1_700_000_000_000));
        // The adapter fills token_url/client_id; the import file does not carry them.
        assert!(c.token_url.is_empty());
        assert!(c.client_id.is_none());
    }

    #[test]
    fn import_rejects_unknown_source_and_missing_refresh() {
        assert!(matches!(
            OAuthCredential::import("nope", b"{}"),
            Err(ImportError::UnknownSource(_))
        ));
        assert!(matches!(
            OAuthCredential::import("opencode", br#"{"access":"a"}"#),
            Err(ImportError::MissingField("refresh"))
        ));
        assert!(matches!(
            OAuthCredential::import("opencode", b"not json"),
            Err(ImportError::Malformed(_))
        ));
    }

    #[test]
    fn expiry_uses_skew_and_treats_absent_as_fresh() {
        let mut c = sample();
        c.expires_at_ms = Some(1000);
        assert!(c.is_access_expired(1000, 0), "at expiry is expired");
        assert!(c.is_access_expired(900, 200), "within skew is expired");
        assert!(!c.is_access_expired(799, 200), "outside skew is fresh");
        c.expires_at_ms = None;
        assert!(!c.is_access_expired(i64::MAX, 0), "no expiry => not forced");
    }
}
