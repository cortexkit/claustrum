//! Credential-id scheme parsing and method → refresh-adapter resolution.
//!
//! A credential id names WHAT a consumer wants. The v1 scheme is
//! `<method>:<provider>[:<account>]` (e.g. `oauth:anthropic`, `apikey:deepseek`,
//! `antigravity:google`, `apikey:openai:work`). A provider can hold several
//! credentials (different methods, and eventually different accounts), each its own
//! record + handle.
//!
//! The refresh adapter a record uses is NOT derivable by naive id-suffix parsing:
//! `oauth:anthropic` wants adapter `anthropic` (the provider segment), but
//! `antigravity:google` wants adapter `antigravity` (the method segment), and
//! `apikey:*` wants NO adapter (a static record). So the adapter is resolved from the
//! METHOD here and stored explicitly on the record; the engine then selects by that
//! stored name. The id is never re-parsed for adapter selection after import.
//!
//! Legacy compatibility: an id whose first segment is NOT a known method is treated
//! as the parked multi-account form `<provider>[:<account>]`, with the provider's
//! default method (oauth), so old ids do not misroute.

/// An auth method in the credential-id scheme. A method selects the credential KIND
/// (oauth vs static api-key) and, for oauth methods, the refresh adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// Provider-native OAuth (refreshed by the provider-named adapter).
    Oauth,
    /// A static API key (no refresh, `CredentialKind::ApiKey`).
    ApiKey,
    /// Google Code-Assist OAuth (the `antigravity` adapter).
    Antigravity,
    /// OpenAI ChatGPT-subscription OAuth. Refreshed by the `openai` adapter (same
    /// token endpoint); the distinct ChatGPT *wire family* is a consumer concern, not
    /// a separate refresh adapter.
    Chatgpt,
    /// GitHub Copilot OAuth backed by a durable GitHub grant.
    Copilot,
}

impl AuthMethod {
    /// Parse a leading id segment as a known method, or `None` if it is not one (so
    /// the id is treated as the legacy provider-first form).
    pub fn from_segment(seg: &str) -> Option<Self> {
        match seg {
            "oauth" => Some(AuthMethod::Oauth),
            "apikey" => Some(AuthMethod::ApiKey),
            "antigravity" => Some(AuthMethod::Antigravity),
            "chatgpt" => Some(AuthMethod::Chatgpt),
            "copilot" => Some(AuthMethod::Copilot),
            _ => None,
        }
    }

    /// The stable string form.
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthMethod::Oauth => "oauth",
            AuthMethod::ApiKey => "apikey",
            AuthMethod::Antigravity => "antigravity",
            AuthMethod::Chatgpt => "chatgpt",
            AuthMethod::Copilot => "copilot",
        }
    }

    /// Whether this method's credential is a static (non-refreshable) api-key.
    pub fn is_api_key(&self) -> bool {
        matches!(self, AuthMethod::ApiKey)
    }
}

/// A parsed credential id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCredentialId {
    /// The method, or `None` for a legacy provider-first id (default = oauth).
    pub method: Option<AuthMethod>,
    /// The provider segment.
    pub provider: String,
    /// The optional account segment (multi-account; forward-compat).
    pub account: Option<String>,
}

/// Parse a credential id into `(method, provider, account)`. If the FIRST segment is
/// a known method, it is the new `<method>:<provider>[:<account>]` scheme; otherwise
/// it is the legacy `<provider>[:<account>]` form (method defaults to oauth).
pub fn parse_credential_id(id: &str) -> ParsedCredentialId {
    let segs: Vec<&str> = id.split(':').collect();
    match AuthMethod::from_segment(segs[0]) {
        Some(method) => ParsedCredentialId {
            method: Some(method),
            provider: segs.get(1).copied().unwrap_or("").to_string(),
            account: segs.get(2).filter(|s| !s.is_empty()).map(|s| s.to_string()),
        },
        None => ParsedCredentialId {
            method: None,
            provider: segs[0].to_string(),
            account: segs.get(1).filter(|s| !s.is_empty()).map(|s| s.to_string()),
        },
    }
}

/// The refresh-adapter name to STORE for a credential, given its method and provider,
/// or `None` for a static api-key record (no adapter, no refresh).
///
/// # Retirement consequence of returning `None`
///
/// A refreshable record retires itself: when the provider rejects its refresh token the
/// exchange returns `invalid_grant`, and the engine flips the record to `needs_reauth`
/// on the spot. No consumer cooperation is involved.
///
/// A static record never enters that machinery, and the effect is wider than "no refresh":
/// EVERY automatic path to `needs_reauth` hangs off the refresh/reconciliation machinery,
/// so a static record cannot reach any of them. A revoked-at-the-provider api key stays
/// `active` in the vault and continues to be served.
///
/// What DOES still apply, and what does not:
/// - The read path quarantines a static record as `corrupt` if it fails to decrypt/decode,
///   or if it decodes to a zero-byte payload. That is integrity, not authentication — it
///   catches a mangled record, never a well-formed key the provider has revoked.
/// - The only automatic path to `needs_reauth` is a consumer calling
///   `credential.report_auth_failure` after the provider rejects the key. Consumers send it
///   fire-and-forget, so a consumer that never sends it leaves a dead key served until a
///   human runs `ck auth logout` or `login --replace`.
///
/// This is accepted rather than overlooked: detecting a revoked static key without a
/// consumer signal would mean the vault periodically spending the credential against the
/// provider to see if it still works, which is a worse property than serving a key whose
/// holder has not yet complained. Any future credential class without a refresh adapter
/// inherits this shape by construction.
///
/// This is the method → adapter table that replaces id-suffix parsing:
/// - oauth (or legacy) → the provider-named adapter (`anthropic`/`openai`/`xai`/`google`)
/// - antigravity → `antigravity`
/// - chatgpt → `openai` (refreshed via the openai token endpoint)
/// - apikey → `None` (static)
pub fn default_refresh_adapter(method: Option<AuthMethod>, provider: &str) -> Option<String> {
    match method {
        None | Some(AuthMethod::Oauth) => Some(provider.to_string()),
        Some(AuthMethod::Antigravity) => Some("antigravity".to_string()),
        Some(AuthMethod::Chatgpt) => Some("openai".to_string()),
        Some(AuthMethod::Copilot) => Some("github-copilot".to_string()),
        Some(AuthMethod::ApiKey) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_new_scheme_methods() {
        let p = parse_credential_id("oauth:anthropic");
        assert_eq!(p.method, Some(AuthMethod::Oauth));
        assert_eq!(p.provider, "anthropic");
        assert_eq!(p.account, None);

        let a = parse_credential_id("antigravity:google");
        assert_eq!(a.method, Some(AuthMethod::Antigravity));
        assert_eq!(a.provider, "google");

        let c = parse_credential_id("copilot:github");
        assert_eq!(c.method, Some(AuthMethod::Copilot));
        assert_eq!(c.provider, "github");

        let k = parse_credential_id("apikey:openai:work");
        assert_eq!(k.method, Some(AuthMethod::ApiKey));
        assert_eq!(k.provider, "openai");
        assert_eq!(k.account.as_deref(), Some("work"));
    }

    #[test]
    fn parses_legacy_provider_first() {
        // First segment is NOT a known method → legacy <provider>[:<account>].
        let p = parse_credential_id("anthropic:personal");
        assert_eq!(p.method, None);
        assert_eq!(p.provider, "anthropic");
        assert_eq!(p.account.as_deref(), Some("personal"));

        let bare = parse_credential_id("deepseek");
        assert_eq!(bare.method, None);
        assert_eq!(bare.provider, "deepseek");
        assert_eq!(bare.account, None);
    }

    #[test]
    fn adapter_resolution_is_method_aware_not_positional() {
        // The load-bearing cases that no single id-segment rule covers:
        assert_eq!(
            default_refresh_adapter(Some(AuthMethod::Oauth), "anthropic"),
            Some("anthropic".to_string()),
            "oauth → provider-named adapter (2nd segment)"
        );
        assert_eq!(
            default_refresh_adapter(Some(AuthMethod::Antigravity), "google"),
            Some("antigravity".to_string()),
            "antigravity → the method-named adapter (1st segment), NOT google"
        );
        assert_eq!(
            default_refresh_adapter(Some(AuthMethod::Chatgpt), "openai"),
            Some("openai".to_string()),
            "chatgpt refreshes via the openai adapter"
        );
        assert_eq!(
            default_refresh_adapter(Some(AuthMethod::Copilot), "github"),
            Some("github-copilot".to_string()),
            "copilot → GitHub Copilot bearer exchange"
        );
        assert_eq!(
            default_refresh_adapter(Some(AuthMethod::ApiKey), "deepseek"),
            None,
            "apikey → static, no adapter"
        );
        assert_eq!(
            default_refresh_adapter(None, "anthropic"),
            Some("anthropic".to_string()),
            "legacy → provider-named oauth adapter"
        );
    }
}
