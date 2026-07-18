//! Bounded per-provider OAuth refresh adapters.
//!
//! An adapter knows how to exchange a canonical [`OAuthCredential`]'s refresh
//! token for a new access (and possibly rotated refresh) token at the provider's
//! token endpoint. Adapters operate ONLY on the canonical type — never on raw
//! provider JSON — so per-provider format knowledge stays at the import boundary,
//! not in the refresh path.
//!
//! v1 is bounded to the providers llm-runner uses (anthropic first; openai,
//! google, xai-style follow). Adding an adapter is a deliberate, reviewed change
//! (a contract amendment), not an open extension point.
//!
//! ## The recovery seam (never rotates)
//!
//! [`RefreshAdapter::refresh`] ROTATES — it is the in-flight refresh path and is
//! NEVER called during crash recovery. [`RefreshAdapter::non_mutating_check`] is a
//! read-only validity probe (e.g. RFC 7662 token introspection of the refresh
//! token) used ONLY by startup reconciliation to decide whether a dangling intent
//! can be cleared without forcing a re-login. It defaults to `None`: the v1
//! providers do not expose a usable non-mutating refresh-validity endpoint, so we
//! do NOT invent one — a dangling intent for them resolves to `needs_reauth` (the
//! accepted, rare re-login residual). The seam exists for correctness and for
//! future providers that do expose introspection.

use async_trait::async_trait;

use crate::oauth::OAuthCredential;

pub mod anthropic;
pub mod antigravity;
pub mod cursor;
pub mod devin;
pub mod digitalocean;
pub mod google;
pub mod openai;
pub mod snowflake;
pub mod xai;

#[cfg(test)]
pub(crate) mod fixture;

/// The result of a successful token refresh: the new tokens to commit. The
/// provider may or may not rotate the refresh token (RFC 9700 providers do); the
/// adapter returns whatever the provider issued, and the engine commits it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshedTokens {
    /// The new access token.
    pub access_token: String,
    /// The refresh token to store going forward. For a rotating provider this is
    /// the NEW refresh token; for a non-rotating one the adapter echoes the
    /// existing refresh token so the stored credential stays complete.
    pub refresh_token: String,
    /// New access-token expiry (Unix ms), when the provider returns one.
    pub expires_at_ms: Option<i64>,
}

/// The outcome of a non-mutating validity check (the recovery probe).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidityOutcome {
    /// The stored refresh state is provably still valid — a dangling intent for
    /// this credential can be cleared WITHOUT a re-login.
    Valid,
    /// The stored refresh state is provably invalid (e.g. the refresh token was
    /// revoked / rotated away) — resolve to `needs_reauth`.
    Invalid,
}

/// A refresh adapter failure.
#[derive(Debug)]
pub enum RefreshError {
    /// The provider rejected the refresh (e.g. 400 `invalid_grant`): the refresh
    /// token is dead → the credential needs re-auth.
    InvalidGrant(String),
    /// A transport/HTTP error reaching the provider (retryable).
    Transport(String),
    /// The provider returned a success status but an undecodable/again-shaped body
    /// (treated as a provider fault, not a dead token).
    Decode(String),
    /// The provider returned an unexpected non-success status.
    Status(u16, String),
}

impl std::fmt::Display for RefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefreshError::InvalidGrant(m) => write!(f, "refresh rejected (invalid_grant): {m}"),
            RefreshError::Transport(m) => write!(f, "refresh transport error: {m}"),
            RefreshError::Decode(m) => write!(f, "refresh response decode error: {m}"),
            RefreshError::Status(code, m) => write!(f, "refresh unexpected status {code}: {m}"),
        }
    }
}

impl std::error::Error for RefreshError {}

/// An HTTP transport the adapters POST through. Abstracted as a trait so the
/// conformance tests drive adapters against RECORDED fixtures (the fidelity rule —
/// never invent a provider response string) with no live network, while production
/// uses a real reqwest-backed implementation.
#[async_trait]
pub trait HttpTransport: Send + Sync {
    /// POST `body` (already-encoded form/JSON) to `url` with `headers`, returning
    /// the response status and body bytes. A transport-level failure is `Err`.
    async fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<HttpResponse, RefreshError>;
}

/// A minimal HTTP response: status + body bytes (all an adapter needs to parse a
/// token endpoint's reply).
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body bytes.
    pub body: Vec<u8>,
}

/// Minimal `application/x-www-form-urlencoded` encoder for the form-POST refresh
/// adapters (Google, xAI). Percent-encodes everything outside the unreserved set,
/// so OAuth token/secret values (which contain `/`, `+`, `=`) are escaped safely.
pub(crate) fn form_urlencode(pairs: &[(&str, &str)]) -> String {
    fn encode(s: &str, out: &mut String) {
        use std::fmt::Write;
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char)
                }
                b' ' => out.push('+'),
                _ => {
                    let _ = write!(out, "%{b:02X}");
                }
            }
        }
    }
    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        encode(k, &mut out);
        out.push('=');
        encode(v, &mut out);
    }
    out
}

/// A bounded per-provider OAuth refresh adapter (see the module docs).
#[async_trait]
pub trait RefreshAdapter: Send + Sync {
    /// The adapter's stable name (matches `VaultRecord::refresh_adapter`).
    fn name(&self) -> &str;

    /// Exchange the credential's refresh token for new tokens. ROTATES — never
    /// called during crash recovery.
    async fn refresh(
        &self,
        cred: &OAuthCredential,
        http: &dyn HttpTransport,
    ) -> Result<RefreshedTokens, RefreshError>;

    /// Read-only validity probe used ONLY by recovery (never rotates). `None` (the
    /// default) means this provider exposes no non-mutating check, so a dangling
    /// intent resolves to `needs_reauth`.
    async fn non_mutating_check(
        &self,
        _cred: &OAuthCredential,
        _http: &dyn HttpTransport,
    ) -> Option<Result<ValidityOutcome, RefreshError>> {
        None
    }
}
