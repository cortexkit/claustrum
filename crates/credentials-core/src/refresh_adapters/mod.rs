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
pub mod github_app;
pub mod github_copilot;
pub mod google;
pub mod kimi;
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
    /// THE DISPOSITION IS "UNSERVICEABLE UNTIL A HUMAN ACTS", not the OAuth error its
    /// name is borrowed from. Routing here latches `needs_reauth`, which is the correct
    /// destination for any cause a retry cannot fix.
    ///
    /// The obvious case is a provider rejecting the refresh (400 `invalid_grant`): the
    /// refresh token is dead. The non-obvious one, and the reason this doc is worded by
    /// disposition, is a GitHub App with no installation — the key is fine and the JWT
    /// authenticates, and it still cannot serve until an operator installs the App. That
    /// case was classified `Decode` (wire class `transient`) until 2026-08-27, so
    /// consumers doing the correct thing for a transient error retried forever, one App
    /// JWT mint per attempt.
    ///
    /// The test when adding a variant here: does a retry have any chance of succeeding
    /// without someone taking an action outside this process? If not, it belongs here
    /// whatever the provider called it.
    InvalidGrant(String),
    /// A transport/HTTP error reaching the provider (retryable).
    Transport(String),
    /// The provider returned a success status but an undecodable/again-shaped body
    /// (treated as a provider fault, not a dead token).
    Decode(String),
    /// The provider returned an unexpected non-success status.
    Status(u16, String),
    // NOTE for anyone persisting or forwarding these: every variant's `String` is RAW
    // PROVIDER RESPONSE TEXT. An OAuth error body can echo submitted parameters, so
    // these strings are not safe to write to a plaintext column or a log. Use
    // [`RefreshError::variant_name`] and [`RefreshError::provider_status`], which carry
    // the diagnostic value without the payload.
}

impl RefreshError {
    /// The variant name alone, safe to persist.
    ///
    /// Exists so diagnostics can record WHICH failure occurred without touching the
    /// attached provider text, which may echo submitted parameters.
    pub fn variant_name(&self) -> &'static str {
        match self {
            RefreshError::InvalidGrant(_) => "invalid_grant",
            RefreshError::Transport(_) => "transport",
            RefreshError::Decode(_) => "decode",
            RefreshError::Status(_, _) => "status",
        }
    }

    /// The provider's HTTP status, when the failure carried one.
    pub fn provider_status(&self) -> Option<u16> {
        match self {
            RefreshError::Status(status, _) => Some(*status),
            _ => None,
        }
    }
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

    /// GET an endpoint with caller-supplied headers. The default keeps existing
    /// transports source-compatible; adapters that need GET override it.
    async fn get(
        &self,
        _url: &str,
        _headers: &[(&str, &str)],
    ) -> Result<HttpResponse, RefreshError> {
        Err(RefreshError::Transport(
            "HTTP GET is unsupported by this transport".into(),
        ))
    }
}

/// A minimal HTTP response: status + body bytes (all an adapter needs to parse a
/// token endpoint's reply).
///
/// WHETHER AN ADAPTER CARRIES `body` INTO ITS ERROR VALUE IS A DECISION, NOT A STYLE
/// CHOICE, and it has to be made per adapter rather than once here.
///
/// Carrying it is usually right: a constant like "Cursor refresh failed" tells a
/// diagnosing operator nothing the status did not already say, and a sibling module lost
/// four hours on 2026-08-17 to a bare 403 whose body named the cause in one line the
/// moment it was allowed to reach a log.
///
/// BUT A TOKEN ENDPOINT'S ERROR BODY CAN ECHO THE PARAMETERS YOU SENT IT, including the
/// refresh token. That is why `AuthObservation::detail` is restricted to typed variant
/// names, and why an error value that reaches the wire or a plaintext column must not
/// carry a raw body. An error value that only reaches an operator's terminal can.
///
/// MEASURED 2026-08-17, so the state of this is known rather than assumed: `anthropic`,
/// `google`, `antigravity` and `github_app` carry bodies into errors that stay local.
/// `cursor`, `github_copilot`, `kimi` and `snowflake` substitute a constant and discard
/// the vendor's explanation -- omissions rather than decisions, left alone deliberately
/// because the safe fix is a bounded redacted detail on the operator-only path, and a
/// redactor for arbitrary provider bodies is how a token reaches a log.
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

#[cfg(test)]
mod endpoint_pins {
    //! Every provider endpoint a refresh can reach, pinned against a LITERAL.
    //!
    //! Each adapter's own tests assert the endpoint by comparing the request's url to
    //! the same `TOKEN_URL` constant the fixture put on the credential, so both sides
    //! move together and the value is invisible. Measured: repointing Anthropic's
    //! `TOKEN_URL` at another host left all 238 core tests and all 8 e2e arms green.
    //!
    //! WHAT THAT COSTS IS NOT A FAILED TEST. A refresh posts a live refresh token in
    //! the request body, so a wrong host RECEIVES A WORKING CREDENTIAL. The symptom is
    //! then indistinguishable from a dead login: the exchange fails, the account reads
    //! as needing re-auth, and the operator's remedy -- log in again -- neither fixes
    //! it nor reveals the cause.
    //!
    //! These constants are the fallback for a record carrying no `token_url`, which is
    //! every credential taken through the import path (`import_*` stores an empty
    //! `token_url`), so the fallback is live rather than vestigial.
    //!
    //! A literal here looks redundant beside the constant it duplicates. That is the
    //! point: a relationship and a value are different claims, and only the value
    //! survives the constant changing. Editing an endpoint must mean editing this test
    //! too -- the deliberate step this exists to force.

    #[test]
    fn refresh_token_endpoints_are_the_expected_hosts() {
        assert_eq!(
            super::anthropic::TOKEN_URL,
            "https://platform.claude.com/v1/oauth/token"
        );
        assert_eq!(
            super::anthropic::LOGIN_TOKEN_URL,
            "https://api.anthropic.com/v1/oauth/token"
        );
        assert_eq!(
            super::google::TOKEN_URL,
            "https://oauth2.googleapis.com/token"
        );
        assert_eq!(
            super::antigravity::TOKEN_URL,
            "https://oauth2.googleapis.com/token"
        );
        assert_eq!(
            super::openai::TOKEN_URL,
            "https://auth.openai.com/oauth/token"
        );
        assert_eq!(super::xai::TOKEN_URL, "https://auth.x.ai/oauth2/token");
        assert_eq!(
            super::github_app::INSTALLATIONS_URL,
            "https://api.github.com/app/installations"
        );
        assert_eq!(
            super::github_app::ACCESS_TOKENS_URL_PREFIX,
            "https://api.github.com/app/installations/"
        );
        assert_eq!(
            super::xai::DEVICE_TOKEN_URL,
            "https://auth.x.ai/oauth2/token"
        );
    }
}

#[cfg(test)]
mod documented_count_tests {
    /// The adapter count stated in the contract and the charter matches the tree.
    ///
    /// Both documents said "v1 adapters are bounded to the 4 providers llm-runner
    /// uses" long after the login expansion took it to 11, and the contract adds
    /// "adding an adapter is a contract amendment" -- so that sentence is an
    /// AMENDMENT LEDGER, not decoration, and it had silently stopped counting.
    ///
    /// A corrected sentence rots again at adapter 12. This checks the number against
    /// the thing it describes, so whoever adds the next one updates the docs rather
    /// than discovering the drift a year later. A peer found the identical shape the
    /// same day -- a matrix claiming 37 providers against a registry that builds 36,
    /// the count taken from a grep of `Box::new` rather than from the registry.
    ///
    /// Counts MODULES rather than trait impls deliberately: the population the docs
    /// describe is "one adapter per provider we can log in to", and a file is what
    /// gets added. `fixture.rs` is the test double and is excluded by name.
    #[test]
    fn the_documented_adapter_count_matches_the_tree() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/refresh_adapters");
        let mut adapters: Vec<String> = std::fs::read_dir(&dir)
            .expect("read refresh_adapters/")
            .filter_map(|e| {
                let name = e.ok()?.file_name().to_string_lossy().to_string();
                let stem = name.strip_suffix(".rs")?.to_string();
                (stem != "mod" && stem != "fixture").then_some(stem)
            })
            .collect();
        adapters.sort();
        let actual = adapters.len();

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root");
        for doc in ["docs/cortexkit-credentials-contract.md", "docs/charter.md"] {
            let text = std::fs::read_to_string(root.join(doc))
                .unwrap_or_else(|e| panic!("read {doc}: {e}"));
            // The sentence names the count immediately before the word "adapters".
            let stated = text
                .split_whitespace()
                .collect::<Vec<_>>()
                .windows(2)
                .find_map(|w| {
                    w[1].starts_with("adapters")
                        .then(|| w[0].trim_matches(|c: char| !c.is_ascii_digit()))
                        .filter(|n| !n.is_empty())
                        .and_then(|n| n.parse::<usize>().ok())
                })
                .unwrap_or_else(|| {
                    panic!("{doc} states no adapter count; the ledger sentence is gone")
                });
            assert_eq!(
                stated, actual,
                "{doc} says {stated} adapters, the tree has {actual}: {adapters:?}.\n\
                 Adding an adapter is a contract amendment -- update the sentence, \
                 not this test."
            );
        }
    }
}
