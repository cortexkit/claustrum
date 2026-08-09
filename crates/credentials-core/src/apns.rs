//! APNs provider tokens: mint the ES256 JWT that authorizes a push submission.
//!
//! This is the signing half only. It takes the `.p8` the vault holds as source of
//! record and produces the `authorization: bearer <jwt>` value APNs wants; it does
//! not submit, hold a connection, or know a device token. That split is deliberate
//! — the signer is pure and testable against Apple's published token shape, and the
//! submit path (which needs a network and a real device) sits above it.
//!
//! ## What APNs requires, and which parts are not negotiable
//!
//! - **ES256 only.** Apple accepts no other algorithm for token auth, so the key is
//!   always P-256 and the header always says `ES256`.
//! - **`kid` in the header, `iss` and `iat` in the claims.** `kid` is the 10-char
//!   key id, `iss` the 10-char team id. There is no `exp`: APNs bounds the token by
//!   `iat` age instead, which is why [`ProviderToken::is_stale_at`] exists rather
//!   than an expiry field.
//! - **Raw `r||s` signatures, not DER.** This is the one that silently produces a
//!   valid-but-rejected token: `p256`'s `Signature::to_der()` yields a perfectly
//!   good ECDSA signature that APNs refuses, because JWS ES256 is defined over the
//!   fixed 64-byte concatenation. `to_bytes()` is the correct encoding and the
//!   difference is invisible until a live 403.
//!
//! ## Token lifetime
//!
//! Apple requires the token be no more than an hour old and asks providers to reuse
//! one rather than mint per request. Both halves matter: minting per request is a
//! documented way to get rate-limited (`TooManyProviderTokenUpdates`), and reusing
//! past the hour is a 403 `ExpiredProviderToken`. [`REUSE_LIMIT_SECS`] is set below
//! the hour so a token minted just before a refresh check is still valid when it
//! arrives.

use base64::Engine as _;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};

/// How long a minted provider token may be reused before it must be replaced.
///
/// Apple's ceiling is 3600s measured on `iat`. This sits well below it so that a
/// token which passes a staleness check has time to be used: a value at the ceiling
/// would let a token be judged fresh and then arrive at APNs expired, which
/// presents as an intermittent 403 rather than as a clock problem.
pub const REUSE_LIMIT_SECS: i64 = 3000;

/// APNs refuses a provider token whose `iat` is more than an hour old. Enforced at
/// COMPILE time rather than in a test: the check is over two constants, so a test
/// asserting it can only ever be constant-folded, and a build that violates it
/// should not produce a binary at all. A later "optimization" raising the reuse
/// limit to exactly 3600 would let a token pass a freshness check locally and
/// arrive at APNs already expired, which presents as an intermittent 403 rather
/// than as a configuration error.
const _: () = assert!(
    REUSE_LIMIT_SECS < 3600,
    "the provider-token reuse limit must leave room for the request to arrive"
);

/// The APNs environments. A token is valid in both, but the HOST is not the same,
/// and a key configured for one environment is silently ignored by the other —
/// notifications are accepted and dropped. Kept as an explicit type so a caller
/// cannot default into one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApnsEnvironment {
    Production,
    Sandbox,
}

impl ApnsEnvironment {
    /// The APNs host for this environment.
    pub fn host(self) -> &'static str {
        match self {
            ApnsEnvironment::Production => "api.push.apple.com",
            ApnsEnvironment::Sandbox => "api.development.push.apple.com",
        }
    }
}

/// Everything about an APNs signing key except the secret bytes. All of it is
/// non-secret and safe to log; the `.p8` is the only part that is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApnsKeyIdentity {
    /// The 10-character key id from the developer account (`kid`).
    pub key_id: String,
    /// The 10-character team id (`iss`).
    pub team_id: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ApnsTokenError {
    /// The `.p8` did not parse as a PKCS#8 P-256 private key.
    KeyDecode(String),
    /// The key id or team id is not the 10 characters Apple issues. Checked because
    /// a wrong-length value produces a 403 that names neither field.
    MalformedIdentity(&'static str),
}

impl std::fmt::Display for ApnsTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApnsTokenError::KeyDecode(detail) => {
                write!(
                    f,
                    "apns signing key did not parse as PKCS#8 P-256: {detail}"
                )
            }
            ApnsTokenError::MalformedIdentity(field) => {
                write!(f, "apns {field} must be exactly 10 characters")
            }
        }
    }
}

impl std::error::Error for ApnsTokenError {}

/// A minted provider token plus the instant it was minted, so a caller can decide
/// whether to reuse it without re-parsing the JWT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderToken {
    /// The compact JWS. Goes into `authorization: bearer <this>`.
    pub jwt: String,
    /// The `iat` claim, seconds since epoch.
    pub issued_at_secs: i64,
}

impl ProviderToken {
    /// Whether this token is too old to reuse at `now_secs`.
    ///
    /// Also true for a token issued in the FUTURE: a clock that jumped backwards
    /// would otherwise make a token look permanently fresh, and APNs judges `iat`
    /// against its own clock rather than ours.
    ///
    /// NOTHING IN THIS WORKSPACE CALLS THIS YET, and that is a statement about the
    /// sender rather than about the method. It exists for a caller that HOLDS a
    /// token across sends; the only sender today mints one per invocation, so it
    /// has no token old enough to ask about. Apple's guidance is explicit that a
    /// provider should reuse a token rather than mint per request, so the caller is
    /// an obligation of the first long-lived sender, not a hypothetical.
    ///
    /// Recorded here because an uncalled function is indistinguishable from an
    /// abandoned one, and the next reader deleting it would remove the reuse bound
    /// at the same time as the code that has not needed it yet.
    pub fn is_stale_at(&self, now_secs: i64) -> bool {
        let age = now_secs - self.issued_at_secs;
        !(0..REUSE_LIMIT_SECS).contains(&age)
    }
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Mint an APNs provider token from a PKCS#8 PEM `.p8` and its identity.
///
/// `issued_at_secs` is a parameter rather than read from the clock so the output is
/// a pure function of its inputs — which is what makes the shape testable against
/// Apple's published example without a fixed-clock seam.
pub fn mint_provider_token(
    p8_pem: &str,
    identity: &ApnsKeyIdentity,
    issued_at_secs: i64,
) -> Result<ProviderToken, ApnsTokenError> {
    if identity.key_id.chars().count() != 10 {
        return Err(ApnsTokenError::MalformedIdentity("key id"));
    }
    if identity.team_id.chars().count() != 10 {
        return Err(ApnsTokenError::MalformedIdentity("team id"));
    }

    let signing_key =
        SigningKey::from_pkcs8_pem(p8_pem).map_err(|e| ApnsTokenError::KeyDecode(e.to_string()))?;

    // Field order inside each JSON object is fixed here rather than left to a
    // serializer: the signature covers the exact bytes, so a reordering would
    // produce a different token. It does not need to match Apple's example, only
    // to be stable.
    let header = format!(
        r#"{{"alg":"ES256","kid":"{}","typ":"JWT"}}"#,
        identity.key_id
    );
    let claims = format!(
        r#"{{"iss":"{}","iat":{}}}"#,
        identity.team_id, issued_at_secs
    );

    let signing_input = format!(
        "{}.{}",
        b64url(header.as_bytes()),
        b64url(claims.as_bytes())
    );

    // to_bytes(), NOT to_der(). See the module header: DER is a valid ECDSA
    // encoding that APNs rejects, and nothing local can tell the difference.
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let jwt = format!("{}.{}", signing_input, b64url(&signature.to_bytes()));

    Ok(ProviderToken {
        jwt,
        issued_at_secs,
    })
}

/// The `:path` for a device token. Separate from the submit call so the encoding
/// rule has one home.
pub fn device_path(device_token_hex: &str) -> String {
    format!("/3/device/{device_token_hex}")
}

use p256::pkcs8::DecodePrivateKey as _;

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, VerifyingKey};

    /// A throwaway P-256 key in the same PKCS#8 PEM shape Apple issues. Generated
    /// once for tests; it authorizes nothing.
    const TEST_P8: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n\
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n\
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n\
-----END PRIVATE KEY-----\n";

    fn identity() -> ApnsKeyIdentity {
        ApnsKeyIdentity {
            key_id: "3Y54KF7PCW".to_string(),
            team_id: "5R5846NBPW".to_string(),
        }
    }

    /// The token has the three-part shape APNs parses, and its claims carry the
    /// values Apple names. Decoded rather than string-matched, so a change to
    /// field order fails on content instead of on formatting.
    #[test]
    fn mints_a_token_apns_can_parse() {
        let token = mint_provider_token(TEST_P8, &identity(), 1_754_000_000).expect("mint");
        let parts: Vec<&str> = token.jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "a compact JWS has exactly three parts");

        let decode = |s: &str| {
            String::from_utf8(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(s)
                    .expect("base64url"),
            )
            .expect("utf8")
        };
        let header = decode(parts[0]);
        let claims = decode(parts[1]);

        assert!(header.contains(r#""alg":"ES256""#), "header: {header}");
        assert!(header.contains(r#""kid":"3Y54KF7PCW""#), "header: {header}");
        assert!(claims.contains(r#""iss":"5R5846NBPW""#), "claims: {claims}");
        assert!(claims.contains(r#""iat":1754000000"#), "claims: {claims}");
    }

    /// The signature is over the exact `header.claims` bytes and verifies under the
    /// key's public half. This is what proves the token is not merely well-shaped:
    /// a signature over the wrong input is the same length and the same encoding,
    /// and only a verification can tell them apart.
    #[test]
    fn signature_verifies_over_the_signing_input() {
        let token = mint_provider_token(TEST_P8, &identity(), 1_754_000_000).expect("mint");
        let parts: Vec<&str> = token.jwt.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);

        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .expect("base64url signature");
        assert_eq!(
            sig_bytes.len(),
            64,
            "JWS ES256 is a fixed 64-byte r||s; a DER signature would be ~70 and \
             variable-length, and APNs rejects it"
        );

        let signature = Signature::from_slice(&sig_bytes).expect("64-byte signature");
        let verifying: VerifyingKey = *SigningKey::from_pkcs8_pem(TEST_P8)
            .expect("key")
            .verifying_key();
        verifying
            .verify(signing_input.as_bytes(), &signature)
            .expect("signature must verify over header.claims");

        // Negative control: the same signature must NOT verify over different
        // bytes, or the assertion above would pass for any input.
        let tampered = format!("{signing_input}x");
        assert!(
            verifying.verify(tampered.as_bytes(), &signature).is_err(),
            "a signature that verifies over arbitrary input proves nothing"
        );
    }

    /// A wrong-length key id or team id is refused locally. APNs answers both with
    /// a 403 that names neither field, so the cheap check is worth more than the
    /// error it replaces.
    #[test]
    fn refuses_malformed_identity() {
        let short = ApnsKeyIdentity {
            key_id: "TOOSHORT".to_string(),
            team_id: "5R5846NBPW".to_string(),
        };
        assert_eq!(
            mint_provider_token(TEST_P8, &short, 0),
            Err(ApnsTokenError::MalformedIdentity("key id"))
        );

        let bad_team = ApnsKeyIdentity {
            key_id: "3Y54KF7PCW".to_string(),
            team_id: "SHORT".to_string(),
        };
        assert_eq!(
            mint_provider_token(TEST_P8, &bad_team, 0),
            Err(ApnsTokenError::MalformedIdentity("team id"))
        );

        // Positive control: the well-formed identity mints, so the refusals above
        // are about the identity rather than about the key or the signer.
        assert!(mint_provider_token(TEST_P8, &identity(), 0).is_ok());
    }

    /// A non-key input fails closed rather than producing a token that APNs would
    /// reject on the wire.
    #[test]
    fn refuses_a_key_that_is_not_pkcs8_p256() {
        let err = mint_provider_token("-----BEGIN PRIVATE KEY-----\nnope\n", &identity(), 0)
            .expect_err("a malformed PEM must not mint");
        assert!(matches!(err, ApnsTokenError::KeyDecode(_)), "got {err:?}");
    }

    /// Staleness is judged on `iat` age, in both directions. The future arm is the
    /// one worth having: a backwards clock jump would otherwise make a token look
    /// fresh forever while APNs measures it against its own clock.
    #[test]
    fn staleness_covers_both_directions() {
        let token = ProviderToken {
            jwt: String::new(),
            issued_at_secs: 1_000_000,
        };
        assert!(!token.is_stale_at(1_000_000), "just minted is fresh");
        assert!(
            !token.is_stale_at(1_000_000 + REUSE_LIMIT_SECS - 1),
            "inside the reuse window is fresh"
        );
        assert!(
            token.is_stale_at(1_000_000 + REUSE_LIMIT_SECS),
            "at the reuse limit is stale"
        );
        assert!(
            token.is_stale_at(999_999),
            "issued in the future is stale, not fresh"
        );
    }

    /// The two environments do not share a host. Pinned because a key configured
    /// for one is silently ignored by the other: notifications are accepted and
    /// dropped, with nothing on the device and nothing in any log we own.
    #[test]
    fn environments_have_distinct_hosts() {
        assert_eq!(ApnsEnvironment::Production.host(), "api.push.apple.com");
        assert_eq!(
            ApnsEnvironment::Sandbox.host(),
            "api.development.push.apple.com"
        );
        assert_ne!(
            ApnsEnvironment::Production.host(),
            ApnsEnvironment::Sandbox.host()
        );
    }

    #[test]
    fn device_path_is_the_documented_shape() {
        assert_eq!(device_path("abc123"), "/3/device/abc123");
    }
}
