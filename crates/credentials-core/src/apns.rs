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
/// What a PKCS#8 PEM actually contains, for a refusal that describes the OPERATOR'S
/// file rather than the parser's expectation.
///
/// Deliberately shallow: it reads the algorithm and named-curve OIDs and nothing else,
/// because its only job is to let a refusal say "this is an RSA key" or "this is
/// P-384". Returns `None` when the structure is unrecognisable, in which case the
/// caller keeps the raw decoder error -- an honest "I cannot tell" beats a guess.
fn describe_key_material(pem: &str) -> Option<&'static str> {
    use p256::pkcs8::der::Decode as _;

    // Strip the PEM armour by hand rather than pulling in a parser: the payload is one
    // base64 blob between the BEGIN/END lines.
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der = base64_decode_standard(body.trim())?;
    let info = p256::pkcs8::PrivateKeyInfo::from_der(&der).ok()?;

    const ID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
    const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
    const ED25519: &str = "1.3.101.112";
    const SECP384R1: &str = "1.3.132.0.34";
    const SECP521R1: &str = "1.3.132.0.35";
    const SECP256K1: &str = "1.3.132.0.10";

    let algorithm = info.algorithm.oid.to_string();
    match algorithm.as_str() {
        RSA_ENCRYPTION => Some("an RSA key"),
        ED25519 => Some("an Ed25519 key"),
        ID_EC_PUBLIC_KEY => {
            // The curve rides in the algorithm parameters, and it is the field that
            // actually decides whether ES256 can be produced.
            let curve = info
                .algorithm
                .parameters_oid()
                .ok()
                .map(|oid| oid.to_string())
                .unwrap_or_default();
            match curve.as_str() {
                SECP384R1 => Some("an EC key on P-384"),
                SECP521R1 => Some("an EC key on P-521"),
                SECP256K1 => Some("an EC key on secp256k1"),
                _ => Some("an EC key on a curve other than P-256"),
            }
        }
        _ => None,
    }
}

/// Standard-alphabet base64 decode for the PEM body. Separate from [`b64url`], which
/// emits the URL alphabet the JWT wants and cannot read this.
fn base64_decode_standard(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for byte in s.bytes() {
        if byte == b'=' || byte.is_ascii_whitespace() {
            continue;
        }
        let value = ALPHABET.iter().position(|&c| c == byte)? as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

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

    // NAME WHAT THE FILE HOLDS, NOT WHAT THE PARSER WANTED.
    //
    // Measured 2026-08-12, feeding real keys of each shape: the upstream error names
    // the EXPECTED OID and never the found one, and the reported value is absent from
    // the file in both failing cases. An RSA key reports `1.2.840.10045.2.1`
    // (id-ecPublicKey); a P-384 key reports `1.2.840.10045.3.1.7`, which IS prime256v1.
    //
    // That last one is not merely unhelpful, it is INVERTED: an operator with a P-384
    // key looks the OID up, finds P-256 -- exactly what APNs requires -- and reads the
    // message as "your P-256 key is unsupported". Every subsequent move is wrong, and
    // the message was confident and specific throughout. Prefer no detail to detail
    // that argues for the wrong conclusion.
    //
    // NAME THE REMEDY FOR THE CONTAINER MISMATCH, not just the cause.
    //
    // A SEC1 PEM (`BEGIN EC PRIVATE KEY`) holds the SAME key material and is what
    // `openssl ecparam -genkey` produces by default, so an operator can hold a
    // perfectly valid key that this refuses. The underlying error names the ASN.1
    // problem, which is accurate and useless at 3am: it reads as "this credential is
    // broken" when the truth is "this credential is fine, in the other envelope", and
    // the conversion is one command. Callosum's Worker-side signer hit exactly this
    // and hardened against it; the same key can arrive at either signer.
    let signing_key = SigningKey::from_pkcs8_pem(p8_pem).map_err(|e| {
        let detail = e.to_string();
        if p8_pem.contains("BEGIN EC PRIVATE KEY") {
            ApnsTokenError::KeyDecode(format!(
                "{detail} -- this is a SEC1 key (BEGIN EC PRIVATE KEY). It holds the \
                 right material in the wrong envelope; convert it with: openssl pkcs8 \
                 -topk8 -nocrypt -in <file> -out <file>.p8"
            ))
        } else if let Some(found) = describe_key_material(p8_pem) {
            ApnsTokenError::KeyDecode(format!(
                "this key is {found}; APNs provider tokens are ES256, which requires a \
                 P-256 (prime256v1) EC key. The underlying decoder names the OID it \
                 EXPECTED rather than the one it found, so ignore any OID it quotes: \
                 [{detail}]"
            ))
        } else {
            ApnsTokenError::KeyDecode(detail)
        }
    })?;

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

    const P384_FIXTURE: &str = "-----BEGIN PRIVATE KEY-----\n\
             MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAXePjbqN+yQPga51Eg\n\
             fXmzU6lFVK3H36w6/8pmkxAm10teqiX8/wIY4glzlwxuAzyhZANiAATxAlKXdgw6\n\
             O7TN160oB24/EZsZ0KEzv4kS3AagU27ZHQB10otXUcjT5WlZ5fHEA5gF3VB9bUC+\n\
             DXUfW1ZHlFS3raU1JkCU+IvUuvlO4uOEDNDCEF05+vUcNDwfgn8WJeg=\n\
             -----END PRIVATE KEY-----\n";

    const SEC1_FIXTURE: &str = "-----BEGIN EC PRIVATE KEY-----\n\
             MHcCAQEEIETz/ydtOsothIXt2aKZgPl9yWljo/vJpYC6JC0H2BSvoAoGCCqGSM49\n\
             AwEHoUQDQgAEQXE5PChcWqV3bw8OnWJxTfjcHF+qSH+8el1GrbA/pWnDxKaLjwIs\n\
             8gD3rFdEA8xX1bSEwDFsiwmdde0vvP6ihA==\n\
             -----END EC PRIVATE KEY-----\n";

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

    /// A SEC1 key -- the same material in the other envelope -- is refused WITH THE
    /// CONVERSION COMMAND.
    ///
    /// The garbage-input test below proves the signer rejects nonsense. This proves the
    /// harder case: a key that is genuinely VALID and genuinely the operator's, which
    /// `openssl ecparam -genkey` produces by default, and which the underlying ASN.1
    /// error describes accurately and uselessly. Without the remedy in the message the
    /// reading is "this credential is broken" when the truth is "wrong envelope, one
    /// command away".
    ///
    /// The fixture is a REAL SEC1 block rather than a malformed string, because the
    /// point is that parsing gets far enough to identify the container.
    #[test]
    fn a_sec1_key_is_refused_with_the_conversion_command() {
        // A real prime256v1 SEC1 key, generated for this test and used nowhere.
        const SEC1: &str = SEC1_FIXTURE;

        let err = mint_provider_token(SEC1, &identity(), 0).expect_err("SEC1 must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("SEC1"),
            "the refusal must name the container, not just the ASN.1 failure: {msg}"
        );
        assert!(
            msg.contains("openssl pkcs8 -topk8"),
            "the refusal must carry the conversion command -- the operator's key is \
             valid and one command from working: {msg}"
        );

        // THE CLAIM IS THAT THE REMEDY WORKS, and the assertion above only checks that
        // the sentence is present -- my text containing my text, which passes however
        // wrong the advice is. So convert the fixture the way the message says and
        // require the RESULT to be accepted. Done in-process rather than by shelling
        // out to openssl: the point is that this exact material, in PKCS#8, signs.
        let converted = sec1_fixture_as_pkcs8();
        mint_provider_token(&converted, &identity(), 0).expect(
            "the refusal promises the key is fine in the other envelope -- if \
                     this fails, the message is telling operators to run a command that \
                     does not fix their problem",
        );
    }

    /// The SEC1 fixture re-encoded as PKCS#8, which is what the refusal's `openssl
    /// pkcs8 -topk8` invocation produces. Kept beside the test so the conversion claim
    /// is checked against the SAME key the refusal is shown for.
    fn sec1_fixture_as_pkcs8() -> String {
        use p256::pkcs8::EncodePrivateKey as _;
        use p256::SecretKey;

        let key = SecretKey::from_sec1_pem(SEC1_FIXTURE).expect("the fixture is a real SEC1 key");
        key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("re-encode as PKCS#8")
            .to_string()
    }

    /// A wrong-ALGORITHM and a wrong-CURVE key are each named for what they ARE.
    ///
    /// Found by measuring the refusals rather than reading them, while checking a peer's
    /// claim that our two signers refused the same shapes. The upstream decoder names
    /// the OID it EXPECTED and never the one it found, and the quoted value is absent
    /// from the file in both cases: an RSA key reported `1.2.840.10045.2.1`
    /// (id-ecPublicKey), and a P-384 key reported `1.2.840.10045.3.1.7` -- which IS
    /// prime256v1.
    ///
    /// The P-384 case is INVERTED rather than merely unhelpful: an operator looks the
    /// OID up, finds P-256 (exactly what APNs requires), and reads the message as "your
    /// P-256 key is unsupported". Confident, specific, and wrong in the direction that
    /// makes every next move wrong too.
    ///
    /// Both fixtures are real keys, so the refusal is about the MATERIAL rather than
    /// malformed bytes.
    #[test]
    fn a_wrong_algorithm_or_curve_is_named_for_what_it_is() {
        // A real RSA-2048 key and a real P-384 key, generated for these tests and used
        // nowhere else.
        const RSA: &str = "-----BEGIN PRIVATE KEY-----\n\
             MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7S+VVs7sxbf+8\n\
             0ndRhzRHdhArFB2go1d5b22SBZsphkS9mF+H4Xro/3oqX473yCVSoPJYf/d8p43o\n\
             3OK9L5TIQLwJdQJ0yq9qrKQz1zRReUF3xz4XSytNWCHxndbGjuTyj969YJSB7Aww\n\
             3nD6zTTtBFuCU1L2gUI4tgGOyyBrxTR6ifyTgkmIK/3rwpEkvi3j2ELmzg7OCy4I\n\
             ICs40r3YSJhzDvYj9zIX91DupWu23VvEBHqe/ND3IU/ATfsXXFdNCqv+j+sdXARY\n\
             5JL4kQZitrDVie1haPifHA9AJhEgaLrnWiPYXKDnO3CpEznxGnoY05ukTQOL1V1j\n\
             se6cg7XXAgMBAAECggEAVK0KYMWiAsXlUbuhQBWtOAWTZ7ZvcpmGSZtr4RFxxcMz\n\
             PrgtsGPrSn1+ALw1CabN4N5s0kAAZrXlvXpnc/qX/DTwDiJ9WsnrpoGotts7hv4X\n\
             8Av+8U8Fo7ENn4updxlRPqx2mg2Y9mf+VvWqBGlT3TgUGwaKwnFLvBHlAGarIK0/\n\
             gqBoLsBezLJqIAWch044xrtFrVMtQN5CUFGTHAO1rmaUXj5kms9nnOJf8izhqOQx\n\
             DVKQwab3OUY881wFfPah8fhFNkWeZ+XFNmHAvR82cCZpIbRLQ7ieB2DCiEh9Qjut\n\
             KK+MBBy26F5HY6TFzYhGPLhHwC3WnTqxEdFqtiHMaQKBgQDx8Y/gBHjcS4VA3Fx7\n\
             KwT76+jIDQxS+jlKqZkDLC7ViKt6qGbvIV/QGj3+kVhmkryAe8kEB3kG5zAjwvzK\n\
             FG275JzlhpVd6/qDCEK5UwDUPikq9IH6bCdgaZDFF//r+O1DnMtp09qxA4SS6R4d\n\
             K1jITnbzTU7A16HAIfCclWDcFQKBgQDGLZCHuLiO97WeUsBT6uzI9vnabFSCFa34\n\
             JwzgekbxFG9TTUNwjo24KnIThQeoeiSFP1YQ0TdinrMox2Knknqhc2rRmebLUesU\n\
             8s8LwsjnuvrPaiWnfpoDAHpY2EL9ckN90fFvRjolRsfzL9IOKMf16xqQk0m3kgki\n\
             9ZQ/p3NJOwKBgQCwQcsO6DMkSeBJ4D9/e1emL7bmBptz19blDajrJsT3yxkhwo06\n\
             qJWkhXmkez5re3rYH1XSGZ+R59qqMuL2VOucdm/WxrUKN1/JFbuGR3HTLXXQVVBb\n\
             n28QTdepvlIzFqXDG/cUocIwMt/iJvJJTcrgIkmF9kvpMS4lSpR/flOSAQKBgGuT\n\
             WkxCOnTpA/6QXvRupuAkKNanTWxbxlbZI8VKuu2ssQ2f+EbGKynYaJot8U1EGET4\n\
             b4ireQwgp5IwQV5DRiwT0d07VKvzqM9zSm7Q6mvX9MPYk94K/CE7Bi7qHdskRnyr\n\
             FQrZLUEE3g8lWznyazET0RS/zxlFvY3rjvDKver3AoGAMZ6lOiTxgQIOCHUHtchA\n\
             TyQ1S3yW2czLSgV5yrrNwEFlYqvUitPak59B3klNuYPHGQpd+abwvqealufBnNxa\n\
             oQUPsczurQFdpMVzsfFscMnWifcqEz8V5t2FPfiNtQjXS/bK7KBo/sCHOdmknMv7\n\
             KlJd/97QR+5d41fpw7622cQ=\n\
             -----END PRIVATE KEY-----\n";
        const P384: &str = P384_FIXTURE;

        let rsa_msg = format!(
            "{}",
            mint_provider_token(RSA, &identity(), 0).expect_err("an RSA key must be refused")
        );
        assert!(
            rsa_msg.contains("an RSA key"),
            "the refusal must name what the file HOLDS: {rsa_msg}"
        );

        let p384_msg = format!(
            "{}",
            mint_provider_token(P384, &identity(), 0).expect_err("a P-384 key must be refused")
        );
        assert!(
            p384_msg.contains("P-384"),
            "the refusal must name the curve the operator actually has: {p384_msg}"
        );
        assert!(
            p384_msg.contains("ignore any OID"),
            "the quoted OID is the EXPECTED one, and for P-384 it reads as prime256v1 -- \
             the message must warn rather than let the operator trust it: {p384_msg}"
        );
    }

    /// PINS THE UPSTREAM BEHAVIOUR THE WARNING ABOVE COMPENSATES FOR.
    ///
    /// That assertion checks my own text against my own text, so it passes whatever the
    /// decoder does -- which makes the CLAIM inside it unguarded. If `p256` ever fixes
    /// its decoder to report the OID it FOUND, my "ignore any OID it quotes" becomes
    /// advice to disregard the one accurate fact in the message, and nothing above would
    /// notice.
    ///
    /// A peer made the general argument while declining to wrap their own correct
    /// upstream message: a paraphrase is a permanent obligation to stay in step with a
    /// string you do not control, and a stale one is a confident message describing
    /// something other than what happened. Wrapping is worth it here because the
    /// upstream is actively misleading -- but only if the wrapper's premise is itself
    /// checked.
    ///
    /// So this asserts the DEFECT still exists: the decoder quotes prime256v1's OID for
    /// a key that is not prime256v1. When this fails, the upstream was fixed and the
    /// warning must be deleted rather than the test relaxed.
    #[test]
    fn the_upstream_decoder_still_reports_the_expected_oid_not_the_found_one() {
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::DecodePrivateKey as _;

        // The same real P-384 key the arm above uses.
        let err = SigningKey::from_pkcs8_pem(P384_FIXTURE)
            .expect_err("a P-384 key cannot yield a P-256 signing key");
        let raw = err.to_string();

        const PRIME256V1_OID: &str = "1.2.840.10045.3.1.7";
        assert!(
            raw.contains(PRIME256V1_OID),
            "the wrapper warns that the quoted OID is the EXPECTED one. If the decoder \
             no longer quotes prime256v1's OID for a P-384 key, that warning is now \
             telling operators to ignore accurate information -- DELETE THE WARNING \
             rather than relaxing this test. Got: {raw}"
        );
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
