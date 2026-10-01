//! Cookie deposit primitives shared by persistence and the wire admission layer.

use sha2::{Digest, Sha256};

/// A committed cookie write and its monotonic record version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositCookieOutcome {
    Created { record_version: u64 },
    Replaced { record_version: u64 },
}

/// The narrow browser-cookie id grammar, measured in UTF-8 bytes.
pub fn valid_deposit_cookie_id(id: &str) -> bool {
    if id.len() > 255 {
        return false;
    }
    let Some(rest) = id.strip_prefix("cookie:") else {
        return false;
    };
    let Some((domain, account)) = rest.split_once(':') else {
        return false;
    };
    if account.is_empty()
        || account.len() > 64
        || !account
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._@+-".contains(&b))
    {
        return false;
    }
    domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// Consent commitment: domain separator, length-prefixed id and consent reference,
/// followed by the raw SHA-256 cookie digest (not its hexadecimal representation).
pub fn deposit_cookie_payload_hash(id: &str, consent_ref: &str, cookie: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"ck-deposit-cookie/v1");
    hash.update((id.len() as u32).to_be_bytes());
    hash.update(id.as_bytes());
    hash.update((consent_ref.len() as u32).to_be_bytes());
    hash.update(consent_ref.as_bytes());
    hash.update(Sha256::digest(cookie));
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_cookie_hash_matches_independently_computed_literal_preimage() {
        // Computed with Python hashlib and struct.pack('>I', length), independently
        // of the Rust helper. The inner digest below is 32 raw bytes.
        let preimage = "636b2d6465706f7369742d636f6f6b69652f763100000016636f6f6b69653a6f6c6c616d612e636f6d3a7566756b0000000b636f6e73656e742d313233a47daa9671e781e941fe41c1fd65a2115d045c0f02f061b11e8511a512278a79";
        let bytes: Vec<u8> = (0..preimage.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&preimage[i..i + 2], 16).unwrap())
            .collect();
        let expected = "d523e692e03fc04a7700e325960047a0283a062980239e5ea7ad03b4eac9bcb7";
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), expected);
        assert_eq!(
            deposit_cookie_payload_hash("cookie:ollama.com:ufuk", "consent-123", b"session=abc"),
            expected
        );
    }

    #[test]
    fn deposit_cookie_id_grammar_boundaries() {
        let total_255 = format!(
            "cookie:{}.{}.{}.com:a",
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63)
        );
        // Extend the account to place the total id length exactly at the 255-byte limit.
        let total_255 = format!("{total_255}{}", "a".repeat(255 - total_255.len()));
        let rows = vec![
            ("cookie:example.com:a".into(), true),
            ("apikey:x".into(), false),
            ("oauth:anthropic".into(), false),
            ("cookie:example.com:a|b".into(), false),
            ("category:browser-session".into(), false),
            (total_255.clone(), true),
            (format!("{total_255}a"), false),
            (format!("cookie:{}.com:a", "a".repeat(63)), true),
            (format!("cookie:{}.com:a", "a".repeat(64)), false),
            (format!("cookie:a.com:{}", "a".repeat(64)), true),
            (format!("cookie:a.com:{}", "a".repeat(65)), false),
            ("cookie:-a.com:a".into(), false),
            ("cookie:a-.com:a".into(), false),
            ("cookie:A.com:a".into(), false),
            ("cookie:localhost:a".into(), false),
            ("cookie:a.com:".into(), false),
            ("cookie:a.com:a:b".into(), false),
            ("cookie:a..com:a".into(), false),
        ];
        for (id, expected) in rows {
            assert_eq!(valid_deposit_cookie_id(&id), expected, "{id}");
        }
    }
}
