//! Recognises Amazon Bedrock SHORT-TERM API keys, which must not be stored.
//!
//! AWS issues two Bedrock API key forms. A long-term key (`ABSK...`) is an IAM service
//! credential with a configured lifetime and belongs in the vault like any API key. A
//! short-term key (`bedrock-api-key-` + base64 of a SigV4-presigned URL) lives at most 12
//! hours and is derived from the session that generated it, so nothing here can renew it.
//! Stored, it serves for a few hours and then fails forever while `ck auth usable` still
//! reports it as an active key with no declared expiry. That is what happened to
//! `apikey:amazon-bedrock`: imported four days after its 12-hour window closed, it sat
//! "active" for 95 days until a consumer finally read it and got 403 "Bearer token has
//! expired". Formats per AWS: https://aws.amazon.com/blogs/security/securing-amazon-bedrock-api-keys-best-practices-for-implementation-and-management/
//!
//! Recognition is by AWS's documented prefix, which is a structural fact about the key
//! rather than a guess at whether some bytes look secret.

use base64::Engine as _;

/// The documented prefix of every short-term Bedrock API key.
pub const SHORT_TERM_PREFIX: &str = "bedrock-api-key-";

/// A short-term Bedrock key, with its expiry when the presigned URL inside it decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShortTermBedrockKey {
    /// `X-Amz-Date` plus `X-Amz-Expires`, in Unix milliseconds. `None` when the body
    /// does not decode to a presigned URL carrying both; the prefix alone still
    /// identifies the form.
    pub expires_at_ms: Option<i64>,
}

/// Returns `Some` when `payload` is a short-term Bedrock API key.
pub fn short_term_bedrock_key(payload: &[u8]) -> Option<ShortTermBedrockKey> {
    let payload = payload.trim_ascii();
    let body = payload.strip_prefix(SHORT_TERM_PREFIX.as_bytes())?;
    Some(ShortTermBedrockKey {
        expires_at_ms: presigned_expiry_ms(body),
    })
}

fn presigned_expiry_ms(body: &[u8]) -> Option<i64> {
    let body = std::str::from_utf8(body).ok()?.trim().trim_end_matches('=');
    let decoded = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(body)
        .ok()?;
    let presigned = String::from_utf8(decoded).ok()?;
    // The URL is written without a scheme (`bedrock.amazonaws.com/?Action=...`), so read
    // the query string directly rather than parsing it as a URL.
    let query = presigned.split_once('?')?.1;
    let mut signed_at = None;
    let mut lifetime_secs = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "X-Amz-Date" => {
                signed_at = chrono::NaiveDateTime::parse_from_str(&value, "%Y%m%dT%H%M%SZ")
                    .ok()
                    .map(|date| date.and_utc().timestamp_millis());
            }
            "X-Amz-Expires" => lifetime_secs = value.parse::<i64>().ok(),
            _ => {}
        }
    }
    signed_at?.checked_add(lifetime_secs?.checked_mul(1000)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_for(query: &str) -> Vec<u8> {
        let url = format!("bedrock.amazonaws.com/?Action=CallWithBearerToken&{query}");
        format!(
            "{SHORT_TERM_PREFIX}{}",
            base64::engine::general_purpose::STANDARD.encode(url)
        )
        .into_bytes()
    }

    #[test]
    fn short_term_key_reports_its_presigned_expiry() {
        let key = key_for(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA%2F20260623%2Fus-east-1%2Fbedrock%2Faws4_request&X-Amz-Date=20260623T080000Z&X-Amz-Expires=43200&X-Amz-SignedHeaders=host&X-Amz-Signature=00",
        );
        // 2026-06-23T08:00:00Z + 12h = 2026-06-23T20:00:00Z.
        let expected = chrono::DateTime::parse_from_rfc3339("2026-06-23T20:00:00Z")
            .unwrap()
            .timestamp_millis();
        assert_eq!(
            short_term_bedrock_key(&key),
            Some(ShortTermBedrockKey {
                expires_at_ms: Some(expected)
            })
        );
    }

    #[test]
    fn prefix_alone_identifies_the_form_when_the_body_does_not_decode() {
        assert_eq!(
            short_term_bedrock_key(b"bedrock-api-key-not*base64"),
            Some(ShortTermBedrockKey {
                expires_at_ms: None
            })
        );
        assert_eq!(
            short_term_bedrock_key(&key_for("X-Amz-Date=20260623T080000Z")),
            Some(ShortTermBedrockKey {
                expires_at_ms: None
            }),
            "no X-Amz-Expires means no computable expiry"
        );
    }

    #[test]
    fn long_term_and_other_keys_are_not_short_term() {
        for key in [
            &b"ABSKQmVkcm9ja0FQSUtleS1leGFtcGxl"[..],
            b"sk-proj-abc",
            b"",
            b"xbedrock-api-key-abc",
        ] {
            assert_eq!(short_term_bedrock_key(key), None, "{key:?}");
        }
    }
}

#[cfg(test)]
mod whitespace_rules {
    use super::*;
    #[test]
    fn short_term_prefix_ignores_surrounding_whitespace() {
        assert!(short_term_bedrock_key(b" \tbedrock-api-key-invalid\n").is_some());
        assert!(short_term_bedrock_key(b" \tbedrock-api-key-\xff\n").is_some());
    }
    #[test]
    fn presigned_expiry_ignores_surrounding_whitespace() {
        let body = base64::engine::general_purpose::STANDARD
            .encode("bedrock.amazonaws.com/?X-Amz-Date=20260623T080000Z&X-Amz-Expires=43200");
        let padded = format!(" \t{body}\n");
        assert_eq!(
            presigned_expiry_ms(padded.as_bytes()),
            Some(1_782_244_800_000)
        );
    }
}
