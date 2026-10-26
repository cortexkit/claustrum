use super::{Secret, ValidationError};
use hmac::{Hmac, Mac};

/// RFC 6238 dynamic truncation. Only the code, never the seed, is returned.
pub fn totp(uri: &str, now_ms: i64) -> Result<Secret<String>, ValidationError> {
    super::validation::validate_otpauth(uri)?;
    let url = url::Url::parse(uri).map_err(|_| ValidationError::InvalidParams)?;
    let pairs: std::collections::HashMap<_, _> = url.query_pairs().collect();
    let encoded = pairs.get("secret").ok_or(ValidationError::InvalidParams)?;
    let (mut bits, mut acc) = (0u32, 0u32);
    let seed = Secret::new(
        encoded
            .trim_end_matches('=')
            .bytes()
            .filter_map(|c| {
                let n = match c {
                    b'A'..=b'Z' => c - b'A',
                    b'2'..=b'7' => c - b'2' + 26,
                    _ => return Some(Err(ValidationError::InvalidParams)),
                };
                acc = (acc << 5) | u32::from(n);
                bits += 5;
                if bits >= 8 {
                    bits -= 8;
                    Some(Ok((acc >> bits) as u8))
                } else {
                    None
                }
            })
            .collect::<Result<Vec<_>, _>>()?,
    );
    let period = pairs
        .get("period")
        .map_or(Ok(30), |s| s.parse::<u64>())
        .map_err(|_| ValidationError::InvalidParams)?;
    let digits = if pairs.get("digits").is_some_and(|s| s == "8") {
        8
    } else {
        6
    };
    let counter =
        (u64::try_from(now_ms).map_err(|_| ValidationError::InvalidParams)? / 1000 / period)
            .to_be_bytes();
    macro_rules! digest {
        ($hash:ty) => {{
            let mut mac = Hmac::<$hash>::new_from_slice(seed.expose())
                .map_err(|_| ValidationError::InvalidParams)?;
            mac.update(&counter);
            Secret::new(mac.finalize().into_bytes().to_vec())
        }};
    }
    let hash = match pairs.get("algorithm").map(|s| s.as_ref()).unwrap_or("SHA1") {
        "SHA1" => digest!(sha1::Sha1),
        "SHA256" => digest!(sha2::Sha256),
        "SHA512" => digest!(sha2::Sha512),
        _ => return Err(ValidationError::InvalidParams),
    };
    let offset = usize::from(hash.expose()[hash.expose().len() - 1] & 15);
    let code = u32::from_be_bytes(
        hash.expose()[offset..offset + 4]
            .try_into()
            .map_err(|_| ValidationError::InvalidParams)?,
    ) & 0x7fff_ffff;
    Ok(Secret::new(format!(
        "{:0width$}",
        code % 10u32.pow(digits),
        width = digits as usize
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn base32(bytes: &[u8]) -> String {
        let mut text = String::new();
        let (mut acc, mut bits) = (0u32, 0u32);
        for b in bytes {
            acc = (acc << 8) | u32::from(*b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                text.push(
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[((acc >> bits) & 31) as usize] as char,
                );
            }
        }
        if bits > 0 {
            text.push(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[((acc << (5 - bits)) & 31) as usize] as char,
            );
        }
        text
    }
    #[test]
    fn secret_totp_matches_all_rfc6238_appendix_b_vectors() {
        let times = [
            59,
            1_111_111_109,
            1_111_111_111,
            1_234_567_890,
            2_000_000_000,
            20_000_000_000i64,
        ];
        let vectors = [
            (
                "SHA1",
                b"12345678901234567890".as_slice(),
                [
                    "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
                ],
            ),
            (
                "SHA256",
                b"12345678901234567890123456789012".as_slice(),
                [
                    "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
                ],
            ),
            (
                "SHA512",
                b"1234567890123456789012345678901234567890123456789012345678901234".as_slice(),
                [
                    "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
                ],
            ),
        ];
        for (algorithm, seed, codes) in vectors {
            let uri = Secret::new(format!(
                "otpauth://totp/test?secret={}&algorithm={algorithm}&digits=8&period=30",
                base32(seed)
            ));
            for (time, expected) in times.into_iter().zip(codes) {
                assert_eq!(
                    totp(uri.expose(), time * 1000).unwrap().expose(),
                    expected,
                    "RFC 6238 {algorithm} at {time}"
                );
            }
        }
        assert!(totp("otpauth://hotp/test?secret=GEZDGNBVGY3TQOJQ", 59_000).is_err());
    }
}
