//! Validation shared by enrollment proposals and operator-approved labels.

pub const MAX_DISPLAY_NAME_CHARS: usize = 40;

/// Absence is optional, but a present display name must be a string, not null.
pub fn deserialize_optional_display_name<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    <String as serde::Deserialize>::deserialize(deserializer).map(Some)
}

/// Trim and validate a person-facing label without truncating or rewriting it.
pub fn validate_display_name(value: &str) -> Result<String, &'static str> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > MAX_DISPLAY_NAME_CHARS {
        return Err("display_name must contain 1 to 40 Unicode scalar values");
    }
    if value.chars().any(|c| {
        c.is_control()
            || matches!(c,
                '\u{2028}' | '\u{2029}' | '\u{061c}' | '\u{200e}' | '\u{200f}'
                | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
                | '\u{200b}'..='\u{200d}' | '\u{feff}')
    }) {
        return Err("display_name contains a forbidden character");
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names_accept_40_scalars_and_refuse_41() {
        assert_eq!(validate_display_name(" x ").unwrap(), "x");
        assert_eq!(
            validate_display_name("\u{2003}Pi 🥧\u{2003}").unwrap(),
            "Pi 🥧"
        );
        assert!(validate_display_name(&"🦀".repeat(40)).is_ok());
        assert!(validate_display_name(&"🦀".repeat(41)).is_err());
        assert!(validate_display_name(&"e\u{301}".repeat(20)).is_ok());
        assert!(validate_display_name(&format!("{}e", "e\u{301}".repeat(20))).is_err());
        assert!(validate_display_name("").is_err());
        assert!(validate_display_name(" \t\n\u{2003}").is_err());
        assert_eq!(
            validate_display_name("Claude sign-in for Pi").unwrap(),
            "Claude sign-in for Pi"
        );
    }

    #[test]
    fn display_names_refuse_controls_separators_bidi_and_zero_width() {
        let forbidden = (0..=0x1f)
            .chain(0x7f..=0x9f)
            .chain([0x2028, 0x2029, 0x061c, 0x200e, 0x200f, 0xfeff])
            .chain(0x202a..=0x202e)
            .chain(0x2066..=0x2069)
            .chain(0x200b..=0x200d);
        for scalar in forbidden {
            let c = char::from_u32(scalar).unwrap();
            assert!(
                validate_display_name(&format!("a{c}b")).is_err(),
                "U+{scalar:04X}"
            );
        }
        // Other Unicode formatting and ordinary non-ASCII text are not prohibited.
        assert!(validate_display_name("π\u{00ad}名").is_ok());
    }
}
