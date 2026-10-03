//! Provider ids: the catalog provider ids an operator says a credential serves.
//!
//! They are NON-SECRET operator metadata, stored in their own table beside the
//! credential row and never inside the sealed record, so writing them never opens or
//! re-seals an envelope. The vault never infers one: an id the operator has not set is
//! simply absent.
//!
//! This module holds the shape rules every writer shares. The vault applies them before
//! it touches the store, and the CLI applies the same function before it sends an op,
//! so a refusal names the same rule and value on both sides.

use crate::store::StoreOpError;

/// Shortest provider id accepted, in bytes.
pub const MIN_PROVIDER_ID_LEN: usize = 2;

/// Longest provider id accepted, in bytes.
pub const MAX_PROVIDER_ID_LEN: usize = 64;

/// Most provider ids one credential may hold. The cap applies to the set that would
/// result from a write, never to the length of a request: removing any number of ids
/// is always allowed, and replacing a full set with a different full set succeeds.
pub const MAX_PROVIDER_IDS_PER_CREDENTIAL: usize = 32;

/// Which provider-id rule refused a write. The spelling is part of the wire contract:
/// it appears in the refusal text as `rule=<token>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderIdRule {
    /// Not lowercase ASCII letters, digits and hyphens starting with a letter. The empty
    /// string fails here, because it has no leading letter.
    Charset,
    /// Shorter than [`MIN_PROVIDER_ID_LEN`] or longer than [`MAX_PROVIDER_ID_LEN`] bytes.
    Length,
    /// The request names the same id twice. An id that is already stored is not a
    /// duplicate.
    Duplicate,
    /// The resulting set would hold more than [`MAX_PROVIDER_IDS_PER_CREDENTIAL`] ids.
    Count,
}

impl ProviderIdRule {
    /// The stable token for this rule.
    pub fn as_str(self) -> &'static str {
        match self {
            ProviderIdRule::Charset => "charset",
            ProviderIdRule::Length => "length",
            ProviderIdRule::Duplicate => "duplicate",
            ProviderIdRule::Count => "count",
        }
    }
}

impl std::fmt::Display for ProviderIdRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

fn charset_ok(id: &str) -> bool {
    let mut bytes = id.bytes();
    match bytes.next() {
        Some(first) if first.is_ascii_lowercase() => {}
        _ => return false,
    }
    bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn length_ok(id: &str) -> bool {
    (MIN_PROVIDER_ID_LEN..=MAX_PROVIDER_ID_LEN).contains(&id.len())
}

/// Check a requested provider-id list against the rules that need no stored state.
///
/// Every requested id is checked in request order, `charset` before `length`; only
/// then is the list scanned for a repeated id, which is named by its second
/// occurrence. The first failure is the one reported. The count cap is NOT checked
/// here: it depends on what the credential already holds, so only the vault can apply
/// it exactly.
pub fn check_provider_ids(ids: &[String]) -> Result<(), StoreOpError> {
    for id in ids {
        let rule = if !charset_ok(id) {
            ProviderIdRule::Charset
        } else if !length_ok(id) {
            ProviderIdRule::Length
        } else {
            continue;
        };
        return Err(StoreOpError::InvalidProviderId {
            rule,
            value: id.clone(),
        });
    }
    let mut seen = std::collections::BTreeSet::new();
    for id in ids {
        if !seen.insert(id.as_str()) {
            return Err(StoreOpError::InvalidProviderId {
                rule: ProviderIdRule::Duplicate,
                value: id.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal(ids: &[&str]) -> Option<(ProviderIdRule, String)> {
        let ids: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        match check_provider_ids(&ids) {
            Ok(()) => None,
            Err(StoreOpError::InvalidProviderId { rule, value }) => Some((rule, value)),
            Err(other) => panic!("unexpected error {other}"),
        }
    }

    #[test]
    fn the_shape_rules_accept_the_boundaries_and_refuse_just_past_them() {
        let max = "a".repeat(MAX_PROVIDER_ID_LEN);
        let too_long = "a".repeat(MAX_PROVIDER_ID_LEN + 1);
        assert_eq!(refusal(&["ab", &max, "zai-coding-plan", "a1-b2"]), None);
        assert_eq!(
            refusal(&["a"]),
            Some((ProviderIdRule::Length, "a".to_string()))
        );
        assert_eq!(
            refusal(&[&too_long]),
            Some((ProviderIdRule::Length, too_long.clone()))
        );
        for bad in [
            "",
            "1a",
            "Ab",
            "-ab",
            "llama.cpp",
            "a_b",
            "a b",
            "a|b",
            "zé",
        ] {
            assert_eq!(
                refusal(&[bad]),
                Some((ProviderIdRule::Charset, bad.to_string())),
                "{bad:?} must fail charset"
            );
        }
    }

    #[test]
    fn charset_runs_before_length_and_both_run_before_duplicate() {
        // `1` is both outside the charset and too short: charset is reported.
        assert_eq!(
            refusal(&["1"]),
            Some((ProviderIdRule::Charset, "1".to_string()))
        );
        // A duplicate early in the list loses to a shape failure later in it.
        assert_eq!(
            refusal(&["aa", "aa", "B"]),
            Some((ProviderIdRule::Charset, "B".to_string()))
        );
        assert_eq!(
            refusal(&["aa", "aa", "b"]),
            Some((ProviderIdRule::Length, "b".to_string()))
        );
        // Ids are checked in request order: the first bad one is named.
        assert_eq!(
            refusal(&["ok", "x", "Y"]),
            Some((ProviderIdRule::Length, "x".to_string()))
        );
    }

    #[test]
    fn a_repeated_id_is_named_by_its_second_occurrence() {
        assert_eq!(
            refusal(&["aa", "bb", "cc", "bb", "aa"]),
            Some((ProviderIdRule::Duplicate, "bb".to_string()))
        );
    }

    #[test]
    fn the_shared_check_applies_no_count_cap() {
        let ids: Vec<String> = (0..MAX_PROVIDER_IDS_PER_CREDENTIAL + 5)
            .map(|i| format!("p{i}"))
            .collect();
        assert!(check_provider_ids(&ids).is_ok());
    }

    #[test]
    fn the_refusal_display_is_the_labelled_wire_text() {
        let error = StoreOpError::InvalidProviderId {
            rule: ProviderIdRule::Count,
            value: "n2".into(),
        };
        assert_eq!(
            error.to_string(),
            "invalid_provider_id/permanent: rule=count value=n2"
        );
        assert_eq!(error.wire_code(), Some("invalid_provider_id"));
        assert_eq!(error.wire_class(), Some("permanent"));
        let empty = StoreOpError::InvalidProviderId {
            rule: ProviderIdRule::Charset,
            value: String::new(),
        };
        assert_eq!(
            empty.to_string(),
            "invalid_provider_id/permanent: rule=charset value="
        );
    }
}
