//! Syntax for operator-asserted subscription tiers. Pricing owns the vocabulary;
//! the vault checks only that a tier is a safe, bounded identifier.

pub const MAX_PLAN_TIER_LEN: usize = 32;

pub fn valid_plan_tier(tier: &str) -> bool {
    (1..=MAX_PLAN_TIER_LEN).contains(&tier.len())
        && tier.as_bytes()[0].is_ascii_lowercase()
        && tier
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_tiers_check_syntax_not_a_pricing_vocabulary() {
        for tier in [
            "a",
            "max_5x",
            "pro_200",
            "unrecognised_plan_123",
            &"a".repeat(31),
            &"a".repeat(32),
        ] {
            assert!(valid_plan_tier(tier), "{tier:?}");
        }
        for tier in [
            "",
            "5x",
            "_max",
            "Max",
            "max-5x",
            "a b",
            "a\n",
            "é",
            &"a".repeat(33),
        ] {
            assert!(!valid_plan_tier(tier), "{tier:?}");
        }
    }
}
