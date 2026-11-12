//! Syntax for operator-asserted subscription tiers. Pricing owns the vocabulary;
//! the vault checks only that a tier is a safe, bounded identifier.

pub const MAX_PLAN_TIER_LEN: usize = 32;
pub const MAX_PLAN_TIER_SINCE_MS: u64 = crate::agent_secret::MAX_SECRET_JSON_INTEGER;

pub fn valid_plan_tier_since_ms(since_ms: u64, now_ms: u64) -> bool {
    (1..=MAX_PLAN_TIER_SINCE_MS).contains(&since_ms) && since_ms <= now_ms
}

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
    fn plan_tier_since_checks_positive_exact_integer_and_now_boundaries() {
        assert!(valid_plan_tier_since_ms(1, 1));
        assert!(!valid_plan_tier_since_ms(0, 1));
        assert!(valid_plan_tier_since_ms(100, 100));
        assert!(!valid_plan_tier_since_ms(101, 100));
        assert!(valid_plan_tier_since_ms(MAX_PLAN_TIER_SINCE_MS, u64::MAX));
        assert!(!valid_plan_tier_since_ms(
            MAX_PLAN_TIER_SINCE_MS + 1,
            u64::MAX
        ));
    }

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
