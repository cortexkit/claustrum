//! Hub counters preserve their wire representation as well as their numeric range.
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// A login-list generation is a positive SQLite integer, encoded as a JSON string
/// because a JavaScript number cannot represent every generation exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HubGeneration(i64);

impl HubGeneration {
    pub const FIRST: Self = Self(1);

    pub fn new(value: i64) -> Option<Self> {
        (value > 0).then_some(Self(value))
    }

    pub fn get(self) -> i64 {
        self.0
    }

    pub fn checked_next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

impl Serialize for HubGeneration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for HubGeneration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.starts_with('0') || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(de::Error::custom("noncanonical login generation"));
        }
        value
            .parse::<i64>()
            .ok()
            .and_then(Self::new)
            .ok_or_else(|| de::Error::custom("login generation out of range"))
    }
}

pub const MAX_HUB_REPORT_SEQ: i64 = 9_007_199_254_740_991;

/// A manifest report sequence is an integer token that fits exactly in a
/// JavaScript number. Deserialize as an integer, not via a floating-point value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HubReportSeq(i64);

impl HubReportSeq {
    pub const FIRST: Self = Self(1);

    pub fn new(value: i64) -> Option<Self> {
        (1..=MAX_HUB_REPORT_SEQ)
            .contains(&value)
            .then_some(Self(value))
    }

    pub fn get(self) -> i64 {
        self.0
    }

    pub fn checked_next(self) -> Option<Self> {
        Self::new(self.0 + 1)
    }
}

impl Serialize for HubReportSeq {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(self.0)
    }
}

impl<'de> Deserialize<'de> for HubReportSeq {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(i64::deserialize(deserializer)?)
            .ok_or_else(|| de::Error::custom("manifest report seq out of range"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hub_generation_requires_a_canonical_positive_i64_string() {
        for (wire, expected) in [("\"1\"", 1), ("\"9223372036854775807\"", i64::MAX)] {
            let generation: HubGeneration = serde_json::from_str(wire).unwrap();
            assert_eq!(generation.get(), expected);
            assert_eq!(serde_json::to_string(&generation).unwrap(), wire);
        }
        for wire in [
            "1",
            "\"0\"",
            "\"01\"",
            "\"-1\"",
            "\"+1\"",
            "\"\"",
            "\"1e0\"",
            "\"１\"",
            "\"9223372036854775808\"",
        ] {
            assert!(
                serde_json::from_str::<HubGeneration>(wire).is_err(),
                "{wire}"
            );
        }
        assert_eq!(HubGeneration::new(i64::MAX).unwrap().checked_next(), None);
    }

    #[test]
    fn hub_report_seq_requires_a_positive_safe_integer_token() {
        for (wire, expected) in [("1", 1), ("9007199254740991", 9_007_199_254_740_991)] {
            let seq: HubReportSeq = serde_json::from_str(wire).unwrap();
            assert_eq!(seq.get(), expected);
            assert_eq!(serde_json::to_string(&seq).unwrap(), wire);
        }
        for wire in [
            "9007199254740992",
            "\"1\"",
            "1.0",
            "1.5",
            "1e0",
            "1E+0",
            "0",
            "-1",
            "+1",
            "01",
        ] {
            assert!(
                serde_json::from_str::<HubReportSeq>(wire).is_err(),
                "{wire}"
            );
        }
        assert_eq!(
            HubReportSeq::new(9_007_199_254_740_991)
                .unwrap()
                .checked_next(),
            None
        );
    }
}
