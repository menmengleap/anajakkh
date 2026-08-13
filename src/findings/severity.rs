//! Finding severity.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Severity of a security finding, ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Informational => "informational",
        }
    }

    /// 0..4 ranking for sorting and aggregation (informational = 0).
    pub fn rank(&self) -> u8 {
        match self {
            Severity::Informational => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" => Ok(Severity::Critical),
            "high" => Ok(Severity::High),
            "medium" | "moderate" => Ok(Severity::Medium),
            "low" => Ok(Severity::Low),
            "informational" | "info" | "none" => Ok(Severity::Informational),
            other => Err(format!("unknown severity `{other}`")),
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_severities_case_insensitively() {
        assert_eq!("critical".parse::<Severity>().unwrap(), Severity::Critical);
        assert_eq!("HIGH".parse::<Severity>().unwrap(), Severity::High);
        assert_eq!("Medium".parse::<Severity>().unwrap(), Severity::Medium);
        assert_eq!("info".parse::<Severity>().unwrap(), Severity::Informational);
        assert!("bogus".parse::<Severity>().is_err());
    }

    #[test]
    fn ordering_is_least_to_most_severe() {
        assert!(Severity::Informational < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
        assert_eq!(Severity::Critical.rank(), 4);
        assert_eq!(Severity::Informational.rank(), 0);
    }

    #[test]
    fn serde_uses_lowercase_names() {
        assert_eq!(
            serde_json::to_string(&Severity::Medium).unwrap(),
            "\"medium\""
        );
        assert_eq!(
            serde_json::from_str::<Severity>("\"high\"").unwrap(),
            Severity::High
        );
    }
}
