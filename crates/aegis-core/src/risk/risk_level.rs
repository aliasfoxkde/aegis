//! Risk level definitions

use serde::{Deserialize, Serialize};

/// Risk level enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    #[default]
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    /// Create from a score
    pub fn from_score(score: i32) -> Self {
        if score == 0 {
            RiskLevel::None
        } else if score < 20 {
            RiskLevel::Low
        } else if score < 50 {
            RiskLevel::Medium
        } else if score < 100 {
            RiskLevel::High
        } else {
            RiskLevel::Critical
        }
    }

    /// Get the numeric value
    pub fn value(&self) -> i32 {
        match self {
            RiskLevel::None => 0,
            RiskLevel::Low => 1,
            RiskLevel::Medium => 2,
            RiskLevel::High => 3,
            RiskLevel::Critical => 4,
        }
    }

    /// Get description
    pub fn description(&self) -> &'static str {
        match self {
            RiskLevel::None => "No risk detected",
            RiskLevel::Low => "Low risk - minor issues",
            RiskLevel::Medium => "Medium risk - moderate issues",
            RiskLevel::High => "High risk - significant issues",
            RiskLevel::Critical => "CRITICAL risk - immediate action required",
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::None => write!(f, "none"),
            RiskLevel::Low => write!(f, "low"),
            RiskLevel::Medium => write!(f, "medium"),
            RiskLevel::High => write!(f, "high"),
            RiskLevel::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for RiskLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(RiskLevel::None),
            "low" => Ok(RiskLevel::Low),
            "medium" | "med" => Ok(RiskLevel::Medium),
            "high" => Ok(RiskLevel::High),
            "critical" | "crit" => Ok(RiskLevel::Critical),
            _ => Err(format!("Unknown risk level: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_score() {
        assert_eq!(RiskLevel::from_score(0), RiskLevel::None);
        assert_eq!(RiskLevel::from_score(10), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(30), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(75), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(150), RiskLevel::Critical);
    }

    #[test]
    fn test_value() {
        assert_eq!(RiskLevel::None.value(), 0);
        assert_eq!(RiskLevel::Low.value(), 1);
        assert_eq!(RiskLevel::Medium.value(), 2);
        assert_eq!(RiskLevel::High.value(), 3);
        assert_eq!(RiskLevel::Critical.value(), 4);
    }

    #[test]
    fn test_parsing() {
        assert_eq!("low".parse::<RiskLevel>().unwrap(), RiskLevel::Low);
        assert_eq!("MEDIUM".parse::<RiskLevel>().unwrap(), RiskLevel::Medium);
        assert_eq!("High".parse::<RiskLevel>().unwrap(), RiskLevel::High);
        assert!("invalid".parse::<RiskLevel>().is_err());
    }

    #[test]
    fn test_display() {
        assert_eq!(RiskLevel::Low.to_string(), "low");
        assert_eq!(RiskLevel::Critical.to_string(), "critical");
    }

    #[test]
    fn test_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn test_parsing_alternatives() {
        // Test alternative spellings
        assert_eq!("med".parse::<RiskLevel>().unwrap(), RiskLevel::Medium);
        assert_eq!("crit".parse::<RiskLevel>().unwrap(), RiskLevel::Critical);
        // Case insensitive
        assert_eq!("NONE".parse::<RiskLevel>().unwrap(), RiskLevel::None);
    }

    #[test]
    fn test_description_all_levels() {
        assert_eq!(RiskLevel::None.description(), "No risk detected");
        assert_eq!(RiskLevel::Low.description(), "Low risk - minor issues");
        assert_eq!(
            RiskLevel::Medium.description(),
            "Medium risk - moderate issues"
        );
        assert_eq!(
            RiskLevel::High.description(),
            "High risk - significant issues"
        );
        assert_eq!(
            RiskLevel::Critical.description(),
            "CRITICAL risk - immediate action required"
        );
    }

    #[test]
    fn test_display_all_levels() {
        assert_eq!(RiskLevel::None.to_string(), "none");
        assert_eq!(RiskLevel::Low.to_string(), "low");
        assert_eq!(RiskLevel::Medium.to_string(), "medium");
        assert_eq!(RiskLevel::High.to_string(), "high");
        assert_eq!(RiskLevel::Critical.to_string(), "critical");
    }

    #[test]
    fn test_default_risk_level() {
        let level = RiskLevel::default();
        assert_eq!(level, RiskLevel::None);
    }
}
