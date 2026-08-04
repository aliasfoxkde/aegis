//! Risk classification utilities

use serde::{Deserialize, Serialize};

/// Risk classification with action items
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskClassification {
    /// Risk level
    pub level: super::RiskLevel,
    /// Risk category
    pub category: RiskCategory,
    /// Recommended action
    pub action: RecommendedAction,
    /// Priority (1-5, 1 being highest)
    pub priority: u8,
}

/// Risk categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCategory {
    /// Secrets and credentials
    Secrets,
    /// Security vulnerabilities
    Security,
    /// Code quality issues
    CodeQuality,
    /// Performance issues
    Performance,
    /// Compliance concerns
    Compliance,
    /// Configuration issues
    Configuration,
    /// Informational
    Informational,
}

impl RiskCategory {
    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            RiskCategory::Secrets => "Secrets & Credentials",
            RiskCategory::Security => "Security Vulnerabilities",
            RiskCategory::CodeQuality => "Code Quality",
            RiskCategory::Performance => "Performance",
            RiskCategory::Compliance => "Compliance",
            RiskCategory::Configuration => "Configuration",
            RiskCategory::Informational => "Informational",
        }
    }
}

/// Recommended actions based on risk
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAction {
    /// No action needed
    None,
    /// Review and fix before merge
    Review,
    /// Fix immediately
    Fix,
    /// Block and escalate
    Block,
    /// Security review required
    SecurityReview,
    /// Compliance review required
    ComplianceReview,
}

impl RecommendedAction {
    /// Get action description
    pub fn description(&self) -> &'static str {
        match self {
            RecommendedAction::None => "No action required",
            RecommendedAction::Review => "Review and address before merging",
            RecommendedAction::Fix => "Fix immediately",
            RecommendedAction::Block => "Block deployment and escalate",
            RecommendedAction::SecurityReview => "Requires security team review",
            RecommendedAction::ComplianceReview => "Requires compliance team review",
        }
    }
}

impl RiskClassification {
    /// Classify a risk level and category
    pub fn new(level: super::RiskLevel, category: RiskCategory) -> Self {
        let action = match (level, category) {
            (super::RiskLevel::None, _) => RecommendedAction::None,
            (super::RiskLevel::Low, RiskCategory::Secrets) => RecommendedAction::Review,
            (super::RiskLevel::Low, _) => RecommendedAction::None,
            (super::RiskLevel::Medium, RiskCategory::Secrets) => RecommendedAction::Fix,
            (super::RiskLevel::Medium, RiskCategory::Security) => RecommendedAction::Fix,
            (super::RiskLevel::Medium, RiskCategory::Compliance) => {
                RecommendedAction::ComplianceReview
            }
            (super::RiskLevel::Medium, _) => RecommendedAction::Review,
            (super::RiskLevel::High, RiskCategory::Secrets) => RecommendedAction::Block,
            (super::RiskLevel::High, RiskCategory::Security) => RecommendedAction::Block,
            (super::RiskLevel::High, RiskCategory::Compliance) => {
                RecommendedAction::ComplianceReview
            }
            (super::RiskLevel::High, _) => RecommendedAction::Fix,
            (super::RiskLevel::Critical, _) => RecommendedAction::Block,
        };

        let priority = match level {
            super::RiskLevel::None => 5,
            super::RiskLevel::Low => 4,
            super::RiskLevel::Medium => 3,
            super::RiskLevel::High => 2,
            super::RiskLevel::Critical => 1,
        };

        Self {
            level,
            category,
            action,
            priority,
        }
    }

    /// Get action description
    pub fn action_description(&self) -> &'static str {
        self.action.description()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_low_secrets() {
        let classification =
            RiskClassification::new(super::super::RiskLevel::Low, RiskCategory::Secrets);
        assert_eq!(classification.action, RecommendedAction::Review);
        assert_eq!(classification.priority, 4);
    }

    #[test]
    fn test_critical_any() {
        let classification =
            RiskClassification::new(super::super::RiskLevel::Critical, RiskCategory::CodeQuality);
        assert_eq!(classification.action, RecommendedAction::Block);
        assert_eq!(classification.priority, 1);
    }

    #[test]
    fn test_medium_compliance() {
        let classification =
            RiskClassification::new(super::super::RiskLevel::Medium, RiskCategory::Compliance);
        assert_eq!(classification.action, RecommendedAction::ComplianceReview);
    }
}
