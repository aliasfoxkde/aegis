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

    #[test]
    fn test_none_level_any_category() {
        for cat in &[RiskCategory::Secrets, RiskCategory::Security, RiskCategory::CodeQuality,
                     RiskCategory::Performance, RiskCategory::Compliance, RiskCategory::Configuration,
                     RiskCategory::Informational] {
            let classification = RiskClassification::new(super::super::RiskLevel::None, *cat);
            assert_eq!(classification.action, RecommendedAction::None);
            assert_eq!(classification.priority, 5);
        }
    }

    #[test]
    fn test_low_non_secrets() {
        for cat in &[RiskCategory::Security, RiskCategory::CodeQuality, RiskCategory::Performance,
                     RiskCategory::Compliance, RiskCategory::Configuration, RiskCategory::Informational] {
            let classification = RiskClassification::new(super::super::RiskLevel::Low, *cat);
            assert_eq!(classification.action, RecommendedAction::None);
            assert_eq!(classification.priority, 4);
        }
    }

    #[test]
    fn test_medium_secrets_and_security() {
        let classification = RiskClassification::new(super::super::RiskLevel::Medium, RiskCategory::Secrets);
        assert_eq!(classification.action, RecommendedAction::Fix);
        assert_eq!(classification.priority, 3);

        let classification = RiskClassification::new(super::super::RiskLevel::Medium, RiskCategory::Security);
        assert_eq!(classification.action, RecommendedAction::Fix);
    }

    #[test]
    fn test_medium_default_review() {
        for cat in &[RiskCategory::CodeQuality, RiskCategory::Performance,
                     RiskCategory::Configuration, RiskCategory::Informational] {
            let classification = RiskClassification::new(super::super::RiskLevel::Medium, *cat);
            assert_eq!(classification.action, RecommendedAction::Review);
            assert_eq!(classification.priority, 3);
        }
    }

    #[test]
    fn test_high_secrets_and_security_block() {
        let classification = RiskClassification::new(super::super::RiskLevel::High, RiskCategory::Secrets);
        assert_eq!(classification.action, RecommendedAction::Block);
        assert_eq!(classification.priority, 2);

        let classification = RiskClassification::new(super::super::RiskLevel::High, RiskCategory::Security);
        assert_eq!(classification.action, RecommendedAction::Block);
    }

    #[test]
    fn test_high_compliance_review() {
        let classification = RiskClassification::new(super::super::RiskLevel::High, RiskCategory::Compliance);
        assert_eq!(classification.action, RecommendedAction::ComplianceReview);
    }

    #[test]
    fn test_high_default_fix() {
        for cat in &[RiskCategory::CodeQuality, RiskCategory::Performance,
                     RiskCategory::Configuration, RiskCategory::Informational] {
            let classification = RiskClassification::new(super::super::RiskLevel::High, *cat);
            assert_eq!(classification.action, RecommendedAction::Fix);
            assert_eq!(classification.priority, 2);
        }
    }

    #[test]
    fn test_risk_category_display_name() {
        assert_eq!(RiskCategory::Secrets.display_name(), "Secrets & Credentials");
        assert_eq!(RiskCategory::Security.display_name(), "Security Vulnerabilities");
        assert_eq!(RiskCategory::CodeQuality.display_name(), "Code Quality");
        assert_eq!(RiskCategory::Performance.display_name(), "Performance");
        assert_eq!(RiskCategory::Compliance.display_name(), "Compliance");
        assert_eq!(RiskCategory::Configuration.display_name(), "Configuration");
        assert_eq!(RiskCategory::Informational.display_name(), "Informational");
    }

    #[test]
    fn test_recommended_action_description() {
        assert_eq!(RecommendedAction::None.description(), "No action required");
        assert_eq!(RecommendedAction::Review.description(), "Review and address before merging");
        assert_eq!(RecommendedAction::Fix.description(), "Fix immediately");
        assert_eq!(RecommendedAction::Block.description(), "Block deployment and escalate");
        assert_eq!(RecommendedAction::SecurityReview.description(), "Requires security team review");
        assert_eq!(RecommendedAction::ComplianceReview.description(), "Requires compliance team review");
    }

    #[test]
    fn test_classification_serialization() {
        let classification = RiskClassification::new(
            super::super::RiskLevel::High,
            RiskCategory::Secrets,
        );
        let json = serde_json::to_string(&classification).unwrap();
        assert!(json.contains("high"));
        assert!(json.contains("secrets"));
    }

    #[test]
    fn test_classification_action_description() {
        let classification = RiskClassification::new(
            super::super::RiskLevel::Critical,
            RiskCategory::Security,
        );
        assert_eq!(classification.action_description(), "Block deployment and escalate");
    }

    #[test]
    fn test_risk_category_serialization() {
        let cat = RiskCategory::Secrets;
        let json = serde_json::to_string(&cat).unwrap();
        assert_eq!(json, "\"secrets\"");
    }

    #[test]
    fn test_recommended_action_serialization() {
        let action = RecommendedAction::Block;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, "\"block\"");
    }
}
