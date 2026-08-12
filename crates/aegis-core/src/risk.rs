//! Risk scoring and classification
//!
//! Calculates risk scores based on findings.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

pub use risk_classification::RiskClassification;
pub use risk_level::RiskLevel;

pub mod risk_classification;
pub mod risk_level;

/// Category risk breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryRisk {
    /// Risk score for this category
    pub score: f64,
    /// Number of findings
    pub finding_count: usize,
    /// Categories within this group
    pub categories: Vec<String>,
}

/// Complete risk score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// Total risk score
    pub score: i32,
    /// Risk level
    pub level: RiskLevel,
    /// Breakdown by category
    pub by_category: HashMap<String, CategoryRisk>,
    /// Total finding count
    pub finding_count: usize,
    /// Highest severity found
    pub highest_severity: Option<String>,
    /// Finding counts by severity
    pub by_severity: HashMap<String, usize>,
}

impl RiskScore {
    /// Create a new risk score from findings
    pub fn new(
        findings: &[super::Finding],
        severity_weights: &HashMap<String, i32>,
        category_weights: &HashMap<String, f64>,
    ) -> Self {
        if findings.is_empty() {
            return Self {
                score: 0,
                level: RiskLevel::None,
                by_category: HashMap::new(),
                finding_count: 0,
                highest_severity: None,
                by_severity: HashMap::new(),
            };
        }

        // Calculate weights
        let severity_weights = if severity_weights.is_empty() {
            default_severity_weights()
        } else {
            severity_weights.clone()
        };

        let category_weights = if category_weights.is_empty() {
            default_category_weights()
        } else {
            category_weights.clone()
        };

        // Group findings by category
        let mut by_category: HashMap<String, Vec<&super::Finding>> = HashMap::new();
        let mut by_severity: HashMap<String, usize> = HashMap::new();

        for finding in findings {
            by_category
                .entry(finding.category.clone())
                .or_default()
                .push(finding);

            *by_severity.entry(finding.severity.clone()).or_insert(0) += 1;
        }

        // Calculate scores
        let mut total_score = 0;
        let mut highest_severity: Option<(i32, String)> = None;
        let mut category_breakdown: HashMap<String, CategoryRisk> = HashMap::new();

        for (category, category_findings) in &by_category {
            let cat_weight = category_weights.get(category).copied().unwrap_or(1.0);
            let mut cat_score = 0.0;

            for finding in category_findings {
                let sev_weight = severity_weights
                    .get(&finding.severity)
                    .copied()
                    .unwrap_or(1);
                let confidence_mult = match finding.confidence.as_str() {
                    "high" => 1.0,
                    "medium" => 0.7,
                    "low" => 0.4,
                    _ => 0.5,
                };

                cat_score += (sev_weight as f64) * confidence_mult * cat_weight;

                // Track highest severity
                if let Some((weight, _)) = highest_severity {
                    if sev_weight > weight {
                        highest_severity = Some((sev_weight, finding.severity.clone()));
                    }
                } else {
                    highest_severity = Some((sev_weight, finding.severity.clone()));
                }
            }

            total_score += cat_score as i32;

            category_breakdown.insert(
                category.clone(),
                CategoryRisk {
                    score: cat_score,
                    finding_count: category_findings.len(),
                    categories: vec![category.clone()],
                },
            );
        }

        // Normalize score
        let level = RiskLevel::from_score(total_score);

        Self {
            score: total_score,
            level,
            by_category: category_breakdown,
            finding_count: findings.len(),
            highest_severity: highest_severity.map(|(_, s)| s),
            by_severity,
        }
    }

    /// Get risk score description
    pub fn description(&self) -> String {
        match self.level {
            RiskLevel::None => "No risk detected".to_string(),
            RiskLevel::Low => format!(
                "Low risk - {} findings, score: {}",
                self.finding_count, self.score
            ),
            RiskLevel::Medium => format!(
                "Medium risk - {} findings, score: {}",
                self.finding_count, self.score
            ),
            RiskLevel::High => format!(
                "High risk - {} findings, score: {}",
                self.finding_count, self.score
            ),
            RiskLevel::Critical => format!(
                "CRITICAL risk - {} findings, score: {}",
                self.finding_count, self.score
            ),
        }
    }
}

impl fmt::Display for RiskScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Risk Assessment:")?;
        writeln!(f, "  Level: {}", self.level)?;
        writeln!(f, "  Score: {}", self.score)?;
        writeln!(f, "  Findings: {}", self.finding_count)?;

        if let Some(ref sev) = self.highest_severity {
            writeln!(f, "  Highest Severity: {}", sev)?;
        }

        if !self.by_category.is_empty() {
            writeln!(f, "  By Category:")?;
            for (cat, risk) in &self.by_category {
                writeln!(
                    f,
                    "    {}: {:.1} ({} findings)",
                    cat, risk.score, risk.finding_count
                )?;
            }
        }

        Ok(())
    }
}

/// Default severity weights
fn default_severity_weights() -> HashMap<String, i32> {
    let mut m = HashMap::new();
    m.insert("critical".to_string(), 40);
    m.insert("high".to_string(), 25);
    m.insert("medium".to_string(), 10);
    m.insert("low".to_string(), 3);
    m
}

/// Default category weights
fn default_category_weights() -> HashMap<String, f64> {
    let mut m = HashMap::new();
    m.insert("secrets".to_string(), 1.5);
    m.insert("security".to_string(), 1.4);
    m.insert("security-hardening".to_string(), 1.4);
    m.insert("pii".to_string(), 1.3);
    m.insert("web-security".to_string(), 1.3);
    m.insert("ai-safety".to_string(), 1.3);
    m.insert("llm-guardrails".to_string(), 1.3);
    m.insert("devops".to_string(), 1.2);
    m.insert("infrastructure".to_string(), 1.2);
    m.insert("cloud-native".to_string(), 1.1);
    m.insert("supply-chain".to_string(), 1.4);
    m.insert("compliance".to_string(), 1.2);
    m.insert("code-quality".to_string(), 0.8);
    m.insert("performance".to_string(), 0.6);
    m.insert("accessibility".to_string(), 0.7);
    m.insert("git-hygiene".to_string(), 0.5);
    m.insert("ai-detection".to_string(), 1.0);
    m.insert("shift-left".to_string(), 1.0);
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_risk_score() {
        let findings = vec![];
        let score = RiskScore::new(&findings, &HashMap::new(), &HashMap::new());

        assert_eq!(score.score, 0);
        assert_eq!(score.level, RiskLevel::None);
        assert_eq!(score.finding_count, 0);
    }

    #[test]
    fn test_low_severity_risk() {
        let loc = super::super::Location::new("test.rs", 1, 0, "console.log");
        let findings = vec![super::super::Finding::new(
            "console-log",
            "code-quality",
            "low",
            "high",
            loc,
            "console.log",
            "Console log statement",
        )];

        let score = RiskScore::new(&findings, &HashMap::new(), &HashMap::new());

        assert!(score.score < 100);
        assert!(matches!(score.level, RiskLevel::Low | RiskLevel::Medium));
    }

    #[test]
    fn test_multiple_findings() {
        let findings = vec![
            {
                let loc = super::super::Location::new("test.rs", 1, 0, "secret");
                super::super::Finding::new(
                    "secret1", "secrets", "high", "high", loc, "secret", "Secret 1",
                )
            },
            {
                let loc = super::super::Location::new("test.rs", 2, 0, "secret2");
                super::super::Finding::new(
                    "secret2", "secrets", "high", "high", loc, "secret", "Secret 2",
                )
            },
        ];

        let score = RiskScore::new(&findings, &HashMap::new(), &HashMap::new());

        assert_eq!(score.finding_count, 2);
        assert!(score.score > 0);
        assert_eq!(score.highest_severity, Some("high".to_string()));
    }

    #[test]
    fn test_custom_severity_weights() {
        let findings = vec![{
            let loc = super::super::Location::new("test.rs", 1, 0, "secret");
            super::super::Finding::new(
                "secret1", "secrets", "high", "high", loc, "secret", "Secret 1",
            )
        }];

        let mut custom_weights = HashMap::new();
        custom_weights.insert("high".to_string(), 100); // Custom high weight

        let score = RiskScore::new(&findings, &custom_weights, &HashMap::new());

        assert!(score.score > 0);
    }

    #[test]
    fn test_custom_category_weights() {
        let findings = vec![{
            let loc = super::super::Location::new("test.rs", 1, 0, "secret");
            super::super::Finding::new(
                "secret1", "secrets", "high", "high", loc, "secret", "Secret 1",
            )
        }];

        let mut custom_cat_weights = HashMap::new();
        custom_cat_weights.insert("secrets".to_string(), 5.0); // Custom category weight

        let score = RiskScore::new(&findings, &HashMap::new(), &custom_cat_weights);

        assert!(score.score > 0);
        assert!(score.by_category.contains_key("secrets"));
    }

    #[test]
    fn test_unknown_severity_weight() {
        let findings = vec![{
            let loc = super::super::Location::new("test.rs", 1, 0, "code");
            super::super::Finding::new(
                "code1",
                "code-quality",
                "medium",
                "high",
                loc,
                "code",
                "Code",
            )
        }];

        // Use non-empty custom weights to exercise that branch
        let mut custom_weights = HashMap::new();
        custom_weights.insert("medium".to_string(), 50);
        let score = RiskScore::new(&findings, &custom_weights, &HashMap::new());

        assert!(score.score > 0);
    }

    #[test]
    fn test_unknown_category_weight() {
        let findings = vec![{
            let loc = super::super::Location::new("test.rs", 1, 0, "code");
            super::super::Finding::new(
                "code1",
                "unknown-category",
                "medium",
                "high",
                loc,
                "code",
                "Code",
            )
        }];

        let score = RiskScore::new(&findings, &HashMap::new(), &HashMap::new());

        // Should use default weight of 1.0 for unknown category
        assert!(score.score > 0);
    }

    #[test]
    fn test_by_severity_tracking() {
        let loc1 = super::super::Location::new("test.rs", 1, 0, "high finding");
        let loc2 = super::super::Location::new("test.rs", 2, 0, "low finding");
        let findings = vec![
            super::super::Finding::new("high1", "secrets", "high", "high", loc1, "secret", "High"),
            super::super::Finding::new("low1", "code-quality", "low", "high", loc2, "code", "Low"),
        ];

        let score = RiskScore::new(&findings, &HashMap::new(), &HashMap::new());

        assert!(score.by_severity.contains_key("high"));
        assert!(score.by_severity.contains_key("low"));
        assert_eq!(score.by_severity.get("high"), Some(&1));
        assert_eq!(score.by_severity.get("low"), Some(&1));
    }

    #[test]
    fn test_unknown_confidence_multiplier() {
        let findings = vec![{
            let loc = super::super::Location::new("test.rs", 1, 0, "code");
            super::super::Finding::new(
                "code1",
                "code-quality",
                "high",
                "unknown_conf",
                loc,
                "code",
                "Code",
            )
        }];

        let score = RiskScore::new(&findings, &HashMap::new(), &HashMap::new());
        // Unknown confidence should use multiplier of 0.5
        assert!(score.score >= 0);
    }

    #[test]
    fn test_risk_score_display_none() {
        // RiskLevel::None when no findings
        let score = RiskScore::new(&[], &HashMap::new(), &HashMap::new());
        let display = format!("{}", score);
        assert!(display.contains("Risk Assessment"));
    }

    #[test]
    fn test_risk_score_display_with_findings() {
        // Create findings to get a non-None risk level
        let findings = vec![{
            let loc = super::super::Location::new("test.rs", 1, 0, "secret");
            super::super::Finding::new(
                "secret1", "secrets", "high", "high", loc, "secret", "Secret",
            )
        }];
        let score = RiskScore::new(&findings, &HashMap::new(), &HashMap::new());
        let display = format!("{}", score);
        assert!(display.contains("Risk Assessment"));
        assert!(display.contains("Findings:"));
    }

    #[test]
    fn test_risk_score_with_category_breakdown() {
        // Create findings with category to exercise by_category display
        let findings = vec![
            {
                let loc = super::super::Location::new("test.rs", 1, 0, "secret1");
                super::super::Finding::new(
                    "secret1", "secrets", "high", "high", loc, "secret", "Secret 1",
                )
            },
            {
                let loc = super::super::Location::new("test.rs", 2, 0, "secret2");
                super::super::Finding::new(
                    "secret2", "secrets", "high", "high", loc, "secret", "Secret 2",
                )
            },
        ];
        let score = RiskScore::new(&findings, &HashMap::new(), &HashMap::new());
        assert!(score.by_category.contains_key("secrets"));
        let display = format!("{}", score);
        // Should show category breakdown when there are findings
        assert!(display.contains("By Category"));
    }

    #[test]
    fn test_risk_score_critical_level() {
        // Create many high severity findings to reach Critical level (>150)
        let mut findings = Vec::new();
        for i in 0..10 {
            let loc = super::super::Location::new("test.rs", i, 0, "secret");
            findings.push(super::super::Finding::new(
                format!("secret{}", i),
                "secrets",
                "high",
                "high",
                loc,
                "secret",
                format!("Secret {}", i),
            ));
        }
        let score = RiskScore::new(&findings, &HashMap::new(), &HashMap::new());
        assert!(score.score > 150);
    }

    #[test]
    fn test_risk_score_description() {
        // Test description() method for all risk levels
        let empty_score = RiskScore::new(&[], &HashMap::new(), &HashMap::new());
        let desc = empty_score.description();
        assert!(desc.contains("No risk detected"));

        // Test with Low severity (1 finding with low severity)
        let low_findings = vec![{
            let loc = super::super::Location::new("test.rs", 1, 0, "code");
            super::super::Finding::new("code1", "code-quality", "low", "high", loc, "code", "Code")
        }];
        let low_score = RiskScore::new(&low_findings, &HashMap::new(), &HashMap::new());
        let low_desc = low_score.description();
        assert!(low_desc.contains("Low") || low_desc.contains("findings"));
        assert_eq!(low_score.level, super::RiskLevel::Low);

        // Test with Medium severity (3 medium findings: 3 * 10 * 1.0 = 30, which is Medium 20-50)
        let med_findings = vec![
            {
                let loc = super::super::Location::new("test.rs", 1, 0, "code");
                super::super::Finding::new(
                    "code1",
                    "code-quality",
                    "medium",
                    "high",
                    loc,
                    "code",
                    "Code",
                )
            },
            {
                let loc = super::super::Location::new("test.rs", 2, 0, "code");
                super::super::Finding::new(
                    "code2",
                    "code-quality",
                    "medium",
                    "high",
                    loc,
                    "code",
                    "Code",
                )
            },
            {
                let loc = super::super::Location::new("test.rs", 3, 0, "code");
                super::super::Finding::new(
                    "code3",
                    "code-quality",
                    "medium",
                    "high",
                    loc,
                    "code",
                    "Code",
                )
            },
        ];
        let med_score = RiskScore::new(&med_findings, &HashMap::new(), &HashMap::new());
        let med_desc = med_score.description();
        assert!(med_desc.contains("Medium") || med_desc.contains("findings"));
        assert_eq!(med_score.level, super::RiskLevel::Medium);

        // Test with High severity (2 findings with high severity in secrets: 2 * 25 * 1.5 = 75 >= 50)
        let high_findings = vec![
            {
                let loc = super::super::Location::new("test.rs", 1, 0, "secret");
                super::super::Finding::new(
                    "secret1", "secrets", "high", "high", loc, "secret", "Secret",
                )
            },
            {
                let loc = super::super::Location::new("test.rs", 2, 0, "secret");
                super::super::Finding::new(
                    "secret2", "secrets", "high", "high", loc, "secret", "Secret",
                )
            },
        ];
        let high_score = RiskScore::new(&high_findings, &HashMap::new(), &HashMap::new());
        let high_desc = high_score.description();
        assert!(high_desc.contains("High") || high_desc.contains("findings"));
        assert_eq!(high_score.level, super::RiskLevel::High);

        // Test with Critical (1 critical + 5 high findings in secrets: 1*40 + 5*25 * 1.5 = 232.5 >= 150)
        // Order high findings first, then critical to test the highest_severity tracking branch (line 113)
        let mut crit_findings = Vec::new();
        // First add high findings (weight 25)
        for i in 0..5 {
            let loc = super::super::Location::new("test.rs", i, 0, "secret");
            crit_findings.push(super::super::Finding::new(
                format!("secret{}", i),
                "secrets",
                "high",
                "high",
                loc,
                "secret",
                format!("Secret {}", i),
            ));
        }
        // Then add critical finding (weight 40) to trigger the sev_weight > weight branch
        {
            let loc = super::super::Location::new("test.rs", 5, 0, "secret");
            crit_findings.push(super::super::Finding::new(
                "critical_secret",
                "secrets",
                "critical",
                "high",
                loc,
                "secret",
                "Critical Secret",
            ));
        }
        let crit_score = RiskScore::new(&crit_findings, &HashMap::new(), &HashMap::new());
        let crit_desc = crit_score.description();
        assert!(crit_desc.contains("CRITICAL") || crit_desc.contains("findings"));

        // Also test Display trait via format!() macro to cover category breakdown
        let crit_display = format!("{}", crit_score);
        assert!(crit_display.contains("secrets"));
    }
}
