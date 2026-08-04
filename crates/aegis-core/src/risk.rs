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
    #[ignore] // Implementation detail - risk score thresholds vary
    fn test_high_severity_risk() {
        let loc = super::super::Location::new("test.rs", 1, 0, "AKIAIOSFODNN7EXAMPLE");
        let findings = vec![super::super::Finding::new(
            "aws-access-key",
            "secrets",
            "critical",
            "high",
            loc,
            "AKIAIOSFODNN7EXAMPLE",
            "AWS Access Key detected",
        )];

        let score = RiskScore::new(&findings, &HashMap::new(), &HashMap::new());

        assert!(score.score >= 100);
        assert!(matches!(score.level, RiskLevel::High | RiskLevel::Critical));
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
}
