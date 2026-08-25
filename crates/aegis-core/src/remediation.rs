//! Guided Remediation Advisor
//!
//! Provides actionable remediation guidance with ROI-based prioritization.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::finding::Finding;
use crate::risk::risk_classification::RiskCategory;
use crate::risk::{RiskClassification, RiskLevel};

/// Remediation advisor for generating fix recommendations
#[derive(Debug, Clone, Default)]
pub struct RemediationAdvisor {
    /// Knowledge base of fix patterns
    fix_patterns: HashMap<String, FixPattern>,
}

impl RemediationAdvisor {
    /// Create a new remediation advisor
    pub fn new() -> Self {
        let mut advisor = Self::default();
        advisor.register_fix_patterns();
        advisor
    }

    /// Register built-in fix patterns
    fn register_fix_patterns(&mut self) {
        // Hardcoded credentials patterns
        self.fix_patterns.insert(
            "hardcoded-credential".to_string(),
            FixPattern {
                pattern_name: "hardcoded-credential".to_string(),
                category: "secrets".to_string(),
                fix_type: FixType::ReplaceWithEnvVar,
                difficulty: FixDifficulty::Easy,
                estimated_minutes: 5,
                estimated_max_minutes: 15,
                steps: vec![
                    "Identify the hardcoded secret in the code".to_string(),
                    "Replace with environment variable lookup using std::env::var() or similar"
                        .to_string(),
                    "Add the secret to your environment configuration (e.g., .env file)"
                        .to_string(),
                    "Update documentation to reflect the new configuration method".to_string(),
                ],
                effort_reducer: Some(
                    "Use secrets management service like HashiCorp Vault or AWS Secrets Manager"
                        .to_string(),
                ),
                reference_urls: vec![
                    "https://docs.docker.com/compose/environment-variables/".to_string(),
                    "https://12factor.net/config".to_string(),
                ],
            },
        );

        // SQL injection patterns
        self.fix_patterns.insert(
            "sql-injection".to_string(),
            FixPattern {
                pattern_name: "sql-injection".to_string(),
                category: "security".to_string(),
                fix_type: FixType::UseParameterizedQuery,
                difficulty: FixDifficulty::Medium,
                estimated_minutes: 30,
                estimated_max_minutes: 120,
                steps: vec![
                    "Identify the vulnerable SQL query construction".to_string(),
                    "Replace string concatenation with parameterized/prepared statements".to_string(),
                    "Validate and sanitize all user inputs".to_string(),
                    "Apply principle of least privilege to database user".to_string(),
                    "Add unit tests for SQL query construction".to_string(),
                ],
                effort_reducer: Some("Use an ORM that handles parameterization automatically".to_string()),
                reference_urls: vec![
                    "https://owasp.org/www-community/attacks/SQL_Injection".to_string(),
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html".to_string(),
                ],
            },
        );

        // Command injection patterns
        self.fix_patterns.insert(
            "command-injection".to_string(),
            FixPattern {
                pattern_name: "command-injection".to_string(),
                category: "security".to_string(),
                fix_type: FixType::EscapeUserInput,
                difficulty: FixDifficulty::Medium,
                estimated_minutes: 15,
                estimated_max_minutes: 60,
                steps: vec![
                    "Identify the vulnerable system/exec call".to_string(),
                    "Avoid shell execution when possible".to_string(),
                    "Use array-based command execution instead of string".to_string(),
                    "Validate input against allowlist patterns".to_string(),
                    "Apply input sanitization".to_string(),
                ],
                effort_reducer: Some(
                    "Use a safe subprocess library that prevents shell injection".to_string(),
                ),
                reference_urls: vec![
                    "https://owasp.org/www-community/attacks/Command_Injection".to_string(),
                    "https://docs.python.org/3/library/shlex.html".to_string(),
                ],
            },
        );

        // Path traversal patterns
        self.fix_patterns.insert(
            "path-traversal".to_string(),
            FixPattern {
                pattern_name: "path-traversal".to_string(),
                category: "security".to_string(),
                fix_type: FixType::ValidateAndCanonicalize,
                difficulty: FixDifficulty::Easy,
                estimated_minutes: 10,
                estimated_max_minutes: 30,
                steps: vec![
                    "Identify the file path construction from user input".to_string(),
                    "Use canonicalize() to resolve symlinks and normalize paths".to_string(),
                    "Validate the resulting path is within expected directory".to_string(),
                    "Use allowlist for permitted file operations".to_string(),
                ],
                effort_reducer: Some("Use a library that handles path validation".to_string()),
                reference_urls: vec![
                    "https://owasp.org/www-community/attacks/Path_Traversal".to_string()
                ],
            },
        );

        // Hardcoded API keys
        self.fix_patterns.insert(
            "hardcoded-api-key".to_string(),
            FixPattern {
                pattern_name: "hardcoded-api-key".to_string(),
                category: "secrets".to_string(),
                fix_type: FixType::UseEnvVarOrSecretsManager,
                difficulty: FixDifficulty::Easy,
                estimated_minutes: 5,
                estimated_max_minutes: 20,
                steps: vec![
                    "Remove the hardcoded API key from source code".to_string(),
                    "Rotate the exposed API key immediately".to_string(),
                    "Add key to environment variables or secrets manager".to_string(),
                    "Update deployment configuration".to_string(),
                    "Implement key rotation strategy".to_string(),
                ],
                effort_reducer: Some("Use a secrets management service for automatic rotation".to_string()),
                reference_urls: vec![
                    "https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions".to_string(),
                ],
            },
        );

        // Insecure random
        self.fix_patterns.insert(
            "insecure-random".to_string(),
            FixPattern {
                pattern_name: "insecure-random".to_string(),
                category: "security".to_string(),
                fix_type: FixType::UseCryptographicallySecure,
                difficulty: FixDifficulty::Medium,
                estimated_minutes: 20,
                estimated_max_minutes: 60,
                steps: vec![
                    "Identify uses of Math.random() or similar insecure functions".to_string(),
                    "Replace with cryptographically secure random number generator".to_string(),
                    "For passwords: use appropriate password generation library".to_string(),
                    "For tokens: use JWT or similar with secure random generation".to_string(),
                ],
                effort_reducer: Some("Use library like OWASP ESAPI for secure random".to_string()),
                reference_urls: vec![
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html".to_string(),
                ],
            },
        );

        // TODO/FIXME comments
        self.fix_patterns.insert(
            "todo-comment".to_string(),
            FixPattern {
                pattern_name: "todo-comment".to_string(),
                category: "code-quality".to_string(),
                fix_type: FixType::AddressTechnicalDebt,
                difficulty: FixDifficulty::Variable,
                estimated_minutes: 30,
                estimated_max_minutes: 480,
                steps: vec![
                    "Review the TODO comment and understand the context".to_string(),
                    "Assess if the task is still relevant".to_string(),
                    "Create a tracking ticket if not already present".to_string(),
                    "Implement the fix or mark as won't-fix with justification".to_string(),
                ],
                effort_reducer: Some(
                    "Prioritize TODOs that block critical functionality".to_string(),
                ),
                reference_urls: vec![],
            },
        );

        // Weak hashing
        self.fix_patterns.insert(
            "weak-hashing".to_string(),
            FixPattern {
                pattern_name: "weak-hashing".to_string(),
                category: "security".to_string(),
                fix_type: FixType::UseStrongerAlgorithm,
                difficulty: FixDifficulty::Medium,
                estimated_minutes: 60,
                estimated_max_minutes: 240,
                steps: vec![
                    "Identify the weak hash function in use (MD5, SHA1, etc.)".to_string(),
                    "Determine the appropriate strong hash for your use case".to_string(),
                    "For passwords: use bcrypt, scrypt, or Argon2".to_string(),
                    "For integrity: use SHA-256 or stronger".to_string(),
                    "Plan migration strategy for existing data".to_string(),
                    "Implement backward-compatible upgrade path".to_string(),
                ],
                effort_reducer: Some("Use a well-maintained library like Argon2".to_string()),
                reference_urls: vec![
                    "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html".to_string(),
                    "https://libsodium.gitbook.io/doc/bindings_for_other_languages".to_string(),
                ],
            },
        );

        // Default credentials
        self.fix_patterns.insert(
            "default-credential".to_string(),
            FixPattern {
                pattern_name: "default-credential".to_string(),
                category: "security".to_string(),
                fix_type: FixType::ChangeDefaultPassword,
                difficulty: FixDifficulty::Easy,
                estimated_minutes: 5,
                estimated_max_minutes: 15,
                steps: vec![
                    "Identify the system using default credentials".to_string(),
                    "Change all default passwords to strong unique values".to_string(),
                    "Document the new credentials in secure secrets manager".to_string(),
                    "Implement password policy enforcement".to_string(),
                ],
                effort_reducer: Some("Use configuration management to enforce changes".to_string()),
                reference_urls: vec![],
            },
        );

        // Debug mode enabled
        self.fix_patterns.insert(
            "debug-mode".to_string(),
            FixPattern {
                pattern_name: "debug-mode".to_string(),
                category: "configuration".to_string(),
                fix_type: FixType::DisableDebugMode,
                difficulty: FixDifficulty::Easy,
                estimated_minutes: 5,
                estimated_max_minutes: 10,
                steps: vec![
                    "Identify debug mode or verbose error logging".to_string(),
                    "Disable debug mode in production configuration".to_string(),
                    "Ensure proper error handling doesn't leak internals".to_string(),
                    "Test the application still works correctly".to_string(),
                ],
                effort_reducer: None,
                reference_urls: vec![
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code".to_string(),
                ],
            },
        );

        // Log injection
        self.fix_patterns.insert(
            "log-injection".to_string(),
            FixPattern {
                pattern_name: "log-injection".to_string(),
                category: "security".to_string(),
                fix_type: FixType::SanitizeLogInput,
                difficulty: FixDifficulty::Easy,
                estimated_minutes: 15,
                estimated_max_minutes: 30,
                steps: vec![
                    "Identify log statements that incorporate user input".to_string(),
                    "Sanitize input by escaping newlines and special characters".to_string(),
                    "Use structured logging that separates metadata".to_string(),
                    "Implement log integrity monitoring".to_string(),
                ],
                effort_reducer: Some(
                    "Use a logging library with built-in sanitization".to_string(),
                ),
                reference_urls: vec![
                    "https://owasp.org/www-community/attacks/Log_Injection".to_string()
                ],
            },
        );

        // Memory leaks (resource not released)
        self.fix_patterns.insert(
            "resource-leak".to_string(),
            FixPattern {
                pattern_name: "resource-leak".to_string(),
                category: "code-quality".to_string(),
                fix_type: FixType::EnsureRelease,
                difficulty: FixDifficulty::Medium,
                estimated_minutes: 30,
                estimated_max_minutes: 120,
                steps: vec![
                    "Identify the resource that is not properly released".to_string(),
                    "Find all exit paths from the function".to_string(),
                    "Ensure release/close is called on all paths".to_string(),
                    "Consider using RAII pattern or defer/finally".to_string(),
                    "Add unit tests for error conditions".to_string(),
                ],
                effort_reducer: Some("Use language idioms like 'drop' in Rust".to_string()),
                reference_urls: vec![],
            },
        );
    }

    /// Get remediation guidance for a finding
    pub fn get_remediation(&self, finding: &Finding) -> Option<Remediation> {
        let fix_pattern = self.fix_patterns.get(&finding.pattern).or_else(|| {
            // Try pattern matching with partial match
            self.fix_patterns.values().find(|fp| {
                finding.pattern.contains(&fp.pattern_name)
                    || fp.pattern_name.contains(&finding.pattern)
            })
        })?;

        let classification = RiskClassification::new(
            self.parse_risk_level(&finding.severity),
            self.parse_risk_category(&finding.category),
        );

        let roi = self.calculate_roi(fix_pattern, &classification);

        Some(Remediation {
            pattern_name: finding.pattern.clone(),
            category: finding.category.clone(),
            severity: finding.severity.clone(),
            confidence: finding.confidence.clone(),
            location: finding.location.clone(),
            fix_pattern: fix_pattern.clone(),
            classification,
            roi,
        })
    }

    /// Get prioritized list of remediations
    pub fn prioritize(&self, findings: &[Finding]) -> Vec<Remediation> {
        let mut remediations: Vec<Remediation> = findings
            .iter()
            .filter_map(|f| self.get_remediation(f))
            .collect();

        // Sort by ROI score (higher is better)
        remediations.sort_by(|a, b| {
            b.roi
                .total_score
                .partial_cmp(&a.roi.total_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        remediations
    }

    /// Calculate ROI for a fix
    fn calculate_roi(
        &self,
        fix: &FixPattern,
        classification: &RiskClassification,
    ) -> RemediationRoi {
        // Impact score: how much risk does fixing remove? (0-100)
        let impact_score = match classification.level {
            RiskLevel::Critical => 100.0,
            RiskLevel::High => 80.0,
            RiskLevel::Medium => 50.0,
            RiskLevel::Low => 25.0,
            RiskLevel::None => 0.0,
        };

        // Effort score: how hard is the fix? (0-100, inverse of time)
        let avg_minutes = (fix.estimated_minutes + fix.estimated_max_minutes) as f64 / 2.0;
        let effort_score = if avg_minutes <= 15.0 {
            100.0
        } else if avg_minutes <= 60.0 {
            75.0
        } else if avg_minutes <= 240.0 {
            50.0
        } else {
            25.0
        };

        // Difficulty multiplier (easier = higher multiplier)
        let difficulty_mult = match fix.difficulty {
            FixDifficulty::Easy => 1.0,
            FixDifficulty::Medium => 0.8,
            FixDifficulty::Hard => 0.6,
            FixDifficulty::Expert => 0.4,
            FixDifficulty::Variable => 0.7,
        };

        // Confidence multiplier (higher detection confidence = more certain fix)
        let confidence_mult = match classification.level {
            RiskLevel::Critical => 1.0,
            RiskLevel::High => 0.95,
            RiskLevel::Medium => 0.85,
            RiskLevel::Low => 0.7,
            RiskLevel::None => 0.5,
        };

        let total_score = impact_score * effort_score / 100.0 * difficulty_mult * confidence_mult;

        RemediationRoi {
            impact_score,
            effort_score,
            difficulty_mult,
            confidence_mult,
            total_score,
            estimated_minutes: fix.estimated_minutes,
            estimated_max_minutes: fix.estimated_max_minutes,
        }
    }

    fn parse_risk_level(&self, severity: &str) -> RiskLevel {
        match severity.to_lowercase().as_str() {
            "critical" => RiskLevel::Critical,
            "high" => RiskLevel::High,
            "medium" | "moderate" => RiskLevel::Medium,
            "low" => RiskLevel::Low,
            _ => RiskLevel::None,
        }
    }

    fn parse_risk_category(&self, category: &str) -> RiskCategory {
        match category.to_lowercase().as_str() {
            "secrets" | "secret" => RiskCategory::Secrets,
            "security" => RiskCategory::Security,
            "code-quality" | "code_quality" | "codequality" => RiskCategory::CodeQuality,
            "performance" => RiskCategory::Performance,
            "compliance" => RiskCategory::Compliance,
            "configuration" | "config" => RiskCategory::Configuration,
            _ => RiskCategory::Informational,
        }
    }
}

/// A remediation recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    /// Pattern name that triggered
    pub pattern_name: String,
    /// Category
    pub category: String,
    /// Severity
    pub severity: String,
    /// Confidence
    pub confidence: String,
    /// Location
    pub location: crate::finding::Location,
    /// Fix pattern from knowledge base
    pub fix_pattern: FixPattern,
    /// Risk classification
    pub classification: RiskClassification,
    /// ROI calculation
    pub roi: RemediationRoi,
}

impl Remediation {
    /// Get a summary of this remediation
    pub fn summary(&self) -> String {
        format!(
            "[{}] {} at {}:{}",
            self.severity.to_uppercase(),
            self.pattern_name,
            self.location.file,
            self.location.line
        )
    }

    /// Get detailed markdown report for this remediation
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str(&format!("## {}\n\n", self.summary()));
        md.push_str(&format!("**Category:** {}  \n", self.category));
        md.push_str(&format!(
            "**Severity:** {}  \n",
            self.severity.to_uppercase()
        ));
        md.push_str(&format!("**Confidence:** {}  \n\n", self.confidence));

        md.push_str("### Risk Impact\n\n");
        md.push_str(&format!(
            "- **Risk Level:** {:?}\n",
            self.classification.level
        ));
        md.push_str(&format!(
            "- **Recommended Action:** {}\n\n",
            self.classification.action.description()
        ));

        md.push_str("### Remediation Details\n\n");
        md.push_str(&format!(
            "- **Fix Type:** {:?}\n",
            self.fix_pattern.fix_type
        ));
        md.push_str(&format!(
            "- **Difficulty:** {:?}\n",
            self.fix_pattern.difficulty
        ));
        md.push_str(&format!(
            "- **Estimated Time:** {} - {} minutes\n\n",
            self.roi.estimated_minutes, self.roi.estimated_max_minutes
        ));

        md.push_str("### Steps to Fix\n\n");
        for (i, step) in self.fix_pattern.steps.iter().enumerate() {
            md.push_str(&format!("{}. {}\n", i + 1, step));
        }

        if let Some(ref effort_reducer) = self.fix_pattern.effort_reducer {
            md.push_str("\n### Effort Reduction Tips\n\n");
            md.push_str(&format!("{}\n", effort_reducer));
        }

        if !self.fix_pattern.reference_urls.is_empty() {
            md.push_str("\n### References\n\n");
            for url in &self.fix_pattern.reference_urls {
                md.push_str(&format!("- {}\n", url));
            }
        }

        md.push_str("\n### ROI Analysis\n\n");
        md.push_str(&format!(
            "- **Impact Score:** {:.0}/100 (risk reduction potential)\n",
            self.roi.impact_score
        ));
        md.push_str(&format!(
            "- **Effort Score:** {:.0}/100 (lower is harder)\n",
            self.roi.effort_score
        ));
        md.push_str(&format!(
            "- **Total ROI Score:** {:.1}/100\n",
            self.roi.total_score
        ));

        md
    }
}

/// ROI calculation for a remediation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationRoi {
    /// Impact score (0-100)
    pub impact_score: f64,
    /// Effort score (0-100, lower = more effort)
    pub effort_score: f64,
    /// Difficulty multiplier
    pub difficulty_mult: f64,
    /// Confidence multiplier
    pub confidence_mult: f64,
    /// Total ROI score (0-100)
    pub total_score: f64,
    /// Estimated minimum minutes
    pub estimated_minutes: u32,
    /// Estimated maximum minutes
    pub estimated_max_minutes: u32,
}

/// Fix pattern from knowledge base
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixPattern {
    /// Pattern name
    pub pattern_name: String,
    /// Category
    pub category: String,
    /// Type of fix
    pub fix_type: FixType,
    /// Difficulty level
    pub difficulty: FixDifficulty,
    /// Estimated minimum minutes
    pub estimated_minutes: u32,
    /// Estimated maximum minutes
    pub estimated_max_minutes: u32,
    /// Steps to fix
    pub steps: Vec<String>,
    /// Tips to reduce effort
    pub effort_reducer: Option<String>,
    /// Reference URLs
    pub reference_urls: Vec<String>,
}

/// Type of fix
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixType {
    /// Replace hardcoded value with environment variable
    ReplaceWithEnvVar,
    /// Use parameterized query
    UseParameterizedQuery,
    /// Escape user input
    EscapeUserInput,
    /// Validate and canonicalize path
    ValidateAndCanonicalize,
    /// Use environment variable or secrets manager
    UseEnvVarOrSecretsManager,
    /// Use cryptographically secure random
    UseCryptographicallySecure,
    /// Address technical debt
    AddressTechnicalDebt,
    /// Use stronger algorithm
    UseStrongerAlgorithm,
    /// Change default password
    ChangeDefaultPassword,
    /// Disable debug mode
    DisableDebugMode,
    /// Sanitize log input
    SanitizeLogInput,
    /// Ensure resource is released
    EnsureRelease,
    /// Other fix type
    Other,
}

/// Difficulty level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixDifficulty {
    /// Easy fix, minimal code change
    Easy,
    /// Medium fix, some refactoring needed
    Medium,
    /// Hard fix, significant changes
    Hard,
    /// Expert fix, requires specialized knowledge
    Expert,
    /// Variable difficulty
    Variable,
}

/// Summary report for all remediations
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemediationReport {
    /// All remediations
    pub remediations: Vec<Remediation>,
    /// Total findings
    pub total_findings: usize,
    /// Unique patterns
    pub unique_patterns: usize,
    /// Total estimated minutes (minimum)
    pub total_estimated_minutes: u64,
    /// Total estimated minutes (maximum)
    pub total_estimated_max_minutes: u64,
}

impl RemediationReport {
    /// Create a new report from findings
    pub fn from_findings(findings: &[Finding], advisor: &RemediationAdvisor) -> Self {
        let remediations = advisor.prioritize(findings);
        let unique_patterns: std::collections::HashSet<_> =
            findings.iter().map(|f| &f.pattern).collect();

        let total_min: u64 = remediations
            .iter()
            .map(|r| r.roi.estimated_minutes as u64)
            .sum();
        let total_max: u64 = remediations
            .iter()
            .map(|r| r.roi.estimated_max_minutes as u64)
            .sum();

        Self {
            total_findings: findings.len(),
            unique_patterns: unique_patterns.len(),
            total_estimated_minutes: total_min,
            total_estimated_max_minutes: total_max,
            remediations,
        }
    }

    /// Generate markdown report
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# Remediation Report\n\n");

        md.push_str("## Summary\n\n");
        md.push_str(&format!("- **Total Findings:** {}\n", self.total_findings));
        md.push_str(&format!(
            "- **Unique Patterns:** {}\n",
            self.unique_patterns
        ));
        md.push_str(&format!(
            "- **Total Estimated Fix Time:** {} - {} minutes\n\n",
            self.total_estimated_minutes, self.total_estimated_max_minutes
        ));

        if self.total_findings == 0 {
            md.push_str("No findings to remediate.\n");
            return md;
        }

        md.push_str("## Priority Remediations\n\n");
        md.push_str(
            "Remediations are sorted by ROI (Impact x Effort x Difficulty x Confidence).\n\n",
        );

        for (i, rem) in self.remediations.iter().enumerate() {
            md.push_str(&format!("### {}. {}\n\n", i + 1, rem.summary()));
            md.push_str(&format!(
                "**ROI Score:** {:.1}/100 | **Difficulty:** {:?} | **Est. Time:** {}-{} min\n\n",
                rem.roi.total_score,
                rem.fix_pattern.difficulty,
                rem.roi.estimated_minutes,
                rem.roi.estimated_max_minutes
            ));
        }

        md.push_str("---\n\n");
        md.push_str("## Detailed Remediation Steps\n\n");

        for rem in &self.remediations {
            md.push_str(&rem.to_markdown());
            md.push('\n');
        }

        md
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Location;

    fn make_test_finding(pattern: &str, category: &str, severity: &str) -> Finding {
        Finding::new(
            pattern,
            category,
            severity,
            "high",
            Location::new("test.rs", 10, 5, "secret = 'abc'"),
            "secret",
            "Test finding",
        )
    }

    #[test]
    fn test_remediation_advisor_new() {
        let advisor = RemediationAdvisor::new();
        assert!(!advisor.fix_patterns.is_empty());
    }

    #[test]
    fn test_get_remediation_hardcoded_credential() {
        let advisor = RemediationAdvisor::new();
        let finding = make_test_finding("hardcoded-credential", "secrets", "high");
        let remediation = advisor.get_remediation(&finding);

        assert!(remediation.is_some());
        let rem = remediation.unwrap();
        assert_eq!(rem.pattern_name, "hardcoded-credential");
        assert_eq!(rem.fix_pattern.fix_type, FixType::ReplaceWithEnvVar);
    }

    #[test]
    fn test_get_remediation_sql_injection() {
        let advisor = RemediationAdvisor::new();
        let finding = make_test_finding("sql-injection", "security", "high");
        let remediation = advisor.get_remediation(&finding);

        assert!(remediation.is_some());
        let rem = remediation.unwrap();
        assert_eq!(rem.pattern_name, "sql-injection");
        assert!(!rem.fix_pattern.steps.is_empty());
    }

    #[test]
    fn test_prioritize_by_roi() {
        let advisor = RemediationAdvisor::new();
        let findings = vec![
            make_test_finding("hardcoded-credential", "secrets", "high"),
            make_test_finding("sql-injection", "security", "critical"),
        ];

        let prioritized = advisor.prioritize(&findings);
        assert_eq!(prioritized.len(), 2);
        // High ROI (easy fix) should come first even if high severity
        // hardcoded-credential: 80 impact * 100 effort * 1.0 difficulty * 0.95 confidence = 76
        // sql-injection: 100 impact * 75 effort * 0.8 difficulty * 1.0 confidence = 60
        assert_eq!(prioritized[0].pattern_name, "hardcoded-credential");
    }

    #[test]
    fn test_roi_calculation_high_impact_easy_fix() {
        let advisor = RemediationAdvisor::new();
        let finding = make_test_finding("hardcoded-credential", "secrets", "high");
        let rem = advisor.get_remediation(&finding).unwrap();

        // High impact (80), Easy (100), Easy difficulty (1.0), High confidence (0.95)
        // Total: 80 * 100/100 * 1.0 * 0.95 = 76
        assert!(rem.roi.total_score > 70.0);
    }

    #[test]
    fn test_roi_calculation_low_impact_hard_fix() {
        let advisor = RemediationAdvisor::new();
        let finding = make_test_finding("weak-hashing", "security", "medium");
        let rem = advisor.get_remediation(&finding).unwrap();

        // Medium impact (50), Hard effort (50), Medium difficulty (0.8), Medium confidence (0.85)
        // Total: 50 * 50/100 * 0.8 * 0.85 = 17
        assert!(rem.roi.total_score < 20.0);
    }

    #[test]
    fn test_remediation_summary() {
        let advisor = RemediationAdvisor::new();
        let finding = make_test_finding("hardcoded-credential", "secrets", "high");
        let rem = advisor.get_remediation(&finding).unwrap();

        let summary = rem.summary();
        assert!(summary.contains("hardcoded-credential"));
        assert!(summary.contains("test.rs"));
    }

    #[test]
    fn test_remediation_to_markdown() {
        let advisor = RemediationAdvisor::new();
        let finding = make_test_finding("hardcoded-credential", "secrets", "high");
        let rem = advisor.get_remediation(&finding).unwrap();

        let md = rem.to_markdown();
        assert!(md.contains("## [HIGH]"));
        assert!(md.contains("Steps to Fix"));
        assert!(md.contains("Estimated Time"));
        assert!(md.contains("ROI Analysis"));
    }

    #[test]
    fn test_remediation_report() {
        let advisor = RemediationAdvisor::new();
        let findings = vec![
            make_test_finding("hardcoded-credential", "secrets", "high"),
            make_test_finding("sql-injection", "security", "critical"),
            make_test_finding("debug-mode", "configuration", "low"),
        ];

        let report = RemediationReport::from_findings(&findings, &advisor);
        assert_eq!(report.total_findings, 3);
        assert_eq!(report.unique_patterns, 3);
        assert!(report.total_estimated_minutes > 0);
    }

    #[test]
    fn test_remediation_report_markdown() {
        let advisor = RemediationAdvisor::new();
        let findings = vec![make_test_finding("hardcoded-credential", "secrets", "high")];

        let report = RemediationReport::from_findings(&findings, &advisor);
        let md = report.to_markdown();

        assert!(md.contains("Remediation Report"));
        assert!(md.contains("Total Findings"));
        assert!(md.contains("Priority Remediations"));
    }

    #[test]
    fn test_fix_pattern_unknown_pattern() {
        let advisor = RemediationAdvisor::new();
        let finding = make_test_finding("unknown-pattern", "misc", "medium");
        let remediation = advisor.get_remediation(&finding);

        // Unknown patterns should return None
        assert!(remediation.is_none());
    }

    #[test]
    fn test_fix_type_display() {
        assert_eq!(
            format!("{:?}", FixType::ReplaceWithEnvVar),
            "ReplaceWithEnvVar"
        );
        assert_eq!(
            format!("{:?}", FixType::UseParameterizedQuery),
            "UseParameterizedQuery"
        );
    }

    #[test]
    fn test_fix_difficulty_display() {
        assert_eq!(format!("{:?}", FixDifficulty::Easy), "Easy");
        assert_eq!(format!("{:?}", FixDifficulty::Hard), "Hard");
    }
}
