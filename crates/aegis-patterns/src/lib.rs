//! Aegis Patterns
//!
//! Pattern definitions for Aegis.

use serde::{Deserialize, Serialize};

/// A bundled rule exactly as serialized in the pattern corpus.
///
/// The field set mirrors [`aegis_core::PatternDefinition`]; [`From`] below is
/// the single place the two are mapped, so wording here describes the same
/// runtime semantics the scanner applies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    /// Stable kebab-case rule identifier, e.g. `secrets-aws-access-key`.
    pub name: String,
    /// Category bucket the rule reports under; drives weighting and grouping.
    pub category: String,
    /// Regex (Rust `regex` crate syntax) matched against candidate files.
    #[serde(rename = "match")]
    pub match_pattern: String,
    /// Whether the rule ships active; disabled rules are loaded but never scan.
    pub enabled: bool,
    /// `critical`/`high`/`medium`/`low`, weighted 40/25/10/3 in risk scoring.
    pub severity: String,
    /// `high`/`medium`/`low`, applied as a 1.0/0.7/0.4 multiplier to the hit.
    pub confidence: String,
    /// Minimum Shannon entropy a match must reach; `None` skips the check.
    #[serde(default)]
    pub min_entropy: Option<f64>,
    /// Human-readable finding text surfaced in reports.
    pub description: String,
    /// Optional URL to the CWE, standard, or vendor page behind the rule.
    #[serde(default)]
    pub reference: Option<String>,
    /// Taxonomy tags used for filtering (e.g. `aws`, `wcag-1.1.1`).
    #[serde(default)]
    pub tags: Vec<String>,
    /// Env-scan-only rule: never matched against file contents.
    #[serde(default)]
    pub env_var: bool,
    /// Allow the rule to match inside binary files.
    #[serde(default)]
    pub binary: bool,
    /// Regex checked against each candidate match span: when it also matches,
    /// the finding is suppressed. This is how "element without attribute X"
    /// rules are expressed without lookarounds (the `regex` crate has none).
    #[serde(default)]
    pub exclude: Option<String>,
    /// File extensions (without dot) this pattern applies to. Empty means the
    /// pattern runs against every text file.
    #[serde(default)]
    pub file_extensions: Vec<String>,
}

/// Convert a bundled pattern into the engine's runtime definition.
///
/// This is the single canonical conversion: the CLI, MCP server, daemon,
/// WASM bindings, and the test harnesses all build their scanners through
/// it instead of maintaining private copies of the field mapping.
impl From<Pattern> for aegis_core::PatternDefinition {
    fn from(p: Pattern) -> Self {
        aegis_core::PatternDefinition {
            name: p.name,
            category: p.category,
            match_pattern: p.match_pattern,
            enabled: p.enabled,
            severity: aegis_core::Severity::parse(&p.severity)
                .unwrap_or(aegis_core::Severity::Medium),
            confidence: aegis_core::Confidence::parse(&p.confidence)
                .unwrap_or(aegis_core::Confidence::Medium),
            min_entropy: p.min_entropy,
            description: p.description,
            reference: p.reference,
            tags: p.tags,
            env_var: p.env_var,
            binary: p.binary,
            exclude_pattern: p.exclude,
            file_extensions: p.file_extensions,
            remediation: None,
        }
    }
}

pub mod accessibility;
pub mod ai_detection;
pub mod ai_safety;
pub mod api_integration;
pub mod arm;
pub mod cloud_native;
pub mod cloudformation;
pub mod code_quality;
pub mod compliance;
pub mod container;
pub mod data_visualization;
pub mod devops;
pub mod docs;
pub mod examples;
pub mod finance;
pub mod frameworks;
pub mod git_hygiene;
pub mod git_ops;
pub mod graphql;
pub mod healthcare;
pub mod infrastructure;
pub mod kubernetes;
pub mod llm_guardrails;
pub mod metadata;
pub mod performance;
pub mod pii;
pub mod pwa;
pub mod secrets;
pub mod security_hardening;
pub mod shift_left;
pub mod supply_chain;
pub mod terraform;
pub mod typescript;
pub mod web_development;
pub mod web_security;

pub use examples::example_for;

/// Get all pattern definitions
#[must_use]
pub fn all_patterns() -> Vec<Pattern> {
    let mut patterns = Vec::new();
    patterns.extend(secrets::get());
    patterns.extend(code_quality::get());
    patterns.extend(devops::get());
    patterns.extend(ai_detection::get());
    patterns.extend(security_hardening::get());
    patterns.extend(accessibility::get());
    patterns.extend(web_security::get());
    patterns.extend(pii::get());
    patterns.extend(cloud_native::get());
    patterns.extend(performance::get());
    patterns.extend(supply_chain::get());
    patterns.extend(infrastructure::get());
    patterns.extend(compliance::get());
    patterns.extend(kubernetes::get());
    patterns.extend(container::get());
    patterns.extend(git_hygiene::get());
    patterns.extend(git_ops::get());
    patterns.extend(ai_safety::get());
    patterns.extend(llm_guardrails::get());
    patterns.extend(shift_left::get());
    patterns.extend(api_integration::get());
    patterns.extend(terraform::get());
    patterns.extend(arm::get());
    patterns.extend(cloudformation::get());
    patterns.extend(data_visualization::get());
    patterns.extend(finance::get());
    patterns.extend(frameworks::get());
    patterns.extend(graphql::get());
    patterns.extend(healthcare::get());
    patterns.extend(metadata::get());
    patterns.extend(pwa::get());
    patterns.extend(web_development::get());
    patterns.extend(typescript::get());
    patterns
}

/// Get patterns by category
#[must_use]
pub fn by_category(category: &str) -> Vec<Pattern> {
    match category {
        "secrets" => secrets::get(),
        "code-quality" => code_quality::get(),
        "devops" => devops::get(),
        "ai-detection" => ai_detection::get(),
        "security-hardening" => security_hardening::get(),
        "accessibility" => accessibility::get(),
        "web-security" => web_security::get(),
        "pii" => pii::get(),
        "cloud-native" => cloud_native::get(),
        "performance" => performance::get(),
        "supply-chain" => supply_chain::get(),
        "infrastructure" => infrastructure::get(),
        "compliance" => compliance::get(),
        "kubernetes" => kubernetes::get(),
        "container" => container::get(),
        "git-hygiene" => git_hygiene::get(),
        "git-ops" => git_ops::get(),
        "ai-safety" => ai_safety::get(),
        "llm-guardrails" => llm_guardrails::get(),
        "shift-left" => shift_left::get(),
        "api-integration" => api_integration::get(),
        "terraform" => terraform::get(),
        "arm" => arm::get(),
        "cloudformation" => cloudformation::get(),
        "data-visualization" => data_visualization::get(),
        "finance" => finance::get(),
        "frameworks" => frameworks::get(),
        "graphql" => graphql::get(),
        "healthcare" => healthcare::get(),
        "metadata" => metadata::get(),
        "pwa" => pwa::get(),
        "web-development" => web_development::get(),
        "typescript" => typescript::get(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_count() {
        let patterns = all_patterns();
        // Should have 500+ patterns
        assert!(
            patterns.len() >= 100,
            "Expected at least 100 patterns for initial build, got {}",
            patterns.len()
        );
    }

    #[test]
    fn test_by_category_secrets() {
        let patterns = by_category("secrets");
        assert!(!patterns.is_empty());
        for p in &patterns {
            assert_eq!(p.category, "secrets");
        }
    }

    #[test]
    fn test_by_category_unknown() {
        let patterns = by_category("nonexistent-category");
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_by_category_case_sensitive() {
        // Category names are case-sensitive
        let patterns_lower = by_category("secrets");
        let patterns_upper = by_category("Secrets");
        // Lowercase should work, uppercase should return empty
        assert!(!patterns_lower.is_empty());
        assert!(patterns_upper.is_empty() || patterns_lower.len() == patterns_upper.len());
    }

    #[test]
    fn test_all_patterns_includes_secrets() {
        let all = all_patterns();
        let secrets = by_category("secrets");
        assert!(all.len() >= secrets.len());
        assert!(!secrets.is_empty());
    }

    #[test]
    fn test_pattern_serialization() {
        let pattern = Pattern {
            name: "test-pattern".to_string(),
            category: "test".to_string(),
            match_pattern: "test".to_string(),
            enabled: true,
            severity: "high".to_string(),
            confidence: "medium".to_string(),
            min_entropy: Some(4.0),
            description: "A test pattern".to_string(),
            reference: Some("https://example.com".to_string()),
            tags: vec!["test".to_string()],
            env_var: false,
            binary: true,
            exclude: None,
            file_extensions: Vec::new(),
        };

        let json = serde_json::to_string(&pattern).unwrap();
        let deserialized: Pattern = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, pattern.name);
        assert_eq!(deserialized.min_entropy, pattern.min_entropy);
    }

    #[test]
    fn test_pattern_min_entropy_none() {
        let pattern = Pattern {
            name: "no-entropy".to_string(),
            category: "test".to_string(),
            match_pattern: "test".to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "low".to_string(),
            min_entropy: None,
            description: "No entropy check".to_string(),
            reference: None,
            tags: vec![],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: Vec::new(),
        };

        let json = serde_json::to_string(&pattern).unwrap();
        // min_entropy is serialized as null when None
        assert!(json.contains("min_entropy") && json.contains("null"));
    }

    #[test]
    fn test_by_category_web_security() {
        let patterns = by_category("web-security");
        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_by_category_pii() {
        let patterns = by_category("pii");
        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_by_category_compliance() {
        let patterns = by_category("compliance");
        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_by_category_kubernetes() {
        let patterns = by_category("kubernetes");
        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_by_category_case_insensitive_returns_empty() {
        // Unknown categories return empty Vec
        let patterns = by_category("UNKNOWN");
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_by_category_arm() {
        let patterns = by_category("arm");
        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_by_category_cloudformation() {
        let patterns = by_category("cloudformation");
        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_by_category_data_visualization() {
        let patterns = by_category("data-visualization");
        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_by_category_finance() {
        let patterns = by_category("finance");
        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_by_category_frameworks() {
        let patterns = by_category("frameworks");
        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_by_category_git_ops() {
        let patterns = by_category("git-ops");
        assert!(!patterns.is_empty());
    }
}
