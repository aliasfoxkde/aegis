//! Aegis Patterns
//!
//! Pattern definitions for Aegis.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    pub name: String,
    pub category: String,
    #[serde(rename = "match")]
    pub match_pattern: String,
    pub enabled: bool,
    pub severity: String,
    pub confidence: String,
    #[serde(default)]
    pub min_entropy: Option<f64>,
    pub description: String,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub env_var: bool,
    #[serde(default)]
    pub binary: bool,
}

pub mod accessibility;
pub mod ai_detection;
pub mod ai_safety;
pub mod cloud_native;
pub mod code_quality;
pub mod compliance;
pub mod devops;
pub mod git_hygiene;
pub mod infrastructure;
pub mod llm_guardrails;
pub mod performance;
pub mod pii;
pub mod secrets;
pub mod security_hardening;
pub mod shift_left;
pub mod supply_chain;
pub mod web_security;

/// Get all pattern definitions
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
    patterns.extend(git_hygiene::get());
    patterns.extend(ai_safety::get());
    patterns.extend(llm_guardrails::get());
    patterns.extend(shift_left::get());
    patterns
}

/// Get patterns by category
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
        "git-hygiene" => git_hygiene::get(),
        "ai-safety" => ai_safety::get(),
        "llm-guardrails" => llm_guardrails::get(),
        "shift-left" => shift_left::get(),
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
}
