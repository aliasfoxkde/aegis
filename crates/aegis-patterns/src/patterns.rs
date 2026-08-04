//! Pattern definitions for Aegis
//!
//! This module contains all 500+ pattern definitions organized by category.

use crate::Pattern;

pub mod secrets;
pub mod code_quality;
pub mod devops;
pub mod ai_detection;
pub mod security_hardening;
pub mod accessibility;
pub mod web_security;
pub mod pii;
pub mod cloud_native;
pub mod performance;
pub mod supply_chain;
pub mod infrastructure;
pub mod compliance;
pub mod git_hygiene;
pub mod ai_safety;
pub mod llm_guardrails;
pub mod shift_left;

/// Get all patterns
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
    fn test_all_patterns() {
        let patterns = all_patterns();
        assert!(patterns.len() >= 500, "Expected 500+ patterns, got {}", patterns.len());
    }

    #[test]
    fn test_category_patterns() {
        for cat in &[
            "secrets", "code-quality", "devops", "ai-detection",
            "security-hardening", "accessibility", "web-security", "pii",
            "cloud-native", "performance", "supply-chain", "infrastructure",
            "compliance", "git-hygiene", "ai-safety", "llm-guardrails", "shift-left"
        ] {
            let patterns = by_category(cat);
            assert!(!patterns.is_empty(), "Category {} should have patterns", cat);
        }
    }
}
