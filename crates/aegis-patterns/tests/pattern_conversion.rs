//! Contract tests for the canonical `Pattern -> PatternDefinition`
//! conversion. Every crate (CLI, MCP, daemon, wasm) funnels its bundled
//! patterns through this single `From` impl, so field preservation is a
//! cross-crate guarantee rather than an implementation detail.

use aegis_core::{Confidence, PatternDefinition, Severity};
use aegis_patterns::Pattern;

fn full_pattern() -> Pattern {
    Pattern {
        name: "full-pattern".to_string(),
        category: "security".to_string(),
        match_pattern: r"\bKEY-[A-Z0-9]{16}\b".to_string(),
        severity: "critical".to_string(),
        confidence: "high".to_string(),
        description: "API key pattern".to_string(),
        enabled: true,
        min_entropy: Some(5.0),
        reference: Some("https://docs.example.com/api-keys".to_string()),
        tags: vec![
            "api".to_string(),
            "key".to_string(),
            "production".to_string(),
        ],
        env_var: true,
        binary: true,
        exclude: None,
        file_extensions: Vec::new(),
    }
}

#[test]
fn conversion_preserves_every_field() {
    let pattern = full_pattern();
    let converted = PatternDefinition::from(pattern.clone());

    assert_eq!(converted.name, pattern.name);
    assert_eq!(converted.category, pattern.category);
    assert_eq!(converted.match_pattern, pattern.match_pattern);
    assert_eq!(converted.severity, Severity::Critical);
    assert_eq!(converted.confidence, Confidence::High);
    assert_eq!(converted.min_entropy, pattern.min_entropy);
    assert_eq!(converted.description, pattern.description);
    assert_eq!(converted.reference, pattern.reference);
    assert_eq!(converted.tags, pattern.tags);
    assert_eq!(converted.env_var, pattern.env_var);
    assert_eq!(converted.binary, pattern.binary);
    assert_eq!(converted.exclude_pattern, pattern.exclude);
    assert_eq!(converted.file_extensions, pattern.file_extensions);
    assert_eq!(converted.enabled, pattern.enabled);
}

#[test]
fn unrated_severities_fall_back_to_medium() {
    let pattern = full_pattern();
    let converted = PatternDefinition::from(pattern);

    let mut lax = full_pattern();
    lax.severity = "not-a-severity".to_string();
    lax.confidence = "not-a-confidence".to_string();
    let lax_converted = PatternDefinition::from(lax);

    // Sanity: rated values parse through unchanged.
    assert_eq!(converted.severity, Severity::Critical);

    // Unrated values degrade to Medium instead of failing the scan setup.
    assert_eq!(lax_converted.severity, Severity::Medium);
    assert_eq!(lax_converted.confidence, Confidence::Medium);
}

#[test]
fn bundled_patterns_convert_without_loss() {
    // Every shipped pattern must survive the round trip into the engine's
    // definition type — a dropped field here would silently weaken scans.
    for pattern in aegis_patterns::all_patterns() {
        let converted = PatternDefinition::from(pattern.clone());
        assert_eq!(converted.name, pattern.name);
        assert_eq!(converted.match_pattern, pattern.match_pattern);
        assert_eq!(converted.category, pattern.category);
        assert_eq!(converted.enabled, pattern.enabled);
        assert_eq!(converted.file_extensions, pattern.file_extensions);
        assert_eq!(converted.min_entropy, pattern.min_entropy);
    }
}
