//! Behavioural coverage for the path-class rules a [`Config`] carries.
//!
//! A rule whose glob does not compile classifies nothing, so a scanner
//! built from such a configuration would quietly ignore a path class the
//! caller believes is in force. The configuration is rejected instead.
//!
//! These live as integration tests because they build a scanner from a
//! configuration the way a library consumer does, through the public
//! `Scanner::from_config` entry point.

use aegis_core::pattern::PatternError;
use aegis_core::{
    Bundle, Confidence, Config, PathClass, PathClassRule, PatternDefinition, Scanner, Severity,
};
use tempfile::TempDir;

/// A glob that does not compile.
const BROKEN_GLOB: &str = "docs/[";

/// The name of the one pattern these tests register.
const PATTERN_NAME: &str = "credential-shape";

/// A value with the shape of a credential, which the pattern below
/// matches.
const CREDENTIAL_SHAPED: &str = "9fK2mQ7xL4nR8vT1yW6zB3cD5";

/// A pattern that matches a credential-shaped run of characters.
fn definition() -> PatternDefinition {
    PatternDefinition {
        name: PATTERN_NAME.to_string(),
        category: "documentation".to_string(),
        match_pattern: "[A-Za-z0-9+/]{24,}".to_string(),
        enabled: true,
        severity: Severity::High,
        confidence: Confidence::High,
        description: "A credential-shaped run of characters".to_string(),
        ..PatternDefinition::default()
    }
}

/// A configuration over one pattern, carrying the given path classes.
fn config_with(rules: Vec<PathClassRule>) -> Config {
    let mut config = Config::default();
    config.bundle = Bundle::new(vec![definition()]);
    config.path_classes = rules;
    // The anomaly layer would report findings of its own; this test is
    // about path classification.
    config.anomaly_detectors = Some(Vec::new());
    config
}

/// The findings the registered pattern produced.
///
/// Test-only helper, but not a `#[test]` function, so clippy.toml's test
/// exemptions do not reach it.
#[allow(clippy::unwrap_used)]
fn findings_of(scanner: &Scanner, root: &TempDir) -> Vec<aegis_core::Finding> {
    let (findings, _stats) = scanner.scan_dir(root.path()).unwrap();
    findings
        .into_iter()
        .filter(|finding| finding.pattern == PATTERN_NAME)
        .collect()
}

#[test]
fn a_config_with_a_valid_path_class_classifies_the_paths_it_matches() {
    let config = config_with(vec![PathClassRule {
        glob: "docs/**".to_string(),
        class: PathClass::Docs,
    }]);
    let scanner = Scanner::from_config(&config).expect("a valid path class is accepted");

    let dir = TempDir::new().expect("a temporary directory");
    let docs = dir.path().join("docs");
    std::fs::create_dir_all(&docs).expect("the docs directory is created");
    std::fs::write(
        docs.join("intro.md"),
        format!("the value {CREDENTIAL_SHAPED} is an example\n"),
    )
    .expect("the file is written");

    let findings = findings_of(&scanner, &dir);
    assert_eq!(findings.len(), 1);
    // The class was applied: the finding was reported at low severity and
    // tagged, rather than left at the pattern's own severity.
    assert_eq!(findings[0].severity, "low");
    assert!(findings[0].tags.iter().any(|tag| tag == "docs"));
}

#[test]
fn a_config_with_an_uncompilable_path_class_is_rejected() {
    let config = config_with(vec![PathClassRule {
        glob: BROKEN_GLOB.to_string(),
        class: PathClass::Docs,
    }]);

    let error = Scanner::from_config(&config).expect_err("a broken glob is an error");
    assert!(matches!(error, PatternError::InvalidPathClass(_)));
    // The message names the glob, so the caller can correct it.
    assert!(error.to_string().contains(BROKEN_GLOB));
}

#[test]
fn one_broken_path_class_rejects_the_whole_configuration() {
    let config = config_with(vec![
        PathClassRule {
            glob: "docs/**".to_string(),
            class: PathClass::Docs,
        },
        PathClassRule {
            glob: BROKEN_GLOB.to_string(),
            class: PathClass::Fixture,
        },
    ]);

    // A scanner that dropped only the broken rule would classify
    // everything else, so the caller would not know a rule was lost.
    let error = Scanner::from_config(&config).expect_err("a broken glob is an error");
    assert!(matches!(error, PatternError::InvalidPathClass(_)));
}
