//! Behavioural coverage for the triage ergonomics aimed at
//! documentation-heavy repositories: path classes, synthetic annotations,
//! and secret triage.
//!
//! The patterns are written here rather than taken from the bundled
//! corpus, so these tests assert the behaviour of the classification layer
//! itself rather than the behaviour of whichever rules happen to ship.

use aegis_core::{
    Confidence, PathClass, PathClassRule, PatternDefinition, ScanOptions, Scanner, Severity,
    TriageOutcome,
};
use tempfile::TempDir;

/// A value with the shape of a random credential: 26 distinct symbols,
/// which is above the entropy threshold the triage uses.
const CREDENTIAL_SHAPED: &str = "9fK2mQ7xL4nR8vT1yW6zB3cD5";

/// A published-example value: it carries the `EXAMPLE` marker, so the
/// triage has evidence that it is not a live credential.
const EXAMPLE_SHAPED: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

/// The name of the one pattern these tests register.
const PATTERN_NAME: &str = "credential-shape";

/// Build a scanner over one hand-written pattern.
///
/// Test-only helper, but not a `#[test]` function, so clippy.toml's test
/// exemptions do not reach it.
#[allow(clippy::unwrap_used)]
fn scanner_with(definition: PatternDefinition) -> Scanner {
    Scanner::from_definitions(vec![definition]).unwrap()
}

/// A pattern that matches a credential-shaped run of characters.
#[allow(clippy::unwrap_used)]
fn definition(category: &str, severity: Severity) -> PatternDefinition {
    PatternDefinition {
        name: PATTERN_NAME.to_string(),
        category: category.to_string(),
        match_pattern: "[A-Za-z0-9+/]{24,}".to_string(),
        enabled: true,
        severity,
        confidence: Confidence::High,
        description: "A credential-shaped run of characters".to_string(),
        ..PatternDefinition::default()
    }
}

/// Write `content` to `relative` below `root`, creating the parent
/// directories.
#[allow(clippy::unwrap_used)]
fn write_file(root: &TempDir, relative: &str, content: &str) {
    let path = root.path().join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

/// The findings the registered pattern produced.
///
/// The scanner also runs its AST and anomaly layers, so a test that counts
/// *every* finding would assert on rules that have nothing to do with the
/// behaviour under test. This selects the one pattern these tests own.
#[allow(clippy::unwrap_used)]
fn findings_of(scanner: &Scanner, root: &TempDir) -> Vec<aegis_core::Finding> {
    let (findings, _stats) = scanner.scan_dir(root.path()).unwrap();
    findings
        .into_iter()
        .filter(|finding| finding.pattern == PATTERN_NAME)
        .collect()
}

#[test]
fn a_documentation_path_reports_its_findings_at_low_severity() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "docs/intro.md",
        &format!("the value {CREDENTIAL_SHAPED} is an example\n"),
    );

    let scanner =
        scanner_with(definition("documentation", Severity::High)).with_options(ScanOptions {
            path_classes: vec![PathClassRule {
                glob: "docs/**".to_string(),
                class: PathClass::Docs,
            }],
            anomaly_detectors: Some(Vec::new()),
            ..ScanOptions::default()
        });

    let findings = findings_of(&scanner, &dir);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, "low");
    assert!(findings[0].tags.iter().any(|tag| tag == "docs"));
}

#[test]
fn a_path_outside_the_classified_glob_keeps_its_severity() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "src/app.rs",
        &format!("let token = \"{CREDENTIAL_SHAPED}\";\n"),
    );

    let scanner =
        scanner_with(definition("documentation", Severity::High)).with_options(ScanOptions {
            path_classes: vec![PathClassRule {
                glob: "docs/**".to_string(),
                class: PathClass::Docs,
            }],
            anomaly_detectors: Some(Vec::new()),
            ..ScanOptions::default()
        });

    let findings = findings_of(&scanner, &dir);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, "high");
    assert!(findings[0].tags.is_empty());
}

#[test]
fn a_secret_keeps_its_severity_under_a_path_class() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "docs/setup.md",
        &format!("the value {CREDENTIAL_SHAPED} is an example\n"),
    );

    let scanner = scanner_with(definition("secrets", Severity::High)).with_options(ScanOptions {
        path_classes: vec![PathClassRule {
            glob: "docs/**".to_string(),
            class: PathClass::Docs,
        }],
        anomaly_detectors: Some(Vec::new()),
        ..ScanOptions::default()
    });

    let findings = findings_of(&scanner, &dir);
    assert_eq!(findings.len(), 1);
    // A credential in a documentation file is still a credential: the class
    // is recorded, the severity is not lowered.
    assert_eq!(findings[0].severity, "high");
    assert!(findings[0].tags.iter().any(|tag| tag == "docs"));
}

#[test]
fn a_downgraded_finding_does_not_survive_a_severity_threshold() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "docs/intro.md",
        &format!("the value {CREDENTIAL_SHAPED} is an example\n"),
    );

    let scanner =
        scanner_with(definition("documentation", Severity::High)).with_options(ScanOptions {
            severity_threshold: Some("medium".to_string()),
            path_classes: vec![PathClassRule {
                glob: "docs/**".to_string(),
                class: PathClass::Docs,
            }],
            anomaly_detectors: Some(Vec::new()),
            ..ScanOptions::default()
        });

    // The finding was downgraded to low before the threshold was applied,
    // so it must not reappear in a medium-and-above report.
    assert!(findings_of(&scanner, &dir).is_empty());
}

#[test]
fn a_synthetic_annotation_keeps_the_finding_at_low_severity() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "fixtures/keys.txt",
        &format!("key = {CREDENTIAL_SHAPED} // aegis:synthetic -- test fixture\n"),
    );

    let scanner =
        scanner_with(definition("secrets", Severity::Critical)).with_options(ScanOptions {
            anomaly_detectors: Some(Vec::new()),
            ..ScanOptions::default()
        });

    let findings = findings_of(&scanner, &dir);
    assert_eq!(findings.len(), 1);
    // The finding is not hidden: it is kept, tagged, and reported at low
    // severity so it stops competing with real signals.
    assert_eq!(findings[0].severity, "low");
    assert!(findings[0].tags.iter().any(|tag| tag == "synthetic"));
}

#[test]
fn a_secret_finding_carries_a_triage_verdict() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "src/app.rs",
        &format!("let token = \"{CREDENTIAL_SHAPED}\";\n"),
    );

    let scanner = scanner_with(definition("secrets", Severity::High)).with_options(ScanOptions {
        anomaly_detectors: Some(Vec::new()),
        ..ScanOptions::default()
    });

    let findings = findings_of(&scanner, &dir);
    assert_eq!(findings.len(), 1);
    let triage = findings[0]
        .secret_triage
        .as_ref()
        .expect("a secret finding carries a verdict");
    assert_eq!(triage.outcome, TriageOutcome::LikelyReal);
    // The verdict names the signal, never the value.
    for reason in &triage.reasons {
        assert!(!reason.contains(CREDENTIAL_SHAPED));
    }
}

#[test]
fn a_published_example_is_triaged_as_a_placeholder() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "src/app.rs",
        &format!("let token = \"{EXAMPLE_SHAPED}\";\n"),
    );

    let scanner = scanner_with(definition("secrets", Severity::High)).with_options(ScanOptions {
        anomaly_detectors: Some(Vec::new()),
        ..ScanOptions::default()
    });

    let findings = findings_of(&scanner, &dir);
    assert_eq!(findings.len(), 1);
    let triage = findings[0]
        .secret_triage
        .as_ref()
        .expect("a secret finding carries a verdict");
    assert_eq!(triage.outcome, TriageOutcome::LikelyPlaceholder);
}

#[test]
fn a_non_secret_finding_carries_no_triage_verdict() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "src/app.rs",
        &format!("let token = \"{CREDENTIAL_SHAPED}\";\n"),
    );

    let scanner =
        scanner_with(definition("documentation", Severity::High)).with_options(ScanOptions {
            anomaly_detectors: Some(Vec::new()),
            ..ScanOptions::default()
        });

    let findings = findings_of(&scanner, &dir);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].secret_triage.is_none());
}
