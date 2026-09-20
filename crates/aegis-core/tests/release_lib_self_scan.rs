//! Regression tests for the audited Aegis self-scan finding in
//! `scripts/release/lib.sh` (pattern `executable-file-upload`, line 5).
//!
//! The pattern matches `(?i)\.(exe|sh|php|asp|jsp)\s*.*upload`, which fired
//! on the prose comment "…build.sh assembles them and publish.sh refuses to
//! upload a directory…". The helper performs no upload — the match was
//! comment prose, not code — so the line carries a narrowly scoped same-line
//! `aegis:ignore` directive naming only that pattern.
//!
//! The tests pin both directions of that decision:
//!
//! 1. the real file scans clean of the pattern (the directive works), and
//! 2. the same prose with the directive stripped still fires, so the
//!    suppression is provably load-bearing and a future regex or parser
//!    change cannot silently void the audit.

use aegis_core::pattern::PatternDefinition;
use aegis_core::Scanner;
use aegis_patterns::Pattern;

const LIB_SH: &str = "scripts/release/lib.sh";
const PATTERN: &str = "executable-file-upload";
const DIRECTIVE: &str = "# aegis:ignore:executable-file-upload";

fn lib_sh_content() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .join(LIB_SH);
    std::fs::read_to_string(path).expect("scripts/release/lib.sh must exist")
}

fn convert(p: &Pattern) -> PatternDefinition {
    PatternDefinition {
        name: p.name.clone(),
        category: p.category.clone(),
        match_pattern: p.match_pattern.clone(),
        enabled: p.enabled,
        severity: aegis_core::Severity::parse(&p.severity).unwrap_or(aegis_core::Severity::Medium),
        confidence: aegis_core::Confidence::parse(&p.confidence)
            .unwrap_or(aegis_core::Confidence::Medium),
        min_entropy: p.min_entropy,
        description: p.description.clone(),
        reference: p.reference.clone(),
        tags: p.tags.clone(),
        env_var: p.env_var,
        binary: p.binary,
        exclude_pattern: p.exclude.clone(),
        file_extensions: p.file_extensions.clone(),
        ..Default::default()
    }
}

fn scanner() -> Scanner {
    Scanner::from_definitions(aegis_patterns::all_patterns().iter().map(convert).collect())
        .expect("bundled patterns must compile")
}

/// The audited false positive (comment prose) stays suppressed by the
/// same-line directive on the offending line.
#[test]
fn release_helper_scans_clean_with_directive() {
    let content = lib_sh_content();
    assert!(
        content.contains(DIRECTIVE),
        "lib.sh must keep the {DIRECTIVE} directive this regression test pins"
    );
    let findings: Vec<_> = scanner()
        .scan_string(&content, LIB_SH)
        .into_iter()
        .filter(|finding| finding.pattern == PATTERN)
        .collect();
    assert!(
        findings.is_empty(),
        "executable-file-upload must stay suppressed in lib.sh, got: {findings:?}"
    );
}

/// Without the directive the exact audited prose still triggers the
/// pattern — the directive, not a scanner change, is what silences it.
#[test]
fn prose_without_directive_still_fires() {
    let content = lib_sh_content();
    let stripped: String = content
        .lines()
        .map(|line| match line.find(DIRECTIVE) {
            Some(marker) => line[..marker].trim_end().to_string(),
            None => line.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert_ne!(
        content, stripped,
        "expected the directive line to change after stripping"
    );

    let findings: Vec<_> = scanner()
        .scan_string(&stripped, LIB_SH)
        .into_iter()
        .filter(|finding| finding.pattern == PATTERN)
        .collect();
    assert_eq!(findings.len(), 1, "stripped prose must fire exactly once");
    assert!(
        findings[0].matched_content.contains("refuses to upload"),
        "unexpected match: {:?}",
        findings[0].matched_content
    );
}
