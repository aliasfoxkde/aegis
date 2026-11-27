//! The XXE rules must fire on an entity declaration, not on prose.
//!
//! Both `xml-external-entity` and `security-hardening-xml-external-entity`
//! match the shape `SYSTEM` + whitespace + a quoted system id. The
//! whitespace that separates the keyword from the literal is horizontal in a
//! real declaration; a rule that accepts any whitespace reads a line that
//! merely ends in the word "system" — followed by a newline and a quote —
//! as an entity payload. A committed build capture carried exactly that
//! shape, and the scanner reported it as a critical finding.
//!
//! These tests pin both halves of the rule: the declaration is still
//! reported, and the prose shape is not.

use aegis_core::Scanner;
use aegis_patterns::Pattern;

/// The rules this file is about.
const XXE_PATTERNS: [&str; 2] = [
    "xml-external-entity",
    "security-hardening-xml-external-entity",
];

// Test-only helpers, but not `#[test]` functions, so clippy.toml's
// test exemptions do not reach them.
#[allow(clippy::unwrap_used)]
fn xxe_scanner() -> Scanner {
    let definitions = aegis_patterns::all_patterns()
        .into_iter()
        .filter(|pattern: &Pattern| XXE_PATTERNS.contains(&pattern.name.as_str()))
        .map(Into::into)
        .collect();
    Scanner::from_definitions(definitions).unwrap()
}

/// The names of the XXE rules that fired on `content`.
#[allow(clippy::unwrap_used)]
fn xxe_hits(content: &str) -> Vec<String> {
    xxe_scanner()
        .scan_string(content, "capture.txt")
        .iter()
        .map(|finding| finding.pattern.clone())
        .filter(|name| XXE_PATTERNS.contains(&name.as_str()))
        .collect()
}

#[test]
fn an_entity_declaration_is_still_a_critical_finding() {
    let declaration =
        "<?xml version=\"1.0\"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n";
    let hits = xxe_hits(declaration);
    for name in XXE_PATTERNS {
        assert!(
            hits.contains(&name.to_string()),
            "{name} stopped reporting a real entity declaration: {hits:?}"
        );
    }
}

#[test]
fn a_system_literal_in_a_doctype_is_still_a_critical_finding() {
    let declaration = "<!DOCTYPE html SYSTEM \"http://example.invalid/html.dtd\">";
    let hits = xxe_hits(declaration);
    assert!(
        !hits.is_empty(),
        "a DOCTYPE with a SYSTEM literal stopped being reported: {hits:?}"
    );
}

#[test]
fn a_public_identifier_in_a_doctype_is_still_a_critical_finding() {
    let declaration =
        "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://example.invalid/x.dtd\">";
    let hits = xxe_hits(declaration);
    assert!(
        !hits.is_empty(),
        "a DOCTYPE with a PUBLIC identifier stopped being reported: {hits:?}"
    );
}

#[test]
fn a_word_ending_in_system_is_not_an_entity_declaration() {
    // The shape a committed build capture carried: a line that ends in the
    // word "system", a newline, and an indented quoted list entry.
    let capture = "    \"crates/amortyx-enterprise\", # Enterprise features: SSO, audit logs, plugin system\n    \"crates/amortyx-enterprise\"\n";
    let hits = xxe_hits(capture);
    assert!(
        hits.is_empty(),
        "prose that ends in the word \"system\" is reported as an entity payload: {hits:?}"
    );
}

#[test]
fn a_public_word_is_not_an_entity_declaration() {
    let prose = "the service is not public\n    \"quoted\"\n";
    let hits = xxe_hits(prose);
    assert!(
        hits.is_empty(),
        "prose that ends in the word \"public\" is reported as an entity payload: {hits:?}"
    );
}
