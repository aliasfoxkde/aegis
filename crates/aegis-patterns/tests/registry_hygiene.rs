//! Registry-wide invariant tests for the shipped pattern corpus.
//!
//! Every pattern must compile, carry unique kebab-case names, belong to a
//! dispatchable kebab-case category, and cite real references. These
//! invariants are what make loud category validation (aegis-core's
//! `validate_categories`) trustworthy: the valid-category list it prints is
//! only correct if every pattern's category is well-formed and dispatched.

use aegis_patterns::{all_patterns, by_category};
use regex::Regex;
use std::collections::{HashMap, HashSet};

/// Kebab-case identifier: lowercase words separated by single hyphens.
fn is_kebab_case(s: &str) -> bool {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z0-9]+(-[a-z0-9]+)*$").unwrap())
        .is_match(s)
}

/// Tags additionally allow dotted segments so WCAG success-criterion tags
/// (`wcag-2.4.1`) stay well-formed.
fn is_well_formed_tag(s: &str) -> bool {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z0-9]+([.-][a-z0-9]+)*$").unwrap())
        .is_match(s)
}

const VALID_SEVERITIES: &[&str] = &["critical", "high", "medium", "low", "info"];
const VALID_CONFIDENCES: &[&str] = &["high", "medium", "low"];

#[test]
fn every_pattern_regex_compiles() {
    let mut failures = Vec::new();
    for p in all_patterns() {
        if let Err(err) = Regex::new(&p.match_pattern) {
            failures.push(format!("{}: match_pattern: {}", p.name, err));
        }
        if let Some(exclude) = &p.exclude {
            if let Err(err) = Regex::new(exclude) {
                failures.push(format!("{}: exclude: {}", p.name, err));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} pattern(s) failed to compile:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn pattern_names_are_unique() {
    let mut seen = HashMap::new();
    let mut dupes = Vec::new();
    for p in all_patterns() {
        if seen.insert(p.name.clone(), true).is_some() {
            dupes.push(p.name.clone());
        }
    }
    assert!(dupes.is_empty(), "duplicate pattern names: {dupes:?}");
}

#[test]
fn pattern_names_and_categories_are_kebab_case() {
    let offenders: Vec<String> = all_patterns()
        .iter()
        .filter(|p| !is_kebab_case(&p.name) || !is_kebab_case(&p.category))
        .map(|p| format!("{} (category: {})", p.name, p.category))
        .collect();
    assert!(
        offenders.is_empty(),
        "names/categories must be kebab-case: {offenders:?}"
    );
}

#[test]
fn categories_are_consistently_dispatchable() {
    // Every category attached to a pattern must round-trip through
    // by_category and return exactly the patterns carrying it.
    let all = all_patterns();
    let mut by_cat: HashMap<&str, Vec<&str>> = HashMap::new();
    for p in &all {
        by_cat.entry(p.category.as_str()).or_default().push(&p.name);
    }

    let mut failures = Vec::new();
    for (category, expected_names) in &by_cat {
        let selected = by_category(category);
        let mut selected_names: Vec<&str> = selected.iter().map(|p| p.name.as_str()).collect();
        selected_names.sort_unstable();
        let mut expected: Vec<&str> = expected_names.clone();
        expected.sort_unstable();
        if selected_names != expected {
            failures.push(format!(
                "category {category}: dispatch returned {} patterns, {} carry it",
                selected_names.len(),
                expected.len()
            ));
        }
    }
    assert!(failures.is_empty(), "category dispatch drift: {failures:?}");
}

#[test]
fn no_pattern_is_orphaned_from_its_category() {
    // Sum of by_category across distinct categories must equal the corpus,
    // proving all_patterns() and by_category() stay in sync.
    let all = all_patterns();
    let total_via_categories: usize = all
        .iter()
        .map(|p| p.category.as_str())
        .collect::<HashSet<_>>()
        .into_iter()
        .map(by_category)
        .map(|v| v.len())
        .sum();
    assert_eq!(
        total_via_categories,
        all.len(),
        "patterns exist that by_category() cannot reach"
    );
}

#[test]
fn severities_and_confidences_are_enumerated_values() {
    let offenders: Vec<String> = all_patterns()
        .iter()
        .filter(|p| {
            !VALID_SEVERITIES.contains(&p.severity.as_str())
                || !VALID_CONFIDENCES.contains(&p.confidence.as_str())
        })
        .map(|p| {
            format!(
                "{} (severity: {}, confidence: {})",
                p.name, p.severity, p.confidence
            )
        })
        .collect();
    assert!(offenders.is_empty(), "invalid enum strings: {offenders:?}");
}

#[test]
fn references_are_https_urls_with_a_host() {
    let offenders: Vec<String> = all_patterns()
        .iter()
        .filter_map(|p| {
            let reference = p.reference.as_deref()?;
            let ok = reference.starts_with("https://")
                && reference["https://".len()..]
                    .split('/')
                    .next()
                    .is_some_and(|host| host.contains('.'));
            if ok {
                None
            } else {
                Some(format!("{}: {}", p.name, reference))
            }
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "references must be absolute https URLs: {offenders:?}"
    );
}

#[test]
fn tags_and_extensions_are_well_formed() {
    let offenders: Vec<String> = all_patterns()
        .iter()
        .filter_map(|p| {
            let bad_tags: Vec<_> = p
                .tags
                .iter()
                .filter(|t| !is_well_formed_tag(t))
                .map(String::as_str)
                .collect();
            let bad_exts: Vec<_> = p
                .file_extensions
                .iter()
                .filter(|e| {
                    !e.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                        || e.is_empty()
                })
                .map(String::as_str)
                .collect();
            if bad_tags.is_empty() && bad_exts.is_empty() {
                None
            } else {
                Some(format!(
                    "{}: bad tags {bad_tags:?}, bad extensions {bad_exts:?}",
                    p.name
                ))
            }
        })
        .collect();
    assert!(offenders.is_empty(), "malformed metadata: {offenders:?}");
}

#[test]
fn every_pattern_has_substantive_content() {
    let offenders: Vec<String> = all_patterns()
        .iter()
        .filter(|p| {
            p.match_pattern.trim().is_empty()
                || p.description.trim().is_empty()
                || p.match_pattern.len() < 2
                || p.description.len() < 10
        })
        .map(|p| p.name.clone())
        .collect();
    assert!(
        offenders.is_empty(),
        "patterns must have a real regex and description: {offenders:?}"
    );
}

#[test]
fn exclude_patterns_exclude_something_related() {
    // An exclude regex that never matches anything the match regex can
    // produce is dead configuration. We can't prove relatedness in
    // general, but we can prove the exclude compiles and is anchored to
    // more than a bare wildcard.
    let offenders: Vec<String> = all_patterns()
        .iter()
        .filter_map(|p| {
            let exclude = p.exclude.as_deref()?;
            if exclude.trim().is_empty() || exclude == ".*" {
                Some(format!("{}: exclude={exclude:?}", p.name))
            } else {
                None
            }
        })
        .collect();
    assert!(offenders.is_empty(), "no-op excludes: {offenders:?}");
}

/// The committed docs must match the shipped patterns. Fails when a pattern
/// is added or changed without regenerating `docs/patterns/README.md`
/// (`cargo run -p aegis-patterns --example generate_docs`).
#[test]
fn pattern_docs_are_fresh() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let readme = manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|root| root.join("docs").join("patterns").join("README.md"))
        .expect("crate must live inside the repository");

    let committed = std::fs::read_to_string(&readme).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}; run cargo run -p aegis-patterns --example generate_docs",
            readme.display()
        )
    });

    // Windows runners check out with CRLF while the generator emits LF, so
    // compare newline-insensitively — the freshness guarantee is about
    // content, not checkout line endings.
    let normalize = |s: &str| s.replace('\r', "");
    assert_eq!(
        normalize(&committed),
        normalize(&aegis_patterns::docs::generate_pattern_docs()),
        "docs/patterns/README.md is stale; run cargo run -p aegis-patterns --example generate_docs"
    );
}

/// Entropy thresholds must fall in the Shannon range (bits per character).
#[test]
fn entropy_thresholds_are_within_shannon_range() {
    let offenders: Vec<String> = all_patterns()
        .iter()
        .filter_map(|p| match p.min_entropy {
            Some(e) if !(0.0..=8.0).contains(&e) => Some(format!("{}: {e}", p.name)),
            _ => None,
        })
        .collect();
    assert!(offenders.is_empty(), "out-of-range entropy: {offenders:?}");
}
