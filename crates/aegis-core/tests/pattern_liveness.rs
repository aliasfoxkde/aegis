//! Rule-liveness harness.
//!
//! Every enabled bundled pattern must fire on its generated example from
//! [`aegis_patterns::example_for`]. The examples are produced by
//! `scripts/generate_examples.py`, which validates each candidate against
//! the pattern's own regex, entropy gate, and exclude regex before emitting
//! it. A missing example, or an example that stops firing, means the rule
//! is dead: fix the rule, not the example table.

use aegis_core::entropy::shannon_entropy;
use aegis_core::pattern::PatternDefinition;
use aegis_core::Scanner;
use aegis_patterns::{example_for, Pattern};

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

/// Filename used to scan an example: the pattern's first allowed extension
/// when it is extension-scoped, otherwise a neutral one.
fn source_for(p: &Pattern) -> String {
    let ext = p.file_extensions.first().map_or("txt", String::as_str);
    format!("example.{ext}")
}

#[test]
fn every_enabled_pattern_has_a_liveness_example() {
    let missing: Vec<String> = aegis_patterns::all_patterns()
        .into_iter()
        .filter(|p| p.enabled)
        .map(|p| p.name)
        .filter(|name| example_for(name).is_none())
        .collect();
    assert!(
        missing.is_empty(),
        "enabled patterns without a liveness example (add them to \
         scripts/generate_examples.py OVERRIDES or fix the generator): {missing:?}"
    );
}

#[test]
fn every_example_fires_its_pattern() {
    let patterns: Vec<Pattern> = aegis_patterns::all_patterns()
        .into_iter()
        .filter(|p| p.enabled)
        .collect();
    assert!(patterns.len() > 600, "unexpectedly small pattern corpus");

    let scanner = Scanner::from_definitions(patterns.iter().map(convert).collect())
        .expect("bundled patterns must compile");

    let mut failures: Vec<String> = Vec::new();
    for p in &patterns {
        let Some(example) = example_for(&p.name) else {
            failures.push(format!("{}: no liveness example", p.name));
            continue;
        };
        if p.env_var {
            validate_env_var_only(p, example, &mut failures);
        } else {
            let filename = source_for(p);
            // No trailing newline: several rules are `$`-anchored, and the
            // regex crate does not match `$` before a trailing newline.
            let fired = scanner
                .scan_string(example, &filename)
                .iter()
                .any(|f| f.pattern == p.name);
            if !fired {
                failures.push(format!(
                    "{}: no finding on example {:?} (source {filename})",
                    p.name, example
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "dead or unreachable rules ({}):\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

#[test]
fn ci_bypass_requires_explicit_configuration_syntax() {
    let pattern = aegis_patterns::all_patterns()
        .into_iter()
        .find(|pattern| pattern.name == "ci-bypass")
        .expect("ci-bypass pattern must exist");
    let scanner =
        Scanner::from_definitions(vec![convert(&pattern)]).expect("ci-bypass pattern must compile");

    assert!(scanner
        .scan_string("skip tests while documenting the workflow", "example.rs")
        .is_empty());
    assert!(scanner
        .scan_string("skip-ci: true", "workflow.yml")
        .iter()
        .any(|finding| finding.pattern == "ci-bypass"));
    assert!(scanner
        .scan_string("continue-on-error: true", "workflow.yaml")
        .iter()
        .any(|finding| finding.pattern == "ci-bypass"));
}

/// Env-var-only patterns are excluded from file-mode scanning by design
/// (see `PatternDefinition::is_env_var_only`), so they are validated
/// directly against their own regex, entropy gate, and exclude regex —
/// the same gates the env scan applies.
fn validate_env_var_only(p: &Pattern, example: &str, failures: &mut Vec<String>) {
    let re = match regex::Regex::new(&p.match_pattern) {
        Ok(re) => re,
        Err(err) => {
            failures.push(format!("{}: regex does not compile: {err}", p.name));
            return;
        }
    };
    let Some(m) = re.find(example) else {
        failures.push(format!("{}: example {:?} does not match", p.name, example));
        return;
    };
    let span = m.as_str();
    if let Some(exclude) = p.exclude.as_deref() {
        if let Ok(excl) = regex::Regex::new(exclude) {
            if excl.is_match(span) {
                failures.push(format!(
                    "{}: example span {span:?} matches its own exclude regex",
                    p.name
                ));
                return;
            }
        }
    }
    if let Some(min) = p.min_entropy {
        let entropy = shannon_entropy(span);
        if entropy < min {
            failures.push(format!(
                "{}: example span entropy {entropy:.2} below gate {min}",
                p.name
            ));
        }
    }
}
