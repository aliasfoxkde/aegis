//! Corpus precision/recall harness.
//!
//! Scores the bundled rule set against the labelled fixtures in
//! `tests/corpus/`: every `aegis:expect <rule>` directive must be satisfied
//! (recall) and every finding must land on a labelled line (precision).
//! Thresholds are pinned just below measured performance — ratchet them up
//! as the corpus grows, never down to make a regression pass.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use aegis_core::pattern::PatternDefinition;
use aegis_core::Scanner;
use aegis_patterns::Pattern;

/// Minimum acceptable recall over the vulnerable corpus.
const RECALL_THRESHOLD: f64 = 0.95;
/// Minimum acceptable precision over the whole corpus.
const PRECISION_THRESHOLD: f64 = 0.95;
/// Guard against the corpus shrinking into a vacuous pass.
const MIN_EXPECTATIONS: usize = 10;
const MIN_CLEAN_FILES: usize = 3;

const DIRECTIVE_PREFIX: &str = "aegis:expect";

fn bundled_scanner() -> Scanner {
    let definitions: Vec<PatternDefinition> = aegis_patterns::all_patterns()
        .into_iter()
        .map(convert)
        .collect();
    Scanner::from_definitions(definitions).expect("bundled patterns must compile")
}

fn convert(p: Pattern) -> PatternDefinition {
    PatternDefinition {
        name: p.name,
        category: p.category,
        match_pattern: p.match_pattern,
        enabled: p.enabled,
        severity: aegis_core::Severity::parse(&p.severity).unwrap_or(aegis_core::Severity::Medium),
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
        ..Default::default()
    }
}

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus")
}

fn collect_sources(dir: &Path) -> Vec<(String, String)> {
    let mut entries: Vec<PathBuf> = walk(dir);
    entries.sort();
    entries
        .into_iter()
        .filter_map(|path| {
            let relative = path
                .strip_prefix(dir)
                .expect("collected paths live under the corpus dir")
                .to_string_lossy()
                .replace('\\', "/");
            std::fs::read_to_string(&path)
                .map(|content| (relative, content))
                .ok()
        })
        .collect()
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else if path.extension().is_some() {
            out.push(path);
        }
    }
    out
}

/// Parse trailing `aegis:expect <rule> [<rule>...]` directives: all rule
/// names listed on a line label that same line, so expectations map line
/// number (1-indexed) -> rule names.
fn expected_rules(content: &str) -> HashMap<usize, Vec<String>> {
    let mut expected: HashMap<usize, Vec<String>> = HashMap::new();
    for (index, line) in content.lines().enumerate() {
        let Some(marker) = line.find(DIRECTIVE_PREFIX) else {
            continue;
        };
        let rules: Vec<String> = line[marker + DIRECTIVE_PREFIX.len()..]
            .split_whitespace()
            .map(str::to_string)
            .collect();
        if !rules.is_empty() {
            expected.insert(index + 1, rules);
        }
    }
    expected
}

/// One directive satisfied by a finding of that rule on the labelled line.
#[derive(Debug)]
struct Miss {
    file: String,
    line: usize,
    rule: String,
}

#[test]
fn corpus_meets_precision_and_recall_thresholds() {
    let scanner = bundled_scanner();
    let root = corpus_root();

    let mut expectations = 0usize;
    let mut satisfied = 0usize;
    let mut misses: Vec<Miss> = Vec::new();
    let mut true_positives = 0usize;
    let mut false_positives: Vec<String> = Vec::new();

    for (relative, content) in collect_sources(&root.join("vulnerable")) {
        let expected = expected_rules(&content);
        expectations += expected.values().map(Vec::len).sum::<usize>();
        let expected_lines: HashSet<usize> = expected.keys().copied().collect();

        let findings = scanner.scan_string(&content, &relative);
        for finding in &findings {
            if expected_lines.contains(&finding.location.line) {
                true_positives += 1;
            } else {
                false_positives.push(format!(
                    "{}:{}: {} fired on an unlabelled line",
                    relative, finding.location.line, finding.pattern
                ));
            }
        }

        for (line, rules) in &expected {
            for rule in rules {
                let hit = findings
                    .iter()
                    .any(|finding| finding.location.line == *line && finding.pattern == *rule);
                if hit {
                    satisfied += 1;
                } else {
                    misses.push(Miss {
                        file: relative.clone(),
                        line: *line,
                        rule: (*rule).to_string(),
                    });
                }
            }
        }
    }

    for (relative, content) in collect_sources(&root.join("clean")) {
        let findings = scanner.scan_string(&content, &relative);
        for finding in &findings {
            false_positives.push(format!(
                "clean/{relative}:{}: {} flagged benign code",
                finding.location.line, finding.pattern
            ));
        }
    }

    assert!(
        expectations >= MIN_EXPECTATIONS,
        "corpus shrank: only {expectations} expectations (need >= {MIN_EXPECTATIONS})"
    );
    let clean_files = collect_sources(&root.join("clean")).len();
    assert!(
        clean_files >= MIN_CLEAN_FILES,
        "corpus shrank: only {clean_files} clean files (need >= {MIN_CLEAN_FILES})"
    );

    let recall = if expectations == 0 {
        0.0
    } else {
        satisfied as f64 / expectations as f64
    };
    let precision = if true_positives + false_positives.len() == 0 {
        0.0
    } else {
        true_positives as f64 / (true_positives + false_positives.len()) as f64
    };

    let mut failure = String::new();
    if recall < RECALL_THRESHOLD {
        failure.push_str(&format!(
            "recall {recall:.3} < {RECALL_THRESHOLD} — missed:\n"
        ));
        for miss in &misses {
            failure.push_str(&format!(
                "  {}:{} expected {}\n",
                miss.file, miss.line, miss.rule
            ));
        }
    }
    if precision < PRECISION_THRESHOLD {
        failure.push_str(&format!(
            "precision {precision:.3} < {PRECISION_THRESHOLD} — false positives:\n"
        ));
        for fp in &false_positives {
            failure.push_str(&format!("  {fp}\n"));
        }
    }
    assert!(failure.is_empty(), "corpus quality gate failed:\n{failure}");

    assert_eq!(
        satisfied + misses.len(),
        expectations,
        "accounting error: satisfied + misses != expectations"
    );
}
