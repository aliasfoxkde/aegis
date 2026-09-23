//! Corpus precision/recall harness.
//!
//! Scores the bundled rule set against the labelled fixtures in
//! `tests/corpus/`:
//!
//! * every `aegis:expect <rule>` directive must be satisfied (recall) and
//!   every finding must land on a labelled line (precision);
//! * per rule, once a rule has enough observations to measure, its
//!   precision must hold a floor and its `confidence` label must be
//!   calibrated against that measured precision (demote-only: a rule
//!   whose data cannot support `high` gets its label lowered or its
//!   regex fixed — the gate never demands promotion);
//! * every `aegis:expect-none <rule>` fixture in `negative/` must keep
//!   the named rule silent outside its directive lines.
//!
//! Thresholds are pinned just below measured performance — ratchet them
//! up as the corpus grows, never down to make a regression pass.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
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
/// The negative corpus may not shrink into a vacuous pass either.
const MIN_NEGATIVE_FILES: usize = 3;
/// The false-positive audit must keep at least this many rules pinned by
/// `aegis:expect-none` fixtures.
const MIN_PINNED_RULES: usize = 5;

/// Minimum acceptable precision for any single rule once it has enough
/// corpus observations to measure. A rule can pass the aggregate gate
/// while being terrible on its own slice; this catches that.
const PER_RULE_PRECISION_FLOOR: f64 = 0.8;
/// TP + FP observations a rule needs before its per-rule gate engages.
const PER_RULE_MIN_OBSERVATIONS: usize = 2;
/// TP + FP observations a rule needs before its confidence label is
/// calibrated against measured precision. Below this the sample is too
/// small to judge a label.
const CALIBRATION_MIN_OBSERVATIONS: usize = 3;
/// Precision a `high`-confidence rule must hold once calibrated.
const HIGH_CONFIDENCE_PRECISION: f64 = 0.95;
/// Precision a `medium`-confidence rule must hold once calibrated.
const MEDIUM_CONFIDENCE_PRECISION: f64 = 0.80;

const DIRECTIVE_PREFIX: &str = "aegis:expect";
const NEGATIVE_PREFIX: &str = "aegis:expect-none";

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

/// Rule name -> declared confidence label, straight from the pattern
/// sources (not from findings, so rules with no findings are still
/// lookable-up).
fn declared_confidence() -> HashMap<String, String> {
    aegis_patterns::all_patterns()
        .into_iter()
        .map(|p| (p.name, p.confidence))
        .collect()
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

/// Parse `aegis:expect-none <rule> [<rule>...]` directives from a
/// negative-corpus file: the named rules must stay silent in that file,
/// and the directive lines themselves are exempt (several rule names
/// self-match their own regex, e.g. `hipaa-phi` contains a standalone
/// `phi`). Returns the named rules and the exempt line numbers.
fn expect_none_rules(content: &str) -> (HashSet<String>, HashSet<usize>) {
    let mut rules = HashSet::new();
    let mut exempt_lines = HashSet::new();
    for (index, line) in content.lines().enumerate() {
        let Some(marker) = line.find(NEGATIVE_PREFIX) else {
            continue;
        };
        for rule in line[marker + NEGATIVE_PREFIX.len()..].split_whitespace() {
            rules.insert(rule.to_string());
        }
        exempt_lines.insert(index + 1);
    }
    (rules, exempt_lines)
}

/// One directive satisfied by a finding of that rule on the labelled line.
#[derive(Debug)]
struct Miss {
    file: String,
    line: usize,
    rule: String,
}

/// Per-rule precision accounting over the positive corpus. A finding is a
/// true positive when it lands on *any* labelled line — generic rules
/// legitimately share lines labelled for a more specific rule — and a
/// false positive otherwise (unlabelled vulnerable line, or anywhere in a
/// clean file).
#[derive(Default)]
struct RuleStat {
    true_positives: usize,
    false_positives: usize,
    false_positive_locations: Vec<String>,
}

impl RuleStat {
    fn precision(&self) -> f64 {
        if self.true_positives + self.false_positives == 0 {
            0.0
        } else {
            self.true_positives as f64 / (self.true_positives + self.false_positives) as f64
        }
    }

    fn observations(&self) -> usize {
        self.true_positives + self.false_positives
    }
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
    let mut rule_stats: BTreeMap<String, RuleStat> = BTreeMap::new();

    for (relative, content) in collect_sources(&root.join("vulnerable")) {
        let expected = expected_rules(&content);
        expectations += expected.values().map(Vec::len).sum::<usize>();
        let expected_lines: HashSet<usize> = expected.keys().copied().collect();

        let findings = scanner.scan_string(&content, &relative);
        for finding in &findings {
            let stat = rule_stats.entry(finding.pattern.clone()).or_default();
            if expected_lines.contains(&finding.location.line) {
                true_positives += 1;
                stat.true_positives += 1;
            } else {
                let location = format!(
                    "vulnerable/{relative}:{}: {} fired on an unlabelled line",
                    finding.location.line, finding.pattern
                );
                false_positives.push(location.clone());
                stat.false_positives += 1;
                stat.false_positive_locations.push(location);
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
                        rule: (*rule).clone(),
                    });
                }
            }
        }
    }

    for (relative, content) in collect_sources(&root.join("clean")) {
        let findings = scanner.scan_string(&content, &relative);
        for finding in &findings {
            let location = format!(
                "clean/{relative}:{}: {} flagged benign code",
                finding.location.line, finding.pattern
            );
            false_positives.push(location.clone());
            let stat = rule_stats.entry(finding.pattern.clone()).or_default();
            stat.false_positives += 1;
            stat.false_positive_locations.push(location);
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
        let _ = writeln!(failure, "recall {recall:.3} < {RECALL_THRESHOLD} — missed:");
        for miss in &misses {
            let _ = writeln!(
                failure,
                "  {}:{} expected {}",
                miss.file, miss.line, miss.rule
            );
        }
    }
    if precision < PRECISION_THRESHOLD {
        let _ = writeln!(
            failure,
            "precision {precision:.3} < {PRECISION_THRESHOLD} — false positives:"
        );
        for fp in &false_positives {
            let _ = writeln!(failure, "  {fp}");
        }
    }
    failure.push_str(&per_rule_failures(&rule_stats));
    assert!(failure.is_empty(), "corpus quality gate failed:\n{failure}");

    assert_eq!(
        satisfied + misses.len(),
        expectations,
        "accounting error: satisfied + misses != expectations"
    );
}

/// Per-rule precision floor and confidence calibration (demote-only).
/// Rules below the observation minimums are unmeasured noise and are
/// skipped, never failed — but they still show up in the negative
/// corpus's absolute-silence check when applicable.
fn per_rule_failures(rule_stats: &BTreeMap<String, RuleStat>) -> String {
    let confidence = declared_confidence();
    let mut failure = String::new();

    for (rule, stat) in rule_stats {
        let precision = stat.precision();
        if stat.observations() >= PER_RULE_MIN_OBSERVATIONS && precision < PER_RULE_PRECISION_FLOOR
        {
            let _ = writeln!(
                failure,
                "per-rule precision: {rule} at {precision:.3} < \
                 {PER_RULE_PRECISION_FLOOR} over {} observations — false positives:",
                stat.observations()
            );
            for location in &stat.false_positive_locations {
                let _ = writeln!(failure, "  {location}");
            }
        }

        if stat.observations() < CALIBRATION_MIN_OBSERVATIONS {
            continue;
        }
        let Some(label) = confidence.get(rule) else {
            continue;
        };
        let required = match label.as_str() {
            "high" => Some(HIGH_CONFIDENCE_PRECISION),
            "medium" => Some(MEDIUM_CONFIDENCE_PRECISION),
            _ => None,
        };
        if let Some(required) = required {
            if precision < required {
                let _ = writeln!(
                    failure,
                    "confidence calibration (demote-only): {rule} is labelled \
                     {label} but measures {precision:.3} < {required} over {} \
                     observations — fix the regex or demote the label",
                    stat.observations()
                );
            }
        }
    }

    failure
}

/// The `negative/` corpus pins the false-positive audit: each fixture
/// names rules with `aegis:expect-none` and those rules must produce zero
/// findings in that file, exempting only the directive lines themselves.
/// Findings from *other* rules are ignored here — a realistic YAML or JS
/// fixture trips unrelated advisory rules, and their false positives are
/// the positive corpus's job to measure.
#[test]
fn negative_corpus_pins_rule_silence() {
    let scanner = bundled_scanner();
    let root = corpus_root().join("negative");
    let files = collect_sources(&root);

    assert!(
        files.len() >= MIN_NEGATIVE_FILES,
        "negative corpus shrank: only {} files (need >= {MIN_NEGATIVE_FILES})",
        files.len()
    );

    let mut pinned_rules: HashSet<String> = HashSet::new();
    let mut failures: Vec<String> = Vec::new();

    for (relative, content) in &files {
        let (rules, exempt_lines) = expect_none_rules(content);
        assert!(
            !rules.is_empty(),
            "negative/{relative} carries no aegis:expect-none directive"
        );
        pinned_rules.extend(rules.iter().cloned());

        for finding in scanner.scan_string(content, relative) {
            if rules.contains(&finding.pattern) && !exempt_lines.contains(&finding.location.line) {
                failures.push(format!(
                    "negative/{relative}:{}: pinned rule {} fired outside its \
                     directive lines",
                    finding.location.line, finding.pattern
                ));
            }
        }
    }

    assert!(
        pinned_rules.len() >= MIN_PINNED_RULES,
        "negative corpus pins only {} rules (need >= {MIN_PINNED_RULES}); the \
         false-positive audit's regression fixtures must not be deleted",
        pinned_rules.len()
    );
    assert!(
        failures.is_empty(),
        "negative-corpus silence violations:\n{}",
        failures.join("\n")
    );
}
