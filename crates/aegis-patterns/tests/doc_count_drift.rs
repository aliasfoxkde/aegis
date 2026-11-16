//! Documentation drift guard for the rule corpus counts.
//!
//! Several documents state how many rules Aegis ships and how many
//! categories they span. Those numbers drift silently: a rule is added,
//! the corpus grows, and the prose keeps claiming the old total until
//! somebody notices by reading it.
//!
//! This test computes the live totals from the shipped corpus and asserts
//! that every place stating them states *these* totals. The phrases are
//! listed in [`TOTAL_CLAIMS`]; re-wording one of them means updating the
//! table below, which is the point — the number and the sentence that
//! carries it stay in lockstep.

use aegis_patterns::all_patterns;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

/// Repository root: this crate is a workspace member two levels below it.
///
/// The lookup is fallible, so it returns `None` rather than asserting
/// here — a helper outside a `#[test]` function may not call `expect`.
fn repo_root() -> Option<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
}

/// Collapse every whitespace run to a single space, so a phrase that wraps
/// across two lines in the source still matches the template.
fn normalize(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Live corpus totals.
#[derive(Debug)]
struct Corpus {
    total: usize,
    categories: usize,
    severities: BTreeMap<String, usize>,
}

impl Corpus {
    fn measure() -> Self {
        let patterns = all_patterns();
        let total = patterns.len();
        let categories = patterns
            .iter()
            .map(|p| p.category.as_str())
            .collect::<HashSet<_>>()
            .len();
        let mut severities: BTreeMap<String, usize> = BTreeMap::new();
        for p in &patterns {
            *severities.entry(p.severity.clone()).or_insert(0) += 1;
        }
        Self {
            total,
            categories,
            severities,
        }
    }

    fn severity(&self, name: &str) -> usize {
        self.severities.get(name).copied().unwrap_or(0)
    }

    /// Render a template with the live totals.
    ///
    /// Placeholders: `{n}` rules, `{c}` categories, and one placeholder per
    /// severity name (`{critical}`, `{high}`, `{medium}`, `{low}`, `{info}`).
    fn render(&self, template: &str) -> String {
        let mut out = template
            .replace("{n}", &self.total.to_string())
            .replace("{c}", &self.categories.to_string());
        for (name, count) in &self.severities {
            out = out.replace(&format!("{{{name}}}"), &count.to_string());
        }
        out
    }
}

/// Every prose claim about the corpus size, and the exact phrase each file
/// must contain. `{n}` is the rule count, `{c}` the category count, and the
/// remaining placeholders are per-severity counts.
///
/// Generated pages (`docs/patterns/`) are covered by the freshness test in
/// `registry_hygiene.rs`; dated records (`CHANGELOG.md`, `docs/audits/`,
/// `docs/handoffs/`, `docs/progress/`) are historical statements and are
/// deliberately not listed here.
const TOTAL_CLAIMS: &[(&str, &str)] = &[
    (
        "AGENTS.md",
        "Built in Rust with {n} detection patterns across {c} categories.",
    ),
    (
        "AGENTS.md",
        "- **Pattern count**: {n} enabled patterns across {c} categories",
    ),
    (
        ".github/CONTRIBUTING.md",
        "Aegis is a security scanner with {n} built-in patterns across {c} categories",
    ),
    (
        ".github/CONTRIBUTING.md",
        "aegis-patterns/   # {n} pattern definitions",
    ),
    (".github/wiki/Home.md", "**{n} patterns** across {c} categories"),
    (".github/wiki/Home.md", "**{n}** detection patterns"),
    (
        ".github/wiki/Home.md",
        "**{c}** pattern categories ({critical} critical, {high} high, {medium} medium, {low} low, {info} info)",
    ),
    (
        ".github/wiki/_Footer.md",
        "{n} patterns across {c} categories",
    ),
    (
        ".github/wiki/_Sidebar.md",
        "All {n} patterns, one detail page per category",
    ),
    (
        "PLATFORM_INTEGRATION.md",
        "the embedded rule set ({n} patterns)",
    ),
    (
        "docs/guides/BUILDING.md",
        "aegis-patterns/    # {n} pattern definitions",
    ),
    (
        "docs/planning/HANDOFF.md",
        "{n} compiled-in detection patterns across {c} categories",
    ),
    (
        "docs/planning/HANDOFF.md",
        "the {n} patterns as Rust source",
    ),
    (
        "docs/patterns/README.md",
        "Aegis ships **{n} detection patterns** across **{c} categories**.",
    ),
    ("docs/PLAN.md", "{n} across {c} categories"),
];

#[test]
fn documented_rule_counts_match_the_corpus() {
    let corpus = Corpus::measure();

    // The severity split must add up, otherwise the wiki breakdown can
    // never be reproduced from the corpus.
    let severity_sum: usize = corpus.severities.values().sum();
    assert_eq!(
        severity_sum, corpus.total,
        "severity counts sum to {severity_sum}, corpus holds {}",
        corpus.total
    );

    let root = repo_root().expect("crate must live inside the repository");
    let mut failures = Vec::new();
    for (relative, template) in TOTAL_CLAIMS {
        let path = root.join(relative);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        // Normalize both sides: a claim that wraps or pads with spaces in
        // the source still has to state the same numbers.
        let expected = normalize(&corpus.render(template));
        if !normalize(&text).contains(&expected) {
            failures.push(format!("{relative}: must contain {expected:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "documented rule counts drifted from the corpus ({} rules, {} categories):\n{}\n\
         Fix each file, or update the phrase in TOTAL_CLAIMS if it was reworded.",
        corpus.total,
        corpus.categories,
        failures.join("\n")
    );
}

/// A category claim is only meaningful against the shipped category list:
/// every category a rule carries must be dispatchable, and the count of
/// distinct categories is what the documents quote.
#[test]
fn documented_category_count_matches_dispatchable_categories() {
    let corpus = Corpus::measure();
    let dispatchable: HashSet<String> = all_patterns().iter().map(|p| p.category.clone()).collect();
    assert_eq!(
        dispatchable.len(),
        corpus.categories,
        "category count disagrees with the shipped category set"
    );
    for category in &dispatchable {
        assert!(
            !aegis_patterns::by_category(category).is_empty(),
            "category {category} is carried by rules but dispatches none"
        );
    }
}
