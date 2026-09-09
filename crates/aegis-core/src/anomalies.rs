//! Statistical anomaly detection over per-file scan metrics.
//!
//! Regex rules judge single lines; this layer judges the repository's shape.
//! After a directory scan it looks for files that sit outside the norm of
//! their own codebase: a comment density far from every other file, a single
//! file absorbing most of the repository's commentary (a Pareto
//! concentration), copy-pasted identifier churn, or a size outlier. These are
//! informative `Severity::Info` observations — never risk-scored, never
//! CI-failing — because the underlying literature on automated AI-text
//! detection shows lexical and distributional cues degrade sharply under
//! paraphrase and routinely fire on formulaic human work.
//!
//! The z-score detectors compare each file against its own language group —
//! the population of eligible files sharing its extension — rather than the
//! whole repository. Comment conventions differ too much between languages
//! for a mixed baseline to mean anything: a narrated Python file judged
//! against terse Rust siblings is a false outlier, not a finding. A group
//! smaller than [`MIN_FILES`] supports no z-score, so minority-language files
//! are simply not judged rather than judged against someone else's norm. The
//! Pareto detector is the exception: comment concentration is a property of
//! the repository total by definition.
//!
//! Detectors are intentionally bounded: each reports only its single most
//! extreme file, so one scan adds at most a handful of findings regardless of
//! repository size.

use std::collections::{HashMap, HashSet};

use lazy_static::lazy_static;
use regex::Regex;

/// Minimum files that must be analyzed before any detector is trusted. A
/// z-score computed over four files is folklore, not statistics.
const MIN_FILES: usize = 8;

/// Minimum line count for a file to take part in ratio-based detectors.
const MIN_LINES_FOR_RATIO: u32 = 10;

/// Minimum identifier tokens before the diversity ratio is meaningful.
const MIN_IDENTIFIER_TOKENS: u32 = 200;

/// Minimum repository-wide comment lines before the Pareto detector runs.
const MIN_REPO_COMMENT_LINES: u32 = 200;

/// Comment share of a single file that counts as a Pareto concentration.
const PARETO_CONCENTRATION: f64 = 0.6;

/// Standard deviations from the repository mean that qualify as an outlier.
const Z_OUTLIER: f64 = 2.5;

/// Every statistical detector, in the order `analyze_anomalies` runs them.
/// These are the names accepted by a detector allow-list.
pub const DETECTOR_NAMES: [&str; 4] = [
    "comment-ratio-outlier",
    "comment-concentration",
    "identifier-diversity-outlier",
    "file-size-outlier",
];

/// Validate a detector allow-list, naming the unknown entries. An empty list
/// is valid: it disables the layer entirely.
///
/// # Errors
///
/// Returns a message listing every name that is not in [`DETECTOR_NAMES`],
/// so a typo cannot silently disable the layer.
pub fn validate_detector_names(names: &[String]) -> Result<(), String> {
    let unknown: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|name| !DETECTOR_NAMES.contains(name))
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    Err(format!(
        "unknown anomaly detector(s): {}. valid detectors: {}",
        unknown.join(", "),
        DETECTOR_NAMES.join(", "),
    ))
}

// Line-based identifier tokens; length ≥ 2 so ubiquitous single-character
// loop counters do not dominate the count.
lazy_static! {
    static ref IDENTIFIER_RE: Regex = Regex::new(r"[A-Za-z_][A-Za-z0-9_]{1,}").unwrap();
}

/// File extensions that carry prose rather than code. Comment heuristics are
/// meaningless there (every Markdown heading looks like a `#` comment), so
/// prose files never enter the statistics.
const PROSE_EXTENSIONS: [&str; 6] = ["md", "markdown", "mdx", "rst", "adoc", "txt"];

/// Generated or vendored artifacts whose size and density say nothing about
/// the code a human wrote next to them.
const GENERATED_BASENAMES: [&str; 8] = [
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "poetry.lock",
    "composer.lock",
    "Gemfile.lock",
    "go.sum",
];

/// Per-file measurements feeding the anomaly detectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetrics {
    /// File path as reported in findings.
    pub path: String,
    /// Total line count.
    pub line_count: u32,
    /// Lines that look like comments under the line-prefix heuristic.
    pub comment_lines: u32,
    /// Whitespace-only lines.
    pub blank_lines: u32,
    /// Length of the longest line, in characters.
    pub max_line_length: usize,
    /// Sum of line lengths, in characters (mean-line-length denominators).
    pub total_line_length: u64,
    /// Identifier-shaped tokens seen (length ≥ 2).
    pub identifier_tokens: u32,
    /// Distinct identifier-shaped tokens seen.
    pub unique_identifiers: u32,
}

/// One anomaly observation, converted to an `Severity::Info` finding by the
/// scanner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnomalyObservation {
    /// Stable rule name, e.g. `comment-ratio-outlier`.
    pub pattern_name: String,
    /// File the observation is about.
    pub path: String,
    /// The measured value that triggered the rule (also the finding's
    /// matched content, so baselines can suppress it on rescan).
    pub evidence: String,
    /// Human-readable explanation including the repository baseline.
    pub description: String,
}

/// True when a file should take part in anomaly statistics.
///
/// Prose documents and generated lockfiles are excluded: their comment
/// heuristics are meaningless and their sizes are stable repository
/// fixtures that would otherwise be permanent size outliers.
#[must_use]
fn is_metrics_eligible(path: &str) -> bool {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    // Dotfiles (.gitignore, .aegisignore, .editorconfig) are configuration
    // written as commentary; their comment share is by design and would be
    // a permanent false outlier.
    if name.starts_with('.') {
        return false;
    }
    if GENERATED_BASENAMES.contains(&name) {
        return false;
    }
    let Some(dot) = name.rfind('.') else {
        // Extensionless source (Makefile, Dockerfile) is ordinary code.
        return true;
    };
    let ext = &name[dot + 1..];
    if PROSE_EXTENSIONS.contains(&ext) {
        return false;
    }
    // Minified bundles (`app.min.js`) and source maps are machine output.
    !(ext == "map" || name.contains(".min."))
}

/// Comment heuristic: a trimmed line whose first characters are a comment
/// opener. Deliberately crude — this layer reasons in bulk, so per-line
/// precision matters less than applying the same ruler to every file.
fn is_comment_like(trimmed: &str) -> bool {
    for prefix in ["//", "#", "/*", "*", "<!--", "--"] {
        if trimmed.starts_with(prefix) {
            // A shebang is an executable directive, not commentary.
            if prefix == "#" && trimmed.starts_with("#!") {
                return false;
            }
            return true;
        }
    }
    false
}

/// Measure one file's content.
///
/// Returns [`None`] for prose and generated files, which never take part in
/// the statistics (see [`is_metrics_eligible`]).
#[must_use]
pub fn compute_metrics(path: &str, content: &str) -> Option<FileMetrics> {
    if !is_metrics_eligible(path) {
        return None;
    }

    let mut metrics = FileMetrics {
        path: path.to_string(),
        line_count: 0,
        comment_lines: 0,
        blank_lines: 0,
        max_line_length: 0,
        total_line_length: 0,
        identifier_tokens: 0,
        unique_identifiers: 0,
    };
    let mut seen = HashSet::new();

    for line in content.lines() {
        metrics.line_count += 1;
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            metrics.blank_lines += 1;
        } else if is_comment_like(trimmed) {
            metrics.comment_lines += 1;
        }
        metrics.max_line_length = metrics.max_line_length.max(line.chars().count());
        metrics.total_line_length += u64::try_from(line.chars().count()).unwrap_or(u64::MAX);
        for token in IDENTIFIER_RE.find_iter(line) {
            metrics.identifier_tokens += 1;
            if seen.insert(token.as_str().to_string()) {
                metrics.unique_identifiers += 1;
            }
        }
    }

    Some(metrics)
}

/// Population standard deviation; [`None`] when every value is identical, so
/// a z-score cannot be computed.
fn mean_and_stddev(values: &[f64]) -> Option<(f64, f64)> {
    if values.is_empty() {
        return None;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / values.len() as f64;
    let stddev = variance.sqrt();
    if stddev <= f64::EPSILON {
        None
    } else {
        Some((mean, stddev))
    }
}

/// The language-group key for a path: its extension, or the empty string for
/// extensionless sources (Makefile, Dockerfile), which are judged as one
/// group of their own. Matched case-sensitively, consistent with the
/// extension checks in [`is_metrics_eligible`].
fn language_key(path: &str) -> &str {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    match name.rfind('.') {
        Some(dot) => &name[dot + 1..],
        None => "",
    }
}

/// Group metrics by extension for per-language baselines. Sorted by key so
/// detector output does not depend on `HashMap` iteration order.
fn group_by_language<'a>(metrics: &[&'a FileMetrics]) -> Vec<(&'a str, Vec<&'a FileMetrics>)> {
    let mut groups: HashMap<&str, Vec<&FileMetrics>> = HashMap::new();
    for m in metrics {
        groups.entry(language_key(&m.path)).or_default().push(m);
    }
    let mut grouped: Vec<(&str, Vec<&FileMetrics>)> = groups.into_iter().collect();
    grouped.sort_by_key(|(key, _)| *key);
    grouped
}

/// Run every detector over the collected metrics.
///
/// Each detector contributes at most one observation — its most extreme
/// file — so the post-pass stays bounded on repositories of any size.
#[must_use]
pub fn analyze_anomalies(metrics: &[FileMetrics]) -> Vec<AnomalyObservation> {
    analyze_anomalies_with(metrics, None)
}

/// Run only the allowed detectors over the collected metrics.
///
/// `None` runs every detector; a list runs exactly the detectors named in
/// it (an empty list runs none, disabling the layer). Each detector still
/// contributes at most one observation.
#[must_use]
pub fn analyze_anomalies_with(
    metrics: &[FileMetrics],
    allowed: Option<&[String]>,
) -> Vec<AnomalyObservation> {
    if metrics.len() < MIN_FILES {
        return Vec::new();
    }
    let runs = |name: &str| {
        allowed.map_or(true, |list| {
            list.iter().any(|allowed_name| allowed_name == name)
        })
    };

    let mut observations = Vec::new();
    if runs("comment-ratio-outlier") {
        observations.extend(comment_ratio_outlier(metrics));
    }
    if runs("comment-concentration") {
        observations.extend(comment_concentration(metrics));
    }
    if runs("identifier-diversity-outlier") {
        observations.extend(identifier_diversity_outlier(metrics));
    }
    if runs("file-size-outlier") {
        observations.extend(file_size_outlier(metrics));
    }
    observations
}

/// Files with a comment share far above their language group's norm — the
/// hallmark of narrated, generated, or padded code.
fn comment_ratio_outlier(metrics: &[FileMetrics]) -> Option<AnomalyObservation> {
    let eligible: Vec<&FileMetrics> = metrics
        .iter()
        .filter(|m| m.line_count >= MIN_LINES_FOR_RATIO && m.blank_lines < m.line_count)
        .collect();

    let mut best: Option<AnomalyObservation> = None;
    let mut best_z = f64::NEG_INFINITY;
    for (extension, group) in group_by_language(&eligible) {
        if group.len() < MIN_FILES {
            continue;
        }

        let ratios: Vec<f64> = group
            .iter()
            .map(|m| f64::from(m.comment_lines) / f64::from(m.line_count - m.blank_lines))
            .collect();
        let Some((mean, stddev)) = mean_and_stddev(&ratios) else {
            continue;
        };

        for (index, ratio) in ratios.iter().enumerate() {
            let z = (ratio - mean) / stddev;
            if z > Z_OUTLIER && z > best_z {
                best_z = z;
                let description = format!(
                    "Comment lines make up {ratio:.0}% of this file's non-blank lines \
                     versus a mean of {mean:.0}% across its {} .{extension} peers \
                     (z = {z:.1}). Unusually narrated for this codebase; worth a \
                     look when the comments explain what the code should do rather \
                     than what it does.",
                    group.len(),
                );
                best = Some(AnomalyObservation {
                    pattern_name: "comment-ratio-outlier".to_string(),
                    path: group[index].path.clone(),
                    evidence: format!("comment_ratio={ratio:.2}"),
                    description,
                });
            }
        }
    }
    best
}

/// Pareto concentration: one file absorbing most of the repository's
/// commentary, as when generated output or a copy-pasted walkthrough lands
/// in the middle of otherwise terse code.
fn comment_concentration(metrics: &[FileMetrics]) -> Option<AnomalyObservation> {
    let total: u32 = metrics.iter().map(|m| m.comment_lines).sum();
    if total < MIN_REPO_COMMENT_LINES {
        return None;
    }

    let (file, share) = metrics
        .iter()
        .map(|m| (m, f64::from(m.comment_lines) / f64::from(total)))
        .max_by(|a, b| a.1.total_cmp(&b.1))?;
    if share < PARETO_CONCENTRATION {
        return None;
    }

    let description = format!(
        "This file holds {share:.0}% of the repository's {total} comment lines. One file \
         dominating commentary is a Pareto-style concentration; check whether \
         documentation that belongs in docs/ or a design note landed in code.",
    );
    Some(AnomalyObservation {
        pattern_name: "comment-concentration".to_string(),
        path: file.path.clone(),
        evidence: format!("comment_share={share:.2}"),
        description,
    })
}

/// Files reusing a tiny identifier vocabulary far below their language
/// group's norm — the statistical footprint of pasted-in or templated
/// repetition.
fn identifier_diversity_outlier(metrics: &[FileMetrics]) -> Option<AnomalyObservation> {
    let eligible: Vec<&FileMetrics> = metrics
        .iter()
        .filter(|m| m.identifier_tokens >= MIN_IDENTIFIER_TOKENS)
        .collect();

    let mut best: Option<AnomalyObservation> = None;
    let mut best_z = f64::INFINITY;
    for (extension, group) in group_by_language(&eligible) {
        if group.len() < MIN_FILES {
            continue;
        }

        let diversities: Vec<f64> = group
            .iter()
            .map(|m| f64::from(m.unique_identifiers) / f64::from(m.identifier_tokens))
            .collect();
        let Some((mean, stddev)) = mean_and_stddev(&diversities) else {
            continue;
        };

        for (index, diversity) in diversities.iter().enumerate() {
            let z = (diversity - mean) / stddev;
            let is_outlier = z < -Z_OUTLIER && *diversity < 0.2;
            if is_outlier && z < best_z {
                best_z = z;
                let file = group[index];
                let description = format!(
                    "Identifier diversity is {diversity:.2} versus a mean of {mean:.2} \
                     across its {} .{extension} peers (z = {z:.1}): the same small \
                     vocabulary reused across {} tokens. Repetition at this scale \
                     usually means copy-paste or template expansion rather than \
                     fresh code.",
                    group.len(),
                    file.identifier_tokens,
                );
                best = Some(AnomalyObservation {
                    pattern_name: "identifier-diversity-outlier".to_string(),
                    path: file.path.clone(),
                    evidence: format!("identifier_diversity={diversity:.2}"),
                    description,
                });
            }
        }
    }
    best
}

/// Files dramatically larger than every same-language sibling — where
/// generated dumps, bundled artifacts, or an unresolved refactor tend to hide.
fn file_size_outlier(metrics: &[FileMetrics]) -> Option<AnomalyObservation> {
    let eligible: Vec<&FileMetrics> = metrics.iter().filter(|m| m.line_count > 0).collect();

    let mut best: Option<AnomalyObservation> = None;
    let mut best_z = f64::NEG_INFINITY;
    for (extension, group) in group_by_language(&eligible) {
        if group.len() < MIN_FILES {
            continue;
        }

        let sizes: Vec<f64> = group.iter().map(|m| f64::from(m.line_count)).collect();
        let Some((mean, stddev)) = mean_and_stddev(&sizes) else {
            continue;
        };

        for file in &group {
            let z = (f64::from(file.line_count) - mean) / stddev;
            if z > Z_OUTLIER && z > best_z {
                best_z = z;
                let description = format!(
                    "At {} lines this file is {z:.1} standard deviations above the \
                     {} .{extension} mean of {mean:.0}. Size outliers are where \
                     generated dumps and unsplit modules accumulate.",
                    file.line_count,
                    group.len(),
                );
                best = Some(AnomalyObservation {
                    pattern_name: "file-size-outlier".to_string(),
                    path: file.path.clone(),
                    evidence: format!("line_count={}", file.line_count),
                    description,
                });
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a metrics row without spelling every field at every call site.
    fn metrics(path: &str, lines: u32, comments: u32, blanks: u32) -> FileMetrics {
        FileMetrics {
            path: path.to_string(),
            line_count: lines,
            comment_lines: comments,
            blank_lines: blanks,
            max_line_length: 80,
            total_line_length: u64::from(lines) * 40,
            identifier_tokens: 300,
            unique_identifiers: 150,
        }
    }

    /// A homogeneous population: `count` identical-shape code files.
    fn uniform_population(count: u32) -> Vec<FileMetrics> {
        (0..count)
            .map(|i| metrics(&format!("src/file{i}.rs"), 100, 10, 10))
            .collect()
    }

    #[test]
    fn metrics_count_lines_comments_and_blanks() {
        let content = "// header\n\nlet x = 1; // inline tail is not a comment line\n# shell-ish\n#!/usr/bin/env bash\n";
        let m = compute_metrics("src/example.sh", content).unwrap();
        assert_eq!(m.line_count, 5);
        // `// header`, `# shell-ish` count; the blank and the shebang do not;
        // `let x = 1; // ...` does not start with a comment opener.
        assert_eq!(m.comment_lines, 2);
        assert_eq!(m.blank_lines, 1);
    }

    #[test]
    fn metrics_count_identifiers_uniquely() {
        let m = compute_metrics("a.rs", "alpha beta alpha\nbeta gamma\n").unwrap();
        // alpha, beta, alpha, beta, gamma
        assert_eq!(m.identifier_tokens, 5);
        assert_eq!(m.unique_identifiers, 3);
    }

    #[test]
    fn prose_and_generated_files_are_excluded() {
        assert!(compute_metrics("README.md", "# heading\n").is_none());
        assert!(compute_metrics("docs/guide.markdown", "text\n").is_none());
        assert!(compute_metrics("package-lock.json", "{}\n").is_none());
        assert!(compute_metrics("web/dist/app.min.js", "var a=1;\n").is_none());
        assert!(compute_metrics("web/dist/app.js.map", "{}\n").is_none());
        // Dotfiles are configuration-by-commentary, never statistics.
        assert!(compute_metrics(".aegisignore", "# keep docs clean\n").is_none());
        assert!(compute_metrics(".gitignore", "target/\n").is_none());
        // Ordinary code and extensionless sources stay eligible.
        assert!(compute_metrics("src/main.rs", "fn main() {}\n").is_some());
        assert!(compute_metrics("Makefile", "all:\n").is_some());
    }

    #[test]
    fn minified_extensions_are_ineligible() {
        assert!(!is_metrics_eligible("assets/bundle.min.css"));
        assert!(is_metrics_eligible("assets/bundle.css"));
    }

    #[test]
    fn too_few_files_produce_no_observations() {
        let below_threshold = u32::try_from(MIN_FILES - 1).unwrap_or(0);
        let population: Vec<FileMetrics> = uniform_population(below_threshold);
        assert!(analyze_anomalies(&population).is_empty());
    }

    #[test]
    fn uniform_population_produce_no_observations() {
        assert!(analyze_anomalies(&uniform_population(40)).is_empty());
    }

    #[test]
    fn identical_values_short_circuit_z_scores() {
        // Every ratio identical => stddev 0 => detector returns quietly.
        let population = uniform_population(20);
        assert!(comment_ratio_outlier(&population).is_none());
    }

    #[test]
    fn comment_ratio_outlier_flags_the_extreme_file() {
        let mut population = uniform_population(20);
        population.push(metrics("src/narrated.rs", 100, 90, 5));
        let observations = analyze_anomalies(&population);
        let hit = observations
            .iter()
            .find(|o| o.pattern_name == "comment-ratio-outlier")
            .unwrap();
        assert_eq!(hit.path, "src/narrated.rs");
        assert!(hit.description.contains("z = "));
    }

    #[test]
    fn comment_ratio_ignores_small_files() {
        let mut population = uniform_population(20);
        // A 5-line file is entirely comments but below MIN_LINES_FOR_RATIO.
        population.push(metrics("src/tiny.rs", 5, 5, 0));
        assert!(comment_ratio_outlier(&population).is_none());
    }

    #[test]
    fn comment_concentration_flags_pareto_dominance() {
        let mut population = uniform_population(20);
        // Repo total 20*10 = 200; one file with 300 of 500 = 60%.
        population.push(metrics("src/wall_of_text.rs", 400, 300, 10));
        let observations = analyze_anomalies(&population);
        let hit = observations
            .iter()
            .find(|o| o.pattern_name == "comment-concentration")
            .unwrap();
        assert_eq!(hit.path, "src/wall_of_text.rs");
    }

    #[test]
    fn comment_concentration_needs_enough_commentary() {
        // 20 files * 2 comments = 40 total: real share, but under the floor.
        let mut population = uniform_population(20);
        population.push(metrics("src/mostly_comments.rs", 40, 30, 2));
        assert!(comment_concentration(&population).is_none());
    }

    #[test]
    fn identifier_diversity_flags_repetition() {
        let mut population = uniform_population(20);
        population.push(FileMetrics {
            path: "src/templated.rs".to_string(),
            line_count: 300,
            comment_lines: 10,
            blank_lines: 10,
            max_line_length: 80,
            total_line_length: 12_000,
            identifier_tokens: 400,
            unique_identifiers: 30,
        });
        let observations = analyze_anomalies(&population);
        let hit = observations
            .iter()
            .find(|o| o.pattern_name == "identifier-diversity-outlier")
            .unwrap();
        assert_eq!(hit.path, "src/templated.rs");
    }

    #[test]
    fn identifier_diversity_needs_token_volume() {
        let mut population = uniform_population(20);
        // 150 tokens is below MIN_IDENTIFIER_TOKENS even at zero diversity.
        population.push(FileMetrics {
            path: "src/short_repetitive.rs".to_string(),
            line_count: 300,
            comment_lines: 10,
            blank_lines: 10,
            max_line_length: 80,
            total_line_length: 12_000,
            identifier_tokens: 150,
            unique_identifiers: 5,
        });
        assert!(identifier_diversity_outlier(&population).is_none());
    }

    #[test]
    fn file_size_outlier_flags_the_extreme_file() {
        let mut population = uniform_population(20);
        population.push(metrics("src/generated_dump.rs", 3_000, 30, 100));
        let observations = analyze_anomalies(&population);
        let hit = observations
            .iter()
            .find(|o| o.pattern_name == "file-size-outlier")
            .unwrap();
        assert_eq!(hit.path, "src/generated_dump.rs");
        assert!(hit.evidence.contains("line_count=3000"));
    }

    #[test]
    fn only_the_most_extreme_outlier_is_reported() {
        // Three heavily-narrated files clear or approach the outlier
        // threshold; the ratio detector still yields a single observation —
        // its most extreme member.
        let mut population = uniform_population(20);
        population.push(metrics("src/narrated_a.rs", 100, 90, 5));
        population.push(metrics("src/narrated_b.rs", 100, 85, 5));
        population.push(metrics("src/narrated_c.rs", 100, 80, 5));
        let observations = analyze_anomalies(&population);
        let ratio_hits = observations
            .iter()
            .filter(|o| o.pattern_name == "comment-ratio-outlier")
            .count();
        assert_eq!(ratio_hits, 1);
        // And it is the most extreme of the candidates.
        assert_eq!(observations[0].path, "src/narrated_a.rs");
    }

    #[test]
    fn mean_and_stddev_reject_constant_input() {
        assert!(mean_and_stddev(&[]).is_none());
        assert!(mean_and_stddev(&[2.0, 2.0, 2.0]).is_none());
        let (mean, stddev) = mean_and_stddev(&[1.0, 2.0, 3.0]).unwrap();
        assert!((mean - 2.0).abs() < 1e-9);
        assert!((stddev - (2.0_f64 / 3.0).sqrt()).abs() < 1e-9);
    }

    #[test]
    fn shebang_is_not_a_comment() {
        assert!(!is_comment_like("#!/usr/bin/env python3"));
        assert!(is_comment_like("# section"));
    }

    #[test]
    fn language_key_is_the_extension() {
        assert_eq!(language_key("src/main.rs"), "rs");
        assert_eq!(language_key("lib/app.min.js"), "js");
        assert_eq!(language_key("Makefile"), "");
        assert_eq!(language_key("windows\\lib\\mod.py"), "py");
    }

    #[test]
    fn minority_language_files_are_not_judged_against_other_languages() {
        // Twenty terse Rust files plus one heavily-narrated Python file.
        // Globally the Python file is an extreme outlier (90% vs 10%); with
        // per-language baselines its group holds one file, below MIN_FILES,
        // so it is never judged against the Rust norm.
        let mut population = uniform_population(20);
        population.push(metrics("scripts/helper.py", 100, 90, 5));
        let observations = analyze_anomalies(&population);
        assert!(observations
            .iter()
            .all(|o| o.pattern_name != "comment-ratio-outlier"));
    }

    #[test]
    fn same_language_outlier_is_judged_against_its_own_extension() {
        // The narrated file now has twenty .py peers, so the group supports a
        // z-score and the outlier is flagged against Python's own baseline.
        let mut population: Vec<FileMetrics> = (0..20)
            .map(|i| metrics(&format!("src/module{i}.py"), 100, 10, 10))
            .collect();
        population.push(metrics("src/narrated.py", 100, 90, 5));
        let observations = analyze_anomalies(&population);
        let hit = observations
            .iter()
            .find(|o| o.pattern_name == "comment-ratio-outlier")
            .unwrap();
        assert_eq!(hit.path, "src/narrated.py");
        assert!(hit.description.contains(".py"));
    }

    #[test]
    fn file_size_outliers_are_grouped_by_extension() {
        // A 3_000-line .js file among ten 100-line .js peers is a real size
        // outlier; the same physical size in a lone .svg is not judged.
        let mut population = uniform_population(20);
        for i in 0..10 {
            population.push(metrics(&format!("web/bundle{i}.js"), 100, 10, 10));
        }
        population.push(metrics("web/generated_dump.js", 3_000, 30, 100));
        let observations = analyze_anomalies(&population);
        let hit = observations
            .iter()
            .find(|o| o.pattern_name == "file-size-outlier")
            .unwrap();
        assert_eq!(hit.path, "web/generated_dump.js");

        let mut isolated = uniform_population(20);
        for i in 0..10 {
            isolated.push(metrics(&format!("web/bundle{i}.js"), 100, 10, 10));
        }
        isolated.push(metrics("assets/diagram.svg", 3_000, 30, 100));
        let observations = analyze_anomalies(&isolated);
        assert!(observations
            .iter()
            .all(|o| o.pattern_name != "file-size-outlier"));
    }

    #[test]
    fn identifier_diversity_groups_by_extension() {
        // Twenty terse-vocabulary .go files make low diversity the group
        // norm; a low-diversity .rs among diverse .rs peers stands out even
        // though the pooled statistics would have washed it out.
        let mut population: Vec<FileMetrics> = (0..20)
            .map(|i| FileMetrics {
                path: format!("src/handler{i}.go"),
                line_count: 200,
                comment_lines: 10,
                blank_lines: 10,
                max_line_length: 80,
                total_line_length: 8_000,
                identifier_tokens: 400,
                unique_identifiers: 40,
            })
            .collect();
        population.extend((0..20).map(|i| metrics(&format!("src/lib{i}.rs"), 200, 10, 10)));
        population.push(FileMetrics {
            path: "src/templated.rs".to_string(),
            line_count: 300,
            comment_lines: 10,
            blank_lines: 10,
            max_line_length: 80,
            total_line_length: 12_000,
            identifier_tokens: 400,
            unique_identifiers: 30,
        });
        let observations = analyze_anomalies(&population);
        let hit = observations
            .iter()
            .find(|o| o.pattern_name == "identifier-diversity-outlier")
            .unwrap();
        assert_eq!(hit.path, "src/templated.rs");
        assert!(hit.description.contains(".rs"));
    }

    /// A population guaranteed to trip both the comment-ratio and file-size
    /// detectors.
    fn outlier_population() -> Vec<FileMetrics> {
        let mut population = uniform_population(20);
        population.push(metrics("src/narrated.rs", 100, 90, 5));
        population.push(metrics("src/generated_dump.rs", 3_000, 30, 100));
        population
    }

    #[test]
    fn validate_detector_names_accepts_known_and_empty_lists() {
        assert!(validate_detector_names(&[]).is_ok());
        let all: Vec<String> = DETECTOR_NAMES
            .iter()
            .map(|name| (*name).to_string())
            .collect();
        assert!(validate_detector_names(&all).is_ok());
    }

    #[test]
    fn validate_detector_names_reports_unknown_entries() {
        let error = validate_detector_names(&["file-size-outlier".to_string(), "nope".to_string()])
            .unwrap_err();
        assert!(error.contains("nope"));
        assert!(error.contains("valid detectors:"));
        // A rejected name still appears alongside the valid ones it was
        // submitted with.
        assert!(error.contains("file-size-outlier"));
    }

    #[test]
    fn allow_list_runs_only_the_named_detectors() {
        let observations = analyze_anomalies_with(
            &outlier_population(),
            Some(&["file-size-outlier".to_string()]),
        );
        assert!(!observations.is_empty());
        assert!(observations
            .iter()
            .all(|o| o.pattern_name == "file-size-outlier"));
    }

    #[test]
    fn empty_allow_list_disables_every_detector() {
        assert!(analyze_anomalies_with(&outlier_population(), Some(&[])).is_empty());
        // Unset runs everything.
        assert!(!analyze_anomalies_with(&outlier_population(), None).is_empty());
    }
}
