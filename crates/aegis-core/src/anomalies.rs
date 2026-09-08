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
//! Detectors are intentionally bounded: each reports only its single most
//! extreme file, so one scan adds at most a handful of findings regardless of
//! repository size.

use std::collections::HashSet;

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

/// Run every detector over the collected metrics.
///
/// Each detector contributes at most one observation — its most extreme
/// file — so the post-pass stays bounded on repositories of any size.
#[must_use]
pub fn analyze_anomalies(metrics: &[FileMetrics]) -> Vec<AnomalyObservation> {
    if metrics.len() < MIN_FILES {
        return Vec::new();
    }

    let mut observations = Vec::new();
    observations.extend(comment_ratio_outlier(metrics));
    observations.extend(comment_concentration(metrics));
    observations.extend(identifier_diversity_outlier(metrics));
    observations.extend(file_size_outlier(metrics));
    observations
}

/// Files with a comment share far above the repository norm — the hallmark
/// of narrated, generated, or padded code.
fn comment_ratio_outlier(metrics: &[FileMetrics]) -> Option<AnomalyObservation> {
    let population: Vec<&FileMetrics> = metrics
        .iter()
        .filter(|m| m.line_count >= MIN_LINES_FOR_RATIO && m.blank_lines < m.line_count)
        .collect();
    if population.len() < MIN_FILES {
        return None;
    }

    let ratios: Vec<f64> = population
        .iter()
        .map(|m| f64::from(m.comment_lines) / f64::from(m.line_count - m.blank_lines))
        .collect();
    let (mean, stddev) = mean_and_stddev(&ratios)?;

    let mut best_z = f64::NEG_INFINITY;
    let mut best_index: Option<usize> = None;
    for (index, ratio) in ratios.iter().enumerate() {
        let z = (ratio - mean) / stddev;
        if z > Z_OUTLIER && z > best_z {
            best_z = z;
            best_index = Some(index);
        }
    }
    let index = best_index?;
    let z = best_z;
    let file = population[index];

    let outliers = ratios
        .iter()
        .filter(|r| (**r - mean) / stddev > Z_OUTLIER)
        .count();
    let description = format!(
        "Comment lines make up {ratio:.0}% of this file's non-blank lines versus a \
         repository mean of {mean:.0}% (z = {z:.1}, {outliers} file(s) above the \
         outlier threshold). Unusually narrated for this codebase; worth a look \
         when the comments explain what the code should do rather than what it does.",
        ratio = ratios[index] * 100.0,
    );
    Some(AnomalyObservation {
        pattern_name: "comment-ratio-outlier".to_string(),
        path: file.path.clone(),
        evidence: format!("comment_ratio={:.2}", ratios[index]),
        description,
    })
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

/// Files reusing a tiny identifier vocabulary far below the repository norm —
/// the statistical footprint of pasted-in or templated repetition.
fn identifier_diversity_outlier(metrics: &[FileMetrics]) -> Option<AnomalyObservation> {
    let population: Vec<&FileMetrics> = metrics
        .iter()
        .filter(|m| m.identifier_tokens >= MIN_IDENTIFIER_TOKENS)
        .collect();
    if population.len() < MIN_FILES {
        return None;
    }

    let diversities: Vec<f64> = population
        .iter()
        .map(|m| f64::from(m.unique_identifiers) / f64::from(m.identifier_tokens))
        .collect();
    let (mean, stddev) = mean_and_stddev(&diversities)?;

    let mut best_z = f64::INFINITY;
    let mut best_index: Option<usize> = None;
    for (index, diversity) in diversities.iter().enumerate() {
        let z = (diversity - mean) / stddev;
        let is_outlier = z < -Z_OUTLIER && *diversity < 0.2;
        if is_outlier && z < best_z {
            best_z = z;
            best_index = Some(index);
        }
    }
    let index = best_index?;
    let z = best_z;
    let file = population[index];

    let description = format!(
        "Identifier diversity is {diversity:.2} versus a repository mean of {mean:.2} \
         (z = {z:.1}): the same small vocabulary reused across {} tokens. Repetition \
         at this scale usually means copy-paste or template expansion rather than \
         fresh code.",
        file.identifier_tokens,
        diversity = diversities[index],
    );
    Some(AnomalyObservation {
        pattern_name: "identifier-diversity-outlier".to_string(),
        path: file.path.clone(),
        evidence: format!(
            "identifier_diversity={:.2}",
            f64::from(file.unique_identifiers) / f64::from(file.identifier_tokens)
        ),
        description,
    })
}

/// Files dramatically larger than every sibling — where generated dumps,
/// bundled artifacts, or an unresolved refactor tend to hide.
fn file_size_outlier(metrics: &[FileMetrics]) -> Option<AnomalyObservation> {
    let sizes: Vec<f64> = metrics
        .iter()
        .map(|m| f64::from(m.line_count))
        .filter(|size| *size > 0.0)
        .collect();
    if sizes.len() < MIN_FILES {
        return None;
    }
    let (mean, stddev) = mean_and_stddev(&sizes)?;

    let mut best_z = f64::NEG_INFINITY;
    let mut best_file: Option<&FileMetrics> = None;
    for file in metrics {
        let z = (f64::from(file.line_count) - mean) / stddev;
        if z > Z_OUTLIER && z > best_z {
            best_z = z;
            best_file = Some(file);
        }
    }
    let z = best_z;
    let file = best_file?;

    let outliers = metrics
        .iter()
        .filter(|m| (f64::from(m.line_count) - mean) / stddev > Z_OUTLIER)
        .count();
    let description = format!(
        "At {} lines this file is {z:.1} standard deviations above the repository \
         mean of {mean:.0} ({outliers} file(s) above the outlier threshold). Size \
         outliers are where generated dumps and unsplit modules accumulate.",
        file.line_count,
    );
    Some(AnomalyObservation {
        pattern_name: "file-size-outlier".to_string(),
        path: file.path.clone(),
        evidence: format!("line_count={}", file.line_count),
        description,
    })
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
}
