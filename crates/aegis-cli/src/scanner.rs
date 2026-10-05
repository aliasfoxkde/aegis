//! Scanner module

use crate::output::Output;
use crate::OutputFormat;
use aegis_core::{
    Finding, InspectionStatus, PatternDefinition, RiskScore, ScanOptions as CoreOptions,
    ScanReceipt, ScanStats, Scanner,
};
use anyhow::Result;
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;

/// The booleans mirror the CLI's scan flag set one-to-one; a settings enum
/// would force every caller to translate back into per-flag fields.
#[allow(clippy::struct_excessive_bools)]
pub struct ScanOptions {
    /// Target of the scan: the repository or directory root, or the single
    /// file when `scan_file` is set.
    pub path: PathBuf,
    /// Scan the single file at `path` instead of walking the tree.
    pub scan_file: bool,
    /// Scan the process environment for leaked credentials.
    pub scan_env: bool,
    /// Take the payload to scan from stdin rather than the filesystem.
    pub scan_stdin: bool,
    /// Descend into symbolic links while walking directories.
    pub follow_symlinks: bool,
    /// Comma-separated allowlist of pattern categories; `None` selects every
    /// category the bundle provides.
    pub categories: Option<String>,
    /// Lowest severity a finding must reach to be reported; `None` keeps all
    /// severities.
    pub severity_threshold: Option<String>,
    /// Destination that `run_scan_and_get_exit_code` writes the rendered
    /// report to; the scan itself only builds the report in memory.
    pub output_file: Option<PathBuf>,
    /// Baseline file (`--format json` output from a previous scan) whose
    /// findings are treated as pre-existing and filtered out
    pub baseline: Option<PathBuf>,
    /// Include disabled patterns in scan
    pub all: bool,
    /// Diff file to scan (only changed lines)
    pub diff: Option<PathBuf>,
    /// Scan the staged (index) content of the git repository at `path`
    /// instead of files on disk — pre-commit mode
    pub staged: bool,
    /// Comma-separated allowlist of statistical anomaly detectors; `None`
    /// runs all of them, an empty string runs none.
    pub anomaly_detectors: Option<String>,
    /// Detect copy-paste code clones while scanning; pairs land in
    /// `ScanStats::clones` and are rendered by the human and JSON formats
    /// without affecting findings or the exit code.
    pub detect_clones: bool,
    /// Renderer for the report buffer, mirroring the `--format` flag.
    pub format: OutputFormat,
    /// Suppress header and stats blocks so the buffer carries findings only.
    pub quiet: bool,
}

/// Build scanner from scan options (testable)
///
/// # Errors
///
/// Returns an error when the pattern bundle cannot be loaded, when a
/// configured baseline file is missing or unreadable, or when `categories`
/// names a category no pattern provides.
pub fn build_scanner_from_opts(opts: &ScanOptions) -> Result<Scanner> {
    // Trimmed, non-empty category list shared by the filter and validation
    let categories: Vec<String> = opts
        .categories
        .as_ref()
        .map(|c| {
            c.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    // Fail loudly on an unusable baseline rather than silently reporting
    // unfiltered results as if they were new-findings-only.
    if let Some(path) = &opts.baseline {
        aegis_core::scanner::load_baseline_fingerprints(path)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // Split the detector allow-list and fail loudly on unknown names, the
    // same way --categories does: a typo would otherwise silently disable
    // every detector.
    let anomaly_detectors: Option<Vec<String>> = opts.anomaly_detectors.as_ref().map(|list| {
        list.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    });
    if let Some(names) = &anomaly_detectors {
        aegis_core::anomalies::validate_detector_names(names)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // Fail loudly on an unusable --severity-threshold before any scan mode
    // runs. Directory and single-file scans are also guarded inside
    // aegis-core, but `--env`/`--stdin`/`--diff` never pass through those
    // entry points, and an unrecognized threshold there would silently
    // disable the filter and report more findings than requested.
    if let Some(threshold) = &opts.severity_threshold {
        let core_threshold = CoreOptions {
            severity_threshold: Some(threshold.clone()),
            ..Default::default()
        };
        core_threshold
            .validate()
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    let core_opts = CoreOptions {
        follow_symlinks: opts.follow_symlinks,
        categories: categories.clone(),
        severity_threshold: opts.severity_threshold.clone(),
        include_disabled: opts.all,
        diff_file: opts.diff.clone(),
        baseline: opts.baseline.clone(),
        anomaly_detectors,
        detect_clones: opts.detect_clones,
        ..Default::default()
    };

    let patterns = aegis_patterns::all_patterns();
    let definitions: Vec<PatternDefinition> = patterns.into_iter().map(Into::into).collect();
    let scanner = Scanner::from_definitions(definitions)
        .map_err(|e| anyhow::anyhow!("Failed to load patterns: {e}"))?
        .with_options(core_opts);

    // Persisted `aegis disable` choices narrow the registry before any
    // scan. A state file that exists but cannot be parsed fails the scan:
    // an ignored preference would silently change results.
    let state = crate::pattern_state::load(&crate::pattern_state::state_dir()?)?;
    crate::pattern_state::apply_to_registry(&state, scanner.registry());

    // Fail loudly on unknown --categories values; a typo would otherwise
    // filter every scanner out and report a clean pass.
    if !categories.is_empty() {
        scanner
            .registry()
            .validate_categories(&categories)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    Ok(scanner)
}

/// Fold findings into the coverage counters so reports, receipts, and the
/// JSON `stats` block agree with the `findings` list they accompany.
fn stats_with_findings(mut stats: ScanStats, findings: &[Finding]) -> ScanStats {
    for finding in findings {
        stats.add_finding(finding);
    }
    stats
}

/// Perform scan based on options (testable)
///
/// # Errors
///
/// Returns an error when the diff file cannot be read, when the target file
/// or directory cannot be scanned, or when `--staged` runs outside a git
/// repository.
pub fn perform_scan(scanner: &Scanner, opts: &ScanOptions) -> Result<(Vec<Finding>, ScanStats)> {
    let (findings, stats): (Vec<Finding>, ScanStats) = if let Some(diff_path) = &opts.diff {
        // Scan only changed lines from a diff file
        let diff_content = std::fs::read_to_string(diff_path)?;
        let findings = scanner.scan_diff(&diff_content, "diff");
        let stats = stats_with_findings(
            ScanStats::for_content(format!("diff:{}", diff_path.display()), diff_content.len()),
            &findings,
        );
        (findings, stats)
    } else if opts.scan_env {
        let findings = scanner.scan_env();
        let stats = stats_with_findings(ScanStats::for_environment(), &findings);
        (findings, stats)
    } else if opts.scan_stdin {
        // Stdin content is drained in async context by the caller and
        // handed to `execute_scan_with_stdin`; reaching this branch means
        // that wiring was bypassed. Scanning a decoy empty string would
        // report a clean pass nobody asked for.
        return Err(anyhow::anyhow!(
            "internal error: --stdin content must be scanned via execute_scan_with_stdin"
        ));
    } else if opts.scan_file {
        let path = &opts.path;
        if path.is_dir() {
            scanner.scan_dir(path).map_err(|e| anyhow::anyhow!("{e}"))?
        } else {
            scanner
                .scan_file(path)
                .map_err(|e| anyhow::anyhow!("{e}"))?
        }
    } else if opts.staged {
        scan_staged(scanner, opts)?
    } else {
        // `scan_file`/`scan_dir` already fold their findings into the
        // returned stats inside aegis-core.
        scanner
            .scan_dir(&opts.path)
            .map_err(|e| anyhow::anyhow!("{e}"))?
    };

    Ok((findings, stats))
}

/// List the paths staged in the git index at `root` (added, copied,
/// modified, renamed). Paths are relative to the repository root, which is
/// also the form `git show :<path>` expects.
fn staged_file_list(root: &Path) -> Result<Vec<String>> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "diff",
            "--cached",
            "--name-only",
            "-z",
            "--diff-filter=ACMR",
        ])
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run git: {e}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "git diff --cached failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .split('\0')
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect())
}

/// Read the staged blob for one index path.
fn staged_blob(root: &Path, file: &str) -> Result<Vec<u8>> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["show", &format!(":{file}")])
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run git: {e}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "git show :{file} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

/// Scan the staged (index) content of the repository at `opts.path`.
///
/// Pre-commit semantics: the index is what a commit would contain and it
/// can differ from the working tree, so blobs are read with
/// `git show :<path>` rather than from disk. Nothing staged means nothing
/// to scan and a clean result.
///
/// Every disposition lands in the inspection ledger, mirroring the
/// engine's own bookkeeping, so the receipt certifies what the pre-commit
/// pass did and did not inspect: the index enumeration itself is a
/// required analyzed unit (a repository with nothing staged was still
/// fully inspected), scanned blobs are required analyzed units, ignored
/// paths are non-required exclusions, and binary blobs are required
/// unsupported units — content the scanner cannot inspect must not exit
/// as a clean commit.
fn scan_staged(scanner: &Scanner, opts: &ScanOptions) -> Result<(Vec<Finding>, ScanStats)> {
    let files = staged_file_list(&opts.path).map_err(|e| {
        anyhow::anyhow!(
            "--staged requires a git repository at {}: {e}",
            opts.path.display()
        )
    })?;

    let mut findings = Vec::new();
    let mut stats = ScanStats::default();
    // `staged_file_list` succeeded, so the requested source — the git
    // index — was fully enumerated, entries or not. Recording it keeps the
    // receipt safe for the documented nothing-staged clean result instead
    // of an empty ledger that no consumer may treat as evidence.
    stats
        .inspection_ledger
        .record("git-index", InspectionStatus::Analyzed, true, None);
    for file in files {
        // Staged blobs bypass `scan_file`, so ignore rules are applied
        // here explicitly; otherwise a staged `.aegis/baseline.json`
        // would re-flag every secret the artifact documents.
        if scanner.should_ignore(Path::new(&file)) {
            stats.files_skipped += 1;
            stats.inspection_ledger.record(
                file.clone(),
                InspectionStatus::Excluded,
                false,
                Some("ignore_rule".to_string()),
            );
            continue;
        }
        let blob = staged_blob(&opts.path, &file)?;
        // Same NUL-sniff the engine applies to files on disk; skipped
        // staged blobs are counted exactly like `scan_dir` skips binaries.
        if aegis_core::scanner::is_binary_blob(&blob) {
            stats.files_skipped += 1;
            stats.inspection_ledger.record(
                file.clone(),
                InspectionStatus::Unsupported,
                true,
                Some("binary_file".to_string()),
            );
            continue;
        }
        let content = String::from_utf8_lossy(&blob);
        let file_findings = scanner.scan_string(&content, &file);
        stats.files_scanned += 1;
        stats.bytes_scanned += blob.len() as u64;
        stats
            .inspection_ledger
            .record(file.clone(), InspectionStatus::Analyzed, true, None);
        findings.extend(file_findings);
    }

    let stats = stats_with_findings(stats, &findings);
    Ok((findings, stats))
}

/// Result of a scan execution
pub struct ScanResult {
    /// Findings that survived category, severity, and baseline filtering.
    pub findings: Vec<Finding>,
    /// Coverage counters plus the inspection ledger recording what was and
    /// was not analyzed.
    pub stats: ScanStats,
    /// Rendered report, exactly as it is echoed to stdout.
    pub output: String,
    /// Whether any non-info finding survived. Informational findings never
    /// contribute; the process exit code itself is decided by
    /// [`scan_exit_code`] from the receipt, so a reported finding and the
    /// exit status can never disagree.
    pub has_findings: bool,
    /// Provenance receipt persisted to `AEGIS_RECEIPT_FILE` when set.
    pub receipt: ScanReceipt,
}

fn build_receipt(opts: &ScanOptions, findings: &[Finding], stats: ScanStats) -> ScanReceipt {
    let profile = format!(
        "cli:file={} env={} stdin={} all={} categories={} severity={}",
        opts.scan_file,
        opts.scan_env,
        opts.scan_stdin,
        opts.all,
        opts.categories.as_deref().unwrap_or("*"),
        opts.severity_threshold.as_deref().unwrap_or("*")
    );
    ScanReceipt::from_scan(
        opts.path.to_string_lossy(),
        "cli_scan",
        profile.clone(),
        Some(ScanReceipt::digest_text(&profile)),
        findings,
        stats,
    )
    .with_source_revision(std::env::var("AEGIS_SOURCE_REVISION").ok())
}

fn persist_receipt_if_configured(receipt: &ScanReceipt) -> Result<()> {
    if let Ok(path) = std::env::var("AEGIS_RECEIPT_FILE") {
        if path.trim().is_empty() {
            return Err(anyhow::anyhow!("AEGIS_RECEIPT_FILE must not be empty"));
        }
        receipt.write_atomic(Path::new(&path))?;
    }
    Ok(())
}

/// Execute scan and return result (testable)
///
/// # Errors
///
/// Returns an error when the scanner cannot be built (bad categories or
/// baseline), when the scan itself fails, or when the report cannot be
/// rendered.
pub fn execute_scan(opts: &ScanOptions) -> Result<ScanResult> {
    let scanner = build_scanner_from_opts(opts)?;
    let (findings, stats) = perform_scan(&scanner, opts)?;
    finish(opts, findings, stats)
}

/// Execute scan from stdin content (testable)
///
/// # Errors
///
/// Returns an error when the scanner cannot be built (bad categories or
/// baseline) or when the report cannot be rendered.
pub fn execute_scan_with_stdin(opts: &ScanOptions, stdin_content: &str) -> Result<ScanResult> {
    let scanner = build_scanner_from_opts(opts)?;
    let findings = scanner.scan_string(stdin_content, "stdin");
    let stats = stats_with_findings(
        ScanStats::for_content("string:stdin", stdin_content.len()),
        &findings,
    );
    finish(opts, findings, stats)
}

/// Shared tail of both scan entry points: score risk, render the report,
/// build the receipt, and package the result. Informational findings are
/// reported but never fail a CI run.
fn finish(opts: &ScanOptions, findings: Vec<Finding>, stats: ScanStats) -> Result<ScanResult> {
    let has_findings = findings.iter().any(|f| !is_info_severity(&f.severity));
    let receipt = build_receipt(opts, &findings, stats.clone());
    let risk = RiskScore::new(
        &findings,
        &std::collections::HashMap::default(),
        &std::collections::HashMap::default(),
    );
    let mut output = Output::new(opts.format.clone(), opts.quiet);
    output.write_findings(&findings, &stats, &risk)?;
    Ok(ScanResult {
        findings,
        stats,
        output: output.to_string(),
        has_findings,
        receipt,
    })
}

/// Run scan with I/O handling (not fully testable due to async stdin and process::exit)
///
/// # Errors
///
/// Returns an error when the scan fails; exits the process with the
/// computed scan exit code (see [`scan_exit_code`]) when it is non-zero.
pub async fn run_scan(opts: ScanOptions) -> Result<()> {
    let exit_code = run_scan_and_get_exit_code(opts).await?;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

/// Retire the configured receipt path, if one is set.
/// Called before scan so a failed scan leaves no stale receipt.
fn retire_receipt_if_configured() {
    if let Ok(path) = std::env::var("AEGIS_RECEIPT_FILE") {
        if !path.trim().is_empty() {
            // Best effort: an absent or unreadable receipt has nothing to retire.
            let _retired = std::fs::remove_file(path);
        }
    }
}

/// Exit status for a complete scan with no policy-blocking findings.
pub const EXIT_CLEAN: i32 = 0;

/// Exit status for a complete scan whose surviving findings include at
/// least one non-info severity. Informational findings never reach this
/// code, per the documented severity policy.
pub const EXIT_FINDINGS: i32 = 1;

/// Exit status for a scan whose receipt does not certify that every
/// required inspection completed — [`ScanReceipt::allows_safe`] is false
/// because a required unit failed, was skipped (for example by the file
/// size limit), had no analyzer (a binary file), or nothing was inspected
/// at all. Deliberately distinct from [`EXIT_FINDINGS`] so "findings were
/// reported" and "the scan could not inspect what it was asked to inspect"
/// stay separable; consumers that only branch on non-zero still fail
/// closed either way.
pub const EXIT_INCOMPLETE: i32 = 3;

/// Whether a finding severity is `info`: the one severity that never fails
/// a run. Informational observations are reported and receipted but must
/// not gate `has_findings` or [`scan_exit_code`]; this predicate is the
/// single authority for that policy, so the report and exit paths cannot
/// drift apart over what counts as blocking.
#[must_use]
fn is_info_severity(severity: &str) -> bool {
    severity == "info"
}

/// Decide the process exit code for a completed scan from the receipt
/// alone, so the exit status agrees with both halves of the fail-closed
/// contract and can never disagree with the evidence a downstream consumer
/// validates:
///
/// - receipt completeness first: [`ScanReceipt::allows_safe`] false means
///   the requested source was not fully inspected, and the scan is
///   [`EXIT_INCOMPLETE`] even when zero findings survived — an incomplete
///   scan must never pass as clean;
/// - then finding policy: a complete receipt carrying a non-info finding
///   is [`EXIT_FINDINGS`]; otherwise [`EXIT_CLEAN`].
#[must_use]
pub fn scan_exit_code(receipt: &ScanReceipt) -> i32 {
    if !receipt.allows_safe() {
        EXIT_INCOMPLETE
    } else if receipt
        .findings
        .iter()
        .any(|finding| !is_info_severity(&finding.severity))
    {
        EXIT_FINDINGS
    } else {
        EXIT_CLEAN
    }
}

/// Run scan and return exit code (testable async wrapper)
///
/// The exit code comes from [`scan_exit_code`] on the scan's own receipt:
/// a complete scan exits [`EXIT_CLEAN`] or [`EXIT_FINDINGS`] per the
/// finding policy (informational findings never fail the run), and a scan
/// whose receipt does not certify that every required inspection completed
/// exits [`EXIT_INCOMPLETE`] even with zero findings. Scan start-up and
/// write failures propagate as errors and exit non-zero through the
/// caller, before any receipt can be misread as evidence.
///
/// # Errors
///
/// Returns an error when the scan fails, when the configured receipt file
/// cannot be persisted, or when `output_file` cannot be written.
pub async fn run_scan_and_get_exit_code(opts: ScanOptions) -> Result<i32> {
    // Fail-closed: remove any existing receipt before scan so a failed scan
    // cannot be confused with a successful one whose result we never persisted.
    retire_receipt_if_configured();

    let result = if opts.scan_stdin {
        let content = read_stdin_content().await?;
        execute_scan_with_stdin(&opts, &content)?
    } else {
        execute_scan(&opts)?
    };

    persist_receipt_if_configured(&result.receipt)?;

    let exit_code = scan_exit_code(&result.receipt);

    // Print to stdout
    println!("{}", result.output);

    // Write to file if specified
    if let Some(ref path) = opts.output_file {
        std::fs::write(path, result.output.as_bytes())?;
    }

    Ok(exit_code)
}

/// Read stdin content (extracted for testing)
async fn read_stdin_content() -> Result<String> {
    let mut stdin = tokio::io::stdin();
    let mut content = String::new();
    stdin.read_to_string(&mut content).await?;
    Ok(content)
}

/// Refresh the pattern bundle from its source.
///
/// # Errors
///
/// Never fails today: patterns ship inside the binary, so there is nothing
/// to download or write.
pub async fn update_bundle(_force: bool) -> Result<()> {
    println!("Checking pattern bundle...");

    // Patterns are bundled in the aegis-patterns crate
    let patterns = aegis_patterns::all_patterns();
    println!("Pattern bundle is up to date.");
    println!(
        "Loaded {} patterns from {} categories",
        patterns.len(),
        patterns
            .iter()
            .map(|p| &p.category)
            .collect::<std::collections::HashSet<_>>()
            .len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn scan_fixture_path() -> PathBuf {
        let fixture_id = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aegis_cli_scan_fixture_{}_{}",
            std::process::id(),
            fixture_id
        ));
        std::fs::create_dir_all(&path).expect("create scan fixture directory");
        std::fs::write(path.join("clean.rs"), "fn main() {}\n").expect("write scan fixture");
        path
    }

    #[tokio::test]
    async fn test_update_bundle() {
        let result = update_bundle(false).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_scan_options_default() {
        let opts = ScanOptions {
            path: PathBuf::from("/test"),
            scan_file: false,
            scan_env: false,
            scan_stdin: false,
            follow_symlinks: false,
            categories: None,
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            staged: false,
            format: OutputFormat::Human,
            quiet: false,
            anomaly_detectors: None,
            detect_clones: false,
        };

        assert!(!opts.scan_file);
        assert!(!opts.scan_env);
        assert!(!opts.scan_stdin);
        assert!(!opts.follow_symlinks);
        assert!(opts.categories.is_none());
    }

    #[test]
    fn test_scan_options_with_categories() {
        let opts = ScanOptions {
            path: PathBuf::from("/test"),
            scan_file: false,
            scan_env: false,
            scan_stdin: false,
            follow_symlinks: false,
            categories: Some("secrets,pii".to_string()),
            severity_threshold: Some("high".to_string()),
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            format: OutputFormat::Json,
            quiet: true,
            staged: false,
            anomaly_detectors: None,
            detect_clones: false,
        };

        assert_eq!(opts.categories.as_ref().unwrap(), "secrets,pii");
        assert_eq!(opts.severity_threshold.as_ref().unwrap(), "high");
        assert!(opts.quiet);
    }

    fn opts_with_anomaly_detectors(list: Option<&str>) -> ScanOptions {
        ScanOptions {
            path: PathBuf::from("/test"),
            scan_file: false,
            scan_env: false,
            scan_stdin: false,
            follow_symlinks: false,
            categories: None,
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            staged: false,
            anomaly_detectors: list.map(str::to_string),
            detect_clones: false,
            format: OutputFormat::Human,
            quiet: false,
        }
    }

    #[test]
    fn test_anomaly_detector_list_builds_a_scanner() {
        let opts = opts_with_anomaly_detectors(Some("file-size-outlier, comment-ratio-outlier"));
        assert!(build_scanner_from_opts(&opts).is_ok());
    }

    #[test]
    fn test_empty_anomaly_detector_list_disables_the_layer() {
        // An empty string means "run none", not "unset": the scanner builds
        // with an explicit empty allow-list.
        let opts = opts_with_anomaly_detectors(Some(""));
        assert!(build_scanner_from_opts(&opts).is_ok());
    }

    #[test]
    fn test_unknown_anomaly_detector_fails_loudly() {
        let opts = opts_with_anomaly_detectors(Some("file-size-outlier,nope"));
        let Err(error) = build_scanner_from_opts(&opts) else {
            panic!("an unknown anomaly detector name must fail loudly");
        };
        assert!(error.to_string().contains("nope"), "got: {error}");
        assert!(error.to_string().contains("valid detectors:"));
    }

    #[tokio::test]
    async fn test_update_bundle_with_force() {
        // Force should still succeed since patterns are bundled
        let result = update_bundle(true).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_scanner_from_opts() {
        let opts = ScanOptions {
            path: PathBuf::from("/test"),
            scan_file: false,
            scan_env: false,
            scan_stdin: false,
            follow_symlinks: false,
            categories: Some("secrets".to_string()),
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            format: OutputFormat::Human,
            quiet: false,
            staged: false,
            detect_clones: false,
            anomaly_detectors: None,
        };

        let scanner = build_scanner_from_opts(&opts);
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_build_scanner_from_opts_no_categories() {
        let opts = ScanOptions {
            path: PathBuf::from("/test"),
            scan_file: false,
            scan_env: false,
            scan_stdin: false,
            follow_symlinks: false,
            categories: None,
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            format: OutputFormat::Human,
            quiet: false,
            staged: false,
            detect_clones: false,
            anomaly_detectors: None,
        };

        let scanner = build_scanner_from_opts(&opts);
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_build_scanner_from_opts_rejects_unknown_category() {
        let opts = ScanOptions {
            path: PathBuf::from("/test"),
            scan_file: false,
            scan_env: false,
            scan_stdin: false,
            follow_symlinks: false,
            categories: Some("secrets,security".to_string()), // "security" is phantom
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            format: OutputFormat::Human,
            quiet: false,
            staged: false,
            detect_clones: false,
            anomaly_detectors: None,
        };

        let Err(err) = build_scanner_from_opts(&opts) else {
            panic!("phantom category must fail the build")
        };
        assert!(
            err.to_string().contains("security"),
            "must name the unknown category: {err}"
        );
    }

    #[test]
    fn test_build_scanner_from_opts_tolerates_whitespace_in_categories() {
        let opts = ScanOptions {
            path: PathBuf::from("/test"),
            scan_file: false,
            scan_env: false,
            scan_stdin: false,
            follow_symlinks: false,
            categories: Some("secrets, web-security".to_string()),
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            format: OutputFormat::Human,
            quiet: false,
            staged: false,
            detect_clones: false,
            anomaly_detectors: None,
        };

        assert!(build_scanner_from_opts(&opts).is_ok());
    }

    #[test]
    fn test_build_scanner_with_severity_threshold() {
        let opts = ScanOptions {
            path: PathBuf::from("/test"),
            scan_file: false,
            scan_env: false,
            scan_stdin: false,
            follow_symlinks: false,
            categories: None,
            severity_threshold: Some("high".to_string()),
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            format: OutputFormat::Human,
            quiet: false,
            staged: false,
            detect_clones: false,
            anomaly_detectors: None,
        };

        let scanner = build_scanner_from_opts(&opts);
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_perform_scan_env() {
        let opts = ScanOptions {
            path: PathBuf::from("/test"),
            scan_file: false,
            scan_env: true,
            scan_stdin: false,
            follow_symlinks: false,
            categories: None,
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            format: OutputFormat::Human,
            quiet: false,
            staged: false,
            detect_clones: false,
            anomaly_detectors: None,
        };

        let scanner = build_scanner_from_opts(&opts).unwrap();
        let result = perform_scan(&scanner, &opts);
        assert!(result.is_ok());
        let (findings, _stats) = result.unwrap();
        // Env scan should return findings or empty vec
        assert!(findings.is_empty() || !findings.is_empty());
    }

    #[test]
    fn test_perform_scan_file_not_found() {
        let opts = ScanOptions {
            path: PathBuf::from("/nonexistent/path/to/file.txt"),
            scan_file: true,
            scan_env: false,
            scan_stdin: false,
            follow_symlinks: false,
            categories: None,
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            format: OutputFormat::Human,
            quiet: false,
            staged: false,
            detect_clones: false,
            anomaly_detectors: None,
        };

        let scanner = build_scanner_from_opts(&opts).unwrap();
        let result = perform_scan(&scanner, &opts);
        // File doesn't exist, should return error
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_scan_with_findings() {
        let scan_path = scan_fixture_path();
        let opts = ScanOptions {
            path: scan_path.clone(),
            scan_file: false,
            scan_env: false,
            scan_stdin: false,
            follow_symlinks: false,
            categories: None,
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            format: OutputFormat::Human,
            quiet: false,
            staged: false,
            detect_clones: false,
            anomaly_detectors: None,
        };

        let result = execute_scan(&opts);
        assert!(result.is_ok());
        let scan_result = result.unwrap();
        // has_findings should match whether findings is empty
        assert_eq!(scan_result.has_findings, !scan_result.findings.is_empty());
        assert_ne!(scan_result.output, "");
        std::fs::remove_dir_all(scan_path).ok();
    }

    #[test]
    fn test_execute_scan_with_stdin() {
        let opts = ScanOptions {
            path: PathBuf::from("/test"),
            scan_file: false,
            scan_env: false,
            scan_stdin: true,
            follow_symlinks: false,
            categories: None,
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            format: OutputFormat::Human,
            quiet: false,
            staged: false,
            detect_clones: false,
            anomaly_detectors: None,
        };

        let result = execute_scan_with_stdin(
            &opts,
            "let password = 'secret123';", // aegis:ignore:hardcoded-credential,hardcoded-password,hardcoded-tf-secrets,password-field,rust-hardcoded-secret
        );
        assert!(result.is_ok());
        let scan_result = result.unwrap();
        assert_ne!(scan_result.output, "");
    }

    #[test]
    fn test_perform_scan_stdin_branch() {
        // perform_scan refuses stdin: the async caller owns the read and
        // forwards content to execute_scan_with_stdin.
        let opts = ScanOptions {
            path: PathBuf::from("/test"),
            scan_file: false,
            scan_env: false,
            scan_stdin: true, // This triggers the stdin branch
            follow_symlinks: false,
            categories: None,
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            format: OutputFormat::Human,
            quiet: false,
            staged: false,
            detect_clones: false,
            anomaly_detectors: None,
        };

        let scanner = build_scanner_from_opts(&opts).unwrap();
        let error = perform_scan(&scanner, &opts).expect_err("stdin must be refused");
        assert!(error.to_string().contains("execute_scan_with_stdin"));
    }

    #[test]
    fn stdin_scan_stats_agree_with_the_findings_list() {
        // Regression: the JSON `stats` block used to report finding_count 0
        // while the findings array carried matches.
        let opts = ScanOptions {
            path: PathBuf::from("/test"),
            scan_file: false,
            scan_env: false,
            scan_stdin: true,
            follow_symlinks: false,
            categories: None,
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            format: OutputFormat::Human,
            quiet: false,
            staged: false,
            detect_clones: false,
            anomaly_detectors: None,
        };

        let result = execute_scan_with_stdin(&opts, "console.log(\"debug\");\n")
            .expect("stdin scan must succeed");
        assert!(
            !result.findings.is_empty(),
            "fixture must produce a finding"
        );
        assert_eq!(result.stats.finding_count, result.findings.len());
        assert_eq!(
            result.stats.findings_by_severity.values().sum::<usize>(),
            result.stats.finding_count
        );
        assert_eq!(
            result.stats.findings_by_category.values().sum::<usize>(),
            result.stats.finding_count
        );
    }

    #[test]
    fn test_perform_scan_file_dir() {
        // Test the perform_scan function with scan_file = true and a directory path (lines 82-84)
        let temp_dir = std::env::temp_dir().join("aegis_test_scan_dir");
        std::fs::create_dir_all(&temp_dir).ok();

        let opts = ScanOptions {
            path: temp_dir.clone(),
            scan_file: true, // This triggers the scan_file branch
            scan_env: false,
            scan_stdin: false,
            follow_symlinks: false,
            categories: None,
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            format: OutputFormat::Human,
            quiet: false,
            staged: false,
            detect_clones: false,
            anomaly_detectors: None,
        };

        let scanner = build_scanner_from_opts(&opts).unwrap();
        let result = perform_scan(&scanner, &opts);
        assert!(result.is_ok());

        std::fs::remove_dir_all(temp_dir).ok();
    }

    #[test]
    fn test_execute_scan_json_format() {
        let scan_path = scan_fixture_path();
        let opts = ScanOptions {
            path: scan_path.clone(),
            scan_file: false,
            scan_env: false,
            scan_stdin: false,
            follow_symlinks: false,
            categories: None,
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            format: OutputFormat::Json,
            quiet: false,
            staged: false,
            detect_clones: false,
            anomaly_detectors: None,
        };

        let result = execute_scan(&opts);
        assert!(result.is_ok());
        let scan_result = result.unwrap();
        assert!(scan_result.output.contains("findings"));
        std::fs::remove_dir_all(scan_path).ok();
    }

    #[test]
    fn test_execute_scan_with_output_file() {
        // Note: execute_scan does NOT write to output_file - that's done by
        // run_scan_and_get_exit_code which is async. This test verifies execute_scan works.
        let temp_dir = std::env::temp_dir().join("aegis_output_test");
        std::fs::create_dir_all(&temp_dir).ok();
        let output_path = temp_dir.join("output.txt");
        let scan_path = scan_fixture_path();

        let opts = ScanOptions {
            path: scan_path.clone(),
            scan_file: false,
            scan_env: false,
            scan_stdin: false,
            follow_symlinks: false,
            categories: None,
            severity_threshold: None,
            output_file: Some(output_path.clone()),
            baseline: None,
            all: false,
            diff: None,
            format: OutputFormat::Human,
            quiet: false,
            staged: false,
            detect_clones: false,
            anomaly_detectors: None,
        };

        let result = execute_scan(&opts);
        assert!(result.is_ok());
        let scan_result = result.unwrap();
        // execute_scan populates output but doesn't write to file (async run_scan_and_get_exit_code does)
        assert_ne!(scan_result.output, "");

        std::fs::remove_dir_all(temp_dir).ok();
        std::fs::remove_dir_all(scan_path).ok();
    }

    #[test]
    fn test_execute_scan_sarif_format() {
        let scan_path = scan_fixture_path();
        let opts = ScanOptions {
            path: scan_path.clone(),
            scan_file: false,
            scan_env: false,
            scan_stdin: false,
            follow_symlinks: false,
            categories: None,
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            format: OutputFormat::Sarif,
            quiet: false,
            staged: false,
            detect_clones: false,
            anomaly_detectors: None,
        };

        let result = execute_scan(&opts);
        assert!(result.is_ok());
        let scan_result = result.unwrap();
        assert!(scan_result.output.contains("version"));
        std::fs::remove_dir_all(scan_path).ok();
    }

    #[test]
    fn test_scan_result_exit_code_logic() {
        // The exit code is decided from the receipt (see `scan_exit_code`);
        // on a safe receipt it must equal EXIT_FINDINGS exactly when a
        // non-info finding survived, and EXIT_CLEAN otherwise.
        let scan_path = scan_fixture_path();
        let opts = ScanOptions {
            path: scan_path.clone(),
            scan_file: false,
            scan_env: false,
            scan_stdin: false,
            follow_symlinks: false,
            categories: None,
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            format: OutputFormat::Human,
            quiet: false,
            staged: false,
            detect_clones: false,
            anomaly_detectors: None,
        };

        let result = execute_scan(&opts).unwrap();
        assert!(result.receipt.allows_safe(), "precondition: clean fixture");
        let expected_exit = if result.has_findings {
            EXIT_FINDINGS
        } else {
            EXIT_CLEAN
        };
        assert_eq!(scan_exit_code(&result.receipt), expected_exit);
        assert_eq!(result.receipt.finding_count, result.findings.len());
        std::fs::remove_dir_all(scan_path).ok();
    }

    /// Receipt-derived fail-closed regression: required work that was not
    /// analyzed must yield `EXIT_INCOMPLETE`, while optional failures do not
    /// invalidate an otherwise complete receipt.
    #[test]
    fn required_incomplete_receipt_units_fail_closed() {
        let opts = ScanOptions {
            path: PathBuf::from("/test"),
            scan_file: false,
            scan_env: false,
            scan_stdin: true,
            follow_symlinks: false,
            categories: None,
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            format: OutputFormat::Human,
            quiet: false,
            staged: false,
            detect_clones: false,
            anomaly_detectors: None,
        };
        let clean = execute_scan_with_stdin(&opts, "clean input\n").expect("scan succeeds");
        assert_eq!(scan_exit_code(&clean.receipt), EXIT_CLEAN);

        for status in [InspectionStatus::Failed, InspectionStatus::Skipped, InspectionStatus::Unsupported] {
            let mut receipt = clean.receipt.clone();
            receipt.inspection_ledger.record(
                format!("synthetic-required-{status:?}"),
                status,
                true,
                Some("regression_test".to_string()),
            );
            assert_eq!(scan_exit_code(&receipt), EXIT_INCOMPLETE, "{status:?}");
        }

        let mut optional_failure = clean.receipt;
        optional_failure.inspection_ledger.record(
            "optional-failure",
            InspectionStatus::Failed,
            false,
            Some("regression_test".to_string()),
        );
        assert_eq!(scan_exit_code(&optional_failure), EXIT_CLEAN);
    }
    #[tokio::test]
    async fn test_receipt_file_failures_retire_stale_and_fail_closed() {
        // Mode 1: stale-receipt retirement. Use a process-unique temp path
        // to avoid races between parallel test invocations; process::id is
        // embedded in the receipt tmp-name so we further isolate by
        // including a monotonic fixture counter.
        let fixture_id = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let receipt_path = std::env::temp_dir().join(format!(
            "aegis_stale_receipt_test_{}_{}",
            std::process::id(),
            fixture_id
        ));

        // Pre-write a valid receipt so we have something that "stales".
        let pre_existing_receipt = ScanReceipt::from_scan(
            String::from("/always/succeeds"),
            String::from("pre-existing-scan"),
            String::from("fixture"),
            None,
            &[],
            ScanStats::default(),
        );
        pre_existing_receipt
            .write_atomic(&receipt_path)
            .expect("pre-existing receipt should be writable");
        assert!(
            receipt_path.exists(),
            "precondition: receipt file must exist before scan"
        );

        // Point AEGIS_RECEIPT_FILE at our temp path and run a scan that is
        // guaranteed to fail (scan_file with a path that does not exist).
        let guard = OnDropEnvVar::new(
            "AEGIS_RECEIPT_FILE",
            receipt_path.to_string_lossy().as_ref(),
        );
        let opts = ScanOptions {
            path: PathBuf::from("/this/path/does/not/exist/at/all"),
            scan_file: true,
            scan_env: false,
            scan_stdin: false,
            follow_symlinks: false,
            categories: None,
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            format: OutputFormat::Human,
            quiet: false,
            staged: false,
            detect_clones: false,
            anomaly_detectors: None,
        };

        let exit_code = run_scan_and_get_exit_code(opts).await;
        // Scan must fail (file does not exist).
        assert!(exit_code.is_err(), "failing scan should propagate error");
        // Receipt file must be gone — not readable as evidence of a scan.
        assert!(
            !receipt_path.exists(),
            "stale receipt must be retired; found {} which should not exist",
            receipt_path.display()
        );
        // Release the first binding before re-pointing the same variable.
        drop(guard);

        // Mode 2: unusable receipt target. A directory cannot be replaced
        // by the receipt file: the atomic rename at persist time fails on
        // every platform.
        let outside = tempfile::tempdir().unwrap();
        let receipt_target = outside.path().join("receipt.json");
        std::fs::create_dir(&receipt_target).unwrap();
        let scan_path = scan_fixture_path();

        let guard = OnDropEnvVar::new(
            "AEGIS_RECEIPT_FILE",
            receipt_target.to_string_lossy().as_ref(),
        );

        let outcome = run_scan_and_get_exit_code(dir_scan_opts(scan_path.clone())).await;
        assert!(
            outcome.is_err(),
            "a receipt that cannot be persisted must fail the scan, not pass"
        );
        assert!(
            receipt_target.is_dir(),
            "the failed persist must not clobber the configured target"
        );

        // Keep the guard alive until the end of the test so its drop can
        // clean up the process-global environment.
        let _guard = guard;
        std::fs::remove_dir_all(scan_path).ok();
    }

    /// RAII guard that sets an env var on construction and removes it on drop.
    struct OnDropEnvVar {
        key: String,
        _original: Option<String>,
    }

    impl OnDropEnvVar {
        fn new(key: &str, value: &str) -> Self {
            let original = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self {
                key: key.to_string(),
                _original: original,
            }
        }
    }

    impl Drop for OnDropEnvVar {
        fn drop(&mut self) {
            std::env::remove_var(&self.key);
        }
    }

    /// Fixture directory holding one file with the same known-bad AWS
    /// access key on two separate lines, so fingerprint-precise filtering
    /// can be observed finding-by-finding (fingerprints bind the line).
    fn baseline_fixture_path() -> PathBuf {
        let path = scan_fixture_path();
        std::fs::write(
            path.join("fixture.env"), // aegis:ignore:env-file-in-git
            // AWS docs example key; directive shares the flagged line.
            "aws_key: AKIAIOSFODNN7EXAMPLE\nsecond_line_key: AKIAIOSFODNN7EXAMPLE\n", // aegis:ignore:aws-access-key
        )
        .expect("write baseline fixture");
        path
    }

    fn baseline_scan_opts(path: PathBuf, baseline: Option<PathBuf>) -> ScanOptions {
        ScanOptions {
            path,
            scan_file: false,
            scan_env: false,
            scan_stdin: false,
            follow_symlinks: false,
            categories: None,
            severity_threshold: None,
            output_file: None,
            baseline,
            all: false,
            diff: None,
            anomaly_detectors: None,
            format: OutputFormat::Human,
            quiet: false,
            staged: false,
            detect_clones: false,
        }
    }

    /// Serialize findings in the exact shape `--format json` writes.
    fn write_baseline_document(path: &Path, findings: &[Finding]) {
        #[derive(serde::Serialize)]
        struct BaselineDocument<'a> {
            findings: &'a [Finding],
            stats: ScanStats,
        }
        let document = BaselineDocument {
            findings,
            stats: ScanStats::default(),
        };
        std::fs::write(path, serde_json::to_string(&document).unwrap())
            .expect("write baseline document");
    }

    #[test]
    fn test_baseline_filters_known_findings() {
        let fixture = baseline_fixture_path();
        let opts = baseline_scan_opts(fixture.clone(), None);
        let scanner = build_scanner_from_opts(&opts).unwrap();
        let (findings, _) = perform_scan(&scanner, &opts).unwrap();
        assert!(
            findings.len() >= 2,
            "precondition: fixture must produce one finding per flagged line, got {}",
            findings.len()
        );

        // The baseline lives outside the scanned tree: a baseline placed
        // outside `.aegis/` would itself be scanned (and flagged) on the
        // next run — only the `.aegis/` state directory is always exempt.
        let outside = tempfile::tempdir().unwrap();
        let baseline_path = outside.path().join("baseline.json");
        write_baseline_document(&baseline_path, &findings);

        let opts = baseline_scan_opts(fixture.clone(), Some(baseline_path));
        let scanner = build_scanner_from_opts(&opts).unwrap();
        let (filtered, _) = perform_scan(&scanner, &opts).unwrap();
        assert!(
            filtered.is_empty(),
            "all baseline findings must be filtered, got {}",
            filtered.len()
        );
        std::fs::remove_dir_all(fixture).ok();
    }

    #[test]
    fn test_in_tree_aegis_baseline_is_not_rescanned() {
        // A baseline tracked at `.aegis/baseline.json` inside the scan
        // root is in the walk set, and it quotes the findings it
        // documents. Without the built-in state-directory skip every
        // gated rescan re-flags the artifact's own contents (fingerprints
        // naming the baseline file, which can never be in the baseline),
        // so the gate could not ever go green.
        let fixture = baseline_fixture_path();
        let state_dir = fixture.join(".aegis");
        std::fs::create_dir(&state_dir).unwrap();
        let in_tree = state_dir.join("baseline.json");

        let record_opts = baseline_scan_opts(fixture.clone(), None);
        let scanner = build_scanner_from_opts(&record_opts).unwrap();
        let (findings, _) = perform_scan(&scanner, &record_opts).unwrap();
        assert!(findings.len() >= 2, "precondition: two flagged lines");
        write_baseline_document(&in_tree, &findings);

        // Refresh pass (no --baseline): the full finding set is expected,
        // but none of it may originate inside the state directory.
        let (refreshed, _) = perform_scan(&scanner, &record_opts).unwrap();
        assert!(
            refreshed
                .iter()
                .all(|finding| !finding.location.file.contains(".aegis")),
            "state-directory files must never be re-flagged: {refreshed:?}"
        );

        // Gated pass (--baseline .aegis/baseline.json): recorded findings
        // are filtered and the artifact contributes nothing new.
        let gate_opts = baseline_scan_opts(fixture.clone(), Some(in_tree));
        let gated_scanner = build_scanner_from_opts(&gate_opts).unwrap();
        let (gated, _) = perform_scan(&gated_scanner, &gate_opts).unwrap();
        assert!(
            gated.is_empty(),
            "in-tree baseline must gate the scan clean, got: {gated:?}"
        );
        std::fs::remove_dir_all(fixture).ok();
    }

    #[test]
    fn test_baseline_keeps_findings_absent_from_baseline() {
        let fixture = baseline_fixture_path();
        let opts = baseline_scan_opts(fixture.clone(), None);
        let scanner = build_scanner_from_opts(&opts).unwrap();
        let (findings, _) = perform_scan(&scanner, &opts).unwrap();
        assert!(findings.len() >= 2, "precondition: two flagged lines");

        // Record only the first finding; the second must survive.
        let outside = tempfile::tempdir().unwrap();
        let baseline_path = outside.path().join("partial_baseline.json");
        write_baseline_document(&baseline_path, &findings[..1]);

        let opts = baseline_scan_opts(fixture.clone(), Some(baseline_path));
        let scanner = build_scanner_from_opts(&opts).unwrap();
        let (filtered, _) = perform_scan(&scanner, &opts).unwrap();
        assert_eq!(filtered.len(), 1, "only the non-baselined finding remains");
        assert_ne!(filtered[0].fingerprint, findings[0].fingerprint);
        assert_eq!(filtered[0].fingerprint, findings[1].fingerprint);
        std::fs::remove_dir_all(fixture).ok();
    }

    #[test]
    fn test_baseline_accepts_bare_findings_array() {
        let fixture = baseline_fixture_path();
        let opts = baseline_scan_opts(fixture.clone(), None);
        let scanner = build_scanner_from_opts(&opts).unwrap();
        let (findings, _) = perform_scan(&scanner, &opts).unwrap();
        assert!(!findings.is_empty());

        let outside = tempfile::tempdir().unwrap();
        let baseline_path = outside.path().join("baseline.json");
        std::fs::write(&baseline_path, serde_json::to_string(&findings).unwrap())
            .expect("write bare-array baseline");

        let opts = baseline_scan_opts(fixture.clone(), Some(baseline_path));
        let scanner = build_scanner_from_opts(&opts).unwrap();
        let (filtered, _) = perform_scan(&scanner, &opts).unwrap();
        assert!(filtered.is_empty(), "bare array baseline must filter too");
        std::fs::remove_dir_all(fixture).ok();
    }

    #[test]
    fn test_baseline_changed_code_refires_finding() {
        let fixture = baseline_fixture_path();
        let opts = baseline_scan_opts(fixture.clone(), None);
        let scanner = build_scanner_from_opts(&opts).unwrap();
        let (findings, _) = perform_scan(&scanner, &opts).unwrap();
        assert!(findings.len() >= 2);

        // Baseline records the line-1 finding, then the code moves the
        // surviving key down to line 3 — a (pattern, line, digest) triple
        // no baseline entry covers. The exact-position baseline must
        // re-fire it.
        let outside = tempfile::tempdir().unwrap();
        let baseline_path = outside.path().join("baseline.json");
        write_baseline_document(&baseline_path, &findings[..1]);

        std::fs::write(
            fixture.join("fixture.env"), // aegis:ignore:env-file-in-git
            "# the key moved down\n# with the edit\nsecond_line_key: AKIAIOSFODNN7EXAMPLE\n", // aegis:ignore:aws-access-key
        )
        .expect("rewrite fixture with key moved down");

        let opts = baseline_scan_opts(fixture.clone(), Some(baseline_path));
        let scanner = build_scanner_from_opts(&opts).unwrap();
        let (filtered, _) = perform_scan(&scanner, &opts).unwrap();
        assert_eq!(
            filtered.len(),
            1,
            "moved code must re-fire even when baselined elsewhere"
        );
        std::fs::remove_dir_all(fixture).ok();
    }

    #[test]
    fn test_baseline_missing_file_is_an_error() {
        let fixture = scan_fixture_path();
        let opts = baseline_scan_opts(fixture.clone(), Some(fixture.join("nope.json")));
        // Validation happens at scanner construction: a missing baseline
        // must fail loudly before anything is scanned.
        let Err(err) = build_scanner_from_opts(&opts) else {
            panic!("baseline validation must fail before scanning")
        };
        assert!(
            err.to_string().contains("baseline"),
            "error must mention the baseline file, got: {err}"
        );
        std::fs::remove_dir_all(fixture).ok();
    }

    /// Create a git repository at `fixture` and stage `files`.
    fn git_repo_with_staged(fixture: &Path, files: &[(&str, &str)]) {
        let run = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(fixture)
                .args(args)
                .output()
                .expect("git must be available")
        };
        std::process::Command::new("git")
            .args(["init", "-q"])
            .arg(fixture)
            .output()
            .expect("git init must succeed");
        for (path, content) in files {
            let target = fixture.join(path);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(target, content).unwrap();
        }
        let add = run(&["add", "."]);
        assert!(
            add.status.success(),
            "git add failed: {}",
            String::from_utf8_lossy(&add.stderr)
        );
    }

    fn staged_scan_opts(path: PathBuf) -> ScanOptions {
        ScanOptions {
            path,
            scan_file: false,
            scan_env: false,
            scan_stdin: false,
            follow_symlinks: false,
            categories: None,
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            staged: true,
            detect_clones: false,
            anomaly_detectors: None,
            format: OutputFormat::Human,
            quiet: false,
        }
    }

    const STAGED_SECRET: &str = "aws_key: AKIAIOSFODNN7EXAMPLE\n"; // aegis:ignore:aws-access-key

    #[test]
    fn test_staged_scan_reports_staged_secret() {
        let fixture = tempfile::tempdir().unwrap();
        git_repo_with_staged(fixture.path(), &[("config.env", STAGED_SECRET)]); // aegis:ignore:env-file-in-git

        let scanner = build_scanner_from_opts(&staged_scan_opts(fixture.path().into())).unwrap();
        let (findings, stats) =
            perform_scan(&scanner, &staged_scan_opts(fixture.path().into())).unwrap();
        assert_eq!(findings.len(), 1, "staged secret must be reported");
        assert_eq!(stats.files_scanned, 1);
        assert_eq!(findings[0].location.file, "config.env"); // aegis:ignore:env-file-in-git
    }

    #[test]
    fn test_staged_scan_skips_the_state_directory() {
        let fixture = tempfile::tempdir().unwrap();
        git_repo_with_staged(
            fixture.path(),
            &[
                ("config.env", STAGED_SECRET),
                // A staged baseline quotes the findings it documents;
                // staged blobs bypass `scan_file`, so the state-directory
                // skip must be applied to the staged list as well.
                (".aegis/baseline.json", STAGED_SECRET),
            ],
        ); // aegis:ignore:env-file-in-git

        let opts = staged_scan_opts(fixture.path().into());
        let scanner = build_scanner_from_opts(&opts).unwrap();
        let (findings, stats) = perform_scan(&scanner, &opts).unwrap();
        assert_eq!(
            findings.len(),
            1,
            "the state-directory blob must not be reported"
        );
        assert_eq!(findings[0].location.file, "config.env");
        assert_eq!(
            stats.files_skipped, 1,
            "the skipped baseline must count as skipped"
        );
    }

    #[test]
    fn test_staged_scan_reads_index_not_working_tree() {
        let fixture = tempfile::tempdir().unwrap();
        git_repo_with_staged(fixture.path(), &[("config.env", STAGED_SECRET)]); // aegis:ignore:env-file-in-git

        // The working tree was cleaned after staging and an unrelated
        // secret was never staged at all; neither may change the result.
        std::fs::write(fixture.path().join("config.env"), "aws_key: clean\n").unwrap(); // aegis:ignore:env-file-in-git
        std::fs::write(fixture.path().join("untracked.env"), STAGED_SECRET).unwrap(); // aegis:ignore:env-file-in-git

        let opts = staged_scan_opts(fixture.path().into());
        let scanner = build_scanner_from_opts(&opts).unwrap();
        let (findings, _) = perform_scan(&scanner, &opts).unwrap();
        assert_eq!(
            findings.len(),
            1,
            "scan must reflect the index, not the working tree or untracked files"
        );
    }

    #[test]
    fn test_staged_scan_clean_when_nothing_staged() {
        let fixture = tempfile::tempdir().unwrap();
        // Secret present on disk but never staged: nothing to commit,
        // nothing to scan.
        std::fs::write(fixture.path().join("config.env"), STAGED_SECRET).unwrap(); // aegis:ignore:env-file-in-git
        std::process::Command::new("git")
            .args(["init", "-q"])
            .arg(fixture.path())
            .output()
            .expect("git init must succeed");

        let opts = staged_scan_opts(fixture.path().into());
        let scanner = build_scanner_from_opts(&opts).unwrap();
        let (findings, _) = perform_scan(&scanner, &opts).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_staged_scan_outside_repository_is_an_error() {
        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(fixture.path().join("config.env"), STAGED_SECRET).unwrap(); // aegis:ignore:env-file-in-git

        let opts = staged_scan_opts(fixture.path().into());
        let scanner = build_scanner_from_opts(&opts).unwrap();
        let Err(err) = perform_scan(&scanner, &opts) else {
            panic!("--staged outside a git repository must fail loudly")
        };
        assert!(
            err.to_string().contains("git repository"),
            "error must name the requirement, got: {err}"
        );
    }

    #[test]
    fn test_baseline_malformed_file_is_an_error() {
        let fixture = baseline_fixture_path();
        let outside = tempfile::tempdir().unwrap();
        let baseline_path = outside.path().join("garbage.json");
        std::fs::write(&baseline_path, "not json at all").unwrap();

        let opts = baseline_scan_opts(fixture.clone(), Some(baseline_path));
        let Err(err) = build_scanner_from_opts(&opts) else {
            panic!("baseline validation must fail before scanning")
        };
        assert!(
            err.to_string().contains("baseline"),
            "error must mention the baseline file, got: {err}"
        );
        std::fs::remove_dir_all(fixture).ok();
    }

    #[test]
    fn test_info_findings_never_fail_the_exit_code() {
        // Build a tree whose only findings are statistical-anomaly info
        // observations: ten quiet files plus one heavily narrated outlier.
        let fixture_id = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let scan_path = std::env::temp_dir().join(format!(
            "aegis_cli_info_exit_fixture_{}_{}",
            std::process::id(),
            fixture_id
        ));
        std::fs::create_dir_all(&scan_path).unwrap();
        for index in 0..10_usize {
            let mut lines = vec![format!("// routine module number {index}")];
            for n in 0..99_u32 {
                lines.push(format!("let value_{n}_{index} = {n} * {index};"));
            }
            std::fs::write(
                scan_path.join(format!("unit_{index}.rs")),
                lines.join("\n") + "\n",
            )
            .unwrap();
        }
        let mut narrated: Vec<String> = (0..95_u32)
            .map(|n| format!("// step {n}: restate the arithmetic in prose"))
            .collect();
        narrated.extend((0..5_u32).map(|n| format!("let value_{n} = {n} + 1;")));
        std::fs::write(scan_path.join("narrated.rs"), narrated.join("\n") + "\n").unwrap();

        let opts = ScanOptions {
            path: scan_path.clone(),
            scan_file: false,
            scan_env: false,
            scan_stdin: false,
            follow_symlinks: false,
            categories: None,
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            format: OutputFormat::Json,
            quiet: false,
            staged: false,
            detect_clones: false,
            anomaly_detectors: None,
        };

        let result = execute_scan(&opts).unwrap();
        let blocking = result
            .findings
            .iter()
            .any(|f| !is_info_severity(&f.severity));
        assert_eq!(
            result.has_findings, blocking,
            "info findings must not flip the exit code; only non-info findings may"
        );
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.category == "statistical-anomaly"),
            "the narrated outlier should surface as an info observation"
        );
        // Case-matrix guard (informational): a safe receipt carrying only
        // info findings still exits clean — the policy is decided from the
        // receipt, so it must agree with `has_findings` here too.
        assert!(
            result.receipt.allows_safe(),
            "precondition: the info-only scan must be complete"
        );
        assert_eq!(
            scan_exit_code(&result.receipt),
            EXIT_CLEAN,
            "info-only findings on a complete scan must stay exit 0"
        );
        std::fs::remove_dir_all(scan_path).ok();
    }

    // ------------------------------------------------------------------
    // R4 fail-closed exit case matrix
    //
    // The exit status must agree with both receipt completeness
    // (`ScanReceipt::allows_safe`) and the finding policy, decided from the
    // same receipt a downstream gate validates. Each test names the matrix
    // case it pins: clean / finding / informational (above) / blocked /
    // skipped-or-timed-out / exit-disagreement / empty-diff / staged
    // coverage. The two `AEGIS_RECEIPT_FILE` failure modes — stale-receipt
    // retirement and the unusable receipt target — share the one
    // serialized env test
    // `test_receipt_file_failures_retire_stale_and_fail_closed`; the
    // repeated-scan baseline ratchet by the `test_baseline_*` suite.
    // ------------------------------------------------------------------

    /// Directory-scan options rooted at `path`, the shape shared by the
    /// exit-code case-matrix tests.
    fn dir_scan_opts(path: PathBuf) -> ScanOptions {
        ScanOptions {
            path,
            scan_file: false,
            scan_env: false,
            scan_stdin: false,
            follow_symlinks: false,
            categories: None,
            severity_threshold: None,
            output_file: None,
            baseline: None,
            all: false,
            diff: None,
            staged: false,
            detect_clones: false,
            anomaly_detectors: None,
            format: OutputFormat::Human,
            quiet: false,
        }
    }

    /// A fixture finding for receipt-construction tests.
    fn matrix_finding(severity: &str) -> Finding {
        Finding::new(
            "matrix-rule",
            "secrets",
            severity,
            "high",
            aegis_core::Location::new("fixture.rs", 4, 2, "matrix = value"),
            "value",
            "case-matrix fixture finding",
        )
    }

    /// Stats whose ledger records one required analyzed unit, the shape
    /// every real content scan path produces.
    fn safe_stats() -> ScanStats {
        ScanStats::for_content("string:case-matrix", 0)
    }

    /// Case matrix, decision level: the exit code is a function of the
    /// receipt alone, covering completeness first and finding policy second.
    #[test]
    fn scan_exit_code_decision_covers_both_contract_dimensions() {
        // Clean and complete: zero findings over a safe ledger.
        let clean =
            ScanReceipt::from_scan("fixture.rs", "cli_scan", "matrix", None, &[], safe_stats());
        assert_eq!(scan_exit_code(&clean), EXIT_CLEAN);

        // Findings and complete: a non-info finding is exit 1.
        let blocking = matrix_finding("high");
        let found = ScanReceipt::from_scan(
            "fixture.rs",
            "cli_scan",
            "matrix",
            None,
            std::slice::from_ref(&blocking),
            safe_stats(),
        );
        assert_eq!(scan_exit_code(&found), EXIT_FINDINGS);

        // Informational-only and complete: policy keeps it exit 0.
        let info = matrix_finding("info");
        let info_only = ScanReceipt::from_scan(
            "fixture.rs",
            "cli_scan",
            "matrix",
            None,
            &[info],
            safe_stats(),
        );
        assert_eq!(scan_exit_code(&info_only), EXIT_CLEAN);

        // Blocked and incomplete: a required failed unit must not pass as
        // clean even with zero findings (the zero-exit/incomplete
        // regression).
        let mut failed_stats = safe_stats();
        failed_stats.inspection_ledger.record(
            "unreadable.txt",
            InspectionStatus::Failed,
            true,
            Some("unreadable".to_string()),
        );
        let blocked =
            ScanReceipt::from_scan("fixture.rs", "cli_scan", "matrix", None, &[], failed_stats);
        assert!(!blocked.allows_safe());
        assert_eq!(scan_exit_code(&blocked), EXIT_INCOMPLETE);

        // Completeness dominates findings: an unproven inspection cannot
        // certify the findings it did see, so the blocked code wins.
        let mut blocked_with_findings_stats = safe_stats();
        blocked_with_findings_stats.inspection_ledger.record(
            "unreadable.txt",
            InspectionStatus::Failed,
            true,
            Some("unreadable".to_string()),
        );
        let blocked_with_findings = ScanReceipt::from_scan(
            "fixture.rs",
            "cli_scan",
            "matrix",
            None,
            &[blocking],
            blocked_with_findings_stats,
        );
        assert_eq!(scan_exit_code(&blocked_with_findings), EXIT_INCOMPLETE);

        // Nothing inspected at all is not a clean pass: an empty ledger
        // carries no evidence.
        let empty_ledger = ScanReceipt::from_scan(
            "fixture.rs",
            "cli_scan",
            "matrix",
            None,
            &[],
            ScanStats::default(),
        );
        assert_eq!(scan_exit_code(&empty_ledger), EXIT_INCOMPLETE);
    }

    /// Case matrix (clean): a readable fixture is a complete scan, and the
    /// receipt is safe with the exit to prove it.
    #[test]
    fn clean_complete_scan_exits_zero_with_safe_receipt() {
        let scan_path = scan_fixture_path();
        let result = execute_scan(&dir_scan_opts(scan_path.clone())).unwrap();
        assert!(
            result.receipt.allows_safe(),
            "a readable tree must inspect fully"
        );
        assert_eq!(result.receipt.finding_count, 0);
        assert_eq!(scan_exit_code(&result.receipt), EXIT_CLEAN);
        std::fs::remove_dir_all(scan_path).ok();
    }

    /// Case matrix (finding + exit-disagreement guard): the exit code, the
    /// result findings, and the receipt findings must all agree.
    #[test]
    fn blocking_findings_exit_one_and_agree_with_the_receipt() {
        let fixture = baseline_fixture_path();
        let result = execute_scan(&dir_scan_opts(fixture.clone())).unwrap();
        assert!(
            result.has_findings,
            "precondition: the fixture carries AWS example keys"
        );
        assert_eq!(
            result.receipt.finding_count,
            result.findings.len(),
            "receipt and result must embed the same finding set"
        );
        assert_eq!(result.receipt.findings.len(), result.findings.len());
        assert!(
            result
                .receipt
                .findings
                .iter()
                .any(|finding| !is_info_severity(&finding.severity)),
            "precondition: at least one finding is policy-blocking"
        );
        assert!(result.receipt.allows_safe());
        assert_eq!(scan_exit_code(&result.receipt), EXIT_FINDINGS);
        std::fs::remove_dir_all(fixture).ok();
    }

    /// Case matrix (blocked): a directory holding one unreadable required
    /// file among readable ones returns a partial result — which must exit
    /// blocked with zero findings, never as a clean pass.
    #[cfg(unix)]
    #[test]
    fn unreadable_required_file_blocks_a_zero_finding_scan() {
        use std::os::unix::fs::PermissionsExt;

        let fixture_id = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let scan_path = std::env::temp_dir().join(format!(
            "aegis_cli_blocked_exit_{}_{}",
            std::process::id(),
            fixture_id
        ));
        std::fs::create_dir_all(&scan_path).unwrap();
        std::fs::write(scan_path.join("readable.rs"), "fn main() {}\n").unwrap();
        let unreadable = scan_path.join("unreadable.txt");
        std::fs::write(&unreadable, "present but not inspectable\n").unwrap();
        let original_mode = std::fs::metadata(&unreadable).unwrap().permissions().mode();
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o0)).unwrap();
        if std::fs::read_to_string(&unreadable).is_ok() {
            // Root bypasses mode bits; do not claim coverage the
            // environment cannot exercise.
            std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(original_mode))
                .unwrap();
            std::fs::remove_dir_all(scan_path).ok();
            return;
        }

        let result = execute_scan(&dir_scan_opts(scan_path.clone())).unwrap();
        assert!(
            result.findings.is_empty(),
            "the fixture must stay finding-free"
        );
        assert!(
            !result.receipt.allows_safe(),
            "the unreadable required file must make the receipt unsafe"
        );
        assert_eq!(
            scan_exit_code(&result.receipt),
            EXIT_INCOMPLETE,
            "regression: an incomplete scan with zero findings must not exit 0"
        );
        let failed = result
            .receipt
            .inspection_ledger
            .units
            .iter()
            .find(|unit| unit.unit_id == unreadable.to_string_lossy())
            .expect("the unreadable file must be a ledger unit");
        assert_eq!(failed.status, InspectionStatus::Failed);
        assert!(failed.required);

        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(original_mode))
            .unwrap();
        std::fs::remove_dir_all(scan_path).ok();
    }

    /// Case matrix (skipped / timed-out inspection): a required unit that
    /// was skipped, left pending, or had no analyzer gates the exit code,
    /// while the same statuses on non-required units gate nothing.
    #[test]
    fn required_skipped_pending_and_unsupported_units_block_the_exit() {
        let scan_path = scan_fixture_path();
        let result = execute_scan(&dir_scan_opts(scan_path.clone())).unwrap();
        assert_eq!(
            scan_exit_code(&result.receipt),
            EXIT_CLEAN,
            "precondition: the readable fixture is a clean pass"
        );

        // A size-limit skip (`Skipped`, required) is the shape a
        // policy-skipped or timed-out inspection records.
        let mut skipped = result.receipt.clone();
        skipped.inspection_ledger.record(
            "huge.env",
            InspectionStatus::Skipped,
            true,
            Some("file_size_limit".to_string()),
        );
        assert!(!skipped.allows_safe());
        assert_eq!(scan_exit_code(&skipped), EXIT_INCOMPLETE);

        // A binary has no analyzer (`Unsupported`, required): content the
        // scan never inspected.
        let mut binary = result.receipt.clone();
        binary.inspection_ledger.record(
            "asset.bin",
            InspectionStatus::Unsupported,
            true,
            Some("binary_file".to_string()),
        );
        assert_eq!(scan_exit_code(&binary), EXIT_INCOMPLETE);

        // A discovered-but-pending unit is not an inspected one.
        let mut pending = result.receipt.clone();
        pending
            .inspection_ledger
            .record("later.rs", InspectionStatus::Discovered, true, None);
        assert_eq!(scan_exit_code(&pending), EXIT_INCOMPLETE);

        // The same statuses on non-required units change nothing.
        let mut optional = result.receipt.clone();
        optional.inspection_ledger.record(
            "optional.bin",
            InspectionStatus::Unsupported,
            false,
            Some("binary_file".to_string()),
        );
        optional.inspection_ledger.record(
            "optional.env",
            InspectionStatus::Skipped,
            false,
            Some("file_size_limit".to_string()),
        );
        assert!(optional.allows_safe());
        assert_eq!(scan_exit_code(&optional), EXIT_CLEAN);
        std::fs::remove_dir_all(scan_path).ok();
    }

    /// Case matrix (empty-diff): an empty diff file is a completed scan of
    /// a legitimately empty change set — a clean pass with evidence — and
    /// must stay distinct from a diff that cannot be read at all.
    #[test]
    fn empty_diff_is_a_completed_clean_scan_and_missing_diff_is_an_error() {
        let outside = tempfile::tempdir().unwrap();

        let empty_diff = outside.path().join("empty.diff");
        std::fs::write(&empty_diff, "").unwrap();
        let mut opts = dir_scan_opts(outside.path().to_path_buf());
        opts.diff = Some(empty_diff);
        let result = execute_scan(&opts).unwrap();
        assert!(result.findings.is_empty());
        assert!(
            result.receipt.allows_safe(),
            "scanning an empty diff is a complete inspection of it"
        );
        assert_eq!(scan_exit_code(&result.receipt), EXIT_CLEAN);

        // A diff that cannot be discovered/read is a scan fault, never a
        // silent no-op clean pass.
        let mut missing = dir_scan_opts(outside.path().to_path_buf());
        missing.diff = Some(outside.path().join("absent.diff"));
        assert!(
            execute_scan(&missing).is_err(),
            "an unreadable diff file must fail the scan, not pass clean"
        );
    }

    /// The staged (pre-commit) path must leave the same kind of evidence as
    /// every other mode: staged blobs are required analyzed units, so the
    /// receipt is safe and the exit agrees with the finding policy.
    #[test]
    fn staged_scan_receipt_covers_what_it_inspected() {
        let fixture = tempfile::tempdir().unwrap();
        git_repo_with_staged(fixture.path(), &[("config.env", STAGED_SECRET)]); // aegis:ignore:env-file-in-git
        let opts = staged_scan_opts(fixture.path().into());
        let result = execute_scan(&opts).unwrap();
        assert_eq!(result.findings.len(), 1);
        let unit = result
            .receipt
            .inspection_ledger
            .units
            .iter()
            .find(|unit| unit.unit_id == "config.env")
            .expect("the staged blob must be a ledger unit");
        assert_eq!(unit.status, InspectionStatus::Analyzed);
        assert!(unit.required);
        assert!(result.receipt.allows_safe());
        assert_eq!(scan_exit_code(&result.receipt), EXIT_FINDINGS);
    }

    /// Nothing staged means the index was fully enumerated and found
    /// empty: a complete inspection, recorded as such, and a clean exit.
    #[test]
    fn staged_scan_with_nothing_staged_is_clean_and_safe() {
        let fixture = tempfile::tempdir().unwrap();
        git_repo_with_staged(fixture.path(), &[]);
        let opts = staged_scan_opts(fixture.path().into());
        let result = execute_scan(&opts).unwrap();
        assert!(result.findings.is_empty());
        assert!(
            result.receipt.allows_safe(),
            "an enumerated empty index is a complete inspection"
        );
        assert_eq!(scan_exit_code(&result.receipt), EXIT_CLEAN);
    }

    /// A staged binary blob is content the pre-commit pass cannot inspect;
    /// committing it must not exit as a clean pass.
    #[test]
    fn staged_binary_blob_blocks_the_pre_commit_exit() {
        let fixture = tempfile::tempdir().unwrap();
        git_repo_with_staged(fixture.path(), &[("asset.bin", "\u{0}\u{1}\u{2}")]);
        let opts = staged_scan_opts(fixture.path().into());
        let result = execute_scan(&opts).unwrap();
        assert!(
            result.findings.is_empty(),
            "binary content is not pattern-scanned"
        );
        assert!(
            !result.receipt.allows_safe(),
            "the skipped binary blob must make the receipt unsafe"
        );
        let unit = result
            .receipt
            .inspection_ledger
            .units
            .iter()
            .find(|unit| unit.unit_id == "asset.bin")
            .expect("the binary blob must be a ledger unit");
        assert_eq!(unit.status, InspectionStatus::Unsupported);
        assert!(unit.required);
        assert_eq!(scan_exit_code(&result.receipt), EXIT_INCOMPLETE);
    }
}
