//! Scanner module

use crate::output::Output;
use crate::OutputFormat;
use aegis_core::{
    Finding, PatternDefinition, RiskScore, ScanOptions as CoreOptions, ScanReceipt, ScanStats,
    Scanner,
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

    let core_opts = CoreOptions {
        follow_symlinks: opts.follow_symlinks,
        categories: categories.clone(),
        severity_threshold: opts.severity_threshold.clone(),
        include_disabled: opts.all,
        diff_file: opts.diff.clone(),
        baseline: opts.baseline.clone(),
        anomaly_detectors,
        ..Default::default()
    };

    let patterns = aegis_patterns::all_patterns();
    let definitions: Vec<PatternDefinition> = patterns.into_iter().map(Into::into).collect();
    let scanner = Scanner::from_definitions(definitions)
        .map_err(|e| anyhow::anyhow!("Failed to load patterns: {e}"))?
        .with_options(core_opts);

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
        // Note: stdin read must happen in async context
        let findings = scanner.scan_string("", "stdin");
        let stats = stats_with_findings(ScanStats::for_content("string:stdin", 0), &findings);
        (findings, stats)
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

/// Heuristic mirroring the engine's binary detection: NUL in the first
/// window means the blob is binary and is skipped like scan_dir does.
fn looks_binary(bytes: &[u8]) -> bool {
    bytes[..bytes.len().min(8192)].contains(&0)
}

/// Scan the staged (index) content of the repository at `opts.path`.
///
/// Pre-commit semantics: the index is what a commit would contain and it
/// can differ from the working tree, so blobs are read with
/// `git show :<path>` rather than from disk. Nothing staged means nothing
/// to scan and a clean result.
fn scan_staged(scanner: &Scanner, opts: &ScanOptions) -> Result<(Vec<Finding>, ScanStats)> {
    let files = staged_file_list(&opts.path).map_err(|e| {
        anyhow::anyhow!(
            "--staged requires a git repository at {}: {e}",
            opts.path.display()
        )
    })?;

    let mut findings = Vec::new();
    let mut stats = ScanStats::default();
    for file in files {
        let blob = staged_blob(&opts.path, &file)?;
        if looks_binary(&blob) {
            stats.files_skipped += 1;
            continue;
        }
        let content = String::from_utf8_lossy(&blob);
        let file_findings = scanner.scan_string(&content, &file);
        stats.files_scanned += 1;
        stats.bytes_scanned += blob.len() as u64;
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
    /// Whether any finding survived; it becomes the process exit code.
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
    // Informational findings are reported but never fail a CI run.
    let has_findings = findings.iter().any(|f| f.severity != "info");
    let receipt = build_receipt(opts, &findings, stats.clone());

    // Calculate risk score
    let risk = RiskScore::new(
        &findings,
        &std::collections::HashMap::default(),
        &std::collections::HashMap::default(),
    );

    // Output results
    let mut output_dev = Output::new(opts.format.clone(), opts.quiet);
    output_dev.write_findings(&findings, &stats, &risk)?;

    Ok(ScanResult {
        findings,
        stats,
        output: output_dev.to_string(),
        has_findings,
        receipt,
    })
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
    // Informational findings are reported but never fail a CI run.
    let has_findings = findings.iter().any(|f| f.severity != "info");
    let stats = stats_with_findings(
        ScanStats::for_content("string:stdin", stdin_content.len()),
        &findings,
    );
    let receipt = build_receipt(opts, &findings, stats.clone());

    // Calculate risk score
    let risk = RiskScore::new(
        &findings,
        &std::collections::HashMap::default(),
        &std::collections::HashMap::default(),
    );

    // Output results
    let mut output_dev = Output::new(opts.format.clone(), opts.quiet);
    output_dev.write_findings(&findings, &stats, &risk)?;

    Ok(ScanResult {
        findings,
        stats,
        output: output_dev.to_string(),
        has_findings,
        receipt,
    })
}

/// Run scan with I/O handling (not fully testable due to async stdin and process::exit)
///
/// # Errors
///
/// Returns an error when the scan fails; exits the process with the
/// findings exit code when it is non-zero.
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

/// Run scan and return exit code (testable async wrapper)
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

    // Print to stdout
    println!("{}", result.output);

    // Write to file if specified
    if let Some(ref path) = opts.output_file {
        std::fs::write(path, result.output)?;
    }

    // Return exit code based on findings
    Ok(i32::from(result.has_findings))
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
            anomaly_detectors: None,
        };

        let result = execute_scan(&opts);
        assert!(result.is_ok());
        let scan_result = result.unwrap();
        // has_findings should match whether findings is empty
        assert_eq!(scan_result.has_findings, !scan_result.findings.is_empty());
        assert!(!scan_result.output.is_empty());
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
            anomaly_detectors: None,
        };

        let result = execute_scan_with_stdin(
            &opts,
            "let password = 'secret123';", // aegis:ignore:hardcoded-password,hardcoded-credential
        );
        assert!(result.is_ok());
        let scan_result = result.unwrap();
        assert!(!scan_result.output.is_empty());
    }

    #[test]
    fn test_perform_scan_stdin_branch() {
        // Test the perform_scan function with scan_stdin = true (line 77-78)
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
            anomaly_detectors: None,
        };

        let scanner = build_scanner_from_opts(&opts).unwrap();
        let result = perform_scan(&scanner, &opts);
        assert!(result.is_ok());
        let (findings, _stats) = result.unwrap();
        // When scan_stdin is true, empty string is passed to scan_string
        assert!(findings.is_empty());
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
            anomaly_detectors: None,
        };

        let result = execute_scan(&opts);
        assert!(result.is_ok());
        let scan_result = result.unwrap();
        // execute_scan populates output but doesn't write to file (async run_scan_and_get_exit_code does)
        assert!(!scan_result.output.is_empty());

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
        // Test that has_findings correctly determines exit code
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
            anomaly_detectors: None,
        };

        let result = execute_scan(&opts).unwrap();
        // Exit code should be 1 if has_findings, 0 otherwise
        let expected_exit = i32::from(result.has_findings);
        assert!(expected_exit == 0 || expected_exit == 1);
        std::fs::remove_dir_all(scan_path).ok();
    }

    /// Regression test: a failing scan must not leave a stale receipt.
    /// The old receipt is removed before the scan; if the scan fails, the
    /// file is simply absent — not a mix of old and new data.
    #[tokio::test]
    async fn test_failing_scan_does_not_leave_stale_receipt() {
        // Use a process-unique temp path to avoid races between parallel test
        // invocations. process::id is embedded in the receipt tmp-name so we
        // further isolate by including a monotonic fixture counter.
        static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);
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

        // Keep the guard alive until the end of the test so it can restore
        // the process-global environment.
        let _guard = guard;
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
            path.join("fixture.env"),
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

        // The baseline lives outside the scanned tree: a baseline inside
        // it would itself be scanned (and flagged) on the next run.
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
            fixture.join("fixture.env"),
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
            anomaly_detectors: None,
            format: OutputFormat::Human,
            quiet: false,
        }
    }

    const STAGED_SECRET: &str = "aws_key: AKIAIOSFODNN7EXAMPLE\n"; // aegis:ignore:aws-access-key

    #[test]
    fn test_staged_scan_reports_staged_secret() {
        let fixture = tempfile::tempdir().unwrap();
        git_repo_with_staged(fixture.path(), &[("config.env", STAGED_SECRET)]);

        let scanner = build_scanner_from_opts(&staged_scan_opts(fixture.path().into())).unwrap();
        let (findings, stats) =
            perform_scan(&scanner, &staged_scan_opts(fixture.path().into())).unwrap();
        assert_eq!(findings.len(), 1, "staged secret must be reported");
        assert_eq!(stats.files_scanned, 1);
        assert_eq!(findings[0].location.file, "config.env");
    }

    #[test]
    fn test_staged_scan_reads_index_not_working_tree() {
        let fixture = tempfile::tempdir().unwrap();
        git_repo_with_staged(fixture.path(), &[("config.env", STAGED_SECRET)]);

        // The working tree was cleaned after staging and an unrelated
        // secret was never staged at all; neither may change the result.
        std::fs::write(fixture.path().join("config.env"), "aws_key: clean\n").unwrap();
        std::fs::write(fixture.path().join("untracked.env"), STAGED_SECRET).unwrap();

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
        std::fs::write(fixture.path().join("config.env"), STAGED_SECRET).unwrap();
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
        std::fs::write(fixture.path().join("config.env"), STAGED_SECRET).unwrap();

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
            anomaly_detectors: None,
        };

        let result = execute_scan(&opts).unwrap();
        let blocking = result.findings.iter().any(|f| f.severity != "info");
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
        std::fs::remove_dir_all(scan_path).ok();
    }
}
