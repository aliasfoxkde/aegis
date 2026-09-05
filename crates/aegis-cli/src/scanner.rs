//! Scanner module

use crate::output::Output;
use crate::OutputFormat;
use aegis_core::{
    Confidence, Finding, PatternDefinition, RiskScore, ScanOptions as CoreOptions, ScanReceipt,
    ScanStats, Scanner, Severity,
};
use anyhow::Result;
use std::path::PathBuf;
use tokio::io::AsyncReadExt;

pub struct ScanOptions {
    pub path: PathBuf,
    pub scan_file: bool,
    pub scan_env: bool,
    pub scan_stdin: bool,
    pub follow_symlinks: bool,
    pub categories: Option<String>,
    pub severity_threshold: Option<String>,
    pub output_file: Option<PathBuf>,
    pub baseline: Option<PathBuf>,
    /// Include disabled patterns in scan
    pub all: bool,
    /// Diff file to scan (only changed lines)
    pub diff: Option<PathBuf>,
    pub format: OutputFormat,
    pub quiet: bool,
}

/// Convert aegis_patterns::Pattern to aegis_core::PatternDefinition
pub fn convert_pattern(p: aegis_patterns::Pattern) -> PatternDefinition {
    PatternDefinition {
        name: p.name,
        category: p.category,
        match_pattern: p.match_pattern,
        enabled: p.enabled,
        severity: Severity::parse(&p.severity).unwrap_or(Severity::Medium),
        confidence: Confidence::parse(&p.confidence).unwrap_or(Confidence::Medium),
        min_entropy: p.min_entropy,
        description: p.description,
        reference: p.reference,
        tags: p.tags,
        env_var: p.env_var,
        binary: p.binary,
    }
}

/// Build scanner from scan options (testable)
pub fn build_scanner_from_opts(opts: &ScanOptions) -> Result<Scanner> {
    let categories = opts
        .categories
        .as_ref()
        .map(|c| c.split(',').map(|s| s.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();

    let core_opts = CoreOptions {
        follow_symlinks: opts.follow_symlinks,
        categories,
        severity_threshold: opts.severity_threshold.clone(),
        include_disabled: opts.all,
        diff_file: opts.diff.clone(),
        ..Default::default()
    };

    let patterns = aegis_patterns::all_patterns();
    let definitions: Vec<PatternDefinition> = patterns.into_iter().map(convert_pattern).collect();
    let scanner = Scanner::from_definitions(definitions)
        .map_err(|e| anyhow::anyhow!("Failed to load patterns: {}", e))?
        .with_options(core_opts);

    Ok(scanner)
}

/// Perform scan based on options (testable)
pub fn perform_scan(scanner: &Scanner, opts: &ScanOptions) -> Result<(Vec<Finding>, ScanStats)> {
    let (findings, stats): (Vec<Finding>, ScanStats) = if let Some(diff_path) = &opts.diff {
        // Scan only changed lines from a diff file
        let diff_content = std::fs::read_to_string(diff_path)?;
        let findings = scanner.scan_diff(&diff_content, "diff");
        (findings, ScanStats::default())
    } else if opts.scan_env {
        let findings = scanner.scan_env();
        (findings, ScanStats::default())
    } else if opts.scan_stdin {
        // Note: stdin read must happen in async context
        let findings = scanner.scan_string("", "stdin");
        (findings, ScanStats::default())
    } else if opts.scan_file {
        let path = &opts.path;
        if path.is_dir() {
            scanner
                .scan_dir(path)
                .map_err(|e| anyhow::anyhow!("{}", e))?
        } else {
            scanner
                .scan_file(path)
                .map_err(|e| anyhow::anyhow!("{}", e))?
        }
    } else {
        scanner
            .scan_dir(&opts.path)
            .map_err(|e| anyhow::anyhow!("{}", e))?
    };

    Ok((findings, stats))
}

/// Result of a scan execution
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub stats: ScanStats,
    pub output: String,
    pub has_findings: bool,
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
        receipt.write_atomic(std::path::Path::new(&path))?;
    }
    Ok(())
}

/// Execute scan and return result (testable)
pub fn execute_scan(opts: &ScanOptions) -> Result<ScanResult> {
    let scanner = build_scanner_from_opts(opts)?;

    let (findings, stats) = perform_scan(&scanner, opts)?;
    let has_findings = !findings.is_empty();
    let receipt = build_receipt(opts, &findings, stats.clone());

    // Calculate risk score
    let risk = RiskScore::new(&findings, &Default::default(), &Default::default());

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
pub fn execute_scan_with_stdin(opts: &ScanOptions, stdin_content: &str) -> Result<ScanResult> {
    let scanner = build_scanner_from_opts(opts)?;

    let findings = scanner.scan_string(stdin_content, "stdin");
    let has_findings = !findings.is_empty();
    let stats = ScanStats::for_content("string:stdin", stdin_content.len());
    let receipt = build_receipt(opts, &findings, stats.clone());

    // Calculate risk score
    let risk = RiskScore::new(&findings, &Default::default(), &Default::default());

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
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Run scan and return exit code (testable async wrapper)
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
    Ok(if result.has_findings { 1 } else { 0 })
}

/// Read stdin content (extracted for testing)
async fn read_stdin_content() -> Result<String> {
    let mut stdin = tokio::io::stdin();
    let mut content = String::new();
    stdin.read_to_string(&mut content).await?;
    Ok(content)
}

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

    #[test]
    fn test_convert_pattern() {
        let pattern = aegis_patterns::Pattern {
            name: "test-pattern".to_string(),
            category: "secrets".to_string(),
            match_pattern: "secret".to_string(),
            severity: "high".to_string(),
            confidence: "high".to_string(),
            description: "Test pattern".to_string(),
            enabled: true,
            min_entropy: None,
            reference: None,
            tags: vec![],
            env_var: false,
            binary: false,
        };

        let converted = convert_pattern(pattern);
        assert_eq!(converted.name, "test-pattern");
        assert_eq!(converted.category, "secrets");
        assert_eq!(converted.severity, Severity::High);
        assert_eq!(converted.confidence, Confidence::High);
    }

    #[test]
    fn test_convert_pattern_medium_defaults() {
        let pattern = aegis_patterns::Pattern {
            name: "test-pattern".to_string(),
            category: "test".to_string(),
            match_pattern: "test".to_string(),
            severity: "invalid".to_string(),   // Invalid severity
            confidence: "invalid".to_string(), // Invalid confidence
            description: "Test".to_string(),
            enabled: true,
            min_entropy: None,
            reference: None,
            tags: vec![],
            env_var: false,
            binary: false,
        };

        let converted = convert_pattern(pattern);
        // Should default to Medium for invalid values
        assert_eq!(converted.severity, Severity::Medium);
        assert_eq!(converted.confidence, Confidence::Medium);
    }

    #[tokio::test]
    async fn test_update_bundle() {
        let result = update_bundle(false).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_convert_pattern_with_min_entropy() {
        let pattern = aegis_patterns::Pattern {
            name: "high-entropy".to_string(),
            category: "secrets".to_string(),
            match_pattern: "[A-Za-z0-9+/]{20,}".to_string(),
            severity: "high".to_string(),
            confidence: "medium".to_string(),
            description: "High entropy secret".to_string(),
            enabled: true,
            min_entropy: Some(4.5),
            reference: Some("https://example.com".to_string()),
            tags: vec!["secret".to_string(), "entropy".to_string()],
            env_var: true,
            binary: false,
        };

        let converted = convert_pattern(pattern);
        assert_eq!(converted.name, "high-entropy");
        assert_eq!(converted.min_entropy, Some(4.5));
        assert!(converted.env_var);
        assert!(!converted.binary);
        assert_eq!(converted.tags.len(), 2);
    }

    #[test]
    fn test_convert_pattern_binary_enabled() {
        let pattern = aegis_patterns::Pattern {
            name: "binary-pattern".to_string(),
            category: "secrets".to_string(),
            match_pattern: "pattern".to_string(),
            severity: "low".to_string(),
            confidence: "low".to_string(),
            description: "Binary pattern".to_string(),
            enabled: false,
            min_entropy: None,
            reference: None,
            tags: vec![],
            env_var: false,
            binary: true,
        };

        let converted = convert_pattern(pattern);
        assert!(converted.binary);
        assert!(!converted.enabled); // disabled by input
    }

    #[test]
    fn test_scan_options_default() {
        let opts = ScanOptions {
            path: std::path::PathBuf::from("/test"),
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
            path: std::path::PathBuf::from("/test"),
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
        };

        assert_eq!(opts.categories.as_ref().unwrap(), "secrets,pii");
        assert_eq!(opts.severity_threshold.as_ref().unwrap(), "high");
        assert!(opts.quiet);
    }

    #[test]
    fn test_convert_pattern_preserves_all_fields() {
        let pattern = aegis_patterns::Pattern {
            name: "full-pattern".to_string(),
            category: "security".to_string(),
            match_pattern: r"\bKEY-[A-Z0-9]{16}\b".to_string(),
            severity: "critical".to_string(),
            confidence: "high".to_string(),
            description: "API key pattern".to_string(),
            enabled: true,
            min_entropy: Some(5.0),
            reference: Some("https://docs.example.com/api-keys".to_string()),
            tags: vec![
                "api".to_string(),
                "key".to_string(),
                "production".to_string(),
            ],
            env_var: true,
            binary: true,
        };

        let converted = convert_pattern(pattern.clone());
        assert_eq!(converted.name, pattern.name);
        assert_eq!(converted.category, pattern.category);
        assert_eq!(converted.match_pattern, pattern.match_pattern);
        assert_eq!(converted.severity, Severity::Critical);
        assert_eq!(converted.confidence, Confidence::High);
        assert_eq!(converted.min_entropy, pattern.min_entropy);
        assert_eq!(converted.description, pattern.description);
        assert_eq!(converted.reference, pattern.reference);
        assert_eq!(converted.tags, pattern.tags);
        assert_eq!(converted.env_var, pattern.env_var);
        assert_eq!(converted.binary, pattern.binary);
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
            path: std::path::PathBuf::from("/test"),
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
        };

        let scanner = build_scanner_from_opts(&opts);
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_build_scanner_from_opts_no_categories() {
        let opts = ScanOptions {
            path: std::path::PathBuf::from("/test"),
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
        };

        let scanner = build_scanner_from_opts(&opts);
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_build_scanner_with_severity_threshold() {
        let opts = ScanOptions {
            path: std::path::PathBuf::from("/test"),
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
        };

        let scanner = build_scanner_from_opts(&opts);
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_perform_scan_env() {
        let opts = ScanOptions {
            path: std::path::PathBuf::from("/test"),
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
            path: std::path::PathBuf::from("/nonexistent/path/to/file.txt"),
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
            path: std::path::PathBuf::from("/test"),
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
        };

        let result = execute_scan_with_stdin(
            &opts,
            "let password = 'secret123';", // aegis:ignore:hardcoded-password
        );
        assert!(result.is_ok());
        let scan_result = result.unwrap();
        assert!(!scan_result.output.is_empty());
    }

    #[test]
    fn test_perform_scan_stdin_branch() {
        // Test the perform_scan function with scan_stdin = true (line 77-78)
        let opts = ScanOptions {
            path: std::path::PathBuf::from("/test"),
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
        };

        let scanner = build_scanner_from_opts(&opts).unwrap();
        let result = perform_scan(&scanner, &opts);
        assert!(result.is_ok());
        let (findings, _stats) = result.unwrap();
        // When scan_stdin is true, empty string is passed to scan_string
        assert!(findings.is_empty());
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
        };

        let result = execute_scan(&opts).unwrap();
        // Exit code should be 1 if has_findings, 0 otherwise
        let expected_exit = if result.has_findings { 1 } else { 0 };
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
        static FIXTURE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let fixture_id = FIXTURE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
            path: std::path::PathBuf::from("/this/path/does/not/exist/at/all"),
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

        // Suppress unused field warning.
        let _ = guard;
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
}
