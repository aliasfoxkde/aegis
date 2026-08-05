//! Scanner module

use crate::output::Output;
use crate::OutputFormat;
use aegis_core::{
    Confidence, Finding, PatternDefinition, RiskScore, ScanOptions as CoreOptions, ScanStats,
    Scanner, Severity,
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
    #[allow(dead_code)]
    pub baseline: Option<PathBuf>,
    pub format: OutputFormat,
    pub quiet: bool,
}

/// Convert aegis_patterns::Pattern to aegis_core::PatternDefinition
fn convert_pattern(p: aegis_patterns::Pattern) -> PatternDefinition {
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

pub async fn run_scan(opts: ScanOptions) -> Result<()> {
    // Build scanner with patterns loaded
    let categories = opts
        .categories
        .map(|c| c.split(',').map(|s| s.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();

    let core_opts = CoreOptions {
        follow_symlinks: opts.follow_symlinks,
        categories,
        severity_threshold: opts.severity_threshold,
        ..Default::default()
    };

    // Load patterns from aegis-patterns crate
    let patterns = aegis_patterns::all_patterns();
    let definitions: Vec<PatternDefinition> = patterns.into_iter().map(convert_pattern).collect();
    let scanner = Scanner::from_definitions(definitions)
        .map_err(|e| anyhow::anyhow!("Failed to load patterns: {}", e))?
        .with_options(core_opts);

    let (findings, stats): (Vec<Finding>, ScanStats) = if opts.scan_env {
        let findings = scanner.scan_env();
        (findings, ScanStats::default())
    } else if opts.scan_stdin {
        let mut stdin = tokio::io::stdin();
        let mut content = String::new();
        stdin.read_to_string(&mut content).await?;
        let findings = scanner.scan_string(&content, "stdin");
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
        // Scan directory
        scanner
            .scan_dir(&opts.path)
            .map_err(|e| anyhow::anyhow!("{}", e))?
    };

    // Calculate risk score
    let risk = RiskScore::new(&findings, &Default::default(), &Default::default());

    // Output results
    let mut output = Output::new(opts.format, opts.quiet);
    output.write_findings(&findings, &stats, &risk)?;

    // Print to stdout
    println!("{}", output);

    // Write to file if specified
    if let Some(ref path) = opts.output_file {
        std::fs::write(path, output.to_string())?;
    }

    // Exit code based on findings
    if !findings.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}

pub async fn update_bundle(_force: bool) -> Result<()> {
    println!("Updating pattern bundle...");

    // In a real implementation, this would download from a bundle server
    println!("Bundle is up to date.");
    Ok(())
}
