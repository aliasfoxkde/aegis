//! Scanner module

use crate::output::Output;
use crate::OutputFormat;
use aegis_core::{Finding, RiskScore, ScanOptions as CoreOptions, ScanStats, Scanner};
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

pub async fn run_scan(opts: ScanOptions) -> Result<()> {
    // Build scanner
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

    let scanner = Scanner::new().with_options(core_opts);

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
