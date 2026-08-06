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
            severity: "invalid".to_string(), // Invalid severity
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
}
