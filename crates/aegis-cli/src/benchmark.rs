//! Benchmark module for Aegis
//!
//! Provides efficient benchmarking capabilities for comparing scan performance.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::scanner::convert_pattern;
use aegis_core::{PatternDefinition, ScanOptions, Scanner};

/// Benchmark options
#[derive(Debug, Clone)]
pub struct BenchmarkOptions {
    /// Path to scan
    pub path: PathBuf,
    /// Number of warmup runs
    pub warmup: usize,
    /// Number of benchmark runs to average
    pub runs: usize,
    /// Compare with Atheon-Enhanced if available
    pub compare: bool,
}

/// Benchmark result for a single run
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    /// Duration of the scan
    pub duration: Duration,
    /// Number of files scanned
    pub files_scanned: usize,
    /// Number of bytes scanned
    pub bytes_scanned: u64,
    /// Number of findings
    pub findings_count: usize,
    /// Files per second throughput
    pub files_per_second: f64,
    /// MB per second throughput
    pub mb_per_second: f64,
}

/// Build scanner for benchmarking
fn build_benchmark_scanner() -> anyhow::Result<Scanner> {
    let patterns = aegis_patterns::all_patterns();
    let definitions: Vec<PatternDefinition> = patterns.into_iter().map(convert_pattern).collect();
    let scanner = Scanner::from_definitions(definitions)
        .map_err(|e| anyhow::anyhow!("Failed to load patterns: {}", e))?
        .with_options(ScanOptions::default());
    Ok(scanner)
}

/// Run Aegis benchmark
pub fn run_aegis_benchmark(
    path: &PathBuf,
    warmup: usize,
    runs: usize,
) -> anyhow::Result<BenchmarkResult> {
    // Warmup runs
    for _ in 0..warmup {
        let scanner = build_benchmark_scanner()?;
        let _ = scanner.scan_dir(path);
    }

    let mut total_duration = Duration::ZERO;
    let mut total_files = 0usize;
    let mut total_bytes = 0u64;
    let mut total_findings = 0;

    for _ in 0..runs {
        let scanner = build_benchmark_scanner()?;
        let start = Instant::now();
        let (findings, stats) = scanner
            .scan_dir(path)
            .map_err(|e| anyhow::anyhow!("Scan failed: {}", e))?;
        let duration = start.elapsed();

        total_duration += duration;
        total_files += stats.files_scanned;
        total_bytes += stats.bytes_scanned;
        total_findings += findings.len();
    }

    let count = runs as f64;
    let avg_duration = total_duration / runs as u32;
    let avg_files = (total_files as f64 / count) as usize;
    let avg_bytes = (total_bytes as f64 / count) as u64;
    let avg_findings = (total_findings as f64 / count) as usize;

    let files_per_second = if avg_duration.as_secs_f64() > 0.0 {
        avg_files as f64 / avg_duration.as_secs_f64()
    } else {
        0.0
    };

    let mb_per_second = if avg_duration.as_secs_f64() > 0.0 {
        avg_bytes as f64 / (1024.0 * 1024.0) / avg_duration.as_secs_f64()
    } else {
        0.0
    };

    Ok(BenchmarkResult {
        duration: avg_duration,
        files_scanned: avg_files,
        bytes_scanned: avg_bytes,
        findings_count: avg_findings,
        files_per_second,
        mb_per_second,
    })
}

/// Run external tool benchmark (e.g., Atheon-Enhanced)
pub fn run_external_benchmark(bin_path: &str, path: &PathBuf) -> anyhow::Result<BenchmarkResult> {
    let start = Instant::now();
    let output = Command::new(bin_path).arg(path).arg("-q").output()?;

    let duration = start.elapsed();

    // Count findings from output (one per line)
    let findings_count = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .count();

    // Estimate files/bytes - for external tools we just track time
    // and count findings
    Ok(BenchmarkResult {
        duration,
        files_scanned: 0, // Unknown for external tool
        bytes_scanned: 0,
        findings_count,
        files_per_second: 0.0,
        mb_per_second: 0.0,
    })
}

/// Main benchmark runner
pub fn run_benchmark(opts: BenchmarkOptions) -> anyhow::Result<()> {
    println!("==============================================");
    println!("Aegis Benchmark");
    println!("==============================================");
    println!();
    println!("Path: {:?}", opts.path);
    println!("Warmup runs: {}", opts.warmup);
    println!("Benchmark runs: {}", opts.runs);
    println!();

    // Run Aegis benchmark
    println!("Running Aegis benchmark...");
    let aegis_result = run_aegis_benchmark(&opts.path, opts.warmup, opts.runs)?;

    println!();
    println!(">>> AEGIS RESULTS <<<");
    println!("----------------------------------------------");
    println!("Duration: {:?}", aegis_result.duration);
    println!("Files scanned: {}", aegis_result.files_scanned);
    println!(
        "Bytes scanned: {} ({:.2} MB)",
        aegis_result.bytes_scanned,
        aegis_result.bytes_scanned as f64 / (1024.0 * 1024.0)
    );
    println!("Findings: {}", aegis_result.findings_count);
    println!(
        "Throughput: {:.2} files/s, {:.2} MB/s",
        aegis_result.files_per_second, aegis_result.mb_per_second
    );

    // Compare with Atheon if requested
    if opts.compare {
        println!();
        println!("Running Atheon-Enhanced comparison...");

        // Check if Atheon exists
        let atheon_path = "/nas/Temp/repos/Atheon-Enhanced/atheon";

        if std::path::Path::new(atheon_path).exists() {
            match run_external_benchmark(atheon_path, &opts.path) {
                Ok(atheon_result) => {
                    println!();
                    println!(">>> ATHEON-ENHANCED RESULTS <<<");
                    println!("----------------------------------------------");
                    println!("Duration: {:?}", atheon_result.duration);
                    println!("Findings: {}", atheon_result.findings_count);

                    let ratio =
                        atheon_result.duration.as_secs_f64() / aegis_result.duration.as_secs_f64();
                    println!();
                    println!(">>> COMPARISON <<<");
                    println!("----------------------------------------------");
                    println!(
                        "Aegis is {:.2}x {} than Atheon-Enhanced",
                        ratio,
                        if ratio > 1.0 { "faster" } else { "slower" }
                    );
                }
                Err(e) => {
                    println!("Atheon benchmark failed: {}", e);
                }
            }
        } else {
            println!(
                "Atheon-Enhanced not found at {}. Skipping comparison.",
                atheon_path
            );
        }
    }

    println!();
    println!("==============================================");

    Ok(())
}
