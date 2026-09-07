//! Benchmark module for Aegis
//!
//! Provides efficient benchmarking capabilities for comparing scan performance.

use std::path::{Path, PathBuf};
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
    path: &Path,
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

    // Compare with Atheon if requested. The comparator binary is opt-in via
    // the environment so no machine-specific path is baked into the binary.
    if opts.compare {
        println!();
        println!("Running Atheon-Enhanced comparison...");

        let atheon_path = std::env::var("AEGIS_ATHEON_PATH").unwrap_or_else(|_| {
            println!("AEGIS_ATHEON_PATH is not set; skipping the external comparison.");
            String::new()
        });

        if !atheon_path.is_empty() && std::path::Path::new(&atheon_path).exists() {
            match run_external_benchmark(&atheon_path, &opts.path) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_target() -> anyhow::Result<tempfile::TempDir> {
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join("sample.js"), r#"const token = "value";"#)?;
        Ok(dir)
    }

    #[test]
    fn aegis_benchmark_averages_runs_over_a_real_target() -> anyhow::Result<()> {
        let dir = sample_target()?;
        let result = run_aegis_benchmark(dir.path(), 0, 2)?;

        assert!(result.files_scanned >= 1, "sample file must be counted");
        assert!(result.bytes_scanned > 0);
        assert!(result.duration > Duration::ZERO);
        // Two runs averaged: the totals must be divisible back down to a
        // per-run file count.
        assert_eq!(result.files_per_second > 0.0, result.files_scanned > 0);
        Ok(())
    }

    #[test]
    fn external_benchmark_counts_non_empty_output_lines() -> anyhow::Result<()> {
        let dir = sample_target()?;
        // `echo` ignores the extra -q flag and prints one line per run.
        let result = run_external_benchmark("/bin/echo", &dir.path().to_path_buf())?;
        assert_eq!(result.findings_count, 1);
        assert_eq!(
            result.files_scanned, 0,
            "external tools report no file counts"
        );
        Ok(())
    }

    #[test]
    fn external_benchmark_surfaces_missing_binaries() {
        let error = run_external_benchmark("/nonexistent/aegis-tool", &PathBuf::from("."))
            .expect_err("missing binary must error");
        assert!(!error.to_string().is_empty());
    }

    #[test]
    fn full_benchmark_runner_completes_on_a_small_target() -> anyhow::Result<()> {
        let dir = sample_target()?;
        let opts = BenchmarkOptions {
            path: dir.path().to_path_buf(),
            warmup: 0,
            runs: 1,
            compare: false,
        };
        run_benchmark(opts)
    }
}
