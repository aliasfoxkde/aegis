//! Benchmarking module for Aegis
//!
//! Provides utilities for measuring scan performance and pattern effectiveness.

use std::time::Duration;

use crate::{Finding, ScanStats};

/// Benchmark result for a single scan
#[derive(Debug, Clone)]
pub struct ScanBenchmark {
    /// Time taken to scan
    pub duration: Duration,
    /// Number of files scanned
    pub files_scanned: usize,
    /// Number of bytes scanned
    pub bytes_scanned: u64,
    /// Number of findings
    pub findings_count: usize,
    /// Throughput: files per second
    pub files_per_second: f64,
    /// Throughput: MB per second
    pub mb_per_second: f64,
}

impl ScanBenchmark {
    /// Create a new benchmark from scan results
    pub fn new(duration: Duration, stats: &ScanStats, findings_count: usize) -> Self {
        let files_scanned = stats.files_scanned;
        let bytes_scanned = stats.bytes_scanned;
        let files_per_second = if duration.as_secs_f64() > 0.0 {
            files_scanned as f64 / duration.as_secs_f64()
        } else {
            0.0
        };
        let mb_per_second = if duration.as_secs_f64() > 0.0 {
            bytes_scanned as f64 / (1024.0 * 1024.0) / duration.as_secs_f64()
        } else {
            0.0
        };

        Self {
            duration,
            files_scanned,
            bytes_scanned,
            findings_count,
            files_per_second,
            mb_per_second,
        }
    }
}

/// Benchmark configuration
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Path to scan
    pub path: String,
    /// Include disabled patterns
    pub include_disabled: bool,
    /// Categories to include (empty = all)
    pub categories: Vec<String>,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            path: ".".to_string(),
            include_disabled: false,
            categories: Vec::new(),
        }
    }
}

/// Format benchmark results as JSON for tracking over time
pub fn format_benchmark_json(
    name: &str,
    benchmark: &ScanBenchmark,
    findings: &[Finding],
) -> serde_json::Value {
    // Count findings by severity
    let mut by_severity: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for f in findings {
        *by_severity.entry(f.severity.clone()).or_insert(0) += 1;
    }

    // Get timestamp as Unix timestamp for simplicity
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    serde_json::json!({
        "name": name,
        "timestamp": timestamp,
        "duration_ms": benchmark.duration.as_millis() as u64,
        "files_scanned": benchmark.files_scanned,
        "bytes_scanned": benchmark.bytes_scanned,
        "findings_count": benchmark.findings_count,
        "files_per_second": benchmark.files_per_second,
        "mb_per_second": benchmark.mb_per_second,
        "findings_by_severity": by_severity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_config_default() {
        let config = BenchmarkConfig::default();
        assert_eq!(config.path, ".");
        assert!(!config.include_disabled);
        assert!(config.categories.is_empty());
    }

    #[test]
    fn test_scan_benchmark() {
        let duration = Duration::from_millis(100);
        let stats = ScanStats {
            files_scanned: 50,
            bytes_scanned: 1024 * 1024,
            ..Default::default()
        };

        let benchmark = ScanBenchmark::new(duration, &stats, 10);
        assert_eq!(benchmark.files_scanned, 50);
        assert_eq!(benchmark.findings_count, 10);
        assert!(benchmark.files_per_second > 0.0);
    }
}
