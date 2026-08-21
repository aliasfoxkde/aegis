//! # Aegis Core
//!
//! Core scanning engine for Aegis pattern matching.
//!
//! ## Features
//!
//! - Pattern registry and management
//! - Bundle loading and verification
//! - Entropy-based secret detection
//! - Risk scoring and classification
//! - AST-based code analysis
//! - Clone detection
//! - Ignore pattern handling
//!
//! ## Example
//!
//! ```rust
//! use aegis_core::{Scanner, Config};
//!
//! let scanner = Scanner::new();
//! let findings = scanner.scan_string("AKIAIOSFODNN7EXAMPLE", "test.rs");
//! ```

pub mod ast;
pub mod benchmark;
pub mod bundle;
pub mod cfg;
pub mod clone;
pub mod config;
pub mod control_center_adapter;
pub mod entropy;
pub mod finding;
pub mod ignore;
pub mod pattern;
pub mod receipt;
pub mod remediation;
pub mod risk;
pub mod sbom;
pub mod scanner;
pub mod suppression;

#[cfg(feature = "output-pipeline")]
pub mod output;

// Internal helpers - not part of public API. Some are intentionally kept as
// reusable seams for analyzers that are being integrated incrementally.
#[allow(dead_code)]
mod internal;

pub use ast::{AstAnalysis, AstAnalyzer, AstFinding, AstInspection, AstInspectionStatus, Language};
pub use benchmark::{format_benchmark_json, BenchmarkConfig, ScanBenchmark};
pub use bundle::{Bundle, BundleMetadata};
pub use config::Config;
pub use control_center_adapter::{
    AdapterError, ControlCenterAdapter, EvidenceRecord, ScanResult, WorkRequest,
};
pub use entropy::shannon_entropy;
pub use finding::{
    Finding, FindingKind, InspectionLedger, InspectionStatus, InspectionUnit, Location, ScanStats,
    INSPECTION_LEDGER_SCHEMA_VERSION,
};
pub use pattern::{Category, Confidence, Pattern, PatternDefinition, PatternRegistry, Severity};
pub use receipt::{ReceiptFinding, ReceiptLocation, ScanReceipt, SCAN_RECEIPT_SCHEMA_VERSION};
pub use remediation::{
    FixDifficulty, FixPattern, FixType, Remediation, RemediationAdvisor, RemediationReport,
    RemediationRoi,
};
pub use risk::{RiskClassification, RiskLevel, RiskScore};
pub use sbom::{Sbom, SbomComponent, SbomDependency, SbomFormat, SbomFormat::Spdx, SbomGenerator};
pub use scanner::{ScanOptions, Scanner};
pub use suppression::Suppression;

#[cfg(feature = "output-pipeline")]
pub use output::{
    database::{DatabaseOutput, MySqlOutput, PostgreSqlOutput, SqliteOutput},
    file::FileOutput,
    webhook::WebhookOutput,
    OutputError, OutputFormat, OutputPipeline, OutputResult, SyncOutputHandler,
};

use std::path::PathBuf;

/// Version string
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default maximum file size to scan (10 MB)
pub const DEFAULT_MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Default number of workers
pub fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| std::cmp::min(n.get() * 2, 64))
        .unwrap_or(4)
}

/// Get the default bundle path
pub fn default_bundle_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("aegis")
        .join("patterns.bundle")
}

/// Get the default cache directory
pub fn default_cache_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("aegis")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_MAX_FILE_SIZE, 10 * 1024 * 1024);
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_default_workers() {
        let workers = default_workers();
        assert!(workers >= 1);
        assert!(workers <= 64);
    }

    #[test]
    fn test_version_not_empty() {
        assert!(!VERSION.is_empty());
        assert!(VERSION.len() >= 5); // At least x.y.z format
    }

    #[test]
    fn test_default_workers_calculation() {
        let workers = default_workers();
        // Workers should be reasonable
        assert!(workers >= 1);
        assert!(workers <= 128); // Capped at some reasonable max
    }

    #[test]
    fn test_default_bundle_path() {
        let path = default_bundle_path();
        assert!(path.to_string_lossy().contains("aegis"));
    }

    #[test]
    fn test_default_cache_dir() {
        let path = default_cache_dir();
        assert!(path.to_string_lossy().contains("aegis"));
    }
}
