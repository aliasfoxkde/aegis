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
pub mod bundle;
pub mod cfg;
pub mod clone;
pub mod config;
pub mod entropy;
pub mod finding;
pub mod ignore;
pub mod pattern;
pub mod risk;
pub mod scanner;
pub mod suppression;

pub use bundle::{Bundle, BundleMetadata};
pub use config::Config;
pub use entropy::shannon_entropy;
pub use finding::{Finding, FindingKind, Location, ScanStats};
pub use pattern::{Category, Confidence, Pattern, PatternDefinition, PatternRegistry, Severity};
pub use risk::{RiskClassification, RiskLevel, RiskScore};
pub use scanner::{ScanOptions, Scanner};
pub use suppression::Suppression;

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
}
