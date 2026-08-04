//! # Atheon Core
//!
//! Core scanning engine for Atheon-Enhanced pattern matching.
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
//! use atheon_core::{Scanner, Config};
//!
//! let scanner = Scanner::new();
//! let findings = scanner.scan_string("AKIAIOSFODNN7EXAMPLE", "test.rs");
//! ```

pub mod pattern;
pub mod bundle;
pub mod scanner;
pub mod finding;
pub mod risk;
pub mod entropy;
pub mod ignore;
pub mod config;
pub mod ast;
pub mod clone;
pub mod cfg;
pub mod suppression;

pub use pattern::{Pattern, PatternRegistry, Severity, Confidence, Category};
pub use bundle::{Bundle, BundleMetadata};
pub use scanner::{Scanner, ScanOptions, ScanStats};
pub use finding::{Finding, FindingKind, Location};
pub use risk::{RiskScore, RiskLevel, RiskClassification};
pub use entropy::calculate_entropy;
pub use config::Config;
pub use suppression::Suppression;

use std::path::PathBuf;

/// Version string
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default maximum file size to scan (10 MB)
pub const DEFAULT_MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Default number of workers
pub fn default_workers() -> usize {
    std::thread::available_concurrency()
        .map(|n| std::cmp::min(n.get() * 2, 64))
        .unwrap_or(4)
}

/// Get the default bundle path
pub fn default_bundle_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("atheon")
        .join("patterns.bundle")
}

/// Get the default cache directory
pub fn default_cache_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("atheon")
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
