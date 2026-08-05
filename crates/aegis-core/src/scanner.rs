//! Main scanner implementation
//!
//! Handles scanning files, directories, and strings for patterns.

use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use walkdir::WalkDir;

use crate::suppression::SuppressionManager;

use crate::bundle::Bundle;
use crate::config::Config;
use crate::finding::{Finding, FindingKind, Location, ScanStats};
use crate::ignore::IgnoreManager;
use crate::pattern::{PatternDefinition, PatternRegistry};

/// Scan options
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Maximum file size to scan
    pub max_file_size: u64,
    /// Follow symbolic links
    pub follow_symlinks: bool,
    /// Scan binary files
    pub scan_binary: bool,
    /// Categories to include (empty = all)
    pub categories: Vec<String>,
    /// Severity threshold
    pub severity_threshold: Option<String>,
    /// Use gitignore
    pub use_gitignore: bool,
    /// Use atheonignore
    pub use_atheonignore: bool,
    /// Number of workers
    pub workers: usize,
    /// Baseline file to suppress known findings
    pub baseline: Option<PathBuf>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_file_size: 10 * 1024 * 1024, // 10MB
            follow_symlinks: false,
            scan_binary: false,
            categories: Vec::new(),
            severity_threshold: None,
            use_gitignore: true,
            use_atheonignore: true,
            workers: num_cpus(),
            baseline: None,
        }
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

/// Main scanner
pub struct Scanner {
    registry: Arc<PatternRegistry>,
    ignore_manager: Arc<IgnoreManager>,
    #[allow(dead_code)]
    suppression_manager: SuppressionManager,
    options: ScanOptions,
}

impl Scanner {
    /// Create a new scanner
    pub fn new() -> Self {
        Self {
            registry: Arc::new(PatternRegistry::new()),
            ignore_manager: Arc::new(IgnoreManager::new()),
            suppression_manager: SuppressionManager::new(),
            options: ScanOptions::default(),
        }
    }

    /// Create a scanner with a bundle
    pub fn from_bundle(bundle: &Bundle) -> Result<Self, crate::pattern::PatternError> {
        let registry = PatternRegistry::from_definitions(bundle.patterns.clone())?;
        Ok(Self {
            registry: Arc::new(registry),
            ignore_manager: Arc::new(IgnoreManager::new()),
            suppression_manager: SuppressionManager::new(),
            options: ScanOptions::default(),
        })
    }

    /// Create a scanner from pattern definitions
    pub fn from_definitions(
        definitions: Vec<PatternDefinition>,
    ) -> Result<Self, crate::pattern::PatternError> {
        let registry = PatternRegistry::from_definitions(definitions)?;
        Ok(Self {
            registry: Arc::new(registry),
            ignore_manager: Arc::new(IgnoreManager::new()),
            suppression_manager: SuppressionManager::new(),
            options: ScanOptions::default(),
        })
    }

    /// Create a scanner with config
    pub fn from_config(config: &Config) -> Result<Self, crate::pattern::PatternError> {
        let mut scanner = Self::from_bundle(&config.bundle)?;

        if let Some(categories) = &config.enabled_categories {
            scanner.registry.disable_all();
            for cat in categories {
                scanner.registry.set_category_enabled(cat, true);
            }
        }

        scanner.options.max_file_size = config.max_file_size_mb * 1024 * 1024;
        scanner.options.use_gitignore = config.gitignore_respect;
        scanner.options.use_atheonignore = config.gitignore_respect;

        Ok(scanner)
    }

    /// Get the pattern registry
    pub fn registry(&self) -> &PatternRegistry {
        &self.registry
    }

    /// Initialize ignore manager with a root directory
    pub fn init_ignore_root(&self, root: &Path) -> std::io::Result<()> {
        self.ignore_manager.set_root(root)
    }

    /// Update options
    pub fn with_options(mut self, options: ScanOptions) -> Self {
        self.options = options;
        self
    }

    /// Scan a string
    pub fn scan_string(&self, content: &str, source: &str) -> Vec<Finding> {
        let start = Instant::now();

        // Parse suppressions from content
        let mut suppression_mgr = SuppressionManager::new();
        suppression_mgr.parse_content(content);

        let patterns = self.registry.enabled();
        let mut findings = Vec::new();

        for pattern in &patterns {
            if pattern.is_env_var_only() {
                continue; // Skip env-var only patterns for string scans
            }

            let matches = pattern.find_matches(content);
            for m in matches {
                let line_num = content[..m.start].matches('\n').count() as u32 + 1;

                // Check if this finding should be suppressed
                if suppression_mgr.is_suppressed(pattern.name(), line_num) {
                    continue;
                }

                let location = Location::new(
                    source,
                    line_num as usize,
                    m.start,
                    m.matched_text.to_string(),
                );
                let mut finding = Finding::new(
                    pattern.name(),
                    pattern.category(),
                    pattern.severity().to_string(),
                    pattern.confidence().to_string(),
                    location,
                    m.matched_text,
                    pattern.description(),
                )
                .with_kind(FindingKind::Pattern);

                if let Some(reference) = pattern.reference() {
                    finding = finding.with_reference(reference);
                }

                findings.push(finding);
            }
        }

        let _ = start.elapsed(); // Used for timing in non-test
        findings
    }

    /// Scan a single file
    pub fn scan_file(&self, path: &Path) -> Result<(Vec<Finding>, ScanStats), ScanError> {
        let start = Instant::now();
        let io_start = Instant::now();

        // Check file size
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ScanError::FileNotFound(path.to_path_buf()));
            }
            Err(e) => return Err(ScanError::IoError(e)),
        };

        if metadata.len() > self.options.max_file_size {
            return Ok((
                Vec::new(),
                ScanStats {
                    files_skipped: 1,
                    ..Default::default()
                },
            ));
        }

        // Check if binary
        let is_binary = is_binary_file(path)?;
        if is_binary && !self.options.scan_binary {
            return Ok((
                Vec::new(),
                ScanStats {
                    files_skipped: 1,
                    ..Default::default()
                },
            ));
        }

        // Read file content
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => return Err(ScanError::IoError(e)),
        };

        let io_time = io_start.elapsed().as_millis() as u64;

        // Check ignore
        if self.ignore_manager.should_ignore(path) {
            return Ok((
                Vec::new(),
                ScanStats {
                    files_skipped: 1,
                    ..Default::default()
                },
            ));
        }

        // Scan content
        let findings = self.scan_string(&content, &path.to_string_lossy());

        let scan_time = start.elapsed().as_millis() as u64;

        let mut stats = ScanStats {
            files_scanned: 1,
            bytes_scanned: metadata.len(),
            scan_time_ms: scan_time,
            io_time_ms: io_time,
            workers_used: 1,
            ..Default::default()
        };

        for finding in &findings {
            stats.add_finding(finding);
        }

        Ok((findings, stats))
    }

    /// Scan a directory recursively
    pub fn scan_dir(&self, root: &Path) -> Result<(Vec<Finding>, ScanStats), ScanError> {
        let start = Instant::now();

        // Initialize ignore manager with the root directory
        if let Err(e) = self.ignore_manager.set_root(root) {
            tracing::debug!("Failed to load ignore files: {}", e);
        }

        let walker = if self.options.follow_symlinks {
            WalkDir::new(root).follow_links(true)
        } else {
            WalkDir::new(root).follow_links(false)
        };

        let entries: Vec<_> = walker
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .collect();

        let total_files = entries.len();

        let (findings, stats): (Vec<_>, Vec<_>) = entries
            .par_iter()
            .filter_map(|entry| self.scan_file(entry.path()).ok())
            .unzip();

        let all_findings: Vec<Finding> = findings.into_iter().flatten().collect();

        let mut merged_stats = ScanStats {
            files_scanned: total_files,
            ..Default::default()
        };

        for stat in stats {
            merged_stats.merge(&stat);
        }

        merged_stats.scan_time_ms = start.elapsed().as_millis() as u64;

        Ok((all_findings, merged_stats))
    }

    /// Scan environment variables
    pub fn scan_env(&self) -> Vec<Finding> {
        let patterns = self.registry.enabled();
        let mut findings = Vec::new();

        for (key, value) in std::env::vars() {
            for pattern in &patterns {
                if !pattern.is_env_var_only() && pattern.category() != "secrets" {
                    continue;
                }

                if pattern.matches(&value) {
                    let location = Location::new("[env]", 1, 0, format!("{}={}", key, value));
                    let finding = Finding::new(
                        pattern.name(),
                        pattern.category(),
                        pattern.severity().to_string(),
                        pattern.confidence().to_string(),
                        location,
                        &value,
                        pattern.description(),
                    )
                    .with_kind(FindingKind::Entropy);

                    findings.push(finding);
                }
            }
        }

        findings
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a file is binary
fn is_binary_file(path: &Path) -> Result<bool, std::io::Error> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut buffer = [0u8; 8192];
    let n = file.read(&mut buffer)?;

    Ok(buffer[..n].contains(&0))
}

/// Scan error types
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("File not found: {0}")]
    FileNotFound(PathBuf),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Permission denied: {0}")]
    PermissionDenied(PathBuf),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_string() {
        let scanner = Scanner::new();

        let findings = scanner.scan_string("AKIAIOSFODNN7EXAMPLE", "test.rs");
        assert!(findings.is_empty()); // No patterns registered
    }

    #[test]
    fn test_scan_empty_string() {
        let scanner = Scanner::new();
        let findings = scanner.scan_string("", "test.rs");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_is_binary_file() {
        // This test file should not be binary
        let result = is_binary_file(Path::new("test"));
        // Path doesn't exist so it should error
        assert!(result.is_err());
    }
}
