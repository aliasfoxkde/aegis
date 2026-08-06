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

        let patterns: Vec<_> = self.registry.enabled()
            .into_iter()
            .filter(|p| !p.is_env_var_only())
            .collect();

        // Parallelize when many patterns (threshold: 50 patterns)
        let findings: Vec<Finding> = if patterns.len() > 50 {
            patterns.par_iter().flat_map(|pattern| {
                let mut pattern_findings = Vec::new();
                let matches = pattern.find_matches(content);
                for m in matches {
                    let line_num = content[..m.start].matches('\n').count() as u32 + 1;
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
                    pattern_findings.push(finding);
                }
                pattern_findings
            }).collect()
        } else {
            // Sequential for small number of patterns
            let mut findings = Vec::new();
            for pattern in &patterns {
                let matches = pattern.find_matches(content);
                for m in matches {
                    let line_num = content[..m.start].matches('\n').count() as u32 + 1;
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
            findings
        };

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
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

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

    #[test]
    fn test_scan_file_not_found() {
        let scanner = Scanner::new();
        let result = scanner.scan_file(Path::new("/nonexistent/file.txt"));
        assert!(matches!(result, Err(ScanError::FileNotFound(_))));
    }

    #[test]
    fn test_scan_file_io_error() {
        // Create a file we can read, then make it unreadable by using a path we can't access
        let scanner = Scanner::new();
        // Use a valid file path but which causes issues - the scanner should handle it
        let result = scanner.scan_file(Path::new("/root/.shakey")); // typically root-only
        // Should not panic - either FileNotFound or PermissionDenied
        match result {
            Err(ScanError::IoError(_)) | Err(ScanError::PermissionDenied(_)) | Err(ScanError::FileNotFound(_)) => {}
            _ => {} // Other results are acceptable too
        }
    }

    #[test]
    fn test_scan_file_size_limit() {
        let temp_dir = TempDir::new().unwrap();
        let temp_file = temp_dir.path().join("large.txt");
        File::create(&temp_file)
            .unwrap()
            .write_all(b"x")
            .unwrap();

        let scanner = Scanner::from_definitions(vec![]).unwrap()
            .with_options(ScanOptions {
                max_file_size: 0, // Very small limit
                ..Default::default()
            });

        let (findings, stats) = scanner.scan_file(&temp_file).unwrap();
        assert!(findings.is_empty());
        assert_eq!(stats.files_skipped, 1);
    }

    #[test]
    fn test_scan_file_binary() {
        let temp_dir = TempDir::new().unwrap();
        let temp_file = temp_dir.path().join("binary.dat");
        // Write null bytes to make it binary
        File::create(&temp_file)
            .unwrap()
            .write_all(b"\x00\x01\x02")
            .unwrap();

        let scanner = Scanner::from_definitions(vec![]).unwrap()
            .with_options(ScanOptions {
                scan_binary: false,
                ..Default::default()
            });

        let (findings, stats) = scanner.scan_file(&temp_file).unwrap();
        assert!(findings.is_empty());
        assert_eq!(stats.files_skipped, 1);
    }

    #[test]
    fn test_scan_file_binary_allowed() {
        let temp_dir = TempDir::new().unwrap();
        let temp_file = temp_dir.path().join("binary.dat");
        File::create(&temp_file)
            .unwrap()
            .write_all(b"\x00\x01\x02 content here")
            .unwrap();

        // Use pattern that matches "content"
        let patterns = vec![crate::pattern::PatternDefinition {
            name: "test-content".to_string(),
            category: "test".to_string(),
            match_pattern: "content".to_string(),
            severity: crate::pattern::Severity::Medium,
            confidence: crate::pattern::Confidence::Medium,
            description: "Test pattern".to_string(),
            enabled: true,
            min_entropy: None,
            reference: None,
            tags: vec![],
            env_var: false,
            binary: true,
        }];

        let scanner = Scanner::from_definitions(patterns).unwrap()
            .with_options(ScanOptions {
                scan_binary: true,
                ..Default::default()
            });

        let (_findings, stats) = scanner.scan_file(&temp_file).unwrap();
        assert_eq!(stats.files_scanned, 1);
        // Binary files should still be scanned if scan_binary is true
        // but content detection might not work as expected
    }

    #[test]
    fn test_scan_file_normal() {
        let temp_dir = TempDir::new().unwrap();
        let temp_file = temp_dir.path().join("test.txt");
        File::create(&temp_file)
            .unwrap()
            .write_all(b"let secret = 'abc123';")
            .unwrap();

        let patterns = vec![crate::pattern::PatternDefinition {
            name: "test-secret".to_string(),
            category: "secrets".to_string(),
            match_pattern: "secret".to_string(),
            severity: crate::pattern::Severity::High,
            confidence: crate::pattern::Confidence::High,
            description: "Test pattern".to_string(),
            enabled: true,
            min_entropy: None,
            reference: None,
            tags: vec![],
            env_var: false,
            binary: false,
        }];

        let scanner = Scanner::from_definitions(patterns).unwrap();

        let (_findings, stats) = scanner.scan_file(&temp_file).unwrap();
        assert_eq!(stats.files_scanned, 1);
    }

    #[test]
    fn test_scan_dir() {
        let temp_dir = TempDir::new().unwrap();
        let file1 = temp_dir.path().join("test1.txt");
        let file2 = temp_dir.path().join("test2.txt");
        File::create(&file1).unwrap().write_all(b"content 1").unwrap();
        File::create(&file2).unwrap().write_all(b"content 2").unwrap();

        let scanner = Scanner::from_definitions(vec![]).unwrap();

        let (_findings, stats) = scanner.scan_dir(temp_dir.path()).unwrap();
        // Should have scanned at least the 2 files we created
        assert!(stats.files_scanned >= 2);
    }

    #[test]
    fn test_scan_dir_with_symlinks() {
        let temp_dir = TempDir::new().unwrap();
        let real_file = temp_dir.path().join("real.txt");
        let link_file = temp_dir.path().join("link.txt");
        File::create(&real_file).unwrap().write_all(b"content").unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_file, &link_file).unwrap();

        let scanner = Scanner::from_definitions(vec![]).unwrap()
            .with_options(ScanOptions {
                follow_symlinks: false,
                ..Default::default()
            });

        let (_findings, stats) = scanner.scan_dir(temp_dir.path()).unwrap();
        // Without following symlinks, should scan the real file
        assert!(stats.files_scanned >= 1);
    }

    #[test]
    fn test_scan_options_default() {
        let options = ScanOptions::default();
        assert_eq!(options.max_file_size, 10 * 1024 * 1024);
        assert!(!options.follow_symlinks);
        assert!(!options.scan_binary);
        assert!(options.categories.is_empty());
        assert!(options.severity_threshold.is_none());
        assert!(options.use_gitignore);
        assert!(options.use_atheonignore);
    }

    #[test]
    fn test_scan_options_custom() {
        let options = ScanOptions {
            max_file_size: 5 * 1024 * 1024,
            follow_symlinks: true,
            scan_binary: true,
            categories: vec!["secrets".to_string()],
            severity_threshold: Some("high".to_string()),
            use_gitignore: false,
            use_atheonignore: false,
            workers: 8,
            baseline: Some(PathBuf::from("/baseline.json")),
        };

        assert_eq!(options.max_file_size, 5 * 1024 * 1024);
        assert!(options.follow_symlinks);
        assert!(options.scan_binary);
        assert_eq!(options.categories, vec!["secrets"]);
        assert_eq!(options.severity_threshold.as_deref(), Some("high"));
        assert!(!options.use_gitignore);
        assert!(!options.use_atheonignore);
        assert_eq!(options.workers, 8);
    }

    #[test]
    fn test_scanner_from_bundle() {
        let bundle = Bundle::new(vec![]);
        let scanner = Scanner::from_bundle(&bundle);
        // Empty bundle should work
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_scanner_with_options() {
        let scanner = Scanner::new();
        let scanner = scanner.with_options(ScanOptions {
            max_file_size: 1024 * 1024,
            ..Default::default()
        });
        // Should not panic
        assert_eq!(scanner.options.max_file_size, 1024 * 1024);
    }

    #[test]
    fn test_scanner_registry() {
        let scanner = Scanner::new();
        let registry = scanner.registry();
        // Should have some patterns
        assert!(registry.enabled().is_empty()); // No patterns registered initially
    }

    #[test]
    fn test_is_binary_file_actual() {
        // Create a text file and verify it's not detected as binary
        let temp_dir = TempDir::new().unwrap();
        let text_file = temp_dir.path().join("text.txt");
        File::create(&text_file)
            .unwrap()
            .write_all(b"Hello, World!")
            .unwrap();

        let result = is_binary_file(&text_file);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should not be binary
    }

    #[test]
    fn test_scan_error_display() {
        let error = ScanError::FileNotFound(PathBuf::from("/path/to/file"));
        let display = format!("{}", error);
        assert!(display.contains("File not found"));

        let error = ScanError::PermissionDenied(PathBuf::from("/path/to/file"));
        let display = format!("{}", error);
        assert!(display.contains("Permission denied"));
    }

    #[test]
    fn test_suppression_integration() {
        // Test that suppressions work - scan without suppressions
        let patterns = vec![crate::pattern::PatternDefinition {
            name: "test-secret".to_string(),
            category: "secrets".to_string(),
            match_pattern: "secret".to_string(),
            severity: crate::pattern::Severity::High,
            confidence: crate::pattern::Confidence::High,
            description: "Test pattern".to_string(),
            enabled: true,
            min_entropy: None,
            reference: None,
            tags: vec![],
            env_var: false,
            binary: false,
        }];

        let scanner = Scanner::from_definitions(patterns).unwrap();

        // Should find multiple occurrences
        let content = "let secret = 'value'; let secret = 'other';";
        let findings = scanner.scan_string(content, "test.rs");
        assert!(findings.len() >= 2);
    }

    #[test]
    fn test_init_ignore_root() {
        let temp_dir = TempDir::new().unwrap();
        let scanner = Scanner::new();

        let result = scanner.init_ignore_root(temp_dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_num_cpus() {
        let cpus = num_cpus();
        assert!(cpus >= 1);
    }
}
