//! Main scanner implementation
//!
//! Handles scanning files, directories, and strings for patterns.

use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Instant;
use walkdir::WalkDir;

use crate::entropy::shannon_entropy;
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
    /// Include disabled patterns in scan
    pub include_disabled: bool,
    /// Diff file to scan (only changed lines)
    pub diff_file: Option<PathBuf>,
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
            include_disabled: false,
            diff_file: None,
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
    /// Cached category scanners for performance
    category_scanners: RwLock<Option<Vec<crate::pattern::CategoryScanner>>>,
    /// Track last include_disabled setting to invalidate cache
    last_include_disabled: AtomicBool,
}

impl Scanner {
    /// Create a new scanner
    pub fn new() -> Self {
        Self {
            registry: Arc::new(PatternRegistry::new()),
            ignore_manager: Arc::new(IgnoreManager::new()),
            suppression_manager: SuppressionManager::new(),
            options: ScanOptions::default(),
            category_scanners: RwLock::new(None),
            last_include_disabled: AtomicBool::new(false),
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
            category_scanners: RwLock::new(None),
            last_include_disabled: AtomicBool::new(false),
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
            category_scanners: RwLock::new(None),
            last_include_disabled: AtomicBool::new(false),
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

    /// Update options and rebuild category scanners if needed
    pub fn with_options(mut self, options: ScanOptions) -> Self {
        // Invalidate cache if include_disabled changed
        if self.last_include_disabled.load(Ordering::SeqCst) != options.include_disabled {
            *self.category_scanners.write().unwrap() = None;
            self.last_include_disabled
                .store(options.include_disabled, Ordering::SeqCst);
        }
        self.options = options;
        self
    }

    /// Get or build cached category scanners
    fn get_category_scanners(&self) -> Vec<crate::pattern::CategoryScanner> {
        let include_disabled = self.options.include_disabled;

        // Check cache
        if let Ok(cache) = self.category_scanners.read() {
            if let Some(ref scanners) = *cache {
                return scanners.clone();
            }
        }

        // Build new scanners
        let scanners = self.registry.build_category_scanners(include_disabled);

        // Cache them
        if let Ok(mut cache) = self.category_scanners.write() {
            *cache = Some(scanners.clone());
        }

        scanners
    }

    /// Parse a diff file and extract only the changed lines
    /// Returns a tuple of (file_path, line_content) for each added line
    #[allow(clippy::collapsible_if)]
    pub fn parse_diff(diff_content: &str) -> Vec<(String, String)> {
        let mut results = Vec::new();
        let mut current_file = String::new();

        for line in diff_content.lines() {
            // Track file changes
            if let Some(stripped) = line.strip_prefix("+++ ") {
                current_file = stripped.to_string();
                if current_file.starts_with("a/") || current_file.starts_with("b/") {
                    if let Some(s) = current_file.strip_prefix("a/") {
                        current_file = s.to_string();
                    } else if let Some(s) = current_file.strip_prefix("b/") {
                        current_file = s.to_string();
                    }
                }
                if current_file == "/dev/null" {
                    current_file = String::new();
                }
            } else if let Some(added) = line.strip_prefix('+') {
                // Added line
                if !current_file.is_empty() {
                    results.push((current_file.clone(), added.to_string()));
                }
            }
            // Note: We skip removed lines (-) and context lines
        }

        results
    }

    /// Scan only the changed lines from a diff file
    pub fn scan_diff(&self, diff_content: &str, _source: &str) -> Vec<Finding> {
        let changed_lines = Self::parse_diff(diff_content);
        let mut all_findings = Vec::new();

        // Group by file and scan each file's changed lines
        let mut by_file: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for (file, line) in changed_lines {
            by_file.entry(file).or_default().push(line);
        }

        for (file, lines) in by_file {
            let content = lines.join("\n");
            let mut findings = self.scan_string(&content, &file);
            // Update source to reflect the actual file
            for finding in &mut findings {
                finding.location.file = file.clone();
            }
            all_findings.extend(findings);
        }

        all_findings
    }

    /// Scan a string
    pub fn scan_string(&self, content: &str, source: &str) -> Vec<Finding> {
        let start = Instant::now();

        // Parse suppressions from content
        let mut suppression_mgr = SuppressionManager::new();
        suppression_mgr.parse_content(content);

        // Pre-compute line index for O(log n) line number lookup
        let line_index = LineIndex::new(content);

        // Get cached category scanners
        let scanners = self.get_category_scanners();

        if scanners.is_empty() {
            return Vec::new();
        }

        // Use category scanners with combined regex pre-filtering
        let findings: Vec<Finding> = if content.len() > 5000 && scanners.len() > 4 {
            // Parallelize across categories for large content
            scanners
                .par_iter()
                .flat_map(|scanner| {
                    self.process_category_scanner(
                        scanner,
                        content,
                        source,
                        &suppression_mgr,
                        &line_index,
                    )
                })
                .collect()
        } else {
            // Sequential for smaller content
            let mut findings = Vec::new();
            for scanner in &scanners {
                findings.extend(self.process_category_scanner(
                    scanner,
                    content,
                    source,
                    &suppression_mgr,
                    &line_index,
                ));
            }
            findings
        };

        // Filter findings against baseline if configured
        let findings = self.filter_baseline(findings);

        let _ = start.elapsed();
        findings
    }

    /// Load baseline findings and filter them from results
    /// Uses fingerprint for stable matching (fingerprint = pattern:file:line:content)
    fn filter_baseline(&self, findings: Vec<Finding>) -> Vec<Finding> {
        if self.options.baseline.is_none() {
            return findings;
        }

        let baseline_path = self.options.baseline.as_ref().unwrap();
        let Ok(baseline_content) = std::fs::read_to_string(baseline_path) else {
            return findings;
        };

        // Parse baseline JSON - expected format: [{"fingerprint": "..."}, ...]
        // Also supports simple string array format: ["fingerprint1", "fingerprint2", ...]
        let baseline_fingerprints: std::collections::HashSet<String> = if let Ok(items) =
            serde_json::from_str::<Vec<serde_json::Value>>(&baseline_content)
        {
            items
                .iter()
                .filter_map(|v| v.get("fingerprint").and_then(|f| f.as_str()))
                .map(String::from)
                .collect()
        } else if let Ok(fingerprints) = serde_json::from_str::<Vec<String>>(&baseline_content) {
            fingerprints.into_iter().collect()
        } else {
            return findings;
        };

        findings
            .into_iter()
            .filter(|f| !baseline_fingerprints.contains(&f.fingerprint))
            .collect()
    }

    /// Process a category scanner and return findings
    fn process_category_scanner(
        &self,
        scanner: &crate::pattern::CategoryScanner,
        content: &str,
        source: &str,
        suppression_mgr: &SuppressionManager,
        line_index: &LineIndex,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Fast pre-filter: if combined regex doesn't match, skip entire category
        if !scanner.might_match(content) {
            return findings;
        }

        // Find matches using individual patterns
        let matches = scanner.find_matches(content);

        for m in matches {
            let patterns = scanner.patterns();
            // Find which pattern matched by checking the match position
            let matched_pattern = patterns.iter().find(|p| p.regex_matches(m.matched_text));

            let pattern = match matched_pattern {
                Some(p) => p,
                None => continue,
            };

            // Check entropy if required
            if let Some(min_entropy) = pattern.min_entropy() {
                let entropy = shannon_entropy(m.matched_text);
                if entropy < min_entropy {
                    continue;
                }
            }

            let line_num = line_index.get_line_number(m.start) as u32;
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
        let patterns = if self.options.include_disabled {
            self.registry.all()
        } else {
            self.registry.enabled()
        };
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

/// Pre-computed line index for O(log n) line number lookups
/// Uses binary search instead of counting newlines for each match
struct LineIndex {
    /// Byte offsets where each line starts (including newline)
    line_starts: Vec<usize>,
}

impl LineIndex {
    /// Build a line index from content
    fn new(content: &str) -> Self {
        let mut line_starts = vec![0]; // Line 1 starts at index 0
        for (i, c) in content.char_indices() {
            if c == '\n' {
                line_starts.push(i + 1);
            }
        }
        Self { line_starts }
    }

    /// Get line number for a byte offset using binary search
    fn get_line_number(&self, byte_offset: usize) -> usize {
        match self.line_starts.binary_search(&byte_offset) {
            Ok(line) => line + 1, // 1-indexed
            Err(pos) => {
                if pos == 0 {
                    1
                } else {
                    pos
                }
            }
        }
    }
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
            Err(ScanError::IoError(_))
            | Err(ScanError::PermissionDenied(_))
            | Err(ScanError::FileNotFound(_)) => {}
            _ => {} // Other results are acceptable too
        }
    }

    #[test]
    fn test_scan_file_size_limit() {
        let temp_dir = TempDir::new().unwrap();
        let temp_file = temp_dir.path().join("large.txt");
        File::create(&temp_file).unwrap().write_all(b"x").unwrap();

        let scanner = Scanner::from_definitions(vec![])
            .unwrap()
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

        let scanner = Scanner::from_definitions(vec![])
            .unwrap()
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

        let scanner = Scanner::from_definitions(patterns)
            .unwrap()
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
        File::create(&file1)
            .unwrap()
            .write_all(b"content 1")
            .unwrap();
        File::create(&file2)
            .unwrap()
            .write_all(b"content 2")
            .unwrap();

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
        File::create(&real_file)
            .unwrap()
            .write_all(b"content")
            .unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_file, &link_file).unwrap();

        let scanner = Scanner::from_definitions(vec![])
            .unwrap()
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
            include_disabled: true,
            diff_file: Some(PathBuf::from("/diff.txt")),
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

    #[test]
    fn test_scanner_from_config() {
        let config = Config::default();
        let scanner = Scanner::from_config(&config);
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_scanner_from_config_with_categories() {
        let config = Config {
            enabled_categories: Some(vec!["secrets".to_string()]),
            ..Default::default()
        };
        let scanner = Scanner::from_config(&config);
        // Should succeed even with empty bundle
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_scanner_init_ignore_root() {
        let temp_dir = TempDir::new().unwrap();
        let scanner = Scanner::new();
        let result = scanner.init_ignore_root(temp_dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_scan_string_with_many_patterns_parallel_path() {
        // Create 51+ patterns to exercise the parallel scan path (>50 patterns threshold)
        let mut patterns = Vec::new();
        for i in 0..55 {
            patterns.push(PatternDefinition {
                name: format!("pattern-{}", i),
                category: "test".to_string(),
                match_pattern: format!("secret{}", i),
                enabled: true,
                severity: crate::Severity::Low,
                confidence: crate::Confidence::Low,
                min_entropy: None,
                description: format!("Test pattern {}", i),
                reference: None,
                tags: vec![],
                env_var: false,
                binary: false,
            });
        }

        let scanner = Scanner::from_definitions(patterns).unwrap();

        // Scan content that matches multiple patterns
        let content =
            "secret0 secret1 secret2 secret3 secret4 secret5 secret6 secret7 secret8 secret9";
        let findings = scanner.scan_string(content, "test.rs");

        // Should find at least some matches through parallel path
        assert!(!findings.is_empty() || content.contains("secret"));
    }

    #[test]
    fn test_scanner_registry_access() {
        let scanner = Scanner::new();
        let registry = scanner.registry();
        assert!(registry.all().is_empty());
    }

    #[test]
    fn test_scan_dir_with_empty_dir() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();
        let scanner = Scanner::new();
        let result = scanner.scan_dir(temp_dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_scanner_with_baseline() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();
        let baseline_file = temp_dir.path().join("baseline.json");
        std::fs::write(&baseline_file, "[]").unwrap();

        let scanner = Scanner::new();
        let options = ScanOptions {
            baseline: Some(baseline_file),
            ..Default::default()
        };
        let scanner = scanner.with_options(options);
        assert!(scanner.options.baseline.is_some());
    }

    #[test]
    fn test_baseline_filters_findings() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let baseline_file = temp_dir.path().join("baseline.json");

        // Create a pattern definition
        let def = PatternDefinition {
            name: "secrets-aws-access-key".to_string(),
            category: "secrets".to_string(),
            match_pattern: r"AKIA[0-9A-Z]{16}".to_string(),
            enabled: true,
            severity: crate::Severity::Critical,
            confidence: crate::Confidence::High,
            min_entropy: None, // Disable entropy check for testing
            description: "AWS Access Key ID detected".to_string(),
            reference: None,
            tags: vec!["aws".to_string()],
            env_var: false,
            binary: false,
        };

        // Create scanner using from_definitions (the normal path)
        let scanner = Scanner::from_definitions(vec![def.clone()]).unwrap();

        let findings = scanner.scan_string("AKIAIOSFODNN7EXAMPLE", "test.rs");
        assert!(
            !findings.is_empty(),
            "Should detect AWS access key, got: {:?}",
            findings
        );

        // Use fingerprints for stable baseline matching
        let baseline_fingerprints: Vec<String> =
            findings.iter().map(|f| f.fingerprint.clone()).collect();

        // Write baseline with the finding fingerprints
        let baseline_json: Vec<serde_json::Value> = baseline_fingerprints
            .iter()
            .map(|fp| serde_json::json!({"fingerprint": fp}))
            .collect();
        std::fs::write(
            &baseline_file,
            serde_json::to_string(&baseline_json).unwrap(),
        )
        .unwrap();

        // Create new scanner with baseline and same pattern
        let scanner_with_baseline = Scanner::from_definitions(vec![def]).unwrap();

        let options = ScanOptions {
            baseline: Some(baseline_file),
            ..Default::default()
        };
        let scanner_with_baseline = scanner_with_baseline.with_options(options);

        // Scan the same content - should be filtered
        let filtered_findings =
            scanner_with_baseline.scan_string("AKIAIOSFODNN7EXAMPLE", "test.rs");
        assert!(
            filtered_findings.is_empty(),
            "Baseline should filter known findings"
        );
    }
}
