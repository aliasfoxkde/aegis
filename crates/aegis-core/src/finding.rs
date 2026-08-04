//! Finding and statistics structures
//!
//! Core data structures for scan results.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Location in source code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    /// File path
    pub file: String,
    /// Line number (1-indexed)
    pub line: usize,
    /// Column number (0-indexed)
    pub column: usize,
    /// Line content
    pub content: String,
}

impl Location {
    /// Create a new location
    pub fn new(
        file: impl Into<String>,
        line: usize,
        column: usize,
        content: impl Into<String>,
    ) -> Self {
        Self {
            file: file.into(),
            line,
            column,
            content: content.into(),
        }
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.column)
    }
}

/// The kind of finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// Pattern match finding
    #[default]
    Pattern,
    /// AST-based finding
    Ast,
    /// Clone detection finding
    Clone,
    /// CFG analysis finding
    Cfg,
    /// Entropy-based finding
    Entropy,
    /// Taint analysis finding
    Taint,
}

impl fmt::Display for FindingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindingKind::Pattern => write!(f, "pattern"),
            FindingKind::Ast => write!(f, "ast"),
            FindingKind::Clone => write!(f, "clone"),
            FindingKind::Cfg => write!(f, "cfg"),
            FindingKind::Entropy => write!(f, "entropy"),
            FindingKind::Taint => write!(f, "taint"),
        }
    }
}

/// A finding from a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier
    pub id: String,
    /// Pattern name that triggered
    pub pattern: String,
    /// Category
    pub category: String,
    /// Severity level
    pub severity: String,
    /// Confidence level
    pub confidence: String,
    /// Location in source
    pub location: Location,
    /// Matched content
    pub matched_content: String,
    /// Description
    pub description: String,
    /// Reference URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Tags
    #[serde(default)]
    pub tags: Vec<String>,
    /// Finding kind
    #[serde(default)]
    pub kind: FindingKind,
    /// Fingerprint for deduplication
    pub fingerprint: String,
}

impl Finding {
    /// Create a new finding
    pub fn new(
        pattern: impl Into<String>,
        category: impl Into<String>,
        severity: impl Into<String>,
        confidence: impl Into<String>,
        location: Location,
        matched_content: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let pattern_str = pattern.into();
        let matched_content_str = matched_content.into();
        let fingerprint = format!(
            "{}:{}:{}:{}",
            pattern_str, location.file, location.line, matched_content_str
        );

        Self {
            id: uuid_v4(),
            pattern: pattern_str,
            category: category.into(),
            severity: severity.into(),
            confidence: confidence.into(),
            location,
            matched_content: matched_content_str,
            description: description.into(),
            reference: None,
            tags: Vec::new(),
            kind: FindingKind::Pattern,
            fingerprint,
        }
    }

    /// Set the reference URL
    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.reference = Some(reference.into());
        self
    }

    /// Set the tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Set the finding kind
    pub fn with_kind(mut self, kind: FindingKind) -> Self {
        self.kind = kind;
        self
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} at {}:{}:{}",
            self.severity,
            self.pattern,
            self.location.file,
            self.location.line,
            self.location.column
        )
    }
}

/// Statistics about a scan
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStats {
    /// Number of files scanned
    pub files_scanned: usize,
    /// Number of files skipped
    pub files_skipped: usize,
    /// Total bytes scanned
    pub bytes_scanned: u64,
    /// Number of findings
    pub finding_count: usize,
    /// Number of patterns matched
    pub patterns_matched: usize,
    /// Time spent scanning (milliseconds)
    pub scan_time_ms: u64,
    /// Time spent on I/O (milliseconds)
    pub io_time_ms: u64,
    /// Number of workers used
    pub workers_used: usize,
    /// Files by extension
    pub files_by_extension: std::collections::HashMap<String, usize>,
    /// Findings by severity
    pub findings_by_severity: std::collections::HashMap<String, usize>,
    /// Findings by category
    pub findings_by_category: std::collections::HashMap<String, usize>,
}

impl ScanStats {
    /// Create new empty stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a finding to the stats
    pub fn add_finding(&mut self, finding: &Finding) {
        self.finding_count += 1;
        *self
            .findings_by_severity
            .entry(finding.severity.clone())
            .or_insert(0) += 1;
        *self
            .findings_by_category
            .entry(finding.category.clone())
            .or_insert(0) += 1;
    }

    /// Merge another stats into this one
    pub fn merge(&mut self, other: &ScanStats) {
        self.files_scanned += other.files_scanned;
        self.files_skipped += other.files_skipped;
        self.bytes_scanned += other.bytes_scanned;
        self.finding_count += other.finding_count;
        self.patterns_matched += other.patterns_matched;
        self.scan_time_ms += other.scan_time_ms;
        self.io_time_ms += other.io_time_ms;

        for (ext, count) in &other.files_by_extension {
            *self.files_by_extension.entry(ext.clone()).or_insert(0) += count;
        }

        for (sev, count) in &other.findings_by_severity {
            *self.findings_by_severity.entry(sev.clone()).or_insert(0) += count;
        }

        for (cat, count) in &other.findings_by_category {
            *self.findings_by_category.entry(cat.clone()).or_insert(0) += count;
        }
    }

    /// Calculate files per second
    pub fn files_per_second(&self) -> f64 {
        if self.scan_time_ms == 0 {
            return 0.0;
        }
        self.files_scanned as f64 / (self.scan_time_ms as f64 / 1000.0)
    }

    /// Calculate MB per second
    pub fn mb_per_second(&self) -> f64 {
        if self.scan_time_ms == 0 {
            return 0.0;
        }
        (self.bytes_scanned as f64 / (1024.0 * 1024.0)) / (self.scan_time_ms as f64 / 1000.0)
    }
}

impl fmt::Display for ScanStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Scan Statistics:")?;
        writeln!(f, "  Files scanned: {}", self.files_scanned)?;
        writeln!(f, "  Files skipped: {}", self.files_skipped)?;
        writeln!(
            f,
            "  Bytes scanned: {:.2} MB",
            self.bytes_scanned as f64 / (1024.0 * 1024.0)
        )?;
        writeln!(f, "  Findings: {}", self.finding_count)?;
        writeln!(f, "  Scan time: {:.2}s", self.scan_time_ms as f64 / 1000.0)?;
        writeln!(
            f,
            "  Throughput: {:.2} files/s, {:.2} MB/s",
            self.files_per_second(),
            self.mb_per_second()
        )?;
        Ok(())
    }
}

/// Generate a simple UUID v4
fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:032x}", timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_location() {
        let loc = Location::new("test.rs", 10, 5, "let x = 1;");
        assert_eq!(loc.file, "test.rs");
        assert_eq!(loc.line, 10);
        assert_eq!(loc.column, 5);
    }

    #[test]
    fn test_finding_creation() {
        let loc = Location::new("test.rs", 1, 0, "secret = 'abc'");
        let finding = Finding::new(
            "hardcoded-secret",
            "secrets",
            "high",
            "high",
            loc,
            "abc",
            "Hardcoded secret detected",
        );

        assert_eq!(finding.pattern, "hardcoded-secret");
        assert_eq!(finding.severity, "high");
        assert_eq!(finding.category, "secrets");
    }

    #[test]
    fn test_finding_with_options() {
        let loc = Location::new("test.rs", 1, 0, "secret = 'abc'");
        let finding = Finding::new(
            "hardcoded-secret",
            "secrets",
            "high",
            "high",
            loc,
            "abc",
            "Hardcoded secret detected",
        )
        .with_reference("https://example.com")
        .with_tags(vec!["security".to_string(), "secret".to_string()])
        .with_kind(FindingKind::Entropy);

        assert_eq!(finding.reference, Some("https://example.com".to_string()));
        assert_eq!(finding.tags, vec!["security", "secret"]);
        assert_eq!(finding.kind, FindingKind::Entropy);
    }

    #[test]
    fn test_scan_stats() {
        let mut stats = ScanStats::new();
        stats.files_scanned = 100;
        stats.bytes_scanned = 1024 * 1024;
        stats.scan_time_ms = 1000;

        assert_eq!(stats.files_per_second(), 100.0);
        assert!((stats.mb_per_second() - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_stats_merge() {
        let mut stats1 = ScanStats::new();
        stats1.files_scanned = 10;
        stats1.finding_count = 5;

        let mut stats2 = ScanStats::new();
        stats2.files_scanned = 5;
        stats2.finding_count = 3;

        stats1.merge(&stats2);

        assert_eq!(stats1.files_scanned, 15);
        assert_eq!(stats1.finding_count, 8);
    }
}
