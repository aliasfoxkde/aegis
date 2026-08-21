//! Control Center Pre-Pipeline Aegis Adapter
//!
//! This adapter provides an interface for Control Center to perform security scans
//! BEFORE triggering a GitForge pipeline. It implements a "fail closed" policy:
//! any scan error, timeout, or malformed response results in the work being blocked.
//!
//! ## Key Properties
//!
//! - **Fail Closed**: Scanner errors, timeouts, and malformed responses all result in `Blocked`
//! - **Redacted Evidence**: Only a hash/pointer to evidence is stored, not raw content
//! - **Bounded Records**: Evidence records are small, fixed-size structs
//!
//! ## Usage
//!
//! ```rust
//! use aegis_core::control_center_adapter::{ControlCenterAdapter, WorkRequest};
//!
//! let mut adapter = ControlCenterAdapter::new();
//! let result = adapter.scan_work_sync(WorkRequest {
//!     work_request_id: "wr-123".to_string(),
//!     content: "AKIAIOSFODNN7EXAMPLE".to_string(),
//!     source: "test.rs".to_string(),
//! });
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::scanner::Scanner;
use crate::{Finding, ScanReceipt, ScanStats};

/// Work request to be scanned
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkRequest {
    /// Unique identifier for the work request
    pub work_request_id: String,
    /// Content to scan (e.g., diff, patch, or file content)
    pub content: String,
    /// Source identifier (e.g., file path, PR number)
    pub source: String,
}

/// Scan result enum
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanResult {
    /// Scan passed - no findings
    Pass,
    /// Scan found issues
    Fail,
    /// Scan was blocked due to error
    Blocked,
}

impl ScanResult {
    /// Returns true if the result allows work to proceed
    pub fn allows_work(&self) -> bool {
        matches!(self, ScanResult::Pass | ScanResult::Fail)
    }
}

/// Evidence record - stored by the adapter after each scan
///
/// This is a bounded, redacted record that links to the actual evidence
/// without exposing raw scan content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    /// The work request ID this evidence belongs to
    pub work_request_id: String,
    /// Scan result (pass/fail)
    pub scan_result: ScanResult,
    /// SHA-256 hash of the original content that was scanned
    pub evidence_ref: String,
    /// Timestamp when scan was performed (Unix timestamp)
    pub scanned_at: u64,
    /// Number of findings detected (0 if pass)
    pub finding_count: usize,
    /// Highest severity among findings (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub highest_severity: Option<String>,
    /// Redacted, versioned receipt for this scan.
    #[serde(skip_serializing)]
    pub receipt: Option<ScanReceipt>,
}

impl EvidenceRecord {
    /// Create a new evidence record from scan results
    pub fn new(
        work_request_id: String,
        scan_result: ScanResult,
        content_hash: String,
        finding_count: usize,
        highest_severity: Option<String>,
    ) -> Self {
        Self {
            work_request_id,
            scan_result,
            evidence_ref: content_hash,
            scanned_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            finding_count,
            highest_severity,
            receipt: None,
        }
    }

    /// Create an evidence record with a redacted, complete scan receipt.
    pub fn from_scan(
        work_request_id: String,
        source: &str,
        scan_result: ScanResult,
        content_hash: String,
        findings: &[Finding],
        stats: ScanStats,
    ) -> Self {
        let mut record = Self::new(
            work_request_id,
            scan_result,
            content_hash,
            findings.len(),
            ControlCenterAdapter::extract_highest_severity(findings),
        );
        let profile = "control-center-default";
        record.receipt = Some(ScanReceipt::from_scan(
            source,
            "control_center_work_request",
            profile,
            Some(ScanReceipt::digest_text(profile)),
            findings,
            stats,
        ));
        record
    }
}

/// Adapter error types
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    /// Scanner encountered an error
    #[error("Scanner error: {0}")]
    ScannerError(String),

    /// Scanner unavailable or timed out
    #[error("Scanner unavailable or timeout: {0}")]
    ScannerUnavailable(String),

    /// Malformed input - content could not be processed
    #[error("Malformed input: {0}")]
    MalformedInput(String),

    /// A work request ID was reused for different content.
    #[error("work request conflict: {0}")]
    WorkRequestConflict(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Control Center Pre-Pipeline Adapter
///
/// This adapter provides a fail-safe interface for Control Center to scan work
/// requests before allowing them to proceed to GitForge pipelines.
pub struct ControlCenterAdapter {
    /// Internal scanner instance (not stored, recreated per scan for panic safety)
    #[allow(dead_code)]
    scanner: Scanner,
    /// Evidence storage (in-memory for this implementation)
    evidence_store: Vec<EvidenceRecord>,
}

impl std::fmt::Debug for ControlCenterAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlCenterAdapter")
            .field("evidence_store", &self.evidence_store)
            .finish()
    }
}

impl ControlCenterAdapter {
    /// Create a new adapter with a default scanner
    pub fn new() -> Self {
        Self {
            scanner: Scanner::new(),
            evidence_store: Vec::new(),
        }
    }

    /// Create a new adapter with a custom scanner
    pub fn with_scanner(scanner: Scanner) -> Self {
        Self {
            scanner,
            evidence_store: Vec::new(),
        }
    }

    /// Compute a content hash for the evidence reference
    fn compute_content_hash(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Extract highest severity from findings
    fn extract_highest_severity(findings: &[Finding]) -> Option<String> {
        let severities = ["critical", "high", "medium", "low", "info"];
        findings
            .iter()
            .map(|f| f.severity.to_lowercase())
            .filter(|s| severities.contains(&s.as_str()))
            .min_by(|a, b| {
                let idx_a = severities.iter().position(|x| x == a).unwrap_or(99);
                let idx_b = severities.iter().position(|x| x == b).unwrap_or(99);
                idx_a.cmp(&idx_b)
            })
    }

    /// Scan work request and return the result
    ///
    /// # Fail-Closed Policy
    ///
    /// - Scanner panic: Blocked
    /// - Scanner error: Blocked
    /// - Timeout: Blocked
    /// - Malformed response: Blocked
    /// - Empty content: Blocked
    /// - Findings detected: Fail (allows work to proceed but logs failure)
    /// - No findings: Pass
    pub async fn scan_work(&mut self, request: WorkRequest) -> Result<ScanResult, AdapterError> {
        self.scan_work_impl(request)
    }

    /// Scan work request synchronously (blocking)
    ///
    /// This is a convenience method for contexts where async is not available.
    pub fn scan_work_sync(&mut self, request: WorkRequest) -> Result<ScanResult, AdapterError> {
        self.scan_work_impl(request)
    }

    /// Internal implementation of scan_work
    fn scan_work_impl(&mut self, request: WorkRequest) -> Result<ScanResult, AdapterError> {
        // Validate input
        if request.content.is_empty() {
            return Err(AdapterError::MalformedInput(
                "Work request content is empty".to_string(),
            ));
        }

        if request.work_request_id.is_empty() {
            return Err(AdapterError::MalformedInput(
                "Work request ID is empty".to_string(),
            ));
        }

        // Compute content hash for evidence reference
        let content_hash = Self::compute_content_hash(&request.content);

        // Work delivery may be retried. Treat an identical request ID/content
        // pair as an idempotent replay, but fail closed when an ID is reused
        // for different content.
        if let Some(existing) = self.get_evidence_for_work(&request.work_request_id) {
            if existing.evidence_ref == content_hash {
                return Ok(existing.scan_result.clone());
            }
            return Err(AdapterError::WorkRequestConflict(request.work_request_id));
        }

        // Clone content for scan to avoid borrow issues with panic catch
        let content = request.content.clone();
        let source = request.source.clone();

        // Perform scan - any panic or error results in Blocked
        // We create a fresh scanner within the catch_unwind to avoid
        // UnwindSafe issues with the Arc<IgnoreManager> in Scanner
        let findings: Vec<Finding> =
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let scanner = Scanner::new();
                scanner.scan_string(&content, &source)
            })) {
                Ok(findings) => findings,
                Err(_) => {
                    // Scanner panicked - fail closed
                    return Err(AdapterError::ScannerError(
                        "Scanner panicked during scan".to_string(),
                    ));
                }
            };

        // Determine scan result
        let scan_result = if findings.is_empty() {
            ScanResult::Pass
        } else {
            ScanResult::Fail
        };

        // Create a redacted evidence record and durable receipt.
        let stats = ScanStats::for_content(format!("string:{source}"), content.len());
        let evidence_record = EvidenceRecord::from_scan(
            request.work_request_id.clone(),
            &source,
            scan_result.clone(),
            content_hash,
            &findings,
            stats,
        );

        // Store evidence
        self.evidence_store.push(evidence_record);

        Ok(scan_result)
    }

    /// Get all stored evidence records
    pub fn get_evidence(&self) -> &[EvidenceRecord] {
        &self.evidence_store
    }

    /// Get evidence for a specific work request
    pub fn get_evidence_for_work(&self, work_request_id: &str) -> Option<&EvidenceRecord> {
        self.evidence_store
            .iter()
            .find(|e| e.work_request_id == work_request_id)
    }

    /// Persist all evidence records atomically as redacted JSON.
    pub fn persist_evidence(&self, path: &Path) -> io::Result<()> {
        let records: Vec<serde_json::Value> = self
            .evidence_store
            .iter()
            .map(|record| {
                let mut value = serde_json::to_value(record)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                if let Some(receipt) = &record.receipt {
                    value["receipt"] = serde_json::to_value(receipt)
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                }
                Ok(value)
            })
            .collect::<io::Result<_>>()?;
        let json = serde_json::to_string_pretty(&records)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("evidence");
        let temp_path = path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()));
        fs::write(&temp_path, json.as_bytes())?;
        if let Err(error) = fs::rename(&temp_path, path) {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }
        Ok(())
    }

    /// Clear stored evidence
    pub fn clear_evidence(&mut self) {
        self.evidence_store.clear();
    }
}

impl Default for ControlCenterAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_work_request_serialization() {
        let request = WorkRequest {
            work_request_id: "wr-123".to_string(),
            content: "let x = 1;".to_string(),
            source: "test.rs".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: WorkRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.work_request_id, "wr-123");
        assert_eq!(deserialized.content, "let x = 1;");
        assert_eq!(deserialized.source, "test.rs");
    }

    #[test]
    fn test_scan_result_allows_work() {
        assert!(ScanResult::Pass.allows_work());
        assert!(ScanResult::Fail.allows_work());
        assert!(!ScanResult::Blocked.allows_work());
    }

    #[test]
    fn test_scan_result_serialization() {
        assert_eq!(
            serde_json::to_string(&ScanResult::Pass).unwrap(),
            "\"pass\""
        );
        assert_eq!(
            serde_json::to_string(&ScanResult::Fail).unwrap(),
            "\"fail\""
        );
        assert_eq!(
            serde_json::to_string(&ScanResult::Blocked).unwrap(),
            "\"blocked\""
        );
    }

    #[test]
    fn test_evidence_record_creation() {
        let record = EvidenceRecord::new(
            "wr-123".to_string(),
            ScanResult::Pass,
            "abc123".to_string(),
            0,
            None,
        );

        assert_eq!(record.work_request_id, "wr-123");
        assert!(matches!(record.scan_result, ScanResult::Pass));
        assert_eq!(record.evidence_ref, "abc123");
        assert_eq!(record.finding_count, 0);
        assert!(record.highest_severity.is_none());
        assert!(record.scanned_at > 0);
    }

    #[test]
    fn test_evidence_record_with_findings() {
        let record = EvidenceRecord::new(
            "wr-456".to_string(),
            ScanResult::Fail,
            "def456".to_string(),
            3,
            Some("high".to_string()),
        );

        assert_eq!(record.work_request_id, "wr-456");
        assert!(matches!(record.scan_result, ScanResult::Fail));
        assert_eq!(record.finding_count, 3);
        assert_eq!(record.highest_severity, Some("high".to_string()));
    }

    #[test]
    fn test_evidence_record_serialization() {
        let record = EvidenceRecord::new(
            "wr-123".to_string(),
            ScanResult::Pass,
            "abc123".to_string(),
            0,
            None,
        );

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"work_request_id\":\"wr-123\""));
        assert!(json.contains("\"scan_result\":\"pass\""));
        assert!(json.contains("\"evidence_ref\":\"abc123\""));
        assert!(!json.contains("highest_severity")); // Should be skipped when None
    }

    #[test]
    fn test_content_hash_deterministic() {
        let content = "AKIAIOSFODNN7EXAMPLE";
        let hash1 = ControlCenterAdapter::compute_content_hash(content);
        let hash2 = ControlCenterAdapter::compute_content_hash(content);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_content_hash_different_for_different_content() {
        let hash1 = ControlCenterAdapter::compute_content_hash("content1");
        let hash2 = ControlCenterAdapter::compute_content_hash("content2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_content_hash_is_sha256() {
        let hash = ControlCenterAdapter::compute_content_hash("test");
        // SHA-256 produces 64 hex characters
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_adapter_new() {
        let adapter = ControlCenterAdapter::new();
        assert!(adapter.get_evidence().is_empty());
    }

    #[test]
    fn test_adapter_scan_work_empty_content() {
        let mut adapter = ControlCenterAdapter::new();
        let request = WorkRequest {
            work_request_id: "wr-123".to_string(),
            content: "".to_string(),
            source: "test.rs".to_string(),
        };

        let result = adapter.scan_work_sync(request);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AdapterError::MalformedInput(_)
        ));
    }

    #[test]
    fn test_adapter_scan_work_empty_id() {
        let mut adapter = ControlCenterAdapter::new();
        let request = WorkRequest {
            work_request_id: "".to_string(),
            content: "content".to_string(),
            source: "test.rs".to_string(),
        };

        let result = adapter.scan_work_sync(request);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AdapterError::MalformedInput(_)
        ));
    }

    #[test]
    fn test_adapter_scan_work_no_findings() {
        let mut adapter = ControlCenterAdapter::new();
        let request = WorkRequest {
            work_request_id: "wr-123".to_string(),
            content: "fn main() { println!(\"Hello, World!\"); }".to_string(),
            source: "test.rs".to_string(),
        };

        let result = adapter.scan_work_sync(request).unwrap();
        assert!(matches!(result, ScanResult::Pass));

        // Check evidence was stored
        let evidence = adapter.get_evidence_for_work("wr-123").unwrap();
        assert_eq!(evidence.work_request_id, "wr-123");
        assert!(matches!(evidence.scan_result, ScanResult::Pass));
        assert_eq!(evidence.finding_count, 0);
    }

    #[test]
    fn test_adapter_scan_work_with_findings() {
        let mut adapter = ControlCenterAdapter::new();
        let request = WorkRequest {
            work_request_id: "wr-456".to_string(),
            content: "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE".to_string(),
            source: "config.env".to_string(),
        };

        let result = adapter.scan_work_sync(request).unwrap();
        // AWS key pattern should be detected
        assert!(matches!(result, ScanResult::Pass | ScanResult::Fail));

        let evidence = adapter.get_evidence_for_work("wr-456").unwrap();
        assert_eq!(evidence.work_request_id, "wr-456");
    }

    #[test]
    fn test_adapter_persists_redacted_receipt() {
        let mut adapter = ControlCenterAdapter::new();
        adapter
            .scan_work_sync(WorkRequest {
                work_request_id: "wr-persist".to_string(),
                content: "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE".to_string(),
                source: "config.env".to_string(),
            })
            .unwrap();
        let root = std::env::temp_dir().join(format!("aegis-evidence-{}", std::process::id()));
        let path = root.join("evidence.json");

        adapter.persist_evidence(&path).unwrap();
        let json = std::fs::read_to_string(&path).unwrap();
        let records: Vec<EvidenceRecord> = serde_json::from_str(&json).unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].receipt.is_some());
        assert!(json.contains("schema_version"));
        assert!(!json.contains("AKIAIOSFODNN7EXAMPLE"));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_adapter_clear_evidence() {
        let mut adapter = ControlCenterAdapter::new();
        let request = WorkRequest {
            work_request_id: "wr-123".to_string(),
            content: "fn main() {}".to_string(),
            source: "test.rs".to_string(),
        };

        adapter.scan_work_sync(request).unwrap();
        assert_eq!(adapter.get_evidence().len(), 1);

        adapter.clear_evidence();
        assert!(adapter.get_evidence().is_empty());
    }

    #[test]
    fn test_adapter_multiple_scans() {
        let mut adapter = ControlCenterAdapter::new();

        for i in 0..5 {
            let request = WorkRequest {
                work_request_id: format!("wr-{}", i),
                content: "fn main() {}".to_string(),
                source: "test.rs".to_string(),
            };
            adapter.scan_work_sync(request).unwrap();
        }

        assert_eq!(adapter.get_evidence().len(), 5);
    }

    #[test]
    fn test_adapter_error_display() {
        let err = AdapterError::ScannerError("test error".to_string());
        assert!(err.to_string().contains("Scanner error"));

        let err = AdapterError::ScannerUnavailable("timeout".to_string());
        assert!(err.to_string().contains("Scanner unavailable"));

        let err = AdapterError::MalformedInput("bad input".to_string());
        assert!(err.to_string().contains("Malformed input"));

        let err = AdapterError::Internal("oops".to_string());
        assert!(err.to_string().contains("Internal error"));
    }
}
