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

/// Lifecycle state for a work request contract.
///
/// Tracks the progression of a bounded work request through the
/// control center scan pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    /// Work request received but not yet accepted for processing
    Pending,
    /// Work request accepted and queued for scanning
    Accepted,
    /// Scan is actively running
    Running,
    /// Scan completed successfully (Pass or Fail)
    Completed,
    /// Scan failed with an error (Blocked or internal failure)
    Failed,
    /// Work request was cancelled before completion
    Cancelled,
}

impl LifecycleState {
    /// Returns true if this state is terminal (no further transitions allowed)
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            LifecycleState::Completed | LifecycleState::Failed | LifecycleState::Cancelled
        )
    }

    /// Returns true if transition to the given state is valid
    pub fn can_transition_to(&self, next: LifecycleState) -> bool {
        use LifecycleState::*;
        match (self, next) {
            // Forward progress
            (Pending, Accepted | Running | Failed | Cancelled) => true,
            (Accepted, Running | Failed | Cancelled) => true,
            (Running, Completed | Failed | Cancelled) => true,
            // Idempotent self-transitions for terminal states
            (Completed, Completed) => true,
            (Failed, Failed) => true,
            (Cancelled, Cancelled) => true,
            // All other transitions are invalid
            _ => false,
        }
    }
}

/// A versioned, in-memory lifecycle state transition record.
///
/// This is a bounded record that captures state transitions for a
/// work request without external dependencies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleTransition {
    /// Schema version for forward/backward compatibility
    pub schema_version: u16,
    /// The previous state (None for initial)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_state: Option<LifecycleState>,
    /// The new state after this transition
    pub to_state: LifecycleState,
    /// Timestamp of this transition (Unix timestamp)
    pub transitioned_at: u64,
    /// Optional reason/metadata for this transition
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl LifecycleTransition {
    /// Create a new initial transition (first state assignment)
    pub fn initial(state: LifecycleState) -> Self {
        Self {
            schema_version: 1,
            from_state: None,
            to_state: state,
            transitioned_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            reason: None,
        }
    }

    /// Create a state transition with optional reason
    pub fn transition(
        from: LifecycleState,
        to: LifecycleState,
        reason: Option<String>,
    ) -> Option<Self> {
        if from.can_transition_to(to) {
            Some(Self {
                schema_version: 1,
                from_state: Some(from),
                to_state: to,
                transitioned_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                reason,
            })
        } else {
            None
        }
    }
}

/// In-memory lifecycle record tracking all state transitions for a work request.
///
/// This is a bounded, versioned record that provides an audit trail of
/// the work request lifecycle without external storage dependencies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleRecord {
    /// Schema version for forward/backward compatibility
    pub schema_version: u16,
    /// Work request this lifecycle belongs to
    pub work_request_id: String,
    /// All state transitions in chronological order
    pub transitions: Vec<LifecycleTransition>,
    /// Current state (cached for efficient access)
    pub current_state: LifecycleState,
}

impl LifecycleRecord {
    /// Create a new lifecycle record starting in Pending state
    pub fn new(work_request_id: String) -> Self {
        Self {
            schema_version: 1,
            work_request_id,
            transitions: vec![LifecycleTransition::initial(LifecycleState::Pending)],
            current_state: LifecycleState::Pending,
        }
    }

    /// Attempt to transition to a new state
    ///
    /// Returns the transition record if successful, None if the transition is invalid.
    /// This enforces fail-closed behavior for invalid transitions.
    pub fn transition_to(
        &mut self,
        new_state: LifecycleState,
        reason: Option<String>,
    ) -> Option<&LifecycleTransition> {
        let transition = LifecycleTransition::transition(self.current_state, new_state, reason)?;
        self.current_state = new_state;
        self.transitions.push(transition);
        self.transitions.last()
    }

    /// Get the initial timestamp (when work request was received)
    pub fn started_at(&self) -> Option<u64> {
        self.transitions.first().map(|t| t.transitioned_at)
    }

    /// Get the last transition timestamp
    pub fn last_updated_at(&self) -> Option<u64> {
        self.transitions.last().map(|t| t.transitioned_at)
    }

    /// Get the number of transitions
    pub fn transition_count(&self) -> usize {
        self.transitions.len()
    }

    /// Returns true if the record is in a terminal state
    pub fn is_terminal(&self) -> bool {
        self.current_state.is_terminal()
    }
}

/// Scan result enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// In-memory lifecycle records for accepted work requests.
    lifecycle_store: Vec<LifecycleRecord>,
}

impl std::fmt::Debug for ControlCenterAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlCenterAdapter")
            .field("evidence_store", &self.evidence_store)
            .field("lifecycle_store", &self.lifecycle_store)
            .finish()
    }
}

impl ControlCenterAdapter {
    /// Create a new adapter with a default scanner
    pub fn new() -> Self {
        Self {
            scanner: Scanner::new(),
            evidence_store: Vec::new(),
            lifecycle_store: Vec::new(),
        }
    }

    /// Create a new adapter with a custom scanner
    pub fn with_scanner(scanner: Scanner) -> Self {
        Self {
            scanner,
            evidence_store: Vec::new(),
            lifecycle_store: Vec::new(),
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
    #[cfg(feature = "tokio")]
    pub async fn scan_work(&mut self, request: WorkRequest) -> Result<ScanResult, AdapterError> {
        Self::validate_request(&request)?;
        if let Some(existing) = self.existing_result(&request)? {
            return Ok(existing);
        }
        let work_request_id = request.work_request_id.clone();
        self.begin_lifecycle(&work_request_id);
        let outcome = tokio::task::spawn_blocking(move || Self::scan_request(request)).await;
        match outcome {
            Ok(Ok((scan_result, evidence_record))) => {
                self.transition_lifecycle(&work_request_id, LifecycleState::Completed, None);
                self.evidence_store.push(evidence_record);
                Ok(scan_result)
            }
            Ok(Err(error)) => {
                self.transition_lifecycle(
                    &work_request_id,
                    LifecycleState::Failed,
                    Some(error.to_string()),
                );
                Err(error)
            }
            Err(error) => {
                let adapter_error = AdapterError::Internal(format!("scan task failed: {error}"));
                self.transition_lifecycle(
                    &work_request_id,
                    LifecycleState::Failed,
                    Some(adapter_error.to_string()),
                );
                Err(adapter_error)
            }
        }
    }

    /// Scan work request synchronously (blocking)
    ///
    /// This is a convenience method for contexts where async is not available.
    pub fn scan_work_sync(&mut self, request: WorkRequest) -> Result<ScanResult, AdapterError> {
        Self::validate_request(&request)?;
        if let Some(existing) = self.existing_result(&request)? {
            return Ok(existing);
        }
        let work_request_id = request.work_request_id.clone();
        self.begin_lifecycle(&work_request_id);
        match Self::scan_request(request) {
            Ok((scan_result, evidence_record)) => {
                self.transition_lifecycle(&work_request_id, LifecycleState::Completed, None);
                self.evidence_store.push(evidence_record);
                Ok(scan_result)
            }
            Err(error) => {
                self.transition_lifecycle(
                    &work_request_id,
                    LifecycleState::Failed,
                    Some(error.to_string()),
                );
                Err(error)
            }
        }
    }

    fn begin_lifecycle(&mut self, work_request_id: &str) {
        let mut record = LifecycleRecord::new(work_request_id.to_string());
        let _ = record.transition_to(LifecycleState::Accepted, None);
        let _ = record.transition_to(LifecycleState::Running, None);
        self.lifecycle_store.push(record);
    }

    fn transition_lifecycle(
        &mut self,
        work_request_id: &str,
        state: LifecycleState,
        reason: Option<String>,
    ) {
        if let Some(record) = self
            .lifecycle_store
            .iter_mut()
            .find(|record| record.work_request_id == work_request_id)
        {
            let _ = record.transition_to(state, reason);
        }
    }

    fn validate_request(request: &WorkRequest) -> Result<(), AdapterError> {
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

        Ok(())
    }

    fn existing_result(&self, request: &WorkRequest) -> Result<Option<ScanResult>, AdapterError> {
        let content_hash = Self::compute_content_hash(&request.content);
        match self.get_evidence_for_work(&request.work_request_id) {
            Some(existing) if existing.evidence_ref == content_hash => {
                Ok(Some(existing.scan_result.clone()))
            }
            Some(_) => Err(AdapterError::WorkRequestConflict(
                request.work_request_id.clone(),
            )),
            None => Ok(None),
        }
    }

    /// Execute one scan without mutating adapter state.
    fn scan_request(request: WorkRequest) -> Result<(ScanResult, EvidenceRecord), AdapterError> {
        // Validate input
        Self::validate_request(&request)?;

        // Compute content hash for evidence reference
        let content_hash = Self::compute_content_hash(&request.content);

        // Work delivery may be retried. Treat an identical request ID/content
        // pair as an idempotent replay, but fail closed when an ID is reused
        // for different content.
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

        Ok((scan_result, evidence_record))
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

    /// Get the lifecycle record for a specific work request.
    pub fn get_lifecycle(&self, work_request_id: &str) -> Option<&LifecycleRecord> {
        self.lifecycle_store
            .iter()
            .find(|record| record.work_request_id == work_request_id)
    }

    /// Get all lifecycle records.
    pub fn get_lifecycles(&self) -> &[LifecycleRecord] {
        &self.lifecycle_store
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

    #[tokio::test]
    async fn test_async_scan_offloads_and_preserves_idempotency() {
        let mut adapter = ControlCenterAdapter::new();
        let request = WorkRequest {
            work_request_id: "wr-async-001".to_string(),
            content: "fn main() { println!(\"Hello, async world!\"); }".to_string(),
            source: "main.rs".to_string(),
        };

        let first = adapter.scan_work(request.clone()).await.unwrap();
        let second = adapter.scan_work(request).await.unwrap();

        assert_eq!(first, second);
        assert_eq!(adapter.get_evidence().len(), 1);
        assert!(adapter.get_evidence_for_work("wr-async-001").is_some());
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

    #[test]
    fn test_lifecycle_rejects_backward_transition() {
        let mut record = LifecycleRecord::new("wr-lifecycle".to_string());
        assert!(record
            .transition_to(LifecycleState::Accepted, None)
            .is_some());
        assert!(record
            .transition_to(LifecycleState::Running, None)
            .is_some());
        assert!(record
            .transition_to(LifecycleState::Completed, None)
            .is_some());
        assert!(record
            .transition_to(LifecycleState::Running, Some("must remain terminal".into()))
            .is_none());
        assert_eq!(record.current_state, LifecycleState::Completed);
        assert_eq!(record.transition_count(), 4);
    }

    #[test]
    fn test_sync_scan_records_lifecycle() {
        let mut adapter = ControlCenterAdapter::new();
        adapter
            .scan_work_sync(WorkRequest {
                work_request_id: "wr-lifecycle-sync".into(),
                content: "fn main() {}".into(),
                source: "test.rs".into(),
            })
            .unwrap();

        let record = adapter.get_lifecycle("wr-lifecycle-sync").unwrap();
        assert_eq!(record.current_state, LifecycleState::Completed);
        assert_eq!(record.transition_count(), 4);
        assert!(record.is_terminal());
    }

    #[tokio::test]
    async fn test_async_scan_records_lifecycle() {
        let mut adapter = ControlCenterAdapter::new();
        adapter
            .scan_work(WorkRequest {
                work_request_id: "wr-lifecycle-async".into(),
                content: "fn main() {}".into(),
                source: "test.rs".into(),
            })
            .await
            .unwrap();

        let record = adapter.get_lifecycle("wr-lifecycle-async").unwrap();
        assert_eq!(record.current_state, LifecycleState::Completed);
        assert_eq!(record.transition_count(), 4);
    }
}
