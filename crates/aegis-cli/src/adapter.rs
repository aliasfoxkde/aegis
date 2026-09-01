//! Control Center pre-pipeline adapter CLI surface.
//!
//! This module exposes the existing fail-closed `ControlCenterAdapter`
//! contract from `aegis-core` through the `aegis adapter scan` subcommand.
//! It is intentionally thin: the adapter already owns the fail-closed
//! policy, redacted evidence, and lifecycle tracking. The CLI layer
//! only renders a JSON response and persists evidence when requested.
//!
//! ## Command contract
//!
//! `aegis adapter scan --work-request-id <ID> --source <SOURCE> \
//!     [--content <CONTENT> | --content-file <PATH>] \
//!     [--evidence-output <PATH>]`
//!
//! * `--work-request-id` and `--source` are required.
//! * Exactly one of `--content` or `--content-file` is required; the
//!   other may be omitted.
//! * When `--content-file` is supplied the file is read fully and its
//!   bytes are used as the work-request content.
//! * `--evidence-output`, when present, receives a JSON array of
//!   evidence records persisted atomically by the adapter.
//!
//! ## Exit codes
//!
//! | Code | Meaning                                                       |
//! |------|---------------------------------------------------------------|
//! | 0    | `Pass` — work may proceed, no findings                        |
//! | 1    | `Fail` — work may proceed, findings present                   |
//! | 2    | `Blocked` — adapter failed closed (do **not** proceed)        |
//! | 3    | Invalid arguments (clap parse failure surfaces as code 3)     |
//!
//! The exit-code mapping matches the existing `aegis scan` reference
//! table in `docs/guides/CLI.md` so callers can rely on a single rule.

use aegis_core::control_center_adapter::{
    AdapterError, ControlCenterAdapter, ScanResult, WorkRequest,
};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

/// Options consumed by `run_adapter_scan` (mirrors the clap definition).
#[derive(Debug, Clone)]
pub struct AdapterScanOptions {
    pub work_request_id: String,
    pub source: String,
    /// Inline content, mutually exclusive with `content_file`.
    pub content: Option<String>,
    /// File containing the work-request content.
    pub content_file: Option<PathBuf>,
    /// Optional destination for the adapter's evidence persistence path.
    pub evidence_output: Option<PathBuf>,
}

/// Bundle of fields consumed by `AdapterScanResponse::from_result`.
#[derive(Debug, Clone)]
struct CompletedResult {
    scan_result: ScanResult,
    evidence_ref: String,
    finding_count: usize,
    highest_severity: Option<String>,
    lifecycle_state: String,
    transition_count: usize,
    evidence_path: Option<String>,
}

/// Outcome of one adapter scan invocation.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AdapterScanResponse {
    pub work_request_id: String,
    pub scan_result: ScanResult,
    pub allows_work: bool,
    pub evidence_ref: String,
    pub finding_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub highest_severity: Option<String>,
    pub lifecycle_state: String,
    pub transition_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl AdapterScanResponse {
    fn from_result(work_request_id: &str, result: CompletedResult) -> Self {
        let CompletedResult {
            scan_result,
            evidence_ref,
            finding_count,
            highest_severity,
            lifecycle_state,
            transition_count,
            evidence_path,
        } = result;
        Self {
            work_request_id: work_request_id.to_string(),
            allows_work: scan_result.allows_work(),
            scan_result,
            evidence_ref,
            finding_count,
            highest_severity,
            lifecycle_state,
            transition_count,
            evidence_path,
            error: None,
        }
    }

    fn blocked(
        work_request_id: &str,
        evidence_ref: String,
        lifecycle_state: String,
        transition_count: usize,
        error: String,
    ) -> Self {
        Self {
            work_request_id: work_request_id.to_string(),
            scan_result: ScanResult::Blocked,
            allows_work: false,
            evidence_ref,
            finding_count: 0,
            highest_severity: None,
            lifecycle_state,
            transition_count,
            evidence_path: None,
            error: Some(error),
        }
    }
}

/// Exit code returned to the shell by the adapter subcommand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterExitCode {
    Pass = 0,
    Fail = 1,
    Blocked = 2,
}

impl AdapterExitCode {
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

/// Outcome combining the rendered response and the exit code.
#[derive(Debug, Clone)]
pub struct AdapterScanOutcome {
    pub response: AdapterScanResponse,
    pub exit_code: AdapterExitCode,
}

/// Read the work-request content according to the supplied options.
///
/// Returns `Err(message)` when neither flag is provided, when both are
/// supplied, or when reading the file fails. The message is suitable for
/// surfacing in `AdapterScanResponse::error` and on stderr.
pub fn resolve_content(opts: &AdapterScanOptions) -> Result<String, String> {
    match (opts.content.as_ref(), opts.content_file.as_ref()) {
        (Some(_), Some(_)) => {
            Err("exactly one of --content or --content-file may be supplied".to_string())
        }
        (None, None) => Err("one of --content or --content-file is required".to_string()),
        (Some(content), None) => Ok(content.clone()),
        (None, Some(path)) => fs::read_to_string(path)
            .map_err(|error| format!("failed to read content from {}: {error}", path.display())),
    }
}

/// Run one adapter scan synchronously. Pure data flow — no I/O beyond
/// the optional file reads and evidence persistence — so the function
/// is straightforward to test.
pub fn run_adapter_scan(opts: AdapterScanOptions) -> AdapterScanOutcome {
    let work_request_id = opts.work_request_id.clone();
    let content = match resolve_content(&opts) {
        Ok(content) => content,
        Err(message) => {
            return AdapterScanOutcome {
                response: AdapterScanResponse::blocked(
                    &work_request_id,
                    String::new(),
                    "rejected".to_string(),
                    0,
                    message,
                ),
                exit_code: AdapterExitCode::Blocked,
            };
        }
    };

    if work_request_id.is_empty() {
        return AdapterScanOutcome {
            response: AdapterScanResponse::blocked(
                &work_request_id,
                String::new(),
                "rejected".to_string(),
                0,
                "work request ID is empty".to_string(),
            ),
            exit_code: AdapterExitCode::Blocked,
        };
    }

    let mut adapter = ControlCenterAdapter::new();
    let request = WorkRequest {
        work_request_id: work_request_id.clone(),
        content,
        source: opts.source.clone(),
    };

    match adapter.scan_work_sync(request) {
        Ok(scan_result) => {
            let lifecycle_state = adapter
                .get_lifecycle(&work_request_id)
                .map(|record| format!("{:?}", record.current_state).to_lowercase())
                .unwrap_or_else(|| "unknown".to_string());
            let transition_count = adapter
                .get_lifecycle(&work_request_id)
                .map(|record| record.transition_count())
                .unwrap_or(0);
            let evidence_ref = adapter
                .get_evidence_for_work(&work_request_id)
                .map(|record| record.evidence_ref.clone())
                .unwrap_or_default();
            let finding_count = adapter
                .get_evidence_for_work(&work_request_id)
                .map(|record| record.finding_count)
                .unwrap_or(0);
            let highest_severity = adapter
                .get_evidence_for_work(&work_request_id)
                .and_then(|record| record.highest_severity.clone());

            let evidence_path = match opts.evidence_output.as_ref() {
                Some(path) => match persist_evidence(&adapter, path) {
                    Ok(()) => Some(path.display().to_string()),
                    Err(error) => {
                        return AdapterScanOutcome {
                            response: AdapterScanResponse::blocked(
                                &work_request_id,
                                evidence_ref,
                                lifecycle_state,
                                transition_count,
                                format!("evidence persistence failed: {error}"),
                            ),
                            exit_code: AdapterExitCode::Blocked,
                        };
                    }
                },
                None => None,
            };

            let exit_code = match scan_result {
                ScanResult::Pass => AdapterExitCode::Pass,
                ScanResult::Fail => AdapterExitCode::Fail,
                ScanResult::Blocked => AdapterExitCode::Blocked,
            };

            AdapterScanOutcome {
                response: AdapterScanResponse::from_result(
                    &work_request_id,
                    CompletedResult {
                        scan_result,
                        evidence_ref,
                        finding_count,
                        highest_severity,
                        lifecycle_state,
                        transition_count,
                        evidence_path,
                    },
                ),
                exit_code,
            }
        }
        Err(error) => {
            let lifecycle_state = adapter
                .get_lifecycle(&work_request_id)
                .map(|record| format!("{:?}", record.current_state).to_lowercase())
                .unwrap_or_else(|| "unknown".to_string());
            let transition_count = adapter
                .get_lifecycle(&work_request_id)
                .map(|record| record.transition_count())
                .unwrap_or(0);
            let evidence_ref = adapter
                .get_evidence_for_work(&work_request_id)
                .map(|record| record.evidence_ref.clone())
                .unwrap_or_default();
            AdapterScanOutcome {
                response: AdapterScanResponse::blocked(
                    &work_request_id,
                    evidence_ref,
                    lifecycle_state,
                    transition_count,
                    error.to_string(),
                ),
                exit_code: AdapterExitCode::Blocked,
            }
        }
    }
}

fn persist_evidence(adapter: &ControlCenterAdapter, path: &Path) -> Result<(), String> {
    adapter
        .persist_evidence(path)
        .map_err(|error| format!("{error}"))
}

/// Map an adapter error to the human-readable classification used in CLI
/// error messages. Kept here so the run function and tests can share it.
pub fn classify_error(error: &AdapterError) -> &'static str {
    match error {
        AdapterError::ScannerError(_) => "scanner_error",
        AdapterError::ScannerUnavailable(_) => "scanner_unavailable",
        AdapterError::MalformedInput(_) => "malformed_input",
        AdapterError::WorkRequestConflict(_) => "work_request_conflict",
        AdapterError::Internal(_) => "internal_error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline_opts() -> AdapterScanOptions {
        AdapterScanOptions {
            work_request_id: "wr-cli-001".to_string(),
            source: "src/lib.rs".to_string(),
            content: Some("fn main() { println!(\"hi\"); }".to_string()),
            content_file: None,
            evidence_output: None,
        }
    }

    #[test]
    fn run_adapter_scan_clean_content_emits_pass() {
        let outcome = run_adapter_scan(baseline_opts());
        assert_eq!(outcome.exit_code, AdapterExitCode::Pass);
        assert_eq!(outcome.response.scan_result, ScanResult::Pass);
        assert!(outcome.response.allows_work);
        assert!(outcome.response.error.is_none());
        assert_eq!(outcome.response.work_request_id, "wr-cli-001");
        assert_eq!(outcome.response.finding_count, 0);
        assert_eq!(outcome.response.evidence_ref.len(), 64);
        assert!(outcome.response.evidence_path.is_none());
    }

    #[test]
    fn run_adapter_scan_records_lifecycle_progress() {
        let outcome = run_adapter_scan(baseline_opts());
        // Pending -> Accepted -> Running -> Completed = 4 transitions
        assert_eq!(outcome.response.lifecycle_state, "completed");
        assert_eq!(outcome.response.transition_count, 4);
    }

    #[test]
    fn run_adapter_scan_rejects_empty_content() {
        let mut opts = baseline_opts();
        opts.content = Some(String::new());
        let outcome = run_adapter_scan(opts);
        assert_eq!(outcome.exit_code, AdapterExitCode::Blocked);
        assert_eq!(outcome.response.scan_result, ScanResult::Blocked);
        assert!(!outcome.response.allows_work);
        assert!(outcome.response.error.is_some());
    }

    #[test]
    fn run_adapter_scan_rejects_empty_work_request_id() {
        let mut opts = baseline_opts();
        opts.work_request_id = String::new();
        let outcome = run_adapter_scan(opts);
        assert_eq!(outcome.exit_code, AdapterExitCode::Blocked);
        assert!(outcome
            .response
            .error
            .as_deref()
            .unwrap_or("")
            .contains("empty"));
    }

    #[test]
    fn run_adapter_scan_requires_content_or_file() {
        let mut opts = baseline_opts();
        opts.content = None;
        opts.content_file = None;
        let outcome = run_adapter_scan(opts);
        assert_eq!(outcome.exit_code, AdapterExitCode::Blocked);
        assert!(outcome
            .response
            .error
            .as_deref()
            .unwrap_or("")
            .contains("--content"));
    }

    #[test]
    fn run_adapter_scan_rejects_both_content_and_file() {
        let mut opts = baseline_opts();
        opts.content_file = Some(PathBuf::from("/tmp/anything"));
        let outcome = run_adapter_scan(opts);
        assert_eq!(outcome.exit_code, AdapterExitCode::Blocked);
        assert!(outcome
            .response
            .error
            .as_deref()
            .unwrap_or("")
            .contains("exactly one"));
    }

    #[test]
    fn run_adapter_scan_reads_content_file() {
        let mut opts = baseline_opts();
        opts.content = None;
        let path = std::env::temp_dir().join(format!(
            "aegis_adapter_cli_{}_content.rs",
            std::process::id()
        ));
        std::fs::write(&path, "fn helper() { println!(\"from file\"); }\n").unwrap();
        opts.content_file = Some(path.clone());
        let outcome = run_adapter_scan(opts);
        assert_eq!(outcome.exit_code, AdapterExitCode::Pass);
        assert_eq!(outcome.response.finding_count, 0);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn run_adapter_scan_reports_missing_content_file() {
        let mut opts = baseline_opts();
        opts.content = None;
        opts.content_file = Some(PathBuf::from("/definitely/does/not/exist/aegis.rs"));
        let outcome = run_adapter_scan(opts);
        assert_eq!(outcome.exit_code, AdapterExitCode::Blocked);
        assert!(outcome
            .response
            .error
            .as_deref()
            .unwrap_or("")
            .contains("failed to read"));
    }

    #[test]
    fn run_adapter_scan_persists_evidence_when_requested() {
        let mut opts = baseline_opts();
        let evidence_path = std::env::temp_dir().join(format!(
            "aegis_adapter_cli_{}_evidence.json",
            std::process::id()
        ));
        opts.evidence_output = Some(evidence_path.clone());
        let outcome = run_adapter_scan(opts);
        assert_eq!(outcome.exit_code, AdapterExitCode::Pass);
        assert_eq!(
            outcome.response.evidence_path.as_deref(),
            Some(evidence_path.to_string_lossy().as_ref())
        );
        let raw = std::fs::read_to_string(&evidence_path).unwrap();
        assert!(raw.contains("wr-cli-001"));
        assert!(raw.contains("\"pass\""));
        std::fs::remove_file(evidence_path).ok();
    }

    #[test]
    fn resolve_content_rejects_missing_both_flags() {
        let opts = AdapterScanOptions {
            work_request_id: "wr".to_string(),
            source: "src".to_string(),
            content: None,
            content_file: None,
            evidence_output: None,
        };
        let err = resolve_content(&opts).unwrap_err();
        assert!(err.contains("required"));
    }

    #[test]
    fn resolve_content_rejects_both_flags_supplied() {
        let opts = AdapterScanOptions {
            work_request_id: "wr".to_string(),
            source: "src".to_string(),
            content: Some("x".to_string()),
            content_file: Some(PathBuf::from("/tmp/aegis_anything")),
            evidence_output: None,
        };
        let err = resolve_content(&opts).unwrap_err();
        assert!(err.contains("exactly one"));
    }

    #[test]
    fn resolve_content_returns_inline_when_only_content() {
        let opts = AdapterScanOptions {
            work_request_id: "wr".to_string(),
            source: "src".to_string(),
            content: Some("inline".to_string()),
            content_file: None,
            evidence_output: None,
        };
        assert_eq!(resolve_content(&opts).unwrap(), "inline");
    }

    #[test]
    fn classify_error_returns_stable_labels() {
        let cases = [
            (AdapterError::ScannerError("x".into()), "scanner_error"),
            (
                AdapterError::ScannerUnavailable("x".into()),
                "scanner_unavailable",
            ),
            (AdapterError::MalformedInput("x".into()), "malformed_input"),
            (
                AdapterError::WorkRequestConflict("x".into()),
                "work_request_conflict",
            ),
            (AdapterError::Internal("x".into()), "internal_error"),
        ];
        for (error, expected) in cases {
            assert_eq!(classify_error(&error), expected);
        }
    }

    #[test]
    fn response_serializes_without_receipt_payload() {
        let outcome = run_adapter_scan(baseline_opts());
        let json = serde_json::to_string(&outcome.response).unwrap();
        assert!(json.contains("\"scan_result\":\"pass\""));
        assert!(json.contains("\"allows_work\":true"));
        assert!(json.contains("\"evidence_ref\""));
        assert!(!json.contains("evidence_path"));
        assert!(!json.contains("error"));
        assert!(!json.contains("highest_severity"));
    }
}
