//! Aegis Daemon Library
//!
//! Core logic for the Aegis daemon.

use aegis_core::{Config, Finding, PatternDefinition, RiskScore, ScanStats, Scanner};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Daemon state
pub struct DaemonState {
    pub scanner: RwLock<Scanner>,
    pub config: RwLock<Config>,
    pub socket_path: PathBuf,
}

impl DaemonState {
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            scanner: RwLock::new(Scanner::new()),
            config: RwLock::new(Config::default()),
            socket_path,
        }
    }
}

/// Initialize scanner with patterns from aegis-patterns
pub fn init_scanner() -> Scanner {
    let patterns = aegis_patterns::all_patterns();
    let definitions: Vec<PatternDefinition> = patterns
        .into_iter()
        .map(|p| PatternDefinition {
            name: p.name,
            category: p.category,
            match_pattern: p.match_pattern,
            enabled: p.enabled,
            severity: aegis_core::Severity::parse(&p.severity)
                .unwrap_or(aegis_core::Severity::Medium),
            confidence: aegis_core::Confidence::parse(&p.confidence)
                .unwrap_or(aegis_core::Confidence::Medium),
            min_entropy: p.min_entropy,
            description: p.description,
            reference: p.reference,
            tags: p.tags,
            env_var: p.env_var,
            binary: p.binary,
        })
        .collect();

    Scanner::from_definitions(definitions).unwrap_or_else(|_| Scanner::new())
}

/// Daemon response
#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonResponse {
    pub success: bool,
    pub findings: Vec<Finding>,
    pub finding_count: usize,
    pub risk_level: String,
    pub risk_score: i32,
    pub stats: ScanStats,
    pub error: Option<String>,
}

impl DaemonResponse {
    pub fn from_findings(findings: Vec<Finding>, stats: ScanStats) -> Self {
        let risk = RiskScore::new(&findings, &Default::default(), &Default::default());
        Self {
            success: true,
            finding_count: findings.len(),
            findings,
            risk_level: risk.level.to_string(),
            risk_score: risk.score,
            stats,
            error: None,
        }
    }

    pub fn error(msg: String) -> Self {
        Self {
            success: false,
            findings: vec![],
            finding_count: 0,
            risk_level: "unknown".to_string(),
            risk_score: 0,
            stats: ScanStats::default(),
            error: Some(msg),
        }
    }
}

/// Handle a JSON-RPC style request
pub async fn handle_request(
    request: &serde_json::Value,
    state: &Arc<DaemonState>,
) -> DaemonResponse {
    let method = match request.get("method").and_then(|v| v.as_str()) {
        Some(m) => m,
        None => return DaemonResponse::error("Missing method".to_string()),
    };

    let params = request.get("params");

    match method {
        "scan_string" => {
            let params = match params {
                Some(serde_json::Value::Array(arr)) => arr,
                _ => {
                    return DaemonResponse::error(
                        "scan_string requires [content, source] params".to_string(),
                    )
                }
            };
            let content = match params.first().and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return DaemonResponse::error("Missing content param".to_string()),
            };
            let source = match params.get(1).and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return DaemonResponse::error("Missing source param".to_string()),
            };

            let scanner = state.scanner.read().await;
            let findings = scanner.scan_string(content, source);
            let stats = ScanStats::default();
            DaemonResponse::from_findings(findings, stats)
        }
        "scan_file" => {
            let path = match params.and_then(|v| v.as_str()) {
                Some(s) => PathBuf::from(s),
                None => return DaemonResponse::error("Missing path param".to_string()),
            };

            let scanner = state.scanner.read().await;
            match scanner.scan_file(&path) {
                Ok((findings, stats)) => DaemonResponse::from_findings(findings, stats),
                Err(e) => DaemonResponse::error(format!("Scan error: {}", e)),
            }
        }
        "scan_dir" => {
            let path = match params.and_then(|v| v.as_str()) {
                Some(s) => PathBuf::from(s),
                None => return DaemonResponse::error("Missing path param".to_string()),
            };

            let scanner = state.scanner.read().await;
            match scanner.scan_dir(&path) {
                Ok((findings, stats)) => DaemonResponse::from_findings(findings, stats),
                Err(e) => DaemonResponse::error(format!("Scan error: {}", e)),
            }
        }
        "scan_env" => {
            let scanner = state.scanner.read().await;
            let findings = scanner.scan_env();
            let stats = ScanStats::default();
            DaemonResponse::from_findings(findings, stats)
        }
        "list_patterns" => {
            let scanner = state.scanner.read().await;
            let registry = scanner.registry();
            let patterns = registry.all();
            let _pattern_infos: Vec<_> = patterns
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "name": p.name(),
                        "category": p.category(),
                        "severity": p.severity().to_string(),
                        "confidence": p.confidence().to_string(),
                        "description": p.description()
                    })
                })
                .collect();
            DaemonResponse {
                success: true,
                findings: vec![],
                finding_count: patterns.len(),
                risk_level: "none".to_string(),
                risk_score: 0,
                stats: ScanStats::default(),
                error: None,
            }
        }
        "ping" => DaemonResponse::from_findings(vec![], ScanStats::default()),
        _ => DaemonResponse::error(format!("Unknown method: {}", method)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_ping() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        // Initialize scanner
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner();
        }

        let request = serde_json::json!({
            "method": "ping",
            "params": [],
            "id": 1
        });

        let response = handle_request(&request, &state).await;
        assert!(response.success);
        assert_eq!(response.finding_count, 0);
    }

    #[tokio::test]
    async fn test_scan_string() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        // Initialize scanner
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner();
        }

        let request = serde_json::json!({
            "method": "scan_string",
            "params": ["aws_key: AKIAIOSFODNN7EXAMPLE", "test.txt"],
            "id": 2
        });

        let response = handle_request(&request, &state).await;
        assert!(response.success);
        assert!(response.finding_count > 0, "Should detect AWS key");
    }

    #[tokio::test]
    async fn test_scan_string_no_findings() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner();
        }

        let request = serde_json::json!({
            "method": "scan_string",
            "params": ["fn main() { println!(\"hello\"); }", "test.rs"],
            "id": 3
        });

        let response = handle_request(&request, &state).await;
        assert!(response.success);
        assert_eq!(response.finding_count, 0);
    }

    #[tokio::test]
    async fn test_missing_method() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner();
        }

        let request = serde_json::json!({
            "params": [],
            "id": 4
        });

        let response = handle_request(&request, &state).await;
        assert!(!response.success);
        assert!(response.error.is_some());
    }

    #[tokio::test]
    async fn test_unknown_method() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner();
        }

        let request = serde_json::json!({
            "method": "unknown_method",
            "params": [],
            "id": 5
        });

        let response = handle_request(&request, &state).await;
        assert!(!response.success);
        assert!(response.error.unwrap().contains("Unknown method"));
    }

    #[tokio::test]
    async fn test_list_patterns() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner();
        }

        let request = serde_json::json!({
            "method": "list_patterns",
            "params": null,
            "id": 6
        });

        let response = handle_request(&request, &state).await;
        assert!(response.success);
        assert!(response.finding_count > 0, "Should have patterns");
    }

    #[test]
    fn test_daemon_response_error() {
        let response = DaemonResponse::error("test error".to_string());
        assert!(!response.success);
        assert_eq!(response.error, Some("test error".to_string()));
    }

    #[test]
    fn test_daemon_response_from_findings() {
        let findings = vec![];
        let stats = ScanStats::default();
        let response = DaemonResponse::from_findings(findings, stats);
        assert!(response.success);
        assert_eq!(response.finding_count, 0);
    }
}
