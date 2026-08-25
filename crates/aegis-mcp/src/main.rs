//! Aegis MCP Server
//!
//! Model Context Protocol server for Aegis security scanning.

mod sandbox;
mod tools;

use aegis_core::{Bundle, Config, PatternDefinition, ScanReceipt, ScanStats, Scanner};
use jsonrpc_core::{BoxFuture, IoHandler, Result, Value};
use jsonrpc_derive::rpc;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::RwLock;

pub use tools::*;

/// MCP server state
pub struct ServerState {
    pub scanner: RwLock<Scanner>,
    pub config: RwLock<Config>,
    pub bundle_version: RwLock<String>,
    pub bundle_checksum: RwLock<String>,
}

impl ServerState {
    pub fn new() -> Self {
        let config = Config::default();
        Self {
            scanner: RwLock::new(Scanner::new()),
            config: RwLock::new(config),
            bundle_version: RwLock::new(String::from("0.0.0")),
            bundle_checksum: RwLock::new(String::new()),
        }
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}

/// RPC trait definition
#[rpc]
pub trait AegisRpc {
    /// Scan a string
    #[rpc(name = "scan_string")]
    fn scan_string(&self, content: String, source: String) -> BoxFuture<Result<ScanResponse>>;

    /// Scan a file
    #[rpc(name = "scan_file")]
    fn scan_file(&self, path: String) -> BoxFuture<Result<ScanResponse>>;

    /// Scan a directory
    #[rpc(name = "scan_dir")]
    fn scan_dir(&self, path: String, recursive: bool) -> BoxFuture<Result<ScanResponse>>;

    /// Scan environment variables
    #[rpc(name = "scan_env")]
    fn scan_env(&self) -> BoxFuture<Result<ScanResponse>>;

    /// List all patterns
    #[rpc(name = "list_patterns")]
    fn list_patterns(&self, category: Option<String>) -> BoxFuture<Result<ListPatternsResponse>>;

    /// List all categories
    #[rpc(name = "list_categories")]
    fn list_categories(&self) -> BoxFuture<Result<Vec<String>>>;

    /// Update bundle
    #[rpc(name = "update_bundle")]
    fn update_bundle(
        &self,
        bundle_path: Option<String>,
        force: bool,
    ) -> BoxFuture<Result<UpdateResponse>>;
}

/// Scan response
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResponse {
    pub findings: Vec<aegis_core::Finding>,
    pub finding_count: usize,
    pub risk_level: String,
    pub risk_score: i32,
    /// Coverage and completeness evidence for the scan.
    pub stats: ScanStats,
    /// Redacted provenance receipt for the scan.
    pub receipt: ScanReceipt,
}

impl ScanResponse {
    fn from_parts(
        findings: Vec<aegis_core::Finding>,
        stats: ScanStats,
        source: impl Into<String>,
    ) -> Self {
        let risk_score =
            aegis_core::RiskScore::new(&findings, &Default::default(), &Default::default());
        let profile = "mcp-default";
        let receipt = ScanReceipt::from_scan(
            source,
            "mcp_scan",
            profile,
            Some(ScanReceipt::digest_text(profile)),
            &findings,
            stats.clone(),
        )
        .with_source_revision(std::env::var("AEGIS_SOURCE_REVISION").ok());
        Self {
            finding_count: findings.len(),
            risk_level: risk_score.level.to_string(),
            risk_score: risk_score.score,
            findings,
            stats,
            receipt,
        }
    }

    fn for_string(findings: Vec<aegis_core::Finding>, source: &str, bytes: usize) -> Self {
        Self::from_parts(
            findings,
            ScanStats::for_content(format!("string:{source}"), bytes),
            format!("string:{source}"),
        )
    }

    fn for_environment(findings: Vec<aegis_core::Finding>) -> Self {
        Self::from_parts(findings, ScanStats::for_environment(), "environment")
    }
}

/// List patterns response
#[derive(Debug, Serialize, Deserialize)]
pub struct ListPatternsResponse {
    pub patterns: Vec<PatternInfo>,
    pub total: usize,
}

/// Pattern info
#[derive(Debug, Serialize, Deserialize)]
pub struct PatternInfo {
    pub name: String,
    pub category: String,
    pub severity: String,
    pub confidence: String,
    pub description: String,
}

/// Update response
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateResponse {
    pub success: bool,
    pub message: String,
    pub pattern_count: usize,
}

/// Aegis RPC implementation
pub struct AegisRpcImpl {
    state: Arc<ServerState>,
}

impl AegisRpcImpl {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

impl AegisRpc for AegisRpcImpl {
    fn scan_string(&self, content: String, source: String) -> BoxFuture<Result<ScanResponse>> {
        let state = self.state.clone();
        Box::pin(async move {
            let scanner = state.scanner.read().await;
            let findings = scanner.scan_string(&content, &source);

            Ok(ScanResponse::for_string(findings, &source, content.len()))
        })
    }

    fn scan_file(&self, path: String) -> BoxFuture<Result<ScanResponse>> {
        let state = self.state.clone();
        Box::pin(async move {
            let path = PathBuf::from(&path);

            // Security: validate path
            if !sandbox::is_path_safe(&path) {
                return Err(jsonrpc_core::Error {
                    code: jsonrpc_core::ErrorCode::InvalidParams,
                    message: "Path is outside allowed directory".to_string(),
                    data: None,
                });
            }

            let scanner = state.scanner.read().await;
            let (findings, stats) = scanner.scan_file(&path).map_err(|e| jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::InternalError,
                message: e.to_string(),
                data: None,
            })?;

            Ok(ScanResponse::from_parts(
                findings,
                stats,
                path.to_string_lossy().to_string(),
            ))
        })
    }

    fn scan_dir(&self, path: String, _recursive: bool) -> BoxFuture<Result<ScanResponse>> {
        let state = self.state.clone();
        Box::pin(async move {
            let path = PathBuf::from(&path);

            // Security: validate path
            if !sandbox::is_path_safe(&path) {
                return Err(jsonrpc_core::Error {
                    code: jsonrpc_core::ErrorCode::InvalidParams,
                    message: "Path is outside allowed directory".to_string(),
                    data: None,
                });
            }

            let scanner = state.scanner.read().await;
            let (findings, stats) = scanner.scan_dir(&path).map_err(|e| jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::InternalError,
                message: e.to_string(),
                data: None,
            })?;

            Ok(ScanResponse::from_parts(
                findings,
                stats,
                path.to_string_lossy().to_string(),
            ))
        })
    }

    fn scan_env(&self) -> BoxFuture<Result<ScanResponse>> {
        let state = self.state.clone();
        Box::pin(async move {
            let scanner = state.scanner.read().await;
            let findings = scanner.scan_env();

            Ok(ScanResponse::for_environment(findings))
        })
    }

    fn list_patterns(&self, category: Option<String>) -> BoxFuture<Result<ListPatternsResponse>> {
        let state = self.state.clone();
        Box::pin(async move {
            let scanner = state.scanner.read().await;
            let registry = scanner.registry();

            let patterns = if let Some(cat) = category {
                registry.by_category(&cat)
            } else {
                registry.all()
            };

            let pattern_infos: Vec<PatternInfo> = patterns
                .iter()
                .map(|p| PatternInfo {
                    name: p.name().to_string(),
                    category: p.category().to_string(),
                    severity: p.severity().to_string(),
                    confidence: p.confidence().to_string(),
                    description: p.description().to_string(),
                })
                .collect();

            Ok(ListPatternsResponse {
                total: pattern_infos.len(),
                patterns: pattern_infos,
            })
        })
    }

    fn list_categories(&self) -> BoxFuture<Result<Vec<String>>> {
        let state = self.state.clone();
        Box::pin(async move {
            let scanner = state.scanner.read().await;
            let registry = scanner.registry();
            Ok(registry.categories())
        })
    }

    fn update_bundle(
        &self,
        bundle_path: Option<String>,
        _force: bool,
    ) -> BoxFuture<Result<UpdateResponse>> {
        let state = self.state.clone();
        Box::pin(async move {
            // If no path provided, use embedded patterns
            let bundle = if let Some(path) = bundle_path {
                let path = PathBuf::from(&path);

                // Security: validate path
                if !sandbox::is_path_safe(&path) {
                    return Err(jsonrpc_core::Error {
                        code: jsonrpc_core::ErrorCode::InvalidParams,
                        message: "Path is outside allowed directory".to_string(),
                        data: None,
                    });
                }

                // Load bundle from file
                Bundle::load(&path).map_err(|e| jsonrpc_core::Error {
                    code: jsonrpc_core::ErrorCode::InternalError,
                    message: format!("Failed to load bundle: {}", e),
                    data: None,
                })?
            } else {
                // Use embedded patterns from aegis-patterns crate
                let patterns: Vec<PatternDefinition> = aegis_patterns::all_patterns()
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
                Bundle::new(patterns)
            };

            // Validate bundle
            bundle.validate().map_err(|e| jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::InternalError,
                message: format!("Invalid bundle: {}", e),
                data: None,
            })?;

            // Create scanner from bundle
            let new_scanner = Scanner::from_bundle(&bundle).map_err(|e| jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::InternalError,
                message: format!("Failed to create scanner: {}", e),
                data: None,
            })?;

            // Update state
            {
                let mut scanner = state.scanner.write().await;
                *scanner = new_scanner;
            }
            {
                let mut version = state.bundle_version.write().await;
                *version = bundle.metadata().version.to_string();
            }
            {
                let mut checksum = state.bundle_checksum.write().await;
                *checksum = bundle.metadata().checksum;
            }

            let pattern_count = bundle.len();
            Ok(UpdateResponse {
                success: true,
                message: format!("Bundle updated with {} patterns", pattern_count),
                pattern_count,
            })
        })
    }
}

/// Initialize scanner with patterns from aegis-patterns
fn init_scanner() -> Scanner {
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("aegis=info")
        .init();

    let state = Arc::new(ServerState::new());

    // Initialize scanner with patterns
    {
        let mut scanner = state.scanner.write().await;
        *scanner = init_scanner();
    }

    let rpc = AegisRpcImpl::new(state.clone());
    let mut io = IoHandler::new();
    io.extend_with(rpc.to_delegate());

    // Keep stdout exclusively machine-readable JSON-RPC. Human diagnostics
    // belong on stderr so MCP/JSON-RPC clients can parse every stdout line.
    eprintln!("Aegis MCP Server starting...");
    eprintln!("Listening on stdin/stdout");

    // JSON-RPC over stdio
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    let stdout = tokio::io::stdout();
    let mut writer = tokio::io::BufWriter::new(stdout);

    while let Ok(Some(line)) = reader.next_line().await {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Parse request
        let _request: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                let response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32700,
                        "message": format!("Parse error: {}", e)
                    },
                    "id": Value::Null
                });
                use tokio::io::AsyncWriteExt;
                writer.write_all(response.to_string().as_bytes()).await.ok();
                writer.write_all(b"\n").await.ok();
                writer.flush().await.ok();
                continue;
            }
        };

        // Handle JSON-RPC request
        let response = io.handle_request(line).await;
        if let Some(resp) = response {
            use tokio::io::AsyncWriteExt;
            writer.write_all(resp.as_bytes()).await.ok();
            writer.write_all(b"\n").await.ok();
            writer.flush().await.ok();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_scanner_has_patterns() {
        let scanner = init_scanner();
        let registry = scanner.registry();
        let patterns = registry.all();
        assert!(!patterns.is_empty(), "Scanner should have patterns loaded");
    }

    #[test]
    fn test_server_state_new() {
        let state = ServerState::new();
        assert!(state.scanner.try_read().is_ok());
        assert!(state.config.try_read().is_ok());
    }

    #[test]
    fn test_server_state_default() {
        let state = ServerState::default();
        assert!(state.scanner.try_read().is_ok());
    }

    #[tokio::test]
    async fn test_server_state_with_scanner() {
        let state = Arc::new(ServerState::new());
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner();
        }
        let scanner = state.scanner.read().await;
        let registry = scanner.registry();
        assert!(!registry.all().is_empty());
    }

    #[test]
    fn test_scan_response_serialization() {
        let response = ScanResponse {
            findings: vec![],
            finding_count: 0,
            risk_level: "none".to_string(),
            risk_score: 0,
            stats: ScanStats::default(),
            receipt: ScanReceipt::from_scan(
                "test",
                "test",
                "test",
                None,
                &[],
                ScanStats::default(),
            ),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("finding_count"));
        assert!(json.contains("risk_level"));
        assert!(json.contains("inspection_ledger"));
        assert!(json.contains("receipt_id"));
    }

    #[test]
    fn test_scan_response_records_string_coverage() {
        let response = ScanResponse::for_string(vec![], "fixture.rs", 12);
        assert_eq!(response.stats.files_scanned, 1);
        assert_eq!(response.stats.bytes_scanned, 12);
        assert!(response.stats.inspection_ledger.allows_safe());
        assert_eq!(
            response.stats.inspection_ledger.units[0].status,
            aegis_core::InspectionStatus::Analyzed
        );
    }

    #[test]
    fn test_list_patterns_response_serialization() {
        let response = ListPatternsResponse {
            patterns: vec![PatternInfo {
                name: "test".to_string(),
                category: "secrets".to_string(),
                severity: "high".to_string(),
                confidence: "high".to_string(),
                description: "Test pattern".to_string(),
            }],
            total: 1,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("total"));
        assert!(json.contains("patterns"));
    }

    #[test]
    fn test_update_response_serialization() {
        let response = UpdateResponse {
            success: true,
            message: "Updated".to_string(),
            pattern_count: 100,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("success"));
        assert!(json.contains("pattern_count"));
    }

    #[test]
    fn test_aegis_rpc_impl_new() {
        let state = Arc::new(ServerState::new());
        let _rpc = AegisRpcImpl::new(state);
    }

    #[tokio::test]
    async fn test_scan_string_empty() {
        let state = Arc::new(ServerState::new());
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner();
        }
        let rpc = AegisRpcImpl::new(state);
        let result = rpc
            .scan_string("".to_string(), "test.txt".to_string())
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.finding_count, 0);
    }

    #[tokio::test]
    async fn test_scan_string_with_secret() {
        let state = Arc::new(ServerState::new());
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner();
        }
        let rpc = AegisRpcImpl::new(state);
        let result = rpc
            .scan_string("AKIAIOSFODNN7EXAMPLE".to_string(), "test.txt".to_string())
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.finding_count > 0, "Should detect AWS key");
    }

    #[tokio::test]
    async fn test_scan_env() {
        let state = Arc::new(ServerState::new());
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner();
        }
        let rpc = AegisRpcImpl::new(state);
        let result = rpc.scan_env().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_patterns() {
        let state = Arc::new(ServerState::new());
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner();
        }
        let rpc = AegisRpcImpl::new(state);
        let result = rpc.list_patterns(None).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.total > 0);
    }

    #[tokio::test]
    async fn test_list_patterns_by_category() {
        let state = Arc::new(ServerState::new());
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner();
        }
        let rpc = AegisRpcImpl::new(state);
        let result = rpc.list_patterns(Some("secrets".to_string())).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.total > 0);
    }

    #[tokio::test]
    async fn test_list_categories() {
        let state = Arc::new(ServerState::new());
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner();
        }
        let rpc = AegisRpcImpl::new(state);
        let result = rpc.list_categories().await;
        assert!(result.is_ok());
        let categories = result.unwrap();
        assert!(!categories.is_empty());
    }
}
