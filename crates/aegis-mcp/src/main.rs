//! Aegis MCP Server
//!
//! Model Context Protocol server for Aegis security scanning.

mod sandbox;
mod tools;

use aegis_core::{Config, PatternDefinition, Scanner};
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
}

impl ServerState {
    pub fn new() -> Self {
        let config = Config::default();
        Self {
            scanner: RwLock::new(Scanner::new()),
            config: RwLock::new(config),
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
    fn update_bundle(&self, force: bool) -> BoxFuture<Result<UpdateResponse>>;
}

/// Scan response
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResponse {
    pub findings: Vec<aegis_core::Finding>,
    pub finding_count: usize,
    pub risk_level: String,
    pub risk_score: i32,
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

            let risk_score =
                aegis_core::RiskScore::new(&findings, &Default::default(), &Default::default());

            Ok(ScanResponse {
                finding_count: findings.len(),
                risk_level: risk_score.level.to_string(),
                risk_score: risk_score.score,
                findings,
            })
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
            let (findings, _) = scanner.scan_file(&path).map_err(|e| jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::InternalError,
                message: e.to_string(),
                data: None,
            })?;

            let risk_score =
                aegis_core::RiskScore::new(&findings, &Default::default(), &Default::default());

            Ok(ScanResponse {
                finding_count: findings.len(),
                risk_level: risk_score.level.to_string(),
                risk_score: risk_score.score,
                findings,
            })
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
            let (findings, _) = scanner.scan_dir(&path).map_err(|e| jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::InternalError,
                message: e.to_string(),
                data: None,
            })?;

            let risk_score =
                aegis_core::RiskScore::new(&findings, &Default::default(), &Default::default());

            Ok(ScanResponse {
                finding_count: findings.len(),
                risk_level: risk_score.level.to_string(),
                risk_score: risk_score.score,
                findings,
            })
        })
    }

    fn scan_env(&self) -> BoxFuture<Result<ScanResponse>> {
        let state = self.state.clone();
        Box::pin(async move {
            let scanner = state.scanner.read().await;
            let findings = scanner.scan_env();

            let risk_score =
                aegis_core::RiskScore::new(&findings, &Default::default(), &Default::default());

            Ok(ScanResponse {
                finding_count: findings.len(),
                risk_level: risk_score.level.to_string(),
                risk_score: risk_score.score,
                findings,
            })
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

    fn update_bundle(&self, _force: bool) -> BoxFuture<Result<UpdateResponse>> {
        Box::pin(async move {
            // Patterns are bundled in the aegis-patterns crate
            let patterns = aegis_patterns::all_patterns();
            Ok(UpdateResponse {
                success: true,
                message: "Bundle is up to date".to_string(),
                pattern_count: patterns.len(),
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

    println!("Aegis MCP Server starting...");
    println!("Listening on stdin/stdout");

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
