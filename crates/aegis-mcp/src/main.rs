//! Aegis MCP Server
//!
//! Model Context Protocol server for Aegis security scanning.

use aegis_core::{Config, Finding, Scanner};
use jsonrpc_core::{BoxFuture, Result};
use jsonrpc_derive::rpc;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::sync::RwLock;

mod sandbox;
mod tools;

pub use tools::*;

/// MCP server state
pub struct ServerState {
    pub scanner: RwLock<Scanner>,
    pub config: RwLock<Config>,
}

impl ServerState {
    pub fn new() -> Self {
        let config = Config::preset("mcp").unwrap_or_else(|| {
            // Fallback to a minimal config if "mcp" preset doesn't exist
            Config::default()
        });
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
    pub findings: Vec<Finding>,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("aegis=info")
        .init();

    let _state = std::sync::Arc::new(ServerState::new());

    let _io = jsonrpc_core::IoHandler::new();
    // Note: jsonrpc_core::FutureResult is different from BoxFuture

    println!("Aegis MCP Server starting...");
    println!("Listening on stdin/stdout");

    // In a real implementation, we would set up the JSON-RPC over stdio
    // For now, just run indefinitely
    tokio::signal::ctrl_c().await?;

    Ok(())
}
