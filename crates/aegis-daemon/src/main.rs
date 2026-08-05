//! Aegis Daemon
//!
//! Long-running daemon mode for Aegis security scanning.
//! Listens on a Unix socket for scan requests.

use aegis_core::{Config, Finding, PatternDefinition, RiskScore, ScanStats, Scanner};
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::signal;
use tokio::sync::{mpsc, RwLock};

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

/// Daemon response
#[derive(Debug, serde::Serialize)]
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

/// Handle a single client connection
async fn handle_client(stream: UnixStream, state: Arc<DaemonState>) -> anyhow::Result<()> {
    let (rd, mut wr) = tokio::io::split(stream);
    let mut reader = BufReader::new(rd);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(e) => {
                tracing::error!("Read error: {}", e);
                break;
            }
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Parse request
        let request: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                let response = DaemonResponse::error(format!("Parse error: {}", e));
                let resp_json = serde_json::to_string(&response).unwrap_or_default();
                wr.write_all(resp_json.as_bytes()).await.ok();
                wr.write_all(b"\n").await.ok();
                wr.flush().await.ok();
                continue;
            }
        };

        // Handle request
        let response = handle_request(&request, &state).await;
        let resp_json = serde_json::to_string(&response).unwrap_or_default();

        wr.write_all(resp_json.as_bytes()).await.ok();
        wr.write_all(b"\n").await.ok();
        wr.flush().await.ok();
    }

    Ok(())
}

/// Handle a JSON-RPC style request
async fn handle_request(request: &serde_json::Value, state: &Arc<DaemonState>) -> DaemonResponse {
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
            let pattern_infos: Vec<_> = patterns
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
                finding_count: pattern_infos.len(),
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

/// Create and listen on Unix socket
fn setup_socket(path: &PathBuf) -> std::io::Result<tokio::net::UnixListener> {
    // Remove existing socket file
    if path.exists() {
        std::fs::remove_file(path)?;
    }

    let listener = tokio::net::UnixListener::bind(path)?;
    Ok(listener)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("aegis=info")
        .init();

    let socket_path = PathBuf::from("/tmp/aegis-daemon.sock");

    println!("Aegis Daemon starting...");
    println!("Socket: {}", socket_path.display());

    let state = Arc::new(DaemonState::new(socket_path.clone()));

    // Initialize scanner with patterns
    {
        let mut scanner = state.scanner.write().await;
        *scanner = init_scanner();
    }

    // Setup Unix socket
    let listener = setup_socket(&socket_path)?;

    println!("Aegis Daemon listening on {}", socket_path.display());

    // Create shutdown channel
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    // Spawn signal handler
    tokio::spawn(async move {
        signal::ctrl_c().await.ok();
        shutdown_tx.send(()).await.ok();
    });

    // Accept connections
    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                println!("Aegis Daemon shutting down...");
                break;
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _)) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, state).await {
                                tracing::error!("Client handler error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::debug!("Accept error: {}", e);
                    }
                }
            }
        }
    }

    // Cleanup socket file
    if socket_path.exists() {
        std::fs::remove_file(&socket_path).ok();
    }

    Ok(())
}
