//! Aegis Daemon
//!
//! Long-running daemon mode for Aegis security scanning.
//! Listens on a Unix socket for scan requests.

use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::signal;
use tokio::sync::mpsc;

pub use aegis_daemon::{handle_request, init_scanner, DaemonResponse, DaemonState};

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
