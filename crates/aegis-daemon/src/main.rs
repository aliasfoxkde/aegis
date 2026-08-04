//! Aegis Daemon
//!
//! Long-running daemon mode for Aegis.

use tokio::signal;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("aegis=info")
        .init();

    println!("Aegis Daemon starting...");

    // Create shutdown channel
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    // Spawn signal handler
    tokio::spawn(async move {
        signal::ctrl_c().await.ok();
        shutdown_tx.send(()).await.ok();
    });

    // Wait for shutdown signal
    shutdown_rx.recv().await;

    println!("Aegis Daemon shutting down...");
    Ok(())
}
