//! Aegis Daemon
//!
//! Long-running daemon mode for Aegis security scanning.
//! Listens on a Unix socket for scan requests.

#[cfg(unix)]
use anyhow::Result;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(unix)]
use tokio::signal;
#[cfg(unix)]
use tokio::sync::mpsc;

pub use aegis_daemon::{
    handle_request, init_scanner, DaemonPeerPolicy, DaemonResponse, DaemonState,
};

#[cfg(unix)]
const DEFAULT_SOCKET_PATH: &str = "/tmp/aegis-daemon.sock";

#[cfg(unix)]
const SOCKET_PATH_ENV: &str = "AEGIS_DAEMON_SOCKET_PATH";

#[cfg(unix)]
const SCAN_ROOT_ENV: &str = "AEGIS_DAEMON_SCAN_ROOT";

/// Handle a single client connection
#[cfg(unix)]
async fn handle_client(
    stream: UnixStream,
    state: Arc<DaemonState>,
    peer_policy: Arc<DaemonPeerPolicy>,
) -> anyhow::Result<()> {
    let credentials = stream.peer_cred().map_err(|error| {
        anyhow::anyhow!("cannot determine Unix peer credentials; refusing client: {error}")
    })?;
    if !peer_policy.allows(&credentials) {
        tracing::warn!(
            uid = credentials.uid(),
            gid = credentials.gid(),
            "rejecting unauthorized Aegis daemon client"
        );
        return Ok(());
    }

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
#[cfg(unix)]
fn setup_socket(path: &Path) -> std::io::Result<tokio::net::UnixListener> {
    // Only remove an existing Unix socket. Refuse regular files, directories,
    // and symlinks so a configurable path cannot be used to unlink an
    // operator-owned or attacker-controlled non-socket entry.
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "refusing unsafe pre-existing socket path: {}",
                    path.display()
                ),
            ));
        }
        fs::remove_file(path)?;
    }

    let listener = tokio::net::UnixListener::bind(path)?;
    set_socket_mode(path, 0o600)?;
    Ok(listener)
}

#[cfg(unix)]
fn set_socket_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(unix)]
fn configured_path(env_name: &str, default: &str) -> std::io::Result<PathBuf> {
    match std::env::var_os(env_name) {
        Some(value) if !value.is_empty() => Ok(PathBuf::from(value)),
        Some(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{env_name} cannot be empty"),
        )),
        None => Ok(PathBuf::from(default)),
    }
}

#[cfg(unix)]
fn remove_socket_if_present(path: &Path) {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_socket() {
            let _ = fs::remove_file(path);
        }
    }
}

#[tokio::main]
#[cfg(unix)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("aegis=info")
        .init();

    let socket_path = configured_path(SOCKET_PATH_ENV, DEFAULT_SOCKET_PATH)?;
    let scan_root = configured_path(SCAN_ROOT_ENV, ".")?;

    println!("Aegis Daemon starting...");
    println!("Socket: {}", socket_path.display());

    let state = Arc::new(DaemonState::try_with_scan_root(
        socket_path.clone(),
        scan_root,
    )?);

    // Initialize scanner with patterns
    {
        let mut scanner = state.scanner.write().await;
        *scanner = init_scanner();
    }

    // Setup Unix socket
    let listener = setup_socket(&socket_path)?;
    let socket_owner_uid = fs::metadata(&socket_path)?.uid();
    let peer_policy = match DaemonPeerPolicy::from_env(socket_owner_uid) {
        Ok(policy) => Arc::new(policy),
        Err(error) => {
            remove_socket_if_present(&socket_path);
            return Err(error.into());
        }
    };
    set_socket_mode(&socket_path, peer_policy.socket_mode())?;

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
                        let peer_policy = peer_policy.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, state, peer_policy).await {
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
    remove_socket_if_present(&socket_path);

    Ok(())
}

/// Stub main for non-Unix platforms
#[cfg(not(unix))]
fn main() {
    eprintln!("Aegis Daemon is only supported on Unix-like systems (Linux, macOS)");
    std::process::exit(1);
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use std::os::unix::fs::MetadataExt;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    fn test_socket_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aegis-daemon-{label}-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }

    #[tokio::test]
    async fn setup_socket_sets_owner_only_permissions() {
        let path = test_socket_path("mode");
        let listener = setup_socket(&path).expect("socket should bind");
        let mode = fs::metadata(&path).expect("socket metadata").mode() & 0o777;
        assert_eq!(mode, 0o600);
        drop(listener);
        remove_socket_if_present(&path);
    }

    #[test]
    fn setup_socket_refuses_non_socket_entries() {
        let path = test_socket_path("regular");
        fs::write(&path, b"do not remove").expect("create sentinel");
        let error = setup_socket(&path).expect_err("regular file must be refused");
        assert_eq!(error.kind(), ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).expect("sentinel remains"), b"do not remove");
        fs::remove_file(path).expect("remove sentinel");
    }

    #[tokio::test]
    async fn authorized_client_keeps_line_protocol() {
        let (client, server) = UnixStream::pair().expect("UnixStream pair");
        let peer_uid = server.peer_cred().expect("peer credentials").uid();
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        let policy = Arc::new(DaemonPeerPolicy::owner_only(peer_uid));
        let server_task = tokio::spawn(handle_client(server, state, policy));

        let (read_half, mut write_half) = client.into_split();
        write_half
            .write_all(br#"{"method":"ping","params":[],"id":1}"#)
            .await
            .expect("write request");
        write_half.write_all(b"\n").await.expect("write delimiter");
        let mut response = String::new();
        BufReader::new(read_half)
            .read_line(&mut response)
            .await
            .expect("read response");
        assert!(response.contains("\"success\":true"));
        drop(write_half);
        server_task
            .await
            .expect("server task join")
            .expect("client");
    }

    /// Verify that a peer whose UID/GID does not match the policy is rejected
    /// at the protocol boundary before any scan is performed.  The server
    /// accepts the TCP connection, checks credentials, and closes the socket
    /// without writing any response — the client sees EOF immediately.
    #[tokio::test]
    async fn unauthorized_peer_rejected_no_scan() {
        // Use a UID that does not match this process (1000) to simulate an
        // untrusted peer.  The policy allows only that foreign UID, so the
        // test-process client is unauthorized.
        const FOREIGN_UID: u32 = 9999;
        let socket_path = test_socket_path("unauthorized");
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind socket");
        let state = Arc::new(DaemonState::new(socket_path.clone()));
        let policy = Arc::new(DaemonPeerPolicy::owner_only(FOREIGN_UID));
        let cleanup_path = socket_path.clone();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            handle_client(stream, state, policy)
                .await
                .expect("handle_client");
            remove_socket_if_present(&cleanup_path);
        });

        // Give the server time to enter the accept loop.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Client connects from the test process (UID 1000) — unauthorized.
        let mut client = UnixStream::connect(&socket_path).await.expect("connect");

        // Send a scan request that would be unsafe if processed. The payload is
        // intentionally benign so the regression fixture cannot trip repository
        // secret scanners while proving that no request reaches the scanner.
        let scan_request = serde_json::json!({
            "method": "scan_string",
            "params": ["unauthorized-peer-probe-payload", "test.txt"],
            "id": 42
        });
        client
            .write_all(serde_json::to_string(&scan_request).unwrap().as_bytes())
            .await
            .expect("send request");
        client.write_all(b"\n").await.expect("send newline");

        // If the policy correctly rejects the peer, the server closes the socket
        // without sending any data, so the read completes with 0 bytes (EOF).
        client.readable().await.expect("mark readable");
        let mut buf = [0u8; 1024];
        let read_result =
            tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut buf))
                .await
                .expect("deadline not cancelled");

        // Depending on whether the client has already written its request,
        // Tokio reports either EOF or ECONNRESET when the rejected server closes
        // the socket. Both prove that no response bytes were emitted.
        match read_result {
            Ok(0) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            Ok(n) => panic!("unauthorized peer received {n} response bytes"),
            Err(error) => panic!("unexpected read error: {error}"),
        }

        server_task.await.expect("server task join");
    }
}
