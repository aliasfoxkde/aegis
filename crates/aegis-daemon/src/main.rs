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

/// Upper bound on one request frame (the JSON line, newline excluded).
///
/// `scan_string` is the only method that ships content in the frame, and
/// it is meant for snippets; file and directory scans carry only a path.
/// Without a cap, `BufReader::read_line` would grow without limit and a
/// single authorized peer could exhaust daemon memory with one line.
#[cfg(unix)]
const MAX_FRAME_BYTES: usize = 10 * 1024 * 1024;

/// What [`read_bounded_line`] produced.
#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
enum FrameRead {
    /// A complete line (a final line without its newline still counts).
    Line,
    /// The peer closed the connection with nothing pending.
    Eof,
    /// The pending line is longer than the configured frame cap.
    Oversize,
}

/// Read one newline-terminated frame without buffering more than the cap.
///
/// Unbounded line reads grow their buffer without limit, so this walks
/// [`tokio::io::AsyncBufRead::fill_buf`] chunks instead and stops at
/// `max_bytes`. Bytes that are not valid UTF-8 become replacement
/// characters, which the JSON parser then rejects — a parse-error
/// response beats the old behaviour of silently dropping the connection.
///
/// # Errors
/// Propagates transport failures; the caller ends the connection.
#[cfg(unix)]
async fn read_bounded_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
    out: &mut String,
) -> std::io::Result<FrameRead> {
    out.clear();
    let mut buffered = 0usize;
    loop {
        let (line_complete, chunk_len) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                // A final partial line is still a frame; nothing pending
                // means the peer closed the connection.
                return Ok(if buffered == 0 {
                    FrameRead::Eof
                } else {
                    FrameRead::Line
                });
            }
            if let Some(end) = available.iter().position(|&byte| byte == b'\n') {
                if buffered + end > max_bytes {
                    return Ok(FrameRead::Oversize);
                }
                out.push_str(&String::from_utf8_lossy(&available[..end]));
                (true, end + 1)
            } else {
                if buffered + available.len() > max_bytes {
                    return Ok(FrameRead::Oversize);
                }
                out.push_str(&String::from_utf8_lossy(available));
                buffered += available.len();
                (false, available.len())
            }
        };
        reader.consume(chunk_len);
        if line_complete {
            return Ok(FrameRead::Line);
        }
    }
}

/// Serialize a response, falling back to a framing-level error envelope if
/// serialization itself fails (infallible in practice).
#[cfg(unix)]
fn serialize_response(response: &DaemonResponse) -> String {
    serde_json::to_string(response).unwrap_or_else(|e| {
        format!(
            "{{\"jsonrpc\":\"2.0\",\"error\":{{\"code\":-32603,\"message\":\"response serialization failed: {e}\"}}}}"
        )
    })
}

/// Handle a single client connection
#[cfg(unix)]
async fn handle_client(
    stream: UnixStream,
    state: Arc<DaemonState>,
    peer_policy: Arc<DaemonPeerPolicy>,
) -> Result<()> {
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
        match read_bounded_line(&mut reader, MAX_FRAME_BYTES, &mut line).await {
            Ok(FrameRead::Line) => {}
            Ok(FrameRead::Eof) => break,
            Ok(FrameRead::Oversize) => {
                tracing::warn!(
                    limit = MAX_FRAME_BYTES,
                    "dropping client that sent an oversized frame"
                );
                let response = DaemonResponse::error(format!(
                    "request frame exceeds maximum size ({MAX_FRAME_BYTES} bytes)"
                ));
                // The rest of the oversized line is still unread and
                // unknowable, so framing cannot resume: answer once, then
                // end the connection.
                write_frame(&mut wr, &serialize_response(&response)).await?;
                break;
            }
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
                let response = DaemonResponse::error(format!("Parse error: {e}"));
                // Serialization of the error envelope is infallible in
                // practice; a failure still produces a framing-level error
                // so the client sees something rather than silence.
                // A dead socket means the client is gone; the connection
                // ends instead of looping on a broken pipe.
                write_frame(&mut wr, &serialize_response(&response)).await?;
                continue;
            }
        };

        // Handle request
        let response = handle_request(&request, &state).await;
        write_frame(&mut wr, &serialize_response(&response)).await?;
    }

    Ok(())
}

/// Write one newline-terminated frame and flush.
///
/// # Errors
/// Propagates transport failures; the caller drops the connection rather
/// than continuing to serve a client that can no longer read responses.
#[cfg(unix)]
async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &str,
) -> std::io::Result<()> {
    writer.write_all(frame.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
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
            drop(fs::remove_file(path));
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
        &scan_root,
    )?);

    // Patterns compile lazily on the first request that needs them (see
    // `DaemonState::ensure_patterns_loaded`); startup only binds the socket.

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
        // macOS caps sockaddr_un at 104 bytes and its TMPDIR is already
        // ~70 chars deep, so the socket name must stay short or every
        // bind fails with a name-too-long error. Labels are unique per
        // test and the pid keeps separate runs apart.
        std::env::temp_dir().join(format!("ad-{}-{label}", std::process::id()))
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
        let path = test_socket_path("refuse-regular");
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
            Err(error) if error.kind() == ErrorKind::ConnectionReset => {}
            Ok(n) => panic!("unauthorized peer received {n} response bytes"),
            Err(error) => panic!("unexpected read error: {error}"),
        }

        server_task.await.expect("server task join");
    }

    /// Drive the line protocol through every branch of `handle_client`:
    /// blank lines are skipped silently, malformed JSON earns a parse-error
    /// response, a valid request earns a normal response, and EOF ends the
    /// connection cleanly.
    #[tokio::test]
    async fn handle_client_protocol_skips_blank_and_answers_malformed_lines() {
        let (client, server) = UnixStream::pair().expect("UnixStream pair");
        let peer_uid = server.peer_cred().expect("peer credentials").uid();
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        let policy = Arc::new(DaemonPeerPolicy::owner_only(peer_uid));
        let server_task = tokio::spawn(handle_client(server, state, policy));

        let (read_half, mut write_half) = client.into_split();
        write_half
            .write_all(b"\n   \n")
            .await
            .expect("write blank lines");
        write_half
            .write_all(br"{definitely not json")
            .await
            .expect("write malformed line");
        write_half.write_all(b"\n").await.expect("write delimiter");
        write_half
            .write_all(br#"{"method":"ping","params":[],"id":7}"#)
            .await
            .expect("write valid line");
        write_half.write_all(b"\n").await.expect("write delimiter");
        write_half.shutdown().await.expect("half-close for EOF");

        let mut reader = BufReader::new(read_half);
        let mut parse_error = String::new();
        reader
            .read_line(&mut parse_error)
            .await
            .expect("read parse-error response");
        assert!(
            parse_error.contains("Parse error"),
            "malformed line must earn a parse error, got: {parse_error}"
        );

        let mut ping = String::new();
        reader
            .read_line(&mut ping)
            .await
            .expect("read ping response");
        assert!(ping.contains("\"success\":true"), "got: {ping}");

        // EOF after the responses: the handler must exit cleanly.
        server_task
            .await
            .expect("server task join")
            .expect("clean client exit");
    }

    #[tokio::test]
    async fn setup_socket_replaces_a_stale_socket_file() {
        let path = test_socket_path("stale");
        drop(setup_socket(&path).expect("first bind"));
        assert!(path.exists(), "socket file outlives its listener");

        // The stale entry is a socket, so the second bind may replace it.
        let listener = setup_socket(&path).expect("rebind over stale socket");
        drop(listener);
        remove_socket_if_present(&path);
    }

    #[test]
    fn configured_path_reads_overrides_and_rejects_empty_values() {
        // Env vars are process-global; both names are exercised in this one
        // serialized test so parallel tests cannot race the mutation.
        std::env::remove_var(SOCKET_PATH_ENV);
        assert_eq!(
            configured_path(SOCKET_PATH_ENV, "/tmp/default.sock").expect("unset falls back"),
            PathBuf::from("/tmp/default.sock")
        );

        std::env::set_var(SOCKET_PATH_ENV, "/tmp/override.sock");
        assert_eq!(
            configured_path(SOCKET_PATH_ENV, "/tmp/default.sock").expect("override wins"),
            PathBuf::from("/tmp/override.sock")
        );

        std::env::set_var(SOCKET_PATH_ENV, "");
        let error = configured_path(SOCKET_PATH_ENV, "/tmp/default.sock")
            .expect_err("empty override must be rejected");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(error.to_string().contains(SOCKET_PATH_ENV));

        std::env::remove_var(SOCKET_PATH_ENV);
    }

    #[tokio::test]
    async fn remove_socket_if_present_only_removes_sockets() {
        let missing = test_socket_path("missing");
        remove_socket_if_present(&missing);
        assert!(!missing.exists());

        let regular = test_socket_path("cleanup-regular");
        fs::write(&regular, b"keep me").expect("create sentinel");
        remove_socket_if_present(&regular);
        assert_eq!(
            fs::read(&regular).expect("regular files survive cleanup"),
            b"keep me"
        );
        fs::remove_file(&regular).expect("remove sentinel");

        let socket = test_socket_path("socket");
        drop(tokio::net::UnixListener::bind(&socket).expect("bind socket"));
        remove_socket_if_present(&socket);
        assert!(!socket.exists(), "stale sockets are cleaned up");
    }

    /// Drive `read_bounded_line` over both halves of an in-memory duplex;
    /// the tiny buffer capacity forces `fill_buf` to hand back partial
    /// chunks, exercising the no-newline-yet accumulation path.
    async fn read_line_over_duplex(input: &[u8], cap: usize) -> std::io::Result<FrameRead> {
        let (mut client, server) = tokio::io::duplex(64);
        let mut reader = BufReader::new(server);
        let input = input.to_vec();
        let writer_task = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            client.write_all(&input).await.expect("write input");
        });

        let mut line = String::new();
        let outcome = read_bounded_line(&mut reader, cap, &mut line).await;
        writer_task.await.expect("writer task");
        outcome
    }

    #[tokio::test]
    async fn bounded_reader_accepts_a_line_within_the_cap() {
        let outcome = read_line_over_duplex(b"{\"method\":\"ping\"}\n", 64)
            .await
            .expect("read succeeds");
        assert_eq!(outcome, FrameRead::Line);
    }

    #[tokio::test]
    async fn bounded_reader_accepts_a_line_exactly_at_the_cap() {
        let payload = vec![b'a'; 32];
        let mut input = payload.clone();
        input.push(b'\n');
        let outcome = read_line_over_duplex(&input, 32)
            .await
            .expect("read succeeds");
        assert_eq!(outcome, FrameRead::Line);
    }

    #[tokio::test]
    async fn bounded_reader_reports_oversize_frames() {
        let input = vec![b'0'; 65]; // one past the cap, newline never arrives
        let outcome = read_line_over_duplex(&input, 64).await;
        assert_eq!(outcome.expect("read succeeds"), FrameRead::Oversize);
    }

    #[tokio::test]
    async fn bounded_reader_reports_oversize_even_when_newline_follows() {
        let mut input = vec![b'0'; 65];
        input.push(b'\n');
        let outcome = read_line_over_duplex(&input, 64).await;
        assert_eq!(outcome.expect("read succeeds"), FrameRead::Oversize);
    }

    #[tokio::test]
    async fn bounded_reader_treats_eof_with_pending_bytes_as_a_line() {
        let outcome = read_line_over_duplex(b"{\"method\":\"ping\"}", 64)
            .await
            .expect("read succeeds");
        assert_eq!(outcome, FrameRead::Line);
    }

    #[tokio::test]
    async fn bounded_reader_reports_eof_on_empty_input() {
        let outcome = read_line_over_duplex(b"", 64).await;
        assert_eq!(outcome.expect("read succeeds"), FrameRead::Eof);
    }

    #[tokio::test]
    async fn bounded_reader_accumulates_across_partial_chunks() {
        // Larger than the 64-byte duplex buffer and newline-free until the
        // end, so the reader must accumulate several fill_buf chunks.
        let mut input = vec![b'x'; 300];
        input.push(b'\n');
        let outcome = read_line_over_duplex(&input, 1024)
            .await
            .expect("read succeeds");
        assert_eq!(outcome, FrameRead::Line);
    }
}
