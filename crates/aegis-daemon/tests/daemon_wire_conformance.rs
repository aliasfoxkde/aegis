//! Wire conformance replay for the aegis-daemon Unix-socket surface.
//!
//! Each case in `fixtures/daemon_wire_conformance.json` is one client
//! connection to a real spawned daemon: the exact request frames go over
//! the socket, every serialized [`DaemonResponse`] frame is matched
//! against the fixture's expected subset, and the connection ends with a
//! half-close. This pins the JSON-lines protocol — error semantics,
//! sandbox refusal, blank-line framing, and scan envelopes — against
//! regressions, exactly as the aegis-mcp suite pins stdio.
//!
//! Requests that must trigger a detection are kept in this file (not the
//! fixture JSON) so the fixture never embeds credential-shaped strings.

// The daemon is a stub on non-Unix platforms (the protocol is a Unix
// socket), so this suite only compiles where the protocol exists.
#![cfg(unix)]
// Test binary: panicking on failure *is* the assertion mechanism, and the
// unwraps/expects here sit in `tokio::spawn` helpers that clippy's
// "only called from `#[test]` functions" analysis cannot see through.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

const FIXTURES: &str = include_str!("fixtures/daemon_wire_conformance.json");

/// The first scan request pays the one-time lazy compilation of 670
/// patterns; on a loaded runner that can take a minute.
const SESSION_DEADLINE: Duration = Duration::from_secs(180);

/// The planted file the daemon's scan root contains; the shape mirrors the
/// unit-test fixtures (assignment-like label + the AWS documentation
/// example key) so `aws-access-key` provably fires.
const PLANTED_LEAK: &str = "aws_key: AKIAIOSFODNN7EXAMPLE\n"; // aegis:ignore:aws-access-key -- synthetic fixture

/// The frame cap the daemon enforces (see `crates/aegis-daemon/src/main.rs`).
const MAX_FRAME_BYTES: usize = 10 * 1024 * 1024;

fn daemon_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("CARGO_BIN_EXE_aegis_daemon") {
        return path.into();
    }
    let test_binary = std::env::current_exe().expect("test executable path is available");
    test_binary
        .parent()
        .and_then(std::path::Path::parent)
        .expect("integration test runs under target/<profile>/deps")
        .join("aegis-daemon")
}

/// A spawned daemon process killed on drop, so a failing assertion cannot
/// leak a server that outlives the test.
struct DaemonProcess {
    child: Child,
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        let _killed = self.child.kill();
        let _reaped = self.child.wait();
    }
}

/// Spawn the daemon against a fresh scan root containing `leak.txt` and
/// wait for its socket to appear. The daemon runs as the test user, so the
/// owner-only peer policy admits the test's connections. `label` keeps
/// concurrent tests' sockets apart.
async fn start_daemon(root: &std::path::Path, label: &str) -> (DaemonProcess, PathBuf) {
    let socket_path =
        std::env::temp_dir().join(format!("ad-conf-{}-{label}.sock", std::process::id()));
    let mut child = Command::new(daemon_binary())
        .env("AEGIS_DAEMON_SOCKET_PATH", &socket_path)
        .env("AEGIS_DAEMON_SCAN_ROOT", root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn aegis-daemon");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if socket_path.exists() {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            let _killed = child.kill();
            let _reaped = child.wait();
            panic!("daemon socket never appeared at {}", socket_path.display());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    (DaemonProcess { child }, socket_path)
}

/// One fixture case: one connection's request frames and expected response
/// subsets. `match` pins exact field values by dotted path;
/// `min_finding_count` pins a floor; the error assertions pin message
/// substrings without pinning run-specific paths.
#[derive(Deserialize)]
struct ExpectedFrame {
    #[serde(rename = "match")]
    field_match: std::collections::BTreeMap<String, Value>,
    #[serde(default)]
    min_finding_count: Option<u64>,
    #[serde(default)]
    error_contains: Option<String>,
    #[serde(default)]
    error_not_contains: Vec<String>,
}

#[derive(Deserialize)]
struct ConformanceCase {
    name: String,
    requests: Vec<String>,
    frames: Vec<ExpectedFrame>,
}

/// Root of the fixture file: prose plus the replayed cases.
#[derive(Deserialize)]
struct FixtureFile {
    #[serde(default)]
    #[allow(dead_code)]
    description: String,
    cases: Vec<ConformanceCase>,
}

/// Run one case as one connection: write every request frame, half-close,
/// and collect the daemon's response frames until EOF.
async fn run_case(socket_path: &std::path::Path, requests: &[String]) -> Vec<String> {
    let stream = tokio::time::timeout(SESSION_DEADLINE, UnixStream::connect(socket_path))
        .await
        .expect("connect within deadline")
        .expect("connect to daemon socket");

    let (read_half, mut write_half) = stream.into_split();
    for line in requests {
        write_half
            .write_all(line.as_bytes())
            .await
            .expect("write request frame");
        write_half
            .write_all(b"\n")
            .await
            .expect("write frame delimiter");
    }
    // Half-close so the daemon sees EOF and ends this connection cleanly.
    write_half
        .shutdown()
        .await
        .expect("half-close the connection");

    let mut output = Vec::new();
    let mut reader = BufReader::new(read_half);
    tokio::time::timeout(SESSION_DEADLINE, reader.read_to_end(&mut output))
        .await
        .expect("responses within deadline")
        .expect("read response frames");

    String::from_utf8_lossy(&output)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_string)
        .collect()
}

/// Resolve a dotted path ("stats.files_scanned") into a JSON value. The
/// daemon response is flat today, but paths keep the matcher honest if it
/// ever grows nesting.
fn resolve<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = match current {
            Value::Object(map) => map.get(segment)?,
            Value::Array(items) => items.get(segment.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(current)
}

fn assert_frame(expected: &ExpectedFrame, frame: &Value, case_name: &str, index: usize) {
    let context = format!("case {case_name:?} frame {index}: {frame}");
    for (path, expected_value) in &expected.field_match {
        let actual = resolve(frame, path)
            .unwrap_or_else(|| panic!("path {path} missing from frame: {context}"));
        assert_eq!(actual, expected_value, "path {path} mismatch: {context}");
    }
    let count = frame
        .get("finding_count")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("finding_count missing: {context}"));
    if let Some(floor) = expected.min_finding_count {
        assert!(
            count >= floor,
            "finding_count {count} below floor {floor}: {context}"
        );
    }
    if let Some(needle) = &expected.error_contains {
        let error = frame
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("error missing from frame: {context}"));
        assert!(
            error.contains(needle.as_str()),
            "error must contain {needle:?}: {context}"
        );
    }
    for needle in &expected.error_not_contains {
        let error = frame.get("error").and_then(Value::as_str).unwrap_or("");
        assert!(
            !error.contains(needle.as_str()),
            "error must not contain {needle:?}: {context}"
        );
    }
}

/// The full fixture replay: one daemon process, one connection per case,
/// frames asserted in order.
#[tokio::test]
async fn wire_conformance_cases_replay() {
    let fixture: FixtureFile = serde_json::from_str(FIXTURES).expect("fixture file parses");
    let cases = fixture.cases;
    assert!(
        cases.len() >= 10,
        "the fixture suite must keep growing, never shrink"
    );

    let root = tempfile::tempdir().expect("scan-root tempdir");
    // The approved root is a subdirectory, so a sibling file exists just
    // outside it: the traversal case must reach the boundary check (path
    // resolves, then is refused) rather than failing resolution outright.
    let scan_root = root.path().join("approved-root");
    std::fs::create_dir(&scan_root).expect("create approved root");
    std::fs::write(scan_root.join("leak.txt"), PLANTED_LEAK).expect("plant leak.txt");
    std::fs::write(root.path().join("outside.txt"), b"outside the boundary\n")
        .expect("plant outside.txt");

    let (daemon, socket_path) = start_daemon(&scan_root, "replay").await;

    for case in &cases {
        let raw_frames = run_case(&socket_path, &case.requests).await;
        let mut frames = Vec::new();
        for line in &raw_frames {
            frames.push(serde_json::from_str::<Value>(line).unwrap_or_else(|error| {
                panic!("case {:?}: invalid JSON frame {line:?}: {error}", case.name)
            }));
        }
        assert_eq!(
            frames.len(),
            case.frames.len(),
            "case {:?}: expected {} response frames, got {}: {raw_frames:?}",
            case.name,
            case.frames.len(),
            frames.len()
        );
        for (index, expected) in case.frames.iter().enumerate() {
            assert_frame(expected, &frames[index], &case.name, index);
        }
    }

    drop(daemon);
}

/// A `scan_string` request carrying a credential assignment must come back
/// as a successful response with the detection counted and a receipt
/// attached — the daemon's answer to "does it actually scan?".
#[tokio::test]
async fn scan_string_detects_a_planted_credential() {
    let root = tempfile::tempdir().expect("scan-root tempdir");
    let (daemon, socket_path) = start_daemon(root.path(), "detect").await;

    let request = "{\"method\":\"scan_string\",\"params\":[\"aws_key: AKIAIOSFODNN7EXAMPLE\",\"planted.rs\"],\"id\":42}"; // aegis:ignore:aws-access-key -- synthetic fixture
    let raw_frames = run_case(&socket_path, &[request.to_string()]).await;
    assert_eq!(raw_frames.len(), 1, "one response frame: {raw_frames:?}");

    let frame: Value = serde_json::from_str(&raw_frames[0]).expect("frame is JSON");
    assert_eq!(frame["success"], true, "{frame}");
    assert!(
        frame["finding_count"].as_u64().unwrap_or(0) > 0,
        "credential assignment must be detected: {frame}"
    );
    // One critical finding maps to a "high" aggregate risk level; the
    // aggregate, not the finding severity, is what the wire carries.
    assert_eq!(frame["risk_level"], "high", "{frame}");
    let receipt = frame["receipt"]["receipt_id"]
        .as_str()
        .expect("receipt carries an id");
    assert!(receipt.starts_with("aegis-receipt-"), "{frame}");
    drop(daemon);
}

/// A frame past the cap is answered with a size error and the connection
/// ends — and the daemon keeps serving subsequent connections.
#[tokio::test]
async fn oversize_frame_is_answered_then_connection_ends() {
    let root = tempfile::tempdir().expect("scan-root tempdir");
    let (daemon, socket_path) = start_daemon(root.path(), "oversize").await;

    // One byte past the cap; the frame is rejected on size before any JSON
    // parsing, so the payload can be filler.
    let oversized = vec![b'a'; MAX_FRAME_BYTES + 1];
    let stream = UnixStream::connect(&socket_path)
        .await
        .expect("connect to daemon socket");
    let (read_half, mut write_half) = stream.into_split();
    write_half
        .write_all(&oversized)
        .await
        .expect("write oversized frame");
    write_half
        .shutdown()
        .await
        .expect("half-close the connection");

    let mut output = Vec::new();
    let mut reader = BufReader::new(read_half);
    tokio::time::timeout(SESSION_DEADLINE, reader.read_to_end(&mut output))
        .await
        .expect("response within deadline")
        .expect("read response frames");

    let raw = String::from_utf8_lossy(&output);
    let frames: Vec<&str> = raw.lines().filter(|line| !line.trim().is_empty()).collect();
    assert_eq!(frames.len(), 1, "exactly one rejection frame: {raw:?}");
    let frame: Value = serde_json::from_str(frames[0]).expect("frame is JSON");
    assert_eq!(frame["success"], false, "{frame}");
    let error = frame["error"].as_str().expect("error message");
    assert!(
        error.contains(&format!("exceeds maximum size ({MAX_FRAME_BYTES} bytes)")),
        "{frame}"
    );

    // The server must survive the dropped client and keep serving.
    let raw_frames = run_case(
        &socket_path,
        &[r#"{"method":"ping","params":[],"id":2}"#.to_string()],
    )
    .await;
    assert_eq!(raw_frames.len(), 1, "daemon still serves: {raw_frames:?}");
    let frame: Value = serde_json::from_str(&raw_frames[0]).expect("frame is JSON");
    assert_eq!(frame["success"], true, "{frame}");
    drop(daemon);
}
