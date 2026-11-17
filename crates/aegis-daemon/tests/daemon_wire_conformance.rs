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

/// The first scan request pays the one-time lazy compilation of 677
/// patterns; on a loaded runner that can take a minute.
const SESSION_DEADLINE: Duration = Duration::from_secs(180);

/// The planted file the daemon's scan root contains; the shape mirrors the
/// unit-test fixtures (assignment-like label + the AWS documentation
/// example key) so `aws-access-key` provably fires.
const PLANTED_LEAK: &str = "aws_key: AKIAIOSFODNN7EXAMPLE\n"; // aegis:ignore:aws-access-key -- synthetic fixture

/// A planted documentation file: `eval` on unvalidated input is a finding
/// in the `security-hardening` category, and it is *not* a secret, so a
/// path class is allowed to lower it.
const PLANTED_DOCS_FILE: &str = "result = eval(user_input)\n"; // aegis:ignore:eval-usage -- synthetic fixture

/// A planted file whose credential is marked as a deliberate example with
/// the `aegis:synthetic` annotation. The finding is kept, tagged, and
/// reported at low severity — the annotation sets an example aside, it
/// does not hide it.
const PLANTED_SYNTHETIC_FILE: &str = "api_key = \"AKIAIOSFODNN7EXAMPLE\"  # aegis:synthetic\n"; // aegis:ignore:aws-access-key -- synthetic fixture

/// A planted file whose credential is a placeholder.
///
/// The quotes are escaped in the Rust source, so the file written to disk
/// carries a real credential assignment — the shape the rule matches —
/// while this source line does not read as one to a scan of the
/// repository's own sources.
const PLANTED_PLACEHOLDER_FILE: &str = "password = \"changeme\"\n";

/// The operator configuration the path-class case runs the daemon with:
/// one glob that classifies documentation paths, exactly as an operator
/// would write it in a profile.
const DOCS_PATH_CLASS_CONFIG: &str =
    r#"{"name":"conformance","path_classes":[{"glob":"docs/**","class":"docs"}]}"#;

/// The frame cap the daemon enforces (see `crates/aegis-daemon/src/main.rs`).
const MAX_FRAME_BYTES: usize = 10 * 1024 * 1024;

/// Path to the daemon binary under test.
///
/// Cargo exports `CARGO_BIN_EXE_<name>` to the integration tests of the
/// package that owns a binary, with `<name>` the target name exactly as
/// written in `Cargo.toml` — so the hyphen is part of the name. The
/// variable is read at compile time on purpose: it does not depend on
/// where Cargo puts the test executable, which has changed between
/// releases (`target/<profile>/deps/` is no longer the only layout).
fn daemon_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aegis-daemon"))
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
///
/// `operator_config` names the profile the daemon applies at startup; the
/// daemon reads it before it binds the socket, so the configuration is in
/// force for every request the socket answers.
async fn start_daemon(
    root: &std::path::Path,
    label: &str,
    operator_config: Option<&std::path::Path>,
) -> (DaemonProcess, PathBuf) {
    let socket_path =
        std::env::temp_dir().join(format!("ad-conf-{}-{label}.sock", std::process::id()));
    let mut command = Command::new(daemon_binary());
    command
        .env("AEGIS_DAEMON_SOCKET_PATH", &socket_path)
        .env("AEGIS_DAEMON_SCAN_ROOT", root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(config) = operator_config {
        command.env("AEGIS_DAEMON_CONFIG", config);
    }
    let mut child = command.spawn().expect("spawn aegis-daemon");

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

    let (daemon, socket_path) = start_daemon(&scan_root, "replay", None).await;

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
    let (daemon, socket_path) = start_daemon(root.path(), "detect", None).await;

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
    let (daemon, socket_path) = start_daemon(root.path(), "oversize", None).await;

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

/// The findings of one scan response, as the wire carries them.
fn findings_of(frame: &Value) -> Vec<&Value> {
    frame["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .collect()
}

/// Whether a finding carries `tag`.
fn has_tag(finding: &Value, tag: &str) -> bool {
    finding["tags"]
        .as_array()
        .expect("tags array")
        .iter()
        .any(|value| value.as_str() == Some(tag))
}

/// A path the operator classified as documentation reports its findings at
/// low severity, and the class is recorded on the finding — over the
/// wire, with the class configured the way an operator configures it.
///
/// The rule is written with `/` and the path the daemon scans is the one
/// the operating system built, so this case also pins the separator
/// handling on the platform the test matrix runs it on.
#[tokio::test]
async fn a_classified_path_lowers_its_findings_over_the_wire() {
    let root = tempfile::tempdir().expect("scan-root tempdir");
    let docs = root.path().join("docs");
    std::fs::create_dir(&docs).expect("create the docs directory");
    std::fs::write(docs.join("example.md"), PLANTED_DOCS_FILE).expect("plant the docs file");
    let config_path = root.path().join("operator.json");
    std::fs::write(&config_path, DOCS_PATH_CLASS_CONFIG).expect("write the operator config");

    let (daemon, socket_path) = start_daemon(root.path(), "pathclass", Some(&config_path)).await;

    let request = r#"{"method":"scan_file","params":"docs/example.md","id":7}"#;
    let raw_frames = run_case(&socket_path, &[request.to_string()]).await;
    assert_eq!(raw_frames.len(), 1, "one response frame: {raw_frames:?}");

    let frame: Value = serde_json::from_str(&raw_frames[0]).expect("frame is JSON");
    assert_eq!(frame["success"], true, "{frame}");
    let finding = findings_of(&frame)
        .into_iter()
        .find(|finding| finding["pattern"] == "eval-usage")
        .expect("the documentation file must still report the finding");
    assert_eq!(finding["severity"], "low", "a classed path reports as low");
    assert!(
        has_tag(finding, "docs"),
        "the class is recorded on the finding: {finding}"
    );
    drop(daemon);
}

/// The `aegis:synthetic` annotation keeps the finding, tags it, and
/// reports it at low severity — over the wire.
#[tokio::test]
async fn a_synthetic_annotation_keeps_its_finding_over_the_wire() {
    let root = tempfile::tempdir().expect("scan-root tempdir");
    std::fs::write(root.path().join("app.py"), PLANTED_SYNTHETIC_FILE).expect("plant the file");

    let (daemon, socket_path) = start_daemon(root.path(), "synthetic", None).await;

    let request = r#"{"method":"scan_file","params":"app.py","id":8}"#;
    let raw_frames = run_case(&socket_path, &[request.to_string()]).await;
    assert_eq!(raw_frames.len(), 1, "one response frame: {raw_frames:?}");

    let frame: Value = serde_json::from_str(&raw_frames[0]).expect("frame is JSON");
    assert_eq!(frame["success"], true, "{frame}");
    let findings = findings_of(&frame);
    assert!(
        !findings.is_empty(),
        "the annotation keeps the finding: {frame}"
    );
    let finding = findings
        .into_iter()
        .find(|finding| has_tag(finding, "synthetic"))
        .expect("the finding must carry the synthetic tag");
    assert_eq!(
        finding["severity"], "low",
        "a synthetic value reports as low"
    );
    drop(daemon);
}

/// A secret finding carries its triage verdict over the wire, and the
/// verdict names the signal it judged without quoting the value it
/// judged: a report that says the secret contains `changeme` is itself a
/// disclosure.
#[tokio::test]
async fn a_secret_finding_carries_its_triage_verdict_over_the_wire() {
    let root = tempfile::tempdir().expect("scan-root tempdir");
    std::fs::write(root.path().join("app.py"), PLANTED_PLACEHOLDER_FILE).expect("plant the file");

    let (daemon, socket_path) = start_daemon(root.path(), "triage", None).await;

    let request = r#"{"method":"scan_file","params":"app.py","id":9}"#;
    let raw_frames = run_case(&socket_path, &[request.to_string()]).await;
    assert_eq!(raw_frames.len(), 1, "one response frame: {raw_frames:?}");

    let frame: Value = serde_json::from_str(&raw_frames[0]).expect("frame is JSON");
    assert_eq!(frame["success"], true, "{frame}");
    let finding = findings_of(&frame)
        .into_iter()
        .find(|finding| finding["pattern"] == "hardcoded-password")
        .expect("the planted password must be reported");
    assert_eq!(
        finding["secret_triage"]["outcome"], "likely_placeholder",
        "a known placeholder marker is a placeholder verdict: {finding}"
    );
    let reasons = finding["secret_triage"]["reasons"]
        .as_array()
        .expect("reasons array");
    assert!(!reasons.is_empty(), "the verdict says why: {finding}");
    for reason in reasons {
        let reason = reason.as_str().expect("a reason is a string");
        assert!(
            !reason.contains("changeme"),
            "a reason must not quote the value: {reason}"
        );
    }
    drop(daemon);
}
