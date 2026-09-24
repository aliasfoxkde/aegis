//! Wire conformance replay for the aegis-mcp stdio surface.
//!
//! Each case in `fixtures/mcp_wire_conformance.json` is one session:
//! the exact request lines go to the server's stdin, and every stdout
//! frame is matched against the fixture's expected subset. This pins the
//! MCP handshake, discovery, and error semantics against regressions —
//! the property generic MCP clients depend on.

// Test binary: panicking on failure *is* the assertion mechanism, and the
// unwraps/expects here sit in child-process helpers that clippy's
// "only called from `#[test]` functions" analysis cannot see through.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use serde::Deserialize;
use serde_json::Value;
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const FIXTURES: &str = include_str!("fixtures/mcp_wire_conformance.json");

/// Sessions that end in a successful scan pay the one-time pattern
/// compilation; on a loaded runner that can take a minute.
const SESSION_DEADLINE: Duration = Duration::from_secs(180);

fn mcp_binary() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("CARGO_BIN_EXE_aegis_mcp") {
        return path.into();
    }
    let test_binary = std::env::current_exe().expect("test executable path is available");
    test_binary
        .parent()
        .and_then(std::path::Path::parent)
        .expect("integration test runs under target/<profile>/deps")
        .join("aegis-mcp")
}

/// One expected stdout frame: a subset match on the JSON plus, if the
/// case is a protocol error, the JSON-RPC error code.
#[derive(Deserialize)]
struct ExpectedFrame {
    id: Value,
    #[serde(rename = "match")]
    field_match: std::collections::BTreeMap<String, Value>,
    error_code: Option<i64>,
}

/// Assertions against the JSON inside `result.content[0].text` of a
/// `tools/call` result.
#[derive(Deserialize)]
struct ExpectedText {
    frame: usize,
    must_contain: Vec<String>,
    #[serde(default)]
    must_not_contain: Vec<String>,
}

#[derive(Deserialize)]
struct ConformanceCase {
    name: String,
    requests: Vec<String>,
    frames: Vec<ExpectedFrame>,
    #[serde(default)]
    text: Option<ExpectedText>,
}

/// Root of the fixture file: prose plus the replayed cases.
#[derive(Deserialize)]
struct FixtureFile {
    #[serde(default)]
    #[allow(dead_code)]
    description: String,
    cases: Vec<ConformanceCase>,
}

/// Run one server session: write every request line, close stdin, and
/// collect all stdout produced before the server exits. Panics if the
/// server outlives the deadline.
fn run_session(requests: &[String]) -> Vec<String> {
    let mut child = Command::new(mcp_binary())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn aegis-mcp");

    {
        let mut stdin = child.stdin.take().expect("stdin piped");
        for line in requests {
            stdin
                .write_all(line.as_bytes())
                .and_then(|()| stdin.write_all(b"\n"))
                .expect("write request line");
        }
    } // stdin dropped: the server sees EOF after answering.

    let mut stdout = child.stdout.take().expect("stdout piped");
    let reader = std::thread::spawn(move || {
        let mut output = String::new();
        // Read to EOF; the server closes stdout when the session ends.
        // A short read here only means the client died first, and the
        // frame-count assertions below will report that.
        drop(stdout.read_to_string(&mut output));
        output
    });

    wait_with_deadline(&mut child);
    let output = reader.join().expect("stdout reader thread");

    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_string)
        .collect()
}

fn wait_with_deadline(child: &mut Child) {
    let deadline = Instant::now() + SESSION_DEADLINE;
    loop {
        match child.try_wait().expect("poll aegis-mcp") {
            Some(_) => return,
            None if Instant::now() >= deadline => {
                let _killed = child.kill();
                let _reaped = child.wait();
                panic!("aegis-mcp did not exit within {SESSION_DEADLINE:?}");
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    }
}

/// Resolve a dotted path ("result.tools.0.name") into a JSON value.
/// Array indices are path segments; a missing path returns `None` so the
/// assertion reports the full frame instead of panicking mid-resolve.
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
    assert_eq!(
        frame.get("jsonrpc").and_then(Value::as_str),
        Some("2.0"),
        "frame must be JSON-RPC 2.0: {context}"
    );
    assert_eq!(
        frame.get("id"),
        Some(&expected.id),
        "response id must match the request: {context}"
    );
    match expected.error_code {
        Some(code) => {
            let error = frame
                .get("error")
                .unwrap_or_else(|| panic!("expected error frame: {context}"));
            assert_eq!(
                error.get("code").and_then(Value::as_i64),
                Some(code),
                "error code mismatch: {context}"
            );
            assert!(
                frame.get("result").is_none(),
                "error frame must not carry a result: {context}"
            );
        }
        None => {
            assert!(
                frame.get("error").is_none(),
                "unexpected protocol error: {context}"
            );
        }
    }
    for (path, expected_value) in &expected.field_match {
        let actual = resolve(frame, path)
            .unwrap_or_else(|| panic!("path {path} missing from frame: {context}"));
        assert_eq!(actual, expected_value, "path {path} mismatch: {context}");
    }
}

fn assert_text(expected: &ExpectedText, frames: &[Value], case_name: &str) {
    let frame = &frames[expected.frame];
    let text = resolve(frame, "result.content.0.text")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("case {case_name:?}: result.content.0.text missing: {frame}"));
    for needle in &expected.must_contain {
        assert!(
            text.contains(needle.as_str()),
            "case {case_name:?}: text must contain {needle:?}: {text}"
        );
    }
    for needle in &expected.must_not_contain {
        assert!(
            !text.contains(needle.as_str()),
            "case {case_name:?}: text must not contain {needle:?}: {text}"
        );
    }
}

#[test]
fn wire_conformance_cases_replay() {
    let fixture: FixtureFile = serde_json::from_str(FIXTURES).expect("fixture file parses");
    let cases = fixture.cases;
    assert!(
        cases.len() >= 8,
        "the fixture suite must keep growing, never shrink"
    );

    for case in &cases {
        let raw_frames = run_session(&case.requests);
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
        if let Some(text) = &case.text {
            assert_text(text, &frames, &case.name);
        }
    }
}

/// The full lifecycle a generic MCP client performs, in one session:
/// negotiate, signal readiness, discover, then call a tool. The frames
/// must come back in request order with the request ids.
#[test]
fn full_mcp_client_lifecycle_in_one_session() {
    let requests = vec![
        r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"conformance","version":"0.0.1"}},"id":1}"#.to_string(),
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_string(),
        r#"{"jsonrpc":"2.0","method":"tools/list","params":{},"id":2}"#.to_string(),
    ];
    let lines = run_session(&requests);
    assert_eq!(
        lines.len(),
        2,
        "the notification must produce no frame: {lines:?}"
    );

    let initialize: Value = serde_json::from_str(&lines[0]).expect("initialize frame is JSON");
    assert_eq!(initialize["id"], 1);
    assert_eq!(initialize["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(initialize["result"]["serverInfo"]["name"], "aegis-mcp");

    let tools: Value = serde_json::from_str(&lines[1]).expect("tools/list frame is JSON");
    assert_eq!(tools["id"], 2);
    let tool_list = tools["result"]["tools"]
        .as_array()
        .expect("tools array")
        .clone();
    assert_eq!(tool_list.len(), 7, "seven tools: {tools}");
    for tool in &tool_list {
        assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
        assert!(!tool["description"].as_str().unwrap_or_default().is_empty());
    }
}

/// A successful tools/call pays the lazy pattern compilation, so it runs
/// as its own session-scoped test: the planted credential assignment
/// must surface as findings inside isError:false text content.
#[test]
fn tools_call_scan_string_reports_findings_as_text_content() {
    let request = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"scan_string","arguments":{"content":"OPENAI_KEY = \"sk-U6JX9JE2SMfjqS8iK9uj9Q\"","source":"conformance"}},"id":42}"#;
    let lines = run_session(&[request.to_string()]);
    assert_eq!(lines.len(), 1, "one response frame: {lines:?}");

    let frame: Value = serde_json::from_str(&lines[0]).expect("frame is JSON");
    assert_eq!(frame["id"], 42);
    assert_eq!(frame["result"]["isError"], false, "{frame}");
    assert_eq!(frame["result"]["content"][0]["type"], "text");

    let text = frame["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    let payload: Value = serde_json::from_str(text).expect("text content is the scan JSON");
    assert!(
        payload["finding_count"].as_u64().unwrap_or(0) > 0,
        "credential assignment must be detected: {text}"
    );
}

/// The frame cap (`MAX_FRAME_BYTES` in `crates/aegis-mcp/src/main.rs`)
/// bounds the line reader: a frame one byte past the cap earns a single
/// `-32600` request error — before any JSON parsing, so filler bytes are
/// enough — and the session then ends, because framing cannot resume
/// inside an oversized line. Kept out of the fixture JSON: the payload is
/// megabytes, not a reproducible golden line.
#[test]
fn oversize_frame_is_answered_then_the_session_ends() {
    const MAX_FRAME_BYTES: usize = 10 * 1024 * 1024;
    let oversized = "a".repeat(MAX_FRAME_BYTES + 1);
    let lines = run_session(&[oversized]);
    assert_eq!(lines.len(), 1, "exactly one rejection frame: {lines:?}");

    let frame: Value = serde_json::from_str(&lines[0]).expect("frame is JSON");
    assert_eq!(frame["id"], Value::Null, "{frame}");
    assert_eq!(frame["error"]["code"], -32600, "{frame}");
    let message = frame["error"]["message"].as_str().expect("error message");
    assert!(
        message.contains(&format!("exceeds maximum size ({MAX_FRAME_BYTES} bytes)")),
        "{frame}"
    );
}
