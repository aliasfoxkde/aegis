//! Integration tests for the Aegis MCP server.

use std::io::{Read, Write};

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

fn send_mcp_request(request: &str) -> String {
    let mut child = std::process::Command::new(mcp_binary())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to spawn MCP server");

    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(request.as_bytes())
        .expect("Failed to write to stdin");
    drop(stdin);

    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        stdout
            .read_to_end(&mut output)
            .expect("Failed to read MCP server output");
        output
    });

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match child.try_wait().expect("Failed to poll MCP server") {
            Some(_) => break,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                panic!("MCP server did not exit before the 30-second deadline");
            }
            None => std::thread::sleep(std::time::Duration::from_millis(25)),
        }
    }

    let _ = child.wait().expect("Failed to collect MCP server status");
    let output = reader.join().expect("MCP output reader panicked");
    String::from_utf8_lossy(&output).to_string()
}

#[test]
fn test_mcp_scan_string() {
    let request = r#"{"jsonrpc":"2.0","method":"scan_string","params":["AKIAIOSFODNN7EXAMPLE","test.rs"],"id":1}"#;
    let response = send_mcp_request(request);
    assert!(response.contains("jsonrpc"), "Response: {}", response);
    assert!(response.contains("findings"), "Response: {}", response);
}

#[test]
fn test_mcp_list_patterns() {
    let request = r#"{"jsonrpc":"2.0","method":"list_patterns","params":null,"id":2}"#;
    let response = send_mcp_request(request);
    assert!(response.contains("patterns"), "Response: {}", response);
}

#[test]
fn test_mcp_list_categories() {
    let request = r#"{"jsonrpc":"2.0","method":"list_categories","params":[],"id":3}"#;
    let response = send_mcp_request(request);
    assert!(response.contains("secrets"), "Response: {}", response);
}

#[test]
fn test_mcp_stdout_contains_only_json_rpc_responses() {
    let request = r#"{"jsonrpc":"2.0","method":"list_categories","params":[],"id":8}"#;
    let response = send_mcp_request(request);
    let lines: Vec<_> = response
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();

    assert_eq!(
        lines.len(),
        1,
        "stdout must contain one response: {response}"
    );
    let value: serde_json::Value =
        serde_json::from_str(lines[0]).expect("stdout line must be valid JSON");
    assert_eq!(value["jsonrpc"], "2.0");
    assert_eq!(value["id"], 8);
    assert!(value.get("result").is_some());
}

#[test]
fn test_mcp_update_bundle() {
    let request = r#"{"jsonrpc":"2.0","method":"update_bundle","params":[null,false],"id":4}"#;
    let response = send_mcp_request(request);
    assert!(response.contains("success"), "Response: {}", response);
}

#[test]
fn test_mcp_scan_dir() {
    let fixture_dir =
        std::env::temp_dir().join(format!("aegis-mcp-scan-dir-{}", std::process::id()));
    std::fs::create_dir_all(&fixture_dir).unwrap();
    std::fs::write(fixture_dir.join("fixture.rs"), "fn main() {}\n").unwrap();
    let request = format!(
        r#"{{"jsonrpc":"2.0","method":"scan_dir","params":[{:?}],"id":5}}"#,
        fixture_dir.to_string_lossy()
    );
    let response = send_mcp_request_in_dir(&request, &fixture_dir);
    let _ = std::fs::remove_dir_all(fixture_dir);
    assert!(response.contains("jsonrpc"), "Response: {}", response);
}

#[test]
fn test_mcp_scan_env() {
    let request = r#"{"jsonrpc":"2.0","method":"scan_env","params":[],"id":6}"#;
    let response = send_mcp_request(request);
    assert!(response.contains("jsonrpc"), "Response: {}", response);
}

#[test]
fn test_mcp_list_patterns_with_category() {
    let request = r#"{"jsonrpc":"2.0","method":"list_patterns","params":["secrets"],"id":7}"#;
    let response = send_mcp_request(request);
    assert!(response.contains("patterns"), "Response: {}", response);
}

/// Decode the single JSON-RPC response line on stdout.
fn parse_single_response(response: &str) -> serde_json::Value {
    let lines: Vec<_> = response
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "stdout must contain exactly one response line: {response}"
    );
    serde_json::from_str(lines[0]).expect("response line must be valid JSON")
}

/// Send one JSON-RPC request to the MCP server with an explicit working
/// directory. The sandbox only allows paths under the server's working
/// directory, so safe-path fixtures must run with cwd = fixture directory.
fn send_mcp_request_in_dir(request: &str, current_dir: &std::path::Path) -> String {
    let mut child = std::process::Command::new(mcp_binary())
        .current_dir(current_dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to spawn MCP server");

    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(request.as_bytes())
        .expect("Failed to write to stdin");
    drop(stdin);

    let output = child
        .wait_with_output()
        .expect("Failed to wait for MCP server");
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn test_mcp_scan_file_documented_positional_params_accepted() {
    // The documented request shape is a positional single-element array:
    // {"method":"scan_file","params":["/path/to/config.json"]}.
    let fixture_dir =
        std::env::temp_dir().join(format!("aegis-mcp-scan-file-safe-{}", std::process::id()));
    std::fs::create_dir_all(&fixture_dir).unwrap();
    let fixture_file = fixture_dir.join("fixture.txt");
    std::fs::write(&fixture_file, "plain fixture content\n").unwrap();

    let request = format!(
        r#"{{"jsonrpc":"2.0","method":"scan_file","params":[{:?}],"id":10}}"#,
        fixture_file.to_string_lossy()
    );
    let response = send_mcp_request_in_dir(&request, &fixture_dir);
    let _ = std::fs::remove_dir_all(&fixture_dir);

    let value = parse_single_response(&response);
    assert_eq!(value["jsonrpc"], "2.0", "Response: {response}");
    assert_eq!(value["id"], 10, "Response: {response}");
    let error = value.get("error");
    assert!(
        error.is_none(),
        "documented scan_file params must be accepted: {response}"
    );
    let result = &value["result"];
    assert!(
        result.get("finding_count").is_some(),
        "result must be a scan response: {response}"
    );
    assert_eq!(result["finding_count"], 0, "Response: {response}");
}

#[test]
fn test_mcp_scan_file_unsafe_path_rejected() {
    let request = r#"{"jsonrpc":"2.0","method":"scan_file","params":["/etc/passwd"],"id":11}"#;
    let response = send_mcp_request(request);
    let value = parse_single_response(&response);
    assert_eq!(value["jsonrpc"], "2.0", "Response: {response}");
    assert_eq!(value["id"], 11, "Response: {response}");
    let error = value
        .get("error")
        .unwrap_or_else(|| panic!("unsafe path must be rejected: {response}"));
    assert_eq!(
        error["code"], -32602,
        "unsafe path must be an InvalidParams error: {response}"
    );
    assert!(
        !response.contains("root:"),
        "unsafe path must not leak file contents: {response}"
    );
}

#[test]
fn test_mcp_scan_file_malformed_params_rejected() {
    for (label, request) in [
        (
            "non-string element",
            r#"{"jsonrpc":"2.0","method":"scan_file","params":[42],"id":12}"#,
        ),
        (
            "too many elements",
            r#"{"jsonrpc":"2.0","method":"scan_file","params":["a","b"],"id":13}"#,
        ),
        (
            "empty params",
            r#"{"jsonrpc":"2.0","method":"scan_file","params":[],"id":14}"#,
        ),
        (
            "object params",
            r#"{"jsonrpc":"2.0","method":"scan_file","params":{"path":"Cargo.toml"},"id":15}"#,
        ),
    ] {
        let response = send_mcp_request(request);
        let value = parse_single_response(&response);
        let error = value
            .get("error")
            .unwrap_or_else(|| panic!("malformed params ({label}) must be rejected: {response}"));
        assert_eq!(
            error["code"], -32602,
            "malformed params ({label}) must be InvalidParams: {response}"
        );
        assert!(value.get("result").is_none(), "Response: {response}");
    }
}

#[test]
fn test_mcp_scan_dir_documented_positional_params_accepted() {
    // The documented request shape is a positional single-element array:
    // {"method":"scan_dir","params":["/path/to/project"]}.
    let fixture_dir =
        std::env::temp_dir().join(format!("aegis-mcp-scan-dir-safe-{}", std::process::id()));
    std::fs::create_dir_all(&fixture_dir).unwrap();
    std::fs::write(fixture_dir.join("fixture_a.txt"), "plain fixture content\n").unwrap();
    std::fs::write(fixture_dir.join("fixture_b.txt"), "more plain content\n").unwrap();

    let request = format!(
        r#"{{"jsonrpc":"2.0","method":"scan_dir","params":[{:?}],"id":20}}"#,
        fixture_dir.to_string_lossy()
    );
    let response = send_mcp_request_in_dir(&request, &fixture_dir);
    let _ = std::fs::remove_dir_all(&fixture_dir);

    let value = parse_single_response(&response);
    assert_eq!(value["jsonrpc"], "2.0", "Response: {response}");
    assert_eq!(value["id"], 20, "Response: {response}");
    assert!(
        value.get("error").is_none(),
        "documented scan_dir params must be accepted: {response}"
    );
    let result = &value["result"];
    assert!(
        result.get("finding_count").is_some(),
        "result must be a scan response: {response}"
    );
    assert_eq!(result["finding_count"], 0, "Response: {response}");
    assert_eq!(
        result["stats"]["files_scanned"], 2,
        "both fixture files must be scanned: {response}"
    );
}

#[test]
fn test_mcp_scan_dir_unsafe_path_rejected() {
    let request = r#"{"jsonrpc":"2.0","method":"scan_dir","params":["/etc"],"id":21}"#;
    let response = send_mcp_request(request);
    let value = parse_single_response(&response);
    assert_eq!(value["jsonrpc"], "2.0", "Response: {response}");
    assert_eq!(value["id"], 21, "Response: {response}");
    let error = value
        .get("error")
        .unwrap_or_else(|| panic!("unsafe path must be rejected: {response}"));
    assert_eq!(
        error["code"], -32602,
        "unsafe path must be an InvalidParams error: {response}"
    );
    assert!(
        value.get("result").is_none(),
        "unsafe path must not produce a scan result: {response}"
    );
}

fn send_mcp_request_with_stderr_capture(request: &str) -> (String, String) {
    use std::io::{BufRead, BufReader};

    let mut child = std::process::Command::new(mcp_binary())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn MCP server");

    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(request.as_bytes())
        .expect("Failed to write to stdin");
    drop(stdin);

    let stdout_h = child.stdout.take().unwrap();
    let stderr_h = child.stderr.take().unwrap();

    let (stdout_tx, stdout_rx) = std::sync::mpsc::channel();
    let (stderr_tx, stderr_rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout_h);
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            stdout_tx.send(std::mem::take(&mut line)).unwrap();
            line.clear();
        }
    });
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr_h);
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            stderr_tx.send(std::mem::take(&mut line)).unwrap();
            line.clear();
        }
    });

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match child.try_wait().expect("Failed to poll MCP server") {
            Some(_) => break,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("MCP server did not exit before the 30-second deadline");
            }
            None => std::thread::sleep(std::time::Duration::from_millis(25)),
        }
    }

    let _ = child.wait().expect("Failed to collect MCP server status");
    let stdout = stdout_rx.into_iter().collect::<Vec<_>>().join("");
    let stderr = stderr_rx.into_iter().collect::<Vec<_>>().join("");
    (stdout, stderr)
}

/// Verify that tracing output appears only on stderr and stdout carries clean
/// JSON-RPC with no tracing contamination.
#[test]
fn test_tracing_stays_off_stdout_json_rpc_clean() {
    // A request that produces at least one finding triggers internal span/logging.
    let request = r#"{"jsonrpc":"2.0","method":"scan_string","params":["AWS_SECRET_KEY=abcdefghijk","test.rs"],"id":99}"#;

    let (stdout, _stderr) = send_mcp_request_with_stderr_capture(request);

    // --- stdout must be a single valid JSON-RPC response line ---
    let lines: Vec<_> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "stdout must have exactly one response line, got {} lines: {stdout:?}",
        lines.len()
    );

    let value: serde_json::Value =
        serde_json::from_str(lines[0]).expect("stdout must be valid JSON");
    assert_eq!(
        value["jsonrpc"], "2.0",
        "stdout must be a JSON-RPC 2.0 response"
    );
    assert_eq!(value["id"], 99, "stdout id must match request id");
    assert!(
        value.get("result").is_some(),
        "stdout must contain a result (not an error)"
    );

    // --- no tracing keywords on stdout ---
    let lower = stdout.to_lowercase();
    assert!(
        !lower.contains("tracing")
            && !lower.contains("span")
            && !lower.contains("debug")
            && !lower.contains("info"),
        "stdout must not contain tracing output, but got: {stdout}"
    );

    // --- result is a valid scan response ---
    let result = &value["result"];
    assert!(
        result.get("findings").is_some(),
        "result must be a scan response"
    );
    assert!(
        result["finding_count"].as_i64().unwrap_or(0) > 0,
        "AWS secret should produce a finding"
    );
}

#[test]
fn test_mcp_scan_dir_malformed_params_rejected() {
    for (label, request) in [
        (
            "non-string element",
            r#"{"jsonrpc":"2.0","method":"scan_dir","params":[42],"id":22}"#,
        ),
        (
            "legacy two-element tuple",
            r#"{"jsonrpc":"2.0","method":"scan_dir","params":["/tmp",false],"id":23}"#,
        ),
        (
            "empty params",
            r#"{"jsonrpc":"2.0","method":"scan_dir","params":[],"id":24}"#,
        ),
        (
            "object params",
            r#"{"jsonrpc":"2.0","method":"scan_dir","params":{"path":"."},"id":25}"#,
        ),
    ] {
        let response = send_mcp_request(request);
        let value = parse_single_response(&response);
        let error = value
            .get("error")
            .unwrap_or_else(|| panic!("malformed params ({label}) must be rejected: {response}"));
        assert_eq!(
            error["code"], -32602,
            "malformed params ({label}) must be InvalidParams: {response}"
        );
        assert!(value.get("result").is_none(), "Response: {response}");
    }
}
