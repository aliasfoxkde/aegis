//! Integration tests for Aegis MCP server

use std::io::{Read, Write};
use std::path::PathBuf;

fn mcp_binary() -> PathBuf {
    static BUILD: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BUILD
        .get_or_init(|| {
            let status = std::process::Command::new("cargo")
                .args([
                    "build",
                    "--package",
                    "aegis-mcp",
                    "--bin",
                    "aegis-mcp",
                    "--quiet",
                ])
                .status()
                .expect("Failed to build MCP server");
            assert!(status.success(), "MCP server build failed: {status}");

            let target_dir = std::env::var_os("CARGO_TARGET_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target"));
            target_dir.join("debug").join("aegis-mcp")
        })
        .clone()
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

    // Drain stdout concurrently so a large JSON-RPC response cannot fill the
    // pipe and deadlock the child before it exits.
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
        r#"{{"jsonrpc":"2.0","method":"scan_dir","params":[{:?},false],"id":5}}"#,
        fixture_dir.to_string_lossy()
    );
    let response = send_mcp_request(&request);
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
