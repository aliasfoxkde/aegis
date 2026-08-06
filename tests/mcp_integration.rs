//! Integration tests for Aegis MCP server

use std::io::Write;

fn send_mcp_request(request: &str) -> String {
    let mut child = std::process::Command::new("cargo")
        .args([
            "run", "--package", "aegis-mcp", "--bin", "aegis-mcp", "--quiet",
        ])
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
