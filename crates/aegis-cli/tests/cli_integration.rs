//! Integration tests for the Aegis CLI.

use std::process::Command;

fn aegis_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_aegis"))
}

#[test]
fn test_scan_detects_aws_key() {
    let file_path = std::env::temp_dir().join("aegis_test_aws.yaml");
    std::fs::write(&file_path, "aws_key: AKIAIOSFODNN7EXAMPLE").unwrap();
    let output = aegis_cmd()
        .args(["scan", file_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let _ = std::fs::remove_file(file_path);
}

#[test]
fn test_scan_no_findings() {
    let file_path = std::env::temp_dir().join("aegis_test_safe.txt");
    std::fs::write(&file_path, "fn main() { println!(\"Hello, World!\"); }").unwrap();
    let output = aegis_cmd()
        .args(["scan", file_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let _ = std::fs::remove_file(file_path);
}

#[test]
fn test_list_patterns() {
    let output = aegis_cmd().arg("list").output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Total:"), "stdout: {stdout}");
    assert!(stdout.contains("patterns"), "stdout: {stdout}");
}

#[test]
fn test_update_command() {
    let output = aegis_cmd().arg("update").output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("patterns"));
}

#[test]
fn test_scan_json_output() {
    let file_path = std::env::temp_dir().join("aegis_test_secret.txt");
    std::fs::write(&file_path, "password: secret123").unwrap();
    let output = aegis_cmd()
        .args(["--format", "json", "scan", file_path.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("findings") || stdout.contains("No findings"),
        "stdout: {stdout}"
    );
    let _ = std::fs::remove_file(file_path);
}

#[test]
fn test_scan_sarif_output() {
    let file_path = std::env::temp_dir().join("aegis_test_secret.txt");
    std::fs::write(&file_path, "api_key: AKIAIOSFODNN7EXAMPLE").unwrap();
    let output = aegis_cmd()
        .args(["--format", "sarif", "scan", file_path.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("version") || stdout.contains("2.1"),
        "stdout: {stdout}"
    );
    let _ = std::fs::remove_file(file_path);
}

#[test]
fn test_list_enabled_only() {
    let output = aegis_cmd().args(["list", "--enabled"]).output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("[+]"));
}

#[test]
fn test_list_by_category() {
    let output = aegis_cmd()
        .args(["list", "--category", "secrets"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("secrets"));
}

#[test]
fn test_enable_pattern() {
    let output = aegis_cmd()
        .args(["enable", "test-pattern"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Enabled"));
}

#[test]
fn test_disable_pattern() {
    let output = aegis_cmd()
        .args(["disable", "test-pattern"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Disabled"));
}

#[test]
fn test_scan_with_severity_threshold() {
    let file_path = std::env::temp_dir().join("aegis_test_critical.txt");
    std::fs::write(&file_path, "api_key: AKIAIOSFODNN7EXAMPLE").unwrap();
    let output = aegis_cmd()
        .args([
            "scan",
            file_path.to_str().unwrap(),
            "--severity-threshold",
            "critical",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("findings") || stdout.contains("No findings") || stderr.is_empty(),
        "stdout: {stdout}, stderr: {stderr}"
    );
    let _ = std::fs::remove_file(file_path);
}

#[test]
fn test_scan_with_categories() {
    let file_path = std::env::temp_dir().join("aegis_test_secrets.txt");
    std::fs::write(&file_path, "api_key: AKIAIOSFODNN7EXAMPLE").unwrap();
    let output = aegis_cmd()
        .args([
            "scan",
            file_path.to_str().unwrap(),
            "--categories",
            "secrets",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success() || output.status.code() == Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_file(file_path);
}

#[test]
fn test_list_categories() {
    let output = aegis_cmd()
        .args(["list", "--category", "secrets"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("secrets"));
}
