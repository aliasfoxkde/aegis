//! Integration tests for Aegis CLI

use std::process::Command;

fn aegis_cmd() -> Command {
    let mut cmd = Command::new("cargo");
    cmd.args(["run", "--package", "aegis-cli", "--bin", "aegis", "--"]);
    cmd
}

#[test]
fn test_scan_detects_aws_key() {
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join("aegis_test_aws.yaml");
    std::fs::write(&file_path, "aws_key: AKIAIOSFODNN7EXAMPLE").unwrap();

    let output = aegis_cmd()
        .arg("scan")
        .arg(file_path.to_string_lossy().as_ref())
        .output()
        .unwrap();

    // Exit code 1 means findings were detected
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
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join("aegis_test_safe.txt");
    // Use content that shouldn't trigger any patterns
    std::fs::write(&file_path, "fn main() { println!(\"Hello, World!\"); }").unwrap();

    let output = aegis_cmd()
        .arg("scan")
        .arg(file_path.to_string_lossy().as_ref())
        .output()
        .unwrap();

    // Exit code 0 means no findings
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
    assert!(stdout.contains("Total:"), "stdout: {}", stdout);
    assert!(stdout.contains("patterns"), "stdout: {}", stdout);
}

#[test]
fn test_update_command() {
    let output = aegis_cmd().arg("update").output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("patterns"), "stdout: {}", stdout);
}

#[test]
fn test_scan_json_output() {
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join("aegis_test_secret.txt");
    std::fs::write(&file_path, "password: secret123").unwrap();

    let output = aegis_cmd()
        .args(["--format", "json", "scan", file_path.to_str().unwrap()])
        .output()
        .unwrap();

    // Should complete (findings or not)
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("findings") || stdout.contains("No findings"), "stdout: {}", stdout);
}

#[test]
fn test_scan_sarif_output() {
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join("aegis_test_secret.txt");
    std::fs::write(&file_path, "api_key: AKIAIOSFODNN7EXAMPLE").unwrap();

    let output = aegis_cmd()
        .args(["--format", "sarif", "scan", file_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    // SARIF output should contain version
    assert!(stdout.contains("version") || stdout.contains("2.1"), "stdout: {}", stdout);
}

#[test]
fn test_list_enabled_only() {
    let output = aegis_cmd()
        .args(["list", "--enabled"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should show [+]
    assert!(stdout.contains("[+]"), "stdout: {}", stdout);
}

#[test]
fn test_list_by_category() {
    let output = aegis_cmd()
        .args(["list", "--category", "secrets"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("secrets"), "stdout: {}", stdout);
}

#[test]
fn test_enable_pattern() {
    let output = aegis_cmd()
        .args(["enable", "test-pattern"])
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Enabled"), "stdout: {}", stdout);
}

#[test]
fn test_disable_pattern() {
    let output = aegis_cmd()
        .args(["disable", "test-pattern"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Disabled"), "stdout: {}", stdout);
}
