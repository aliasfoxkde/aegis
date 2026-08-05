//! Integration tests for Aegis CLI

use std::process::Command;

#[test]
fn test_scan_detects_aws_key() {
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join("aegis_test_aws.yaml");
    std::fs::write(&file_path, "aws_key: AKIAIOSFODNN7EXAMPLE").unwrap();

    let output = Command::new("target/release/aegis")
        .args(["scan", &file_path.to_string_lossy()])
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

    let output = Command::new("target/release/aegis")
        .args(["scan", &file_path.to_string_lossy()])
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
    let output = Command::new("target/release/aegis")
        .args(["list"])
        .output()
        .unwrap();

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
    let output = Command::new("target/release/aegis")
        .args(["update"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("patterns"), "stdout: {}", stdout);
}
