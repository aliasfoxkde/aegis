//! End-to-end integration tests for the `aegis adapter scan` subcommand.
//!
//! These tests run the real binary, hit the real CLI surface, and verify
//! the documented fail-closed contract end-to-end. They mirror the unit
//! tests in `crates/aegis-cli/src/adapter.rs` but exercise clap parsing,
//! exit-code handling, stdout/stderr separation, and the JSON response
//! shape that downstream platforms (Control Center, GitForge) parse.
//!
//! All file-system and process IO is sandboxed under
//! `std::env::temp_dir()` to avoid touching the repository working tree.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn aegis_cmd() -> Command {
    let mut cmd = Command::new("cargo");
    cmd.args([
        "run",
        "--quiet",
        "--package",
        "aegis-cli",
        "--bin",
        "aegis",
        "--",
    ]);
    cmd
}

fn write_temp_file(name: &str, body: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "aegis_adapter_cli_{}_{}_{}",
        std::process::id(),
        name,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::write(&path, body).expect("write temp fixture");
    path
}

fn parse_stdout_json(stdout: &[u8]) -> Value {
    let body = std::str::from_utf8(stdout).expect("stdout is utf-8");
    serde_json::from_str(body).unwrap_or_else(|error| {
        panic!("stdout is not valid JSON: {error}\nbody: {body}");
    })
}

#[test]
fn adapter_scan_clean_content_returns_pass_exit_zero() {
    let output = aegis_cmd()
        .args([
            "adapter",
            "scan",
            "--work-request-id",
            "wr-int-clean-001",
            "--source",
            "src/main.rs",
            "--content",
            "fn main() { println!(\"hello\"); }\n",
        ])
        .output()
        .expect("spawn aegis");

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output.stdout);
    assert_eq!(json["work_request_id"], "wr-int-clean-001");
    assert_eq!(json["scan_result"], "pass");
    assert_eq!(json["allows_work"], true);
    assert_eq!(json["finding_count"], 0);
    assert_eq!(json["lifecycle_state"], "completed");
    assert_eq!(json["transition_count"], 4);
    assert!(json["evidence_ref"].as_str().unwrap().len() == 64);
    assert!(json.get("error").is_none() || json["error"].is_null());
}

#[test]
fn adapter_scan_missing_content_returns_blocked_with_exit_two() {
    let output = aegis_cmd()
        .args([
            "adapter",
            "scan",
            "--work-request-id",
            "wr-int-missing-001",
            "--source",
            "src/main.rs",
        ])
        .output()
        .expect("spawn aegis");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output.stdout);
    assert_eq!(json["scan_result"], "blocked");
    assert_eq!(json["allows_work"], false);
    assert!(
        json["error"].as_str().unwrap_or("").contains("--content"),
        "error field should mention the missing flag: {}",
        json["error"]
    );
}

#[test]
fn adapter_scan_empty_content_returns_blocked_with_exit_two() {
    let output = aegis_cmd()
        .args([
            "adapter",
            "scan",
            "--work-request-id",
            "wr-int-empty-001",
            "--source",
            "src/main.rs",
            "--content",
            "",
        ])
        .output()
        .expect("spawn aegis");

    assert_eq!(output.status.code(), Some(2));
    let json = parse_stdout_json(&output.stdout);
    assert_eq!(json["scan_result"], "blocked");
    assert_eq!(json["allows_work"], false);
}

#[test]
fn adapter_scan_empty_work_request_id_returns_blocked() {
    let output = aegis_cmd()
        .args([
            "adapter",
            "scan",
            "--work-request-id",
            "",
            "--source",
            "src/main.rs",
            "--content",
            "fn main() {}",
        ])
        .output()
        .expect("spawn aegis");

    assert_eq!(output.status.code(), Some(2));
    let json = parse_stdout_json(&output.stdout);
    assert_eq!(json["scan_result"], "blocked");
    assert!(json["error"].as_str().unwrap_or("").contains("empty"));
}

#[test]
fn adapter_scan_both_content_and_content_file_rejected() {
    let fixture = write_temp_file("both_flags", "fn main() {}\n");
    let output = aegis_cmd()
        .args([
            "adapter",
            "scan",
            "--work-request-id",
            "wr-int-both-001",
            "--source",
            "src/main.rs",
            "--content",
            "fn main() {}\n",
            "--content-file",
        ])
        .arg(&fixture)
        .output()
        .expect("spawn aegis");

    std::fs::remove_file(&fixture).ok();

    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output.stdout);
    assert_eq!(json["scan_result"], "blocked");
    assert!(json["error"].as_str().unwrap_or("").contains("exactly one"));
}

#[test]
fn adapter_scan_reads_content_file_and_reports_pass() {
    let fixture = write_temp_file(
        "content_file",
        "fn shipped() { println!(\"from file\"); }\n",
    );
    let output = aegis_cmd()
        .args([
            "adapter",
            "scan",
            "--work-request-id",
            "wr-int-file-001",
            "--source",
            "src/lib.rs",
            "--content-file",
        ])
        .arg(&fixture)
        .output()
        .expect("spawn aegis");

    std::fs::remove_file(&fixture).ok();

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output.stdout);
    assert_eq!(json["scan_result"], "pass");
    assert_eq!(json["work_request_id"], "wr-int-file-001");
}

#[test]
fn adapter_scan_missing_content_file_is_blocked() {
    let output = aegis_cmd()
        .args([
            "adapter",
            "scan",
            "--work-request-id",
            "wr-int-missing-file-001",
            "--source",
            "src/lib.rs",
            "--content-file",
            "/definitely/does/not/exist/aegis_integration.rs",
        ])
        .output()
        .expect("spawn aegis");

    assert_eq!(output.status.code(), Some(2));
    let json = parse_stdout_json(&output.stdout);
    assert_eq!(json["scan_result"], "blocked");
    assert!(json["error"]
        .as_str()
        .unwrap_or("")
        .contains("failed to read"));
}

#[test]
fn adapter_scan_persists_redacted_evidence_to_output_path() {
    let evidence_path = std::env::temp_dir().join(format!(
        "aegis_adapter_cli_int_evidence_{}.json",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));

    let output = aegis_cmd()
        .args([
            "adapter",
            "scan",
            "--work-request-id",
            "wr-int-evidence-001",
            "--source",
            "src/lib.rs",
            "--content",
            "fn safe() {}\n",
            "--evidence-output",
        ])
        .arg(&evidence_path)
        .output()
        .expect("spawn aegis");

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output.stdout);
    assert_eq!(
        json["evidence_path"].as_str().unwrap_or(""),
        evidence_path.to_string_lossy()
    );

    let persisted = std::fs::read_to_string(&evidence_path).expect("read evidence");
    assert!(persisted.contains("wr-int-evidence-001"));
    assert!(persisted.contains("\"pass\""));
    // The CLI must never echo the raw scanned content into evidence JSON.
    assert!(!persisted.contains("fn safe()"));

    std::fs::remove_file(&evidence_path).ok();
}

#[test]
fn adapter_scan_idempotent_replay_returns_same_result() {
    let cmd = || {
        aegis_cmd()
            .args([
                "adapter",
                "scan",
                "--work-request-id",
                "wr-int-idempotent-001",
                "--source",
                "src/lib.rs",
                "--content",
                "fn idempotent() {}\n",
            ])
            .output()
            .expect("spawn aegis")
    };
    let first = cmd();
    let second = cmd();
    assert_eq!(first.status.code(), Some(0));
    assert_eq!(second.status.code(), Some(0));
    let first_json = parse_stdout_json(&first.stdout);
    let second_json = parse_stdout_json(&second.stdout);
    assert_eq!(first_json["evidence_ref"], second_json["evidence_ref"]);
    assert_eq!(first_json["scan_result"], second_json["scan_result"]);
}

#[test]
fn adapter_help_lists_subcommand() {
    let output = aegis_cmd()
        .args(["adapter", "--help"])
        .output()
        .expect("spawn aegis");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("scan"), "stdout: {stdout}");
    assert!(stdout.contains("Control Center"), "stdout: {stdout}");
}

#[test]
fn adapter_scan_help_describes_required_flags() {
    let output = aegis_cmd()
        .args(["adapter", "scan", "--help"])
        .output()
        .expect("spawn aegis");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--work-request-id"), "stdout: {stdout}");
    assert!(stdout.contains("--source"), "stdout: {stdout}");
    assert!(stdout.contains("--content"), "stdout: {stdout}");
    assert!(stdout.contains("--content-file"), "stdout: {stdout}");
    assert!(stdout.contains("--evidence-output"), "stdout: {stdout}");
}
