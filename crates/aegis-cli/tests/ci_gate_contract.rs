//! The report contract the CI gate depends on.
//!
//! Control Center runs Aegis as a pre-pipeline gate: it spawns the binary,
//! parses the JSON report, and blocks the work request when the report
//! contains a high or critical finding. Every field that decision reads
//! — `findings`, `severity`, `id`, `pattern`, `category`,
//! `location.file`, `location.line` — and the exit code it correlates
//! with are pinned here, so a change to the report shape fails in this
//! repository instead of in the gate that depends on it.
//!
//! The evidence record for the integration is
//! `docs/audits/2026-11-16-gitforge-integration-evidence.md`.

use std::process::Command;

/// Runs the real binary against an isolated `XDG_CONFIG_HOME`, so a
/// developer's stored pattern state cannot change what these tests see.
struct ConfigGuard(tempfile::TempDir);

#[allow(clippy::expect_used)]
fn isolated_config() -> ConfigGuard {
    ConfigGuard(tempfile::TempDir::new().expect("create isolated config dir"))
}

impl ConfigGuard {
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_aegis"));
        command.env("XDG_CONFIG_HOME", self.0.path());
        command
    }
}

/// A critical credential that the gate must block on.
const CRITICAL_KEY: &str = "AKIAIOSFODNN7EXAMPLE"; // aegis:ignore:aws-access-key,env-credential-assignment -- synthetic fixtures

/// A finding below the gate's threshold.
const LOW_FINDING: &str = "first_name: 'Ada Lovelace'\n";

#[allow(clippy::unwrap_used)]
fn write(root: &std::path::Path, name: &str, content: &str) {
    std::fs::write(root.join(name), content).unwrap();
}

/// Collects every JSON key used anywhere in the document.
fn keys_in(value: &serde_json::Value, keys: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                keys.push(key.clone());
                keys_in(child, keys);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                keys_in(item, keys);
            }
        }
        _ => {}
    }
}

#[test]
fn test_report_carries_every_field_the_gate_decides_on() {
    let cfg = isolated_config();
    let root = tempfile::TempDir::new().unwrap();
    write(
        root.path(),
        "config.yaml",
        &format!("aws_key: {CRITICAL_KEY}\n"),
    );

    let output = cfg
        .command()
        .args([
            "--format",
            "json",
            "scan",
            root.path().to_str().unwrap(),
            "--severity-threshold",
            "high",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let document: serde_json::Value = serde_json::from_str(&stdout).expect("json report");

    let findings = document["findings"].as_array().expect("findings array");
    assert!(
        !findings.is_empty(),
        "the credential must be reported: {stdout}"
    );
    for finding in findings {
        assert!(finding["id"].is_string(), "id: {finding}");
        assert!(finding["pattern"].is_string(), "pattern: {finding}");
        assert!(finding["category"].is_string(), "category: {finding}");
        assert!(finding["severity"].is_string(), "severity: {finding}");
        assert!(
            finding["location"]["file"]
                .as_str()
                .is_some_and(|file| file.ends_with("config.yaml")),
            "the file must point at the scanned file: {finding}"
        );
        assert!(
            finding["location"]["line"]
                .as_u64()
                .is_some_and(|line| line >= 1),
            "the line must be a 1-based line number: {finding}"
        );
    }
    assert!(
        findings
            .iter()
            .any(|finding| finding["severity"] == "critical"),
        "the credential must be reported as critical: {stdout}"
    );
}

#[test]
fn test_report_never_carries_the_matched_secret() {
    let cfg = isolated_config();
    let root = tempfile::TempDir::new().unwrap();
    write(
        root.path(),
        "config.yaml",
        &format!("aws_key: {CRITICAL_KEY}\n"),
    );

    let output = cfg
        .command()
        .args(["--format", "json", "scan", root.path().to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains(CRITICAL_KEY),
        "the report must not echo the matched secret"
    );

    let document: serde_json::Value = serde_json::from_str(&stdout).expect("json report");
    let mut keys = Vec::new();
    keys_in(&document, &mut keys);
    for forbidden in ["matched_content", "matched_text", "content"] {
        assert!(
            !keys.iter().any(|key| key == forbidden),
            "the report must not carry `{forbidden}`: {keys:?}"
        );
    }
}

#[test]
fn test_exit_code_one_when_a_blocking_finding_is_present() {
    let cfg = isolated_config();
    let root = tempfile::TempDir::new().unwrap();
    write(
        root.path(),
        "config.yaml",
        &format!("aws_key: {CRITICAL_KEY}\n"),
    );

    let output = cfg
        .command()
        .args([
            "--format",
            "json",
            "scan",
            root.path().to_str().unwrap(),
            "--severity-threshold",
            "high",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "a blocking finding must fail the run: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn test_exit_code_zero_when_only_findings_below_the_threshold_are_present() {
    let cfg = isolated_config();
    let root = tempfile::TempDir::new().unwrap();
    write(root.path(), "profile.txt", LOW_FINDING);

    let output = cfg
        .command()
        .args([
            "--format",
            "json",
            "scan",
            root.path().to_str().unwrap(),
            "--severity-threshold",
            "high",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a finding below the threshold must not block: {stdout}"
    );
    let document: serde_json::Value = serde_json::from_str(&stdout).expect("json report");
    assert!(
        document["findings"]
            .as_array()
            .expect("findings array")
            .is_empty(),
        "the threshold must also filter the report: {stdout}"
    );
}

#[test]
fn test_report_exposes_the_inspection_ledger() {
    let cfg = isolated_config();
    let root = tempfile::TempDir::new().unwrap();
    write(
        root.path(),
        "config.yaml",
        &format!("aws_key: {CRITICAL_KEY}\n"),
    );

    let output = cfg
        .command()
        .args(["--format", "json", "scan", root.path().to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let document: serde_json::Value = serde_json::from_str(&stdout).expect("json report");
    let units = document["stats"]["inspection_ledger"]["units"]
        .as_array()
        .expect("the ledger must list the inspected units");
    assert!(
        !units.is_empty(),
        "every inspection must be recorded: {stdout}"
    );
    let unit = &units[0];
    assert!(unit["unit_id"].is_string(), "unit_id: {unit}");
    assert!(unit["status"].is_string(), "status: {unit}");
    assert!(unit["required"].is_boolean(), "required: {unit}");
}

#[test]
fn test_a_missing_scan_root_fails_closed() {
    let cfg = isolated_config();
    let missing = std::env::temp_dir().join("aegis_ci_gate_missing_root");
    let output = cfg
        .command()
        .args(["--format", "json", "scan", missing.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "a scan that never ran must not report success"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("\"findings\""),
        "a failed scan must not emit a report the gate could read as clean: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}
