//! Integration tests for the Aegis CLI.

use std::process::Command;

/// Runs the real binary against an isolated `XDG_CONFIG_HOME`.
///
/// The CLI persists `aegis disable` choices under the user config
/// directory; tests must never touch the developer's actual pattern
/// state, and scan expectations must not depend on ambient machine
/// state. The [`ConfigGuard`] keeps the temporary directory alive for
/// the duration of the test.
struct ConfigGuard(tempfile::TempDir);

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

#[test]
fn test_cli_version_matches_package_version() {
    let cfg = isolated_config();
    let output = cfg.command().arg("--version").output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("aegis {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn test_scan_detects_aws_key() {
    let cfg = isolated_config();
    let file_path = std::env::temp_dir().join("aegis_test_aws.yaml");
    std::fs::write(&file_path, "aws_key: AKIAIOSFODNN7EXAMPLE").unwrap();
    let output = cfg
        .command()
        .args(["scan", file_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let _removed = std::fs::remove_file(file_path);
}

#[test]
fn test_scan_no_findings() {
    let cfg = isolated_config();
    let file_path = std::env::temp_dir().join("aegis_test_safe.txt");
    std::fs::write(&file_path, "fn main() { println!(\"Hello, World!\"); }").unwrap();
    let output = cfg
        .command()
        .args(["scan", file_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let _removed = std::fs::remove_file(file_path);
}

#[test]
fn test_list_patterns() {
    let cfg = isolated_config();
    let output = cfg.command().arg("list").output().unwrap();
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
    let cfg = isolated_config();
    let output = cfg.command().arg("update").output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("patterns"));
}

#[test]
fn test_scan_json_output() {
    let cfg = isolated_config();
    let file_path = std::env::temp_dir().join("aegis_test_secret.txt");
    std::fs::write(&file_path, "password: secret123").unwrap();
    let output = cfg
        .command()
        .args(["--format", "json", "scan", file_path.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("findings") || stdout.contains("No findings"),
        "stdout: {stdout}"
    );
    let _removed = std::fs::remove_file(file_path);
}

#[test]
fn test_scan_sarif_output() {
    let cfg = isolated_config();
    // Distinct fixture per test: cargo runs tests in parallel, and two
    // tests sharing one temp path race each other's write/remove.
    let file_path = std::env::temp_dir().join("aegis_test_sarif.txt");
    std::fs::write(&file_path, "api_key: AKIAIOSFODNN7EXAMPLE").unwrap();
    let output = cfg
        .command()
        .args(["--format", "sarif", "scan", file_path.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("version") || stdout.contains("2.1"),
        "stdout: {stdout}"
    );
    let _removed = std::fs::remove_file(file_path);
}

#[test]
fn test_list_enabled_only() {
    let cfg = isolated_config();
    let output = cfg.command().args(["list", "--enabled"]).output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("[+]"));
}

#[test]
fn test_list_by_category() {
    let cfg = isolated_config();
    let output = cfg
        .command()
        .args(["list", "--category", "secrets"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("secrets"));
}

#[test]
fn test_disable_then_enable_pattern_round_trips() {
    let cfg = isolated_config();
    let pattern = "secrets-aws-access-key";

    let disabled = cfg.command().args(["disable", pattern]).output().unwrap();
    assert!(
        disabled.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&disabled.stderr)
    );
    assert!(String::from_utf8_lossy(&disabled.stdout).contains("Disabled"));

    // The disablement is visible to `list --disabled` in the same state dir.
    let listed = cfg.command().args(["list", "--disabled"]).output().unwrap();
    assert!(String::from_utf8_lossy(&listed.stdout).contains(pattern));

    let enabled = cfg.command().args(["enable", pattern]).output().unwrap();
    assert!(
        enabled.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&enabled.stderr)
    );
    assert!(String::from_utf8_lossy(&enabled.stdout).contains("Enabled"));

    // And back out again: the pattern is enabled, so --disabled is empty.
    let listed = cfg.command().args(["list", "--disabled"]).output().unwrap();
    assert!(!String::from_utf8_lossy(&listed.stdout).contains(pattern));
}

#[test]
fn test_disable_unknown_pattern_fails_loud() {
    let cfg = isolated_config();
    let output = cfg
        .command()
        .args(["disable", "no-such-pattern"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "disabling an unknown pattern must fail, not no-op"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no-such-pattern"), "stderr: {stderr}");
    assert!(stderr.contains("aegis list"), "stderr: {stderr}");
}

#[test]
fn test_scan_with_severity_threshold() {
    let cfg = isolated_config();
    let file_path = std::env::temp_dir().join("aegis_test_critical.txt");
    std::fs::write(&file_path, "api_key: AKIAIOSFODNN7EXAMPLE").unwrap();
    let output = cfg
        .command()
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
    let _removed = std::fs::remove_file(file_path);
}

#[test]
fn test_scan_with_categories() {
    let cfg = isolated_config();
    let file_path = std::env::temp_dir().join("aegis_test_secrets.txt");
    std::fs::write(&file_path, "api_key: AKIAIOSFODNN7EXAMPLE").unwrap();
    let output = cfg
        .command()
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
    let _removed = std::fs::remove_file(file_path);
}

#[test]
fn test_list_categories() {
    let cfg = isolated_config();
    let output = cfg
        .command()
        .args(["list", "--category", "secrets"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("secrets"));
}

/// Fixture with two structurally identical, renamed regions — each long
/// enough to clear the detector's 40-token block size — plus no content any
/// shipped pattern flags, so the scan exits 0 and clone reporting is the
/// only observable output.
fn clone_fixture() -> String {
    // `bound`, not `limit`: identifiers followed by a space trip the
    // `missing-limit` (`LIMIT\s+`) rule, and the fixture must stay
    // findings-clean so the exit code proves clones never affect it.
    let region = |name: &str| {
        format!(
            "fn {name}(bound: i64) -> i64 {{\n\
             \x20   let mut aggregate = 0;\n\
             \x20   for index in 0..bound {{\n\
             \x20       aggregate += index * 3;\n\
             \x20       aggregate -= index / 5;\n\
             \x20       aggregate += bound % 11;\n\
             \x20   }}\n\
             \x20   let adjusted = aggregate - bound;\n\
             \x20   let scaled = adjusted * 6 + aggregate / 4;\n\
             \x20   scaled - adjusted + aggregate\n\
             }}\n"
        )
    };
    format!(
        "{}\n// a separating comment\n\n{}",
        region("first_region"),
        region("second_region")
    )
}

#[test]
fn test_scan_detect_clones_pins_json_shape_and_exit_code() {
    let cfg = isolated_config();
    let dir = tempfile::TempDir::new().unwrap();
    let file_path = dir.path().join("clones_fixture.rs");
    std::fs::write(&file_path, clone_fixture()).unwrap();

    let output = cfg
        .command()
        .args([
            "--format",
            "json",
            "scan",
            "--detect-clones",
            file_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    // Clones are detected but the fixture is clean: the exit code must stay
    // 0, proving clone reporting never turns a scan into a failure.
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let document: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).unwrap();
    let clones = document["stats"]["clones"]
        .as_array()
        .expect("clones array present in stats");
    assert!(!clones.is_empty(), "expected at least one clone pair");
    let first = &clones[0];
    assert!(
        first["kind"]
            .as_str()
            .is_some_and(|kind| kind.starts_with("type-")),
        "unexpected clone kind: {first}"
    );
    assert!(first["similarity"].as_f64().unwrap() >= 0.75);
    assert!(first["token_count"].as_u64().unwrap() > 0);
    let locations = first["locations"].as_array().unwrap();
    assert_eq!(locations.len(), 2);
    for location in locations {
        assert_eq!(location["file"], file_path.to_string_lossy().as_ref());
        let start = location["start_line"].as_u64().unwrap();
        let end = location["end_line"].as_u64().unwrap();
        assert!(start >= 1 && end >= start);
    }
    // The findings channel is untouched by clone detection.
    assert_eq!(document["stats"]["finding_count"], 0);
    assert_eq!(document["findings"].as_array().map(Vec::len), Some(0));
}

#[test]
fn test_scan_without_detect_clones_omits_the_clones_key() {
    let cfg = isolated_config();
    let dir = tempfile::TempDir::new().unwrap();
    let file_path = dir.path().join("clones_fixture.rs");
    std::fs::write(&file_path, clone_fixture()).unwrap();

    let output = cfg
        .command()
        .args(["--format", "json", "scan", file_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let document: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).unwrap();
    assert!(document["stats"].get("clones").is_none());
}

#[test]
fn test_scan_detect_clones_human_output_lists_pairs() {
    let cfg = isolated_config();
    let dir = tempfile::TempDir::new().unwrap();
    let file_path = dir.path().join("clones_fixture.rs");
    std::fs::write(&file_path, clone_fixture()).unwrap();

    let output = cfg
        .command()
        .args(["scan", "--detect-clones", file_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Code clones ("), "stdout: {stdout}");
    assert!(stdout.contains("Code clone at"), "stdout: {stdout}");
}
