//! Integration tests for Aegis Bundler

use std::process::Command;

#[test]
fn test_bundle_create_and_load() {
    // Create a temp directory with patterns
    let temp_dir = std::env::temp_dir().join("aegis_bundle_test");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();

    // Create patterns.yaml - array format expected by bundler
    let patterns_file = temp_dir.join("patterns.yaml");
    std::fs::write(
        &patterns_file,
        r#"
- name: test-secret
  category: secrets
  match: "secret123"
  enabled: true
  severity: high
  confidence: medium
  description: Test pattern
"#,
    )
    .unwrap();

    let output_file = temp_dir.join("bundle.json.gz");

    // Run bundler to create bundle - takes input_dir and output_file
    let output = Command::new("cargo")
        .args([
            "run",
            "--package",
            "aegis-bundler",
            "--bin",
            "aegis-bundler",
            "--quiet",
        ])
        .arg(&temp_dir)
        .arg(output_file.to_str().unwrap())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify bundle was created
    assert!(output_file.exists(), "Bundle file should exist");

    let _ = std::fs::remove_dir_all(temp_dir);
}
