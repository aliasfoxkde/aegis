//! Behavioral coverage for the scanner's diff mode, baseline fallback, and
//! walk-error accounting. These live as integration tests because they build
//! a scanner from the bundled pattern corpus through the canonical
//! `From<Pattern>` conversion, whose types only line up when the crates are
//! used externally.

use aegis_core::{InspectionStatus, ScanOptions, Scanner};
use tempfile::TempDir;

/// Build a scanner over the full bundled pattern set.
fn bundled_scanner() -> Scanner {
    let definitions = aegis_patterns::all_patterns()
        .into_iter()
        .map(Into::into)
        .collect();
    Scanner::from_definitions(definitions).unwrap()
}

#[test]
fn parse_diff_extracts_only_added_lines_of_tracked_files() {
    let diff = "\
diff --git a/src/app.rs b/src/app.rs
--- a/src/app.rs
+++ b/src/app.rs
@@ -1,3 +1,4 @@
 context line stays out
+let token = \"added\";
-let removed = \"ignored\";
diff --git a/src/gone.rs b/src/gone.rs
deleted file mode 100644
--- a/src/gone.rs
+++ /dev/null
-println!(\"removed lines are never reported\");
";
    let changed = Scanner::parse_diff(diff);

    assert_eq!(
        changed,
        vec![(
            "src/app.rs".to_string(),
            "let token = \"added\";".to_string()
        )]
    );
}

#[test]
fn parse_diff_ignores_additions_before_any_file_header() {
    let diff = "+orphaned addition\n+++ b/src/late.rs\n+attributed addition\n";
    let changed = Scanner::parse_diff(diff);

    // An addition before any `+++` header has no file to belong to and is
    // dropped rather than guessed.
    assert_eq!(
        changed,
        vec![("src/late.rs".to_string(), "attributed addition".to_string())]
    );
}

#[test]
fn scan_diff_attributes_findings_to_the_real_file() {
    let scanner = bundled_scanner();
    let diff = "\
--- a/config/prod.env
+++ b/config/prod.env
@@ -0,0 +1 @@
+aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"
";
    let findings = scanner.scan_diff(diff, "diff");

    assert!(
        findings.iter().any(|f| f.pattern == "aws-access-key"),
        "added credential line must be reported, got: {:?}",
        findings
            .iter()
            .map(|f| f.pattern.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        findings
            .iter()
            .all(|f| f.location.file == "config/prod.env"),
        "findings must carry the diff file path"
    );
}

#[test]
fn baseline_load_failure_falls_back_to_unfiltered_scan() {
    let temp = TempDir::new().unwrap();
    let broken_baseline = temp.path().join("broken.json");
    std::fs::write(&broken_baseline, "{not json").unwrap();

    let scanner = bundled_scanner().with_options(ScanOptions {
        baseline: Some(broken_baseline),
        ..Default::default()
    });

    let findings = scanner.scan_string(
        "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"",
        "fallback.env",
    );
    assert!(
        findings.iter().any(|f| f.pattern == "aws-access-key"),
        "an unusable baseline must not silence findings"
    );
}

#[cfg(unix)]
#[test]
fn unreadable_directory_entries_are_ledgered_as_failed() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().unwrap();
    let locked = temp.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::write(locked.join("hidden.txt"), b"content").unwrap();

    let original_mode = std::fs::metadata(&locked).unwrap().permissions().mode();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

    let scanner = bundled_scanner();
    let result = scanner.scan_dir(temp.path());

    // Restore before asserting so the temp dir can always be cleaned up.
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(original_mode)).unwrap();

    // Fail closed: when every required unit failed to inspect, the scan is
    // an error carrying the stats rather than a silently empty success.
    let error = result.expect_err("an all-failed scan must error");
    let stats = match error {
        aegis_core::ScanError::AllRequiredFilesFailed { stats, .. } => stats,
        other => panic!("unexpected scan error: {other}"),
    };
    assert_eq!(stats.files_failed, 1);
    assert!(stats
        .inspection_ledger
        .units
        .iter()
        .any(|unit| { unit.status == InspectionStatus::Failed && unit.reason.is_some() }));
}
