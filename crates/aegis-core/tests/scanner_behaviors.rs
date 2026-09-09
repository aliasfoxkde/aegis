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

// ---------------------------------------------------------------------------
// Statistical anomaly post-pass
// ---------------------------------------------------------------------------

/// A quiet code file: near-zero comment share, healthy identifier variety.
fn uniform_file(index: usize) -> String {
    let mut lines = vec![format!("// routine module number {index}")];
    for n in 0..99_u32 {
        lines.push(format!("let value_{n}_{index} = {n} * {index};"));
    }
    lines.join("\n") + "\n"
}

/// A file that narrates almost everything: the comment-ratio outlier shape.
fn narrated_file() -> String {
    let mut lines = Vec::new();
    for n in 0..95_u32 {
        lines.push(format!("// step {n}: restate the arithmetic in prose"));
    }
    for n in 0..5_u32 {
        lines.push(format!("let value_{n} = {n} + 1;"));
    }
    lines.join("\n") + "\n"
}

/// Ten quiet files plus one heavily narrated outlier.
fn anomaly_fixture() -> TempDir {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    for index in 0..10 {
        std::fs::write(src.join(format!("unit_{index}.rs")), uniform_file(index)).unwrap();
    }
    std::fs::write(src.join("narrated.rs"), narrated_file()).unwrap();
    temp
}

fn statistical(findings: &[aegis_core::Finding]) -> Vec<&aegis_core::Finding> {
    findings
        .iter()
        .filter(|f| f.category == "statistical-anomaly")
        .collect()
}

#[test]
fn statistical_anomalies_are_reported_as_info_findings() {
    let temp = anomaly_fixture();
    let scanner = bundled_scanner();

    let (findings, stats) = scanner.scan_dir(temp.path()).unwrap();
    let anomalies = statistical(&findings);

    assert!(
        anomalies.iter().any(
            |f| f.pattern == "comment-ratio-outlier" && f.location.file.contains("narrated.rs")
        ),
        "the narrated file must be flagged as a comment-ratio outlier, got: {:?}",
        anomalies
            .iter()
            .map(|f| f.pattern.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        anomalies
            .iter()
            .all(|f| f.severity == "info" && f.confidence == "low"),
        "anomaly observations are informational, not verdicts"
    );
    assert!(
        stats.findings_by_severity.get("info").copied().unwrap_or(0) >= 1,
        "info observations must be reflected in the stats aggregate"
    );
}

#[test]
fn repeated_scans_do_not_duplicate_anomaly_observations() {
    // The metrics sink must be per-walk: leftover metrics from a previous
    // run would otherwise skew every later scan of the same scanner.
    let temp = anomaly_fixture();
    let scanner = bundled_scanner();

    let (first, _) = scanner.scan_dir(temp.path()).unwrap();
    let (second, _) = scanner.scan_dir(temp.path()).unwrap();

    assert_eq!(statistical(&first).len(), statistical(&second).len());
    assert!(
        !statistical(&second).is_empty(),
        "a fresh scan must still observe the same outliers"
    );
}

#[test]
fn severity_threshold_suppresses_info_observations() {
    let temp = anomaly_fixture();
    let definitions = aegis_patterns::all_patterns()
        .into_iter()
        .map(Into::into)
        .collect();
    let scanner = Scanner::from_definitions(definitions)
        .unwrap()
        .with_options(ScanOptions {
            severity_threshold: Some("low".to_string()),
            ..ScanOptions::default()
        });

    let (findings, _) = scanner.scan_dir(temp.path()).unwrap();
    assert!(
        statistical(&findings).is_empty(),
        "a low-severity threshold excludes weight-zero info observations"
    );
}

#[test]
fn single_file_scans_never_emit_or_leak_anomaly_observations() {
    // Anomalies are repository-shape observations: a lone file has no
    // baseline to deviate from, and its metrics must not pollute the next
    // directory walk performed with the same scanner.
    let dir_temp = TempDir::new().unwrap();
    let src = dir_temp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    for index in 0..10 {
        std::fs::write(src.join(format!("unit_{index}.rs")), uniform_file(index)).unwrap();
    }

    let single_temp = TempDir::new().unwrap();
    let lone = single_temp.path().join("narrated.rs");
    std::fs::write(&lone, narrated_file()).unwrap();

    let scanner = bundled_scanner();
    let (single_findings, _) = scanner.scan_file(&lone).unwrap();
    assert!(statistical(&single_findings).is_empty());

    let (dir_findings, _) = scanner.scan_dir(&src).unwrap();
    assert!(
        statistical(&dir_findings).is_empty(),
        "stale single-file metrics must not seed the next walk's statistics"
    );
}

#[test]
fn anomaly_allow_list_restricts_detectors() {
    // The narrated fixture trips comment-ratio; allowing only the
    // file-size detector must suppress it and run nothing else.
    let temp = anomaly_fixture();
    let definitions = aegis_patterns::all_patterns()
        .into_iter()
        .map(Into::into)
        .collect();
    let scanner = Scanner::from_definitions(definitions)
        .unwrap()
        .with_options(ScanOptions {
            anomaly_detectors: Some(vec!["file-size-outlier".to_string()]),
            ..ScanOptions::default()
        });

    let (findings, _) = scanner.scan_dir(temp.path()).unwrap();
    let anomalies = statistical(&findings);
    assert!(
        anomalies.iter().all(|f| f.pattern == "file-size-outlier"),
        "only the allowed detector may report, got: {:?}",
        anomalies
            .iter()
            .map(|f| f.pattern.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn empty_anomaly_allow_list_disables_the_layer() {
    let temp = anomaly_fixture();
    let definitions = aegis_patterns::all_patterns()
        .into_iter()
        .map(Into::into)
        .collect();
    let scanner = Scanner::from_definitions(definitions)
        .unwrap()
        .with_options(ScanOptions {
            anomaly_detectors: Some(Vec::new()),
            ..ScanOptions::default()
        });

    let (findings, stats) = scanner.scan_dir(temp.path()).unwrap();
    assert!(
        statistical(&findings).is_empty(),
        "an empty allow-list disables every detector"
    );
    assert_eq!(stats.findings_by_severity.get("info"), None);
}
