//! Behavioral coverage for the scanner's diff mode, baseline fallback, and
//! walk-error accounting. These live as integration tests because they build
//! a scanner from the bundled pattern corpus through the canonical
//! `From<Pattern>` conversion, whose types only line up when the crates are
//! used externally.

use aegis_core::{InspectionStatus, ScanOptions, Scanner};
use tempfile::TempDir;

/// Build a scanner over the full bundled pattern set.
// Test-only helpers, but not `#[test]` functions, so clippy.toml's
// test exemptions do not reach them.
#[allow(clippy::unwrap_used)]
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
@@ -1,2 +1,2 @@
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

    // The addition is the second line of the new file (one context line
    // precedes it in the hunk); the deleted file has no post-image and
    // contributes nothing.
    assert_eq!(
        changed,
        vec![(
            "src/app.rs".to_string(),
            "let token = \"added\";".to_string(),
            2
        )]
    );
}

#[test]
fn parse_diff_ignores_additions_before_any_file_header() {
    let diff = "+orphaned addition\n+++ b/src/late.rs\n@@ -0,0 +1 @@\n+attributed addition\n";
    let changed = Scanner::parse_diff(diff);

    // An addition is only reported when both a `+++` header (which file)
    // and an enclosing `@@` hunk (which line) anchor it; the orphaned
    // addition has neither and is dropped rather than guessed.
    assert_eq!(
        changed,
        vec![(
            "src/late.rs".to_string(),
            "attributed addition".to_string(),
            1
        )]
    );
}

#[test]
fn parse_diff_reports_target_file_lines_across_hunks() {
    let diff = "\
--- a/src/app.rs
+++ b/src/app.rs
@@ -7,3 +7,4 @@
 unchanged context
+let first = \"inserted\";
 more context
 yet more context
@@ -40,3 +45,4 @@
 gap context
+let second = \"inserted\";
 trailing context
 last context
";
    let changed = Scanner::parse_diff(diff);

    // Line numbers must come from each hunk's post-image start (7 and 45),
    // not from the position within the joined addition-only text (1 and 2).
    assert_eq!(
        changed,
        vec![
            (
                "src/app.rs".to_string(),
                "let first = \"inserted\";".to_string(),
                8
            ),
            (
                "src/app.rs".to_string(),
                "let second = \"inserted\";".to_string(),
                46
            ),
        ]
    );
}

#[test]
fn parse_diff_headers_tolerate_timestamps_quotes_and_spaced_paths() {
    // Plain `diff -u` appends a tab-separated timestamp after the path;
    // git C-quotes paths containing quotes, backslashes, control
    // characters, or non-ASCII bytes (spaces pass through unquoted).
    let diff = concat!(
        "--- a/docs/my notes.md\n",
        "+++ b/docs/my notes.md\t2026-10-04 10:00:00.000000000 +0000\n",
        "@@ -1 +1,2 @@\n",
        " anchor\n",
        "+timestamped path keeps its spaces\n",
        "--- a/src/app.rs\n",
        "+++ \"b/src/caf\\303\\251.rs\"\n",
        "@@ -1 +1,2 @@\n",
        " anchor\n",
        "+git octal-quoted path decodes\n",
        "--- a/src/app.rs\n",
        "+++ \"b/name with \\\"quote\\\".rs\"\t2026-10-04 10:00:00 +0000\n",
        "@@ -1 +1,2 @@\n",
        " anchor\n",
        "+quoted path drops the closing-quote timestamp\n",
    );
    let changed = Scanner::parse_diff(diff);

    // Octal escapes decode to raw bytes, so `caf\303\251` reassembles the
    // two UTF-8 bytes of `é`; timestamps never leak into the path.
    assert_eq!(
        changed,
        vec![
            (
                "docs/my notes.md".to_string(),
                "timestamped path keeps its spaces".to_string(),
                2
            ),
            (
                "src/caf\u{e9}.rs".to_string(),
                "git octal-quoted path decodes".to_string(),
                2
            ),
            (
                "name with \"quote\".rs".to_string(),
                "quoted path drops the closing-quote timestamp".to_string(),
                2
            ),
        ]
    );
}

#[test]
fn parse_diff_drops_additions_under_malformed_quoted_headers() {
    // A quoted header that never closes, or hides an escape git never
    // emits, has no trustworthy path: the additions under it are dropped
    // instead of attributed to a guessed name, and a later well-formed
    // header recovers attribution.
    let diff = concat!(
        "+++ \"b/src/unterminated.rs\n",
        "@@ -0,0 +1 @@\n",
        "+orphaned by an unterminated quote\n",
        "+++ \"b/src/bad\\xescape.rs\"\n",
        "@@ -0,0 +1 @@\n",
        "+orphaned by an unknown escape\n",
        "+++ \"b/src/out-of-range\\400.rs\"\n",
        "@@ -0,0 +1 @@\n",
        "+orphaned by an out-of-range octal escape\n",
        "+++ b/src/recovered.rs\n",
        "@@ -1 +1,2 @@\n",
        " anchor\n",
        "+attributed after the malformed headers\n",
    );
    let changed = Scanner::parse_diff(diff);

    assert_eq!(
        changed,
        vec![(
            "src/recovered.rs".to_string(),
            "attributed after the malformed headers".to_string(),
            2
        )]
    );
}

#[test]
fn parse_diff_never_invents_sources_for_deleted_renamed_or_binary_files() {
    // The `+`-prefixed line in the last section is a base85 binary-patch
    // body line (git's alphabet includes `+`); it sits outside any hunk and
    // must not be attributed to `patch.bin`.
    let diff = "\
diff --git a/src/gone.rs b/src/gone.rs
deleted file mode 100644
index 1111111..0000000
--- a/src/gone.rs
+++ /dev/null
@@ -1,2 +0,0 @@
-was here
-gone too
diff --git a/src/moved.rs b/src/renamed.rs
similarity index 90%
rename from src/moved.rs
rename to src/renamed.rs
--- a/src/moved.rs
+++ b/src/renamed.rs
@@ -1 +1,2 @@
 context of rename
+rename addition lands on the new name
diff --git a/patch.bin b/patch.bin
index 3333333..4444444 100644
--- a/patch.bin
+++ b/patch.bin
GIT binary patch
literal 8
+cmZPEeSPk&3v
";
    let changed = Scanner::parse_diff(diff);

    // Only the rename's addition survives, on the new path: a deletion has
    // no post-image, and a binary body never enters a hunk.
    assert_eq!(
        changed,
        vec![(
            "src/renamed.rs".to_string(),
            "rename addition lands on the new name".to_string(),
            2
        )]
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
fn scan_diff_reports_original_line_numbers_across_hunks() {
    let scanner = bundled_scanner();
    // Identical credential lines in two hunks: only the attribution can
    // tell them apart, so the reported lines must be the hunk anchors
    // (4 and 55), not positions in the joined addition-only text (1 and 2).
    let added = "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"";
    let diff = format!(
        "\
--- a/config/prod.env
+++ b/config/prod.env
@@ -3 +3,2 @@
 existing = \"untouched\"
+{added}
@@ -50 +54,2 @@
 later = \"also untouched\"
+{added}
"
    );
    let findings = scanner.scan_diff(&diff, "diff");

    assert!(
        findings.iter().any(|f| f.pattern == "aws-access-key"),
        "both added credential lines must be reported, got: {:?}",
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

    let mut lines: Vec<usize> = findings.iter().map(|f| f.location.line).collect();
    lines.sort_unstable();
    lines.dedup();
    assert!(
        lines.contains(&4) && lines.contains(&55),
        "findings must carry the target-file line numbers 4 and 55, got: {lines:?}"
    );
    assert!(
        lines.iter().all(|line| *line >= 4),
        "no finding may fall back to a position in the joined addition text, got: {lines:?}"
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

// ---------------------------------------------------------------------------
// Diff scanning x baseline ordering
// ---------------------------------------------------------------------------

/// The credential line the fixtures in this section add.
const SECRET_LINE: &str = "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"";

/// The four-line post-image the diff adds to: the credential's real target
/// line is 4, while inside the diff's joined addition-only text it is line 1.
fn secret_post_image() -> String {
    format!("a=1\nb=2\nc=3\n{SECRET_LINE}\n")
}

/// A diff whose single addition lands on target line 4 of `config/prod.env`.
fn diff_adding_secret_at_target_line_4() -> String {
    format!(
        "\
--- a/config/prod.env
+++ b/config/prod.env
@@ -1,3 +1,4 @@
 a=1
 b=2
 c=3
+{SECRET_LINE}
"
    )
}

/// Write a baseline file holding `fingerprints` in the bare-array form
/// `load_baseline_fingerprints` accepts.
#[allow(clippy::unwrap_used)] // test fixture builder, not a `#[test]` fn
fn baseline_file(dir: &std::path::Path, fingerprints: &[String]) -> std::path::PathBuf {
    let path = dir.join("baseline.json");
    let entries: Vec<serde_json::Value> = fingerprints
        .iter()
        .map(|fingerprint| serde_json::json!({ "fingerprint": fingerprint }))
        .collect();
    std::fs::write(&path, serde_json::to_string(&entries).unwrap()).unwrap();
    path
}

#[test]
fn diff_baseline_at_the_real_target_line_suppresses_the_finding() {
    let temp = TempDir::new().unwrap();

    // The baseline mirrors a previous full-file scan of the post-image, so
    // its credential fingerprint sits at the real target line (4).
    let known = bundled_scanner().scan_string(&secret_post_image(), "config/prod.env");
    let known_key = known
        .iter()
        .find(|f| f.pattern == "aws-access-key" && f.location.line == 4)
        .expect("fixture must flag the credential at target line 4");
    let baseline = baseline_file(temp.path(), std::slice::from_ref(&known_key.fingerprint));

    let scanner = bundled_scanner().with_options(ScanOptions {
        baseline: Some(baseline),
        ..Default::default()
    });

    let findings = scanner.scan_diff(&diff_adding_secret_at_target_line_4(), "diff");
    assert!(
        findings.is_empty(),
        "a baseline entry recorded at the real target line must suppress \
         the diff finding, got: {findings:?}"
    );
}

#[test]
fn diff_baseline_at_a_synthetic_line_does_not_suppress_a_different_real_line() {
    let temp = TempDir::new().unwrap();

    // A fingerprint keyed the way a pre-remap diff finding would carry it:
    // same pattern, file, and content, but at the synthetic joined-text
    // line (1). It must not silence a finding whose real target line is 4.
    let synthetic = bundled_scanner().scan_string(SECRET_LINE, "config/prod.env");
    let synthetic_key = synthetic
        .iter()
        .find(|f| f.pattern == "aws-access-key")
        .expect("fixture must flag the bare credential line");
    assert_eq!(
        synthetic_key.location.line, 1,
        "fixture precondition: the bare line scans at synthetic line 1"
    );
    let baseline = baseline_file(
        temp.path(),
        std::slice::from_ref(&synthetic_key.fingerprint),
    );

    let scanner = bundled_scanner().with_options(ScanOptions {
        baseline: Some(baseline),
        ..Default::default()
    });

    let findings = scanner.scan_diff(&diff_adding_secret_at_target_line_4(), "diff");
    let survivors: Vec<&aegis_core::Finding> = findings
        .iter()
        .filter(|f| f.pattern == "aws-access-key")
        .collect();
    assert!(
        !survivors.is_empty(),
        "a baseline keyed at the synthetic line must not suppress a finding \
         whose real target line differs"
    );
    assert!(
        survivors
            .iter()
            .all(|f| f.location.file == "config/prod.env" && f.location.line == 4),
        "the surviving finding must carry real target coordinates, got: {survivors:?}"
    );
}

#[cfg(unix)]
#[test]
fn unreadable_directory_entries_are_ledgered_as_failed() {
    use std::os::unix::fs::PermissionsExt;

    // The premise is that mode 000 denies entry. Root (CI containers
    // commonly run as root) bypasses file permissions entirely, so the
    // directory stays readable and the all-failed contract cannot be
    // exercised there — skip rather than fail.
    let permissions_deny = |dir: &std::path::Path| {
        std::fs::File::open(dir).is_err() && std::fs::read_dir(dir).is_err()
    };

    let temp = TempDir::new().unwrap();
    let locked = temp.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::write(locked.join("hidden.txt"), b"content").unwrap();

    let original_mode = std::fs::metadata(&locked).unwrap().permissions().mode();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

    if !permissions_deny(&locked) {
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(original_mode)).unwrap();
        return;
    }

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
#[allow(clippy::unwrap_used)] // test fixture builder, not a `#[test]` fn
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
