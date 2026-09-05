#![cfg(feature = "output-pipeline")]

use aegis_cli::{Output, OutputFormat};
use aegis_core::{
    FileOutput, Finding, InspectionStatus, Location, RiskScore, ScanReceipt, ScanStats,
    SyncOutputHandler,
};
use serde_json::Value;
use tempfile::TempDir;

fn fixture() -> (Vec<Finding>, ScanStats, RiskScore) {
    let finding = Finding::new(
        "hardcoded-secret",
        "secrets",
        "high",
        "high",
        Location::new("fixture.rs", 4, 2, "secret = value"),
        "value",
        "redacted fixture finding",
    );
    let mut stats = ScanStats::for_content("string:fixture.rs", 14);
    stats
        .inspection_ledger
        .record("fixture.rs", InspectionStatus::Analyzed, true, None);
    stats.inspection_ledger.record(
        "optional-exclusion",
        InspectionStatus::Excluded,
        false,
        Some("fixture policy".into()),
    );
    stats.inspection_ledger.record(
        "unsupported-language",
        InspectionStatus::Unsupported,
        false,
        Some("no grammar".into()),
    );
    stats.inspection_ledger.record(
        "optional-skip",
        InspectionStatus::Skipped,
        false,
        Some("fixture skip".into()),
    );
    stats.inspection_ledger.record(
        "suppressed-finding",
        InspectionStatus::Suppressed,
        false,
        Some("approved fixture suppression".into()),
    );
    stats.inspection_ledger.record(
        "discovered-unit",
        InspectionStatus::Discovered,
        false,
        Some("awaiting optional analyzer".into()),
    );
    stats.finding_count = 1;
    let risk = RiskScore::new(
        std::slice::from_ref(&finding),
        &Default::default(),
        &Default::default(),
    );
    (vec![finding], stats, risk)
}

fn cli_output(
    format: OutputFormat,
    findings: &[Finding],
    stats: &ScanStats,
    risk: &RiskScore,
) -> Value {
    let mut output = Output::new(format, false);
    output.write_findings(findings, stats, risk).unwrap();
    serde_json::from_str(&output.to_string()).unwrap()
}

#[test]
fn cross_entry_outputs_preserve_identity_and_ledger() {
    let (findings, stats, risk) = fixture();
    assert!(stats.inspection_ledger.allows_safe());
    let stable_id = findings[0].stable_id.clone();

    let cli_json = cli_output(OutputFormat::Json, &findings, &stats, &risk);
    let cli_sarif = cli_output(OutputFormat::Sarif, &findings, &stats, &risk);
    assert_eq!(cli_json["findings"][0]["stable_id"], stable_id);
    assert_eq!(
        cli_json["stats"]["inspection_ledger"],
        cli_sarif["runs"][0]["properties"]["inspectionLedger"]
    );
    assert_eq!(
        cli_json["stats"]["inspection_ledger"]["schema_version"],
        aegis_core::finding::INSPECTION_LEDGER_SCHEMA_VERSION
    );
    assert_eq!(
        cli_sarif["runs"][0]["properties"]["inspectionLedger"]["schema_version"],
        aegis_core::finding::INSPECTION_LEDGER_SCHEMA_VERSION
    );
    assert_eq!(cli_sarif["runs"][0]["results"][0]["ruleId"], stable_id);

    let temp_dir = TempDir::new().unwrap();
    let json_path = temp_dir.path().join("core.json");
    let sarif_path = temp_dir.path().join("core.sarif");
    let core_json = FileOutput::json(&json_path);
    let core_sarif = FileOutput::sarif(&sarif_path);
    core_json.emit_sync(&findings, &stats, &risk).unwrap();
    core_sarif.emit_sync(&findings, &stats, &risk).unwrap();
    let core_json: Value =
        serde_json::from_str(&std::fs::read_to_string(json_path).unwrap()).unwrap();
    let core_sarif: Value =
        serde_json::from_str(&std::fs::read_to_string(sarif_path).unwrap()).unwrap();
    assert_eq!(core_json["findings"][0]["stable_id"], stable_id);
    assert_eq!(
        core_json["stats"]["inspection_ledger"],
        core_sarif["runs"][0]["properties"]["inspectionLedger"]
    );
    assert_eq!(
        core_json["stats"]["inspection_ledger"]["schema_version"],
        aegis_core::finding::INSPECTION_LEDGER_SCHEMA_VERSION
    );
    assert_eq!(core_sarif["runs"][0]["results"][0]["ruleId"], stable_id);
    assert_eq!(
        core_sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
            ["uri"],
        "fixture.rs"
    );
    assert_eq!(
        core_sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
            ["startLine"],
        4
    );

    let receipt =
        ScanReceipt::from_scan("fixture.rs", "fixture", "default", None, &findings, stats);
    assert_eq!(receipt.findings[0].stable_id, stable_id);
    assert_eq!(
        serde_json::to_value(&receipt.inspection_ledger).unwrap(),
        core_sarif["runs"][0]["properties"]["inspectionLedger"]
    );
    assert!(!receipt.to_json().unwrap().contains("secret = value"));
}

#[test]
fn required_failure_is_not_safe_even_without_findings() {
    let (_, mut stats, _) = fixture();
    stats.inspection_ledger.record(
        "required-parser",
        InspectionStatus::Failed,
        true,
        Some("syntax error".into()),
    );
    assert!(!stats.inspection_ledger.allows_safe());
}
