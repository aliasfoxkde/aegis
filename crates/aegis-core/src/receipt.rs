//! Redacted, versioned scan receipts.
//!
//! Receipts are the durable evidence boundary between Aegis and callers such
//! as CI, Control Center, and delegated agents. They intentionally omit
//! matched content so persisting a receipt cannot disclose a detected secret.

use crate::{Finding, InspectionLedger, Location, RiskScore, ScanStats};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Schema version for serialized scan receipts.
pub const SCAN_RECEIPT_SCHEMA_VERSION: u16 = 1;

/// Redacted source location retained in a receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptLocation {
    pub file: String,
    pub line: usize,
    pub column: usize,
}

impl From<&Location> for ReceiptLocation {
    fn from(location: &Location) -> Self {
        Self {
            file: location.file.clone(),
            line: location.line,
            column: location.column,
        }
    }
}

/// Redacted finding metadata retained in a receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptFinding {
    pub stable_id: String,
    pub pattern: String,
    pub category: String,
    pub severity: String,
    pub confidence: String,
    pub kind: String,
    pub location: ReceiptLocation,
}

impl From<&Finding> for ReceiptFinding {
    fn from(finding: &Finding) -> Self {
        Self {
            stable_id: finding.stable_id.clone(),
            pattern: finding.pattern.clone(),
            category: finding.category.clone(),
            severity: finding.severity.clone(),
            confidence: finding.confidence.clone(),
            kind: finding.kind.to_string(),
            location: ReceiptLocation::from(&finding.location),
        }
    }
}

/// A durable, redacted record of one scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReceipt {
    pub schema_version: u16,
    pub receipt_id: String,
    pub created_at: u64,
    pub source: String,
    pub scope: String,
    pub profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_digest: Option<String>,
    pub finding_count: usize,
    pub risk_level: String,
    pub risk_score: i32,
    pub findings: Vec<ReceiptFinding>,
    pub stats: ScanStats,
    pub inspection_ledger: InspectionLedger,
}

impl ScanReceipt {
    /// Return a redacted SHA-256 digest for an effective profile/config string.
    pub fn digest_text(value: &str) -> String {
        hex::encode(Sha256::digest(value.as_bytes()))
    }

    /// Create a receipt without retaining matched source content.
    pub fn from_scan(
        source: impl Into<String>,
        scope: impl Into<String>,
        profile: impl Into<String>,
        config_digest: Option<String>,
        findings: &[Finding],
        stats: ScanStats,
    ) -> Self {
        let source = source.into();
        let scope = scope.into();
        let profile = profile.into();
        let risk = RiskScore::new(findings, &Default::default(), &Default::default());
        let redacted_findings = findings
            .iter()
            .map(ReceiptFinding::from)
            .collect::<Vec<_>>();
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let identity_material = format!(
            "{}|{}|{}|{}|{}",
            source,
            scope,
            profile,
            created_at,
            redacted_findings
                .iter()
                .map(|finding| finding.stable_id.as_str())
                .collect::<Vec<_>>()
                .join(",")
        );
        let receipt_id = format!(
            "aegis-receipt-{}",
            hex::encode(Sha256::digest(identity_material.as_bytes()))
        );
        let inspection_ledger = stats.inspection_ledger.clone();
        // Keep the embedded statistics consistent with the embedded findings:
        // callers such as the CLI diff/env/stdin paths pass coverage-only stats,
        // so recompute the finding-derived counts from the actual findings.
        let mut stats = stats;
        stats.finding_count = redacted_findings.len();
        stats.findings_by_severity.clear();
        stats.findings_by_category.clear();
        for finding in &redacted_findings {
            *stats
                .findings_by_severity
                .entry(finding.severity.clone())
                .or_insert(0) += 1;
            *stats
                .findings_by_category
                .entry(finding.category.clone())
                .or_insert(0) += 1;
        }

        Self {
            schema_version: SCAN_RECEIPT_SCHEMA_VERSION,
            receipt_id,
            created_at,
            source,
            scope,
            profile,
            source_revision: None,
            config_digest,
            finding_count: findings.len(),
            risk_level: risk.level.to_string(),
            risk_score: risk.score,
            findings: redacted_findings,
            stats,
            inspection_ledger,
        }
    }

    /// Attach an optional source revision without changing the receipt identity inputs.
    pub fn with_source_revision(mut self, source_revision: Option<String>) -> Self {
        self.source_revision = source_revision;
        self
    }

    /// Whether the receipt has enough inspection evidence for a safe result.
    pub fn allows_safe(&self) -> bool {
        self.inspection_ledger.allows_safe()
    }

    /// Serialize this receipt as stable, human-readable JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Atomically persist this receipt, replacing an existing file.
    pub fn write_atomic(&self, path: &Path) -> io::Result<()> {
        let json = self
            .to_json()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("receipt");
        let temp_path = path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()));
        fs::write(&temp_path, json.as_bytes())?;
        if let Err(error) = fs::rename(&temp_path, path) {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }
        Ok(())
    }

    /// Read and validate a serialized receipt.
    pub fn read_json(path: &Path) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        serde_json::from_str(&content)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding() -> Finding {
        Finding::new(
            "test-rule",
            "secrets",
            "high",
            "high",
            Location::new("fixture.rs", 4, 2, "secret = value"),
            "value",
            "redacted test finding",
        )
    }

    #[test]
    fn receipt_redacts_matched_content_and_preserves_identity() {
        let finding = finding();
        let receipt = ScanReceipt::from_scan(
            "fixture.rs",
            "fixture",
            "default",
            None,
            std::slice::from_ref(&finding),
            ScanStats::for_content("string:fixture.rs", 14),
        );
        let json = receipt.to_json().unwrap();

        assert_eq!(receipt.schema_version, SCAN_RECEIPT_SCHEMA_VERSION);
        assert_eq!(receipt.finding_count, 1);
        assert!(json.contains(&finding.stable_id));
        assert!(!json.contains("secret = value"));
        assert!(!json.contains("matched_content"));
        assert!(receipt.allows_safe());
    }

    #[test]
    fn receipt_round_trips_atomically() {
        let root = std::env::temp_dir().join(format!("aegis-receipt-{}", std::process::id()));
        let path = root.join("scan.json");
        let receipt = ScanReceipt::from_scan(
            "fixture.rs",
            "fixture",
            "default",
            Some("config-digest".to_string()),
            &[],
            ScanStats::for_content("string:fixture.rs", 0),
        );

        receipt.write_atomic(&path).unwrap();
        let loaded = ScanReceipt::read_json(&path).unwrap();
        assert_eq!(loaded.receipt_id, receipt.receipt_id);
        assert_eq!(loaded.config_digest, receipt.config_digest);
        assert_eq!(
            serde_json::to_string(&loaded.inspection_ledger).unwrap(),
            serde_json::to_string(&receipt.inspection_ledger).unwrap()
        );
        assert!(path.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn incomplete_receipt_is_not_safe() {
        let mut stats = ScanStats::default();
        stats.inspection_ledger.record(
            "required-analyzer",
            crate::InspectionStatus::Failed,
            true,
            Some("parser_error".to_string()),
        );
        let receipt = ScanReceipt::from_scan("fixture.rs", "fixture", "default", None, &[], stats);

        assert!(!receipt.allows_safe());
    }

    #[test]
    fn receipt_stats_align_with_embedded_findings() {
        let high = finding();
        let low = Finding::new(
            "weak-rule",
            "injection",
            "low",
            "medium",
            Location::new("fixture2.rs", 9, 1, "query = input"),
            "input",
            "redacted low finding",
        );
        let findings = [high, low];
        // Coverage-only stats (as produced by CLI diff/env/stdin paths): they
        // carry no finding-derived counts even though findings exist.
        let stats = ScanStats::for_content("string:fixture.rs", 42);

        let receipt =
            ScanReceipt::from_scan("fixture.rs", "fixture", "default", None, &findings, stats);

        assert_eq!(receipt.finding_count, 2);
        assert_eq!(receipt.stats.finding_count, receipt.finding_count);
        assert_eq!(receipt.stats.findings_by_severity.get("high"), Some(&1));
        assert_eq!(receipt.stats.findings_by_severity.get("low"), Some(&1));
        assert_eq!(receipt.stats.findings_by_severity.len(), 2);
        assert_eq!(receipt.stats.findings_by_category.get("secrets"), Some(&1));
        assert_eq!(
            receipt.stats.findings_by_category.get("injection"),
            Some(&1)
        );
        assert_eq!(receipt.stats.findings_by_category.len(), 2);
        // Coverage fields from the caller are preserved, not discarded.
        assert_eq!(receipt.stats.files_scanned, 1);
        assert_eq!(receipt.stats.bytes_scanned, 42);
    }

    #[test]
    fn empty_receipt_stats_show_no_findings() {
        let mut stats = ScanStats::for_content("string:fixture.rs", 0);
        // Simulate stale finding-derived counts that disagree with zero findings.
        stats.finding_count = 3;
        stats.findings_by_severity.insert("high".to_string(), 3);
        stats.findings_by_category.insert("secrets".to_string(), 3);

        let receipt = ScanReceipt::from_scan("fixture.rs", "fixture", "default", None, &[], stats);

        assert_eq!(receipt.finding_count, 0);
        assert_eq!(receipt.stats.finding_count, 0);
        assert!(receipt.stats.findings_by_severity.is_empty());
        assert!(receipt.stats.findings_by_category.is_empty());
    }
}
