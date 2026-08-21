//! # File Output Handler
//!
//! Supports writing findings to files in various formats: JSON, CSV, SARIF.

use super::{severity_to_level, OutputResult, SyncOutputHandler};
use crate::finding::{Finding, ScanStats};
use crate::risk::RiskScore;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::{fmt::Debug, path::PathBuf};

/// File output handler - writes findings to a file
#[derive(Debug)]
pub struct FileOutput {
    path: PathBuf,
    format: FileFormat,
    append: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum FileFormat {
    Json,
    Csv,
    Sarif,
    Human,
}

impl FileOutput {
    /// Create a new JSON file output
    pub fn json(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            format: FileFormat::Json,
            append: false,
        }
    }

    /// Create a new CSV file output
    pub fn csv(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            format: FileFormat::Csv,
            append: false,
        }
    }

    /// Create a new SARIF file output
    pub fn sarif(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            format: FileFormat::Sarif,
            append: false,
        }
    }

    /// Create a new human-readable file output
    pub fn human(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            format: FileFormat::Human,
            append: false,
        }
    }

    /// Enable append mode
    pub fn with_append(mut self, append: bool) -> Self {
        self.append = append;
        self
    }

    /// Get the file path
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn open_writer(&self) -> std::io::Result<BufWriter<File>> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(!self.append)
            .append(self.append)
            .open(&self.path)?;
        Ok(BufWriter::new(file))
    }

    fn write_content(
        &self,
        findings: &[Finding],
        stats: &ScanStats,
        risk: &RiskScore,
    ) -> OutputResult {
        let mut writer = self.open_writer()?;

        match self.format {
            FileFormat::Json => self.write_json(&mut writer, findings, stats)?,
            FileFormat::Csv => self.write_csv(&mut writer, findings)?,
            FileFormat::Sarif => self.write_sarif(&mut writer, findings, stats)?,
            FileFormat::Human => self.write_human(&mut writer, findings, stats, risk)?,
        }

        writer.flush()?;
        Ok(())
    }

    fn write_json(
        &self,
        writer: &mut BufWriter<File>,
        findings: &[Finding],
        stats: &ScanStats,
    ) -> OutputResult {
        #[derive(serde::Serialize)]
        struct JsonOutput<'a> {
            findings: &'a [Finding],
            stats: &'a ScanStats,
        }

        let output = JsonOutput { findings, stats };
        let json = serde_json::to_string_pretty(&output)?;
        writeln!(writer, "{}", json)?;
        Ok(())
    }

    fn write_csv(&self, writer: &mut BufWriter<File>, findings: &[Finding]) -> OutputResult {
        let mut csv_writer = csv::Writer::from_writer(writer);

        // Write header
        csv_writer.write_record([
            "id",
            "pattern",
            "category",
            "severity",
            "confidence",
            "file",
            "line",
            "column",
            "description",
        ])?;

        for finding in findings {
            csv_writer.write_record([
                &finding.id,
                &finding.pattern,
                &finding.category,
                &finding.severity,
                &finding.confidence,
                &finding.location.file,
                &finding.location.line.to_string(),
                &finding.location.column.to_string(),
                &finding.description,
            ])?;
        }

        csv_writer.flush()?;
        Ok(())
    }

    fn write_sarif(
        &self,
        writer: &mut BufWriter<File>,
        findings: &[Finding],
        stats: &ScanStats,
    ) -> OutputResult {
        #[derive(serde::Serialize)]
        struct SarifOutput {
            version: String,
            runs: Vec<SarifRun>,
        }

        #[derive(serde::Serialize)]
        struct SarifRun {
            tool: SarifTool,
            results: Vec<SarifResult>,
            properties: SarifRunProperties,
        }

        #[derive(serde::Serialize)]
        struct SarifRunProperties {
            #[serde(rename = "inspectionLedger")]
            inspection_ledger: crate::finding::InspectionLedger,
        }

        #[derive(serde::Serialize)]
        struct SarifTool {
            driver: SarifDriver,
        }

        #[derive(serde::Serialize)]
        struct SarifDriver {
            name: String,
            version: String,
            rules: Vec<SarifRule>,
        }

        #[derive(serde::Serialize)]
        struct SarifRule {
            id: String,
            name: String,
            severity: String,
        }

        #[derive(serde::Serialize)]
        struct SarifResult {
            rule_id: String,
            level: String,
            message: String,
            locations: Vec<SarifLocation>,
        }

        #[derive(serde::Serialize)]
        struct SarifLocation {
            physical_location: SarifPhysicalLocation,
        }

        #[derive(serde::Serialize)]
        struct SarifPhysicalLocation {
            artifact_location: SarifArtifactLocation,
            region: SarifRegion,
        }

        #[derive(serde::Serialize)]
        struct SarifArtifactLocation {
            uri: String,
        }

        #[derive(serde::Serialize)]
        struct SarifRegion {
            start_line: usize,
            start_column: usize,
        }

        // Build unique rules
        let mut rules_map: std::collections::HashMap<String, &Finding> =
            std::collections::HashMap::new();
        for f in findings {
            rules_map.entry(f.stable_id.clone()).or_insert(f);
        }

        let rules: Vec<SarifRule> = rules_map
            .values()
            .map(|f| SarifRule {
                id: f.stable_id.clone(),
                name: f.pattern.clone(),
                severity: f.severity.clone(),
            })
            .collect();

        let results: Vec<SarifResult> = findings
            .iter()
            .map(|f| SarifResult {
                rule_id: f.stable_id.clone(),
                level: severity_to_level(&f.severity).to_string(),
                message: f.description.clone(),
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: f.location.file.clone(),
                        },
                        region: SarifRegion {
                            start_line: f.location.line,
                            start_column: f.location.column,
                        },
                    },
                }],
            })
            .collect();

        let output = SarifOutput {
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "Aegis".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        rules,
                    },
                },
                results,
                properties: SarifRunProperties {
                    inspection_ledger: stats.inspection_ledger.clone(),
                },
            }],
        };

        let json = serde_json::to_string_pretty(&output)?;
        writeln!(writer, "{}", json)?;
        Ok(())
    }

    fn write_human(
        &self,
        writer: &mut BufWriter<File>,
        findings: &[Finding],
        stats: &ScanStats,
        risk: &RiskScore,
    ) -> OutputResult {
        writeln!(writer, "Aegis Security Scan")?;
        writeln!(writer, "==================")?;
        writeln!(writer, "{}", risk)?;
        writeln!(writer)?;

        if findings.is_empty() {
            writeln!(writer, "No findings detected.")?;
            return Ok(());
        }

        for finding in findings {
            let severity_color = match finding.severity.as_str() {
                "critical" => "\x1b[31m",
                "high" => "\x1b[33m",
                "medium" => "\x1b[35m",
                "low" => "\x1b[36m",
                _ => "\x1b[0m",
            };
            let reset = "\x1b[0m";

            writeln!(
                writer,
                "{}[{}]{} {} at {}:{}:{}",
                severity_color,
                finding.severity.to_uppercase(),
                reset,
                finding.pattern,
                finding.location.file,
                finding.location.line,
                finding.location.column
            )?;
            writeln!(writer, "  {}", finding.description)?;
        }

        writeln!(writer)?;
        writeln!(writer, "{}", stats)?;
        Ok(())
    }
}

impl SyncOutputHandler for FileOutput {
    fn emit_sync(&self, findings: &[Finding], stats: &ScanStats, risk: &RiskScore) -> OutputResult {
        self.write_content(findings, stats, risk)
    }

    fn flush_sync(&self) -> OutputResult {
        // File is flushed after each write
        Ok(())
    }

    fn name(&self) -> &str {
        "file"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Location;
    use tempfile::TempDir;

    fn make_test_finding() -> Finding {
        Finding::new(
            "hardcoded-secret",
            "secrets",
            "high",
            "high",
            Location::new("test.rs", 10, 5, "secret = 'abc'"),
            "abc",
            "Hardcoded secret detected",
        )
    }

    #[test]
    fn test_file_output_json() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("findings.json");

        let output = FileOutput::json(&path);
        let findings = vec![make_test_finding()];
        let stats = ScanStats::new();
        let risk = RiskScore::new(&[], &Default::default(), &Default::default());

        output.emit_sync(&findings, &stats, &risk).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("findings"));
        assert!(content.contains("hardcoded-secret"));
    }

    #[test]
    fn test_file_output_csv() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("findings.csv");

        let output = FileOutput::csv(&path);
        let findings = vec![make_test_finding()];
        let stats = ScanStats::new();
        let risk = RiskScore::new(&[], &Default::default(), &Default::default());

        output.emit_sync(&findings, &stats, &risk).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("id,pattern,category"));
        assert!(content.contains("hardcoded-secret"));
    }

    #[test]
    fn test_file_output_sarif() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("findings.sarif");

        let output = FileOutput::sarif(&path);
        let findings = vec![make_test_finding()];
        let stats = ScanStats::new();
        let risk = RiskScore::new(&[], &Default::default(), &Default::default());

        output.emit_sync(&findings, &stats, &risk).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"version\""));
        assert!(content.contains("2.1.0"));
        assert!(content.contains("inspectionLedger"));
        assert!(content.contains(&findings[0].stable_id));
        assert!(!content.contains("\"rule_id\": \"hardcoded-secret\""));
    }

    #[test]
    fn test_file_output_append() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("findings.json");

        let output = FileOutput::json(&path).with_append(true);
        let findings = vec![make_test_finding()];
        let stats = ScanStats::new();
        let risk = RiskScore::new(&[], &Default::default(), &Default::default());

        output.emit_sync(&findings, &stats, &risk).unwrap();
        output.emit_sync(&findings, &stats, &risk).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        // Should contain two sets of findings (appended)
        assert!(content.matches("hardcoded-secret").count() >= 2);
    }

    #[test]
    fn test_file_outputs_redact_sensitive_material() {
        let temp_dir = TempDir::new().unwrap();
        let secret = "TOP-SECRET-FILE-FIXTURE";
        let finding = Finding::new(
            "hardcoded-secret",
            "secrets",
            "high",
            "high",
            Location::new("config.toml", 4, 2, format!("token = '{secret}'")),
            secret,
            "Hardcoded secret detected",
        );
        let findings = vec![finding.clone()];
        let stats = ScanStats::for_content("config.toml", 32);
        let risk = RiskScore::new(&findings, &Default::default(), &Default::default());

        let outputs = [
            (
                "json",
                FileOutput::json(temp_dir.path().join("findings.json")),
            ),
            ("csv", FileOutput::csv(temp_dir.path().join("findings.csv"))),
            (
                "sarif",
                FileOutput::sarif(temp_dir.path().join("findings.sarif")),
            ),
            (
                "human",
                FileOutput::human(temp_dir.path().join("findings.txt")),
            ),
        ];

        for (name, output) in outputs {
            output.emit_sync(&findings, &stats, &risk).unwrap();
            let content = std::fs::read_to_string(output.path()).unwrap();
            assert!(!content.contains(secret), "{name} output leaked fixture");
            assert!(
                !content.contains("matched_content"),
                "{name} output exposed matched_content"
            );
            if name != "human" && name != "csv" {
                assert!(content.contains(&finding.stable_id));
            }
        }
    }
}
