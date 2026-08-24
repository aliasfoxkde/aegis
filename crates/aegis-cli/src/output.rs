//! Output formatting

use crate::OutputFormat;
use aegis_core::{Finding, RiskScore, ScanStats};

pub struct Output {
    format: OutputFormat,
    quiet: bool,
    buffer: String,
}

impl std::fmt::Write for Output {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.buffer.write_str(s)
    }
}

impl Output {
    pub fn new(format: OutputFormat, quiet: bool) -> Self {
        Self {
            format,
            quiet,
            buffer: String::new(),
        }
    }

    pub fn write_findings(
        &mut self,
        findings: &[Finding],
        stats: &ScanStats,
        risk: &RiskScore,
    ) -> Result<(), std::fmt::Error> {
        match self.format {
            OutputFormat::Human => self.write_human(findings, stats, risk),
            OutputFormat::Json => self.write_json(findings, stats, risk),
            OutputFormat::Sarif => self.write_sarif(findings, stats, risk),
        }
    }

    fn write_human(
        &mut self,
        findings: &[Finding],
        stats: &ScanStats,
        risk: &RiskScore,
    ) -> Result<(), std::fmt::Error> {
        use std::fmt::Write;

        if !self.quiet {
            writeln!(self, "Aegis Security Scan")?;
            writeln!(self, "==================")?;
            writeln!(self, "{}", risk)?;
            writeln!(self)?;
        }

        if findings.is_empty() {
            if !self.quiet {
                writeln!(self, "No findings detected.")?;
            }
            return Ok(());
        }

        for finding in findings {
            let severity_color = match finding.severity.as_str() {
                "critical" => "\x1b[31m", // Red
                "high" => "\x1b[33m",     // Yellow
                "medium" => "\x1b[35m",   // Magenta
                "low" => "\x1b[36m",      // Cyan
                _ => "\x1b[0m",           // Reset
            };
            let reset = "\x1b[0m";

            writeln!(
                self,
                "{}[{}]{} {} at {}:{}:{}",
                severity_color,
                finding.severity.to_uppercase(),
                reset,
                finding.pattern,
                finding.location.file,
                finding.location.line,
                finding.location.column
            )?;
            writeln!(self, "  {}", finding.description)?;
        }

        if !self.quiet {
            writeln!(self)?;
            writeln!(self, "{}", stats)?;
        }

        Ok(())
    }

    fn write_json(
        &mut self,
        findings: &[Finding],
        stats: &ScanStats,
        _risk: &RiskScore,
    ) -> Result<(), std::fmt::Error> {
        use std::fmt::Write;

        #[derive(serde::Serialize)]
        struct JsonOutput<'a> {
            findings: &'a [Finding],
            stats: &'a ScanStats,
        }

        let output = JsonOutput { findings, stats };
        let json = serde_json::to_string_pretty(&output).map_err(|_| std::fmt::Error)?;
        writeln!(self.buffer, "{}", json)?;
        Ok(())
    }

    fn write_sarif(
        &mut self,
        findings: &[Finding],
        stats: &ScanStats,
        _risk: &RiskScore,
    ) -> Result<(), std::fmt::Error> {
        use std::fmt::Write;

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
            inspection_ledger: aegis_core::finding::InspectionLedger,
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
        }

        #[derive(serde::Serialize)]
        struct SarifResult {
            #[serde(rename = "ruleId")]
            rule_id: String,
            level: String,
            message: SarifMessage,
            locations: Vec<SarifLocation>,
        }

        #[derive(serde::Serialize)]
        struct SarifMessage {
            text: String,
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
            #[serde(rename = "startLine")]
            start_line: usize,
            #[serde(rename = "startColumn")]
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
            })
            .collect();

        let results: Vec<SarifResult> = findings
            .iter()
            .map(|f| SarifResult {
                rule_id: f.stable_id.clone(),
                level: severity_to_sarif_level(&f.severity),
                message: SarifMessage {
                    text: f.description.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: f.location.file.clone(),
                        },
                        region: SarifRegion {
                            start_line: f.location.line.max(1),
                            start_column: f.location.column.max(1),
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

        let json = serde_json::to_string_pretty(&output).map_err(|_| std::fmt::Error)?;
        writeln!(self.buffer, "{}", json)?;
        Ok(())
    }
}

impl std::fmt::Display for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.buffer)
    }
}

pub(crate) fn severity_to_sarif_level(severity: &str) -> String {
    match severity {
        "critical" | "high" => "error".to_string(),
        "medium" => "warning".to_string(),
        "low" => "note".to_string(),
        _ => "none".to_string(),
    }
}

#[cfg(test)]
pub(crate) fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        // Truncate at character boundary to handle UTF-8 properly
        for (char_count, (byte_idx, _)) in s.char_indices().enumerate() {
            if char_count >= max_len {
                return format!("{}...", &s[..byte_idx]);
            }
        }
        s.to_string()
    }
}

/// Format patterns for listing (testable)
pub fn format_patterns(enabled: bool, disabled: bool, category: Option<String>) -> String {
    use aegis_core::Severity;

    let patterns = aegis_patterns::all_patterns();

    // Filter by category if specified
    let patterns: Vec<_> = match &category {
        Some(cat) => patterns
            .into_iter()
            .filter(|p| &p.category == cat)
            .collect(),
        None => patterns,
    };

    // Filter by enabled/disabled status
    let patterns: Vec<_> = if enabled && !disabled {
        patterns.into_iter().filter(|p| p.enabled).collect()
    } else if disabled && !enabled {
        patterns.into_iter().filter(|p| !p.enabled).collect()
    } else {
        patterns
    };

    let mut output = String::new();
    output.push_str("Aegis Patterns\n");
    output.push_str("==============\n");
    output.push_str(&format!("Total: {} patterns\n", patterns.len()));
    if let Some(ref cat) = category {
        output.push_str(&format!("Category: {}\n", cat));
    }
    output.push('\n');

    for p in &patterns {
        let status = if p.enabled { "[+]" } else { "[ ]" };
        let severity_str = match Severity::parse(&p.severity) {
            Some(Severity::Critical) => "\x1b[31mCRITICAL\x1b[0m",
            Some(Severity::High) => "\x1b[33mHIGH\x1b[0m",
            Some(Severity::Medium) => "\x1b[35mMEDIUM\x1b[0m",
            Some(Severity::Low) => "\x1b[36mLOW\x1b[0m",
            None => &p.severity,
        };
        output.push_str(&format!(
            "{} {:15} {:8} {}\n",
            status, p.name, severity_str, p.description
        ));
    }

    output
}

pub fn list_patterns(
    enabled: bool,
    disabled: bool,
    category: Option<String>,
) -> Result<String, anyhow::Error> {
    Ok(format_patterns(enabled, disabled, category))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::{Finding, Location, RiskScore, ScanStats};

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

    fn make_test_stats() -> ScanStats {
        let mut stats = ScanStats::new();
        stats.files_scanned = 10;
        stats.bytes_scanned = 1024;
        stats.finding_count = 1;
        stats
    }

    fn make_test_risk() -> RiskScore {
        RiskScore::new(&[], &Default::default(), &Default::default())
    }

    #[test]
    fn test_output_new() {
        let output = Output::new(OutputFormat::Human, false);
        assert!(output.buffer.is_empty());
    }

    #[test]
    fn test_output_write_findings_human() {
        let mut output = Output::new(OutputFormat::Human, false);
        let finding = make_test_finding();
        let stats = make_test_stats();
        let risk = make_test_risk();

        let result = output.write_findings(&[finding], &stats, &risk);
        assert!(result.is_ok());
        assert!(!output.buffer.is_empty());
    }

    #[test]
    fn test_output_write_findings_json() {
        let mut output = Output::new(OutputFormat::Json, false);
        let finding = make_test_finding();
        let stats = make_test_stats();
        let risk = make_test_risk();

        let result = output.write_findings(&[finding], &stats, &risk);
        assert!(result.is_ok());
        assert!(output.buffer.contains("findings"));
    }

    #[test]
    fn test_output_write_findings_sarif() {
        let mut output = Output::new(OutputFormat::Sarif, false);
        let finding = Finding::new(
            "zero-based-location",
            "secrets",
            "high",
            "high",
            Location::new("test.rs", 0, 0, "secret"),
            "secret",
            "Secret fixture",
        );
        let stats = make_test_stats();
        let risk = make_test_risk();

        let result = output.write_findings(&[finding], &stats, &risk);
        assert!(result.is_ok());
        assert!(output.buffer.contains("\"version\""));
        assert!(output.buffer.contains("inspectionLedger"));
        assert!(output.buffer.contains("\"ruleId\""));
        assert!(output.buffer.contains("\"startLine\": 1"));
        assert!(output.buffer.contains("\"startColumn\": 1"));
        assert!(output.buffer.contains("\"text\": \"Secret fixture\""));
        assert!(!output.buffer.contains("start_line"));
        assert!(!output.buffer.contains("\"rule_id\""));
    }

    #[test]
    fn test_output_quiet_mode() {
        let mut output = Output::new(OutputFormat::Human, true);
        let finding = make_test_finding();
        let stats = make_test_stats();
        let risk = make_test_risk();

        let result = output.write_findings(&[finding], &stats, &risk);
        assert!(result.is_ok());
        // Quiet mode should not print header
        assert!(!output.buffer.contains("Aegis Security Scan"));
    }

    #[test]
    fn test_output_empty_findings() {
        let mut output = Output::new(OutputFormat::Human, false);
        let stats = make_test_stats();
        let risk = make_test_risk();

        let result = output.write_findings(&[], &stats, &risk);
        assert!(result.is_ok());
        assert!(output.buffer.contains("No findings detected"));
    }

    #[test]
    fn test_output_display() {
        let output = Output::new(OutputFormat::Human, false);
        let display = format!("{}", output);
        assert_eq!(display, "");
    }

    #[test]
    fn test_severity_to_sarif_level() {
        assert_eq!(severity_to_sarif_level("critical"), "error");
        assert_eq!(severity_to_sarif_level("high"), "error");
        assert_eq!(severity_to_sarif_level("medium"), "warning");
        assert_eq!(severity_to_sarif_level("low"), "note");
        assert_eq!(severity_to_sarif_level("unknown"), "none");
    }

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("short", 10), "short");
        assert_eq!(
            truncate_string("this is a long string", 10),
            "this is a ..."
        );
        assert_eq!(truncate_string("exactly10!", 10), "exactly10!");
    }

    #[test]
    fn test_output_with_multiple_findings() {
        let mut output = Output::new(OutputFormat::Human, false);
        let finding1 = make_test_finding();
        let finding2 = Finding::new(
            "another-pattern",
            "secrets",
            "medium",
            "medium",
            Location::new("other.rs", 20, 10, "secret2 = 'xyz'"),
            "xyz",
            "Another finding",
        );
        let stats = make_test_stats();
        let risk = make_test_risk();

        let result = output.write_findings(&[finding1, finding2], &stats, &risk);
        assert!(result.is_ok());
        assert!(output.buffer.contains("hardcoded-secret"));
        assert!(output.buffer.contains("another-pattern"));
    }

    #[test]
    fn test_output_json_with_multiple_findings() {
        let mut output = Output::new(OutputFormat::Json, false);
        let finding1 = make_test_finding();
        let finding2 = Finding::new(
            "another-pattern",
            "secrets",
            "medium",
            "medium",
            Location::new("other.rs", 20, 10, "secret2 = 'xyz'"),
            "xyz",
            "Another finding",
        );
        let stats = make_test_stats();
        let risk = make_test_risk();

        let result = output.write_findings(&[finding1, finding2], &stats, &risk);
        assert!(result.is_ok());
        assert!(output.buffer.contains("findings"));
    }

    #[test]
    fn test_output_sarif_with_multiple_findings() {
        let mut output = Output::new(OutputFormat::Sarif, false);
        let finding1 = make_test_finding();
        let finding2 = Finding::new(
            "another-pattern",
            "secrets",
            "medium",
            "medium",
            Location::new("other.rs", 20, 10, "secret2 = 'xyz'"),
            "xyz",
            "Another finding",
        );
        let stats = make_test_stats();
        let risk = make_test_risk();

        let result = output.write_findings(&[finding1, finding2], &stats, &risk);
        assert!(result.is_ok());
        assert!(output.buffer.contains("\"version\""));
    }

    #[test]
    fn test_severity_colors_in_human_output() {
        let mut output = Output::new(OutputFormat::Human, false);
        let critical_finding = Finding::new(
            "critical-pattern",
            "secrets",
            "critical",
            "high",
            Location::new("test.rs", 1, 0, "critical secret"),
            "secret",
            "Critical finding",
        );
        let stats = make_test_stats();
        let risk = make_test_risk();

        let result = output.write_findings(&[critical_finding], &stats, &risk);
        assert!(result.is_ok());
        // ANSI color codes should be present for critical (red)
        assert!(output.buffer.contains("\x1b[31m")); // Red for critical
    }

    #[test]
    fn test_output_buffer_display() {
        let mut output = Output::new(OutputFormat::Human, false);
        let finding = make_test_finding();
        let stats = make_test_stats();
        let risk = make_test_risk();
        output.write_findings(&[finding], &stats, &risk).ok();

        // Display impl should return the buffer
        let display_str = format!("{}", output);
        assert!(!display_str.is_empty());
    }

    #[test]
    fn test_output_with_high_severity() {
        let mut output = Output::new(OutputFormat::Human, false);
        let finding = Finding::new(
            "high-pattern",
            "secrets",
            "high",
            "high",
            Location::new("test.rs", 10, 5, "secret = 'abc'"),
            "abc",
            "High severity finding",
        );
        let stats = make_test_stats();
        let risk = make_test_risk();

        let result = output.write_findings(&[finding], &stats, &risk);
        assert!(result.is_ok());
        // Yellow color for high
        assert!(output.buffer.contains("\x1b[33m"));
    }

    #[test]
    fn test_output_with_medium_severity() {
        let mut output = Output::new(OutputFormat::Human, false);
        let finding = Finding::new(
            "medium-pattern",
            "secrets",
            "medium",
            "medium",
            Location::new("test.rs", 10, 5, "code = 'abc'"),
            "abc",
            "Medium severity finding",
        );
        let stats = make_test_stats();
        let risk = make_test_risk();

        let result = output.write_findings(&[finding], &stats, &risk);
        assert!(result.is_ok());
        // Magenta color for medium
        assert!(output.buffer.contains("\x1b[35m"));
    }

    #[test]
    fn test_output_with_low_severity() {
        let mut output = Output::new(OutputFormat::Human, false);
        let finding = Finding::new(
            "low-pattern",
            "code-quality",
            "low",
            "low",
            Location::new("test.rs", 10, 5, "code = 'abc'"),
            "abc",
            "Low severity finding",
        );
        let stats = make_test_stats();
        let risk = make_test_risk();

        let result = output.write_findings(&[finding], &stats, &risk);
        assert!(result.is_ok());
        // Cyan color for low
        assert!(output.buffer.contains("\x1b[36m"));
    }

    #[test]
    fn test_output_with_unknown_severity() {
        let mut output = Output::new(OutputFormat::Human, false);
        // Use an invalid severity value to trigger the default branch
        let finding = Finding::new(
            "unknown-pattern",
            "secrets",
            "invalid_severity",
            "high",
            Location::new("test.rs", 10, 5, "secret = 'abc'"),
            "abc",
            "Finding with unknown severity",
        );
        let stats = make_test_stats();
        let risk = make_test_risk();

        let result = output.write_findings(&[finding], &stats, &risk);
        assert!(result.is_ok());
        // Should contain the pattern name even with unknown severity
        assert!(output.buffer.contains("unknown-pattern"));
    }

    #[test]
    fn test_output_with_empty_matched_content() {
        let mut output = Output::new(OutputFormat::Human, false);
        let finding = Finding::new(
            "pattern-no-content",
            "secrets",
            "high",
            "high",
            Location::new("test.rs", 10, 5, ""),
            "",
            "Finding with no matched content",
        );
        let stats = make_test_stats();
        let risk = make_test_risk();

        let result = output.write_findings(&[finding], &stats, &risk);
        assert!(result.is_ok());
        // Should not have "Matched:" line when content is empty
        assert!(!output.buffer.contains("Matched:"));
    }

    #[test]
    fn test_output_with_long_matched_content() {
        let mut output = Output::new(OutputFormat::Human, false);
        let long_content = "a".repeat(100);
        let finding = Finding::new(
            "pattern-long-content",
            "secrets",
            "high",
            "high",
            Location::new("test.rs", 10, 5, &long_content),
            &long_content,
            "Finding with long matched content",
        );
        let stats = make_test_stats();
        let risk = make_test_risk();

        let result = output.write_findings(&[finding], &stats, &risk);
        assert!(result.is_ok());
        // Public human output must never include matched source material.
        assert!(!output.buffer.contains(&long_content));
        assert!(!output.buffer.contains("Matched:"));
    }

    #[test]
    fn test_public_outputs_redact_sensitive_material() {
        let secret = "TOP-SECRET-CLI-FIXTURE";
        let finding = Finding::new(
            "hardcoded-secret",
            "secrets",
            "high",
            "high",
            Location::new("config.toml", 4, 2, format!("token = '{secret}'")),
            secret,
            "Hardcoded secret detected",
        );
        let stats = ScanStats::for_content("config.toml", 32);
        let risk = make_test_risk();

        for format in [OutputFormat::Human, OutputFormat::Json, OutputFormat::Sarif] {
            let expect_identity = !matches!(&format, OutputFormat::Human);
            let mut output = Output::new(format, false);
            output
                .write_findings(std::slice::from_ref(&finding), &stats, &risk)
                .unwrap();
            let content = output.to_string();
            assert!(!content.contains(secret));
            assert!(!content.contains("matched_content"));
            if expect_identity {
                assert!(content.contains(&finding.stable_id));
            }
        }
    }

    #[test]
    fn test_format_patterns_basic() {
        let output = format_patterns(false, false, None);
        assert!(output.contains("Aegis Patterns"));
        assert!(output.contains("Total:"));
    }

    #[test]
    fn test_format_patterns_with_category() {
        let output = format_patterns(false, false, Some("secrets".to_string()));
        assert!(output.contains("Category: secrets"));
    }

    #[test]
    fn test_format_patterns_enabled_only() {
        let output = format_patterns(true, false, None);
        assert!(output.contains("[+]"));
    }

    #[test]
    fn test_format_patterns_disabled_only() {
        let output = format_patterns(false, true, None);
        // When filtering disabled only, format is still correct
        assert!(output.contains("Total:"));
        assert!(output.contains("patterns"));
    }

    #[test]
    fn test_format_patterns_all_statuses() {
        // Both enabled and disabled - should show all
        let output = format_patterns(true, true, None);
        assert!(output.contains("[+]") || output.contains("[ ]"));
    }

    #[test]
    fn test_format_patterns_severity_colors() {
        let output = format_patterns(false, false, None);
        // Should contain ANSI color codes for severity
        assert!(output.contains("\x1b[31m") || output.contains("\x1b[33m"));
    }

    #[test]
    fn test_list_patterns_returns_ok() {
        let result = list_patterns(false, false, None);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("Aegis Patterns"));
    }

    #[test]
    fn test_list_patterns_with_category() {
        let result = list_patterns(false, false, Some("secrets".to_string()));
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("Category: secrets"));
    }
}
