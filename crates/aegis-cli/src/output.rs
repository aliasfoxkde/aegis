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

            if !finding.matched_content.is_empty() {
                writeln!(
                    self,
                    "  Matched: {}",
                    truncate_string(&finding.matched_content, 60)
                )?;
            }
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
        _stats: &ScanStats,
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
            rules_map.entry(f.pattern.clone()).or_insert(f);
        }

        let rules: Vec<SarifRule> = rules_map
            .values()
            .map(|f| SarifRule {
                id: f.pattern.clone(),
                name: f.pattern.clone(),
                severity: f.severity.clone(),
            })
            .collect();

        let results: Vec<SarifResult> = findings
            .iter()
            .map(|f| SarifResult {
                rule_id: f.pattern.clone(),
                level: severity_to_sarif_level(&f.severity),
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

pub(crate) fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

pub fn list_patterns(
    enabled: bool,
    disabled: bool,
    category: Option<String>,
) -> Result<(), anyhow::Error> {
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

    println!("Aegis Patterns");
    println!("==============");
    println!("Total: {} patterns", patterns.len());
    if let Some(ref cat) = category {
        println!("Category: {}", cat);
    }
    println!();

    for p in &patterns {
        let status = if p.enabled { "[+]" } else { "[ ]" };
        let severity_str = match Severity::parse(&p.severity) {
            Some(Severity::Critical) => "\x1b[31mCRITICAL\x1b[0m",
            Some(Severity::High) => "\x1b[33mHIGH\x1b[0m",
            Some(Severity::Medium) => "\x1b[35mMEDIUM\x1b[0m",
            Some(Severity::Low) => "\x1b[36mLOW\x1b[0m",
            None => &p.severity,
        };
        println!(
            "{} {:15} {:8} {}",
            status, p.name, severity_str, p.description
        );
    }

    Ok(())
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
        let finding = make_test_finding();
        let stats = make_test_stats();
        let risk = make_test_risk();

        let result = output.write_findings(&[finding], &stats, &risk);
        assert!(result.is_ok());
        assert!(output.buffer.contains("\"version\""));
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
        assert_eq!(truncate_string("this is a long string", 10), "this is a ...");
        assert_eq!(truncate_string("exactly10!", 10), "exactly10!");
    }
}
