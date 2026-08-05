//! Output formatting

use super::OutputFormat;
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

fn severity_to_sarif_level(severity: &str) -> String {
    match severity {
        "critical" | "high" => "error".to_string(),
        "medium" => "warning".to_string(),
        "low" => "note".to_string(),
        _ => "none".to_string(),
    }
}

fn truncate_string(s: &str, max_len: usize) -> String {
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
        Some(cat) => patterns.into_iter().filter(|p| &p.category == cat).collect(),
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
        println!("{} {:15} {:8} {}", status, p.name, severity_str, p.description);
    }

    Ok(())
}
