//! # Multi-Output Pipeline
//!
//! Supports multiple concurrent output formats: files, databases, and webhooks.

pub mod database;
pub mod file;
pub mod webhook;

use crate::finding::{Finding, ScanStats};
use crate::risk::RiskScore;
use std::fmt::Debug;

/// Result type for output operations
pub type OutputResult = Result<(), OutputError>;

/// Output error types
#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Webhook error: {0}")]
    Webhook(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

impl From<serde_json::Error> for OutputError {
    fn from(e: serde_json::Error) -> Self {
        OutputError::Serialization(e.to_string())
    }
}

impl From<csv::Error> for OutputError {
    fn from(e: csv::Error) -> Self {
        OutputError::Serialization(e.to_string())
    }
}

impl From<rusqlite::Error> for OutputError {
    fn from(e: rusqlite::Error) -> Self {
        OutputError::Database(e.to_string())
    }
}

/// Synchronous output handler trait for simple outputs
pub trait SyncOutputHandler: Send + Sync + Debug {
    /// Write findings to this output (synchronous)
    fn emit_sync(&self, findings: &[Finding], stats: &ScanStats, risk: &RiskScore) -> OutputResult;

    /// Flush any buffered data
    fn flush_sync(&self) -> OutputResult;

    /// Get the output name for logging
    fn name(&self) -> &str;

    /// Check if this output is enabled
    fn is_enabled(&self) -> bool {
        true
    }
}

/// Multi-output pipeline that writes to multiple destinations
#[derive(Debug, Default)]
pub struct OutputPipeline {
    outputs: Vec<Box<dyn SyncOutputHandler>>,
}

impl OutputPipeline {
    /// Create a new empty pipeline
    pub fn new() -> Self {
        Self {
            outputs: Vec::new(),
        }
    }

    /// Add a synchronous output handler
    #[allow(clippy::should_implement_trait)]
    pub fn add(mut self, output: Box<dyn SyncOutputHandler>) -> Self {
        self.outputs.push(output);
        self
    }

    /// Emit findings to all outputs
    pub fn emit(&self, findings: &[Finding], stats: &ScanStats, risk: &RiskScore) {
        for output in &self.outputs {
            if output.is_enabled() {
                if let Err(e) = output.emit_sync(findings, stats, risk) {
                    tracing::warn!("Output {} failed: {}", output.name(), e);
                }
            }
        }
    }

    /// Flush all outputs
    pub fn flush(&self) {
        for output in &self.outputs {
            if let Err(e) = output.flush_sync() {
                tracing::warn!("Output {} flush failed: {}", output.name(), e);
            }
        }
    }

    /// Get the number of outputs in this pipeline
    pub fn len(&self) -> usize {
        self.outputs.len()
    }

    /// Check if the pipeline is empty
    pub fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }
}

/// Output format types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// Human-readable format
    #[default]
    Human,
    /// JSON format
    Json,
    /// SARIF format
    Sarif,
    /// CSV format
    Csv,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "human" | "text" | "txt" => Ok(OutputFormat::Human),
            "json" => Ok(OutputFormat::Json),
            "sarif" => Ok(OutputFormat::Sarif),
            "csv" => Ok(OutputFormat::Csv),
            _ => Err(format!("Unknown output format: {}", s)),
        }
    }
}

/// Severity level mapping for outputs
pub fn severity_to_level(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" => "error",
        "high" => "error",
        "medium" | "moderate" => "warning",
        "low" => "note",
        _ => "none",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_empty() {
        let pipeline = OutputPipeline::new();
        assert!(pipeline.is_empty());
        assert_eq!(pipeline.len(), 0);

        let findings = vec![];
        let stats = ScanStats::new();
        let risk = RiskScore::new(&[], &Default::default(), &Default::default());
        pipeline.emit(&findings, &stats, &risk);
    }

    #[test]
    fn test_output_format_parsing() {
        assert_eq!(
            "human".parse::<OutputFormat>().unwrap(),
            OutputFormat::Human
        );
        assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!(
            "sarif".parse::<OutputFormat>().unwrap(),
            OutputFormat::Sarif
        );
        assert_eq!("csv".parse::<OutputFormat>().unwrap(), OutputFormat::Csv);
        assert_eq!("CSV".parse::<OutputFormat>().unwrap(), OutputFormat::Csv);
        assert!("unknown".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn test_severity_to_level() {
        assert_eq!(severity_to_level("critical"), "error");
        assert_eq!(severity_to_level("high"), "error");
        assert_eq!(severity_to_level("medium"), "warning");
        assert_eq!(severity_to_level("moderate"), "warning");
        assert_eq!(severity_to_level("low"), "note");
        assert_eq!(severity_to_level("unknown"), "none");
    }
}
