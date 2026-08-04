//! Configuration management

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::bundle::Bundle;

/// Configuration profile
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Profile name
    pub name: String,
    /// Enabled categories
    #[serde(default)]
    pub enabled_categories: Option<Vec<String>>,
    /// Strict mode
    #[serde(default)]
    pub strict_mode: StrictMode,
    /// Performance mode
    #[serde(default)]
    pub performance_mode: PerformanceMode,
    /// Exit on findings
    #[serde(default = "default_true")]
    pub exit_on_findings: bool,
    /// Max file size in MB
    #[serde(default = "default_max_file_size")]
    pub max_file_size_mb: u64,
    /// Binary file detection
    #[serde(default = "default_true")]
    pub binary_file_detection: bool,
    /// Respect gitignore
    #[serde(default = "default_true")]
    pub gitignore_respect: bool,
    /// Output format
    #[serde(default)]
    pub output_format: OutputFormat,
    /// Timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    /// Bundle path
    #[serde(skip)]
    pub bundle: Bundle,
}

fn default_true() -> bool {
    true
}

fn default_max_file_size() -> u64 {
    10
}

fn default_timeout() -> u64 {
    300
}

/// Strictness level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StrictMode {
    #[default]
    Permissive,
    Standard,
    Strict,
}

/// Performance mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PerformanceMode {
    #[default]
    Debug,
    Standard,
    Optimized,
}

/// Output format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Human,
    Json,
    Sarif,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Human => write!(f, "human"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Sarif => write!(f, "sarif"),
        }
    }
}

impl Config {
    /// Load config from a file
    pub fn load(path: &PathBuf) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;

        // Bundle should be loaded separately
        Ok(config)
    }

    /// Save config to a file
    pub fn save(&self, path: &PathBuf) -> Result<(), ConfigError> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Get a preset configuration
    pub fn preset(name: &str) -> Option<Self> {
        match name {
            "production" => Some(Self {
                name: "production".to_string(),
                enabled_categories: Some(vec![
                    "secrets".to_string(),
                    "pii".to_string(),
                    "security".to_string(),
                    "code-quality".to_string(),
                ]),
                strict_mode: StrictMode::Strict,
                performance_mode: PerformanceMode::Optimized,
                exit_on_findings: true,
                max_file_size_mb: 5,
                binary_file_detection: true,
                gitignore_respect: true,
                output_format: OutputFormat::Sarif,
                timeout_seconds: 60,
                bundle: Bundle::new(vec![]),
            }),
            "pipeline" => Some(Self {
                name: "pipeline".to_string(),
                enabled_categories: Some(vec![
                    "secrets".to_string(),
                    "pii".to_string(),
                    "security".to_string(),
                    "code-quality".to_string(),
                    "devops".to_string(),
                ]),
                strict_mode: StrictMode::Standard,
                performance_mode: PerformanceMode::Optimized,
                exit_on_findings: true,
                max_file_size_mb: 10,
                binary_file_detection: true,
                gitignore_respect: true,
                output_format: OutputFormat::Json,
                timeout_seconds: 300,
                bundle: Bundle::new(vec![]),
            }),
            "development" => Some(Self {
                name: "development".to_string(),
                enabled_categories: None, // All categories
                strict_mode: StrictMode::Standard,
                performance_mode: PerformanceMode::Debug,
                exit_on_findings: false,
                max_file_size_mb: 50,
                binary_file_detection: false,
                gitignore_respect: true,
                output_format: OutputFormat::Human,
                timeout_seconds: 0, // No timeout
                bundle: Bundle::new(vec![]),
            }),
            "mcp" => Some(Self {
                name: "mcp".to_string(),
                enabled_categories: None,
                strict_mode: StrictMode::Standard,
                performance_mode: PerformanceMode::Optimized,
                exit_on_findings: false,
                max_file_size_mb: 10,
                binary_file_detection: true,
                gitignore_respect: true,
                output_format: OutputFormat::Json,
                timeout_seconds: 30,
                bundle: Bundle::new(vec![]),
            }),
            _ => None,
        }
    }

    /// List available presets
    pub fn list_presets() -> Vec<&'static str> {
        vec!["production", "pipeline", "development", "mcp"]
    }

    /// Create a default configuration
    pub fn default_config() -> Self {
        Self {
            name: "default".to_string(),
            enabled_categories: None,
            strict_mode: StrictMode::Standard,
            performance_mode: PerformanceMode::Standard,
            exit_on_findings: false,
            max_file_size_mb: 10,
            binary_file_detection: true,
            gitignore_respect: true,
            output_format: OutputFormat::Human,
            timeout_seconds: 300,
            bundle: Bundle::new(vec![]),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::default_config()
    }
}

/// Config error types
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    ParseError(#[from] serde_json::Error),

    #[error("Unknown preset: {0}")]
    UnknownPreset(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preset_production() {
        let config = Config::preset("production").unwrap();
        assert_eq!(config.name, "production");
        assert!(config.exit_on_findings);
        assert_eq!(config.max_file_size_mb, 5);
    }

    #[test]
    fn test_preset_pipeline() {
        let config = Config::preset("pipeline").unwrap();
        assert_eq!(config.name, "pipeline");
        assert!(config.enabled_categories.is_some());
    }

    #[test]
    fn test_preset_unknown() {
        assert!(Config::preset("unknown").is_none());
    }

    #[test]
    fn test_list_presets() {
        let presets = Config::list_presets();
        assert!(presets.contains(&"production"));
        assert!(presets.contains(&"pipeline"));
    }

    #[test]
    fn test_output_format_display() {
        assert_eq!(OutputFormat::Human.to_string(), "human");
        assert_eq!(OutputFormat::Json.to_string(), "json");
        assert_eq!(OutputFormat::Sarif.to_string(), "sarif");
    }
}
