//! Configuration management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::{fs, io};

// =============================================================================
// Preset Configuration (YAML-based)
// =============================================================================

/// Preset configuration for scan bundles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlPreset {
    /// Preset name
    pub name: String,
    /// Description
    #[serde(default)]
    pub description: String,
    /// Version
    #[serde(default = "default_version")]
    pub version: String,
    /// Categories to enable
    #[serde(default)]
    pub enabled_categories: Vec<String>,
    /// Categories to disable
    #[serde(default)]
    pub disabled_categories: Vec<String>,
    /// Include patterns
    #[serde(default)]
    pub include_patterns: Vec<String>,
    /// Exclude patterns
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    /// Max file size in MB
    #[serde(default = "default_max_file_size")]
    pub max_file_size_mb: u64,
    /// Follow symlinks
    #[serde(default)]
    pub follow_symlinks: bool,
    /// Scan binary files
    #[serde(default)]
    pub scan_binary: bool,
    /// Use gitignore
    #[serde(default = "default_true")]
    pub gitignore_respect: bool,
    /// Use atheonignore
    #[serde(default = "default_true")]
    pub gitignore_atheon_respect: bool,
    /// Output formats
    #[serde(default)]
    pub output_formats: Vec<YamlOutputFormatConfig>,
    /// Webhooks
    #[serde(default)]
    pub webhooks: Vec<YamlWebhookConfig>,
    /// Database outputs
    #[serde(default)]
    pub database_outputs: Vec<YamlDatabaseOutputConfig>,
    /// Severity threshold
    #[serde(default)]
    pub severity_threshold: Option<String>,
    /// Risk weights
    #[serde(default)]
    pub risk_weights: HashMap<String, f64>,
    /// Scan env vars
    #[serde(default)]
    pub scan_env_vars: bool,
    /// Custom settings
    #[serde(default)]
    pub settings: HashMap<String, serde_json::Value>,
}

fn default_version() -> String {
    "1.0".to_string()
}
fn default_max_file_size() -> u64 {
    10
}
fn default_true() -> bool {
    true
}
fn default_retries() -> u32 {
    3
}
fn default_timeout() -> u64 {
    30
}
fn default_table_name() -> String {
    "aegis_findings".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlOutputFormatConfig {
    pub format: YamlOutputFormatType,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub append: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum YamlOutputFormatType {
    Human,
    Json,
    Sarif,
    Csv,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlWebhookConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub webhook_type: YamlWebhookType,
    pub url: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_retries")]
    pub retries: u32,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum YamlWebhookType {
    Http,
    Discord,
    Slack,
    Teams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlDatabaseOutputConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub database_type: YamlDatabaseType,
    pub connection: String,
    #[serde(default = "default_table_name")]
    pub table_name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum YamlDatabaseType {
    Sqlite,
    PostgreSql,
    MySql,
}

impl YamlPreset {
    /// Load from YAML file
    pub fn from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        content.parse()
    }

    /// Save to YAML file
    pub fn to_file(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let yaml = serde_yaml::to_string(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, yaml)
    }

    /// Convert to Config
    pub fn to_config(&self) -> Config {
        Config {
            name: self.name.clone(),
            enabled_categories: (!self.enabled_categories.is_empty())
                .then(|| self.enabled_categories.clone()),
            max_file_size_mb: self.max_file_size_mb,
            gitignore_respect: self.gitignore_respect,
            severity_threshold: self.severity_threshold.clone(),
            ..Config::default()
        }
    }
}

impl FromStr for YamlPreset {
    type Err = io::Error;

    fn from_str(yaml: &str) -> Result<Self, Self::Err> {
        serde_yaml::from_str(yaml).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Preset registry
#[derive(Debug, Default)]
pub struct YamlPresetRegistry {
    presets: HashMap<String, YamlPreset>,
}

impl YamlPresetRegistry {
    pub fn new() -> Self {
        Self {
            presets: HashMap::new(),
        }
    }

    pub fn load_directory(&mut self, path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref();
        if !path.is_dir() {
            return Err(io::Error::other(format!(
                "{} is not a directory",
                path.display()
            )));
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let p = entry.path();
            if p.extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
            {
                if let Ok(preset) = YamlPreset::from_file(&p) {
                    self.presets.insert(preset.name.clone(), preset);
                }
            }
        }
        Ok(())
    }

    pub fn register(&mut self, preset: YamlPreset) {
        self.presets.insert(preset.name.clone(), preset);
    }

    pub fn get(&self, name: &str) -> Option<&YamlPreset> {
        self.presets.get(name)
    }

    pub fn list(&self) -> Vec<String> {
        self.presets.keys().cloned().collect()
    }
}

// =============================================================================
// Original Config types
// =============================================================================

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
    #[serde(default = "default_timeout_cfg")]
    pub timeout_seconds: u64,
    /// Severity threshold
    #[serde(default)]
    pub severity_threshold: Option<String>,
    /// Bundle path
    #[serde(skip)]
    pub bundle: Bundle,
}

fn default_timeout_cfg() -> u64 {
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
    pub fn load(path: &std::path::PathBuf) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// Save config to a file
    pub fn save(&self, path: &std::path::PathBuf) -> Result<(), ConfigError> {
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
                severity_threshold: None,
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
                severity_threshold: None,
                bundle: Bundle::new(vec![]),
            }),
            "development" => Some(Self {
                name: "development".to_string(),
                enabled_categories: None,
                strict_mode: StrictMode::Standard,
                performance_mode: PerformanceMode::Debug,
                exit_on_findings: false,
                max_file_size_mb: 50,
                binary_file_detection: false,
                gitignore_respect: true,
                output_format: OutputFormat::Human,
                timeout_seconds: 0,
                severity_threshold: None,
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
                severity_threshold: None,
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
            severity_threshold: None,
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
    fn test_preset_parse_yaml() {
        let yaml = r#"
name: test-preset
description: Test preset
enabled_categories:
  - secrets
  - pii
max_file_size_mb: 5
"#;
        let preset: YamlPreset = yaml.parse().unwrap();
        assert_eq!(preset.name, "test-preset");
        assert_eq!(preset.enabled_categories, vec!["secrets", "pii"]);
        assert_eq!(preset.max_file_size_mb, 5);
    }

    #[test]
    fn test_preset_to_config() {
        let yaml = r#"
name: test
enabled_categories:
  - secrets
max_file_size_mb: 15
"#;
        let preset: YamlPreset = yaml.parse().unwrap();
        let config = preset.to_config();
        assert_eq!(config.enabled_categories, Some(vec!["secrets".to_string()]));
        assert_eq!(config.max_file_size_mb, 15);
    }

    #[test]
    fn test_preset_list() {
        let registry = YamlPresetRegistry::new();
        assert!(registry.list().is_empty());
    }

    #[test]
    fn test_config_preset_production() {
        let config = Config::preset("production").unwrap();
        assert_eq!(config.name, "production");
        assert!(config.exit_on_findings);
    }

    #[test]
    fn test_output_format_display() {
        assert_eq!(OutputFormat::Human.to_string(), "human");
        assert_eq!(OutputFormat::Json.to_string(), "json");
        assert_eq!(OutputFormat::Sarif.to_string(), "sarif");
    }

    #[test]
    fn test_strict_mode_default() {
        assert_eq!(StrictMode::default(), StrictMode::Permissive);
    }
}
