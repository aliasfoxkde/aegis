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
    /// Respect .aegisignore (or legacy .atheonignore)
    #[serde(default = "default_true", alias = "gitignore_atheon_respect")]
    pub aegisignore_respect: bool,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
            aegisignore_respect: self.aegisignore_respect,
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
    /// Respect .aegisignore (or legacy .atheonignore)
    #[serde(default = "default_true", alias = "gitignore_atheon_respect")]
    pub aegisignore_respect: bool,
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
                    "security-hardening".to_string(),
                    "web-security".to_string(),
                    "code-quality".to_string(),
                ]),
                strict_mode: StrictMode::Strict,
                performance_mode: PerformanceMode::Optimized,
                exit_on_findings: true,
                max_file_size_mb: 5,
                binary_file_detection: true,
                gitignore_respect: true,
                aegisignore_respect: true,
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
                    "security-hardening".to_string(),
                    "web-security".to_string(),
                    "code-quality".to_string(),
                    "devops".to_string(),
                ]),
                strict_mode: StrictMode::Standard,
                performance_mode: PerformanceMode::Optimized,
                exit_on_findings: true,
                max_file_size_mb: 10,
                binary_file_detection: true,
                gitignore_respect: true,
                aegisignore_respect: true,
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
                aegisignore_respect: true,
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
                aegisignore_respect: true,
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
            aegisignore_respect: true,
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

    #[test]
    fn yaml_preset_defaults_fill_in_from_minimal_document() {
        let preset: YamlPreset = "name: minimal".parse().expect("minimal preset");
        assert_eq!(preset.version, "1.0");
        assert_eq!(preset.max_file_size_mb, 10);
        assert!(preset.gitignore_respect && preset.aegisignore_respect);
        assert!(!preset.scan_binary && !preset.follow_symlinks);
        assert!(preset.enabled_categories.is_empty());
        assert!(preset.output_formats.is_empty());
        assert!(preset.webhooks.is_empty());
        assert!(preset.database_outputs.is_empty());
    }

    #[test]
    fn invalid_yaml_is_rejected_as_invalid_data() {
        let error = "name: [unclosed".parse::<YamlPreset>().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn yaml_preset_file_round_trip_preserves_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("preset.yaml");
        let yaml = r#"
name: full
enabled_categories: [secrets, pii]
webhooks:
  - name: alert
    type: slack
    url: https://hooks.example.com/T000/B000/XXXXXXXX
    retries: 5
database_outputs:
  - name: ledger
    type: postgresql
    connection: postgresql://localhost/aegis
output_formats:
  - format: sarif
    path: out.sarif
"#;
        let preset: YamlPreset = yaml.parse().expect("parse preset");
        preset.to_file(&path).expect("write preset");

        let loaded = YamlPreset::from_file(&path).expect("read preset");
        assert_eq!(loaded.name, "full");
        assert_eq!(loaded.webhooks.len(), 1);
        assert_eq!(loaded.webhooks[0].webhook_type, YamlWebhookType::Slack);
        assert_eq!(loaded.webhooks[0].retries, 5);
        assert!(loaded.webhooks[0].enabled);
        assert_eq!(
            loaded.database_outputs[0].database_type,
            YamlDatabaseType::PostgreSql
        );
        assert_eq!(loaded.database_outputs[0].table_name, "aegis_findings");
        assert_eq!(loaded.output_formats[0].format, YamlOutputFormatType::Sarif);
    }

    #[test]
    fn to_config_propagates_scanner_relevant_fields() {
        let preset: YamlPreset = r#"
name: propagated
enabled_categories: [secrets]
gitignore_respect: false
aegisignore_respect: false
severity_threshold: high
"#
        .parse()
        .expect("parse preset");
        let config = preset.to_config();
        assert_eq!(config.name, "propagated");
        assert_eq!(config.enabled_categories, Some(vec!["secrets".to_string()]));
        assert!(!config.gitignore_respect);
        assert!(!config.aegisignore_respect);
        assert_eq!(config.severity_threshold.as_deref(), Some("high"));
    }

    #[test]
    fn to_config_with_no_categories_leaves_selection_open() {
        let preset: YamlPreset = "name: open".parse().expect("parse preset");
        assert!(preset.to_config().enabled_categories.is_none());
    }

    #[test]
    fn registry_registers_gets_and_overwrites_by_name() {
        let mut registry = YamlPresetRegistry::new();
        let first: YamlPreset = "name: dup".parse().expect("first");
        let second: YamlPreset = "name: dup\nmax_file_size_mb: 3".parse().expect("second");
        registry.register(first);
        registry.register(second);
        assert_eq!(registry.get("dup").expect("registered").max_file_size_mb, 3);
        assert!(registry.get("missing").is_none());
        assert_eq!(registry.list(), vec!["dup".to_string()]);
    }

    #[test]
    fn registry_load_directory_reads_yaml_and_yml_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("alpha.yaml"), "name: alpha").expect("write yaml");
        std::fs::write(dir.path().join("beta.yml"), "name: beta").expect("write yml");
        std::fs::write(dir.path().join("gamma.json"), "name: gamma").expect("write json");
        std::fs::write(dir.path().join("broken.yaml"), "name: [oops").expect("write broken");

        let mut registry = YamlPresetRegistry::new();
        registry.load_directory(dir.path()).expect("load directory");
        let mut names = registry.list();
        names.sort();
        assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[test]
    fn registry_load_directory_rejects_non_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").expect("write file");
        let mut registry = YamlPresetRegistry::new();
        let error = registry.load_directory(&file).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn every_listed_preset_resolves() {
        for name in Config::list_presets() {
            assert!(
                Config::preset(name).is_some(),
                "listed preset {name} must resolve"
            );
        }
        assert!(Config::preset("no-such-preset").is_none());
    }

    #[test]
    fn config_save_and_load_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.json");
        let config = Config::preset("production").expect("production preset");
        config.save(&path).expect("save config");
        let loaded = Config::load(&path).expect("load config");
        assert_eq!(loaded.name, "production");
        assert_eq!(loaded.strict_mode, StrictMode::Strict);
        assert_eq!(loaded.output_format, OutputFormat::Sarif);
        assert_eq!(loaded.max_file_size_mb, 5);
    }

    #[test]
    fn config_load_missing_file_is_io_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = Config::load(&dir.path().join("absent.json")).unwrap_err();
        assert!(matches!(error, ConfigError::IoError(_)));
    }

    #[test]
    fn config_load_malformed_json_is_parse_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("broken.json");
        std::fs::write(&path, "{not json").expect("write broken json");
        let error = Config::load(&path).unwrap_err();
        assert!(matches!(error, ConfigError::ParseError(_)));
    }

    #[test]
    fn default_config_and_default_impl_agree() {
        assert_eq!(Config::default_config().name, "default");
        let (default, manual) = (Config::default(), Config::default_config());
        assert_eq!(default.strict_mode, manual.strict_mode);
        assert_eq!(default.max_file_size_mb, manual.max_file_size_mb);
        assert_eq!(default.timeout_seconds, manual.timeout_seconds);
        assert!(!default.exit_on_findings);
    }

    #[test]
    fn serde_defaults_apply_for_sparse_documents() {
        let config: Config = serde_json::from_str("{}").expect("sparse config");
        assert_eq!(config.timeout_seconds, 300);
        assert_eq!(config.max_file_size_mb, 10);
        assert!(config.exit_on_findings);
        assert_eq!(config.output_format, OutputFormat::Human);
    }

    #[test]
    fn output_format_serde_round_trip() {
        for (text, expected) in [
            ("human", OutputFormat::Human),
            ("json", OutputFormat::Json),
            ("sarif", OutputFormat::Sarif),
        ] {
            let parsed: OutputFormat = serde_json::from_value(serde_json::json!(text))
                .unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(parsed, expected);
            assert_eq!(expected.to_string(), text);
        }
    }

    #[test]
    fn aegisignore_alias_still_deserializes() {
        let config: Config =
            serde_json::from_str(r#"{ "gitignore_atheon_respect": false }"#).expect("aliased");
        assert!(!config.aegisignore_respect);
    }
}
