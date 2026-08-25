//! # YAML Preset Configuration System
//!
//! Supports reusable scan configuration bundles with include/compose semantics.
//! Inspired by BBOT's YAML preset system.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::{fmt::Debug, fs, io};

/// Preset configuration for scan bundles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preset {
    /// Preset name
    pub name: String,
    /// Description of what this preset does
    #[serde(default)]
    pub description: String,
    /// Version of the preset format
    #[serde(default = "default_version")]
    pub version: String,
    /// Categories to enable
    #[serde(default)]
    pub enabled_categories: Vec<String>,
    /// Categories to disable
    #[serde(default)]
    pub disabled_categories: Vec<String>,
    /// Custom pattern paths to include
    #[serde(default)]
    pub include_patterns: Vec<String>,
    /// Patterns to exclude
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    /// Maximum file size in MB
    #[serde(default = "default_max_file_size")]
    pub max_file_size_mb: u64,
    /// Follow symbolic links
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
    /// Output formats to use
    #[serde(default)]
    pub output_formats: Vec<OutputFormatConfig>,
    /// Webhook configurations
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,
    /// Database output configurations
    #[serde(default)]
    pub database_outputs: Vec<DatabaseOutputConfig>,
    /// Severity threshold
    #[serde(default)]
    pub severity_threshold: Option<String>,
    /// Risk score weights
    #[serde(default)]
    pub risk_weights: HashMap<String, f64>,
    /// Environment variables to scan
    #[serde(default)]
    pub scan_env_vars: bool,
    /// Custom settings as key-value pairs
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

/// Output format configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputFormatConfig {
    /// Format type
    pub format: OutputFormatType,
    /// Output path (for file outputs)
    #[serde(default)]
    pub path: Option<String>,
    /// Whether to append (for file outputs)
    #[serde(default)]
    pub append: bool,
}

/// Output format types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormatType {
    /// Human-readable
    Human,
    /// JSON format
    Json,
    /// SARIF format
    Sarif,
    /// CSV format
    Csv,
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook name
    pub name: String,
    /// Webhook type
    #[serde(rename = "type")]
    pub webhook_type: WebhookType,
    /// URL for the webhook
    pub url: String,
    /// Enable/disable this webhook
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Number of retries
    #[serde(default = "default_retries")]
    pub retries: u32,
    /// Timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_retries() -> u32 {
    3
}

fn default_timeout() -> u64 {
    30
}

/// Webhook types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebhookType {
    /// HTTP generic webhook
    Http,
    /// Discord webhook
    Discord,
    /// Slack webhook
    Slack,
    /// Microsoft Teams webhook
    Teams,
}

/// Database output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseOutputConfig {
    /// Database name
    pub name: String,
    /// Database type
    #[serde(rename = "type")]
    pub database_type: DatabaseType,
    /// Connection string or path
    pub connection: String,
    /// Table name
    #[serde(default = "default_table_name")]
    pub table_name: String,
    /// Enable/disable this output
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_table_name() -> String {
    "aegis_findings".to_string()
}

/// Database types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseType {
    /// SQLite
    Sqlite,
    /// PostgreSQL
    PostgreSql,
    /// MySQL
    MySql,
}

impl Preset {
    /// Load a preset from a YAML file
    pub fn from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        Self::from_str(&content)
    }

    /// Parse a preset from YAML string
    pub fn from_str(yaml: &str) -> io::Result<Self> {
        serde_yaml::from_str(yaml)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Save a preset to a YAML file
    pub fn to_file(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let yaml = self.to_string()?;
        fs::write(path, yaml)
    }

    /// Convert preset to YAML string
    pub fn to_string(&self) -> io::Result<String> {
        serde_yaml::to_string(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Merge multiple presets together (later presets override earlier ones)
    pub fn merge(&self, other: &Preset) -> Preset {
        let mut merged = self.clone();

        // Override fields with other's values if present
        if !other.enabled_categories.is_empty() {
            merged.enabled_categories = other.enabled_categories.clone();
        }
        if !other.disabled_categories.is_empty() {
            merged.disabled_categories = other.disabled_categories.clone();
        }
        if !other.include_patterns.is_empty() {
            merged.include_patterns = other.include_patterns.clone();
        }
        if !other.exclude_patterns.is_empty() {
            merged.exclude_patterns = other.exclude_patterns.clone();
        }
        if other.max_file_size_mb != 10 {
            merged.max_file_size_mb = other.max_file_size_mb;
        }
        merged.follow_symlinks = other.follow_symlinks;
        merged.scan_binary = other.scan_binary;
        merged.gitignore_respect = other.gitignore_respect;
        merged.gitignore_atheon_respect = other.gitignore_atheon_respect;

        // Merge collections
        merged.output_formats.extend(other.output_formats.clone());
        merged.webhooks.extend(other.webhooks.clone());
        merged.database_outputs.extend(other.database_outputs.clone());

        for (key, value) in &other.settings {
            merged.settings.insert(key.clone(), value.clone());
        }
        for (key, value) in &other.risk_weights {
            merged.risk_weights.insert(key.clone(), *value);
        }

        merged
    }

    /// Apply preset to create a resolved config
    pub fn to_config(&self) -> crate::Config {
        let mut config = crate::Config::default();

        config.enabled_categories = if self.enabled_categories.is_empty() {
            None
        } else {
            Some(self.enabled_categories.clone())
        };

        config.max_file_size_mb = self.max_file_size_mb;
        config.gitignore_respect = self.gitignore_respect;
        config.severity_threshold = self.severity_threshold.clone();

        config
    }
}

/// Preset registry for managing multiple presets
#[derive(Debug, Default)]
pub struct PresetRegistry {
    presets: HashMap<String, Preset>,
}

impl PresetRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            presets: HashMap::new(),
        }
    }

    /// Load presets from a directory
    pub fn load_directory(&mut self, path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref();
        if !path.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!("{} is not a directory", path.display()),
            ));
        }

        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "yaml" || ext == "yml") {
                if let Ok(preset) = Preset::from_file(&path) {
                    self.presets.insert(preset.name.clone(), preset);
                }
            }
        }

        Ok(())
    }

    /// Register a preset
    pub fn register(&mut self, preset: Preset) {
        self.presets.insert(preset.name.clone(), preset);
    }

    /// Get a preset by name
    pub fn get(&self, name: &str) -> Option<&Preset> {
        self.presets.get(name)
    }

    /// List all preset names
    pub fn list(&self) -> Vec<String> {
        self.presets.keys().cloned().collect()
    }

    /// Resolve a preset with its includes
    pub fn resolve(&self, name: &str) -> Option<Preset> {
        let preset = self.presets.get(name)?;
        Some(preset.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preset_parse() {
        let yaml = r#"
name: test-preset
description: Test preset for security scanning
version: "1.0"
enabled_categories:
  - secrets
  - pii
disabled_categories:
  - code-quality
max_file_size_mb: 5
follow_symlinks: true
scan_binary: false
output_formats:
  - format: json
    path: /tmp/findings.json
webhooks:
  - name: slack-alerts
    type: slack
    url: https://hooks.slack.com/services/xxx
    enabled: true
"#;
        let preset = Preset::from_str(yaml).unwrap();
        assert_eq!(preset.name, "test-preset");
        assert_eq!(preset.enabled_categories, vec!["secrets", "pii"]);
        assert_eq!(preset.max_file_size_mb, 5);
        assert!(preset.follow_symlinks);
        assert_eq!(preset.webhooks.len(), 1);
        assert_eq!(preset.output_formats.len(), 1);
    }

    #[test]
    fn test_preset_merge() {
        let yaml1 = r#"
name: base
enabled_categories:
  - secrets
max_file_size_mb: 10
"#;
        let yaml2 = r#"
name: extended
enabled_categories:
  - pii
  - security
max_file_size_mb: 20
"#;
        let base: Preset = Preset::from_str(yaml1).unwrap();
        let extended: Preset = Preset::from_str(yaml2).unwrap();
        let merged = base.merge(&extended);

        assert_eq!(merged.enabled_categories, vec!["pii", "security"]);
        assert_eq!(merged.max_file_size_mb, 20);
    }

    #[test]
    fn test_preset_to_config() {
        let yaml = r#"
name: test
enabled_categories:
  - secrets
max_file_size_mb: 15
gitignore_respect: true
"#;
        let preset = Preset::from_str(yaml).unwrap();
        let config = preset.to_config();

        assert_eq!(config.enabled_categories, Some(vec!["secrets".to_string()]));
        assert_eq!(config.max_file_size_mb, 15);
    }

    #[test]
    fn test_preset_round_trip() {
        let yaml = r#"
name: roundtrip-test
description: Testing round-trip serialization
enabled_categories:
  - secrets
webhooks:
  - name: test
    type: discord
    url: https://discord.com/api/webhooks/test
    enabled: true
"#;
        let preset = Preset::from_str(yaml).unwrap();
        let serialized = preset.to_string().unwrap();
        let parsed: Preset = Preset::from_str(&serialized).unwrap();

        assert_eq!(parsed.name, preset.name);
        assert_eq!(parsed.description, preset.description);
    }
}
