//! Configuration management

use serde::{Deserialize, Serialize};
use std::{fs, io};

// =============================================================================
// Original Config types
// =============================================================================

use crate::bundle::Bundle;

/// Configuration profile
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
// Mirrors the on/off CLI flags 1:1.
#[allow(clippy::struct_excessive_bools)]
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
    /// Statistical anomaly detectors a profile keeps enabled; `None` runs
    /// every detector, an empty list disables the statistical layer, and a
    /// non-empty list runs exactly the named detectors.
    #[serde(default)]
    pub anomaly_detectors: Option<Vec<String>>,
    /// Bundle path
    #[serde(skip)]
    pub bundle: Bundle,
}

fn default_timeout_cfg() -> u64 {
    300
}

fn default_true() -> bool {
    true
}

fn default_max_file_size() -> u64 {
    10
}

/// Strictness level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StrictMode {
    /// Relaxed level; applied when a profile leaves `strict_mode` unset.
    #[default]
    Permissive,
    /// Balanced level chosen by the `pipeline`, `development`, and `mcp`
    /// presets.
    Standard,
    /// Tightest level, chosen by the `production` preset.
    Strict,
}

/// Performance mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PerformanceMode {
    /// Unoptimized profile that favours introspection; the default and the
    /// `development` preset's choice.
    #[default]
    Debug,
    /// Middle-of-the-road profile used by `Config::default_config`.
    Standard,
    /// Fastest profile, picked by the `production`, `pipeline`, and `mcp`
    /// presets.
    Optimized,
}

/// Output format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// Text report meant to be read in a terminal; the default.
    #[default]
    Human,
    /// Machine-readable JSON for tooling and the `pipeline` preset.
    Json,
    /// SARIF report for code-scanning upload; the `production` preset's choice.
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
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::IoError`] if the file cannot be read and
    /// [`ConfigError::ParseError`] if it is not valid JSON.
    pub fn load(path: &std::path::PathBuf) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// Save config to a file
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::ParseError`] if the config cannot be
    /// serialized and [`ConfigError::IoError`] if the file cannot be written.
    pub fn save(&self, path: &std::path::PathBuf) -> Result<(), ConfigError> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Get a preset configuration
    #[must_use]
    pub fn preset(name: &str) -> Option<Self> {
        match name {
            "production" => Some(Self {
                name: "production".to_string(),
                enabled_categories: Some(vec![
                    "secrets".to_string(),
                    "pii".to_string(),
                    "security-hardening".to_string(),
                    "web-security".to_string(),
                    "compliance".to_string(),
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
                anomaly_detectors: None,
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
                    "ai-detection".to_string(),
                    "supply-chain".to_string(),
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
                anomaly_detectors: None,
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
                anomaly_detectors: None,
                bundle: Bundle::new(vec![]),
            }),
            "mcp-integration" => Some(Self {
                name: "mcp-integration".to_string(),
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
                anomaly_detectors: None,
                bundle: Bundle::new(vec![]),
            }),
            _ => None,
        }
    }

    /// List available presets
    #[must_use]
    pub fn list_presets() -> Vec<&'static str> {
        vec!["production", "pipeline", "development", "mcp-integration"]
    }

    /// Create a default configuration
    #[must_use]
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
            anomaly_detectors: None,
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
    /// A config file could not be read or written; wraps [`io::Error`].
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
    /// The document on disk was not valid config JSON; wraps
    /// [`serde_json::Error`].
    #[error("Parse error: {0}")]
    ParseError(#[from] serde_json::Error),
    /// No preset answers to the carried name.
    #[error("Unknown preset: {0}")]
    UnknownPreset(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_builtin_presets_match_shipped_profile_files() {
        // config/profiles/*.json is the user-facing copy of the built-in
        // presets; the two must not drift. The files omit only `#[serde(skip)]`
        // and defaulted fields, so compare the fields they actually carry.
        for name in Config::list_presets() {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../config/profiles")
                .join(format!("{name}.json"));
            let from_file = Config::load(&path)
                .unwrap_or_else(|e| panic!("shipped profile {name}.json must parse: {e}"));
            let preset = Config::preset(name)
                .unwrap_or_else(|| panic!("preset {name} must exist in list_presets"));
            assert_eq!(from_file.name, preset.name, "preset {name}");
            assert_eq!(
                from_file.enabled_categories, preset.enabled_categories,
                "preset {name}"
            );
            assert_eq!(from_file.strict_mode, preset.strict_mode, "preset {name}");
            assert_eq!(
                from_file.performance_mode, preset.performance_mode,
                "preset {name}"
            );
            assert_eq!(
                from_file.exit_on_findings, preset.exit_on_findings,
                "preset {name}"
            );
            assert_eq!(
                from_file.max_file_size_mb, preset.max_file_size_mb,
                "preset {name}"
            );
            assert_eq!(
                from_file.binary_file_detection, preset.binary_file_detection,
                "preset {name}"
            );
            assert_eq!(
                from_file.output_format, preset.output_format,
                "preset {name}"
            );
            assert_eq!(
                from_file.timeout_seconds, preset.timeout_seconds,
                "preset {name}"
            );
            assert_eq!(
                from_file.severity_threshold, preset.severity_threshold,
                "preset {name}"
            );
        }
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
        fs::write(&path, "{not json").expect("write broken json");
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
