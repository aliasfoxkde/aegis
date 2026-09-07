//! Aegis Bundler Library
//!
//! Core logic for creating pattern bundles.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use walkdir::WalkDir;

/// Pattern structure matching YAML format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    /// Stable identifier written into every finding and used by `aegis:ignore`
    /// directives, so renaming a rule breaks existing suppressions.
    pub name: String,
    /// Taxonomy bucket the rule files under, driving category filters and the
    /// risk rollup reported with a scan.
    pub category: String,
    /// Regex applied to each inspected line; a value that will not compile
    /// aborts the bundle build. Serialized under the key `match` since
    /// `match` is a reserved word in Rust.
    #[serde(rename = "match")]
    pub match_pattern: String,
    /// Whether the rule ships active; disabled entries stay in the artifact
    /// for reference but are skipped by the scanner.
    pub enabled: bool,
    /// Impact rating assigned to hits — `low`, `medium`, `high`, or
    /// `critical` — which sets their weight in the risk score.
    pub severity: String,
    /// Expected rate of true positives (`low`, `medium`, `high`); low-
    /// confidence rules read as signals to review rather than verdicts.
    pub confidence: String,
    /// Shannon-entropy floor a candidate must clear before it is reported,
    /// used to cut random-looking false positives in broad secret rules;
    /// `None` means no entropy gate.
    #[serde(default, alias = "minEntropy")]
    pub min_entropy: Option<f64>,
    /// Human-readable explanation carried with each hit so consumers can show
    /// context without consulting the rule source.
    pub description: String,
    /// Optional link to authoritative documentation for the flagged issue.
    #[serde(default)]
    pub reference: Option<String>,
    /// Free-form labels used for grouping, reporting, or excluding rules.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Confine the rule to environment-variable scanning so it can never fire
    /// on file content.
    #[serde(default)]
    pub env_var: bool,
    /// Let the rule match inside binary files, which the scanner otherwise
    /// skips entirely.
    #[serde(default)]
    pub binary: bool,
    /// Suppress finding when this regex also matches the matched span
    #[serde(default)]
    pub exclude: Option<String>,
    /// Restrict pattern to these file extensions; empty = all files
    #[serde(default, alias = "fileExtensions")]
    pub file_extensions: Vec<String>,
}

/// Bundle structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    /// Format revision stamped into the artifact; consumers reject a version
    /// they do not implement, so it only changes with a breaking layout.
    pub schema_version: u32,
    /// Build time as a decimal count of seconds since the Unix epoch, which
    /// makes two artifacts of the same input distinguishable.
    pub created_at: String,
    /// Rules carried by the artifact, in the order the input YAML files were
    /// walked; this is the payload everything else describes.
    pub patterns: Vec<Pattern>,
}

/// Read patterns from a directory of YAML files
///
/// # Errors
///
/// Returns an error when `input_dir` does not exist or is not a directory,
/// when a `*.yaml` file cannot be read or parsed, or when a pattern's
/// `match` regex fails to compile.
pub fn read_patterns_from_dir(input_dir: &Path) -> Result<Vec<Pattern>> {
    // A missing or non-directory input would otherwise walk zero entries
    // and silently produce a valid-looking but empty bundle.
    if !input_dir.is_dir() {
        anyhow::bail!(
            "input directory does not exist or is not a directory: {}",
            input_dir.display()
        );
    }

    let mut patterns = Vec::new();

    for entry in WalkDir::new(input_dir)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;

        let yaml_patterns: Vec<Pattern> = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse {}", path.display()))?;

        for yaml_pat in yaml_patterns {
            // Fail closed: a pattern whose regex will never compile must
            // abort the bundle build, not silently shrink coverage.
            if let Err(err) = regex::Regex::new(&yaml_pat.match_pattern) {
                anyhow::bail!(
                    "Invalid regex in pattern '{}' from {}: {err}",
                    yaml_pat.name,
                    path.display()
                );
            }

            patterns.push(yaml_pat);
        }
    }

    Ok(patterns)
}

/// Create a bundle from patterns
///
/// # Panics
///
/// Panics if the system clock is set before the Unix epoch, so the created
/// timestamp cannot be computed.
#[must_use]
pub fn create_bundle(patterns: Vec<Pattern>) -> Bundle {
    Bundle {
        schema_version: 2,
        created_at: format!(
            "{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ),
        patterns,
    }
}

/// Serialize and compress a bundle
///
/// # Errors
///
/// Returns an error when the bundle cannot be serialized to JSON or the
/// gzip stream cannot be written or finished.
pub fn serialize_bundle(bundle: &Bundle) -> Result<Vec<u8>> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    let json = serde_json::to_string(bundle)?;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(json.as_bytes())?;
    let compressed = encoder.finish()?;

    Ok(compressed)
}

/// Full bundle creation from directory
///
/// # Errors
///
/// Returns an error when [`read_patterns_from_dir`] fails or when the
/// bundle cannot be serialized and compressed.
pub fn create_bundle_from_dir(input_dir: &Path) -> Result<Vec<u8>> {
    let patterns = read_patterns_from_dir(input_dir)?;
    let bundle = create_bundle(patterns);
    serialize_bundle(&bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_pattern_serialization() {
        let pattern = Pattern {
            name: "test-pattern".to_string(),
            category: "test".to_string(),
            match_pattern: r"secret_\w+".to_string(),
            enabled: true,
            severity: "high".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Test pattern".to_string(),
            reference: None,
            tags: vec![],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: Vec::new(),
        };

        let json = serde_json::to_string(&pattern).unwrap();
        assert!(json.contains("test-pattern"));
    }

    #[test]
    fn test_bundle_creation() {
        let patterns = vec![
            Pattern {
                name: "test-1".to_string(),
                category: "test".to_string(),
                match_pattern: r"pattern1".to_string(),
                enabled: true,
                severity: "high".to_string(),
                confidence: "high".to_string(),
                min_entropy: None,
                description: "Test 1".to_string(),
                reference: None,
                tags: vec![],
                env_var: false,
                binary: false,
                exclude: None,
                file_extensions: Vec::new(),
            },
            Pattern {
                name: "test-2".to_string(),
                category: "test".to_string(),
                match_pattern: r"pattern2".to_string(),
                enabled: true,
                severity: "low".to_string(),
                confidence: "low".to_string(),
                min_entropy: None,
                description: "Test 2".to_string(),
                reference: None,
                tags: vec![],
                env_var: false,
                binary: false,
                exclude: None,
                file_extensions: Vec::new(),
            },
        ];

        let bundle = create_bundle(patterns);
        assert_eq!(bundle.schema_version, 2);
        assert_eq!(bundle.patterns.len(), 2);
    }

    #[test]
    fn test_serialize_bundle() {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let patterns = vec![Pattern {
            name: "test".to_string(),
            category: "test".to_string(),
            match_pattern: r"test".to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Test".to_string(),
            reference: None,
            tags: vec![],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: Vec::new(),
        }];

        let bundle = create_bundle(patterns);
        let compressed = serialize_bundle(&bundle).unwrap();

        // Should be able to decompress
        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut decompressed = String::new();
        decoder.read_to_string(&mut decompressed).unwrap();

        assert!(decompressed.contains("test"));
        assert!(decompressed.contains("schema_version"));
    }

    #[test]
    fn test_read_patterns_from_dir() {
        // Create a temp directory with a YAML file
        let temp_dir = TempDir::new().unwrap();
        let yaml_file = temp_dir.path().join("patterns.yaml");

        let yaml_content = r#"
- name: test-yaml-pattern
  category: test
  match: "test_pattern"
  enabled: true
  severity: high
  confidence: medium
  description: A test pattern from YAML
"#;

        std::fs::write(&yaml_file, yaml_content).unwrap();

        let patterns = read_patterns_from_dir(temp_dir.path()).unwrap();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].name, "test-yaml-pattern");
    }

    #[test]
    fn test_invalid_regex_ignored() {
        let temp_dir = TempDir::new().unwrap();
        let yaml_file = temp_dir.path().join("patterns.yaml");

        // Invalid regex with unbalanced parens
        let yaml_content = r#"
- name: bad-pattern
  category: test
  match: "(unbalanced"
  enabled: true
  severity: high
  confidence: medium
  description: Bad pattern
"#;

        std::fs::write(&yaml_file, yaml_content).unwrap();

        // Fail closed: the build must abort and name the offending pattern
        let err = read_patterns_from_dir(temp_dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("bad-pattern"),
            "error must name the offending pattern: {err}"
        );
    }

    #[test]
    fn test_read_patterns_from_dir_empty() {
        let temp_dir = TempDir::new().unwrap();
        // Don't create any yaml files
        let patterns = read_patterns_from_dir(temp_dir.path()).unwrap();
        assert_eq!(patterns.len(), 0);
    }

    #[test]
    fn test_read_patterns_from_dir_ignores_non_yaml() {
        let temp_dir = TempDir::new().unwrap();
        let txt_file = temp_dir.path().join("readme.txt");
        std::fs::write(&txt_file, "not a yaml file").unwrap();

        let patterns = read_patterns_from_dir(temp_dir.path()).unwrap();
        assert_eq!(patterns.len(), 0);
    }

    #[test]
    fn test_create_bundle_with_timestamp() {
        let patterns = vec![Pattern {
            name: "test".to_string(),
            category: "test".to_string(),
            match_pattern: "test".to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Test".to_string(),
            reference: None,
            tags: vec![],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: Vec::new(),
        }];

        let bundle = create_bundle(patterns);
        // Timestamp should be set
        assert!(!bundle.created_at.is_empty());
        assert_eq!(bundle.schema_version, 2);
    }

    #[test]
    fn test_create_bundle_from_dir() {
        let temp_dir = TempDir::new().unwrap();
        let yaml_file = temp_dir.path().join("patterns.yaml");
        let yaml_content = r#"
- name: test-pattern
  category: test
  match: "test"
  enabled: true
  severity: medium
  confidence: medium
  description: Test
"#;
        std::fs::write(&yaml_file, yaml_content).unwrap();

        let result = create_bundle_from_dir(temp_dir.path());
        assert!(result.is_ok());
        let compressed = result.unwrap();
        assert!(!compressed.is_empty());
    }

    #[test]
    fn test_pattern_yaml_deserialization() {
        let yaml_content = r#"
- name: yaml-test
  category: secrets
  match: "password123"
  enabled: true
  severity: high
  confidence: high
  description: Test pattern
  min_entropy: 4.0
"#;
        let patterns: Vec<Pattern> = serde_yaml::from_str(yaml_content).unwrap();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].name, "yaml-test");
        assert_eq!(patterns[0].min_entropy, Some(4.0));
    }

    #[test]
    fn test_pattern_with_all_fields() {
        let pattern = Pattern {
            name: "full-pattern".to_string(),
            category: "secrets".to_string(),
            match_pattern: "secret".to_string(),
            enabled: true,
            severity: "critical".to_string(),
            confidence: "high".to_string(),
            min_entropy: Some(4.5),
            description: "Full test pattern".to_string(),
            reference: Some("https://example.com".to_string()),
            tags: vec!["tag1".to_string(), "tag2".to_string()],
            env_var: true,
            binary: false,
            exclude: None,
            file_extensions: Vec::new(),
        };

        // Test serialization
        let json = serde_json::to_string(&pattern).unwrap();
        assert!(json.contains("full-pattern"));
        assert!(json.contains("tag1"));

        // Test deserialization
        let deserialized: Pattern = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "full-pattern");
        assert_eq!(deserialized.tags, vec!["tag1", "tag2"]);
    }

    #[test]
    fn test_bundle_deserialization() {
        let patterns = vec![Pattern {
            name: "test".to_string(),
            category: "test".to_string(),
            match_pattern: "test".to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Test".to_string(),
            reference: None,
            tags: vec![],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: Vec::new(),
        }];

        let bundle = create_bundle(patterns);
        let json = serde_json::to_string(&bundle).unwrap();
        let deserialized: Bundle = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.schema_version, 2);
        assert_eq!(deserialized.patterns.len(), 1);
    }
}
