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
    pub name: String,
    pub category: String,
    #[serde(rename = "match")]
    pub match_pattern: String,
    pub enabled: bool,
    pub severity: String,
    pub confidence: String,
    #[serde(default)]
    pub min_entropy: Option<f64>,
    pub description: String,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub env_var: bool,
    #[serde(default)]
    pub binary: bool,
}

/// Bundle structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub schema_version: u32,
    pub created_at: String,
    pub patterns: Vec<Pattern>,
}

/// Read patterns from a directory of YAML files
pub fn read_patterns_from_dir(input_dir: &Path) -> Result<Vec<Pattern>> {
    let mut patterns = Vec::new();

    for entry in WalkDir::new(input_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }

        let content =
            std::fs::read_to_string(path).with_context(|| format!("Failed to read {:?}", path))?;

        let yaml_patterns: Vec<Pattern> = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse {:?}", path))?;

        for yaml_pat in yaml_patterns {
            // Validate regex
            if regex::Regex::new(&yaml_pat.match_pattern).is_err() {
                eprintln!("  Warning: Invalid regex in pattern '{}'", yaml_pat.name);
                continue;
            }

            patterns.push(yaml_pat);
        }
    }

    Ok(patterns)
}

/// Create a bundle from patterns
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
pub fn serialize_bundle(bundle: &Bundle) -> Result<Vec<u8>> {
    let json = serde_json::to_string(bundle)?;

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(json.as_bytes())?;
    let compressed = encoder.finish()?;

    Ok(compressed)
}

/// Full bundle creation from directory
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
            },
        ];

        let bundle = create_bundle(patterns);
        assert_eq!(bundle.schema_version, 2);
        assert_eq!(bundle.patterns.len(), 2);
    }

    #[test]
    fn test_serialize_bundle() {
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
        }];

        let bundle = create_bundle(patterns);
        let compressed = serialize_bundle(&bundle).unwrap();

        // Should be able to decompress
        use flate2::read::GzDecoder;
        use std::io::Read;
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

        // Should not panic, just warn and skip
        let patterns = read_patterns_from_dir(temp_dir.path()).unwrap();
        assert_eq!(patterns.len(), 0);
    }
}
