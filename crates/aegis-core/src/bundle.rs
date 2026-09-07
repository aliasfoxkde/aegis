//! Pattern bundle management
//!
//! Handles loading, saving, and verification of pattern bundles.

use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use thiserror::Error;

use crate::pattern::PatternDefinition;

/// Bundle format version
pub const BUNDLE_VERSION: u32 = 2;

/// Bundle metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleMetadata {
    /// Bundle format version this metadata describes; mirrors
    /// [`Bundle::schema_version`].
    pub version: u32,
    /// Creation timestamp as reported by the platform clock, formatted as a
    /// decimal Unix-epoch-seconds string (for example `"1712345678"`).
    pub created_at: String,
    /// Number of patterns carried by the bundle.
    pub pattern_count: usize,
    /// Hex-encoded SHA-256 digest of the serialized pattern list, as
    /// produced by [`Bundle::checksum`].
    pub checksum: String,
}

/// Bundle format v2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    /// Format version the bundle was written with. Newly built bundles carry
    /// [`BUNDLE_VERSION`]; anything else fails [`Bundle::validate`].
    pub schema_version: u32,
    /// Creation timestamp as a decimal Unix-epoch-seconds string; empty for
    /// [`Bundle::default`].
    pub created_at: String,
    /// Pattern definitions shipped in this bundle, in file order.
    pub patterns: Vec<PatternDefinition>,
}

impl Default for Bundle {
    fn default() -> Self {
        Self {
            schema_version: 2,
            created_at: String::new(),
            patterns: Vec::new(),
        }
    }
}

impl Bundle {
    /// Create a new bundle
    #[must_use]
    pub fn new(patterns: Vec<PatternDefinition>) -> Self {
        Self {
            schema_version: BUNDLE_VERSION,
            created_at: chrono_now(),
            patterns,
        }
    }

    /// Load a bundle from a file
    ///
    /// # Errors
    ///
    /// Returns [`BundleError::IoError`] if the file cannot be opened or
    /// read, and any error from [`Bundle::from_gzip`] while decoding it.
    pub fn load(path: &Path) -> Result<Self, BundleError> {
        let mut file = File::open(path).map_err(BundleError::IoError)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(BundleError::IoError)?;

        Self::from_gzip(&buffer)
    }

    /// Load a bundle from gzip-compressed bytes
    ///
    /// # Errors
    ///
    /// Returns [`BundleError::DecompressError`] if the data is not valid
    /// gzip, and [`BundleError::ParseError`] if the decompressed bytes are
    /// not a valid JSON bundle.
    pub fn from_gzip(data: &[u8]) -> Result<Self, BundleError> {
        use flate2::read::GzDecoder;
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| BundleError::DecompressError(e.to_string()))?;
        let bundle: Bundle =
            serde_json::from_slice(&decompressed).map_err(BundleError::ParseError)?;
        Ok(bundle)
    }

    /// Save bundle to a file
    ///
    /// # Errors
    ///
    /// Returns [`BundleError::IoError`] if encoding fails, the staging file
    /// cannot be created or flushed, or the rename into place fails.
    pub fn save(&self, path: &Path) -> Result<(), BundleError> {
        let data = self.to_gzip()?;

        // Atomic write: write to temp file, then rename
        let temp_path = path.with_extension("tmp");
        let mut file = File::create(&temp_path).map_err(BundleError::IoError)?;
        file.write_all(&data).map_err(BundleError::IoError)?;
        file.sync_all().map_err(BundleError::IoError)?;

        fs::rename(&temp_path, path).map_err(BundleError::IoError)?;

        Ok(())
    }

    /// Convert bundle to gzip-compressed bytes
    ///
    /// # Errors
    ///
    /// Returns [`BundleError::SerializeError`] if the bundle cannot be
    /// serialized or the gzip stream cannot be finished.
    pub fn to_gzip(&self) -> Result<Vec<u8>, BundleError> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let json =
            serde_json::to_string(self).map_err(|e| BundleError::SerializeError(e.to_string()))?;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(json.as_bytes())
            .map_err(|e| BundleError::SerializeError(e.to_string()))?;
        encoder
            .finish()
            .map_err(|e| BundleError::SerializeError(e.to_string()))
    }

    /// Get the number of patterns
    #[must_use]
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Check if bundle is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Validate the bundle
    ///
    /// # Errors
    ///
    /// Returns [`BundleError::InvalidVersion`] when the schema version is
    /// not [`BUNDLE_VERSION`], [`BundleError::DuplicatePattern`] when two
    /// patterns share a name, and [`BundleError::InvalidPattern`] or
    /// [`BundleError::InvalidRegex`] when a pattern has no match expression
    /// or a match expression that does not compile.
    pub fn validate(&self) -> Result<(), BundleError> {
        if self.schema_version != BUNDLE_VERSION {
            return Err(BundleError::InvalidVersion(self.schema_version));
        }

        let mut names = std::collections::HashSet::new();
        for pattern in &self.patterns {
            if names.contains(&pattern.name) {
                return Err(BundleError::DuplicatePattern(pattern.name.clone()));
            }
            names.insert(pattern.name.clone());

            if pattern.match_pattern.is_empty() {
                return Err(BundleError::InvalidPattern(pattern.name.clone()));
            }

            // Validate regex
            if regex::Regex::new(&pattern.match_pattern).is_err() {
                return Err(BundleError::InvalidRegex(pattern.name.clone()));
            }
        }

        Ok(())
    }

    /// Get metadata
    #[must_use]
    pub fn metadata(&self) -> BundleMetadata {
        BundleMetadata {
            version: self.schema_version,
            created_at: self.created_at.clone(),
            pattern_count: self.patterns.len(),
            checksum: self.checksum(),
        }
    }

    /// Calculate SHA-256 checksum
    #[must_use]
    pub fn checksum(&self) -> String {
        use sha2::{Digest, Sha256};
        let data = serde_json::to_vec(&self.patterns).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&data);
        hex::encode(hasher.finalize())
    }
}

/// Get current timestamp in ISO format
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    format!("{secs}")
}

/// Bundle error types
#[derive(Debug, Error)]
pub enum BundleError {
    /// Reading or writing the bundle file failed; the offending
    /// [`std::io::Error`] is carried as the source.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// The input is not a valid gzip stream, or decoding it was cut short.
    /// The message comes from the decompressor.
    #[error("Failed to decompress bundle: {0}")]
    DecompressError(String),

    /// The decompressed payload is not a JSON document matching the bundle
    /// schema. The [`serde_json::Error`] is carried as the source.
    #[error("Failed to parse bundle: {0}")]
    ParseError(#[from] serde_json::Error),

    /// The bundle could not be turned into JSON, or the gzip encoder could
    /// not be flushed. Serialization is infallible for in-memory bundles, so
    /// this usually signals an encoder failure.
    #[error("Failed to serialize bundle")]
    SerializeError(String),

    /// [`Bundle::validate`] rejected a bundle whose schema version differs
    /// from [`BUNDLE_VERSION`]; the offending version is reported.
    #[error("Invalid bundle version: {0}")]
    InvalidVersion(u32),

    /// [`Bundle::validate`] found two patterns with the same name; the
    /// duplicated name is reported.
    #[error("Duplicate pattern: {0}")]
    DuplicatePattern(String),

    /// [`Bundle::validate`] found a pattern whose `match_pattern` is empty;
    /// the pattern name is reported.
    #[error("Invalid pattern: {0}")]
    InvalidPattern(String),

    /// [`Bundle::validate`] found a pattern whose `match_pattern` is not a
    /// compilable regular expression; the pattern name is reported.
    #[error("Invalid regex in pattern: {0}")]
    InvalidRegex(String),

    /// A recomputed digest did not match the recorded one. Not produced by
    /// the current loader or validator; retained for bundle verifiers.
    #[error("Checksum mismatch")]
    ChecksumMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::{Confidence, Severity};

    fn test_pattern() -> PatternDefinition {
        PatternDefinition {
            name: "test-pattern".to_string(),
            category: "test".to_string(),
            match_pattern: r"test\d+".to_string(),
            exclude_pattern: None,
            file_extensions: Vec::new(),
            enabled: true,
            severity: Severity::Low,
            confidence: Confidence::High,
            min_entropy: None,
            description: "Test pattern".to_string(),
            reference: None,
            tags: vec![],
            env_var: false,
            binary: false,
            remediation: None,
        }
    }

    #[test]
    fn test_bundle_creation() {
        let patterns = vec![test_pattern()];
        let bundle = Bundle::new(patterns);

        assert_eq!(bundle.schema_version, BUNDLE_VERSION);
        assert_eq!(bundle.patterns.len(), 1);
    }

    #[test]
    fn test_bundle_gzip() {
        let patterns = vec![test_pattern()];
        let bundle = Bundle::new(patterns.clone());

        let gzip_data = bundle.to_gzip().unwrap();
        assert!(!gzip_data.is_empty());

        let loaded = Bundle::from_gzip(&gzip_data).unwrap();
        assert_eq!(loaded.patterns.len(), 1);
        assert_eq!(loaded.patterns[0].name, "test-pattern");
    }

    #[test]
    fn test_bundle_validation() {
        let patterns = vec![test_pattern()];
        let bundle = Bundle::new(patterns);

        assert!(bundle.validate().is_ok());
    }

    #[test]
    fn test_duplicate_validation() {
        let patterns = vec![test_pattern(), test_pattern()];
        let bundle = Bundle::new(patterns);

        assert!(matches!(
            bundle.validate(),
            Err(BundleError::DuplicatePattern(_))
        ));
    }

    #[test]
    fn test_checksum() {
        let patterns = vec![test_pattern()];
        let bundle = Bundle::new(patterns.clone());
        let checksum = bundle.checksum();

        assert_eq!(checksum.len(), 64); // SHA-256 hex

        // Same patterns should produce same checksum
        let bundle2 = Bundle::new(patterns);
        assert_eq!(bundle2.checksum(), checksum);
    }

    #[test]
    fn test_bundle_len_and_empty() {
        let bundle = Bundle::new(vec![]);
        assert!(bundle.is_empty());
        assert_eq!(bundle.len(), 0);

        let bundle = Bundle::new(vec![test_pattern()]);
        assert!(!bundle.is_empty());
        assert_eq!(bundle.len(), 1);
    }

    #[test]
    fn test_bundle_metadata() {
        let patterns = vec![test_pattern()];
        let bundle = Bundle::new(patterns);
        let metadata = bundle.metadata();

        assert_eq!(metadata.version, BUNDLE_VERSION);
        assert_eq!(metadata.pattern_count, 1);
        assert!(!metadata.checksum.is_empty());
        assert!(!metadata.created_at.is_empty());
    }

    #[test]
    fn test_bundle_default() {
        let bundle = Bundle::default();
        assert_eq!(bundle.schema_version, 2);
        assert!(bundle.patterns.is_empty());
    }

    #[test]
    fn test_bundle_validation_invalid_version() {
        let mut bundle = Bundle::new(vec![]);
        bundle.schema_version = 99;
        assert!(matches!(
            bundle.validate(),
            Err(BundleError::InvalidVersion(99))
        ));
    }

    #[test]
    fn test_bundle_validation_invalid_regex() {
        let patterns = vec![PatternDefinition {
            name: "bad-pattern".to_string(),
            category: "test".to_string(),
            match_pattern: "(".to_string(), // Invalid regex
            exclude_pattern: None,
            file_extensions: Vec::new(),
            enabled: true,
            severity: Severity::Low,
            confidence: Confidence::Medium,
            min_entropy: None,
            description: "Bad pattern".to_string(),
            reference: None,
            tags: vec![],
            env_var: false,
            binary: false,
            remediation: None,
        }];
        let bundle = Bundle::new(patterns);
        assert!(matches!(
            bundle.validate(),
            Err(BundleError::InvalidRegex(_))
        ));
    }

    #[test]
    fn test_bundle_validation_empty_match() {
        let patterns = vec![PatternDefinition {
            name: "empty-pattern".to_string(),
            category: "test".to_string(),
            match_pattern: String::new(),
            exclude_pattern: None,
            file_extensions: Vec::new(),
            enabled: true,
            severity: Severity::Low,
            confidence: Confidence::Medium,
            min_entropy: None,
            description: "Empty pattern".to_string(),
            reference: None,
            tags: vec![],
            env_var: false,
            binary: false,
            remediation: None,
        }];
        let bundle = Bundle::new(patterns);
        assert!(matches!(
            bundle.validate(),
            Err(BundleError::InvalidPattern(_))
        ));
    }

    #[test]
    fn test_bundle_save_and_load() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let bundle_path = temp_dir.path().join("test.bundle");

        let bundle = Bundle::new(vec![test_pattern()]);
        bundle.save(&bundle_path).unwrap();

        let loaded = Bundle::load(&bundle_path).unwrap();
        assert_eq!(loaded.patterns.len(), 1);
        assert_eq!(loaded.patterns[0].name, "test-pattern");
    }

    #[test]
    fn test_bundle_load_not_found() {
        let result = Bundle::load(Path::new("/nonexistent/bundle.json.gz"));
        assert!(result.is_err());
    }

    #[test]
    fn test_bundle_from_gzip_invalid() {
        let result = Bundle::from_gzip(b"not gzip data");
        assert!(result.is_err());
    }

    #[test]
    fn test_bundle_error_display() {
        let error = BundleError::InvalidVersion(99);
        assert!(error.to_string().contains("99"));

        let error = BundleError::DuplicatePattern("test".to_string());
        assert!(error.to_string().contains("test"));

        let error = BundleError::InvalidRegex("bad".to_string());
        assert!(error.to_string().contains("bad"));
    }

    #[test]
    fn test_bundle_metadata_serialization() {
        let metadata = BundleMetadata {
            version: 2,
            created_at: "1234567890".to_string(),
            pattern_count: 10,
            checksum: "abc123".to_string(),
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: BundleMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.version, 2);
        assert_eq!(deserialized.pattern_count, 10);
    }
}
