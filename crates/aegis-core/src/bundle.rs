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
    pub version: u32,
    pub created_at: String,
    pub pattern_count: usize,
    pub checksum: String,
}

/// Bundle format v2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub schema_version: u32,
    pub created_at: String,
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
    pub fn new(patterns: Vec<PatternDefinition>) -> Self {
        Self {
            schema_version: BUNDLE_VERSION,
            created_at: chrono_now(),
            patterns,
        }
    }

    /// Load a bundle from a file
    pub fn load(path: &Path) -> Result<Self, BundleError> {
        let mut file = File::open(path).map_err(BundleError::IoError)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(BundleError::IoError)?;

        Self::from_gzip(&buffer)
    }

    /// Load a bundle from gzip-compressed bytes
    pub fn from_gzip(data: &[u8]) -> Result<Self, BundleError> {
        use flate2::read::GzDecoder;
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        use std::io::Read;
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| BundleError::DecompressError(e.to_string()))?;
        let bundle: Bundle =
            serde_json::from_slice(&decompressed).map_err(BundleError::ParseError)?;
        Ok(bundle)
    }

    /// Save bundle to a file
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
    pub fn to_gzip(&self) -> Result<Vec<u8>, BundleError> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let json =
            serde_json::to_string(self).map_err(|e| BundleError::SerializeError(e.to_string()))?;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        use std::io::Write;
        encoder
            .write_all(json.as_bytes())
            .map_err(|e| BundleError::SerializeError(e.to_string()))?;
        encoder
            .finish()
            .map_err(|e| BundleError::SerializeError(e.to_string()))
    }

    /// Get the number of patterns
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Check if bundle is empty
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Validate the bundle
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
    pub fn metadata(&self) -> BundleMetadata {
        BundleMetadata {
            version: self.schema_version,
            created_at: self.created_at.clone(),
            pattern_count: self.patterns.len(),
            checksum: self.checksum(),
        }
    }

    /// Calculate SHA-256 checksum
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
    format!("{}", secs)
}

/// Bundle error types
#[derive(Debug, Error)]
pub enum BundleError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Failed to decompress bundle: {0}")]
    DecompressError(String),

    #[error("Failed to parse bundle: {0}")]
    ParseError(#[from] serde_json::Error),

    #[error("Failed to serialize bundle")]
    SerializeError(String),

    #[error("Invalid bundle version: {0}")]
    InvalidVersion(u32),

    #[error("Duplicate pattern: {0}")]
    DuplicatePattern(String),

    #[error("Invalid pattern: {0}")]
    InvalidPattern(String),

    #[error("Invalid regex in pattern: {0}")]
    InvalidRegex(String),

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
            enabled: true,
            severity: Severity::Low,
            confidence: Confidence::High,
            min_entropy: None,
            description: "Test pattern".to_string(),
            reference: None,
            tags: vec![],
            env_var: false,
            binary: false,
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
}
