//! User-defined detection patterns from `.aegis.yml`.
//!
//! A scan root may contain a `.aegis.yml` (or `.aegis.yaml`) file with a
//! `patterns:` list. Every entry is validated eagerly — invalid regex,
//! unknown severity, duplicate names — and the scan fails loudly instead of
//! silently skipping a misconfigured rule. Validated patterns are merged
//! into the scanner's registry alongside the bundled rules.
//!
//! ```yaml
//! patterns:
//!   - name: internal-token-prefix
//!     category: secrets
//!     severity: high
//!     description: Internal service token committed to source
//!     match: 'INTT_[A-Za-z0-9]{24,}'
//!     exclude: 'INTT_EXAMPLE'
//!     file_extensions: [rs, py, ts]
//!     remediation: Move the token into an environment variable
//! ```

use std::path::Path;

/// File names recognized at the scan root, in lookup order
pub const USER_PATTERN_FILE_NAMES: [&str; 2] = [".aegis.yml", ".aegis.yaml"];

/// Category assigned to user patterns that omit `category`
pub const DEFAULT_CATEGORY: &str = "custom";

/// Errors encountered while loading user-defined patterns.
#[derive(Debug, thiserror::Error)]
pub enum UserPatternError {
    /// The file was read but failed validation; `message` names the rule that
    /// was broken.
    #[error("custom patterns file {path}: {message}")]
    Invalid {
        /// The offending `.aegis.yml`, as it should appear in diagnostics.
        path: String,
        /// Human-readable explanation of the first failure.
        message: String,
    },

    /// The patterns file exists but could not be read from disk.
    #[error("failed to read custom patterns file {path}: {source}")]
    Io {
        /// The file that could not be read.
        path: String,
        /// Underlying read failure.
        source: std::io::Error,
    },
}

impl UserPatternError {
    fn invalid(path: &Path, message: impl Into<String>) -> Self {
        Self::Invalid {
            path: path.display().to_string(),
            message: message.into(),
        }
    }
}

/// One user-defined pattern as written in `.aegis.yml`.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserPattern {
    /// Unique pattern name; also the rule id shown in findings
    pub name: String,
    /// Category used for risk weighting and `--categories` filtering;
    /// defaults to `custom`
    #[serde(default)]
    pub category: Option<String>,
    /// Regex applied per line
    #[serde(alias = "match")]
    pub match_pattern: String,
    /// Regex that suppresses a candidate match span when it also matches
    #[serde(default)]
    pub exclude: Option<String>,
    /// Required severity; one of `critical`, `high`, `medium`, `low`
    pub severity: String,
    /// `high`, `medium`, or `low`; defaults to `medium`
    #[serde(default)]
    pub confidence: Option<String>,
    /// Human-readable explanation shown with the finding
    pub description: String,
    /// How to fix a hit; shown with the finding
    #[serde(default)]
    pub remediation: Option<String>,
    /// Reference URL shown with the finding
    #[serde(default)]
    pub reference: Option<String>,
    /// Minimum Shannon entropy for the matched text
    #[serde(default)]
    pub min_entropy: Option<f64>,
    /// Restrict the pattern to these extensions (without dot); empty = all
    #[serde(default)]
    pub file_extensions: Vec<String>,
}

/// Top-level `.aegis.yml` document.
#[derive(Debug, serde::Deserialize)]
pub struct UserPatternFile {
    /// Entries listed under `patterns:`; an absent key deserializes to an
    /// empty list, which the loader rejects.
    #[serde(default)]
    pub patterns: Vec<UserPattern>,
}

/// Locate the user patterns file at the scan root, if any.
#[must_use]
pub fn find_user_pattern_file(root: &Path) -> Option<std::path::PathBuf> {
    USER_PATTERN_FILE_NAMES
        .iter()
        .map(|name| root.join(name))
        .find(|path| path.is_file())
}

/// Load and validate user pattern definitions from the scan root.
///
/// Returns `Ok(None)` when the root has no `.aegis.yml` / `.aegis.yaml`.
/// Any malformed entry is an error: a typo would otherwise silently
/// disable a rule the author believes is protecting them.
///
/// # Errors
///
/// Returns [`UserPatternError`] when the file exists but cannot be read
/// (`Io`), or when it fails validation (`Invalid`: malformed YAML, empty or
/// duplicate names, invalid regex, unknown severity or confidence, out-of
/// range `min_entropy`, dotted extensions, empty description).
pub fn load_user_pattern_definitions(
    root: &Path,
) -> Result<Option<Vec<crate::pattern::PatternDefinition>>, UserPatternError> {
    let Some(path) = find_user_pattern_file(root) else {
        return Ok(None);
    };

    let content = std::fs::read_to_string(&path).map_err(|source| UserPatternError::Io {
        path: path.display().to_string(),
        source,
    })?;

    parse_user_pattern_content(&content, &path).map(Some)
}

/// Parse and validate the YAML content of a user patterns file.
///
/// Split from [`load_user_pattern_definitions`] so the validation logic is
/// fuzzable without a filesystem. Diagnostics reference `path` exactly as
/// they do when the content was read from disk.
///
/// # Errors
///
/// Returns [`UserPatternError::Invalid`] when the YAML is malformed or any
/// entry fails validation.
pub fn parse_user_pattern_content(
    content: &str,
    path: &Path,
) -> Result<Vec<crate::pattern::PatternDefinition>, UserPatternError> {
    let file: UserPatternFile = serde_yaml::from_str(content)
        .map_err(|e| UserPatternError::invalid(path, format!("invalid YAML: {e}")))?;

    if file.patterns.is_empty() {
        return Err(UserPatternError::invalid(
            path,
            "`patterns:` must list at least one pattern",
        ));
    }

    let mut definitions = Vec::with_capacity(file.patterns.len());
    let mut seen = std::collections::HashSet::new();
    for pattern in file.patterns {
        validate_unique_name(path, &pattern.name, &mut seen)?;
        definitions.push(convert(pattern, path)?);
    }

    Ok(definitions)
}

/// Reject empty and duplicate names; the name is the rule identity used in
/// suppressions and baselines.
fn validate_unique_name(
    path: &Path,
    name: &str,
    seen: &mut std::collections::HashSet<String>,
) -> Result<(), UserPatternError> {
    if name.trim().is_empty() {
        return Err(UserPatternError::invalid(
            path,
            "pattern name must not be empty",
        ));
    }
    if !seen.insert(name.to_string()) {
        return Err(UserPatternError::invalid(
            path,
            format!("duplicate pattern name `{name}`"),
        ));
    }
    Ok(())
}

/// Validate one entry and convert it to an engine [`PatternDefinition`].
fn convert(
    pattern: UserPattern,
    path: &Path,
) -> Result<crate::pattern::PatternDefinition, UserPatternError> {
    use crate::pattern::{Confidence, PatternDefinition, Severity};

    if pattern.match_pattern.trim().is_empty() {
        return Err(UserPatternError::invalid(
            path,
            format!("pattern `{}`: `match` must not be empty", pattern.name),
        ));
    }
    regex::Regex::new(&pattern.match_pattern).map_err(|e| {
        UserPatternError::invalid(
            path,
            format!("pattern `{}`: invalid `match` regex: {e}", pattern.name),
        )
    })?;

    if let Some(exclude) = &pattern.exclude {
        regex::Regex::new(exclude).map_err(|e| {
            UserPatternError::invalid(
                path,
                format!("pattern `{}`: invalid `exclude` regex: {e}", pattern.name),
            )
        })?;
    }

    let severity = Severity::parse(&pattern.severity).ok_or_else(|| {
        UserPatternError::invalid(
            path,
            format!(
                "pattern `{}`: unknown severity `{}` (expected critical, high, medium, or low)",
                pattern.name, pattern.severity
            ),
        )
    })?;

    let confidence = match &pattern.confidence {
        Some(raw) => Confidence::parse(raw).ok_or_else(|| {
            UserPatternError::invalid(
                path,
                format!(
                    "pattern `{}`: unknown confidence `{raw}` (expected high, medium, or low)",
                    pattern.name
                ),
            )
        })?,
        None => Confidence::Medium,
    };

    if let Some(entropy) = pattern.min_entropy {
        if !(0.0..=8.0).contains(&entropy) {
            return Err(UserPatternError::invalid(
                path,
                format!(
                    "pattern `{}`: `min_entropy` must be between 0.0 and 8.0, got {entropy}",
                    pattern.name
                ),
            ));
        }
    }

    if let Some(bad) = pattern
        .file_extensions
        .iter()
        .find(|ext| ext.trim().is_empty() || ext.starts_with('.'))
    {
        return Err(UserPatternError::invalid(
            path,
            format!(
                "pattern `{}`: file extension `{bad}` must be a bare extension without a dot",
                pattern.name
            ),
        ));
    }

    if pattern.description.trim().is_empty() {
        return Err(UserPatternError::invalid(
            path,
            format!(
                "pattern `{}`: `description` must not be empty",
                pattern.name
            ),
        ));
    }

    Ok(PatternDefinition {
        name: pattern.name,
        category: pattern
            .category
            .unwrap_or_else(|| DEFAULT_CATEGORY.to_string()),
        match_pattern: pattern.match_pattern,
        enabled: true,
        severity,
        confidence,
        min_entropy: pattern.min_entropy,
        description: pattern.description,
        reference: pattern.reference,
        remediation: pattern.remediation,
        tags: Vec::new(),
        env_var: false,
        binary: false,
        exclude_pattern: pattern.exclude,
        file_extensions: pattern
            .file_extensions
            .iter()
            .map(|ext| ext.trim().to_ascii_lowercase())
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_config(root: &Path, content: &str) -> std::path::PathBuf {
        let path = root.join(".aegis.yml");
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn returns_none_without_config_file() {
        let temp = TempDir::new().unwrap();
        assert!(load_user_pattern_definitions(temp.path())
            .unwrap()
            .is_none());
        assert!(find_user_pattern_file(temp.path()).is_none());
    }

    #[test]
    fn loads_valid_patterns() {
        let temp = TempDir::new().unwrap();
        write_config(
            temp.path(),
            r"
patterns:
  - name: internal-token
    category: secrets
    severity: high
    match: 'INTT_[A-Za-z0-9]{24,}'
    description: Internal service token
    remediation: Use an environment variable
",
        );

        let definitions = load_user_pattern_definitions(temp.path())
            .unwrap()
            .expect("definitions present");
        assert_eq!(definitions.len(), 1);
        let definition = &definitions[0];
        assert_eq!(definition.name, "internal-token");
        assert_eq!(definition.category, "secrets");
        assert_eq!(definition.severity.to_string(), "high");
        assert_eq!(
            definition.remediation.as_deref(),
            Some("Use an environment variable")
        );
    }

    #[test]
    fn applies_defaults_for_optional_fields() {
        let temp = TempDir::new().unwrap();
        write_config(
            temp.path(),
            r"
patterns:
  - name: todo-tracker
    severity: low
    match: 'TD-[0-9]+'
    description: Unresolved tracker reference
",
        );

        let definition = &load_user_pattern_definitions(temp.path()).unwrap().unwrap()[0];
        assert_eq!(definition.category, DEFAULT_CATEGORY);
        assert_eq!(definition.confidence.to_string(), "medium");
        assert!(definition.remediation.is_none());
    }

    #[test]
    fn accepts_yaml_extension() {
        let temp = TempDir::new().unwrap();
        std::fs::write(temp.path().join(".aegis.yaml"), "patterns: []").unwrap();
        let err = load_user_pattern_definitions(temp.path()).unwrap_err();
        assert!(err.to_string().contains("at least one pattern"), "{err}");
    }

    #[test]
    fn empty_patterns_section_is_an_error() {
        let temp = TempDir::new().unwrap();
        write_config(temp.path(), "patterns: []\n");
        let err = load_user_pattern_definitions(temp.path()).unwrap_err();
        assert!(err.to_string().contains("at least one pattern"), "{err}");
    }

    #[test]
    fn invalid_regex_is_an_error() {
        let temp = TempDir::new().unwrap();
        write_config(
            temp.path(),
            r"
patterns:
  - name: broken
    severity: high
    match: '[unclosed'
    description: Broken regex
",
        );
        let err = load_user_pattern_definitions(temp.path()).unwrap_err();
        assert!(err.to_string().contains("invalid `match` regex"), "{err}");
        assert!(err.to_string().contains("broken"), "{err}");
    }

    #[test]
    fn unknown_severity_is_an_error() {
        let temp = TempDir::new().unwrap();
        write_config(
            temp.path(),
            r"
patterns:
  - name: typo-severity
    severity: sever
    match: 'X'
    description: Misspelled severity
",
        );
        let err = load_user_pattern_definitions(temp.path()).unwrap_err();
        assert!(
            err.to_string().contains("unknown severity `sever`"),
            "{err}"
        );
    }

    #[test]
    fn duplicate_names_are_an_error() {
        let temp = TempDir::new().unwrap();
        write_config(
            temp.path(),
            r"
patterns:
  - name: same-name
    severity: low
    match: 'A'
    description: First
  - name: same-name
    severity: low
    match: 'B'
    description: Second
",
        );
        let err = load_user_pattern_definitions(temp.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("duplicate pattern name `same-name`"),
            "{err}"
        );
    }

    #[test]
    fn out_of_range_entropy_is_an_error() {
        let temp = TempDir::new().unwrap();
        write_config(
            temp.path(),
            r"
patterns:
  - name: bad-entropy
    severity: low
    match: 'A'
    description: Out of range
    min_entropy: 99.0
",
        );
        let err = load_user_pattern_definitions(temp.path()).unwrap_err();
        assert!(err.to_string().contains("min_entropy"), "{err}");
    }

    #[test]
    fn dotted_extension_is_an_error() {
        let temp = TempDir::new().unwrap();
        write_config(
            temp.path(),
            r"
patterns:
  - name: dotted-ext
    severity: low
    match: 'A'
    description: Dotted extension
    file_extensions: ['.rs']
",
        );
        let err = load_user_pattern_definitions(temp.path()).unwrap_err();
        assert!(err.to_string().contains("without a dot"), "{err}");
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let temp = TempDir::new().unwrap();
        write_config(
            temp.path(),
            r"
patterns:
  - name: typoed-field
    severity: low
    match: 'A'
    description: Typo
    severirty: low
",
        );
        let err = load_user_pattern_definitions(temp.path()).unwrap_err();
        assert!(err.to_string().contains("invalid YAML"), "{err}");
    }
}
