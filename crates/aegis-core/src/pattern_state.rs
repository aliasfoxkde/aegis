//! Persisted pattern enable/disable state.
//!
//! `aegis disable <pattern>` records the pattern's name in a state file so
//! the choice survives across runs; `aegis enable <pattern>` removes it
//! again. Every surface that scans - the command line, the daemon, and the
//! MCP server - reads the same document and applies the state to its
//! pattern registry before scanning, so a disabled pattern stops firing.
//!
//! The file is JSON:
//!
//! ```json
//! { "version": 1, "disabled_patterns": ["hardcoded-password"] }
//! ```
//!
//! A malformed state file is an error, never a silent fallback: an ignored
//! preference silently changes scan results.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::pattern::PatternRegistry;

/// Schema version of the state file.
pub const STATE_VERSION: u32 = 1;

/// The name of the state file inside the state directory.
pub const STATE_FILE_NAME: &str = "pattern-state.json";

/// The environment variable that names the state file a process reads.
///
/// A daemon or an MCP server usually runs under a service account whose
/// configuration directory is not the operator's, so the operator names the
/// file this way when the two have to share one.
pub const STATE_PATH_ENV: &str = "AEGIS_PATTERN_STATE";

/// The set of patterns the user has disabled, persisted between runs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatternState {
    /// Schema version; written as [`STATE_VERSION`] and validated on load.
    #[serde(default = "default_version")]
    pub version: u32,
    /// Names of patterns the user disabled.
    #[serde(default)]
    pub disabled_patterns: BTreeSet<String>,
}

impl Default for PatternState {
    // A derived Default would stamp `version: 0` - a version this very
    // loader rejects - so the default is authored to the current schema.
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            disabled_patterns: BTreeSet::new(),
        }
    }
}

fn default_version() -> u32 {
    STATE_VERSION
}

impl PatternState {
    /// An empty state: every pattern enabled.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Whether the named pattern is disabled in this state.
    #[must_use]
    pub fn is_disabled(&self, name: &str) -> bool {
        self.disabled_patterns.contains(name)
    }
}

/// Everything that can go wrong while reading or writing the state file.
#[derive(Debug, thiserror::Error)]
pub enum PatternStateError {
    /// The file exists but cannot be read.
    #[error("cannot read {path}: {source}")]
    Read {
        /// The file that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The file is not a state document.
    #[error("{path} is not a valid pattern-state document: {source}")]
    Parse {
        /// The file that could not be parsed.
        path: PathBuf,
        /// The underlying parse error.
        source: serde_json::Error,
    },
    /// The file carries a schema version this build does not understand.
    #[error("{path} has schema version {found}, but this build understands version {expected}")]
    Version {
        /// The file that holds the unknown version.
        path: PathBuf,
        /// The version the file carries.
        found: u32,
        /// The version this build understands.
        expected: u32,
    },
    /// The state cannot be written as JSON.
    #[error("cannot serialize the pattern state for {path}: {source}")]
    Serialize {
        /// The file the state was headed for.
        path: PathBuf,
        /// The underlying serialization error.
        source: serde_json::Error,
    },
    /// The directory holding the file does not exist and cannot be created.
    #[error("cannot create {path}: {source}")]
    Create {
        /// The directory that could not be created.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The file cannot be written.
    #[error("cannot write {path}: {source}")]
    Write {
        /// The file that could not be written.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// No user configuration directory can be resolved.
    #[error("cannot resolve a user configuration directory")]
    NoConfigDir,
}

/// The user-level directory holding the state file.
///
/// # Errors
///
/// Returns an error when no user configuration directory can be resolved
/// (typically a missing home directory); the caller decides whether the
/// missing preference store is fatal.
pub fn state_dir() -> Result<PathBuf, PatternStateError> {
    dirs::config_dir()
        .map(|dir| dir.join("aegis"))
        .ok_or(PatternStateError::NoConfigDir)
}

/// The state file a process reads when nothing names one explicitly.
///
/// # Errors
///
/// Returns an error when no user configuration directory can be resolved.
pub fn default_state_file() -> Result<PathBuf, PatternStateError> {
    Ok(state_dir()?.join(STATE_FILE_NAME))
}

/// The state file a process reads.
///
/// An explicitly named file wins over the default one, so a daemon or an
/// MCP server running under a service account can be pointed at the
/// operator's file. The caller reads the environment at the edge and passes
/// the result in here, so the decision itself never reads it.
///
/// # Errors
///
/// Returns an error when no state file can be resolved at all.
pub fn resolve_state_file(explicit: Option<&Path>) -> Result<PathBuf, PatternStateError> {
    match explicit {
        Some(path) => Ok(path.to_path_buf()),
        None => default_state_file(),
    }
}

/// Load the persisted state from `path`.
///
/// A missing file is an empty state, not an error: nothing disabled yet is
/// a valid preference. A malformed file is an error that names the file.
///
/// # Errors
///
/// Returns an error when the file exists but cannot be read or parsed, or
/// when it carries a schema version this build does not understand.
pub fn load(path: &Path) -> Result<PatternState, PatternStateError> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PatternState::empty());
        }
        Err(error) => {
            return Err(PatternStateError::Read {
                path: path.to_path_buf(),
                source: error,
            });
        }
    };
    let state: PatternState =
        serde_json::from_str(&content).map_err(|source| PatternStateError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
    if state.version != STATE_VERSION {
        return Err(PatternStateError::Version {
            path: path.to_path_buf(),
            found: state.version,
            expected: STATE_VERSION,
        });
    }
    Ok(state)
}

/// Persist `state` to `path`, creating its directory when missing.
///
/// The write is atomic-ish: the document is written to a sibling temporary
/// file and renamed over the target, so a crash mid-write cannot leave a
/// truncated document behind.
///
/// # Errors
///
/// Returns an error when the directory cannot be created or the file
/// cannot be written.
pub fn save(path: &Path, state: &PatternState) -> Result<(), PatternStateError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| PatternStateError::Create {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let tmp = path.with_extension(format!("json.tmp-{}", std::process::id()));
    let content =
        serde_json::to_string_pretty(state).map_err(|source| PatternStateError::Serialize {
            path: path.to_path_buf(),
            source,
        })?;
    std::fs::write(&tmp, content).map_err(|source| PatternStateError::Write {
        path: tmp.clone(),
        source,
    })?;
    std::fs::rename(&tmp, path).map_err(|source| PatternStateError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

/// Apply the persisted disablements in `state` to `registry`.
///
/// Names in the state file that no longer exist (a rule was removed in an
/// upgrade) are ignored: the stale entry must not fail every scan, and the
/// next `enable`/`disable` rewrite drops it.
pub fn apply_to_registry(state: &PatternState, registry: &PatternRegistry) {
    for name in &state.disabled_patterns {
        registry.disable(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state_file(tag: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::Builder::new()
            .prefix(&format!("aegis_state_{tag}_{}_", std::process::id()))
            .tempdir()
            .expect("tempdir");
        let path = dir.path().join(STATE_FILE_NAME);
        (dir, path)
    }

    #[test]
    fn a_missing_state_file_is_an_empty_state() {
        let (_dir, path) = temp_state_file("missing");
        let state = load(&path).expect("missing file must load as empty");
        assert_eq!(state, PatternState::empty());
        assert!(!state.is_disabled("anything"));
    }

    #[test]
    fn save_then_load_round_trips_disablements() {
        let (_dir, path) = temp_state_file("roundtrip");
        let mut state = PatternState::empty();
        state
            .disabled_patterns
            .insert("hardcoded-password".to_string());
        save(&path, &state).expect("save");

        let loaded = load(&path).expect("reload");
        assert!(loaded.is_disabled("hardcoded-password"));
        assert_eq!(loaded.version, STATE_VERSION);
    }

    #[test]
    fn a_malformed_state_file_is_an_error_naming_the_file() {
        let (_dir, path) = temp_state_file("malformed");
        std::fs::write(&path, "{not json").expect("write malformed state");

        let error = load(&path).expect_err("malformed state must fail");
        assert!(error.to_string().contains(&path.display().to_string()));
    }

    #[test]
    fn a_wrong_schema_version_is_an_error() {
        let (_dir, path) = temp_state_file("version");
        std::fs::write(&path, r#"{ "version": 999, "disabled_patterns": [] }"#)
            .expect("write future schema");

        let error = load(&path).expect_err("future schema must fail");
        assert!(error.to_string().contains("999"));
    }

    #[test]
    fn an_explicitly_named_file_wins_over_the_default_one() {
        let explicit = Path::new("/tmp/aegis-state.json");
        let resolved = resolve_state_file(Some(explicit)).expect("resolve");
        assert_eq!(resolved, explicit);
    }

    #[test]
    fn apply_to_registry_disables_only_the_listed_pattern() {
        let registry = PatternRegistry::from_definitions(
            aegis_patterns::all_patterns()
                .into_iter()
                .map(Into::into)
                .collect(),
        )
        .expect("registry builds");

        let mut state = PatternState::empty();
        state
            .disabled_patterns
            .insert("hardcoded-password".to_string());
        // A stale name from an older rule set must not break the apply.
        state
            .disabled_patterns
            .insert("removed-in-an-upgrade".to_string());
        apply_to_registry(&state, &registry);

        assert!(!registry.is_enabled("hardcoded-password"));
        assert!(registry.is_enabled("jwt-token"));
    }
}
