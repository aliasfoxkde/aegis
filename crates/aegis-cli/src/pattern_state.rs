//! Persisted pattern enable/disable state.
//!
//! `aegis disable <pattern>` writes the pattern's name to a user-level
//! state file so the choice survives across runs; `aegis enable <pattern>`
//! removes it again. Scans built through
//! [`crate::scanner::build_scanner_from_opts`] apply the state to the
//! pattern registry before scanning, so a disabled pattern stops firing,
//! and `--all` (`--include-disabled`) still sees it.
//!
//! The file is JSON at `<config-dir>/aegis/pattern-state.json`:
//!
//! ```json
//! { "version": 1, "disabled_patterns": ["todo-comment"] }
//! ```
//!
//! A malformed state file is an error, never a silent fallback: an
//! ignored preference silently changes scan results.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Schema version of the state file.
const STATE_VERSION: u32 = 1;

/// The set of patterns the user has disabled, persisted between runs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatternState {
    /// Schema version; written as `STATE_VERSION` and validated on load.
    #[serde(default = "default_version")]
    pub version: u32,
    /// Names of patterns the user disabled.
    #[serde(default)]
    pub disabled_patterns: BTreeSet<String>,
}

impl Default for PatternState {
    // A derived Default would stamp `version: 0` — a version this very
    // loader rejects — so the default is authored to the current schema.
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

/// The user-level directory holding the state file.
///
/// # Errors
///
/// Returns an error when no user configuration directory can be resolved
/// (typically a missing home directory); the caller decides whether the
/// missing preference store is fatal.
pub fn state_dir() -> anyhow::Result<PathBuf> {
    dirs::config_dir()
        .map(|dir| dir.join("aegis"))
        .ok_or_else(|| anyhow::anyhow!("cannot resolve a user configuration directory"))
}

/// The user-level state file path.
///
/// # Errors
///
/// Returns an error when no user configuration directory can be resolved.
pub fn state_file_path() -> anyhow::Result<PathBuf> {
    Ok(state_dir()?.join("pattern-state.json"))
}

/// Load the persisted state from `dir/pattern-state.json`.
///
/// A missing file is an empty state, not an error: nothing disabled yet is
/// a valid preference. A malformed file is an error that names the file.
///
/// # Errors
///
/// Returns an error when the file exists but cannot be read or parsed.
pub fn load(dir: &Path) -> anyhow::Result<PatternState> {
    let path = dir.join("pattern-state.json");
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PatternState::empty());
        }
        Err(error) => {
            return Err(error).with_context(|| format!("cannot read {}", path.display()));
        }
    };
    let state: PatternState = serde_json::from_str(&content)
        .with_context(|| format!("{} is not a valid pattern-state document", path.display()))?;
    if state.version != STATE_VERSION {
        anyhow::bail!(
            "{} has schema version {}, but this build understands version {STATE_VERSION}",
            path.display(),
            state.version
        );
    }
    Ok(state)
}

/// Persist `state` to `dir/pattern-state.json`, creating `dir` when missing.
///
/// The write is atomic-ish: the document is written to a sibling temporary
/// file and renamed over the target, so a crash mid-write cannot leave a
/// truncated document behind.
///
/// # Errors
///
/// Returns an error when the directory cannot be created or the file
/// cannot be written.
pub fn save(dir: &Path, state: &PatternState) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let path = dir.join("pattern-state.json");
    let tmp = dir.join(format!("pattern-state.json.tmp-{}", std::process::id()));
    let content = serde_json::to_string_pretty(state).context("serialize pattern state")?;
    std::fs::write(&tmp, content).with_context(|| format!("cannot write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("cannot move {} into place", path.display()))?;
    Ok(())
}

/// The name of every shipped pattern, for validating user input.
fn known_pattern_names() -> BTreeSet<String> {
    aegis_patterns::all_patterns()
        .into_iter()
        .map(|definition| definition.name)
        .collect()
}

/// Validate a pattern name against the shipped rule set.
fn validate_pattern_name(name: &str) -> anyhow::Result<()> {
    if known_pattern_names().contains(name) {
        return Ok(());
    }
    anyhow::bail!("unknown pattern `{name}`; use `aegis list` to see valid pattern names")
}

/// Disable `name`, persisting the choice to `dir`.
///
/// # Errors
///
/// Returns an error when the pattern is unknown or the state file cannot
/// be written.
pub fn disable_pattern(dir: &Path, name: &str) -> anyhow::Result<String> {
    validate_pattern_name(name)?;
    let mut state = load(dir)?;
    state.disabled_patterns.insert(name.to_string());
    save(dir, &state)?;
    Ok(format!(
        "Disabled pattern: {name} (persisted to {})",
        dir.join("pattern-state.json").display()
    ))
}

/// Enable `name`, removing any persisted disablement from `dir`.
///
/// # Errors
///
/// Returns an error when the pattern is unknown or the state file cannot
/// be written.
pub fn enable_pattern(dir: &Path, name: &str) -> anyhow::Result<String> {
    validate_pattern_name(name)?;
    let mut state = load(dir)?;
    if state.disabled_patterns.remove(name) {
        save(dir, &state)?;
        Ok(format!("Enabled pattern: {name}"))
    } else {
        Ok(format!("Pattern already enabled: {name}"))
    }
}

/// Apply the persisted disablements in `state` to `registry`.
///
/// Names in the state file that no longer exist (a rule was removed in an
/// upgrade) are ignored: the stale entry must not fail every scan, and the
/// next `enable`/`disable` rewrite drops it.
pub fn apply_to_registry(state: &PatternState, registry: &aegis_core::PatternRegistry) {
    for name in &state.disabled_patterns {
        registry.disable(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state_dir(tag: &str) -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(&format!("aegis_state_{tag}_{}_", std::process::id()))
            .tempdir()
            .expect("tempdir")
    }

    #[test]
    fn missing_state_file_is_an_empty_state() {
        let dir = temp_state_dir("missing");
        let state = load(dir.path()).expect("missing file must load as empty");
        assert_eq!(state, PatternState::empty());
        assert!(!state.is_disabled("anything"));
    }

    #[test]
    fn save_then_load_round_trips_disablements() {
        let dir = temp_state_dir("roundtrip");
        let message = disable_pattern(dir.path(), "todo-comment").expect("disable");
        assert!(message.contains("todo-comment"));

        let state = load(dir.path()).expect("reload");
        assert!(state.is_disabled("todo-comment"));
        assert_eq!(state.version, STATE_VERSION);
    }

    #[test]
    fn enable_removes_the_persisted_disablement() {
        let dir = temp_state_dir("enable");
        disable_pattern(dir.path(), "todo-comment").expect("disable");
        let message = enable_pattern(dir.path(), "todo-comment").expect("enable");
        assert!(message.contains("Enabled"));
        let state = load(dir.path()).expect("reload");
        assert!(!state.is_disabled("todo-comment"));
    }

    #[test]
    fn enable_on_an_enabled_pattern_reports_idempotence() {
        let dir = temp_state_dir("idempotent");
        let message = enable_pattern(dir.path(), "todo-comment").expect("enable");
        assert!(message.contains("already enabled"));
    }

    #[test]
    fn unknown_pattern_names_fail_loudly() {
        let dir = temp_state_dir("unknown");
        let error = disable_pattern(dir.path(), "no-such-pattern")
            .expect_err("unknown pattern must be rejected");
        assert!(error.to_string().contains("no-such-pattern"));
        assert!(error.to_string().contains("aegis list"));
    }

    #[test]
    fn malformed_state_file_is_an_error_naming_the_file() {
        let dir = temp_state_dir("malformed");
        std::fs::create_dir_all(dir.path()).expect("create dir");
        let path = dir.path().join("pattern-state.json");
        std::fs::write(&path, "{not json").expect("write malformed state");

        let error = load(dir.path()).expect_err("malformed state must fail");
        assert!(error.to_string().contains(&path.display().to_string()));
    }

    #[test]
    fn wrong_schema_version_is_an_error() {
        let dir = temp_state_dir("version");
        std::fs::create_dir_all(dir.path()).expect("create dir");
        std::fs::write(
            dir.path().join("pattern-state.json"),
            r#"{ "version": 999, "disabled_patterns": [] }"#,
        )
        .expect("write future schema");

        let error = load(dir.path()).expect_err("future schema must fail");
        assert!(error.to_string().contains("999"));
    }

    #[test]
    fn apply_to_registry_disables_only_the_listed_pattern() {
        let registry = aegis_core::PatternRegistry::from_definitions(
            aegis_patterns::all_patterns()
                .into_iter()
                .map(Into::into)
                .collect(),
        )
        .expect("registry builds");

        let mut state = PatternState::empty();
        state.disabled_patterns.insert("todo-comment".to_string());
        // A stale name from an older rule set must not break the apply.
        state
            .disabled_patterns
            .insert("removed-in-an-upgrade".to_string());
        apply_to_registry(&state, &registry);

        assert!(!registry.is_enabled("todo-comment"));
        assert!(registry.is_enabled("aws-access-key"));
    }
}
