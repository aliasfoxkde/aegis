//! Persisted pattern enable/disable state.
//!
//! `aegis disable <pattern>` writes the pattern's name to a user-level
//! state file so the choice survives across runs; `aegis enable <pattern>`
//! removes it again. Scans built through
//! [`crate::scanner::build_scanner_from_opts`] apply the state to the
//! pattern registry before scanning, so a disabled pattern stops firing,
//! and `--all` (`--include-disabled`) still sees it.
//!
//! The state document itself lives in `aegis-core`, so the command line,
//! the daemon, and the MCP server read and write the same file. This
//! module holds the command-line half: where the file is, whether a
//! pattern name is one the build ships, and the two commands that record
//! the choice.
//!
//! The file is JSON at `<config-dir>/aegis/pattern-state.json`:
//!
//! ```json
//! { "version": 1, "disabled_patterns": ["hardcoded-password"] }
//! ```
//!
//! A malformed state file is an error, never a silent fallback: an
//! ignored preference silently changes scan results.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub use aegis_core::pattern_state::{
    apply_to_registry, default_state_file, load, resolve_state_file, save, state_dir, PatternState,
    PatternStateError, STATE_FILE_NAME, STATE_PATH_ENV, STATE_VERSION,
};

/// The state file this process reads.
///
/// The environment is read here, at the edge: `AEGIS_PATTERN_STATE` names
/// the file, and the default is this user's configuration directory.
///
/// # Errors
///
/// Returns an error when no state file can be resolved at all.
pub fn state_file() -> anyhow::Result<PathBuf> {
    let explicit = std::env::var_os(STATE_PATH_ENV).map(PathBuf::from);
    Ok(resolve_state_file(explicit.as_deref())?)
}

/// The name of every shipped pattern, for validating user input.
fn known_pattern_names() -> BTreeSet<String> {
    aegis_patterns::all_patterns()
        .into_iter()
        .map(|definition| definition.name)
        .collect()
}

/// Validate a pattern name against the shipped rule set.
///
/// # Errors
///
/// Returns an error naming the pattern when the build ships no such rule.
fn validate_pattern_name(name: &str) -> anyhow::Result<()> {
    if known_pattern_names().contains(name) {
        return Ok(());
    }
    anyhow::bail!("unknown pattern `{name}`; use `aegis list` to see valid pattern names")
}

/// Disable `name`, persisting the choice to `path`.
///
/// # Errors
///
/// Returns an error when the pattern is unknown or the state file cannot
/// be written.
pub fn disable_pattern(path: &Path, name: &str) -> anyhow::Result<String> {
    validate_pattern_name(name)?;
    let mut state = load(path)?;
    state.disabled_patterns.insert(name.to_string());
    save(path, &state)?;
    Ok(format!(
        "Disabled pattern: {name} (persisted to {})",
        path.display()
    ))
}

/// Enable `name`, removing any persisted disablement from `path`.
///
/// # Errors
///
/// Returns an error when the pattern is unknown or the state file cannot
/// be written.
pub fn enable_pattern(path: &Path, name: &str) -> anyhow::Result<String> {
    validate_pattern_name(name)?;
    let mut state = load(path)?;
    if state.disabled_patterns.remove(name) {
        save(path, &state)?;
        Ok(format!("Enabled pattern: {name}"))
    } else {
        Ok(format!("Pattern already enabled: {name}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state_file(tag: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::Builder::new()
            .prefix(&format!("aegis_state_{tag}_{}_", std::process::id()))
            .tempdir()
            .expect("tempdir");
        let path = dir.path().join(STATE_FILE_NAME);
        (dir, path)
    }

    #[test]
    fn save_then_load_round_trips_disablements() {
        let (_dir, path) = temp_state_file("roundtrip");
        let message = disable_pattern(&path, "hardcoded-password").expect("disable");
        assert!(message.contains("hardcoded-password"));

        let state = load(&path).expect("reload");
        assert!(state.is_disabled("hardcoded-password"));
        assert_eq!(state.version, STATE_VERSION);
    }

    #[test]
    fn enable_removes_the_persisted_disablement() {
        let (_dir, path) = temp_state_file("enable");
        disable_pattern(&path, "hardcoded-password").expect("disable");
        let message = enable_pattern(&path, "hardcoded-password").expect("enable");
        assert!(message.contains("Enabled"));
        let state = load(&path).expect("reload");
        assert!(!state.is_disabled("hardcoded-password"));
    }

    #[test]
    fn enable_on_an_enabled_pattern_reports_idempotence() {
        let (_dir, path) = temp_state_file("idempotent");
        let message = enable_pattern(&path, "hardcoded-password").expect("enable");
        assert!(message.contains("already enabled"));
    }

    #[test]
    fn unknown_pattern_names_fail_loudly() {
        let (_dir, path) = temp_state_file("unknown");
        let error = disable_pattern(&path, "no-such-pattern")
            .expect_err("unknown pattern must be rejected");
        assert!(error.to_string().contains("no-such-pattern"));
        assert!(error.to_string().contains("aegis list"));
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
}
