//! Configuration management

use std::path::PathBuf;

/// Enable a pattern.
///
/// # Errors
///
/// None yet: pattern state is not persisted, so this always returns
/// `Ok(())`.
#[allow(dead_code)]
pub fn enable_pattern(_pattern: &str) -> Result<(), anyhow::Error> {
    // In real implementation, this would update the pattern state file
    Ok(())
}

/// Disable a pattern.
///
/// # Errors
///
/// None yet: pattern state is not persisted, so this always returns
/// `Ok(())`.
#[allow(dead_code)]
pub fn disable_pattern(_pattern: &str) -> Result<(), anyhow::Error> {
    // In real implementation, this would update the pattern state file
    Ok(())
}

/// Get the message to display when enabling a pattern
#[must_use]
pub fn enable_pattern_message(pattern: &str) -> String {
    format!("Enabled pattern: {pattern}")
}

/// Get the message to display when disabling a pattern
#[must_use]
pub fn disable_pattern_message(pattern: &str) -> String {
    format!("Disabled pattern: {pattern}")
}

/// Load a configuration document from disk.
///
/// # Errors
///
/// Returns an error when `path` cannot be read or when its contents are not
/// a valid JSON configuration.
#[allow(dead_code)]
pub fn load_config(path: &PathBuf) -> Result<aegis_core::Config, anyhow::Error> {
    let content = std::fs::read_to_string(path)?;
    let config: aegis_core::Config = serde_json::from_str(&content)?;
    Ok(config)
}

/// Write a configuration document to disk.
///
/// # Errors
///
/// Returns an error when `config` cannot be serialized or when `path`
/// cannot be written.
#[allow(dead_code)]
pub fn save_config(config: &aegis_core::Config, path: &PathBuf) -> Result<(), anyhow::Error> {
    let content = serde_json::to_string_pretty(config)?;
    std::fs::write(path, content)?;
    Ok(())
}

/// Resolve a `-c/--config` value to a configuration profile.
///
/// A value that names an existing file or directory path is loaded from
/// disk; anything else is looked up among the built-in presets
/// (`production`, `pipeline`, `development`, `mcp-integration`). Unknown
/// names fail with the list of valid presets.
///
/// # Errors
///
/// Returns an error when `name_or_path` looks like a file but cannot be
/// read or parsed, or when it is not a known preset.
pub fn resolve_profile(name_or_path: &str) -> Result<aegis_core::Config, anyhow::Error> {
    let candidate = PathBuf::from(name_or_path);
    if candidate.is_file() {
        return aegis_core::Config::load(&candidate).map_err(anyhow::Error::from);
    }
    aegis_core::Config::preset(name_or_path).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown configuration profile `{name_or_path}`; available presets: {}",
            aegis_core::Config::list_presets().join(", ")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enable_pattern() {
        let result = enable_pattern("test-pattern");
        assert!(result.is_ok());
    }

    #[test]
    fn test_disable_pattern() {
        let result = disable_pattern("test-pattern");
        assert!(result.is_ok());
    }

    #[test]
    fn test_enable_pattern_message() {
        let msg = enable_pattern_message("my-pattern");
        assert!(msg.contains("Enabled"));
        assert!(msg.contains("my-pattern"));
    }

    #[test]
    fn test_disable_pattern_message() {
        let msg = disable_pattern_message("my-pattern");
        assert!(msg.contains("Disabled"));
        assert!(msg.contains("my-pattern"));
    }

    #[test]
    fn test_load_config_missing_file() {
        let path = PathBuf::from("/nonexistent/config.json");
        let result = load_config(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_save_and_load_config() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.json");

        // Create a minimal config
        let config = aegis_core::Config::default();

        // Save it
        let save_result = save_config(&config, &config_path);
        assert!(save_result.is_ok());

        // Load it back
        let loaded = load_config(&config_path);
        assert!(loaded.is_ok());
    }

    #[test]
    fn resolve_profile_loads_builtin_presets_by_name() {
        for name in aegis_core::Config::list_presets() {
            let profile = resolve_profile(name).expect("built-in preset must resolve");
            assert_eq!(profile.name, name);
        }
    }

    #[test]
    fn resolve_profile_loads_profiles_from_file_paths() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/profiles/production.json"
        );
        let profile = resolve_profile(path).expect("profile file must resolve");
        assert_eq!(profile.name, "production");
        assert_eq!(
            profile.output_format,
            aegis_core::config::OutputFormat::Sarif
        );
    }

    #[test]
    fn resolve_profile_rejects_unknown_names_with_preset_list() {
        let error = resolve_profile("no-such-profile").expect_err("unknown preset");
        let message = error.to_string();
        assert!(message.contains("no-such-profile"));
        assert!(message.contains("production"));
        assert!(message.contains("mcp-integration"));
    }
}
