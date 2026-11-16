//! Configuration management

use std::path::{Path, PathBuf};

/// Load a configuration document from disk.
///
/// # Errors
///
/// Returns an error when `path` cannot be read or when its contents are not
/// a valid JSON configuration.
#[allow(dead_code)]
// aegis-allow: public config loader kept for embedders; the CLI reads profiles through its own config module | expires=2027-12-31 | approver=maintainers
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
// aegis-allow: public config writer kept for embedders; the CLI writes pattern state through its own state module | expires=2027-12-31 | approver=maintainers
pub fn save_config(config: &aegis_core::Config, path: &PathBuf) -> Result<(), anyhow::Error> {
    let content = serde_json::to_string_pretty(config)?;
    std::fs::write(path, content)?;
    Ok(())
}

/// Resolve a `-c/--config` value to a configuration profile.
///
/// A value that looks like a path — it carries a path separator or ends in
/// `.json` — is loaded from disk, so a typo'd path fails with the real
/// I/O error instead of a preset list. Anything else is a bare preset
/// name (`production`, `pipeline`, `development`, `mcp-integration`);
/// probing bare names against the working directory would make a stray
/// file called `production` hijack the preset. Unknown names fail with
/// the list of valid presets.
///
/// # Errors
///
/// Returns an error when `name_or_path` looks like a path but cannot be
/// read or parsed, or when it is not a known preset.
pub fn resolve_profile(name_or_path: &str) -> Result<aegis_core::Config, anyhow::Error> {
    let looks_like_path = name_or_path.contains('/')
        || name_or_path.contains('\\')
        || Path::new(name_or_path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));
    if !looks_like_path {
        return aegis_core::Config::preset(name_or_path).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown configuration profile `{name_or_path}`; available presets: {}",
                aegis_core::Config::list_presets().join(", ")
            )
        });
    }
    let candidate = PathBuf::from(name_or_path);
    aegis_core::Config::load(&candidate).map_err(anyhow::Error::from)
}

/// Parse `--classify-path GLOB=KIND` specifications into path-class rules.
///
/// A specification names the glob and the class it assigns, separated by
/// the last `=`: `docs/**=docs`, `**/tests/**=fixture`. Every rule is
/// checked before it is returned, because a malformed rule would classify
/// nothing and leave the operator believing a path had been quieted.
///
/// # Errors
///
/// Returns an error when a specification has no `=`, has an empty glob,
/// names an unknown class, or carries a glob that does not compile.
pub fn parse_path_class_specs(
    specs: &[String],
) -> Result<Vec<aegis_core::PathClassRule>, anyhow::Error> {
    let mut rules = Vec::with_capacity(specs.len());
    for spec in specs {
        let Some((glob, class)) = spec.rsplit_once('=') else {
            anyhow::bail!("invalid --classify-path `{spec}`: expected GLOB=KIND");
        };
        let glob = glob.trim();
        if glob.is_empty() {
            anyhow::bail!("invalid --classify-path `{spec}`: the glob is empty");
        }
        let rule = aegis_core::PathClassRule::new(glob, class.trim())
            .map_err(|message| anyhow::anyhow!("invalid --classify-path `{spec}`: {message}"))?;
        rule.validate()
            .map_err(|message| anyhow::anyhow!("invalid --classify-path `{spec}`: {message}"))?;
        rules.push(rule);
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn resolve_profile_treats_missing_json_paths_as_io_errors() {
        // A path-looking value must fail with the real read error, not the
        // preset list — that is how a typo'd `--config` gets diagnosed.
        let error = resolve_profile("./config/no-such-profile.json").expect_err("missing file");
        let message = error.to_string();
        // The OS-specific wording differs ("No such file or directory" vs
        // "The system cannot find the path specified"); the contract is
        // that it is the wrapped I/O error, not the preset-list hint.
        assert!(message.contains("I/O error"), "unexpected error: {message}");
        assert!(!message.contains("available presets"));
    }

    #[test]
    fn resolve_profile_prefers_presets_over_same_named_cwd_files() {
        // `production.json` in the working directory must not shadow the
        // bare `production` preset name.
        let profile = resolve_profile("production").expect("bare preset name");
        assert_eq!(profile.name, "production");
    }

    #[test]
    fn parse_path_class_specs_reads_glob_and_class() {
        let specs = vec![
            "docs/**=docs".to_string(),
            "**/tests/**=fixture".to_string(),
        ];
        let rules = parse_path_class_specs(&specs).expect("valid specifications");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].glob, "docs/**");
        assert_eq!(rules[0].class, aegis_core::PathClass::Docs);
        assert_eq!(rules[1].class, aegis_core::PathClass::Fixture);
    }

    #[test]
    fn parse_path_class_specs_rejects_a_specification_without_a_class() {
        let specs = vec!["docs/**".to_string()];
        let error = parse_path_class_specs(&specs).expect_err("missing class");
        let message = error.to_string();
        assert!(message.contains("GLOB=KIND"), "unexpected error: {message}");
    }

    #[test]
    fn parse_path_class_specs_rejects_an_unknown_class() {
        let specs = vec!["docs/**=prose".to_string()];
        let error = parse_path_class_specs(&specs).expect_err("unknown class");
        let message = error.to_string();
        assert!(message.contains("docs"), "unexpected error: {message}");
        assert!(message.contains("fixture"), "unexpected error: {message}");
    }

    #[test]
    fn parse_path_class_specs_rejects_an_empty_glob() {
        let specs = vec!["=docs".to_string()];
        let error = parse_path_class_specs(&specs).expect_err("empty glob");
        assert!(error.to_string().contains("empty"));
    }

    #[test]
    fn parse_path_class_specs_rejects_a_glob_that_cannot_compile() {
        // A glob that does not compile would classify nothing, and the
        // operator would believe the path had been quieted.
        let specs = vec!["docs/**b=docs".to_string()];
        let error = parse_path_class_specs(&specs).expect_err("invalid glob");
        assert!(error.to_string().contains("glob"));
    }
}
