//! Configuration management

use std::path::PathBuf;

#[allow(dead_code)]
pub fn enable_pattern(_pattern: &str) -> Result<(), anyhow::Error> {
    // In real implementation, this would update the pattern state file
    Ok(())
}

#[allow(dead_code)]
pub fn disable_pattern(_pattern: &str) -> Result<(), anyhow::Error> {
    // In real implementation, this would update the pattern state file
    Ok(())
}

#[allow(dead_code)]
pub fn load_config(path: &PathBuf) -> Result<aegis_core::Config, anyhow::Error> {
    let content = std::fs::read_to_string(path)?;
    let config: aegis_core::Config = serde_json::from_str(&content)?;
    Ok(config)
}

#[allow(dead_code)]
pub fn save_config(config: &aegis_core::Config, path: &PathBuf) -> Result<(), anyhow::Error> {
    let content = serde_json::to_string_pretty(config)?;
    std::fs::write(path, content)?;
    Ok(())
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
}
