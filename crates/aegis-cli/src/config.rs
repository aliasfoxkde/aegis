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
