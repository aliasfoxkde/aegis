//! Ignore pattern management
//!
//! Handles .atheonignore and .gitignore files.

use glob::Pattern;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

/// Manages ignore patterns for scanning
pub struct IgnoreManager {
    /// Patterns from .atheonignore
    atheonignore: RwLock<Vec<Pattern>>,
    /// Patterns from .gitignore
    gitignore: RwLock<Vec<Pattern>>,
    /// Root directory for ignore files
    root: RwLock<Option<PathBuf>>,
}

impl IgnoreManager {
    /// Create a new ignore manager
    pub fn new() -> Self {
        Self {
            atheonignore: RwLock::new(Vec::new()),
            gitignore: RwLock::new(Vec::new()),
            root: RwLock::new(None),
        }
    }

    /// Set the root directory and load ignore files
    pub fn set_root(&self, root: &Path) -> std::io::Result<()> {
        *self.root.write().unwrap() = Some(root.to_path_buf());

        // Load .atheonignore
        let atheon_path = root.join(".atheonignore");
        if atheon_path.exists() {
            self.load_atheonignore(&atheon_path)?;
        }

        // Load .gitignore
        let gitignore_path = root.join(".gitignore");
        if gitignore_path.exists() {
            self.load_gitignore(&gitignore_path)?;
        }

        Ok(())
    }

    /// Load patterns from .atheonignore
    fn load_atheonignore(&self, path: &Path) -> std::io::Result<()> {
        let content = std::fs::read_to_string(path)?;
        let mut patterns = self.atheonignore.write().unwrap();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            //Negate patterns
            if let Some(negated) = line.strip_prefix('!') {
                match Pattern::new(negated) {
                    Ok(_p) => {
                        // Store negated patterns with a special flag
                        // For simplicity, we'll handle this differently
                    }
                    Err(_) => continue,
                }
            } else {
                match Pattern::new(line) {
                    Ok(p) => patterns.push(p),
                    Err(_) => continue,
                }
            }
        }

        Ok(())
    }

    /// Load patterns from .gitignore
    fn load_gitignore(&self, path: &Path) -> std::io::Result<()> {
        let content = std::fs::read_to_string(path)?;
        let mut patterns = self.gitignore.write().unwrap();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Negated patterns
            if let Some(negated) = line.strip_prefix('!') {
                _ = negated; // Ignored for now
            } else {
                match Pattern::new(line) {
                    Ok(p) => patterns.push(p),
                    Err(_) => continue,
                }
            }
        }

        Ok(())
    }

    /// Check if a path should be ignored
    pub fn should_ignore(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        // Check .atheonignore patterns
        let atheon_patterns = self.atheonignore.read().unwrap();
        for pattern in atheon_patterns.iter() {
            if pattern.matches(&path_str) {
                return true;
            }
        }

        // Check .gitignore patterns
        let git_patterns = self.gitignore.read().unwrap();
        for pattern in git_patterns.iter() {
            if pattern.matches(&path_str) {
                return true;
            }
        }

        // Check if file is in a node_modules or target directory
        let components: Vec<_> = path.components().collect();
        for component in components {
            let name = component.as_os_str().to_string_lossy();
            if name == "node_modules" || name == "target" || name == ".git" {
                return true;
            }
        }

        false
    }

    /// Add a pattern directly
    pub fn add_pattern(&self, pattern: &str) -> Result<(), PatternError> {
        let p =
            Pattern::new(pattern).map_err(|_| PatternError::InvalidPattern(pattern.to_string()))?;
        self.atheonignore.write().unwrap().push(p);
        Ok(())
    }

    /// Clear all patterns
    pub fn clear(&self) {
        self.atheonignore.write().unwrap().clear();
        self.gitignore.write().unwrap().clear();
        *self.root.write().unwrap() = None;
    }
}

impl Default for IgnoreManager {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for IgnoreManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IgnoreManager")
            .field(
                "atheonignore_count",
                &self.atheonignore.read().unwrap().len(),
            )
            .field("gitignore_count", &self.gitignore.read().unwrap().len())
            .finish()
    }
}

/// Pattern error types
#[derive(Debug, thiserror::Error)]
pub enum PatternError {
    #[error("Invalid glob pattern: {0}")]
    InvalidPattern(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ignore_manager_new() {
        let manager = IgnoreManager::new();
        assert!(!manager.should_ignore(Path::new("test.rs")));
    }

    #[test]
    fn test_add_pattern() {
        let manager = IgnoreManager::new();
        manager.add_pattern("*.log").unwrap();
        assert!(manager.should_ignore(Path::new("debug.log")));
        assert!(!manager.should_ignore(Path::new("debug.txt")));
    }

    #[test]
    fn test_ignore_directories() {
        let manager = IgnoreManager::new();
        assert!(manager.should_ignore(Path::new("node_modules/package.json")));
        assert!(manager.should_ignore(Path::new("target/debug/binary")));
    }

    #[test]
    fn test_invalid_pattern() {
        let manager = IgnoreManager::new();
        assert!(manager.add_pattern("[").is_err());
    }
}
