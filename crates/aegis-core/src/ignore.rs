//! Ignore pattern management
//!
//! Handles .atheonignore and .gitignore files.

use glob::Pattern;
use parking_lot::RwLock;
use std::path::{Path, PathBuf};

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
        *self.root.write() = Some(root.to_path_buf());

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
        let mut patterns = self.atheonignore.write();

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
        let mut patterns = self.gitignore.write();

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
        let atheon_patterns = self.atheonignore.read();
        for pattern in atheon_patterns.iter() {
            if pattern.matches(&path_str) {
                return true;
            }
        }

        // Check .gitignore patterns
        let git_patterns = self.gitignore.read();
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
        self.atheonignore.write().push(p);
        Ok(())
    }

    /// Clear all patterns
    pub fn clear(&self) {
        self.atheonignore.write().clear();
        self.gitignore.write().clear();
        *self.root.write() = None;
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
                &self.atheonignore.read().len(),
            )
            .field("gitignore_count", &self.gitignore.read().len())
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
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

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
        assert!(manager.should_ignore(Path::new(".git/config")));
    }

    #[test]
    fn test_invalid_pattern() {
        let manager = IgnoreManager::new();
        assert!(manager.add_pattern("[").is_err());
    }

    #[test]
    fn test_set_root_nonexistent() {
        let manager = IgnoreManager::new();
        // Should not error when root doesn't exist
        let result = manager.set_root(Path::new("/nonexistent/path/12345"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_set_root_with_atheonignore() {
        let temp_dir = TempDir::new().unwrap();
        let ignore_file = temp_dir.path().join(".atheonignore");
        File::create(&ignore_file)
            .unwrap()
            .write_all(b"*.log\n!important.log\n")
            .unwrap();

        let manager = IgnoreManager::new();
        let result = manager.set_root(temp_dir.path());
        assert!(result.is_ok());
        // *.log should be ignored
        assert!(manager.should_ignore(Path::new("debug.log")));
    }

    #[test]
    fn test_set_root_with_gitignore() {
        let temp_dir = TempDir::new().unwrap();
        let gitignore = temp_dir.path().join(".gitignore");
        File::create(&gitignore)
            .unwrap()
            .write_all(b"*.tmp\nbuild/\n")
            .unwrap();

        let manager = IgnoreManager::new();
        let result = manager.set_root(temp_dir.path());
        assert!(result.is_ok());
        assert!(manager.should_ignore(Path::new("debug.tmp")));
    }

    #[test]
    fn test_clear_patterns() {
        let manager = IgnoreManager::new();
        manager.add_pattern("*.log").unwrap();
        assert!(manager.should_ignore(Path::new("debug.log")));

        manager.clear();
        // After clear, should not ignore (unless default rules apply)
        // Note: node_modules/target/.git are always ignored
        assert!(!manager.should_ignore(Path::new("debug.log")));
    }

    #[test]
    fn test_multiple_patterns() {
        let manager = IgnoreManager::new();
        manager.add_pattern("*.log").unwrap();
        manager.add_pattern("*.tmp").unwrap();
        assert!(manager.should_ignore(Path::new("debug.log")));
        assert!(manager.should_ignore(Path::new("file.tmp")));
        assert!(!manager.should_ignore(Path::new("file.txt")));
    }

    #[test]
    fn test_debug_trait() {
        let manager = IgnoreManager::new();
        manager.add_pattern("*.log").unwrap();
        let debug_str = format!("{:?}", manager);
        assert!(debug_str.contains("IgnoreManager"));
        assert!(debug_str.contains("atheonignore_count"));
    }

    #[test]
    fn test_should_ignore_with_star_pattern() {
        let manager = IgnoreManager::new();
        manager.add_pattern("*secret*").unwrap();
        assert!(manager.should_ignore(Path::new("my_secret.txt")));
        assert!(manager.should_ignore(Path::new("src/secret/config.rs")));
    }
}
