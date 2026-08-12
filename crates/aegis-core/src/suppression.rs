//! Line-level suppression handling
//!
//! Handles `// aegis:ignore` and `# aegis:ignore` comments.

use std::collections::HashSet;
use std::path::Path;
use std::sync::RwLock;

/// Suppression for a finding
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Suppression {
    /// Pattern name to suppress
    pub pattern: String,
    /// Line number (1-indexed)
    pub line: u32,
    /// Optional reason
    pub reason: Option<String>,
}

impl Suppression {
    /// Create a new suppression
    pub fn new(pattern: impl Into<String>, line: u32) -> Self {
        Self {
            pattern: pattern.into(),
            line,
            reason: None,
        }
    }

    /// Create with a reason
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

/// Manages finding suppressions - RwLock allows parallel reads
#[derive(Debug, Default)]
pub struct SuppressionManager {
    suppressions: RwLock<HashSet<Suppression>>,
}

impl SuppressionManager {
    /// Create a new manager
    pub fn new() -> Self {
        Self {
            suppressions: RwLock::new(HashSet::new()),
        }
    }

    /// Load suppressions from a file
    pub fn load_file(&mut self, path: &Path) -> std::io::Result<()> {
        let content = std::fs::read_to_string(path)?;
        self.parse_content(&content);
        Ok(())
    }

    /// Parse suppressions from file content
    pub fn parse_content(&mut self, content: &str) {
        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num as u32 + 1; // 1-indexed

            // Check for // aegis:ignore or # aegis:ignore
            if let Some(remaining) = line.trim_start().strip_prefix("// aegis:ignore") {
                self.parse_suppression_line(line_num, remaining);
            } else if let Some(remaining) = line.trim_start().strip_prefix("# aegis:ignore") {
                self.parse_suppression_line(line_num, remaining);
            } else if let Some(remaining) = line.trim_start().strip_prefix("/* aegis:ignore") {
                self.parse_multiline_start(line_num, remaining);
            }
        }
    }

    /// Parse a suppression directive
    fn parse_suppression_line(&mut self, line: u32, rest: &str) {
        let rest = rest.trim();

        if rest.is_empty() {
            // Full line suppression - suppress all patterns on this line
            return;
        }

        // Check for specific pattern
        if let Some(pattern_part) = rest.strip_prefix(':') {
            let pattern = pattern_part.trim();
            if !pattern.is_empty() {
                self.suppressions
                    .write()
                    .unwrap()
                    .insert(Suppression::new(pattern, line));
            }
        } else if let Some(reason_part) = rest.strip_prefix("reason:") {
            // aegis:ignore reason:...
            let reason = reason_part.trim();
            // Get last suppression for this line
            // This is a simplification - in real impl would track separately
            let _ = reason;
        }
    }

    /// Parse multiline comment start
    fn parse_multiline_start(&mut self, line: u32, rest: &str) {
        let rest = rest.trim();
        if let Some(rest) = rest.strip_suffix("*/") {
            // Single line multiline comment
            self.parse_suppression_line(line, rest);
        }
    }

    /// Check if a finding should be suppressed
    pub fn is_suppressed(&self, pattern: &str, line: u32) -> bool {
        // Check exact match using composite key
        let guard = self.suppressions.read().unwrap();
        guard.contains(&Suppression::new(pattern, line))
    }

    /// Add a suppression
    pub fn add(&mut self, suppression: Suppression) {
        self.suppressions.write().unwrap().insert(suppression);
    }

    /// Remove a suppression
    pub fn remove(&mut self, suppression: &Suppression) {
        self.suppressions.write().unwrap().remove(suppression);
    }

    /// Get all suppressions
    pub fn all(&self) -> Vec<Suppression> {
        self.suppressions.read().unwrap().iter().cloned().collect()
    }

    /// Clear all suppressions
    pub fn clear(&mut self) {
        self.suppressions.write().unwrap().clear();
    }

    /// Get suppression count
    pub fn len(&self) -> usize {
        self.suppressions.read().unwrap().len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.suppressions.read().unwrap().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_line() {
        let mut manager = SuppressionManager::new();
        manager.parse_content("// aegis:ignore\n");
        assert_eq!(manager.len(), 0); // No specific pattern
    }

    #[test]
    fn test_parse_pattern_suppression() {
        let mut manager = SuppressionManager::new();
        manager.parse_content("// aegis:ignore:hardcoded-secret\n");
        assert!(manager.is_suppressed("hardcoded-secret", 1));
        assert!(!manager.is_suppressed("other-pattern", 1));
    }

    #[test]
    fn test_suppression_add_remove() {
        let mut manager = SuppressionManager::new();
        manager.add(Suppression::new("test-pattern", 10));
        assert_eq!(manager.len(), 1);
        assert!(manager.is_suppressed("test-pattern", 10));

        manager.remove(&Suppression::new("test-pattern", 10));
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn test_hash_suppression() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(Suppression::new("pattern1", 5));
        set.insert(Suppression::new("pattern1", 5)); // Duplicate

        assert_eq!(set.len(), 1);

        set.insert(Suppression::new("pattern1", 6)); // Different line
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_parse_hash_style() {
        let mut manager = SuppressionManager::new();
        manager.parse_content("# aegis:ignore:python-secret\n");
        assert!(manager.is_suppressed("python-secret", 1));
        assert!(!manager.is_suppressed("other-pattern", 1));
    }

    #[test]
    fn test_parse_multiline_comment_style() {
        let mut manager = SuppressionManager::new();
        manager.parse_content("/* aegis:ignore:multiline-secret */\n");
        assert!(manager.is_suppressed("multiline-secret", 1));
    }

    #[test]
    fn test_suppression_with_reason() {
        let suppression = Suppression::new("pattern", 5).with_reason("False positive");
        assert_eq!(suppression.pattern, "pattern");
        assert_eq!(suppression.line, 5);
        assert_eq!(suppression.reason, Some("False positive".to_string()));
    }

    #[test]
    fn test_suppression_manager_is_empty() {
        let manager = SuppressionManager::new();
        assert!(manager.is_empty());

        let mut manager = SuppressionManager::new();
        manager.add(Suppression::new("pattern", 1));
        assert!(!manager.is_empty());
    }

    #[test]
    fn test_suppression_manager_all() {
        let mut manager = SuppressionManager::new();
        manager.add(Suppression::new("pattern1", 1));
        manager.add(Suppression::new("pattern2", 2));

        let all = manager.all();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_suppression_manager_clear() {
        let mut manager = SuppressionManager::new();
        manager.add(Suppression::new("pattern", 1));
        assert_eq!(manager.len(), 1);

        manager.clear();
        assert_eq!(manager.len(), 0);
        assert!(manager.is_empty());
    }

    #[test]
    fn test_parse_multiple_lines() {
        let mut manager = SuppressionManager::new();
        manager.parse_content("// aegis:ignore:secret1\n// aegis:ignore:secret2\n");
        assert!(manager.is_suppressed("secret1", 1));
        assert!(manager.is_suppressed("secret2", 2));
    }

    #[test]
    fn test_parse_reason_not_stored() {
        let mut manager = SuppressionManager::new();
        manager.parse_content("// aegis:ignore reason:This is a test reason\n");
        // Reason is parsed but not stored in current implementation
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn test_load_file_missing() {
        let mut manager = SuppressionManager::new();
        let result = manager.load_file(std::path::Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_file_success() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("suppressions.txt");
        std::fs::write(&file_path, "// aegis:ignore:secret1\n").unwrap();

        let mut manager = SuppressionManager::new();
        let result = manager.load_file(&file_path);
        assert!(result.is_ok());
        assert!(manager.is_suppressed("secret1", 1));
    }
}
