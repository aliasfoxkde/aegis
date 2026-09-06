//! Ignore pattern management
//!
//! Handles `.aegisignore` (or its legacy alias `.atheonignore`) and
//! `.gitignore` files. Rules use gitignore-style globs; within a file the
//! last matching rule wins, and a `!` prefix re-includes (un-ignores) a
//! previously ignored path.

use glob::Pattern;
use parking_lot::RwLock;
use std::path::{Path, PathBuf};

/// One parsed ignore rule with its negation flag.
struct IgnoreRule {
    pattern: Pattern,
    /// Pattern text after `!` and trailing `/` removal
    body: String,
    negated: bool,
}

/// Manages ignore patterns for scanning
pub struct IgnoreManager {
    /// Rules from .aegisignore / .atheonignore, in file order
    aegis_rules: RwLock<Vec<IgnoreRule>>,
    /// Rules added programmatically via [`IgnoreManager::add_pattern`]
    explicit_rules: RwLock<Vec<IgnoreRule>>,
    /// Rules from .gitignore, in file order
    gitignore_rules: RwLock<Vec<IgnoreRule>>,
    /// Root directory for ignore files
    root: RwLock<Option<PathBuf>>,
}

impl IgnoreManager {
    /// Create a new ignore manager
    pub fn new() -> Self {
        Self {
            aegis_rules: RwLock::new(Vec::new()),
            explicit_rules: RwLock::new(Vec::new()),
            gitignore_rules: RwLock::new(Vec::new()),
            root: RwLock::new(None),
        }
    }

    /// Set the root directory and load all ignore files
    pub fn set_root(&self, root: &Path) -> std::io::Result<()> {
        self.set_root_with(root, true, true)
    }

    /// Set the root directory, loading only the requested ignore sources.
    ///
    /// Disabling a source re-scans from a clean slate for that source: a
    /// previously loaded file's rules are dropped, so toggling options
    /// between scans cannot leave stale rules behind.
    pub fn set_root_with(
        &self,
        root: &Path,
        respect_gitignore: bool,
        respect_aegisignore: bool,
    ) -> std::io::Result<()> {
        *self.root.write() = Some(root.to_path_buf());

        // .gitignore first: .aegisignore is evaluated after it and can
        // therefore re-include paths the gitignore excludes.
        *self.gitignore_rules.write() = Vec::new();
        if respect_gitignore {
            let gitignore_path = root.join(".gitignore");
            if gitignore_path.exists() {
                self.load_gitignore(&gitignore_path)?;
            }
        }

        *self.aegis_rules.write() = Vec::new();
        if respect_aegisignore {
            let aegis_path = root.join(".aegisignore");
            let legacy_path = root.join(".atheonignore");
            if aegis_path.exists() {
                self.load_aegisignore(&aegis_path)?;
            } else if legacy_path.exists() {
                self.load_aegisignore(&legacy_path)?;
            }
        }

        Ok(())
    }

    /// Load patterns from `.aegisignore` (or legacy `.atheonignore`)
    fn load_aegisignore(&self, path: &Path) -> std::io::Result<()> {
        let content = std::fs::read_to_string(path)?;
        *self.aegis_rules.write() = parse_ignore_rules(&meaningful_lines(&content));
        Ok(())
    }

    /// Load patterns from .gitignore
    fn load_gitignore(&self, path: &Path) -> std::io::Result<()> {
        let content = std::fs::read_to_string(path)?;
        *self.gitignore_rules.write() = parse_ignore_rules(&meaningful_lines(&content));
        Ok(())
    }

    /// Check if a path should be ignored.
    ///
    /// Later matching rules override earlier ones, so a `!pattern` line in
    /// `.aegisignore` re-includes a path excluded by `.gitignore`.
    pub fn should_ignore(&self, path: &Path) -> bool {
        // Built-in rules first: build/cache/VCS directories are always
        // ignored and cannot be re-included.
        for name in path.components() {
            let name = name.as_os_str().to_string_lossy();
            if name == "node_modules" || name == "target" || name == ".git" {
                return true;
            }
        }

        // Walkers rooted at "." yield "./"-prefixed paths; strip it so
        // ignore rules written as "docs/**" match "docs/**" paths.
        let raw = path.to_string_lossy();
        let rel = raw.strip_prefix("./").unwrap_or(&raw);
        let basename = rel.rsplit('/').next().unwrap_or(rel);

        let mut ignored = false;
        {
            let gitignore_rules = self.gitignore_rules.read();
            for rule in gitignore_rules.iter() {
                if rule_matches(rule, rel, basename) {
                    ignored = !rule.negated;
                }
            }
        }
        let aegis_rules = self.aegis_rules.read();
        for rule in aegis_rules.iter() {
            if rule_matches(rule, rel, basename) {
                ignored = !rule.negated;
            }
        }
        // Explicit rules are evaluated last so API callers can override
        // anything an ignore file on disk decided.
        let explicit_rules = self.explicit_rules.read();
        for rule in explicit_rules.iter() {
            if rule_matches(rule, rel, basename) {
                ignored = !rule.negated;
            }
        }
        ignored
    }

    /// Add a pattern directly
    pub fn add_pattern(&self, pattern: &str) -> Result<(), PatternError> {
        compile_rule(pattern)
            .map(|rule| self.explicit_rules.write().push(rule))
            .map_err(|_| PatternError::InvalidPattern(pattern.to_string()))
    }

    /// Clear all patterns
    pub fn clear(&self) {
        self.aegis_rules.write().clear();
        self.explicit_rules.write().clear();
        self.gitignore_rules.write().clear();
        *self.root.write() = None;
    }
}

/// Split an ignore file into its meaningful lines (comments and blanks
/// removed), keeping the original order for last-match-wins evaluation.
fn meaningful_lines(content: &str) -> Vec<String> {
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

/// Parse ignore-file lines into ordered rules. Invalid globs are skipped
/// so one bad line cannot disable the rest of the ignore file.
fn parse_ignore_rules(lines: &[String]) -> Vec<IgnoreRule> {
    lines
        .iter()
        .filter_map(|line| compile_rule(line).ok())
        .collect()
}

/// Compile one ignore-file line into a rule. A trailing `/` marks a
/// directory rule; it is stripped because matching walks path prefixes,
/// which never carry a trailing slash.
fn compile_rule(line: &str) -> Result<IgnoreRule, ()> {
    let (negated, raw) = match line.trim().strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, line.trim()),
    };
    let body = raw.trim_end_matches('/');
    if body.is_empty() {
        return Err(());
    }
    let pattern = Pattern::new(body).map_err(|_| ())?;
    Ok(IgnoreRule {
        pattern,
        body: body.to_string(),
        negated,
    })
}

/// Gitignore-style matching for one rule against a normalized relative
/// path.
///
/// A rule hits when it matches the basename (`*.log` matching
/// `src/debug.log`), the full path (`docs/keep.md`), or an ancestor
/// directory prefix (`build` matching everything under `build/`, and for
/// unanchored rules at any depth: `nested/build/...`).
fn rule_matches(rule: &IgnoreRule, rel: &str, basename: &str) -> bool {
    if rule.pattern.matches(basename) || rule.pattern.matches(rel) {
        return true;
    }
    let components: Vec<&str> = rel.split('/').collect();
    // Anchored rules (containing `/`) match from the path root only;
    // unanchored rules can match a directory at any depth.
    let starts: Vec<usize> = if rule.body.contains('/') {
        vec![0]
    } else {
        (0..components.len()).collect()
    };
    for start in starts {
        let mut prefix = String::with_capacity(rel.len());
        for component in &components[start..] {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            if rule.pattern.matches(&prefix) {
                return true;
            }
        }
    }
    false
}

impl Default for IgnoreManager {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for IgnoreManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IgnoreManager")
            .field("aegis_rule_count", &self.aegis_rules.read().len())
            .field("explicit_rule_count", &self.explicit_rules.read().len())
            .field("gitignore_rule_count", &self.gitignore_rules.read().len())
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
    fn test_add_negated_pattern() {
        let manager = IgnoreManager::new();
        manager.add_pattern("*.log").unwrap();
        manager.add_pattern("!keep.log").unwrap();
        assert!(manager.should_ignore(Path::new("debug.log")));
        assert!(!manager.should_ignore(Path::new("keep.log")));
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
    fn test_set_root_with_aegisignore() {
        let temp_dir = TempDir::new().unwrap();
        let ignore_file = temp_dir.path().join(".aegisignore");
        File::create(&ignore_file)
            .unwrap()
            .write_all(b"*.log\n!important.log\n")
            .unwrap();

        let manager = IgnoreManager::new();
        let result = manager.set_root(temp_dir.path());
        assert!(result.is_ok());
        // *.log should be ignored, and the later bare line is not a
        // re-include (it has no `!`), so important.log is also ignored.
        assert!(manager.should_ignore(Path::new("debug.log")));
    }

    #[test]
    fn test_negation_reincludes_ignored_path() {
        let temp_dir = TempDir::new().unwrap();
        let ignore_file = temp_dir.path().join(".aegisignore");
        File::create(&ignore_file)
            .unwrap()
            .write_all(b"fixtures/**\n!fixtures/allowed/**\n")
            .unwrap();

        let manager = IgnoreManager::new();
        manager.set_root(temp_dir.path()).unwrap();
        assert!(manager.should_ignore(Path::new("fixtures/sample.txt")));
        assert!(!manager.should_ignore(Path::new("fixtures/allowed/ok.txt")));
    }

    #[test]
    fn test_aegisignore_overrides_gitignore() {
        let temp_dir = TempDir::new().unwrap();
        File::create(temp_dir.path().join(".gitignore"))
            .unwrap()
            .write_all(b"docs/**\n")
            .unwrap();
        File::create(temp_dir.path().join(".aegisignore"))
            .unwrap()
            .write_all(b"!docs/keep.md\n")
            .unwrap();

        let manager = IgnoreManager::new();
        manager.set_root(temp_dir.path()).unwrap();
        assert!(manager.should_ignore(Path::new("docs/other.md")));
        assert!(!manager.should_ignore(Path::new("docs/keep.md")));
    }

    #[test]
    fn test_legacy_atheonignore_still_loaded() {
        let temp_dir = TempDir::new().unwrap();
        File::create(temp_dir.path().join(".atheonignore"))
            .unwrap()
            .write_all(b"*.legacy\n")
            .unwrap();

        let manager = IgnoreManager::new();
        manager.set_root(temp_dir.path()).unwrap();
        assert!(manager.should_ignore(Path::new("old.legacy")));
    }

    #[test]
    fn test_set_root_with_can_disable_sources() {
        let temp_dir = TempDir::new().unwrap();
        File::create(temp_dir.path().join(".gitignore"))
            .unwrap()
            .write_all(b"*.gitignored\n")
            .unwrap();
        File::create(temp_dir.path().join(".aegisignore"))
            .unwrap()
            .write_all(b"*.aegisignored\n")
            .unwrap();

        let manager = IgnoreManager::new();

        // Both disabled: no file rules apply.
        manager
            .set_root_with(temp_dir.path(), false, false)
            .unwrap();
        assert!(!manager.should_ignore(Path::new("x.gitignored")));
        assert!(!manager.should_ignore(Path::new("x.aegisignored")));

        // Only .aegisignore enabled.
        manager.set_root_with(temp_dir.path(), false, true).unwrap();
        assert!(!manager.should_ignore(Path::new("x.gitignored")));
        assert!(manager.should_ignore(Path::new("x.aegisignored")));

        // Only .gitignore enabled.
        manager.set_root_with(temp_dir.path(), true, false).unwrap();
        assert!(manager.should_ignore(Path::new("x.gitignored")));
        assert!(!manager.should_ignore(Path::new("x.aegisignored")));
    }

    #[test]
    fn test_set_root_with_keeps_explicit_patterns() {
        let temp_dir = TempDir::new().unwrap();
        File::create(temp_dir.path().join(".aegisignore"))
            .unwrap()
            .write_all(b"*.fromfile\n")
            .unwrap();

        let manager = IgnoreManager::new();
        manager.add_pattern("*.explicit").unwrap();

        // Reload with the source disabled: the explicit pattern must
        // survive, the file rule must not.
        manager
            .set_root_with(temp_dir.path(), false, false)
            .unwrap();
        assert!(manager.should_ignore(Path::new("x.explicit")));
        assert!(!manager.should_ignore(Path::new("x.fromfile")));
    }

    #[test]
    fn test_explicit_patterns_override_files() {
        let temp_dir = TempDir::new().unwrap();
        File::create(temp_dir.path().join(".aegisignore"))
            .unwrap()
            .write_all(b"*.log\n")
            .unwrap();

        let manager = IgnoreManager::new();
        manager.set_root(temp_dir.path()).unwrap();
        assert!(manager.should_ignore(Path::new("x.log")));

        manager.add_pattern("!keep.log").unwrap();
        assert!(manager.should_ignore(Path::new("other.log")));
        assert!(!manager.should_ignore(Path::new("keep.log")));
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
        assert!(debug_str.contains("aegis_rule_count"));
    }

    #[test]
    fn test_should_ignore_with_star_pattern() {
        let manager = IgnoreManager::new();
        manager.add_pattern("*secret*").unwrap();
        assert!(manager.should_ignore(Path::new("my_secret.txt")));
        assert!(manager.should_ignore(Path::new("src/secret/config.rs")));
    }

    #[test]
    fn test_ignore_manager_default() {
        // Test Default trait
        let manager: IgnoreManager = Default::default();
        // Default manager should not ignore regular files
        assert!(!manager.should_ignore(Path::new("src/main.rs")));
    }

    #[test]
    fn test_should_ignore_with_gitignore_pattern() {
        // Create a temp dir with .gitignore containing a pattern
        let temp_dir = TempDir::new().unwrap();
        let gitignore = temp_dir.path().join(".gitignore");
        File::create(&gitignore)
            .unwrap()
            .write_all(b"*.secret\n")
            .unwrap();

        let manager = IgnoreManager::new();
        manager.set_root(temp_dir.path()).ok();

        // Should ignore files matching the gitignore pattern
        assert!(manager.should_ignore(Path::new("test.secret")));
        assert!(manager.should_ignore(Path::new("src/my.secret")));
    }

    #[test]
    fn test_load_aegisignore_with_empty_lines_and_comments() {
        // Test that empty lines and comments are properly skipped
        let temp_dir = TempDir::new().unwrap();
        let ignore_file = temp_dir.path().join(".aegisignore");
        File::create(&ignore_file)
            .unwrap()
            .write_all(b"# Comment line\n\n*.log\n# Another comment\n*.tmp\n")
            .unwrap();

        let manager = IgnoreManager::new();
        let result = manager.set_root(temp_dir.path());
        assert!(result.is_ok());

        // Should ignore *.log and *.tmp files
        assert!(manager.should_ignore(Path::new("debug.log")));
        assert!(manager.should_ignore(Path::new("file.tmp")));
        // Should not ignore other files
        assert!(!manager.should_ignore(Path::new("debug.txt")));
    }

    #[test]
    fn test_load_gitignore_with_invalid_patterns() {
        // Test that invalid patterns are gracefully skipped
        let temp_dir = TempDir::new().unwrap();
        let gitignore = temp_dir.path().join(".gitignore");
        // Write invalid glob patterns that will fail to parse
        File::create(&gitignore)
            .unwrap()
            .write_all(b"[invalid\n*.tmp\n")
            .unwrap();

        let manager = IgnoreManager::new();
        let result = manager.set_root(temp_dir.path());
        assert!(result.is_ok());

        // Should still load the *.tmp pattern even though [invalid fails
        assert!(manager.should_ignore(Path::new("debug.tmp")));
    }

    #[test]
    fn test_load_aegisignore_with_negated_invalid_pattern() {
        // Invalid globs are skipped; valid rules on other lines still load
        let temp_dir = TempDir::new().unwrap();
        let ignore_file = temp_dir.path().join(".aegisignore");
        File::create(&ignore_file)
            .unwrap()
            .write_all(b"![invalid\n*.tmp\n")
            .unwrap();

        let manager = IgnoreManager::new();
        let result = manager.set_root(temp_dir.path());
        assert!(result.is_ok());

        // The *.tmp pattern should still work
        assert!(manager.should_ignore(Path::new("debug.tmp")));
    }

    #[test]
    fn test_basename_matching_for_extension_rules() {
        // gitignore semantics: "*.log" ignores logs at any depth
        let manager = IgnoreManager::new();
        manager.add_pattern("*.log").unwrap();
        assert!(manager.should_ignore(Path::new("src/nested/debug.log")));
    }

    #[test]
    fn test_dot_slash_prefixed_paths_match() {
        // Walking a scan root of "." produces "./"-prefixed paths; ignore
        // rules must still match them.
        let manager = IgnoreManager::new();
        manager.add_pattern("docs/**").unwrap();
        assert!(manager.should_ignore(Path::new("./docs/guide.md")));
        assert!(manager.should_ignore(Path::new("docs/guide.md")));
        assert!(!manager.should_ignore(Path::new("./src/lib.rs")));
    }

    #[test]
    fn test_directory_name_rule_ignores_contents() {
        // "build" (or "build/") ignores everything beneath the directory
        let manager = IgnoreManager::new();
        manager.add_pattern("build/").unwrap();
        assert!(manager.should_ignore(Path::new("build/output.js")));
        assert!(manager.should_ignore(Path::new("nested/build/output.js")));

        let manager = IgnoreManager::new();
        manager.add_pattern("dist").unwrap();
        assert!(manager.should_ignore(Path::new("dist/bundle.js")));
    }
}
