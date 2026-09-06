//! Inline suppression handling
//!
//! Directives embedded in source comments keep flagged lines out of
//! results. All directives work in `//`, `#`, and single-line `/* ... */`
//! comments:
//!
//! | Directive | Effect |
//! |-----------|--------|
//! | `aegis:ignore:pat1,pat2` | Suppress the named patterns on this line |
//! | `aegis:ignore-start` | Begin suppressing every pattern |
//! | `aegis:ignore-end` | End the innermost open range |
//! | `aegis:ignore-file` | Suppress the entire file |
//!
//! An optional reason follows a `--` separator:
//! `aegis:ignore:hardcoded-secret -- test fixture`. A bare
//! `aegis:ignore` with no pattern list suppresses nothing —
//! suppressions must name what they suppress.

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

/// Suppression for a finding
#[derive(Debug, Clone)]
pub struct Suppression {
    /// Pattern name to suppress
    pub pattern: String,
    /// Line number (1-indexed)
    pub line: u32,
    /// Optional reason
    pub reason: Option<String>,
}

// Equality and hashing deliberately ignore `reason`: lookups by
// `(pattern, line)` must find suppressions regardless of whether a
// reason was recorded alongside them.
impl PartialEq for Suppression {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern && self.line == other.line
    }
}
impl Eq for Suppression {}
impl std::hash::Hash for Suppression {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.pattern.hash(state);
        self.line.hash(state);
    }
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

/// A line range over which every pattern is suppressed.
///
/// An open range (`end: None`) extends to the end of the file; ranges
/// are only produced by `aegis:ignore-start` directives, and a directive
/// on the start line suppresses that line too.
#[derive(Debug, Clone)]
pub struct SuppressionRange {
    /// First suppressed line (1-indexed)
    pub start: u32,
    /// Last suppressed line, or `None` for "to end of file"
    pub end: Option<u32>,
    /// Optional reason
    pub reason: Option<String>,
}

impl SuppressionRange {
    /// Whether this range covers the line
    pub fn contains(&self, line: u32) -> bool {
        match self.end {
            Some(end) => line >= self.start && line <= end,
            None => line >= self.start,
        }
    }
}

/// Manages finding suppressions - RwLock allows parallel reads
#[derive(Debug, Default)]
pub struct SuppressionManager {
    suppressions: RwLock<HashSet<Suppression>>,
    /// `aegis:ignore-start` ranges, all-pattern
    ranges: RwLock<Vec<SuppressionRange>>,
    /// `aegis:ignore-file` reason, when the file is wholly suppressed
    file_suppressed: RwLock<Option<String>>,
    /// Findings actually suppressed by `is_suppressed`
    suppressed_hits: AtomicU64,
}

impl SuppressionManager {
    /// Create a new manager
    pub fn new() -> Self {
        Self {
            suppressions: RwLock::new(HashSet::new()),
            ranges: RwLock::new(Vec::new()),
            file_suppressed: RwLock::new(None),
            suppressed_hits: AtomicU64::new(0),
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

            // Check for // aegis:ignore or # aegis:ignore. Rust fixtures often
            // need an inline directive after the expression being tested.
            if let Some(remaining) = line.trim_start().strip_prefix("// aegis:ignore") {
                self.parse_directive(line_num, remaining);
            } else if let Some(marker) = line.find("// aegis:ignore") {
                self.parse_directive(line_num, &line[marker + 15..]);
            } else if let Some(remaining) = line.trim_start().strip_prefix("# aegis:ignore") {
                self.parse_directive(line_num, remaining);
            } else if let Some(marker) = line.find("# aegis:ignore") {
                // Mid-line `#` directives (YAML, shell, Python) — mirrors
                // the mid-line `//` handling above.
                if !line[..marker].contains("//") {
                    self.parse_directive(line_num, &line[marker + 14..]);
                }
            } else if let Some(remaining) = line.trim_start().strip_prefix("/* aegis:ignore") {
                // `/* ... */` on one line: drop the closer before parsing.
                let remaining = remaining
                    .trim()
                    .strip_suffix("*/")
                    .map(str::trim)
                    .unwrap_or(remaining);
                self.parse_directive(line_num, remaining);
            }
        }
    }

    /// Parse one suppression directive body (the text after the marker).
    fn parse_directive(&mut self, line: u32, raw_rest: &str) {
        // Strip a trailing block-comment closer so a directive inside
        // `/* ... */` parses; the name tokenizer below already tolerates
        // stray characters from directives embedded in string literals.
        let rest = raw_rest.trim();
        let rest = rest.strip_suffix("*/").map(str::trim).unwrap_or(rest);

        // Split an optional trailing reason: `:pat -- why`.
        let (spec, reason) = match rest.split_once(" -- ") {
            Some((spec, reason)) => (spec.trim(), Some(reason.trim())),
            None => (rest, None),
        };

        if let Some(rest) = spec.strip_prefix("-file") {
            // aegis:ignore-file — the whole file, patterns cannot be named.
            let mut file = self.file_suppressed.write().unwrap();
            *file = Some(reason.unwrap_or(rest.trim()).to_string());
            return;
        }

        if let Some(rest) = spec.strip_prefix("-start") {
            if rest.trim().is_empty() {
                self.ranges.write().unwrap().push(SuppressionRange {
                    start: line,
                    end: None,
                    reason: reason.map(str::to_string),
                });
            }
            return;
        }

        if let Some(rest) = spec.strip_prefix("-end") {
            if rest.trim().is_empty() {
                // Close the most recently opened unterminated range; an
                // `-end` with no open range is a no-op.
                if let Some(open) = self
                    .ranges
                    .write()
                    .unwrap()
                    .iter_mut()
                    .rev()
                    .find(|range| range.end.is_none())
                {
                    open.end = Some(line);
                }
            }
            return;
        }

        // Pattern list: `:pat1,pat2`. A bare directive suppresses
        // nothing — suppressions must name what they suppress.
        let Some(pattern_part) = spec.strip_prefix(':') else {
            return;
        };
        let mut suppressions = self.suppressions.write().unwrap();
        for pattern in pattern_part.split(',').map(str::trim) {
            // A directive embedded in a string literal (common in
            // fixtures that test this parser) carries trailing source
            // characters like `")`. Take only the name token.
            let name: String = pattern
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
                .collect();
            if !name.is_empty() {
                let suppression = Suppression::new(name, line);
                let suppression = match reason {
                    Some(reason) => suppression.with_reason(reason),
                    None => suppression,
                };
                suppressions.insert(suppression);
            }
        }
    }

    /// Check if a finding should be suppressed
    pub fn is_suppressed(&self, pattern: &str, line: u32) -> bool {
        let suppressed = self.file_suppressed.read().unwrap().is_some()
            || self
                .ranges
                .read()
                .unwrap()
                .iter()
                .any(|range| range.contains(line))
            || self
                .suppressions
                .read()
                .unwrap()
                .contains(&Suppression::new(pattern, line));
        if suppressed {
            self.suppressed_hits.fetch_add(1, Ordering::Relaxed);
        }
        suppressed
    }

    /// The reason recorded for a suppressed `(pattern, line)`, if any.
    pub fn reason_for(&self, pattern: &str, line: u32) -> Option<String> {
        self.suppressions
            .read()
            .unwrap()
            .get(&Suppression::new(pattern, line))
            .and_then(|suppression| suppression.reason.clone())
    }

    /// Whether the whole file is suppressed via `aegis:ignore-file`.
    pub fn is_file_suppressed(&self) -> bool {
        self.file_suppressed.read().unwrap().is_some()
    }

    /// The reason recorded by `aegis:ignore-file`, if any.
    pub fn file_reason(&self) -> Option<String> {
        self.file_suppressed
            .read()
            .unwrap()
            .clone()
            .filter(|reason| !reason.is_empty())
    }

    /// All `aegis:ignore-start` ranges, open or closed.
    pub fn ranges(&self) -> Vec<SuppressionRange> {
        self.ranges.read().unwrap().clone()
    }

    /// How many findings `is_suppressed` has suppressed so far.
    pub fn suppressed_count(&self) -> u64 {
        self.suppressed_hits.load(Ordering::Relaxed)
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
        self.ranges.write().unwrap().clear();
        *self.file_suppressed.write().unwrap() = None;
        self.suppressed_hits.store(0, Ordering::Relaxed);
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
    fn test_parse_inline_pattern_suppression() {
        let mut manager = SuppressionManager::new();
        manager.parse_content("let fixture = \"test\"; // aegis:ignore:hardcoded-secret\n");
        assert!(manager.is_suppressed("hardcoded-secret", 1));
        assert!(!manager.is_suppressed("other-pattern", 1));
    }

    #[test]
    fn test_parse_multiple_inline_pattern_suppressions() {
        let mut manager = SuppressionManager::new();
        manager.parse_content("fixture // aegis:ignore:first-pattern, second-pattern\n");
        assert!(manager.is_suppressed("first-pattern", 1));
        assert!(manager.is_suppressed("second-pattern", 1));
        assert!(!manager.is_suppressed("other-pattern", 1));
    }

    #[test]
    fn test_directive_embedded_in_string_literal() {
        // Fixtures that test this parser embed the directive inside a
        // string literal; trailing source characters like `")` after the
        // last pattern name must not poison the token.
        let mut manager = SuppressionManager::new();
        manager.parse_content(
            "    let f = b\"let secret = 'abc'; // aegis:ignore:hardcoded-password\");\n",
        );
        assert!(manager.is_suppressed("hardcoded-password", 1));
        assert!(!manager.is_suppressed("hardcoded-password\"", 1));
    }

    #[test]
    fn test_midline_hash_directive() {
        let mut manager = SuppressionManager::new();
        manager.parse_content(
            "  uses: actions/upload-artifact@v4 # v4.6.2 # aegis:ignore:executable-file-upload\n",
        );
        assert!(manager.is_suppressed("executable-file-upload", 1));
    }

    #[test]
    fn test_hash_directive_skipped_when_url_fragment() {
        // A `# ...` after `//` is a URL fragment or Rust comment text, not
        // a YAML/shell directive.
        let mut manager = SuppressionManager::new();
        manager.parse_content("let url = \"http://x/# aegis:ignore:eval-usage\";\n");
        assert!(!manager.is_suppressed("eval-usage", 1));
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

    #[test]
    fn test_reason_stored_with_directive() {
        let mut manager = SuppressionManager::new();
        manager.parse_content("// aegis:ignore:hardcoded-secret -- demo fixture\n");
        assert!(manager.is_suppressed("hardcoded-secret", 1));
        assert_eq!(
            manager.reason_for("hardcoded-secret", 1),
            Some("demo fixture".to_string())
        );
        // A different pattern on the same line has no reason.
        assert!(!manager.is_suppressed("other-pattern", 1));
        assert_eq!(manager.reason_for("other-pattern", 1), None);
    }

    #[test]
    fn test_reason_lookup_matches_reasonless_suppression() {
        let mut manager = SuppressionManager::new();
        manager.add(Suppression::new("pat", 3).with_reason("why"));
        // Lookup keys carry no reason; equality must ignore it.
        assert!(manager.is_suppressed("pat", 3));
        assert_eq!(manager.reason_for("pat", 3), Some("why".to_string()));
        manager.remove(&Suppression::new("pat", 3));
        assert!(!manager.is_suppressed("pat", 3));
    }

    #[test]
    fn test_range_suppresses_every_pattern_between_markers() {
        let mut manager = SuppressionManager::new();
        manager.parse_content(
            "line1\n// aegis:ignore-start -- generated block\nline3\nline4\n// aegis:ignore-end\nline6\n",
        );
        assert!(!manager.is_suppressed("any-pattern", 1));
        assert!(manager.is_suppressed("any-pattern", 2));
        assert!(manager.is_suppressed("other-pattern", 3));
        assert!(manager.is_suppressed("third-pattern", 4));
        assert!(manager.is_suppressed("any-pattern", 5));
        assert!(!manager.is_suppressed("any-pattern", 6));
        let ranges = manager.ranges();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, 2);
        assert_eq!(ranges[0].end, Some(5));
        assert_eq!(ranges[0].reason.as_deref(), Some("generated block"));
    }

    #[test]
    fn test_open_range_extends_to_end_of_file() {
        let mut manager = SuppressionManager::new();
        manager.parse_content("// aegis:ignore-start\nline2\nline3\n");
        assert!(manager.is_suppressed("any-pattern", 2));
        assert!(manager.is_suppressed("any-pattern", 3));
        assert_eq!(manager.ranges()[0].end, None);
    }

    #[test]
    fn test_nested_ranges_close_innermost_first() {
        let mut manager = SuppressionManager::new();
        manager.parse_content(
            "// aegis:ignore-start\n// aegis:ignore-start -- inner\n// aegis:ignore-end\nline4\nline5-still-outer\n",
        );
        // The single -end closed the inner range; the outer stays open
        // and keeps suppressing to end of file.
        assert!(manager.is_suppressed("any-pattern", 4));
        assert!(manager.is_suppressed("any-pattern", 5));
        let ranges = manager.ranges();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].end, None, "outer range stays open");
        assert_eq!(ranges[1].end, Some(3));
        assert_eq!(ranges[1].reason.as_deref(), Some("inner"));
    }

    #[test]
    fn test_end_without_open_range_is_noop() {
        let mut manager = SuppressionManager::new();
        manager.parse_content("// aegis:ignore-end\nline2\n");
        assert!(manager.ranges().is_empty());
        assert!(!manager.is_suppressed("any-pattern", 2));
    }

    #[test]
    fn test_file_level_suppression() {
        let mut manager = SuppressionManager::new();
        manager.parse_content("# aegis:ignore-file -- vendored generated code\nsecret at line 2\n");
        assert!(manager.is_file_suppressed());
        assert_eq!(
            manager.file_reason(),
            Some("vendored generated code".to_string())
        );
        assert!(manager.is_suppressed("any-pattern", 2));
        assert!(manager.is_suppressed("other-pattern", 99));
    }

    #[test]
    fn test_file_level_directive_without_reason() {
        let mut manager = SuppressionManager::new();
        manager.parse_content("// aegis:ignore-file\n");
        assert!(manager.is_file_suppressed());
        assert_eq!(manager.file_reason(), None);
    }

    #[test]
    fn test_suppressed_count_tracks_actual_hits() {
        let mut manager = SuppressionManager::new();
        manager.parse_content("// aegis:ignore:pat-a -- counted\n");
        assert_eq!(manager.suppressed_count(), 0);
        assert!(manager.is_suppressed("pat-a", 1));
        assert!(manager.is_suppressed("pat-a", 1));
        assert!(!manager.is_suppressed("pat-b", 1));
        assert_eq!(manager.suppressed_count(), 2);
    }

    #[test]
    fn test_clear_resets_ranges_file_level_and_counter() {
        let mut manager = SuppressionManager::new();
        manager.parse_content("// aegis:ignore-file\n// aegis:ignore-start\n// aegis:ignore:pat\n");
        assert!(manager.is_suppressed("pat", 3));
        manager.clear();
        assert!(!manager.is_file_suppressed());
        assert!(manager.ranges().is_empty());
        assert!(manager.is_empty());
        assert_eq!(manager.suppressed_count(), 0);
        assert!(!manager.is_suppressed("pat", 3));
    }
}
