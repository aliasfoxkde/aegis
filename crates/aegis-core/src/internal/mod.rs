//! Internal implementation details
//!
//! This module contains internal helpers and utilities that are not part of
//! the public API. These may change at any time without notice.
//!
//! # Visibility Rules
//!
//! Items in this module are not documented as part of the public API and
//! should not be relied upon by external code.

use std::path::Path;

/// Check if a path should be ignored based on size limits
pub fn check_file_size_limit(path: &Path, max_size_bytes: u64) -> bool {
    match std::fs::metadata(path) {
        Ok(metadata) => metadata.len() <= max_size_bytes,
        Err(_) => false, // Can't read metadata, assume we should skip
    }
}

/// Calculate a simple hash for deduplication
pub fn simple_hash(content: &[u8]) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    hasher.finish()
}

/// Normalize a severity string to lowercase
pub fn normalize_severity(severity: &str) -> String {
    severity.to_lowercase()
}

/// Check if a string looks like a secret (high entropy)
#[allow(dead_code)]
pub fn looks_like_secret(content: &str) -> bool {
    let entropy = crate::entropy::shannon_entropy(content);
    entropy > 4.0 && content.len() >= 8
}

/// Format bytes as human-readable string
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format duration as human-readable string
pub fn format_duration_ms(ms: u64) -> String {
    if ms >= 1000 {
        format!("{:.2}s", ms as f64 / 1000.0)
    } else {
        format!("{}ms", ms)
    }
}

/// Trim string to max length with ellipsis
pub fn trim_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len > 3 {
        format!("{}...", &s[..max_len - 3])
    } else {
        s[..max_len].to_string()
    }
}

/// Check if a line is likely a comment
pub fn is_comment_line(line: &str, language: &str) -> bool {
    let trimmed = line.trim();
    match language {
        "rust" | "go" | "java" | "javascript" | "typescript" | "c" | "cpp" => {
            trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with("*")
        }
        "python" | "ruby" => trimmed.starts_with('#') || trimmed.starts_with("\"\"\""),
        _ => trimmed.starts_with('#') || trimmed.starts_with("//"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration_ms(500), "500ms");
        assert_eq!(format_duration_ms(1500), "1.50s");
    }

    #[test]
    fn test_trim_string() {
        assert_eq!(trim_string("hello", 10), "hello");
        assert_eq!(trim_string("hello world", 8), "hello...");
        assert_eq!(trim_string("hello", 3), "hel");
    }

    #[test]
    fn test_normalize_severity() {
        assert_eq!(normalize_severity("HIGH"), "high");
        assert_eq!(normalize_severity("Medium"), "medium");
        assert_eq!(normalize_severity("CRITICAL"), "critical");
    }

    #[test]
    fn test_is_comment_line() {
        // Rust/Go/JavaScript style
        assert!(is_comment_line("// comment", "rust"));
        assert!(is_comment_line("/* comment */", "rust"));
        assert!(!is_comment_line("let x = 1;", "rust"));

        // Python style
        assert!(is_comment_line("# comment", "python"));
        assert!(is_comment_line("\"\"\" docstring \"\"\"", "python"));
    }
}
