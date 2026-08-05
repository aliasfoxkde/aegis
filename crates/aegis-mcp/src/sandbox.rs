//! Security sandbox for MCP server

use std::path::{Path, PathBuf};

/// Check if a path is safe (within allowed boundaries)
pub fn is_path_safe(path: &PathBuf) -> bool {
    // Get current working directory and resolve it to an absolute, canonical path
    let cwd = match std::env::current_dir() {
        Ok(c) => c,
        Err(_) => return false,
    };

    let cwd = match cwd.canonicalize() {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Resolve the input path to an absolute path
    let abs_path = if path.is_relative() {
        cwd.join(path)
    } else {
        path.clone()
    };

    // Canonicalize the absolute path to resolve symlinks and .. components
    let abs_path = match abs_path.canonicalize() {
        Ok(p) => p,
        // If the path doesn't exist, check if normalized path would be within cwd
        Err(_) => {
            let normalized = normalize_path(&abs_path);
            return normalized.starts_with(&cwd);
        }
    };

    // Check if the canonical path starts with cwd
    abs_path.starts_with(&cwd)
}

/// Normalize a path without requiring it to exist
#[allow(clippy::ptr_arg)]
fn normalize_path(path: &PathBuf) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                result.pop();
            }
            std::path::Component::Normal(s) => {
                result.push(s);
            }
            std::path::Component::RootDir => {
                result = PathBuf::from("/");
            }
            std::path::Component::Prefix(p) => {
                result.push(p.as_os_str());
            }
            std::path::Component::CurDir => {}
        }
    }
    result
}

/// Validate that a path doesn't contain dangerous patterns
#[allow(dead_code)]
pub fn is_path_dangerous(path: &Path) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();

    // Check for dangerous patterns
    let dangerous = [
        "/etc/passwd",
        "/etc/shadow",
        "/.ssh/",
        "/.aws/",
        "/proc/",
        "/sys/",
        "/dev/",
    ];

    for pattern in dangerous {
        if path_str.contains(pattern) {
            return true;
        }
    }

    false
}

/// Get the sandboxed root directory
#[allow(dead_code)]
pub fn get_sandbox_root() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_safe_relative_src() {
        // Use a path that actually exists relative to cwd
        let cwd = std::env::current_dir().unwrap();
        let test_path = cwd.join("src");
        assert!(is_path_safe(&test_path), "src dir should be safe");
    }

    #[test]
    fn test_path_safe_absolute_outside() {
        // /etc should never be accessible
        assert!(!is_path_safe(&PathBuf::from("/etc/passwd")));
    }

    #[test]
    fn test_path_safe_parent_traversal() {
        // /tmp/.. should eventually not be safe if /home is cwd
        let cwd = std::env::current_dir().unwrap();
        if cwd.starts_with("/home") {
            let malicious = cwd.join("..").join("etc").join("passwd");
            assert!(!is_path_safe(&malicious));
        }
    }

    #[test]
    fn test_dangerous_paths() {
        assert!(is_path_dangerous(&PathBuf::from("/etc/passwd")));
        assert!(is_path_dangerous(&PathBuf::from("/.ssh/id_rsa")));
        assert!(is_path_dangerous(&PathBuf::from("/proc/self/environ")));
        assert!(!is_path_dangerous(&PathBuf::from(
            "/home/user/project/src/main.rs"
        )));
    }

    #[test]
    fn test_normalize_path_parent() {
        let path = PathBuf::from("/home/user/project/../etc/passwd");
        let normalized = normalize_path(&path);
        assert_eq!(normalized, PathBuf::from("/home/user/etc/passwd"));
    }

    #[test]
    fn test_normalize_path_cur_dir() {
        let path = PathBuf::from("/home/user/./project/./file");
        let normalized = normalize_path(&path);
        assert_eq!(normalized, PathBuf::from("/home/user/project/file"));
    }
}
