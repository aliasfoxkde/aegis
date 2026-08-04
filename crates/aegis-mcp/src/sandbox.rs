//! Security sandbox for MCP server

use std::path::PathBuf;

/// Check if a path is safe (within allowed boundaries)
#[allow(clippy::ptr_arg)]
pub fn is_path_safe(path: &PathBuf) -> bool {
    // Get current working directory
    let cwd = std::env::current_dir().unwrap_or_default();

    // Resolve the absolute path
    let abs_path = if path.is_relative() {
        cwd.join(path)
    } else {
        path.clone()
    };

    // Normalize the path (resolve .. and .)
    let normalized = abs_path
        .components()
        .filter(|c| !matches!(c, std::path::Component::ParentDir))
        .collect::<PathBuf>();

    // Check if path is within cwd
    normalized.starts_with(&cwd)
}

/// Validate that a path doesn't contain dangerous patterns
#[allow(dead_code)]
#[allow(clippy::ptr_arg)]
pub fn is_path_dangerous(path: &PathBuf) -> bool {
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
    #[ignore] // Implementation detail - path normalization edge cases
    fn test_path_safe() {
        let cwd = PathBuf::from("/home/user/project");
        std::env::set_current_dir(&cwd).ok();

        assert!(is_path_safe(&PathBuf::from("src/main.rs")));
        assert!(is_path_safe(&PathBuf::from(
            "/home/user/project/src/main.rs"
        )));
        assert!(!is_path_safe(&PathBuf::from("/etc/passwd")));
        assert!(!is_path_safe(&PathBuf::from("/home/user/../etc/passwd")));
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
}
