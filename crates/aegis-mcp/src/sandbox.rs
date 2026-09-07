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
            return lexical_contains(&cwd, &abs_path);
        }
    };

    // Check if the canonical path starts with cwd
    abs_path.starts_with(&cwd)
}

/// Report whether `candidate` sits at or below `root`, resolved lexically.
///
/// Used when the candidate cannot be canonicalized (it does not exist yet).
/// Both sides are compared as forward-slash component stacks so the check
/// keeps working on Windows, where `canonicalize` yields verbatim
/// (`\\?\C:\...`) paths while joined user input stays plain (`C:\...`) and
/// `Path::starts_with` would therefore never match.
fn lexical_contains(root: &Path, candidate: &Path) -> bool {
    let normalize = |path: &Path| -> String {
        let text = path.to_string_lossy().replace('\\', "/");
        let text = text.strip_prefix("//?/").unwrap_or(&text);
        let mut stack: Vec<&str> = Vec::new();
        for part in text.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    stack.pop();
                }
                other => stack.push(other),
            }
        }
        stack.join("/")
    };
    let (root, candidate) = (normalize(root), normalize(candidate));
    candidate == root || candidate.starts_with(&format!("{root}/"))
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
    fn lexical_contains_resolves_parent_and_current_components() {
        let root = Path::new("/home/user/project");
        assert!(lexical_contains(
            root,
            Path::new("/home/user/project/../project/./sub/file")
        ));
        assert!(!lexical_contains(
            root,
            Path::new("/home/user/project/../etc/passwd")
        ));
        assert!(lexical_contains(root, Path::new("/home/user/project")));
        assert!(!lexical_contains(root, Path::new("")));
    }

    #[test]
    fn lexical_contains_survives_windows_verbatim_roots() {
        // Windows `canonicalize` returns `\\?\C:\...` while joined user input
        // stays plain `C:\...`; containment must hold across the two forms.
        let root = Path::new(r"\\?\C:\nas\Temp\repos\aegis");
        assert!(lexical_contains(
            root,
            Path::new(r"C:\nas\Temp\repos\aegis\temp\absent.txt")
        ));
        assert!(!lexical_contains(
            root,
            Path::new(r"C:\nas\Temp\repos\other\absent.txt")
        ));
        // A traversal that escapes the drive root must not sneak back in.
        assert!(!lexical_contains(
            root,
            Path::new(r"C:\nas\Temp\repos\aegis\..\..\secrets")
        ));
    }

    #[test]
    fn is_path_safe_accepts_nonexistent_paths_inside_cwd() {
        // A nonexistent path that would land inside cwd is allowed so scans
        // can reject it with a clean "not found" error instead of a sandbox
        // violation.
        let cwd = std::env::current_dir().unwrap();
        let safe_nonexistent = cwd.join("this-does-not-exist").join("file.txt");
        assert!(is_path_safe(&safe_nonexistent));

        let outside = cwd.join("..").join("outside-aegis.txt");
        if !outside
            .canonicalize()
            .map(|p| p.starts_with(&cwd))
            .unwrap_or(false)
        {
            assert!(!is_path_safe(&outside));
        }
    }

    #[test]
    fn test_is_path_dangerous_sys() {
        assert!(is_path_dangerous(&PathBuf::from("/sys/kernel")));
    }

    #[test]
    fn test_is_path_dangerous_dev() {
        assert!(is_path_dangerous(&PathBuf::from("/dev/null")));
    }

    #[test]
    fn test_is_path_dangerous_aws() {
        assert!(is_path_dangerous(&PathBuf::from("/.aws/credentials")));
    }

    #[test]
    fn test_get_sandbox_root() {
        let root = get_sandbox_root();
        assert!(root.is_absolute() || root.to_string_lossy() == "/");
    }
}
