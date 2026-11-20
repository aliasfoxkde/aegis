//! Security sandbox for MCP server

use std::path::{Path, PathBuf};

/// Check if a path is safe (within allowed boundaries).
///
/// A path is admitted only when one of two conditions holds:
///
/// 1. It `canonicalize`s to a location inside the canonicalized working
///    directory. Symlinks and `..` chains are fully resolved first, so a
///    path that resolves to an existing file or directory outside the
///    working directory is rejected no matter how it is spelled.
/// 2. `canonicalize` fails and its lexically normalized spelling stays
///    inside the working directory (the [`lexical_contains`] fallback).
///    That failure is not limited to a nonexistent final component:
///    unreadable components (`EACCES`), symlink cycles (`ELOOP`),
///    non-directory components (`ENOTDIR`), and overlong names all fail
///    the same way. What those cases share is that the path cannot be
///    resolved at all, so nothing can be read through it at check time;
///    containment rests on the spelling, and a read of that same spelling
///    either stays inside the working directory or fails to resolve for
///    the same reason.
pub fn is_path_safe(path: &PathBuf) -> bool {
    // Get current working directory and resolve it to an absolute, canonical path
    let Ok(cwd) = std::env::current_dir() else {
        return false;
    };

    let Ok(cwd) = cwd.canonicalize() else {
        return false;
    };

    // Resolve the input path to an absolute path
    let abs_path = if path.is_relative() {
        cwd.join(path)
    } else {
        path.clone()
    };

    // Canonicalize the absolute path to resolve symlinks and .. components.
    // If the path doesn't exist, check if normalized path would be within cwd
    let Ok(abs_path) = abs_path.canonicalize() else {
        return lexical_contains(&cwd, &abs_path);
    };

    // Check if the canonical path starts with cwd
    abs_path.starts_with(&cwd)
}

/// Report whether `candidate` sits at or below `root`, resolved lexically.
///
/// Used when the candidate cannot be canonicalized at all — most often
/// because it does not exist, but any other resolution failure (unreadable
/// component, symlink cycle, non-directory component) lands here too.
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
        // A nonexistent path that would land inside cwd is allowed so the
        // scan, not the sandbox, reports it: a missing file surfaces as an
        // InternalError carrying the not-found I/O message, never as the
        // sandbox violation (InvalidParams).
        let cwd = std::env::current_dir().unwrap();
        let safe_nonexistent = cwd.join("this-does-not-exist").join("file.txt");
        assert!(is_path_safe(&safe_nonexistent));

        let outside = cwd.join("..").join("outside-aegis.txt");
        if !outside.canonicalize().is_ok_and(|p| p.starts_with(&cwd)) {
            assert!(!is_path_safe(&outside));
        }
    }

    #[cfg(unix)]
    #[test]
    fn is_path_safe_rejects_symlinked_targets_outside_cwd() {
        // The load-bearing invariant: any path that resolves to an EXISTING
        // file outside the working directory is refused, no matter how the
        // indirection is spelled. `canonicalize` resolves the full symlink
        // chain, so the containment check sees the real location.
        let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
        // Both fixtures are TempDir-owned and uniquely named per run: the
        // symlinks must sit inside cwd for containment to apply, and the
        // probed target must sit outside it — the parent of cwd is the
        // nearest such spot. RAII removes only these run-owned directories,
        // so nothing shared or fixed is ever written or deleted.
        let outside_dir = tempfile::tempdir_in(cwd.parent().unwrap()).unwrap();
        std::fs::create_dir_all(outside_dir.path().join("sub")).unwrap();
        std::fs::write(outside_dir.path().join("target.txt"), "probe fixture").unwrap();

        let fixture = tempfile::tempdir_in(&cwd).unwrap();
        let link_dir = fixture.path().join("link-dir");
        let link_file = fixture.path().join("link-file");
        std::os::unix::fs::symlink(outside_dir.path(), &link_dir).unwrap();
        std::os::unix::fs::symlink(outside_dir.path().join("target.txt"), &link_file).unwrap();

        // Symlink file pointing directly at an existing outside file.
        assert!(!is_path_safe(&link_file));
        // Symlink directory pointing at an existing outside directory.
        assert!(!is_path_safe(&link_dir));
        // Existing outside file reached through the symlinked directory,
        // both plainly and via `..` that stays inside the symlink target.
        assert!(!is_path_safe(&link_dir.join("target.txt")));
        assert!(!is_path_safe(
            &link_dir.join("sub").join("..").join("target.txt")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn is_path_safe_absent_target_through_symlink_cannot_read_outside() {
        // A symlinked directory plus a NONEXISTENT final component cannot be
        // canonicalized, so the lexical fallback judges the spelling. The
        // spelling is inside cwd, the path is allowed — but only because
        // nothing exists to read there; the scan then fails with
        // InternalError (the underlying not-found I/O error), not
        // InvalidParams. (The existing-target variants of the same shapes
        // are refused by is_path_safe_rejects_symlinked_targets_outside_cwd.)
        let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
        let outside_dir = tempfile::tempdir_in(cwd.parent().unwrap()).unwrap();

        let fixture = tempfile::tempdir_in(&cwd).unwrap();
        let link_dir = fixture.path().join("link-dir");
        std::os::unix::fs::symlink(outside_dir.path(), &link_dir).unwrap();

        let absent_through_link = link_dir.join("absent.txt");
        assert!(!absent_through_link.exists());
        assert!(is_path_safe(&absent_through_link));
    }

    #[test]
    fn is_path_safe_rejects_absent_traversals_that_escape_cwd() {
        // Missing targets are judged on their normalized spelling: a `..`
        // chain that escapes cwd is refused even though nothing exists at
        // the end, and a sibling sharing cwd's name prefix is not cwd.
        let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
        if let Some(parent) = cwd.parent() {
            let absent_outside = parent.join("aegis-absent-outside-probe.txt");
            if absent_outside.canonicalize().is_err() {
                assert!(!is_path_safe(&absent_outside));
            }
        }

        let cwd_name = cwd
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let sibling = cwd
            .parent()
            .map(|p| p.join(format!("{cwd_name}-absent-sibling")))
            .filter(|p| p.canonicalize().is_err());
        if let Some(sibling) = sibling {
            assert!(!is_path_safe(&sibling.join("x.txt")));
        }
    }

    #[test]
    fn lexical_contains_rejects_rooted_drive_traversal() {
        // Backslash-separated `..` must participate in normalization on
        // Windows forms: a traversal that survives inside the drive must
        // stay contained, and one that overflows the drive root must not
        // sneak back under the root.
        let root = Path::new(r"C:\repo");
        assert!(lexical_contains(
            root,
            Path::new(r"C:\repo\sub\..\file.txt")
        ));
        assert!(!lexical_contains(
            root,
            Path::new(r"C:\repo\..\..\secret.txt")
        ));
        assert!(!lexical_contains(root, Path::new(r"C:\repo\..\other")));
    }
}
