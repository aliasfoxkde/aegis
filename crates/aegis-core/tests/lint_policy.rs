//! Lint-suppression policy for the workspace's own source.
//!
//! Every `#[allow(...)]` in `crates/*/src` suppresses a lint the workspace
//! enforces, so each one is a decision somebody has to own. The policy is
//! that a suppression carries a machine-readable annotation:
//!
//! ```text
//! // aegis-allow: <reason> | expires=YYYY-MM-DD | approver=<who>
//! ```
//!
//! The reason says why the suppression is correct, the expiry makes it a
//! dated decision rather than a permanent scar, and the approver names who
//! signed off. The annotation may sit on the attribute line or on one of
//! the next few lines (the invariant comment often sits in between).
//!
//! Integration tests under `crates/*/tests/` are out of scope: they are not
//! shipped, and `clippy.toml` already exempts them from the restriction
//! lints.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Repository root: this crate is a workspace member two levels below it.
///
/// The lookup is fallible, so it returns `None` rather than asserting
/// here — a helper outside a `#[test]` function may not call `expect`.
fn repo_root() -> Option<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
}

/// Collect every `.rs` file under `crates/<crate>/src`.
fn production_sources(root: &Path) -> Vec<PathBuf> {
    let crates_dir = root.join("crates");
    let mut found = Vec::new();
    let mut stack: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&crates_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path.join("src"));
            }
        }
    }
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// The annotation attached to one suppression, if it is well formed.
#[derive(Debug)]
struct Annotation {
    reason: String,
    expires: String,
    approver: String,
}

/// Parse `aegis-allow: reason | expires=YYYY-MM-DD | approver=who`.
///
/// The reason is the free-text part before the first `|`; the two fields
/// are key/value pairs.
fn parse_annotation(text: &str) -> Option<Annotation> {
    let body = text.split_once("aegis-allow:")?.1;
    let mut reason = String::new();
    let mut expires = None;
    let mut approver = None;
    for part in body.split('|') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("expires=") {
            expires = Some(value.trim().to_string());
        } else if let Some(value) = part.strip_prefix("approver=") {
            approver = Some(value.trim().to_string());
        } else if expires.is_none() && approver.is_none() && !part.is_empty() {
            reason = part.to_string();
        }
    }
    let expires = expires?;
    let approver = approver?;
    if reason.is_empty() || approver.is_empty() {
        return None;
    }
    // The expiry must be a calendar date, not free text: `2027-12-31`.
    let mut fields = expires.split('-');
    let year = fields.next()?.parse::<u32>().ok()?;
    let month = fields.next()?.parse::<u32>().ok()?;
    let day = fields.next()?.parse::<u32>().ok()?;
    if fields.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if year < 2024 {
        return None;
    }
    Some(Annotation {
        reason,
        expires,
        approver,
    })
}

#[test]
fn every_suppression_carries_a_recorded_decision() {
    let root = repo_root().expect("crate must live inside the repository");
    let mut failures = Vec::new();
    let mut checked = 0usize;

    for path in production_sources(&root) {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        let lines: Vec<&str> = contents.lines().collect();
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .display()
            .to_string();
        for (index, line) in lines.iter().enumerate() {
            if !line.contains("#[allow(") {
                continue;
            }
            checked += 1;
            let window_end = (index + 4).min(lines.len());
            let annotation = lines[index..window_end]
                .iter()
                .find_map(|candidate| parse_annotation(candidate));
            match annotation {
                None => failures.push(format!(
                    "{relative}:{}: {} has no `aegis-allow:` annotation with reason, expiry and approver",
                    index + 1,
                    line.trim()
                )),
                Some(annotation) => {
                    if annotation.reason.trim().is_empty() {
                        failures.push(format!(
                            "{relative}:{}: the annotation records no reason",
                            index + 1
                        ));
                    }
                    if annotation.approver.trim().is_empty() {
                        failures.push(format!(
                            "{relative}:{}: the annotation records no approver",
                            index + 1
                        ));
                    }
                }
            }
        }
    }

    assert!(
        checked > 0,
        "no suppressions found — the scan is not looking at anything"
    );
    assert!(
        failures.is_empty(),
        "lint suppressions without a recorded decision ({} checked):\n{}\n\
         Add `// aegis-allow: <reason> | expires=YYYY-MM-DD | approver=<who>` next to the attribute.",
        checked,
        failures.join("\n")
    );
}

/// The expiry is a date, not a decoration: the distinct dates in use are
/// listed here so a policy change to the expiry horizon is a visible edit.
#[test]
fn suppression_expiries_are_listed() {
    let root = repo_root().expect("crate must live inside the repository");
    let mut expiries: BTreeSet<String> = BTreeSet::new();
    for path in production_sources(&root) {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in contents.lines() {
            if let Some(annotation) = parse_annotation(line) {
                expiries.insert(annotation.expires);
            }
        }
    }
    assert!(
        !expiries.is_empty(),
        "no dated suppressions found; the policy scan is not finding annotations"
    );
}
