//! Path classification: documentation and test-fixture paths.
//!
//! A repository that ships mostly documentation and fixtures produces
//! findings that are true of the text and irrelevant to the risk: prose
//! that mentions a credential-shaped string is not a credential, and a
//! test fixture that hard-codes an example token is not a leak.
//!
//! A *path class* names that difference. A rule maps a glob to a class,
//! and findings below a classified path are reported at low severity so
//! they stop competing with real signals. The class is also recorded as a
//! tag on the finding, so a report can still show where the finding came
//! from and why it was downgraded.
//!
//! Secret findings are never downgraded by a path class: a credential in
//! a documentation file is still a credential, and hiding it would be the
//! one mistake this feature must not make. Those findings keep their
//! severity and carry the class tag.
//!
//! ## How a path is matched
//!
//! A rule is matched against the path relative to the scan root when the
//! root is known, and against the path as written otherwise. A directory
//! rule matches at any depth: `docs/**` covers `docs/setup.md` and
//! `crates/docs/setup.md` alike, because the path is also tried with
//! leading components removed at every directory boundary. A rule without
//! a separator (`*.md`) matches the file name.

use crate::config::{PathClass, PathClassRule};
use crate::finding::Finding;
use crate::secret_triage::SECRET_CATEGORY;
use glob::{MatchOptions, Pattern};

/// One compiled path-class rule.
#[derive(Debug)]
struct CompiledRule {
    /// The glob, compiled. An invalid glob is skipped, not fatal.
    pattern: Pattern,
    /// The class the rule assigns.
    class: PathClass,
}

/// Matches paths against the configured path classes.
#[derive(Debug, Default)]
pub struct PathClassMatcher {
    rules: Vec<CompiledRule>,
}

impl PathClassMatcher {
    /// Compile the configured rules.
    ///
    /// A glob that does not compile is skipped with a warning: one broken
    /// rule must not take the whole scan down, and the warning says which
    /// rule was ignored.
    #[must_use]
    pub fn new(rules: &[PathClassRule]) -> Self {
        let compiled = rules
            .iter()
            .filter_map(|rule| match Pattern::new(&rule.glob) {
                Ok(pattern) => Some(CompiledRule {
                    pattern,
                    class: rule.class,
                }),
                Err(error) => {
                    tracing::warn!("ignoring path class rule `{}`: {error}", rule.glob);
                    None
                }
            })
            .collect();
        Self { rules: compiled }
    }

    /// Whether any rule is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The class of a path, if a rule matches it.
    ///
    /// `path` is the path as written; `relative` is the same path relative
    /// to the scan root, when the root is known.
    #[must_use]
    pub fn class_of(&self, path: &str, relative: Option<&str>) -> Option<PathClass> {
        if self.rules.is_empty() {
            return None;
        }
        let normalized = path.strip_prefix("./").unwrap_or(path);
        let base = relative
            .map(|relative| relative.strip_prefix("./").unwrap_or(relative))
            .unwrap_or(normalized);

        let mut candidates: Vec<&str> = Vec::new();
        candidates.push(base);
        candidates.extend(suffixes_at_directory_boundaries(base));
        if let Some(name) = base.rsplit('/').next() {
            candidates.push(name);
        }

        for rule in &self.rules {
            for candidate in &candidates {
                if rule.pattern.matches_with(candidate, MATCH_OPTIONS) {
                    return Some(rule.class);
                }
            }
        }
        None
    }
}

/// The path with leading components removed at every directory boundary.
///
/// `a/b/c.md` yields `a/b/c.md`, `b/c.md`, and `c.md`. A directory rule
/// therefore matches at any depth, while `b/c.md` cannot match inside
/// `xb/c.md`: the removal happens at boundaries, not inside a name.
fn suffixes_at_directory_boundaries(path: &str) -> impl Iterator<Item = &str> {
    path.match_indices('/').map(|(index, _)| &path[index + 1..])
}

/// Apply a path class to a finding.
///
/// The class is recorded as a tag so a report says *why* a finding is
/// reported the way it is.
///
/// Secret findings keep their severity: a credential in a documentation
/// file is still a credential, and downgrading it would hide exactly the
/// finding the class was meant to quieten. They carry the class tag so a
/// report can still show where they came from.
pub fn apply_path_class(finding: &mut Finding, class: PathClass) {
    finding.add_tag(class.tag());
    if finding.category == SECRET_CATEGORY {
        return;
    }
    finding.downgrade_to_low();
}

/// The options every rule is matched with.
///
/// `*` stays inside one path component and `**` still spans components, so
/// `docs/**` covers everything below `docs/` while `*.md` does not reach
/// across a separator.
const MATCH_OPTIONS: MatchOptions = MatchOptions {
    case_sensitive: true,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(glob: &str, class: PathClass) -> PathClassRule {
        PathClassRule {
            glob: glob.to_string(),
            class,
        }
    }

    #[test]
    fn a_directory_glob_covers_everything_below_it() {
        let matcher = PathClassMatcher::new(&[rule("docs/**", PathClass::Docs)]);
        assert_eq!(
            matcher.class_of("docs/intro.md", None),
            Some(PathClass::Docs)
        );
        assert_eq!(
            matcher.class_of("docs/guides/deep/setup.md", None),
            Some(PathClass::Docs)
        );
        assert_eq!(matcher.class_of("src/main.rs", None), None);
    }

    #[test]
    fn a_leading_recursive_glob_covers_nested_directories() {
        let matcher = PathClassMatcher::new(&[rule("**/tests/**", PathClass::Fixture)]);
        assert_eq!(
            matcher.class_of("crates/aegis-core/tests/scanner.rs", None),
            Some(PathClass::Fixture)
        );
        assert_eq!(matcher.class_of("src/main.rs", None), None);
    }

    #[test]
    fn a_glob_without_a_separator_matches_the_file_name() {
        let matcher = PathClassMatcher::new(&[rule("*.md", PathClass::Docs)]);
        assert_eq!(
            matcher.class_of("docs/guides/setup.md", None),
            Some(PathClass::Docs)
        );
        assert_eq!(matcher.class_of("src/main.rs", None), None);
    }

    #[test]
    fn the_relative_path_is_matched_before_the_absolute_one() {
        let matcher = PathClassMatcher::new(&[rule("docs/**", PathClass::Docs)]);
        assert_eq!(
            matcher.class_of("/home/dev/repo/docs/intro.md", Some("docs/intro.md")),
            Some(PathClass::Docs)
        );
    }

    #[test]
    fn a_directory_glob_matches_at_any_depth() {
        let matcher = PathClassMatcher::new(&[rule("docs/**", PathClass::Docs)]);
        assert_eq!(
            matcher.class_of("crates/tool/docs/intro.md", None),
            Some(PathClass::Docs)
        );
    }

    #[test]
    fn a_directory_glob_does_not_match_inside_a_longer_name() {
        let matcher = PathClassMatcher::new(&[rule("docs/**", PathClass::Docs)]);
        assert_eq!(matcher.class_of("src/xdocs/intro.md", None), None);
    }

    #[test]
    fn an_invalid_glob_is_skipped_without_failing_the_matcher() {
        let matcher = PathClassMatcher::new(&[
            rule("a/**b", PathClass::Docs),
            rule("src/**", PathClass::Fixture),
        ]);
        assert_eq!(
            matcher.class_of("src/main.rs", None),
            Some(PathClass::Fixture)
        );
    }

    #[test]
    fn an_empty_matcher_classifies_nothing() {
        let matcher = PathClassMatcher::new(&[]);
        assert!(matcher.is_empty());
        assert_eq!(matcher.class_of("src/main.rs", None), None);
    }
}
