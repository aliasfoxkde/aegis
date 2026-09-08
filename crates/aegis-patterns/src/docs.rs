//! Generated pattern documentation.
//!
//! The committed docs under `docs/patterns/` are produced by
//! `cargo run -p aegis-patterns --example generate_docs` from these
//! renderers, and a freshness test fails CI if they drift from the source
//! patterns:
//!
//! - [`generate_pattern_index`] renders `docs/patterns/README.md`, the
//!   high-level entry point: what patterns are, how they score, and a
//!   linked table of categories.
//! - [`generate_category_docs`] renders one
//!   `docs/patterns/categories/<category>.md` page per category with a
//!   summary table and a detail section for every pattern, including the
//!   liveness-verified example input (credential-shaped runs elided by
//!   [`redact_token_runs`]) and the raw regex.
//!
//! Generation is deterministic: categories and patterns are emitted in
//! sorted order.

use crate::all_patterns;
use crate::example_for;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Render the high-level pattern index (`docs/patterns/README.md`).
#[must_use]
pub fn generate_pattern_index() -> String {
    let all = all_patterns();
    let by_category = group_by_category(&all);
    let total = all.len();
    let categories = by_category.len();

    let mut out = String::with_capacity(16 * 1024);
    let _ = writeln!(
        out,
        "# Detection Patterns

Aegis ships **{total} detection patterns** across **{categories} categories**.
Every pattern is compiled into every Aegis surface (CLI, MCP server,
daemon, WASM) from the source in `crates/aegis-patterns/src/`.

This index is the entry point; each category has its own page under
[`categories/`](./categories/) with the full detail for every pattern —
regex, scoping, tags, reference links, and a verified example input.

> This documentation is generated from the pattern source. Regenerate
> with `cargo run -p aegis-patterns --example generate_docs`; a freshness
> test (`registry_hygiene.rs`) fails CI when the committed pages drift.

## How a pattern works

Each pattern is a regex plus scoping and scoring metadata:

- **Match** — a Rust `regex`-syntax pattern matched against candidate
  file content (or environment values for `scope: environment` rules).
- **Severity** — `critical` (40 points), `high` (25), `medium` (10), or
  `low` (3) in the risk score; findings also drive the exit code.
- **Confidence** — `high` (×1.0), `medium` (×0.7), or `low` (×0.4)
  multiplier applied to the severity weight.
- **Entropy floor** — optional minimum Shannon entropy a match must
  reach, which filters low-entropy placeholder strings.
- **File extensions** — when set, the pattern only runs on files with a
  listed extension; empty means every text file.
- **Exclude** — an optional regex matched against the candidate match
  span; a hit suppresses the finding (used to exempt documentation
  examples and safe idioms).
- **Scope** — file rules scan content; `scope: environment` rules only
  run during `aegis scan --env`.

Every pattern ships enabled, and every pattern has a provably firing
example enforced by the liveness test (`pattern_liveness.rs` in CI).

## Severity distribution

| Severity | Patterns |
|----------|----------|"
    );

    for severity in ["critical", "high", "medium", "low"] {
        let _ = writeln!(
            out,
            "| {} | {} |",
            severity,
            all.iter().filter(|p| p.severity == severity).count()
        );
    }

    let _ = writeln!(
        out,
        "
## Categories

| Category | Patterns | Description |
|----------|----------|-------------|"
    );

    for (category, patterns) in &by_category {
        let _ = writeln!(
            out,
            "| [{}](./categories/{category}.md) | {} | {} |",
            category,
            patterns.len(),
            category_description(category)
        );
    }

    out
}

/// Render one detail page per category, keyed by category name.
///
/// Each value is the full Markdown for
/// `docs/patterns/categories/<category>.md`: a summary table followed by
/// a detail section for every pattern in the category.
#[must_use]
pub fn generate_category_docs() -> BTreeMap<String, String> {
    let all = all_patterns();
    let by_category = group_by_category(&all);

    by_category
        .into_iter()
        .map(|(category, mut patterns)| {
            patterns.sort_by(|a, b| a.name.cmp(&b.name));
            let document = render_category_page(category, &patterns);
            (category.to_string(), document)
        })
        .collect()
}

fn group_by_category(all: &[crate::Pattern]) -> BTreeMap<&str, Vec<&crate::Pattern>> {
    let mut by_category: BTreeMap<&str, Vec<&crate::Pattern>> = BTreeMap::new();
    for pattern in all {
        by_category
            .entry(pattern.category.as_str())
            .or_default()
            .push(pattern);
    }
    by_category
}

fn render_category_page(category: &str, patterns: &[&crate::Pattern]) -> String {
    let mut out = String::with_capacity(16 * 1024);
    let _ = writeln!(
        out,
        "# {category} patterns

{}

**{} patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|",
        category_description(category),
        patterns.len()
    );
    for pattern in patterns {
        let _ = writeln!(
            out,
            "| [`{}`](#{}) | {} | {} | {} |",
            pattern.name,
            pattern.name,
            pattern.severity,
            pattern.confidence,
            escape_table_cell(&pattern.description)
        );
    }

    out.push_str("\n## Pattern details\n");

    for pattern in patterns {
        let _ = writeln!(
            out,
            "
### {}

{}

| Field | Value |
|-------|-------|
| Severity | `{}` |
| Confidence | `{}` |
| Scope | {} |
| Applies to | {} |
| Binary files | {} |",
            pattern.name,
            escape_table_cell(&pattern.description),
            pattern.severity,
            pattern.confidence,
            if pattern.env_var {
                "`environment` — runs only during `aegis scan --env`"
            } else {
                "`file content`"
            },
            if pattern.file_extensions.is_empty() {
                "every text file".to_string()
            } else {
                format!("`.{}`", pattern.file_extensions.join("`, `."))
            },
            if pattern.binary { "allowed" } else { "skipped" },
        );

        if let Some(entropy) = pattern.min_entropy {
            let _ = writeln!(out, "| Entropy floor | `{entropy}` |");
        }
        if !pattern.tags.is_empty() {
            let _ = writeln!(
                out,
                "| Tags | {} |",
                pattern
                    .tags
                    .iter()
                    .map(|tag| format!("`{tag}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        let _ = writeln!(
            out,
            "
**Match pattern** (Rust `regex` syntax):

{}
",
            fenced_block(&pattern.match_pattern, "regex")
        );

        if let Some(exclude) = &pattern.exclude {
            let _ = writeln!(
                out,
                "**Exclude pattern** — a match span that also matches this
regex is suppressed:

{}",
                fenced_block(exclude, "regex")
            );
        }

        if let Some(reference) = &pattern.reference {
            let _ = writeln!(out, "**Reference**: <{reference}>\n");
        }

        match example_for(&pattern.name) {
            Some(example) => {
                let label = if pattern.env_var {
                    "Environment value that fires"
                } else {
                    "Input that fires"
                };
                match redact_token_runs(example) {
                    Some(redacted) => {
                        let _ = writeln!(
                            out,
                            "**{label}** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

{}",
                            fenced_block(&redacted, "text")
                        );
                    }
                    None => {
                        let _ = writeln!(
                            out,
                            "**{label}** (verified by the liveness test):

{}",
                            fenced_block(example, "text")
                        );
                    }
                }
            }
            None => {
                let _ = writeln!(out, "**Example**: none stored for this pattern.\n");
            }
        }
    }

    out
}

/// Wrap `content` in a fenced code block, growing the fence when the
/// content itself contains backtick runs.
fn fenced_block(content: &str, language: &str) -> String {
    let mut fence_len = 3;
    let mut longest = 0usize;
    for ch in content.chars() {
        if ch == '`' {
            longest += 1;
            fence_len = fence_len.max(longest + 1);
        } else {
            longest = 0;
        }
    }
    let fence: String = "`".repeat(fence_len);
    format!("{fence}{language}\n{content}\n{fence}")
}

/// Pipe characters would break the Markdown table rows.
fn escape_table_cell(text: &str) -> String {
    text.replace('|', "\\|")
}

/// Elide long token-shaped runs in an example before rendering it into
/// the committed docs.
///
/// Several liveness examples are shaped exactly like the real
/// credentials their patterns detect — that is what makes them fire —
/// and `examples.rs` splits those strings with `concat!()` so the
/// repository never contains a contiguous credential-shaped literal.
/// The docs renderer reassembles them, which would re-create exactly the
/// strings GitHub push protection rejects. Keeping the first and last
/// few characters of any run of 13+ token characters preserves the shape
/// a reader needs while leaving nothing contiguous enough to match a
/// provider-credential detector. Returns `None` when nothing was elided.
fn redact_token_runs(example: &str) -> Option<String> {
    const MIN_RUN: usize = 13;
    const KEEP_HEAD: usize = 8;
    const KEEP_TAIL: usize = 2;

    fn token_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || c == '_' || c == '-'
    }

    fn flush_run(out: &mut String, run: &mut String, changed: &mut bool) {
        let len = run.chars().count();
        if len >= MIN_RUN {
            let head: String = run.chars().take(KEEP_HEAD).collect();
            let tail: String = run.chars().skip(len - KEEP_TAIL).collect();
            out.push_str(&head);
            out.push('…');
            out.push_str(&tail);
            *changed = true;
        } else {
            out.push_str(run);
        }
        run.clear();
    }

    let mut out = String::with_capacity(example.len());
    let mut changed = false;
    let mut run = String::new();
    for ch in example.chars() {
        if token_char(ch) {
            run.push(ch);
        } else {
            flush_run(&mut out, &mut run, &mut changed);
            out.push(ch);
        }
    }
    flush_run(&mut out, &mut run, &mut changed);
    changed.then_some(out)
}

/// Short human-readable blurbs for the category table.
fn category_description(category: &str) -> &'static str {
    match category {
        "accessibility" => "WCAG 2.x success criteria for markup, media, and styles",
        "ai-detection" => {
            "Informative markers of likely AI-generated code — triage signals, not verdicts"
        }
        "ai-safety" => "Agentic and LLM application safety checks",
        "api-integration" => "HTTP client and webhook integration mistakes",
        "arm" => "Azure Resource Manager template issues",
        "cloud-native" => "Cloud-native build and runtime practices",
        "cloudformation" => "AWS CloudFormation template issues",
        "code-quality" => "Language anti-patterns and dangerous constructs",
        "compliance" => "Regulatory frameworks: GDPR, HIPAA, PCI-DSS, SOC 2",
        "container" => "Container build and runtime hardening",
        "data-visualization" => "Charting and visualization pitfalls",
        "devops" => "CI/CD pipeline and deployment checks",
        "finance" => "Financial data handling rules",
        "frameworks" => "Web framework-specific issues",
        "git-hygiene" => "Repository hygiene: artifacts, debug files, history",
        "git-ops" => "GitOps workflow and manifest checks",
        "graphql" => "GraphQL API security and usage",
        "healthcare" => "Clinical data and HIPAA-adjacent rules",
        "infrastructure" => "Infrastructure as code security",
        "kubernetes" => "Kubernetes manifest hardening",
        "llm-guardrails" => "Prompt-injection and LLM guardrail checks",
        "metadata" => "Metadata and editor configuration leaks",
        "performance" => "Performance anti-patterns",
        "pii" => "Personal data: emails, phones, national IDs",
        "pwa" => "Progressive web app checks",
        "secrets" => "Credentials, API keys, and tokens",
        "security-hardening" => "General hardening practices",
        "shift-left" => "Early-lifecycle security practices",
        "supply-chain" => "Dependency and artifact supply-chain rules",
        "terraform" => "HashiCorp Terraform issues",
        "typescript" => "TypeScript and typed-JavaScript rules",
        "web-development" => "General web development checks",
        "web-security" => "XSS, injection, CORS, and SSRF",
        _ => "Detection patterns",
    }
}

#[cfg(test)]
mod tests {
    use super::redact_token_runs;

    #[test]
    fn long_token_runs_are_elided() {
        // 26 contiguous token characters — shaped like a real GitLab PAT,
        // which is why the liveness example fires. Split with concat!()
        // (the examples.rs convention) so the source file itself never
        // contains a credential-shaped literal either.
        let sample = concat!("glpat-YH6PpZhg", "TWozFM4DBYqA");
        let redacted = redact_token_runs(sample).expect("26-char run must be elided");
        assert_eq!(redacted, "glpat-YH…qA");
        // Nothing contiguous remains for a credential detector to match.
        assert!(!redacted.contains("YH6PpZ"));
        assert!(!redacted.contains("WozFM4"));
    }

    #[test]
    fn short_runs_pass_through_verbatim() {
        let example = "routing_ -_ -- _no: =:= : = 735982468";
        assert_eq!(redact_token_runs(example), None);
    }

    #[test]
    fn only_long_runs_change_and_punctuation_survives() {
        let example = "token=abcdefghijklmnop; count=12";
        let redacted = redact_token_runs(example).expect("16-char run must be elided");
        assert_eq!(redacted, "token=abcdefgh…op; count=12");
    }

    #[test]
    fn elision_leaves_no_contiguous_run_long_enough_to_redact_again() {
        // Idempotence matters: whatever the renderer emits must itself be
        // push-protection safe, so every surviving run stays under the
        // threshold that triggered redaction.
        for pattern in crate::all_patterns() {
            if let Some(example) = crate::example_for(&pattern.name) {
                if let Some(redacted) = redact_token_runs(example) {
                    assert_eq!(
                        redact_token_runs(&redacted),
                        None,
                        "pattern {}: redaction is not stable",
                        pattern.name
                    );
                }
            }
        }
    }
}
