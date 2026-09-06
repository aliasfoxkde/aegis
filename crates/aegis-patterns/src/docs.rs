//! Generated pattern documentation.
//!
//! `generate_pattern_docs()` renders the shipped corpus to Markdown. The
//! committed `docs/patterns/README.md` is produced by
//! `cargo run -p aegis-patterns --example generate_docs`, and a freshness
//! test fails CI if the docs drift from the source patterns. Generation is
//! deterministic: categories and patterns are emitted in sorted order.

use crate::all_patterns;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Render the full pattern catalog as Markdown.
pub fn generate_pattern_docs() -> String {
    // BTreeMap keeps category order stable across runs.
    let mut by_category: BTreeMap<&str, Vec<&crate::Pattern>> = BTreeMap::new();
    let all = all_patterns();
    for pattern in &all {
        by_category
            .entry(pattern.category.as_str())
            .or_default()
            .push(pattern);
    }

    let total = all.len();
    let categories = by_category.len();

    let mut out = String::with_capacity(64 * 1024);
    let _ = writeln!(
        out,
        "# Detection Patterns

Aegis ships **{total} detection patterns** across **{categories} categories**.
This document is generated from the pattern source in
`crates/aegis-patterns/src/`; regenerate with:

```bash
cargo run -p aegis-patterns --example generate_docs
```

A freshness test (`registry_hygiene.rs`) fails CI when this file drifts
from the shipped patterns.

## Pattern Selection

Each pattern can carry two optional scoping fields:

- `exclude` — a regex matched against the finding's text; a hit suppresses
  the finding (used to exempt documentation examples and safe idioms).
- `file_extensions` — the pattern only runs on files with a listed
  extension. An empty list means the pattern applies everywhere.

## Categories

| Category | Patterns | Description |
|----------|----------|-------------|
"
    );

    for (category, patterns) in &by_category {
        let _ = writeln!(
            out,
            "| [{}](#{}) | {} | {} |",
            category,
            category.replace('-', ""),
            patterns.len(),
            category_description(category)
        );
    }

    out.push_str("\n---\n");

    for (category, mut patterns) in by_category {
        patterns.sort_by(|a, b| a.name.cmp(&b.name));
        let _ = writeln!(
            out,
            "\n## {}\n\n| Pattern | Severity | Confidence | Description |\n|----------|----------|------------|-------------|",
            category
        );
        for p in patterns {
            let _ = writeln!(
                out,
                "| `{}` | {} | {} | {} |",
                p.name,
                p.severity,
                p.confidence,
                escape_table_cell(&p.description)
            );
        }
    }

    out
}

/// Pipe characters would break the Markdown table rows.
fn escape_table_cell(text: &str) -> String {
    text.replace('|', "\\|")
}

/// Short human-readable blurbs for the category table.
fn category_description(category: &str) -> &'static str {
    match category {
        "accessibility" => "WCAG 2.x success criteria for markup, media, and styles",
        "ai-detection" => "Heuristics that flag likely AI-generated code",
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
