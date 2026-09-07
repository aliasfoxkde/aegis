# Pattern Specification

## Overview

Patterns are the core detection units in Aegis. Each pattern is a Rust
struct in `crates/aegis-patterns/src/<category>.rs`; every surface (CLI,
MCP, daemon, WASM) builds its `PatternRegistry` from the compiled-in
corpus via `aegis_patterns::all_patterns()`. The same corpus can be
serialized into a gzip+JSON bundle, which the MCP `update_bundle` method
loads and installs in place of the built-in set.

The generated catalog of every shipped pattern lives in
[docs/patterns/README.md](./patterns/README.md) (regenerate with
`cargo run -p aegis-patterns --example generate_docs`; a freshness test
fails CI when it drifts).

## Pattern Format

```rust
pub struct Pattern {
    pub name: String,             // Unique kebab-case identifier
    pub category: String,         // Kebab-case category, dispatchable via by_category()
    pub match_pattern: String,    // RE2-syntax regex (serde key: "match")
    pub exclude: Option<String>,  // Suppress finding when this regex hits the matched span
    pub file_extensions: Vec<String>, // Scope to extensions; empty = all files
    pub enabled: bool,
    pub severity: String,         // critical | high | medium | low
    pub confidence: String,       // high | medium | low
    pub min_entropy: Option<f64>, // Shannon entropy floor for secrets
    pub description: String,
    pub reference: Option<String>, // Absolute https URL
    pub tags: Vec<String>,
    pub env_var: bool,            // true = env-scan-only (excluded from file scans)
    pub binary: bool,             // Allow matching in binary files
}
```

### Regex engine constraints

`match_pattern` and `exclude` use the Rust `regex` crate (RE2 syntax):

- **No lookarounds** — negative checks are expressed with `exclude`
  instead: the finding is suppressed when the exclude regex matches the
  matched span (unanchored `is_match`).
- **`.` does not cross newlines** — use explicit classes such as `[^\n]`
  for line-bounded wildcards. Beware negated classes (`[^;]`) which DO
  match newlines and can produce multiline spans.
- **`\b` treats `_` as a word character** — `\bKEY\b` will not match
  inside `API_KEY`; drop the boundary when matching keyword substrings.
- Escape `[` inside character classes (`[<{\[]`) and prefer raw strings
  of the right depth (`r##"..."##`) when the content contains `"#`.

### Scoping semantics

- `exclude` is checked against the matched text only — it cannot see the
  rest of the line. Design matches so the span includes the context that
  should suppress it (e.g. `{0,200}` after a route path).
- `file_extensions` compares against the lowercase extension of the file
  name. Files without an extension (`.gitignore`, `Dockerfile`, `README`)
  have **no** extension and therefore never match a scoped pattern.
- `env_var: true` marks a pattern as **env-scan-only**: it is removed
  from file scanning entirely and only `scan_env` runs it, matching the
  environment variable *value*. Reserve the flag for shapes that are
  only precise with an env-var key name for context (bare
  `[A-Za-z0-9]{25,}` blobs, base64 spans, UUIDs, crypto addresses) —
  vendor-prefixed credentials (`glpat-`, `sk-ant-`, `npm_`, ...) must
  stay file-active so leaks in source files are caught. Every `secrets`
  category pattern runs in environment scans regardless of this flag.
  The env-scan-only set is pinned by
  `crates/aegis-core/tests/env_var_semantics.rs`; extending it is a
  deliberate, test-visible decision.

## Categories

Every category is a lowercase kebab-case string dispatched by
`aegis_patterns::by_category()`. Selecting an unknown category with
`--categories` or in a config profile is a hard error listing the valid
names (`PatternRegistry::validate_categories`). Current categories:
accessibility, ai-detection, ai-safety, api-integration, arm,
cloud-native, cloudformation, code-quality, compliance, container,
data-visualization, devops, finance, frameworks, git-hygiene, git-ops,
graphql, healthcare, infrastructure, kubernetes, llm-guardrails,
metadata, performance, pii, pwa, secrets, security-hardening,
shift-left, supply-chain, terraform, typescript, web-development,
web-security.

Per-category descriptions and full pattern tables are in the
[generated catalog](./patterns/README.md).

---

## Severity Levels

| Level | Weight | Description |
|-------|--------|-------------|
| Critical | 40 | Immediate security risk |
| High | 25 | Significant security issue |
| Medium | 10 | Code quality issue |
| Low | 3 | Minor issue, informational |

---

## Confidence Levels

| Level | Multiplier | Description |
|-------|------------|-------------|
| High | 1.0 | Pattern is reliable |
| Medium | 0.7 | May have false positives |
| Low | 0.4 | Experimental pattern |

Per-finding risk contribution = severity weight × confidence multiplier ×
category weight, summed into the scan's risk score.

---

## Entropy

Shannon entropy filters low-information matches (e.g. `password = ""`).

```rust
min_entropy: Some(3.5) // Minimum entropy threshold
```

For a string of length N with character frequencies f(c):

```
H = log2(N) - (1/N) * Σ f(c) * log2(f(c))
```

---

## Pattern Testing

Every pattern pack must satisfy two directions, locked by
`crates/aegis-cli/tests/pattern_fixtures.rs`:

1. **Compliant fixtures** — realistic correct code must produce zero
   findings from the pack.
2. **Violation fixtures** — each planted violation must trigger exactly
   the intended rule.

Corpus-wide invariants (compile checks, unique names, kebab-case naming,
category dispatch round-trip, https references, tag/extension hygiene)
are enforced by `crates/aegis-patterns/tests/registry_hygiene.rs`.

---

## Bundle Format

```json
{
  "schema_version": 2,
  "created_at": "2026-01-01T00:00:00Z",
  "patterns": [
    {
      "name": "aws-access-key",
      "category": "secrets",
      "match": "AKIA[0-9A-Z]{16}",
      "enabled": true,
      "severity": "critical",
      "confidence": "high",
      "min_entropy": 4.5,
      "description": "AWS Access Key ID detected",
      "reference": "https://docs.aws.amazon.com/IAM/",
      "tags": ["aws", "cloud", "credential"],
      "exclude": null,
      "file_extensions": [],
      "env_var": false,
      "binary": false
    }
  ]
}
```

Loading is fail-closed: a bundle containing an invalid regex, a duplicate
pattern name, or a stale `schema_version` aborts the scan rather than
degrading to a partial pattern set.

---

## Validation Rules

Enforced at load time (`PatternRegistry::from_definitions`):

1. `name` must be unique across all patterns
2. `match` must be a valid RE2 regex (compile check)
3. `exclude`, when present, must also compile

Enforced by the hygiene test suite (`registry_hygiene.rs`):

4. `name` and `category` must be kebab-case
5. Every category must round-trip through `by_category()` with no
   orphaned patterns
6. `severity` must be one of: critical, high, medium, low
7. `confidence` must be one of: high, medium, low
8. `min_entropy` must be between 0.0 and 8.0
9. `reference`, when present, must be an absolute https URL with a host
10. Tags must be lowercase (`wcag-<SC>` dotted form allowed); extensions
    must be lowercase alphanumeric without dots
