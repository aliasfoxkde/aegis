# Adding Patterns

Aegis patterns can be added in two ways:

1. **Rust code** (core patterns, in `crates/aegis-patterns/src/`)
2. **YAML files** (community contributions, bundled with `aegis-bundler`)

Both formats share the same semantics; YAML exists so contributions don't
require recompiling the binary.

## Naming and Structure Rules

- Pattern names are **kebab-case** (`aws-access-key`, not
  `AWS_accessKey`). The hygiene test suite rejects anything else.
- Categories are kebab-case and must already exist in
  `aegis_patterns::by_category()`.
- Regexes use the Rust `regex` crate (RE2 syntax): **no lookarounds**,
  `.` does not cross newlines, and nested quantifiers cannot backtrack
  (keep repetitions bounded anyway).

## Rust Pattern Format

Add to the appropriate module in `crates/aegis-patterns/src/`:

```rust
Pattern {
    name: "my-service-key".to_string(),
    category: "secrets".to_string(),
    match_pattern: r#"(?i)myservice[_-]?key\s*[:=]\s*['\"][A-Za-z0-9]{16,}"#.to_string(),
    enabled: true,
    severity: "high".to_string(),
    confidence: "high".to_string(),
    min_entropy: Some(3.5),
    description: "Detects hardcoded MyService keys".to_string(),
    reference: Some("https://docs.example.com/security".to_string()),
    tags: vec!["secrets".to_string(), "api-key".to_string()],
    env_var: false,
    binary: false,
    exclude: Some(r#"(?i)example|placeholder|your[-_]key"#.to_string()),
    file_extensions: Vec::new(),
}
```

Then:

1. Run `cargo run -p aegis-patterns --example generate_docs` so the
   generated catalog stays fresh (a CI test enforces this).
2. Add positive and negative fixtures to
   `crates/aegis-cli/tests/pattern_fixtures.rs`.

### Scoping fields

- `exclude` — when this regex also matches the finding's text, the
  finding is suppressed. Use it to exempt documentation examples and
  safe idioms. It only sees the matched span, not the rest of the line.
- `file_extensions` — pattern runs only on files with a listed
  extension. Empty list = all files. Files without an extension
  (`README`, `Dockerfile`) never match scoped patterns.

## YAML Pattern Format

Create a YAML file (a list of patterns) for the bundler:

```yaml
- name: my-service-key
  category: secrets
  match: '(?i)myservice[_-]?key\s*[:=]\s*["''][A-Za-z0-9]{16,}'
  enabled: true
  severity: high
  confidence: high
  minEntropy: 3.5
  description: Detects hardcoded MyService keys
  reference: https://docs.example.com/security
  tags: [secrets, api-key]
  exclude: '(?i)example|placeholder'
  fileExtensions: [js, ts]
```

**Required fields:** `name`, `category`, `match`, `enabled`, `severity`,
`confidence`, `description`.

**Optional fields:** `minEntropy` (`minEntropy` or `min_entropy`),
`reference`, `tags`, `envVar` (`envVar` or `env_var`), `binary`,
`exclude`, `fileExtensions` (`fileExtensions` or `file_extensions`).

## Building and Verifying

```bash
# Build a distributable bundle from a directory of YAML files
cargo run -p aegis-bundler -- <input_dir> <output_file.json.gz>

# Registry-level validation runs automatically on load: an invalid regex,
# duplicate name, or wrong schema aborts the scan (fail-closed).
```

Corpus-wide invariants (unique names, kebab-case categories, category
dispatch, https references) are enforced by
`cargo test -p aegis-patterns --test registry_hygiene`.

## Testing Patterns

Every pattern must pass in both directions:

```rust
// crates/aegis-cli/tests/pattern_fixtures.rs
#[test]
fn my_pattern_detects_its_target() {
    let scanner = scanner(); // full shipped corpus
    let findings = scanner.scan_string(
        "myservice_key = 'AKIAIOSFODNN7EXAMPLE'",
        "fixtures/sample.js",
    );
    assert!(findings.iter().any(|f| f.pattern == "my-service-key"));
}

#[test]
fn my_pattern_ignores_placeholders() {
    let scanner = scanner();
    let findings = scanner.scan_string(
        "myservice_key = 'your-key-here-placeholder'",
        "fixtures/sample.js",
    );
    assert!(findings.iter().all(|f| f.pattern != "my-service-key"));
}
```

### Severity Guidelines

| Severity | When to Use |
|----------|-------------|
| `critical` | Immediate security risk (RCE, data breach) |
| `high` | Significant security issue (exposed secrets, injection) |
| `medium` | Moderate issue (misconfiguration, weak crypto) |
| `low` | Minor issue (style, performance) |

### Confidence Guidelines

| Confidence | When to Use |
|------------|-------------|
| `high` | Pattern rarely produces false positives |
| `medium` | Pattern may have some false positives |
| `low` | Pattern is experimental or heuristic |

## Submitting Patterns

1. Fork the repository
2. Add the pattern (Rust module or YAML file)
3. Run the full gates: `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`
4. Submit a pull request
