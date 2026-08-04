# Adding Patterns

Aegis patterns can be added in two ways:

1. **YAML files** (recommended for community contributions)
2. **Rust code** (for core patterns)

## YAML Pattern Format

Create a YAML file in the appropriate category directory:

```yaml
name: my-pattern
match: '(?i)(secret|api[_-]?key)\s*[:=]\s*["\'][A-Za-z0-9]{16,}'
severity: high
confidence: high
minEntropy: 3.5
description: 'Detects hardcoded API keys or secrets'
tags:
  - secrets
  - api-key
reference: https://example.com/docs/pattern
```

**Required Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Unique pattern name (snake_case) |
| `match` | string | Regex pattern |
| `severity` | string | `critical`, `high`, `medium`, or `low` |
| `confidence` | string | `high`, `medium`, or `low` |
| `description` | string | Human-readable description |

**Optional Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `minEntropy` | float | Minimum entropy threshold (0.0-8.0) |
| `reference` | string | Documentation URL |
| `tags` | list | Additional categorization tags |

## Pattern Categories

Place YAML files in category directories:

```
community/
├── secrets/
│   ├── my-api-key.yaml
│   └── my-token.yaml
├── pii/
│   ├── my-pii-pattern.yaml
└── web-security/
    └── my-xss.yaml
```

## Testing Patterns

### Validate YAML Syntax

```bash
# Using the bundler
aegis-bundler validate patterns/

# Or load directly
cargo run -- validate patterns/
```

### Test Against Samples

```bash
# Test a pattern against sample text
echo "api_key = '1234567890abcdef'" | cargo run -- scan --pattern my-pattern
```

### Add Tests

Add test cases in `crates/aegis-patterns/tests/`:

```rust
#[test]
fn test_my_pattern() {
    let scanner = Scanner::new();
    let findings = scanner.scan_string(
        "api_key = 'AKIAIOSFODNN7EXAMPLE'",
        Some("secrets")
    );
    assert!(!findings.is_empty());
    assert_eq!(findings[0].pattern.name, "my-pattern");
}
```

## Rust Pattern Format

For core patterns, add to the appropriate module in `crates/aegis-patterns/src/`:

```rust
Pattern {
    name: "my-pattern".to_string(),
    category: "secrets".to_string(),
    match_pattern: r#"(?i)(secret|api[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9]{16,}"#.to_string(),
    enabled: true,
    severity: "high".to_string(),
    confidence: "high".to_string(),
    min_entropy: Some(3.5),
    description: "Detects hardcoded API keys or secrets".to_string(),
    reference: Some("https://example.com/docs".to_string()),
    tags: vec!["secrets".to_string(), "api-key".to_string()],
    env_var: false,
    binary: false,
}
```

## Pattern Guidelines

### Naming Conventions

- Use `snake_case` for pattern names
- Be specific: `aws-access-key` not `api-key`
- Include the platform/service if applicable

### Regex Best Practices

- Use `\b` for word boundaries
- Use non-capturing groups `(?:...)` when needed
- Avoid catastrophic backtracking `(a+)+`
- Test with samples before submitting

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
2. Add your pattern to the appropriate `community/<category>/` directory
3. Test your pattern
4. Submit a pull request

## Pattern Bundle

Patterns are bundled for distribution:

```bash
# Export patterns to YAML
aegis-bundler export ./community ./patterns-export

# Import patterns from YAML
aegis-bundler import ./community ./bundle.json.gz

# Create distribution bundle
aegis-bundler bundle ./community ./aegis-patterns.bundle
```
