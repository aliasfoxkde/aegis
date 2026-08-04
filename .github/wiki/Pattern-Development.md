# Pattern Development Guide

Aegis patterns are simple YAML files. No Rust required!

## Creating Your First Pattern

### 1. Choose a Category

Patterns go in `community/<category>/` directories:

- **secrets/** - API keys, tokens, credentials
- **pii/** - Personal information (SSN, credit cards)
- **web-security/** - XSS, SQLi, injection
- **code-quality/** - Debug statements, TODOs
- **ai-detection/** - AI-generated code markers
- **devops/** - CI/CD, Docker, Kubernetes

Or create a new category directory.

### 2. Create the Pattern File

```yaml
# community/secrets/my-service-api-key.yaml
name: my-service-api-key
match: '\bmsvc_[A-Za-z0-9]{32}\b'
severity: high
confidence: high
minEntropy: 3.5
description: 'Detects MyService API keys'
tags:
  - secrets
  - api-key
```

### 3. Test Your Pattern

```bash
# Build the project
cargo build --workspace

# List your pattern
cargo run --bin aegis-cli -- list --search my-service

# Test scan
echo "msvc_12345678901234567890123456789012" | cargo run --bin aegis-cli -- scan
```

## Pattern Format

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Unique pattern name (snake_case) |
| `match` | string | Valid regex pattern |
| `severity` | string | `critical`, `high`, `medium`, or `low` |
| `confidence` | string | `high`, `medium`, or `low` |
| `description` | string | Human-readable description |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `minEntropy` | float | Minimum entropy threshold (0.0-8.0) |
| `reference` | string | Documentation URL |
| `tags` | list | Additional categorization tags |

## Pattern Best Practices

### 1. Use Word Boundaries

```yaml
# ❌ BAD - matches substrings
match: 'sk-[A-Za-z0-9]{32}'

# ✅ GOOD - whole tokens only
match: '\bsk-[A-Za-z0-9]{32}\b'
```

### 2. Be Specific

```yaml
# ❌ TOO GENERIC - many false positives
match: '[A-Z]{2}-[A-Z]{5}'

# ✅ SPECIFIC - with identifiable prefix
match: '\bMSVC_[A-Za-z0-9]{32}\b'
```

### 3. Consider False Positives

```yaml
# ❌ MANY FALSE POSITIVES
match: 'token[A-Z]*'

# ✅ CONTEXT AWARE
match: '\bapi[_-]?token["\s]*[:=]["\s]*[A-Za-z0-9]{32,}'
```

### 4. Set Appropriate Entropy

```yaml
# High-entropy strings are more likely to be secrets
minEntropy: 4.0  # Reject low-entropy matches
```

## Pattern Examples

### API Keys

```yaml
# AWS Access Key
name: aws-access-key
match: '\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'
severity: critical
confidence: high
minEntropy: 3.5
description: 'AWS access key ID detected'
tags:
  - secrets
  - aws

# GitHub Token
name: github-token
match: '\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b'
severity: critical
confidence: high
minEntropy: 5.0
description: 'GitHub personal access token'
tags:
  - secrets
  - github

# Stripe API Key
name: stripe-api-key
match: '\b(?:sk|pk)_(?:live|test)_[0-9a-z]{24,}\b'
severity: critical
confidence: high
minEntropy: 4.5
description: 'Stripe API key detected'
tags:
  - secrets
  - payment
```

### Code Quality

```yaml
# TODO comments
name: todo-comment
match: '(?i)TODO[^\n]*:'
severity: low
confidence: medium
description: 'TODO comment detected'
tags:
  - code-quality
  - maintenance

# Debug print
name: debug-print
match: '(?i)(console\.log|fmt\.Print|log\.Print)\s*\('
severity: medium
confidence: high
description: 'Debug print statement detected'
tags:
  - code-quality
  - debugging
```

### AI Detection

```yaml
# AI-generated marker
name: ai-generated-marker
match: '(?i)(generated\s+by|ai[-\s]generated|created\s+by\s+chatgpt)'
severity: low
confidence: medium
description: 'AI generation marker detected'
tags:
  - ai-detection
  - metadata
```

## Testing Your Pattern

### Manual Testing

```bash
# Test with sample content
echo "AKIAIOSFODNN7EXAMPLE" | cargo run --bin aegis-cli -- scan --category secrets

# Test specific pattern
cargo run --bin aegis-cli -- list --search aws-access-key
```

### Automated Testing

Add test cases in `crates/aegis-patterns/tests/`:

```rust
#[test]
fn test_aws_access_key() {
    let scanner = Scanner::new();
    let findings = scanner.scan_string(
        "AKIAIOSFODNN7EXAMPLE",
        Some("secrets")
    );
    assert!(!findings.is_empty());
    assert_eq!(findings[0].pattern.name, "aws-access-key");
}
```

## Submitting Patterns

1. Fork the repository
2. Add your pattern to `community/<category>/`
3. Test thoroughly
4. Submit a pull request

See [CONTRIBUTING](../.github/CONTRIBUTING.md) for full guidelines.

## Pattern Quality Checklist

- ✅ **Specificity** - Uses word boundaries `\b` where appropriate
- ✅ **Accuracy** - Minimal false positives on real code
- ✅ **Clarity** - Pattern name clearly describes what it detects
- ✅ **Testing** - Tested with real examples and edge cases
- ✅ **Entropy** - Appropriate `minEntropy` for secrets
- ✅ **Metadata** - Description explains what pattern detects

## Common Mistakes

### ❌ Overly Generic

```yaml
match: '[0-9]{32}'  # Matches ANY 32-digit number
```

### ❌ Missing Word Boundaries

```yaml
match: 'password'  # Matches "password" anywhere
```

### ❌ Catastrophic Backtracking

```yaml
# ❌ DANGEROUS - can hang on certain inputs
match: '(a+)+$'

# ✅ SAFE - no nested quantifiers
match: '\ba{8,32}\b'
```

---

**Need inspiration?** Browse existing patterns in `community/` directory.
