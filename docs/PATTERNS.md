# Pattern Specification

## Overview

Patterns are the core detection units in Atheon-Enhanced. They are defined in YAML format and bundled into a gzip+JSON archive for efficient loading.

## Pattern Format

```yaml
name: pattern-name              # Unique identifier (required)
category: category-name         # Category directory (required)
match: "regex-pattern"         # RE2 regex (required)
enabled: true                  # Default enabled state (default: true)
severity: high                # critical, high, medium, low (required)
confidence: high              # high, medium, low (required)
minEntropy: 3.5               # Minimum entropy for secrets (optional)
description: "Description"     # Human-readable description (required)
reference: "https://..."      # Reference URL (optional)
tags: [tag1, tag2]           # Taxonomy tags (optional)
envVar: false                 # Only match in env vars (optional)
binary: false                 # Allow binary file matching (optional)
```

## Categories

### secrets
API keys, tokens, credentials, private keys.
- AWS access keys
- GitHub tokens
- Database credentials
- SSH private keys
- JWT tokens

### code-quality
Debug artifacts, dead code, complexity issues.
- Console.log statements
- TODO comments
- Dead code detection
- High cyclomatic complexity
- Long functions

### devops
CI/CD pipelines, deployment markers.
- CI bypass markers
- Pipeline secrets
- Hardcoded IPs
- Debug endpoints

### ai-detection
AI-generated code markers, template detection.
- AI assistant markers
- Generated code patterns
- Template artifacts

### security-hardening
Insecure configurations, weak cryptography.
- Weak SSL/TLS
- Insecure headers
- Dangerous functions
- Hardcoded passwords

### accessibility
WCAG compliance, ARIA patterns.
- Missing alt text
- Low contrast
- Missing labels

### web-security
XSS, SQL injection, CORS issues.
- Reflected XSS
- SQL injection
- CORS misconfiguration

### pii
Personal identifiable information.
- Email addresses
- Phone numbers
- SSN patterns
- Credit card numbers

### cloud-native
Kubernetes, Docker, cloud deployments.
- Hardcoded cloud credentials
- Insecure container configs
- Kubernetes secrets

### performance
Blocking calls, synchronous patterns.
- Sync I/O in async
- N+1 queries
- Memory leaks

### supply-chain
Dependency vulnerabilities, malicious packages.
- Known vulnerable deps
- Typosquatting
- Unknown sources

### infrastructure
IaC, Terraform, Kubernetes manifests.
- Insecure Terraform
- Kubernetes misconfigs
- Exposed services

### compliance
GDPR, HIPAA, PCI compliance.
- Data retention issues
- Missing encryption
- Audit log gaps

### git-hygiene
Merge conflicts, fixup commits.
- Unresolved conflicts
- Large commits
- Secret commits

### ai-safety
Prompt injection, jailbreaks.
- Prompt injection
- System prompt leakage
- Dangerous outputs

### llm-guardrails
LLM input/output safety.
- Toxic content
- Personal data leakage
- Harmful instructions

### shift-left
Early detection patterns.
- Pre-commit hooks
- PR review patterns
- Early testing markers

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

---

## Entropy

Shannon entropy is used to detect high-entropy secrets like API keys and tokens.

```yaml
minEntropy: 3.5  # Minimum entropy threshold
```

Entropy formula:
```
H = -Σ p(x) * log2(p(x))
```

For a string of length N with character frequencies f(c):
```
H = log2(N) - (1/N) * Σ f(c) * log2(f(c))
```

---

## Pattern Testing

Patterns should be tested with:
1. Positive cases (should match)
2. Negative cases (should not match)
3. Edge cases (empty, very long, special chars)

```rust
#[cfg(test)]
mod pattern_tests {
    use super::*;

    #[test]
    fn test_aws_access_key_positive() {
        let pattern = Pattern::new("aws-access-key", "secrets",
            "AKIA[0-9A-Z]{16}", Severity::Critical, Confidence::High);
        assert!(pattern.matches("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_aws_access_key_negative() {
        let pattern = Pattern::new("aws-access-key", "secrets",
            "AKIA[0-9A-Z]{16}", Severity::Critical, Confidence::High);
        assert!(!pattern.matches("AKIA00000000000000AA")); // Invalid checksum
    }
}
```

---

## Bundle Format

```json
{
  "schema_version": 2,
  "created_at": "2024-01-01T00:00:00Z",
  "patterns": [
    {
      "name": "aws-access-key",
      "category": "secrets",
      "match": "AKIA[0-9A-Z]{16}",
      "enabled": true,
      "severity": "critical",
      "confidence": "high",
      "minEntropy": 4.5,
      "description": "AWS Access Key ID detected",
      "reference": "https://docs.aws.amazon.com/IAM/",
      "tags": ["aws", "cloud", "credential"]
    }
  ]
}
```

---

## Validation Rules

1. `name` must be unique across all patterns
2. `category` must match a known category
3. `match` must be valid RE2 regex
4. `severity` must be one of: critical, high, medium, low
5. `confidence` must be one of: high, medium, low
6. `minEntropy` must be between 0.0 and 8.0
7. At least one of `match` or `astPattern` required
