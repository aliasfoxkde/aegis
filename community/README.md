# Community Patterns

Pattern files for Aegis, organized by category. Each `.yaml` file defines one pattern.

## Categories

| Category | Patterns | Description |
|----------|----------|-------------|
| secrets | 40 | API keys, tokens, credentials, private keys |
| pii | 39 | Personally identifiable information |
| security-hardening | 33 | Insecure configs, weak crypto, unsafe calls |
| web-security | 37 | XSS, SQLi, CORS, injection risks |
| infrastructure | 55 | Terraform, IaC security |
| cloud-native | 38 | Kubernetes, Docker, cloud deployment |
| ai-safety | 50 | Prompt injection, AI safety |
| compliance | 33 | GDPR, HIPAA, PCI compliance |
| supply-chain | 35 | Dependency vulnerabilities |
| frameworks | 31 | Django, React, Vue framework patterns |
| ai-detection | 25 | AI-generated code markers |
| llm-guardrails | 25 | LLM safety patterns |
| shift-left | 20 | Early detection patterns |
| git-hygiene | 28 | Merge conflicts, git hygiene |
| performance | 22 | Blocking calls, synchronous patterns |
| accessibility | 22 | WCAG compliance, ARIA |
| code-quality | 15 | Debug artifacts, hardcoded values |
| devops | 15 | CI/CD patterns |
| graphql | 4 | GraphQL security |
| kubernetes | 11 | Kubernetes-specific patterns |
| healthcare | 7 | PHI, HIPAA-relevant patterns |
| finance | 6 | Payment identifiers, financial data |
| terraform | 7 | Terraform-specific patterns |
| web-development | 12 | Frontend anti-patterns |
| api-integration | 9 | API keys, webhook secrets |
| container | 4 | Container security patterns |
| cloudformation | 3 | AWS CloudFormation patterns |
| arm | 2 | ARM architecture patterns |
| metadata | 4 | File metadata patterns |
| pwa | 5 | Progressive Web App patterns |
| git-ops | 3 | GitOps workflow patterns |
| data-visualization | 5 | Chart/graph library patterns |

**Total: 621 patterns across 32 categories**

## Pattern File Format

```yaml
name: pattern-name          # lowercase, hyphenated, unique
match: "regex-pattern"      # valid regex
severity: high             # critical, high, medium, low
confidence: high           # high, medium, low
minEntropy: 3.5            # optional entropy threshold
description: "What it detects"
tags:
  - secrets
  - api-key
```

## Adding a Pattern

1. Create `community/<category>/<name>.yaml`
2. Follow the format above
3. Open a PR — CI validates patterns automatically

See [docs/guides/ADDING_PATTERNS.md](../docs/guides/ADDING_PATTERNS.md) for full contribution guidelines.

## Category Organization

Each category folder may contain a `README.md` documenting patterns in that category.
