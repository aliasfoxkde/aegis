# Detection Patterns

Aegis includes **620 detection patterns** across **32 categories** for comprehensive security scanning.

## Pattern Categories

### Core Security Categories

| Category | Patterns | Description |
|----------|----------|-------------|
| [Secrets & Credentials](./categories/secrets.md) | 40 | API keys, tokens, credentials |
| [PII & Privacy](./categories/pii.md) | 39 | Personal data detection |
| [Security Hardening](./categories/security-hardening.md) | 33 | Security best practices |
| [Web Security](./categories/web-security.md) | 37 | XSS, SQLi, CORS, SSRF |
| [Supply Chain](./categories/supply-chain.md) | 35 | Dependency vulnerabilities |

### Infrastructure & Cloud

| Category | Patterns | Description |
|----------|----------|-------------|
| [Infrastructure as Code](./categories/infrastructure.md) | 55 | Terraform, IaC security |
| [Cloud Native](./categories/cloud-native.md) | 38 | Kubernetes, Docker |
| [Kubernetes](./categories/kubernetes.md) | 11 | Kubernetes-specific |
| [Terraform](./categories/terraform.md) | 7 | Terraform patterns |
| [CloudFormation](./categories/cloudformation.md) | 3 | AWS CloudFormation |

### AI & Machine Learning

| Category | Patterns | Description |
|----------|----------|-------------|
| [AI Safety & LLM](./categories/ai-safety-llm.md) | 50 | Prompt injection, AI safety |
| [AI Detection](./categories/ai-detection.md) | 25 | AI-generated code detection |

### Compliance & Governance

| Category | Patterns | Description |
|----------|----------|-------------|
| [Compliance](./categories/compliance.md) | 33 | GDPR, HIPAA, PCI-DSS |
| [Healthcare](./categories/healthcare.md) | 7 | Healthcare compliance |
| [Finance](./categories/finance.md) | 6 | Financial compliance |

### Code Quality & Development

| Category | Patterns | Description |
|----------|----------|-------------|
| [Code Quality](./categories/code-quality.md) | 15 | Code best practices |
| [Performance](./categories/performance.md) | 22 | Performance issues |
| [Accessibility](./categories/accessibility.md) | 22 | WCAG compliance |
| [Frameworks](./categories/frameworks.md) | 31 | Framework-specific |

### DevOps & Operations

| Category | Patterns | Description |
|----------|----------|-------------|
| [DevOps & CI/CD](./categories/devops.md) | 15 | CI/CD pipelines |
| [Container](./categories/container.md) | 4 | Container security |
| [GitOps](./categories/git-ops.md) | 3 | GitOps patterns |

### Other Categories

| Category | Patterns | Description |
|----------|----------|-------------|
| shift_left | 20 | Early detection patterns |
| git_hygiene | 28 | Git practices |
| graphql | 4 | GraphQL security |
| metadata | 4 | Metadata patterns |
| pwa | 5 | Progressive web apps |
| web_development | 12 | Web development |
| api_integration | 9 | API integrations |
| data_visualization | 5 | Data viz patterns |
| arm | 2 | ARM architecture |

## Quick Reference: Top Critical Patterns

| Pattern | Category | Severity | Description |
|---------|----------|----------|-------------|
| github-token | secrets | critical | GitHub personal access token |
| stripe-api-key | secrets | critical | Stripe API key |
| slack-token | secrets | critical | Slack bot/user token |
| aws-access-key | secrets | critical | AWS access key |
| gcp-service-account | secrets | critical | GCP service account |
| private-key-exposed | security-hardening | critical | Private key in code |
| sql-injection | web-security | high | SQL injection |
| command-injection | security-hardening | critical | OS command injection |
| prompt-injection | ai-safety | high | Prompt injection attack |
| data-exfiltration-attempt | llm-guardrails | critical | Data exfiltration |

## Pattern Format

Patterns are defined as Rust code in the `aegis-patterns` crate:

```rust
Pattern {
    name: "pattern-name".to_string(),
    match: Regex::new(r"regex-pattern").unwrap(),
    severity: Severity::High,
    description: "Pattern description".to_string(),
    tags: vec!["category".to_string()],
    ..Default::default()
}
```

## Contributing Patterns

See [Adding Patterns](../guides/ADDING_PATTERNS.md) for contribution guidelines.

## Pattern Statistics

- **Total Patterns**: 620
- **Categories**: 32
- **Critical Severity**: ~45
- **High Severity**: ~180
- **Medium Severity**: ~250
- **Low Severity**: ~146
