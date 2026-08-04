# Detection Patterns

Aegis includes **621 detection patterns** across **32 categories** for comprehensive security scanning.

## Pattern Categories

### Secrets & Credentials (40 patterns)
Detection of exposed secrets, API keys, tokens, and credentials.

| Pattern | Severity | Description |
|---------|----------|-------------|
| aws-access-key | high | AWS access key ID |
| github-token | critical | GitHub personal access token |
| stripe-api-key | critical | Stripe API key |
| slack-token | critical | Slack bot/user token |
| azure-devops-token | critical | Azure DevOps PAT |
| gcp-service-account | critical | GCP service account key |
| *+35 more* | | |

### PII & Privacy (39 patterns)
Personal data and privacy-related detections.

| Pattern | Severity | Description |
|---------|----------|-------------|
| email-address | medium | Email address detection |
| ssn | critical | Social Security Number |
| credit-card | critical | Credit card number |
| phone-number | medium | Phone number |
| passport-number | high | Passport number |
| ip-address | low | IPv4/IPv6 address |
| *+33 more* | | |

### Security Hardening (33 patterns)
Security best practices and vulnerability detection.

| Pattern | Severity | Description |
|---------|----------|-------------|
| jwt-secret-hardcoded | high | Hardcoded JWT secret |
| private-key-exposed | critical | Private key in code |
| password-in-url | high | Password in URL |
| aws-access-key | critical | AWS credentials |
| command-injection | critical | OS command injection |
| *+28 more* | | |

### Supply Chain (35 patterns)
Dependency and supply chain security.

| Pattern | Severity | Description |
|---------|----------|-------------|
| vulnerable-dependency | high | Known vulnerable dependency |
| malicious-package | critical | Malicious package detected |
| typosquatting | high | Typosquatted package name |
| unauthorized-dependency | medium | Unauthorized package |
| *+31 more* | | |

### Web Security (37 patterns)
OWASP Top 10 and web vulnerabilities.

| Pattern | Severity | Description |
|---------|----------|-------------|
| sql-injection | high | SQL injection vulnerability |
| reflected-xss | high | Reflected XSS |
| cors-misconfiguration | medium | CORS wildcard origin |
| csrf-missing | medium | CSRF protection missing |
| ssrf | high | Server-side request forgery |
| *+32 more* | | |

### Infrastructure as Code (55 patterns)
Terraform, CloudFormation, Kubernetes, and container security.

| Pattern | Severity | Description |
|---------|----------|-------------|
| terraform-s3-public | high | Public S3 bucket |
| kubernetes-privileged | critical | Privileged container |
| cloudformation-s3-public | high | Public S3 via CloudFormation |
| container-privileged | critical | Privileged container mode |
| *+51 more* | | |

### Cloud Native (38 patterns)
Kubernetes, Docker, and cloud-native patterns.

| Pattern | Severity | Description |
|---------|----------|-------------|
| kubernetes-secrets-env | high | Secrets in environment vars |
| docker-socket-mount | critical | Docker socket mounted |
| run-as-root | high | Running as root |
| *+35 more* | | |

### AI Safety & LLM (50 patterns)
AI system security and responsible AI patterns.

| Pattern | Severity | Description |
|---------|----------|-------------|
| prompt-injection | high | Prompt injection attack |
| system-prompt-leak | medium | System prompt exposure |
| data-exfiltration | critical | Data exfiltration attempt |
| jailbreak-attempt | high | LLM jailbreak attempt |
| harmful-content-marker | high | Harmful content marker |
| *+45 more* | | |

### Code Quality (15 patterns)
Code quality and best practices.

| Pattern | Severity | Description |
|---------|----------|-------------|
| commented-password | high | Password in comments |
| debug-breakpoint | medium | Debug breakpoint left in |
| commented-secret | high | Secret in comments |
| bare-except | medium | Bare except clause |
| *+11 more* | | |

### Compliance (33 patterns)
Regulatory compliance checks (GDPR, HIPAA, PCI-DSS, SOC2).

| Pattern | Severity | Description |
|---------|----------|-------------|
| gdpr-personal-data | high | Personal data under GDPR |
| hipaa-health-data | critical | Health information |
| pci-cardholder-data | critical | Credit card data |
| soc2-sensitive-data | high | Sensitive data |
| *+29 more* | | |

### Performance (22 patterns)
Performance and efficiency issues.

| Pattern | Severity | Description |
|---------|----------|-------------|
| n-plus-one-query | medium | N+1 database query |
| sync-in-async | medium | Sync call in async context |
| regex-in-loop | medium | Regex compiled in loop |
| *+19 more* | | |

### Accessibility (22 patterns)
WCAG accessibility compliance.

| Pattern | Severity | Description |
|---------|----------|-------------|
| missing-alt-text | medium | Image without alt text |
| low-contrast | medium | Insufficient color contrast |
| missing-label | medium | Form control without label |
| *+19 more* | | |

### DevOps & CI/CD (15 patterns)
CI/CD pipeline and DevOps patterns.

| Pattern | Severity | Description |
|---------|----------|-------------|
| github-actions-workflow | low | GitHub Actions workflow |
| gitlab-ci-pipeline | low | GitLab CI config |
| jenkinsfile | low | Jenkinsfile detected |
| *+12 more* | | |

### Frameworks (31 patterns)
Framework-specific security patterns.

| Pattern | Severity | Description |
|---------|----------|-------------|
| react-xss | high | React XSS pattern |
| angular-ssr | medium | Angular SSR consideration |
| nextjs-image | low | Next.js image optimization |
| *+28 more* | | |

### Additional Categories

| Category | Count | Description |
|----------|-------|-------------|
| shift_left | 20 | Early detection patterns |
| ai_detection | 25 | AI-generated code detection |
| llm_guardrails | 25 | LLM safety rails |
| git_hygiene | 28 | Git practices |
| graphql | 4 | GraphQL security |
| healthcare | 7 | Healthcare compliance |
| finance | 6 | Financial compliance |
| container | 4 | Container security |
| cloudformation | 3 | AWS CloudFormation |
| arm | 2 | ARM architecture |
| metadata | 4 | Metadata patterns |
| pwa | 5 | Progressive web apps |
| web_development | 12 | Web development |
| git_ops | 3 | GitOps patterns |
| api_integration | 9 | API integrations |
| data_visualization | 5 | Data viz patterns |
| kubernetes | 11 | Kubernetes security |
| terraform | 7 | Terraform patterns |

## Pattern Format

Patterns are defined as YAML files for easy contribution:

```yaml
name: pattern-name
match: regex-pattern
severity: critical|high|medium|low
confidence: high|medium|low
minEntropy: 3.5  # optional entropy threshold
description: 'Pattern description'
tags:
  - category
  - security
```

## Contributing Patterns

See [Adding Patterns](../guides/ADDING_PATTERNS.md) for contribution guidelines.

## Pattern Statistics

- **Total Patterns**: 621
- **Categories**: 32
- **Critical Severity**: ~45
- **High Severity**: ~180
- **Medium Severity**: ~250
- **Low Severity**: ~146
