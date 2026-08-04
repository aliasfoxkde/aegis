# Secrets Patterns

Detection of exposed secrets, API keys, tokens, and credentials.

## Patterns

| Pattern | Severity | Description |
|---------|----------|-------------|
| aws-access-key | high | AWS access key ID |
| github-token | critical | GitHub personal access token |
| stripe-api-key | critical | Stripe API key |
| slack-token | critical | Slack bot/user token |
| azure-devops-token | critical | Azure DevOps PAT |
| gcp-service-account | critical | GCP service account key |
| jwt-secret | high | JWT secret |
| private-key | critical | Private key in code |
| password-in-url | high | Password embedded in URL |

## Examples

```yaml
# AWS Access Key
name: aws-access-key
match: '\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'
severity: high
confidence: high
minEntropy: 3.5
description: 'AWS access key ID detected'
tags:
  - secrets
  - aws
```

```yaml
# GitHub Token
name: github-token
match: '(?i)(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}'
severity: critical
confidence: high
minEntropy: 5.0
description: 'GitHub personal access token detected'
tags:
  - secrets
  - github
```
