# Security Hardening (33 patterns)

## Patterns

| Pattern | Severity | Description |
|---------|----------|-------------|
| weak-ssl|high|Weak cryptographic protocol/algorithm detected |
| hardcoded-encryption-key|critical|Hardcoded encryption key detected |
| insecure-random|medium|Insecure random number generation (Math.random) |
| sql-query|low|SQL query detected (potential SQL injection) |
| security-hardening-command-injection|critical|Potential command injection vulnerability |
| security-hardening-path-traversal|high|Potential path traversal vulnerability |
| xss-vulnerability|high|Potential XSS vulnerability (unsafe DOM manipulation) |
| insecure-cookie|medium|Insecure cookie configuration detected |
| csrf-missing|low|CSRF protection reference detected |
| hardcoded-iv|high|Hardcoded IV detected for encryption |
| jwt-secret-hardcoded|high|Hardcoded JWT secret detected |
| private-key-exposed|critical|Private key exposed in code |
| password-in-url|high|Password embedded in URL detected |
| bearer-token-url|medium|Bearer token detected in code |
| basic-auth-url|high|Basic authentication credentials in URL |
| security-hardening-aws-access-key|critical|AWS access key ID detected |
| aws-secret-key|critical|AWS secret access key detected |
| github-token|critical|GitHub token detected |
| slack-token|critical|Slack token detected |
| stripe-api-key|critical|Stripe API key detected |
| sendgrid-api-key|critical|SendGrid API key detected |
| twilio-api-key|critical|Twilio API key detected |
| mailgun-api-key|critical|Mailgun API key detected |
| security-hardening-jwt-none-algorithm|critical|JWT 'none' algorithm vulnerability detected |
| security-hardening-xml-external-entity|critical|XML External Entity (XXE) vulnerability detected |
| deserialization-vulnerability|critical|Potential insecure deserialization vulnerability |
| eval-usage|high|Dangerous eval() usage detected |
| setuid-root|high|Setuid/Setgid permissions detected |
| world-writable|high|World-writable file permissions detected |
| sensitive-file-access|medium|Access to sensitive system files detected |
| ldap-injection|high|Potential LDAP injection vulnerability |
| xpath-injection|high|Potential XPath injection vulnerability |
| ssti-template|high|Potential server-side template injection |

## Related
- [All Patterns](../README.md)
