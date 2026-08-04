# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| older   | :x:                |

## Reporting a Vulnerability

**Please DO NOT file a public GitHub issue for security vulnerabilities.**

Instead, please report them by:

1. **Email**: Send to the maintainers directly (preferred for critical issues)
2. **GitHub Private Vulnerability Reporting**: Use GitHub's [private vulnerability reporting](https://github.com/aliasfoxkde/aegis/security/advisories/new)

### What to Include

When reporting, please include:

- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/commit/branch)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue

### Response Timeline

- **Initial response**: Within 48 hours
- **Status update**: Within 7 days
- **Resolution**: As quickly as possible (critical issues prioritized)

## Security Best Practices for Users

### Scanning

- Always use the latest version of Aegis patterns
- Run scans before committing code
- Use severity thresholds appropriate for your environment

### CI/CD Integration

- Use SARIF format for integration with security tools
- Enable fail-on options for critical/high severity findings
- Review suppressions carefully

### Configuration

- Use appropriate profiles for your environment (production vs development)
- Regularly update pattern bundles with `aegis update`

## Security-Related Pattern Categories

Aegis includes security-focused pattern categories:

- `secrets` - API keys, tokens, credentials
- `security-hardening` - Security best practices
- `web-security` - XSS, SQLi, CORS, etc.
- `supply-chain` - Dependency vulnerabilities
- `infrastructure` - Terraform, IaC security
- `cloud-native` - Kubernetes, Docker security
