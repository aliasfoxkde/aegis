# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Aegis, please report it responsibly.

### How to Report

1. **Do NOT** create a public GitHub issue for security vulnerabilities
2. Email the maintainers at the repository's contact address
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

### What to Expect

- Acknowledgment of your report within 48 hours
- Regular updates on the progress
- Credit for the discovery (unless you prefer to remain anonymous)

### Scope

Security issues in the following are in scope:
- Core scanning engine vulnerabilities
- Path traversal vulnerabilities
- Pattern bypass vulnerabilities
- Denial of service issues
- Secret exfiltration concerns

## Security Best Practices

When using Aegis:

- Run scans in isolated environments
- Review suppressions carefully - they disable security checks
- Keep patterns updated via `aegis update`
- Use baseline files to track known issues
