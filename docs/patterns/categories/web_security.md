# Web Security (37 patterns)

## Patterns

| Pattern | Severity | Description |
|---------|----------|-------------|
| reflected-xss|high|Potential reflected XSS vulnerability |
| sql-injection|high|Potential SQL injection vulnerability |
| cors-misconfiguration|medium|CORS misconfiguration detected (wildcard origin) |
| stored-xss|high|Potential stored XSS via innerHTML |
| dom-xss|high|Potential DOM XSS vulnerability |
| xss-via-url|medium|Potential XSS via URL parameters |
| csrf-missing-token|medium|State-changing operation may lack CSRF protection |
| csrf-token-header|low|CSRF token header detected |
| command-injection|critical|Potential OS command injection |
| path-traversal|high|Potential path traversal vulnerability |
| directory-traversal|high|Directory traversal pattern detected |
| ssrf|high|Potential Server-Side Request Forgery (SSRF) |
| ssrf-localhost|medium|Potential SSRF targeting internal resources |
| missing-security-headers|medium|Security headers detected |
| hsts-missing|medium|HSTS header not detected |
| x-frame-options|medium|X-Frame-Options header detected |
| x-content-type-options|medium|X-Content-Type-Options header detected |
| content-security-policy|low|Content-Security-Policy header detected |
| hardcoded-credential|critical|Hardcoded credential detected |
| weak-password-hash|high|Weak password hashing algorithm detected |
| jwt-none-algorithm|critical|JWT with 'none' algorithm detected |
| session-fixation|medium|Potential session fixation vulnerability |
| xxe|critical|XXE protection disabled |
| xml-external-entity|critical|XML External Entity (XXE) detected |
| insecure-deserialization|critical|Potential insecure deserialization |
| unrestricted-file-upload|high|File upload without validation |
| executable-file-upload|critical|Executable file upload detected |
| open-redirect|medium|Potential open redirect vulnerability |
| redirect-to-relative|low|Redirect to relative path |
| debug-mode|medium|Debug mode enabled in production |
| stack-trace-exposure|low|Stack trace exposure detected |
| server-version|low|Server version header detected |
| rate-limiting|medium|Rate limiting detected |
| api-key-exposure|high|API key in source code |
| missing-authentication|high|API endpoint may lack authentication |
| graphql-introspection|medium|GraphQL introspection enabled |
| graphql-batch-limit|medium|GraphQL depth limiting detected |

## Related
- [All Patterns](../README.md)
