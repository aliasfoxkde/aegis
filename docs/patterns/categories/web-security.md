# web-security patterns

XSS, injection, CORS, and SSRF

**37 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`api-key-exposure`](#api-key-exposure) | high | high | API key in source code |
| [`command-injection`](#command-injection) | critical | high | Potential OS command injection |
| [`content-security-policy`](#content-security-policy) | low | high | Content-Security-Policy header detected |
| [`cors-misconfiguration`](#cors-misconfiguration) | medium | high | CORS misconfiguration detected (wildcard origin) |
| [`csrf-missing-token`](#csrf-missing-token) | medium | medium | State-changing operation may lack CSRF protection |
| [`csrf-token-header`](#csrf-token-header) | low | high | CSRF token header detected |
| [`debug-mode`](#debug-mode) | medium | high | Debug mode enabled in production |
| [`directory-traversal`](#directory-traversal) | high | medium | URL-encoded directory traversal sequence detected |
| [`dom-xss`](#dom-xss) | high | high | Potential DOM XSS vulnerability |
| [`executable-file-upload`](#executable-file-upload) | critical | high | Executable file upload detected |
| [`graphql-batch-limit`](#graphql-batch-limit) | medium | high | GraphQL depth limiting detected |
| [`graphql-introspection`](#graphql-introspection) | medium | high | GraphQL introspection enabled |
| [`hardcoded-credential`](#hardcoded-credential) | critical | high | Hardcoded credential detected |
| [`hsts-missing`](#hsts-missing) | medium | high | HSTS header not detected |
| [`insecure-deserialization`](#insecure-deserialization) | critical | high | Potential insecure deserialization |
| [`jwt-none-algorithm`](#jwt-none-algorithm) | critical | high | JWT with 'none' algorithm detected |
| [`missing-authentication`](#missing-authentication) | high | medium | API endpoint may lack authentication |
| [`missing-security-headers`](#missing-security-headers) | medium | high | Security headers detected |
| [`open-redirect`](#open-redirect) | medium | medium | Potential open redirect vulnerability |
| [`path-traversal`](#path-traversal) | high | medium | Potential path traversal vulnerability |
| [`rate-limit-missing`](#rate-limit-missing) | medium | medium | Authentication route without visible rate limiting; brute-force protection not evident |
| [`redirect-to-relative`](#redirect-to-relative) | low | high | Redirect to relative path |
| [`reflected-xss`](#reflected-xss) | high | medium | Potential reflected XSS vulnerability |
| [`server-version`](#server-version) | low | high | Server version header detected |
| [`session-fixation`](#session-fixation) | medium | high | Potential session fixation vulnerability |
| [`sql-injection`](#sql-injection) | high | medium | Potential SQL injection vulnerability |
| [`ssrf`](#ssrf) | high | medium | Potential Server-Side Request Forgery (SSRF) |
| [`ssrf-localhost`](#ssrf-localhost) | medium | medium | Potential SSRF targeting internal resources |
| [`stack-trace-exposure`](#stack-trace-exposure) | low | high | Stack trace exposure detected |
| [`stored-xss`](#stored-xss) | high | medium | Potential stored XSS via innerHTML |
| [`unrestricted-file-upload`](#unrestricted-file-upload) | high | medium | File upload without validation |
| [`weak-password-hash`](#weak-password-hash) | high | high | Weak password hashing algorithm detected |
| [`x-content-type-options`](#x-content-type-options) | medium | high | X-Content-Type-Options header detected |
| [`x-frame-options`](#x-frame-options) | medium | high | X-Frame-Options header detected |
| [`xml-external-entity`](#xml-external-entity) | critical | high | XML External Entity (XXE) detected |
| [`xss-via-url`](#xss-via-url) | medium | medium | Potential XSS via URL parameters |
| [`xxe`](#xxe) | critical | high | XXE protection disabled |

## Pattern details

### api-key-exposure

API key in source code

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `api-key`, `security`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9]{16,}
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
api-key = 'xJEX3mzf…ff
```

### command-injection

Potential OS command injection

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `command-injection`, `security`, `os` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(exec|spawn|system|popen)\s*\([^)]*\+
```

**Reference**: <https://owasp.org/www-community/attacks/Command_Injection>

**Input that fires** (verified by the liveness test):

```text
exec (EcsL=sox9zi4H+
```

### content-security-policy

Content-Security-Policy header detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `csp`, `security`, `xss` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)Content-Security-Policy
```

**Reference**: <https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
Content-…cy
```

### cors-misconfiguration

CORS misconfiguration detected (wildcard origin)

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cors`, `security`, `web` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(Access-Control-Allow-Origin.*\*|allow.*origin.*\*)
```

**Reference**: <https://owasp.org/www-community/attacks/csrf>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
Access-C…n7*
```

### csrf-missing-token

State-changing operation may lack CSRF protection

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.js`, `.ts`, `.jsx`, `.tsx`, `.vue`, `.svelte`, `.php`, `.rb`, `.py`, `.java`, `.kt`, `.cs` |
| Binary files | skipped |
| Tags | `csrf`, `security`, `web` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:app|router|server|express|fastify|koa|route)\s*\.\s*(?:post|put|delete|patch)\s*\([^)]*\)
```

**Reference**: <https://owasp.org/www-community/attacks/csrf>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
app . post (ubQAqzpG…bp)
```

### csrf-token-header

CSRF token header detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `csrf`, `security`, `token` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)X-CSRF-Token|XSRF-TOKEN|csrf-token
```

**Reference**: <https://owasp.org/www-community/attacks/csrf>

**Input that fires** (verified by the liveness test):

```text
X-CSRF-Token
```

### debug-mode

Debug mode enabled in production

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.js`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.jsx`, `.yaml`, `.yml`, `.json`, `.env` |
| Binary files | skipped |
| Tags | `debug`, `security`, `disclosure` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(debug\s*=\s*true|DEBUG\s*=\s*true|app\.env\s*=\s*['\"]dev['\"])
```

**Input that fires** (verified by the liveness test):

```text
debug = true
```

### directory-traversal

URL-encoded directory traversal sequence detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `path-traversal`, `security`, `injection` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(?:%2e%2e(?:%2f|%5c)|\.\.%2f|\.\.%5c)
```

**Reference**: <https://owasp.org/www-community/attacks/Path_Traversal>

**Input that fires** (verified by the liveness test):

```text
%2e%2e%2f
```

### dom-xss

Potential DOM XSS vulnerability

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.php`, `.vue`, `.svelte`, `.html`, `.htm` |
| Binary files | skipped |
| Tags | `xss`, `security`, `dom` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(?:document\.write(?:ln)?\s*\(|\beval\s*\(|new\s+Function\s*\()
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)\bexample\.(?:com|org|net)\b
```
**Reference**: <https://owasp.org/www-community/attacks/xss/>

**Input that fires** (verified by the liveness test):

```text
document.writeln (
```

### executable-file-upload

Executable file upload detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `file-upload`, `security`, `rce` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\.(exe|sh|php|asp|jsp)\s*.*upload|move_uploaded_file
```

**Reference**: <https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload>

**Input that fires** (verified by the liveness test):

```text
.exe 7upload
```

### graphql-batch-limit

GraphQL depth limiting detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `graphql`, `security`, `depth-limit` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)query\s*depth|maxDepth|batch.*limit
```

**Input that fires** (verified by the liveness test):

```text
query depth
```

### graphql-introspection

GraphQL introspection enabled

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `graphql`, `security`, `introspection` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)introspection.*true|__schema
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
introspe…o2.@5rXmNtrue
```

### hardcoded-credential

Hardcoded credential detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `credential`, `security`, `hardcoded` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(username|password|credential)\s*=\s*['\"][^'\"]{4,}
```

**Reference**: <https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
username = 'CiXXMh-p…4X
```

### hsts-missing

HSTS header not detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `hsts`, `security`, `https` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)Strict-Transport-Security
```

**Reference**: <https://hstspreload.org/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
Strict-T…ty
```

### insecure-deserialization

Potential insecure deserialization

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `deserialization`, `security`, `rce` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(unpickle|unserialize|ObjectInputStream|YAML\.load)\s*\(
```

**Reference**: <https://owasp.org/www-community/attacks/Insecure_Deserialization>

**Input that fires** (verified by the liveness test):

```text
unpickle (
```

### jwt-none-algorithm

JWT with 'none' algorithm detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `jwt`, `security`, `algorithm` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\balg(?:orithm)?\s*["']?\s*[:=]\s*["']?\s*none\b
```

**Reference**: <https://owasp.org/www-project-web-security-testing/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens>

**Input that fires** (verified by the liveness test):

```text
algorithm " : " none
```

### missing-authentication

API endpoint may lack authentication

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `authentication`, `security`, `api` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(@GetMapping|@PostMapping|@RequestMapping)
```

**Input that fires** (verified by the liveness test):

```text
@GetMapping
```

### missing-security-headers

Security headers detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `security-headers`, `security`, `web` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)X-Content-Type-Options|X-XSS-Protection|Content-Security-Policy
```

**Reference**: <https://owasp.org/www-community/projects/verification>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
X-Conten…ns
```

### open-redirect

Potential open redirect vulnerability

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `redirect`, `security`, `phishing` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(redirect|forward|location)\s*\([^)]*request\.(params|query|body)
```

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html>

**Input that fires** (verified by the liveness test):

```text
redirect (m=wikrequest.params
```

### path-traversal

Potential path traversal vulnerability

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `path-traversal`, `security`, `file` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(readFile|readFileSync|open|fs\.).*\+.*(?:user|input|param|query)
```

**Reference**: <https://owasp.org/www-community/attacks/Path_Traversal>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
readFile…vi+WM_user
```

### rate-limit-missing

Authentication route without visible rate limiting; brute-force protection not evident

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `rate-limiting`, `security`, `api` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:post|put|patch)\s*\(\s*['"][^'"]*(?:login|auth|signin|sign-in|register|signup|password)[^'"]*['"]
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)rate[_-]?limit|throttle|brute|slowdown
```
**Reference**: <https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
post ( "ysWZW4Hm…FL'
```

### redirect-to-relative

Redirect to relative path

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `redirect`, `security`, `relative` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)redirect\s*\(\s*\/[^\)]
```

**Input that fires** (verified by the liveness test):

```text
redirect ( /e
```

### reflected-xss

Potential reflected XSS vulnerability

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `xss`, `security`, `web` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(request\.params|request\.query|request\.body|req\.params)\.[\w_]+\s*\+
```

**Reference**: <https://owasp.org/www-community/attacks/xss/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
request.params.1w_57__9…oq +
```

### server-version

Server version header detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `server`, `security`, `disclosure` |

**Match pattern** (Rust `regex` syntax):

```regex
(?im)^\s*(?:server|x-powered-by|x-aspnet-version|x-aspnetmvc-version|x-generator)\s*:\s*\S[^\n]{0,80}$
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
 server : Tih8mkRt…NF+BHc/wTHaZMRq…2R VHobTwNA:wiQbyy
```

### session-fixation

Potential session fixation vulnerability

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `session`, `security`, `authentication` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)session\s*=\s*request\.getParameter|sessionId.*getParameter
```

**Reference**: <https://owasp.org/www-community/attacks/Session_fixation>

**Input that fires** (verified by the liveness test):

```text
session = request.getParameter
```

### sql-injection

Potential SQL injection vulnerability

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `sql`, `injection`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)query\s*\([^)]*\+[^)]*\)
```

**Reference**: <https://owasp.org/www-community/attacks/SQL_Injection>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
query (qm3-JCa9…BS+g6hZ7.RA7c/Hsf_X)
```

### ssrf

Potential Server-Side Request Forgery (SSRF)

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ssrf`, `security`, `web` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(fetch|axios|request|httpClient)\s*\(.*(?:url|uri|href|src).*\)
```

**Reference**: <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
fetch (tN3L.5NQurl_3…gD)
```

### ssrf-localhost

Potential SSRF targeting internal resources

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ssrf`, `security`, `internal` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|metadata\.google)
```

**Reference**: <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery>

**Input that fires** (verified by the liveness test):

```text
localhost
```

### stack-trace-exposure

Stack trace exposure detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `stack-trace`, `security`, `disclosure` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)stack\s*trace|exception.*print|printStackTrace
```

**Input that fires** (verified by the liveness test):

```text
stack trace
```

### stored-xss

Potential stored XSS via innerHTML

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `xss`, `security`, `stored` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)innerHTML\s*=|outerHTML\s*=
```

**Reference**: <https://owasp.org/www-community/attacks/xss/>

**Input that fires** (verified by the liveness test):

```text
innerHTML =
```

### unrestricted-file-upload

File upload without validation

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `file-upload`, `security`, `web` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(multipart|fileUpload|uploadFile).*without.*validation
```

**Reference**: <https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
multipar…on
```

### weak-password-hash

Weak password hashing algorithm detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `password`, `security`, `hashing` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(md5|sha1|des|crypt)\s*\(.*password
```

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>

**Input that fires** (verified by the liveness test):

```text
md5 (F_/o6/4i2password
```

### x-content-type-options

X-Content-Type-Options header detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `x-content-type-options`, `security`, `mime` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)X-Content-Type-Options.*nosniff
```

**Reference**: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
X-Conten…ff
```

### x-frame-options

X-Frame-Options header detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `x-frame-options`, `security`, `clickjacking` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)X-Frame-Options
```

**Reference**: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
X-Frame-…ns
```

### xml-external-entity

XML External Entity (XXE) detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `xxe`, `security`, `xml` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)<!ENTITY|SYSTEM\s+\"|PUBLIC\s+\"
```

**Reference**: <https://owasp.org/www-community/attacks/XML_External_Entities_(XXE)_Processing>

**Input that fires** (verified by the liveness test):

```text
<!ENTITY
```

### xss-via-url

Potential XSS via URL parameters

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `xss`, `security`, `url` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(window\.location|document\.URL|document\.referrer)[^\;]*\+
```

**Reference**: <https://owasp.org/www-community/attacks/xss/>

**Input that fires** (verified by the liveness test):

```text
window.locationtYL+u xZ+j_JP++
```

### xxe

XXE protection disabled

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `xxe`, `security`, `xml` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(DocumentBuilder|SAXParser|XMLReader|XMLInputFactory).*disabled
```

**Reference**: <https://owasp.org/www-community/attacks/XML_External_Entities_(XXE)_Processing>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
Document…ed
```
