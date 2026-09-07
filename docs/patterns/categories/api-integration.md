# api-integration patterns

HTTP client and webhook integration mistakes

**9 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`api-client-no-timeout`](#api-client-no-timeout) | low | medium | HTTP client created without a timeout |
| [`api-key-in-query-param`](#api-key-in-query-param) | high | high | Credential passed in a URL query string; use an Authorization header instead |
| [`api-polling-loop`](#api-polling-loop) | low | medium | Fixed-interval polling loop with fetch; prefer event-driven updates or exponential backoff |
| [`api-response-status-unchecked`](#api-response-status-unchecked) | low | medium | Fetch response body parsed without a visible status check |
| [`bearer-token-logged`](#bearer-token-logged) | high | high | Authorization token passed to a logging call |
| [`cors-credentials-wildcard`](#cors-credentials-wildcard) | high | medium | CORS configured with wildcard origin and credentials together |
| [`hardcoded-internal-endpoint`](#hardcoded-internal-endpoint) | low | medium | Hardcoded localhost/internal endpoint; move base URLs to configuration |
| [`ssl-verification-disabled`](#ssl-verification-disabled) | high | high | TLS certificate verification disabled for an API client |
| [`webhook-signature-unchecked`](#webhook-signature-unchecked) | medium | medium | Webhook route registered without a visible signature check |

## Pattern details

### api-client-no-timeout

HTTP client created without a timeout

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx` |
| Binary files | skipped |
| Tags | `api-integration`, `reliability`, `timeout` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\baxios\.create\s*\(\s*\{[^}\n]*\}
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)\btimeout\b
```
**Reference**: <https://axios.rest/pages/advanced/request-config>

**Input that fires** (verified by the liveness test):

```text
axios.create ( {xY9Pk/D_QuEPV}
```

### api-key-in-query-param

Credential passed in a URL query string; use an Authorization header instead

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.py`, `.rb`, `.php`, `.go` |
| Binary files | skipped |
| Tags | `api-integration`, `secrets`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)[?&](?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|api[_-]?token)=['"]?[A-Za-z0-9_\-]{4,}
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)example\.(?:com|org|net)|your[-_]|placeholder|<[^>]*>|\$\{|insert[-_]?key|xxx
```
**Reference**: <https://cwe.mitre.org/data/definitions/598.html>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
?api_key="uAhgr95c…9o
```

### api-polling-loop

Fixed-interval polling loop with fetch; prefer event-driven updates or exponential backoff

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx` |
| Binary files | skipped |
| Tags | `api-integration`, `rate-limiting`, `performance` |

**Match pattern** (Rust `regex` syntax):

```regex
\bsetInterval\s*\([^)\n]{0,120}\bfetch\b
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
\bbackoff\b|\bjitter\b|\bretry\b
```
**Reference**: <https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/>

**Input that fires** (verified by the liveness test):

```text
setInterval (A4hRzrkvC==/iDkPao9S:fetch
```

### api-response-status-unchecked

Fetch response body parsed without a visible status check

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx` |
| Binary files | skipped |
| Tags | `api-integration`, `error-handling`, `reliability` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)await\s+[^;\n]{0,60}\bfetch\b[^;\n]{0,40}\.json\s*\(\s*\)
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)\.ok\b|\.status\b|checkStatus|assert
```
**Reference**: <https://developer.mozilla.org/en-US/docs/Web/API/Window/fetch>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
await ZzSE96gv…Jj:kLDbMYbK7je=od-u+93_.HwxLTDor…v6/Wn-s fetch+dSP/3aBU/f.json ( )
```

### bearer-token-logged

Authorization token passed to a logging call

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx` |
| Binary files | skipped |
| Tags | `api-integration`, `logging`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:console|logger|logging|log)\s*\.\s*(?:log|debug|info|warn|error|trace)\s*\([^)\n]*(?:authorization|bearer|auth[_-]?token|access[_-]?token)
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)redact|scrub|mask|placeholder|your[-_]?token
```
**Reference**: <https://cwe.mitre.org/data/definitions/532.html>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
console . log (brk4auth…on
```

### cors-credentials-wildcard

CORS configured with wildcard origin and credentials together

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.py`, `.rb`, `.php`, `.go` |
| Binary files | skipped |
| Tags | `api-integration`, `cors`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)Access-Control-Allow-Credentials['"\s:,]+true\b[^;\n]{0,120}Access-Control-Allow-Origin['"\s:]+\*|Access-Control-Allow-Origin['"\s:]+\*[^;\n]{0,120}Access-Control-Allow-Credentials['"\s:,]+true\b
```

**Reference**: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
Access-C…in :"' "':":' :"'  *LHmskezG…Ny+hqoY84c= .MUS2d/gjCvX_7Q…ZD:wutia9.DWy-Fxrf…qv=PoAu XnE/t92JNzdL…BK+Access-C…ls",' ::' ,"' ,":", ':"',: : ",',: "'':," ,": '"': ,:"', ,:true
```

### hardcoded-internal-endpoint

Hardcoded localhost/internal endpoint; move base URLs to configuration

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.py`, `.rb`, `.php`, `.go` |
| Binary files | skipped |
| Tags | `api-integration`, `configuration`, `portability` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)['"]https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|(?:[a-z0-9-]+\.)*(?:internal|local|lan))(?::\d+)?(?:/[^'"]*)?['"]
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)\btest\b|\bspec\b|\bmock\b|allow[_-]?origin|proxy|redirect
```
**Reference**: <https://12factor.net/config>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
"https://localhost:2/7iBxLSCL…ED"
```

### ssl-verification-disabled

TLS certificate verification disabled for an API client

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.py`, `.rb`, `.php`, `.go` |
| Binary files | skipped |
| Tags | `api-integration`, `tls`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)rejectUnauthorized\s*[:=]\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0\b|verify\s*[:=]\s*False\b|ssl[_-]?verify\s*[:=]\s*false|check_hostname\s*[:=]\s*False\b|InsecureSkipVerify\s*:\s*true\b|CURLOPT_SSL_VERIFYPEER\s*,\s*false\b
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)\b(?:example|test|spec|dummy|mock)\b
```
**Reference**: <https://cwe.mitre.org/data/definitions/295.html>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
rejectUn…ed = false
```

### webhook-signature-unchecked

Webhook route registered without a visible signature check

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.js`, `.ts`, `.py`, `.rb` |
| Binary files | skipped |
| Tags | `api-integration`, `webhooks`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:post|put)\s*\(\s*['"][^'"]*webhooks?[^'"]*['"][^\n]{0,200}
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)signature|signing[_-]?secret|hmac|\bverify|raw[_-]?body|x-hub|x-signature
```
**Reference**: <https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
post ( ":6zD7n-we…VE"eojXMNLZ…W6/w9m5+8CAJx5Ba-i=.hAMK6.t9TUZ5bc…2X.g=pDoA+.PR9ToAHo…3h.UPk2q o9.J.9wtmFtDbr TVWBZFJb…FA/9KDm62F
```
