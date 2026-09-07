# security-hardening patterns

General hardening practices

**32 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`aws-secret-key`](#aws-secret-key) | critical | high | AWS secret access key detected |
| [`basic-auth-url`](#basic-auth-url) | high | high | Basic authentication credentials in URL |
| [`bearer-token-url`](#bearer-token-url) | medium | high | Bearer token detected in code |
| [`deserialization-vulnerability`](#deserialization-vulnerability) | critical | high | Potential insecure deserialization vulnerability |
| [`eval-usage`](#eval-usage) | high | high | Dangerous eval() usage detected |
| [`github-token`](#github-token) | critical | high | GitHub token detected |
| [`hardcoded-encryption-key`](#hardcoded-encryption-key) | critical | high | Hardcoded encryption key detected |
| [`hardcoded-iv`](#hardcoded-iv) | high | high | Hardcoded IV detected for encryption |
| [`insecure-cookie`](#insecure-cookie) | medium | high | Insecure cookie configuration detected |
| [`insecure-random`](#insecure-random) | medium | high | Insecure random number generation (Math.random) |
| [`jwt-secret-hardcoded`](#jwt-secret-hardcoded) | high | high | Hardcoded JWT secret detected |
| [`ldap-injection`](#ldap-injection) | high | medium | Potential LDAP injection vulnerability |
| [`mailgun-api-key`](#mailgun-api-key) | critical | medium | Mailgun API key detected |
| [`password-in-url`](#password-in-url) | high | high | Password embedded in URL detected |
| [`private-key-exposed`](#private-key-exposed) | critical | high | Private key exposed in code |
| [`security-hardening-aws-access-key`](#security-hardening-aws-access-key) | critical | high | AWS access key ID detected |
| [`security-hardening-command-injection`](#security-hardening-command-injection) | critical | medium | Potential command injection vulnerability |
| [`security-hardening-jwt-none-algorithm`](#security-hardening-jwt-none-algorithm) | critical | high | JWT 'none' algorithm vulnerability detected |
| [`security-hardening-path-traversal`](#security-hardening-path-traversal) | high | medium | Potential path traversal vulnerability |
| [`security-hardening-xml-external-entity`](#security-hardening-xml-external-entity) | critical | high | XML External Entity (XXE) vulnerability detected |
| [`sendgrid-api-key`](#sendgrid-api-key) | critical | high | SendGrid API key detected |
| [`sensitive-file-access`](#sensitive-file-access) | medium | medium | Access to sensitive system files detected |
| [`setuid-root`](#setuid-root) | high | medium | Setuid/Setgid permissions detected |
| [`slack-token`](#slack-token) | critical | high | Slack token detected |
| [`sql-query`](#sql-query) | low | low | SQL query detected (potential SQL injection) |
| [`ssti-template`](#ssti-template) | high | medium | Potential server-side template injection |
| [`stripe-api-key`](#stripe-api-key) | critical | high | Stripe API key detected |
| [`twilio-api-key`](#twilio-api-key) | critical | high | Twilio API key detected |
| [`weak-ssl`](#weak-ssl) | high | high | Weak cryptographic protocol/algorithm detected |
| [`world-writable`](#world-writable) | high | high | World-writable file permissions detected |
| [`xpath-injection`](#xpath-injection) | high | medium | Potential XPath injection vulnerability |
| [`xss-vulnerability`](#xss-vulnerability) | high | medium | Potential XSS vulnerability (unsafe DOM manipulation) |

## Pattern details

### aws-secret-key

AWS secret access key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `5` |
| Tags | `aws`, `security`, `secrets` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)aws_secret_?(access_key|key)\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
aws_secr…ey = 'TqQ4+NthUFfHwSGm/kAP3d6nu…iX
```

### basic-auth-url

Basic authentication credentials in URL

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `security`, `auth`, `credentials` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\bhttps?://[^\s:/@]+:[^\s/@]+@[^\s"'<>]*
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)\bexample\.(?:com|org|net)\b|[<{\[]|username\s*:\s*password|user\s*:\s*pass\b
```
**Input that fires** (verified by the liveness test):

```text
https://-N7.2fvLaBD:BmD@tngeHw
```

### bearer-token-url

Bearer token detected in code

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `security`, `auth`, `token` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)bearer\s+[A-Za-z0-9_\-\.]+
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
bearer uw8Ynyke…kK
```

### deserialization-vulnerability

Potential insecure deserialization vulnerability

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

### eval-usage

Dangerous eval() usage detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `security`, `eval`, `rce` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\beval\s*\(
```

**Input that fires** (verified by the liveness test):

```text
eval (
```

### github-token

GitHub token detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `5` |
| Tags | `github`, `security`, `secrets` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
ghu_Eqfc…eN
```

### hardcoded-encryption-key

Hardcoded encryption key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `3.5` |
| Tags | `crypto`, `secrets` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(encryption_key|encrypt_key|crypto_key)\s*[:=]\s*['"][^'"]{8,}
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
encrypti…ey = 'BQtH9GnQ…Un
```

### hardcoded-iv

Hardcoded IV detected for encryption

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `3.5` |
| Tags | `crypto`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(iv|initialization_vector)\s*[:=]\s*['"][a-fA-F0-9]{16,}
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
iv = 'F845d3EB…a4
```

### insecure-cookie

Insecure cookie configuration detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cookie`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)cookie.*(secure|samesite).*=.*false
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
cookie56…8p=82kkVeRk…se
```

### insecure-random

Insecure random number generation (Math.random)

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `security`, `random` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)Math\.random\(\)
```

**Input that fires** (verified by the liveness test):

```text
Math.random()
```

### jwt-secret-hardcoded

Hardcoded JWT secret detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4` |
| Tags | `jwt`, `security`, `secrets` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(jwt|json.web.token)\s*[:=]\s*['"][^'\"]{16,}
```

**Input that fires** (verified by the liveness test):

```text
jwt = "u 5GM::3i/FkWvGq mrvDqr
```

### ldap-injection

Potential LDAP injection vulnerability

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ldap`, `injection`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(ldap|LDAP).*\+.*request|screen\s*name
```

**Input that fires** (verified by the liveness test):

```text
ldapT9H2 UMb7H2+5request
```

### mailgun-api-key

Mailgun API key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4.5` |
| Tags | `mailgun`, `security`, `secrets` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(key|api)[_-]?(key)?\s*[:=]\s*['\"][a-zA-Z0-9]{32}
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
key-key : 'bQncDx2x…8i
```

### password-in-url

Password embedded in URL detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `security`, `credentials`, `url` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\bhttps?://[^\s:/@]+:[^\s/@]+@[^\s"'<>]*
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)\bexample\.(?:com|org|net)\b|[<{\[]|username\s*:\s*password|user\s*:\s*pass\b
```
**Input that fires** (verified by the liveness test):

```text
https://93AC9X3A:SQoWYE8s.ewFns@ez
```

### private-key-exposed

Private key exposed in code

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `5` |
| Tags | `crypto`, `security`, `keys` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(PRIVATE\s+KEY|-----\s*BEGIN\s+.*PRIVATE\s+KEY-----)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
----- BEGIN DpjG zZta2Kfc@u3YLdQN6…ne.r_PRIVATE KEY-----
```

### security-hardening-aws-access-key

AWS access key ID detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `3.5` |
| Tags | `aws`, `security`, `secrets` |

**Match pattern** (Rust `regex` syntax):

```regex
\b(ABIA|ACCA|ASIA)[A-Z0-9]{16}\b
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
ABIA8TWB…G7
```

### security-hardening-command-injection

Potential command injection vulnerability

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `injection`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(exec|system|popen|shell_exec)\s*\(\s*["'].*\$\{?[\w_]
```

**Reference**: <https://owasp.org/www-community/attacks/Command_Injection>

**Input that fires** (verified by the liveness test):

```text
exec ( "8XVn@czUKWm-${c
```

### security-hardening-jwt-none-algorithm

JWT 'none' algorithm vulnerability detected

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
algorithm ' : " none
```

### security-hardening-path-traversal

Potential path traversal vulnerability

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `injection`, `security`, `path` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:open|read|readFile|readFileSync|writeFile|unlink|load|include|require|join|fopen|sendFile|createReadStream|createWriteStream|Path)[\w:.!]*\s*\([^)\n]*\+[^)\n]*(?:req\.|params|query|user|input)
```

**Reference**: <https://owasp.org/www-community/attacks/Path_Traversal>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
openS84J…bz (UtadUk22…tE+=Jw6wLw2p:req.
```

### security-hardening-xml-external-entity

XML External Entity (XXE) vulnerability detected

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

### sendgrid-api-key

SendGrid API key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `5` |
| Tags | `sendgrid`, `security`, `secrets` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
SG.RDHt2PyJ…Xf.yMCU7Fu5…ZZ
```

### sensitive-file-access

Access to sensitive system files detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `security`, `filesystem` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(/etc/passwd|/etc/shadow|\.ssh|\.aws|\.git/config)
```

**Input that fires** (verified by the liveness test):

```text
/etc/passwd
```

### setuid-root

Setuid/Setgid permissions detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `security`, `permissions`, `linux` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)chmod\s+[47]\d{3}
```

**Input that fires** (verified by the liveness test):

```text
chmod 7535
```

### slack-token

Slack token detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `5` |
| Tags | `slack`, `security`, `secrets` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z0-9]+
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
xoxp-247…gD
```

### sql-query

SQL query detected (potential SQL injection)

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `sql`, `database` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)['"][^'"\n]{0,300}?(?:\bselect\s+[^'\"\n]{0,200}?\bfrom\s|\binsert\s+into\s|\bdelete\s+from\s|\bupdate\s+\w+\s+set\s|\bdrop\s+(?:table|database|schema)\s|\balter\s+table\s)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
' GmJkdS93…Fh:Q-Mfrng.oDR+/=suz4_y2H…bM+alter table 
```

### ssti-template

Potential server-side template injection

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ssti`, `injection`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(template|render|view)\s*\.\s*(format|render|make)
```

**Input that fires** (verified by the liveness test):

```text
template . format
```

### stripe-api-key

Stripe API key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `5` |
| Tags | `stripe`, `security`, `secrets` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
sk_live_…pT
```

### twilio-api-key

Twilio API key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `5` |
| Tags | `twilio`, `security`, `secrets` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)SK[a-zA-Z0-9]{32}
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
SKUkvBVS…Eq
```

### weak-ssl

Weak cryptographic protocol/algorithm detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `crypto`, `security`, `ssl` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(ssl_v2|ssl_v3|tls_1[01]|md5|sha1)\s*[=:]
```

**Reference**: <https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure>

**Input that fires** (verified by the liveness test):

```text
ssl_v2 :
```

### world-writable

World-writable file permissions detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `security`, `permissions` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)chmod\s+777|chmod\s+a\+rw
```

**Input that fires** (verified by the liveness test):

```text
chmod 777
```

### xpath-injection

Potential XPath injection vulnerability

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `xpath`, `injection`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(?:xpath|XPath)[^\n]*\+[^\n]*(?:input|param|query)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
xpathLSL…tm+W4/TS=-Drinput
```

### xss-vulnerability

Potential XSS vulnerability (unsafe DOM manipulation)

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `xss`, `security`, `javascript` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(innerHTML|outerHTML|document\.write)\s*\([^)]*\+
```

**Reference**: <https://owasp.org/www-community/attacks/xss/>

**Input that fires** (verified by the liveness test):

```text
innerHTML (DK-+
```
