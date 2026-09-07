# frameworks patterns

Web framework-specific issues

**31 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`angular-bypass-security-trust`](#angular-bypass-security-trust) | high | high | Angular security bypass detected. bypassSecurityTrust calls disable Angular's built-in XSS protection. |
| [`angular-innerhtml-xss`](#angular-innerhtml-xss) | high | high | Angular innerHTML assignment detected. This can introduce XSS vulnerabilities. |
| [`django-csrf-exempt`](#django-csrf-exempt) | high | high | Missing CSRF protection. Forms should include CSRF tokens. |
| [`django-debug-print`](#django-debug-print) | low | high | Debug code should be removed before production deployment. |
| [`django-secret-key-hardcoded`](#django-secret-key-hardcoded) | high | high | Hardcoded Django SECRET_KEY detected. Use environment variables instead. |
| [`express-eval-usage`](#express-eval-usage) | high | high | Express.js eval() with user input detected. This can lead to remote code execution. |
| [`express-sql-injection`](#express-sql-injection) | high | high | Express.js SQL query with template literal interpolation detected. This can lead to SQL injection. |
| [`flask-debug-enabled`](#flask-debug-enabled) | medium | high | Flask debug mode enabled. This should be disabled in production. |
| [`flask-sqlalchemy-raw-sql`](#flask-sqlalchemy-raw-sql) | high | high | Flask-SQLAlchemy raw SQL with string interpolation detected. This can lead to SQL injection. |
| [`go-defer-goroutine-leak`](#go-defer-goroutine-leak) | high | high | defer with goroutine may cause goroutine leak. |
| [`go-json-marshal-error-ignore`](#go-json-marshal-error-ignore) | medium | high | json.Marshal/Unmarshal result checked without error handling. |
| [`go-strconv-error-ignore`](#go-strconv-error-ignore) | medium | high | strconv function result used without error check. |
| [`laravel-app-key-hardcoded`](#laravel-app-key-hardcoded) | high | high | Laravel APP_KEY hardcoded in source. This should be stored in environment variables. |
| [`laravel-raw-db-query`](#laravel-raw-db-query) | high | high | Laravel raw database query with string formatting detected. This can lead to SQL injection. |
| [`nodejs-hardcoded-jwt-secret`](#nodejs-hardcoded-jwt-secret) | high | high | Hardcoded JWT secret detected. Use environment variables instead. |
| [`nodejs-sync-fs-readfile`](#nodejs-sync-fs-readfile) | high | high | Synchronous file read detected. Use async version for better performance. |
| [`nodejs-todo-development`](#nodejs-todo-development) | low | high | TODO/FIXME comment detected. Pending tasks should be tracked in issue tracker. |
| [`rails-raw-sql-injection`](#rails-raw-sql-injection) | high | high | Rails raw SQL execution detected. This can lead to SQL injection. |
| [`rails-secret-key-hardcoded`](#rails-secret-key-hardcoded) | high | high | Rails secret key hardcoded in source. Use environment variables. |
| [`react-console-log-dev`](#react-console-log-dev) | low | high | Debug logging detected. Remove before production deployment. |
| [`react-missing-key-prop`](#react-missing-key-prop) | low | high | React map without key prop detected. |
| [`rust-env-macro`](#rust-env-macro) | medium | high | Rust env! macro detected. This will panic if environment variable is not set. |
| [`rust-expect-usage`](#rust-expect-usage) | medium | high | Rust .expect() call detected. This can panic. |
| [`rust-hardcoded-secret`](#rust-hardcoded-secret) | critical | high | Hardcoded secret detected in Rust code. |
| [`rust-println-debug`](#rust-println-debug) | low | high | Rust debug println! with formatting detected. |
| [`rust-unsafe-block`](#rust-unsafe-block) | high | high | Rust unsafe block detected. Bypasses memory safety guarantees. |
| [`rust-unsafe-extern`](#rust-unsafe-extern) | high | high | Rust unsafe extern block detected. |
| [`rust-unwrap-usage`](#rust-unwrap-usage) | medium | high | Rust .unwrap() call detected. This can panic. |
| [`spring-deserialization-read-object`](#spring-deserialization-read-object) | high | high | Java deserialization detected. Unsafe deserialization can lead to RCE. |
| [`vue-template-injection`](#vue-template-injection) | high | high | Vue.js template injection detected. |
| [`vue-v-html-xss`](#vue-v-html-xss) | high | high | Vue.js v-html directive detected. This can introduce XSS vulnerabilities. |

## Pattern details

### angular-bypass-security-trust

Angular security bypass detected. bypassSecurityTrust calls disable Angular's built-in XSS protection.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `angular`, `xss`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
\.bypassSecurityTrust(HTML|Url|Script|Style|ResourceUrl)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
.bypassSe…ML
```

### angular-innerhtml-xss

Angular innerHTML assignment detected. This can introduce XSS vulnerabilities.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `angular`, `xss`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
\.innerHTML\s*=
```

**Input that fires** (verified by the liveness test):

```text
.innerHTML =
```

### django-csrf-exempt

Missing CSRF protection. Forms should include CSRF tokens.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `django`, `csrf`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
@csrf_exempt\b
```

**Input that fires** (verified by the liveness test):

```text
@csrf_exempt
```

### django-debug-print

Debug code should be removed before production deployment.

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.py` |
| Binary files | skipped |
| Tags | `django`, `debug`, `python` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(print\(.*request|DEBUG\s*=\s*True|django.*debug)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
print(_nc_mJfZ…st
```

### django-secret-key-hardcoded

Hardcoded Django SECRET_KEY detected. Use environment variables instead.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `django`, `secret`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
\bSECRET_KEY\s*=\s*["\x27][^\x27"]{20,}["\x27]
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
SECRET_KEY = "c/+pcwr6jgc…LV:+"
```

### express-eval-usage

Express.js eval() with user input detected. This can lead to remote code execution.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `express`, `nodejs`, `rce` |

**Match pattern** (Rust `regex` syntax):

```regex
eval\s*\(.*(?:req|request|body|params|query)
```

**Input that fires** (verified by the liveness test):

```text
eval (pcZnmXH/scExkreq
```

### express-sql-injection

Express.js SQL query with template literal interpolation detected. This can lead to SQL injection.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `express`, `nodejs`, `sql-injection` |

**Match pattern** (Rust `regex` syntax):

```regex
(query|execute)\s*\(.*[\+\`].*\$\{
```

**Input that fires** (verified by the liveness test):

```text
query (.x84g8R 5`dNVnPnm9${
```

### flask-debug-enabled

Flask debug mode enabled. This should be disabled in production.

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `flask`, `python`, `debug` |

**Match pattern** (Rust `regex` syntax):

```regex
app\.run\s*\([^)]*debug\s*=\s*True
```

**Input that fires** (verified by the liveness test):

```text
app.run (fdebug = True
```

### flask-sqlalchemy-raw-sql

Flask-SQLAlchemy raw SQL with string interpolation detected. This can lead to SQL injection.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `flask`, `sqlalchemy`, `sql-injection` |

**Match pattern** (Rust `regex` syntax):

```regex
(execute|raw_sql)\s*\(.*[%\#\{]
```

**Input that fires** (verified by the liveness test):

```text
execute (s/d4sDKQCY#
```

### go-defer-goroutine-leak

defer with goroutine may cause goroutine leak.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `go`, `goroutine`, `concurrency` |

**Match pattern** (Rust `regex` syntax):

```regex
defer\s+go\s+
```

**Input that fires** (verified by the liveness test):

```text
defer go 
```

### go-json-marshal-error-ignore

json.Marshal/Unmarshal result checked without error handling.

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `go`, `json`, `error-handling` |

**Match pattern** (Rust `regex` syntax):

```regex
json\.(Marshal|Unmarshal)\([^,)]+,\s*[^)]+\)\s*$
```

**Input that fires** (verified by the liveness test):

```text
json.Marshal(=X, zZksfMS) 
```

### go-strconv-error-ignore

strconv function result used without error check.

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `go`, `strconv`, `error-handling` |

**Match pattern** (Rust `regex` syntax):

```regex
strconv\.(ParseInt|ParseUint|ParseFloat|ParseBool)\([^)]+\)[^\s]
```

**Input that fires** (verified by the liveness test):

```text
strconv.ParseInt(Z5y:gGTQVgC)d
```

### laravel-app-key-hardcoded

Laravel APP_KEY hardcoded in source. This should be stored in environment variables.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `laravel`, `php`, `secret` |

**Match pattern** (Rust `regex` syntax):

```regex
APP_KEY\s*=\s*(base64:)?[a-zA-Z0-9\/+=]{32,}
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
APP_KEY = base64:YEjWYhPJ…uL=C+6Wa=PQTqwE8n…eb
```

### laravel-raw-db-query

Laravel raw database query with string formatting detected. This can lead to SQL injection.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `laravel`, `php`, `sql-injection` |

**Match pattern** (Rust `regex` syntax):

```regex
DB::(?:select|statement|unprepared)\s*\(.*["\'].*%s
```

**Input that fires** (verified by the liveness test):

```text
DB::select (X6A8J@8QC_8"9Cz-k8MjxPs_ %s
```

### nodejs-hardcoded-jwt-secret

Hardcoded JWT secret detected. Use environment variables instead.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `nodejs`, `jwt`, `secret` |

**Match pattern** (Rust `regex` syntax):

```regex
\b(jwt\.sign|jsonwebtoken\.sign)\s*\(\s*[^,]+,\s*["\x27][A-Za-z0-9_\-]{16,}["\x27]
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
jsonwebtoken.sign ( ZUZ=+bg+-dAM, "Bzh5H4z_…Dr"
```

### nodejs-sync-fs-readfile

Synchronous file read detected. Use async version for better performance.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `nodejs`, `filesystem`, `performance` |

**Match pattern** (Rust `regex` syntax):

```regex
\bfs\.readFileSync\s*\(
```

**Input that fires** (verified by the liveness test):

```text
fs.readFileSync (
```

### nodejs-todo-development

TODO/FIXME comment detected. Pending tasks should be tracked in issue tracker.

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `nodejs`, `code-quality`, `todo` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(console\.log.*todo|\/\/\s*TODO.*fixme|FIXME.*console\.log)
```

**Input that fires** (verified by the liveness test):

```text
console.logXcGDtodo
```

### rails-raw-sql-injection

Rails raw SQL execution detected. This can lead to SQL injection.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `rails`, `ruby`, `sql-injection` |

**Match pattern** (Rust `regex` syntax):

```regex
\.execute\s*\(.*[#\{]
```

**Input that fires** (verified by the liveness test):

```text
.execute (Z_.8WJUsaaGWHz{
```

### rails-secret-key-hardcoded

Rails secret key hardcoded in source. Use environment variables.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `rails`, `ruby`, `secret` |

**Match pattern** (Rust `regex` syntax):

```regex
(secret_key_base|secret_token)\s*=\s*["'][a-f0-9]{64}["']
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
secret_k…se = "bdc9cdae…95'
```

### react-console-log-dev

Debug logging detected. Remove before production deployment.

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `react`, `javascript`, `debug` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(console\.log|console\.debug|console\.warn).*development|if.*process\.env\.NODE_ENV.*development
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
console.logEcqcJ…nt
```

### react-missing-key-prop

React map without key prop detected.

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `react`, `javascript`, `jsx` |

**Match pattern** (Rust `regex` syntax):

```regex
\.\s*map\s*\([^)]*\)\s*=>\s*[<\(]
```

**Input that fires** (verified by the liveness test):

```text
. map (SoxvoBWg.r5) => <
```

### rust-env-macro

Rust env! macro detected. This will panic if environment variable is not set.

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `rust`, `env`, `panic` |

**Match pattern** (Rust `regex` syntax):

```regex
env!\s*\(
```

**Input that fires** (verified by the liveness test):

```text
env! (
```

### rust-expect-usage

Rust .expect() call detected. This can panic.

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `rust`, `error-handling`, `panic` |

**Match pattern** (Rust `regex` syntax):

```regex
\.expect\(
```

**Input that fires** (verified by the liveness test):

```text
.expect(
```

### rust-hardcoded-secret

Hardcoded secret detected in Rust code.

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `rust`, `secret`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
(api_key|apiKey|secret|password|token|credential)\s*[:=]\s*["\'][^"\'\s]{8,}["\']
```

**Input that fires** (verified by the liveness test):

```text
api_key : 'f5=:v./AdCkqzFbWT'
```

### rust-println-debug

Rust debug println! with formatting detected.

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `rust`, `debug`, `println` |

**Match pattern** (Rust `regex` syntax):

```regex
println!\s*\(\s*"[^"]*\{:?\?:[^}]*\}[^"]*"\s*,
```

**Input that fires** (verified by the liveness test):

```text
println! ( "rPU3s9{:?:=ESD}vEh/FUoh" ,
```

### rust-unsafe-block

Rust unsafe block detected. Bypasses memory safety guarantees.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `rust`, `unsafe`, `memory-safety` |

**Match pattern** (Rust `regex` syntax):

```regex
unsafe\s*\{[^}]*\}
```

**Input that fires** (verified by the liveness test):

```text
unsafe {fwiQuw-CnH_.k}
```

### rust-unsafe-extern

Rust unsafe extern block detected.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `rust`, `unsafe`, `ffi` |

**Match pattern** (Rust `regex` syntax):

```regex
extern\s*"[^"]*"\s*\{
```

**Input that fires** (verified by the liveness test):

```text
extern "=ibNv4nmdJrR" {
```

### rust-unwrap-usage

Rust .unwrap() call detected. This can panic.

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `rust`, `error-handling`, `panic` |

**Match pattern** (Rust `regex` syntax):

```regex
\.unwrap\(\)
```

**Input that fires** (verified by the liveness test):

```text
.unwrap()
```

### spring-deserialization-read-object

Java deserialization detected. Unsafe deserialization can lead to RCE.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `spring`, `java`, `deserialization` |

**Match pattern** (Rust `regex` syntax):

```regex
(ObjectInputStream|readObject)\s*\(\s*\)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
ObjectIn…am ( )
```

### vue-template-injection

Vue.js template injection detected.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `vue`, `template-injection`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
:[a-z]+=["'][^"]*request|:[a-z]+=["'][^"]*input|:[a-z]+=["'][^"]*params
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
:ohtmfwxw…or="/tU_request
```

### vue-v-html-xss

Vue.js v-html directive detected. This can introduce XSS vulnerabilities.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `vue`, `xss`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
v-html=["'][^"']{10,}["']
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
v-html="v 6yeBGrRp…LD'
```
