# performance patterns

Performance anti-patterns

**20 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`box-inside-loop`](#box-inside-loop) | low | medium | Box allocation inside loop - consider alternatives |
| [`console-log-production`](#console-log-production) | low | high | Console logging in production code |
| [`document-write`](#document-write) | high | high | document.write() detected - blocks page parsing |
| [`event-listener-leak`](#event-listener-leak) | medium | medium | Event listener added without removeEventListener |
| [`expensive-computation-loop`](#expensive-computation-loop) | medium | medium | Expensive computation inside loop |
| [`force-reflow`](#force-reflow) | medium | high | Reading layout properties causes forced reflow |
| [`global-variable`](#global-variable) | low | medium | Global variable assignment detected |
| [`gzip-not-enabled`](#gzip-not-enabled) | medium | high | gzip compression not enabled |
| [`inner-html-assignment`](#inner-html-assignment) | medium | medium | innerHTML assignment may cause performance issues |
| [`missing-database-index`](#missing-database-index) | medium | low | CREATE TABLE without explicit index |
| [`missing-limit`](#missing-limit) | medium | high | Query missing LIMIT clause |
| [`n-plus-one-query`](#n-plus-one-query) | medium | low | Potential N+1 query pattern |
| [`no-cache-headers`](#no-cache-headers) | low | high | Cache headers not detected in response |
| [`no-connection-pool`](#no-connection-pool) | medium | medium | Database connection without pooling |
| [`regex-in-loop`](#regex-in-loop) | medium | high | Regex creation inside loop - compile outside |
| [`select-star`](#select-star) | low | high | SELECT * detected - consider selecting specific columns |
| [`string-concatenation-loop`](#string-concatenation-loop) | medium | high | String concatenation in loop - use StringBuilder or join() |
| [`sync-in-async`](#sync-in-async) | medium | medium | Blocking *Sync() call detected; prefer the async API |
| [`synchronous-xmlhttprequest`](#synchronous-xmlhttprequest) | high | high | Synchronous XMLHttpRequest blocks UI thread |
| [`unsized-image`](#unsized-image) | low | high | Image without explicit dimensions |

## Pattern details

### box-inside-loop

Box allocation inside loop - consider alternatives

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `performance`, `memory`, `allocation` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)for\s*\{[^}]*Box::new
```

**Input that fires** (verified by the liveness test):

```text
for {dDcfBox::new
```

### console-log-production

Console logging in production code

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `performance`, `javascript`, `logging` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)console\.(log|debug|info).*\/|\s*\(.*\).*eslint
```

**Input that fires** (verified by the liveness test):

```text
console.logm5M_Z/
```

### document-write

document.write() detected - blocks page parsing

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `performance`, `javascript`, `blocking` |

**Match pattern** (Rust `regex` syntax):

```regex
document\.write
```

**Input that fires** (verified by the liveness test):

```text
document.write
```

### event-listener-leak

Event listener added without removeEventListener

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `performance`, `javascript`, `memory-leak` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)addEventListener
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
addEvent…er
```

### expensive-computation-loop

Expensive computation inside loop

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `performance`, `cpu`, `loop` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)for\s*\(.*\)\s*\{[^}]*(Math\.|pow\(|sqrt\(|cos\(|sin\()
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
for (HWRX5NwU…xK.) {WSBxH7WMath.
```

### force-reflow

Reading layout properties causes forced reflow

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `performance`, `javascript`, `layout` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(offsetHeight|offsetWidth|scrollTop|scrollLeft|clientTop|clientLeft)\s*=
```

**Input that fires** (verified by the liveness test):

```text
offsetHeight =
```

### global-variable

Global variable assignment detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `performance`, `javascript`, `memory` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)^var\s+\w+\s*=|window\.\w+\s*=
```

**Input that fires** (verified by the liveness test):

```text
var o52Qt4xjPVit =
```

### gzip-not-enabled

gzip compression not enabled

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `performance`, `compression`, `network` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)Accept-Encoding
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
Accept-E…ng
```

### inner-html-assignment

innerHTML assignment may cause performance issues

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `performance`, `javascript`, `dom` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)innerHTML\s*=
```

**Input that fires** (verified by the liveness test):

```text
innerHTML =
```

### missing-database-index

CREATE TABLE without explicit index

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `performance`, `database`, `index` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)CREATE\s+TABLE
```

**Input that fires** (verified by the liveness test):

```text
CREATE TABLE
```

### missing-limit

Query missing LIMIT clause

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `performance`, `database`, `sql` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)LIMIT\s+
```

**Input that fires** (verified by the liveness test):

```text
LIMIT 
```

### n-plus-one-query

Potential N+1 query pattern

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `performance`, `database`, `n-plus-one` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)for\s*\([^)]*\)\s*\{[^}]*query|for\s*\([^)]*\)\s*\{[^}]*db\. 
```

**Reference**: <https://stackoverflow.com/questions/97197/what-is-the-n1-selects-problem>

**Input that fires** (verified by the liveness test):

```text
for (3mCeY5x4cth) {nb6query
```

### no-cache-headers

Cache headers not detected in response

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `performance`, `caching`, `http` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)Cache-Control|CacheDirectives
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
Cache-Co…ol
```

### no-connection-pool

Database connection without pooling

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `performance`, `database`, `pooling` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)db\.connect|new\s+Connection\(.*\)
```

**Input that fires** (verified by the liveness test):

```text
db.connect
```

### regex-in-loop

Regex creation inside loop - compile outside

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `performance`, `regex`, `loop` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)for\s*\{[^}]*new\s+RegExp|for\s*\{[^}]*\.\.match\(|for\s*\{[^}]*\.\.test\(
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
for {u2npuj73…ew RegExp
```

### select-star

SELECT * detected - consider selecting specific columns

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `performance`, `database`, `sql` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)SELECT\s+\*
```

**Input that fires** (verified by the liveness test):

```text
SELECT *
```

### string-concatenation-loop

String concatenation in loop - use StringBuilder or join()

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `performance`, `string`, `memory` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)for\s*\{[^}]*\+\s*="[^\"]*"\}
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
for {zvSHK+ ="YNTpDgCA…LY"}
```

### sync-in-async

Blocking *Sync() call detected; prefer the async API

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.js`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.jsx` |
| Binary files | skipped |
| Tags | `performance`, `async`, `blocking` |

**Match pattern** (Rust `regex` syntax):

```regex
\b\w+Sync\s*\(
```

**Reference**: <https://nodejs.org/api/fs.html#synchronous-apis>

**Input that fires** (verified by the liveness test):

```text
dezGq52bSync (
```

### synchronous-xmlhttprequest

Synchronous XMLHttpRequest blocks UI thread

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `performance`, `javascript`, `network` |

**Match pattern** (Rust `regex` syntax):

```regex
new\s+XMLHttpRequest\(\).*send\(null\)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
new XMLHttpR…st()_@T7kf2mmuv.o-SCsend(null)
```

### unsized-image

Image without explicit dimensions

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `performance`, `image`, `html` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)<img\b[^>]*(?:/>|>)
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)\bwidth\s*=|\bheight\s*=|aspect-ratio
```
**Input that fires** (verified by the liveness test):

```text
<img/Z8G5gB/>
```
