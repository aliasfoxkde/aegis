# code-quality patterns

Language anti-patterns and dangerous constructs

**15 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`code-quality-eval-usage`](#code-quality-eval-usage) | high | high | Use of eval() detected |
| [`commented-code`](#commented-code) | low | medium | Commented-out code detected |
| [`console-log`](#console-log) | low | high | Console logging statement detected |
| [`debugger-statement`](#debugger-statement) | medium | high | Debugger statement detected |
| [`double-negation`](#double-negation) | low | high | Double negation (!!) detected |
| [`empty-catch-block`](#empty-catch-block) | medium | high | Empty catch block detected |
| [`excess-line-length`](#excess-line-length) | low | high | Excessively long line detected (>200 characters) |
| [`hardcoded-date`](#hardcoded-date) | low | high | Hardcoded date detected |
| [`loose-equality`](#loose-equality) | low | high | Loose equality comparison ('=='); prefer strict equality ('===') |
| [`magic-number`](#magic-number) | low | medium | Magic number detected |
| [`nested-callbacks`](#nested-callbacks) | medium | medium | Deeply nested callbacks detected (callback hell) |
| [`print-statement`](#print-statement) | low | high | Print statement detected |
| [`todo-comment`](#todo-comment) | low | high | TODO/FIXME comment detected |
| [`var-declaration`](#var-declaration) | low | high | Use of 'var' instead of 'let'/'const' (ES6+) |
| [`with-statement`](#with-statement) | medium | high | Use of with statement detected |

## Pattern details

### code-quality-eval-usage

Use of eval() detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.php`, `.py`, `.rb`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `security`, `dangerous` |

**Match pattern** (Rust `regex` syntax):

```regex
\beval\s*\(
```

**Reference**: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval>

**Input that fires** (verified by the liveness test):

```text
eval (
```

### commented-code

Commented-out code detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `comment`, `dead-code` |

**Match pattern** (Rust `regex` syntax):

```regex
^\s*//\s*(function|const|let|var|if|for|while|return|class|import)
```

**Input that fires** (verified by the liveness test):

```text
 // function
```

### console-log

Console logging statement detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `debug`, `logging` |

**Match pattern** (Rust `regex` syntax):

```regex
console\.(log|debug|info|warn|error)\s*\(
```

**Reference**: <https://eslint.org/docs/rules/no-console>

**Input that fires** (verified by the liveness test):

```text
console.log (
```

### debugger-statement

Debugger statement detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `debug`, `development` |

**Match pattern** (Rust `regex` syntax):

```regex
\bdebugger\b
```

**Input that fires** (verified by the liveness test):

```text
debugger
```

### double-negation

Double negation (!!) detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `readability`, `javascript` |

**Match pattern** (Rust `regex` syntax):

```regex
!![a-zA-Z_]
```

**Input that fires** (verified by the liveness test):

```text
!!s
```

### empty-catch-block

Empty catch block detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `error-handling`, `anti-pattern` |

**Match pattern** (Rust `regex` syntax):

```regex
catch\s*\([^)]*\)\s*\{\s*\}
```

**Input that fires** (verified by the liveness test):

```text
catch (Tr+SJwXX+mKrCn) { }
```

### excess-line-length

Excessively long line detected (>200 characters)

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `complexity`, `maintainability` |

**Match pattern** (Rust `regex` syntax):

```regex
(?m)^.{200,}$
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
NDscJ5Uk_g@tNYZ_LP28@PEG_uL4x…V5.82ZfEyt.vuhuE_y4tCEF X.u-T3s_tjh_D@4WPdRAQB_-Yk.A@gFQJzZY/N.__NTQrLK.hhTciqWz…SG VfEjo_bZ…mv 8q_xa.Z6BYUCzk…e4
```

### hardcoded-date

Hardcoded date detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `hardcoded`, `date` |

**Match pattern** (Rust `regex` syntax):

```regex
new\s+Date\(\s*['"]\d{4}-\d{2}-\d{2}
```

**Input that fires** (verified by the liveness test):

```text
new Date( "5752-83-64
```

### loose-equality

Loose equality comparison ('=='); prefer strict equality ('===')

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `javascript`, `best-practice` |

**Match pattern** (Rust `regex` syntax):

```regex
[^=!<>]==[^=]
```

**Reference**: <https://eslint.org/docs/latest/rules/eqeqeq>

**Input that fires** (verified by the liveness test):

```text
c==T
```

### magic-number

Magic number detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `readability`, `maintainability` |

**Match pattern** (Rust `regex` syntax):

```regex
\b\d{4,}\b
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
\A(?:(?:19|20)\d{2}|1000|1024|2048|4096|8192|16384|32768|65536|131072|262144|524288|1048576|2097152|4194304|8388608|16777216)\z
```
**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
87325387…55
```

### nested-callbacks

Deeply nested callbacks detected (callback hell)

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `complexity`, `readability` |

**Match pattern** (Rust `regex` syntax):

```regex
\)\s*\)\s*\)\s*\)
```

**Input that fires** (verified by the liveness test):

```text
) ) ) )
```

### print-statement

Print statement detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `debug`, `logging` |

**Match pattern** (Rust `regex` syntax):

```regex
\bprint\s*\(|\bSystem\.out\.print|\bprintln\s*\(|\blog\.(info|debug|warn|error)
```

**Input that fires** (verified by the liveness test):

```text
print (
```

### todo-comment

TODO/FIXME comment detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `comment`, `technical-debt` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(TODO|FIXME|HACK|XXX)\b
```

**Input that fires** (verified by the liveness test):

```text
TODO
```

### var-declaration

Use of 'var' instead of 'let'/'const' (ES6+)

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `javascript`, `es6`, `best-practice` |

**Match pattern** (Rust `regex` syntax):

```regex
\bvar\s+[A-Za-z_$][\w$]*\s*=
```

**Reference**: <https://eslint.org/docs/latest/rules/no-var>

**Input that fires** (verified by the liveness test):

```text
var VGAJDIl2O =
```

### with-statement

Use of with statement detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `javascript`, `anti-pattern` |

**Match pattern** (Rust `regex` syntax):

```regex
\bwith\s*\(
```

**Reference**: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/with>

**Input that fires** (verified by the liveness test):

```text
with (
```
