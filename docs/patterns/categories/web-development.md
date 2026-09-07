# web-development patterns

General web development checks

**11 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`bundler-optimization`](#bundler-optimization) | low | high | Bundler optimization issue |
| [`error-boundaries`](#error-boundaries) | low | high | React error boundary implementation |
| [`form-validation`](#form-validation) | low | high | Form validation issue |
| [`incorrect-semantic-html`](#incorrect-semantic-html) | medium | high | Incorrect semantic HTML usage |
| [`inefficient-css`](#inefficient-css) | low | high | Inefficient CSS implementation |
| [`missing-prop-validation`](#missing-prop-validation) | medium | high | Missing prop type validation |
| [`nextjs`](#nextjs) | low | high | Next.js specific pattern |
| [`poor-error-boundary`](#poor-error-boundary) | high | high | Poor error boundary implementation |
| [`react-optimization`](#react-optimization) | low | high | React optimization issue |
| [`seo-meta-tags`](#seo-meta-tags) | low | high | SEO meta tag configuration |
| [`state-management`](#state-management) | low | high | State management issue |

## Pattern details

### bundler-optimization

Bundler optimization issue

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `web-development`, `bundler` |

**Match pattern** (Rust `regex` syntax):

```regex
import.*\*.*from|require.*dynamic.*import|import.*\(?.*await
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
importjc…Ek*8FFuF.R7eyR9Kfrom
```

### error-boundaries

React error boundary implementation

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `web-development`, `react`, `error-handling` |

**Match pattern** (Rust `regex` syntax):

```regex
componentDidCatch|getDerivedStateFromError|class.*ErrorBoundary
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
componen…ch
```

### form-validation

Form validation issue

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `web-development`, `forms`, `validation` |

**Match pattern** (Rust `regex` syntax):

```regex
form.*onSubmit.*preventDefault|input.*required.*false|pattern.*validation
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
formnJMk…it/ 4yq5B-Bv…lt
```

### incorrect-semantic-html

Incorrect semantic HTML usage

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `web-development`, `accessibility`, `html` |

**Match pattern** (Rust `regex` syntax):

```regex
<div\s+class=".*container.*"><div\s+class=".*row.*"><div\s+class=".*col.*"|<div\s+role="navigation"|<div\s+role="main"
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
<div class="-m-s6uco…Lq@boLw5"><div class="U5rowwS_FqQ"><div class="yXYDCKaC…lu"
```

### inefficient-css

Inefficient CSS implementation

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `web-development`, `css`, `performance` |

**Match pattern** (Rust `regex` syntax):

```regex
@import.*css|style.*attribute.*important|\*.*\{.*display.*none|animation.*no.*hardware
```

**Input that fires** (verified by the liveness test):

```text
@importZrk@aD9uqHwbcss
```

### missing-prop-validation

Missing prop type validation

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `web-development`, `react`, `prop-types` |

**Match pattern** (Rust `regex` syntax):

```regex
PropsTypes|propTypes.*isRequired|React\.PropTypes.*\.isRequired
```

**Input that fires** (verified by the liveness test):

```text
PropsTypes
```

### nextjs

Next.js specific pattern

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `web-development`, `nextjs`, `react` |

**Match pattern** (Rust `regex` syntax):

```regex
useEffect.*\[\].*fetch|export default.*function.*props|getStaticPaths.*fallback.*false
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
useEffec…em hbA[]UtadUk22…ch
```

### poor-error-boundary

Poor error boundary implementation

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `web-development`, `react`, `error-handling` |

**Match pattern** (Rust `regex` syntax):

```regex
componentDidCatch.*console\.log|ErrorBoundary.*return.*null|catch.*error.*render.*null
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
componen…le.log
```

### react-optimization

React optimization issue

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `web-development`, `react`, `performance` |

**Match pattern** (Rust `regex` syntax):

```regex
useCallback.*\[\]|useMemo.*\[\]|React\.memo.*props.*object
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
useCallb…BU@iz6rPea/a/D[]
```

### seo-meta-tags

SEO meta tag configuration

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `web-development`, `seo` |

**Match pattern** (Rust `regex` syntax):

```regex
<!DOCTYPE html>|<meta name="description"|<meta property="og:|<link rel="canonical"|<meta name="keywords"
```

**Input that fires** (verified by the liveness test):

```text
<!DOCTYPE html>
```

### state-management

State management issue

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `web-development`, `state-management` |

**Match pattern** (Rust `regex` syntax):

```regex
useState.*useEffect.*useState|setState.*prevState|dispatch.*action.*type
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
useStateo@suseEffe…te
```
