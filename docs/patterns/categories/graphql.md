# graphql patterns

GraphQL API security and usage

**4 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`graphql-debug-mode`](#graphql-debug-mode) | high | high | Detects GraphQL with debug mode enabled |
| [`graphql-field-cost-undefined`](#graphql-field-cost-undefined) | medium | high | Detects GraphQL without field cost analysis enabled |
| [`graphql-introspection-enabled`](#graphql-introspection-enabled) | medium | high | Detects GraphQL with introspection enabled in production |
| [`graphql-query-depth-unlimited`](#graphql-query-depth-unlimited) | high | high | Detects GraphQL with unlimited query depth |

## Pattern details

### graphql-debug-mode

Detects GraphQL with debug mode enabled

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.js`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.jsx`, `.yaml`, `.yml`, `.json`, `.graphql`, `.gql` |
| Binary files | skipped |
| Tags | `graphql`, `debug` |

**Match pattern** (Rust `regex` syntax):

```regex
(?:debug|DEBUG|debugMode)\s*[:=]\s*(?:true|True|TRUE)
```

**Input that fires** (verified by the liveness test):

```text
debug : true
```

### graphql-field-cost-undefined

Detects GraphQL without field cost analysis enabled

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `graphql`, `performance` |

**Match pattern** (Rust `regex` syntax):

```regex
(?:complexity|fieldCost|costAnalysis)\s*[:=]\s*(?:false|disabled|none)
```

**Input that fires** (verified by the liveness test):

```text
complexity : false
```

### graphql-introspection-enabled

Detects GraphQL with introspection enabled in production

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `graphql`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
introspection\s*[:=]\s*(?:true|True|TRUE)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
introspe…on = true
```

### graphql-query-depth-unlimited

Detects GraphQL with unlimited query depth

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `graphql`, `dos` |

**Match pattern** (Rust `regex` syntax):

```regex
(?:maxDepth|defaultMaxDepth|queryDepth)\s*[:=]\s*(?:0|null|undefined|false)
```

**Input that fires** (verified by the liveness test):

```text
maxDepth = 0
```
