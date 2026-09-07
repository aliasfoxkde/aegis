# metadata patterns

Metadata and editor configuration leaks

**4 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`backup-file`](#backup-file) | low | high | Detects backup files that may contain sensitive data |
| [`ide-config-leak`](#ide-config-leak) | medium | high | Detects IDE configuration files that may contain sensitive settings |
| [`os-cache-file`](#os-cache-file) | low | high | Detects operating system cache files that may contain metadata |
| [`temporary-file`](#temporary-file) | low | high | Detects temporary files that may contain sensitive data |

## Pattern details

### backup-file

Detects backup files that may contain sensitive data

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `metadata`, `backup` |

**Match pattern** (Rust `regex` syntax):

```regex
\.(bak|old|backup|orig|rpmorig|dpkg-(?:old|dist)|~\")$
```

**Input that fires** (verified by the liveness test):

```text
.bak
```

### ide-config-leak

Detects IDE configuration files that may contain sensitive settings

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `metadata`, `ide` |

**Match pattern** (Rust `regex` syntax):

```regex
\.(idea|vscode|vscodium|settings\.json|workspace\.json)$
```

**Input that fires** (verified by the liveness test):

```text
.idea
```

### os-cache-file

Detects operating system cache files that may contain metadata

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `metadata`, `os-cache` |

**Match pattern** (Rust `regex` syntax):

```regex
\.(DS_Store|Thumbs\.db|desktop\.ini|\.AppleDouble|\.LSOverride)$
```

**Input that fires** (verified by the liveness test):

```text
.DS_Store
```

### temporary-file

Detects temporary files that may contain sensitive data

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `metadata`, `temporary` |

**Match pattern** (Rust `regex` syntax):

```regex
\.(tmp|temp|cache|swp|swo)$
```

**Input that fires** (verified by the liveness test):

```text
.tmp
```
