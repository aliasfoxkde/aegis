# git-ops patterns

GitOps workflow and manifest checks

**3 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`git-credential-leak`](#git-credential-leak) | critical | high | Detects potential git credential leakage in configuration or URLs |
| [`git-ops-force-push-detected`](#git-ops-force-push-detected) | high | high | Detects force push commands which can overwrite remote history |
| [`protected-branch-delete`](#protected-branch-delete) | critical | high | Detects commands that delete or modify protected branches |

## Pattern details

### git-credential-leak

Detects potential git credential leakage in configuration or URLs

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git-ops`, `git`, `credentials`, `leak` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(git\s+config\s+--local\s+credential\.helper|git\s+clone\s+https?://[^@]+@|url\s*=\s*https?://[^:]+:[^@]+@)
```

**Reference**: <https://git-scm.com/docs/git-credential>

**Input that fires** (verified by the liveness test):

```text
git config --local credential.helper
```

### git-ops-force-push-detected

Detects force push commands which can overwrite remote history

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git-ops`, `git`, `force-push` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(git\s+push\s+--force|git\s+push\s+-f\s+origin|push\s+--force-with-lease|--force-with-lease)
```

**Reference**: <https://git-scm.com/docs/git-push>

**Input that fires** (verified by the liveness test):

```text
git push --force
```

### protected-branch-delete

Detects commands that delete or modify protected branches

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git-ops`, `git`, `protected-branch`, `destructive` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(git\s+push\s+origin\s+--delete\s+(main|master|develop|release|prod)|git\s+branch\s+-D\s+(main|master|develop|release|prod)|branch\s*=\s*["']?(main|master|develop|release|prod)["']?\s*\n\s*protection\s*:\s*false)
```

**Reference**: <https://git-scm.com/docs/git-push>

**Input that fires** (verified by the liveness test):

```text
git push origin --delete main
```
