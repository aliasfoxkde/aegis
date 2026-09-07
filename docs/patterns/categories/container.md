# container patterns

Container build and runtime hardening

**4 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`dockerfile-cap-add-all`](#dockerfile-cap-add-all) | high | high | Detects Docker run or Dockerfile with --cap-add=ALL or cap_add: - ALL |
| [`dockerfile-exposed-socket`](#dockerfile-exposed-socket) | critical | high | Detects Docker socket mount which can give container full Docker access |
| [`dockerfile-privileged-mode`](#dockerfile-privileged-mode) | critical | high | Detects Docker container running in privileged mode with full host access |
| [`dockerfile-running-as-root`](#dockerfile-running-as-root) | high | high | Detects Dockerfile or Docker run with user set to root or UID 0 |

## Pattern details

### dockerfile-cap-add-all

Detects Docker run or Dockerfile with --cap-add=ALL or cap_add: - ALL

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `container`, `dockerfile`, `capabilities` |

**Match pattern** (Rust `regex` syntax):

```regex
(--cap-add\s*=\s*ALL|cap_add:\s*-\s*ALL)
```

**Input that fires** (verified by the liveness test):

```text
--cap-add = ALL
```

### dockerfile-exposed-socket

Detects Docker socket mount which can give container full Docker access

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `container`, `dockerfile`, `docker-socket` |

**Match pattern** (Rust `regex` syntax):

```regex
(-v|--mount)(?:=|\s+)(?:/var/run/docker\.sock|var/run/docker\.sock)
```

**Input that fires** (verified by the liveness test):

```text
-v=/var/run/docker.sock
```

### dockerfile-privileged-mode

Detects Docker container running in privileged mode with full host access

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `container`, `dockerfile`, `privileged` |

**Match pattern** (Rust `regex` syntax):

```regex
(--privileged|privileged:\s*true)
```

**Input that fires** (verified by the liveness test):

```text
--privileged
```

### dockerfile-running-as-root

Detects Dockerfile or Docker run with user set to root or UID 0

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `container`, `dockerfile`, `root` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)^(?:USER|user)\s*(?::\s*|=|\s+)(?:root|0)$
```

**Input that fires** (verified by the liveness test):

```text
USER : root
```
