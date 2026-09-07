# kubernetes patterns

Kubernetes manifest hardening

**11 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`hostnetwork`](#hostnetwork) | high | high | Pod uses host network |
| [`hostpid`](#hostpid) | high | high | Pod uses host PID namespace |
| [`k8s-allow-privilege-escalation`](#k8s-allow-privilege-escalation) | high | high | Container allows privilege escalation |
| [`k8s-empty-dir-memory-backed`](#k8s-empty-dir-memory-backed) | medium | high | EmptyDir volume uses memory-backed storage |
| [`k8s-missing-capability-drop`](#k8s-missing-capability-drop) | medium | medium | Security context defined but missing capability drop |
| [`k8s-no-network-policy`](#k8s-no-network-policy) | medium | high | No network policy defined for namespace |
| [`k8s-run-as-non-root`](#k8s-run-as-non-root) | high | high | Container run as root or missing runAsNonRoot configuration |
| [`kubernetes-latest-tag`](#kubernetes-latest-tag) | medium | high | Container image uses latest tag |
| [`kubernetes-privileged-container`](#kubernetes-privileged-container) | critical | high | Container runs in privileged mode |
| [`no-resource-limits`](#no-resource-limits) | medium | high | Container has no resource limits defined |
| [`secrets-in-manifest`](#secrets-in-manifest) | high | high | Secrets may be exposed in Kubernetes manifests |

## Pattern details

### hostnetwork

Pod uses host network

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `security`, `network` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)securityContext:\s*\n\s*hostNetwork:\s*true
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
security…xt: 
 hostNetwork: true
```

### hostpid

Pod uses host PID namespace

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `security`, `process` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)securityContext:\s*\n\s*hostPID:\s*true
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
security…xt: 
 hostPID: true
```

### k8s-allow-privilege-escalation

Container allows privilege escalation

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
allowPrivilegeEscalation:\s*(true|null)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
allowPri…on: true
```

### k8s-empty-dir-memory-backed

EmptyDir volume uses memory-backed storage

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `security`, `resource` |

**Match pattern** (Rust `regex` syntax):

```regex
emptyDir:\s*\n\s*medium:\s*Memory
```

**Input that fires** (verified by the liveness test):

```text
emptyDir: 
 medium: Memory
```

### k8s-missing-capability-drop

Security context defined but missing capability drop

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `security`, `capabilities` |

**Match pattern** (Rust `regex` syntax):

```regex
securityContext
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
security…xt
```

### k8s-no-network-policy

No network policy defined for namespace

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `security`, `network` |

**Match pattern** (Rust `regex` syntax):

```regex
(NetworkPolicy|networkPolicy).*:\s*\|?\s*-\s*\{
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
NetworkP…X3: | - {
```

### k8s-run-as-non-root

Container run as root or missing runAsNonRoot configuration

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `security`, `root` |

**Match pattern** (Rust `regex` syntax):

```regex
(runAsNonRoot|runAsRoot):\s*(true|false)
```

**Input that fires** (verified by the liveness test):

```text
runAsNonRoot: true
```

### kubernetes-latest-tag

Container image uses latest tag

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `security`, `image` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)image:\s*[^:\n]+:latest
```

**Input that fires** (verified by the liveness test):

```text
image: 7b:latest
```

### kubernetes-privileged-container

Container runs in privileged mode

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `security`, `privileged` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)securityContext:\s*\n\s*privileged:\s*true
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
security…xt: 
 privileged: true
```

### no-resource-limits

Container has no resource limits defined

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `security`, `resource` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(containers:|-\s+name:).*?(image:|containers:)|resources:\s*\n\s*limits:
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
containers:_.EARp-6ja…ge:
```

### secrets-in-manifest

Secrets may be exposed in Kubernetes manifests

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `security`, `secrets` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(apiVersion:\s*v1\s*\n\s*kind:\s*Secret|secretKeyRef|data:\s*\n\s*  [a-zA-Z_]+:\s*['\"][^'\"]+['\"])
```

**Input that fires** (verified by the liveness test):

```text
apiVersion: v1 
 kind: Secret
```
