# pwa patterns

Progressive web app checks

**5 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`caching-strategy`](#caching-strategy) | medium | high | PWA caching strategy issue |
| [`manifest`](#manifest) | medium | high | PWA manifest configuration issue |
| [`offline-support`](#offline-support) | medium | high | PWA offline support issue |
| [`service-worker`](#service-worker) | medium | high | PWA service worker issue |
| [`shortcuts`](#shortcuts) | medium | high | PWA shortcuts configuration issue |

## Pattern details

### caching-strategy

PWA caching strategy issue

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pwa`, `caching` |

**Match pattern** (Rust `regex` syntax):

```regex
cache.*first.*network|network.*first.*cache|stale.*while.*revalidate
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
cacheM8F…xh cnetwork
```

### manifest

PWA manifest configuration issue

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pwa`, `manifest` |

**Match pattern** (Rust `regex` syntax):

```regex
manifest.*name.*short_name.*different|display.*standalone.*theme_color.*different|icons.*192.*512
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
manifest…wJ  Bdifferent
```

### offline-support

PWA offline support issue

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pwa`, `offline` |

**Match pattern** (Rust `regex` syntax):

```regex
offline.*html.*503|navigator\.onLine.*false|fallback.*page.*offline
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
offline_…lg.wT503
```

### service-worker

PWA service worker issue

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pwa`, `service-worker` |

**Match pattern** (Rust `regex` syntax):

```regex
cache.*addAll.*urls.*100\+|fetch.*respondWith.*cache.*match.*network|skipWaiting\(\).*clients\.claim
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
cachehYk39h.addAll_u…00+
```

### shortcuts

PWA shortcuts configuration issue

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pwa`, `shortcuts` |

**Match pattern** (Rust `regex` syntax):

```regex
shortcuts.*name.*url|icons.*shortcuts.*manifest|app.*shortcuts.*home.*screen
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
shortcut…Kj@M/Xnameburl
```
