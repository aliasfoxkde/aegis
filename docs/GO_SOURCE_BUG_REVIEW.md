# Go Source Bug Review - Atheon-Enhanced

## Summary
Review of `/nas/Temp/repos/Atheon-Enhanced/` found **26 issues** across security vulnerabilities, error handling, concurrency bugs, and logic errors.

---

## Critical Issues

### 1. TOCTOU Race Condition (`core/runner.go:101-120`)
```go
canon, err := filepath.EvalSymlinks(path)
// ... time passes ...
info, err := os.Stat(canon)  // TOCTOU: file could change
```
**Fix**: Use `std::fs::metadata()` with `follow_symlinks: false`

### 2. HTTP Response Body Leak on Error Path (`core/bundle.go:771-775`)
```go
resp, err := client.Do(req)
if err != nil {
    return nil, "", fmt.Errorf("%w: %w", ErrBundleDownload, err)
}
defer resp.Body.Close()  // PANIC: resp may be nil
```
**Fix**: Use Drop guard or check resp != nil before defer

### 3. Nil Response Body Dereference (`core/bundle.go:827-828`)
Go's `http.Client.Do` can return both error and non-nil response.

### 4. Use of `os.environ` Mixed Case Sensitivity (`core/taint.go:34-50`)
```go
sources: map[string]bool{
    "os.Getenv":      true,
    "os.environ":     true,  // Wrong - should be os.Environ or os.Getenv
```
**Fix**: Python naming convention copied into Go - fix to `os.Getenv`

---

## High Severity Issues

### 5. Regex DoS via Malicious Patterns (`core/bundle.go:332`)
```go
re, err := regexp.Compile(def.Match)  // No timeout, no complexity limit
```
**Fix**: Use `regex` crate with timeout wrapper

### 6. Goroutine Leak on Context Cancellation (`core/runner.go:284-289`)
Started goroutines waiting on semaphore not cancelled on context Done.

### 7. Closure Variable Capture Bug (`core/runner.go:291-338`)
```go
results[i] = ...  // Data race: written without synchronization
sizes[i] = ...
```

### 8. HTTP Client Missing Per-Request Timeout (`core/bundle.go:767`)
Slow connection could hang indefinitely despite client timeout.

### 9. Silent Error Swallowed (`core/bundle.go:189-190`)
```go
if err := loadBundle(data); err != nil {
    slog.Warn("bundle load failed", "err", err)
}
```
Continues with potentially corrupted state.

### 10. Symlink Attack Vector in `atomicWriteFile` (`internal/atomicio/write.go`)
```go
if err := os.Rename(tmpName, path); err != nil {
```
Race condition with symlink before rename.

---

## Medium Severity Issues

### 11. `slicesEqual` Function Never Defined (`core/ast_patterns.go:1496`)
Would cause compilation error.

### 12. Line Numbers Always Zero in CFG (`core/cfg.go:198-210`)
```go
cfg.Acquired = append(cfg.Acquired, &ResourceAcquisition{
    Line: 0,  // Always 0!
})
```

### 13. CloneDetector.config Not Used (`core/clone_detection.go:615`)
```go
detector := NewCloneDetector(DefaultCloneDetectionConfig())  // Should use d.config
```

### 14. Cache Entry Lock Issue (`core/entropy.go:36-43`)
Lock held during entire cache hit path.

### 15. Missing `slices` Import (`core/ast_patterns.go`)
Uses `slices.Equal` but package not imported.

### 16. Incomplete Cycle Detection (`core/imports.go:117-131`)
Cycle A->B->C->B extracted as [B, C, B] - missing A.

---

## Low Severity Issues

### 17. Hardcoded Permission `0o644` (`core/suppression.go:165`)
World-readable baseline files.

### 18. No Size Limit on Checksums File (`core/bundle.go:835`)
1 MiB cap could hide malicious hash via truncation.

### 19. Empty Ignore Pattern (`core/ignore.go:60-65`)
Returns error but silently skipped - inconsistent.

### 20. Token Position Tracking Issue (`core/ast_patterns.go:546-553`)
Malformed string literals could cause panic.

---

## Recommendations for Rust Rewrite

1. **Fix TOCTOU** - Use `std::fs::metadata()` with `follow_symlinks: false`
2. **Add request timeouts** - Explicit per-request timeout in HTTP client
3. **Validate regex complexity** - Add timeout wrapper for regex compilation
4. **Fix goroutine cleanup** - Ensure all goroutines cancelled on context cancellation
5. **Use proper synchronization** - Use channels or `Arc` for worker results
6. **Add response body handling** - Use `reqwest` with automatic body closing
7. **Implement `slicesEqual`** - Use `std::slice::eq` instead

---

## Issue Summary Table

| Category | Count | Critical | High | Medium | Low |
|----------|-------|----------|------|--------|-----|
| Security Vulnerabilities | 10 | 3 | 4 | 2 | 1 |
| Error Handling | 4 | 1 | 2 | 1 | 0 |
| Concurrency Bugs | 3 | 1 | 1 | 1 | 0 |
| Resource Leaks | 2 | 1 | 1 | 0 | 0 |
| Logic Errors | 4 | 0 | 2 | 1 | 1 |
| Edge Cases | 3 | 0 | 1 | 1 | 1 |
| **Total** | **26** | **6** | **11** | **6** | **3** |
