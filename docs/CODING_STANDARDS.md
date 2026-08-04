# Coding Standards

## Rust Standards

### No Unsafe Code
- No `unsafe` blocks in production code
- FFI boundaries must be reviewed and documented
- Use safe abstractions (Vec, Box, Rc, Arc)

### Error Handling
- Use `Result<T, E>` for fallible operations
- No `.unwrap()` in production code
- No `.expect()` in production code
- Use `?` operator or match for error propagation
- Custom error types with `thiserror` or `anyhow`

### Testing
- Unit tests in `#[cfg(test)]` modules
- Integration tests in `tests/` directory
- Property-based tests with `proptest`
- Minimum 99% line coverage for core crate

### Linting
- `cargo clippy --workspace --all-targets -- -D warnings` must pass
- `cargo fmt --all` must pass
- No clippy warnings allowed

### Naming Conventions
- Crates: `kebab-case` (atheon-core, atheon-cli)
- Modules: `snake_case.rs` (pattern.rs, scanner.rs)
- Types: `PascalCase` (PatternRegistry, RiskScore)
- Functions: `snake_case` (scan_file, calculate_entropy)
- Constants: `SCREAMING_SNAKE_CASE` (MAX_FILE_SIZE)
- Variables: `snake_case` (finding_count)

### Module Organization

```rust
// src/lib.rs - Public API and re-exports
pub mod pattern;
pub mod scanner;
pub mod finding;
pub mod risk;

// src/pattern.rs - Pattern management
// src/scanner.rs - Main scanning logic
// src/finding.rs - Finding structures
// src/risk.rs - Risk calculation
// src/bundle.rs - Bundle loading
// src/entropy.rs - Entropy calculation
// src/ignore.rs - Ignore handling

// src/ast/ - AST analysis
// src/ast/mod.rs
// src/ast/go.rs - Go AST patterns
// src/ast/rust.rs - Rust AST patterns
```

### Documentation
- All public types and functions documented
- Use `cargo doc` compatible comments
- Include examples in docs
- Update docs when changing APIs

### Anti-Patterns
- No versioned files (*_v1, *_v2)
- No placeholder code (TODO, FIXME, HACK)
- No duplicate implementations
- No hardcoded values (use constants)

---

## Anti-Patterns (Forbidden)

### No `unwrap()` or `expect()`
```rust
// BAD
let value = some_result.unwrap();

// GOOD
let value = some_result?;
```

### No `panic!()`
```rust
// BAD
panic!("this should never happen");

// GOOD
return Err(MyError::UnexpectedState);
```

### No `unsafe {}`
```rust
// BAD - unless for FFI
unsafe { std::ptr::read(ptr) }

// GOOD
ptr.read()
```

### No `unwrap_or()` with side effects
```rust
// BAD
let val = map.get("key").unwrap_or(expensive_compute());

// GOOD
let val = map.get("key").copied().unwrap_or_else(|| expensive_compute());
```

---

## Testing Standards

### Test Organization
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matches() {
        // ...
    }

    #[test]
    fn test_pattern_enabled_state() {
        // ...
    }
}
```

### Property-Based Testing
```rust
#[cfg(test)]
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_entropy_calculation(entropy in 0.0f64..8.0) {
        let result = calculate_entropy(&entropy);
        prop_assert!(result >= 0.0 && result <= 8.0);
    }
}
```

### Benchmark Tests
```rust
#[cfg(test)]
mod benches {
    use super::*;
    use test::Bencher;

    #[bench]
    fn bench_pattern_scan(b: &mut Bencher) {
        let content = "x".repeat(1000);
        b.iter(|| scan_string(&content, &Default::default()));
    }
}
```

---

## Commit Format

```
<type>(<scope>): <subject>

<body>
```

Types: feat, fix, docs, style, refactor, test, chore

Subject: max 50 chars, imperative mood
Body: wrap at 72 chars
