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
- Coverage is measured in CI with `cargo llvm-cov --workspace --lcov`.
  The enforcing gate is `scripts/coverage-floor.sh`, run in the Coverage
  job against that report: below 89.0% lines fails the build.
  `crates/aegis-wasm` and the root shim binary are excluded (mirroring
  `codecov.yml`). The pipeline measures 89.96% lines (2026-09-24); the
  floor sits at measured minus one and ratchets up, never down. Codecov
  itself currently cannot evaluate its targets: uploads fail for lack of
  a CODECOV_TOKEN secret (Phase 17C in `docs/PLAN.md`)

### Linting
Every member crate opts in with `[lints] workspace = true`, and CI runs
clippy with `-D warnings`, so the `[workspace.lints]` table in the root
`Cargo.toml` is the effective floor:

- `rust`: `unsafe_code` deny, `let_underscore_drop` deny,
  `future_incompatible` deny, `rust_2018_idioms` warn,
  `unused_qualifications` warn, `missing_docs` warn
- `rustdoc`: `broken_intra_doc_links` deny, `private_intra_doc_links`
  deny (enforced by the `Rustdoc` CI job, which also builds docs with
  `RUSTDOCFLAGS=-D warnings`)
- `clippy`: `all` warn, `pedantic` warn, `unwrap_used`/`expect_used`/
  `panic` **deny** — errors must be values in production code. Test code
  is exempt via `clippy.toml`'s `allow-…-in-tests` flags; the few
  deliberate production exceptions carry an inline `#[allow]` with the
  invariant it protects (static regexes, epoch arithmetic, documented
  panicking convenience constructors). Note that clippy's test exemption
  only reaches code inside `#[test]` functions — a helper called from
  tests (or a `tokio::spawn` closure inside one) still needs an explicit
  `#[allow]` with a justification comment
- Remaining clippy allowances, each documented at the lint site:
  `cast_precision_loss`, `doc_markdown`, `too_many_lines`

- `cargo clippy --workspace --all-targets -- -D warnings` must pass
- `cargo doc --workspace --no-deps` (with `-D warnings`) must pass
- `cargo fmt --all` must pass
- No clippy warnings allowed

### CI Gates
`.github/workflows/ci.yml` runs on every push and PR to `main`:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo doc --workspace --no-deps` with `RUSTDOCFLAGS=-D warnings`
- `cargo test --workspace` on ubuntu, macOS, and Windows
- `cargo build --workspace --release`
- Coverage via `cargo-llvm-cov` + Codecov
- `cargo audit` and `cargo deny check` (advisories, licenses, bans, sources)
- CodeQL (Rust) analysis
- `cargo fuzz` targets run on a weekly schedule (`.github/workflows/fuzz.yml`)

### Naming Conventions
- Crates: `kebab-case` (aegis-core, aegis-cli)
- Modules: `snake_case.rs` (pattern.rs, scanner.rs)
- Types: `PascalCase` (PatternRegistry, RiskScore)
- Functions: `snake_case` (scan_file, shannon_entropy)
- Constants: `SCREAMING_SNAKE_CASE` (DEFAULT_MAX_FILE_SIZE, BUNDLE_VERSION)
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

// src/ast/ - AST analysis (single module file)
// src/ast/mod.rs - Go, Rust, Python, JavaScript/TypeScript rules

// Other core modules
// src/suppression.rs - inline suppression directives
// src/user_patterns.rs - `.aegis.yml` custom rules
// src/receipt.rs - redacted scan receipts
// src/internal/ - private helpers (not public API)
```

### Documentation
- All public types and functions documented — `missing_docs` is a
  workspace lint and clippy runs with `-D warnings`, so an undocumented
  public item fails CI
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

The only accepted uses in production code are lock re-acquisition on a
poisoned `std::sync` lock (a panic elsewhere has already failed the scan)
and test scaffolding.

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

`proptest` is a dev-dependency of `aegis-core`:

```rust
#[cfg(test)]
use aegis_core::entropy::shannon_entropy;

proptest! {
    #[test]
    fn test_shannon_entropy_bounds(content in "[a-z ]{0,4096}") {
        let result = shannon_entropy(&content);
        prop_assert!((0.0..=8.0).contains(&result));
    }
}
```

### Benchmarks

Benchmarks use `criterion` and live in a crate's `benches/` directory
(`crates/aegis-core/benches/pattern_matching.rs`,
`benches/scanner_init.rs`, `benches/clone_detection.rs`), declared in
`Cargo.toml` with `harness = false`:

```rust
use aegis_core::Scanner;
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

fn bench_pattern_scan(c: &mut Criterion) {
    let scanner = Scanner::new();
    let content = "x".repeat(1000);
    c.bench_function("pattern_scan_1k", |b| {
        b.iter(|| scanner.scan_string(black_box(&content), "bench.rs"))
    });
}

criterion_group!(benches, bench_pattern_scan);
criterion_main!(benches);
```

Run with `cargo bench -p aegis-core`.

---

## Commit Format

```
<type>(<scope>): <subject>

<body>
```

Types: `feat` | `fix` | `docs` | `test` | `refactor` | `chore` | `ci` | `build` | `perf`

Subject: max 50 chars, imperative mood
Body: wrap at 72 chars
