# Building from Source

This guide is for contributors who want to build Aegis from source.

## Requirements

- **Rust 1.88+** (the workspace `rust-version`) - Install via
  [rustup](https://rustup.rs/)
- **Cargo** - Included with Rust
- **Git**

## Clone the Repository

```bash
git clone https://github.com/aliasfoxkde/aegis.git
cd aegis
```

## Build Commands

### Build All Crates

```bash
cargo build --workspace --locked
```

### Build Release Version

```bash
cargo build --workspace --release --locked
```

### Build Specific Crate

```bash
cargo build -p aegis-cli
cargo build -p aegis-core
cargo build -p aegis-mcp
```

The CLI binary is named `aegis` and lands at
`target/release/aegis` (or `target/debug/aegis`). The other binaries are
`aegis-mcp`, `aegis-daemon`, and `aegis-bundler`; the workspace root
also defines an `aegis-bootstrap` binary from `src/main.rs`.

### Optional Features

`aegis-core` has one optional feature, `tree-sitter` (off by default),
which enables the tree-sitter-based AST analysis and pulls in the Go,
Rust, Python, JavaScript, and TypeScript grammars:

```bash
cargo build -p aegis-core --features tree-sitter --locked
```

The default feature set is just `tokio`.

## Running Tests

```bash
# Run all tests
cargo test --workspace --locked

# Run also the ignored (slow, corpus- and liveness-heavy) tests
cargo test --workspace --locked -- --include-ignored

# Run specific test
cargo test -p aegis-core test_scanner
```

Coverage uses `cargo-llvm-cov`:

```bash
cargo llvm-cov --workspace --html
```

## Code Quality

### Format Code

```bash
cargo fmt --all
```

### Run Clippy

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

### All Checks (CI Equivalent)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --release --locked
cargo build -p aegis-wasm --target wasm32-unknown-unknown --locked
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/my-feature
```

### 2. Make Changes

Edit the relevant source files.

### 3. Test Changes

```bash
cargo test --workspace
```

### 4. Format and Lint

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --locked -- -D warnings
```

### 5. Commit

```bash
git add .
git commit -m "feat: add new pattern category"
```

### 6. Push and PR

```bash
git push origin feature/my-feature
```

## Project Structure

```
aegis/
├── crates/
│   ├── aegis-core/        # Core scanning engine
│   │   └── src/
│   │       ├── scanner.rs  # Main scanner
│   │       ├── pattern.rs  # Pattern matching
│   │       ├── entropy.rs  # Entropy detection
│   │       ├── finding.rs  # Finding structs
│   │       ├── ignore.rs   # .aegisignore / .gitignore handling
│   │       └── lib.rs      # Core exports
│   ├── aegis-cli/         # CLI application
│   │   └── src/
│   │       ├── main.rs     # Argument parsing and dispatch
│   │       ├── scanner.rs  # Scan orchestration and exit codes
│   │       ├── output.rs   # Report rendering
│   │       └── config.rs   # Pattern enable/disable helpers
│   ├── aegis-mcp/         # MCP server
│   ├── aegis-daemon/      # Daemon mode (Unix sockets)
│   ├── aegis-bundler/     # Pattern bundler
│   ├── aegis-wasm/        # WebAssembly binding
│   └── aegis-patterns/    # 670 pattern definitions
│       └── src/
│           ├── secrets.rs
│           ├── pii.rs
│           └── ... (category files)
├── config/
│   └── profiles/           # Configuration profiles (JSON)
└── docs/                  # Documentation
```

## Adding a New Pattern Category

1. Create `crates/aegis-patterns/src/my_category.rs`
2. Implement `pub fn get() -> Vec<Pattern>`
3. Add a `mod my_category;` declaration to `crates/aegis-patterns/src/lib.rs`
4. Add the module to `all_patterns()` and a `my-category` arm to
   `by_category()` in that same `lib.rs`
5. Add tests
6. Update documentation

## Performance Profiling

```bash
# Build with profiling
RUSTFLAGS="-C instrument-coverage" cargo build --workspace

# Run with perf
perf record -g ./target/debug/aegis scan .
perf report
```

## Troubleshooting

### Compilation Errors

```bash
# Clean and rebuild
cargo clean
cargo build --workspace --locked
```

CI builds with `--locked`, so a changed `Cargo.lock` fails there. If you
deliberately bumped a dependency, run `cargo update -p <crate>` (or
`cargo update`) and commit the updated `Cargo.lock` with your change.

### Clippy Warnings

```bash
# Fix auto-fixable warnings
cargo clippy --workspace --fix --allow-dirty
```

### Test Failures

```bash
# Run with output
RUST_BACKTRACE=1 cargo test -p aegis-core test_name
```
