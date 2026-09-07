# Building from Source

This guide is for contributors who want to build Aegis from source.

## Requirements

- **Rust 1.75+** (the workspace `rust-version`) - Install via
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
cargo build --workspace
```

### Build Release Version

```bash
cargo build --workspace --release
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

`aegis-cli` exposes an `output-pipeline` feature (which enables
`aegis-core/output-pipeline`, pulling in `reqwest` and `rusqlite`):

```bash
cargo build -p aegis-cli --features output-pipeline
```

`aegis-core` also has a `tree-sitter` feature for AST-based rules, plus
`tokio` and `jsonschema`, both on by default.

## Running Tests

```bash
# Run all tests
cargo test --workspace

# Run with coverage
cargo test --workspace -- --include-ignored

# Run specific test
cargo test -p aegis-core test_scanner
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
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
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
cargo clippy --workspace -- -D warnings
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
│   └── aegis-patterns/    # 633 pattern definitions
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
# Update dependencies
cargo update

# Clean and rebuild
cargo clean
cargo build --workspace
```

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
