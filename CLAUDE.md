# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Build entire workspace
cargo build --workspace

# Build release
cargo build --workspace --release

# Run tests
cargo test --workspace

# Run single test
cargo test --package aegis-core --lib -- test_function_name

# Lint (Clippy)
cargo clippy --workspace --all-targets -- -D warnings

# Format check
cargo fmt --all -- --check

# Format
cargo fmt --all
```

## Architecture

Aegis is a security scanning tool built as a Rust workspace with 6 crates:

### Core Crates

- **aegis-core** (`crates/aegis-core/`) - Scanning engine
  - `scanner.rs` - Main `Scanner` struct that orchestrates scanning
  - `pattern.rs` - `PatternRegistry` manages detection patterns
  - `finding.rs` - `Finding` struct for reported issues
  - `risk.rs` - Risk scoring and classification
  - `entropy.rs` - Shannon entropy for secret detection
  - `bundle.rs` - Pattern bundle loading/serialization (gzip compressed)

- **aegis-patterns** (`crates/aegis-patterns/`) - 590+ detection patterns
  - Pattern definitions as Rust code returning `Vec<Pattern>`
  - Categories: secrets, pii, security-hardening, web-security, ai-safety, etc.
  - Each category file (e.g., `secrets.rs`) exports `get()` function

- **aegis-cli** (`crates/aegis-cli/`) - Command-line interface
  - `src/main.rs` - CLI entry with clap, defines `scan`, `list`, `enable`, `disable`, `update` commands
  - `src/scanner.rs` - Scan execution, initializes Scanner with patterns from aegis-patterns
  - `src/output.rs` - Output formatting (human, JSON, SARIF)

### Supporting Crates

- **aegis-mcp** (`crates/aegis-mcp/`) - MCP server for AI tool integration
- **aegis-daemon** (`crates/aegis-daemon/`) - Daemon mode (stub/imcomplete)
- **aegis-bundler** (`crates/aegis-bundler/`) - Tool to create pattern bundles from YAML

### Key Data Flow

1. CLI parses args → creates `Scanner::from_definitions()` with patterns from `aegis_patterns::all_patterns()`
2. Scanner scans files/directories using `PatternRegistry`
3. Each pattern matches content via regex; entropy check for secrets
4. Findings collected with location, severity, confidence
5. Risk score calculated, output formatted per `--format` flag

### Important Implementation Notes

- **Pattern loading**: aegis-cli MUST depend on aegis-patterns and convert patterns using `convert_pattern()` function in `scanner.rs`
- **Pattern names must be unique**: Duplicate names cause `PatternError::Duplicate` at runtime
- **Regex compatibility**: Patterns use `regex` crate (not `regex-syntax`) - avoid lookarounds (`(?!)`, `(?<!)`)
- **Output**: Use `println!("{}", output)` to print - the `Display` impl returns `buffer`

## CI/CD

- **CI workflow** (`.github/workflows/ci.yml`): CodeQL, Format, Clippy, Test, Build, Coverage
- **Release workflow** (`.github/workflows/release.yml`): Builds on Linux/macOS/Windows, uploads artifacts, creates GitHub Release on tag push
- Push to `main` requires PR with passing CI checks
- Releases created by pushing `v*` tags

## Repository Structure

```
/crates/
  aegis-core/     # Core scanning engine
  aegis-cli/      # CLI binary (aegis)
  aegis-patterns/ # Detection patterns (~590 patterns)
  aegis-mcp/      # MCP server binary
  aegis-daemon/   # Daemon binary
  aegis-bundler/  # Pattern bundler binary
/.github/workflows/ # CI and release workflows
/docs/             # Documentation guides
```
