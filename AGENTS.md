# AGENTS.md

This file provides guidance for AI agents working on the Aegis project.

## Project Overview

Aegis is a high-performance security scanning tool for DevOps, CI/CD pipelines, and AI systems. Built in Rust with 620+ detection patterns.

## Key Commands

```bash
# Build
cargo build --workspace --release

# Test
cargo test --workspace

# Lint
cargo clippy --workspace --all-targets -- -D warnings

# Format
cargo fmt --all

# Coverage
cargo llvm-cov --workspace
```

## Architecture

- **aegis-core**: Core scanning engine with pattern matching
- **aegis-cli**: Command-line interface
- **aegis-patterns**: Detection pattern definitions
- **aegis-mcp**: MCP server for AI integration
- **aegis-daemon**: Unix-only daemon mode
- **aegis-bundler**: Pattern bundler tool
- **aegis-wasm**: WASM bindings for browser environments

## Important Notes

- **WASM**: The aegis-wasm crate provides WASM bindings. It must be built with `cargo build --target wasm32-unknown-unknown --package aegis-wasm`
- **Daemon**: aegis-daemon is Unix-only due to Unix domain sockets
- **Tokio**: Core uses tokio with `sync`, `fs`, `io-util` features only
- **Pattern count**: 620 patterns (NOT 621)

## License

Apache-2.0 (NOT MIT OR Apache-2.0)

## Release Process

1. Create a tag: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
2. Push tag: `git push origin vX.Y.Z`
3. GitHub Actions will build and create draft release
4. Release workflow builds: Linux, macOS (x86 + ARM), Windows, WASM

## Quality Requirements

- All tests must pass
- Clippy must be clean (`-D warnings`)
- Format must be clean
- 90%+ code coverage target
