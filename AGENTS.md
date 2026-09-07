# AGENTS.md

This file provides guidance for AI agents working on the Aegis project.

## Project Overview

Aegis is a high-performance security scanning tool for DevOps, CI/CD pipelines, and AI systems. Built in Rust with 633 detection patterns across 33 categories.

## Key Commands

All of these were verified to pass from the repository root on the current working tree.

```bash
# Build
cargo build --workspace --release

# Test (~729 tests across 30 test binaries, all green)
cargo test --workspace

# Lint (enforced: clean, zero warnings)
cargo clippy --workspace --all-targets -- -D warnings

# Format (CI checks; add -- --check to match CI exactly)
cargo fmt --all

# Coverage (97.2% lines / 94.5% regions measured; requires cargo-llvm-cov)
cargo llvm-cov --workspace
```

`cargo clippy --workspace --all-targets -- -D warnings` is an **enforced gate**, not an aspiration. It runs as a dedicated CI job, runs again in the release workflow's test job, and currently passes clean. Every workspace crate also opts into a shared `[lints]` block (`pedantic`, `rust_2018_idioms`, `missing_docs`, `unsafe_code = deny`) from the root `Cargo.toml`, so most lint findings surface as errors during a plain build too. Fix the code; do not add an allow.

## Architecture

Workspace members live under `crates/`:

- **aegis-core**: Core scanning engine — pattern matching, AST/clone/CFG analyzers, risk scoring, suppression, receipts, `.aegisignore`, custom user patterns
- **aegis-cli**: Command-line interface (`aegis`, plus the scan/list/enable/disable/update/benchmark subcommands)
- **aegis-patterns**: Detection pattern definitions as Rust source, with generated examples backing the rule-liveness tests
- **aegis-mcp**: MCP server over stdio
- **aegis-daemon**: Unix-only daemon mode
- **aegis-bundler**: Pattern bundler tool
- **aegis-wasm**: WASM bindings for browser environments

The workspace root package itself only contributes the `aegis-bootstrap` placeholder binary, which prints a pointer to the real CLI so shared profile/dependency configuration has somewhere to live.

## Important Notes

- **WASM**: The aegis-wasm crate provides WASM bindings. It must be built with `cargo build --target wasm32-unknown-unknown --package aegis-wasm` (a normal `cargo build --workspace` does not produce it). The browser binding keeps `matched_text` on each finding, unlike the native serialization, which strips it.
- **Daemon**: aegis-daemon is Unix-only due to Unix domain sockets. Every code path is `#[cfg(unix)]`; on Windows the binary builds but exits 1 with an explanatory message.
- **Tokio**: aegis-core uses tokio with only the `sync`, `fs`, `io-util`, and `rt` features, and they are optional. Other crates use `features = ["full"]`.
- **Pattern count**: 633 enabled patterns across 33 categories. `aegis list` reflects enabled rules only; do not quote counts from memory, since the set is actively pruned.
- **Self-scan**: The repository scans itself in CI at high severity over `secrets,security-hardening,web-security`:

  ```bash
  ./target/release/aegis -f json scan . \
    --categories secrets,security-hardening,web-security --severity-threshold high
  ```

  This currently reports **2 known findings** and exits 1 (exit 1 means "findings", not "tool failure"). Both are `env-credential-assignment` hits on the AWS documentation example key inside `#[cfg(test)]` fixtures — `crates/aegis-mcp/src/tools.rs:373` and `crates/aegis-daemon/src/lib.rs:900`. Each already carries an `aegis:ignore:aws-secret-key` directive, but it sits on the `.expect(...)` line rather than the flagged line, so it does not take effect. Check this list before assuming a new finding is yours, and put any new directive on the same line as the finding.

## Branch and Commit Policy

- `main` is **PR-only**: squash merges, and every merge must be green on the full gate set (fmt, clippy, 3-OS test matrix, build, coverage, cargo-audit, cargo-deny, CodeQL). Direct pushes are not the workflow.
- Commit subjects follow **Conventional Commits** (`feat(core): ...`, `fix(mcp): ...`), and PR squashes carry the PR number.
- CI and the release workflow both run on `main` and on `pull_request` targeting `main`.

## Release Process

1. Bump the single workspace version in the root `Cargo.toml` and refresh `Cargo.lock` plus `fuzz/Cargo.lock`, then land that as its own PR.
2. Create a tag on that bumped commit: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
3. Push tag: `git push origin vX.Y.Z`
4. GitHub Actions builds on tag push, uploads assets to a **draft** release, verifies all 9 expected assets are present, and only then publishes it. Assets are uploaded while the release is still mutable because GitHub rejects uploads to a published release.
5. Release workflow builds: Linux (x86_64 + ARM64), macOS (x86_64 + ARM64), Windows, WASM, plus source archives and checksums.

Note: a tag that was already published once cannot be reused — deleting and re-pushing an immutable tag will not re-run asset upload. Cut a new tag instead.

## License

Apache-2.0 (NOT MIT OR Apache-2.0)

## Quality Requirements

- All tests must pass (`cargo test --workspace`)
- Clippy must be clean (`-D warnings`) — enforced by CI
- Format must be clean (`cargo fmt --all -- --check`)
- Coverage target is 90% project / 85% patch per `codecov.yml`; `cargo llvm-cov --workspace --summary-only` measures 97.2% lines and 94.5% regions, with the wasm crate and the root placeholder binary excluded from the gate
- `cargo deny check` and `cargo audit` must pass
