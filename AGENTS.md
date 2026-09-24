# AGENTS.md

This file provides guidance for AI agents working on the Aegis project.

## Project Overview

Aegis is a high-performance security scanning tool for DevOps, CI/CD pipelines, and AI systems. Built in Rust with 670 detection patterns across 34 categories.

## Key Commands

All of these were verified to pass from the repository root on the current working tree.

```bash
# Build
cargo build --workspace --release

# Test (830 tests across 25 test binaries, all green — measured 2026-09-24)
cargo test --workspace

# Lint (enforced: clean, zero warnings)
cargo clippy --workspace --all-targets -- -D warnings

# Docs (enforced: rustdoc lints deny broken intra-doc links)
cargo doc --workspace --no-deps

# Format (CI checks; add -- --check to match CI exactly)
cargo fmt --all

# Coverage (measured ~96.9% lines / ~97.5% regions; requires cargo-llvm-cov)
cargo llvm-cov --workspace
```

`cargo clippy --workspace --all-targets -- -D warnings` is an **enforced gate**, not an aspiration. It runs as a dedicated CI job on every PR and push to `main` and currently passes clean. Every workspace crate also opts into a shared `[lints]` block (`pedantic`, `rust_2018_idioms`, `missing_docs`, `unsafe_code`/`unwrap_used`/`expect_used`/`panic` denied) from the root `Cargo.toml`, so most lint findings surface as errors during a plain build too. Unwinding panics are denied in production code — errors must be values; test code is exempt via `clippy.toml`. Fix the code; do not add an allow (the few deliberate exceptions carry an inline `#[allow]` with the invariant it protects). A `Rustdoc` CI job runs `cargo doc` with `-D warnings`, enforcing the `[lints.rustdoc]` table.

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
- **Pattern count**: 670 enabled patterns across 34 categories. `aegis list` reflects enabled rules only; do not quote counts from memory, since the set is actively pruned.
- **Self-scan**: The repository scans itself in CI at high severity over `secrets,security-hardening,web-security`:

  ```bash
  ./target/release/aegis -f json scan . \
    --categories secrets,security-hardening,web-security --severity-threshold high
  ```

  This currently reports **0 findings**. It exits 1 when it reports findings (exit 1 means "findings", not "tool failure"). Synthetic test credentials (the AWS documentation example key) appear in a few `#[cfg(test)]` fixtures and are suppressed with a same-line `aegis:ignore:aws-secret-key,env-credential-assignment -- synthetic fixtures` directive — the directive must sit on the **same line as the finding**, or it does not take effect. Check this list before assuming a new finding is yours.

## Branch and Commit Policy

- `main` is **PR-only**: squash merges, and every merge must be green on the full gate set (fmt, clippy, 3-OS test matrix, build, coverage, cargo-audit, cargo-deny, CodeQL). Direct pushes are not the workflow.
- Commit subjects follow **Conventional Commits** (`feat(core): ...`, `fix(mcp): ...`), and PR squashes carry the PR number.
- CI runs on pushes to `main` and on `pull_request` targeting `main`. The release workflow is **not** tag-triggered: it is a `workflow_dispatch` job that takes the tag as an input and runs `scripts/release/build.sh` then `scripts/release/publish.sh` — the same scripts GitForge's pipeline runs, so either path produces the same asset set.

## Release Process

Releases are **GitForge-first**: the GitForge pipeline (see `docs/guides/RELEASES.md`) runs `scripts/release/build.sh` and `scripts/release/publish.sh` against the tag and mirrors the assets to the GitHub release. The `release.yml` workflow on GitHub is the equivalent dispatch path — same scripts, same asset set — triggered via `workflow_dispatch` with the tag as its input.

1. Bump the single workspace version in the root `Cargo.toml` and refresh `Cargo.lock` plus `fuzz/Cargo.lock`, then land that as its own PR.
2. Create a tag on that bumped commit: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
3. Push the tag and run the release (GitForge pipeline first; the GitHub workflow takes the same tag as a `workflow_dispatch` input).
4. `publish.sh` uploads the **10 expected assets** — 5 platform archives (Linux x86_64/ARM64, macOS x86_64/ARM64, Windows x86_64), `aegis-wasm.wasm`, `source.tar.gz`, `source.zip`, `checksums.txt`, `attestation.json` — verifies all of them are visible on the release, and only then flips it from draft to published.

Note: a tag that was already published once cannot be reused — deleting and re-pushing an immutable tag will not re-run asset upload. Cut a new tag instead.

## License

Apache-2.0 (NOT MIT OR Apache-2.0)

## Quality Requirements

- All tests must pass (`cargo test --workspace`)
- Clippy must be clean (`-D warnings`) — enforced by CI
- Format must be clean (`cargo fmt --all -- --check`)
- Coverage gate is 95% project / 90% patch per `codecov.yml` (ratcheted to just below measured reality; never lowered to make a regression pass); `cargo llvm-cov --workspace --summary-only` measures ~96.9% lines and ~97.5% regions, with the wasm crate and the root placeholder binary excluded from the gate
- `cargo deny check` and `cargo audit` must pass
