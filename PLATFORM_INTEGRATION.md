# Platform Integration: Aegis

**Component:** Aegis Security Scanner  
**Template version:** 1.0  
**Created:** 2026-08-24  
**Status:** Active security enforcement component; integration contract documented

## Role

Aegis is the deterministic security and policy scanning boundary for source trees, CI/CD jobs, AI-assisted development, and MCP-connected tools. It detects secrets, vulnerabilities, policy violations, unsafe AI/MCP patterns, and related code-quality risks, returning human-readable, JSON, or SARIF findings.

## Ownership Boundary

Aegis owns scanning rules, pattern bundles, severity/risk evaluation, scan lifecycle results, CLI/MCP transport behavior, and SARIF/JSON serialization.

The platform orchestration layer owns task dispatch, provider/model selection, retries, receipts, and approval workflow. GitForge owns build/test execution and CI/CD job lifecycle. Control Center owns user-facing status and approval presentation. Aegis does not own model routing, repository mutation, or release promotion.

## Canonical Repo Path

```text
/nas/Temp/repos/aegis
```

Canonical upstream: `https://github.com/aliasfoxkde/aegis.git`

## Startup Commands

Build the CLI:

```bash
cargo build --workspace --release
```

Run a local MCP server over stdio:

```bash
cargo run --release -p aegis-mcp
```

Run the Unix daemon when a socket-based long-lived scanner is required:

```bash
cargo run --release -p aegis-daemon
```

## Health and Smoke Commands

Aegis is a process/stdio component rather than an HTTP service. Use a deterministic CLI smoke check:

```bash
cargo run --release -p aegis-cli -- --help
printf 'credential = "test-only"\n' | cargo run --release -p aegis-cli -- scan --format json
```

For MCP transport health, start `aegis-mcp`, send an `initialize` request, and require a valid JSON-RPC response on stdout. Diagnostic logging must remain on stderr.

## API Surface

### Inbound APIs

| Interface | Method/operation | Purpose |
|-----------|------------------|---------|
| CLI | `aegis scan [path]` | Scan files/directories and return findings |
| CLI | `aegis scan --env` | Scan environment variables |
| CLI | `aegis list` | List bundled detection patterns |
| CLI | `aegis update` | Update the pattern bundle when configured |
| MCP stdio | `scan_string` | Scan in-memory content |
| MCP stdio | `scan_file` | Scan one file |
| MCP stdio | `scan_dir` | Scan a directory |
| MCP stdio | `scan_env` | Scan environment variables |
| Unix daemon | configured local socket | Long-lived scan requests where enabled |

### Outbound APIs

| Component | Endpoint/interface | Purpose |
|-----------|--------------------|---------|
| Filesystem | local paths | Read bounded scan targets and configuration |
| Pattern bundle | bundled YAML/data | Load the immutable pattern snapshot for a scan |
| Control Center adapter | repository-owned integration | Report scan lifecycle/results; adapter must not bypass Aegis policy |

Aegis does not call Amortyx or external model providers during deterministic scanning.

## Depends On

- Rust toolchain compatible with the workspace MSRV (`1.75` per repository policy)
- Bundled Aegis pattern definitions
- Optional configuration/profile files
- Optional Unix socket support for the daemon crate

## Used By

- GitForge CI/CD security gates
- Control Center pre-pipeline and scan-status adapters
- MCP clients and agent harnesses
- Local developer pre-commit or pre-push checks
- Release validation workflows

## Required Environment Variables

Aegis has no required secret environment variable for the basic CLI/MCP path. Configuration is profile/file driven. CI integrations may provide ordinary workflow variables for scan thresholds and output paths.

| Variable | Description | Example |
|----------|-------------|---------|
| `RUST_BACKTRACE` | Enables Rust diagnostics during development/CI | `1` |
| `AEGIS_CONFIG` | Optional explicit configuration path, when supported by the selected command | `/workspace/aegis.toml` |
| `SCAN_SEVERITY` | CI wrapper input for the minimum severity threshold | `high` |
| `SCAN_PRESET` | CI wrapper input for the scan preset | `pipeline` |

Do not place provider credentials, repository tokens, or raw findings containing secrets in this document or in source control.

## Test and Quality Commands

Required repository gates:

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --release
cargo build --target wasm32-unknown-unknown --package aegis-wasm
```

The repository targets 90%+ coverage. Coverage tooling is environment-dependent:

```bash
cargo llvm-cov --workspace
```

## Platform Acceptance Contract

A platform promotion may claim Aegis integration only when all of the following are evidenced:

- the exact Aegis commit and pattern bundle are recorded;
- the deterministic CLI smoke scan returns parseable output;
- the MCP initialize/tool path returns valid JSON-RPC;
- findings and blocked/error states are distinguishable from a clean result;
- SARIF output is preserved as an artifact when CI scanning is enabled;
- GitForge records the scan receipt and does not treat a transport failure as a clean scan;
- Control Center displays the scan lifecycle without inventing a success state;
- no credentials or raw secret findings are copied into receipts or logs.

## Current Gaps

- [ ] Validate the MCP initialize and each tool operation through the platform's actual MCP runner.
- [ ] Validate the GitForge runner's fail-closed handling for `SAFE`, `FINDINGS`, and `BLOCKED` outcomes.
- [ ] Add a versioned scan-receipt schema shared with Control Center and GitForge.
- [ ] Confirm Aegis branch promotion from `platform-handoff/aegis-w2-03` to the canonical branch.
- [ ] Run the WASM gate on the Fedora builder and retain its artifact receipt.
- [ ] Resolve remaining release/CI hardening items identified in the Platform-Architecture Aegis handoff before production promotion.

## VIVERE Boundary

VIVERE is a separate experimental project. It is not an Aegis dependency, does not share Aegis runtime ownership, and must not be treated as part of the Aegis production security boundary. Cross-project references belong in Platform-Architecture planning documents only.

