# Aegis Handoff — Security Scanner

**Last Updated:** 2026-09-07
**Evidence boundary (central audit):** branch `main`, HEAD `5717e06f231157b85f319a8d8584addee0954f39`, 0 dirty status entries. The code boundary is the clean `main` checkout; older phase and rating statements below remain historical context, not release gates.
**Status:** 🔄 Active — CI (3-OS test matrix, clippy `-D warnings`, cargo-audit + cargo-deny, CodeQL, coverage), 729 workspace tests, and the release workflow are evidenced in-repo; independent stdio, deployment, and enforced consumer-gate qualification remain pending
**Location:** `/nas/Temp/repos/aegis`
**Rating:** 8.5/10

> **Current execution authority:** Use `/nas/Temp/repos/Platform-Architecture/docs/planning/HANDOFF_AUDIT_2026-08-13.md` for verified cross-repository findings and `/nas/Temp/repos/Platform-Architecture/docs/planning/CODEX_CLI_EXECUTION_PACKETS_2026-08-13.md` for bounded implementation sessions. Aegis is the intended active security successor to Atheon-Enhanced; release, stdio, and benchmark claims remain unverified until reproduced from this checkout. Pattern count and category count are reproducible here: 633 across 33 categories (see `docs/patterns/README.md`, freshness-tested in CI).

---

## Project Overview

Aegis is a Rust security scanner and intended successor to Atheon-Enhanced (Go). Historical planning claims it is 12x faster and has 20% smaller binaries; reproduce those claims from repository artifacts before treating them as guarantees.

Key exclusive features: daemon mode, WASM support, AST-level analysis, clone detection.

---

## Architecture

```
aegis-core/       — Core scanning engine (lib)
aegis-cli/        — Command-line interface (binary: aegis)
aegis-mcp/        — MCP server (binary: aegis-mcp, stdio transport)
aegis-daemon/     — Long-running daemon (binary: aegis-daemon, Unix socket)
aegis-bundler/    — Pattern bundle creation/packaging (binary: aegis-bundler)
aegis-patterns/   — 633 patterns, 33 categories, compiled into the binary
aegis-wasm/       — WebAssembly target
```

**MCP transport:** JSON-RPC 2.0 over stdio (`scan_string`, `scan_file`,
`scan_dir`, `scan_env`, `list_patterns`, `list_categories`,
`update_bundle`); scan paths are sandboxed to the server's working directory
**Pattern format:** Rust structs in `crates/aegis-patterns/src/`, compiled
in; `aegis-bundler` can pack YAML definitions into a gzip+JSON bundle,
which MCP `update_bundle` can install

---

## Test Status

```
cargo test --workspace  ✅ 729 tests
cargo clippy --workspace --all-targets -- -D warnings  ✅ PASSES CLEANLY
```

CI runs the suite on ubuntu, macOS, and Windows, plus cargo-audit,
cargo-deny, CodeQL, and a `cargo llvm-cov` coverage upload (97.24% lines
measured). MCP integration tests spawn a real server process per test and
are the slowest slice of the suite.

---

## Quick Start

```bash
# Scan a directory
cargo run -p aegis-cli -- scan /path/to/repo

# Daemon mode
cargo run -p aegis-daemon

# MCP server
cargo run -p aegis-mcp

# Run tests
cargo test --workspace

# Lint
cargo clippy --workspace --all-targets -- -D warnings
```

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `aegis scan <path>` | Scan directory (also `--file`, `--env`, `--stdin`, `--staged`, `--diff`, `--baseline`) |
| `aegis list` | List patterns (`--enabled`, `--disabled`, `--category`) |
| `aegis enable <pattern>` | Report enabling a pattern (state is not persisted yet) |
| `aegis disable <pattern>` | Report disabling a pattern (state is not persisted yet) |
| `aegis update` | Re-read the in-binary pattern set (no network access) |
| `aegis benchmark <path>` | Time scans with warmup/run averaging |

`aegis-daemon` and `aegis-mcp` are separate binaries, not subcommands.
Top-level flags: `--format human|json|sarif`, `--config <profile>`;
`--verbose` and `--quiet` are global and may appear anywhere.

---

## Enhancement Roadmap (from ENHANCEMENT_ROADMAP.md)

The authoritative phase list is now `docs/PLAN.md` (2026-09 improvement
plan). The original roadmap items, honestly restated:

### Phase 1 — Production Hardening
- [x] Core scanning engine complete
- [x] 633 patterns across 33 categories
- [x] CLI and MCP server
- [x] Clippy clean (workspace `[lints]`: pedantic + `missing_docs`)
- [ ] Publish to crates.io (`cargo publish`)
- [x] Integration tests: 12 suites under `crates/*/tests/`, plus corpus
      precision/recall and per-rule liveness harnesses

### Phase 2 — AST Analysis (PARTIALLY SHIPPED)
- [x] AST-based analysis per language (`aegis-core::ast`: Go, Rust,
      Python, JavaScript/TypeScript; optional `tree-sitter` feature)
- [x] Clone detection at token level (`aegis-core::clone`)
- [ ] Proximity matching (find similar code blocks)
- [ ] ML/regex hybrid detection

### Phase 3 — API Verification
- [ ] Verify API call patterns (OAuth, API keys, endpoints)
- [ ] Protocol-specific vulnerability detection

---

## Known Issues

1. **MCP integration tests are the slow slice** — each one spawns a server
   process
2. **`aegis enable` / `aegis disable` are informational** — pattern state
   is not persisted (`crates/aegis-cli/src/config.rs`)
3. **`ScanOptions::workers` is recorded but not wired to the rayon pool**
4. **PostgreSQL/MySQL output handlers are placeholders** — only SQLite
   writes today (`crates/aegis-core/src/output/database.rs`)
5. **No `build.rs`** — patterns are Rust source in `aegis-patterns` and are
   compiled in, so none is needed

---

## Migration from Atheon-Enhanced

See: `/nas/Temp/repos/Platform-Architecture/docs/architecture/AEGIS_ATHEON_MIGRATION.md`

Key changes:
- Binary: `atheon` → `aegis`
- `atheon scan` → `aegis scan`
- Config: `~/.atheon.yaml` → `--config <profile>` (JSON; presets in
  `config/profiles/`), plus per-scan-root `.aegis.yml` user patterns
- Daemon: `atheon-daemon` → `aegis-daemon`
- MCP: `atheon-mcp` → `aegis-mcp`

---

## Integration with GitForge

GitForge should trigger Aegis scans as a pre-pipeline security gate. Contract schema at:
```
/nas/Temp/repos/Platform-Architecture/contracts/schemas/gitforge-aegis.json
```

Example trigger:
```json
{
  "scan_id": "scan-789",
  "repo_url": "https://gitforge.example.com/user/my-cli-tool",
  "commit_sha": "abc123def456",
  "branch": "main",
  "scan_type": "incremental",
  "severity_threshold": "high",
  "categories": ["secrets", "pii", "security-hardening"]
}
```

---

## Next Steps

1. **P0:** Reproduce local workspace test, clippy, release-build, representative scan, and stdio MCP evidence; record exact commit/output.
2. **P0:** Add Aegis to GitForge CI as a pre-pipeline gate only after the runner lifecycle is live.
3. **P1:** Add Aegis MCP tools to the Control Center service summary only after the stdio contract is tested.
4. **P2:** Verify release/publication claims independently; do not use them as the Control Center baseline gate.

---

## What a New Developer Needs to Know

1. **Pattern format:** Rust structs in `crates/aegis-patterns/src/<category>.rs` —
   `name`, `category`, `match_pattern` (serde key `match`), `severity`,
   `confidence`, optional `min_entropy`, `exclude`, `file_extensions`,
   `env_var`, `reference`, `tags`. See `docs/PATTERNS.md`.
2. **Scanner flow:** `scan_dir` walks (honouring `.gitignore`/`.aegisignore`)
   → selects the per-extension scanner cache → combined-regex pre-filter per
   category → per-pattern regex + entropy + exclude → suppression and
   baseline filtering → findings plus an inspection ledger
3. **MCP uses stdio** — JSON-RPC 2.0 requests on stdin, responses on stdout
4. **Daemon mode** — long-running process that accepts scan requests over a
   Unix socket with peer-credential allowlisting (no HTTP)
5. **No runtime dependencies** — all patterns compiled in; no external
   services needed

## Current Control Center handoff evidence (2026-08-15)

The current Aegis core and CLI test slices pass (276 core tests and 56 CLI
tests). The scanner is the active successor to the former Atheon pre-gate.
The Control Center/GitForge pre-pipeline adapter is not yet proven, so Aegis
must not be reported as an enforced production gate. The next bounded packet
must run Aegis before pipeline trigger, fail closed on scanner/contract errors,
persist a redacted evidence reference, and cover clean, finding, malformed,
and unavailable-scanner outcomes.

## Control Center adapter update (2026-08-15)

Control Center now invokes the operator-configured Aegis CLI before its
GitForge trigger and persists a bounded `aegis_scan_receipts` record. The
disposable adapter proof returned HTTP 202 only after a valid Aegis JSON scan
(`decision=passed`, 0 high, 0 critical) was stored. The full failure matrix,
owner-scoped receipt API/UI, and one clean completed pipeline remain open; the
adapter is therefore an enforced candidate gate, not yet a final promotion
claim.
