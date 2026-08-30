# Aegis Handoff — Security Scanner

**Last Updated:** 2026-08-30
**Evidence boundary (central audit):** branch `platform-handoff/aegis-w2-03`, HEAD `9f875db`, 1 dirty status entry (`Cargo.lock`). Refresh this boundary before relying on any test or rating below; numeric ratings are historical context, not release gates.
**Status:** 🔄 Active — source security gates validated; deployment and external promotion evidence pending
**Location:** `/nas/Temp/repos/aegis`
**Rating:** 8.5/10

> **Current execution authority:** Use `/nas/Temp/repos/Platform-Architecture/docs/planning/HANDOFF_AUDIT_2026-08-13.md` (`HANDOFF_AUDIT_2026-08-13.md`) for verified cross-repository findings and `/nas/Temp/repos/Platform-Architecture/docs/planning/CODEX_CLI_EXECUTION_PACKETS_2026-08-13.md` (`CODEX_CLI_EXECUTION_PACKETS_2026-08-13.md`) for bounded implementation sessions. Aegis is the intended active security successor to Atheon-Enhanced; release, stdio, pattern-count, and benchmark claims remain unverified until reproduced from this checkout.

---

## Project Overview

Aegis is a Rust security scanner and intended successor to Atheon-Enhanced (Go). Historical planning claims it is 12x faster, has 20% smaller binaries, and has 620 patterns across 32 categories; reproduce those claims from repository artifacts before treating them as guarantees.

Key exclusive features: daemon mode, WASM support, AST-level analysis, clone detection.

---

## Architecture

```
aegis-core/       — Core scanning engine (lib)
aegis-cli/        — Command-line interface
aegis-mcp/        — MCP server (stdio transport)
aegis-daemon/     — Long-running daemon mode
aegis-bundler/    — Pattern bundle creation/packaging
aegis-patterns/   — 620 patterns, 32 categories
aegis-wasm/       — WebAssembly target
```

**MCP Protocol:** 2024-11-05 over stdio
**Pattern Format:** YAML bundles loaded at runtime

---

## Test Status

```
cargo test --workspace  ✅ ALL PASS
cargo clippy --workspace --all-targets -- -D warnings  ✅ PASSES CLEANLY
```

41 tests passing across core crates. MCP tests are slow (60+ sec each — spawns new process per test).

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
| `aegis scan <path>` | Scan directory for security issues |
| `aegis init` | Initialize Aegis configuration |
| `aegis bundle` | Create pattern bundle |
| `aegis daemon` | Start long-running daemon |
| `aegis mcp` | Start MCP server |

---

## Enhancement Roadmap (from ENHANCEMENT_ROADMAP.md)

### Phase 1 — Production Hardening
- [x] Core scanning engine complete
- [x] 620 patterns across 32 categories
- [x] CLI and MCP server
- [x] Clippy clean
- [ ] Publish to crates.io (`cargo publish`)
- [ ] Add more comprehensive integration tests

### Phase 2 — AST Analysis (IN PROGRESS)
- [ ] Implement real AST-based parsing per language
- [ ] Clone detection at semantic level
- [ ] Proximity matching (find similar code blocks)
- [ ] ML/regex hybrid detection

### Phase 3 — API Verification
- [ ] Verify API call patterns (OAuth, API keys, endpoints)
- [ ] Protocol-specific vulnerability detection

---

## Known Issues

1. **MCP tests slow** — each test spawns a new process, takes 60+ seconds
2. **AST analysis stubs** — `ast.rs` and `clone.rs` modules are structural stubs, not yet implemented
3. **No `build.rs`** for pattern generation — patterns are loaded from YAML bundles at runtime

---

## Migration from Atheon-Enhanced

See: `/nas/Temp/repos/Platform-Architecture/docs/architecture/AEGIS_ATHEON_MIGRATION.md`

Key changes:
- Binary: `atheon` → `aegis`
- `atheon scan` → `aegis scan`
- Config: `~/.atheon.yaml` → `~/.aegis.yaml`
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

1. **Pattern format:** YAML files in `aegis-patterns/` — each pattern has `id`, `name`, `category`, `severity`, `regex`, `message`
2. **Scanner flow:** `scan_dir` → detect language → load patterns → regex scan → deduplicate → report
3. **MCP uses stdio** — JSON-RPC 2.0 requests on stdin, responses on stdout
4. **Daemon mode** — long-running process that accepts scan requests over HTTP or Unix socket
5. **No runtime dependencies** — all patterns compiled in; no external services needed

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
