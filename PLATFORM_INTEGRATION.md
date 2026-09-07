# Platform Integration: Aegis

**Component:** Aegis Security Scanner  
**Template version:** 1.0  
**Created:** 2026-08-24  
**Status:** Active security enforcement component; integration contract documented

## Role

Aegis is the deterministic security and policy scanning boundary for source trees, CI/CD jobs, AI-assisted development, and MCP-connected tools. It detects secrets, vulnerabilities, policy violations, unsafe AI/MCP patterns, and related code-quality risks, returning human-readable, JSON, or SARIF findings. Every scan also produces a redacted, versioned scan receipt that callers can persist as evidence without risking secret disclosure.

## Ownership Boundary

Aegis owns scanning rules, pattern bundles, severity/risk evaluation, scan lifecycle results, CLI/MCP transport behavior, and SARIF/JSON serialization. Aegis also owns the scan receipt schema and produces receipts for CLI, MCP, and daemon scans (`aegis_core::ScanReceipt`, schema version 1).

The platform orchestration layer owns task dispatch, provider/model selection, retries, and approval workflow; it consumes the receipts Aegis emits rather than constructing its own. GitForge owns build/test execution and CI/CD job lifecycle. Control Center owns user-facing status and approval presentation. Aegis does not own model routing, repository mutation, or release promotion.

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

Run the Unix daemon when a socket-based long-lived scanner is required. It binds `/tmp/aegis-daemon.sock` by default; override with `AEGIS_DAEMON_SOCKET_PATH` and confine the scan root with `AEGIS_DAEMON_SCAN_ROOT`:

```bash
cargo run --release -p aegis-daemon
```

## Health and Smoke Commands

Aegis is a process/stdio component rather than an HTTP service. Use a deterministic CLI smoke check. Note that `--format` is a **top-level** option and must precede the subcommand, and that reading stdin requires `--stdin`:

```bash
cargo run --release -p aegis-cli -- --help
printf 'credential = "test-only"\n' \
  | cargo run --release -p aegis-cli -- --format json scan --stdin
```

The second command returns a JSON document with at least one finding and exit code 1. Exit code 1 means "findings reported", not "tool failure". The `stats` block agrees with the `findings` array (`finding_count` equals its length).

For transport health, start `aegis-mcp` from the configured allowed root and send line-delimited JSON-RPC 2.0 requests. Diagnostic logging is written to stderr; stdout must contain only JSON responses.

**Protocol boundary:** the server implements a custom JSON-RPC method set — `scan_string`, `scan_file`, `scan_dir`, `scan_env`, `list_patterns`, `list_categories`, and `update_bundle`. These are not a superset of MCP and there is currently **no** MCP lifecycle or tool-discovery adapter: `initialize`, `notifications/initialized`, `tools/list`, and `tools/call` all return JSON-RPC error `-32601 Method not found`. A client that requires standard MCP discovery cannot talk to Aegis today without a translation shim. All registered methods share the same sandboxed scanner functions.

`update_bundle` installs either the embedded rule set (633 patterns) or a bundle loaded from a sandboxed path, and reports the installed `pattern_count`.

## API Surface

### Inbound APIs

| Interface | Method/operation | Purpose |
|-----------|------------------|---------|
| CLI | `aegis --format <fmt> scan [path]` | Scan files/directories and return findings |
| CLI | `aegis scan --env` | Scan environment variables |
| CLI | `aegis scan --stdin` | Scan piped content |
| CLI | `aegis scan --staged` | Scan the git index for pre-commit checks |
| CLI | `aegis scan --baseline <file>` | Suppress previously recorded findings; exit code reflects new findings only; the baseline file itself is excluded from the scan |
| CLI | `aegis list` / `enable` / `disable` | Inspect and toggle bundled detection patterns |
| CLI | `aegis update` | Reinstall the pattern bundle |
| CLI | `aegis benchmark` | Measure scan throughput against a path |
| MCP stdio | `scan_string` | Scan in-memory content; params `[content, source]` |
| MCP stdio | `scan_file` | Scan one file inside the sandbox |
| MCP stdio | `scan_dir` | Scan a directory inside the sandbox |
| MCP stdio | `scan_env` | Scan environment variables |
| MCP stdio | `list_patterns` / `list_categories` | Introspect the rule set |
| MCP stdio | `update_bundle` | Swap the serving rule set |
| Unix daemon | line-delimited JSON over `AEGIS_DAEMON_SOCKET_PATH` | Long-lived scan requests; Unix-only |

The MCP and daemon sandboxes differ. MCP confines paths to the server process's working directory and rejects anything else with JSON-RPC `-32602`. The daemon canonicalizes every request against its approved scan root and refuses paths — including symlink escapes — that resolve outside it.

### Outbound APIs

| Component | Endpoint/interface | Purpose |
|-----------|--------------------|---------|
| Filesystem | local paths | Read bounded scan targets, `.aegisignore`, and `.aegis.yml` custom patterns |
| Pattern bundle | compiled Rust rules in `aegis-patterns` | Load the pattern snapshot for a scan; not a runtime YAML fetch |
| Environment | process variables | `scan_env` input and `AEGIS_SOURCE_REVISION` receipt attribution |
| Control Center adapter | repository-owned integration | Report scan lifecycle/results; adapter must not bypass Aegis policy |

Aegis makes no network calls during a deterministic scan. It does not call Amortyx or external model providers.

### Exit Codes

`aegis` exit codes are coarse and must not be read alone:

- `0` — scan completed with no surviving findings.
- `1` — scan completed with findings.
- `1` — the scan itself failed (for example an unreadable or nonexistent path).

Because findings and scan errors share exit code 1, a CI integration must distinguish SAFE, FINDINGS, and BLOCKED by writing `--output-file` and then checking that the file exists, is non-empty, and parses. This is exactly what `.github/workflows/aegis-scan.yml` does.

### Result Payloads

`--format json` emits a document with two top-level keys, `findings` and `stats`. Each finding carries `id`, `pattern`, `category`, `severity`, `confidence`, `location` (`file`, `line`, `column`), `description`, `tags`, `kind`, `fingerprint`, and `stable_id`. `stats` carries `bytes_scanned`, `files_scanned`, `files_skipped`, `files_failed`, `finding_count`, `suppressed_count`, `patterns_matched`, `scan_time_ms`, `io_time_ms`, `workers_used`, `files_by_extension`, `findings_by_category`, `findings_by_severity`, and `inspection_ledger`. Findings never include the matched source text.

`--format sarif` emits a SARIF 2.1.0 document: `version` plus `runs[]`, each run holding `tool.driver` (`name`, `version`, `rules[]`), `results[]`, and `properties.inspectionLedger`. Severity maps to SARIF level as critical/high → `error`, medium → `warning`, low → `note`, unknown → `none`.

Every MCP and daemon scan response embeds a `receipt` in its payload (`Option<ScanReceipt>` on the daemon, absent for errors and for `list_patterns`). The CLI builds the same receipt for `scope: "cli_scan"` but does **not** inline it in `--format json`; it writes it atomically to the path named by `AEGIS_RECEIPT_FILE` when that variable is set. A receipt records `schema_version`, `receipt_id`, `created_at`, `source`, `scope`, `profile`, optional `source_revision` and `config_digest`, `finding_count`, `risk_level`, `risk_score`, redacted `findings`, `stats`, and `inspection_ledger`. Matched content is stripped before serialization, so persisting a receipt cannot disclose the secret that triggered a rule. Consult `inspection_ledger` (via `ScanReceipt::allows_safe`) before treating a receipt as a clean pass — a scan that excluded units is not the same as a scan that analyzed them.

The CLI is fail-closed about receipts: it removes any existing `AEGIS_RECEIPT_FILE` target before scanning, so a failed scan can never leave a stale receipt behind to be mistaken for evidence of a fresh pass.

## Depends On

- Rust toolchain compatible with the workspace MSRV (`rust-version = "1.75"` in the root `Cargo.toml`). Note that CI builds and tests with `stable`; the MSRV is declared but not currently exercised by a dedicated CI job.
- Bundled Aegis pattern definitions (compiled into the binary; no download step)
- Optional configuration/profile files (`.aegisignore`, `.aegis.yml`)
- Unix socket support for the daemon crate (Linux, macOS); unsupported on Windows

## Used By

- GitForge CI/CD security gates
- Control Center pre-pipeline and scan-status adapters
- MCP clients and agent harnesses (custom JSON-RPC only; see the protocol boundary note above)
- Local developer pre-commit or pre-push checks
- Release validation workflows

## Required Environment Variables

Aegis has no required secret environment variable for the basic CLI/MCP path. Configuration is profile/file driven. CI integrations may provide ordinary workflow variables for scan thresholds and output paths.

| Variable | Description | Example |
|----------|-------------|---------|
| `RUST_BACKTRACE` | Enables Rust diagnostics during development/CI | `1` |
| `AEGIS_SOURCE_REVISION` | Optional VCS revision recorded in scan receipts; informational only | `main@abc1234` |
| `AEGIS_RECEIPT_FILE` | Path the CLI writes its scan receipt to, atomically; must not be empty when set | `/tmp/aegis-receipt.json` |
| `AEGIS_DAEMON_SOCKET_PATH` | Daemon Unix socket location | `/run/aegis/aegis.sock` |
| `AEGIS_DAEMON_SCAN_ROOT` | Canonical directory the daemon confines scan paths to | `/workspace/repo` |
| `AEGIS_DAEMON_ALLOWED_UIDS` | Comma-separated extra peer UIDs allowed on the socket | `1000,1001` |
| `AEGIS_DAEMON_ALLOWED_GIDS` | Comma-separated extra peer primary GIDs allowed on the socket | `990` |
| `SCAN_SEVERITY` | CI wrapper input for the minimum severity threshold | `high` |
| `SCAN_PRESET` | CI wrapper input for the scan preset | `pipeline` |

There is no `AEGIS_CONFIG` variable; configuration is supplied through the `-c/--config` CLI flag, `.aegisignore`, and `.aegis.yml`.

The daemon authorizes peers with `SO_PEERCRED` before reading a single request byte. The socket owner is always allowed; extra UIDs or primary GIDs may be added through the allowlist variables above. The socket mode is `0600`, or `0660` when a group allowlist is configured, and the application-level check remains authoritative regardless.

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

All of these were verified to pass from the repository root on the current working tree, including clippy with `-D warnings`.

The repository measures 97.2% line coverage and 94.5% region coverage against a 90% project / 85% patch gate. The wasm crate and the workspace root's placeholder binary are excluded from the gate because they need a wasm runtime or are trivial. Coverage tooling:

```bash
cargo llvm-cov --workspace
```

## Platform Acceptance Contract

A platform promotion may claim Aegis integration only when all of the following are evidenced:

- the exact Aegis commit and pattern bundle are recorded;
- the deterministic CLI smoke scan returns parseable output;
- the custom JSON-RPC methods return valid responses;
- the custom JSON-RPC path returns only machine-readable stdout and keeps diagnostics on stderr;
- findings and blocked/error states are distinguishable from a clean result, using the output file rather than the exit code alone, since findings and scan errors both exit 1;
- SARIF output is preserved as an artifact when CI scanning is enabled;
- GitForge records the Aegis-produced scan receipt and does not treat a transport failure as a clean scan;
- Control Center displays the scan lifecycle without inventing a success state, and consults `inspection_ledger` rather than assuming an empty finding list means full coverage;
- no credentials or raw secret findings are copied into receipts or logs — Aegis redacts receipts by construction, and callers must not re-attach matched text.

## Current Gaps

- [ ] No MCP lifecycle adapter exists (`initialize`, `tools/list`, `tools/call` are unimplemented and return `-32601`). Standard MCP clients need a translation shim, or the adapter needs building, before Aegis can be registered in an MCP client's native tool list.
- [ ] Validate each custom JSON-RPC tool operation through the platform's actual MCP runner.
- [ ] Validate the GitForge runner's fail-closed handling for `SAFE`, `FINDINGS`, and `BLOCKED` outcomes, given that findings and scan errors share exit code 1.
- [ ] Resolve the divergent `platform-handoff/aegis-w2-03` branch: it holds 23 commits not in `main`, and `main` has moved 43 commits past their merge base. Confirm whether anything unique there still needs promoting.
- [ ] Run the WASM gate on the Fedora builder and retain its artifact receipt.
- [ ] Resolve remaining release/CI hardening items identified in the Platform-Architecture Aegis handoff before production promotion.

## VIVERE Boundary

VIVERE is a separate experimental project. It is not an Aegis dependency, does not share Aegis runtime ownership, and must not be treated as part of the Aegis production security boundary. Cross-project references belong in Platform-Architecture planning documents only.
