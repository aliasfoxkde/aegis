# Aegis Handoff — Security Scanner

**Last Updated:** 2026-09-22
**Status:** 🔄 Active — v0.6.2 released (first release whose assets were
actually built by the GitForge pipeline: 7-step run green, 10 artifacts,
checksums verified at publish); full gate set green (`--locked` fmt /
clippy `-D warnings` / tests); repository self-scan clean (0 findings at
`--severity-threshold high`); releases run GitForge-first with GitHub as the
sync mirror
**Location:** `/nas/Temp/repos/aegis`
**MSRV:** 1.88 (pinned by locked deps `time 0.3.55` / `ignore 0.4.33`; CI and
the release builder image both use `rust:1.88`)

Everything below is reproducible from this checkout. Where a claim could not
be verified locally, it says so.

---

## Project Overview

Aegis is a Rust security scanner: 670 compiled-in detection patterns across
34 categories (secrets, PII, AI/LLM safety, supply chain, Kubernetes,
Terraform, code quality, and more), with entropy gates, per-extension
dispatch, suppression directives, baseline filtering, and a
provable-liveness harness that requires every enabled rule to fire on a
shipped example.

It is the active successor to Atheon-Enhanced (Go). The historical "12x
faster / 20% smaller" claims from the original planning documents were
never reproduced and should not be repeated.

---

## Architecture

```
aegis-core/       — scanning engine (regex+entropy pipeline, AST module,
                    clone detection, anomaly layer, risk scoring, SARIF/JSON
                    output, SBOM)
aegis-cli/        — the `aegis` binary: scan/list/enable/disable/update/
                    benchmark subcommands
aegis-mcp/        — `aegis-mcp` binary: JSON-RPC 2.0 over stdio
                    (custom method set — NOT MCP-discoverable; see below)
aegis-daemon/     — `aegis-daemon` binary: long-running server on a local
                    Unix socket with peer-credential allowlisting (no HTTP)
aegis-bundler/    — packs YAML pattern sets into SHA-256-verified bundles
aegis-patterns/   — the 670 patterns as Rust source, compiled in
aegis-wasm/       — WebAssembly target (`scan_content` → JSON findings)
```

**Pattern authoring loop** (all steps required — a test enforces the last
one):

1. Edit the pattern in `crates/aegis-patterns/src/<category>.rs`.
2. `cargo run -p aegis-patterns --example dump_patterns > /tmp/patterns.json`
3. `python3 scripts/generate_examples.py /tmp/patterns.json crates/aegis-patterns/src/examples.rs`
   (hand-written samples live in that script's `OVERRIDES` dict)
4. `cargo run -p aegis-patterns --example generate_docs` — refreshes
   `docs/patterns/`
5. `cargo test -p aegis-core --test pattern_liveness` — fails if any enabled
   pattern no longer fires on its generated example

**MCP transport:** `aegis-mcp` speaks JSON-RPC 2.0 over stdio and answers
the MCP lifecycle (`initialize`, `notifications/initialized`, `tools/list`,
`tools/call`, `ping`) across protocol revisions 2024-11-05 / 2025-03-26 /
2025-06-18, plus the original custom method set with positional params.
Both surfaces share one implementation; wire shapes are pinned by the
conformance fixtures in `crates/aegis-mcp/tests/fixtures/`. See
`docs/guides/MCP.md`. Scan paths are sandboxed to the server's working
directory.

**Daemon transport:** Unix socket only (env: `AEGIS_DAEMON_SOCKET_PATH`,
`AEGIS_DAEMON_SCAN_ROOT`). There is no HTTP interface and therefore no
Kubernetes Service; cluster usage is the scan CronJob in
`kubernetes/cronjob.yaml`.

---

## Test Status (verified 2026-09-22)

```
cargo fmt --all -- --check                              ✅
cargo clippy --workspace --all-targets --locked -- -D warnings  ✅
cargo test --workspace --locked                         ✅ 764 tests
aegis scan . --severity-threshold high                  ✅ 0 findings
```

Coverage (`cargo llvm-cov --workspace`, local 2026-09-22): 96.93% lines /
93.89% functions / 97.51% regions. CI's Codecov gate is 90% project / 85%
patch — the gate ratchets up with measured reality, never down.

CI also runs: multi-OS test matrix, cargo-audit, cargo-deny, CodeQL, weekly
cargo-fuzz (4 targets), criterion benchmarks, and the corpus
precision/recall harness (0.95 gate). All builds and tests use `--locked`.

---

## Quick Start

```bash
# Scan a directory (exit 1 = findings, 0 = clean)
cargo run -p aegis-cli -- scan /path/to/repo

# JSON/SARIF output — note --format goes BEFORE the subcommand
cargo run -p aegis-cli -- --format sarif scan . --output-file out.sarif

# Profile presets ship in config/profiles/
cargo run -p aegis-cli -- scan . -c config/profiles/production.json

# Pattern management (persists to <config dir>/aegis/pattern-state.json)
cargo run -p aegis-cli -- disable secrets-aws-access-key
cargo run -p aegis-cli -- list --disabled

# Daemon / MCP are separate binaries, not subcommands
cargo run -p aegis-daemon
cargo run -p aegis-mcp

# Gates
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

CLI details: `--format` must precede the subcommand (top-level short `-f`
would collide with `scan --file`); `-c/--config`, `-q`, `-v` are global.
`RUST_LOG` is the only behavior-affecting environment variable.

---

## Release Process (GitForge-first, since v0.6.1)

1. PR-only main, squash merge, full gate set green.
2. Bump version in `Cargo.toml` + `Cargo.lock`, update `CHANGELOG.md`.
3. Tag `vX.Y.Z` and push to **both** remotes (`gitforge` first, then
   `origin`/GitHub mirror).
4. The GitForge `.gitforce.yml` pipeline builds all release assets in the
   builder image (`rust:1.88` + cross targets + rustfmt/clippy — see
   `docker/release-builder/Dockerfile`) and runs the quality gates.
5. `scripts/release/publish.sh` (manual dispatch or local run) verifies the
   tag, collects artifacts from the GitForge pipeline, and mirrors the
   release to GitHub.
6. Download-and-run e2e: fetch a tarball via the GitForge `/content`
   endpoint and scan something with it.

The `.gitforce.yml` trigger list is `[manual, tag]`; the GitHub
`release.yml` workflow is a manual-dispatch fallback only. The pipeline of
record is GitForge. GitHub Actions does run green on this public repo
(CodeQL, 3-OS matrix, coverage) and its CodeQL result gates merges on
GitHub.

v0.6.2 (2026-09-22) is the first release actually built by that pipeline:
a tag push triggers it (a same-commit `push` run also fires — cancel the
duplicate), the single job runs the seven ordered steps, and the runner
collects `artifacts/` (5 platform tarballs, wasm, source archives,
`checksums.txt`, `attestation.json`). `publish.sh` verifies every SHA-256
against the runner receipt before uploading. Two lane-shape rules the run
enforced: test steps must omit `--all-targets` (criterion benches reject
`--test-threads`), and the build step refuses non-tag HEADs by design.

---

## Known Issues (honest, current)

1. **GitForge pipelines run one job** — the deployed trigger path queues
   only the first `needs`-empty job and never schedules dependents, so
   `.gitforce.yml` is a single ordered job (format → clippy → four test
   lanes → release build). Until GitForge wires in its DAG engine, a
   multi-job pipeline here would silently skip everything after the first
   job.
2. **MCP integration tests are the slow slice** — each spawns a real
   server process (and a successful `tools/call` pays the one-time
   pattern compilation).
3. **No crates.io publishing** — binaries ship via release tarballs and
   the container image; a `cargo publish` job (or a recorded decision not
   to) is still open (`docs/PLAN.md` Phase 13).
4. **Performance targets are targets** — the 10GB/min throughput and
   <100MB memory figures in `docs/PLAN.md` are aspirational; only startup
   latency is criterion-measured.
5. **Pattern false-positive tuning is regex-heuristic, not data-driven** —
   the 2026-09-22 audit fixed five false-positive-prone rules by hand
   (hipaa-phi, code-injection-request, mesa-optimization,
   executable-file-upload, k8s-run-as-non-root); there is no measured
   FP-rate harness over a labelled corpus per rule yet.
6. **`ast` proximity matching and ML/regex hybrid detection** remain
   unshipped roadmap items (Phase 14).

Resolved 2026-09-22 (previously listed here): pattern state not persisted
(now `pattern-state.json`), `ScanOptions::workers` ignored (now sizes the
pool), placeholder PostgreSQL/MySQL output handlers (module removed), the
phantom Kubernetes HTTP daemon (replaced by the CronJob), the
non-building Docker image (rebuilt on `rust:1.88-slim` and verified
end-to-end), and `aegis-mcp` not speaking MCP discovery (the lifecycle
and `tools/*` are now implemented and conformance-tested).

---

## What a New Developer Needs to Know

1. **Fail loud, never fake it.** No placeholder implementations, no
   swallowed errors, no synthetic test shortcuts. The Unreleased
   CHANGELOG section documents what happens when this is violated.
2. **Pattern format:** Rust structs in `crates/aegis-patterns/src/` —
   `name`, `category`, `match_pattern` (serde key `match`), `severity`,
   `confidence`, optional `min_entropy`/`exclude`/`file_extensions`/
   `env_var`/`reference`/`tags`. Always regenerate examples + docs after
   editing (loop above).
3. **Scanner flow:** walk (honouring `.gitignore`/`.aegisignore`) →
   per-extension scanner cache → combined-regex pre-filter per category →
   per-pattern regex + entropy + exclude → suppression directives
   (`aegis:ignore:<p1,p2>` on the flagged line) and baseline filtering →
   findings + inspection ledger.
4. **Fix pattern false positives at the regex, not with suppressions** —
   suppressions are for genuinely-flagged fixture lines only. The five
   regex fixes in this cycle each started as "our own repo flags itself."
5. **`--locked` everywhere**, MSRV 1.88, workspace lints are pedantic +
   `missing_docs` at `-D warnings`.
6. **Authoritative planning doc:** `docs/PLAN.md` (phase roadmap with
   delivered/open status). This file summarizes; PLAN.md decides.

---

## Migration from Atheon-Enhanced

See `/nas/Temp/repos/Platform-Architecture/docs/architecture/AEGIS_ATHEON_MIGRATION.md`
for the original mapping (`atheon` → `aegis`, YAML config → `-c` profiles
plus per-root `.aegis.yml`, daemon/MCP binaries renamed). Note that the
Control Center adapter history below is cross-project context: in *this*
repo, the GitForge integration surface is `.gitforce.yml` plus the scan
CronJob contract.

## Control Center adapter status (historical, 2026-08-15)

Control Center invokes the operator-configured Aegis CLI before its GitForge
trigger and persists a bounded `aegis_scan_receipts` record. The adapter
proof (HTTP 202 after a valid `decision=passed` scan receipt) passed; the
full failure matrix, owner-scoped receipt API/UI, and a clean completed
pipeline remained open at last cross-repo audit — the adapter is an enforced
candidate gate, not a promoted one. Verify against
`/nas/Temp/repos/Platform-Architecture/docs/planning/` before relying on
this; it is outside this repository's test boundary.
