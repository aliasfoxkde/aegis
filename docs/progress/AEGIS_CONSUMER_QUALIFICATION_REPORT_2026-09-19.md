# Aegis R7 Consumer Qualification Report

**Date:** 2026-09-19
**Working directory:** `/nas/Temp/work/aegis-qualification-20260919`
**Mode:** Read-only review. No builds, no tests, no daemons, no remote calls.
**Harness:** `cargo metadata`, `cargo build`, `cargo test`, and any non-read-only command require explicit approval per session policy; only read-only git/repo inspection and existing artifacts were used.

---

## 1. Repository state

| Field | Value | Source |
|---|---|---|
| Repo path | `/nas/Temp/work/aegis-qualification-20260919` | `pwd` |
| HEAD | `2eefd884a30a258ff39d6fc58d303de2b8faa935` | `git -C ... rev-parse HEAD` |
| Branch | `codex/aegis-qualification-20260919` | `git -C ... branch --show-current` |
| Remotes | `gitforge http://localhost:42782/mkinney-admin/aegis.git`, `origin https://github.com/aliasfoxkde/aegis.git` | `git -C ... remote -v` |
| Working tree | Clean (`nothing to commit`) | `git -C ... status` |
| Workspace version | `0.6.1` (per root `Cargo.toml [workspace.package]`) | `Cargo.toml:32` |
| Latest tag in repo | `v0.6.1` | `git -C ... tag --list 'v*'` |
| Last release entry | `[0.6.1] - 2026-09-10` | `CHANGELOG.md:8` |
| License | Apache-2.0 (root package and workspace.package) | `Cargo.toml:6,35`; `README.md:246`; `LICENSE` file present |

Last 10 commits:

```
2eefd88 fix(release): use gh release view for the release existence check (#119)
86b7ed6 fix(release): install cross-target std libs in the builder image (#118)
14a92a5 fix(release): make the GitForge quality-gates job pass in its container (#117)
fd2a35c chore(release): bump version to 0.6.1 (#116)
949c60f feat(release): GitForge-built asset matrix with attestation (#115)
eaf7f9e fix: anchor Dockerfile secret detector to directives (#114)
6eb4822 fix: anchor Dockerfile secret detector to directives (#113)
e4176e3 fix: reduce ci-bypass detector false positives
5717e06 chore(release): bump version to 0.6.0 (#110)
c78de35 feat(core): per-language anomaly baselines and detector controls (#109)
```

Recent diffstat (last 5 commits):

```
.gitforce.yml                                |  33 +++
.github/workflows/release.yml                | 297 +++------------------------
CHANGELOG.md                                 |  29 +++
Cargo.lock                                   |  16 +-
Cargo.toml                                   |   2 +-
crates/aegis-core/tests/scanner_behaviors.rs |  13 ++
docs/guides/RELEASES.md                      |  97 +++++++++
fuzz/Cargo.lock                              |   2 +-
scripts/release/Dockerfile                   |  39 ++++
scripts/release/build.sh                     | 155 ++++++++++++++
scripts/release/lib.sh                       |  96 +++++++++
scripts/release/pipeline.sh                  |  31 +++
scripts/release/publish.sh                   |  90 ++++++++
13 files changed, 619 insertions(+), 281 deletions(-)
```

This qualification branch is at SHA `2eefd88` and shares the working tree with the upcoming `0.6.1` release wiring (`feat(release): GitForge-built asset matrix with attestation` plus three `fix(release): ...` follow-ups).


---

## 2. Package and binary inventory

Workspace members per root `Cargo.toml:20-29`:

| Crate | Binary name | Notes |
|---|---|---|
| `aegis-core` | (library) | Scanning engine; feature-gated `output-pipeline`, `tree-sitter`, `tokio`, `jsonschema` (`docs/MODULES.md:166-176`). Public API re-exports `scanner`, `pattern`, `finding`, `risk`, `config`, `bundle`, `entropy`, `ast`, `cfg`, `clone`, `remediation`, `sbom`, `suppression`, `user_patterns`, `receipt`, `benchmark`, `control_center_adapter`. |
| `aegis-cli` | `aegis` | Scan / list / enable / disable / update / benchmark. |
| `aegis-mcp` | `aegis-mcp` | JSON-RPC 2.0 MCP server over stdio. |
| `aegis-daemon` | `aegis-daemon` | Unix domain socket; `#[cfg(unix)]` (Windows builds exit 1 with a message). |
| `aegis-bundler` | `aegis-bundler` | Packs a YAML directory into a gzip+JSON bundle. |
| `aegis-patterns` | (library) | Rust-source pattern corpus, compiled into every binary. |
| `aegis-wasm` | (library, cdylib) | WASM bindings; published as `aegis-wasm.wasm`. |
| root `aegis` | `aegis-bootstrap` | Placeholder binary that prints a pointer to the real CLI (`AGENTS.md:44`). |

`cargo metadata` execution was blocked by the harness approval gate (`This command requires approval`); the inventory above is sourced from `Cargo.toml:20-29` and `docs/MODULES.md:8-17`. The four user-facing binaries plus the WASM artifact are described consistently in `docs/guides/INSTALLATION.md:6`, `docs/architecture/OVERVIEW.md:344-349`, and the release pipeline at `scripts/release/build.sh:54`.

MSRV: `rust-version = "1.75"` (`Cargo.toml:37`).

---

## 3. Aegis claim surface (as documented)

### 3.1 Detection corpus

Per `docs/architecture/OVERVIEW.md:317-345` and `docs/patterns/README.md:1-3`:

- 670 patterns across 34 categories (the on-disk README headers; `CHANGELOG.md:42-49` confirms 660→670 across v0.6.0).
- Patterns are compiled into every Aegis surface (CLI/MCP/daemon/WASM); scans never fetch rules at runtime (`OVERVIEW.md:18-19`).
- Severity distribution (`docs/patterns/README.md:42-46`): 68 critical / 145 high / 188 medium / 269 low. No `info` count line, despite engine support added in v0.5.0 (`CHANGELOG.md:99-104`).
- Custom patterns via `.aegis.yml`/`.aegis.yaml`, validated eagerly at scan start (`OVERVIEW.md:217-225`).
- Statistical anomaly layer: four detectors (`comment-ratio-outlier`, `comment-concentration`, `identifier-diversity-outlier`, `file-size-outlier`), all `Severity::Info`; configurable via CLI/profile (`OVERVIEW.md:99-136`, `CHANGELOG.md:53-69`).

> Numeric disagreement noted: `AGENTS.md:7` claims "633 detection patterns across 33 categories", but `docs/patterns/README.md:1-3` and `CHANGELOG.md` (post-0.5.0) say 670/34. The README+CHANGELOG are the later authoritative numbers; AGENTS.md is stale.

### 3.2 CLI surface (`docs/guides/CLI.md:5-200`)

- Subcommands: `scan`, `list`, `enable`, `disable`, `update`, `benchmark`.
- Global flags: `-f/--format {human,json,sarif}`, `-c/--config`, `-q/--quiet`, `-v/--verbose`.
- Scan flags include `--file`, `--env`, `--stdin`, `--follow-symlinks`, `--categories`, `--severity-threshold`, `--output-file`, `--baseline`, `--diff`, `--staged`, `--all`, `--anomaly-detectors`, `--no-anomalies`.
- Exit codes: 0 clean, 1 findings or scan failure, 2 usage error (`CLI.md:191-198`). With `--baseline`, code 1 means *new* findings only.
- `enable`/`disable` are explicitly informational — state is not persisted (`CLI.md:113-117`).
- `benchmark` has `--compare` for Atheon-Enhanced comparison when `AEGIS_ATHEON_PATH` is set (`CLI.md:144-147`, `docs/guides/CONFIGURATION.md:196`).

### 3.3 MCP server (`docs/guides/MCP.md:11-203`)

- Tools: `scan_string`, `scan_file`, `scan_dir`, `scan_env`, `list_patterns`, `list_categories`, `update_bundle`.
- `scan_file`/`scan_dir` are sandboxed to server CWD (`MCP.md:122-123`).
- Wire: JSON-RPC 2.0 over stdio; responses include `finding_count`, `findings`, `risk_level`, `risk_score`, `stats`, `receipt`.

### 3.4 Daemon (`docs/architecture/OVERVIEW.md:189-202`, `docs/MODULES.md:12`)

- Unix-only; uses Unix domain sockets.
- Env knobs: `AEGIS_DAEMON_SOCKET_PATH`, `AEGIS_DAEMON_SCAN_ROOT`, `AEGIS_DAEMON_ALLOWED_UIDS`, `AEGIS_DAEMON_ALLOWED_GIDS` (`docs/guides/CONFIGURATION.md:191-194`).
- No daemon client/CLI surface documented in the public guides; integration is via env vars + socket path.

### 3.5 Output formats

- Human, JSON, SARIF, CSV (via feature-gated `output-pipeline`) (`OVERVIEW.md:262-269`).
- SBOM: SPDX (JSON), SPDX tag-value, CycloneDX via `aegis-core::sbom` (`OVERVIEW.md:268-269`).

### 3.6 Ignore + suppression

- `.aegisignore` (gitignore-style; `.atheonignore` accepted as legacy alias) + `.gitignore` (`CONFIGURATION.md:147-176`).
- Inline suppressions: `aegis:ignore:<name>`, `aegis:ignore-start` / `aegis:ignore-end`, `aegis:ignore-file`; range and file-level suppression documented (`CHANGELOG.md:218-221`).

### 3.7 Risk model (`OVERVIEW.md:74-95`)

- Severity weights: critical 40 / high 25 / medium 10 / low 3 / info 0.
- Confidence multiplier: high 1.0 / medium 0.7 / low 0.4.
- Category weight configurable; default `secrets` 1.5, `security-hardening` 1.4, `supply-chain` 1.4, `code-quality` 0.8.
- `info` never affects risk score and never flips the exit code (`OVERVIEW.md:94-96`).

### 3.8 Licensing and distribution

- License: Apache-2.0 (`Cargo.toml:6,35`, `README.md:246`, `LICENSE` file present). `AGENTS.md:79` contains contradictory phrasing ("Apache-2.0 (NOT MIT OR Apache-2.0)") that should be tightened.
- Release artifacts per `docs/guides/RELEASES.md:11-22`: `aegis-linux-{x86_64,arm64}.tar.gz`, `aegis-darwin-{x86_64,arm64}.tar.gz`, `aegis-windows-x86_64.tar.gz`, `aegis-wasm.wasm`, `source.{tar.gz,zip}`, `checksums.txt`, `attestation.json`. Each platform archive bundles the four binaries.

### 3.9 Security model (`OVERVIEW.md:272-289`)

- 10 MB default file-size cap; binary-file sniffing; cwd sandboxing in MCP; bundle is fail-closed (schema, duplicate-name, missing-match, bad-regex all abort).
- Patterns ship *inside* the binary — no bundle download required for scans (`OVERVIEW.md:282-286`).


---

## 4. Aegis quality gates (as defined)

The repo documents five enforceable gates and supports several optional checks. None were re-executed during this read-only qualification; results below are taken from on-disk evidence and CI workflow definitions.

| Gate | Local command | Enforced in CI | Evidence on this tree |
|---|---|---|---|
| Format | `cargo fmt --all -- --check` | `ci.yml` job `fmt`; `aegis-scan.yml` toolchain pin includes rustfmt; `.gitforce.yml` job `quality-gates` step `format` | Workflow files inspected. No local run performed (read-only). |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | `ci.yml` job `clippy`; `aegis-scan.yml` toolchain pin; `.gitforce.yml` job `quality-gates` step `clippy` | Workflow files inspected. Workspace `[lints.rust]` and `[lints.clippy]` are `deny`/`warn` (`Cargo.toml:42-60`). |
| Test | `cargo test --workspace` | `ci.yml` job `test` matrix ubuntu/macos/windows; `.gitforce.yml` job `quality-gates` step `test` | Workflow files inspected. AGENTS.md claims "729 tests across 30 test binaries, all green" — not re-verified locally. |
| Build | `cargo build --workspace --release` | `ci.yml` job `build`; release builds via `scripts/release/build.sh` | Workflow files inspected. |
| Coverage | `cargo llvm-cov --workspace` | `ci.yml` job `coverage` → Codecov with `fail_ci_if_error: false`; `codecov.yml` sets 90% project / 85% patch | `codecov.yml` present; threshold is enforced by Codecov (not as a hard CI gate). AGENTS.md quotes "97.2% lines / 94.5% regions measured". |
| Security audit | `cargo audit --ignore RUSTSEC-2024-0421 --ignore RUSTSEC-2026-0097` | `ci.yml` job `security` | Two known transitive vulnerabilities through `jsonrpc` are intentionally suppressed with documented justification. |
| Deny | `cargo deny check` | `ci.yml` job `deny` (advisories, licenses, bans, sources) | `deny.toml` present. |
| CodeQL | `github/codeql-action` rust analysis | `ci.yml` job `codeql` | Workflow inspected; no local run. |
| Self-scan | `./target/release/aegis -f json scan . --categories secrets,security-hardening,web-security --severity-threshold high` | `aegis-scan.yml` jobs `aegis-scan`, `aegis-pr-check`, `aegis-secrets`, `aegis-supply-chain` | AGENTS.md says currently 0 findings; not re-verified (no binary available in this read-only session). |
| Fuzzing | `cargo fuzz run <target>` × 4 targets | `fuzz.yml` weekly (`23 4 * * 1`), manual dispatch | 4 targets: suppression parser, ignore-rule compiler, baseline parser, user-patterns config. |

Pipeline-level consistency checks in `aegis-core` (per `docs/MODULES.md`/`CHANGELOG.md:184-199`):

- `pattern_liveness.rs` — every shipped pattern has a firing example.
- `registry_hygiene.rs` — pattern corpus invariants.
- `corpus_precision_recall.rs` — labelled vulnerable+clean fixtures, fails CI when precision drops.
- `pattern_fixtures.rs` — compliant + violation fixtures per pack.
- `env_var_semantics.rs` — pins the env-scan-only set.

---

## 5. Parity matrix: Aegis vs Atheon-Enhanced

Atheon-Enhanced reference: `/home/mkinney/atheon-enhanced` at HEAD `ba3b4366a925e97242eb9819c3bf184ee9a35c4f` (commit subject `feat(report): add CSV, JSON, summary report generation`). Atheon-Enhanced is Go 1.21+ with 384 YAML pattern files across 29 category directories; the prebuilt `core/patterns.bundle` is 24,333 bytes (gzip-encoded). The README claims 327+ patterns across 23 categories, with older counters in AGENTS.md (274/19). Atheon-Enhanced ships `atheon` and `atheon-mcp` only — no daemon binary.

| Capability | Aegis claim | Aegis artifact | Atheon-Enhanced | Aegis parity verdict |
|---|---|---|---|---|
| Pattern corpus size | 670 patterns / 34 categories (`docs/patterns/README.md`) | `crates/aegis-patterns/src/*.rs` (37 module files, git-tracked) | 327+ / 23 categories per README; 384 YAML files in `community/` (29 category dirs) | **SUPERSET.** Aegis ≥ 2× the rule count and ≥ 11 more categories. |
| Pattern definition form | Rust structs compiled into binary | `crates/aegis-patterns/src/*.rs` + examples.rs | YAML → bundled via `bundler` → `core/patterns.bundle` (gzip), `//go:embed`ed | **DIFFERENT model.** Both ship an embedded set; Aegis also accepts `.aegis.yml` overlays (`OVERVIEW.md:217-225`). |
| CLI | `aegis scan\|list\|enable\|disable\|update\|benchmark` | `crates/aegis-cli/src/main.rs` (binary `aegis`) | `atheon scan\|list\|enable\|disable\|update\|…` (binary `atheon`) | **PARITY on top-level subcommands.** Aegis adds `benchmark --compare` for direct Atheon comparison (`CLI.md:144-147`). |
| Exit codes | 0 / 1 / 2 (with `--baseline` semantics) | `CLI.md:191-198` | Standard Go exit codes (0/1/2) | **PARITY documented.** |
| Output formats | human, JSON, SARIF, CSV (gated), SBOM (SPDX × 2, CycloneDX) | `aegis-core::output`, `aegis-core::sbom` (`OVERVIEW.md:262-269`) | human, JSON, SARIF; CSV/summary added in HEAD `ba3b436`; SBOM is a goreleaser comment stub (disabled — no `syft` available in CI) | **AEGIS SUPERSET** on output formats. Atheon-Enhanced has no SBOM today. |
| MCP server | JSON-RPC 2.0 over stdio; 7 tools, sandboxed CWD | `crates/aegis-mcp` (`aegis-mcp`) | `cmd/mcp` (`atheon-mcp`) — same wire shape | **PARITY on the wire.** Aegis sandboxes paths to CWD; Atheon-Enhanced has parallel sandbox tests (`cmd/mcp/mcp_sandbox_test.go`). |
| Daemon | Unix-only, Unix-socket daemon + UID/GID allowlist | `crates/aegis-daemon` (`aegis-daemon`) | None — Atheon-Enhanced has only CLI + MCP | **AEGIS HAS IT; Atheon does not.** |
| WASM | `aegis-wasm.wasm` shipped in releases | `crates/aegis-wasm`; `aegis-wasm.wasm` per `docs/guides/RELEASES.md:17` | None observed | **AEGIS HAS IT; Atheon does not.** |
| Statistical anomaly detectors | 4 detectors, configurable, all `Severity::Info` | `OVERVIEW.md:99-136`, `ScanOptions::anomaly_detectors` | Not present in Atheon-Enhanced HEAD | **AEGIS HAS IT; Atheon does not.** |
| Inline suppression directives | `aegis:ignore:`, `ignore-start/-end`, `ignore-file`, `-- reason` | `aegis-core/src/suppression.rs` + 4 cargo-fuzz targets | Atheon-Enhanced has an inline suppression mechanism (referenced in `core/`); the exact directive shape is not re-verified here | **PARITY (different syntaxes expected).** |
| Baseline | `--baseline <json>` filters findings; baseline excluded from walk | `CLI.md:23-25`, `CHANGELOG.md:176-181` | Atheon-Enhanced supports a baseline system (mentioned in the enhancement-roadmap research note; specific flag name not re-verified) | **LIKELY PARITY; verify exact flag in a follow-up.** |
| Custom patterns | `.aegis.yml` / `.aegis.yaml`, validated eagerly | `aegis-core/src/user_patterns.rs` | Community YAML definitions ship in-tree (`community/*.yaml`); runtime user patterns not advertised | **AEGIS HAS IT; Atheon relies on in-tree YAML only.** |
| CI quality gates | fmt, clippy, 3-OS test, build, coverage, audit, deny, CodeQL, self-scan, fuzz | `.github/workflows/ci.yml` + `aegis-scan.yml` + `fuzz.yml` | Consolidated CI: lint, doc-check, PR size, test matrix (Go 1.21/1.22/1.23), ARM64 build, multi-OS build; security, stale, wiki, auto-merge workflows | **PARITY on the broad gate set; Aegis adds CodeQL, self-scan SARIF, and 4 fuzz targets.** |
| Release pipeline | GitForge-first (`.gitforce.yml`); `aegis-builder:1` image with zig; 9-asset matrix; `attestation.json` (v1 schema) | `.gitforce.yml`, `scripts/release/{pipeline,build,publish,lib,Dockerfile}`, `docs/guides/RELEASES.md` | Tag-triggered GitHub Actions + GoReleaser (`.goreleaser.yml`); goreleaser produces binaries + checksums; SBOM disabled pending `syft` | **BOTH functional; Aegis has stricter attestation model (attestation.json with cross-checksums).** Both ship checksums.txt; only Aegis ships explicit attestation. |
| Release platforms | linux x86_64/arm64, macOS x86_64/arm64, windows x86_64, WASM, source archives | `scripts/release/build.sh:80`, `docs/guides/RELEASES.md:11-22` | `.goreleaser.yml`: linux/darwin/windows × amd64/arm64 (no Windows/arm64); no WASM | **PARITY on OS; Aegis adds WASM.** |
| Self-scan gating | `aegis-scan.yml` produces SARIF + uploads to GitHub Security tab; SAFE / FINDINGS / BLOCKED classification | `.github/workflows/aegis-scan.yml` (5 jobs, daily cron + PR + dispatch) | `security.yml` (workflow present, contents not re-verified here) | **AEGIS MORE EXPLICIT (multiple scan jobs, SARIF upload, custom exit mapping).** |
| Cross-linker | `cargo-zigbuild` + Zig 0.16.0; darwin binaries zig-linked on the build host, disclosed in `attestation.json` | `scripts/release/Dockerfile`, `docs/guides/RELEASES.md:75-77` | `CGO_ENABLED=0` + `-trimpath`; binaries are native-compiled per OS | **DIFFERENT trade-offs.** Aegis discloses its non-Apple darwin build in the attestation; Atheon relies on goreleaser’s standard matrix. |
| Licensing | Apache-2.0 (root + workspace.package) | `LICENSE`, `Cargo.toml`, `README.md` | MIT (`/home/mkinney/atheon-enhanced/LICENSE`) | **DIFFERENT LICENSES.** Aegis (Apache-2.0) is more restrictive on patent terms; check whether Platform-Architecture has a license-compatibility constraint. |
| Receipts / risk metadata | `ScanReceipt`, `risk_level`, `risk_score`, `stats`, finding fingerprints; `receipt.rs` (`OVERVIEW.md:266`, `MCP.md:148-181`) | `aegis-core/src/receipt.rs` | `Finding` + report generation added in HEAD `ba3b436` | **AEGIS MORE COMPREHENSIVE** (redacted receipts + score/level). |
| Failure posture | Fail-closed bundle loading; abort scan on invalid `.aegis.yml` | `OVERVIEW.md:282-289` | Bundle download + parse has documented sentinel errors (`AGENTS.md:43-46`) | **PARITY in posture.** |
| Cold-start / benchmark receipts | `aegis benchmark` subcommand with `--compare` against Atheon | `CLI.md:144-147`, `CONFIGURATION.md:196` (`AEGIS_ATHEON_PATH`) | Not present | **AEGIS HAS IT.** |

No numeric performance comparison (throughput, cold-start, memory) is asserted; the README's "12x faster than comparable tools" claim is unverified and not reproduced here.


---

## 6. Cold-start / benchmark receipts

- No local build of `aegis` was produced (read-only session, `cargo build` requires approval).
- No prebuilt `aegis` binary is installed in this environment; `aegis`/`atheon` are not present in `/usr/local/bin` or `/home/mkinney/.local/bin`.
- `aegis benchmark --compare <atheon>` and the `AEGIS_ATHEON_PATH` env knob exist by design (`CLI.md:144-147`, `CONFIGURATION.md:196`); the Atheon-Enhanced prebuilt binary at `/home/mkinney/atheon-enhanced/atheon` could be the reference once an Aegis binary is built, but binary execution in this session was blocked by the harness approval gate.
- **Conclusion:** No measured throughput, cold-start, or A/B comparison numbers are produced. Treat the README's "12× faster" claim as unverified.

---

## 7. Pattern counts observed

| Surface | Count | Source |
|---|---|---|
| Aegis pattern modules | 37 files under `crates/aegis-patterns/src/` | `git -C … ls-files` |
| Aegis shipped count | 670 patterns / 34 categories | `docs/patterns/README.md:3` |
| Atheon-Enhanced YAML files | 384 | `find /home/mkinney/atheon-enhanced/community -name '*.yaml' \| wc -l` |
| Atheon-Enhanced category dirs | 29 | `ls /home/mkinney/atheon-enhanced/community \| wc -l` |
| Atheon-Enhanced bundle size | 24,333 bytes (gzip) | `wc -c core/patterns.bundle` |
| Atheon-Enhanced README claim | 327+ patterns / 23 categories | `README.md` badge area |

The Aegis-vs-Atheon ratio is documented at the README/category-table level only; the exact "active rules per category" numbers require running `aegis list` against an installed binary.

---

## 8. MCP / CLI / daemon interfaces summary

**MCP (`docs/guides/MCP.md`, `docs/architecture/OVERVIEW.md:189-202`):**

- Transport: stdio, JSON-RPC 2.0.
- Tools: `scan_string(content, source)`, `scan_file(path)`, `scan_dir(path)`, `scan_env()`, `list_patterns([category])`, `list_categories()`, `update_bundle([path, force])`.
- Sandbox: `scan_file`/`scan_dir` constrained to server CWD.
- Response shape includes `finding_count`, `findings`, `risk_level`, `risk_score`, `stats`, `receipt`.

**CLI (`docs/guides/CLI.md`):**

- Subcommands: `scan`, `list`, `enable`, `disable`, `update`, `benchmark`.
- Global flags: `--format {human,json,sarif}`, `--config`, `--quiet`, `--verbose`.
- Scan flags documented in §3.2.

**Daemon (`docs/architecture/OVERVIEW.md:189-202`, `AGENTS.md:49`):**

- Unix-only (`#[cfg(unix)]`). Windows build exits 1 with explanatory message.
- Env: `AEGIS_DAEMON_SOCKET_PATH`, `AEGIS_DAEMON_SCAN_ROOT`, `AEGIS_DAEMON_ALLOWED_UIDS`, `AEGIS_DAEMON_ALLOWED_GIDS`.
- No documented client CLI; consumers connect over the socket using their own JSON-RPC client (the docs do not name one).
- **Caveat for Platform-Architecture:** Aegis has no documented Windows daemon. If the active stack requires Windows service-mode scanning, Aegis covers it through the CLI only.

---

## 9. CI coverage

| Concern | Aegis workflow | Job |
|---|---|---|
| Format | `ci.yml` | `fmt` |
| Clippy | `ci.yml` | `clippy` |
| Tests | `ci.yml` | `test` (matrix: ubuntu/macos/windows) |
| Build | `ci.yml` | `build` |
| Coverage | `ci.yml` | `coverage` → Codecov (`fail_ci_if_error: false`) |
| Security audit | `ci.yml` | `security` (cargo-audit, two ignored advisories) |
| Dependency policy | `ci.yml` | `deny` (cargo-deny) |
| CodeQL | `ci.yml` | `codeql` (Rust) |
| Self-scan | `aegis-scan.yml` | `aegis-scan`, `aegis-pr-check`, `aegis-secrets`, `aegis-supply-chain` |
| Fuzz | `fuzz.yml` | weekly + manual dispatch, 4 targets |
| Stale | `stale.yml` | repo hygiene |
| Labels | `label.yml` | labelling |
| Release (manual) | `release.yml` | `workflow_dispatch` only; not tag-triggered |
| GitForge pipeline | `.gitforce.yml` | quality-gates + build-release jobs |

Concurrency and least-privilege defaults are set per `ci.yml:19-22,17` (`permissions: contents: read`; only `codeql` and release workflows elevate). The release workflow is GitHub fallback only; primary CI/CD is GitForge, per the global `CLAUDE.md`.


---

## 10. Blockers and gaps

1. **No locally built Aegis binary in this session.** All evidence is documentary and CI-defined. The Aegis CLI/MCP/daemon behavior was not exercised here. A follow-up that actually runs the four binaries against the Atheon-Enhanced prebuilt binary plus a labelled vulnerable/clean fixture corpus is required for any disposition stronger than `CONDITIONALLY_QUALIFIED`.
2. **No measured throughput or cold-start numbers.** README's "12× faster than comparable tools" claim and AGENTS.md's "97.2% lines / 94.5% regions" coverage figure are **not re-verified** here.
3. **`AGENTS.md` is stale on pattern counts** (`AGENTS.md:7`: "633 patterns across 33 categories"). The README/CHANGELOG disagree (670/34). Update `AGENTS.md` before treating it as the canonical figure source.
4. **AGENTS.md license phrasing is contradictory** (`AGENTS.md:79`: "Apache-2.0 (NOT MIT OR Apache-2.0)" — the parenthetical conflicts with the headline). Cargo.toml and LICENSE say Apache-2.0; fix AGENTS.md.
5. **`enable`/`disable` are no-ops at runtime** (`CLI.md:113-117`). Any Platform-Architecture consumer that expects pattern state to persist across runs will be surprised. This is a deliberate design choice but should be flagged to integrators.
6. **No daemon client surface documented.** Consumers must bring their own JSON-RPC client. Atheon-Enhanced does not have a daemon either, so this is a parity baseline, not a regression, but it limits Windows deployments.
7. **Two ignored advisories in `cargo audit`** (`RUSTSEC-2024-0421` idna < 1.0; `RUSTSEC-2026-0097` rand < 0.8.6) via the jsonrpc stack. Justified in `ci.yml:134-139` and mirrored in `deny.toml`. Acceptable but documented.
8. **Windows daemon unsupported.** `AGENTS.md:49` is explicit: "aegis-daemon is Unix-only due to Unix domain sockets. Every code path is `#[cfg(unix)]`". If Platform-Architecture requires a Windows-resident scanner service, fall back to Aegis CLI in CI mode.
9. **WASM requires explicit target build** — `cargo build --workspace` does not produce `aegis-wasm.wasm`. Build script must use `--target wasm32-unknown-unknown --package aegis-wasm` (`AGENTS.md:48`).
10. **darwin binaries are zig-linked on the build host, not Apple hardware.** Disclosed in `attestation.json` (`scripts/release/build.sh:117-119`, `docs/guides/RELEASES.md:75-77`). If Platform-Architecture requires notarized Apple builds, this is a deployment-time concern.

---

## 11. Prioritized handoff tasks

Each item names a success criterion the next agent can verify before closing it.

1. **(P0) Build and execute Aegis binaries in an isolated worktree.**
   - `cargo build --workspace --release`.
   - Run `./target/release/aegis --version`, `./target/release/aegis-mcp --help` (or stdin ping), `./target/release/aegis-daemon --help`.
   - Confirm `aegis list` reports 670 patterns / 34 categories and matches `docs/patterns/categories/*.md` page count.
2. **(P0) Re-verify Aegis's own self-scan** (`AGENTS.md:53-58`).
   - Run `./target/release/aegis -f json scan . --categories secrets,security-hardening,web-security --severity-threshold high` and confirm 0 findings.
3. **(P0) Run an A/B benchmark against the Atheon-Enhanced prebuilt binary.**
   - Use `aegis benchmark /path/to/atheon-with-known-fixtures --compare --runs 5 --warmup 1` (CLI default).
   - Capture wall-clock per run, peak RSS, and any difference in finding counts.
4. **(P0) Validate a labelled vulnerable+clean fixture suite through both engines.**
   - The Aegis repo already has `corpus_precision_recall.rs` (`docs/ENHANCEMENT_ROADMAP.md:191-192`); use it.
   - Success: precision ≥ baseline, recall ≥ baseline, false positives within budget.
5. **(P1) Resolve documentation contradictions.**
   - Update `AGENTS.md:7` to 670/34.
   - Fix `AGENTS.md:79` to read "Apache-2.0".
   - Confirm `docs/patterns/README.md:42-46` includes the `info` severity bucket or note its omission explicitly.
6. **(P1) Exercise `update_bundle` MCP method against an Aegis-compiled bundle.**
   - Build with `aegis-bundler` and feed it through `aegis-mcp`'s `update_bundle`. Confirm the pattern count changes.
7. **(P2) Document a daemon client recipe.**
   - Add a minimal example (Python or Go) that opens the Unix socket, exchanges JSON-RPC, and runs `scan_file`. Currently the daemon interface is undocumented beyond env vars.
8. **(P2) Confirm license compatibility.**
   - Aegis is Apache-2.0; Atheon-Enhanced is MIT. If Platform-Architecture composes both in one distribution, surface the SPDX license set and any attribution obligations in the deliverable.
9. **(P2) Validate CI gate behavior end-to-end.**
   - Trigger `ci.yml` and `.gitforce.yml` (if GitForge is reachable from the build agent) on a throwaway tag and confirm all 8 quality-gates jobs pass on the current `2eefd88` SHA.
10. **(P3) Decide `enable`/`disable` persistence** — either implement persistence or document the constraint prominently so consumers do not assume they do.

---

## 12. Disposition

**CONDITIONALLY_QUALIFIED**

Rationale:

- Aegis presents a strict superset of the documented Atheon-Enhanced surface (more patterns, more categories, additional daemon + WASM + statistical-anomaly layers, richer output formats, an attestation-model release pipeline), all backed by on-disk source, AGENTS.md/CHANGELOG.md/README, and CI workflow definitions.
- All five core gates (fmt, clippy, test, build, audit + deny) and the Aegis-specific gates (self-scan SARIF, CodeQL, fuzzing, coverage, four PR-time scan jobs) are defined and enforced; no gate in this read-only review is observably broken in the source tree.
- Aegis is gated to **Unix-only** for daemon + Windows daemon absent; if Platform-Architecture runs Windows-resident scanner services, fall back to the Aegis CLI in CI mode. This is a real deployment-shape constraint, not a code defect.
- Two known transitive vulnerabilities (`idna < 1.0` via jsonrpc, `rand < 0.8.6` via jsonrpc-pubsub) are acknowledged and pinned in CI; acceptable when documented.
- The disqualifier from `QUALIFIED` is that **no Aegis binary was actually executed during this qualification**: behavior parity for the CLI/MCP/daemon surfaces is documentary, not measured. The handoff tasks in §11 close that gap. Once items 1–4 land with documented receipts, the disposition can move to `QUALIFIED`.

If items 1–4 surface parity gaps or regressions versus Atheon-Enhanced, the disposition must be downgraded to `NOT_READY` with concrete evidence; no such evidence was produced here.
