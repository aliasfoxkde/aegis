# Aegis ⇄ Atheon-Enhanced — Parity, Validation & Rollout Handoff

**Date:** 2026-10-11
**Author:** GLM-5.3-Flash agent session (Anthropic Claude Agent SDK, Pro
subscription), docs-only task. No product code, no fixtures, no
benchmarks were produced by this document.
**Branch:** `codex/aegis-atheon-parity-handoff-20261011`, base Aegis
`5c86a06a87610063dc09ff3310f53dd90bd06aa5` (= `origin/main` at authoring time).
**Status:** Proposal. Nothing in this document is released, deployed,
promoted, or measured as a win. Every forward-looking number is labeled
**PROPOSED** and requires operator ratification.

---

## 0. How to read this document

Evidence labels, used throughout:

| Label | Meaning |
|---|---|
| **VERIFIED** | Read directly from source/docs in a pinned revision, with file+line cited. Reproducible by the command given. |
| **INFERRED** | Reasoned from cited source (e.g. clap-derive defaults). The reasoning is stated and can be checked. |
| **UNKNOWN** | Searched for and not found, or never examined. Listed in §3.12 rather than guessed at. |
| **PROPOSED** | A threshold, gate, or decision this document introduces. Not ratified until the operator signs off. |

Sources and their pinned revisions (full register in §13):

- **Aegis:** this worktree at `5c86a06a8761…`, the GitForge mirror
  `bigdata-ci/aegis` / GitHub `aliasfoxkde/aegis`. Aegis file citations
  are repo-relative (`crates/…`, `docs/…`).
- **Atheon-Enhanced:** canonical source
  `https://github.com/aliasfoxkde/Atheon-Enhanced` — the `origin` of the
  local checkout `/nas/Temp/repos/Atheon-Enhanced`. Parity evidence is
  pinned to `bc42edf2563df9618b9c8ff429f0bacd19dd4e15` (2026-08-04),
  which carries **both** tags `v1.5.4-enhanced` and `v1.5.5-enhanced`;
  Atheon citations are absolute paths into a clean checkout of that
  commit. Fetched 2026-10-11: canonical `main` is ahead at
  `24fa243819dc382df76de5791818cdb059692080` (2026-08-11, a dependabot
  actions-bump merge carrying tags `v1.5.6-enhanced` through
  `v1.5.9-enhanced`). **Every Atheon-side claim in this document is
  therefore evidence about `bc42edf`, not about current `main`**; if the
  operator re-pins, every Atheon row requires revalidation (§3.12-9).
  The local checkout sits at `bc42edf` but carries heavy uncommitted
  drift (32 modified, 3 deleted, 16 untracked files — including five
  `cmd/atheon/*.go` files that exist in no commit at all); it was used
  read-only, and the pinned-revision facts below were re-verified
  2026-10-11 against a clean checkout of `bc42edf`.
- **Migration literature:**
  `/nas/Temp/repos/Platform-Architecture/docs/architecture/AEGIS_ATHEON_MIGRATION.md`
  (fenced as "historical/reference fence … not execution authority",
  its header, 2026-09-04).

Three claims from earlier planning documents are **retired** and must
not be repeated (VERIFIED: `docs/planning/HANDOFF.md:30-32` — "The
historical '12x faster / 20% smaller' claims … were never reproduced and
should not be repeated"; and the migration guide's own table marks Speed
and Binary-size as "Pending benchmark", lines 17-19). This handoff
assumes **no parity, no speed advantage, no production readiness, and
no benchmark win** until each is established by the evidence tasks
below. A post-authoring review (2026-10-11) re-verified the Aegis-side
citations against this tree and the Atheon-side citations against a
clean checkout of the pinned commit, corrected the wrong ones in place,
and downgraded to **UNKNOWN** anything the pinned evidence could not
support.

---

## 1. Objective and success definition

**Objective.** Aegis (Rust) replaces Atheon-Enhanced (Go) as the
scanner/gating project of the platform, with demonstrated feature parity
(plus a strictly larger pattern set) and measured cold-start behavior,
validated inside real repo CI workflows — not asserted from architecture
resemblance.

**Success is defined as all of:**

1. A frozen, dual-labelled parity corpus exists and both binaries run it
   green under the thresholds in §10 (§5).
2. A cross-tool conformance suite passes: CLI invocation matrix, output
   payload mapping, exit-code semantics, MCP and daemon wire behavior (§6).
3. A cold/warm/throughput/memory benchmark has been executed on one
   pinned host with identical inputs and published raw results — whatever
   the numbers turn out to be (§7, §8).
4. Shadow-mode evidence from real GitForge lanes shows Aegis tracking
   Atheon findings with an accepted FP/FN delta (§9).
5. Canary waves gate with Aegis without a single rollback trigger firing (§9, §11).
6. Every Atheon rule with no Aegis counterpart carries a signed waiver
   row, and every verified divergence is either mapped, implemented
   around, or waived (§3.11, §10).

Failure of any one of these is a decision to *not* migrate yet — the
rollback posture in §11 keeps Atheon gating until then.

---

## 2. Current state of both projects

### 2.1 Aegis (successor, active)

- Workspace `aegis` version **0.6.4** (`Cargo.toml:32`), MSRV 1.88
  (`Cargo.toml` rust-version; `MSRV 1.88` CI job gates it).
- **677 shipped detection patterns across 35 categories** — measured on
  this tree, not quoted:
  `rg -c '^\s+category: "' crates/aegis-patterns/src/*.rs` → 679
  literals in 36 module files, of which 2 are `category: "test"`
  fixtures in `crates/aegis-patterns/src/lib.rs:285,310`; distinct
  categories excluding `test` = 35. Matches the generated catalog
  (`docs/patterns/README.md:3`) and the PR-facing docs
  (`README.md:10,88-89`). Note `AGENTS.md:7,54` still says "670 across
  34" — stale prose; AGENTS.md itself warns not to quote counts from
  memory.
- Five binaries: `aegis` (CLI), `aegis-mcp`, `aegis-daemon` (Unix),
  `aegis-bundler`, and the `aegis-bootstrap` workspace placeholder, plus
  the `aegis-wasm` cdylib (VERIFIED: agent sweep of `[[bin]]`/`fn main`
  across `Cargo.toml` and `crates/*/Cargo.toml`).
- Test/quality posture (documented, **not re-run in this docs-only
  task**): 818 tests across 25 binaries green (`AGENTS.md:17`, measured
  2026-09-24; `docs/planning/HANDOFF.md:92` records 824 the same week),
  clippy `-D warnings` enforced; CI enforces a 97.0% line-coverage
  floor by passing it explicitly (`ci.yml:236`) — the enforcing
  script's standalone default is 89.0 (`scripts/coverage-floor.sh:17`),
  so manual runs must repeat the 97.0 argument; corpus precision/
  recall gates 0.95/0.95 with a 0.80 per-rule floor
  (`crates/aegis-core/tests/corpus_precision_recall.rs:36-61`).
- Known open items (VERIFIED, `docs/PLAN.md`): Phase 14 remainder
  (ML/regex hybrid, AST API-call verification — `PLAN.md:471-480`);
  Phase 16 Control-Center gate promotion (outside repo boundary,
  `PLAN.md:506-515`); Phase 17 open CI-lane items including
  `CODECOV_TOKEN` (`PLAN.md:517+`).
- Known operational facts (VERIFIED, `docs/planning/HANDOFF.md:260-266`):
  the MCP integration-test slice is the slow/occasionally-flaky one;
  rerun-first policy under load.

### 2.2 Atheon-Enhanced (predecessor, frozen at the pin)

- Go module `github.com/aliasfoxkde/Atheon` (`go.mod:1`), Go 1.21.0
  directive (`go.mod:3`), single runtime dep `goccy/go-yaml`;
  `CGO_ENABLED=0` applies to the goreleaser release builds
  (`.goreleaser.yml:11,35`) — the CI arm64 job builds with
  `CGO_ENABLED=1` (`.github/workflows/ci.yml:229-261`).
- **409 YAML pattern files across 28 category directories** at the pin
  (VERIFIED at `bc42edf`); severity distribution 183 high, 117 medium,
  84 low, 25 critical. The compiled `core/patterns.bundle` at the pin
  embeds only **406** pattern entries — the earlier draft's "bundle
  agrees at 409" was measured on the local checkout's uncommitted
  bundle rebuild, not the pin. The bundle's flat slugs do not map 1:1
  onto YAML paths, so the 406-vs-409 delta cannot be attributed by name;
  reconciliation is a C-2/S1 task. The bundler's input struct carries
  no `confidence`/`minEntropy` fields (`bundler/main.go:20-26`), so
  those never survive into a bundle.
- Four binaries: `atheon` CLI, `atheon-mcp`, `atheon-daemon`, and a
  network security-header scanner (`cmd/network-scanner/`), plus a
  `bundler` build tool.
- Self-described status: **experimental fork**, upstream `HoraDomu/Atheon`
  labeled "production-ready" in its own comparison table
  (`README.md:84`, `README.md:524`). Last commit on the local branch
  2026-08-04; canonical `main` last commit 2026-08-11 — **~2 months
  stale** at authoring time (2026-10-11). No file in the pinned tree
  mentions Aegis; nothing there records its own supersession
  (case-insensitive sweep at the pin: zero hits for "aegis").
- Test suite: 1577 `func Test` declarations across 116 `*_test.go`
  files (117 counting `cmd/atheon/main_test_main.go`, which holds
  `TestMain`) — but a large fraction exist to hit coverage percentages
  (12 sequential `coverage_phaseN_test.go` files, phases 2-13, in
  `core/` alone). **Do not read test counts as a quality comparison**
  (see Risks, §12).
- Performance evidence in-tree: 12 Go benchmarks and hedged reference
  numbers in `docs/BENCHMARKS.md:65-80` ("These numbers will drift with
  hardware and Go version"), which are also internally inconsistent
  (ScanFile on 1 MB reported ~42× slower than ScanString on 100 KB —
  not directly comparable). **No throughput/MB/s claim exists anywhere
  in the pinned tree.**

### 2.3 Why the prior migration guide is not authority

`AEGIS_ATHEON_MIGRATION.md` is explicitly fenced: "frozen migration
draft; not execution authority … pattern compatibility, and feature
comparisons are not a qualified cutover contract" (header fence,
2026-09-04). Its 2026-10-03 source-sample feature table (lines 167-192)
checked five capability *names* on both sides and itself warns that
"the presence of matching capability names does not prove equivalent
behavior." Its install examples (`get.aegis.dev`, `aegis-action@v1`) are
**UNKNOWN** — no evidence either exists; treat them as prose, not
instructions. This handoff supersedes it as the working plan; it does
not delete it.

### 2.4 Open Aegis PRs — checks refreshed 2026-10-11 (VERIFIED via `gh`)

| PR | Title | Checks (refreshed 2026-10-11) |
|---|---|---|
| **#162** | "Harden Aegis scan status and diff attribution" (`codex/aegis-scan-hardening-20261005`, **draft**) | **All green**: Build, Clippy, CodeQL (×2), Coverage, Format, MSRV 1.88, Rustdoc, Feature tree-sitter, Test (ubuntu/macos/windows), Security Audit, Dependency Policy, Supply Chain, Links, Notices, Label — 24/24 reportable pass; CodeRabbit "Review skipped: draft pull request". Run 37255767341. |
| **#163** | "build(deps): bump tokio 1.53.1 → 1.53.2 in the prod-deps group" (dependabot) | **One red**: `Third-Party Notices` **fail** (run 37530089752, job 112497071976). Everything else pass. |

Consequences for this plan: #162 is merge-ready by checks but is a
**draft** and touches scan status/diff attribution — i.e. it lands
squarely on divergence D-09/D-16 below; the parity work must rebase its
expectations on whatever shape it lands with. #163 should not merge
until its notices job is green; a tokio patch bump regenerating notices
is the likely fix (owner: aegis-maintainer; out of scope here). This
document itself travels as open PR **#168** (docs-only, this file);
re-checked 2026-10-11.

---

## 3. Actual feature matrix

All rows carry citations. "Aegis" = this tree @ `5c86a06`; "Atheon" =
`bc42edf` (tags `v1.5.4-enhanced`/`v1.5.5-enhanced`) — re-verified on
2026-10-11 against a clean checkout of that commit, not the drifting
local working copy.

### 3.1 Entrypoints & transports

| Surface | Aegis | Atheon | Parity verdict |
|---|---|---|---|
| CLI binary | `aegis` (`crates/aegis-cli/src/main.rs:11-15`, clap derive) | `atheon` (`cmd/atheon/main.go:223` argv switch, `:301-315` positional path — hand-rolled parsing) | Equivalent role, different parsing model (§3.2) |
| MCP server | `aegis-mcp`, JSON-RPC 2.0 over stdio; lifecycle `initialize`/`tools/list`/`tools/call`/`ping`, protocol versions 2024-11-05/2025-03-26/2025-06-18 (`crates/aegis-mcp/src/protocol.rs:26,302-330`); 10 MiB frame cap (`crates/aegis-core/src/transport.rs:15`) | `atheon-mcp`, JSON-RPC over stdio; core lifecycle + `$/cancelRequest`, **no `ping` method** (unknown methods → -32601, `cmd/mcp/main.go:412`) (`cmd/mcp/main.go:208-210,387-397`) | **7/7 tool names identical** (VERIFIED both sides): `scan_string`, `scan_file`, `scan_dir`, `scan_env`, `list_patterns`, `list_categories`, `update_bundle` |
| Daemon | `aegis-daemon`, Unix socket, line protocol, peer-credential (SO_PEERCRED) allowlist, 10 MiB caps (`crates/aegis-daemon/src/lib.rs:18-130,403-498`; cap `crates/aegis-core/src/transport.rs:15`), wire fixtures | `atheon-daemon`, Unix socket (`cmd/daemon/main.go:47,57`) | Role parity; wire-detail comparison incomplete (UNKNOWN: Atheon frame caps/auth) |
| Bundler | `aegis-bundler` (YAML/JSON → SHA-256-verified bundle; roundtrip tests `crates/aegis-bundler/tests/roundtrip.rs`) | `bundler` build tool compiles `community/**/*.yaml` → gzip bundle (`bundler/main.go:108-110,161-171,191`) | Role parity; formats differ |
| WASM | `aegis-wasm` cdylib (`scan_content`, `get_pattern_count`; `crates/aegis-wasm/src/lib.rs:91,122`) | none found | Aegis-only (VERIFIED absent in Atheon tree) |
| Network scanner | none | `cmd/network-scanner` (HTTP security-header checker) | Atheon-only; waiver candidate |
| Placeholder | `aegis-bootstrap` prints a pointer (`src/main.rs:7-9`) | — | n/a |

### 3.2 CLI surface & configuration

| Aspect | Aegis | Atheon |
|---|---|---|
| Subcommands | `scan`, `list`, `enable <pat>`, `disable <pat>`, `update`, `benchmark` (`crates/aegis-cli/src/main.rs:40-163`) | positional `<path>`, `update`, `enable`, `disable`, `list [categories]`, `help` (`cmd/atheon/main.go:223-339`: update `:224`, enable `:233`, disable `:245`, list `:257`, help `:260`, positional path `:301-315`) |
| Global flags | `-v/--verbose`, `-f/--format` (top-level only), `-c/--config`, `-q/--quiet` (`crates/aegis-cli/src/main.rs:15-37`) | `--quiet/-q` (`cmd/atheon/main.go:391`), `--json`/`--sarif` (**must be argv[1]**, `cmd/atheon/main.go:162-166`), `--version` (`:170`), `--completion[=bash\|zsh\|fish]` / `--shell-complete` (`:399-400`, `:516-536`) |
| Scan flags (shared intent) | `--file`, `--env`, `--stdin`, `--follow-symlinks`, `--categories`, `--severity-threshold`, `--output-file`, `--baseline`, `--all`, `--diff`, `--staged`, `--anomaly-detectors`, `--no-anomalies`, `--detect-clones` (`crates/aegis-cli/src/main.rs:43-109`) | `--env`, `--stdin`, `--file`, `--no-follow-symlinks`, `--categories=`, `--severity-threshold=`, `--output-file=`, `--baseline=`, `--diff=`, `--all`, `--config=` (`cmd/atheon/main.go:264-397`; `--no-follow-symlinks` `:613`, `--config=` `:100`) |
| Aegis-only | `--staged` (git-index pre-commit mode), `--detect-clones`, anomaly-detector layer | — |
| Atheon-only | — | `--completion`, `--shell-complete`, `--version` (Aegis: clap-derive emits `--version`/`--help` by default — VERIFIED, `crates/aegis-cli/src/main.rs:13`; `--completion` machinery confirmed absent in Aegis sweep 2026-10-11) |
| Config files | Explicit `-c <preset-or-path>` only; **no auto-discovery** (`crates/aegis-cli/src/config.rs:45-61`; `rg AEGIS_CONFIG` → none). Presets: 4 shipped profiles kept in sync by test `builtin_presets_match_shipped_profile_files` (`crates/aegis-core/src/config/mod.rs:190-216`) | `~/.atheon/config.json` + `--config=`; **parsed then discarded** — the result is dropped on the floor (`cmd/atheon/main.go:60-66,72-93,98-107`; discarded at `:194`); the 4 shipped `config/profiles/*.json` are not auto-loaded either. **All 19 `ConfigProfile` fields (`main.go:38-58`) are inert** (VERIFIED) |
| State paths | XDG: `<config_dir>/aegis/pattern-state.json`, bundle in data_local, cache in cache_dir (`crates/aegis-cli/src/pattern_state.rs:75-88`, `crates/aegis-core/src/lib.rs:90-103`) | `$HOME`-relative: `~/.atheon/{patterns.bundle,pattern_state.json}` (`core/bundle.go:160`, `core/pattern_state.go:28-31`); no XDG anywhere |
| Env vars | `RUST_LOG` (`docs/guides/CONFIGURATION.md:157`), `AEGIS_RECEIPT_FILE`, `AEGIS_SOURCE_REVISION`, daemon socket/root/UID/GID vars (`PLATFORM_INTEGRATION.md:139-149`), `AEGIS_ATHEON_PATH` benchmark comparator (`docs/guides/CONFIGURATION.md:164`, `crates/aegis-cli/src/benchmark.rs:197`) | `ATHEON_LOG_LEVEL`, `ATHEON_LOG_FORMAT` (`cmd/atheon/main.go:126,139`), `ATHEON_SKIP_DIRS`, `ATHEON_BINARY_EXTS` (`core/runner.go:32,41`) |

**Migration-critical reading:** because Atheon's config is inert,
current Atheon behavior in production is *flag-driven only*. The parity
baseline is "flags + ignore files + pattern state", not "profiles".

### 3.3 Pattern / rule coverage

| Aspect | Aegis | Atheon |
|---|---|---|
| Count / source of truth | 677 shipped / 35 categories; Rust source modules (`crates/aegis-patterns/src/*.rs`, `all_patterns()` at
`crates/aegis-patterns/src/lib.rs:150-188`); docs generated + freshness-tested (`crates/aegis-patterns/tests/registry_hygiene.rs:245-303`, test `pattern_docs_are_fresh`) | 409 / 28 categories; YAML one-file-per-pattern under `community/<category>/`; compiled to gzip bundle (406 entries at the pin — §2.2); counting script `scripts/pattern-count.sh` |
| Severity model | critical/high/medium/low + **info** (`crates/aegis-core/src/pattern.rs:23`); weights 40/25/10/3 (`crates/aegis-patterns/src/lib.rs:47-50`) | low/medium/high/critical, no info (`core/bundle.go:58`); 183h/117m/84l/25c distribution |
| Confidence model | high/medium/low, ×1.0/0.7/0.4 (`crates/aegis-patterns/src/lib.rs:47-50`) | high/medium/low (`core/bundle.go:116`); at the pin exactly **1 of 409** YAML patterns sets `confidence:` and 1 sets `minEntropy:` (both `community/secrets/aws.yaml:4-5`); the pinned bundle carries neither field in any of its 406 entries (the bundler's struct omits them, `bundler/main.go:20-26`) |
| Entropy gate | Per-pattern `min_entropy`, Shannon (`crates/aegis-core/src/entropy.rs`) | Shannon with LRU cache (`core/entropy.go:13-30`); effectively unused (one YAML pattern sets `minEntropy: 3.5`, `community/secrets/aws.yaml:5`; the pinned bundle carries none) |
| Custom user rules | `.aegis.yml`/`.aegis.yaml` at scan root, fail-loud validation (`crates/aegis-core/src/user_patterns.rs:24,116-130,166+`) | none user-facing (`core.Register()` is a Go API only, `core/pattern.go:90`) |
| Rule updates | `aegis update` reports the compiled-in set; **no download** (`README.md:80-82`) | `atheon update` downloads bundle from release URL, SHA-256 + SSRF guards, 100 MiB cap (`core/bundle.go:517,542,562-590,671,822-905`) |
| Beyond-regex detection | AST module (Go/Rust/Python/JS/TS rule sets; Java/C/C++ recognized-but-ruleless, `crates/aegis-core/src/ast/mod.rs:96-125`); optional `tree-sitter` feature (CI lane `ci.yml:117-134`); Type-3 clone detection (`--detect-clones`, `PLAN.md:452-468`); anomaly detectors; risk scoring (`risk.rs`); inspection ledger; receipts | Go-AST patterns (`core/ast_patterns.go:32`, Go-only); 9 audit layers (`core/audit_layers.go:15-34,45-53`); CFG detectors (lock/resource/transaction, `core/cfg.go:383-440`); taint tracker (`core/taint.go:13`); circular-import detection; clone detection; "YARA-like" simplified scanner (`core/yara_scanner.go:20-22` — name only, no libyara) |
| Language coverage (regex scoping) | `file_extensions` per pattern; per-extension scanner cache (`crates/aegis-core/src/pattern.rs:829-849`) | Not per-pattern extension-scoped; category-level scanning. **No per-pattern language field exists at the pin** — the pinned `PatternDef` (`core/bundle.go:37-48`) has no `Language` member (the earlier draft's `PatternDef.Language` claim is wrong), so per-pattern language wiring is absent, not merely unexamined |

### 3.4 Traversal & excludes

| Aspect | Aegis | Atheon |
|---|---|---|
| Ignore files | `.gitignore` then `.aegisignore` (aegis `!` rules can re-include); **`.atheonignore` accepted as legacy fallback** (`crates/aegis-core/src/ignore.rs:71-89`) — a deliberate migration bridge | `.atheonignore` + `.gitignore`, root only (`core/runner.go:70-79`) |
| Hard-coded skips | `node_modules`, `target`, `.git`, `.aegis` (`ignore.rs:120-125`) | 12 dirs: `.git node_modules vendor .terraform dist build __pycache__ .idea .vscode .svn .hg .cache` (`core/runner.go:18-22`), extensible via `ATHEON_SKIP_DIRS` |
| Binary skip | NUL-sniff 8 KiB window (`crates/aegis-core/src/scanner.rs:1282-1299`); opt-in `scan_binary` (lib API only) | Extension **blocklist** (`.png .jpg … .dylib`, `runner.go:24-28`) + 8 KiB NUL sniff + UTF-16 BOM rejection (`runner.go:309-333`), extensible via `ATHEON_BINARY_EXTS` |
| Size cap | 10 MiB default, `ScanOptions` only — **no CLI flag** (`crates/aegis-core/src/scanner.rs:113`, `crates/aegis-core/src/lib.rs:80`) | 10 MiB, `readFileCapped` with `EvalSymlinks` TOCTOU guard (`runner.go:56,101-120`) |
| Symlinks | **Not followed by default**; `--follow-symlinks` opts in (`crates/aegis-core/src/scanner.rs:71,1086-1089`) | **Followed by default**; `--no-follow-symlinks` opts out (`runner.go:231-237`) |
| Hidden files | No special filter; ignore rules decide (sweep: 0 hits for `hidden`) | No special filter (NOT FOUND) |
| Walk errors | Counted, `files_failed += 1`, ledger records; walk continues (`crates/aegis-core/src/scanner.rs:1130-1142`) | Collected into `Stats.Errors`; walk continues (`runner.go:213-222`) — **but see exit-code divergence D-01** |
| Concurrency | rayon pool, `ScanOptions::workers` default = cores (`crates/aegis-core/src/scanner.rs:1153-1158,120`) | goroutines `min(max(NumCPU()*2,4),64)` (`runner.go:279`) — **contradicts the "configurable, default 256" claim** in `docs/ARCHITECTURE.md:201` |

### 3.5 Secrets / policy / suppression

| Aspect | Aegis | Atheon |
|---|---|---|
| Inline suppression | Directive family: `aegis:ignore:<p1,p2>` (line), `aegis:ignore-start/-end` (nesting), `aegis:ignore-file`, optional `-- reason` (`crates/aegis-core/src/suppression.rs:7-17,131-234`) | Substring `atheon:ignore`, line-scoped only (`core/runner.go:456`) — no ranges, no file, no reason |
| Baseline | `--baseline <json>`: machine output of a prior `--format json` run; SHA-256 fingerprints, commit-safe; baseline file excluded from its own scan (`crates/aegis-core/src/scanner.rs:205-237,1098-1126`) | YAML baseline at `.atheon-baseline.yaml|.atheon/baseline.yaml`, auto-discovered (`core/suppression.go:123-143`); `CreateBaselineFile` (`:146`) |
| Severity threshold gating | `--severity-threshold` with 5-level validation incl. `info` (`crates/aegis-core/src/scanner.rs:148-157`; `Severity::parse` `crates/aegis-core/src/pattern.rs:53-60`) | `--severity-threshold=` with 4-level rank (`cmd/atheon/main.go:22-27`) |
| Policy engine | None as such; six mechanisms (threshold, risk score (report-only), baseline, inline directives, pattern-state, transport admission) — sweep VERIFIED NOT FOUND for a policy-file engine | None as such; same-shaped scatter (threshold, baseline, ignore, pattern state) |
| Receipts / evidence | Versioned redacted `ScanReceipt` (schema v1) on CLI/MCP/daemon paths; fail-closed receipt deletion (`PLATFORM_INTEGRATION.md:116-118`; `crates/aegis-cli/src/scanner.rs:413-431`) | None found |
| Inspection ledger | Per-unit `InspectionStatus` (analyzed/excluded/failed) embedded in JSON + SARIF; `AllRequiredFilesFailed` fail-closed error (`crates/aegis-core/src/scanner.rs:1372-1374`) | None found (only `Stats.Errors`) |

### 3.6 Output formats & payload contracts

| Aspect | Aegis | Atheon |
|---|---|---|
| Formats | `human` (default), `json`, `sarif` — `--format` **top-level**, must precede subcommand (`crates/aegis-cli/src/lib.rs:23-33`, `output.rs:47-51`; ordering rationale `main.rs:20-22`) | text (default), `--json`, `--sarif` — **positional argv[1] only** (`cmd/atheon/main.go:162-166,620-668`) |
| JSON shape | `{findings[], stats{…}}`; findings carry `id, pattern, category, severity, confidence, location, description, tags, kind, fingerprint, stable_id`; stats carry timings/ledger; **matched text never serialized** (`PLATFORM_INTEGRATION.md:112`) | findings + stats; `Stats.ElapsedMs` (`core/finding.go:43`); text footer `scanned %d file(s) … %dms` (`cmd/atheon/main.go:655-656`) — full JSON stats shape UNKNOWN, must be captured in task C-2 |
| SARIF | 2.1.0; `properties.inspectionLedger`; level map critical/high→error, medium→warning, low/info→note (`crates/aegis-cli/src/output.rs:166-324`) | 2.1.0 (`csd03` tag, `cmd/atheon/main.go:739-740`); **CWE taxonomies** (`categoryCWE`/`ruleCWE`, `:800-826`) and GitHub `security-severity` mapping (`:782-795`); snippets redacted (`:944`) |
| stdout/stderr | Report → stdout; tracing → stderr (MCP explicitly so) (`crates/aegis-cli/src/scanner.rs:443`; `crates/aegis-mcp/src/main.rs:479-484`) | Findings → stdout; `slog` → stderr always (`cmd/atheon/main.go:140,142`) |

**Consumer-facing gap:** GitHub code scanning consumers may depend on
Atheon's CWE/security-severity fields; Aegis SARIF does not emit them
today. Mapping or extension is a P1 divergence (D-11).

### 3.7 Exit semantics — **the highest-risk parity area**

Both tools reduce everything to 0/1 (VERIFIED both sides; neither has
an exit-code enum):

- Aegis: exit = `i32::from(has_findings)` where a finding is any
  non-`info` severity (`crates/aegis-cli/src/scanner.rs:379,450-451`);
  any `Err` bubbles out of `anyhow::Result` → exit 1
  (`crates/aegis-cli/src/main.rs:166`). Documented contract including the SAFE/FINDINGS/BLOCKED
  `--output-file` protocol: `PLATFORM_INTEGRATION.md:100-108`.
- Atheon: `0` clean, `1` findings **or any error**, plus `1` when
  `scanErrorsPresent(stats)` (`cmd/atheon/main.go:296-298,334-336`;
  `scanErrorsPresent` at `:689-691`).

Verified divergences with gating consequences:

- **D-01 (P0).** *Partial-failure exit.* Atheon exits **1** when any
  per-file error is present, even with zero findings
  (`scanErrorsPresent`, cited above). Aegis exits **0** with per-file
  failures recorded in the ledger — unless *all* required files failed,
  which raises `ScanError::AllRequiredFilesFailed`
  (`crates/aegis-core/src/scanner.rs:1130-1142,1372-1374`). Migrating Atheon CI consumers
  naively would silently downgrade partial failures from "blocked" to
  "clean". Must be decided + documented + tested before any canary wave
  (task S3/C-6).
- **D-02 (P0).** `info`-severity findings exist only in Aegis and never
  flip the exit code (`crates/aegis-cli/src/scanner.rs:379`; test
  `test_info_findings_never_fail_the_exit_code`,
  `crates/aegis-cli/src/scanner.rs:1565,1615`). Atheon has no info
  level. Threshold mappings must be explicit per wave.
- **D-03 (P1).** Exit codes alone cannot distinguish findings from
  failure on *either* tool — the `--output-file` protocol is mandatory
  in every migrated lane (`PLATFORM_INTEGRATION.md:108`).

### 3.8 Error surfaces

- Aegis: `anyhow::Result` mains (all 5 bins); typed `thiserror` enums in
  the library (`ScanError`, `ConfigError`, `BundleError`, … — 10 enums,
  sweep table); workspace lints deny `unwrap_used`/`expect_used`/`panic`
  in production code (`Cargo.toml:64-66`).
- Atheon: error values threaded to `run()` returning `int`; `slog` to
  stderr; no panic-recovery contract located (UNKNOWN).

### 3.9 Platforms & packaging

| Aspect | Aegis | Atheon |
|---|---|---|
| CI test matrix | ubuntu/macos/windows (`.github/workflows/ci.yml:85-101`) + MSRV + tree-sitter feature lane | go 1.22–1.25 × ubuntu/macos/windows (`.github/workflows/ci.yml:193-277`) + ARM64 **cross-compilation** (`CGO_ENABLED=1`, `ci.yml:229-261`; a step is *named* QEMU, `:244` — it is not emulation) |
| Release targets | 5 archives (linux x86_64/arm64, darwin x86_64/arm64, windows x86_64) × 4 binaries + wasm + source archives + checksums + attestation (`scripts/release/lib.sh:26-41`; `AGENTS.md:77`); darwin cross-linked with zig on Linux — **disclosed per-link exception**, not Apple-hardware builds (`scripts/release/build.sh:146-165`) | 5 target triples × 2 binaries, CGO_ENABLED=0, `-trimpath` (`.goreleaser.yml:9-35`) |
| Daemon availability | Unix-only; Windows binary builds but exits 1 (`AGENTS.md:52`) | Unix socket; flock split `!windows`/windows (`core/flock_*.go`) |
| Container/K8s | Verified image + scan CronJob (`docs/planning/HANDOFF.md:83,288-289`) | Docker dir present; no cluster contract found (UNKNOWN depth) |
| Self-scan gate | CI dogfoods Aegis (SARIF upload; `aegis-scan.yml`) | CI self-scan **blocking** on `secrets,pii` count (`.github/workflows/security.yml:54-107`) |

### 3.10 Performance evidence — current (this is the section that justifies §7)

**There is no valid cross-tool performance claim today.** Specifically:

- Aegis: criterion benches exist for registry init / first-scan /
  cached-scan (`crates/aegis-core/benches/scanner_init.rs:1-92`),
  pattern matching throughput on a **synthetic** 1,024-line input
  (`crates/aegis-core/benches/pattern_matching.rs:20,84,95`), and clone
  detection. A weekly non-gating trend run compares against its own
  previous baseline (`.github/workflows/bench.yml:51-80`). `aegis
  benchmark` can time an external binary
  via `AEGIS_ATHEON_PATH` (`crates/aegis-cli/src/benchmark.rs:131-153,197-229`)
  — but its external methodology is a **stub**: it spawns
  `<bin> <path> -q`, times wall-clock, and "counts findings" as
  non-empty stdout lines (`:137-141`). It is a smoke hook, not a
  comparison instrument.
- Atheon: hedged, internally inconsistent reference numbers
  (`docs/BENCHMARKS.md:65-80`); marketing-grade unmeasured claims that
  contradict the code (worker pool "default: 256" vs `runner.go:279`).
- Aegis targets are targets: "Throughput: 10GB+/minute … (target, not a
  measured gate)"; "Memory: <100MB baseline … (target)"
  (`docs/PLAN.md:695-697`); `docs/planning/HANDOFF.md:267-269` states
  plainly "Performance targets are targets".

Measured input sizes recorded for later benchmark use (VERIFIED
2026-10-11, commands in §13). **Scope matters:** Aegis figures are for
the base tree `5c86a06` = 246 tracked files / 2,887,740 B (`git
ls-tree -r -l`); this branch adds only this document, so the branch
tree measures 247 files / 2,955,199 B (measured at `ddf5992`, the
branch head at re-measurement — the byte total tracks this
document's own size, so the figure is pinned to that revision).
Atheon figures are for the pin
`bc42edf` = 706 tracked files / 2,766,557 B (`ls-tree -r -l` at a
clean checkout), superseding the earlier ≈2,748,140 B figure, which
was measured across the drifting local working copy (uncommitted
changes to 32 files, 3 deletions, 16 untracked additions — §13.2).
Both are small; the benchmark protocol (§7) adds a large real repo as
input I-3.

### 3.11 Divergence register (the parity worklist)

Priority: **P0** = blocks gating migration; **P1** = blocks promotion
claim; **P2** = document and move on.

| ID | Divergence (VERIFIED unless noted) | Priority | Disposition |
|---|---|---|---|
| D-01 | Partial-failure exit: Atheon 1 vs Aegis 0-with-ledger (§3.7) | **P0** | Decide + implement mapping + conformance test (C-6) before canary |
| D-02 | `info` severity exists only in Aegis; never gates | P0 | Threshold-mapping table per consumer (S1) |
| D-03 | Exit codes ambiguous on both; `--output-file` protocol required | P0 | Encode in lane templates (S5/S6) |
| D-04 | Symlink default: Aegis off, Atheon on | P1 | Migrated lanes set `--follow-symlinks` explicitly where Atheon followed |
| D-05 | Hard-coded skip sets differ (Atheon skips vendor/dist/build/…; Aegis doesn't) | P1 | Corpus must include a repo where gitignore does NOT cover those dirs; decide parity set |
| D-06 | Binary skip: extension blocklist+ BOM (Atheon) vs NUL-sniff only (Aegis) | P1 | Documented difference; test corpus rows for UTF-16 and binary-adjacent text |
| D-07 | Baseline format + discovery: JSON single-file (Aegis) vs YAML auto-discovered (Atheon) | P1 | One-time baseline conversion script at migration; no auto-discovery in Aegis by design |
| D-08 | Suppression directives: Aegis family vs Atheon line-substring | P1 | Mechanical conversion (`atheon:ignore` → `aegis:ignore:`) in migrated repos |
| D-09 | `--diff` semantics: both exist; Aegis attribution hardening in flight via PR #162; Atheon does changed-line-only filtering (`cmd/atheon/main.go:411-431,441-495`) | P1 | Pin behavior with conformance cases after #162 lands |
| D-10 | Output flag syntax (`--format` top-level vs `--json/--sarif` argv[1]) | P2 | Lane templates absorb it |
| D-11 | SARIF payload: Atheon emits CWE + security-severity; Aegis emits inspectionLedger, no CWE | P1 | Decision: extend Aegis SARIF or accept loss; GitHub consumers decide |
| D-12 | Findings JSON field names differ | P1 | Field mapping table (C-2) + adapter for consumers |
| D-13 | Config: Atheon profiles inert vs Aegis `-c` functional | P2 | Migrate only flags that were actually in use |
| D-14 | Pattern state location (`~/.atheon/pattern_state.json` vs XDG) | P2 | Manual state migration, or re-disable explicitly |
| D-15 | `network-scanner` binary has no Aegis counterpart | P2 | Waiver (out of scanner scope) |
| D-16 | Atheon shell completion (`--completion`, `--shell-complete`, `cmd/atheon/main.go:399-400,516-536`) has no Aegis equivalent found | P2 | Waiver or backlog |
| D-17 | `atheon update` downloads; `aegis update` reports compiled-in set only | P2 | Intentional Aegis design (supply-chain posture); document |
| D-18 | MCP `$/cancelRequest` (Atheon, `cmd/mcp/main.go:387-397`) has no Aegis counterpart — confirmed absent 2026-10-11 (no cancellation method in `aegis-mcp`) | P2 | Confirmed divergence; waive or backlog; C-4 pins the absence |

### 3.12 Unknown register (explicitly not assumed)

1. Rule-level behavioral equivalence for any individual pattern — the
   entire point of the parity corpus (§5). Pattern *count* superiority
   (677 vs 409) proves nothing about coverage overlap.
2. GitForge pipeline schema capabilities: multi-pipeline-per-repo,
   runner pinning/labels. The runner fleet is observable (`t5500-docker`
   cap 2 and `fedora-docker` cap 5 online, heartbeats 2026-10-11 —
   snapshot will drift), but `.gitforce.yml` shows no runner-selector
   field, and the single-job constraint is documented
   (`.gitforce.yml:8-19`; `docs/planning/HANDOFF.md:248-259`).
3. Atheon `--json` stats schema (needed for throughput parsing, §7).
4. Aegis SARIF/JSON behavior under PR #162's "scan status and diff
   attribution" hardening — matrix to be re-validated after it lands.
5. `get.aegis.dev` / `aegis-action@v1` existence (fenced migration-doc
   prose; never verified).
6. Aegis shell-completion support — **resolved 2026-10-11: absent**
   (no `clap_complete` dependency, no completion flags in any crate;
   clap derive gives `--help`/`--version` only — VERIFIED sweep).
7. Atheon daemon wire-level details (frame caps, auth) — never audited.
8. Upstream `HoraDomu/Atheon` relationship and whether *it* (not the
   Enhanced fork) is the real migration baseline for any consumer —
   flagged by Atheon's own README table; out of scope here, decision
   for the operator.
9. Behavioral drift between the pin `bc42edf` and canonical `main`
   `24fa2438` (four tags, seven days apart) — never audited. All
   Atheon rows in §3 are `bc42edf` evidence; if the operator re-pins
   to `main`, every Atheon citation must be revalidated before use.
   (Aegis shell-completion support, formerly UNKNOWN here, was
   resolved 2026-10-11: **absent** — no `clap_complete` dependency and
   no completion flags in any crate; clap derive gives
   `--help`/`--version` only.)

---

## 4. Staged migration plan

Roles used by every task:

- **operator** — human sign-off, waivers, promotion/rollback decisions.
- **aegis-maintainer** — agent/human sessions with write access to the
  Aegis repo (Rust, CI, docs). Model role: heavy-reasoning model for
  regex/semantic work and FP adjudication; standard model for
  mechanical transcription.
- **parity-analyst** — read-only sessions across both repos (mapping,
  corpus labelling prep, evidence collection). Model role:
  heavy-reasoning for rule equivalence judgments; never the arbiter —
  operator adjudicates conflicts.
- **infra-operator** — GitForge/GitHub lane and runner changes.

Dependency chain: S0 → S1 → (S2 → S3 → S4) → S5 → S6 → S7, with S8
(GitForge lane) required by S4 (reproducible bench evidence, §8) and
recommended before S5–S6; S0–S1 independent of it.

### S0 — Baseline & governance (this document)

| Field | Content |
|---|---|
| Task | Ratify this handoff; freeze the comparison revisions: Aegis at the SHA that merges this PR's base or later; Atheon at `bc42edf` (tags `v1.5.4-enhanced`/`v1.5.5-enhanced`; canonical `main` is ahead at `24fa2438` — re-pinning is an operator decision, §3.12-9) |
| Source target | This file; `docs/planning/HANDOFF.md` |
| Owner / model role | operator + aegis-maintainer / heavy-reasoning for review |
| Validation | This PR green on repo gates (Links job validates `docs/**/*.md`; no local lychee binary exists on this host — VERIFIED `which lychee` empty) |
| Acceptance | Document merged; revisions pinned here match `.gitdescribe` outputs at execution time |
| Risks | Atheon working-tree drift (32 modified / 3 deleted / 16 untracked files, five of them `cmd/atheon/*.go` that exist in no commit) — mitigation: citations and benchmarks use a clean clone at the pinned SHA, never the live checkout |
| Rollback | n/a (docs) |

### S1 — Mapping freeze (docs + tables, no code)

| Field | Content |
|---|---|
| Task | Produce three mapping tables under `docs/parities/`: (a) CLI/flag matrix with exit semantics per invocation; (b) JSON/SARIF field map (Atheon→Aegis) including CWE decision for D-11; (c) rule-map skeleton: every Atheon `community/**` pattern → matching Aegis pattern(s) or `UNMAPPED` |
| Source target | `cmd/atheon/main.go` (the pinned CLI surface — the previously listed `commands.go`/`flags.go`/`output.go` do not exist at the pin, §13.3); `crates/aegis-cli/src/main.rs`, `crates/aegis-cli/src/output.rs`; `community/**/*.yaml`; `crates/aegis-patterns/src/*.rs` |
| Owner / model role | parity-analyst → aegis-maintainer review; heavy-reasoning model for rule matching (regex semantics), standard model for transcription |
| Validation | Rule-map row count == 409 (mechanically checked: `find community -mindepth 2 -name '*.yaml' | wc -l`); every row has a disposition |
| Acceptance | 0 rows with status "unknown"; D-01/D-02/D-11 decisions recorded and operator-signed |
| Risks | Regex semantic mismatches (Go RE2 vs Rust `regex` crate: both are RE2-family, but look-around is absent in both while syntax corners differ) — mitigation: equivalence spot-checked by execution in S2, not by reading alone |
| Rollback | Tables are additive docs; delete `docs/parities/` to retract |

### S2 — Baseline parity corpus (see §5 for the full spec)

| Field | Content |
|---|---|
| Task | Build and land the corpus + dual-label runner (script, not product code) |
| Source target | New `crates/aegis-core/tests/parity_corpus/` (or separate repo — decision inside the task); seeds: existing `crates/aegis-core/tests/corpus/` (15 files) and Atheon `community/` samples |
| Owner / model role | aegis-maintainer (test infrastructure) + parity-analyst (labels) + operator (adjudication) |
| Validation | `cargo test -p aegis-core --test parity_corpus` (new); label-syntax tests mirror `corpus_precision_recall.rs:423-468` |
| Acceptance | Corpus meets minima in §5; both binaries execute it; conflict log reviewed by operator |
| Risks | Fixture secrets leaking into the repo — hard rule: synthetic credentials only, `concat!`-assembled where a complete literal would otherwise appear (existing repo discipline, `docs/planning/HANDOFF.md:215-218`) |
| Rollback | Corpus is test-only; revert the PR |

### S3 — Cross-tool conformance suite (see §6)

| Field | Content |
|---|---|
| Task | Implement C-1…C-6 as scripted conformance checks + fixtures |
| Source target | `scripts/parity/` (new, scripts only); existing wire fixtures `crates/aegis-mcp/tests/fixtures/mcp_wire_conformance.json`, `crates/aegis-daemon/tests/fixtures/daemon_wire_conformance.json` |
| Owner / model role | aegis-maintainer / standard model for scripting, heavy-reasoning for exit-matrix design |
| Validation | Suite runs both binaries from pinned builds; every case records PASS/FAIL with command + output digest |
| Acceptance | 100% of C-1 matrix rows produce the mapped exit code on both tools; C-4/C-5 wire replays green against both servers |
| Risks | PR #162 changes status/exit attribution mid-stream — re-run suite after it merges |
| Rollback | Suite is opt-in tooling; no product impact |

### S4 — Benchmark execution (see §7)

| Field | Content |
|---|---|
| Task | Execute the §7 protocol on the pinned host; publish raw JSON + a prose report with **no adjectives** |
| Source target | §7 commands; `docs/handoffs/` for the report |
| Owner / model role | infra-operator executes; scripts produce numbers — **models never author measurement numbers** |
| Validation | Raw `hyperfine --export-json` + `/usr/bin/time -v` transcripts committed alongside the report; host fingerprint recorded |
| Acceptance | N ≥ 30 per measurement, medians + p95 + bootstrap CIs; all four axes (cold/warm/throughput/memory) present; "faster" appears only if PR-5 (§10) is met |
| Risks | Runner contention (the 19-run burst precedent, `HANDOFF.md:255-258`) — mitigation: dedicated manual runs, idle-fleet precondition check |
| Rollback | Results are evidence only; discard the report to retract any claim |

### S5 — Shadow mode (see §9)

### S6 — Canary waves (see §9)

### S7 — Promotion decision & Atheon retirement plan

| Field | Content |
|---|---|
| Task | Operator reviews S2–S6 evidence against §10 gates; go/no-go per consumer repo; retirement schedule for `atheon` lanes (definition-removal after one green cycle + 2 weeks) |
| Acceptance | Signed decision record; any "no-go" carries named blockers |
| Rollback | §11 |

### S8 — GitForge serial benchmark/gating lane (see §8)

---

## 5. Baseline parity corpus (spec)

**Purpose:** the only artifact allowed to support a parity claim. It
must be dual-labelled — every fixture states what *each* tool is
expected to find — so both binaries are measurable by the same harness.

**Composition (all real-repo or real-rule derived; synthetic strings
only as rule-liveness probes, never for headline statistics):**

1. **Seed layer:** the existing Aegis corpus
   `crates/aegis-core/tests/corpus/` — 15 tracked files (14 fixtures +
   the directory README): `vulnerable/` 5 (`aegis:expect`), `clean/` 3
   (zero findings), `negative/` 6 (`aegis:expect-none`) — VERIFIED
   inventory in §13.
2. **Atheon-derived layer:** ≥ 1 fixture per Atheon category (28),
   each exercising a real `community/**/*.yaml` rule's regex on
   realistic code, labelled for both tools (`aegis:expect …` /
   `atheon:expect …` conventions; the parity runner script parses
   both).
3. **Real-repo layer:** pinned snapshots (recorded SHA + measured
   file/byte counts) of ≥ 3 internal repos — candidates: `aegis`
   (base `5c86a06`: 246 files / 2.89 MB, measured), `Atheon-Enhanced`
   (pin `bc42edf`: 706 files / 2.77 MB, measured), one large repo
   ≥ 10⁴ files selected by infra-operator — plus ≥ 1 public OSS
   snapshot. These are scanned by both tools with diffs adjudicated,
   not pre-labelled.
4. **Adversarial FP layer:** the `clean/` + `negative/` pattern
   extended with files that historically trigger scanner FPs:
   dynamic shell assignments (the PR #166 territory), `concat!`
   test fixtures, UTF-16 files, minified JS, lockfiles.

**Labeling protocol:** parity-analyst proposes labels → both binaries
run → every disagreement (either direction) is adjudicated by the
operator with a one-line rationale stored next to the fixture. Labels
use the existing directive grammar where possible
(`crates/aegis-core/tests/corpus_precision_recall.rs:150-188` for
expectation semantics; `negative/` pins per `:423-468`).

**Minima (VERIFIED basis — the existing harness constants):** ≥ 30
`aegis:expect` directives, ≥ 5 clean files, ≥ 6 negative files, ≥ 10
pinned silent rules — floor values are the existing harness minima
(`corpus_precision_recall.rs:36-61`: MIN_EXPECTATIONS 10,
MIN_CLEAN_FILES 3, MIN_NEGATIVE_FILES 3, MIN_PINNED_RULES 5) scaled
up 2–3× for parity work; exact final minima are **PROPOSED** in the task
and ratified at S2 exit.

**Placement decision (S2):** default in-repo at
`crates/aegis-core/tests/parity_corpus/` so CI gates it; if size
becomes an issue, the real-repo layer moves to a GitForge-hosted
fixture repo referenced by pinned SHA. No fixture may contain a real
credential — synthetic values only, `concat!`-assembled per repo
discipline (`docs/planning/HANDOFF.md:215-218`).

---

## 6. Conformance test plan

| ID | Suite | What it pins | Command / gate (future) | Acceptance |
|---|---|---|---|---|
| C-1 | CLI invocation matrix | ~25 mapped invocations (scan path/file/env/stdin, categories, threshold, baseline, staged-n/a, diff, output-file; list/enable/disable/update) × both binaries; expected exit + output-shape per row; D-01/D-02 rows explicit | `scripts/parity/cli_conformance.sh` against pinned release builds of both | 100% rows mapped-exact; any drift fails the suite |
| C-2 | JSON payload map | Atheon `--json` vs Aegis `--format json` field-by-field table, executed not just written (parse both, assert map completeness); resolves UNKNOWN §3.12-3 | `scripts/parity/json_map.py` | Every Aegis field mapped or explicitly `unmapped+reasoned` |
| C-3 | SARIF consumer check | Both SARIF outputs validate as SARIF 2.1.0; D-11 CWE/security-severity delta measured | `scripts/parity/sarif_check.py` | Deltas enumerated; decision recorded |
| C-4 | MCP wire conformance | The existing Aegis fixture replay (`crates/aegis-mcp/tests/mcp_wire_conformance.rs`, 4 tests; fixture floor `cases.len() >= 8` at `:212`) extended to drive `atheon-mcp` with the same client script; resolves D-18 | fixture replay + client script | Same 7 tools answer identically-shaped responses for identical inputs |
| C-5 | Daemon wire conformance | Same approach with `crates/aegis-daemon/tests/daemon_wire_conformance.rs` (3 tests; fixture floor `cases.len() >= 10` at `:230`) vs `atheon-daemon` | fixture replay | Parity or documented difference |
| C-6 | Exit-semantics unit pins | D-01: Aegis behavior on partial failure (ledger present, exit 0) pinned by test; Atheon's `scanErrorsPresent` behavior pinned on the Atheon side; both documented in `docs/parities/` | `cargo test -p aegis-core --test scanner_behaviors` extensions + Atheon-side Go test (in Atheon's tree — requires operator-approved write there, else pinned by scripted observation in C-1) | Decision implemented + tested |

C-4/C-5 require no product changes — they reuse the existing fixture
replay machinery. Aegis-side additions are test scripts; **any change
that touches product code (e.g. D-01 policy change) is a separate,
normally-gated PR after this plan is ratified.**

---

## 7. Benchmark protocol (cold / warm / throughput / memory)

**Principles:** one pinned host; identical inputs; contemporaneous
release builds of both binaries; the same input set for both tools;
raw data published; no synthetic corpora for published numbers; models
never type measurement results — tools do.

**Environment pin (record per run):** host identity, CPU model/cores,
RAM, kernel (`uname -r`), CPU governor if settable, toolchain versions
(Rust: the `aegis-builder:1` image's 1.88-pinned toolchain; Go: the
version that built Atheon, recorded from `go version`). Rust and Go
cannot share a compiler — "same toolchain" is satisfied as *each
project's pinned standard release toolchain on the same host*, both
recorded. Workspace hygiene: `TMPDIR` on NVMe (`/var/tmp`), never the
NAS spinner; benchmark repo clones live on local disk.

**Builds:**

```bash
# Aegis (release, locked) — inside a pinned worktree
cargo build --release --locked -p aegis-cli
# Atheon — fresh clone of the canonical remote at the pinned tag
# (v1.5.4-enhanced and v1.5.5-enhanced both = bc42edf)
git clone --branch v1.5.4-enhanced \
  https://github.com/aliasfoxkde/Atheon-Enhanced.git && cd Atheon-Enhanced \
  && go build -trimpath -o atheon ./cmd/atheon
```

**Inputs** (measured at run time; counts below recorded 2026-10-11):

| ID | Input | Pinned at | Tracked files / bytes |
|---|---|---|---|
| I-1 | aegis repo | base `5c86a06` (the branch tree adds only this document: 247 / 2,955,199 B at `ddf5992`) | 246 / 2,887,740 B at base (measured) |
| I-2 | Atheon-Enhanced repo | `bc42edf` / `v1.5.4-enhanced` (= `v1.5.5-enhanced`) | 706 / 2,766,557 B (`ls-tree` at clean checkout; the earlier ≈2,748,140 B figure was measured across the dirty working copy — clone fresh) |
| I-3 | large real repo (≥ 10⁴ files) | SHA recorded at execution | measured at execution |

**Cold start** (process spawn → completed scan; the axis the objective
names). `hyperfine` if installed, else the `/usr/bin/time` fallback —
both given so the lane doesn't invent one:

```bash
# hyperfine: NO warmup, N individual runs, JSON export
hyperfine -N --warmup 0 --min-runs 30 --style basic \
  --export-json cold-aegis.json \
  "./target/release/aegis --format json scan <INPUT> --output-file /dev/null"
hyperfine -N --warmup 0 --min-runs 30 --style basic \
  --export-json cold-atheon.json \
  "./atheon --json <INPUT> --output-file /dev/null"
```

Atheon flag order is positional (`--json` must be argv[1],
`cmd/atheon/main.go:162-166`) — the commands above respect each tool's real
syntax; do not "normalize" them. Optional cache-cold variant (operator
executes, root): `sync && echo 3 > /proc/sys/vm/drop_caches` between
runs; if not available, "cold" means fresh-process and the report must
say so.

**Warm** (page-cache warm, repeated): same commands with
`--warmup 3 --min-runs 30`. In-process warm reference: existing
criterion `scanner_init/cached_scan_extension_rs`
(`crates/aegis-core/benches/scanner_init.rs:79-92`) reported alongside.

**Throughput:** from each tool's own stats, not wall clock:
Aegis `stats.bytes_scanned / stats.scan_time_ms` (fields VERIFIED,
`PLATFORM_INTEGRATION.md:112`); Atheon from its `--json` stats or the
stdout footer (`scanned %d file(s) … %dms`, `cmd/atheon/main.go:655-656`)
— shape to be pinned by C-2 first (UNKNOWN §3.12-3). Report MB/s per
input, sequential runs, no concurrent load.

**Memory:** `/usr/bin/time -v <cmd> 2>&1 | grep 'Maximum resident'`
per tool per input; the `PLAN.md:696` "<100MB" figure is a target, not
a gate.

**Reporting:** per measurement — N, median, p95, MAD, bootstrap 95% CI
(10k resamples, scripted); raw exports committed to
`docs/handoffs/bench-<date>/` with the host fingerprint. **Claim rule
(PR-5):** the word "faster" may appear in Aegis documentation only if
the cold-start median CI and the throughput CI both favor Aegis
non-overlappingly on the same pinned host; otherwise the report states
"no measured difference" or reports Atheon's advantage, as measured.
The stub comparator in `aegis benchmark --compare`
(`crates/aegis-cli/src/benchmark.rs:131-153`) is explicitly **not**
evidence for any claim.

---

## 8. GitForge serial benchmark lane

**Verified constraints:** GitForge pipelines here are a single job with
ordered steps, because the deployed trigger path queues only the first
job with empty `needs` (`.gitforce.yml:8-19`; `HANDOFF.md:248-259`);
runs share one workspace, so fan-out lanes would collide over `target/`
and `artifacts/`; test steps serialize with `--test-threads=1`
(`.gitforce.yml:38-44`); the release pipeline triggers `[manual, tag]`
only. Runner fleet snapshot 2026-10-11: `t5500-docker` (capacity 2,
online), `fedora-docker` (capacity 5, online) — via the GitForge
`/api/runners` endpoint; **no runner-selector field is evidenced in the
`.gitforce.yml` schema** (UNKNOWN §3.12-2).

**Design:**

1. **G-1 (evidence, first):** infra-operator verifies against GitForge
   (its repo/docs — outside this handoff's write scope): multi-pipeline
   per repo support; runner pinning; artifact export between pipelines.
2. **G-2 (preferred end state):** a second pipeline `aegis-bench` in
   `.gitforce.yml`-schema (or a second file if supported), `trigger_on:
   [manual]`, image `aegis-builder:1`, steps: build both pinned
   binaries → run §7 script → export raw JSON as run artifacts. Manual
   trigger keeps tags burst-free.
3. **G-3 (fallback if multi-pipeline/pinning unsupported):** benchmarks
   run as an infra-operator-executed script on the low-capacity runner
   host during an idle-fleet window; the run records runner id +
   heartbeat evidence; GitForge pipeline integration is revisited after
   upstream gaps (#215/#216/#217 per `HANDOFF.md:255-259`) close.
4. **Serial execution discipline:** one bench run at a time; fleet
   idle-check precedes the run; every result row carries the runner
   name so cross-host numbers are never merged. Criterion benches stay
   out of this lane (they self-baseline); any test steps keep
   `--test-threads=1` per the existing precedent.

Acceptance for the lane: two consecutive manual runs on the same runner
produce medians within run-to-run noise (reported, not thresholded —
noise magnitude is itself a deliverable).

---

## 9. Shadow mode and canary rollout

### 9.1 Shadow mode (non-gating, evidence-producing)

- **Mechanism:** in consumer repos' GitForge/GitHub lanes, add a
  non-gating step that runs the pinned Aegis build with
  `--format sarif --output-file aegis-shadow.sarif` and
  `|| true` semantics (exit swallowed), uploads the artifact, and
  emits a diff report against the stored Atheon result for the same
  SHA (Atheon keeps gating unchanged during shadow).
- **Duration/exit criteria:** ≥ 20 consecutive real runs per repo, or
  2 weeks, whichever is later; every FP/FN delta adjudicated into the
  waiver ledger (§10); shadow overhead measured each run (lane wall-time
  delta) with a **PROPOSED** budget of ≤ 20% lane-time increase — a
  breach is a shadow finding, not a silent acceptance.
- **Failure handling:** a shadow run failing to *execute* (crash,
  timeout) is a blocker-grade defect per the repo's validation
  discipline (silence/failure that isn't surfaced is a finding) — it
  pauses shadow accrual and files a defect with repro anchors before
  the wave continues.
- **First shadow target:** Aegis's own repo (it already dogfoods
  itself in `aegis-scan.yml`, so the incremental risk is the
  comparison harness, not the scanner).

### 9.2 Canary waves (Aegis becomes the gate)

| Wave | Scope | Gate semantics | Soak | Exit criteria |
|---|---|---|---|---|
| W-1 | `aegis` repo itself | Aegis gate replaces Atheon self-scan; `--output-file` protocol per D-03; Atheon shadow continues | ≥ 10 runs / 1 week | Zero FP escapes; zero D-01 surprises (partial-failure matrix green) |
| W-2 | 2 low-risk internal repos, owner consent | Same | ≥ 2 weeks or ≥ 30 runs | Same + waiver ledger current |
| W-3 | Remaining consumers, batched | Same | 2 weeks per batch | — |

Preconditions for any wave: S1–S4 complete; D-01/D-02/D-03 decisions
implemented and tested (C-6); §10 gates green. Waves do not overlap
per repo; Atheon job definitions are disabled, **not deleted**, for one
full cycle after each wave (rollback speed, §11).

---

## 10. Acceptance thresholds and FP/FN policy

### 10.1 Hard gates that already exist (must stay green throughout)

fmt; clippy `-D warnings`; 3-OS test matrix; coverage floor 97.0%
lines (CI passes 97.0 explicitly — `ci.yml:236`; the script's
standalone default is 89.0, `scripts/coverage-floor.sh:17`);
cargo-audit/deny; CodeQL; corpus aggregate precision/recall ≥
0.95/0.95; per-rule precision floor 0.80 (≥ 2 observations); demote-only
confidence calibration; negative-corpus silence pins
(`corpus_precision_recall.rs:36-61`; `ci.yml:236`). New parity assets
enter these gates, never bypass them.

### 10.2 Parity gates (all **PROPOSED** — operator ratifies at S1 exit)

| ID | Gate | Threshold | Basis |
|---|---|---|---|
| PR-1 | Aegis recall of adjudicated true positives on the dual-labelled corpus | ≥ 0.95 | Existing `RECALL_THRESHOLD = 0.95` (`corpus_precision_recall.rs:36-61`) |
| PR-2 | Aegis aggregate precision on the corpus | ≥ 0.95 (maintained) | Existing `PRECISION_THRESHOLD` |
| PR-3 | FP count on the clean/adversarial layer | Aegis ≤ 1.10 × Atheon's count, per corpus | Ratio chosen to tolerate small absolute deltas on small corpora; waivable per rule |
| PR-4 | Rule-map completeness | 0 `UNMAPPED` rows without a signed waiver | §4/S1 acceptance |
| PR-5 | Performance claim license | "Faster" only with non-overlapping CIs favoring Aegis (§7) | Anti-fib rule from `HANDOFF.md:30-32` |
| PR-6 | D-01 partial-failure semantics | Decision implemented + pinned by tests before any gating wave | §3.7 |

### 10.3 FP/FN handling policy

- **FN (missed true positive) is release-blocking** for a gating wave:
  any Atheon-confirmed TP that Aegis misses on the parity corpus is
  either fixed (at the regex, per `HANDOFF.md:316-319` — "Fix pattern
  false positives at the regex, not with suppressions") or waived with
  a mapping row + operator signature. No unwaived FN may exist when a
  wave goes live.
- **FP adjudication:** every shadow/canary FP gets: rule id, fixture
  anchor, root cause, disposition (regex fix / corpus pin / waiver).
  Suppression directives are for genuinely-flagged fixture lines only.
- **FP storm trigger (rollback):** > 10 new FPs in one week across
  canary repos, or any FP that blocks a real pipeline with no waiver.
- **Waiver ledger:** `docs/parities/waivers.md` (created at S1); every
  entry carries owner, date, and re-review at each release cycle;
  expired waivers revert the item to "blocking gap".
- **Silence is a finding:** if Aegis gates but produces no receipt,
  no ledger, and no output where Atheon produced evidence, that is a
  blocker (repo validation discipline; `PLATFORM_INTEGRATION.md:188`
  already requires consulting `inspection_ledger` rather than trusting
  an empty finding list).

---

## 11. Rollback

**Posture:** through S6, every wave keeps Atheon runnable and its lane
definitions present (disabled, not deleted). Rollback is a revert of
one gate step, not a project.

- **Lane rollback (minutes):** re-enable the `atheon` gate step /
  disable the `aegis` gate step in the affected repo's lane; both
  binaries coexist by construction during all waves. GitForge artifacts
  and receipts are per-run; nothing accumulates that a rollback invalidates.
- **Client rollback:** MCP client configs point back at `atheon-mcp`
  (config-only change; the two servers never share state — Aegis writes
  only its own XDG paths, VERIFIED §3.2).
- **State rollback:** Aegis `pattern-state.json` and Atheon
  `~/.atheon/pattern_state.json` are disjoint; stopping use of Aegis
  binaries restores prior behavior with no migration of state needed
  backwards.
- **Docs rollback:** any claim published under §7 that later fails to
  replicate gets retracted in the handoff errata, not defended.
- **Rollback triggers (any one suffices):** FP storm (§10.3); FN escape
  (a secret reaches `main` past an Aegis gate); D-01-class semantic
  surprise in production; lane latency budget breach sustained; scanner
  crash/timeout in gating path; supply-chain advisory against a pinned
  Aegis artifact.
- **Post-rollback obligation:** defect filed with repro anchors and a
  failing case added to the parity corpus before the next wave attempt
  (validation discipline: findings are stored, not chatted).

---

## 12. Risks (register)

| Risk | Impact | Mitigation |
|---|---|---|
| Pattern-count fallacy: 677 vs 409 invites "more = parity" reasoning | False promotion | PR-1/PR-4 measure overlap, not totals; count claims always carry the measured command |
| Atheon moving target | Comparisons rot | Frozen at `bc42edf`/`v1.5.4-enhanced`; canonical `main` (`24fa2438`) is four tags ahead — re-pinning is an operator decision (§3.12-9); fresh clone per run at the pinned SHA (live checkout drifts: 32 modified / 3 deleted / 16 untracked files) |
| Atheon test-count vanity (1577, coverage-phase bloat) | Misleading quality comparison | Tests never compared by count in any deliverable |
| GitForge runner contention (19-run burst precedent) | Noisy benchmarks, blocked lanes | Manual-trigger bench runs, idle-fleet precondition, runner id recorded (§8) |
| PR #162 changes scan-status/exit attribution under us | Conformance suite churn | Suite re-run on the #162 merge SHA before W-1 (§6 risk row) |
| PR #163 notices job red | Merge-blocker noise | Informational here; aegis-maintainer regenerates notices |
| MCP integration-test flakiness under load | False conformance failures | Rerun-first policy (`HANDOFF.md:260-266`); conformance runs serialized |
| ConfigProfile inertness misleads migrators | "Profiles will behave the same" fallacy | §3.2 called out; only flags migrate |
| Synthetic-credential leakage into corpus | Self-inflicted finding | `concat!` discipline + self-scan gate catches regressions |
| NAS-backed temp dirs breaking test runs | Flaky evidence | Benchmark/conformance runs set `TMPDIR` to NVMe |

---

## 13. Sources & reproducibility appendix

### 13.1 Revisions

- Aegis: branch `codex/aegis-atheon-parity-handoff-20261011`, base
  `5c86a06a87610063dc09ff3310f53dd90bd06aa5` (recent history includes
  `#166` dynamic-secret suppression and `#167` diff source-line fix).
  Codebase-memory index for this worktree:
  `home-mkinney-worktrees-aegis-atheon-parity-handoff-20261011`
  (3,247 nodes / 13,053 edges, re-indexed 2026-10-11 from the stale
  `nas-Temp-repos-aegis` index which predated `5c86a06` — an indexer
  snapshot, tool output rather than a source-tree fact).
- Atheon-Enhanced: canonical remote
  `https://github.com/aliasfoxkde/Atheon-Enhanced`; parity pin
  `bc42edf2563df9618b9c8ff429f0bacd19dd4e15` = tags
  `v1.5.4-enhanced` **and** `v1.5.5-enhanced` (2026-08-04). Canonical
  `main` fetched 2026-10-11 =
  `24fa243819dc382df76de5791818cdb059692080` (2026-08-11; tags
  `v1.5.6-enhanced`…`v1.5.9-enhanced`). Pinned facts were re-verified
  2026-10-11 against a clean checkout of `bc42edf`;
  `/nas/Temp/repos/Atheon-Enhanced` sits at the pin but drifts (§13.2).
  `/nas/Temp/repos/Atheon-Scanner` is a **different
  project** (module `github.com/aliasfoxkde/Atheon-GitHub-Scanner`,
  unrelated import graph, analytics platform) — out of parity scope.
- Migration literature: Platform-Architecture
  `docs/architecture/AEGIS_ATHEON_MIGRATION.md` (fenced draft) — read,
  not authority (§2.3).

### 13.2 Commands and outputs (all run 2026-10-11)

```text
# Aegis pattern count (this worktree)
rg -c '^\s+category: "' crates/aegis-patterns/src/*.rs   # 36 files, 679 total
rg -c 'category: "test"' crates/aegis-patterns/src/lib.rs # 2 (fixtures, at :285,:310) → 677 shipped
rg -o 'category: "([a-z-]+)"' -r '$1' crates/aegis-patterns/src/*.rs | sort -u | wc -l  # 36 → 35 shipped + "test"
find crates/aegis-core/tests/corpus -type f | wc -l      # 15 (README + vulnerable 5 / clean 3 / negative 6)

# Canonical Atheon refs (fetched 2026-10-11)
git ls-remote https://github.com/aliasfoxkde/Atheon-Enhanced.git HEAD
#   → 24fa243819dc382df76de5791818cdb059692080 (= main; tags v1.5.6..v1.5.9-enhanced;
#     local pin bc42edf = tags v1.5.4-enhanced AND v1.5.5-enhanced)

# Atheon counts at the pin (clean checkout of bc42edf — NOT the drifting
# /nas/Temp/repos/Atheon-Enhanced working copy)
git ls-tree -r bc42edf --name-only | grep -c '^community/[^/]*/.*\.yaml$'  # 409
gunzip -c core/patterns.bundle | grep -o '"name":' | wc -l              # 406 at the pin
#   (the dirty local checkout's rebuilt bundle reports 409 — that is what the
#    original draft quoted; the pin is 406 vs 409 YAML, delta unattributed)
git ls-tree -r bc42edf --name-only | grep -c '_test\.go$'              # 116 (original draft said 111; 117 counting
#   cmd/atheon/main_test_main.go, which holds TestMain but does not match the *_test.go suffix)

# Input sizes (for §7) — scope: pinned trees, not working copies
git ls-tree -r -l 5c86a06 | awk '{s+=$4} END {print s}'                  # 2,887,740 B / 246 files (aegis base)
git -C <clean bc42edf checkout> ls-tree -r -l HEAD | awk '{s+=$4} END {print s}'  # 2,766,557 B / 706 files (atheon pin)
git ls-tree -r -l ddf5992 | awk '{f++; s+=$4} END {print f, s}'   # 247 files / 2,955,199 B (branch tree at review head ddf5992;
#   the total tracks this document's own size — the superseded 2,946,993 B was
#   measured at 91ab20b, before the two review-cite commits grew this document)
# Superseded: ≈2,748,140 B for atheon was measured across the drifting working copy:
#   git -C /nas/Temp/repos/Atheon-Enhanced status --porcelain | awk '{print $1}' | sort | uniq -c
#   → 32 M, 3 D (renamed lowercase), 16 ?? — incl. five untracked cmd/atheon/*.go
#     (commands.go, flags.go, output.go, completion.go, baseline_diff.go) that exist
#     in NO commit; all citations to them were re-homed to cmd/atheon/main.go at the pin.

# PR checks refresh (re-run 2026-10-11)
gh pr list --repo aliasfoxkde/aegis --state open        # → #162, #163, #168 (this document)
gh pr checks 162 / 163 --repo aliasfoxkde/aegis         # 162: all pass (draft);
                                                        # 163: Third-Party Notices FAIL
```

### 13.3 Atheon-side citations not reproduced verbatim above

Key Atheon files audited (read-only, clean checkout of `bc42edf`,
re-verified 2026-10-11): `cmd/atheon/main.go` (+ its `*_test.go`),
`cmd/{mcp,daemon,network-scanner}/main.go`, `core/{bundle.go,runner.go,
ignore.go,suppression.go,entropy.go,ast_patterns.go,audit_layers.go,cfg.go,
taint.go,imports.go,clone_detection.go,yara_scanner.go,pattern_state.go,
finding.go,pattern.go,flock_unix.go,flock_windows.go,bench_test.go,entropy_test.go}`,
`bundler/main.go`, `runtime/**` (dead code from the CLI's perspective —
no `cmd/`, `bundler/`, or `adapters/` file imports it; re-swept at the
pin 2026-10-11; `ConfigProfile` parsed-and-discarded at
`cmd/atheon/main.go:194`), `docs/{BENCHMARKS.md,ARCHITECTURE.md,FAQ.md,
BRANCH_STRATEGY.md}`, `.github/workflows/{ci.yml,security.yml,release.yml}`,
`.goreleaser.yml`, `.pre-commit-config.yaml`, `Makefile`,
`scripts/pattern-count.sh`.

**Correction of record:** the original draft cited
`cmd/atheon/{commands.go,flags.go,output.go,completion.go,baseline_diff.go}`.
Those files **do not exist at `bc42edf` (nor anywhere in the repo's
history)** — they were untracked files in the drifting local working
copy. Every behavior claim attached to them was re-homed to
`cmd/atheon/main.go` at the pin (§3.1, §3.2, §3.6, §3.7, D-09, D-16);
any statement not re-homed must be treated as unvalidated.

### 13.4 Environment notes

- Docs check: no `lychee`/`markdownlint`/`pandoc` binary on this host
  (re-VERIFIED 2026-10-11); the repo's docs gate is the CI `Links` job —
  lychee v0.23.0, `--no-progress 'README.md' 'docs/**/*.md'`, config in
  `lychee.toml` (`.github/workflows/ci.yml:192-210`). This file sits
  inside that glob and contains no markdown links (zero `](` —
  re-checked 2026-10-11; cross-references are backticked paths), so the
  CI Links job is the authoritative format check.
- This document adds no product code, no fixtures, no generated data,
  and asserts no release/deploy state.
