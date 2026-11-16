# Stale-branch cleanup record — 2026-11-16

**Issue:** [#136](https://github.com/aliasfoxkde/aegis/issues/136) — "chore: stale-branch cleanup record — 66 deleted, 13 kept with unmerged work"
**Scope:** the two remotes of this repository — `origin` (`https://github.com/aliasfoxkde/aegis.git`) and `gitforge` (`http://localhost:42782/bigdata-ci/aegis.git`)
**Audit boundary:** branch `main`, HEAD `086d478c0f89608cf926795910cf5a0881c0852e` (`origin/main`, verified 2026-11-16)
**Method:** see [Method](#method). Every claim below is reproducible from the repository; no claim rests on a watcher's memory of an earlier run.

---

## 1. Summary

The 2026-09-23 audit deleted 66 branches whose content was provably in `main`
and kept 13 branches carrying work that had never landed. This pass
re-validated every kept branch against the current `origin/main` — which has
moved 21 commits since — and reached a disposition for each:

| Outcome | Count | Branches |
|---|---|---|
| Revived — content promoted to `main` by this change | 1 | `codex/aegis-qualification-20260919` |
| Explicitly discarded — content superseded or moot | 4 | `audit/t5500-clean-stack`, `codex/aegis-shared-parity-20260919`, `docs/benchmark-results`, `codex/aegis-strict-clippy-20260910` |
| Superseded — content provably in `main` via a merged PR | 8 | `codex/aegis-precision-20260914`, `chore/release-v0.6.1`, `codex/aegis-h2-security-20260831`, `codex/aegis-mcp-test-isolation-20260831`, `platform-handoff/aegis-baseline-20260821`, `codex/aegis-diff-eof-failclosed-20261011`, `codex/aegis-diff-header-correctness-20261011`, `codex/aegis-scan-hardening-20261005`, `codex/aegis-scan-hardening-mainline-20261011` |
| Retained — unique work, deliberately not deleted | 4 | `codex/control-center-adapter-cli`, `platform-handoff/aegis-w1-01`, `codex/pa-handoff-aegis-sarif-20261011`, `release/v0.1.3` |

Five branches on `gitforge` had no merged PR and no unique content of their
own and are also deleted: `chore/release-0.6.4`, `chore/v0.6.3`,
`ci/coverage-floor`, `ci/drift-checks`, `feat/*` (4), `fix/*` (7),
`docs/accuracy-sweep`, `docs/archive-roadmap-distribution`,
`docs/plan-item-e-investigation`, and `codex/aegis-atheon-parity-handoff-20261011`.
Each of those has a merged PR on `origin` whose head branch carries the same
name, so the squash-merged content is in `origin/main`.

One further branch, `codex/control-center-adapter-cli`, was reassessed: the
2026-09-23 audit called it "stale-superseded", but that judgement is wrong
(§4.4) — it holds the only copy of an unshipped CLI feature and is therefore
retained, not deleted.

`dependabot/github_actions/actions-bb9577a03d`, listed in the original audit
as "active, has open PR #125", is no longer active: PR #125 merged on
2026-09-24 and GitHub removed the head branch automatically.

## 2. Method

Three independent signals were used, in this order, and the strongest
applicable one decided each branch:

1. **Merged-PR head-name mapping.** The repository squash-merges, so a branch's
   content survives its deletion under the *merged PR's* head name. All 185
   pull requests (`gh pr list --state all --limit 300`) were enumerated and
   their head names collected. A branch whose name appears as the head of a
   merged PR has its content in `main`; this is authoritative under squash
   merges and is the same signal the 2026-09-23 audit used.
2. **Content presence against `origin/main`.** For every file touched by a
   branch's unique commits, the blob at the branch tip was compared with the
   blob at `origin/main`: `SAME` (identical), `DIFFERS` (present in both, but
   `main` has since moved on), `NEW-ONLY` (absent from `main`), or `DELETED`
   (the branch deleted a path that `main` still carries).
3. **Patch-id uniqueness (`git cherry`).** Used only as a *lower bound* on
   unique work. Under squash merges the patch-ids of merged commits do not
   survive, so `git cherry` reports `"+"` for work that in fact landed; the
   four October branches below all report 7–11 "unique" commits that are
   already in `main`. Signal 3 alone would have produced a wrong answer in
   every case, which is why content presence (signal 2) decided the outcome.

## 3. Findings that required a code or documentation change

### 3.1 The `executable-file-upload` self-scan test is obsolete

`codex/aegis-qualification-20260919` added
`crates/aegis-core/tests/release_lib_self_scan.rs` (107 lines) to pin a
suppression in `scripts/release/lib.sh`: the real file must scan clean with
the directive, and the directive-stripped prose must still fire, so the
suppression stays load-bearing.

Both of its assertions are false against `main` today:

- `main`'s `scripts/release/lib.sh` carries **no** `aegis:ignore` directive
  (`grep -c 'aegis:ignore'` → 0). The branch's edit was a one-line directive
  on a file that was since rewritten by the v0.6.x release-script rework.
- The branch-era pattern was `(?i)\.(exe|sh|php|asp|jsp)\s*.*upload`, which
  matched the prose `publish.sh refuses to upload a directory`. The current
  pattern (`crates/aegis-patterns/src/web_security.rs`,
  `executable-file-upload`) is
  `(?i)\bupload[\w-]{0,10}\s*\(?\s*["']?[^\s"']{0,60}\.(exe|sh|php|asp|jsp)\b|move_uploaded_file`,
  which does not match that prose — the anchor is now on the *upload verb*,
  not on the filename. The directive-stripped prose now fires **zero** times,
  so the test's second assertion ("fires exactly once") would fail.

The rule was fixed upstream; the test that guarded the old workaround was
not, and must not be promoted. **Disposition: discarded**, not revived.

### 3.2 The qualification report is promoted

`AEGIS_CONSUMER_QUALIFICATION_REPORT_2026-09-19.md` (340 lines) was absent
from `main`. It is now at
`docs/audits/2026-09-19-R7-consumer-qualification.md`, byte-identical to the
recovered copy (29 879 bytes). It is a read-only consumer qualification
report against v0.6.1, and it is the evidence base for several of the
documentation corrections in §3.4.

### 3.3 Three documentation defects from that branch were never landed

The branch's `docs/progress/2026-09-19-docs-remediation.md` proposed four
documentation fixes. Two had already been overtaken by later work; two were
still outstanding and are fixed by this change:

| Fix | State on `main` before this change | Action |
|---|---|---|
| `AGENTS.md` license wording: `Apache-2.0 (NOT MIT OR Apache-2.0)` (self-contradictory) | still present | Fixed — `Apache-2.0 (see LICENSE; Cargo.toml declares license = "Apache-2.0")` |
| `docs/guides/CONFIGURATION.md`: note that `AEGIS_DAEMON_*` configures a Unix-socket daemon | still absent | Fixed — one sentence added below the variable table |
| `AGENTS.md` pattern/category counts | `670` / `34` | Fixed — see §3.4 |
| `docs/guides/CLI.md`: mark `enable`/`disable` as non-persisting no-ops | obsolete — pattern state **is** persisted now (`crates/aegis-cli/src/pattern_state.rs`) | Not applied (would have been wrong) |

### 3.4 The pattern/category count was stale in eight files

`docs/patterns/README.md` — the canonical catalog index — states
**677 detection patterns across 35 categories**. Eight other files still
claimed `670`/`34`:

`.github/CONTRIBUTING.md` (×2), `.github/wiki/Home.md` (×2),
`.github/wiki/_Footer.md`, `.github/wiki/_Sidebar.md`, `AGENTS.md` (×2),
`PLATFORM_INTEGRATION.md`, `docs/guides/BUILDING.md`,
`docs/planning/HANDOFF.md` (×3).

All were corrected to `677`/`35`. The figure was re-derived from the source
rather than copied: 677 `severity:` literals, 677 `category:` literals over 35
distinct categories, and 677 distinct rule names across the 35
`get()`-returning modules in `crates/aegis-patterns/src/` (excluding
`#[cfg(test)]` blocks), with **zero** `enabled: false` occurrences — so the
enabled count and the shipped count are the same number. `AGENTS.md` now names
`docs/patterns/README.md` as the source of truth.

The measured severity distribution is 68 critical / 145 high / 188 medium /
269 low / **7 info** = 677. The canonical catalog's severity table
(`docs/patterns/README.md`) lists only the first four, so the wiki statistics
block was corrected to include the 7 `info` rules; without them the breakdown
did not sum to the stated total. `info` is a supported severity, not a
stray value: `crates/aegis-core/src/risk.rs:210` maps it to weight 0 so
informational rules (the `ai-slop` category) contribute nothing to the risk
score.

The `CHANGELOG.md` entry `660 → 670 patterns` under `[0.6.0]` is a historical
release note and was deliberately left alone.

## 4. Per-branch disposition

### 4.1 Revived — `codex/aegis-qualification-20260919` (2 unique commits)

`origin` + `gitforge`, tip `455c854a8da32b40a2d594e689fc357ef5cb3039`.

| File | State vs `main` | Disposition |
|---|---|---|
| `docs/progress/AEGIS_CONSUMER_QUALIFICATION_REPORT_2026-09-19.md` | NEW-ONLY | **Promoted** → `docs/audits/2026-09-19-R7-consumer-qualification.md` |
| `docs/progress/2026-09-19-docs-remediation.md` | NEW-ONLY | Superseded by §3.3 (its fixes are applied directly) |
| `crates/aegis-core/tests/release_lib_self_scan.rs` | NEW-ONLY | **Discarded** — obsolete, see §3.1 |
| `scripts/release/lib.sh` | DIFFERS | Branch edit obsolete; `main`'s rewrite stands |
| `AGENTS.md`, `docs/guides/{BUILDING,CLI,CONFIGURATION}.md`, `docs/planning/HANDOFF.md`, `PLATFORM_INTEGRATION.md` | DIFFERS | `main` has moved on; only the two live defects fixed (§3.3) |

### 4.2 Explicitly discarded — `audit/t5500-clean-stack` (1 unique commit)

`origin`, tip `c7a098aa016094b83c88f5e80045e20fb1cfe721`. The only unique
file is `CLEAN-SETUP-NOTES.md` (25 lines, 2026-09-20), which reported three
gaps. All three are resolved in `main`:

| Reported gap | State on `main` |
|---|---|
| "No `--json` output mode for CI integration" | **Resolved** — `--format json` / `-f json` exists (`OutputFormat` in `crates/aegis-cli/src/lib.rs:23`) |
| "Pattern-bundle `update` requires network + no offline bundle path" | **Moot** — `update_bundle` (`crates/aegis-cli/src/scanner.rs:636`) is a local no-op that prints the embedded pattern/category counts; there is no network fetch and nothing to mirror offline |
| "README's build section should name the package (`-p aegis-cli`)" | **Already present** — `docs/guides/BUILDING.md:36` names `cargo build -p aegis-cli` |
| "`/tmp` is silently skipped by scan" | **Not reproducible** — `main`'s built-in ignores are `node_modules`, `target`, `.git`, `.aegis` (`crates/aegis-core/src/ignore.rs:122`); no `/tmp` rule exists in the walk. The observation was environment-specific and is not a property of the scanner |

The note also asserted "670 patterns loaded" — the same stale figure fixed in
§3.4. Nothing from it is worth keeping as a separate file.

### 4.3 Explicitly discarded — `codex/aegis-shared-parity-20260919` (1 unique commit)

`origin` + `gitforge`, tip `e388c2831466d6bfa7cd90ce073b6a3aa529d29d`.
Contains `docs/progress/AEGIS_ATHEON_SHARED_PARITY_RECEIPT_2026-09-19.md`
(66 lines) plus six scan fixtures under
`docs/progress/fixtures/aegis-atheon-parity-20260919/`.

- The receipt is self-labelled **"(NOT PROMOTED)"** by its own author.
- Its substance (Aegis ⇄ Atheon parity, rollout steps, canonical source
  pinning) is now covered in full by
  `docs/handoffs/2026-10-11-aegis-atheon-parity-and-rollout.md` in `main`
  (977 lines), which is a superset of the earlier 880-line branch revision:
  the canonical-source paragraph now names
  `https://github.com/aliasfoxkde/Atheon-Enhanced` and the `v1.5.5`–`v1.5.9`
  tag range.
- The six fixtures are synthetic credential files (`aws_key.env`,
  `password.env`, …). Promoting them into the repository tree would trip the
  repository's own secrets scan and the `aegis:ignore` fixture convention.
  They are disposable inputs to a one-off manual comparison, not fixtures
  worth versioning.

### 4.4 Retained — `codex/control-center-adapter-cli` (16 unique commits)

`origin`, tip `6bd5fc4a94ac2080aa4e646ff8f58c603cab4995`.

The 2026-09-23 audit assessed this as "stale-superseded — adapter landed in
`aegis-core` via PR #42; targets a CLI layout that no longer exists". The
first half is right and the second half does not license deletion:
`crates/aegis-core/src/control_center_adapter.rs` is in `main` (1 340 lines),
but **there is no `aegis adapter` subcommand in `main` at all** —
`crates/aegis-cli/src/` contains only `benchmark.rs`, `config.rs`, `lib.rs`,
`main.rs`, `output.rs`, `pattern_state.rs`, `scanner.rs`.

The branch's unique files are therefore unshipped work, not superseded work:

- `crates/aegis-cli/src/adapter.rs` (NEW-ONLY, 528 lines) — the CLI wrapper
- `crates/aegis-cli/tests/output_contract_matrix.rs` (NEW-ONLY)
- `crates/aegis-core/src/output/{database,file,mod,webhook}.rs` (NEW-ONLY) —
  an output-sink layer that `main` still lacks
- `crates/aegis-core/src/config/preset.rs` (NEW-ONLY)
- `crates/aegis-mcp/src/tools.rs` (NEW-ONLY)
- `tests/adapter_cli_integration.rs` (347 lines), `tests/mcp_integration.rs`
- `kubernetes/{configmap,deployment,service}.yaml` (NEW-ONLY)
- `docs/progress/CONTROL_CENTER_ADAPTER_CLI_RECEIPT_2026-09-01.md`

It does not compile against `main` (it targets a `crates/aegis-core/src/output/`
layout and a `config.rs` → `config/mod.rs` move that `main` has since made in
the other direction). Reviving it is a feature task, not a cleanup task, so
the branch is **retained** with its SHA recorded here. Nothing is lost, and
nothing unmergeable is deleted.

### 4.5 Retained — `platform-handoff/aegis-w1-01` (1 unique commit)

`gitforge` only, tip `ddb5af965774b06c176bc5531182bb69c9cbaf24`.

| File | State vs `main` |
|---|---|
| `crates/aegis-patterns/src/ai_runtime.rs` | NEW-ONLY (193 lines) |
| `crates/aegis-patterns/tests/ai_runtime_test.rs` | NEW-ONLY |
| `tests/fixtures/ai_runtime/{auth_003_positive,auth_003_false_positive,runtime_001_positive,runtime_001_false_positive,runtime_003_positive,runtime_004_positive}.rs` | NEW-ONLY (6 fixtures) |

Six AI-runtime defect rules — `ai-auth-003-anonymous-router-bind`,
`ai-auth-003-anonymous-curl-probe`, `ai-runtime-001-process-group-zero`,
`ai-runtime-001-pkill-f-usage`, `ai-runtime-003-reasoning-content-passthrough`,
`ai-runtime-004-low-max-tokens`.

The file targets the pre-rework `Pattern` struct (no `exclude` /
`file_extensions` fields, which `main`'s `Pattern` has) and uses cross-line
regexes such as `[\s\S]{0,2000}`. Promoting it as-is would fail the
per-rule corpus gate and the provable-liveness harness, which require
generated examples for every enabled rule. Salvaging it means re-authoring
the rules against the current `Pattern` API and regenerating the corpus —
a pattern contribution task, not a cleanup task. The branch is **retained**
with its SHA recorded here.

### 4.6 Retained — `codex/pa-handoff-aegis-sarif-20261011` (2 unique commits)

`origin`, tip `8f4d83779f402f5981788f86f84c132d6867c50e`. **This branch has
an open pull request** — [#174](https://github.com/aliasfoxkde/aegis/pull/174)
("docs: add SARIF GitHub consumer parity handoff", draft, all 24 checks
`SUCCESS`). A branch with an open PR is not stale. Its 11 unique files (the
`docs/handoffs/2026-10-11-sarif-contract-p0/` contract, evidence-receipt
template and seven SARIF fixtures, plus
`docs/handoffs/2026-10-11-sarif-github-consumer-parity.md`) are absent from
`main` and are carried by that PR.

### 4.7 Retained — `release/v0.1.3` (ruleset-protected)

`origin`, tip `6c34b661aad26c5daad7d9205549aea867e2be3a`. The **Safeguards**
ruleset (id `20411250`, active, no bypass actors) protects `release/*`,
`stable/*` and the default branch against deletion and non-fast-forward
updates. Leaving it in place is required, not an oversight.

### 4.8 Superseded — confirmed content in `main`

| Branch | Uniq | Evidence |
|---|---|---|
| `codex/aegis-strict-clippy-20260910` | 1 | Every unique file targets `crates/aegis-core/src/output/*` — a directory that does not exist in `main` (`main` keeps output in `crates/aegis-cli/src/output.rs`). A stale-layout strict-clippy pass |
| `codex/aegis-precision-20260914` | 3 | `docs/progress/DOCKERFILE_SCOPE_PRECISION_RECEIPT_2026-09-14.md` is **SAME** in `main`; the Dockerfile scoping landed via PR #113/#114 (rules carry `file_extensions: ["dockerfile"]`); the `.gitforce.yml` lane split was replaced by the single-job design of PR #127 — `main`'s `.gitforce.yml` documents *why* a `needs`-based split silently degrades to "first job only" |
| `chore/release-v0.6.1` | 2 | `ci/release/Dockerfile`, `scripts/release/build_release.sh` and `scripts/release/publish_github_release.sh` were replaced by the current `scripts/release/{build,publish,pipeline}.sh` trio; v0.6.1 shipped via PR #116 |
| `codex/aegis-h2-security-20260831` | 21 | August adapter lineage plus a `Cargo.lock` h2 bump; `main`'s lockfile is strictly newer |
| `codex/aegis-mcp-test-isolation-20260831` | 20 | Sibling variant `codex/aegis-mcp-test-isolation-main-20260831` merged via PR #47; `main`'s `crates/aegis-cli/tests/cli_integration.rs` has no nested `cargo` invocation |
| `platform-handoff/aegis-baseline-20260821` | 9 | August adapter lineage; the only unique file is `docs/planning/BASELINE_RECEIPT_2026-08-21.md`, superseded by the current audit trail in `docs/audits/` and `docs/handoffs/` |
| `codex/aegis-diff-eof-failclosed-20261011` | 11 | Landed as PRs #167, #175, #179 and #180 (see §4.9) |
| `codex/aegis-diff-header-correctness-20261011` | 10 | Same landing set |
| `codex/aegis-scan-hardening-20261005` | 7 | Same landing set |
| `codex/aegis-scan-hardening-mainline-20261011` | 9 | Same landing set |

### 4.9 The October scan-hardening branches: why `git cherry` would have lied

The four October branches report 7–11 "unique" commits each. Every one of
those commits is already in `main`, under a squash merge with a different
SHA:

| Branch commit | Landed as |
|---|---|
| `28930cf fix(scanner): fail closed on EOF target header` | `622beb5 fix(scanner): consolidate fail-closed scan hardening (#179)` |
| `5e5683c fix(scanner): tell diff body shapes from file headers` | `622beb5` (#179) |
| `f79fd5c fix(scanner): fail closed on malformed diff hunks` | `622beb5` (#179) |
| `f20af89 fix(scan): anchor diff findings to target lines` | `370e567 fix(scanner): preserve source lines in diff scans (#167)` |
| `852d891 fix(cli): compute status before writing output` | `9d9c1cf fix(cli): fail closed on incomplete scans (#175)` |
| `064c408 fix(cli): fail closed on incomplete inspections` | `9d9c1cf` (#175) |
| `f2b788f` / `ac0be25 fix(ci): build CI targets off the workspace share` | `84edb97 fix(aegis): fail closed on stale outputs and staged gaps (#180)` |

`main` carries the resulting machinery: `INSPECTION_LEDGER_SCHEMA_VERSION`
(`crates/aegis-core/src/finding.rs:240`), 14 `EXIT_INCOMPLETE` references in
`crates/aegis-cli/src/scanner.rs`, and the diff-header state machine in
`crates/aegis-core/src/scanner.rs` (lines ~498–612) that distinguishes diff
body shapes from file headers. `crates/aegis-core/src/finding.rs`,
`.gitforce.yml`, `scripts/ci/classify_aegis_sarif.py`, `scripts/README.md`
and `scripts/test_classify_aegis_sarif.py` are **SAME** between the branches
and `main`.

### 4.10 `docs/benchmark-results` — superseded, and its claim must not return

`origin` + `gitforge`, tip `fb5d46743ad797b8d1dbea990c643ff49b64b7cc`.
Two unique files: `benchmark.sh` and `docs/BENCHMARK.md`. The harness
superseded it: `main` has `crates/aegis-core/src/benchmark.rs` plus three
benches (`clone_detection`, `pattern_matching`, `scanner_init`) and an
`aegis benchmark` subcommand.

The branch's `docs/BENCHMARK.md` additionally asserts **"Aegis is ~25x
faster"** on a 32-file dataset, measured once, against a local Atheon build.
`main`'s `docs/planning/HANDOFF.md` explicitly retires this class of claim:
*"The historical '12x faster / 20% smaller' claims from the original planning
documents were never reproduced and should not be repeated."* The claim was
not reproduced and is not repeated here.

## 5. Mirror drift found while re-validating

`gitforge/main` was **14 commits behind** `origin/main`, and 2 commits ahead
of it:

- `gitforge/main` = `46cd30a` = `v0.6.4` (`fa5d032`) + `afdcf5a` +
  `46cd30a`.
- `origin/main` = `086d478`, which contains 14 commits that
  `gitforge/main` does not: 10 feature/fix merges (#166, #168, #172, #175,
  #178, #179, #180, #187, #189, #190) and 4 dependency bumps (#177, #184,
  #188, and the actions-toolchain bump).

Because the release path is GitForge-first, a release cut from
`gitforge/main` would have shipped a tree missing the fail-closed scan
hardening (#179, #180), the PII-marker boundary fix (#189), and the
CodeRabbit draft-review configuration (#190). This is the direct
cause of the branch residue in §4.8: GitForge-only branches are leftovers
from merged PRs that never got mirrored back.

The two commits unique to `gitforge/main` — `afdcf5a` (handoff evidence
boundary) and `46cd30a` (the recovered qualification report) — are promoted
to `origin/main` by this change, which removes the "ahead" half of the
divergence. The "behind" half is closed by merging `origin/main` into
`gitforge/main` (a merge commit — no force-push, no history rewrite), after
which both remotes carry the same tree.

**Executed 2026-11-16.** PR #191 (squash `18d63b1`) promoted both commits
into `origin/main`; `origin/main` was then merged into `gitforge/main` as
merge commit `bccf626` (one conflict, in `docs/planning/HANDOFF.md`,
resolved to the `origin/main` side). The two remotes now carry a
byte-identical tree, and the merge was a fast-forward for the `gitforge`
ref — no history was rewritten on either remote.

## 6. Deleted branches

`origin` (12): `audit/t5500-clean-stack`, `chore/release-v0.6.1`,
`codex/aegis-diff-eof-failclosed-20261011`,
`codex/aegis-diff-header-correctness-20261011`,
`codex/aegis-precision-20260914`, `codex/aegis-qualification-20260919`,
`codex/aegis-scan-hardening-20261005`,
`codex/aegis-scan-hardening-mainline-20261011`,
`codex/aegis-shared-parity-20260919`, `codex/aegis-strict-clippy-20260910`,
`docs/benchmark-results`, `platform-handoff/aegis-baseline-20260821`.

`gitforge` (30): the 10 of those names that exist on that mirror (it never
had `audit/t5500-clean-stack` or `chore/release-v0.6.1`), plus
`chore/release-0.6.4`, `chore/v0.6.3`, `ci/coverage-floor`, `ci/drift-checks`,
`codex/aegis-atheon-parity-handoff-20261011`,
`codex/aegis-h2-security-20260831`,
`codex/aegis-mcp-test-isolation-20260831`, `docs/accuracy-sweep`,
`docs/archive-roadmap-distribution`, `docs/plan-item-e-investigation`,
`feat/ai-slop-detection`, `feat/code-smells`, `feat/strict-lints`,
`feat/third-party-notices`, `fix/deterministic-cross-linking`,
`fix/finding-line-column`, `fix/loud-severity-and-bounded-clones`,
`fix/lychee-exclude-gdpr`, `fix/scan-exclude-state-dir`,
`fix/tag-mtime-epoch`.

Every gitforge-only branch in that list has a merged PR on `origin` whose
head branch carries the same name, except the four October scan-hardening
branches and the shared-parity/benchmark/qualification branches, which are
dispositioned in §4.

Retained: `release/v0.1.3` (ruleset-protected),
`codex/control-center-adapter-cli` and
`platform-handoff/aegis-w1-01` (unique work, §4.4/§4.5),
`codex/pa-handoff-aegis-sarif-20261011` (open PR #174, §4.6).

**Executed 2026-11-16.** The 12 `origin` branches and the 30 `gitforge`
branches above were deleted; `origin` kept `main`, `release/v0.1.3`,
`codex/control-center-adapter-cli` and
`codex/pa-handoff-aegis-sarif-20261011`, and `gitforge` kept `main` and
`platform-handoff/aegis-w1-01`. The audit record itself landed in PR #191
(squash `18d63b1`).

## 7. Residual scope

- **Local branches and worktrees were not pruned.** The canonical checkout
  holds 124 local branches and 11 worktrees, several of which belong to
  other sessions (e.g. `/home/mkinney/agent-work/aegis-parity-gap-20261020`).
  Pruning them is an operator action on shared local state, not a repository
  cleanup, and is deliberately out of scope here.
- **`AGENTS.md` still claims "818 tests across 25 test binaries (measured
  2026-09-24)".** The figure is dated and not re-measurable here (no local
  `cargo` build was run — the host build-admission hook denied it). It needs
  a fresh measurement when the toolchain is next available.
- **`crates/aegis-core/tests/release_lib_self_scan.rs` was not revived**
  (§3.1). If a regression test for the `executable-file-upload` rule is
  wanted, it should assert against the *current* pattern rather than the
  superseded one.
