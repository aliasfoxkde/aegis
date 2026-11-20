# Aegis R0 Identity Inventory — Q-16 (2026-10-12)

Read-only reconciliation of the two repos/checkouts and scanner binaries/pins.
All values below were measured live on 2026-10-12. No fetch, no network, no
scanner/test execution, no GitForge API calls; both dirty trees were left
untouched. This is the only file created; no existing file was edited.

> Revised 2026-10-12 per independent review (GLM-5.3), each correction re-verified read-only against
> live state: (1) registered Aegis worktrees are 14, not 13 (`/nas/Temp/work/aegis-strict-clippy-20260910`
> was omitted); (2) Atheon-Enhanced dirty status is 32 modified, not 34 (the per-file enumeration was
> already correct; only the header count was wrong); (3) `taiki-e/install-action` is pinned in
> `ci.yml`/`fuzz.yml`, not `release.yml` — attribution corrected and `release.yml`'s actual pins listed.
> All other facts unchanged.
>
> Second revision, same day, same review cycle: the Aegis diff grew after the original measurement —
> `.github/workflows/aegis-scan.yml` joined the modified set (8 modified paths now) and this report
> itself is the tree's one untracked path; and one line reference went stale as the diff grew (the
> `v0.6.3` pinning example in `docs/guides/CICD_INTEGRATION.md` is at line 227, was 216 — all other
> line references re-verified current, including `kubernetes/cronjob.yaml:51`). Revision edits touch
> only this report; both measured trees remain otherwise untouched.

## 1. Aegis checkout (this worktree) — OBSERVED

- Path: `/home/mkinney/worktrees/aegis-r4-fail-closed-20261012`
- Branch: `codex/aegis-r4-fail-closed-20261012` (tracks `origin/main`, shown in sync with the **local** `origin/main` ref; no fetch performed, so remote freshness is unknown)
- HEAD: `bebadc7da2bcd28af0f26452f42ce4e0e901fc66`
- Worktree of backing repo: `git rev-parse --git-common-dir` → `/nas/Temp/repos/aegis/.git`
- Remotes: `gitforge` → `http://localhost:42782/bigdata-ci/aegis.git`; `origin` → `https://github.com/aliasfoxkde/aegis.git`
- Dirty paths (8 modified, 1 untracked; preserved, not cleaned):
  - `M .github/workflows/aegis-scan.yml`
  - `M CHANGELOG.md`
  - `M PLATFORM_INTEGRATION.md`
  - `M crates/aegis-cli/src/scanner.rs`
  - `M crates/aegis-cli/tests/cli_integration.rs`
  - `M docs/guides/CICD_INTEGRATION.md`
  - `M docs/guides/CLI.md`
  - `M kubernetes/cronjob.yaml`
  - `?? docs/progress/AEGIS_R0_IDENTITY_INVENTORY_2026-10-12.md` (this report)

### Backing repo `/nas/Temp/repos/aegis` — OBSERVED
- Branch `main`, HEAD `370e5679d48980ac1bb4ad1e28e3e1df70b6dabe`
- `git merge-base --is-ancestor 370e567 bebadc7` → yes (worktree HEAD descends from current `main` HEAD)
- Registered worktrees (14 total, re-verified via `git worktree list` at revision time), this checkout among them:
  `/nas/Temp/repos/aegis` (main, 370e567); `~/repos/aegis/.worktrees/platform-handoff.safety-w1-01` (48f12d3, detached);
  `~/worktrees/aegis-atheon-parity-handoff-20261011` (ddf5992); `~/worktrees/aegis-parity-corpus-s2-20261011` (bee833c);
  `~/worktrees/aegis-r4-fail-closed-20261012` (bebadc7, this one); `~/worktrees/aegis-scan-hardening-mainline-20261011` (ac0be25);
  `~/worktrees/pa-handoff-aegis-20261011` (8f4d837); `/nas/Temp/work/aegis-diff-attribution-20261005` (f20af89);
  `/nas/Temp/work/aegis-fail-closed-20261005` (e316d42); `/nas/Temp/work/aegis-parity-20260919` (e388c28);
  `/nas/Temp/work/aegis-pattern-scope-20261007` (a6e0ba5); `/nas/Temp/work/aegis-precision-20260914` (24dee83);
  `/nas/Temp/work/aegis-qualification-20260919` (455c854); `/nas/Temp/work/aegis-strict-clippy-20260910`
  (57f92d0, branch `codex/aegis-strict-clippy-20260910`).

## 2. Atheon-Enhanced — OBSERVED

- Path: `/nas/Temp/repos/Atheon-Enhanced` (standalone `.git`, not a worktree)
- Branch: `fix/audit-issues-26` (tracks `origin/fix/audit-issues-26`, **ahead 1, behind 1** per local refs; no fetch performed)
- HEAD: `bc42edf2563df9618b9c8ff429f0bacd19dd4e15`
- Remote: `origin` → `https://github.com/aliasfoxkde/Atheon-Enhanced.git` (no `gitforge` remote configured)
- Dirty paths (preserved, not cleaned) — 32 modified, 3 deleted, 16 untracked (51 total paths; counts
  re-verified via `git status --porcelain` at revision time):
  `M AGENTS.md`, `M README.md`, `M adapters/pi/pi.go`, `M bundler/bundle_internal_test.go`, `M bundler/main.go`,
  `M cmd/atheon/main.go`, `M community/README.md`, `M community/devops/README.md`,
  `D community/devops/action-with-SSH-key.yaml`, `M community/frameworks/spring/spring-deserialization.yaml`,
  `D community/metadata/IDE-config-leak.yaml`, `M community/metadata/README.md`,
  `M community/supply-chain/npm-internal-alias.yaml`, `M community/web-security/README.md`,
  `D community/web-security/innerHTML-user-input.yaml`, `M core/bundle.go`, `M core/detection_test.go`,
  `M core/example_test.go`, `M core/pattern_validation_test.go`, `M core/patterns.bundle`,
  `M docs/BENCHMARKS.md`, `M docs/BRANCH_STRATEGY.md`, `M docs/FAQ.md`, `M docs/INSTALLATION.md`,
  `M docs/OWNER_CHECKLIST.md`, `M docs/PATTERN_FORMAT.md`, `M docs/PROGRESS.md`, `M docs/RELEASE.md`,
  `M docs/architecture/PATTERN_CATEGORIES.md`, `M docs/architecture/SYSTEM_ARCHITECTURE.md`,
  `M docs/development/SETUP.md`, `M docs/guides/GitForge-Integration.md`, `M docs/guides/TROUBLESHOOTING.md`,
  `M runtime/scanner/scanner_test.go`, `M scripts/validate-patterns.py`;
  `?? cmd/atheon/baseline_diff.go`, `?? cmd/atheon/commands.go`, `?? cmd/atheon/completion.go`,
  `?? cmd/atheon/flags.go`, `?? cmd/atheon/output.go`, `?? community/devops/action-with-ssh-key.yaml`,
  `?? community/metadata/ide-config-leak.yaml`, `?? community/web-security/innerhtml-user-input.yaml`,
  `?? docs/ANALYSIS_REPORT.md`, `?? docs/CONTRIBUTORS.md`, `?? docs/INDEX.md`, `?? docs/ROADMAP.md`,
  `?? docs/TASKS.md`, `?? docs/architecture/PERFORMANCE.md`,
  `?? docs/architecture/decisions/0007-per-scan-pattern-state.md`, `?? docs/reports/`
- Observation (no action taken): three deleted/untracked pairs differ only in filename case
  (`action-with-SSH-key`→`action-with-ssh-key`, `IDE-config-leak`→`ide-config-leak`,
  `innerHTML-user-input`→`innerhtml-user-input`); cause (rename vs. filesystem case handling) not investigated.

## 3. Binaries — fingerprinted only; NEVER executed

Version strings were **not** obtained (execution is out of scope for R0); identity is via sha256 + size + mtime.

| Binary | Size (B) | mtime (ls) | sha256 |
|---|---|---|---|
| `/nas/Temp/repos/aegis/target/release/aegis` | 4,791,952 | Sep 25 11:27 | `e8ee23371d656dd149cb8a9d234340651ac05226770eb79d2462e93eeb4b2db8` |
| `/nas/Temp/repos/aegis/target/release/aegis-mcp` | 4,441,952 | Sep 22 11:19 | `4cab12068d3039bc9ce6eaec4a0a74a2411d6614981da6236253c18d141dbffe` |
| `/nas/Temp/repos/Atheon-Enhanced/atheon` | 10,795,365 | Aug 9 16:00 | `1dd8a8b941fbe891204be4faeb46d064675c2b809c75a1f417db87704d39deb1` |
| `/nas/Temp/repos/Atheon-Enhanced/atheon-mcp` | 9,673,813 | Jul 16 12:17 | `38b601fb0a817860fe6b26a5d91aeda2df5b110c85ea992b74d1d1424e8adcb7` |
| `/nas/Temp/repos/Atheon-Enhanced/bin/atheon` | 10,783,694 | Aug 4 08:22 | `b053980f80d1fe727ee953543516945422053b716fe2349d421edc6735aa1952` |
| `/nas/Temp/repos/Atheon-Enhanced/bin/atheon-mcp` | 9,617,525 | Aug 4 08:22 | `035d35658289f1b596fde922cfdd9d396329d305395634952407c37601d853a5` |

Additional observed: no `aegis`/`atheon`/`gitforge` binary on PATH in this shell; this worktree has no `target/` build output (builds live in the backing repo's `target/`).

## 4. Aegis version/pin state in Aegis repo CI/docs — OBSERVED (read from dirty working tree)

- `.github/workflows/aegis-scan.yml`: scanner is **built from source** at run time (`cargo build --release -p aegis-cli`, then `./target/release/aegis ...`) — no externally pinned Aegis version; effectively self-scanning at the checked-out SHA. Third-party actions are SHA-pinned with version comments (`actions/checkout@3d3c42e5… # v7.0.1`, `dtolnay/rust-toolchain@7e38f4b… # v1`, `github/codeql-action/upload-sarif@2892aa5… # v4.38.2`, `actions/upload-artifact@043fb46… # v7.0.1`).
- `.github/workflows/ci.yml` / `fuzz.yml`: `taiki-e/install-action@98d24199… # v2` (SHA-pinned) — 5 uses in `ci.yml`
  (`cargo-machete`, `cargo-about@0.9.2`, `cargo-llvm-cov`, `cargo-audit`, `cargo-deny`) and 1 in `fuzz.yml`
  (`cargo-fuzz`). **Not** in `release.yml`: that workflow's only third-party action pins are
  `actions/checkout@3d3c42e5… # v7.0.1`, `dtolnay/rust-toolchain@7e38f4b… # v1`, `Swatinem/rust-cache@6323deb… # v2`;
  it builds via `cargo-zigbuild` + `ziglang==0.16.0`, installed by `pip install ziglang==0.16.0` and
  `cargo install --locked cargo-zigbuild` (not SHA/version-ref-pinned as actions). Nothing pins an external Aegis binary.
- `kubernetes/cronjob.yaml:51` (dirty file): `image: aegis:latest` — floating local tag, no registry digest pin.
- `docs/guides/CICD_INTEGRATION.md` (dirty file): install examples use floating `releases/latest/download/aegis-linux-x86_64.tar.gz` (lines 21, 55, 76, 110) and `docker build -t aegis:latest` (line 148); it also documents pinning guidance with example `releases/download/v0.6.3/…` (line 227) — a doc example, not a deployment pin.
- Source version: workspace `version = "0.6.4"` (`Cargo.toml:32`; `aegis-cli`, `aegis-core`, `aegis-mcp` inherit via `version.workspace = true`). `CHANGELOG.md`: latest release `## [0.6.4] - 2026-09-27`, with `## [Unreleased]` above it. Released 0.6.4 binaries are attached to GitHub releases per CHANGELOG preamble (release contents not inspected — no network).

## 5. Aegis references in Atheon-Enhanced CI/docs — OBSERVED (targeted greps only)

- `.github/workflows/*` (9 files listed): **no** `aegis` matches.
- `README.md`, `docs/guides/GitForge-Integration.md`: **no** `aegis` matches.
- Conclusion: no configured/pinned Aegis binary found in the Atheon-Enhanced files checked (targeted file greps; not a whole-repo scan).

## 6. GitForge

- Observed: only the remote URL config `gitforge → http://localhost:42782/bigdata-ci/aegis.git` on the Aegis checkout (absent from Atheon-Enhanced). Service liveness/version/API state **not probed** (out of R0 scope).

## 7. Unknown / not measured (explicit)

- Executable version strings of all six binaries above (execution disallowed).
- Freshness of `origin/*` refs and the Atheon "ahead 1, behind 1" relative to the true remote (no fetch).
- Whether the Aegis 0.6.4 tag artifacts correspond to any on-disk binary (release assets not downloaded).
- Cause of the Atheon case-variant file pairs; whether any are intentional renames.
- GitForge service state; anything about repos not listed above (no broad `/nas` scans performed — only the exact paths named in this report).

## Constraints honored

No fetch/network; no tests, builds, or scans; no scanner/test execution; no GitForge APIs; no commits/pushes; no edits to existing files (both dirty trees preserved as found; this report is the sole new file).
