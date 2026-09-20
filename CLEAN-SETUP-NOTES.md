# Aegis clean-setup notes — t5500 audit branch (2026-09-20)

## Build
- `cargo build --release` clean: **2m40s**; the CLI needs an explicit
  `-p aegis-cli` (default workspace build produces `aegis-bootstrap`, not
  the `aegis` scanner binary) — **top doc gap**: README's build section
  should name the package.
- Binary name is `aegis` but only inside `target/release/` after the
  package-scoped build. Recommend a symlink step in the README.

## Runtime (verified working)
- 670 patterns loaded; `scan <path>` with risk score + severity + category
  breakdown; `list` / `enable` / `disable` / `benchmark` subcommands.
- AWS secret + GitHub token planted test: correctly flagged CRITICAL
  (risk 96) — **when scanned outside /tmp**.

## Gaps found
1. **`/tmp` is silently skipped** by scan (common convention, but the
   output shows "Level: none, Score: 0" with no mention of the skip —
   a one-line "skipped N paths (temp)" note would save an hour of
   confusion on a fresh install).
2. No `--json` output mode for CI integration (findings are
   human-format only) — matters for the CI/CD pipeline story.
3. Pattern-bundle `update` requires network + no offline bundle path is
   documented for air-gapped installs.
