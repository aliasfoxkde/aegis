# 2026-09-19 — Documentation remediation

## Scope

A read-only consumer qualification (`AEGIS_CONSUMER_QUALIFICATION_REPORT_2026-09-19.md`, 2026-09-19) flagged three
concrete documentation defects. This change is a narrow docs-only
remediation derived directly from the report; no source, release,
license, or generated file was touched, no benchmarks were run, and no
binary was executed.

## What changed

### 1. `AGENTS.md` pattern/category counts (lines 7 and 51)

Previously: `633 detection patterns across 33 categories` (line 7) and
`633 enabled patterns across 33 categories` (line 51).

Now: `670 detection patterns across 34 categories`, with a source/date
note pointing at `docs/patterns/README.md:3` and the `CHANGELOG.md`
`[0.6.0]` `660 → 670 patterns` entry, verified 2026-09-19.

### 2. `AGENTS.md` license wording (line 79)

Previously: `Apache-2.0 (NOT MIT OR Apache-2.0)` — contradictory.

Now: `Apache-2.0`, with a pointer to `LICENSE`, `Cargo.toml:6`, and
`[workspace.package] license = "Apache-2.0"` at `Cargo.toml:35`. The
license itself is unchanged.

### 3. `enable` / `disable` no-op semantics (CLI.md)

The `aegis enable` / `aegis disable` section in `docs/guides/CLI.md`
already documented that pattern state is not persisted; an additional
sentence now flags the subcommands as informational no-ops so
integrators do not assume persistence between invocations. No claim
is made about Windows support.

### 4. Unix-only `aegis-daemon` (CONFIGURATION.md)

The `AEGIS_DAEMON_*` variable block in `docs/guides/CONFIGURATION.md`
now ends with a single sentence noting that those variables configure
`aegis-daemon`, which listens on a Unix domain socket and so is only
meaningful on Unix-like platforms, with a pointer to the existing
`ARCHITECTURE.md` and `CLI.md` sections. The note describes the
current behavior; it does not assert a missing Windows capability
that the source does not actually carry.

## What remains unverified

The following items from `AEGIS_CONSUMER_QUALIFICATION_REPORT_2026-09-19.md` §10 and §11 are **out of scope**
for this docs-only remediation and remain open:

- No locally built Aegis binary was exercised in this branch — every
  behavioral claim is documentary, not measured.
- README "12× faster" claim and AGENTS.md "97.2% lines / 94.5%
  regions" coverage figure are not re-verified here and were not
  changed.
- `aegis list` was not run; the 670/34 figure is taken from
  `docs/patterns/README.md:3` and the `CHANGELOG.md` `[0.6.0]`
  `660 → 670 patterns` entry.
- `enable` / `disable` persistence decision (P3 in the qualification report §11)
  is intentionally not implemented; this change documents the
  current no-op behavior only.
- Daemon client recipe (P2 in the qualification report §11) is intentionally not
  added; this change clarifies the existing socket/env-knob surface
  only.
- Parity, performance, precision/recall, and license-compatibility
  claims (P0/P2 in the qualification report §11) are not made here.

## Checks performed

Bounded text-level checks only:

- Markdown link/reference sanity (manual review of the changed
  anchors — `docs/architecture/OVERVIEW.md#cli-interface` and
  `docs/guides/CLI.md#aegis-daemon`).
- `grep` for `633` / `NOT MIT` / `aegis-daemon` references across
`AGENTS.md`, `docs/guides/BUILDING.md`, `docs/guides/CLI.md`, and
`docs/guides/CONFIGURATION.md`
  to confirm no stale count or daemon-emission note was added beyond
  what was changed.

No `cargo` commands, no test runs, no daemon/CLI invocation, no
remote calls. `git status` was used to verify the working tree
between edits.
