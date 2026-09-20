# Aegis / Atheon Shared Parity Receipt — 2026-09-19

- Source SHA: `2eefd884a30a258ff39d6fc58d303de2b8faa935` (branch `codex/aegis-shared-parity-20260919`)
- Fixture directory: `docs/progress/fixtures/aegis-atheon-parity-20260919` (synthetic, hand-built — see Disclosure)
- Raw manual outputs: `/nas/Temp/work/aegis-agent-logs/parity-manual/aegis.json`, `/nas/Temp/work/aegis-agent-logs/parity-manual/atheon.json`

## Exact commands (verified)

Directory scan, run from repo root against the fixture directory for each tool:

```
aegis scan docs/progress/fixtures/aegis-atheon-parity-20260919
atheon scan docs/progress/fixtures/aegis-atheon-parity-20260919
```

Exit codes captured per file via single-file scans of the same fixture directory.

## Verified results

### Directory scan summary

| Tool | Exit | Files scanned | Findings | Suppressed | Failed |
|------|------|---------------|----------|------------|--------|
| Aegis | 1 | 6 | 3 (all `aws-access-key`) | 1 | 0 |
| Atheon | 1 | 6 | 6 (3 `aws-access-key`, 2 `container-no-tag`, 1 `print-debug-leftover`) | — | — |

Note: Atheon flagged extra rule types (`container-no-tag`, `print-debug-leftover`) inside the fixture files that Aegis did not flag; only `aws-access-key` findings are directly comparable.

### Per-file results

| File | Aegis findings / exit | Atheon findings / exit |
|------|----------------------|------------------------|
| `aws_key.env` | 1 / exit 1 | 1 / exit 1 |
| `aws_key_aegis_ignore.env` | 0 / exit 0 | 2 / exit 1 |
| `aws_key_aegis_ignore_wrongname.env` | 1 / exit 1 | 2 / exit 1 |
| `aws_key_atheon_ignore.env` | 1 / exit 1 | 0 / exit 0 |
| `password.env` | 0 / exit 0 | 0 / exit 0 |

(`clean.txt` present in fixture; counted in the 6-file scan totals.)

## Suppression / exit-code differences

1. **Aegis suppression honored only by Aegis.** `aws_key_aegis_ignore.env` (`# aegis:ignore:aws-access-key`) suppresses the finding in Aegis (0 findings, exit 0) but Atheon still reports 2 findings and exits 1. Suppressions are tool-specific, not shared.
2. **Wrong-name suppression is not honored by Aegis.** `aws_key_aegis_ignore_wrongname.env` (`# aegis:ignore:secrets-aws-access-key`) does NOT suppress in Aegis (1 finding, exit 1) — Aegis requires the exact rule name `aws-access-key`.
3. **Atheon suppression honored only by Atheon.** `aws_key_atheon_ignore.env` (`# atheon:ignore`) suppresses in Atheon (0 findings, exit 0) but Aegis still reports 1 finding, exit 1.
4. Exit codes agree on plain findings (`aws_key.env`: both 1; `password.env`: both 0) but diverge wherever either tool's suppression syntax appears.

## MCP parity

**Untested.** No MCP-server parity comparison was run in this session. No MCP parity claims are made.

## Synthetic-fixture disclosure

All fixtures in `docs/progress/fixtures/aegis-atheon-parity-20260919` are **synthetic**, created manually for this comparison (including the canonical `AKIAIOSFODNN7EXAMPLE` AWS example key and a dummy password). They were not drawn from real source code. Suppression-comment fixtures were constructed specifically to probe each tool's ignore syntax.

## Limitations

- Results are from manual single-machine runs recorded in `/nas/Temp/work/aegis-agent-logs/parity-manual/`; not produced by an automated CI parity suite.
- Rule catalogs differ beyond `aws-access-key` (Atheon reported `container-no-tag` and `print-debug-leftover`; Aegis did not), so whole-directory counts (3 vs 6) are not apples-to-apples.
- Severity/field metadata differs between the two JSON outputs (e.g., severity `critical` vs `high` for the same finding); not normalized here.
- Suppression semantics were probed with only two Aegis-syntax and one Atheon-syntax variants; other variants untested.
- MCP parity untested (see above).

## Recommendation: NOT PROMOTED

Do **not** promote this as a verified shared-parity pass. Suppression syntaxes and exit codes diverge on suppression-bearing fixtures, rule catalogs differ, and MCP parity is untested. The only verified agreement is detection of plain `aws-access-key` findings and clean exits on non-matching files.
