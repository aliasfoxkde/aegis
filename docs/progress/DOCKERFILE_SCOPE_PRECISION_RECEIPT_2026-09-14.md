# Dockerfile scope precision receipt

**Date:** 2026-09-14  
**Branch:** `codex/aegis-precision-20260914`

## Change

The `secrets-in-dockerfile` detector is restricted to `Dockerfile` and
`Dockerfile.*` basenames. Its directive and whitespace expressions are
line-oriented, so indentation matching cannot consume newline characters.
The liveness harness supplies a Dockerfile filename for this rule.

## Validation

- `cargo test -p aegis-core --test pattern_liveness -- --test-threads=1`: 4
  passed.
- `cargo test -p aegis-core -p aegis-patterns --all-targets --
  --test-threads=2`: core and pattern tests passed before the aggregate run
  output was truncated; the aggregate command itself is not the accepted gate.
- `cargo clippy -p aegis-core --all-targets -- -D warnings`: passed.
- `target/release/aegis scan --severity-threshold high` against the exact
  GitForge candidate `bdb39826`: 103 findings, exit 1.
- The pre-fix scan reported 1,865 findings; the corrected scan no longer
  reports the Dockerfile rule against Rust source.

## Remaining limitation

The full Aegis workspace run timed out at 300 seconds and the serialized CLI
package run timed out at 180 seconds. These are recorded as validation-lane
failures; they do not justify a baseline or broad ignore. Split the expensive
targets into separately bounded CI lanes before promotion.
