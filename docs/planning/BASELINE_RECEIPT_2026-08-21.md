# Aegis Baseline Receipt

Date: 2026-08-21
Repository: `/nas/Temp/worker-aegis-baseline`
Commit: `b880a0d` (`feat(aegis): record scan lifecycle transitions`)
Evidence owner: parent validation (the delegated Hermes attempt did not
produce an artifact and is not credited for these results)

## Results

| Check | Result | Evidence |
|---|---|---|
| `cargo test --workspace` | PASS | 535 tests/doc-tests passed; 0 failed |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS | Exit 0; only Cargo profile warning |
| `cargo build --workspace --release` | PASS | Exit 0; Cargo reports duplicate `aegis` output-name warnings |
| CLI clean stdin scan | PASS | JSON result had zero findings; exit 0 |
| CLI finding stdin scan | PASS | AWS example key classified critical/high; exit 1 |
| MCP integration | PASS | 7/7 `tests/mcp_integration.rs` tests passed within workspace run |
| Control Center adapter integration | PASS | 36/36 tests passed within workspace run |

## Reproduction commands

```text
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --release
printf 'const key = "AKIAIOSFODNN7EXAMPLE";\n' | target/release/aegis --format json scan --stdin
printf 'package main\nfunc main() {}\n' | target/release/aegis --format json scan --stdin
```

The finding scan returned exit code 1 and reported pattern `aws-access-key`,
category `pii`, severity `critical`, confidence `high`. The clean scan returned
exit code 0 with `finding_count: 0`. Sensitive test material was a public AWS
documentation example key and no real credential was used.

## Caveats and next gates

- Release and debug builds emit Cargo warnings about duplicate `aegis` binary
  output names between the root package and `aegis-cli`; this is a packaging
  debt and should be resolved before publication.
- This receipt proves repository-local scanner and MCP behavior only. It does
  not prove a live Control Center-to-GitForge pipeline, deployment, crates.io
  publication, or production promotion.
- Aegis remains the candidate pre-pipeline gate; promotion still requires the
  external adapter matrix and one clean completed GitForge pipeline.
