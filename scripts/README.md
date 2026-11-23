# scripts/

Support tooling for CI, coverage, and releases. Each entry is runnable
standalone; release scripts are driven by `.gitforce.yml`.

## Index

| Script | Purpose |
| --- | --- |
| `ci/classify_aegis_sarif.py` | Classify an Aegis scan report as `SAFE`, `FINDINGS`, or `BLOCKED` from its embedded inspection ledger plus the scan exit code; fails closed on missing/malformed reports, partial coverage, or unknown exit codes. Stdlib only. Tested by `scripts/test_classify_aegis_sarif.py`. |
| `check-advisory-parity.sh` | Fail unless `cargo-audit` and `cargo-deny` waive the same advisories. |
| `check-allow-expiry.sh` | Fail when a lint suppression has no dated, owned decision, or its expiry has passed or is near. |
| `check-fuzz-lock.sh` | Fail unless `fuzz/Cargo.lock` pins the same `aegis-core` version as the workspace. |
| `check-gate-parity.py` | Fail when a change weakens a configured quality gate — a lint relaxed, a waiver added, a coverage floor dropped, or a gate that stopped running (a CI step, a workflow file, `deny.toml`, or `codecov.yml` removed). Stdlib only. Tested by `scripts/test_check_gate_parity.py`. |
| `check-license-parity.sh` | Fail unless `deny.toml` and `about.toml` carry identical license allow lists. |
| `coverage-floor.sh` | Enforce the workspace line-coverage floor from an lcov report (Codecov cannot, for lack of a token). |
| `generate_examples.py` | Regenerate `crates/aegis-patterns/src/examples.rs` from a `dump_patterns` output. |
| `patch-coverage-floor.py` | Enforce a floor on the lines a change adds, from the same lcov report the workspace floor uses: the lines the diff adds are intersected with the report's hit counts and the job fails below the floor. Stdlib only. Tested by `scripts/test_patch_coverage_floor.py`. |
| `release/build.sh` | Build the full release asset matrix from a plain `vX.Y.Z` tag. |
| `release/pipeline.sh` | Entry point for the GitForge release pipeline (runs in the `aegis-builder` container). |
| `release/publish.sh` | Mirror release assets built by `build.sh` to the GitHub release. |
| `release/generate-notices.sh` | Regenerate `THIRD-PARTY-NOTICES.md` from `Cargo.lock`. |
| `release/Dockerfile` | Image for the release pipeline container. |
| `test_check_gate_parity.py` | Deterministic stdlib unittest for `check-gate-parity.py`. |
| `test_classify_aegis_sarif.py` | Deterministic stdlib unittest for `ci/classify_aegis_sarif.py` (`python3 scripts/test_classify_aegis_sarif.py`). |
| `test_patch_coverage_floor.py` | Deterministic stdlib unittest for `patch-coverage-floor.py` (`python3 scripts/test_patch_coverage_floor.py`). |
| `test_release_remap.py` | Deterministic stdlib unittest for the release scripts' path remapping (`python3 scripts/test_release_remap.py`). |
