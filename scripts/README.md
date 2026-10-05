# scripts/

Support tooling for CI, coverage, and releases. Each entry is runnable
standalone; release scripts are driven by `.gitforce.yml`.

## Index

| Script | Purpose |
| --- | --- |
| `ci/classify_aegis_sarif.py` | Classify an Aegis scan report as `SAFE`, `FINDINGS`, or `BLOCKED` from its embedded inspection ledger plus the scan exit code; fails closed on missing/malformed reports, partial coverage, or unknown exit codes. Stdlib only. Tested by `scripts/test_classify_aegis_sarif.py`. |
| `check-fuzz-lock.sh` | Fail unless `fuzz/Cargo.lock` pins the same `aegis-core` version as the workspace. |
| `check-license-parity.sh` | Fail unless `deny.toml` and `about.toml` carry identical license allow lists. |
| `coverage-floor.sh` | Enforce the workspace line-coverage floor from an lcov report (Codecov cannot, for lack of a token). |
| `generate_examples.py` | Regenerate `crates/aegis-patterns/src/examples.rs` from a `dump_patterns` output. |
| `release/build.sh` | Build the full release asset matrix from a plain `vX.Y.Z` tag. |
| `release/pipeline.sh` | Entry point for the GitForge release pipeline (runs in the `aegis-builder` container). |
| `release/publish.sh` | Mirror release assets built by `build.sh` to the GitHub release. |
| `release/generate-notices.sh` | Regenerate `THIRD-PARTY-NOTICES.md` from `Cargo.lock`. |
| `release/Dockerfile` | Image for the release pipeline container. |
| `test_classify_aegis_sarif.py` | Deterministic stdlib unittest for `ci/classify_aegis_sarif.py` (`python3 -m unittest scripts/test_classify_aegis_sarif.py`). |
