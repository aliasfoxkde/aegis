# Changelog

All notable changes to Aegis are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Binary assets for
every release are attached to the matching GitHub release.

## [0.6.1] - 2026-09-10

### Changed

- Releases are built by the GitForge pipeline (`.gitforce.yml`) and synced
  to the GitHub release by `scripts/release/publish.sh`; the GitHub
  `Release` workflow remains as a manual-dispatch fallback running the same
  scripts. Every release now ships `attestation.json`
  (`aegis.release-attestation/v1`) recording the tag, commit, builder
  platform, toolchains, and the SHA-256 of every other asset, and the WASM
  asset is published as `aegis-wasm.wasm` — previously the crate-mangled
  `aegis_wasm.wasm` — to match the `aegis-<target>` naming of the platform
  archives. Release titles are the bare tag. darwin binaries are
  cross-linked with zig on the build host rather than built on Apple
  hardware; the attestation states this instead of hiding it.

### Fixed

- The `secrets-in-dockerfile` rule is anchored to line-oriented Dockerfile
  directives — `^\s*(ARG|ENV)\s+…` under multiline matching, where it
  previously matched `ARG`/`ENV` and a secret-ish word anywhere in a file —
  so Rust, Markdown, and test prose containing words like `ENV` or `TOKEN`
  are no longer reported as Dockerfile secrets.
- The `ci-bypass` rule now requires explicit bypass syntax (`--no-verify`,
  `continue-on-error: true`, or a direct verb–target pairing such as
  `skip tests`) and fires only in CI, configuration, and shell file types,
  instead of flagging any line of prose where a bypass-like word appears
  near a CI-like one.

## [0.6.0] - 2026-09-08

### Added

- Ten PHI-handling rules in `healthcare`, which previously only held
  identifier-format detectors: three more provider identifiers (NPI,
  DEA registration, Medicare MBI/HICN) plus seven HIPAA
  technical-safeguard hazards — PHI in log or print output, hard-coded
  patient-identifier literals, patient resources referenced over
  plaintext HTTP, PHI routed through email, `SELECT *` over PHI tables
  (the minimum-necessary standard), patient identifiers in URL query
  strings, and encryption explicitly disabled next to patient data.
  660 → 670 patterns.

### Changed

- Statistical anomaly z-scores are now computed per language group —
  the eligible files sharing an extension — instead of across the whole
  repository. Comment conventions differ too much between languages for
  a mixed baseline to mean anything: a narrated Python file judged
  against terse Rust siblings was a false outlier waiting to happen. A
  group smaller than eight files supports no z-score, so files in
  minority languages are not judged rather than judged against someone
  else's norm; the Pareto comment-concentration detector remains
  repository-total by definition.
- The statistical anomaly layer is configurable:
  `ScanOptions::anomaly_detectors` in the core API, `--no-anomalies` and
  `--anomaly-detectors <list>` on the CLI (unknown names fail loudly
  with the valid list), and an `anomaly_detectors` field in
  `-c/--config` profile JSON. `null`/unset runs all four detectors, an
  empty allow-list disables the layer entirely, and a non-empty list
  runs exactly the named detectors. A disabled layer also skips metric
  collection during the walk.

### Fixed

- Release pipeline `checksums.txt` is now a usable verification file: it
  lists every published archive (platform tarballs, WASM, source) in
  standard `sha256sum -c` format, computed from the final assembled
  assets. Previously each platform job hashed its unpacked binaries, the
  Windows job stripped filenames from its lines, and artifact merging
  let the Windows file silently overwrite all the others — so v0.5.0
  shipped four bare Windows binary hashes that matched nothing
  downloadable (release assets are immutable once published, so that
  file cannot be corrected in place; it is superseded from the next
  release on).

## [0.5.0] - 2026-09-08

### Added

- Statistical anomaly layer in the engine: directory scans now collect
  per-file metrics (line counts, comment share under a line-prefix
  heuristic, identifier diversity) and emit `Severity::Info` findings in
  the new `statistical-anomaly` category for files far outside their own
  repository's baseline — `comment-ratio-outlier` (z > 2.5), Pareto-style
  `comment-concentration` (one file holding ≥ 60% of repo commentary),
  `identifier-diversity-outlier` (heavy token reuse below 0.2 diversity),
  and `file-size-outlier` (z > 2.5). Each detector reports only its most
  extreme file; prose, dotfiles, lockfiles, and minified bundles are
  excluded. Grounded in the detection-brittleness literature, the
  observations are triage signals, not verdicts.
- `Severity::Info` across the engine: weight 0 in risk scoring, `info`
  accepted by `Severity::parse` and custom `.aegis.yml` patterns, an INFO
  label in text output, SARIF `note` level, and exclusion from the exit
  code — informational findings are reported in every format but can
  never fail a CI run. They also respect category, severity-threshold,
  and baseline filters like every other finding.
- Seven money-correctness rules in `finance`, which previously only held
  PII/credential detectors: money in binary floating-point fields,
  `toFixed` currency rounding, `Math.round` on money, exact-equality
  money comparisons, `parseFloat` money parsing, unsynchronized
  read-modify-write balance updates, and wall-clock settlement/expiry
  timestamps. Counting-shaped identifiers (`total_findings == 0`) are
  excluded from the equality rule. 653 → 660 patterns.
- New `cryptography` category with ten primitive-misuse rules: MD5/SHA-1
  password hashing, weak HMACs, ECB mode, legacy ciphers (DES/3DES/RC4/
  Blowfish), sub-15000-iteration PBKDF2, RSA without OAEP, key material
  derived from non-cryptographic PRNGs (including Go `:=` assignments),
  all-zero IVs/nonces, hard-coded salts, and timing-unsafe MAC
  comparisons. 644 → 653 patterns.
- Removed the byte-identical duplicate of `jwt-none-algorithm` that also
  shipped as `security-hardening-jwt-none-algorithm` (same regex,
  severity, and confidence in two categories); the web-security rule
  remains.
- Five hallucination-artifact markers in `ai-detection`: retired OpenAI
  `/v1/engines` endpoint, doc-example placeholder credential assignments,
  placeholder environment variable reads, imports of placeholder package
  names, and comment-marked stub implementations — the shapes left behind
  when generated code is pasted in unverified, each a silent-failure risk.
  639 → 644 patterns.
- Six research-grounded AI-writing markers in `ai-detection` (assistant-conversation
  remnants, formulaic verbs, marketing vocabulary, hedging boilerplate, academic
  phrasing, emoji-led Markdown headings), informed by the detector-ablation
  literature; the category page now states explicitly that these are triage
  signals rather than verdicts, since formulaic human writing triggers them and
  paraphrasing defeats them. 633 → 639 patterns.
- `scripts/generate_examples.py` now emits the lint attributes on the generated
  `example_for` lookup, so regenerating liveness examples no longer produces a
  file that fails `clippy -D warnings`.
- Hierarchical pattern catalog under `docs/patterns/`: a high-level index
  (scoring, scoping, severity distribution) linking one generated page per
  category with every pattern's regex, metadata, and liveness-verified
  example. Regenerated by `cargo run -p aegis-patterns --example
  generate_docs`; a freshness test fails CI when the pages drift. Long
  credential-shaped runs in rendered examples are elided so the catalog can
  live in the repository without tripping secret scanners; the exact inputs
  stay compiled in `crates/aegis-patterns/src/examples.rs`.

### Changed

- Documentation count refresh: the README category table now lists all 34
  categories with per-category counts (the previous 15-row table predates
  `ai-detection`, `cryptography`, and the finance expansion), and the wiki
  mirror, `docs/README.md`, `docs/PLAN.md`, and the quick-start guide carry
  the 660/34 totals with the current severity distribution.
- Wiki and documentation audit: replaced stale references (invented install
  paths, flags, config formats, release asset names) with the real CLI/MCP
  surface, corrected pattern counts, and rewrote the six wiki pages to match
  v0.4.0 behavior.

## [0.4.0] - 2026-09-07

### Added

- `-c/--config` is wired on every scan invocation: a built-in preset
  (`production`, `pipeline`, `development`, `mcp-integration`) or a path to a
  JSON profile file supplies defaults for flags the operator did not set
  (output format, categories, severity threshold); explicit flags always win.
  Unknown names fail with the list of valid presets, and the built-in presets
  are tested field-by-field against the shipped `config/profiles/*.json` so
  they cannot drift.
- Rule-liveness harness: 633 provably-firing example matches, one per bundled
  pattern, so a pattern that cannot match anything fails CI.
- Custom user patterns via `.aegis.yml` in the scan root, merged into the
  registry before the walk.

### Fixed

- **Baseline rescans stay green**: `scan` no longer scans the baseline file
  itself. A baseline records findings verbatim, so a rescan that included it
  re-flagged every documented secret and kept the exit code red even when no
  new findings existed. The baseline path is now excluded from the walk, and
  the exit-code contract is verified end-to-end (0 = no new findings,
  1 = new findings only).
- **`stats` agrees with `findings`**: stdin (`--stdin`), env (`--env`), and
  diff (`--diff`) scans folded findings into ad-hoc counters, so
  `--format json` could emit `finding_count: 0` next to a non-empty
  `findings` array. All scan paths now aggregate through
  `ScanStats::add_finding`; reports and receipts agree with the finding list.
- **WASM scanner works**: `scan_content` previously scanned nothing; the WASM
  build now bundles the full pattern set.
- **Vendor-prefixed secret rules are file-active** again after the noise
  audit.
- **Noise audit round two**: repaired noisy patterns and deduplicated AST
  rules, cutting the project's self-scan from 941 to 817 findings and the
  CI-parity self-scan (secrets, security-hardening, web-security at high+) to
  0 findings.
- Suppression fixtures in the MCP and daemon suites now name the rules that
  actually fire and sit on the finding's own line, so inline suppression is
  genuinely exercised.

### Changed

- Lazy per-extension pattern compilation: patterns are grouped and compiled
  once per file extension, so a TypeScript rule never runs against a Rust
  file and unreachable regexes are never compiled.
- Workspace-wide strict lint enforcement (`clippy` all + pedantic,
  `rust_2018_idioms`, `unused_qualifications`, `missing_docs`) with
  `-D warnings` in CI; fail-closed scanner initialization.
- Test coverage swept to 98% line coverage across the workspace, with a
  coverage gate in CI.
- Documentation accuracy audit: every user-facing claim re-verified against
  the built binaries; public API fully documented (`missing_docs` enforced).

## [0.3.0] - 2026-09-06

### Added

- `--staged` pre-commit mode: scan the git index instead of the working tree.
- `--baseline` filtering: record a scan with `--format json`, then rescan with
  `--baseline` so the exit code reflects new findings only.
- Inline suppression directives with reasons (`aegis:ignore:<patterns> --
  why`), suppression ranges (`ignore-start`/`ignore-end`), file-level
  ignores, and expanded AST coverage.
- Coverage gate, Criterion benchmarks, fuzz targets, and a corpus harness.

## [0.2.7] - 2026-09-06

### Fixed

- Release pipeline fixes; supersedes the poisoned v0.2.6 draft release.

[Unreleased]: https://github.com/aliasfoxkde/aegis/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/aliasfoxkde/aegis/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/aliasfoxkde/aegis/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/aliasfoxkde/aegis/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/aliasfoxkde/aegis/compare/v0.2.7...v0.3.0
[0.2.7]: https://github.com/aliasfoxkde/aegis/compare/v0.2.6-final...v0.2.7
