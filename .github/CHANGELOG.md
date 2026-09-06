# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - 2026-09-06

### Features

- **ADDED**: custom user detection patterns via `.aegis.yml` /
  `.aegis.yaml` at the scan root — fail-loud validation (unknown fields,
  invalid regex, unknown severity, duplicate names all abort the scan
  with the file and pattern named), `remediation` guidance threaded
  through to findings and JSON output (#78);
- **ADDED**: `aegis scan . --staged` pre-commit mode that scans the git
  index instead of the working tree, with binary-blob skipping and a
  clean pass when nothing is staged (#79);
- **ADDED**: suppression upgrades — per-directive reasons, span/range
  suppression, and file-level directives; baseline fingerprint filtering
  is now a real engine option with fail-loud baseline loading (#74, #75,
  #76);
- **ADDED**: quality infrastructure — codecov thresholds pinned to
  measured coverage (94.5% lines), criterion benchmarks for the
  pattern-matching hot path (`cargo bench -p aegis-core`), four
  cargo-fuzz targets (suppression directives, ignore globs, baseline
  JSON, user pattern configs) with a weekly fuzz workflow, and a
  labelled corpus precision/recall harness gated at 0.95 (#80, #81).

### Fixes

- **FIXED**: `secrets-aws-access-key` was unreachable — its 4.5 entropy
  floor exceeds the log2(20) ceiling for any 20-character match; lowered
  to 3.5;
- **FIXED**: `flask-debug-enabled` now catches `app.run(host=...,
  debug=True)`, not just `debug` as the first argument;
- **FIXED**: `indian-aadhaar` no longer matches 12-digit sequences with
  leading 0/1 (UIDAI numbers start with 2-9), unflagging AWS ARN account
  ids;
- **FIXED**: MCP integration tests no longer flake on a fixed 30-second
  deadline while the ~633-pattern registry compiles synchronously;
  request and bundle-update deadlines are now separate constants (#77).

## [0.2.7] - 2026-09-05

### Features

- **ADDED**: working `.aegisignore` support with gitignore-compatible
  semantics — `!` re-inclusion, basename matching for unanchored rules,
  `./`-prefixed walker paths, directory rules that cover contents, and
  last-match-wins precedence across `.gitignore` and `.aegisignore`;
- **ADDED**: independent respect flags `gitignore_respect` and
  `aegisignore_respect` in `Config` and every preset, with legacy
  `gitignore_atheon_respect` still accepted as an alias;
- **ADDED**: registry hygiene suite — fail-loud category and pattern-shape
  validation plus a generated pattern catalog kept fresh by test
  (`cargo run -p aegis-patterns --example generate_docs`);
- **ADDED**: rebuilt `api-integration` pack and kebab-case category
  normalization across all 33 categories (633 patterns);
- **ADDED**: suppression parser hardening — directives embedded in string
  literals tokenize cleanly, and mid-line `# aegis:ignore` directives now
  work in YAML, shell, and Python.

### Fixes

- **FIXED**: removed five semantically broken patterns (`csrf-missing`,
  `vector-initial-capacity`, `multiple-redirects`, `comment-block-repeat`,
  `ai-magic-number`) and re-anchored eight context-starved matchers,
  cutting self-scan noise by 71%;
- **FIXED**: CI-parity scan (`secrets,security-hardening,web-security` at
  high+ severity) now reports zero findings on this repository;
- **FIXED**: Rust AST analysis no longer double-emits panic signals already
  owned by their regex patterns;
- **FIXED**: receipt statistics stay aligned with findings, and stale
  receipt files fail closed (#68, #69);
- **FIXED**: MCP tracing stays off the stdout JSON-RPC transport, and the
  documented positional `scan_file`/`scan_dir` parameters are accepted
  (#70);
- **FIXED**: release publication is idempotent (#61).

## [0.2.6] - 2026-09-01

### Fixes

- **FIXED**: release automation waits for GitHub to confirm deletion of an
  immutable placeholder before creating the mutable draft release.

## [0.2.5] - 2026-09-01

### Fixes

- **FIXED**: release automation now uploads artifacts to a mutable draft
  release and publishes only after every artifact is attached.
- **FIXED**: tag-triggered release runs normalize any published placeholder
  into a draft before asset upload, avoiding GitHub immutable-release errors.

## [0.2.4] - 2026-09-01

### Fixes

- **FIXED**: SQLite output now binds source coordinates using SQLite-compatible
  signed integers with explicit overflow handling.
- **FIXED**: WASM builds no longer compile the optional Tokio-backed async
  Control Center adapter when `aegis-core` default features are disabled.

## [0.2.3] - 2026-09-01

### Fixes

- **FIXED**: synchronized workspace package versions in `Cargo.lock`, restoring
  reproducible `cargo build --locked` resolution;
- **FIXED**: kept `aegis-mcp` startup diagnostics on stderr so stdout remains a
  clean JSON-RPC transport;
- **ADDED**: regression coverage proving MCP stdout contains only JSON-RPC
  responses.

## [0.2.2] - 2026-08-28

### Features

- **ADDED**: Control Center pre-pipeline adapter for Aegis-core with 17 integration tests
- **ADDED**: Async offload for Control Center scans — scan lifecycle transitions are now recorded
- **ADDED**: Config refactor — `config.rs` split into `config/mod.rs` and `config/preset.rs` with preset configurations
- **ADDED**: New `output` module — `output/database.rs`, `output/file.rs`, `output/webhook.rs` with `output/mod.rs` coordinator
- **ADDED**: `receipt.rs` — structured scan receipt generation
- **ADDED**: `remediation.rs` — remediation guidance for findings
- **ADDED**: `sbom.rs` — Software Bill of Materials generation
- **ADDED**: `internal/mod.rs` — internal shared utilities
- **ADDED**: `aegis-bundler` output improvements and contract matrix tests
- **ADDED**: Docker support — `docker/Dockerfile`, `docker/docker-compose.yml`, `docker/README.md`
- **ADDED**: Kubernetes manifests — `kubernetes/configmap.yaml`, `kubernetes/deployment.yaml`, `kubernetes/service.yaml`, `kubernetes/README.md`
- **ADDED**: Platform integration contract (`PLATFORM_INTEGRATION.md`)

### Security

- **ADDED**: `aegis-scan.yml` GitHub workflow for validated security scanning and receipt gates
- **ADDED**: Security scanning gates in release workflow

### Error Handling

- **FIXED**: WASM native scan runtime isolation (`fix(wasm)`)
- **FIXED**: Parallel scan test fixtures properly isolated (`test(cli)`)

### MCP Server

- **ADDED**: Modern lifecycle and tool call support (`feat(mcp): add modern lifecycle and tool calls`)
- **ADDED**: Custom protocol boundary documentation
- **ADDED**: `aegis-mcp` tools and main.rs improvements
- **FIXED**: Diagnostics output routed to stderr, not stdout
- **FIXED**: `Initialized` notification now registered synchronously

### CI/CD

- **ADDED**: `aegis-scan.yml` — security scan gate in CI
- **IMPROVED**: `ci.yml` — enhanced release workflow with receipt validation
- **IMPROVED**: Control Center adapter integration tests (458-line test expansion)

### Dependencies

- **UPDATED**: `Cargo.lock` — workspace dependency refresh

### Documentation

- **UPDATED**: `docs/planning/HANDOFF.md` — refreshed Aegis handoff provenance
- **UPDATED**: `docs/MODULES.md` — new project modules documentation

## [0.1.3] - 2026-08-05

### Security
- **FIXED**: Path traversal vulnerability in MCP sandbox (canonicalization bypass)
- **ADDED**: SECURITY.md policy file

### Error Handling
- **FIXED**: Replaced `std::sync::RwLock` with `parking_lot::RwLock` in IgnoreManager (poisoning issues)
- **FIXED**: `uuid_v4()` now handles pre-UNIX_EPOCH system times gracefully
- **FIXED**: Clone detection sort now handles `partial_cmp` edge cases

### Code Quality
- **REMOVED**: 9 ignored/flaky tests that couldn't pass reliably
- **CLEANED**: All `unwrap()` calls that could panic in production
- **IMPROVED**: Bundle update in MCP server now properly validates and loads bundles

### CI/CD
- **ADDED**: Security audit step (`cargo audit`) to CI pipeline
- **ENABLED**: Coverage reporting to Codecov

### Dependencies
- Updated workspace to Rust 1.75+

## [0.1.2] - 2026-08-04

### Features
- Bundle update implementation in MCP server
- Removal of ghost crate directories (atheon-*, aetheon-*)

## [0.1.1] - 2026-08-04

### Features
- MCP server implementation with JSON-RPC over stdio
- Daemon mode with Unix socket support
- Suppression system (`// aegis:ignore` comments)
- IgnoreManager for .gitignore and .aegisignore files

### Security
- Path traversal protection in MCP sandbox
- Proper canonicalization of file paths

## [0.1.0] - 2026-08-03

Initial release with core scanning capabilities.

### Features
- 590+ detection patterns
- Pattern categories: secrets, PII, security-hardening, web-security, ai-safety
- Multiple output formats: human, JSON, SARIF
- CLI tool with scan, list, enable, disable commands
