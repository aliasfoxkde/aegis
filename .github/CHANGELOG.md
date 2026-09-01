# Changelog

All notable changes to this project will be documented in this file.

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
