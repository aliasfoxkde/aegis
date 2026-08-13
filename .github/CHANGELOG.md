# Changelog

All notable changes to this project will be documented in this file.

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
