# Aegis Wiki

Welcome to the Aegis wiki! This wiki contains project documentation that syncs with the repository.

## About This Project

**Aegis** is a high-performance security scanning tool for DevOps, CI/CD pipelines, and AI systems. Built in Rust for maximum speed and reliability.

**Key Features:**
- **633 patterns** across 33 categories (browse the [pattern catalog](https://github.com/aliasfoxkde/aegis/blob/main/docs/patterns/README.md))
- Multi-format output: JSON, SARIF, plain text
- MCP server for AI assistant integration
- CI/CD integration (GitHub Actions, GitLab, Jenkins, Azure)
- Risk scoring and intelligent prioritization
- Custom patterns via `.aegis.yml` in the scan root, or YAML bundled with `aegis-bundler`

## Downloads

**[Latest release](https://github.com/aliasfoxkde/aegis/releases/latest)** — every release ships these assets:

| Platform | Asset |
|----------|-------|
| Linux x86_64 | [aegis-linux-x86_64.tar.gz](https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-linux-x86_64.tar.gz) |
| Linux arm64 | [aegis-linux-arm64.tar.gz](https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-linux-arm64.tar.gz) |
| macOS Apple Silicon | [aegis-darwin-arm64.tar.gz](https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-darwin-arm64.tar.gz) |
| macOS Intel | [aegis-darwin-x86_64.tar.gz](https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-darwin-x86_64.tar.gz) |
| Windows x86_64 | [aegis-windows-x86_64.tar.gz](https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-windows-x86_64.tar.gz) |
| WebAssembly | [aegis_wasm.wasm](https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis_wasm.wasm) |

Each tarball contains the `aegis` CLI plus the `aegis-mcp`, `aegis-daemon`, and `aegis-bundler` binaries; `checksums.txt` covers every artifact.

## Quick Links

See the **Sidebar** for navigation, or browse:

- [Getting Started](Getting-Started) - Installation and first steps
- [Pattern Development](Pattern-Development) - Writing custom patterns
- [Troubleshooting](Troubleshooting) - Common issues and solutions

## Related Documentation

GitHub wikis cannot link into the repository with relative paths, so repository links below are absolute.

| Document | Location |
|----------|----------|
| README | [README.md](https://github.com/aliasfoxkde/aegis/blob/main/README.md) |
| User Guides | [docs/guides/](https://github.com/aliasfoxkde/aegis/blob/main/docs/guides/) |
| Architecture | [docs/architecture/OVERVIEW.md](https://github.com/aliasfoxkde/aegis/blob/main/docs/architecture/OVERVIEW.md) |
| Pattern Catalog | [docs/patterns/README.md](https://github.com/aliasfoxkde/aegis/blob/main/docs/patterns/README.md) |
| Building from Source | [docs/guides/BUILDING.md](https://github.com/aliasfoxkde/aegis/blob/main/docs/guides/BUILDING.md) |
| Changelog | [CHANGELOG.md](https://github.com/aliasfoxkde/aegis/blob/main/CHANGELOG.md) |

## Statistics

Counts are generated from the shipped pattern corpus; the catalog is canonical.

- **633** detection patterns
- **33** pattern categories (69 critical, 131 high, 175 medium, 258 low)
- **7** workspace crates: aegis-core, aegis-cli, aegis-mcp, aegis-daemon, aegis-bundler, aegis-patterns, aegis-wasm
- **4** configuration presets: production, pipeline, development, mcp-integration
- **100%** Rust implementation
