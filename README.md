# Aegis

**Aegis** is a high-performance security scanning tool for DevOps, CI/CD pipelines, and AI systems. It detects secrets, credentials, security vulnerabilities, AI-generated code patterns, and more.

[![Build Status](https://github.com/aliasfoxkde/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/aliasfoxkde/aegis/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)

## Features

- **[621 Detection Patterns](docs/patterns/README.md)** across 32 categories
- **High Performance** - Built in Rust with category-based regex pre-filtering (12x faster than comparable tools)
- **CI/CD Integration** - GitHub Actions, GitLab CI, Jenkins, Azure DevOps
- **MCP Server** - Model Context Protocol server for AI tool integration
- **Risk Scoring** - Intelligent risk assessment and prioritization
- **Multiple Output Formats** - Human-readable, JSON, and SARIF
- **YAML Patterns** - Easy contribution via YAML pattern files

## Quick Install

**Binary releases (no dependencies):**

```bash
# Linux x86_64
curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-x86_64-unknown-linux-gnu.tar.gz
tar -xzf aegis-x86_64-unknown-linux-gnu.tar.gz
sudo mv aegis /usr/local/bin/

# macOS Intel
curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-x86_64-apple-darwin.tar.gz
tar -xzf aegis-x86_64-apple-darwin.tar.gz
sudo mv aegis /usr/local/bin/

# macOS Apple Silicon
curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-aarch64-apple-darwin.tar.gz
tar -xzf aegis-aarch64-apple-darwin.tar.gz
sudo mv aegis /usr/local/bin/

# Windows
curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-x86_64-pc-windows-gnu.tar.gz
tar -xzf aegis-x86_64-pc-windows-gnu.tar.gz
```

**Verify:**

```bash
aegis --version
```

**Install script (Linux/macOS):**

```bash
curl -sSL https://get.aegis.dev | sh
```

For full installation instructions, see [Installation Guide](docs/guides/INSTALLATION.md).

## Quick Start

```bash
# Scan a directory
aegis scan .

# Scan with JSON output
aegis scan . --format json

# Scan environment variables
aegis scan --env

# List all patterns
aegis list

# Update pattern bundle
aegis update
```

More examples in the [Quick Start Guide](docs/guides/QUICK_START.md).

## Pattern Categories

Aegis includes **621 patterns** across **32 categories**:

| Category | Patterns | Description |
|----------|----------|-------------|
| [secrets](docs/patterns/README.md#secrets--credentials-40-patterns) | 40 | API keys, tokens, credentials |
| [pii](docs/patterns/README.md#secrets--credentials-40-patterns) | 39 | Personal data detection |
| [security-hardening](docs/patterns/README.md#security-hardening-33-patterns) | 33 | Security best practices |
| [web-security](docs/patterns/README.md#web-security-37-patterns) | 37 | XSS, SQLi, CORS, SSRF |
| [infrastructure](docs/patterns/README.md#infrastructure-as-code-55-patterns) | 55 | Terraform, IaC security |
| [cloud-native](docs/patterns/README.md#cloud-native-38-patterns) | 38 | Kubernetes, Docker |
| [ai-safety](docs/patterns/README.md#ai-safety--llm-50-patterns) | 50 | Prompt injection, AI safety |
| [compliance](docs/patterns/README.md#compliance-33-patterns) | 33 | GDPR, HIPAA, PCI-DSS |
| [supply-chain](docs/patterns/README.md#supply-chain-35-patterns) | 35 | Dependency vulnerabilities |
| [frameworks](docs/patterns/README.md#frameworks-31-patterns) | 31 | React, Angular, Next.js |

Browse all [621 detection patterns](docs/patterns/README.md).

## Documentation

- [Installation](docs/guides/INSTALLATION.md) - Binary releases, Docker, package managers
- [Quick Start](docs/guides/QUICK_START.md) - Basic usage and common workflows
- [CLI Reference](docs/guides/CLI.md) - All available commands
- [Configuration](docs/guides/CONFIGURATION.md) - Profiles and options
- [CI/CD Integration](docs/guides/CICD_INTEGRATION.md) - GitHub, GitLab, Jenkins, Azure
- [MCP Server](docs/guides/MCP.md) - AI tool integration

## Development

- [Building from Source](docs/guides/BUILDING.md) - Contributor setup
- [Adding Patterns](docs/guides/ADDING_PATTERNS.md) - Contribute new patterns
- [Architecture Overview](docs/architecture/OVERVIEW.md) - System design
- [Coding Standards](docs/CODING_STANDARDS.md) - Rust conventions
- [Go Source Bug Review](docs/GO_SOURCE_BUG_REVIEW.md) - Original project issues

## CI/CD Integration

### GitHub Actions

```yaml
- name: Security Scan
  uses: aliasfoxkde/aegis-action@v1
  with:
    severity-threshold: high
    format: sarif
```

### GitLab CI

```yaml
security_scan:
  script:
    - aegis scan . --format json --severity-threshold medium
  artifacts:
    reports:
      sast: aegis-results.json
```

### GitHub Actions (Manual)

```yaml
- name: Run Aegis
  run: |
    curl -sSL https://get.aegis.dev | sh
    aegis scan . --format sarif --output results.sarif
```

See the [CI/CD Integration Guide](docs/guides/CICD_INTEGRATION.md) for more examples.

## MCP Server

Start the MCP server for AI tool integration:

```bash
aegis-mcp
```

Available tools:
- `scan_string` - Scan in-memory content
- `scan_file` - Scan a single file
- `scan_dir` - Scan a directory
- `scan_env` - Scan environment variables
- `list_patterns` - List all patterns
- `list_categories` - List all categories

See the [MCP Guide](docs/guides/MCP.md) for details.

## Architecture

```
aegis/
├── crates/
│   ├── aegis-core/       # Core scanning engine
│   ├── aegis-cli/        # CLI application
│   ├── aegis-mcp/        # MCP server
│   ├── aegis-daemon/     # Daemon mode
│   ├── aegis-bundler/    # Pattern bundler
│   └── aegis-patterns/    # 621 pattern definitions
├── config/profiles/       # Configuration profiles
└── docs/                  # Documentation
```

## Contributing Patterns

Patterns are defined as YAML files for easy contribution:

```yaml
# community/secrets/my-api-key.yaml
name: my-api-key
match: '(?i)myapi[_-]?key\s*[:=]\s*["\'][A-Za-z0-9]{16,}'
severity: high
confidence: high
minEntropy: 3.5
description: 'Detects MyAPI key patterns'
tags:
  - secrets
  - api-key
```

See [Adding Patterns](docs/guides/ADDING_PATTERNS.md) for contribution guidelines.

## License

MIT OR Apache-2.0
