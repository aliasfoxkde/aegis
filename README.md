# Aegis

**Aegis** is a high-performance security scanning tool for DevOps, CI/CD pipelines, and AI systems. It detects secrets, credentials, security vulnerabilities, AI-generated code patterns, and more.

[![Build Status](https://github.com/aliasfoxkde/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/aliasfoxkde/aegis/actions)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

## Features

- **[660 Detection Patterns](docs/patterns/README.md)** across 34 categories
- **High Performance** - Built in Rust with category-based regex pre-filtering (12x faster than comparable tools)
- **CI/CD Integration** - GitHub Actions, GitLab CI, Jenkins, Azure DevOps
- **MCP Server** - Model Context Protocol server for AI tool integration
- **Risk Scoring** - Intelligent risk assessment and prioritization
- **Multiple Output Formats** - Human-readable, JSON, and SARIF
- **YAML Patterns** - Easy contribution via YAML pattern files

## Quick Install

**Binary releases (no dependencies):**

Each archive bundles `aegis`, `aegis-mcp`, `aegis-daemon`, and
`aegis-bundler`.

```bash
# Linux x86_64
curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-linux-x86_64.tar.gz
tar -xzf aegis-linux-x86_64.tar.gz
sudo mv aegis /usr/local/bin/

# Linux ARM64
curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-linux-arm64.tar.gz
tar -xzf aegis-linux-arm64.tar.gz
sudo mv aegis /usr/local/bin/

# macOS Intel
curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-darwin-x86_64.tar.gz
tar -xzf aegis-darwin-x86_64.tar.gz
sudo mv aegis /usr/local/bin/

# macOS Apple Silicon
curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-darwin-arm64.tar.gz
tar -xzf aegis-darwin-arm64.tar.gz
sudo mv aegis /usr/local/bin/

# Windows
curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-windows-x86_64.tar.gz
tar -xzf aegis-windows-x86_64.tar.gz
```

**Verify:**

```bash
aegis --version
```

For full installation instructions, see [Installation Guide](docs/guides/INSTALLATION.md).

## Quick Start

```bash
# Scan a directory
aegis scan .

# Scan with JSON output (--format is a global flag, so it precedes the
# subcommand)
aegis --format json scan .

# Scan environment variables
aegis scan --env

# List all patterns
aegis list

# Update pattern bundle
aegis update
```

More examples in the [Quick Start Guide](docs/guides/QUICK_START.md).

## Pattern Categories

Aegis includes **660 patterns** across **34 categories** (counts generated
from source; see the full catalog for every rule):

| Category | Patterns | Description |
|----------|----------|-------------|
| [infrastructure](docs/patterns/README.md#infrastructure) | 55 | Terraform, IaC security |
| [secrets](docs/patterns/README.md#secrets) | 41 | API keys, tokens, credentials |
| [pii](docs/patterns/README.md#pii) | 39 | Personal data detection |
| [cloud-native](docs/patterns/README.md#cloud-native) | 38 | Kubernetes, Docker |
| [web-security](docs/patterns/README.md#web-security) | 37 | XSS, SQLi, CORS, SSRF |
| [supply-chain](docs/patterns/README.md#supply-chain) | 35 | Dependency vulnerabilities |
| [ai-detection](docs/patterns/README.md#ai-detection) | 33 | AI-slop and hallucination-artifact markers |
| [compliance](docs/patterns/README.md#compliance) | 33 | GDPR, HIPAA, PCI-DSS |
| [security-hardening](docs/patterns/README.md#security-hardening) | 31 | Security best practices |
| [frameworks](docs/patterns/README.md#frameworks) | 31 | React, Angular, Next.js |
| [accessibility](docs/patterns/README.md#accessibility) | 28 | WCAG success criteria |
| [git-hygiene](docs/patterns/README.md#git-hygiene) | 28 | Repo hygiene and artifacts |
| [ai-safety](docs/patterns/README.md#ai-safety) | 25 | Prompt injection, AI safety |
| [llm-guardrails](docs/patterns/README.md#llm-guardrails) | 25 | LLM input/output guardrails |
| [performance](docs/patterns/README.md#performance) | 20 | Performance anti-patterns |
| [shift-left](docs/patterns/README.md#shift-left) | 20 | Early-lifecycle security practices |
| [code-quality](docs/patterns/README.md#code-quality) | 15 | Language anti-patterns |
| [devops](docs/patterns/README.md#devops) | 15 | CI/CD pipeline checks |
| [finance](docs/patterns/README.md#finance) | 13 | Financial identifiers and money-correctness |
| [typescript](docs/patterns/README.md#typescript) | 13 | Typed-JavaScript rules |
| [kubernetes](docs/patterns/README.md#kubernetes) | 11 | Kubernetes manifest hardening |
| [web-development](docs/patterns/README.md#web-development) | 11 | General web development |
| [cryptography](docs/patterns/README.md#cryptography) | 10 | Cryptographic primitive misuse |
| [api-integration](docs/patterns/README.md#api-integration) | 9 | HTTP client, webhook mistakes |
| [terraform](docs/patterns/README.md#terraform) | 7 | HashiCorp Terraform |
| [healthcare](docs/patterns/README.md#healthcare) | 7 | Clinical data rules |
| [data-visualization](docs/patterns/README.md#data-visualization) | 5 | Charting pitfalls |
| [pwa](docs/patterns/README.md#pwa) | 5 | Progressive web app checks |
| [container](docs/patterns/README.md#container) | 4 | Container hardening |
| [graphql](docs/patterns/README.md#graphql) | 4 | GraphQL security |
| [metadata](docs/patterns/README.md#metadata) | 4 | Metadata and editor leaks |
| [git-ops](docs/patterns/README.md#git-ops) | 3 | GitOps workflows |
| [cloudformation](docs/patterns/README.md#cloudformation) | 3 | CloudFormation templates |
| [arm](docs/patterns/README.md#arm) | 2 | Azure Resource Manager |

Browse all [660 detection patterns](docs/patterns/README.md).

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

## CI/CD Integration

### GitHub Actions

```yaml
- name: Install Aegis
  run: |
    curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-linux-x86_64.tar.gz
    tar -xzf aegis-linux-x86_64.tar.gz
    sudo mv aegis /usr/local/bin/

- name: Security Scan
  run: aegis --format sarif scan . --severity-threshold high
```

### GitLab CI

```yaml
security_scan:
  script:
    - aegis --format json scan . --severity-threshold medium
  artifacts:
    reports:
      sast: aegis-results.json
```

### GitHub Actions (Manual)

```yaml
- name: Install Aegis
  run: |
    curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-linux-x86_64.tar.gz
    tar -xzf aegis-linux-x86_64.tar.gz
    sudo mv aegis /usr/local/bin/

- name: Run Aegis
  run: aegis --format sarif scan . --output-file results.sarif
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
- `update_bundle` - Check for pattern bundle updates

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
│   └── aegis-patterns/    # 660 pattern definitions
├── config/profiles/       # Configuration profiles
└── docs/                  # Documentation
```

## Contributing Patterns

Patterns are defined as YAML files for easy contribution. A pattern file
holds a **list** of rules:

```yaml
# community/secrets/my-api-key.yaml
- name: my-api-key
  category: secrets
  match: '(?i)myapi[_-]?key\s*[:=]\s*["''][A-Za-z0-9]{16,}'
  enabled: true
  severity: high
  confidence: high
  minEntropy: 3.5
  description: 'Detects MyAPI key patterns'
  tags:
    - secrets
    - api-key
```

Build it into a distributable bundle with `aegis-bundler`:

```bash
cargo run -p aegis-bundler -- community/secrets my.bundle
```

See [Adding Patterns](docs/guides/ADDING_PATTERNS.md) for contribution guidelines.

## License

Apache-2.0
