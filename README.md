# Aegis

**Aegis** is a high-performance security scanning tool for DevOps, CI/CD pipelines, and AI systems. It detects secrets, credentials, security vulnerabilities, AI-generated code patterns, and more.

## Features

- **500+ Detection Patterns** - Comprehensive coverage across secrets, security, code quality, DevOps, and AI safety
- **High Performance** - Built in Rust for maximum speed and reliability
- **CI/CD Integration** - GitHub Actions, GitLab CI, Jenkins, Azure DevOps support
- **MCP Server** - Model Context Protocol server for AI tool integration
- **Risk Scoring** - Intelligent risk assessment and prioritization
- **Multiple Output Formats** - Human-readable, JSON, and SARIF

## Installation

```bash
# From source
cargo build --release

# Or install via script
curl -sSL https://get.aegis.dev | sh
```

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

## Configuration Profiles

Aegis uses configuration profiles for different use cases:

- **production** - High-security production environments
- **pipeline** - CI/CD pipelines
- **development** - Local development
- **mcp-integration** - MCP server mode

## Pattern Categories

| Category | Count | Description |
|----------|-------|-------------|
| secrets | 75 | API keys, tokens, credentials |
| code-quality | 60 | Debug artifacts, complexity |
| devops | 35 | CI/CD patterns |
| ai-detection | 30 | AI-generated code markers |
| security-hardening | 30 | Insecure configurations |
| accessibility | 25 | WCAG compliance |
| web-security | 20 | XSS, SQLi, CORS |
| pii | 20 | Personal data |
| cloud-native | 20 | Kubernetes, Docker |
| performance | 18 | Blocking calls |
| supply-chain | 15 | Dependency vulnerabilities |
| infrastructure | 15 | IaC, Terraform |
| compliance | 12 | GDPR, HIPAA, PCI |
| ai-safety | 10 | Prompt injection |
| llm-guardrails | 15 | LLM safety |
| shift-left | 12 | Early detection |

## CI/CD Integration

### GitHub Actions

```yaml
- name: Security Scan
  uses: aegis/scan-action@v1
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

## MCP Server

Start the MCP server:

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

## Risk Scoring

Aegis calculates risk scores based on:
- Pattern severity (critical=40, high=25, medium=10, low=3)
- Confidence multiplier (high=1.0, medium=0.7, low=0.4)
- Category weights
- Finding density

Risk levels: None, Low, Medium, High, Critical

## Architecture

```
aegis/
├── crates/
│   ├── aegis-core/      # Core scanning engine
│   ├── aegis-cli/       # CLI application
│   ├── aegis-mcp/       # MCP server
│   ├── aegis-daemon/    # Daemon mode
│   ├── aegis-bundler/   # Pattern bundler
│   └── aegis-patterns/  # Pattern definitions
├── config/profiles/     # Configuration profiles
└── docs/                # Documentation
```

## Documentation

- [Architecture](docs/architecture/OVERVIEW.md)
- [Pattern Specification](docs/PATTERNS.md)
- [Coding Standards](docs/CODING_STANDARDS.md)
- [CI/CD Integration](docs/guides/CICD_INTEGRATION.md)
- [Plan](docs/PLAN.md)

## License

MIT OR Apache-2.0
