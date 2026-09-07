# Getting Started with Aegis

## Quick Installation

### Binary Releases (Recommended)

Grab the asset for your platform from the [latest release](https://github.com/aliasfoxkde/aegis/releases/latest):

```bash
# Linux x86_64
curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-linux-x86_64.tar.gz
tar -xzf aegis-linux-x86_64.tar.gz
sudo mv aegis /usr/local/bin/

# macOS Apple Silicon
curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-darwin-arm64.tar.gz
tar -xzf aegis-darwin-arm64.tar.gz
sudo mv aegis /usr/local/bin/

# macOS Intel
curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-darwin-x86_64.tar.gz
tar -xzf aegis-darwin-x86_64.tar.gz
sudo mv aegis /usr/local/bin/

# Linux arm64
curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-linux-arm64.tar.gz
tar -xzf aegis-linux-arm64.tar.gz
sudo mv aegis /usr/local/bin/

# Windows: download aegis-windows-x86_64.tar.gz and extract it

# Verify (each tarball also carries aegis-mcp, aegis-daemon, aegis-bundler)
aegis --version
```

### From Source

Requires Rust 1.75+ (`rustup update stable` if needed):

```bash
git clone https://github.com/aliasfoxkde/aegis
cd aegis
cargo build --release
# Binaries land in target/release/
```

See [Building from Source](https://github.com/aliasfoxkde/aegis/blob/main/docs/guides/BUILDING.md) for details.

## Your First Scan

```bash
# Scan current directory
aegis scan .

# Scan a specific file
aegis scan --file ./config/app.yaml

# Scan with a severity filter
aegis scan . --severity-threshold high

# JSON output for tooling
aegis --format json scan .
```

The `-c/--config` flag takes a preset (`production`, `pipeline`,
`development`, `mcp-integration`) or a profile JSON file, and supplies
defaults for flags you did not set explicitly:

```bash
aegis -c production scan .
```

## Understanding the Output

```
Aegis Security Scan
==================
Risk Assessment:
  Level: critical
  Score: 65
  Findings: 1
  Highest Severity: critical

[CRITICAL] aws-access-key at config/app.yaml:47:9
  AWS Access Key ID detected

Scan Statistics:
  Files scanned: 23
  ...
```

Findings never include the matched source text — reports reference the
location, not the secret. Use `--format json` for the machine-readable
document (`findings` + `stats`), or `--format sarif` for code-scanning
platforms.

## Common Use Cases

### Pre-commit Hook

Scan exactly what would be committed (the git index), even if the
working tree has since changed:

```bash
echo '#!/bin/sh
aegis scan . --staged' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### CI Gate Over New Findings Only

```bash
# Record a baseline once (exit code reflects new findings afterwards)
aegis --format json scan . --output-file baseline.json

# Every later scan: exit 0 when nothing new was introduced
aegis scan . --baseline baseline.json
```

### GitHub Actions

The repository ships its own scanning workflow at
[.github/workflows/aegis-scan.yml](https://github.com/aliasfoxkde/aegis/blob/main/.github/workflows/aegis-scan.yml);
copy it into your project. See
[CI/CD Integration](https://github.com/aliasfoxkde/aegis/blob/main/docs/guides/CICD_INTEGRATION.md)
for GitLab, Jenkins, and Azure examples.

### MCP Server Setup

```bash
# Start the MCP server on stdio
aegis-mcp

# Configure an MCP client (e.g. Claude Desktop). Add to
# claude_desktop_config.json:
{
  "mcpServers": {
    "aegis": {
      "command": "aegis-mcp"
    }
  }
}
```

The server exposes `scan_string`, `scan_file`, `scan_dir`, `scan_env`,
`list_patterns`, `list_categories`, and `update_bundle` over JSON-RPC.

## Configuration Presets

Four presets ship with the CLI and are kept in lockstep with the profile
files in
[config/profiles/](https://github.com/aliasfoxkde/aegis/tree/main/config/profiles):

- **production** - high-security gate (SARIF output, strict categories)
- **pipeline** - CI/CD optimized
- **development** - full feature set for local work
- **mcp-integration** - MCP server settings

```bash
aegis -c pipeline scan .
```

## Pattern Management

```bash
# List all patterns
aegis list

# List by category
aegis list --category secrets

# Browse the full generated catalog with per-pattern details
# (GitHub) https://github.com/aliasfoxkde/aegis/blob/main/docs/patterns/README.md
```

## Ignoring Files and Findings

Create `.aegisignore` in your project root to skip **files** (gitignore
syntax):

```
# Ignore vendored code
vendor/

# Ignore build output
dist/
build/

# Ignore test fixtures
**/*_test.go
**/*.test.ts
```

To suppress a **finding** on a specific line, add an inline directive on
that same line:

```js
const token = "sample"; // aegis:ignore:generic-secret -- test fixture
```

Between `--` and the end of the line is an optional reason. Ranges
(`aegis:ignore-start` / `aegis:ignore-end`) and whole files
(`aegis:ignore-file`) are also supported.

## Troubleshooting

- **"command not found" after installation** — verify `PATH` includes
  the install directory: `echo $PATH | grep /usr/local/bin`.
- **Pattern not behaving as expected** — check its detail page in the
  [catalog](https://github.com/aliasfoxkde/aegis/blob/main/docs/patterns/README.md);
  every page documents the regex, scoping, and a verified example.
- More in [Troubleshooting](Troubleshooting).

## Next Steps

- Explore [Configuration](https://github.com/aliasfoxkde/aegis/blob/main/docs/guides/CONFIGURATION.md)
- Learn about [Pattern Development](Pattern-Development)
- Set up [CI/CD Integration](https://github.com/aliasfoxkde/aegis/blob/main/docs/guides/CICD_INTEGRATION.md)
- Configure [MCP Integration](https://github.com/aliasfoxkde/aegis/blob/main/docs/guides/MCP.md)
