# Getting Started with Aegis

## Quick Installation

### Binary Releases (Recommended)

```bash
# Linux
curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-linux-x86_64.tar.gz
tar -xzf aegis-linux-x86_64.tar.gz
sudo mv aegis /usr/local/bin/

# macOS
curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-macos.tar.gz
tar -xzf aegis-macos.tar.gz
sudo mv aegis /usr/local/bin/

# Verify
aegis --version
```

### Install Script

```bash
curl -sSL https://get.aegis.dev | sh
```

### Docker

```bash
docker run --rm -v $(pwd):/scan ghcr.io/aliasfoxkde/aegis scan /scan
```

## Your First Scan

```bash
# Scan current directory
aegis scan .

# Scan specific file
aegis scan ./config/app.yaml

# Scan with severity filter
aegis scan . --severity-threshold high
```

## Understanding the Output

```
[CRITICAL] aws-access-key detected
  File: config/app.yaml:47
  Content: AKIAIOSFODNN7EXAMPLE

[HIGH] commented-secret detected
  File: src/auth.rs:23
  Content: # password:supersecret123

2 finding(s) in 23 file(s) - 41.3 KB scanned in 4ms
```

## Common Use Cases

### Pre-commit Hook

```bash
# Create hook
echo '#!/bin/sh
aegis scan .' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### CI/CD Integration

#### GitHub Actions

```yaml
- name: Security Scan
  uses: aliasfoxkde/aegis-action@v1
  with:
    severity-threshold: high
    format: sarif
```

#### GitLab CI

```yaml
security_scan:
  script:
    - aegis scan . --format json --severity-threshold medium
  artifacts:
    reports:
      sast: aegis-results.json
```

### MCP Server Setup

```bash
# Start MCP server
aegis-mcp

# Configure AI assistant (Claude Desktop)
# Add to claude_desktop_config.json:
{
  "mcpServers": {
    "aegis": {
      "command": "aegis-mcp"
    }
  }
}
```

## Configuration Profiles

Aegis comes with pre-configured profiles:

- **production** - High-security production environments
- **pipeline** - CI/CD optimized (default for CI)
- **development** - Full features for local testing
- **mcp-integration** - MCP server settings

```bash
# Use profile
aegis scan ./my-project --profile production
```

## Pattern Management

```bash
# List all patterns
aegis list

# Search patterns
aegis list --search aws

# List by category
aegis list --category secrets

# Update patterns
aegis update
```

## Ignoring Files

Create `.aegisignore` in your project root:

```
# Ignore node_modules
node_modules/

# Ignore build output
dist/
build/

# Ignore test files
**/*_test.go
**/*.test.ts

# Ignore specific findings
ignore: aws-access-key
ignore: commented-secret
```

## Troubleshooting

### "command not found" after installation

```bash
# Verify PATH includes /usr/local/bin
echo $PATH | grep /usr/local/bin

# Or install to ~/.local/bin
export PATH=$PATH:$HOME/.local/bin
```

### Performance issues on large projects

```bash
# Use severity filter
aegis scan . --severity-threshold high

# Use pipeline profile
aegis scan . --profile pipeline

# Increase workers
aegis scan . --workers 8
```

### Pattern not working

- Check if pattern is enabled: `aegis list --search <name>`
- Verify pattern regex with `aegis list --json | jq '.[] | select(.name == "pattern")'`
- Try updating patterns: `aegis update`

## Next Steps

- Explore [Configuration Profiles](../docs/guides/CONFIGURATION.md)
- Learn about [Pattern Development](Pattern-Development)
- Set up [CI/CD Integration](../docs/guides/CICD_INTEGRATION.md)
- Configure [MCP Integration](../docs/guides/MCP.md)
