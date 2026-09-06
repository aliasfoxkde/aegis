# Quick Start

## Basic Usage

### Scan a Directory

```bash
aegis scan .
```

### Scan with Severity Filter

```bash
# Only show high and critical findings
aegis scan . --severity-threshold high

# Show medium and above
aegis scan . --severity-threshold medium
```

### Output Formats

```bash
# Human-readable output (default)
aegis scan .

# JSON output for automation
aegis scan . --format json

# SARIF for CI/CD integration
aegis scan . --format sarif --output results.sarif
```

## Environment Scanning

```bash
# Scan environment variables for secrets
aegis scan --env

# Scan specific env var
AEGIS_SECRET=mykey aegis scan --env
```

## Pattern Management

```bash
# List all available patterns
aegis list

# List patterns in a category
aegis list --category secrets

# Search patterns
aegis list --search "aws"

# Update pattern bundle
aegis update
```

## Configuration

```bash
# Use a specific profile
aegis scan . --profile production

# Available profiles:
#   - production: High-security production environments
#   - pipeline: CI/CD pipelines
#   - development: Local development
#   - mcp-integration: MCP server mode
```

## Ignoring Files

Create `.aegisignore` in your project root (gitignore-style globs):

```
# Ignore node_modules
node_modules/

# Ignore build output
dist/
build/

# Ignore test files (optional)
**/*_test.go
**/*.test.ts

# Re-include a path excluded above or by .gitignore
!src/generated/keep.ts
```

A `!` prefix re-includes a path; later rules override earlier ones.
`.aegisignore` is evaluated after `.gitignore`, so it always wins. See
[Configuration](CONFIGURATION.md#ignoring-files) for full semantics.

## CI/CD Examples

### GitHub Actions

```yaml
- name: Run Aegis Scan
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

## Next Steps

- [CLI Reference](CLI.md) - Full command documentation
- [CI/CD Integration](CICD_INTEGRATION.md) - Detailed integration guides
- [Detection Patterns](../patterns/README.md) - Browse all 638 patterns
