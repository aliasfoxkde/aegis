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
aegis --format json scan .

# SARIF for CI/CD integration
aegis --format sarif scan . --output-file results.sarif
```

`--format` is a top-level flag, so it goes before the subcommand. Scan-level
options such as `--severity-threshold` and `--output-file` come after the
path.

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

# List only disabled patterns
aegis list --disabled

# Update pattern bundle
aegis update
```

## Configuration

`-c/--config` is a top-level flag that names a preset profile:

```bash
aegis --config production scan .
```

Available presets: `production`, `pipeline`, `development`,
`mcp-integration`. A profile supplies defaults for anything you did not
set on the command line (categories, output format, severity
threshold); explicit flags win. JSON copies of the preset documents
also ship in `config/profiles/`.
See [Configuration](CONFIGURATION.md) for the field reference.

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
- name: Install Aegis
  run: |
    curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-linux-x86_64.tar.gz
    tar -xzf aegis-linux-x86_64.tar.gz
    sudo mv aegis /usr/local/bin/

- name: Run Aegis Scan
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

## Next Steps

- [CLI Reference](CLI.md) - Full command documentation
- [CI/CD Integration](CICD_INTEGRATION.md) - Detailed integration guides
- [Detection Patterns](../patterns/README.md) - Browse all 660 patterns
