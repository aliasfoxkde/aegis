# Troubleshooting Guide

## Installation Issues

### "command not found" after installation

```bash
# Verify installation
which aegis
aegis --version

# Check PATH
echo $PATH | grep -E '(usr|local|bin)'

# Reinstall from the latest release assets
# https://github.com/aliasfoxkde/aegis/releases/latest
```

### Build failures

```bash
# Ensure Rust 1.75+ (the MSRV) is installed
rustc --version

# Update Rust
rustup update stable

# Clean and rebuild
cargo clean
cargo build --workspace
```

### Binary permission denied

```bash
# Make executable
chmod +x aegis

# Or on Linux
sudo chmod +x /usr/local/bin/aegis
```

## Scanning Issues

### "No findings" but expected results

**Check the rule exists and what it scopes to:**

```bash
# List all patterns
aegis list

# List by category
aegis list --category secrets

# Every pattern's regex, scoping, and a verified example lives in the
# generated catalog:
# https://github.com/aliasfoxkde/aegis/blob/main/docs/patterns/README.md
```

**Mind the scoping rules:**

- Patterns with `file_extensions` set only run on matching files; a file
  without an extension (`Dockerfile`, `README`) never matches a scoped
  pattern.
- `scope: environment` patterns only run during `aegis scan --env`.
- All shipped patterns are enabled by default.

**Try with lower threshold:**

```bash
# Include all findings
aegis scan . --severity-threshold low
```

### Slow scanning on large projects

**Use severity and category filtering:**

```bash
# Scan only high+ severity
aegis scan . --severity-threshold high

# Scan only specific categories
aegis scan . --categories secrets,web-security

# Use the CI-optimized preset
aegis -c pipeline scan .
```

Worker threads scale with the machine automatically. Scanning is
streaming, so file size is bounded by the 10 MB default limit
(configurable per profile).

### False positives

**Skip files with `.aegisignore`** (gitignore syntax, in the scan root):

```text
# Ignore test fixtures
test/
**/*_test.go
*.test.ts

# Ignore generated files
*.generated.*
.env.example
```

**Suppress a finding inline** — the directive must be on the same line
as the finding and name the pattern (a bare `aegis:ignore` suppresses
nothing):

```bash
DEBUG_KEY=fake_key_for_testing  # aegis:ignore:generic-secret -- test fixture
```

Ranges (`aegis:ignore-start` / `aegis:ignore-end`) and whole-file
(`aegis:ignore-file`) directives are also supported. Prefer an upstream
fix: patterns carry an `exclude` regex for safe idioms, so a repeat
false positive is worth a contribution to
[the pattern source](https://github.com/aliasfoxkde/aegis/tree/main/crates/aegis-patterns/src).

## Pattern Issues

### Pattern not matching

1. Open the pattern's page in the
   [generated catalog](https://github.com/aliasfoxkde/aegis/blob/main/docs/patterns/README.md)
   — it documents the exact regex, scoping, entropy floor, and a
   **verified example input** that provably fires.
2. Check `file_extensions`: your file must have a listed extension.
3. Check `exclude`: your match span may be hitting a suppression rule.
4. Check inline directives in the file (`aegis:ignore:` on the same line).

### Pattern pack not loading

```bash
# Validate a YAML pattern list by bundling it
cargo build --release -p aegis-bundler
./target/release/aegis-bundler ./patterns-dir ./test.bundle

# Install a bundle into a running MCP server
# JSON-RPC: {"method": "update_bundle", "params": ["./my-patterns.bundle", true]}

# Refresh the CLI's cached bundle
aegis update
```

## CI/CD Issues

### GitHub Actions not working

There is no external action; copy the repository's own scanning
workflow into your project:
[.github/workflows/aegis-scan.yml](https://github.com/aliasfoxkde/aegis/blob/main/.github/workflows/aegis-scan.yml).
It runs the scan on push/pull_request, uploads SARIF to code scanning,
and fails on secrets, security-hardening, and web-security findings.

**Check artifact upload:**

```yaml
- name: Upload SARIF
  uses: actions/upload-artifact@v4
  with:
    name: aegis-results
    path: results.sarif
```

### Hook not executing

```bash
# Verify hook permissions
ls -la .git/hooks/pre-commit

# Make executable
chmod +x .git/hooks/pre-commit

# Test manually
.git/hooks/pre-commit
```

A better pre-commit hook scans the staged content rather than the
working tree:

```bash
aegis scan . --staged
```

### Exit code issues

```bash
# Exit codes:
# 0 = success (or no NEW findings when --baseline is used)
# 1 = findings reported (also: a scan itself failed)
# 2 = invalid usage

# Debug with verbose
aegis scan . -v
```

With `--baseline`, exit 1 means findings that are not recorded in the
baseline — a clean CI gate over new work.

## MCP Integration Issues

### MCP server not starting

`aegis-mcp` speaks JSON-RPC 2.0 on **stdio** — it has no network port.
Test it by piping a request:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"list_categories"}' | aegis-mcp
```

**Client configuration:**

```json
{
  "mcpServers": {
    "aegis": {
      "command": "/absolute/path/to/aegis-mcp"
    }
  }
}
```

Restart the AI assistant completely after configuration changes.

## Performance Issues

### High CPU usage

```bash
# Use category filtering
aegis scan . --categories secrets,pii

# Use severity filter
aegis scan . --severity-threshold high
```

### High memory usage

Scanning is streaming and per-file size is capped (10 MB by default);
the largest consumers are worker threads, which scale with CPU count.
Narrow the scan with `--categories`/`--severity-threshold` rather than
tuning workers.

## Configuration Issues

### Profile not loading

```bash
# Built-in presets
aegis -c production scan .
aegis -c pipeline scan .
aegis -c development scan .
aegis -c mcp-integration scan .

# Or an explicit profile file
aegis -c ./config/profiles/production.json scan .
```

A profile supplies defaults for flags you did not set explicitly
(output format, categories, severity threshold); explicit flags always
win. An unknown preset fails with the list of valid names.

### Settings not persisting

There is no global config file; configuration is per-invocation via
flags and `-c/--config`. Use command-line flags for one-off overrides.

## Getting Help

### Documentation
- [Getting Started](Getting-Started)
- [Configuration](https://github.com/aliasfoxkde/aegis/blob/main/docs/guides/CONFIGURATION.md)
- [CLI Reference](https://github.com/aliasfoxkde/aegis/blob/main/docs/guides/CLI.md)

### Community Support
- [GitHub Issues](https://github.com/aliasfoxkde/aegis/issues)
- [GitHub Discussions](https://github.com/aliasfoxkde/aegis/discussions)

### Debug Mode

```bash
# Enable verbose output
aegis scan . -v

# Run with backtrace
RUST_BACKTRACE=1 aegis scan .
```

## Common Error Messages

### "bundle load failed"

The cached bundle is corrupt. Remove the cache and refresh:

```bash
# Linux: ~/.local/share/aegis/patterns.bundle
rm ~/.local/share/aegis/patterns.bundle
aegis update
```

### "pattern validation failed"

- Check YAML syntax
- Verify the regex compiles (RE2 syntax: no lookarounds)
- Ensure required fields are present: `name`, `match`, `severity`,
  `confidence`, `description`

### "permission denied"

```bash
# Fix permissions
chmod +x aegis
chmod +x aegis-mcp
```
