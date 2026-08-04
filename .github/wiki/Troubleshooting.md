# Troubleshooting Guide

## Installation Issues

### "command not found" after installation

```bash
# Verify installation
which aegis
aegis --version

# Check PATH
echo $PATH | grep -E '(usr|local|bin)'

# Reinstall if needed
curl -sSL https://get.aegis.dev | sh
```

### Build failures

```bash
# Ensure Rust 1.70+ is installed
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

**Check pattern status:**

```bash
# List all patterns
aegis list

# Search for specific pattern
aegis list --search aws

# List by category
aegis list --category secrets
```

**Verify pattern is enabled:**

Patterns may be disabled by default. Enable with profile or individual pattern settings.

**Try with lower threshold:**

```bash
# Include all findings
aegis scan . --severity-threshold low
```

### Slow scanning on large projects

**Use severity filtering:**

```bash
# Scan only high+ severity
aegis scan . --severity-threshold high

# Use pipeline profile (optimized for speed)
aegis scan . --profile pipeline
```

**Increase workers:**

```bash
# Use more workers for parallel processing
aegis scan . --workers 8
```

**Memory issues:**

```bash
# Check available memory
free -h  # Linux
vm_stat   # macOS
```

### False positives

**Add ignore rules:**

```bash
# Create .aegisignore
cat > .aegisignore << EOF
# Ignore test files
test/
**/*_test.go
*.test.ts

# Ignore generated files
*.generated.*
.env.example

# Specific pattern suppression
ignore: aws-access-key
EOF
```

**Inline ignore:**

```bash
# Add ignore directive to line
DEBUG_KEY=fake_key_for_testing  # aegis:ignore
```

## Pattern Issues

### Pattern not matching

**Test regex pattern:**

```bash
# List pattern details
aegis list --search <pattern-name> --json | jq '.'

# Verify pattern exists
aegis list --category <category>
```

**Check pattern syntax:**

```bash
# View pattern details in JSON
aegis list --json | jq '.[] | select(.name == "pattern-name")'
```

### Pattern not loading

```bash
# Update pattern bundle
aegis update

# Check for errors
aegis update --verbose
```

## CI/CD Issues

### GitHub Actions not working

**Verify workflow syntax:**

```yaml
# Correct format
- name: Security Scan
  uses: aliasfoxkde/aegis-action@v1
  with:
    severity-threshold: high
    format: sarif
```

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

### Exit code issues

```bash
# Check exit codes:
# 0 = success, 1 = findings, 2 = error, 3 = invalid args

# Debug with verbose
aegis scan . --verbose

# Fail on findings (for CI)
aegis scan . --severity-threshold medium || exit 1
```

## MCP Integration Issues

### MCP server not starting

**Build verification:**

```bash
# Verify binary exists
ls -la $(which aegis-mcp)

# Test directly
aegis-mcp --help
```

**Port conflicts:**

```bash
# Use custom port
aegis-mcp --port 8765

# Update AI assistant config
{
  "mcpServers": {
    "aegis": {
      "command": "aegis-mcp",
      "args": ["--port", "8765"]
    }
  }
}
```

### AI assistant not using Aegis

**Configuration check:**

```json
// In claude_desktop_config.json
{
  "mcpServers": {
    "aegis": {
      "command": "/absolute/path/to/aegis-mcp"
    }
  }
}
```

**Restart AI assistant:**

After configuration changes, restart the AI assistant completely.

## Performance Issues

### High CPU usage

```bash
# Use category filtering
aegis scan . --category secrets,pii

# Use severity filter
aegis scan . --severity-threshold high
```

### High memory usage

```bash
# Reduce workers
aegis scan . --workers 2

# Use streaming (automatic for large files)
```

## Configuration Issues

### Profile not loading

```bash
# List available profiles
ls config/profiles/

# Use explicit path
aegis scan . --profile ./config/profiles/production.json
```

### Settings not persisting

```bash
# Check config locations (first found wins)
cat ./.aegis.toml
cat ~/.aegis/config.toml
cat /etc/aegis/config.toml

# Use command line flags for testing
aegis scan . --profile production --severity-threshold high
```

## Getting Help

### Documentation
- [Getting Started](Getting-Started)
- [Configuration](../docs/guides/CONFIGURATION.md)
- [CLI Reference](../docs/guides/CLI.md)

### Community Support
- [GitHub Issues](https://github.com/aliasfoxkde/aegis/issues)
- [GitHub Discussions](https://github.com/aliasfoxkde/aegis/discussions)

### Debug Mode

```bash
# Enable verbose output
RUST_LOG=debug aegis scan .

# Run with backtrace
RUST_BACKTRACE=1 aegis scan .
```

## Common Error Messages

### "bundle load failed"

```bash
# Delete local bundle
rm -rf ~/.aegis/

# Update patterns
aegis update
```

### "pattern validation failed"

- Check YAML syntax
- Verify regex is valid
- Ensure required fields present

### "permission denied"

```bash
# Fix permissions
chmod +x aegis
chmod +x aegis-mcp
```
