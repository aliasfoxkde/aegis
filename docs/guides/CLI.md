# CLI Reference

## Commands

### aegis scan

Scan directories, files, or environment variables for security issues.

```bash
aegis scan [path] [options]
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--format` | Output format: `text`, `json`, `sarif` | `text` |
| `--severity-threshold` | Minimum severity: `critical`, `high`, `medium`, `low` | `low` |
| `--profile` | Configuration profile | `development` |
| `--output`, `-o` | Output file path | stdout |
| `--env` | Scan environment variables | `false` |
| `--workers` | Number of worker threads | auto |
| `--ignore` | Paths to ignore | `.aegisignore` |

**Examples:**

```bash
# Scan current directory
aegis scan .

# Scan with JSON output
aegis scan . --format json

# Scan with severity filter
aegis scan . --severity-threshold high

# Scan and save to file
aegis scan . -o results.sarif --format sarif

# Scan environment variables
aegis scan --env
```

### aegis list

List available detection patterns.

```bash
aegis list [options]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--category` | Filter by category |
| `--search` | Search pattern names/descriptions |
| `--json` | Output as JSON |

**Examples:**

```bash
# List all patterns
aegis list

# List secrets patterns
aegis list --category secrets

# Search for AWS patterns
aegis list --search aws

# JSON output
aegis list --json
```

### aegis update

Update the pattern bundle to the latest version.

```bash
aegis update [options]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--url` | Custom bundle URL |
| `--force` | Force update even if current |

### aegis config

Manage configuration.

```bash
aegis config [subcommand]
```

**Subcommands:**

- `aegis config show` - Display current configuration
- `aegis config set <key> <value>` - Set a config value
- `aegis config profile <name>` - Switch profile

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Scan completed, no issues found |
| 1 | Scan completed, issues found |
| 2 | Scan failed (error) |
| 3 | Invalid arguments |

## Configuration File

`~/.aegis/config.toml`:

```toml
[defaults]
profile = "development"
format = "text"
severity_threshold = "low"
workers = 4

[profiles.production]
severity_threshold = "medium"
workers = 8

[profiles.pipeline]
severity_threshold = "high"
format = "sarif"
```
