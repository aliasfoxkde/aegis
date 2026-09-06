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
| `path` | Path to scan | `.` |
| `-f, --file` | Treat the path as a single file | `false` |
| `-e, --env` | Scan environment variables | `false` |
| `--stdin` | Read content to scan from stdin | `false` |
| `--follow-symlinks` | Follow symbolic links | `false` |
| `--categories` | Comma-separated category list to include | all |
| `--severity-threshold` | Minimum severity: `critical`, `high`, `medium`, `low` | all |
| `--output-file` | Write results to a file instead of stdout | stdout |
| `--baseline` | Filter out findings recorded in this baseline — JSON output from a previous `--format json` scan; the exit code then reflects new findings only | none |
| `--diff` | Scan only the changed lines of a unified diff file | none |
| `--staged` | Scan the staged (index) content of the git repository instead of files on disk; `<path>` selects the repository | `false` |
| `--all` | Include disabled patterns | `false` |

**Global flags** (usable before the subcommand): `-f, --format`
(`human`, `json`, `sarif`), `--config` (configuration profile),
`--quiet`, `--verbose`.

**Examples:**

```bash
# Scan current directory
aegis scan .

# Scan with JSON output
aegis -f json scan .

# Scan with severity filter
aegis scan . --severity-threshold high

# Scan and save to file
aegis -f sarif scan . --output-file results.sarif

# Scan environment variables
aegis scan --env

# CI gate over new findings only: record a baseline once, then
# compare every subsequent scan against it
aegis -f json scan . --output-file baseline.json
aegis scan . --baseline baseline.json

# Pre-commit: scan exactly what would be committed (the git index),
# even if the working tree has since changed
aegis scan . --staged
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

## Custom Patterns

A scan root may contain a `.aegis.yml` (or `.aegis.yaml`) file with a
`patterns:` list. Directory scans (`aegis scan <dir>`, MCP `scan_dir`,
daemon scans) merge these rules with the bundled patterns; every field
is validated up front and an invalid file aborts the scan with a
descriptive error rather than silently skipping a rule.

```yaml
patterns:
  - name: internal-token
    category: secrets          # optional, default: custom
    severity: high             # required: critical | high | medium | low
    match: 'INTT_[A-Za-z0-9]{24,}'
    exclude: 'INTT_EXAMPLE'    # optional: suppress matching spans
    description: Internal service token committed to source
    remediation: Load the token from an environment variable
    reference: https://internal.example.com/token-policy  # optional
    confidence: medium         # optional: high | medium | low (default medium)
    min_entropy: 3.5           # optional: 0.0–8.0 Shannon entropy gate
    file_extensions: [rs, py, ts]  # optional: bare extensions, empty = all
```

| Field | Required | Notes |
|-------|----------|-------|
| `name` | yes | Unique; the rule id shown in findings, suppressions, and baselines |
| `severity` | yes | `critical`, `high`, `medium`, or `low` |
| `match` | yes | Regex (Rust `regex` crate syntax) |
| `description` | yes | Shown with every finding |
| `category` | no | Defaults to `custom`; unknown categories use a neutral risk weight |
| `exclude` | no | Suppress a candidate span when this regex also matches |
| `confidence` | no | Defaults to `medium` |
| `remediation` | no | Fix guidance surfaced with the finding |
| `reference` | no | URL shown with the finding |
| `min_entropy` | no | Skip matches below this Shannon entropy |
| `file_extensions` | no | Bare extensions (`rs`), no leading dot |

Names must be unique across the file and must not collide with bundled
pattern names. Suppressions (`aegis:ignore:<name>`) and baselines work
for custom patterns exactly as for bundled ones.

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
