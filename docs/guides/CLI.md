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

### aegis adapter scan

Run the Control Center pre-pipeline adapter over a single work request.
This is the fail-closed surface for Control Center and GitForge; every
input error, scanner failure, or reused work-request ID is reported as
`blocked` so callers never accidentally promote a partial scan.

```bash
aegis adapter scan [options]
```

**Required flags:**

| Flag | Description |
|------|-------------|
| `--work-request-id` | Stable identifier for the work request (must be non-empty) |
| `--source` | Source identifier (file path, PR number, etc.) |

**Content (exactly one required):**

| Flag | Description |
|------|-------------|
| `--content` | Inline content to scan |
| `--content-file` | Path to a file whose contents will be scanned |

**Optional flags:**

| Flag | Description |
|------|-------------|
| `--evidence-output` | Persist redacted evidence records to this JSON path |

**JSON response fields (`stdout`):**

| Field | Description |
|-------|-------------|
| `work_request_id` | Echoes the input ID |
| `scan_result` | `pass`, `fail`, or `blocked` |
| `allows_work` | True for `pass`/`fail`, false for `blocked` |
| `evidence_ref` | SHA-256 hash of the scanned content |
| `finding_count` | Number of findings detected |
| `highest_severity` | Highest severity among findings (omitted when none) |
| `lifecycle_state` | Final lifecycle state of the work request |
| `transition_count` | Number of lifecycle transitions recorded |
| `evidence_path` | Path to persisted evidence (only when `--evidence-output` is set) |
| `error` | Human-readable failure detail (only present on `blocked`) |

**Exit codes:**

| Code | Meaning |
|------|---------|
| 0 | `pass` — no findings, work may proceed |
| 1 | `fail` — findings present, work may proceed |
| 2 | `blocked` — adapter failed closed; do **not** proceed |
| 3 | Invalid arguments |

**Examples:**

```bash
# Inline content
aegis adapter scan \
  --work-request-id wr-123 \
  --source src/lib.rs \
  --content "fn main() { println!(\"hi\"); }"

# Read content from a file and persist evidence
aegis adapter scan \
  --work-request-id wr-124 \
  --source src/lib.rs \
  --content-file src/lib.rs \
  --evidence-output /tmp/aegis-evidence.json
```

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
