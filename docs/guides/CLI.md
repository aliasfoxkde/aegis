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
| `--stdin` | Accepted, but currently scans an empty string rather than reading stdin; pipe content to a file and use `--file` or `--diff` instead | `false` |
| `--follow-symlinks` | Follow symbolic links | `false` |
| `--categories` | Comma-separated category list to include | all |
| `--severity-threshold` | Minimum severity: `critical`, `high`, `medium`, `low` | all |
| `--output-file` | Also write results to this file, rendered in the selected `--format`; stdout output is unaffected | none |
| `--baseline` | Filter out findings recorded in this baseline — JSON output from a previous `--format json` scan; the exit code then reflects new findings only | none |
| `--diff` | Scan only the changed lines of a unified diff file | none |
| `--staged` | Scan the staged (index) content of the git repository instead of files on disk; `<path>` selects the repository | `false` |
| `--all` | Include disabled patterns | `false` |

**Global flags:** `-f, --format <human|json|sarif>` and `-c, --config
<profile>` are top-level options, so they must come **before** the
subcommand (`aegis --format json scan .`). `-q, --quiet` and
`-v, --verbose` are marked global and work anywhere.

`--config` is accepted and resolves a preset name (`production`,
`pipeline`, `development`, `mcp`) or a JSON profile path, but profile
loading is not wired into the scan path yet: the flag has no effect on
the run, and `--format` and the scan-level flags remain authoritative.
See [Configuration](CONFIGURATION.md) for the profile schema.

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
| `--enabled` | List only enabled patterns |
| `--disabled` | List only disabled patterns |

`aegis list` prints the rule id, severity, and description for each
pattern, preceded by a `Total: N patterns` line.

**Examples:**

```bash
# List all patterns
aegis list

# List secrets patterns
aegis list --category secrets

# List only disabled patterns
aegis list --disabled
```

### aegis enable / aegis disable

Report a pattern as enabled or disabled by id.

```bash
aegis enable <pattern-id>
aegis disable <pattern-id>
```

Pattern state is not persisted, so these only print the requested change;
they do not alter what a later scan loads. Use `scan --all` to include
disabled patterns in a scan.

### aegis update

Update the pattern bundle to the latest version.

```bash
aegis update [options]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--force` | Force update even if cached |

### aegis benchmark

Run a benchmark comparison against a path.

```bash
aegis benchmark [path]
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--warmup` | Number of warmup runs | `1` |
| `--runs` | Number of benchmark runs to average | `3` |
| `--compare` | Compare with Atheon-Enhanced if available | off |

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
| 0 | Scan completed, no findings |
| 1 | Scan completed with findings. Also used when a scan itself fails (for example an unreadable scan root or an invalid `.aegis.yml`) |
| 2 | Usage error: unknown subcommand or flag, or an invalid value for a global flag such as `--format` |

With `--baseline`, code 1 means the scan produced findings that are not
in the baseline; findings already recorded there do not affect the exit
code.

## Configuration

There is no global configuration file that Aegis reads automatically.
A run's settings come from CLI flags, plus optional JSON profile
documents selected with the top-level `-c/--config` flag. See
[Configuration](CONFIGURATION.md) for the profile schema and the
presets shipped in `config/profiles/`.
