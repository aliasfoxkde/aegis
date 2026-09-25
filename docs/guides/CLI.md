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
| `--stdin` | Read the payload to scan from stdin; findings carry the source label `stdin` | `false` |
| `--follow-symlinks` | Follow symbolic links | `false` |
| `--categories` | Comma-separated category list to include | all |
| `--severity-threshold` | Minimum severity: `critical`, `high`, `medium`, `low` (`info` observations sit below every threshold and never fail the exit code) | all |
| `--output-file` | Also write results to this file, rendered in the selected `--format`; stdout output is unaffected | none |
| `--baseline` | Filter out findings recorded in this baseline — JSON output from a previous `--format json` scan; the exit code then reflects new findings only. The `.aegis/` state directory is always excluded from scans, so the baseline can live at `.aegis/baseline.json` inside the scanned tree | none |
| `--diff` | Scan only the changed lines of a unified diff file | none |
| `--staged` | Scan the staged (index) content of the git repository instead of files on disk; `<path>` selects the repository | `false` |
| `--all` | Include disabled patterns | `false` |
| `--anomaly-detectors` | Comma-separated allow-list of statistical anomaly detectors: `comment-ratio-outlier`, `comment-concentration`, `identifier-diversity-outlier`, `file-size-outlier`; unknown names fail with the valid list | all |
| `--no-anomalies` | Disable the statistical anomaly layer entirely (conflicts with `--anomaly-detectors`) | `false` |
| `--detect-clones` | Also detect copy-paste code clones (Type 1–3) within each scanned file. Pairs render in a `Code clones` section (human) and under `stats.clones` (JSON) with kind, description, similarity, token count, and line ranges. Pairing stops at 256 pairs per file, so pathological minified or generated files stay bounded. SARIF omits them; they never affect findings or the exit code | `false` |

**Global flags:** `-f, --format <human|json|sarif>` is a top-level
option, so it must come **before** the subcommand
(`aegis --format json scan .`). `-c, --config <profile>`, `-q, --quiet`,
and `-v, --verbose` are marked global in clap and may appear anywhere.

`--config` resolves a built-in preset name (`production`, `pipeline`,
`development`, `mcp-integration`) or a path to a JSON profile file, and
supplies defaults for anything you did not set explicitly: the profile's
`enabled_categories` become the `--categories` allowlist, its
`output_format` becomes the render, its `severity_threshold` the
threshold, and its `anomaly_detectors` the anomaly-detector allowlist.
Flags given on the command line always win over profile
values. See [Configuration](CONFIGURATION.md) for the profile schema.

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
# compare every subsequent scan against it. The `.aegis/` state
# directory is always skipped, so the baseline can live at
# .aegis/baseline.json inside the scanned tree.
aegis -f json scan . --output-file .aegis/baseline.json
aegis scan . --baseline .aegis/baseline.json

# Pre-commit: scan exactly what would be committed (the git index),
# even if the working tree has since changed
aegis scan . --staged

# Also surface copy-paste code clones; reported separately, never
# part of the exit code
aegis scan . --detect-clones
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

Enable or disable a pattern by id. The choice persists to
`<config dir>/aegis/pattern-state.json` and is honored by every later
scan and by `aegis list`.

```bash
aegis enable <pattern-id>
aegis disable <pattern-id>
```

Use `scan --all` to include disabled patterns in a single scan without
changing stored state. Unknown pattern names fail with the valid-name
hint.

### aegis update

Report the state of the compiled-in pattern set. Patterns ship inside
the binary — there is no bundle download, so this never fetches
anything:

```bash
aegis update [options]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--force` | Accepted for compatibility; has no effect |

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
| `severity` | yes | `critical`, `high`, `medium`, or `low` (`info` is a bundled-rule severity only; custom patterns must be actionable) |
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

There is no global configuration *settings* file that Aegis reads
automatically — a run's settings come from CLI flags, plus optional JSON
profile documents selected with the top-level `-c/--config` flag. The
one auto-read state file is `<config dir>/aegis/pattern-state.json`,
written by `aegis enable`/`aegis disable` and applied to every scan and
`aegis list`. The config directory follows the XDG convention: it is
`$XDG_CONFIG_HOME` when set, otherwise `~/.config`. See
[Configuration](CONFIGURATION.md) for the profile schema and the
presets shipped in `config/profiles/`.
