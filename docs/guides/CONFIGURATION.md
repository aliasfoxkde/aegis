# Configuration

## Profiles

Aegis takes its settings from CLI flags plus an optional JSON **profile**
document. Profiles are selected with the top-level `-c/--config` flag,
which must come before the subcommand:

```bash
aegis --config production scan .
```

Four preset names are built in: `production`, `pipeline`,
`development`, and `mcp-integration`. A test in `aegis-core` keeps the
built-ins in sync with the JSON copies that ship in
[`config/profiles/`](../../config/profiles/) (`development.json`,
`pipeline.json`, `production.json`, `mcp-integration.json`).

A profile supplies defaults for the current run — `enabled_categories`
become the category allowlist, `output_format` the render, and
`severity_threshold` the threshold — for any flag you did not set
explicitly. Flags given on the command line always win over profile
values. The remaining profile fields (`strict_mode`,
`performance_mode`, `max_file_size_mb`, `timeout_seconds`,
`exit_on_findings`) are recorded profile metadata and are not yet
applied to the scan itself.

## Profile Fields

A profile is a single JSON object with these keys:

| Field | Type | Notes |
|-------|------|-------|
| `name` | string | Profile label |
| `enabled_categories` | array or `null` | Restrict the scan to these categories; `null` enables all |
| `strict_mode` | string | `permissive`, `standard`, or `strict` |
| `performance_mode` | string | `debug`, `standard`, or `optimized` |
| `exit_on_findings` | bool | Exit non-zero when findings are reported |
| `max_file_size_mb` | integer | Files above this size are skipped |
| `binary_file_detection` | bool | Detect and skip binary files |
| `gitignore_respect` | bool | Honour `.gitignore` (default `true`) |
| `aegisignore_respect` | bool | Honour `.aegisignore` (default `true`) |
| `output_format` | string | `human`, `json`, or `sarif` |
| `timeout_seconds` | integer | Scan timeout; `0` means no timeout |
| `severity_threshold` | string or `null` | Minimum severity to report |

Unknown keys are ignored; omitted keys fall back to their default.

### Production Profile

High-security settings for production environments
(`config/profiles/production.json`):

```json
{
  "name": "production",
  "enabled_categories": [
    "secrets",
    "pii",
    "security-hardening",
    "web-security",
    "compliance"
  ],
  "strict_mode": "strict",
  "performance_mode": "optimized",
  "exit_on_findings": true,
  "max_file_size_mb": 5,
  "binary_file_detection": true,
  "gitignore_respect": true,
  "output_format": "sarif",
  "timeout_seconds": 60
}
```

### Pipeline Profile

Optimized for CI/CD pipelines (`config/profiles/pipeline.json`):

```json
{
  "name": "pipeline",
  "enabled_categories": [
    "secrets",
    "pii",
    "security-hardening",
    "web-security",
    "code-quality",
    "devops",
    "ai-detection",
    "supply-chain"
  ],
  "strict_mode": "standard",
  "performance_mode": "optimized",
  "exit_on_findings": true,
  "max_file_size_mb": 10,
  "binary_file_detection": true,
  "gitignore_respect": true,
  "output_format": "json",
  "timeout_seconds": 300
}
```

### Development Profile

Relaxed settings for local development
(`config/profiles/development.json`):

```json
{
  "name": "development",
  "enabled_categories": null,
  "strict_mode": "standard",
  "performance_mode": "debug",
  "exit_on_findings": false,
  "max_file_size_mb": 50,
  "binary_file_detection": false,
  "gitignore_respect": true,
  "output_format": "human",
  "timeout_seconds": 0
}
```

### MCP Integration Profile

Settings for MCP server mode
(`config/profiles/mcp-integration.json`):

```json
{
  "name": "mcp-integration",
  "enabled_categories": null,
  "strict_mode": "standard",
  "performance_mode": "optimized",
  "exit_on_findings": false,
  "max_file_size_mb": 10,
  "binary_file_detection": true,
  "gitignore_respect": true,
  "output_format": "json",
  "timeout_seconds": 30
}
```

## Ignoring Files

Create `.aegisignore` in your project root. Rules are gitignore-style
globs; a later rule overrides an earlier one, and a `!` prefix
re-includes a path that an earlier rule (including one from
`.gitignore`) excluded. `.aegisignore` rules are evaluated after
`.gitignore` rules, so they always win.

```
# Glob patterns
node_modules/
dist/
build/
*.min.js

# File types
**/*.png
**/*.jpg
**/*.lock

# Re-include a path excluded above or by .gitignore
!docs/public-api.md
```

Semantics:

- `*.log` matches at any depth (basename matching).
- `build/` or `build` ignores the directory and everything beneath it.
- `docs/keep.md` (a rule containing `/`) is anchored to the scan root.
- Blank lines and `#` comments are skipped; invalid globs are ignored.
- `.atheonignore` is still read as a legacy alias when `.aegisignore`
  is absent.
- `node_modules/`, `target/`, and `.git/` are always ignored.

Both sources can be toggled independently in a profile:
`gitignore_respect` and `aegisignore_respect` (both default to `true`;
the legacy key `gitignore_atheon_respect` is still accepted as an alias
for the latter).

## Environment Variables

Aegis reads only these variables; there is no general `AEGIS_CONFIG` or
`AEGIS_PROFILE` override.

| Variable | Description |
|----------|-------------|
| `AEGIS_RECEIPT_FILE` | Path a scan writes its receipt to; the file is removed again before a subsequent scan so a failed scan never leaves a stale receipt behind |
| `AEGIS_DAEMON_SOCKET_PATH` | Socket the daemon listens on |
| `AEGIS_DAEMON_SCAN_ROOT` | Root directory the daemon restricts scans to |
| `AEGIS_DAEMON_ALLOWED_UIDS` | Comma-separated UIDs permitted to talk to the daemon |
| `AEGIS_DAEMON_ALLOWED_GIDS` | Comma-separated GIDs permitted to talk to the daemon |
| `AEGIS_SOURCE_REVISION` | Source revision stamped into scan receipts (informational only) |
| `AEGIS_ATHEON_PATH` | Path to an Atheon binary that `aegis benchmark --compare` runs against; when unset, the external comparison is skipped |

## Risk Scoring

Risk scoring is not user-configurable. Each finding contributes its
severity weight — `critical` 40, `high` 25, `medium` 10, `low` 3,
`info` 0 —
multiplied by a confidence factor of `high` 1.0, `medium` 0.7, `low` 0.4.
The scan reports an overall level and score plus a per-category rollup.

## Pattern Categories

Categories are enabled or disabled in bulk, not individually. Either pass
a list on the command line:

```bash
aegis scan . --categories secrets,pii
```

or set `enabled_categories` in a profile (a JSON array of category
names, or `null` for all of them). `aegis list --category <name>`
filters the pattern listing the same way.

There is no per-category `severity_override`: severities are fixed per
pattern in the registry.
