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

A `-c` value is treated as a file path when it contains a path
separator or ends in `.json`, and as a preset name otherwise — so a
stray file called `production` in the working directory cannot hijack
the preset, and a typo'd path fails with the real I/O error instead of
the preset list.

A profile supplies defaults for the current run for any flag you did
not set explicitly. Five fields are applied: `enabled_categories`
become the category allowlist, `output_format` the render,
`severity_threshold` the threshold, `anomaly_detectors` the
statistical-anomaly allowlist, and `path_classes` the path
classifications. Flags given on the command line always
win over profile values.

## Profile Fields

A profile is a single JSON object with these keys:

| Field | Type | Notes |
|-------|------|-------|
| `name` | string | Profile label |
| `enabled_categories` | array or `null` | Restrict the scan to these categories; `null` enables all |
| `output_format` | string | `human`, `json`, or `sarif` |
| `severity_threshold` | string or `null` | Minimum severity to report: `critical`, `high`, `medium`, or `low`; anything else fails the scan (`info` observations sit below every threshold) |
| `anomaly_detectors` | array or `null` | Statistical anomaly detectors to run; `null` runs all four, `[]` disables the layer, and a list runs exactly the named detectors (`comment-ratio-outlier`, `comment-concentration`, `identifier-diversity-outlier`, `file-size-outlier`) |
| `path_classes` | array | Path classifications: `{"glob": "docs/**", "class": "docs"}` objects whose findings are reported at low severity. `class` is `docs` or `fixture`; secret findings keep their severity and carry the class as a tag. See [Triage](TRIAGE.md) |

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
  "output_format": "sarif"
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
    "ai-slop",
    "supply-chain"
  ],
  "output_format": "json"
}
```

### Development Profile

Relaxed settings for local development
(`config/profiles/development.json`):

```json
{
  "name": "development",
  "enabled_categories": null,
  "output_format": "human"
}
```

### MCP Integration Profile

Settings for MCP server mode
(`config/profiles/mcp-integration.json`):

```json
{
  "name": "mcp-integration",
  "enabled_categories": null,
  "output_format": "json"
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

Ignore handling is always on for scans of directories; there is no
profile key or flag to turn it off.

## Environment Variables

Aegis reads only these variables; there is no general `AEGIS_CONFIG` or
`AEGIS_PROFILE` override.

| Variable | Description |
|----------|-------------|
| `RUST_LOG` | `tracing` log filter; when set it overrides the built-in level (`aegis=info`, or `aegis=debug` with `-v`) |
| `AEGIS_RECEIPT_FILE` | Path a scan writes its receipt to; the file is removed again before a subsequent scan so a failed scan never leaves a stale receipt behind |
| `AEGIS_DAEMON_SOCKET_PATH` | Socket the daemon listens on |
| `AEGIS_DAEMON_SCAN_ROOT` | Root directory the daemon restricts scans to |
| `AEGIS_DAEMON_ALLOWED_UIDS` | Comma-separated UIDs permitted to talk to the daemon |
| `AEGIS_DAEMON_ALLOWED_GIDS` | Comma-separated GIDs permitted to talk to the daemon |
| `AEGIS_DAEMON_CONFIG` | Profile file the daemon applies at startup; see [Operator Configuration](#operator-configuration-for-the-daemon-and-the-mcp-server) |
| `AEGIS_MCP_CONFIG` | Profile file the MCP server applies at startup; see [Operator Configuration](#operator-configuration-for-the-daemon-and-the-mcp-server) |
| `AEGIS_SOURCE_REVISION` | Source revision stamped into scan receipts (informational only) |
| `AEGIS_ATHEON_PATH` | Path to an Atheon binary that `aegis benchmark --compare` runs against; when unset, the external comparison is skipped |

These `AEGIS_DAEMON_*` variables configure `aegis-daemon`, which serves its
protocol over a Unix domain socket and is therefore only meaningful on
Unix-like platforms; on Windows the binary builds but exits with an
explanatory message. See `crates/aegis-daemon/README.md` for the socket and
peer-credential boundary.

### Operator Configuration for the Daemon and the MCP Server

Both long-running servers start with the default configuration unless an
operator names a profile file:

```bash
AEGIS_DAEMON_CONFIG=/etc/aegis/daemon.json aegis-daemon
AEGIS_MCP_CONFIG=/etc/aegis/mcp.json aegis-mcp
```

The file is the same JSON profile document the CLI reads with
`aegis --config <file>` (see [Profile Fields](#profile-fields)). The
fields that take effect are:

| Field | Effect in the daemon and the MCP server |
|-------|-----------------------------------------|
| `enabled_categories` | The category allowlist; findings in every other category are not produced |
| `severity_threshold` | Findings below the threshold are not reported |
| `anomaly_detectors` | The statistical-anomaly allowlist; `[]` disables the layer |
| `path_classes` | Path classifications; matching findings are tagged and non-secret findings are reported at low severity |
| `name` | A label, not used by the servers |
| `output_format` | Not used; the response format of each protocol is fixed |

The configuration is applied once, at startup, before the daemon binds its
socket and before the MCP server answers. A configuration that cannot be
applied stops the process rather than leaving it serving scans it was not
configured for: an unknown category, a path-class glob that does not
compile, a severity threshold that does not parse, and an unknown anomaly
detector are each reported as the reason for the refusal.

The configuration is deliberately **operator-side and not part of the
protocol**. Neither server accepts a request that changes it, because a
client that could set the severity threshold or the category list could
weaken the scan it was asked for. Change the profile file and restart the
service.

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
