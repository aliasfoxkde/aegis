# Aegis Architecture

## Overview

Aegis is a pattern matching engine designed for:
- Secrets detection
- AI-generated code identification
- Code quality enforcement
- DevOps/CI/CD issue detection
- Early issue detection for AI systems

## Core Components

### Pattern System

Patterns are Rust structs in `crates/aegis-patterns/src/<category>.rs`,
compiled into every Aegis binary — scans never fetch rules at runtime.
`aegis-bundler` can additionally pack a directory of YAML pattern
definitions into the gzip+JSON bundle format:

```yaml
# aegis-bundler input schema: a top-level sequence of pattern definitions
- name: aws-access-key
  category: secrets
  match: "AKIA[0-9A-Z]{16}"
  enabled: true
  severity: critical
  confidence: high
  min_entropy: 3.5
  description: "AWS Access Key ID detected"
  reference: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
  tags: [aws, cloud, credential]
```

### Scanning Pipeline

```
Input (file/dir/string/env)
       │
       ▼
┌─────────────────┐
│ Pre-processing  │ ← .aegisignore, gitignore
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Pattern Filter   │ ← Category/severity filters
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Entropy Check   │ ← Skip low-entropy matches
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Regex Match      │ ← RE2-compatible regex
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ AST Analysis     │ ← Code structure analysis
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Risk Scoring    │
└────────┬────────┘
         │
         ▼
    Output (findings)
```

### Risk Scoring

Each finding contributes `severity weight × confidence multiplier ×
category weight`, summed per category and for the scan:

- Pattern severity weight (critical 40, high 25, medium 10, low 3, info 0)
- Confidence multiplier (high 1.0, medium 0.7, low 0.4)
- Category risk weight (`secrets` 1.5, `security-hardening` 1.4,
  `supply-chain` 1.4, `code-quality` 0.8, … configurable via `Config`)

Finding density and scan context are not modelled.

| Severity | Weight | Confidence Multiplier |
|----------|--------|----------------------|
| Critical | 40 | High: 1.0, Med: 0.7, Low: 0.4 |
| High | 25 | High: 1.0, Med: 0.7, Low: 0.4 |
| Medium | 10 | High: 1.0, Med: 0.7, Low: 0.4 |
| Low | 3 | High: 1.0, Med: 0.7, Low: 0.4 |
| Info | 0 | High: 1.0, Med: 0.7, Low: 0.4 |

Info findings are informative-only: they are reported in every output
format but contribute nothing to the risk score and never fail the exit
code, so a CI run stays green regardless of how many appear.

### Statistical Anomaly Layer

After a directory walk, the scanner analyzes per-file metrics (line
counts, comment share, identifier diversity) collected during the scan
and emits `Severity::Info` findings in the `statistical-anomaly` category
for files that deviate sharply from their own baseline:

- `comment-ratio-outlier` — comment share more than 2.5 standard
  deviations above the file's language-group mean (the narrated or padded
  file)
- `comment-concentration` — a single file holding ≥ 60% of the
  repository's comment lines (a Pareto-style concentration)
- `identifier-diversity-outlier` — identifier variety far below the
  language-group norm with heavy token reuse (the copy-paste /
  template-expansion footprint)
- `file-size-outlier` — more than 2.5 standard deviations above the
  language-group mean line count (where generated dumps accumulate)

The z-score detectors compare each file against its language group — the
eligible files sharing its extension — because comment conventions differ
too much between languages for a mixed baseline to mean anything: a
narrated Python file judged against terse Rust siblings would be a false
outlier. A group smaller than eight files supports no z-score, so files
in minority languages are not judged rather than judged against someone
else's norm. The Pareto detector is the exception: comment concentration
is a property of the repository total by definition.

Each detector reports at most its single most extreme file, so the
post-pass stays bounded on any repository. Prose documents, dotfiles,
lockfiles, and minified bundles never enter the statistics. Observations
pass through the same category, severity-threshold, and baseline filters
as every other finding, and — like all info findings — never flip the
exit code.

The layer is configurable: `ScanOptions::anomaly_detectors` (core), the
CLI `--anomaly-detectors <list>` allow-list with `--no-anomalies`
disabling the layer entirely, and the `anomaly_detectors` field in a
`-c/--config` profile JSON all select which of the four detectors run.
Unknown detector names fail loudly with the valid list.

### Concurrency Model

- Worker pool: `rayon` over files, defaulting to `available_parallelism()`
  workers (`ScanOptions::workers`; falls back to 4 when the OS does not
  report it)
- A second rayon fan-out splits one file's categories across threads when
  the content is over 5000 bytes and more than 4 categories apply
- Registry shared behind `Arc` with `parking_lot` read/write locks
- Per-extension scanners are compiled on first use and cached for the
  process lifetime (invalidated when the applicable pattern set changes)

### Bundle Format

```
Bundle v2:
{
  "schema_version": 2,
  "created_at": "2024-01-01T00:00:00Z",
  "patterns": [
    {
      "name": "pattern-name",
      "category": "secrets",
      "match": "regex-pattern",
      "enabled": true,
      "severity": "high",
      "confidence": "high",
      "min_entropy": 3.5,
      "description": "...",
      "reference": "...",
      "tags": ["tag1"],
      "exclude": null,
      "file_extensions": [],
      "env_var": false,
      "binary": false
    }
  ]
}
```

### CLI Interface

```
aegis scan <path>            # Scan directory (also --file, --env, --stdin,
                             # --staged, --diff, --baseline)
aegis list                   # List all patterns
aegis list --enabled         # List enabled only
aegis enable <pattern>       # Informational: pattern state is not persisted yet
aegis disable <pattern>      # Informational: pattern state is not persisted yet
aegis update                 # Re-reads the in-binary pattern set (no download)
aegis benchmark <path>       # Warmup/runs timing, optional --compare
```

### MCP Server

JSON-RPC 2.0 over stdio with methods:
- `scan_string` - Scan in-memory content
- `scan_file` - Scan single file
- `scan_dir` - Scan directory
- `scan_env` - Scan environment variables
- `list_patterns` - List patterns
- `list_categories` - List categories
- `update_bundle` - Install a compiled scanner from a bundle

`scan_file`/`scan_dir` are sandboxed to the server's working directory
(`crates/aegis-mcp/src/sandbox.rs`); paths that escape it are rejected.

### Ignore Handling

1. `.aegisignore` - Aegis-specific ignore patterns
2. `.gitignore` - Standard git ignore
3. Inline suppression directives (`//`, `#`, `/* ... */` comments):
   - `aegis:ignore:pattern-name` - suppress named patterns on that line
   - `aegis:ignore-start` / `aegis:ignore-end` - suppress a line range
   - `aegis:ignore-file` - suppress the whole file
   - optional reason after `--` is recorded with the suppression
4. `--baseline` - Baseline file suppression (findings from a previous
   `--format json` scan are filtered; exit codes reflect new findings)

### Custom Patterns

A scan root's `.aegis.yml` (or `.aegis.yaml`) defines user patterns
(`patterns:` list with `name`, `severity`, `match`, `description`, and
optional `category`, `exclude`, `confidence`, `remediation`,
`reference`, `min_entropy`, `file_extensions`). They are validated
eagerly at scan start — an invalid file aborts the scan — and merged
into the registry alongside the bundled rules. Findings from custom
patterns flow through the same suppression, baseline, and output
pipeline as any other rule.

### File vs. Environment Scan Scope

Pattern definitions carry an `env_var` flag with a deliberate meaning:
`env_var: true` marks a rule as **env-scan-only**. Such rules never run
against file contents; `scan_env` matches them against environment
variable *values*, where the variable name (visible as `KEY=value` in
the reported line) supplies context that a bare match in a file lacks.

Design decision (Phase 5 audit, 2026-09):

- The flag is reserved for shapes that are only precise in an
  environment context — bare `[A-Za-z0-9]{25,}` blobs (`twitter-api-key`),
  base64 spans (`azure-api-key`), UUIDs (`heroku-api-key`), and data that
  is not secret at all but is sensitive when paired with an env-var name
  (crypto addresses, Stripe publishable keys).
- Vendor-prefixed credentials (`glpat-`, `sk-ant-`, `npm_`, `AIza…`,
  JWTs, Discord bot tokens, …) are precise in source files too and are
  file-active. The Phase 5 measurement found 13 such families that were
  env-scan-only and therefore invisible to file scans; they were
  flipped, with zero new findings on Aegis's own tree and no change to
  corpus precision/recall.
- Every rule in the `secrets` category runs in environment scans
  regardless of the flag, so clearing the flag never weakens env
  coverage.
- The set of env-scan-only rules is pinned by the
  `env_scan_only_rules_are_exactly_the_documented_set` test
  (`crates/aegis-core/tests/env_var_semantics.rs`), and the file-mode
  capability for each vendor prefix is pinned alongside it. Changing
  either requires a deliberate test update.
- Files with no extension (`.env`, `.npmrc`) still get generic
  credential-assignment coverage from `env-credential-assignment` and
  the other extension-less secrets rules.

### Output Formats

- **Human** - Pretty-printed with colors
- **JSON** - Structured JSON output (the shape a `--baseline` file takes)
- **SARIF** - Static Analysis Results Interchange Format, carrying the
  inspection ledger as run properties
- **CSV** - Through the feature-gated `output` module (`FileOutput`
  supports JSON, CSV, and SARIF)
- **SBOM** - `aegis-core::sbom` builds a component inventory and emits
  SPDX (JSON), SPDX tag-value, and CycloneDX

---

## Security Architecture

### Input Validation
- File size limits (10MB default; larger files are skipped, not read)
- Path sandboxing (cwd boundary, enforced in the MCP server)
- Binary file detection (NUL byte sniffing of the first 8 KiB)
- Custom patterns from `.aegis.yml` are validated before a scan starts; an
  invalid file aborts the scan instead of degrading to a partial rule set

### Bundle Security
- No network fetch: patterns ship inside the binary, so there is no bundle
  URL to protect and no download path to harden
- Bundles carry a SHA-256 checksum over the serialized pattern list
  (`Bundle::checksum`, surfaced through `BundleMetadata`)
- Loading is fail-closed: a wrong `schema_version`, a duplicate pattern
  name, a missing match expression, or a regex that does not compile
  aborts the scan rather than degrading to a partial pattern set

---

## Performance Architecture

### Memory Management
- Files above `max_file_size` are skipped before any read
- One task per file (rayon), with results collected and merged after the
  parallel section instead of through shared mutable queues
- Pre-computed line index per file so match offsets map to line numbers by
  binary search

### Pattern Matching Optimization
- Combined alternation regex per category acts as the pre-filter
- Individual pattern regexes run only on files the pre-filter matched
- Entropy gate skips low-information secret matches
- Binary files are not analyzed unless `scan_binary` is set

### Caching
- Per-extension compiled scanner cache, built lazily and reused across
  scans (see `PatternRegistry::build_category_scanners_for_extension`)
- No bundle cache: the pattern set is static inside the binary

---

## Directory Structure

```
aegis/
├── crates/
│   ├── aegis-core/         # Core engine
│   │   ├── src/
│   │   │   ├── lib.rs       # Public API and re-exports
│   │   │   ├── pattern.rs   # Pattern management and registry
│   │   │   ├── bundle.rs    # Bundle loading and validation
│   │   │   ├── scanner.rs   # Main scanner
│   │   │   ├── entropy.rs   # Entropy calculation
│   │   │   ├── finding.rs   # Finding structures, inspection ledger
│   │   │   ├── risk.rs      # Risk scoring (risk/ holds level + classification)
│   │   │   ├── suppression.rs  # Inline suppression directives
│   │   │   ├── user_patterns.rs # .aegis.yml custom rules
│   │   │   ├── receipt.rs   # Redacted scan receipts
│   │   │   ├── ast/         # AST analysis (ast/mod.rs)
│   │   │   ├── clone.rs     # Clone detection
│   │   │   ├── cfg.rs       # Control flow
│   │   │   ├── config/      # Config types and presets (mod.rs, preset.rs)
│   │   │   ├── output/      # Output pipeline (feature-gated)
│   │   │   └── internal/    # Private helpers shared by analyzers
│   │   └── tests/           # Integration tests
│   ├── aegis-cli/          # CLI tool (binary: aegis)
│   ├── aegis-mcp/           # MCP server (binary: aegis-mcp)
│   ├── aegis-daemon/        # Daemon (binary: aegis-daemon)
│   ├── aegis-bundler/       # Bundler tool (binary: aegis-bundler)
│   ├── aegis-patterns/     # Pattern definitions
│   └── aegis-wasm/         # WebAssembly bindings
├── config/
│   └── profiles/             # Config profiles (JSON)
├── docs/                     # Documentation
└── src/                      # aegis-bootstrap: workspace aggregator that
                              # points users at the real CLI entry point
```
