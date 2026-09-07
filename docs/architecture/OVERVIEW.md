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

Patterns are defined in YAML and bundled into a gzip+JSON format.

```yaml
name: aws-access-key
category: secrets
match: "AKIA[0-9A-Z]{16}"
enabled: true
severity: critical
confidence: high
minEntropy: 3.5
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

Risk scores are calculated based on:
- Pattern severity weight
- Confidence multiplier
- Category risk weights
- Finding density
- Context (CI/CD, local, etc.)

| Severity | Weight | Confidence Multiplier |
|----------|--------|----------------------|
| Critical | 40 | High: 1.0, Med: 0.7, Low: 0.4 |
| High | 25 | High: 1.0, Med: 0.7, Low: 0.4 |
| Medium | 10 | High: 1.0, Med: 0.7, Low: 0.4 |
| Low | 3 | High: 1.0, Med: 0.7, Low: 0.4 |

### Concurrency Model

- Worker pool: `min(NumCPU * 2, 64)` workers
- Per-scan snapshot of active patterns
- Context propagation for cancellation
- Atomic pattern registry access

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
      "tags": ["tag1"]
    }
  ]
}
```

### CLI Interface

```
aegis scan <path>           # Scan directory or file
aegis list                   # List all patterns
aegis list --enabled         # List enabled only
aegis enable <pattern>       # Enable pattern
aegis disable <pattern>      # Disable pattern
aegis update                 # Update bundle
```

### MCP Server

JSON-RPC 2.0 interface with tools:
- `scan_string` - Scan in-memory content
- `scan_file` - Scan single file
- `scan_dir` - Scan directory
- `scan_env` - Scan environment variables
- `list_patterns` - List patterns
- `list_categories` - List categories
- `update_bundle` - Update pattern bundle

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
- **JSON** - Structured JSON output
- **SARIF** - Static Analysis Results Interchange Format

---

## Security Architecture

### Input Validation
- File size limits (10MB default)
- Path sandboxing (cwd boundary)
- Binary file detection (NUL byte sniffing)
- Request size limits (MCP: 64MiB)

### Bundle Security
- SHA-256 hash verification
- ETag-based caching (24h)
- SSRF protection (hostname validation)

### Rate Limiting
- Token bucket algorithm
- Configurable limits
- Per-client limiting (MCP)

---

## Performance Architecture

### Memory Management
- Bounded file reads (capped at maxFileSize)
- Chunked scanning
- Worker pool with bounded queues
- Pattern snapshot per scan

### Pattern Matching Optimization
- Combined regex per category
- Pre-filtering with simple patterns
- Entropy pre-screening for secrets
- Skip analysis for binary files

### Caching
- Pattern state persistence
- ETag-based bundle caching
- Compiled regex caching

---

## Directory Structure

```
aegis/
├── crates/
│   ├── aegis-core/         # Core engine
│   │   ├── src/
│   │   │   ├── lib.rs       # Public API
│   │   │   ├── pattern.rs   # Pattern management
│   │   │   ├── bundle.rs    # Bundle loading
│   │   │   ├── scanner.rs   # Main scanner
│   │   │   ├── entropy.rs   # Entropy calculation
│   │   │   ├── finding.rs   # Finding structures
│   │   │   ├── risk.rs      # Risk scoring
│   │   │   ├── ast/         # AST analysis
│   │   │   ├── clone.rs     # Clone detection
│   │   │   ├── cfg.rs       # Control flow
│   │   │   └── ignore.rs    # Ignore handling
│   │   └── tests/           # Integration tests
│   ├── aegis-cli/          # CLI tool
│   ├── aegis-mcp/           # MCP server
│   ├── aegis-daemon/        # Daemon
│   ├── aegis-bundler/       # Bundler tool
│   └── aegis-patterns/     # Pattern definitions
├── config/
│   └── profiles/             # Config profiles
├── docs/                     # Documentation
└── runtime/                  # Runtime files
```
