# Aegis Module Architecture

This document describes the architecture of the Aegis codebase.

## Crate Structure

```
aegis/
└── crates/
    ├── aegis-core/     # Core scanning engine (library)
    ├── aegis-cli/      # CLI application (binary: aegis)
    ├── aegis-daemon/   # Long-running daemon service (binary: aegis-daemon)
    ├── aegis-mcp/      # MCP (Model Context Protocol) server (binary: aegis-mcp)
    ├── aegis-wasm/     # WebAssembly bindings
    ├── aegis-patterns/ # Pattern definitions bundle
    └── aegis-bundler/  # Bundle creation utilities (binary: aegis-bundler)
```

## aegis-core Module Organization

The core library is organized into the following modules:

### Public API (`lib.rs`)

```rust
// Core scanning
pub use scanner::{ScanError, ScanOptions, Scanner};
pub use finding::{Finding, FindingKind, InspectionLedger, InspectionStatus,
                  InspectionUnit, Location, ScanStats};
pub use pattern::{Pattern, PatternDefinition, PatternRegistry, Severity, Confidence, Category};
pub use bundle::{Bundle, BundleMetadata};

// Suppression, user rules, receipts
pub use suppression::Suppression;
pub use receipt::{ScanReceipt, ReceiptFinding, ReceiptLocation};
// user pattern types live in the module: aegis_core::user_patterns::{UserPattern, UserPatternFile}

// Output pipeline
#[cfg(feature = "output-pipeline")]
pub use output::{OutputPipeline, FileOutput, WebhookOutput, DatabaseOutput, SyncOutputHandler};

// Risk & Remediation
pub use risk::{RiskLevel, RiskScore, RiskClassification};
pub use remediation::{RemediationAdvisor, RemediationReport, ...};

// Configuration
pub use config::Config;

// SBOM
pub use sbom::{SbomGenerator, SbomFormat, ...};

// AST Analysis
pub use ast::{AstAnalyzer, AstAnalysis, AstFinding, Language};

// Control Center / GitForge adapter
pub use control_center_adapter::{ControlCenterAdapter, WorkRequest, ScanResult, EvidenceRecord};
```

### Module Hierarchy

```
aegis_core
├── ast/              # AST-based code analysis (ast/mod.rs)
├── benchmark.rs      # Benchmarking utilities
├── bundle.rs         # Pattern bundle loading and validation
├── cfg.rs            # Control flow graph analysis
├── clone.rs          # Code clone detection
├── config/           # Configuration management
│   ├── mod.rs       # Config types and error types
│   └── preset.rs    # Preset configurations
├── control_center_adapter.rs  # Control Center / GitForge integration
├── entropy.rs        # Entropy-based secret detection
├── finding.rs        # Finding, location, and inspection-ledger types
├── ignore.rs         # Ignore pattern management (.aegisignore, gitignore)
├── output/           # Multi-output pipeline (feature-gated)
│   ├── mod.rs       # Pipeline trait and OutputFormat
│   ├── file.rs      # File output (JSON/CSV/SARIF)
│   ├── webhook.rs   # Webhook output (HTTP/Discord/Slack/Teams)
│   └── database.rs  # Database output (SQLite implemented;
│                    # PostgreSQL/MySQL handlers are placeholders)
├── pattern.rs        # Pattern registry, definitions, category scanners
├── receipt.rs        # Redacted scan receipts
├── remediation.rs    # Guided remediation advisor
├── risk.rs           # Risk scoring (RiskScore)
├── risk/             # Risk submodules
│   ├── risk_classification.rs
│   └── risk_level.rs
├── sbom.rs           # SBOM generation (SPDX, SPDX tag-value, CycloneDX)
├── scanner.rs        # Main scanner implementation
├── suppression.rs    # Inline finding suppression
└── user_patterns.rs  # `.aegis.yml` custom rule loading
```

## Design Principles

### 1. Public vs Internal

- **Public modules**: `scanner`, `pattern`, `finding`, `risk`, `config`,
  `bundle`, `entropy`, `ast`, `cfg`, `clone`, `remediation`, `sbom`,
  `suppression`, `user_patterns`, `receipt`, `benchmark`,
  `control_center_adapter`, and the feature-gated `output`
- **Internal module**: `internal/` is declared as a private `mod` in
  `lib.rs`; it is not part of the public API and may change at any time

### 2. Feature Gates

Key features are feature-gated:
- `output-pipeline`: Multi-output system (file, webhook, database)
- `tree-sitter`: Enhanced AST analysis with tree-sitter parsers
- `tokio`: Async runtime support
- `jsonschema`: JSON schema validation

### 3. Error Handling

All public functions return `Result` or use `thiserror`:
```rust
pub enum ConfigError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    ParseError(#[from] serde_json::Error),
    #[error("Unknown preset: {0}")]
    UnknownPreset(String),
}
```

### 4. Extensibility

#### Output Pipeline

New outputs implement `SyncOutputHandler`:

```rust
pub trait SyncOutputHandler: Send + Sync + Debug {
    fn emit_sync(&self, findings: &[Finding], stats: &ScanStats, risk: &RiskScore) -> OutputResult;
    fn flush_sync(&self) -> OutputResult;
    fn name(&self) -> &str;
}
```

#### Pattern Types

Every rule is a `PatternDefinition`: a regex `match_pattern`, an optional
`exclude_pattern` that suppresses a candidate span, an optional
`min_entropy` floor, `file_extensions` scoping, and an `env_var` flag that
confines a rule to environment scans. AST analysis is a separate pass over
the same sources (`ast::AstAnalyzer`), not a third pattern type.

### 5. Data Flow

```
Source Code
    ↓
Scanner (rayon across files, and across categories for large files)
    ↓
Per-extension Category Scanners (combined-regex pre-filter, then per-pattern)
    ↓
Findings (location, severity, confidence, redacted fingerprint) + Inspection Ledger
    ↓
Risk Score (severity weight × confidence multiplier × category weight)
    ↓
Output (human / json / sarif; optional output pipeline: file, webhook, database)
    ↓
Remediation Advisor (ROI-based prioritization)
```

## Feature Flags

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `default` | Tokio + JSON Schema | tokio, jsonschema |
| `output-pipeline` | Multi-output system | reqwest, rusqlite |
| `tree-sitter` | Deep AST analysis | tree-sitter-* crates |
| `tokio` | Async runtime | tokio |
| `jsonschema` | Schema validation | jsonschema |

## Performance Considerations

1. **Parallel scanning**: Uses `rayon` for data parallelism over files
   (and over categories within one large file)
2. **Lazy compilation**: An extension's regexes compile on first use and
   are then cached, so startup and `scan_string` pay only for what they use
3. **Combined-regex pre-filter**: a file that does not match a category's
   alternation never runs that category's individual patterns
4. **Worker pools**: rayon's global pool (one thread per core).
   `ScanOptions::workers` records an explicit choice but is not yet wired
   to the pool

## Testing Strategy

- **Unit tests**: In `#[cfg(test)]` modules
- **Integration tests**: In `tests/` directory
- **Property tests**: Using `proptest`
- **Benchmarks**: Using `criterion` (`benches/pattern_matching.rs`,
  `benches/scanner_init.rs`)

## Documentation

- `lib.rs`: Module-level documentation with examples
- `MODULES.md`: This file
- `docs/architecture/OVERVIEW.md`: System design overview
- `docs/`: Additional documentation
