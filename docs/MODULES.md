# Aegis Module Architecture

This document describes the architecture of the Aegis codebase.

## Crate Structure

```
aegis/
├── aegis-core/     # Core scanning engine (library)
├── aegis-cli/      # CLI application
├── aegis-daemon/   # Long-running daemon service
├── aegis-mcp/      # MCP (Model Context Protocol) server
├── aegis-wasm/     # WebAssembly bindings
├── aegis-patterns/ # Pattern definitions bundle
└── aegis-bundler/  # Bundle creation utilities
```

## aegis-core Module Organization

The core library is organized into the following modules:

### Public API (`lib.rs`)

```rust
// Core scanning
pub use scanner::{ScanOptions, Scanner};
pub use finding::{Finding, FindingKind, Location, ScanStats};
pub use pattern::{Pattern, PatternRegistry, ...};
pub use bundle::{Bundle, BundleMetadata};

// Output pipeline
#[cfg(feature = "output-pipeline")]
pub use output::{OutputPipeline, FileOutput, WebhookOutput, DatabaseOutput};

// Risk & Remediation
pub use risk::{RiskLevel, RiskScore, RiskClassification};
pub use remediation::{RemediationAdvisor, RemediationReport, ...};

// Configuration
pub use config::Config;

// SBOM
pub use sbom::{SbomGenerator, SbomFormat, ...};

// AST Analysis
pub use ast::AstAnalyzer;
```

### Module Hierarchy

```
aegis_core
├── ast/              # AST-based code analysis
│   └── mod.rs        # Go, Rust, Python, JavaScript analysis
├── benchmark/        # Benchmarking utilities
├── bundle/           # Pattern bundle management
├── cfg/              # Control flow graph analysis
├── clone/            # Code clone detection
├── config/           # Configuration management
│   ├── mod.rs       # Config types and YAML presets
│   └── preset/      # Preset configurations
├── control_center_adapter/  # Control Center integration
├── entropy/          # Entropy-based secret detection
├── finding/          # Finding and location types
├── ignore/           # Ignore pattern management
├── output/           # Multi-output pipeline
│   ├── mod.rs       # Pipeline trait
│   ├── file.rs      # File output (JSON/CSV/SARIF)
│   ├── webhook.rs   # Webhook output (HTTP/Discord/Slack)
│   └── database.rs  # Database output (SQLite/PostgreSQL/MySQL)
├── pattern/          # Pattern registry and definitions
├── remediation/       # Guided remediation advisor
├── risk/             # Risk scoring and classification
│   ├── mod.rs       # RiskScore
│   ├── risk_classification.rs
│   └── risk_level.rs
├── sbom/             # SBOM generation
├── scanner/          # Main scanner implementation
└── suppression/       # Finding suppression
```

## Design Principles

### 1. Public vs Internal

- **Public modules**: Scanner, Pattern, Finding, Risk, Output, Config
- **Internal modules**: Implementation details hidden in `internal/` (future)

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
pub trait SyncOutputHandler: Send + Sync {
    fn write(&self, finding: &Finding) -> Result<(), OutputError>;
    fn flush(&self) -> Result<(), OutputError>;
}
```

#### Pattern Types

Patterns are defined via `PatternDefinition`:
- Entropy-based (secret detection)
- AST-based (code analysis)
- Regex-based (pattern matching)

### 5. Data Flow

```
Source Code
    ↓
Scanner (multi-threaded with rayon)
    ↓
Pattern Registry (regex, entropy, AST)
    ↓
Findings (with location, severity, confidence)
    ↓
Output Pipeline (file, webhook, database)
    ↓
Risk Score (weighted by category/severity)
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

1. **Parallel scanning**: Uses `rayon` for data parallelism
2. **Memory efficiency**: Processes files in batches
3. **Incremental hashing**: For large file change detection
4. **Worker pools**: Configurable worker threads

## Testing Strategy

- **Unit tests**: In `#[cfg(test)]` modules
- **Integration tests**: In `tests/` directory
- **Property tests**: Using `proptest`
- **Benchmarks**: Using `criterion`

## Documentation

- `lib.rs`: Module-level documentation with examples
- `MODULES.md`: This file
- `ARCHITECTURE.md`: System design overview
- `docs/`: Additional documentation
