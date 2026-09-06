# Aegis Rust Rewrite Plan

## Project Overview

**Aegis** is a high-performance pattern matching engine for secrets detection, AI-generated code identification, code quality enforcement, and DevOps/CI/CD issue detection. This is a complete rewrite from Go to Rust for enhanced performance, safety, and reliability.

### Goals
- Complete rewrite in Rust (from Go)
- 638 pattern coverage
- 99%+ test coverage
- DevOps/CI/CD integration focus
- Early issue detection for AI systems

---

## Architecture

### Workspace Structure

```
aegis/
├── crates/
│   ├── aegis-core/        # Core scanning engine
│   ├── aegis-cli/         # CLI application
│   ├── aegis-mcp/         # MCP server
│   ├── aegis-daemon/      # Daemon mode
│   ├── aegis-bundler/     # Pattern bundler tool
│   └── aegis-patterns/    # Pattern definitions
├── config/
│   └── profiles/           # Configuration profiles
├── docs/                   # Documentation
├── runtime/                # Runtime support files
└── schemas/                # JSON schemas
```

### Crate Responsibilities

#### aegis-core
Core scanning engine with no external dependencies.
- Pattern registry and management
- Bundle loading (gzip+JSON)
- Entropy calculation (Shannon)
- Finding and risk scoring
- AST-based analysis
- Clone detection
- CFG analysis
- Ignore pattern handling

#### aegis-cli
Command-line interface.
- scan, list, enable, disable, update subcommands
- JSON/SARIF output formats
- Config profile support

#### aegis-mcp
Model Context Protocol server.
- JSON-RPC 2.0 interface
- Security sandboxing
- Rate limiting

#### aegis-daemon
Long-running daemon mode.

#### aegis-bundler
Pattern bundling utility.
- YAML → gzip+JSON conversion
- Validation

#### aegis-patterns
Pattern definitions (hand-written Rust modules, generated docs).
- 33 categories; counts in docs/patterns/README.md

---

## Phase 1: Project Setup
- [x] Initialize Rust workspace
- [x] Create crate structure
- [x] Set up cargo fmt and clippy
- [x] Configure CI/CD
- [ ] Create .cargo/config

## Phase 2: Core Engine
- [x] Pattern interface and registry
- [x] Bundle system (load/save/verify)
- [x] Pattern matching (regex engine)
- [x] Entropy calculation
- [x] Finding and Stats structures
- [x] Risk scoring

## Phase 3: Advanced Analysis
- [x] AST pattern analysis
- [x] Clone detection
- [x] CFG analysis
- [x] Taint tracking
- [x] Suppression handling

## Phase 4: CLI Tool
- [x] scan subcommand
- [x] list/enable/disable subcommands
- [x] update subcommand
- [x] JSON/SARIF output
- [x] Configuration profiles

## Phase 5: MCP Server
- [x] JSON-RPC 2.0 implementation
- [x] Tool handlers
- [x] Security sandboxing
- [ ] Rate limiting

## Phase 6: Bundler & Patterns
- [x] Bundler tool
- [x] Migrate 409 patterns
- [x] Add 100+ new patterns

## Phase 7: Testing & Documentation
- [ ] 99%+ test coverage
- [x] Integration tests
- [ ] Property-based tests
- [x] Complete documentation

---

## Pattern Categories

The authoritative per-category pattern counts live in
[docs/patterns/README.md](patterns/README.md), which is generated from
source by `cargo run -p aegis-patterns --example generate_docs` and kept
fresh by a CI test. Do not duplicate counts here.

---

## Risk Scoring

```rust
enum RiskLevel { None, Low, Medium, High, Critical }

struct RiskScore {
    score: i32,
    level: RiskLevel,
    by_category: HashMap<String, CategoryRisk>,
    finding_count: usize,
    highest_severity: Severity,
}
```

Risk calculation considers:
- Pattern severity (critical=40, high=25, medium=10, low=3)
- Confidence multiplier (high=1.0, medium=0.7, low=0.4)
- Category weight
- Finding density
- Context (CI/CD vs local)

---

## Performance Targets

- **Throughput**: 10GB+/minute on modern hardware
- **Memory**: <100MB baseline, scales with patterns
- **Latency**: <10ms per file (avg)
- **Concurrency**: Worker pool with N*2 workers (N=CPU cores)
- **Bundle load**: <100ms startup

---

## Testing Strategy

### Coverage Requirements
- Line coverage: 99%+
- Branch coverage: 95%+
- All public APIs tested
- Property-based tests for core algorithms

### Test Categories
1. Unit tests (per-crate)
2. Integration tests
3. Property-based tests (arbitrary patterns, fuzzing)
4. Performance benchmarks
5. Snapshot tests for findings

---

## Security Considerations

- No unsafe code (except FFI boundaries)
- All regex compiled with timeout limits
- Bundle SHA-256 verification
- SSRF protection in bundle download
- Path sandboxing in MCP
- Rate limiting
- Input validation throughout
