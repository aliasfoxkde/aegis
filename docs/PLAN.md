# Aegis Rust Rewrite Plan

## Project Overview

**Aegis** is a high-performance pattern matching engine for secrets detection, AI-generated code identification, code quality enforcement, and DevOps/CI/CD issue detection. This is a complete rewrite from Go to Rust for enhanced performance, safety, and reliability.

### Goals
- Complete rewrite in Rust (from Go)
- 620 pattern coverage (expanding from 409)
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
│   └── aegis-patterns/    # Pattern definitions (409 → 620)
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
Generated pattern definitions.
- 29 categories
- 620 patterns

---

## Phase 1: Project Setup
- [ ] Initialize Rust workspace
- [ ] Create crate structure
- [ ] Set up cargo fmt and clippy
- [ ] Configure CI/CD
- [ ] Create .cargo/config

## Phase 2: Core Engine
- [ ] Pattern interface and registry
- [ ] Bundle system (load/save/verify)
- [ ] Pattern matching (regex engine)
- [ ] Entropy calculation
- [ ] Finding and Stats structures
- [ ] Risk scoring

## Phase 3: Advanced Analysis
- [ ] AST pattern analysis
- [ ] Clone detection
- [ ] CFG analysis
- [ ] Taint tracking
- [ ] Suppression handling

## Phase 4: CLI Tool
- [ ] scan subcommand
- [ ] list/enable/disable subcommands
- [ ] update subcommand
- [ ] JSON/SARIF output
- [ ] Configuration profiles

## Phase 5: MCP Server
- [ ] JSON-RPC 2.0 implementation
- [ ] Tool handlers
- [ ] Security sandboxing
- [ ] Rate limiting

## Phase 6: Bundler & Patterns
- [ ] Bundler tool
- [ ] Migrate 409 patterns
- [ ] Add 100+ new patterns

## Phase 7: Testing & Documentation
- [ ] 99%+ test coverage
- [ ] Integration tests
- [ ] Property-based tests
- [ ] Complete documentation

---

## Pattern Categories (29 → 35)

| Category | Count | Focus |
|----------|-------|-------|
| secrets | 75 | API keys, tokens, credentials |
| code-quality | 60 | Debug, dead code, complexity |
| devops | 35 | CI/CD, pipelines, secrets |
| ai-detection | 30 | AI markers, template detection |
| security-hardening | 30 | Insecure configs, weak crypto |
| accessibility | 25 | WCAG, ARIA compliance |
| web-security | 20 | XSS, SQLi, CORS |
| pii | 20 | Personal data detection |
| cloud-native | 20 | Kubernetes, Docker |
| performance | 18 | Blocking calls, async issues |
| supply-chain | 15 | Dependency vulnerabilities |
| infrastructure | 15 | IaC, terraform, kubernetes |
| compliance | 12 | GDPR, HIPAA, PCI |
| git-hygiene | 10 | Conflicts, fixups |
| ai-safety | 10 | Prompt injection, jailbreaks |
| (new) llm-guardrails | 15 | LLM input/output safety |
| (new) shift-left | 12 | Early detection patterns |

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
