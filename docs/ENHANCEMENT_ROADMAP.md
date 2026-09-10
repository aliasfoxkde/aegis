# Aegis Enhancement Roadmap

This document outlines research findings and recommendations for enhancing Aegis security scanning capabilities.

## Research Summary

### 1. GitHub Security Scanning Projects Analysis

| Project | Key Features | Pattern Approach |
|---------|--------------|-----------------|
| **Gitleaks** | Entropy + regex, proximity matching, multi-format output | TOML rules |
| **TruffleHog** | 700+ API verifiers, active credential confirmation | JSON/YAML |
| **detect-secrets** | ML-based false positive reduction, baseline system | JSON baseline |
| **git-secrets** | AWS-specific patterns, git hooks | Arguments |

**Key Insights:**
- Gitleaks proximity matching (withinLines/withinColumns) enables context-aware detection
- TruffleHog's API verification is unique for live credential validation
- detect-secrets ML model reduces false positives significantly
- All tools use entropy + regex hybrid approaches

### 2. arxiv.org Papers (2024-2026)

| Paper | Key Finding | Relevance |
|-------|-------------|-----------|
| **YASA** (arXiv:2601.17390) | Unified AST for multi-language taint analysis | Cross-language scanning |
| **VulStyle** (arXiv:2604.26313) | AST + stylometry for vulnerability detection | Reduces false positives |
| **IssueGuard** (arXiv) | Regex + CodeBERT hybrid, 92.7% F1 | Hybrid ML approach |
| **Secret Scanner Agent** | LLM multi-agent for context extraction | Advanced detection |
| **PyGuard** (arXiv:2601.16463) | Hierarchical pattern mining + LLMs | Semantic abstraction |

**Key Insights:**
- AST normalization improves pattern matching accuracy
- Hybrid regex + ML approaches outperform single-method
- Pre-analysis simplification can achieve 3x+ speedup
- Tree-sitter confirmed as robust AST foundation

### 3. AST Projects & Tools

| Tool | Language | WASM | Best For |
|------|----------|------|----------|
| **tree-sitter** | C | Yes | Multi-language incremental parsing |
| **syn** | Rust | No | Rust-specific AST analysis |
| **Biome** | Rust | Yes | JS/TS deep analysis |

---

## Status: Shipped Since 2026-08-13

The following items from the original recommendation list are now in the
product; they are kept here so the research rationale stays attached to
the shipped work:

| Item | Status | Where |
|------|--------|-------|
| 8. Baseline scanning system | **Shipped (v0.2.6+)** | `--baseline` flag; engine-level filtering (`aegis-core::scanner::load_baseline_fingerprints`); fingerprints are redacted (SHA-256 of matched text only) so baselines are safe to commit |
| 9. Inline allowlisting | **Shipped (v0.2.7)** | `aegis:ignore:pattern`, `aegis:ignore-start`/`aegis:ignore-end` ranges (nesting supported), `aegis:ignore-file`, optional `-- reason`; AST findings pass through the same gate; `ScanStats.suppressed_count` reports usage |
| Entropy gate | **Shipped** | Shannon entropy with per-pattern `min_entropy` (see `aegis-core::entropy`) |
| Custom rules | **Shipped (post-0.2.7)** | `.aegis.yml` / `.aegis.yaml` at the scan root: user patterns with `match`/`exclude` regex, severity, category, extensions, entropy gate, and `remediation` guidance; fail-loud validation |
| Pre-commit mode | **Shipped (post-0.2.7)** | `aegis scan . --staged` scans the git index (not the working tree) so pre-commit hooks judge exactly what will be committed |

## Recommended Enhancements

### High Priority

#### 1. AST-Based Contextual Analysis
- **What**: Use tree-sitter for AST-aware pattern matching
- **Why**: Proximity matching (Gitleaks style) and AST context improve accuracy
- **Effort**: Medium (2-4 weeks)
- **References**: YASA paper, CodeSentinel (tree-sitter integration)

#### 2. Hybrid ML/Regex Detection
- **What**: Add optional ML-based secondary verification for high-confidence findings
- **Why**: Reduces false positives, improves precision (IssueGuard achieved 92.7% F1)
- **Effort**: Medium-High (4-8 weeks)
- **References**: IssueGuard, Secret Scanner Agent papers

#### 3. Proximity Matching Rules
- **What**: Implement Gitleaks-style `withinLines`/`withinColumns` rules
- **Why**: Context-aware detection reduces false positives significantly
- **Effort**: Low (1-2 weeks)
- **References**: Gitleaks composite rules

#### 4. API Verification Integration
- **What**: Add optional live credential verification (like TruffleHog)
- **Why**: Confirms if detected secrets are active/revocable
- **Effort**: High (8+ weeks, requires API integrations)
- **References**: TruffleHog's 700+ verifiers

### Medium Priority

#### 5. Tree-sitter Integration
- **What**: Deepen the existing optional `tree-sitter` feature (Go, Rust,
  Python, JavaScript, TypeScript grammars are already wired behind
  `--features tree-sitter`) so AST rules can carry findings, not just
  metrics
- **Why**: Enables language-aware scanning beyond regex
- **Effort**: Medium (3-5 weeks)
- **References**: YASA, CodeSentinel papers

#### 6. Pre-analysis Optimization
- **What**: Compiler-based IR simplification before pattern matching
- **Why**: Can achieve 3x+ speedup per academic research
- **Effort**: Medium (3-4 weeks)
- **References**: Accelerating Pointer Analysis (arXiv:2608.04466)

#### 7. Entropy Calculation Improvements
- **What**: Enhanced entropy algorithm with better false positive filtering
- **Why**: Current entropy detection flagged as weakness in benchmarks
- **Effort**: Low-Medium (2-3 weeks)
- **References**: detect-secrets gibberish model, PyGuard

### Lower Priority

#### 10. Additional Output Formats
- **What**: JUnit output (CSV file output and SPDX/CycloneDX SBOM are
  already shipped — see `aegis-core::output::file` and `aegis-core::sbom`)
- **Why**: Better CI/CD integration
- **Effort**: Low (1 week)
- **References**: Gitleaks multi-format support

---

## Pattern Sources to Consider

### Secret Patterns
1. **Gitleaks Rules** (700+ rules, TOML format) - https://github.com/gitleaks/gitleaks
2. **TruffleHog Detectors** (700+ verifiers) - https://github.com/trufflesecurity/trufflehog
3. **Yelp detect-secrets** (baseline format) - https://github.com/Yelp/detect-secrets

### Security Pattern Repositories
- **MITRE CWE** - Common Weakness Enumeration
- **NIST NVD** - National Vulnerability Database
- **OWASP** - Top 10, API Security
- **SANS** - Common Vulnerabilities

---

## Implementation Notes

### Tree-sitter Integration Path
1. ~~Add `tree-sitter` and language grammar crates~~ — done: the optional
   `tree-sitter` feature pulls `tree-sitter-go/-rust/-python/-javascript/-typescript`
2. ~~Create AST-based scanner wrapper~~ — done: `aegis-core::ast` wraps the
   grammars and also ships a regex-free fallback analyzer
3. Implement language-specific query patterns that produce findings
4. Add WASM support via tree-sitter's wasm runtime

### Hybrid Detection Path
1. Train/finetune small model for false positive classification
2. Integrate as optional post-processor
3. Add confidence scores to findings
4. Enable/disable via feature flag

---

## References

### Papers
- YASA: Scalable Multi-Language Taint Analysis (arXiv:2601.17390)
- VulStyle: Multi-Modal Pre-Training (arXiv:2604.26313)
- IssueGuard: Regex + CodeBERT Hybrid (arXiv)
- Secret Scanner Agent: Multi-Agent LLM (arXiv)
- PyGuard: Hierarchical Pattern Mining (arXiv:2601.16463)
- Accelerating Pointer Analysis (arXiv:2608.04466)

### Tools
- Gitleaks: https://github.com/gitleaks/gitleaks
- TruffleHog: https://github.com/trufflesecurity/trufflehog
- detect-secrets: https://github.com/Yelp/detect-secrets
- tree-sitter: https://github.com/tree-sitter/tree-sitter
- Biome: https://github.com/biomejs/biome

---

---

## Engineering Quality Backlog

Tracked as standing work alongside features:

- **Coverage gate**: shipped — `cargo llvm-cov --workspace` runs in CI and
  `codecov.yml` pins real thresholds (90% project / 85% patch); measured
  97.24% lines, so the gate can be raised as coverage rises
- **Benchmarks**: shipped — criterion suite for the pattern-matching hot
  path and for scanner init (`crates/aegis-core/benches/`)
- **Fuzzing**: shipped — four cargo-fuzz targets for the suppression
  parser, the ignore/glob compiler, the baseline parser, and the
  `.aegis.yml` pattern compiler, run weekly
- **Corpus precision/recall harness**: shipped — labelled vulnerable +
  clean fixtures with expected findings, failing CI when precision drops
  (`crates/aegis-core/tests/corpus_precision_recall.rs`)
- **Rule-liveness proof**: shipped — every shipped rule has a provably
  firing example (`crates/aegis-core/tests/pattern_liveness.rs`)
- **Strict lints**: shipped — workspace `[lints]` with pedantic +
  `missing_docs`, `-D warnings` in CI
- **Crates.io publishing**: open — `cargo publish` for the library crates
  in the release workflow (needs a `CARGO_REGISTRY_TOKEN` secret; the
  workspace version source is already single-sourced for this)

---

## WCAG 2.2 Coverage (accessibility pack)

The accessibility pattern pack encodes 28 patterns covering 21 distinct
WCAG 2.2 success criteria (Level A and AA, plus 4.1.3): 1.1.1, 1.2.2,
1.2.3, 1.3.1, 1.3.5, 1.4.2, 1.4.4, 2.1.1, 2.1.4, 2.2.2, 2.3.1, 2.4.1,
2.4.2, 2.4.4, 2.4.6, 2.4.7, 3.1.1, 3.2.5, 3.3.2, 4.1.2, 4.1.3. Each
pattern references the W3C "Understanding" page for its criterion via
`reference` and tags it `wcag-<sc>`. Coverage is intentionally limited
to criteria detectable by static regex/AST analysis; several Level AAA
criteria require rendering, interaction, or assistive-technology
testing and are out of scope by design.

## Distribution

Current channels:

- **GitHub Releases**: checksummed binaries (SHA-256 `checksums.txt` per
  platform) for linux x86_64/arm64 (static musl), macOS x86_64/arm64,
  Windows, plus `aegis-wasm.wasm`, built by the GitForge release lane
  (`.gitforce.yml` → `ci/release/Dockerfile`) and published from the
  lane artifacts by `scripts/release/publish_github_release.sh` —
  10 assets plus a `release-attestation.json` in total; the
  `.github/workflows/release.yml` workflow remains as a manual
  fallback rebuild only
- **From source**: `cargo install --path crates/aegis-cli` or the
  workspace build; MSRV 1.75
- **MCP / daemon**: `aegis-mcp` and `aegis-daemon` binaries ship in the
  same release assets for editor and service integrations

---

*Last Updated: 2026-09-07*
*Maintained by: Aegis Team*
