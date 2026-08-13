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
- **What**: Add tree-sitter for multi-language AST parsing
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

#### 8. Baseline Scanning System
- **What**: Add `.aegis-baseline` for known-finding suppression
- **Why**: Improves CI/CD UX for existing projects
- **Effort**: Low (1-2 weeks)
- **References**: detect-secrets baseline system

#### 9. Inline Allowlisting
- **What**: `# aegis:allow` style comments
- **Why**: Developer-friendly suppression
- **Effort**: Low (1 week)
- **References**: Gitleaks, detect-secrets inline comments

#### 10. Additional Output Formats
- **What**: JUnit, CSV, SPDX SBOM output
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
1. Add `tree-sitter` and `tree-sitter-languages` crates
2. Create AST-based scanner wrapper
3. Implement language-specific query patterns
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

*Last Updated: 2026-08-13*
*Maintained by: Aegis Team*
