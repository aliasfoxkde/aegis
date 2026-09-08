# Detection Patterns

Aegis ships **639 detection patterns** across **33 categories**.
Every pattern is compiled into every Aegis surface (CLI, MCP server,
daemon, WASM) from the source in `crates/aegis-patterns/src/`.

This index is the entry point; each category has its own page under
[`categories/`](./categories/) with the full detail for every pattern —
regex, scoping, tags, reference links, and a verified example input.

> This documentation is generated from the pattern source. Regenerate
> with `cargo run -p aegis-patterns --example generate_docs`; a freshness
> test (`registry_hygiene.rs`) fails CI when the committed pages drift.

## How a pattern works

Each pattern is a regex plus scoping and scoring metadata:

- **Match** — a Rust `regex`-syntax pattern matched against candidate
  file content (or environment values for `scope: environment` rules).
- **Severity** — `critical` (40 points), `high` (25), `medium` (10), or
  `low` (3) in the risk score; findings also drive the exit code.
- **Confidence** — `high` (×1.0), `medium` (×0.7), or `low` (×0.4)
  multiplier applied to the severity weight.
- **Entropy floor** — optional minimum Shannon entropy a match must
  reach, which filters low-entropy placeholder strings.
- **File extensions** — when set, the pattern only runs on files with a
  listed extension; empty means every text file.
- **Exclude** — an optional regex matched against the candidate match
  span; a hit suppresses the finding (used to exempt documentation
  examples and safe idioms).
- **Scope** — file rules scan content; `scope: environment` rules only
  run during `aegis scan --env`.

Every pattern ships enabled, and every pattern has a provably firing
example enforced by the liveness test (`pattern_liveness.rs` in CI).

## Severity distribution

| Severity | Patterns |
|----------|----------|
| critical | 69 |
| high | 131 |
| medium | 175 |
| low | 264 |

## Categories

| Category | Patterns | Description |
|----------|----------|-------------|
| [accessibility](./categories/accessibility.md) | 28 | WCAG 2.x success criteria for markup, media, and styles |
| [ai-detection](./categories/ai-detection.md) | 28 | Informative markers of likely AI-generated code — triage signals, not verdicts |
| [ai-safety](./categories/ai-safety.md) | 25 | Agentic and LLM application safety checks |
| [api-integration](./categories/api-integration.md) | 9 | HTTP client and webhook integration mistakes |
| [arm](./categories/arm.md) | 2 | Azure Resource Manager template issues |
| [cloud-native](./categories/cloud-native.md) | 38 | Cloud-native build and runtime practices |
| [cloudformation](./categories/cloudformation.md) | 3 | AWS CloudFormation template issues |
| [code-quality](./categories/code-quality.md) | 15 | Language anti-patterns and dangerous constructs |
| [compliance](./categories/compliance.md) | 33 | Regulatory frameworks: GDPR, HIPAA, PCI-DSS, SOC 2 |
| [container](./categories/container.md) | 4 | Container build and runtime hardening |
| [data-visualization](./categories/data-visualization.md) | 5 | Charting and visualization pitfalls |
| [devops](./categories/devops.md) | 15 | CI/CD pipeline and deployment checks |
| [finance](./categories/finance.md) | 6 | Financial data handling rules |
| [frameworks](./categories/frameworks.md) | 31 | Web framework-specific issues |
| [git-hygiene](./categories/git-hygiene.md) | 28 | Repository hygiene: artifacts, debug files, history |
| [git-ops](./categories/git-ops.md) | 3 | GitOps workflow and manifest checks |
| [graphql](./categories/graphql.md) | 4 | GraphQL API security and usage |
| [healthcare](./categories/healthcare.md) | 7 | Clinical data and HIPAA-adjacent rules |
| [infrastructure](./categories/infrastructure.md) | 55 | Infrastructure as code security |
| [kubernetes](./categories/kubernetes.md) | 11 | Kubernetes manifest hardening |
| [llm-guardrails](./categories/llm-guardrails.md) | 25 | Prompt-injection and LLM guardrail checks |
| [metadata](./categories/metadata.md) | 4 | Metadata and editor configuration leaks |
| [performance](./categories/performance.md) | 20 | Performance anti-patterns |
| [pii](./categories/pii.md) | 39 | Personal data: emails, phones, national IDs |
| [pwa](./categories/pwa.md) | 5 | Progressive web app checks |
| [secrets](./categories/secrets.md) | 41 | Credentials, API keys, and tokens |
| [security-hardening](./categories/security-hardening.md) | 32 | General hardening practices |
| [shift-left](./categories/shift-left.md) | 20 | Early-lifecycle security practices |
| [supply-chain](./categories/supply-chain.md) | 35 | Dependency and artifact supply-chain rules |
| [terraform](./categories/terraform.md) | 7 | HashiCorp Terraform issues |
| [typescript](./categories/typescript.md) | 13 | TypeScript and typed-JavaScript rules |
| [web-development](./categories/web-development.md) | 11 | General web development checks |
| [web-security](./categories/web-security.md) | 37 | XSS, injection, CORS, and SSRF |
