# Aegis Systematic Enhancement Audit and Plan

**Prepared:** 2026-11-20  
**Status:** Refreshed against fetched `origin/main` (`db42bbe`). Phase 0 reconciliation is complete. Audit branch `codex/systematic-audit-20261120` contains the MCP/pattern hardening and handoff; draft PR #208 is open. CI run 44833384158 passed build/MSRV, formatting, three-OS tests, CodeQL, dependency policy, and the Aegis security scan, but failed Clippy, patch coverage (86.69% against 90%), and the Nature link check (publisher returned 503). Run 44834948808 exposed test compile errors in added coverage tests; the `json!` import and qualification diagnostics are fixed in the working tree. The Nature reference now points to the NCBI-hosted full-text record to avoid the publisher's 503; verify in the next link-check run.

## Executive assessment

Aegis has a strong engineering baseline: strict Rust lint and rustdoc gates, multi-OS CI, MSRV checks, dependency policy, fuzzing, Criterion benches, rule-liveness tests, a labeled precision/recall corpus, SARIF, receipts, and distinct CLI, MCP, daemon, bundler, and WASM surfaces. Recent local `origin/main` history also records fail-closed scan handling, secret triage, path classes, conformance fixtures, and patch coverage.

The largest product gap is evidence depth. Rule liveness proves that a rule can fire; it does not demonstrate that most rules are accurate in realistic code. The current corpus gate sets minimums of 10 expectations, 3 clean files, 3 negative files, and 5 pinned rules; per-rule precision engages at 2 observations and confidence calibration at 3 (`crates/aegis-core/tests/corpus_precision_recall.rs:35-61`). The second major gap is semantic depth: the feature called AST analysis is mostly line-based heuristics. Tree-sitter parse status is checked behind an optional feature, but the inspected path discards the syntax tree (`crates/aegis-core/src/ast/mod.rs:180-249,263-274,567-570,631-641`).

The initial checkout was `main` at `46cd30a`, 28 commits behind fetched `origin/main` (`db42bbe`) and two commits ahead, with substantial dirty MCP/pattern/docs work. That work was stashed, carried onto a new branch from `origin/main`, conflict-resolved, and reviewed; the resulting branch commits are `42d679d`, `76bdf09`, and `b6d8485`. The Sep 19 qualification report already exists identically on `origin/main`; the local-only handoff provenance was carried over and refreshed to the fetched baseline. The original stash is retained as a recovery copy. A non-writable `docs/audits` directory prevented checkout; tracked audit files were restored into a writable directory and the original directory was preserved as an untracked backup.

### Execution update — 2026-11-20

- **Implemented:** MCP scan and bundle work now runs on blocking workers; active configuration is retained across bundle updates; request concurrency is capped at 32, the response queue is bounded, overload returns `-32001`, and docs explain that cancellation stops response waiting while already-running blocking work continues under its admission slot. Added a regression for `graphql-batch-limit` matching `find -maxdepth`.
- **Local validation:** `cargo fmt --all -- --check` and `git diff --check` pass. Direct Cargo testing was blocked by the repository's NAS-build guard. Managed Aegis scan `723cd108-8d4a-404e-b668-4524841e448a` failed before scanning because the selected harness profile requires a missing `.aegis-baseline.json`; this is a harness configuration failure, not a scan result.
- **PR disposition:** #206 (`parking_lot` 0.13) was closed because it raises MSRV to 1.95, incompatible with the workspace's Rust 1.88 promise. #207's rerun passed all checks; the earlier macOS job was cancelled, not a code failure. #174's five owner-reviewed documentation defects were corrected and pushed as `5a31112`; it remains draft pending CI/review. #208 remains draft. Its first Ubuntu run exposed an ordering assumption in `full_mcp_client_lifecycle_in_one_session`; the test now correlates responses by ID, and the second run reached a test compile failure because the added unit tests lacked a macro import and had an overqualified type path. Those diagnostics were fixed in the latest working tree. Focused tests now cover timeout, handler failure, overload, cancellation, bundle loading, and blocking-task panic handling; CI must report patch coverage before we know whether further tests are needed.
- **Checkout cleanup:** 136 local branches and 15 worktrees were found. Pruning remote refs removed 13 stale tracking refs; three fully merged unattached local branches were safely deleted. Gone/unmerged refs, historical release refs, and attached worktrees remain preserved pending mapping to PRs and durable work. The pre-reconcile audit backup remains untracked because the original directory is owned by `nobody` and cannot be removed by this account.

## Scope and limits

Inspected manifests, source modules, tests/corpora, CI and release workflows, current plans/audits, and GitHub PR/check state. Three read-only reviews covered core/patterns, CI/release, and interfaces. The graph MCP route was unavailable in this terminal, so source relationships were inspected with direct reads and repository search. Formatting and diff checks ran. CI provided compiled/test validation; its first run exposed Clippy and coverage failures. The local scan profile did not run the scanner because its baseline input was absent. Resource and path-race risks still need focused verification.

## Strengths to preserve

- Strict Rust linting, rustdoc, three-OS tests, MSRV, dependency audit/deny, CodeQL, fuzzing, and coverage gates (`.github/workflows/ci.yml`).
- Rule liveness plus labeled positive/negative corpus tests (`crates/aegis-core/tests/pattern_liveness.rs`, `corpus_precision_recall.rs`); generated pattern documentation and drift checks in local `origin/main`.
- JSON/SARIF CLI output, MCP and daemon conformance fixtures, scan receipts, and recent fail-closed completeness work.
- Symlink-safe scanner defaults, ignore support, daemon canonical scan root and Unix peer-credential checks.
- Scripted releases, checksums, attestation metadata, release receipts, and a GitForge-first process.

## Findings

| ID | Priority | Finding | Evidence / implication |
|---|---|---|---|
| F0 | P0 | Stale, dirty checkout — **resolved** | Reconciled onto `origin/main` at `db42bbe`; local work is preserved in stash and on the audit branch, with merge conflicts resolved. Remaining untracked backup directory is preserved because its files are owned by `nobody` and not writable. |
| F1 | P1 | Rule efficacy is measured for a small slice of the catalog | Low corpus minimums and 2/3 observation gates mean most rules can remain unmeasured. Synthetic examples are a reachability guard, not realistic accuracy evidence. |
| F2 | P1 | AST analysis is largely lexical | Language-specific loops produce findings; tree-sitter parse status is checked but the syntax tree is discarded. Structural context, test-vs-production distinction, and API-call verification remain limited. |
| F3 | P1 | Recognized languages can imply unsupported coverage | `ast/mod.rs:96-124,183-195` recognizes Java/C/C++ while the inspected fallback analysis returns no findings. Users need a language × parser × analyzer coverage matrix and visible unsupported/lexical-only states. |
| F4 | P2 | Parse errors and partial findings lack a clearly stated shared policy | `ast/mod.rs:225-249` retains findings on parse errors, while scanner inspection records failure and can still merge findings (`scanner.rs:636-651,983-997`). Specify “partial findings, incomplete coverage” across outputs and wire APIs. |
| F5 | P2 | Clone detection is intra-file and skips short regions | `clone.rs:26-44,63-80`; scanner invokes it per source (`scanner.rs:954-955`). Cross-file detection needs a bounded index and its own precision/recall evidence. |
| F6 | P2 | Daemon scans are synchronous in async handlers; connections are spawned per client | Newer local source: `crates/aegis-daemon/src/main.rs:279-282`, `src/lib.rs:567-592`. Move heavy work to a blocking pool and bound clients/scans and idle/read duration. |
| F7 | P2 | MCP cancellation and path validation need follow-up | The audit branch moves scan and bundle work to blocking workers and caps request work/response buffering. Cancellation and timeout stop waiting for a response, but already-started blocking work continues while holding a slot. Path admission still canonicalizes for the check and later reads the original path, leaving a possible symlink check/use race under concurrent filesystem changes; descriptor-based containment is a separate security task. |
| F8 | P2 | Performance claims exceed measurements | Existing benches cover scanner initialization, pattern matching, and clone detection; `docs/PLAN.md` calls throughput/memory targets aspirational. Define representative workloads and measure peak memory/concurrency before setting SLOs. |
| F9 | P2 | Release and gate consistency can improve | Newer local `origin/main` `.github/workflows/bench.yml:56-63` ends a benchmark pipeline with `|| true`, hiding command failures. Manual release uses floating stable Rust and unpinned cargo-zigbuild (`release.yml:33-46`), unlike pinned container inputs. `publish.sh:75-82` requires expected assets to exist but does not require exact equality with the remote asset set. Coverage exclusions are duplicated and are not checked for parity by the inspected gate-parity script. |
| F10 | P2 | WASM has limited adoption guidance | `crates/aegis-wasm/src/lib.rs:77-124` exposes content scanning and pattern count; findings retain matched text. Add a JS/TS example and explain payload/privacy differences from native output. |
| F11 | P2 | Rule provenance is not consistently reviewable | Pattern metadata has stable IDs, category, severity/confidence, references, tags, exclusions, and extensions (`crates/aegis-patterns/src/lib.rs`), but no systematic per-rule scope, known false positives, evidence level, or realistic negative-case status. |
| F12 | P2 | Status docs disagree by age | Supplied `AGENTS.md` and checkout docs contain older state; local `origin/main` `AGENTS.md` still says 818 tests measured 2026-09-24 while its `docs/PLAN.md` records 949 in CI on 2026-11-16. Generate counts where possible and date receipts. |

### Research signals

Use these as design inputs rather than templates to copy. Gitleaks makes rule keywords, secret extraction, entropy, allowlists, and baselines explicit ([configuration](https://github.com/gitleaks/gitleaks#configuration), [baselines](https://github.com/gitleaks/gitleaks#creating-a-baseline)). CodeQL separates query precision from severity and publishes query rationale/remediation ([metadata](https://codeql.github.com/docs/writing-codeql-queries/metadata-for-codeql-queries/), [query help](https://codeql.github.com/docs/writing-codeql-queries/query-help-files/)). OpenSSF Scorecard treats tests, code review, fuzzing, pinned dependencies, signed releases, and security policy as distinct controls ([checks](https://github.com/ossf/scorecard#checks)). Aegis has many of these engineering controls; a periodic posture check can cover repository and operator controls beyond Rust tests.

## Phased roadmap and task ledger

All items are proposed and unassigned. Start dependent implementation only after its prerequisite and the current base are confirmed.

### Phase 0 — Trustworthy baseline

| Task | Priority | Done when |
|---|---|---|
| 0.1 Inventory incoming commits, local commits, tracked edits, and untracked files; classify each without discarding user work. | P0 | **Done:** work preserved, conflicts resolved, audit branch based on fetched main. |
| 0.2 Refresh remote refs and recheck source/CI findings against the actual target commit. | P0 | **Done for source baseline:** audit names `db42bbe`; recheck CI/PR failures as they are resolved. |
| 0.3 Refresh stale status claims using generated counts or dated receipts. | P1 | `AGENTS.md`, `docs/PLAN.md`, and release/test receipts agree on source and date. |

**Gate:** do not begin source changes from the stale branch. Preserve and review the dirty tree; no reset/overwrite operation is part of this plan.

### Phase 1 — Measure rule quality

| Task | Priority | Depends on | Done when |
|---|---|---|---|
| 1.1 Define separate metrics for liveness, positive corpus coverage, negative/clean coverage, observations, and measured precision by rule/category/language. | P1 | 0.2 | Deterministic CI report distinguishes “live” from “validated” and “unmeasured.” |
| 1.2 Grow labeled fixtures risk-first: secrets/auth, injection/web, IaC/container/cloud, then lower-risk rules. Include realistic positives and adversarial near-misses. | P1 | 1.1 | High-severity rules have reviewed positive and negative evidence; category coverage is reported. |
| 1.3 Calibrate confidence from adequate samples, report sample sizes, and keep changes demote-only until evidence justifies promotion. | P1 | 1.1, 1.2 | No low-evidence rule is presented as measured; thresholds only ratchet from evidence. |
| 1.4 Add a rule-review checklist: rationale, source/reference, scope, false positives, evidence, and test fixtures. | P2 | 1.2 | Each new or materially changed rule has reviewable evidence. |

**Gate:** generated examples remain a dead-rule guard and do not count as realistic precision evidence.

### Phase 2 — Honest language support and semantics

| Task | Priority | Depends on | Done when |
|---|---|---|---|
| 2.1 Publish a language matrix separating recognized file type, lexical coverage, parser availability/default, AST rules, and dataflow rules. | P1 | 0.2 | Unsupported and lexical-only states are visible to users. |
| 2.2 Define parse-error/partial-finding semantics for CLI, MCP, daemon, SARIF, JSON, and WASM. | P1 | 2.1 | Shared contract and fixtures ensure incomplete scans cannot look clean and complete. |
| 2.3 Pilot AST-backed rules in one high-value language (Python or JS/TS): call arguments, imports, route decorators, and test-vs-production context. | P1 | 2.1, 2.2 | Positive, negative, malformed-source, and parser-version cases are pinned; lexical rules remain during migration. |
| 2.4 Add source-to-sink/API-call verification only after the pilot demonstrates reliable parsing and corpus gains. | P2 | 2.3 | Explanations identify source/sink/argument path; precision improves without broad scan regressions. |
| 2.5 Evaluate optional cross-file clone indexing with CPU/memory budgets. | P2 | 1.2 | Accuracy and performance are measured before changing current intra-file behavior. |

**Gate:** parser failures stay visible; no silent conversion from parse failure to “no issue.”

### Phase 3 — Long-running interfaces and resource bounds

| Task | Priority | Depends on | Done when |
|---|---|---|---|
| 3.1 Independently review the in-flight MCP diff for cancellation, bounded queues/concurrency, configuration races, and canonical-path use. | P1 | 0.1 | **Partially done:** config races and overload/queue bounds addressed in `42d679d`; cancellation work lifetime and canonical-path check/use gap remain. |
| 3.2 Move daemon scans to blocking execution and bound active clients/scans plus idle/read duration. | P2 | 0.2 | Wire cases cover saturation, timeout, disconnect, and recovery; defaults are documented. |
| 3.3 Decide whether MCP and daemon share a core admission/resource policy. | P2 | 3.1, 3.2 | Shared policy or explicit rationale for different limits. |

**Gate:** do not widen daemon exposure or weaken current local-socket/stdio boundaries as part of this work.

### Phase 4 — Measurable performance

| Task | Priority | Depends on | Done when |
|---|---|---|---|
| 4.1 Define repeatable workloads by file count, size, extension mix, and rule set. | P2 | 0.2 | Workload manifest is reproducible. |
| 4.2 Measure cold/warm start, throughput, peak RSS, concurrency, parser cost, and clone cost with toolchain/host/commit receipts. | P2 | 4.1 | Bench output supports like-for-like comparisons. |
| 4.3 Fix benchmark failure masking; set regression thresholds only after stable baselines. | P2 | 4.2 | A failed `cargo bench` fails the job; threshold changes cite measurements. |

### Phase 5 — Consumer and authoring experience

| Task | Priority | Depends on | Done when |
|---|---|---|---|
| 5.1 Add a browser JS/TS WASM example, including build/init/options/output and handling of matched source text. | P2 | 0.2 | Example works from documented commands and payload differences are clear. |
| 5.2 Version and document finding/completeness/triage/receipt contracts across surfaces. | P2 | 2.2 | Golden fixtures cover each surface; release notes describe changes. |
| 5.3 Extend rule metadata/docs with scope, false-positive notes, evidence status, remediation, and applicable languages. | P2 | 1.1 | Generated catalog exposes this for every rule; new rules meet the authoring contract. |

### Phase 6 — Supply chain and assurance

| Task | Priority | Depends on | Done when |
|---|---|---|---|
| 6.1 Remove benchmark `|| true` while keeping performance deltas non-gating; report parse/display failures separately. | P1 | 0.2 | Injected benchmark failure is red with logs preserved. |
| 6.2 Align GitForge and GitHub release toolchains (Rust, Zig, cargo-zigbuild, linkers). | P2 | 0.2 | Both paths use pinned inputs or document qualified differences. |
| 6.3 Require the remote release asset set to equal the expected manifest before publishing. | P2 | 6.2 | Missing, extra, or mismatched assets block publication and leave a recoverable draft. |
| 6.4 Add parity checks for duplicated coverage exclusions and gate policy. | P2 | 0.2 | A drift fixture proves mismatch fails CI. |
| 6.5 Review signing and independent verification of release artifacts/attestations. | P2 | 6.2 | Trust chain and clean-machine verification are documented; unsigned checksums are not described as signatures. |
| 6.6 Periodically assess an agreed Scorecard/OSPS subset and separate repo controls from operator/platform-owned items. | P3 | 0.2 | Dated posture report has evidence and explicit exclusions. |

## Recommended order

1. Push the current focused tests/lint/link fixes, then resolve any remaining PR #208 coverage deficit without weakening the gate; require the complete CI set to pass before promoting or merging it.
2. Re-run managed scanning with a profile that does not require a nonexistent baseline, and save the scan receipt.
3. Map remaining branches/worktrees to open PRs and durable work before deleting further refs.
4. Confirm CI/review disposition for corrected draft PR #174; #206 is closed for MSRV incompatibility and #207's rerun is green.
5. Revalidate the 2026-11-16 gap analysis against refreshed main and close only remaining verified issues.
6. Establish per-rule evidence metrics and grow the realistic corpus before adding large rule batches.
7. Publish honest language coverage, then pilot parser-backed rules.
8. Address daemon resource bounds and the MCP path check/use gap; then establish representative performance baselines.
9. Improve WASM/consumer docs, rule authoring metadata, and release/gate parity after contracts stabilize.

## Cross-cutting acceptance gates

- Every scan surface reports completeness; “no findings” is clean only when inspection completed.
- Every detection change has positive and meaningful near-miss/clean evidence; liveness and efficacy remain separate.
- Keep suppressions narrow, explained, attributable, and measurable; do not use broad exclusions to hide noisy rules.
- Measure parser/clone cost before widening defaults; make memory and concurrency budgets explicit.
- Keep output changes fixture-backed across CLI, MCP, daemon, and WASM.
- Do not weaken lint, coverage, security, license, or release gates to ease implementation.
- Report missing receipts and partial results as unknown/incomplete, never success.

## First ticket after Phase 0

**Rule evidence coverage report v1** is the recommended first product-quality task. It adds no detection behavior and makes the central uncertainty observable. Report, per category and language: generated liveness status; realistic positive corpus presence; negative/clean corpus presence; observation count; measured precision; and unmeasured rules. Start informational; only introduce category-specific gates after sufficient evidence exists to justify thresholds.

## References

- Existing roadmap: `docs/PLAN.md` on local `origin/main` (dated 2026-11-17).
- Prior known-gap closure report: `docs/audits/2026-11-16-gap-analysis.md` on local `origin/main`.
- Core evidence: `crates/aegis-patterns/src/lib.rs`; `crates/aegis-core/tests/pattern_liveness.rs`; `crates/aegis-core/tests/corpus_precision_recall.rs`; `crates/aegis-core/src/ast/mod.rs`.
- Interfaces/release evidence: `.github/workflows/ci.yml`; `.github/workflows/bench.yml`; `.github/workflows/release.yml`; `scripts/release/publish.sh`; MCP, daemon, and WASM sources.
