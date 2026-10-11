# Aegis SARIF → GitHub code-scanning consumer parity (D-11 implementation)

**Date:** 2026-10-11
**Author:** GLM-5.3-Flash agent session (Anthropic Claude Agent SDK), docs-only
handoff task. Written in the isolated NVMe worktree
`/home/mkinney/worktrees/pa-handoff-aegis-20261011`. No product code, no
fixtures, no builds, no measurement runs were produced by this document.
**Base revision:** Aegis `9bf61f3` (= merge of PR #168; `origin/main` is one
commit ahead at `bebadc7`, PR #172, `crates/aegis-mcp` tests only — no file
this plan touches). All Aegis citations below were read directly from this
tree at `9bf61f3`.
**Status:** Proposal. Nothing here is implemented, measured, or ratified.
Every threshold/mapping introduced is labeled **PROPOSED** until the
operator signs off.

---

## 0. How to read this document

Evidence labels, as in `docs/handoffs/2026-10-11-aegis-atheon-parity-and-rollout.md`:

| Label | Meaning |
|---|---|
| **VERIFIED** | Read directly from source/docs in this pinned tree, file+line cited; reproducible by the command given in §9. |
| **MEASURED** | Command output captured 2026-10-11 in this tree (§9.2). |
| **INFERRED** | Reasoned from cited source; reasoning stated and checkable. |
| **UNKNOWN** | Searched and not found, or not determinable without an external test. Listed in §7, never guessed at. |
| **PROPOSED** | A mapping, threshold, or decision this document introduces. Requires operator ratification. |

Aegis citations are repo-relative. Atheon citations are inherited from the
parity handoff (§3.6 there), pinned to Atheon-Enhanced `bc42edf`
(tags `v1.5.4-enhanced`/`v1.5.5-enhanced`), and were re-verified there on
2026-10-11; they are not re-audited here. GitHub-side contract statements
come from the fetched docs page named in §9.3 (fetched 2026-10-11).

No markdown hyperlinks appear in this file (the CI `Links` job lints
`docs/**/*.md` with lychee; the sibling handoff in this directory uses the
same zero-link convention). All references are backticked paths.

---

## 1. Objective and success definition

**Objective.** Close divergence **D-11** from the ratified parity plan:
Aegis SARIF carries no CWE identifiers and no GitHub `security-severity`,
while Atheon emits both. Today a GitHub code-scanning consumer of Aegis
SARIF gets severity only through the coarse `level` map (error/warning/note);
the docs document no CWE display for third-party uploads at all (§3.4-2),
so any display benefit is tested, not assumed (P0-2). This handoff defines the
implementation work to make Aegis SARIF a first-class GitHub code-scanning
payload, and thereby removes the named P1 promotion blocker in the parity
plan's divergence register.

**Success is all of:**

1. Every SARIF rule in an operator-ratified security category carries the
   `security` tag. It carries `security-severity` only when DEC-1 defines a
   score for that severity; `info` and unknown severities omit the property.
   Non-security categories carry neither field. Tests pin these cases
   separately (§5 P1).
2. Every SARIF rule carries `helpUri` when its pattern has a reference URL
   (VERIFIED feasible: `Finding.reference` already exists and flows to
   findings today).
3. CWE identifiers exist as first-class pattern metadata and are emitted in
   SARIF (and JSON) findings, with per-rule coverage measured — the
   baseline is 4 distinct CWE ids across the whole 677-rule registry
   (MEASURED, §9.2) — and every rule without a CWE id carries either a
   ratified "no CWE applies" waiver or sits outside the security category
   set (§5 P2).
4. Scan behavior is provably unchanged: findings, exit codes, and ledger
   are byte-identical before/after on the repo self-scan and the corpus
   gates (§5 P4). This is a metadata-and-serialization change only; it
   must never touch a regex.
5. The D-11 row in the parity handoff is updated from "Decision: extend
   Aegis SARIF or accept loss" to the recorded decision with evidence, and
   parity-plan task C-3 (SARIF consumer check) can execute against the new
   shape.

---

## 2. Scope selection — why this, why now

### 2.1 Active fronts excluded (worktree/PR overlap check, 2026-10-11)

Checked before selecting scope: open PRs and their changed files
(`gh pr diff --name-only`, §9.2), the git worktree list, and
`agent-locks list` (no active locks).

| Front | PR / worktree | Files touched | Conflict with this plan |
|---|---|---|---|
| Scan-status & diff-attribution hardening | PR #169 (draft), worktree `aegis-scan-hardening-mainline-20261011` | `crates/aegis-core/src/scanner.rs`, `crates/aegis-core/src/finding.rs`, `crates/aegis-cli/src/scanner.rs`, `scripts/ci/classify_aegis_sarif.py` (+docs, `.gitforce.yml`) | None on `crates/aegis-cli/src/output.rs`. Its new classifier script reads only `runs[].properties.inspectionLedger` — it does not constrain rule metadata (§9.2). **Caveat:** it edits `crates/aegis-core/src/finding.rs`, which P2 also edits; branch P2 after #169 merges. |
| Diff header correctness / EOF fail-closed | PRs #170, #171 (drafts) | `crates/aegis-core/src/scanner.rs` + `scanner_behaviors.rs` only | None |
| MCP sandbox boundary tests | worktree `aegis-parity-corpus-s2-20261011`, branch `codex/aegis-mcp-path-safety-audit-20261011` (head `bee833c`) | `crates/aegis-mcp` tests/docs | None |
| Dependency bumps | PR #173 | `Cargo.lock` | None |

No open PR or worktree touches `crates/aegis-cli/src/output.rs`, the
pattern modules' reference/tags metadata, or SARIF shape. This plan owns
those files exclusively.

### 2.2 Candidates considered and rejected

- **D-01 partial-failure exit semantics (P0 in the parity register):**
  already owned by the in-flight hardening wave — PR #169 ships the
  fail-closed ledger classifier (`scripts/ci/classify_aegis_sarif.py`)
  and its scanner-side predicate work. Starting D-01 here would duplicate
  active work.
- **Gitleaks-style proximity matching** (`docs/ENHANCEMENT_ROADMAP.md`
  item 3, "Low effort 1–2 weeks"): an engine-hot-path change landing in
  `crates/aegis-core/src/scanner.rs` — the single file three open PRs are
  mutating right now. Wrong moment; guaranteed merge friction.
- **Phase 14 ML/regex hybrid & AST API verification** (`docs/PLAN.md`
  Phase 14 via `docs/planning/HANDOFF.md:277-283`): 4–8+ week research
  tracks, not an implementation handoff; also corpus-bounded (Known Issue
  4) before they can even be evaluated.
- **Per-rule precision corpus growth:** unbounded data work; subsumed by
  parity-plan S2 when that lane starts.
- **SARIF CWE/security-severity (this plan):** P1 in the parity register
  (D-11), explicitly blocking the *promotion claim* (parity handoff §3.6
  "Consumer-facing gap"); zero file overlap with active fronts; bounded
  scope with a hard, testable equivalence guarantee (metadata-only); and
  standalone product value for any GitHub code-scanning consumer, not
  just the migration.

### 2.3 Position relative to the parity plan

This plan does not replace parity-plan S1/C-3 — it *supplies their missing
input*: S1's mapping freeze defers "the CWE decision for D-11" and C-3
measures the SARIF delta. Implementing D-11 before C-3 shrinks the delta C-3
has to adjudicate, and the GitHub-contract facts in §3.4 (including the
correction to the parity plan's CWE assumption, §3.4-2, and the
fingerprint-path facts that reframe DEC-5, §3.4-4) are exactly the
decision inputs S1 asked for.

---

## 3. Current state — evidence

### 3.1 The SARIF emitter today (VERIFIED, this tree)

All in `crates/aegis-cli/src/output.rs`:

- `Output::write_sarif`, lines **166–308**: hand-rolled serde structs;
  SARIF `version: "2.1.0"` at **:289**; run carries `tool.driver`
  (`name`, `version`, `rules[]`), `results[]`, and
  `properties.inspectionLedger` (**:299–301**).
- `SarifRule` is exactly `{ id, name }` — lines **205–209**. No `helpUri`,
  no `properties`, no tags, no CWE. (Sweep: `grep -n 'helpUri'` across
  `crates/` → zero hits.)
- `SarifResult` is `{ ruleId, level, message, locations }` — lines
  **211–218**. No `partialFingerprints`, no per-result properties.
- The `rules` array is built **from the findings of this run only**
  (rules_map over `findings`, lines **251–264**): a rule that produced no
  finding in a given run never appears in `driver.rules`. Any rule-level
  metadata feature inherits this shape — see §4 decision DEC-3.
- Severity→level map `severity_to_sarif_level`, lines **317–324**:
  critical/high→`error`, medium→`warning`, low/info→`note`, else `none`.
  Documented contract: `PLATFORM_INTEGRATION.md:114`.
- Existing tests pinning this shape: `test_output_write_findings_sarif`
  (**:518**), `test_output_sarif_never_carries_clones` (**:657**),
  `test_severity_to_sarif_level` (**:676**),
  `test_output_sarif_with_multiple_findings` (**:738**), plus
  `test_scan_sarif_output` in
  `crates/aegis-cli/tests/cli_integration.rs:119-136`.

### 3.2 Metadata that already exists and can carry the new fields (VERIFIED)

- `Finding` (`crates/aegis-core/src/finding.rs:89-130`, serde
  `Serialize`/`Deserialize` at **:88**) carries `reference: Option<String>`
  (**:113**), `remediation` (**:116**), `tags: Vec<String>` (**:119**),
  `fingerprint` (**:127**), `stable_id` (**:130**). JSON output serializes
  findings directly (`write_json`, `output.rs:146-164`), so these fields
  are already consumer-visible in `--format json`.
- **`stable_id` is content-free** — `"aegis-" + sha256("pattern|category|
  file|line|column")` (`finding.rs:152-160`). It is the safe candidate for
  an **Aegis supplemental** `partialFingerprints` key — safe because it
  hashes only locator fields, never matched content. It is not a key
  GitHub documents consuming: code scanning "only uses the
  `primaryLocationLineHash`" (§3.4-4). Corrected framing in DEC-5.
- **`fingerprint` is content-derived** — includes
  `sha256(matched_content)` (`finding.rs:147-150`). It must **not** be
  exposed in an uploaded artifact: a SHA-256 of a matched secret is an
  offline-confirmation oracle for low-entropy secrets. See §4 DEC-5.
- `Pattern` (`crates/aegis-patterns/src/lib.rs:37-77`) carries
  `reference` (doc: "Optional URL to the CWE, standard, or vendor page
  behind the rule", **:56-58**) and `tags` (**:59-61**). The
  `From<Pattern> for aegis_core::PatternDefinition` conversion
  (**:84-106**, doc comment: "the single place the two are mapped") is
  where any new CWE field must be threaded; note it currently hard-codes
  `remediation: None` (**:103**).

### 3.3 CWE coverage baseline (MEASURED, §9.2)

- Registry: 677 shipped rules across 35 categories (inherited from the
  parity handoff §2.1, measured there at the parent commit; category
  distribution re-measured here, top categories: infrastructure 55,
  secrets 41, pii 39, cloud-native 38, web-security 37, supply-chain 35 —
  full table in §9.2).
- Rules carrying a `cwe.mitre.org` reference: **2 module files, 4 distinct
  CWE ids total** (CWE-208 `cryptography.rs:168`, CWE-532/CWE-598/
  CWE-295 `api_integration.rs:55,79,101`). 392 `reference: Some(...)`
  entries exist overall, but nearly all point at vendor/standard pages
  that are not CWE.
- Consequence: "derive CWE from existing reference URLs" covers ~0.6% of
  the registry. A per-rule CWE mapping table is the real work item (§5 P2).

### 3.4 The consumer contract (VERIFIED against GitHub docs, 2026-10-11)

From `docs.github.com` → "SARIF support for code scanning" (§9.3):

1. **`properties.security-severity` is supported on rules**
   (`reportingDescriptor`), as a string score, 0.1–10.0. GitHub bands:
   >9.0 critical, 7.0–8.9 high, 4.0–6.9 medium, 0.1–3.9 low; `0.0` or
   out-of-range means "no security severity". Documented as "Recommended
   only for security rules".
2. **CWE display is NOT documented.** The page's supported-fields tables
   contain no `taxonomies` array, and state the rest of the supported
   fields are ignored. Rule `properties.tags[]` are documented for
   filtering (max 20 tags/rule, 10 displayed), with no CWE-specific tag
   documented.
   **This corrects the parity plan's working assumption** (its §3.6 treats
   Atheon's CWE taxonomies as a consumer-facing gap on the assumption
   GitHub consumes them). For third-party uploads, the GitHub display
   benefit of `taxonomies` is **UNKNOWN** until tested (P0-2). Atheon
   emits them at the pin (`cmd/atheon/main.go:782-795,800-826`, per the
   parity handoff §3.6), so emitting them is still an Atheon-parity and
   SARIF-2.1.0-correctness argument — but the plan below refuses to claim
   a GitHub display win without P0 evidence (same anti-fib rule as parity
   gate PR-5).
3. The doc's security-severity row carries the qualifier "for security
   queries (`@tags` includes `security`)" — CodeQL phrasing. Whether the
   `security` tag requirement gates third-party uploads is **UNKNOWN**
   (P0-1). Cheap to satisfy anyway: emit `security` among rule tags for
   ratified security categories (PROPOSED, DEC-2).
4. **Alert matching: GitHub uses `partialFingerprints`, and the only key
   it documents using is `primaryLocationLineHash`.** The "Fingerprint
   generation" section: GitHub uses `partialFingerprints` to detect when
   two results are logically identical, and consistent filepaths across
   runs are the precondition for a stable fingerprint. The docs draw a
   path asymmetry: with the `upload-sarif` action, missing
   `partialFingerprints` are populated from the source files; via the
   `/code-scanning/sarifs` API, uploading without fingerprint data still
   processes and displays alerts but "users may see duplicate alerts",
   so the docs say to populate `partialFingerprints` before upload
   (citing the action's `fingerprints.ts` as a starting point). The
   result-object row is explicit: "Code scanning only uses the
   `primaryLocationLineHash`." No custom key — including any Aegis
   supplemental key — is documented as consumed. **This reframes
   DEC-5**: `{"aegisStableId/v1": ...}` is SARIF-legal supplemental
   data, not a documented GitHub alert-identity mechanism. P0-3 may record
   observed alert outcomes for its exact synthetic fixture, route, and
   versions; it cannot establish that the custom key caused or guarantees
   deduplication.

### 3.5 The Atheon side (inherited evidence, pin `bc42edf`)

Atheon SARIF emits: SARIF 2.1.0; GitHub `security-severity` mapping
(`cmd/atheon/main.go:782-795`); CWE taxonomies via `categoryCWE`/`ruleCWE`
(`:800-826`); redacted snippets (`:944`) — parity handoff §3.6, re-verified
2026-10-11 at the clean pin. Aegis need not copy Atheon's score values, but
P2 should transcribe them as the starting point for score parity
(DEC-1 note).

---

## 4. Decision register (ratify at P0/P1 exit)

| ID | Decision | Status |
|---|---|---|
| DEC-1 | Severity→`security-severity` score map. **PROPOSED:** critical→`"9.5"`, high→`"8.5"`, medium→`"5.5"`, low→`"2.0"` (mid-band per GitHub's documented bands, §3.4-1); `info` and unknown → property **omitted** (never `"0.0"`, which GitHub reads as "no severity" — acceptable, but omission is honest and shorter). Alternatives: copy Atheon's exact scores from the pin (score parity) — operator picks one; if Atheon's values are transcribed, record them here. | PROPOSED |
| DEC-2 | Which rules get `security` tag + `security-severity`. **PROPOSED seed:** all categories **except** the non-security quality set `accessibility, code-quality, data-visualization, performance, pwa, web-development, metadata, typescript, frameworks, finance, healthcare`. Operator ratifies the exclusion list at P1 exit; the ratified list becomes a test fixture, not prose. Rationale: Aegis is a security scanner; the burden of proof sits on exclusion, not inclusion. | PROPOSED |
| DEC-3 | Rules array is findings-derived today (`output.rs:251-264`). Options: (a) keep findings-derived and accept metadata appearing only for rules that fired; (b) switch `driver.rules` to the full enabled registry via the aegis-patterns catalog. **PROPOSED:** (a) for P1 (no dependency on patterns crate in the CLI output path, zero behavior risk), revisit (b) only if P0-2 shows GitHub needs stable rule inventory across runs. | PROPOSED |
| DEC-4 | Emit `taxonomies[]` for CWE? Emit it as SARIF-2.1.0-correct output + Atheon parity regardless of P0-2 outcome, but the docs and CHANGELOG may claim GitHub display **only** with P0-2 evidence. | PROPOSED |
| DEC-5 | **No production `partialFingerprints` in this phase.** (a) GitHub documents `primaryLocationLineHash` as the key it uses (§3.4-4); it does not document any custom key as consumed. Aegis does not emit a line hash because it would expose a source-line-derived hash, which may include a detected secret. (b) `{"aegisStableId/v1": <stable_id>}` is SARIF-legal and content-safe (`finding.rs:152-160`), but this handoff does not implement it: there is no demonstrated GitHub benefit. P0-3 may record a narrowly scoped observed result for its synthetic fixture; it cannot establish that GitHub recognizes the custom key or guarantee alert lineage. (c) **Never emit `fingerprint`** — it embeds `sha256(matched_content)` (`finding.rs:147-150`), an offline oracle against low-entropy secrets. | PROPOSED (rule (c) is not negotiable without operator sign-off) |
| DEC-6 | `severity_to_sarif_level` (`output.rs:317-324`) stays byte-identical. The `level` map plus the ledger is a consumed contract (PR #169's classifier, `PLATFORM_INTEGRATION.md:114`); this plan adds fields, never moves existing ones. | DECIDED |

---

## 5. Phased plan

Roles, as in the parity plan: **operator** (ratification, waivers),
**aegis-maintainer** (repo write access), **parity-analyst** (read-only
mapping/evidence), **infra-operator** (GitHub-side tests, lanes).

Dependency chain: **P0 ∥ P1 → P2 → P3 → P4**. P1 is landable within days
and delivers most of the consumer value; P2 is the long pole (data work);
P3/P4 are small.

### P0 — Contract pin (no product change)

| Field | Content |
|---|---|
| Task | (P0-1) In a throwaway GitHub repo, upload minimal SARIF variants through the supported code-scanning action: (i) rule with `security-severity` only; (ii) same + `security` in rule tags. Record the observed severity behavior without generalizing beyond this repository/tool version. (P0-2) Test whether CWE/taxonomy metadata from a third-party SARIF upload is accepted and displayed; record unknown or unavailable UI behavior as unknown. (P0-3) In a disposable repository with a harmless synthetic finding (no secret or sensitive source line), compare repeated uploads across two commits using the `upload-sarif` action and the SARIF API: omit fingerprints, include only the proposed Aegis supplemental key, and include a valid `primaryLocationLineHash` only in the synthetic fixture. Record action/API versions, upload IDs, and whether the same finding remains one alert or duplicates. This is an empirical compatibility probe, not permission to add source-content hashes to production Aegis output. |
| Owner / model role | infra-operator executes; operator reads results; parity-analyst drafts the sample SARIFs from `output.rs:166-308` shape |
| Validation | Reproducible SARIF fixtures and a dated evidence receipt stored under `docs/handoffs/2026-10-11-sarif-contract-p0/` (or a linked evidence repo); record action version, API path, commit, upload ID, and observed result for each run. Do not store source lines containing real secrets. |
| Acceptance | DEC-1/DEC-2/DEC-4 clauses that were PROPOSED-pending-P0 are flipped to DECIDED only where the evidence answers them. DEC-5 stays no-fingerprint for production in this phase; record the synthetic probe observation without inferring that GitHub recognizes a custom key or guarantees lineage. Resolve or preserve UNKNOWN items §7.2 explicitly. |
| Risks | Uses a code-scanning enable on a scratch repo — disposable; nothing touches production lanes |
| Rollback | n/a (evidence only) |

### P1 — Rule metadata in SARIF (small, immediate)

| Field | Content |
|---|---|
| Task | In `crates/aegis-cli/src/output.rs`: add SARIF rule `properties` (`tags`, `security-severity`) and `helpUri` to `SarifRule` (**:205-209**); forward `Finding.tags`/`Finding.reference` (already serde-visible, `finding.rs:113,119`). Apply DEC-1 scores + DEC-2 category list (the list lives as a const table with a doc comment naming the ratifying decision record). Do not add `partialFingerprints` in this phase: the custom key has no documented GitHub behavior, and the recognized line hash is excluded by the source-content hash rule. Do not touch `severity_to_sarif_level` (DEC-6). |
| Source target | `crates/aegis-cli/src/output.rs` only (plus its tests) |
| Owner / model role | aegis-maintainer / standard model for the mechanical emission; heavy-reasoning review for the category list and score map |
| Validation | `cargo test -p aegis-cli --lib output` (extends the four shape-pinning tests, §3.1); `cargo test -p aegis-cli --test cli_integration`; full gates per §6 |
| Acceptance | (1) SARIF fixtures assert: security-category rules have the `security` tag; mapped severities have `security-severity` == DEC-1; `info`/unknown severities omit it; excluded-category rules have neither; `helpUri` is present iff reference. No `partialFingerprints` or content-derived `fingerprint` is emitted in this phase. (2) `--format json` and exit codes unchanged (DEC-6 test). (3) Equivalence proof (§6) green. (4) Documentation reports only the P0-3 synthetic observation and does not claim a custom key is GitHub-recognized or guarantees alert lineage. |
| Risks | Downstream strict SARIF validators choking on new fields — mitigated: all added fields are documented SARIF/`reportingDescriptor` members; validate with a SARIF 2.1.0 schema check in tests (P0 artifacts can carry the schema reference) |
| Rollback | Revert the PR; consumers that appeared meanwhile read only added fields |

### P2 — CWE data layer (the long pole)

| Field | Content |
|---|---|
| Task | Add `cwe_ids: Vec<String>` (canonical form `CWE-<int>`) to `Pattern` (`crates/aegis-patterns/src/lib.rs:37-77`), to `aegis_core::PatternDefinition`, and to `Finding` — threaded through the canonical `From` conversion (**lib.rs:84-106**, which P2 must not let drift from its "single place" contract). Populate via: (a) per-rule table for the security categories ratified in DEC-2, starting by transcribing Atheon's `ruleCWE`/`categoryCWE` mappings from the pin (§3.5) where rules correspond, then completing rule-by-rule; (b) a category-level default for rules where a single CWE genuinely covers the category (used sparingly — wrong CWEs are worse than none); (c) explicit waiver rows for rules with no defensible CWE. Target: every rule in a DEC-2 security category carries CWE ids or a waiver. Non-security categories are out of scope by design. |
| Source target | `crates/aegis-patterns/src/*.rs`, `crates/aegis-core/src/finding.rs` (+ `crates/aegis-core/src/pattern.rs` for `PatternDefinition`), generated `docs/patterns/` |
| Owner / model role | parity-analyst drafts the mapping table (heavy-reasoning model for rule→CWE judgment); aegis-maintainer applies + runs the regeneration loop; operator adjudicates disputed rows and signs waivers |
| Validation | **The full pattern authoring loop is mandatory** (`docs/planning/HANDOFF.md:53-63`): `cargo run -p aegis-patterns --example dump_patterns`, `scripts/generate_examples.py`, `--example generate_docs`, then `cargo test -p aegis-core --test pattern_liveness` and the registry-hygiene docs-freshness test. Plus the corpus lane (`corpus_precision_recall`) per the standing rule that pattern-file edits always run it — even though this change cannot alter matching, the lane is the proof. |
| Acceptance | (1) Registry hygiene + liveness + corpus gates green. (2) Coverage report committed: N rules in security categories, M with CWE ids, W waived, M+W == N. (3) Equivalence proof (§6) green — zero finding delta. (4) `Finding.cwe_ids` serializes in JSON (additive; consumers that don't know it are unaffected — VERIFIED pattern: `Finding` is plain serde, `finding.rs:88`). |
| Risks | Branch collision with PR #169 on `crates/aegis-core/src/finding.rs` (§2.1) — sequence P2 to start after #169 merges; if #169 stalls, rebase discipline over its head commit. Wrong-CWE noise (rule mapped to a fashionable-but-wrong CWE) — mitigated by the waiver option and operator adjudication. WASM crate serializes `Finding` too — additive field needs no API change but `crates/aegis-wasm` tests must run. |
| Rollback | Test-only + additive metadata; revert the PR. The mapping table should live in one module so retraction is one file. |

### P3 — CWE into SARIF (+ taxonomy decision)

| Field | Content |
|---|---|
| Task | `SarifRule` gains CWE in `properties` (e.g. `properties.cwe` or tags `cwe-532` style — match whatever P0-2 showed GitHub honors; SARIF-standards-correct taxonomies per DEC-4 otherwise). `SarifResult` unchanged beyond P1. Update `PLATFORM_INTEGRATION.md:114` (the documented SARIF contract) and `docs/guides/CICD_INTEGRATION.md:210-218` (the "Upload SARIF to GitHub Security tab" section) to state exactly what is emitted and what GitHub does with it — with the P0 evidence caveat, per DEC-4. CHANGELOG under Unreleased. |
| Owner / model role | aegis-maintainer / standard model |
| Validation | Same test set as P1 + a fixture asserting CWE appears for a mapped rule and is absent for a waived one |
| Acceptance | Docs and code agree verbatim (the docs-freshness discipline applied to the platform contract); D-11 row in the parity handoff updated to "implemented, evidence: this file" |
| Risks | None beyond P1's (same mechanism) |
| Rollback | Revert PR |

### P4 — Conformance closure

| Field | Content |
|---|---|
| Task | Run the equivalence proof (§6) and publish it next to the P4 PR. If parity-plan S1 has landed `docs/parities/`, file the closed D-11 row there; otherwise append the closure note to the parity handoff's divergence register section of the PR description. Update the UNKNOWN register (§7) with resolutions. |
| Owner / model role | aegis-maintainer + operator sign-off |
| Acceptance | Parity-plan C-3 (when it exists) runs against the new shape with a strictly smaller delta than at authoring time; D-11 no longer lists "extend Aegis SARIF" as an open option |
| Rollback | n/a (docs) |

---

## 6. Test commands and gates

Existing enforced gates (unchanged; from `AGENTS.md` and CI):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo doc --workspace --no-deps        # Rustdoc lints gate
cargo llvm-cov --workspace --summary-only   # coverage floor 97.0 lines (CI passes 97.0
                                            # explicitly; script standalone default is 89.0)
```

Targeted commands per phase:

```bash
# P1/P3 — emitter shape
cargo test -p aegis-cli --lib output
cargo test -p aegis-cli --test cli_integration

# P2 — pattern metadata
cargo test -p aegis-patterns --lib
cargo test -p aegis-core --test pattern_liveness
cargo test -p aegis-core --test registry_hygiene   # docs-freshness lives here
cargo test -p aegis-core --test corpus_precision_recall   # always run when touching patterns/
```

**Equivalence proof (P1/P2/P3 acceptance):** release-build the base commit
and the PR head, then diff findings on the repo self-scan and one corpus
fixture set — identical `stable_id` sets, counts, and exit codes:

```bash
./target/release/aegis -f json scan . \
  --categories secrets,security-hardening,web-security --severity-threshold high
# compare findings[].stable_id sets before/after; expect: equal, exit 0 both
```

Any finding delta from this change is a bug by construction — the change
must not touch a regex, the walker, the suppression parser, or the ledger.

---

## 7. Baseline vs unknown

### 7.1 Baseline (established, this tree unless noted)

- SARIF emitter shape, rules-from-findings, level map: §3.1 (VERIFIED).
- `Finding`/`Pattern` metadata fields available today: §3.2 (VERIFIED).
- CWE coverage: 4 distinct CWE ids / 2 modules / 392 total references:
  §3.3 (MEASURED).
- Category distribution (for DEC-2): §9.2 (MEASURED).
- Atheon emits security-severity + CWE taxonomies at the pin: §3.5
  (inherited VERIFIED).
- GitHub honors `properties.security-severity` on rules with documented
  bands: §3.4-1 (VERIFIED against docs).
- No open PR touches the files this plan owns: §2.1 (VERIFIED via
  `gh pr diff --name-only`, 2026-10-11).

### 7.2 Unknown register

1. **GitHub CWE display for third-party uploads** — the docs page lists
   no `taxonomies` support; resolved only by P0-2. Until then, no doc may
   claim CWE display on GitHub (DEC-4).
2. **Whether `security` in rule tags gates `security-severity`** for
   third-party tools (docs qualifier is CodeQL phrasing) — P0-1. The
   plan emits the tag for security categories regardless (cheap,
   honest).
3. **Current consumer inventory of Aegis SARIF** beyond PR #169's ledger
   classifier — never audited. P1 is additive-only, so unknown consumers
   are safe by construction; note it in the PR description.
4. **Atheon's exact security-severity score values** at the pin (the
   parity handoff cites the mapping location `cmd/atheon/main.go:782-795`
   but not the numbers) — transcribe during P2 if DEC-1 lands on score
   parity; otherwise ignore.
5. **Whether GitHub alert lineage needs `partialFingerprints`** for
   third-party tools to avoid alert churn — UNKNOWN until P0-3. The
   supplemental Aegis key may be standards-valid, but GitHub documents only
   `primaryLocationLineHash`; do not infer that the custom key fixes alert
   churn or is consumed by GitHub.

---

## 8. Risks and stop conditions

| Risk | Impact | Mitigation |
|---|---|---|
| Wrong CWE on hundreds of rules (data-quality debt) | Consumer distrust, rework | Waiver path is first-class; category defaults used sparingly; operator adjudicates; coverage report is a committed artifact, not prose |
| `security` tag applied to non-security rules | Dishonest filtering in GitHub UI | DEC-2 exclusion list ratified as a test fixture |
| Content-hash exposure via fingerprints | Secret-confirmation oracle in an uploaded artifact | DEC-5 prohibition; fixture test greps the SARIF for the content-hash shape |
| Merge collision with PR #169 on `finding.rs` | Rebase churn | P2 sequenced after #169; P1 touches only `output.rs` (verified untouched by all open PRs, §2.1) |
| Strict downstream SARIF validators reject new members | Consumer breakage | All added members are documented SARIF 2.1.0 / GitHub-supported; schema validation in tests; P0 uploads exercise the real ingestion path |
| Scope creep into rules-inventory (DEC-3 option b) | Couples CLI output to the patterns crate, grows blast radius | Explicitly deferred; revisit only on P0 evidence |
| Coverage floor regression from new serialization code | CI red | New branches are tiny; tests pin every emitted field shape |

**Stop conditions (any one halts the plan):**

- The equivalence proof (§6) shows any finding/exit/ledger delta — halt,
  diagnose; this change has no license to alter scan behavior.
- P0-1 shows GitHub rejects uploads containing the new members — restrict
  to the documented field set and re-run P0 before any P1 merge.
- A pattern liveness, registry-hygiene, or corpus gate goes red in P2 and
  does not reduce to a mechanical docs-regeneration miss — halt; metadata
  work must never destabilize the detection gates that the parity and
  qualification work depend on.
- PR #169 lands changes to SARIF shape (it does not today) — re-baseline
  §3.1 before P1.

---

## 9. Sources & reproducibility appendix

### 9.1 Revisions

- Aegis: this worktree at `9bf61f3` (merge of PR #168); `origin/main`
  fetched 2026-10-11 = `bebadc7` (PR #172, `crates/aegis-mcp` tests only —
  no file cited here differs).
- Atheon-Enhanced: cited only via the parity handoff
  `docs/handoffs/2026-10-11-aegis-atheon-parity-and-rollout.md`, pin
  `bc42edf` (§13.1 there).
- GitHub docs: "SARIF support for code scanning", fetched 2026-10-11
  (§9.3).

### 9.2 Commands and outputs (run 2026-10-11 in this tree)

```text
# PR changed-file overlap (§2.1)
gh pr diff 169 --repo aliasfoxkde/aegis --name-only   # scanner.rs, finding.rs,
    # aegis-cli/src/scanner.rs, scripts/ci/classify_aegis_sarif.py, docs, .gitforce.yml
gh pr diff 170|171 --repo aliasfoxkde/aegis --name-only  # aegis-core/src/scanner.rs + tests only
gh pr diff 173 --repo aliasfoxkde/aegis --name-only   # Cargo.lock only
git worktree list        # 16 worktrees; none own aegis-cli/src/output.rs work
agent-locks list         # no active locks

# Emitter facts (§3.1)
grep -n 'helpUri\|help_uri\|partialFingerprints' crates/aegis-cli/src/output.rs \
  crates/aegis-core/src/*.rs    # → zero hits
grep -n 'test_output_write_findings_sarif|test_severity_to_sarif_level|' \
     'test_output_sarif_never_carries_clones|test_output_sarif_with_multiple_findings' \
  crates/aegis-cli/src/output.rs   # → 518, 657, 676, 738

# CWE baseline (§3.3)
rg -l 'cwe\.mitre\.org' crates/aegis-patterns/src/ | wc -l          # 2
rg -o 'cwe\.mitre\.org/data/definitions/(\d+)' -r '$1' \
   crates/aegis-patterns/src/ -N --no-filename | sort -u | wc -l    # 4
rg -c 'reference: Some\(' crates/aegis-patterns/src/*.rs \
   | awk -F: '{s+=$2} END {print s}'                                # 392

# Category distribution, top rows (§3.3 / DEC-2 seed)
rg -o 'category: "([a-z-]+)"' -r '$1' crates/aegis-patterns/src/*.rs \
  --no-filename | sort | uniq -c | sort -rn | head -6
# 55 infrastructure, 41 secrets, 39 pii, 38 cloud-native, 37 web-security,
# 35 supply-chain   (35 shipped categories + "test" fixtures)

# Codebase-memory MCP (used before raw file reads)
list_projects → freshest aegis indexes:
    home-mkinney-worktrees-aegis-scan-hardening-mainline-20261011 (4,771 nodes)
    home-mkinney-worktrees-aegis-parity-corpus-s2-20261011 (4,676 nodes)
search_graph(query="sarif output severity level") on the scan-hardening index
    → confirmed write_sarif @ output.rs:166-308, severity_to_sarif_level @ :317-324,
      test inventory; cross-checked against this tree (identical lines)
```

### 9.3 External fetch (2026-10-11)

- `docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning` —
  `properties.security-severity` on rules, string 0.1–10.0, bands >9.0 /
  7.0–8.9 / 4.0–6.9 / 0.1–3.9, 0.0 = no severity, "recommended only for
  security rules", qualifier "for security queries (`@tags` includes
  `security`)"; tags for filtering, 20 max / 10 displayed; **no
  `taxonomies` documented** ("the rest of the supported fields are
  ignored").

### 9.4 Environment notes

- Docs gate: CI `Links` job (lychee) covers `docs/**/*.md`; this file
  contains zero markdown hyperlinks (all references backticked), matching
  the sibling handoff's convention.
- This document adds no product code, no fixtures, no generated data, and
  asserts no release/deploy state.
