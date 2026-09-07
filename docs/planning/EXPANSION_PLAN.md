# Aegis Expansion Plan

This plan expands the audit of 2026-09-05 into a phased, actionable program. It records
what was found, what was fixed, what is being added, and what remains. Planning-level
designs and example code live here; shipped behavior lives in the crates and the
`docs/patterns/` reference.

---

## 1. Audit findings (2026-09-05)

### 1.1 Confirmed bugs (fixed in this expansion)

| # | Finding | Root cause | Fix |
|---|---------|-----------|-----|
| B1 | Duplicate findings (same pattern+file+line twice) | `CategoryScanner::find_matches` flattened matches from all patterns, then re-attributed each match to the *first* pattern whose regex re-matched the text. Overlapping patterns (`<input[^>]*>` used by two patterns) double-reported. | `find_matches` now returns `(pattern_index, match)` pairs; attribution is by construction, not re-matching. |
| B2 | `--categories security` selected zero patterns | Exact string match against pattern `category` values; no pattern carries category `security` (patterns use `security-hardening`). Presets, `production.json`, and `aegis-scan.yml` all passed `security`. | Phantom category removed everywhere; unknown category names are now a hard CLI error listing valid names. |
| B3 | Category naming split (`web_development`, `api_integration`, `data_visualization` vs hyphenated everything else) | Typo drift in pattern modules. | All category values normalized to kebab-case; selection normalizes `_` → `-` on input. |
| B4 | `code-quality-eval-usage` regex `eval\s*` matched the words "retrieval"/"evaluation" | Missing call-paren anchor. | `eval\s*\(` etc., scoped by file type. |
| B5 | `with-statement` regex `with\s*` matched the English word "with" | No anchor. | `^\s*with\s*\(` (JS with-statement), JS-scoped. |
| B6 | `long-function` regex `(?s).{200,}` matched every file over 200 chars | Regex cannot see function boundaries. | Removed from regex engine; documented as an AST-only metric (complexity metrics exist in `aegis_core::ast`). |
| B7 | `unused-import` regex matched every import statement | No usage analysis possible in a single regex. | Removed; documented as AST-only. |
| B8 | `magic-number` / `unused-variable` regexes flagged correct code | Regex cannot see identifiers or usage. | Removed; documented as AST-only. |
| B9 | Accessibility "missing X" patterns (`<img[^>]*>`) fired on fully compliant markup | The `regex` crate (RE2 syntax) has no lookarounds, so "tag without attribute" was inexpressible; patterns degraded to match-everything. | Engine gained `exclude_pattern`: a finding is suppressed when the matched span also matches the exclude regex. `<img\b[^>]*>` + exclude `alt\s*=` now means "img without alt". |
| B10 | Patterns flagged correct ARIA usage (`role-definition`, `live-region`, `tab-index-usage`) | Informational detections modeled as findings. | Rewritten as true violations only (e.g. positive `tabindex="1.."`), demoted to informational severity, or removed. |

### 1.2 Structural gaps (addressed)

- **G1 — No file-type scoping.** Every pattern ran against every text file
  (`console.log` patterns scanned Rust, TS patterns scanned markdown).
  `Pattern.file_extensions` added; empty = universal. `scan_file` selects scanners
  by file extension with a per-extension cache.
- **G2 — No per-pattern tests.** Only 2 of 34 modules had tests; every bug above
  would have been caught by a positive/negative test pair. A validation suite now
  compile-checks every regex (match + exclude), enforces unique names, kebab-case
  categories, https references, and non-empty tags; rebuilt packs carry explicit
  positive/negative tests per pattern.
- **G3 — TypeScript coverage ≈ 0.** One `typescript-any` pattern, unreachable due
  to B3. A dedicated `typescript` category now covers the regex-expressible subset
  of typescript-eslint's `recommended-type-checked` / `strict-type-checked` presets.
- **G4 — Accessibility signal-to-noise ≈ 0.** Rebuilt against the statically
  testable subset of W3C ACT Rules / axe-core rule classes, each tagged with its
  WCAG success criterion and conformance level.

### 1.3 Honest scope statement on WCAG "AAA"

WCAG 2.2 (current Recommendation) defines 86–87 success criteria; AAA criteria are
largely **not automatable** — most require human judgment (sign-language
interpretation, reading level, cognitive tests). Static analysis can reliably cover a
subset of A/AA violations plus a handful of AAA-shaped source smells (e.g.
`outline: none` on `:focus`). Aegis therefore:

- tags every accessibility finding with its SC number and level (`wcag:2.4.7`,
  `level:aa`),
- never claims AAA conformance from a passing scan,
- documents that full AAA requires runtime/browser testing (axe-core, PAVE, manual
  audit). This is the same posture as axe-core and eslint-plugin-jsx-a11y.

---

## 2. Architecture decisions

### 2.1 `exclude_pattern` instead of lookarounds

Switching the engine to `fancy-regex` (lookaround support) costs performance and
Catalyst complexity for one use-case class. Instead:

```text
match:    <img\b[^>]*>
exclude:  alt\s*=|aria-label(?:ledby)?\s*=|role\s*=\s*["']?(?:presentation|none)
```

- `match` runs in the hot path exactly as before (combined-regex pre-filter
  unchanged).
- `exclude` runs only on candidate matches (cold path), checked against the
  **matched span**, not the whole file — deterministic and cheap.
- Limitation: exclusion sees only the matched span, so patterns must match the full
  element/tag. `[^>]` classes naturally cross newlines, so multi-line tags work.

### 2.2 Attribution by construction

`CategoryScanner::find_matches` returns `(pattern_index, PatternMatch)` pairs. The
combined alternation regex stays a pre-filter only; per-pattern iteration produces
attributed matches. This removes the re-match heuristic, its ambiguity, and its
duplicates in one move.

### 2.3 File-type scoping model

- `Pattern.file_extensions: Vec<String>` — empty means "all files".
- `Scanner` keeps a per-extension `CategoryScanner` cache; unknown/extension-less
  sources (`scan_string` from MCP, stdin) use the universal set only.
- AST inspection continues to gate itself by extension (tree-sitter grammars).

### 2.4 Pattern taxonomy rules (enforced by tests)

1. `name` unique across all packs, kebab-case.
2. `category` kebab-case, in the known category set.
3. `file_extensions` required when the pattern is language-specific.
4. Every pattern carries ≥ 1 tag; security packs carry a reference URL.
5. Every regex (match and exclude) must compile.
6. New/rebuilt patterns ship with positive **and** negative test cases.

---

## 3. Phases

### Phase 0 — Correctness (shipped with this plan)

B1–B10 above, plus: preset/profile/workflow category fixes, dedup regression test,
good-code fixture regression test (a fully compliant HTML+TS fixture must produce
zero findings in the affected categories).

### Phase 1 — Pattern quality infrastructure (shipped)

- `exclude_pattern`, `file_extensions`, attribution fix (engine).
- Validation suite wired into `cargo test` and CI.
- Rebuilt `accessibility` (22 → 28 patterns, WCAG-tagged).
- New `typescript` category (13 patterns, file-scoped).
- Repaired `code-quality` (kept patterns made precise; un-fixable-in-regex patterns
  removed and documented).

### Phase 2 — Coverage expansion (next)

1. **Secrets parity with Gitleaks.** Diff Gitleaks' TOML rules against
   `secrets.rs`; port the missing high-value detectors (each with positive/negative
   tests, entropy where applicable).
2. **GitHub Actions / CI security pack.** `${{ inputs.x }}` script-injection in
   `run:` blocks, unpinned actions (`uses:` without SHA), `pull_request_target`
   with checkout of PR head, `secrets` echoed to logs, `continue-on-error` on
   security jobs.
3. **Dockerfile/Kubernetes hardening expansion.** `:latest` tags, missing
   `USER`, `--privileged`, `allowPrivilegeEscalation`, `readOnlyRootFilesystem`,
   missing resource limits, hostPath mounts, `--cap-add=NET_ADMIN`.
4. **Python pack.** `eval`/`exec`, `yaml.load` without Loader, `pickle.loads` on
   network data, `subprocess` with `shell=True` + string interpolation, `verify=False`,
   `assert` for control flow, mutable default args.
5. **Go pack (AST-backed).** Leverage existing tree-sitter-go: unchecked `err`,
   `interface{}` assertions without ok, `math/rand` for tokens, `os/exec` string
   concatenation.
6. **Rust pack (AST-backed).** `unwrap`/`expect` outside tests, `unsafe` without
   `// SAFETY:` comment, `std::process::Command` with shell, `format!` into SQL.

### Phase 3 — Detection depth (research track)

1. **Proximity rules** (Gitleaks-style `withinLines`/`withinColumns`): composite
   patterns — keyword + secret-shape near each other. Cuts secret-scan FPs further.
2. **AST-backed rules** for JS/TS via the existing optional `tree-sitter-typescript`
   feature: floating promises, missing `await`, unused vars/imports, function-length
   and complexity gates (restoring B6/B7 properly), React hook dependency analysis.
3. **Rule authoring in data, not code.** Ship the bundler's YAML loader end-to-end
   in the CLI (`aegis --patterns-dir community/`) so the empty `community/` packs
   become contribution-ready; add `aegis validate --patterns-dir` for CI.
4. **Baseline workflow polish**: `aegis baseline` subcommand writing
   current findings' fingerprints for legacy-code adoption (filter machinery exists).

### Phase 4 — CI/CD & release hygiene

1. `aegis-scan.yml`: fixed categories; add an explicit `fail-on-findings` input
   (default false, `security-hardening` job true) once baselines exist.
2. Publish pre-commit hook docs (`aegis scan --diff` on staged changes) as the
   documented front door.
3. Release automation: tag `vX.Y.Z` → `release.yml` builds artifacts; version bump
   discipline via workspace `Cargo.toml`.

### Phase 5 — Documentation (items 1–3 shipped; 4 open)

1. `docs/patterns/` regenerated from source (script counts updated). ✅
2. `README.md` feature table updated (category count, new fields). ✅
3. `PATTERNS.md` spec: document `exclude` and `file_extensions` fields. ✅
4. `CONTRIBUTING.md`: pattern authoring checklist (tests, tags, references,
   file scoping, FP self-review fixture). Not started — `guides/ADDING_PATTERNS.md`
   is the current stand-in.

---

## 4. Verification protocol

Every phase lands with:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./target/release/aegis scan /tmp/aegis-fixture --categories accessibility,code-quality   # 0 findings expected
./target/release/aegis scan . --categories secrets --severity-threshold high             # self-scan
```

The good-code fixture (`/tmp/aegis-fixture`) contains fully compliant HTML and
strictly-typed TS and is the FP tripwire: any finding there is a regression.

---

## 5. References

- [WCAG 2.2 Recommendation](https://www.w3.org/TR/WCAG22/)
- [W3C ACT Rules](https://www.w3.org/WAI/WCAG22/Understanding/understanding-act-rules.html)
- [typescript-eslint rule presets](https://typescript-eslint.io/rules/no-explicit-any/)
- [eslint-plugin-jsx-a11y](https://github.com/jsx-eslint/eslint-plugin-jsx-a11y)
- [axe-core](https://github.com/dequelabs/axe-core)
- [Gitleaks rules](https://github.com/gitleaks/gitleaks)
