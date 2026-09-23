# Detection corpus

Labelled fixtures used by `tests/corpus_precision_recall.rs` to score the
bundled rule set for recall (every labelled vulnerable line is detected)
and precision (every reported finding lands on a labelled line), plus a
per-rule precision floor, confidence calibration, and a negative corpus
pinning the false-positive audit.

## Layout

- `vulnerable/` — real-shaped insecure code. Each line that must be
  detected carries a trailing directive:
  `// aegis:expect <rule-name> [<rule-name>...]` (the comment style adapts
  to the language, e.g. `# aegis:expect ...` in Python). List every rule
  that legitimately fires on the line — findings on unlabelled lines count
  as false positives.
- `clean/` — realistic code that must produce **zero** findings: secrets
  read from the environment, high-entropy hashes, and ordinary logic that
  naive regex scanners flag as noise.
- `negative/` — regression fixtures for rules whose regexes were widened
  enough to flag benign code (the 2026-09-22 false-positive audit: commit
  `e0abd61` fixed five of them). Each file names its rule in a
  file-level directive, `# aegis:expect-none <rule-name>`, and that rule
  must produce **zero** findings in the file. Findings from *other* rules
  are ignored in `negative/` — realistic fixtures legitimately trip
  unrelated advisory rules, and their measurement belongs to the positive
  corpus.

### `aegis:expect-none` semantics

- The directive is file-scoped: it names the rules that must stay silent,
  wherever they would fire in the file.
- The directive line itself is exempt — several rule names self-match
  their own regex (`hipaa-phi` contains a standalone `phi`), so a rule
  firing on its own directive line is not a violation.
- Every fixture must preserve the shape that made the *old* regex fire
  (e.g. `resource` for the old substring `rce`, `runAsNonRoot: true` for
  the old value-blind alternation). A negative fixture that the old regex
  also ignored pins nothing.

## Per-rule gates

- **Per-rule precision floor:** any rule with at least 2 measured
  observations (TP + FP) must hold precision ≥ 0.80 on its own slice.
  A finding counts as a true positive when it lands on *any* labelled
  line — generic rules legitimately share lines labelled for a more
  specific rule — and as a false positive otherwise.
- **Confidence calibration (demote-only):** once a rule has ≥ 3
  observations, its declared `confidence` label must be supported by
  measured precision — `high` needs ≥ 0.95, `medium` needs ≥ 0.80.
  `low` is never gated. When a rule fails its band, the fix is a regex
  correction or *demoting* the label; the gate never demands promotion.

## Rules for fixtures

- Values are the canonical documentation examples (AWS docs, RFC 7519) or
  obviously synthetic strings; never a real credential.
- Every file must be realistic enough to paste into a project — the corpus
  scores the scanner against code, not against regex edge cases.
- Patterns carrying `env_var: true` run only in environment-variable scan
  mode, so labels must reference the rules that are active on file content.
- Thresholds in the harness are pinned just below measured performance;
  when a fixture is added, re-run and keep the pin honest.
