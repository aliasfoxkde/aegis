# Detection corpus

Labelled fixtures used by `tests/corpus_precision_recall.rs` to score the
bundled rule set for recall (every labelled vulnerable line is detected)
and precision (every reported finding lands on a labelled line).

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

## Rules for fixtures

- Values are the canonical documentation examples (AWS docs, RFC 7519) or
  obviously synthetic strings; never a real credential.
- Every file must be realistic enough to paste into a project — the corpus
  scores the scanner against code, not against regex edge cases.
- Patterns carrying `env_var: true` run only in environment-variable scan
  mode, so labels must reference the rules that are active on file content.
- Thresholds in the harness are pinned just below measured performance;
  when a fixture is added, re-run and keep the pin honest.
