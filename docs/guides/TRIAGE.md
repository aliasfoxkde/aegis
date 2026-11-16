# Triage: path classes, synthetic values, and secret verdicts

A repository that ships mostly documentation and fixtures produces findings
that are true of the text and irrelevant to the risk. A prose sentence that
mentions a credential-shaped string is not a credential, and a test fixture
that hard-codes an example token is not a leak.

Aegis offers three independent mechanisms for that situation. None of them
hides a finding: each one records *why* a finding is reported the way it is.

| Mechanism | Scope | Effect on severity | Effect on the report |
|-----------|-------|--------------------|----------------------|
| Path class | A directory or glob | Non-secret findings drop to `low`; secrets keep their severity | Finding carries a `docs` or `fixture` tag |
| Synthetic annotation | One line, or one whole file | The finding drops to `low` | Finding carries a `synthetic` tag |
| Secret triage | Every `secrets`-category finding | None | Finding carries a verdict and its reasons |

## Path classes

A path class maps a glob to a class. Findings below a classified path are
reported at low severity so they stop competing with real signals — except
secret findings, which keep their severity (see below).

```bash
aegis scan . --classify-path "docs/**=docs" --classify-path "**/tests/**=fixture"
```

The value is `GLOB=KIND`, where `KIND` is `docs` or `fixture` (`doc`,
`documentation`, `fixtures`, `test`, and `test-fixture` are accepted
spellings, case-insensitively). The flag may be repeated. A malformed
specification fails the scan instead of being ignored, because a rule
that never matches leaves the operator believing a path had been quieted.

The same rules can live in a profile:

```json
{
  "name": "documentation-heavy",
  "path_classes": [
    { "glob": "docs/**", "class": "docs" },
    { "glob": "**/fixtures/**", "class": "fixture" }
  ]
}
```

Rules given on the command line are applied before the profile's rules, so
an explicit rule wins over a profile rule that matches the same path.

**How a path is matched.** A rule is matched against the path relative to
the scan root when the root is known, and against the path as written
otherwise. A directory rule matches at any depth: `docs/**` covers
`docs/setup.md` and `crates/docs/setup.md` alike. A rule without a
separator (`*.md`) matches the file name.

**Secrets are never downgraded.** A credential in a documentation file is
still a credential, and hiding it would be the one mistake this feature
must not make. A `secrets`-category finding keeps its severity under a
path class and carries the class as a tag instead.

Downgrading happens before the severity threshold is applied, so a finding
that drops to `low` does not survive `--severity-threshold medium`.

A path class quiets a path; it does not remove it. When a path should
not be scanned at all, `.aegisignore` is the mechanism — it drops the
file from the scan, receipt and ledger alike. A path class keeps the
finding visible and explains why it was downgraded.

## Synthetic values

A synthetic annotation marks a deliberate example where it stands. The
finding is kept, tagged `synthetic`, and reported at low severity:

```rust
let token = "AKIAIOSFODNN7EXAMPLE"; // aegis:synthetic -- published example
```

`aegis:synthetic` applies to the line it is written on.
`aegis:synthetic-file` applies to every line of the file. A reason may
follow a `--` separator.

This is different from `aegis:ignore`, which hides a finding. A
suppression says "this rule does not apply here"; an annotation says "this
value is an example, and I want the report to show that I know it".

## Secret triage

A secret-pattern hit is a shape, not a proof. A vendor's published example
key and a live AWS key have the same shape, and only one of them is worth
a rotation. Every `secrets`-category finding that has matched text to
judge therefore carries a verdict:

| Verdict | Meaning |
|---------|---------|
| `likely_placeholder` | The value is a documentation example, a test double, or a template — it needs no rotation |
| `likely_real` | The value has the shape of a live credential and should be treated as exposed until it is proved otherwise |
| `uncertain` | The signals disagree or are too weak to decide; a human has to look |

The verdict combines five independent signals: values published by vendors
as documentation examples, placeholder markers (`example`, `changeme`,
`your-api-key`, …), template shapes (`<token>`, `{{token}}`), values that
repeat one character many times, and Shannon entropy.

The reasons name the *signal*, never the value:

```
[CRITICAL] aws-access-key at docs/intro.md:1:10
  AWS access key detected
  tags: docs
  secret triage: likely_placeholder (high confidence)
    - matches a published documentation example
```

A verdict is a triage aid, never a clearance: `likely_real` means "look at
this first", and `likely_placeholder` means "the shape is right but the
evidence says this is an example". The verdict never repeats the value it
judged — a report that says "the secret contains `example`" is itself a
disclosure.

## Output formats

- **human** — the tags and the verdict are rendered under the finding.
- **json** — `tags` and `secret_triage` are fields of every finding.
- **sarif** — the same information travels in the result's `properties`
  bag; results without either carry no property bag at all.

## What this does not do

- Path classes and annotations never suppress a finding: a downgraded
  finding is still a finding, and it still reaches a report that asks for
  `low`. A severity threshold, however, is applied after the downgrade, so
  a threshold of `medium` or higher leaves the downgraded finding out.
- A secret finding never loses severity to a path class.
- Secret triage never changes the exit code: it adds a verdict, not a
  severity.
- Triage judges the *shape* of a value, not its validity. Proving a
  credential live would mean calling the provider, which a static
  scanner does not do; a `likely_real` verdict means "rotate it", not
  "it still works".
- The staged-blob scan (`--staged`) reads the git index rather than the
  working tree, so path classes do not apply to it.
