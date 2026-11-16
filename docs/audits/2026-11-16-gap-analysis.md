# Aegis gap analysis — 2026-11-16

A systematic pass over the repository as it stands on `main` at `bce16c5`
(PR #193), 24 commits and seven weeks after the `v0.6.4` tag
(2026-09-27). Every claim below was checked against this tree on the day
it was written; the evidence line names the file, the gate, or the run
the claim came from.

**What was examined:** the source tree, the CI workflow definitions and
the rules they enforce, the changelog, `docs/PLAN.md`, the CLI/daemon/MCP
surfaces, the shipped secret-triage and path-class features, and the
gates that guard them.

**What was not:** the GitForge repository, the Control Center, the
CodeRabbit account, and the CI host's own admission policy. Those are
recorded as external items with the exact input each one needs, not as
findings.

Severity used here: **P1** — a shipped behaviour is wrong or a
documented contract is violated; **P2** — a real gap that costs
correctness, review, or trust but is not currently wrong; **P3** —
outside this repository's boundary.

---

## 1. Correctness defects in shipped work — P1

### 1.1 The triage reason named the placeholder word it matched — FIXED, PR #195

The secret-triage contract says a verdict's reasons name the *signal* and
never quote the value: "a report that says 'the secret contains
`example`' is itself a disclosure"
(`crates/aegis-core/src/secret_triage.rs`, `docs/guides/TRIAGE.md:102`
and `:114`). The implementation named the matched marker instead —
`contains the placeholder marker \`changeme\`` — so every placeholder
finding put a fragment of the matched credential into the report.

Fixed in PR #195: the reason reads "contains a known placeholder
marker", the match no longer binds the word at all, and a regression test
asserts that no reason names the marker the verdict matched.

Lesson worth keeping: the contract lived in the module docs and the
guide, but nothing tested the *reasons* against the value — the existing
test asserted the whole value was absent, which a single matched word
satisfied. A contract that is not asserted is a comment.

### 1.2 `Scanner::from_config` silently drops an invalid path-class rule — P1, IN FLIGHT (PR #197)

`Scanner::from_config` copies `config.path_classes` into the scanner's
options and builds the matcher without validating the globs
(`crates/aegis-core/src/scanner.rs:404-410`). `PathClassMatcher::new`
skips a glob that does not compile and logs a `tracing::warn!`
(`crates/aegis-core/src/path_class.rs:55-70`). A library or daemon
caller that hands over one bad glob gets a scanner that quietly does not
apply that rule — a rule that "cannot fire" is a bug of the worst kind
by this repository's own first guiding principle.

The CLI is not affected: `parse_path_class_specs` validates both the glob
and the class before the rule is ever constructed
(`crates/aegis-cli/src/config.rs:76-92`), and profile rules are validated
on the same path.

**Next step:** decide the error surface — a `PatternError` variant for
an invalid path-class rule, or a dedicated error enum for
`from_config` — then make `from_config` fail loudly instead of
degrading. Add a regression that a bad glob in a `Config` is an error,
not a warning.

Decided and in flight in PR #197: the error surface is a
`PatternError::InvalidPathClass` variant (the function already maps
configuration problems such as an unknown category into `PatternError`),
and `from_config` rejects the configuration naming the offending glob.
Integration coverage over the public entry point is in the same
change.

---

## 2. Feature reach across surfaces — P1

### 2.1 The daemon's and the MCP server's `config` is inert — RESOLVED (PRs #198, #199)

Both wire surfaces published a live configuration that was never read:

- `crates/aegis-daemon/src/lib.rs` — `pub config: RwLock<Config>`,
  seeded with `Config::default()` at startup and never read again.
- `crates/aegis-mcp/src/main.rs` — `pub config: RwLock<Config>`, seeded
  at startup and never read again.

Both servers built their scanner once from the bundled pattern corpus
(`init_scanner`) and scanned with default options, so the daemon and the
MCP server could not apply path classes, severity thresholds, or category
filters — and a host process that wrote `state.config` saw no effect and
no error. The doc comment on the daemon field called it "live
configuration"; it was not.

**Resolved in PR #198** — the "apply" branch, because a control-plane
consumer is the caller the field was promised to. Both surfaces now read
the configuration when the scanner is built (the lazy first compilation
included), publish the configuration in force (`config()`), and rebuild
the scanner around a new configuration (`set_config()`).

- A configuration that cannot be applied is rejected with the reason and
  the configuration already in force keeps serving: an unknown category,
  a path-class rule whose glob does not compile (the rejection of item
  1.2), a severity threshold no severity name matches, or an unknown
  anomaly detector. A rejected configuration never leaves either surface
  half-configured.
- The rule set is not a configuration decision: an installed bundle keeps
  serving, and installing a bundle now builds around the configuration in
  force, so the rule set and the configuration cannot disagree.
- The configuration fields are private now. The daemon's is read with
  `config()` and changed with `set_config()`; the same is true of the
  MCP server's. Neither can be written behind the scanner's back.

**Deliberately not done:** the wire protocols gain no configuration
method. A peer that can set the severity threshold or the category list
can weaken the very scan it was asked for — the configuration belongs to
the operator side of the trust boundary, not to the client.

**Resolved in PR #199** — the operator profile file. `AEGIS_DAEMON_CONFIG`
and `AEGIS_MCP_CONFIG` name the same JSON profile document the CLI reads
with `aegis --config <file>`; the categories, severity threshold,
anomaly detectors, and path classes in it are applied before the daemon
binds its socket and before the MCP server answers. A configuration that
cannot be applied stops the process instead of leaving it serving scans
it was not configured for, and an empty variable is refused rather than
read as "no configuration". The configuration stays operator-side: no
request over either protocol changes it.

**A defect found while landing it.** The two paths that build and install
a scanner — the lazy compilation on first use and the configuration change
— could interleave: a compilation that began before a configuration was
applied installed its scanner afterwards and silently undid the change.
That is the same "the configuration does nothing" defect this item exists
to remove, reached by a different route. Both surfaces now serialize the
two paths with one lock, and both carry a regression that asserts the
configuration in force after the change is the one that was applied.

### 2.2 The triage ergonomics are CLI-only — P2

Path classes, the `aegis:synthetic` annotation, and the secret-triage
verdict all landed in PR #193. The verdict does reach the wire surfaces
(the `Finding` struct serializes `secret_triage`,
`crates/aegis-core/src/finding.rs:139-140`), but the *inputs* — path
classes and the synthetic annotation — are configured only through the
CLI (`--classify-path`, `crates/aegis-cli/src/main.rs:114`). The daemon
and MCP conformance suites (Phase 15) have no fixture that pins the
behaviour of any of the three.

**Next step:** item 2.1 has landed, so the wire conformance fixtures for
the path-class classification, the synthetic annotation, and a triage
verdict on a secret finding can be written — the same shape as the
existing daemon and MCP fixture suites.

---

## 3. Release and changelog debt — P1

### 3.1 Seven weeks of merged work, no release, and the changelog is silent about the largest feature of the period — OPEN

`v0.6.4` is dated 2026-09-27; `main` has carried 24 commits since,
including the whole triage-ergonomics feature set from PR #193. The
`[Unreleased]` section of `CHANGELOG.md` documents the `ai-slop`
category, the exit-code-3 change, and the `llm-guardrails` fix — and
says nothing about path classes, the synthetic annotation, or the secret
triage verdict. A user reading the changelog between `v0.6.4` and today
cannot learn that the scanner's triage behaviour changed.

**Next step:** write the `[Unreleased]` entries for PR #193's feature
set, refresh the `Current state` header of `docs/PLAN.md` (still dated
2026-09-24 and still naming v0.6.3), and cut `v0.6.5` through the
GitForge-first release path documented in `docs/guides/RELEASES.md`.

### 3.2 The plan's current-state block and test count are stale — P2

`docs/PLAN.md:10` still reads "Current state (2026-09-24 … v0.6.3
released)" and quotes "818 tests across 25 binaries". The tree now
carries 875 `#[test]` functions across the same 25 test binaries (17
integration test files plus 8 crate test binaries), and the pattern
count of 677 across 35 categories is still current
(`docs/patterns/README.md:3`).

**Next step:** refresh those figures from a CI run (the CI total is
authoritative, not the attribute count) in the same change that lands
the changelog entries.

---

## 4. Documentation drift — P2

### 4.1 Phase 17F contradicts the tree — OPEN

`docs/PLAN.md:591-594` records as an open item that
`scripts/release/Dockerfile` "builds on `rust:1-bookworm` (floating
minor) while `docker/Dockerfile` pins `rust:1.88-slim`". The file pins
`rust:1.88-bookworm` (`scripts/release/Dockerfile:16`), which Phase
17H already records as delivered. The open item is stale: the
remaining honest content of 17F is the unsigned `checksums.txt` on the
GitHub mirror, which was resolved by decision (the minisign-signed
GitForge attestation is the provenance anchor).

**Next step:** correct the bullet so the open item matches the tree.

### 4.2 `CONTRIBUTING.md` does not say how to keep a branch current — OPEN

`.github/CONTRIBUTING.md:147` says "Branch from `main` → PR to `main`",
and merges are squash-only (`:151`). With squash-only merges and no
force-push policy, a long-lived branch has to *merge* `main` forward,
which nobody is told. Two of the merges in this period were fix-forward
after CI caught a regression on an already-pushed head — the recipe for
that (merge `main` into the branch, never rebase) is worth writing down.

**Next step:** add the branch-sync rule to `CONTRIBUTING.md`.

### 4.3 The triage guide's contract had no test behind it — see item 1.1

The disclosure contract in `docs/guides/TRIAGE.md` was asserted only for
the whole value, not for the words inside it. Fixed with the reason
change; worth remembering when the next contract sentence is written.

---

## 5. Gate gaps — P2

### 5.1 Nothing enforces patch coverage — OPEN

`scripts/coverage-floor.sh` computes one project-wide line percentage
over the counted set and fails below 97.0%; `codecov.yml` also declares
a `patch` target of 90%, but Codecov uploads have never been evaluated
(no `CODECOV_TOKEN`, so every upload fails and is ignored). The net
effect: a pull request can add uncovered lines and stay green, because
only the whole-project floor is enforced and the whole-project floor
barely moves when a small uncovered file arrives.

**Next step:** compute a patch floor from the same CI lcov report —
the lines added by the diff, and their hit counts — and fail the
Coverage job below it. Keep the floor just below measured reality and
ratchet it up, as the repository's own rule requires.

### 5.2 External, recorded not fixable here — P3

- **Codecov annotations** need a `CODECOV_TOKEN` secret on the
  repository. Operator action; until then the native floor is the only
  coverage gate that runs.
- **CodeRabbit auto-review** is configured (`.coderabbit.yaml`:
  `auto_review.enabled: true`, `drafts: true`) but the check reports
  *skipped* on this repository — the OSS account-side restriction, not
  a configuration problem. The config is demonstrably read: the skip
  reason differs between branches with and without it.
- **GitForge required checks** remain a product gap in the GitForge
  repository itself (no pull-request or ref-protection model exists
  there), recorded in `docs/PLAN.md` Phase 17E. It cannot be closed
  from this repository.

---

## 6. Open roadmap items outside this boundary — P3

- **Phase 16 — Control Center gate promotion.** The daemon/MCP
  conformance fixtures it needed are met; the remaining work is on the
  Control-Center side.
- **Phase 14 — ML/regex hybrid ranker** and **API-call verification**
  (verifying argument semantics for OAuth and crypto calls through the
  AST module). Both are capability work, not gaps in what exists.
- **Phase 17E — GitForge required checks** (see 5.2).

---

## 7. Ordered next steps

Work in this order; each item is independently mergeable and each names
the gate that proves it.

1. **Land PR #195** (triage reason) — Clippy, Format, and the three-OS
   test matrix are the gate.
2. **Land PR #197** (reject an invalid path-class rule in
   `from_config`, item 1.2) — the core test suite is the gate.
3. **Resolve the inert `config` field on the daemon and the MCP server**
   (item 2.1) — apply it or delete it; the daemon's own test suite and
   the MCP wire conformance suite are the gate. *Done in PR #198 and
   PR #199: both surfaces read the configuration when the scanner is
   built, publish it, and rebuild the scanner around a new one; and an
   operator profile file — `AEGIS_DAEMON_CONFIG`, `AEGIS_MCP_CONFIG` —
   lets a deployment choose categories, a severity threshold, or path
   classes at startup, without a wire method that would let a client
   weaken its own scan. The two paths that install a scanner are now
   serialized, so a compilation that began before a configuration was
   applied cannot undo it.*
4. **Write the changelog entries for PR #193's features, refresh
   `docs/PLAN.md`'s current-state block, and cut `v0.6.5`** (items 3.1,
   3.2) — the release workflow is the gate.
5. **Add a patch-coverage floor** to the Coverage job (item 5.1) — the
   script's own report over a CI lcov file is the gate.
6. **Add wire conformance fixtures for the triage ergonomics** (item
   2.2) — the daemon and MCP conformance suites are the gate.
7. **Documentation cleanups** (items 4.1, 4.2) — the `Links` job and a
   reviewer's eye are the gate.

Items 1 and 2 are correctness work on shipped code. Items 3, 5, and 6
are the work that keeps the shipped behaviour reachable and provable.
Item 4 is what a user actually reads.
