# Aegis gap analysis — 2026-11-23 (refreshed 2026-11-24)

Baseline: `main` at `cd1004f` ("chore(release): 0.6.6"), plus the pull
requests this pass closed: #212 (gate parity), #213 (OWASP links), #214 (the
test-count gate), #217 (the persisted pattern state), #219 (the two P1
command-line defects and the receipt-path defect beside them).

The previous gap analysis (`docs/audits/2026-11-16-gap-analysis.md`) had its
§7 work order fully executed; `docs/audits/2026-11-23-gap-analysis.md` was
the fresh pass over the tree that work left behind, and this document is its
successor: every item that has landed is marked closed with the evidence that
closed it, every item that is still open carries its original finding and
file/line evidence, and a new section records the correctness defects found
while re-deriving the open items.

Method: every finding below was re-derived against the sources on this
baseline, not carried over from the earlier audit. Where a number is quoted,
it comes from the authoritative store — the CI run for this commit, the
workflow file on disk, or the ruleset read from the API — and the citation
says which.

Severity:

- **P1** — shipped behaviour contradicts a documented contract, or a gate
  that exists to catch a class of failure cannot catch it.
- **P2** — real drift or a missing capability across surfaces, with a
  workaround that costs the user something.
- **P3** — polish: stale snapshots, missing index entries, ergonomics.

---

## 1. Contract defects in shipped work

### 1.1 The persisted pattern state is honoured by the CLI only — CLOSED by #217

The finding, as recorded on 2026-11-23: the state file written by
`aegis enable` / `aegis disable` was applied in exactly one place in the
workspace — `crates/aegis-cli/src/scanner.rs` — while `docs/guides/CLI.md`
said the state was "honored by every later scan". The daemon and the MCP
server scanned with the full rule set, so a pattern the operator had turned
off still fired on every daemon request and every MCP tool call.

What landed: the state document, its schema, its parsing, and its
application to a pattern registry now live once in `aegis-core`
(`crates/aegis-core/src/pattern_state.rs`). The command line, the daemon,
and the MCP server read the same file. The environment variable that names
the file (`AEGIS_PATTERN_STATE`) is read once at the process edge and passed
in as a value — the decision core never reads the environment itself. The
daemon and the MCP server re-read the file before each request or tool call
and rebuild the scanner only when the disable set actually changed, so a
disable takes effect without a restart. A malformed file is an error on
every surface, never a silent fallback.

The regression tests pin the agreement: the daemon and the MCP server each
prove that a disabled pattern stops firing on the next request, and each
prove that a malformed state file is refused rather than ignored.

### 1.2 Deleting a gate *step* from a CI job is invisible to the gate that exists to catch weakened gates — CLOSED by #212

The finding, as recorded on 2026-11-23: the required-check list names
*jobs*, not *steps*, so deleting a gate that lives as a step inside a
required job left the job green and the required check passing. `scripts/
check-gate-parity.py` compared floors and files, never the set of gate
steps.

What landed: `scripts/check-gate-parity.py` now compares the set of gate
steps between the base and the head and fails when a step that ran at the
base is gone. The detectors are covered by
`scripts/test_check_gate_parity.py`.

### 1.3 Deleting `deny.toml` or `codecov.yml` wholesale is invisible to the parity script — CLOSED by #212

The finding, as recorded on 2026-11-23: every file comparison in the parity
script was guarded by `if base_file and head_file:`, so a deleted file
skipped the whole block and the script reported nothing. Deleting
`codecov.yml` removed the declared project and patch targets with no
complaint from any gate.

What landed: both files now carry an explicit "was removed" problem, the
same shape the script already gave a removed coverage floor.

### 1.4 The gate that detects weakened gates is itself untested for most of what it detects — CLOSED by #212

The finding, as recorded on 2026-11-23: every test in
`scripts/test_check_gate_parity.py` exercised a helper that reads a number
out of workflow text; not one exercised a detector in `main()`.

What landed: each detector has a regression test carrying the mutation it is
supposed to catch, and the `scripts/README.md` description of the test file
now matches what it tests.

---

## 2. Feature reach across surfaces

### 2.1 Six CLI capabilities have no counterpart on the daemon or the MCP server — OPEN (P2)

Both wire surfaces build their scan options from the configuration and
nothing else:

- `crates/aegis-daemon/src/lib.rs` — `scanner_for_with_state` builds
  `ScanOptions { path_classes, severity_threshold, anomaly_detectors, ..ScanOptions::default() }`
- `crates/aegis-mcp/src/main.rs` — `scanner_for_with_state` builds the same
  shape

`ScanOptions` carries more fields than that. The three that matter for a
caller's decision are:

| CLI flag | What it does | Wire status |
| --- | --- | --- |
| `--baseline <file>` | filters out findings already recorded in a baseline — the "what is new since last time" mode | absent |
| `--follow-symlinks` | follows symlinks while walking | absent (default: off) |
| `--detect-clones` | enables the clone-detection pass | absent (default: off) |

`--staged` (scan the git index rather than the working tree) and `--all`
are CLI-only for the same reason: neither is representable in `Config`, and
`Config` is the only configuration channel the wire surfaces have.

The baseline gap is the sharpest of the three. `docs/guides/CLI.md`
documents the baseline file as the way to make a scan report only what is
new, and the CI-gate use is the mode the feature exists for; the wire
surfaces can only ever answer "what is wrong now". A consumer that drives
Aegis through MCP — the consumption mode for an agent — cannot use the
feature that makes a scanner usable as a gate.

### 2.2 The daemon is missing two methods the MCP server has — OPEN (P2), narrowed

Method inventory, read from the dispatch tables:

| Method | CLI | Daemon | MCP |
| --- | --- | --- | --- |
| `scan_string` | yes | yes | yes |
| `scan_file` | yes | yes | yes |
| `scan_dir` | yes | yes | yes |
| `scan_env` | yes | yes | yes |
| `list_patterns` | yes | yes | yes |
| `list_categories` | yes | **no** | yes |
| `update_bundle` | yes | **no** | yes |

**Correction to the 2026-11-23 recommendation.** That pass recommended
giving the daemon an `update_bundle` method as well. That is wrong, and the
reason is the deliberate omission class the wire surfaces already draw:
`Config::bundle` is `#[serde(skip)]`, so a bundle can never arrive from a
client, and installing a bundle is a change to the rule set rather than a
read. The daemon's protocol is operator-side configuration; giving a client
the ability to replace the rule set under a running daemon would break the
boundary the daemon was built with. The MCP server's `update_bundle` is
narrower than it looks — it swaps the bundle the server itself serves, and
that server is configured by the operator who starts it.

The actionable part is therefore one method, not two: `list_categories` is a
read-only listing that the daemon should have for parity with the CLI and
the MCP server. `update_bundle` stays CLI-and-MCP-only, and the daemon's
missing it is a deliberate omission, not a gap.

### 2.3 The daemon's bundle comment describes a path that does not exist — OPEN (P3)

`crates/aegis-daemon/src/lib.rs` carries a comment saying the shipped
corpus is the rule set "unless a bundle is installed on top". The daemon has
no install path. `Config::bundle` is `#[serde(skip)]`, so it can never
arrive from a client, and `shipped_bundle()` is the only bundle the daemon
ever builds. The clause is dead, and it is dead in a comment that a
maintainer would read as "the daemon can also serve an installed bundle" —
which is the question §2.2 raises. With §2.2 corrected, the comment should
say the daemon serves the shipped corpus and nothing else.

### 2.4 The daemon protocol is undocumented — OPEN (P2)

`crates/aegis-daemon/README.md` is 48 lines and names no method, no
parameter, and no response field. `docs/guides/MCP.md` specifies the MCP
surface in full — methods, parameters, response shape. There is no
`docs/guides/DAEMON.md`.

A daemon is a wire protocol. A wire protocol nobody can implement a client
against is not a usable daemon; it is a binary that happens to answer on a
socket. The MCP server got a guide because a client had to exist for it;
the daemon has no client and therefore never got one.

---

## 3. Documentation drift

### 3.1 The quoted test count is stale in two places, and nothing guards it — CLOSED by #214

The finding, as recorded on 2026-11-23: `AGENTS.md:17` and `docs/PLAN.md`
both quoted "818 tests across 25 test binaries", measured 2026-09-24, while
the CI store for the baseline said 949 across 30. Nothing guarded the
number, so it drifted once and could drift again.

What landed: `scripts/check-test-count.py` re-measures the count from each
lane's own test log and fails when the recorded table no longer matches, and
the table and the `AGENTS.md` count are updated in the same change.

Two things the implementation had to get right, both of which the first
version of the gate got wrong and the fix corrected:

- Cargo prints the suite *headers* ("Running unittests src/lib.rs") on
  stderr and the suite *counts* ("12 tests, 0 benchmarks") on stdout. A
  gate that reads stdout alone counts the six doctest suites as test
  binaries — the first version of the gate reported 36 where the tree has
  30. The gate now reads both streams and counts test binaries from the
  headers.
- The doctest suites are counted as suites but not as test binaries; the
  recorded column counts binaries, so the two are separated.

Measured at the merge of #214, on the three CI lanes, from the job logs
directly: Linux 954 tests across 31 test binaries, macOS 954 across 31,
Windows 925 across 31.

### 3.2 The enhancement roadmap is a 2026-09-07 snapshot that contradicts the tree — OPEN (P2)

`docs/ENHANCEMENT_ROADMAP.md` still says, among other things:

- `:189-190` — "codecov.yml pins real thresholds (90% project / 85% patch)".
  The real targets are `97%` project / `90%` patch (`codecov.yml:25-31`),
  and the enforced floors are `97.0` (`ci.yml:297`) and `90.0`
  (`ci.yml:272`).
- `:202-205` — "**Crates.io publishing**: open". Phase 13 of `docs/PLAN.md`
  decided against publishing the library crates; the GitForge-first
  pipeline ships binaries and source archives instead.
- `:226-231` — "published by `.github/workflows/release.yml` on `v*` tags —
  9 assets in total". The release is `workflow_dispatch` on a GitForge
  pipeline and produces **10** assets (5 platform tarballs, the WASM
  module, two source archives, `checksums.txt`, `attestation.json` — see
  `uploaded_assets()` in `scripts/release/lib.sh:44-51`). This one already
  carries a "historical claim below predates the GitForge-first pipeline"
  banner, so it is marked, but the count is still wrong.
- Footer — "Last Updated: 2026-09-07".

### 3.3 The documentation index links a third of the documentation — OPEN (P3)

`docs/README.md` links 12 documents. The repository has 64 markdown files
under `docs/`. Nothing links:

- `docs/audits/` (4 files, including both gap analyses)
- `docs/progress/` (3 receipts)
- `docs/planning/` (2)
- `docs/handoffs/` (1)
- `docs/MODULES.md`
- `docs/ENHANCEMENT_ROADMAP.md`
- `docs/guides/RELEASES.md`

The `Links` CI job checks that the links which exist resolve. It cannot
check for the links that do not exist, so an index that has quietly stopped
pointing at half the tree passes the gate that appears to cover it.

---

## 4. Correctness defects found on the command-line surface

These were found while re-deriving §2.1 against the code rather than against
the documentation, and each was re-derived from the source on this baseline.
The two P1 defects (§4.1, §4.2) and the receipt-path defect found beside
them (§4.8) are closed; §4.3 through §4.7 are open.

### 4.1 `aegis scan --env` ignores the severity threshold, the category list, and the baseline — CLOSED by #219

The finding, as recorded on 2026-11-23: `crates/aegis-cli/src/scanner.rs:185-188`
called `scanner.scan_env()`, and `scan_env`
(`crates/aegis-core/src/scanner.rs:1611-1648`) matched patterns against every
environment value and pushed findings with no category or severity gate. The
shared gates — `passes_post_filters`
(`crates/aegis-core/src/scanner.rs:1005-1016`) and `passes_severity_threshold`
(`:1023-1039`) — were applied inside `scan_string_with_inspection_ext`
(`:949`) and to anomaly findings (`:1568`), never on the environment path.
`--baseline` was ignored there too.

What landed: the environment scan now goes through the same filter path as
every other scan. `scan_env` became the edge that reads the environment and
hands it to `scan_env_vars`, which applies the shared post-filters, the
severity threshold, and the baseline before a finding is reported. Three
tests pin it — one per filter — and each fails against the old
implementation.

### 4.2 `aegis benchmark --runs 0` divides by zero and panics — CLOSED by #219

The finding, as recorded on 2026-11-23: `crates/aegis-cli/src/benchmark.rs:88`
computed `total_duration / u32::try_from(runs).unwrap_or(u32::MAX)`.
`u32::try_from(0)` is `Ok(0)`, so `unwrap_or` did not substitute
`u32::MAX`, and `Duration / 0` panicked with "attempt to divide by zero".
The zero-guard a few lines below (`:92-100`) protected only the file, byte,
and finding counters and was reached *after* the division, so it never fired.

What landed: the flag rejects a zero run count at parse time — `--runs` is
parsed as `u64` with `value_parser!(u64).range(1..)`, so `--runs 0` is a
clap usage error with exit code 2 and no panic — and the division is guarded
as well, so the zeroed averages are a value the code can produce rather than
an accident. The integration test
`test_benchmark_rejects_a_zero_run_count` asserts the exit code and that
nothing panicked.

### 4.3 `aegis scan --file <dir>` silently scans the whole tree — P3

`--file` is a boolean (`crates/aegis-cli/src/main.rs:48-50`); the target is
the positional `path`. In `perform_scan` (`crates/aegis-cli/src/scanner.rs:
197-205`) the `--file` branch checks `path.is_dir()` and, if so, calls
`scanner.scan_dir(path)` — byte-for-byte the same work as the default
branch (`:211-213`).

The result is correct, so this is not a wrong-answer defect: the flag is a
no-op for a directory, and its documented meaning ("Treat the path as a
single file") does not hold. A user who passes `--file` on a directory gets
a full-tree scan and no warning. Either the flag rejects a directory, or
the documentation says what actually happens.

### 4.4 Scanning an empty directory exits 3 — P2

`scan_dir` on an empty tree produces no file entries, so the inspection
ledger stays empty (`crates/aegis-core/src/scanner.rs:1495-1516`); the
`required_units > 0 && successfully_inspected == 0` error at `:1599` does
not trigger, because the required count is zero. `InspectionLedger::
allows_safe` requires a non-empty unit list
(`crates/aegis-core/src/finding.rs:375-381`), and `scan_exit_code` maps a
non-safe receipt to `EXIT_INCOMPLETE = 3`
(`crates/aegis-cli/src/scanner.rs:531, 555-557`).

"Nothing to inspect" is reported as "not proven inspected". A repository
that scans an empty build directory — a common CI shape — gets exit code 3
and the pipeline fails. The exit code is the contract: 3 means the receipt
cannot certify that every required inspection completed, and an empty tree
has completed every inspection there was.

### 4.5 The scan modes are not exclusive and the precedence is silent — P2

No mode flag carries `conflicts_with` (`crates/aegis-cli/src/main.rs:
43-116`); the only enforced pair is `--no-anomalies` against
`--anomaly-detectors` (`:236-240`). The precedence is implicit in an
`if / else if` chain: `run_scan_and_get_exit_code` takes the stdin branch
whenever `--stdin` is set (`crates/aegis-cli/src/scanner.rs:607-612`), and
otherwise `perform_scan` orders diff → env → stdin → file → staged →
directory (`:176-214`).

So `--stdin --env` scans stdin and says nothing about `--env`, and
`--diff --staged` scans the diff. A user who combines two modes gets one of
them and no notice that the other was dropped. Clap's `conflicts_with` is
the built-in answer, and it makes the mistake a usage error (exit 2) rather
than a silently different scan.

### 4.6 Path classification does not reach every finding — P2

`apply_path_class` (`crates/aegis-core/src/path_class.rs:161-168`) does the
documented thing where it is called: it adds the class tag, returns early
for the secrets category (`crates/aegis-core/src/secret_triage.rs:35`) so
secret findings keep their severity, and downgrades every other category to
low (`crates/aegis-core/src/finding.rs:249-259`) with a re-filter against the
threshold (`crates/aegis-core/src/scanner.rs:1311-1316`).

The gap is where it is called. `apply_path_class` has exactly one call site
(`crates/aegis-core/src/scanner.rs:1313`), inside `scan_file_with_root`, so
only file and directory scans are classified. `--env`
(`crates/aegis-core/src/scanner.rs:1611`), `--diff` (`:803`), `--stdin`, and
`--staged` (`crates/aegis-cli/src/scanner.rs:377`) never consult
`path_classes`. The anomaly post-pass (`crates/aegis-core/src/scanner.rs:
1562-1572`) runs after the per-file path, so `statistical-anomaly` findings
are never downgraded under a classified path either.

Path classification is a per-file side effect of the file scanner rather
than a property of the finding pipeline. Content that arrives through any
other entry point escapes it.

### 4.7 Two flags are parsed and then never read — P3

- `aegis update --force` (`crates/aegis-cli/src/main.rs:146-150`) is parsed
  and threaded into `update_bundle`, whose parameter is literally
  `_force: bool` and is never read
  (`crates/aegis-cli/src/scanner.rs:643-658`). The flag can never change
  behaviour.
- The core `ScanOptions::diff_file` field
  (`crates/aegis-core/src/scanner.rs:149`) is set by the CLI
  (`crates/aegis-cli/src/scanner.rs:126`) and read nowhere in `aegis-core`,
  because the CLI calls `scanner.scan_diff(...)` directly.

No dead *detector* name exists: all four `--anomaly-detectors` names are
validated against `DETECTOR_NAMES` (`crates/aegis-core/src/anomalies.rs:
52-80`) and each is dispatched in `analyze_anomalies_with` (`:290-315`).

### 4.8 The receipt file path was read from the environment inside the scan — CLOSED by #219

Found while fixing §4.1, and recorded here because it was a pre-existing
defect that predates this audit: the CLI read `AEGIS_RECEIPT_FILE` inside
the scan function, so the process-global environment decided where the
receipt was written while the scan ran. A sibling test that set the same
variable made another test's receipt land in the wrong place, and the
failure surfaced as `Is a directory (os error 21)` in
`test_successful_scan_writes_replacement_output_file` — a failure that only
appeared when the suite ran as a whole, and that passed in isolation.

The fix follows the repository's decision-core rule: the environment is read
once at the edge and passed in as a value
(`run_scan_and_get_exit_code_with_receipt(opts, receipt_path)`), so no test
mutates the environment. The same shape was applied to `AEGIS_ATHEON_PATH`
in the benchmark comparator. The empty-value case now fails before the
previous receipt is retired, so a bad target cannot destroy the old one.

---

## 5. Recorded, external, not fixable in this repository — P3

- **`CODECOV_TOKEN`** — unset, so the Codecov upload in
  `.github/workflows/ci.yml` fails silently (`fail_ci_if_error: false`) and
  `codecov.yml`'s targets have never been evaluated by Codecov. The
  effective floor is `scripts/coverage-floor.sh lcov.info 97.0` and the
  patch floor is 90%. Consequence worth recording: the `Safeguards`
  ruleset carries a `code_coverage` rule (`minimum_coverage: 70`,
  `max_coverage_drop: 10`) that no integration reports, so that rule
  enforces nothing, and the `max_coverage_drop` property — the one thing
  the ruleset says that the CI floor does not — is not enforced anywhere.
- **GitForge required checks** — the GitForge mirror does not carry the
  `Safeguards` required-check set, so a merge there is not gated by the
  same 22 contexts.
- **CodeRabbit** — auto-review of drafts is configured and requested; the
  OSS plan does not run it for draft pull requests.
- **Phase 14 (ML/regex hybrid ranker)** and **Phase 16 (Control Center)**
  remain open roadmap work outside this boundary.

---

## 6. Ordered next steps

Each item is independently shippable, ordered so that each one makes the
next one verifiable.

1. ~~**Fix the two P1 command-line defects** (§4.1, §4.2)~~ — **DONE,
   #219**: the environment scan goes through the shared filter path, and
   `--runs 0` is rejected at parse time instead of dividing by zero. The
   receipt-path defect found beside them (§4.8) is closed in the same pull
   request.
2. **Give the daemon a documented protocol** (§2.4) — `docs/guides/
   DAEMON.md` with the method table, the parameter and response shapes,
   and the error model — and add the one method the daemon is missing,
   `list_categories` (§2.2). The daemon does not get `update_bundle`: the
   bundle install path is client-writable rule-set replacement, which is
   the omission class the daemon's protocol deliberately keeps.
3. **Close the wire-surface capability gaps** (§2.1): at minimum `baseline`
   and `follow_symlinks`, expressed in `Config` so every surface can carry
   them.
4. **Make the scan modes exclusive and the emptiness rule honest** (§4.4,
   §4.5): `conflicts_with` on the mode flags, and an empty tree reported as
   clean rather than as an unproven inspection.
5. **Apply path classification to the findings that currently escape it**
   (§4.6): move it into the finding pipeline rather than the file scanner,
   so `--env`, `--diff`, `--stdin`, `--staged`, and the anomaly pass are
   classified too.
6. **Refresh the stale documentation** (§3.2, §3.3): the roadmap snapshot
   and the `docs/README.md` index.
7. **Record the `code_coverage` ruleset rule as unevaluated** (§5), so the
   ruleset is not read as enforcing a 70% floor that nothing reports.
8. **Retire the flags that can never fire** (§4.3, §4.7): make `--file`
   reject a directory or document what it does, and drop `--force` and the
   unread `diff_file` field.
