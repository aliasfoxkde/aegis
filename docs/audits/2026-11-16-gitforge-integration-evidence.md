# GitForge integration evidence — 2026-11-16

**Issue:** [#165](https://github.com/aliasfoxkde/aegis/issues/165) — "Prove Aegis GitForge work-item integration and Atheon parity"
**Scope:** the request path from a Control Center work request to an Aegis scan, and what that path does and does not guarantee.
**Method:** source inspection of this repository and of the Control Center checkout at `/nas/Temp/repos/Control-Center` (read-only). Every claim below names the file and line it rests on. Where a claim could not be established from source, it is listed as unverified in §6 rather than asserted.

---

## 1. Summary

The request path **exists**, and it runs through the `aegis` **executable**,
not through the library adapter that the indexed graph pointed at.

- Control Center spawns `aegis` against a work request's checkout, reads
  back a JSON report, and turns it into a Pass/Blocked decision correlated
  by work-request ID (§2).
- The `aegis_core::ControlCenterAdapter` that the issue's graph evidence
  names has **no caller anywhere in this workspace**. It is a library
  component that scans a supplied content string, and it is not on the
  integration path (§3).
- The path boundary, the exclusion handling, the fail-closed behaviour, and
  the redaction of the persisted receipt are all real and source-provable
  (§4).
- **No parity claim is made with Atheon.** No differential corpus run was
  performed in this task; §5 records the comparison basis and what is still
  missing.
- One runtime end-to-end observation is still missing: this task inspected
  the wiring, it did not execute a work request through the running Control
  Center (§6).

## 2. The proven path

Two Control Center entry points reach Aegis. Both invoke the same service.

### 2.1 Pre-pipeline gate (work request → GitForge CI trigger)

`Control-Center/apps/api/src/routes/pipeline_routes.rs`:

1. The route loads the work request, its repository, and the workspace row
   (`wr.id`, `w.path`, `r.id`), and requires the workspace to be `ready`
   and owned by the caller (`pipeline_routes.rs:661`).
2. It rejects a `base_sha` that differs from the persisted workspace base
   (`pipeline_routes.rs:694`), so the scan and the CI run are anchored to
   the same commit.
3. It canonicalizes the workspace path and requires it to live inside the
   configured workspace root (`canonical_workspace`, `pipeline_routes.rs:377`).
4. It runs the Aegis gate (`pipeline_routes.rs:704`):
   `aegis_service::scan_workspace(&workspace_path)`.
5. The decision is persisted **keyed by `work_request_id`** in the
   `aegis_scan_receipts` table, with the redacted receipt as JSON
   (`pipeline_routes.rs:719`).
6. A `Blocked` decision returns `400` and **no GitForge trigger is sent**
   (`pipeline_routes.rs:727`). The GitForge trigger
   (`POST /pipelines/trigger` with `repo_id`, `ref_name`, `old_hash`,
   `new_hash`) happens only after the gate passes (`pipeline_routes.rs:740`).

This is the correlation the issue asks about: the work-request ID reaches
the scan, the receipt is stored under that ID, and the CI trigger is
downstream of the decision.

### 2.2 Workflow path (dark factory)

`Control-Center/apps/api/src/dark_factory/service.rs:91` runs the same
`scan_workspace` service on an isolated workspace created for the work
request, before triggering the GitForge DAG. A `blocked` result fails the
job; an Aegis *error* is fatal outside dry-run (`dark_factory/service.rs:100`).

### 2.3 The scanner boundary

`Control-Center/apps/api/src/services/aegis_service.rs` is the only place
where Aegis is invoked:

- The executable path is operator configuration (`AEGIS_BIN`, default
  `/nas/Temp/bin/aegis`) — never request-selected (`aegis_service.rs:65`).
- The arguments are fixed by the service, not by the caller:
  `--format json --config <profile> scan <workspace> --severity-threshold high`
  (`aegis_service.rs:73`), plus at most one scope modifier (`--baseline` or
  `--diff`).
- The profile name is restricted to ASCII letters, digits, `_` and `-`
  (`validate_profile`, `aegis_service.rs:94`); the baseline and diff paths
  must be absolute (`optional_path_variable`, `aegis_service.rs:107`).
- The child process is bounded: 90 s timeout, 8 MiB output cap
  (`aegis_service.rs:13`, `aegis_service.rs:191`).
- The decision is `Blocked` when any finding is `high` or `critical`, else
  `Passed` (`summarize_document`, `aegis_service.rs:156`).
- The persisted receipt carries only `id`, `pattern`, `category`,
  `severity`, `file` and `line` for blocking findings, plus counts
  (`aegis_service.rs:146`). It carries **no matched content**, so the
  receipt is redacted by construction.

The scope modifier is what makes the scan "the intended checkout" rather
than "the supplied snippet": without `--baseline`/`--diff` the CLI scans
the whole workspace directory, and with them the scan is explicitly
scoped to changed content against a recorded baseline.

## 3. What the graph evidence pointed at, and where it actually landed

`aegis_core::ControlCenterAdapter` (`crates/aegis-core/src/control_center_adapter.rs`)
implements request validation, a lifecycle state machine, fail-closed error
handling, and bounded evidence records. It is a **library** component:

```
$ grep -rn "ControlCenterAdapter\|WorkRequest" --include="*.rs" crates/ \
    | grep -v crates/aegis-core/src/control_center_adapter.rs \
    | grep -v crates/aegis-core/tests/control_center_adapter_integration.rs
crates/aegis-core/src/lib.rs:60:    AdapterError, ControlCenterAdapter, EvidenceRecord, ScanResult, WorkRequest,
```

The only hit is the re-export in `lib.rs`. There is no caller in
`aegis-cli`, `aegis-mcp`, `aegis-daemon`, or `aegis-wasm`, and no route
that constructs a `WorkRequest`. The adapter scans `WorkRequest::content` —
a string — so it could not scan a checkout even if it were wired: the
integration path is the CLI, which scans a directory.

**Conclusion:** the issue's concern "avoid assuming the adapter receives or
scans the intended checkout" is answered — the adapter is not on the path.
The path that exists scans the work request's checkout directory.

## 4. Path boundaries, exclusions, and error reporting

| Boundary | Where it is enforced | Behaviour |
|---|---|---|
| Workspace must exist and be a directory | `aegis_service.rs:183` | `InvalidWorkspace` → fail closed |
| Workspace must live inside the workspace root | `canonical_workspace`, `pipeline_routes.rs:377` | 400 before any scan |
| Request-selected command | `aegis_service.rs:65` | executable is configuration only |
| Profile name shape | `aegis_service.rs:94` | invalid profile → fail closed |
| Scope modifier path shape | `aegis_service.rs:107` | non-absolute path → fail closed |
| Baseline and diff are mutually exclusive | `aegis_service.rs:58` | invalid configuration → fail closed |
| Output size | `aegis_service.rs:197` | `OutputTooLarge` → fail closed |
| Timeout | `aegis_service.rs:191` | `Timeout` → fail closed |
| Malformed report | `aegis_service.rs:200` | `Malformed` → fail closed |

Inside Aegis itself, the CLI scan of a workspace honours `.gitignore` and
`.aegisignore` (`ScanOptions::use_gitignore`, `use_aegisignore`), skips the
`.aegis/` state directory, and reports a file it could not read through the
inspection ledger rather than by silently dropping it. A scan whose
findings cannot be reconciled with the inspected files produces an
incomplete receipt, which the CLI reports with exit code 3.

## 5. Atheon comparison basis — no parity claim

Aegis ships **677 rules across 35 categories** (`docs/patterns/README.md`
is the source of truth; `cargo test -p aegis-patterns --test doc_count_drift`
keeps the documented counts honest).

Atheon-Enhanced exposes directory and file scanning through
`core.runner.ScanDir` and `core.runner.ScanFile`, and its AST layer through
`core/ast_patterns.go`. Those are the entry points an equivalence claim
would have to compare, and they are *not* the same shape as Aegis's
`Scanner::scan_dir`: Atheon's walker collects walk errors into
`Stats.Errors` rather than dropping them, and its AST rules are
hand-written per-language detectors rather than a shared rule corpus.

**What was not done:** no corpus was scanned through both scanners and
compared finding-by-finding. Atheon is not installed on this host —
`/nas/Temp/bin` holds only Aegis builds and `command -v atheon` finds
nothing — so a differential run was not possible here. Without that run,
any statement of the form "Aegis matches Atheon on rule, severity,
location, entropy, and AST cases" would be unevidenced, so this record
does not make one. The concrete remaining work is a differential run over
a representative GitForge checkout, comparing matched findings,
divergences, and accepted exclusions — with the false-negative cases named
explicitly.

## 6. Unverified in this task

- No live work request was executed through a running Control Center
  instance in this task. §2 is source evidence of the wiring, not a
  recorded end-to-end run.
- The Control Center's own test suite was not executed here; the file
  references are read from the checkout, not from a green CI run.
- The GitForge trigger response beyond the first response (retry policy,
  duplicate-trigger handling) was not traced.
- The differential Atheon comparison of §5 was not performed: Atheon is
  not installed on this host, so there was nothing to compare against.
- The `aegis_core::ControlCenterAdapter` remains unwired. It is kept
  because it is a tested library surface, not because it serves the
  integration path.

## 7. What Aegis owes the integration path

The behaviours the Control Center depends on are pinned by tests in this
repository, so a change that breaks them fails here first:

| Behaviour | Test |
|---|---|
| A workspace scan reports findings and exits 1 | `crates/aegis-cli/tests/cli_integration.rs` |
| A clean scan exits 0 and writes a receipt with an inspection ledger | `crates/aegis-cli/tests/cli_integration.rs` |
| The JSON report carries `findings` and `stats` and no matched content | `crates/aegis-cli/tests/ci_gate_contract.rs`, `crates/aegis-cli/src/output.rs` |
| The report carries every field the gate decides on (`id`, `pattern`, `category`, `severity`, `location.file`, `location.line`) | `crates/aegis-cli/tests/ci_gate_contract.rs` |
| The exit code agrees with the gate's decision rule (a high or critical finding fails the run) | `crates/aegis-cli/tests/ci_gate_contract.rs` |
| The report exposes the inspection ledger that backs the fail-closed exit | `crates/aegis-cli/tests/ci_gate_contract.rs` |
| A missing or unreadable input is an error, not a clean pass | `crates/aegis-core/tests/scanner_behaviors.rs` |
| Exclusions (`.gitignore`, `.aegisignore`, `.aegis/`) are honoured | `crates/aegis-core/tests/scanner_behaviors.rs` |
| The CLI surfaces an incomplete scan instead of a clean pass | `crates/aegis-core/src/receipt.rs`, `crates/aegis-cli/src/scanner.rs` |
