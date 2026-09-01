# Control Center Adapter CLI — Tranche Receipt

**Date:** 2026-09-01
**Branch:** `codex/control-center-adapter-cli`
**Repo:** `platform-aegis-validation-20260824`
**Scope:** Expose the existing fail-closed `ControlCenterAdapter` contract through
the Aegis CLI in the smallest maintainable way, with a documented command,
input/output contract, and real unit + integration tests.

---

## Summary

Added the `aegis adapter scan` subcommand to the `aegis-cli` crate. It is a
thin renderer over the existing `aegis_core::control_center_adapter`
contract — every safety property, evidence-redaction rule, and lifecycle
transition remains owned by `ControlCenterAdapter`. The CLI layer only:

1. Resolves work-request content from inline text or a file path.
2. Forwards a `WorkRequest` to `ControlCenterAdapter::scan_work_sync`.
3. Renders the result as a JSON document on stdout.
4. Maps the three terminal `ScanResult` variants to documented exit codes.
5. Optionally persists redacted evidence to a caller-supplied path.

No safety properties were weakened. No scanner or pattern data was
invented. No unrelated code was rewritten.

## Files Touched

| File | Change |
|------|--------|
| `crates/aegis-cli/src/adapter.rs` | **New** — CLI surface over the adapter contract |
| `crates/aegis-cli/src/lib.rs` | Expose `adapter` module + new types |
| `crates/aegis-cli/src/main.rs` | Wire `aegis adapter scan` subcommand |
| `tests/adapter_cli_integration.rs` | **New** — 11 end-to-end CLI integration tests |
| `docs/guides/CLI.md` | Document the new command and exit-code table |
| `docs/MODULES.md` | Note the `aegis-cli` adapter rendering seam |
| `PLATFORM_INTEGRATION.md` | Add the new entry to the inbound API surface |
| `Cargo.toml` | Add `serde_json` dev-dependency for the integration test |

## Command Contract

```text
aegis adapter scan \
    --work-request-id <ID> \
    --source <SOURCE> \
    [--content <CONTENT> | --content-file <PATH>] \
    [--evidence-output <PATH>]
```

* `--work-request-id` and `--source` are required and must be non-empty.
* Exactly one of `--content` or `--content-file` is required.
* `--content-file` is read fully; missing or unreadable files yield `blocked`.
* `--evidence-output`, when set, receives the adapter's atomic JSON
  evidence persistence (raw scanned content is never copied in).

### JSON Response (stdout)

```json
{
  "work_request_id": "wr-123",
  "scan_result": "pass",
  "allows_work": true,
  "evidence_ref": "<sha256-hex>",
  "finding_count": 0,
  "lifecycle_state": "completed",
  "transition_count": 4,
  "evidence_path": "/optional/evidence.json"
}
```

On `blocked`, `scan_result` is `"blocked"`, `allows_work` is `false`,
`finding_count` is `0`, and `error` carries the human-readable cause
(e.g. `Malformed input: Work request content is empty`). `evidence_ref`,
`evidence_path`, and `highest_severity` are omitted when not applicable.

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | `pass` — work may proceed, no findings |
| 1 | `fail` — work may proceed, findings present |
| 2 | `blocked` — adapter failed closed; do **not** proceed |
| 3 | Invalid arguments (clap parse failure surfaces as code 3) |

This matches the existing `aegis scan` exit-code table in
`docs/guides/CLI.md` so platform callers can rely on a single rule.

## Quality Gates — Exact Commands and Results

### 1. `cargo fmt --all`

```bash
cargo fmt --all
```

Result: 4 files reformatted (`crates/aegis-cli/src/adapter.rs`,
`crates/aegis-cli/src/lib.rs`, `crates/aegis-cli/src/main.rs`,
`tests/adapter_cli_integration.rs`). No diff against `cargo fmt --check`.

```bash
cargo fmt --all -- --check ; echo "fmt exit: $?"
# fmt exit: 0
```

### 2. `cargo clippy --workspace --all-targets -- -D warnings`

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Result: clean. Finished with `Finished `dev` profile [unoptimized +
debuginfo] target(s) in 1.26s`. No warnings, no errors.

### 3. `cargo test --workspace --no-fail-fast`

```bash
cargo test --workspace --no-fail-fast
```

Result: every binary, lib, integration, and doc test passed. Highlights:

| Suite | Result |
|-------|--------|
| `tests/adapter_cli_integration.rs` (new) | **11 passed, 0 failed** |
| `aegis-cli` unit tests (incl. `adapter::tests`) | **71 passed, 0 failed** |
| `aegis-core` lib + integration | **328 + 36 passed, 0 failed** |
| `aegis-mcp` lib | 38 passed, 0 failed |
| `aegis-daemon` lib | 13 passed, 0 failed |
| `aegis-patterns` lib | 18 passed, 0 failed |
| Doc-tests (`aegis_core`) | 2 passed, 0 failed |
| All other crates | 0 failed |

Zero failures across the workspace.

### 4. `cargo build -p aegis-cli --bin aegis`

```bash
cargo build -p aegis-cli --bin aegis
```

Result: built in 10.31s, `Finished `dev` profile`.

## Manual Smoke Commands

### `aegis adapter --help`

```bash
cargo run --quiet -p aegis-cli --bin aegis -- adapter --help
```

Output:

```text
Run the Control Center pre-pipeline adapter over a single work request

Usage: aegis adapter [OPTIONS] <COMMAND>

Commands:
  scan  Scan a single work request through the fail-closed adapter
  help  Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose  Enable verbose output
  -q, --quiet    Suppress output except findings
  -h, --help     Print help
```

### Clean content → `pass`

```bash
cargo run --quiet -p aegis-cli --bin aegis -- adapter scan \
  --work-request-id wr-smoke-1 \
  --source src/main.rs \
  --content 'fn main() { println!("hello"); }'
```

Stdout (exit code `0`):

```json
{"work_request_id":"wr-smoke-1","scan_result":"pass","allows_work":true,"evidence_ref":"8486640f656161782668fc9a71b0b7788a412a27a5814da4cc5f822ed3d44672","finding_count":0,"lifecycle_state":"completed","transition_count":4}
```

### Empty content → `blocked` (fail closed)

```bash
cargo run --quiet -p aegis-cli --bin aegis -- adapter scan \
  --work-request-id wr-smoke-2 \
  --source src/main.rs \
  --content ''
```

Stderr + stdout (exit code `2`):

```text
Malformed input: Work request content is empty
{"work_request_id":"wr-smoke-2","scan_result":"blocked","allows_work":false,"evidence_ref":"","finding_count":0,"lifecycle_state":"unknown","transition_count":0,"error":"Malformed input: Work request content is empty"}
```

## Unit Tests Added (`crates/aegis-cli/src/adapter.rs`)

* `run_adapter_scan_clean_content_emits_pass` — clean content returns
  `pass` with exit 0 and a 64-char `evidence_ref`.
* `run_adapter_scan_records_lifecycle_progress` — verifies the documented
  `Pending → Accepted → Running → Completed` (4 transitions) lifecycle.
* `run_adapter_scan_rejects_empty_content` — empty content → blocked.
* `run_adapter_scan_rejects_empty_work_request_id` — empty id → blocked.
* `run_adapter_scan_requires_content_or_file` — neither flag → blocked.
* `run_adapter_scan_rejects_both_content_and_file` — both flags → blocked.
* `run_adapter_scan_reads_content_file` — `--content-file` reads correctly.
* `run_adapter_scan_reports_missing_content_file` — missing file → blocked.
* `run_adapter_scan_persists_evidence_when_requested` —
  `--evidence-output` writes a redacted JSON document.
* `resolve_content_rejects_missing_both_flags` /
  `resolve_content_rejects_both_flags_supplied` /
  `resolve_content_returns_inline_when_only_content` — content resolution
  helpers.
* `classify_error_returns_stable_labels` — every `AdapterError` variant
  maps to a stable label.
* `response_serializes_without_receipt_payload` — JSON shape matches the
  documented contract (omitted `evidence_path` / `error` / `highest_severity`
  when not applicable).

## Integration Tests Added (`tests/adapter_cli_integration.rs`)

End-to-end tests that invoke the real binary, parse the JSON stdout, and
check exit codes. All 11 pass.

* `adapter_scan_clean_content_returns_pass_exit_zero`
* `adapter_scan_missing_content_returns_blocked_with_exit_two`
* `adapter_scan_empty_content_returns_blocked_with_exit_two`
* `adapter_scan_empty_work_request_id_returns_blocked`
* `adapter_scan_both_content_and_content_file_rejected`
* `adapter_scan_reads_content_file_and_reports_pass`
* `adapter_scan_missing_content_file_is_blocked`
* `adapter_scan_persists_redacted_evidence_to_output_path` (asserts raw
  scanned content is **not** copied into the evidence file)
* `adapter_scan_idempotent_replay_returns_same_result` (same work-request
  ID + content returns the same `evidence_ref` and `scan_result`)
* `adapter_help_lists_subcommand`
* `adapter_scan_help_describes_required_flags`

## Safety Properties Preserved

* **Fail-closed.** The CLI maps every error path (empty ID, empty content,
  unreadable file, both content flags, adapter error) to `scan_result =
  "blocked"` and exit code `2`. The adapter's internal panic-catch and
  `WorkRequestConflict` paths are untouched.
* **Redacted evidence.** `AdapterScanResponse` never embeds raw content;
  only the SHA-256 `evidence_ref`. `--evidence-output` reuses
  `ControlCenterAdapter::persist_evidence`, which already strips the
  matched content from receipts.
* **Lifecycle invariants.** `lifecycle_state` and `transition_count` are
  populated from the adapter's `LifecycleRecord`, so the documented
  forward-only state machine is observable end-to-end.

## Remaining Gaps (out of scope for this tranche)

* No auto-update / streaming protocol — adapter CLI is one work request per
  invocation by design.
* No `--format json|sarif|human` switch — adapter output is intentionally
  machine-readable JSON only; Control Center and GitForge parse it as-is.
* No coverage run (`cargo llvm-cov`) was executed — the repo's CI runs it
  on the Fedora builder per `PLATFORM_INTEGRATION.md`. Local coverage is
  unverified for this tranche.
* Pre-existing repository gap: the `.platform-mcp-fixture/` directory at
  the repo root is not part of this branch's commit (excluded per task
  instructions).