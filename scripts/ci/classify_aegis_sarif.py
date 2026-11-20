#!/usr/bin/env python3
"""Classify an Aegis scan report for CI gating. Prints exactly one of
SAFE, FINDINGS, or BLOCKED and exits 0.

Under fail-closed semantics a partial scan still exits 1 with a valid
report, so the exit code alone cannot distinguish "findings" from "the
scan did not cover everything". Aegis therefore embeds its inspection
ledger in the report, and this helper applies the canonical
`InspectionLedger::allows_safe` rule to it:

    at least one unit, and every required unit status is Analyzed or
    Suppressed

Accepted report shapes (the ledger is the same schema in both):

  * SARIF (`--format sarif`):  runs[].properties.inspectionLedger
  * JSON  (`--format json`):   stats.inspection_ledger

Classification:

  BLOCKED   missing/unreadable/invalid report, missing or malformed runs
            or ledger, a required unit whose status is not in the ledger's
            safe set (analyzed, suppressed), or an exit code other than
            0 or 1
  SAFE      ledger allows safe and exit code is 0
  FINDINGS  ledger allows safe and exit code is 1

The serialization casing mirrors crates/aegis-core/src/finding.rs; only
ledger schema version 1 is accepted, so an unfamiliar future format blocks:
statuses are serde `snake_case` variants ("analyzed", "suppressed",
"failed", ...), ledger fields are `schema_version` and `units`, unit
fields are `unit_id`, `status`, `required`, and `reason`. The SARIF
wrapper renames the ledger key to camelCase `inspectionLedger`
(crates/aegis-cli/src/output.rs).

Usage:
    python3 scripts/ci/classify_aegis_sarif.py <report-file> <exit-code>

Stdlib only; safe to run on any CI runner with Python 3.9+.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SAFE = "SAFE"
FINDINGS = "FINDINGS"
BLOCKED = "BLOCKED"

# Every `InspectionStatus` variant, as serde serializes it.
KNOWN_STATUSES = frozenset(
    {
        "discovered",
        "analyzed",
        "skipped",
        "excluded",
        "unsupported",
        "failed",
        "suppressed",
    }
)

# The statuses `InspectionLedger::allows_safe` accepts for required units.
SAFE_STATUSES = frozenset({"analyzed", "suppressed"})
SUPPORTED_LEDGER_SCHEMA_VERSION = 1

# Exit codes a scan is allowed to report; anything else is unknown and
# fails closed.
KNOWN_EXIT_CODES = frozenset({0, 1})


class MalformedReport(Exception):
    """A report cannot be trusted for a gating decision."""


def _require_dict(value: object, what: str) -> dict:
    if not isinstance(value, dict):
        raise MalformedReport(f"{what} must be an object")
    return value


def _require_member(container: dict, key: str, what: str) -> object:
    if key not in container:
        raise MalformedReport(f"{what} is missing {key!r}")
    return container[key]


def _validate_schema_version(ledger: dict, what: str) -> None:
    version = _require_member(ledger, "schema_version", what)
    # serde deserializes a u16: JSON booleans and out-of-range integers
    # would be rejected there, so they are malformed here too.
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or not 0 <= version <= 0xFFFF
    ):
        raise MalformedReport(f"{what}.schema_version must be a u16 integer")
    if version != SUPPORTED_LEDGER_SCHEMA_VERSION:
        raise MalformedReport(
            f"{what}.schema_version {version} is unsupported; "
            f"expected {SUPPORTED_LEDGER_SCHEMA_VERSION}"
        )


def _validate_unit(unit: object, what: str) -> dict:
    _require_dict(unit, what)
    unit_id = _require_member(unit, "unit_id", what)
    if not isinstance(unit_id, str) or not unit_id.strip():
        raise MalformedReport(f"{what}.unit_id must be a non-empty string")
    status = _require_member(unit, "status", what)
    if not isinstance(status, str) or status not in KNOWN_STATUSES:
        raise MalformedReport(f"{what}.status {status!r} is not a known variant")
    required = _require_member(unit, "required", what)
    if not isinstance(required, bool):
        raise MalformedReport(f"{what}.required must be a boolean")
    # `reason` is Option<String>: absent, null, and string are all valid.
    reason = unit.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise MalformedReport(f"{what}.reason must be a string or null")
    return {"status": status, "required": required}


def _validate_ledger(ledger: object, what: str) -> list:
    _require_dict(ledger, what)
    _validate_schema_version(ledger, what)
    units = _require_member(ledger, "units", what)
    if not isinstance(units, list):
        raise MalformedReport(f"{what}.units must be a list")
    return [_validate_unit(unit, f"{what}.units[{index}]") for index, unit in enumerate(units)]


def _extract_ledgers(report_text: str) -> list:
    if not report_text.strip():
        raise MalformedReport("report is empty")
    try:
        document = json.loads(report_text)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise MalformedReport(f"report is not valid JSON: {exc}") from exc
    _require_dict(document, "report")

    if "runs" in document:
        runs = document["runs"]
        if not isinstance(runs, list) or not runs:
            raise MalformedReport("SARIF 'runs' must be a non-empty list")
        ledgers = []
        for index, run in enumerate(runs):
            what = f"runs[{index}]"
            _require_dict(run, what)
            properties = _require_dict(
                _require_member(run, "properties", what), f"{what}.properties"
            )
            ledger = _require_member(
                properties, "inspectionLedger", f"{what}.properties"
            )
            ledgers.append(
                _validate_ledger(ledger, f"{what}.properties.inspectionLedger")
            )
        return ledgers

    if "stats" in document:
        stats = _require_dict(document["stats"], "stats")
        ledger = _require_member(stats, "inspection_ledger", "stats")
        return [_validate_ledger(ledger, "stats.inspection_ledger")]

    raise MalformedReport("report embeds no inspection ledger")


def _ledger_allows_safe(units: list) -> bool:
    """Mirror of `InspectionLedger::allows_safe` over validated units."""
    if not units:
        return False
    return all(
        not unit["required"] or unit["status"] in SAFE_STATUSES for unit in units
    )


def _parse_exit_code(exit_code_text: str) -> int:
    try:
        exit_code = int(str(exit_code_text).strip())
    except ValueError as exc:
        raise MalformedReport(f"exit code {exit_code_text!r} is not an integer") from exc
    if exit_code not in KNOWN_EXIT_CODES:
        raise MalformedReport(f"unknown exit code {exit_code}")
    return exit_code


def classify_report(report_text: str, exit_code_text: str) -> str:
    """Classify one report; raises MalformedReport instead of blocking so
    callers can log why. Returns SAFE, FINDINGS, or BLOCKED."""
    exit_code = _parse_exit_code(exit_code_text)
    ledgers = _extract_ledgers(report_text)
    if any(not _ledger_allows_safe(units) for units in ledgers):
        return BLOCKED
    return SAFE if exit_code == 0 else FINDINGS


def main(argv: list | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} <report-file> <exit-code>", file=sys.stderr)
        print(BLOCKED)
        return 0

    report_path, exit_code_text = argv
    try:
        report_text = Path(report_path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"blocked: cannot read report: {exc}", file=sys.stderr)
        print(BLOCKED)
        return 0

    try:
        status = classify_report(report_text, exit_code_text)
    except MalformedReport as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        status = BLOCKED
    except Exception as exc:  # defensive net: never fail open
        print(f"blocked: unexpected error: {exc}", file=sys.stderr)
        status = BLOCKED

    print(status)
    return 0


if __name__ == "__main__":
    sys.exit(main())
