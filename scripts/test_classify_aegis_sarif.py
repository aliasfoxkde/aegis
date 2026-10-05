#!/usr/bin/env python3
"""Tests for scripts/ci/classify_aegis_sarif.py.

Deterministic: fixed fixtures, no network, no clock, no external
dependencies. Run from the repository root with:

    python3 -m unittest scripts/test_classify_aegis_sarif.py
    # or: python3 scripts/test_classify_aegis_sarif.py
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HELPER_PATH = Path(__file__).resolve().parent / "ci" / "classify_aegis_sarif.py"

_SPEC = importlib.util.spec_from_file_location("classify_aegis_sarif", HELPER_PATH)
assert _SPEC is not None and _SPEC.loader is not None
helper = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(helper)


def ledger_unit(status: str, required: bool = True, unit_id: str = "src/main.rs") -> dict:
    return {"unit_id": unit_id, "status": status, "required": required}


def sarif_report(units: list, schema_version: int = 1) -> str:
    """One-run SARIF document in the shape crates/aegis-cli emits."""
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "aegis", "version": "0.0.0"}},
                    "results": [],
                    "properties": {
                        "inspectionLedger": {
                            "schema_version": schema_version,
                            "units": units,
                        }
                    },
                }
            ],
        }
    )


def json_report(units: list, schema_version: int = 1) -> str:
    """Plain JSON document in the shape crates/aegis-cli emits."""
    return json.dumps(
        {
            "findings": [],
            "stats": {
                "files_scanned": 1,
                "inspection_ledger": {
                    "schema_version": schema_version,
                    "units": units,
                },
            },
        }
    )


class ClassifyReportTests(unittest.TestCase):
    """classify_report() over in-memory fixtures."""

    def test_safe_scan_exit_zero(self):
        report = sarif_report([ledger_unit("analyzed")])
        self.assertEqual(helper.classify_report(report, "0"), "SAFE")

    def test_findings_exit_one(self):
        report = sarif_report([ledger_unit("analyzed")])
        self.assertEqual(helper.classify_report(report, "1"), "FINDINGS")

    def test_suppressed_required_unit_stays_safe(self):
        report = sarif_report([ledger_unit("suppressed")])
        self.assertEqual(helper.classify_report(report, "0"), "SAFE")
        self.assertEqual(helper.classify_report(report, "1"), "FINDINGS")

    def test_optional_unit_in_any_status_is_not_gating(self):
        # Only required units gate allows_safe, mirroring the Rust rule.
        for status in sorted(helper.KNOWN_STATUSES):
            with self.subTest(status=status):
                report = sarif_report(
                    [ledger_unit("analyzed"), ledger_unit(status, required=False)]
                )
                self.assertEqual(helper.classify_report(report, "0"), "SAFE")

    def test_required_non_safe_status_blocks_even_on_exit_zero(self):
        # Analyzed/Suppressed are excluded: every other required variant
        # must block, regardless of the exit code.
        for status in sorted(helper.KNOWN_STATUSES - helper.SAFE_STATUSES):
            for exit_code in ("0", "1"):
                with self.subTest(status=status, exit_code=exit_code):
                    report = sarif_report([ledger_unit(status)])
                    self.assertEqual(helper.classify_report(report, exit_code), "BLOCKED")

    def test_empty_ledger_blocks(self):
        report = sarif_report([])
        self.assertEqual(helper.classify_report(report, "0"), "BLOCKED")

    def test_multiple_runs_all_ledgers_must_allow_safe(self):
        safe = ledger_unit("analyzed")
        both_safe = json.dumps(
            {
                "runs": [
                    {"properties": {"inspectionLedger": {"schema_version": 1, "units": [safe]}}},
                    {"properties": {"inspectionLedger": {"schema_version": 1, "units": [safe]}}},
                ]
            }
        )
        self.assertEqual(helper.classify_report(both_safe, "0"), "SAFE")

        one_blocked = json.dumps(
            {
                "runs": [
                    {"properties": {"inspectionLedger": {"schema_version": 1, "units": [safe]}}},
                    {
                        "properties": {
                            "inspectionLedger": {
                                "schema_version": 1,
                                "units": [ledger_unit("failed")],
                            }
                        }
                    },
                ]
            }
        )
        self.assertEqual(helper.classify_report(one_blocked, "0"), "BLOCKED")


class MalformedReportTests(unittest.TestCase):
    """Anything that cannot be trusted must fail closed.

    These go through main(), the exact entry point the workflow calls:
    classify_report() surfaces a MalformedReport for diagnostics, and
    main() turns that into a printed BLOCKED with exit 0.
    """

    def run_classify(self, report_text: str | None, exit_code: str = "0") -> str:
        """Run helper.main() on a fixture file; returns its stdout."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report"
            if report_text is not None:
                path.write_text(report_text, encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_status = helper.main([str(path), exit_code])
        self.assertEqual(exit_status, 0)
        return stdout.getvalue()

    def assertBlocked(self, report_text: str | None, exit_code: str = "0"):
        self.assertEqual(self.run_classify(report_text, exit_code), "BLOCKED\n")

    def test_required_failed_blocks(self):
        self.assertBlocked(sarif_report([ledger_unit("failed")]))

    def test_required_skipped_blocks(self):
        self.assertBlocked(sarif_report([ledger_unit("skipped")]))

    def test_required_unsupported_blocks(self):
        self.assertBlocked(sarif_report([ledger_unit("unsupported")]))

    def test_invalid_json_blocks(self):
        self.assertBlocked("{not json")

    def test_json_scalar_blocks(self):
        self.assertBlocked("42")

    def test_sarif_without_runs_blocks(self):
        self.assertBlocked(json.dumps({"version": "2.1.0"}))

    def test_empty_runs_list_blocks(self):
        self.assertBlocked(json.dumps({"runs": []}))

    def test_runs_not_a_list_blocks(self):
        self.assertBlocked(json.dumps({"runs": {}}))

    def test_run_without_properties_blocks(self):
        self.assertBlocked(json.dumps({"runs": [{"results": []}]}))

    def test_run_without_ledger_blocks(self):
        self.assertBlocked(json.dumps({"runs": [{"properties": {}}]}))

    def test_ledger_without_schema_version_blocks(self):
        report = json.dumps(
            {"runs": [{"properties": {"inspectionLedger": {"units": [ledger_unit("analyzed")]}}}]}
        )
        self.assertBlocked(report)

    def test_boolean_schema_version_blocks(self):
        # bool is not a u16: serde would reject it.
        report = json.dumps(
            {
                "runs": [
                    {
                        "properties": {
                            "inspectionLedger": {
                                "schema_version": True,
                                "units": [ledger_unit("analyzed")],
                            }
                        }
                    }
                ]
            }
        )
        self.assertBlocked(report)

    def test_unsupported_schema_versions_block(self):
        # Version 1 is the only schema this classifier understands. A
        # future or invalid version must never inherit version-1 semantics.
        for version in (0, 2, 65536):
            with self.subTest(version=version):
                self.assertBlocked(sarif_report([ledger_unit("analyzed")], version))

    def test_ledger_without_units_blocks(self):
        report = json.dumps(
            {"runs": [{"properties": {"inspectionLedger": {"schema_version": 1}}}]}
        )
        self.assertBlocked(report)

    def test_unit_missing_required_flag_blocks(self):
        unit = {"unit_id": "src/main.rs", "status": "analyzed"}
        self.assertBlocked(sarif_report([unit]))

    def test_unit_missing_status_blocks(self):
        unit = {"unit_id": "src/main.rs", "required": True}
        self.assertBlocked(sarif_report([unit]))

    def test_empty_unit_id_blocks(self):
        self.assertBlocked(sarif_report([ledger_unit("analyzed", unit_id=" ")]))

    def test_unknown_status_variant_blocks(self):
        # serde rejects unknown enum variants; the classifier must too,
        # otherwise an unfamiliar status would silently pass the gate.
        self.assertBlocked(sarif_report([ledger_unit("partially-analyzed")]))

    def test_json_report_without_ledger_blocks(self):
        self.assertBlocked(json.dumps({"findings": [], "stats": {"files_scanned": 1}}))

    def test_report_of_unknown_shape_blocks(self):
        self.assertBlocked(json.dumps({"hello": "world"}))

    def test_unknown_exit_codes_block(self):
        # classify_report() raises for an invalid protocol input; main()
        # catches that error and prints BLOCKED, which the malformed-report
        # entrypoint tests below verify.
        report = sarif_report([ledger_unit("analyzed")])
        for exit_code in ("2", "3", "130", "-1", "abc", ""):
            with self.subTest(exit_code=exit_code):
                with self.assertRaises(helper.MalformedReport):
                    helper.classify_report(report, exit_code)
                self.assertBlocked(report, exit_code)


class JsonReportShapeTests(unittest.TestCase):
    """The supply-chain job scans with --format json; the ledger then lives
    at stats.inspection_ledger."""

    def test_json_report_safe_and_findings(self):
        report = json_report([ledger_unit("analyzed")])
        self.assertEqual(helper.classify_report(report, "0"), "SAFE")
        self.assertEqual(helper.classify_report(report, "1"), "FINDINGS")

    def test_json_report_partial_scan_blocks(self):
        report = json_report([ledger_unit("failed")])
        self.assertEqual(helper.classify_report(report, "1"), "BLOCKED")


class CommandLineTests(unittest.TestCase):
    """End-to-end contract: exactly one status token on stdout, exit 0."""

    def run_helper(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(HELPER_PATH), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_safe_scan_exit_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "aegis-results.sarif"
            report.write_text(sarif_report([ledger_unit("analyzed")]), encoding="utf-8")
            result = self.run_helper(str(report), "0")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "SAFE\n")

    def test_findings_exit_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "aegis-results.sarif"
            report.write_text(sarif_report([ledger_unit("analyzed")]), encoding="utf-8")
            result = self.run_helper(str(report), "1")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "FINDINGS\n")

    def test_partial_scan_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "aegis-results.sarif"
            report.write_text(sarif_report([ledger_unit("failed")]), encoding="utf-8")
            result = self.run_helper(str(report), "1")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "BLOCKED\n")

    def test_missing_report_file_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "does-not-exist.sarif"
            result = self.run_helper(str(missing), "0")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "BLOCKED\n")

    def test_empty_report_file_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "aegis-results.sarif"
            report.write_text("", encoding="utf-8")
            result = self.run_helper(str(report), "0")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "BLOCKED\n")

    def test_usage_error_blocks(self):
        result = self.run_helper()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "BLOCKED\n")
        self.assertIn("usage:", result.stderr)


if __name__ == "__main__":
    unittest.main()
