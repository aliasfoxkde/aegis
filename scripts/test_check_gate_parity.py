#!/usr/bin/env python3
"""Tests for scripts/check-gate-parity.py.

The parity script is the gate that notices when a change lowers a floor.
Its own parsing has to be right, or a floor can be lowered without the
gate seeing it. Deterministic: fixed inputs, no network, no clock. Run
from the repository root with:

    python3 scripts/test_check_gate_parity.py
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

HELPER_PATH = Path(__file__).resolve().parent / "check-gate-parity.py"

_SPEC = importlib.util.spec_from_file_location("check_gate_parity", HELPER_PATH)
assert _SPEC is not None and _SPEC.loader is not None
helper = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(helper)

WORKFLOW = """
  coverage:
    name: Coverage
    env:
      PATCH_COVERAGE_FLOOR: 90.0
    steps:
      - name: Enforce coverage floor
        run: scripts/coverage-floor.sh lcov.info 97.0
      - name: Enforce patch coverage floor
        run: scripts/patch-coverage-floor.py lcov.info "$BASE" HEAD "$PATCH_COVERAGE_FLOOR"
"""


class PatchFloorTest(unittest.TestCase):
    def test_the_floor_is_read_from_the_workflow(self) -> None:
        self.assertEqual(helper.patch_coverage_floor(WORKFLOW), 90.0)

    def test_a_workflow_without_the_floor_reads_as_none(self) -> None:
        self.assertIsNone(helper.patch_coverage_floor("name: Coverage\n"))

    def test_a_whole_percent_reads_as_a_float(self) -> None:
        self.assertEqual(
            helper.patch_coverage_floor("PATCH_COVERAGE_FLOOR: 97.5"), 97.5
        )

    def test_the_wiring_is_detected(self) -> None:
        self.assertTrue(helper.patch_floor_is_wired(WORKFLOW))

    def test_an_unwired_workflow_is_detected(self) -> None:
        self.assertFalse(
            helper.patch_floor_is_wired("run: scripts/coverage-floor.sh lcov.info 97.0")
        )


class ProjectFloorTest(unittest.TestCase):
    def test_the_project_floor_is_still_read(self) -> None:
        self.assertEqual(helper.coverage_floor(WORKFLOW), 97.0)

    def test_a_workflow_without_the_project_floor_reads_as_none(self) -> None:
        self.assertIsNone(helper.coverage_floor("name: Coverage\n"))


class CodecovTargetTest(unittest.TestCase):
    def test_both_targets_are_read(self) -> None:
        text = """
coverage:
  status:
    project:
      default:
        target: 97%
    patch:
      default:
        target: 90%
"""
        self.assertEqual(
            helper.codecov_targets(text), {"project": 97.0, "patch": 90.0}
        )

    def test_the_repositorys_own_codecov_file_is_read(self) -> None:
        """The real file, not a fixture that resembles it.

        `project:` is followed by `default:` at a deeper indentation, so
        a body that stopped at the next key of any kind would never
        reach the `target:` line and the gate would never fire.
        """
        text = (HELPER_PATH.parent.parent / "codecov.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            helper.codecov_targets(text), {"project": 97.0, "patch": 90.0}
        )

    def test_a_scope_without_a_target_is_skipped(self) -> None:
        text = """
coverage:
  status:
    project:
      default:
        threshold: 1%
"""
        self.assertEqual(helper.codecov_targets(text), {})


if __name__ == "__main__":
    unittest.main()
