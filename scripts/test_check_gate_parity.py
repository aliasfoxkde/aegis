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

CI_WORKFLOW = ".github/workflows/ci.yml"


def files(**bodies: str | None) -> dict[str, bytes | None]:
    """A file map for the comparison, keyed the way the script keys it."""
    return {
        name: (body.encode("utf-8") if body is not None else None)
        for name, body in bodies.items()
    }


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


# The detectors below are the ones that decide whether a floor can be
# lowered. The helper tests above read numbers out of text; these check
# that a weakening is actually reported.


MANIFEST_DENY = """
[workspace.lints.rust]
unsafe_code = "deny"
missing_docs = "warn"
"""

DENY_TOML = """
[advisories]
ignore = ["RUSTSEC-2021-0001"]

[licenses]
allow = ["MIT"]
"""

CODECOV = """
coverage:
  status:
    project:
      default:
        target: 97%
    patch:
      default:
        target: 90%
"""

GATE_WORKFLOW = """
  gate-policy:
    name: Gate policy
    steps:
      - name: Check that no quality gate was weakened
        run: scripts/check-gate-parity.py "$BASE_REF"
      - name: Check that no lint suppression expired
        run: scripts/check-allow-expiry.sh
      - name: Diff against committed notices
        run: git diff --exit-code THIRD-PARTY-NOTICES.md
"""


class LintDetectorTest(unittest.TestCase):
    def test_a_relaxed_lint_is_reported(self) -> None:
        base = files(**{"Cargo.toml": MANIFEST_DENY})
        head = files(
            **{"Cargo.toml": MANIFEST_DENY.replace('"deny"', '"allow"')}
        )
        problems = helper.gate_problems(base, head)
        self.assertTrue(
            any("unsafe_code was relaxed" in problem for problem in problems),
            problems,
        )

    def test_a_removed_lint_is_reported(self) -> None:
        base = files(**{"Cargo.toml": MANIFEST_DENY})
        head = files(
            **{"Cargo.toml": MANIFEST_DENY.replace('missing_docs = "warn"\n', "")}
        )
        problems = helper.gate_problems(base, head)
        self.assertTrue(
            any("missing_docs was removed" in problem for problem in problems),
            problems,
        )

    def test_a_raised_lint_is_not_reported(self) -> None:
        base = files(**{"Cargo.toml": MANIFEST_DENY})
        head = files(
            **{"Cargo.toml": MANIFEST_DENY.replace('"warn"', '"deny"')}
        )
        self.assertEqual(helper.gate_problems(base, head), [])


class DenyDetectorTest(unittest.TestCase):
    def test_an_added_advisory_waiver_is_reported(self) -> None:
        base = files(**{"deny.toml": DENY_TOML})
        head = files(
            **{
                "deny.toml": DENY_TOML.replace(
                    'ignore = ["RUSTSEC-2021-0001"]',
                    'ignore = ["RUSTSEC-2021-0001", "RUSTSEC-2024-0002"]',
                )
            }
        )
        problems = helper.gate_problems(base, head)
        self.assertTrue(
            any("RUSTSEC-2024-0002" in problem for problem in problems), problems
        )

    def test_an_added_license_is_reported(self) -> None:
        base = files(**{"deny.toml": DENY_TOML})
        head = files(
            **{"deny.toml": DENY_TOML.replace('allow = ["MIT"]', 'allow = ["MIT", "Apache-2.0"]')}
        )
        problems = helper.gate_problems(base, head)
        self.assertTrue(
            any("Apache-2.0" in problem for problem in problems), problems
        )

    def test_a_removed_deny_file_is_reported(self) -> None:
        base = files(**{"deny.toml": DENY_TOML})
        head = files(**{"deny.toml": None})
        problems = helper.gate_problems(base, head)
        self.assertTrue(
            any("deny.toml was removed" in problem for problem in problems),
            problems,
        )


class CoverageDetectorTest(unittest.TestCase):
    def test_a_dropped_project_floor_is_reported(self) -> None:
        base = files(**{CI_WORKFLOW: WORKFLOW})
        head = files(**{CI_WORKFLOW: WORKFLOW.replace("97.0", "90.0")})
        problems = helper.gate_problems(base, head)
        self.assertTrue(
            any("coverage floor dropped" in problem for problem in problems),
            problems,
        )

    def test_a_removed_project_floor_is_reported(self) -> None:
        base = files(**{CI_WORKFLOW: WORKFLOW})
        head = files(
            **{CI_WORKFLOW: WORKFLOW.replace("scripts/coverage-floor.sh lcov.info 97.0\n", "")}
        )
        problems = helper.gate_problems(base, head)
        self.assertTrue(
            any("coverage floor step was removed" in problem for problem in problems),
            problems,
        )

    def test_a_dropped_patch_floor_is_reported(self) -> None:
        base = files(**{CI_WORKFLOW: WORKFLOW})
        head = files(**{CI_WORKFLOW: WORKFLOW.replace("PATCH_COVERAGE_FLOOR: 90.0", "PATCH_COVERAGE_FLOOR: 80.0")})
        problems = helper.gate_problems(base, head)
        self.assertTrue(
            any("patch coverage floor dropped" in problem for problem in problems),
            problems,
        )

    def test_a_removed_patch_floor_is_reported(self) -> None:
        base = files(**{CI_WORKFLOW: WORKFLOW})
        head = files(
            **{CI_WORKFLOW: WORKFLOW.replace("PATCH_COVERAGE_FLOOR: 90.0\n", "")}
        )
        problems = helper.gate_problems(base, head)
        self.assertTrue(
            any("patch coverage floor" in problem for problem in problems), problems
        )


class CodecovDetectorTest(unittest.TestCase):
    def test_a_dropped_target_is_reported(self) -> None:
        base = files(**{"codecov.yml": CODECOV})
        head = files(**{"codecov.yml": CODECOV.replace("target: 97%", "target: 80%")})
        problems = helper.gate_problems(base, head)
        self.assertTrue(
            any("codecov project target dropped" in problem for problem in problems),
            problems,
        )

    def test_a_removed_target_is_reported(self) -> None:
        base = files(**{"codecov.yml": CODECOV})
        head = files(
            **{
                "codecov.yml": """
coverage:
  status:
    patch:
      default:
        target: 90%
"""
            }
        )
        problems = helper.gate_problems(base, head)
        self.assertTrue(
            any("codecov project target was removed" in problem for problem in problems),
            problems,
        )

    def test_a_removed_codecov_file_is_reported(self) -> None:
        base = files(**{"codecov.yml": CODECOV})
        head = files(**{"codecov.yml": None})
        problems = helper.gate_problems(base, head)
        self.assertTrue(
            any("codecov.yml was removed" in problem for problem in problems),
            problems,
        )

    def test_an_enforced_floor_below_the_declared_target_is_reported(self) -> None:
        base = files(**{"codecov.yml": CODECOV, CI_WORKFLOW: WORKFLOW})
        head = files(
            **{
                "codecov.yml": CODECOV,
                CI_WORKFLOW: WORKFLOW.replace("PATCH_COVERAGE_FLOOR: 90.0", "PATCH_COVERAGE_FLOOR: 80.0"),
            }
        )
        problems = helper.gate_problems(base, head)
        self.assertTrue(
            any("enforced patch coverage floor" in problem for problem in problems),
            problems,
        )


class WorkflowStepDetectorTest(unittest.TestCase):
    def test_a_removed_gate_step_is_reported(self) -> None:
        base = files(**{CI_WORKFLOW: GATE_WORKFLOW})
        head = files(
            **{
                CI_WORKFLOW: GATE_WORKFLOW.replace(
                    "      - name: Check that no lint suppression expired\n"
                    "        run: scripts/check-allow-expiry.sh\n",
                    "",
                )
            }
        )
        problems = helper.gate_problems(base, head)
        self.assertTrue(
            any("check-allow-expiry" in problem for problem in problems), problems
        )
        self.assertTrue(
            any("no lint suppression expired" in problem for problem in problems),
            problems,
        )

    def test_a_removed_shell_only_gate_is_reported(self) -> None:
        base = files(**{CI_WORKFLOW: GATE_WORKFLOW})
        head = files(
            **{
                CI_WORKFLOW: GATE_WORKFLOW.replace(
                    "      - name: Diff against committed notices\n"
                    "        run: git diff --exit-code THIRD-PARTY-NOTICES.md\n",
                    "",
                )
            }
        )
        problems = helper.gate_problems(base, head)
        self.assertTrue(
            any("Diff against committed notices" in problem for problem in problems),
            problems,
        )

    def test_a_renamed_step_that_still_runs_is_not_reported(self) -> None:
        base = files(**{CI_WORKFLOW: GATE_WORKFLOW})
        head = files(
            **{
                CI_WORKFLOW: GATE_WORKFLOW.replace(
                    "Check that no lint suppression expired",
                    "Check that no lint suppression has expired",
                )
            }
        )
        self.assertEqual(helper.gate_problems(base, head), [])

    def test_a_removed_workflow_is_reported(self) -> None:
        base = files(**{CI_WORKFLOW: GATE_WORKFLOW})
        head = files(**{CI_WORKFLOW: None})
        problems = helper.gate_problems(base, head)
        self.assertTrue(
            any("was removed" in problem for problem in problems), problems
        )

    def test_an_unchanged_workflow_is_not_reported(self) -> None:
        base = files(**{CI_WORKFLOW: GATE_WORKFLOW})
        head = files(**{CI_WORKFLOW: GATE_WORKFLOW})
        self.assertEqual(helper.gate_problems(base, head), [])

    def test_a_step_added_to_the_head_is_not_reported(self) -> None:
        base = files(**{CI_WORKFLOW: GATE_WORKFLOW})
        head = files(
            **{
                CI_WORKFLOW: GATE_WORKFLOW
                + "      - name: Check the fuzz lock\n"
                "        run: scripts/check-fuzz-lock.sh\n"
            }
        )
        self.assertEqual(helper.gate_problems(base, head), [])


if __name__ == "__main__":
    unittest.main()
