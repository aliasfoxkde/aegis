#!/usr/bin/env python3
"""Tests for scripts/patch-coverage-floor.py.

Deterministic: fixed fixtures, a temporary git repository, no network, no
clock, no external dependencies. Run from the repository root with:

    python3 -m unittest scripts/test_patch_coverage_floor.py
    # or: python3 scripts/test_patch_coverage_floor.py
"""

from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

HELPER_PATH = Path(__file__).resolve().parent / "patch-coverage-floor.py"

_SPEC = importlib.util.spec_from_file_location("patch_coverage_floor", HELPER_PATH)
assert _SPEC is not None and _SPEC.loader is not None
helper = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(helper)


def lcov(records: list[tuple[str, list[tuple[int, int]]]]) -> str:
    """Render line hit counts in the lcov format the CI job produces."""
    lines: list[str] = []
    for path, hits in records:
        lines.append(f"SF:{path}")
        for number, count in hits:
            lines.append(f"DA:{number},{count}")
        lines.append("end_of_record")
    return "\n".join(lines) + "\n"


class NormalizeTest(unittest.TestCase):
    def test_an_absolute_checkout_path_reduces_to_the_workspace_path(self) -> None:
        self.assertEqual(
            helper.normalize("/home/runner/work/aegis/aegis/crates/aegis-core/src/lib.rs"),
            "crates/aegis-core/src/lib.rs",
        )

    def test_a_workspace_relative_path_is_unchanged(self) -> None:
        self.assertEqual(
            helper.normalize("crates/aegis-core/src/lib.rs"),
            "crates/aegis-core/src/lib.rs",
        )

    def test_a_path_outside_the_crates_tree_is_unchanged(self) -> None:
        self.assertEqual(helper.normalize("src/main.rs"), "src/main.rs")


class IgnoreTest(unittest.TestCase):
    def test_the_wasm_crate_is_not_counted(self) -> None:
        self.assertTrue(helper.is_ignored("crates/aegis-wasm/src/lib.rs"))

    def test_the_bootstrap_binary_is_not_counted(self) -> None:
        self.assertTrue(helper.is_ignored("src/main.rs"))

    def test_an_ordinary_crate_binary_is_counted(self) -> None:
        self.assertFalse(helper.is_ignored("crates/aegis-cli/src/main.rs"))

    def test_an_ordinary_crate_source_file_is_counted(self) -> None:
        self.assertFalse(helper.is_ignored("crates/aegis-core/src/lib.rs"))


class ReadLcovTest(unittest.TestCase):
    def test_line_hits_are_read_per_file(self) -> None:
        report = lcov(
            [
                ("/work/crates/aegis-core/src/lib.rs", [(1, 3), (2, 0)]),
                ("/work/crates/aegis-cli/src/main.rs", [(7, 1)]),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lcov.info"
            path.write_text(report, encoding="utf-8")
            hits = helper.read_lcov(path)
        self.assertEqual(hits["/work/crates/aegis-core/src/lib.rs"], {1: 3, 2: 0})
        self.assertEqual(hits["/work/crates/aegis-cli/src/main.rs"], {7: 1})

    def test_a_malformed_line_is_skipped_rather_than_fatal(self) -> None:
        report = "SF:/work/a.rs\nDA:not-a-number,1\nDA:5,2\n"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lcov.info"
            path.write_text(report, encoding="utf-8")
            hits = helper.read_lcov(path)
        self.assertEqual(hits["/work/a.rs"], {5: 2})


class MeasureTest(unittest.TestCase):
    def test_covered_added_lines_count_toward_the_total(self) -> None:
        hits = {"/work/crates/aegis-core/src/lib.rs": {1: 4, 2: 0, 3: 1}}
        added = {"crates/aegis-core/src/lib.rs": {1, 2, 3}}
        total, covered, uncovered, missing = helper.measure(hits, added)
        self.assertEqual((total, covered), (3, 2))
        self.assertEqual(uncovered, ["crates/aegis-core/src/lib.rs:2"])
        self.assertEqual(missing, [])

    def test_a_line_the_report_does_not_mention_is_not_instrumented(self) -> None:
        """A blank line or a comment has no coverage record; it must not
        count against the patch."""
        hits = {"/work/crates/aegis-core/src/lib.rs": {1: 4}}
        added = {"crates/aegis-core/src/lib.rs": {1, 2}}
        total, covered, uncovered, _ = helper.measure(hits, added)
        self.assertEqual((total, covered), (1, 1))
        self.assertEqual(uncovered, [])

    def test_a_file_absent_from_the_report_counts_as_uncovered(self) -> None:
        hits = {"/work/crates/aegis-core/src/lib.rs": {1: 4}}
        added = {"crates/aegis-core/src/new.rs": {1, 2}}
        total, covered, uncovered, missing = helper.measure(hits, added)
        self.assertEqual((total, covered), (2, 0))
        self.assertEqual(missing, ["crates/aegis-core/src/new.rs"])
        self.assertEqual(
            uncovered, ["crates/aegis-core/src/new.rs:1", "crates/aegis-core/src/new.rs:2"]
        )

    def test_ignored_files_are_left_out_of_the_measurement(self) -> None:
        hits = {}
        added = {"crates/aegis-wasm/src/lib.rs": {1}}
        total, covered, uncovered, missing = helper.measure(hits, added)
        self.assertEqual((total, covered), (0, 0))
        self.assertEqual(uncovered, [])
        self.assertEqual(missing, [])


class AddedLinesTest(unittest.TestCase):
    """The diff reader, exercised against a real git repository."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name)
        self._run("git", "init", "-q")
        self._run("git", "config", "user.email", "test@example.invalid")
        self._run("git", "config", "user.name", "Test")
        (self.repo / "crates/aegis-core/src").mkdir(parents=True)
        self.source = self.repo / "crates/aegis-core/src/lib.rs"
        self.source.write_text("fn one() {}\n", encoding="utf-8")
        self._run("git", "add", ".")
        self._run("git", "commit", "-q", "-m", "base")
        self.base = self._run("git", "rev-parse", "HEAD").stdout.strip()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            args, cwd=self.repo, capture_output=True, text=True, check=True
        )

    def test_added_lines_are_the_new_line_numbers(self) -> None:
        self.source.write_text(
            "fn one() {}\nfn two() {}\nfn three() {}\n", encoding="utf-8"
        )
        self._run("git", "commit", "-aqm", "add two functions")
        head = self._run("git", "rev-parse", "HEAD").stdout.strip()
        added = helper.added_lines(self.base, head, cwd=str(self.repo))
        self.assertEqual(added["crates/aegis-core/src/lib.rs"], {2, 3})

    def test_removed_lines_are_not_added_lines(self) -> None:
        self.source.write_text("fn one() {}\nfn three() {}\n", encoding="utf-8")
        self._run("git", "commit", "-aqm", "remove a function")
        head = self._run("git", "rev-parse", "HEAD").stdout.strip()
        added = helper.added_lines(self.base, head, cwd=str(self.repo))
        self.assertEqual(added["crates/aegis-core/src/lib.rs"], {2})

    def test_the_merge_base_is_used_rather_than_the_base_tip(self) -> None:
        """A branch that lags its base still measures against the fork.

        The base tip carries a line the branch never saw. Diffing against
        the tip would show that line as removed and report nothing added;
        diffing against the merge base shows what the branch actually
        introduces.
        """
        self.source.write_text("fn one() {}\nfn two() {}\n", encoding="utf-8")
        self._run("git", "commit", "-aqm", "branch work")
        branch = self._run("git", "rev-parse", "HEAD").stdout.strip()
        self._run("git", "checkout", "-q", "-b", "other", self.base)
        self.source.write_text(
            "fn zero() {}\nfn one() {}\nfn two() {}\n", encoding="utf-8"
        )
        self._run("git", "commit", "-aqm", "base moves on")
        moved = self._run("git", "rev-parse", "HEAD").stdout.strip()
        added = helper.added_lines(moved, branch, cwd=str(self.repo))
        self.assertEqual(added["crates/aegis-core/src/lib.rs"], {2})


class MainTest(unittest.TestCase):
    """The command line, exercised as a subprocess."""

    def _run_script(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(HELPER_PATH), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_a_missing_report_is_an_error_not_a_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = str(Path(tmp) / "absent.info")
            result = self._run_script(missing, "HEAD", "HEAD")
        self.assertEqual(result.returncode, 2)
        self.assertIn("report not found", result.stderr)

    def test_an_empty_report_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lcov.info"
            path.write_text("", encoding="utf-8")
            result = self._run_script(str(path), "HEAD", "HEAD")
        self.assertEqual(result.returncode, 2)
        self.assertIn("no line records", result.stderr)

    def test_a_change_that_adds_no_instrumented_lines_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lcov.info"
            path.write_text(lcov([("/work/crates/aegis-core/src/lib.rs", [(1, 1)])]))
            result = self._run_script(str(path), "HEAD", "HEAD", "90")
        self.assertEqual(result.returncode, 0)
        self.assertIn("no instrumented lines", result.stdout)

    def test_a_change_below_the_floor_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "crates/aegis-core/src").mkdir(parents=True)
            source = repo / "crates/aegis-core/src/lib.rs"
            source.write_text("fn one() {}\n", encoding="utf-8")
            subprocess.run(
                ["git", "init", "-q"], cwd=repo, check=True, capture_output=True
            )
            for key, value in (
                ("user.email", "test@example.invalid"),
                ("user.name", "Test"),
            ):
                subprocess.run(
                    ["git", "config", key, value],
                    cwd=repo,
                    check=True,
                    capture_output=True,
                )
            subprocess.run(
                ["git", "add", "."], cwd=repo, check=True, capture_output=True
            )
            subprocess.run(
                ["git", "commit", "-qm", "base"],
                cwd=repo,
                check=True,
                capture_output=True,
            )
            base = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repo,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            source.write_text("fn one() {}\nfn two() {}\n", encoding="utf-8")
            subprocess.run(
                ["git", "commit", "-aqm", "add"],
                cwd=repo,
                check=True,
                capture_output=True,
            )
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repo,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            report = repo / "lcov.info"
            report.write_text(
                lcov(
                    [
                        (
                            "/work/crates/aegis-core/src/lib.rs",
                            [(1, 1), (2, 0)],
                        )
                    ]
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    "python3",
                    str(HELPER_PATH),
                    str(report),
                    base,
                    head,
                    "90",
                ],
                cwd=repo,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("BELOW floor", result.stderr)
        self.assertIn("0.00%", result.stdout)


if __name__ == "__main__":
    unittest.main()
