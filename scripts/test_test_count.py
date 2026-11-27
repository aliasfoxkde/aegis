#!/usr/bin/env python3
"""Tests for scripts/check-test-count.py.

The gate reads a listing of the suite and the recorded table and says
whether they agree. Its parsing has to be right, or a stale count
passes, or a correct count fails. Deterministic: fixed inputs, no
network, no clock. Run from the repository root with:

    python3 scripts/test_test_count.py
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

HELPER_PATH = Path(__file__).resolve().parent / "check-test-count.py"

_SPEC = importlib.util.spec_from_file_location("check_test_count", HELPER_PATH)
assert _SPEC is not None and _SPEC.loader is not None
helper = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(helper)

LISTING = """
     Running unittests src/lib.rs (target/debug/deps/aegis_core-1)
foo: test
bar: test

12 tests, 0 benchmarks
     Running tests/one.rs (target/debug/deps/one-2)
baz: test

3 tests, 0 benchmarks
   Doc-tests aegis_core
0 tests, 0 benchmarks
"""

PLAN = """
| Platform | Tests | Test binaries |
| --- | --- | --- |
| Linux | 15 | 2 |
| macOS | 15 | 2 |
| Windows | 15 | 2 |
"""

AGENTS = "# Test (15 tests across 2 test binaries on Linux and macOS)\n"

# Cargo splits its output: the per-suite counts go to stdout, the
# headers that announce each suite go to stderr. The gate read stdout
# alone, so every doctest suite counted as a test binary and the lane
# failed on a suite that never drifted.
LISTING_STDOUT = """
foo: test
bar: test

12 tests, 0 benchmarks
baz: test

3 tests, 0 benchmarks
0 tests, 0 benchmarks
"""

LISTING_STDERR = """
     Running unittests src/lib.rs (target/debug/deps/aegis_core-1)
     Running tests/one.rs (target/debug/deps/one-2)
   Doc-tests aegis_core
"""


class MeasureTest(unittest.TestCase):
    def test_the_tests_and_the_binaries_are_counted(self) -> None:
        self.assertEqual(helper.measure(LISTING), (15, 2))

    def test_a_listing_without_counts_measures_nothing(self) -> None:
        self.assertEqual(helper.measure("nothing here\n"), (0, 0))

    def test_carriage_returns_do_not_hide_a_count(self) -> None:
        self.assertEqual(helper.measure(LISTING.replace("\n", "\r\n")), (15, 2))

    def test_a_timestamped_line_is_still_counted(self) -> None:
        """The CI log prefixes every line with a timestamp."""
        stamped = "\n".join(
            f"2026-11-17T02:53:14.9315198Z {line}"
            for line in LISTING.splitlines()
        )
        self.assertEqual(helper.measure(stamped), (15, 2))

    def test_a_run_output_is_read_the_same_way(self) -> None:
        """A run prints "test result: ok." where a listing prints a count."""
        run = """
     Running unittests src/lib.rs (target/debug/deps/aegis_core-1)
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

   Doc-tests aegis_core

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
"""
        self.assertEqual(helper.measure(run), (15, 1))

    def test_an_ignored_test_is_counted(self) -> None:
        """A listing counts ignored tests, so the run's ignored count does too."""
        run = "test result: ok. 12 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out\n"
        self.assertEqual(helper.measure(run), (15, 1))

    def test_colour_codes_do_not_hide_a_doctest_suite(self) -> None:
        """CI sets CARGO_TERM_COLOR, so cargo's headers carry colour codes."""
        coloured = "\n".join(
            f"\x1b[1m\x1b[92m   Doc-tests\x1b[0m aegis_core"
            for _ in range(1)
        )
        listing = f"{coloured}\n0 tests, 0 benchmarks\n\n12 tests, 0 benchmarks\n"
        self.assertEqual(helper.measure(listing), (12, 1))

    def test_a_doctest_suite_is_not_a_test_binary(self) -> None:
        """Cargo's headers and its counts arrive on different streams."""
        both = LISTING_STDOUT + LISTING_STDERR
        self.assertEqual(helper.measure(both), (15, 2))

    def test_a_capture_of_stdout_alone_has_no_suite_headers(self) -> None:
        """Stdout holds the counts; the headers are on stderr."""
        self.assertFalse(helper.suite_headers(LISTING_STDOUT))
        self.assertTrue(helper.suite_headers(LISTING_STDERR))
        self.assertTrue(helper.suite_headers(LISTING_STDOUT + LISTING_STDERR))


class TableTest(unittest.TestCase):
    def test_every_platform_row_is_read(self) -> None:
        self.assertEqual(
            helper.recorded_table(PLAN),
            {"linux": (15, 2), "macos": (15, 2), "windows": (15, 2)},
        )

    def test_a_table_without_a_platform_row_is_short(self) -> None:
        table = helper.recorded_table(
            "| Platform | Tests | Test binaries |\n| --- | --- | --- |\n"
            "| Linux | 15 | 2 |\n"
        )
        self.assertEqual(table, {"linux": (15, 2)})

    def test_a_row_that_is_not_numeric_is_skipped(self) -> None:
        table = helper.recorded_table("| Linux | many | some |\n")
        self.assertEqual(table, {})


class CheckTest(unittest.TestCase):
    def test_an_agreeing_set_of_numbers_passes(self) -> None:
        self.assertEqual(helper.check(LISTING, PLAN, AGENTS, platform="linux"), [])

    def test_a_stale_count_is_reported(self) -> None:
        stale = PLAN.replace("| Linux | 15 | 2 |", "| Linux | 12 | 2 |")
        problems = helper.check(LISTING, stale, AGENTS, platform="linux")
        self.assertTrue(
            any("measured 15 across 2" in problem for problem in problems), problems
        )

    def test_a_stale_binary_count_is_reported(self) -> None:
        stale = PLAN.replace("| Linux | 15 | 2 |", "| Linux | 15 | 25 |")
        problems = helper.check(LISTING, stale, AGENTS, platform="linux")
        self.assertTrue(
            any("measured 15 across 2" in problem for problem in problems), problems
        )

    def test_a_missing_platform_row_is_reported(self) -> None:
        partial = "| Platform | Tests | Test binaries |\n| Linux | 15 | 2 |\n"
        problems = helper.check(LISTING, partial, AGENTS, platform="linux")
        self.assertTrue(
            any("macOS" in problem for problem in problems), problems
        )

    def test_a_missing_agents_count_is_reported(self) -> None:
        problems = helper.check(LISTING, PLAN, "# Test (all green)\n", platform="linux")
        self.assertTrue(
            any("AGENTS.md" in problem for problem in problems), problems
        )

    def test_a_listing_without_counts_is_reported(self) -> None:
        problems = helper.check("no counts\n", PLAN, AGENTS, platform="linux")
        self.assertTrue(
            any("no test counts" in problem for problem in problems), problems
        )

    def test_a_windows_lane_checks_the_windows_row(self) -> None:
        plan = PLAN.replace("| Windows | 15 | 2 |", "| Windows | 12 | 2 |")
        problems = helper.check(LISTING, plan, AGENTS, platform="windows")
        self.assertTrue(
            any("Windows" in problem for problem in problems), problems
        )

    def test_the_two_streams_agree_with_the_table(self) -> None:
        """The shape cargo actually produces passes the gate."""
        both = LISTING_STDOUT + LISTING_STDERR
        self.assertEqual(helper.check(both, PLAN, AGENTS, platform="linux"), [])

    def test_a_capture_without_the_headers_is_reported(self) -> None:
        """A stdout-only capture cannot say how many suites are doctests."""
        problems = helper.check(LISTING_STDOUT, PLAN, AGENTS, platform="linux")
        self.assertTrue(
            any("suite headers" in problem for problem in problems), problems
        )


if __name__ == "__main__":
    unittest.main()
