#!/usr/bin/env python3
"""Fail when the recorded test counts no longer match the measured ones.

The repository states its test count in prose, in more than one document.
That prose drifted: it claimed 818 tests across 25 test binaries long
after the suite had grown past 949 across 30, and nothing noticed. The
rule corpus has a drift guard (`crates/aegis-patterns/tests/
doc_count_drift.rs`); the test count had none.

This gate closes that hole. The counts are recorded in one table in
`docs/PLAN.md`, the table is measured against the suite on every test
lane, and the prose that quotes the numbers is checked against the
table. A pull request that adds a test has to update the table in the
same change - which is the point, and is exactly what the pattern-count
guard already asks for.

The count is platform-dependent: some tests are Unix-only, so Windows
runs fewer of them. Each lane measures its own platform and checks its
own row, and the table must carry a row for every platform.

The measurement is `cargo test -- --list`, which enumerates the suite
without running it. The listing counts every test in the suite,
including the ones marked `#[ignore]`, so the number does not move when
a test is skipped rather than removed. A run's own output is read the
same way, so the gate can be pointed at a CI log as well as at cargo.

Usage: scripts/check-test-count.py [listing]
    listing defaults to running `cargo test --locked --workspace --
    --list` and reading its output; a path names a file holding that
    output instead.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

PLAN = REPO / "docs" / "PLAN.md"
AGENTS = REPO / "AGENTS.md"

# The platforms the test lanes run on, and the label the table uses for
# each. A lane that runs on a platform outside this set cannot check a
# row, so it says so rather than passing silently.
PLATFORMS = {
    "linux": "Linux",
    "macos": "macOS",
    "windows": "Windows",
}

# The line cargo prints at the end of each test binary's listing:
# "24 tests, 0 benchmarks". A CI log prefixes every line with a
# timestamp, so the count is looked for at the end of the line rather
# than at its start.
COUNT_RE = re.compile(r"(?<![\d.])(\d+) tests?, (\d+) benchmarks?\s*$")
# The line cargo prints when it *runs* a suite:
# "test result: ok. 24 passed; 0 failed; 0 ignored; ...". Both shapes
# are read, so the gate measures the same number whether it is handed
# a listing or a run log.
RESULT_RE = re.compile(
    r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored"
)
# The header cargo prints before a doctest suite. The CI log may prefix
# every line with a timestamp, so this is searched for anywhere in the
# line rather than matched at its start.
DOCTEST_RE = re.compile(r"\bDoc-tests\s+\S")
# Cargo colours its output when `CARGO_TERM_COLOR` is set, which CI
# does. The colour codes sit between the words of a header, so they
# have to go before the lines are read.
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def current_platform() -> str | None:
    """The platform key this lane runs on, or None when it is unknown."""
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform in ("win32", "cygwin"):
        return "windows"
    return None


def listing() -> str:
    """The suite's listing, from cargo."""
    result = subprocess.run(
        ["cargo", "test", "--locked", "--workspace", "--", "--list"],
        cwd=REPO,
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()
        tail = detail[-1] if detail else "no output"
        raise RuntimeError(f"cargo test --list failed: {tail}")
    return result.stdout


def measure(text: str) -> tuple[int, int]:
    """Return the (tests, test binaries) the listing reports.

    A doctest suite is listed like any other test target, so the suite
    count is the number of suites and the binary count is that minus
    the doctest suites.

    A run's ignored tests are counted, because a listing counts them
    too: the number must not move when a test is skipped rather than
    removed.
    """
    tests = 0
    suites = 0
    doctests = 0
    for line in ANSI_RE.sub("", text).replace("\r", "\n").splitlines():
        if DOCTEST_RE.search(line):
            doctests += 1
        match = COUNT_RE.search(line)
        if match:
            suites += 1
            tests += int(match.group(1))
            continue
        match = RESULT_RE.search(line)
        if match:
            suites += 1
            tests += int(match.group(1)) + int(match.group(3))
    return tests, suites - doctests


def recorded_table(plan_text: str) -> dict[str, tuple[int, int]]:
    """Read the recorded counts out of the plan's table.

    A row is a markdown table row whose first cell is one of the
    platform labels and whose next two cells are integers.
    """
    table: dict[str, tuple[int, int]] = {}
    for line in plan_text.splitlines():
        row = line.strip()
        if not row.startswith("|"):
            continue
        cells = [cell.strip() for cell in row.strip("|").split("|")]
        if len(cells) < 3:
            continue
        for key, label in PLATFORMS.items():
            if cells[0] != label:
                continue
            try:
                table[key] = (int(cells[1]), int(cells[2]))
            except ValueError:
                continue
    return table


def check(
    list_text: str,
    plan_text: str,
    agents_text: str,
    platform: str | None = None,
) -> list[str]:
    """Everything that disagrees between the listing, the table and the prose."""
    problems: list[str] = []

    measured_tests, measured_binaries = measure(list_text)
    if measured_tests == 0:
        problems.append(
            "the listing holds no test counts; the lane did not produce them"
        )
        return problems

    table = recorded_table(plan_text)
    for key, label in PLATFORMS.items():
        if key not in table:
            problems.append(f"docs/PLAN.md has no recorded test count for {label}")

    if platform is None:
        platform = current_platform()
    if platform is None:
        print(
            f"test-count: unknown platform {sys.platform}; the recorded table "
            f"was not checked",
            file=sys.stderr,
        )
        return problems

    recorded = table.get(platform)
    if recorded is None:
        problems.append(
            f"docs/PLAN.md has no recorded test count for {PLATFORMS[platform]}"
        )
    elif recorded != (measured_tests, measured_binaries):
        problems.append(
            f"docs/PLAN.md records {recorded[0]} tests across {recorded[1]} test "
            f"binaries for {PLATFORMS[platform]}, but this lane measured "
            f"{measured_tests} across {measured_binaries}"
        )

    # The prose in AGENTS.md quotes the Linux row, because that is the
    # platform a reader is most likely on.
    linux = table.get("linux")
    if linux is not None:
        phrase = f"{linux[0]} tests across {linux[1]} test binaries"
        if phrase not in agents_text:
            problems.append(f"AGENTS.md does not state {phrase!r}")

    return problems


def main() -> int:
    if len(sys.argv) > 1:
        path = Path(sys.argv[1])
        try:
            list_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            print(f"test-count: cannot read {path}: {error}", file=sys.stderr)
            return 2
    else:
        try:
            list_text = listing()
        except (RuntimeError, OSError) as error:
            print(f"test-count: {error}", file=sys.stderr)
            return 2

    problems = check(
        list_text,
        PLAN.read_text(encoding="utf-8"),
        AGENTS.read_text(encoding="utf-8"),
    )
    if problems:
        print("test-count: the recorded test counts are wrong:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print(
            "test-count: a test was added, removed, or skipped on this platform. "
            "Update the\n  table in docs/PLAN.md and the count in AGENTS.md in the "
            "same change.",
            file=sys.stderr,
        )
        return 1

    tests, binaries = measure(list_text)
    print(
        f"test-count: {tests} tests across {binaries} test binaries match the "
        f"recorded table"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
