#!/usr/bin/env python3
"""Enforce a patch-coverage floor: the lines a change adds must be covered.

Why this exists: ``scripts/coverage-floor.sh`` pins the project-wide line
coverage, which barely moves when a change adds a small uncovered file, so a
pull request can add uncovered lines and stay green. ``codecov.yml`` declares
a ``patch`` target, but no Codecov upload is ever evaluated (no
``CODECOV_TOKEN``), so nothing enforces it. This script is the gate that
actually runs: it intersects the lines a diff adds with the hit counts in
the same lcov report and fails below the floor.

The floor sits just below measured reality and is ratcheted up — never
lowered to pass (see docs/PLAN.md, "Measure, then pin").

Usage:
    scripts/patch-coverage-floor.py <lcov.info> <base> <head> [floor_percent]

``base`` and ``head`` are revisions; the diff is taken against their merge
base, which is what a pull request introduces. Standard library only.

Tested by scripts/test_patch_coverage_floor.py.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

# The files Codecov does not count, mirrored from codecov.yml's `ignore`
# list and from scripts/coverage-floor.sh. A change to them has no
# coverage to measure.
IGNORED_PATH_PARTS = ("crates/aegis-wasm/",)
IGNORED_BASENAMES = ("src/main.rs",)

HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def normalize(path: str) -> str:
    """Reduce a source path to the shape the diff uses.

    lcov records carry absolute paths on a CI runner (``/home/runner/work/
    aegis/aegis/crates/...``) and workspace-relative paths on a local run;
    the diff carries workspace-relative paths. Anchoring on the ``crates/``
    segment compares the two without depending on where the checkout lives.
    """
    marker = "crates/"
    index = path.find(marker)
    if index >= 0:
        return path[index:]
    return path


def is_ignored(path: str) -> bool:
    """Report whether a path is outside the counted set."""
    normalized = normalize(path)
    if any(part in normalized for part in IGNORED_PATH_PARTS):
        return True
    if normalized.endswith(IGNORED_BASENAMES) and "crates/" not in normalized:
        return True
    return False


def read_lcov(path: Path) -> dict[str, dict[int, int]]:
    """Read the line hit counts per file from an lcov report."""
    hits: dict[str, dict[int, int]] = defaultdict(dict)
    current: str | None = None
    with path.open(encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.strip()
            if line.startswith("SF:"):
                current = line[3:]
                continue
            if line.startswith("DA:"):
                if current is None:
                    continue
                payload = line[3:].split(",")
                if len(payload) < 2:
                    continue
                try:
                    number = int(payload[0])
                    count = int(payload[1])
                except ValueError:
                    continue
                hits[current][number] = count
    return hits


def added_lines(base: str, head: str, cwd: str | None = None) -> dict[str, set[int]]:
    """Return the line numbers each file gains between two revisions."""
    try:
        merge_base = subprocess.run(
            ["git", "merge-base", base, head],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except subprocess.CalledProcessError:
        merge_base = base
    diff = subprocess.run(
        [
            "git",
            "diff",
            "--unified=0",
            "--no-color",
            "--no-ext-diff",
            merge_base,
            head,
            "--",
            "crates/",
        ],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    added: dict[str, set[int]] = defaultdict(set)
    current: str | None = None
    line_number = 0
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:].strip()
            if target.startswith("b/"):
                target = target[2:]
            current = None if target == "/dev/null" else target
            continue
        if raw.startswith("--- ") or raw.startswith("diff --git"):
            continue
        header = HUNK_HEADER.match(raw)
        if header:
            line_number = int(header.group(3))
            continue
        if current is None:
            continue
        if raw.startswith("+"):
            added[current].add(line_number)
            line_number += 1
        elif raw.startswith("-"):
            continue
        elif raw.startswith(" ") or raw == "":
            line_number += 1
    return added


def measure(
    hits: dict[str, dict[int, int]], added: dict[str, set[int]]
) -> tuple[int, int, list[str], list[str]]:
    """Count the added lines that are instrumented, and how many are covered.

    Returns the instrumented total, the covered count, the uncovered lines,
    and the files the coverage report does not mention at all.
    """
    total = 0
    covered = 0
    uncovered: list[str] = []
    missing_files: list[str] = []
    # The report keys its records by the path the compiler saw, which on a
    # CI runner is absolute; the diff keys them by the workspace path.
    # Index both by the normalized form so they meet.
    index: dict[str, dict[int, int]] = {}
    for path, record in hits.items():
        index.setdefault(normalize(path), {}).update(record)
    for path, numbers in sorted(added.items()):
        if is_ignored(path):
            continue
        record = index.get(normalize(path))
        if record is None:
            missing_files.append(path)
            total += len(numbers)
            uncovered.extend(f"{path}:{number}" for number in sorted(numbers))
            continue
        for number in sorted(numbers):
            count = record.get(number)
            if count is None:
                # Not an instrumented line: a blank line, a comment, or a
                # brace. Coverage has no opinion about it.
                continue
            total += 1
            if count > 0:
                covered += 1
            else:
                uncovered.append(f"{path}:{number}")
    return total, covered, uncovered, missing_files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lcov", type=Path, help="the lcov report to read")
    parser.add_argument("base", help="the revision the change is measured against")
    parser.add_argument("head", help="the revision that carries the change")
    parser.add_argument(
        "floor",
        nargs="?",
        type=float,
        default=90.0,
        help="the patch-coverage floor in percent (default: 90.0)",
    )
    args = parser.parse_args()

    if not args.lcov.is_file():
        print(f"patch-coverage-floor: report not found: {args.lcov}", file=sys.stderr)
        return 2

    hits = read_lcov(args.lcov)
    if not hits:
        print(
            f"patch-coverage-floor: no line records found in {args.lcov} (wrong format?)",
            file=sys.stderr,
        )
        return 2

    added = added_lines(args.base, args.head)
    total, covered, uncovered, missing = measure(hits, added)

    if missing:
        print(
            "patch-coverage-floor: these files are not in the coverage report; "
            "their added lines count as uncovered:",
            file=sys.stderr,
        )
        for path in missing:
            print(f"  - {path}", file=sys.stderr)

    if total == 0:
        print("patch-coverage-floor: the change adds no instrumented lines")
        return 0

    percent = 100.0 * covered / total
    print(
        f"patch-coverage-floor: {percent:.2f}% of the added instrumented lines "
        f"are covered ({covered}/{total}, floor {args.floor}%)"
    )
    if uncovered:
        print(f"patch-coverage-floor: {len(uncovered)} added lines are not covered:")
        for entry in uncovered[:50]:
            print(f"  - {entry}")
        if len(uncovered) > 50:
            print(f"  ... and {len(uncovered) - 50} more")

    if percent + 0.0 < args.floor:
        print(
            "patch-coverage-floor: BELOW floor — add tests or remove dead code; "
            "do not lower the floor",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
