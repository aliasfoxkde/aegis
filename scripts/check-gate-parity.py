#!/usr/bin/env python3
"""Fail when a change weakens a configured quality gate.

A gate is a promise about the repository's floor: which lints are denied,
which advisories are waived, which licenses are accepted, how much coverage
is required. Any of those can be edited in a "small cleanup" commit and
nobody notices, because the check that would have failed is the one that was
turned off.

This script compares the gate configuration against the merge base with the
target branch and fails when the change moves a floor down. It only knows
about floors that are expressed as configuration; a gate that is *deleted*
(a removed CI job) is caught by the branch-protection required checks, not
here.

Usage: scripts/check-gate-parity.py [base-ref]
    base-ref defaults to origin/main, and the merge base with HEAD is used.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Higher is stricter. A lint may move up this ladder, never down.
LEVELS = {"allow": 0, "warn": 1, "deny": 2, "forbid": 2}


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO, check=True, capture_output=True, text=True
    ).stdout


def base_ref() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]
    return "origin/main"


def merge_base(ref: str) -> str:
    if set(ref) <= {"0"}:
        raise LookupError("the base ref is empty (first push on this branch)")
    return git("merge-base", ref, "HEAD").strip()


def read_at(ref: str, path: str) -> bytes | None:
    result = subprocess.run(
        ["git", "show", f"{ref}:{path}"], cwd=REPO, capture_output=True, text=True
    )
    if result.returncode != 0:
        return None
    return result.stdout.encode()


def current(path: str) -> bytes | None:
    target = REPO / path
    return target.read_bytes() if target.is_file() else None


def lint_levels(manifest: bytes) -> dict[str, int]:
    """Return the workspace lint level for every configured lint."""
    data = tomllib.loads(manifest.decode())
    workspace = data.get("workspace", {})
    levels: dict[str, int] = {}
    for group in ("rust", "rustdoc", "clippy"):
        for name, value in workspace.get("lints", {}).get(group, {}).items():
            if isinstance(value, str):
                levels[f"{group}::{name}"] = LEVELS.get(value, 0)
            elif isinstance(value, dict) and "level" in value:
                levels[f"{group}::{name}"] = LEVELS.get(value["level"], 0)
    return levels


def string_list(text: str, section: str, key: str) -> set[str]:
    """Read one array of strings out of a TOML section, without a TOML parser."""
    pattern = re.compile(
        r"^\[" + re.escape(section) + r"\]\s*$(.*?)(?=^\[|\Z)", re.M | re.S
    )
    match = pattern.search(text)
    if not match:
        return set()
    body = match.group(1)
    key_match = re.search(r"^" + re.escape(key) + r"\s*=\s*\[(.*?)\]", body, re.M | re.S)
    if not key_match:
        return set()
    return set(re.findall(r'"([^"]+)"', key_match.group(1)))


def codecov_targets(text: str) -> dict[str, float]:
    """Read the coverage targets out of codecov.yml.

    A scope's body runs to the next line at the same indentation, not to
    the next key of any kind: `project:` is followed by `default:` at a
    deeper indentation, and a body that stopped there would never reach
    the `target:` line.
    """
    targets: dict[str, float] = {}
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)(project|patch):\s*$", line)
        if not match:
            continue
        indent = len(match.group(1))
        scope = match.group(2)
        for body in lines[index + 1 :]:
            if not body.strip() or body.lstrip().startswith("#"):
                continue
            if len(body) - len(body.lstrip()) <= indent:
                break
            value = re.search(r"target:\s*([0-9.]+)%", body)
            if value:
                targets[scope] = float(value.group(1))
                break
    return targets


def coverage_floor(text: str) -> float | None:
    """Read the enforced coverage floor out of the CI workflow."""
    value = re.search(r"coverage-floor\.sh\s+\S+\s+([0-9.]+)", text)
    return float(value.group(1)) if value else None


def patch_coverage_floor(text: str) -> float | None:
    """Read the enforced patch-coverage floor out of the CI workflow."""
    value = re.search(r"PATCH_COVERAGE_FLOOR:\s*([0-9.]+)", text)
    return float(value.group(1)) if value else None


def patch_floor_is_wired(text: str) -> bool:
    """Report whether the CI workflow still runs the patch floor."""
    return "patch-coverage-floor.py" in text


def report(problems: list[str]) -> int:
    if not problems:
        print("gate-parity: no gate was weakened")
        return 0
    print("gate-parity: this change weakens a quality gate:", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    print(
        "gate-parity: gates move up deliberately. Ratchet a floor down only in a\n"
        "  change that says so in the PR body and updates the recorded measurement.",
        file=sys.stderr,
    )
    return 1


def main() -> int:
    ref = base_ref()
    try:
        base = merge_base(ref)
    except LookupError as error:
        print(f"gate-parity: skipped — {error}")
        return 0
    except subprocess.CalledProcessError:
        print(f"gate-parity: cannot resolve the merge base of {ref}", file=sys.stderr)
        return 2

    problems: list[str] = []

    base_manifest = read_at(base, "Cargo.toml")
    head_manifest = current("Cargo.toml")
    if base_manifest and head_manifest:
        base_levels = lint_levels(base_manifest)
        head_levels = lint_levels(head_manifest)
        for name, level in sorted(base_levels.items()):
            if name not in head_levels:
                problems.append(f"lint {name} was removed (was {level_name(level)})")
            elif head_levels[name] < level:
                problems.append(
                    f"lint {name} was relaxed from {level_name(level)} to "
                    f"{level_name(head_levels[name])}"
                )

    base_deny = read_at(base, "deny.toml")
    head_deny = current("deny.toml")
    if base_deny and head_deny:
        for section, key in (("advisories", "ignore"), ("licenses", "allow")):
            base_list = string_list(base_deny.decode(), section, key)
            head_list = string_list(head_deny.decode(), section, key)
            for added in sorted(head_list - base_list):
                problems.append(f"deny.toml [{section}] {key} gained {added}")

    base_ci = read_at(base, ".github/workflows/ci.yml")
    head_ci = current(".github/workflows/ci.yml")
    head_floor = head_patch = None
    if base_ci and head_ci:
        base_floor = coverage_floor(base_ci.decode())
        head_floor = coverage_floor(head_ci.decode())
        if base_floor is not None:
            if head_floor is None:
                problems.append("the coverage floor step was removed from ci.yml")
            elif head_floor < base_floor:
                problems.append(
                    f"the coverage floor dropped from {base_floor}% to {head_floor}%"
                )

        base_patch = patch_coverage_floor(base_ci.decode())
        head_patch = patch_coverage_floor(head_ci.decode())
        if base_patch is not None:
            if head_patch is None:
                problems.append(
                    "the patch coverage floor was removed from ci.yml"
                )
            elif head_patch < base_patch:
                problems.append(
                    f"the patch coverage floor dropped from {base_patch}% to "
                    f"{head_patch}%"
                )
        if patch_floor_is_wired(base_ci.decode()) and not patch_floor_is_wired(
            head_ci.decode()
        ):
            problems.append("the patch coverage floor step was removed from ci.yml")

    base_codecov = read_at(base, "codecov.yml")
    head_codecov = current("codecov.yml")
    if base_codecov and head_codecov:
        base_targets = codecov_targets(base_codecov.decode())
        head_targets = codecov_targets(head_codecov.decode())
        for scope, value in sorted(base_targets.items()):
            if scope not in head_targets:
                problems.append(f"codecov {scope} target was removed (was {value}%)")
            elif head_targets[scope] < value:
                problems.append(
                    f"codecov {scope} target dropped from {value}% to {head_targets[scope]}%"
                )
        # codecov.yml states the target; the CI floor is the one that
        # actually fails a build. The enforced floor may not be the
        # weaker of the two.
        for scope, enforced in (("project", head_floor), ("patch", head_patch)):
            declared = head_targets.get(scope)
            if declared is not None and enforced is not None and enforced < declared:
                problems.append(
                    f"the enforced {scope} coverage floor ({enforced}%) is below "
                    f"the codecov {scope} target ({declared}%)"
                )

    print(f"gate-parity: compared HEAD against {ref} ({base[:12]})")
    return report(problems)


def level_name(level: int) -> str:
    for name, value in LEVELS.items():
        if value == level:
            return name
    return str(level)


if __name__ == "__main__":
    raise SystemExit(main())
