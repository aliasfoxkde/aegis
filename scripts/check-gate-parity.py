#!/usr/bin/env python3
"""Fail when a change weakens a configured quality gate.

A gate is a promise about the repository's floor: which lints are denied,
which advisories are waived, which licenses are accepted, how much coverage
is required. Any of those can be edited in a "small cleanup" commit and
nobody notices, because the check that would have failed is the one that was
turned off.

This script compares the gate configuration against the merge base with the
target branch and fails when the change moves a floor down. It also fails
when a gate is *removed*: a CI step that ran at the base and does not run
at the head, a workflow file that no longer exists, or a gate
configuration file that was deleted outright. A removed CI *job* is caught
by the branch-protection required checks, which name jobs; the steps
inside a job are named by nothing else, so they are caught here.

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


# A gate step is identified by the scripts it runs. A step that runs no
# script is still a gate - `git diff --exit-code THIRD-PARTY-NOTICES.md`
# is one - so the step's name is the fallback identity.
SCRIPT_RE = re.compile(r"scripts/[A-Za-z0-9_./-]+")
STEP_NAME_RE = re.compile(r"^\s*-\s+name:\s*(.+?)\s*$")
RUN_RE = re.compile(r"^(\s*)run:\s*(.*)$")


def parse_steps(text: str) -> list[tuple[str, str]]:
    """Return the (name, run body) of every step in a workflow file.

    The workflow files are YAML and the repository's rule is that the
    gate scripts are stdlib only, so this parses the two shapes the
    workflows actually use rather than pulling in a YAML library: a step
    is a `- name:` line followed by a `run:` line, and a `run:` block
    scalar runs until a line at the `run:` line's own indentation.
    """
    steps: list[tuple[str, str]] = []
    lines = text.splitlines()
    name = ""
    index = 0
    while index < len(lines):
        line = lines[index]
        name_match = STEP_NAME_RE.match(line)
        if name_match:
            name = name_match.group(1).strip().strip("'\"")
        run_match = RUN_RE.match(line)
        if run_match:
            indent, first = run_match.group(1), run_match.group(2)
            block = [first]
            index += 1
            while index < len(lines):
                following = lines[index]
                if following.strip():
                    depth = len(following) - len(following.lstrip())
                    if depth <= len(indent):
                        break
                block.append(following)
                index += 1
            steps.append((name, "\n".join(block)))
            continue
        index += 1
    return steps


def scripts_in(body: str) -> set[str]:
    """Return the repository scripts a run body invokes."""
    found: set[str] = set()
    for line in body.splitlines():
        if line.strip().startswith("#"):
            continue
        for match in SCRIPT_RE.finditer(line):
            found.add(match.group(0).rstrip(".,;:"))
    return found


def removed_steps(base_text: str, head_text: str) -> list[str]:
    """Return the base steps that the head no longer runs.

    A step counts as removed when nothing in the head invokes the scripts
    it invoked *and* no head step carries its name. Renaming a step while
    it keeps running its script is not a removal; deleting the step, or
    repointing it at a different script, is.
    """
    head_scripts: set[str] = set()
    head_names: set[str] = set()
    for name, body in parse_steps(head_text):
        head_names.add(name)
        head_scripts |= scripts_in(body)

    removed: list[str] = []
    for name, body in parse_steps(base_text):
        base_scripts = scripts_in(body)
        if base_scripts & head_scripts:
            continue
        if name and name in head_names:
            continue
        label = name or body.strip().splitlines()[0]
        if base_scripts:
            label = f"{label} ({', '.join(sorted(base_scripts))})"
        removed.append(label)
    return removed


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


GATE_FILES = ("Cargo.toml", "deny.toml", "codecov.yml")
WORKFLOW_DIR = ".github/workflows"
CI_WORKFLOW = ".github/workflows/ci.yml"


def workflow_paths(ref: str | None) -> list[str]:
    """The workflow files at a ref; None reads the working tree."""
    if ref is None:
        root = REPO / WORKFLOW_DIR
        if not root.is_dir():
            return []
        return sorted(
            str(path.relative_to(REPO))
            for path in root.iterdir()
            if path.suffix in (".yml", ".yaml")
        )
    listing = git("ls-tree", "--name-only", ref, WORKFLOW_DIR)
    return sorted(
        line for line in listing.splitlines() if line.endswith((".yml", ".yaml"))
    )


def collect_files(ref: str | None) -> dict[str, bytes | None]:
    """Every file the gate comparison reads, at one ref."""
    files: dict[str, bytes | None] = {}
    for path in GATE_FILES:
        files[path] = current(path) if ref is None else read_at(ref, path)
    for path in workflow_paths(ref):
        files[path] = current(path) if ref is None else read_at(ref, path)
    return files


def lint_problems(
    base_manifest: bytes | None, head_manifest: bytes | None
) -> list[str]:
    """Lints that were relaxed or removed."""
    if not base_manifest or not head_manifest:
        return []
    problems: list[str] = []
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
    return problems


def deny_problems(base_deny: bytes | None, head_deny: bytes | None) -> list[str]:
    """Waivers that were added, or the whole file that carried them."""
    if not base_deny:
        return []
    if not head_deny:
        return [
            "deny.toml was removed; the advisory waivers and the license "
            "allow-list went with it"
        ]
    problems: list[str] = []
    for section, key in (("advisories", "ignore"), ("licenses", "allow")):
        base_list = string_list(base_deny.decode(), section, key)
        head_list = string_list(head_deny.decode(), section, key)
        for added in sorted(head_list - base_list):
            problems.append(f"deny.toml [{section}] {key} gained {added}")
    return problems


def coverage_problems(base_ci: bytes | None, head_ci: bytes | None) -> list[str]:
    """Coverage floors that were dropped or removed."""
    if not base_ci or not head_ci:
        return []
    problems: list[str] = []
    base_text = base_ci.decode()
    head_text = head_ci.decode()

    base_floor = coverage_floor(base_text)
    head_floor = coverage_floor(head_text)
    if base_floor is not None:
        if head_floor is None:
            problems.append("the coverage floor step was removed from ci.yml")
        elif head_floor < base_floor:
            problems.append(
                f"the coverage floor dropped from {base_floor}% to {head_floor}%"
            )

    base_patch = patch_coverage_floor(base_text)
    head_patch = patch_coverage_floor(head_text)
    if base_patch is not None:
        if head_patch is None:
            problems.append("the patch coverage floor was removed from ci.yml")
        elif head_patch < base_patch:
            problems.append(
                f"the patch coverage floor dropped from {base_patch}% to "
                f"{head_patch}%"
            )
    if patch_floor_is_wired(base_text) and not patch_floor_is_wired(head_text):
        problems.append("the patch coverage floor step was removed from ci.yml")
    return problems


def codecov_problems(
    base_codecov: bytes | None,
    head_codecov: bytes | None,
    head_ci: bytes | None,
) -> list[str]:
    """Codecov targets that were dropped, and the file itself."""
    if not base_codecov:
        return []
    if not head_codecov:
        return [
            "codecov.yml was removed; the coverage targets it declared went "
            "with it"
        ]
    problems: list[str] = []
    base_targets = codecov_targets(base_codecov.decode())
    head_targets = codecov_targets(head_codecov.decode())
    for scope, value in sorted(base_targets.items()):
        if scope not in head_targets:
            problems.append(f"codecov {scope} target was removed (was {value}%)")
        elif head_targets[scope] < value:
            problems.append(
                f"codecov {scope} target dropped from {value}% to "
                f"{head_targets[scope]}%"
            )
    # codecov.yml states the target; the CI floor is the one that
    # actually fails a build. The enforced floor may not be the weaker
    # of the two.
    head_text = head_ci.decode() if head_ci else ""
    head_floor = coverage_floor(head_text)
    head_patch = patch_coverage_floor(head_text)
    for scope, enforced in (("project", head_floor), ("patch", head_patch)):
        declared = head_targets.get(scope)
        if declared is not None and enforced is not None and enforced < declared:
            problems.append(
                f"the enforced {scope} coverage floor ({enforced}%) is below "
                f"the codecov {scope} target ({declared}%)"
            )
    return problems


def workflow_problems(
    base: dict[str, bytes | None], head: dict[str, bytes | None]
) -> list[str]:
    """Gates that stopped running because a step or a workflow went away.

    The required status checks name jobs, so a job that disappears is
    caught by the ruleset. A step inside a job that still exists is named
    by nothing, so it is caught here.
    """
    problems: list[str] = []
    paths = sorted(
        path
        for path in set(base) | set(head)
        if path.startswith(WORKFLOW_DIR)
    )
    for path in paths:
        base_bytes = base.get(path)
        head_bytes = head.get(path)
        if not base_bytes:
            continue
        if not head_bytes:
            problems.append(f"the workflow {path} was removed")
            continue
        for name in removed_steps(base_bytes.decode(), head_bytes.decode()):
            problems.append(f"the CI step {name!r} was removed from {path}")
    return problems


def gate_problems(
    base: dict[str, bytes | None], head: dict[str, bytes | None]
) -> list[str]:
    """Everything this change would weaken, as a list of sentences."""
    problems: list[str] = []
    problems += lint_problems(base.get("Cargo.toml"), head.get("Cargo.toml"))
    problems += deny_problems(base.get("deny.toml"), head.get("deny.toml"))
    problems += coverage_problems(base.get(CI_WORKFLOW), head.get(CI_WORKFLOW))
    problems += codecov_problems(
        base.get("codecov.yml"), head.get("codecov.yml"), head.get(CI_WORKFLOW)
    )
    problems += workflow_problems(base, head)
    return problems


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

    problems = gate_problems(collect_files(base), collect_files(None))

    print(f"gate-parity: compared HEAD against {ref} ({base[:12]})")
    return report(problems)


def level_name(level: int) -> str:
    for name, value in LEVELS.items():
        if value == level:
            return name
    return str(level)


if __name__ == "__main__":
    raise SystemExit(main())
