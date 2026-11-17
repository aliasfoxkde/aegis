#!/usr/bin/env python3
"""Tests for the release scripts' path remapping.

`scripts/release/build.sh` remaps the workspace path and the cargo home
out of the compiled paths, so a release is byte-reproducible wherever it
is built. The remapping is what the v0.6.5 cross-build measured the
absence of, so the helper has to keep doing what it claims: the same
prefix has to produce the same flag, a caller's own RUSTFLAGS have to
survive, and a prefix that cannot be remapped has to be refused rather
than silently producing path-dependent binaries.

Deterministic: fixed inputs, no network, no build. Run from the
repository root with:

    python3 scripts/test_release_remap.py
"""

from __future__ import annotations

import os
import shlex
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LIB = REPO_ROOT / "scripts" / "release" / "lib.sh"
BUILD = REPO_ROOT / "scripts" / "release" / "build.sh"


def run_bash(body: str, rustflags: str | None = None) -> subprocess.CompletedProcess:
    """Run `body` in a shell that has sourced lib.sh."""
    env = dict(os.environ)
    env.pop("RUSTFLAGS", None)
    if rustflags is not None:
        env["RUSTFLAGS"] = rustflags
    script = "set -euo pipefail\nsource {lib}\n{body}\n".format(
        lib=shlex.quote(str(LIB)), body=body
    )
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env, check=False
    )


class RemapPathPrefixTest(unittest.TestCase):
    def test_a_prefix_becomes_a_remap_flag(self) -> None:
        result = run_bash('remap_path_prefix /workspace\nprintf "%s\\n" "$RUSTFLAGS"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "--remap-path-prefix=/workspace=")

    def test_the_callers_own_flags_survive(self) -> None:
        result = run_bash(
            'remap_path_prefix /workspace\nprintf "%s\\n" "$RUSTFLAGS"',
            rustflags="-C debuginfo=2",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            "-C debuginfo=2 --remap-path-prefix=/workspace=",
        )

    def test_two_prefixes_both_appear(self) -> None:
        result = run_bash(
            'remap_path_prefix /workspace\nremap_path_prefix /cargo\n'
            'printf "%s\\n" "$RUSTFLAGS"'
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            "--remap-path-prefix=/workspace= --remap-path-prefix=/cargo=",
        )

    def test_an_empty_prefix_is_a_no_op(self) -> None:
        result = run_bash('remap_path_prefix ""\nprintf "%s\\n" "${RUSTFLAGS-}"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "")

    def test_a_prefix_with_whitespace_is_refused(self) -> None:
        result = run_bash(
            'remap_path_prefix "/work space"\nprintf "%s\\n" "$RUSTFLAGS"'
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("whitespace", result.stderr)

    def test_a_refused_prefix_leaves_the_flags_alone(self) -> None:
        result = run_bash(
            'remap_path_prefix "/work space"\nprintf "%s\\n" "$RUSTFLAGS"',
            rustflags="-C debuginfo=2",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("--remap-path-prefix", result.stdout)


class BuildWiringTest(unittest.TestCase):
    """The helper only helps if the build actually calls it."""

    def test_the_build_remaps_the_workspace_and_the_cargo_home(self) -> None:
        text = BUILD.read_text(encoding="utf-8")
        self.assertIn('remap_path_prefix "$repo"', text)
        self.assertIn('remap_path_prefix "${CARGO_HOME:-$HOME/.cargo}"', text)

    def test_the_build_does_not_replace_the_callers_flags(self) -> None:
        lib = LIB.read_text(encoding="utf-8")
        self.assertIn('${RUSTFLAGS:+', lib)
        self.assertNotIn('RUSTFLAGS="--remap-path-prefix', lib)


if __name__ == "__main__":
    unittest.main()
