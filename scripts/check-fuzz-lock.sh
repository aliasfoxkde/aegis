#!/usr/bin/env bash
# Fail unless fuzz/Cargo.lock pins the same aegis-core version as the
# workspace. The fuzz lock is outside the workspace and is not verified by
# `cargo check --locked` in CI (see docs/guides/RELEASES.md); a version
# bump that forgets `cd fuzz && cargo update -p aegis-core` would otherwise
# resolve fresh at fuzz time, silently fuzzing the wrong dependency graph.
set -euo pipefail
cd "$(dirname "$0")/.."

workspace="$(cargo metadata --no-deps --format-version 1 |
    jq -r '.packages[] | select(.name == "aegis-core") | .version')"
# Lockfile entries are `name = "..."` immediately followed by `version = "..."`.
fuzz="$(awk '/^name = "aegis-core"$/{getline; print; exit}' fuzz/Cargo.lock |
    sed -E 's/^version = "(.+)"$/\1/')"

if [[ -z "$fuzz" ]]; then
    printf 'aegis-core not found in fuzz/Cargo.lock\n' >&2
    exit 1
fi
if [[ "$workspace" != "$fuzz" ]]; then
    printf 'fuzz/Cargo.lock pins aegis-core %s but the workspace declares %s\n' "$fuzz" "$workspace" >&2
    printf 'fix: cd fuzz && cargo update -p aegis-core\n' >&2
    exit 1
fi
printf 'fuzz lock matches workspace (aegis-core %s)\n' "$workspace"
