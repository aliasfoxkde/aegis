#!/usr/bin/env bash
# Regenerate THIRD-PARTY-NOTICES.md from Cargo.lock.
#
# This is the canonical entry point: developers run it after a dependency
# change and commit the result, and the `notices` CI job runs it and diffs
# against the committed file, so the shipped notices cannot go stale. The
# pinned cargo-about version lives in the `notices` job in
# .github/workflows/ci.yml; locally,
#   cargo install cargo-about --locked --version <that version>
set -euo pipefail
cd "$(dirname "$0")/../.."

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# --all-features: the notices must cover every distributable configuration,
# including the optional `tree-sitter` feature. --fail: a crate whose license
# cannot be read or clarified aborts generation instead of shipping a gap.
cargo about generate --workspace --all-features --locked --fail \
    --output-file "$tmp" notices.hbs

# cargo-about has no config option to exclude crates (its config schema is
# `accepted` plus per-crate `clarify` overrides), and the workspace members
# are first-party — they are not third parties. Build the exclusion from the
# manifest itself rather than a hand-maintained list that can drift. Crate
# names are [a-z0-9_-], so they need no sed escaping.
members="$(cargo metadata --no-deps --format-version 1 |
    jq -r '.packages[].name' | paste -sd '|')"
sed -E -i "/^- (${members}) /d" "$tmp"

mv "$tmp" THIRD-PARTY-NOTICES.md
