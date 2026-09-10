#!/usr/bin/env bash
# Entry point for the GitForge release pipeline (see .gitforce.yml).
#
# The pipeline runs this inside the aegis-builder container with the repo
# mounted at the working directory. The workspace must already be checked out
# at the release tag — the pipeline engine passes no ref information, so the
# tag is derived from HEAD and every step below re-verifies it rather than
# trusting the checkout.
set -euo pipefail

source "$(git rev-parse --show-toplevel)/scripts/release/lib.sh"

repo="$(git rev-parse --show-toplevel)"
cd "$repo"

tag="$(git describe --tags --exact-match HEAD)" ||
    { printf 'HEAD is not exactly on a tag; check out the release tag first\n' >&2; exit 1; }
version="$(version_from_tag "$tag")"
check_manifest_version "$repo" "$version"

# The tree must be clean: the sources that get archived and attested have to
# be the tag's, not a working-copy variant.
[[ -z "$(git status --porcelain)" ]] || {
    printf 'working tree is dirty; refusing to build a release from it\n' >&2
    exit 1
}

printf 'building release %s (version %s, commit %s)\n' \
    "$tag" "$version" "$(git rev-parse HEAD)"

exec scripts/release/build.sh "$tag"
