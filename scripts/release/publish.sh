#!/usr/bin/env bash
# Publish a release to GitHub from a directory produced by build.sh.
#
# Usage: scripts/release/publish.sh <tag> [artifacts-dir]
#
# This is the sync step of the GitForge-first release flow: GitForge's
# pipeline builds the assets, this script mirrors them to the GitHub release
# for distribution. It is idempotent — rerunning after a partial failure
# repairs the release instead of duplicating it.
#
# Requires `gh` authenticated against aliasfoxkde/aegis. The release title is
# the bare tag (vX.Y.Z); the body is {summary} then {changelog}, where the
# summary comes from $AEGIS_SUMMARY_FILE (or artifacts/SUMMARY.md) and the
# changelog is the version's CHANGELOG.md section.
set -euo pipefail

source "$(git rev-parse --show-toplevel)/scripts/release/lib.sh"

repo="$(git rev-parse --show-toplevel)"
tag="${1:?usage: publish.sh <tag> [artifacts-dir]}"
version="$(version_from_tag "$tag")"

dir="${2:-$repo/artifacts}"
[[ -d "$dir" ]] || { printf 'no artifacts dir: %s\n' "$dir" >&2; exit 1; }
cd "$dir"

command -v gh >/dev/null || { printf 'missing tool: gh\n' >&2; exit 1; }

# The directory must hold exactly the expected set, verified against its own
# manifest, before anything is uploaded.
[[ "$(printf '%s\n' * | sort)" == "$(uploaded_assets | sort)" ]] || {
    printf 'artifact set mismatch in %s:\n' "$dir" >&2
    diff <(uploaded_assets | sort) <(printf '%s\n' * | sort) >&2 || true
    exit 1
}
sha256sum -c checksums.txt

gh_repo='aliasfoxkde/aegis'

# Notes: {summary} then {changelog}. The summary comes from
# $AEGIS_SUMMARY_FILE so the artifacts directory stays exactly the published
# set; a missing summary degrades to changelog only. A missing changelog
# section is fatal — the notes are the release.
notes="$(mktemp)"
trap 'rm -f "$notes"' EXIT
if [[ -n "${AEGIS_SUMMARY_FILE:-}" ]]; then
    [[ -f "$AEGIS_SUMMARY_FILE" ]] || { printf 'summary file not found: %s\n' "$AEGIS_SUMMARY_FILE" >&2; exit 1; }
    cat "$AEGIS_SUMMARY_FILE" >> "$notes"
    printf '\n' >> "$notes"
fi
changelog_section "$repo" "$version" >> "$notes"
if ! grep -q . "$notes"; then
    printf 'no CHANGELOG.md section for %s; add the release entry first\n' "$version" >&2
    exit 1
fi

# Create the release as a draft (mutable) unless it already exists. A
# published release is immutable on GitHub — assets can neither be replaced
# nor added — so publishing is deferred until the full set is verified below.
existing_id="$(gh api "repos/$gh_repo/releases/tags/$tag" --jq '.id' 2>/dev/null || true)"
if [[ -z "$existing_id" ]]; then
    gh release create "$tag" --repo "$gh_repo" --verify-tag --draft \
        --title "$tag" --notes-file "$notes" >/dev/null
elif [[ "$(gh api "repos/$gh_repo/releases/$existing_id" --jq '.draft')" == "true" ]]; then
    gh release edit "$tag" --repo "$gh_repo" --title "$tag" --notes-file "$notes" >/dev/null
fi

while read -r asset; do
    gh release upload "$tag" "$asset" --repo "$gh_repo" --clobber
done < <(uploaded_assets)

# Verify every expected asset is visible on the release, then publish.
visible="$(gh release view "$tag" --repo "$gh_repo" --json assets --jq '[.assets[].name] | sort | join("\n")')"
while read -r asset; do
    grep -Fqx -- "$asset" <<<"$visible" || {
        printf 'asset missing after upload: %s\n' "$asset" >&2
        exit 1
    }
done < <(uploaded_assets)

is_draft="$(gh release view "$tag" --repo "$gh_repo" --json isDraft --jq '.isDraft')"
if [[ "$is_draft" == "true" ]]; then
    gh release edit "$tag" --repo "$gh_repo" --draft=false --latest >/dev/null
fi

printf 'release %s published: %s\n' "$tag" \
    "https://github.com/$gh_repo/releases/tag/$tag"
