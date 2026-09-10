#!/usr/bin/env bash
# Build the full release asset matrix into ./artifacts/.
#
# Usage: scripts/release/build.sh [tag]
#
# `tag` defaults to the exact annotated tag reachable from HEAD. The script
# refuses to run on anything other than a plain vX.Y.Z tag whose version
# matches the workspace manifest, so a release can never be cut from an
# untagged or mis-versioned tree.
#
# Outputs (uploaded verbatim by publish.sh):
#   aegis-<os>-<arch>.tar.gz  x5   the four binaries per platform
#   aegis-wasm.wasm                the browser/Node scanner module
#   source.tar.gz / source.zip     `git archive` of the tag
#   checksums.txt                  `sha256sum -c` manifest over all of the above
#   attestation.json               build provenance (schema below)
set -euo pipefail

source "$(git rev-parse --show-toplevel)/scripts/release/lib.sh"

repo="$(git rev-parse --show-toplevel)"
tag="${1:-$(git describe --tags --exact-match HEAD)}"
version="$(version_from_tag "$tag")"
check_manifest_version "$repo" "$version"
commit="$(git rev-parse --verify "$tag^{commit}")"

cd "$repo"

missing=0
for tool in sha256sum git; do
    command -v "$tool" >/dev/null || { printf 'missing tool: %s\n' "$tool" >&2; missing=1; }
done
command -v cargo >/dev/null || { printf 'missing tool: cargo\n' >&2; missing=1; }
# The matrix always includes cross targets, which zigbuild links with zig.
command -v cargo-zigbuild >/dev/null || { printf 'missing tool: cargo-zigbuild (cross targets)\n' >&2; missing=1; }
command -v zig >/dev/null || { printf 'missing tool: zig (cross linker)\n' >&2; missing=1; }
(( missing == 0 )) || exit 1

out="$repo/artifacts"
rm -rf "$out"
mkdir -p "$out"

rustc_version="$(rustc --version)"
zig_version="$(zig version 2>/dev/null || printf 'n/a')"

build_platform() {
    local target="$1"
    local dir bin

    # cargo-zigbuild wraps `cargo build` — it takes no `build` subcommand.
    if [[ "$target" == x86_64-unknown-linux-gnu ]]; then
        cargo build --workspace --release
        dir="target/release"
    else
        cargo zigbuild --workspace --release --target "$target"
        dir="target/$target/release"
    fi

    local archive members=()
    # `|| [[ -n $bin ]]` keeps a final unterminated line from being dropped.
    while read -r bin || [[ -n "$bin" ]]; do
        members+=("$(bin_name "$bin" "$target")")
    done < <(platform_binaries)

    for bin in "${members[@]}"; do
        [[ -f "$dir/$bin" ]] || { printf 'missing binary %s/%s\n' "$dir" "$bin" >&2; return 1; }
    done

    archive="$(archive_for "$target")"
    tar -czf "$out/$archive" -C "$dir" "${members[@]}"
    tar -tzf "$out/$archive" >/dev/null   # the archive itself must be readable

    printf 'built %s\n' "$archive"
}

for target in "${TARGETS[@]}"; do
    build_platform "$target"
done

# WASM module. The crate is `aegis-wasm`; its artifact is `aegis_wasm.wasm`
# (cargo munges the crate name), and the published name uses the same dash
# style as every other asset.
cargo build --release --package aegis-wasm --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/aegis_wasm.wasm "$out/aegis-wasm.wasm"
printf 'built aegis-wasm.wasm\n'

# Source archives, generated from the tag itself so they cannot drift.
git archive --format=zip     --prefix="aegis-$tag/" -o "$out/source.zip"   "$tag"
git archive --format=tar.gz  --prefix="aegis-$tag/" -o "$out/source.tar.gz" "$tag"
printf 'built source.zip, source.tar.gz\n'

# Pass 1: checksum everything except attestation.json and checksums.txt.
# attestation.json then embeds this file's digest, and pass 2 adds the
# attestation itself — digests stay acyclic.
(cd "$out" && sha256sum -- *.tar.gz *.wasm *.zip > checksums.txt)

# Build provenance. Built where the toolchain runs; darwin targets are
# cross-linked with zig on this host and are NOT Apple-hardware builds —
# recorded here rather than papered over.
host="$(uname -s)-$(uname -m)"
digest_of() { (cd "$out" && sha256sum "$1" | awk '{print $1}'); }
bytes_of()  { stat -c '%s' "$out/$1"; }

{
    printf '{\n'
    printf '  "schema": "aegis.release-attestation/v1",\n'
    printf '  "tag": "%s",\n' "$tag"
    printf '  "version": "%s",\n' "$version"
    printf '  "commit": "%s",\n' "$commit"
    printf '  "built_at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"
    printf '  "builder": {\n'
    printf '    "platform": "%s",\n' "$host"
    printf '    "rustc": "%s",\n' "$rustc_version"
    printf '    "zig": "%s",\n' "$zig_version"
    printf '    "note": "all targets cross-compiled on %s; darwin binaries are zig-linked (cargo-zigbuild), not built on Apple hardware"\n' "$host"
    printf '  },\n'
    printf '  "source": {\n'
    printf '    "url": "https://github.com/aliasfoxkde/aegis",\n'
    printf '    "ref": "%s",\n' "$tag"
    printf '    "commit": "%s"\n' "$commit"
    printf '  },\n'
    printf '  "checks": {\n'
    printf '    "version_match": true,\n'
    printf '    "tarball_members_verified": true,\n'
    printf '    "checksums_txt_sha256": "%s"\n' "$(digest_of checksums.txt)"
    printf '  },\n'
    printf '  "assets": [\n'
    first=1
    while read -r asset; do
        [[ "$asset" == "attestation.json" ]] && continue
        (( first )) || printf ',\n'
        first=0
        printf '    {"name": "%s", "sha256": "%s", "bytes": %s}' \
            "$asset" "$(digest_of "$asset")" "$(bytes_of "$asset")"
    done < <(uploaded_assets | sort)
    printf '\n  ]\n}\n'
} > "$out/attestation.json"

# Pass 2: the manifest covers the attestation too.
(cd "$out" && sha256sum -- *.tar.gz *.wasm *.zip attestation.json > checksums.txt)

# Self-check: the manifest must verify and the uploaded set must be exact.
(cd "$out" && sha256sum -c checksums.txt >/dev/null)
[[ "$(cd "$out" && printf '%s\n' * | sort)" == "$(uploaded_assets | sort)" ]] || {
    printf 'artifact set mismatch:\n' >&2
    diff <(uploaded_assets | sort) <(cd "$out" && printf '%s\n' * | sort) >&2 || true
    exit 1
}

printf 'release %s built into %s:\n' "$tag" "$out"
ls -la "$out"
