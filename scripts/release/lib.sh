#!/usr/bin/env bash
# Shared helpers for the release scripts. Source this, don't execute it.
#
# Every release asset this project publishes is named from one of the two
# tables below; build.sh assembles them and publish.sh refuses to upload a
# directory that does not hold exactly this set. Keep both tables identical.

# Platform archives and the WASM module, by target triple. Order matters
# only for readability; checksums.txt and attestation.json sort on their own.
TARGETS=(
    x86_64-unknown-linux-gnu
    aarch64-unknown-linux-gnu
    x86_64-apple-darwin
    aarch64-apple-darwin
    x86_64-pc-windows-gnu
)

# Archive name for a target triple.
archive_for() {
    local target="$1"
    printf 'aegis-%s.tar.gz\n' "$(asset_os_arch "$target")"
}

# The `<os>-<arch>` chunk of an asset name (matches the historical layout:
# linux-x86_64, linux-arm64, darwin-x86_64, darwin-arm64, windows-x86_64).
asset_os_arch() {
    case "$1" in
        x86_64-unknown-linux-gnu) printf 'linux-x86_64' ;;
        aarch64-unknown-linux-gnu) printf 'linux-arm64' ;;
        x86_64-apple-darwin) printf 'darwin-x86_64' ;;
        aarch64-apple-darwin) printf 'darwin-arm64' ;;
        x86_64-pc-windows-gnu) printf 'windows-x86_64' ;;
        *) return 1 ;;
    esac
}

# The four binaries packaged per platform (plus .exe on Windows). The
# trailing newline matters: `while read` drops a final unterminated line.
platform_binaries() {
    printf 'aegis\naegis-mcp\naegis-daemon\naegis-bundler\n'
}

# Every uploaded asset, in the canonical order used by publish.sh.
# Source code (zip) / Source code (tar.gz) are GitHub-generated and are not
# uploaded by us, so they are not listed here.
uploaded_assets() {
    local target
    for target in "${TARGETS[@]}"; do archive_for "$target"; done
    printf 'aegis-wasm.wasm\n'
    printf 'source.tar.gz\n'
    printf 'source.zip\n'
    printf 'checksums.txt\n'
    printf 'attestation.json\n'
}

# Reject anything that is not a plain release tag: vMAJOR.MINOR.PATCH.
version_from_tag() {
    local tag="$1"
    if ! [[ "$tag" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
        printf 'tag %q is not a release tag (expected vX.Y.Z)\n' "$tag" >&2
        return 1
    fi
    printf '%s\n' "${BASH_REMATCH[1]}"
}

# Fail unless the workspace manifest declares exactly this version.
check_manifest_version() {
    local repo="$1" version="$2"
    if ! grep -qx "version = \"${version}\"" "$repo/Cargo.toml"; then
        printf 'Cargo.toml workspace version does not match %s; cut the version-bump PR first\n' "$version" >&2
        return 1
    fi
}

# Print the CHANGELOG.md section for a version (without the `## [x.y.z]`
# header line, up to the next `## [`), ready to append under a summary.
changelog_section() {
    local repo="$1" version="$2"
    awk -v v="$version" '
        f && /^## \[/ { exit }
        $0 ~ ("^## \\[" v "\\]") { f = 1; next }
        f { print }
    ' "$repo/CHANGELOG.md"
}

# Print the executable name for a binary on a given target.
bin_name() {
    local bin="$1" target="$2"
    if [[ "$target" == *windows* ]]; then printf '%s.exe\n' "$bin"; else printf '%s\n' "$bin"; fi
}

# Cross-compilation goes through `cargo zigbuild` (zig's linker covers
# aarch64 glibc, both darwin targets and windows-gnu); the native host and
# wasm use plain `cargo build`. cargo-zigbuild wraps `cargo build` and takes
# no `build` subcommand of its own.

