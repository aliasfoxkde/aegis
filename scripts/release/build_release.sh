#!/usr/bin/env bash
# build_release.sh — build, package, checksum, and attest one Aegis
# release inside the GitForge release lane.
#
# Runs in the aegis-release image: every toolchain is preloaded and the
# cargo registry is vendored into the image, so the job never touches
# the network. Output is dist/ in the job workspace; the workstation
# publisher (scripts/release/publish_github_release.sh) collects it,
# verifies checksums.txt, and publishes the GitHub release. GitForge is
# the build path of record; GitHub is the sharing mirror.
#
# Asset naming follows the release template:
#   aegis-darwin-arm64.tar.gz    aegis-darwin-x86_64.tar.gz
#   aegis-linux-arm64.tar.gz     aegis-linux-x86_64.tar.gz
#   aegis-windows-x86_64.tar.gz  aegis-wasm.wasm
#   source.tar.gz source.zip checksums.txt release-attestation.json
#
# Linux archives are static musl builds; darwin and windows are
# produced by cargo-zigbuild (zig as the cross linker). The Android
# archive joins TARGETS once the release image carries the Android NDK:
# zig alone cannot compile aws-lc-sys C sources for android targets.

set -euo pipefail

version="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)"
if [ -z "$version" ]; then
  echo "cannot read workspace version from Cargo.toml" >&2
  exit 1
fi
tag="v$version"
# The lane runner materializes the workspace checkout under a different
# uid than the job process runs as, and git refuses such "dubious
# ownership" outright. Trust exactly the checkout this script was
# invoked to archive; the config is container-local and dies with the
# job.
git config --global --add safe.directory "$(pwd)"
commit="$(git rev-parse HEAD)"
dist="$PWD/dist"
mkdir -p "$dist"

echo "release: aegis $tag ($commit)"

build_and_package() {
  target="$1"
  out="$2"
  echo "--- building $target"
  cargo zigbuild --release --locked --target "$target" \
    -p aegis-cli -p aegis-mcp -p aegis-daemon -p aegis-bundler
  ext=""
  if [ "$target" = "x86_64-pc-windows-gnu" ]; then
    ext=".exe"
  fi
  tar -czf "dist/$out" -C "target/$target/release" \
    "aegis$ext" "aegis-mcp$ext" "aegis-daemon$ext" "aegis-bundler$ext"
}

# Order matters for reproducibility of the log; each leg fails the job
# on the first failure (set -eu).
build_and_package x86_64-unknown-linux-musl aegis-linux-x86_64.tar.gz
build_and_package aarch64-unknown-linux-musl aegis-linux-arm64.tar.gz
build_and_package x86_64-pc-windows-gnu      aegis-windows-x86_64.tar.gz
build_and_package aarch64-apple-darwin       aegis-darwin-arm64.tar.gz
build_and_package x86_64-apple-darwin        aegis-darwin-x86_64.tar.gz

echo "--- building wasm32-unknown-unknown"
cargo build --release --locked --target wasm32-unknown-unknown -p aegis-wasm
# The crate emits aegis_wasm.wasm (underscored crate name); the release
# template names the asset with a dash.
cp target/wasm32-unknown-unknown/release/aegis_wasm.wasm dist/aegis-wasm.wasm

echo "--- source archives"
git archive --format=zip    --prefix="aegis-$tag/" -o dist/source.zip HEAD
git archive --format=tar.gz --prefix="aegis-$tag/" -o dist/source.tar.gz HEAD

echo "--- attestation"
write_attestation() {
  python3 - "$version" "$tag" "$commit" "$dist" <<'PY'
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

version, tag, commit, dist = sys.argv[1:5]


def tool_version(argv):
    try:
        out = subprocess.run(
            argv, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"
    return out.splitlines()[0] if out else "unavailable"


artifacts = []
for name in sorted(os.listdir(dist)):
    path = os.path.join(dist, name)
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    artifacts.append(
        {
            "filename": name,
            "sha256": digest.hexdigest(),
            "bytes": os.path.getsize(path),
        }
    )

attestation = {
    "attestation_version": 1,
    "name": "aegis",
    "version": version,
    "tag": tag,
    "commit": commit,
    "built_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    "builder": {"system": "gitforge-release-lane", "pipeline": "aegis-release"},
    "toolchain": {
        "cargo": tool_version(["cargo", "--version"]),
        "rustc": tool_version(["rustc", "--version"]),
        "zig": tool_version(["zig", "version"]),
        "cargo_zigbuild": tool_version(["cargo-zigbuild", "--version"]),
    },
    "artifacts": artifacts,
}
with open(os.path.join(dist, "release-attestation.json"), "w") as handle:
    json.dump(attestation, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
}
write_attestation

echo "--- checksums"
(cd dist && sha256sum -- * > checksums.txt)

echo "--- dist manifest"
ls -la dist
cat dist/checksums.txt
echo "release build complete: aegis $tag ($commit)"
