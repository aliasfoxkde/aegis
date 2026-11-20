#!/usr/bin/env bash
# Build and install the aegis-mcp binary, verifying the installed version.
#
# Usage:
#   scripts/install-mcp.sh              # installs to ~/.local/bin/aegis-mcp
#   DESTDIR=<dir> scripts/install-mcp.sh   # installs to <dir>/bin/aegis-mcp
#
# The script exits non-zero if the binary cannot be built or the version
# check fails. Installation replaces the destination atomically.

set -euo pipefail

DESTDIR="${DESTDIR:-$HOME/.local}"
INSTALL_DIR="${DESTDIR}/bin"
TARGET="aegis-mcp"

# Resolve the workspace root (one level up from this script's directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Version from the workspace manifest.
WANT_VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "${REPO_ROOT}/Cargo.toml" | head -1)"
if [[ -z "${WANT_VERSION}" ]]; then
    echo "error: could not read workspace version from Cargo.toml" >&2
    exit 1
fi

echo "=== building aegis-mcp ${WANT_VERSION} ==="
(
    cd "${REPO_ROOT}"
    cargo build --release --package "${TARGET}"
)

SRC="${REPO_ROOT}/target/release/${TARGET}"
if [[ ! -x "${SRC}" ]]; then
    echo "error: release binary not found: ${SRC}" >&2
    exit 1
fi

echo "=== installing to ${INSTALL_DIR}/${TARGET} ==="
mkdir -p "${INSTALL_DIR}"
INSTALL_PATH="${INSTALL_DIR}/${TARGET}"
TEMP_PATH="$(mktemp "${INSTALL_DIR}/.${TARGET}.XXXXXX")"
trap 'rm -f "${TEMP_PATH}"' EXIT
install -m 0755 "${SRC}" "${TEMP_PATH}"

INSTALLED_VERSION="$("${TEMP_PATH}" --version 2>/dev/null | awk '{print $2}')"
if [[ "${INSTALLED_VERSION}" != "${WANT_VERSION}" ]]; then
    echo "error: built binary version '${INSTALLED_VERSION}' differs from workspace version '${WANT_VERSION}'" >&2
    exit 1
fi

mv -f "${TEMP_PATH}" "${INSTALL_PATH}"
trap - EXIT
echo "installed: ${INSTALL_PATH}"
echo "installed version: ${INSTALLED_VERSION}"

echo "=== done ==="
echo "Run 'aegis-mcp --version' to verify the PATH binary."
