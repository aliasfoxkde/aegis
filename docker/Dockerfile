# =============================================================================
# Aegis Security Scanner - Docker Image
# =============================================================================
# Multi-stage build for optimal image size and security.
#
# Build: docker build -t aegis:latest -f docker/Dockerfile .
# Run:   docker run --rm -v "$(pwd)":/workspace aegis scan /workspace
# Interactive: docker run --rm -it -v "$(pwd)":/workspace aegis
#
# The image carries the `aegis` scanner, the `aegis-daemon` Unix-socket
# server, and the `aegis-mcp` stdio JSON-RPC server, plus the shipped
# configuration profiles under /etc/aegis/profiles (use with
# `aegis scan <path> -c /etc/aegis/profiles/production.json`).

# -----------------------------------------------------------------------------
# Stage 1: Build
# -----------------------------------------------------------------------------
# 1.88 is the workspace MSRV (rust-version in Cargo.toml); locked
# dependencies (time, ignore) require it.
FROM rust:1.88-slim AS builder

WORKDIR /build

# Copy workspace files. Every workspace member must be present for cargo
# to load the workspace manifest; aegis-wasm and aegis-bundler are not
# built into this image, only their manifests are needed.
COPY Cargo.toml Cargo.lock ./
COPY crates/aegis-core ./crates/aegis-core
COPY crates/aegis-cli ./crates/aegis-cli
COPY crates/aegis-patterns ./crates/aegis-patterns
COPY crates/aegis-bundler ./crates/aegis-bundler
COPY crates/aegis-daemon ./crates/aegis-daemon
COPY crates/aegis-mcp ./crates/aegis-mcp
COPY crates/aegis-wasm ./crates/aegis-wasm

# Build the scanner, daemon, and MCP server in one cargo invocation so
# dependency compilation is shared.
RUN cargo build --release --locked -p aegis-cli -p aegis-daemon -p aegis-mcp

# -----------------------------------------------------------------------------
# Stage 2: Runtime
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# ca-certificates: HTTPS reference validation is not performed at scan
# time, but TLS roots keep any network use honest. tzdata: timestamps in
# scan receipts render with the local zone.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash aegis

ENV RUST_LOG=info

WORKDIR /app

# Copy binaries. The CLI binary is named `aegis`; the servers are
# `aegis-daemon` (Unix socket) and `aegis-mcp` (stdio JSON-RPC).
COPY --from=builder /build/target/release/aegis /usr/local/bin/aegis
COPY --from=builder /build/target/release/aegis-daemon /usr/local/bin/aegis-daemon
COPY --from=builder /build/target/release/aegis-mcp /usr/local/bin/aegis-mcp

# Shipped configuration profiles, loadable with `-c <path>`.
COPY config/profiles /etc/aegis/profiles

# Pattern state (`aegis disable` persists under the user config dir) and
# the default scan root must be writable by the non-root user.
RUN mkdir -p /home/aegis/.config/aegis /workspace \
    && chown -R aegis:aegis /home/aegis /workspace

# Switch to non-root user
USER aegis

# Volume for workspace (scan target)
VOLUME ["/workspace"]

# Default command
ENTRYPOINT ["aegis"]
CMD ["--help"]
