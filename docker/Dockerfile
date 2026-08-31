# =============================================================================
# Aegis Security Scanner - Docker Image
# =============================================================================
# Multi-stage build for optimal image size and security
#
# Build: docker build -t aegis:latest -f docker/Dockerfile .
# Run:   docker run --rm -v $(pwd):/workspace aegis scan /workspace
# Interactive: docker run --rm -it -v $(pwd):/workspace aegis

# -----------------------------------------------------------------------------
# Stage 1: Build
# -----------------------------------------------------------------------------
FROM rust:1.81-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates/aegis-core ./crates/aegis-core
COPY crates/aegis-cli ./crates/aegis-cli
COPY crates/aegis-patterns ./crates/aegis-patterns
COPY crates/aegis-bundler ./crates/aegis-bundler
COPY crates/aegis-daemon ./crates/aegis-daemon
COPY crates/aegis-mcp ./crates/aegis-mcp
COPY crates/aegis-wasm ./crates/aegis-wasm

# Build dependencies first (cached)
RUN cargo build --release -p aegis-cli --bin aegis

# Build the binary
RUN cargo build --release -p aegis-cli

# -----------------------------------------------------------------------------
# Stage 2: Runtime
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash aegis

# Set environment variables
ENV AEGIS_VERSION=latest
ENV AEGIS_HOME=/home/aegis
ENV PATH="${AEGIS_HOME}/bin:${PATH}"
ENV RUST_LOG=info

# Create app directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/target/release/aegis /usr/local/bin/aegis
COPY --from=builder /build/target/release/aegis-cli /usr/local/bin/aegis-cli 2>/dev/null || true

# Create directories for patterns and cache
RUN mkdir -p ${AEGIS_HOME}/.aegis \
    && chown -R aegis:aegis ${AEGIS_HOME}

# Switch to non-root user
USER aegis

# Volume for workspace (scan target)
VOLUME ["/workspace"]

# Default command
ENTRYPOINT ["aegis"]
CMD ["--help"]
