# aegis-builder:1 — image for the GitForge release pipeline (.gitforce.yml).
#
# Rust toolchain plus the cross-linker set used by scripts/release/build.sh:
# cargo-zigbuild and zig cover aarch64 glibc, both darwin targets and
# windows-gnu, so no per-target gcc/SDK packages are needed.
#
# Build and load locally where the GitForge runner executes:
#   docker build -t aegis-builder:1 scripts/release
FROM rust:1-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl xz-utils git \
    && rm -rf /var/lib/apt/lists/*

# The `rust:1` image ships rustup without the lint/format components the
# quality-gates job runs; add them explicitly so the image owns its toolchain.
RUN rustup component add rustfmt clippy

# Every release target's std libraries. The host triple ships with the
# image; the four cross targets and wasm32 do not, and without their std
# crates every cross build dies with "can't find crate for `std`".
RUN rustup target add \
    aarch64-unknown-linux-gnu \
    x86_64-apple-darwin \
    aarch64-apple-darwin \
    x86_64-pc-windows-gnu \
    wasm32-unknown-unknown

# Zig pinned to the version the release attestation records; bump here and
# rebuild the image when the toolchain moves.
ARG ZIG_VERSION=0.16.0
RUN curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz" \
        -o /tmp/zig.tar.xz \
    && mkdir -p /usr/local/zig \
    && tar -xJf /tmp/zig.tar.xz --strip-components=1 -C /usr/local/zig \
    && rm /tmp/zig.tar.xz \
    && ln -s /usr/local/zig/zig /usr/local/bin/zig

RUN cargo install --locked cargo-zigbuild
