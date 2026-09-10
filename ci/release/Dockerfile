# aegis-release — GitForge release lane image for the Aegis workspace.
#
# Toolchain parity with the workstation rehearsal that validated the
# cross matrix on 2026-09-10 (rust 1-bookworm, zig 0.16.0,
# cargo-zigbuild 0.23.4): the five template targets build there, so the
# image ships exactly those versions. The cargo registry is vendored at
# build time so lane jobs run without network access.
#
# Build context: the repo tree (git archive of the release commit)
# plus this file. Only the manifests are consumed, for `cargo vendor`;
# the lane job compiles the checkout the runner clones, never this
# copy, which is deleted in the same layer.
FROM docker.io/library/rust:1-bookworm@sha256:cdb2da72943ec036bf0c731ef5ac9e5fb2b1d17d3a9256a581bad64cf6fc093d

ARG ZIG_VERSION=0.16.0
ARG CARGO_ZIGBUILD_VERSION=0.23.4

RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl xz-utils python3 zip \
 && rm -rf /var/lib/apt/lists/*

RUN rustup target add \
      x86_64-unknown-linux-musl \
      aarch64-unknown-linux-musl \
      x86_64-pc-windows-gnu \
      aarch64-apple-darwin \
      x86_64-apple-darwin \
      wasm32-unknown-unknown
# aarch64-linux-android joins this list when the NDK is added to the
# image; zig alone cannot compile aws-lc-sys C sources for android.

RUN curl -fsSL \
      "https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz" \
      | tar -xJ -C /usr/local \
 && ln -s "/usr/local/zig-x86_64-linux-${ZIG_VERSION}/zig" /usr/local/bin/zig

RUN cargo install --locked --version "${CARGO_ZIGBUILD_VERSION}" cargo-zigbuild

COPY aegis-src/ /tmp/aegis-src
WORKDIR /tmp/aegis-src
# Vendor the lockfile-pinned registry into the image and point cargo at
# it for every future job, then drop the source copy: the image must
# stay source-agnostic (the lane checkout is what gets compiled).
RUN cargo vendor /opt/aegis-vendor > /tmp/vendor-config.toml \
 && printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "/opt/aegis-vendor"\n' \
      > /usr/local/cargo/config.toml \
 && rm -rf /tmp/aegis-src /tmp/vendor-config.toml

ENV CARGO_TERM_COLOR=never
