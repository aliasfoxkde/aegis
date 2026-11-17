# Aegis v0.6.5 release receipt

**Date:** 2026-11-17
**Tag:** `v0.6.5` on `0ffe29e7531e28a683151eceb810eb3935be92ee`
**Release:** https://github.com/aliasfoxkde/aegis/releases/tag/v0.6.5
**Build:** GitForge pipeline `aegis-release` (`c761d8ce-af9b-4476-9dcc-297a3b837dbb`),
run `8e6c6428-86b1-482f-90ab-5b390b452db7`, job `45bc5fd3-c548-46e0-9f64-a2a47d6eb5c5`
**Producer:** the pipeline, in `aegis-builder:1`, at the tag

## How the release was cut

The bump landed through PR #203 (squash `0ffe29e`) with the full check set
terminal and green: fmt, clippy, the three-OS test matrix, build, coverage,
cargo-audit, cargo-deny, CodeQL, WASM, MSRV 1.88, and the gate-policy and
dependency-policy jobs. CodeRabbit reported `skipped` — the known
OSS-account restriction on auto-review, not a defect in the change.

The tag was pushed to the GitForge remote first, then to origin, so the
gateway could resolve `refs/tags/v0.6.5` against the bare storage. The
pipeline run was then triggered at that revision; the job ran the seven
gates-and-release steps (format, clippy, four test lanes, the release
build) and exited 0.

An independent fallback build in the same `aegis-builder:1` image was run
in parallel on an NVMe checkout of the tag, so a pipeline stall could not
hold the release. The pipeline finished first and is the producer of the
published assets.

## Published assets

Ten assets, uploaded verbatim from the pipeline's own artifacts:

| Asset | SHA-256 | Bytes |
|---|---|---|
| `aegis-linux-x86_64.tar.gz` | `f4bda28513d8669cb6aff08d91dfb9439de4d0cdb8624251c31d56ef3e5b0beb` | 7147345 |
| `aegis-linux-arm64.tar.gz` | `aaa34dd2c8d7ff71b0a8586d9b8e18f5dd2fb9fe4b282bfc39cb05b663a6bc15` | 6642597 |
| `aegis-darwin-x86_64.tar.gz` | `47cd47e5519a65039d26348524cecbbd8e056912bc0998f39376ca06a3e78f37` | 6865016 |
| `aegis-darwin-arm64.tar.gz` | `da8bebdcbe8580ec2cd515e7ac5e0742d62945079bee3f589862e8a6d073b999` | 6322551 |
| `aegis-windows-x86_64.tar.gz` | `6b804f3be49e89c6b4c91cacafad386673a53f3f69773e6d03f70167c3869ed7` | 5348977 |
| `aegis-wasm.wasm` | `4538d6706c51c9e7f3880d50e641734c9b6009b182d72ef98fff4eea443b2c0b` | 2459721 |
| `source.tar.gz` | `f2c89d501de888e577efb8962121fb4b82590942c6afe235adc3be3f7705f665` | 748772 |
| `source.zip` | `1b48011c37dc1edd64c3da85d5c65cf7bf5f0ca2f7c6e5d00c90c4519323e95a` | 890166 |
| `checksums.txt` | `4f1575cb896d7f49f18568061614845d206abb33e7c5fa70267f4fb164dd2b97` | 701 |
| `attestation.json` | `70676c3c7277c156776856e006819f2a8468b30b7b6d311fd36c39b44837b862` | 2136 |

Each digest was re-derived from the artifact bytes fetched out of the
pipeline's artifact store and compared with the digest the job reported;
all ten match. `sha256sum -c checksums.txt` passes over the published
set, and the published tarballs carry the four binaries plus `LICENSE`
and `THIRD-PARTY-NOTICES.md`.

## Verification

- `gh release view v0.6.5`: draft `false`, prerelease `false`, published
  `2026-11-17T02:13:42Z`, exactly the ten expected assets visible.
- `gh release download v0.6.5` into a fresh directory, then
  `sha256sum -c checksums.txt`: all assets `OK`.
- The downloaded `aegis-linux-x86_64.tar.gz` unpacks to `aegis`,
  `aegis-mcp`, `aegis-daemon`, `aegis-bundler`, `LICENSE`,
  `THIRD-PARTY-NOTICES.md`; `./aegis --version` prints `aegis 0.6.5` and
  `./aegis --help` renders the command list.
- `attestation.json` records `version_match: true`,
  `tarball_members_verified: true`, the tag, the commit, the toolchain
  (`rustc 1.88.0`, `zig 0.16.0`), and the builder note that the darwin
  binaries are zig-linked on the build host and carry a per-link
  `LC_UUID` that is not reproducible.

## Cross-check against the fallback build — one difference, and what causes it

The fallback build in the same image produced the same ten-asset set.
Comparing the two builds asset by asset:

- `aegis-wasm.wasm`, `source.tar.gz`, and `source.zip` are byte-identical.
- The five platform tarballs differ, and the difference is entirely the
  absolute source path embedded in the binaries: the pipeline builds at
  `/workspace/crates/...`, the fallback at `/src/crates/...`, and those
  strings appear in the compiled panic locations. The binary sizes are
  equal, the only differing bytes are inside those path strings, and the
  GNU build-ids differ accordingly.
- `attestation.json` differs in `built_at` and in the asset digests it
  embeds — the documented volatile field.

This is a real gap in the reproducibility claim in
`docs/guides/RELEASES.md`: the platform tarballs are byte-reproducible
only for the same build directory, because the build path is compiled
into the binaries. The fix is `--remap-path-prefix` in
`scripts/release/build.sh`, which belongs to the next release; it cannot
be applied to `v0.6.5`, whose tag is immutable. Until it lands, two
builds of one tag are comparable by the wasm module, the source archives,
and the tarball *members*, not by the tarball digests.

**Landed after the release:** `scripts/release/build.sh` now remaps the
workspace path *and* the cargo home (the dependency sources carry the
same property — a crate unpacked under `$CARGO_HOME` is compiled from
that absolute path). Verified in `aegis-builder:1`: a build at `/pa`
with `CARGO_HOME=/ca` and a build at `/pb` with `CARGO_HOME=/cb`
produced the identical binary, while a third build that remapped only
the workspace path produced a different one. The next release built
this way is reproducible across directories.

## Residual scope

- `CODECOV_TOKEN` is still unset, so every Codecov upload fails and is
  ignored; the patch-coverage floor reads the lcov report CI already
  produces, so the floor itself is enforced, but the Codecov service
  never sees a report.
- CodeRabbit's auto-review on draft pull requests stays unavailable on
  the OSS account, so draft PRs get no automated review.
- GitForge required checks remain a GitForge product gap, not an aegis
  one.
