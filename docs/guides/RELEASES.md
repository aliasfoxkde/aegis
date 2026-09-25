# Cutting a Release

Aegis releases are built by the **GitForge** pipeline and synced to the
GitHub release for distribution. Both paths run the same scripts, so the
asset set is identical regardless of who drove the build.

## The asset set

Every release ships exactly these uploaded assets:

| Asset | Contents |
|---|---|
| `aegis-linux-x86_64.tar.gz` | `aegis`, `aegis-mcp`, `aegis-daemon`, `aegis-bundler` |
| `aegis-linux-arm64.tar.gz` | same, aarch64 glibc |
| `aegis-darwin-x86_64.tar.gz` | same, Intel macOS |
| `aegis-darwin-arm64.tar.gz` | same, Apple Silicon |
| `aegis-windows-x86_64.tar.gz` | same, `.exe` binaries |
| `aegis-wasm.wasm` | browser/Node scanner module |
| `source.tar.gz`, `source.zip` | `git archive` of the tag |
| `checksums.txt` | `sha256sum -c` manifest over every other asset |
| `attestation.json` | build provenance (schema below) |

GitHub additionally attaches `Source code (zip)` / `Source code (tar.gz)`.
The release **title is the bare tag** (`vX.Y.Z`); the body is a short
summary followed by the version's `CHANGELOG.md` section.

## The flow

1. **Version-bump PR** — set the workspace version in `Cargo.toml`, refresh
   `Cargo.lock` (and `fuzz/Cargo.lock`: `cd fuzz && cargo update -p
   aegis-core`), and add the `CHANGELOG.md` entry. Main is PR-only; the bump
   goes through its own PR.
2. **Tag** `vX.Y.Z` on the merged bump commit and push it to both remotes
   (GitForge first). Verify what you tagged:
   `git show v0.7.0:Cargo.toml | grep 'version ='`.
3. **Build on GitForge** — the `aegis-release` pipeline (`.gitforce.yml`)
   runs the quality gates, then `scripts/release/pipeline.sh` inside the
   `aegis-builder` image. Check out the tag in the pipeline workspace first;
   the script re-verifies tag/version/clean-tree rather than trusting the
   checkout. Artifacts land in the workspace `artifacts/` directory, which
   the runner collects.
4. **Sync to GitHub** — `scripts/release/publish.sh vX.Y.Z [dir]` verifies
   the artifact set against `checksums.txt`, creates the release as a draft,
   uploads every asset, re-verifies the visible asset list, then publishes.
   It is idempotent; rerun after a partial failure. The body's summary
   paragraph comes from `$AEGIS_SUMMARY_FILE` (the artifacts directory
   itself must stay exactly the published set — keep scratch files
   elsewhere).
5. **Verify** — `gh release download`, `sha256sum -c checksums.txt`, and
   run the binary (`./aegis --version`).

The GitHub `Release` workflow is a **manual fallback**
(`workflow_dispatch` with a tag input) that runs the same two scripts on a
GitHub runner. It is not tag-triggered, so a pushed tag cannot race the
GitForge pipeline to create the release first.

## The builder image

`scripts/release/Dockerfile` defines `aegis-builder:1`: Rust plus
[cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild) and a pinned
Zig, whose linker covers aarch64 glibc, both darwin targets and
windows-gnu — no per-target gcc or SDK packages. Rebuild it locally where
the runner executes:

```bash
docker build -t aegis-builder:1 scripts/release
```

## Reproducibility

Two builds of the same tag produce **byte-identical binaries** —
demonstrated for v0.6.3, where the GitForge pipeline build and an
independent fallback build in the same `aegis-builder` image yielded
identical `aegis`, `aegis-mcp`, `aegis-daemon`, `aegis-bundler`,
`aegis-wasm.wasm`, and `source.tar.gz`/`source.zip` (`git archive` is
deterministic by construction).

The five platform **tarballs** are also reproducible: `build.sh` pins
what tar would otherwise copy from the build environment — owner/group
`0:0` (`--numeric-owner`), fixed modes, and every member's mtime set to
the tag's commit time — and gzips with `-n` so no wall clock enters the
header. Before that fix the tarball digests drifted across builders even
with identical contents (each builder's uid/gid leaked into the archive).

The one intentionally volatile asset is `attestation.json`: its
`built_at` records the real build time, and it embeds the asset digests.
To cross-check two builds of the same tag, compare the binaries and
tarball digests; expect `built_at` (and only it) to differ.

## The attestation

`attestation.json` (`aegis.release-attestation/v1`) records the tag,
version, commit, build timestamp, builder platform, toolchain versions, the
SHA-256 of every other asset (including `checksums.txt`), and two checks:
`version_match` (manifest equals tag) and `tarball_members_verified`. The
builder note states plainly that darwin binaries are zig-linked on the
build host, **not** built on Apple hardware — that tradeoff is disclosed,
not hidden.

Digests are acyclic: `checksums.txt` covers every asset *including* the
attestation; the attestation covers every asset *including*
`checksums.txt`.

## Gotchas baked in by history

- **Published GitHub releases are immutable.** Assets can never be
  replaced or added after publishing (HTTP 422) — this is why `publish.sh`
  uploads everything while the release is a draft and publishes only after
  the full asset set verifies. A bad asset can only be fixed forward.
- **Tag names are forever.** A tag name that went through
  publish/delete churn before immutability was enabled can become
  permanently un-publishable (v0.2.6 is the cautionary example). Never reuse
  a tag name; if a release must be redone, cut a new version.
- **`checksums.txt` is over the published archives**, in `sha256sum -c`
  format (since 0.6.0). Per-platform checksum files hashed unpacked
  binaries and were removed.
- **`checksums.txt` on the GitHub mirror is unsigned.** It is verifiable
  only against itself; the provenance anchor is the GitForge release,
  whose attestation is minisign-signed. After every publish, compare the
  mirror's asset digests against the GitForge pipeline's receipt (or let
  both builds of the same tag prove byte-reproducibility — see
  "Reproducibility" above); do not treat the mirror's `checksums.txt` as
  a root of trust.
- **macOS binaries are unsigned and never notarized.** The darwin
  targets are zig-linked on the build host (stated in the attestation),
  so Gatekeeper quarantines them on first launch. Run
  `xattr -d com.apple.quarantine aegis` (or right-click → Open) after
  extracting; the release page says the same instead of implying the
  binaries are Apple-signed.
- **`fuzz/Cargo.lock` pins `aegis-core`** and is not verified by CI — the
  weekly fuzz jobs run `cargo fuzz run` without `--locked`, so a drifted
  lock would silently resolve fresh. The version-bump PR must update it
  by hand (`cd fuzz && cargo update -p aegis-core`).
