# Aegis Docker Support

This directory contains the container build for Aegis and Compose
profiles for common invocations.

## Build the image

```bash
docker build -t aegis:latest -f docker/Dockerfile .
```

The image carries three binaries — the `aegis` scanner, the
`aegis-daemon` Unix-socket server, and the `aegis-mcp` stdio JSON-RPC
server — plus the shipped configuration profiles under
`/etc/aegis/profiles`. It runs as a non-root user (`uid 1000`).

## Run a scan

```bash
docker run --rm -v "$(pwd)":/workspace aegis scan /workspace
```

Exit codes follow the CLI contract: `1` when findings are reported, `0`
on a clean scan. To fail a CI step on findings, just run the container.

## Using Docker Compose

| Profile | Invocation | What it does |
|---------|------------|--------------|
| `default` | `docker compose --profile default run --rm aegis` | Human-readable scan of the checkout |
| `json` | `docker compose --profile json run --rm aegis` | JSON output for downstream tooling |
| `ci` | `docker compose --profile ci run --rm aegis` | `pipeline.json` profile, SARIF written to `aegis-results.sarif` next to the checkout |
| shell | `docker compose run --rm -it aegis /bin/bash` | Interactive shell |

## Scan with a specific profile

```bash
docker run --rm -v "$(pwd)":/workspace aegis \
  scan /workspace -c /etc/aegis/profiles/production.json
```

## SARIF output for GitHub Security

```bash
docker run --rm -v "$(pwd)":/workspace aegis \
  scan /workspace --format sarif --output-file /workspace/aegis-results.sarif
```

## Environment variables

`RUST_LOG` is the only behavior-affecting variable (default `info`).
There are no `AEGIS_FORMAT`/`AEGIS_EXIT_ON_FINDINGS`-style switches —
format and thresholds are CLI flags, and the findings exit code is
built into the binary.

The daemon does take `AEGIS_DAEMON_SOCKET_PATH` and
`AEGIS_DAEMON_SCAN_ROOT`, but it listens on a **Unix socket**; it is a
local integration surface and is not exposed as a container port.
