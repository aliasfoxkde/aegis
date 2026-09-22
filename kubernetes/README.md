# Aegis Kubernetes Deployment

Aegis in a cluster is a **scheduled batch scanner**. The daemon
(`aegis-daemon`) serves a local Unix socket and the MCP server
(`aegis-mcp`) speaks stdio JSON-RPC — neither is a network service, so
there is deliberately no Deployment/Service pair here: a TCP Service in
front of a Unix-socket server would answer nothing.

## What exists

| Manifest | Purpose |
|----------|---------|
| `cronjob.yaml` | Nightly `aegis scan` over a mounted workspace; SARIF report written next to the source |

## Prerequisites

- Kubernetes 1.24+
- A container registry holding the image built from `docker/Dockerfile`
  (update `image:` in `cronjob.yaml`)
- A PersistentVolumeClaim named `aegis-workspace` holding the source tree
  to scan

## Quick Start

```bash
# 1. Build and push the image
docker buildx build --platform linux/amd64,linux/arm64 \
  -t your-registry/aegis:latest -f docker/Dockerfile . --push

# 2. Apply the CronJob
kubectl apply -f kubernetes/cronjob.yaml

# 3. Trigger a scan immediately (don't wait for 2 AM)
kubectl create job --from=cronjob/aegis-scan-cron aegis-scan-manual

# 4. Read the result
kubectl logs job/aegis-scan-manual
# SARIF report: /workspace/scan-results.sarif on the aegis-workspace volume
```

## Exit-code semantics

The container exits `1` when findings survive the profile's filters and
`0` on a clean scan. `restartPolicy: Never` means a findings run is
recorded as a **failed Job** — the intended alerting signal, not an error
to retry away.

## Configuration

- **Scan profile**: the image ships `config/profiles/*.json` under
  `/etc/aegis/profiles`; the CronJob uses `production.json`. Swap in
  `pipeline.json` (broader categories, JSON output defaults) or mount
  your own profile and change the `-c` argument.
- **Schedule**: edit `spec.schedule` (default `0 2 * * *`).
- **Logging**: `RUST_LOG` (`info` default in the image, `warn` in the
  CronJob). This is the only behavior-affecting environment variable.

## Security posture

The container runs non-root (`uid 1000`) with a read-only root
filesystem, all capabilities dropped, and `allowPrivilegeEscalation`
off. It needs **no Kubernetes API access** — no RBAC, no ServiceAccount
mount — because the scanner only reads the mounted filesystem. Mount the
tokenless default service account is still auto-injected; harden with
`automountServiceAccountToken: false` in the pod spec if your cluster
policy allows.

## Troubleshooting

```bash
kubectl get jobs --selector=app=aegis
kubectl logs job/<job-name>
kubectl get events --sort-by='.lastTimestamp' | grep aegis
```
