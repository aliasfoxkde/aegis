# Aegis Kubernetes Deployment

This directory contains Kubernetes manifests for deploying Aegis in a cluster.

## Prerequisites

- Kubernetes 1.24+
- kubectl configured with cluster access
- Container registry with Aegis image

## Quick Start

### 1. Build and push the image

```bash
# Build multi-arch image
docker buildx build --platform linux/amd64,linux/arm64 \
  -t your-registry/aegis:latest -f docker/Dockerfile . --push

# Or use pre-built image from Docker Hub
# Update deployment.yaml image to: docker.io/aegis/aegis:latest
```

### 2. Apply the manifests

```bash
# Apply all manifests
kubectl apply -f kubernetes/

# Check status
kubectl get pods -l app=aegis
kubectl get services -l app=aegis
```

### 3. Access the service

```bash
# Port-forward for local access
kubectl port-forward svc/aegis-service 8080:80

# Or use ingress (requires ingress controller)
# Edit service.yaml with your domain and apply
```

## Components

### Daemon Deployment
Long-running HTTP server for on-demand scanning:
- 2 replicas with HPA support
- Health check endpoints (/health, /ready)
- Prometheus metrics endpoint (/metrics)

### CronJob
Scheduled scans using production preset:
- Runs daily at 2 AM
- Outputs SARIF to persistent volume
- Configurable schedule and preset

### ServiceAccount & RBAC
- Minimal permissions for scanning
- Read-only access to secrets

## Configuration

### Via ConfigMap

```yaml
kubectl create configmap aegis-config --from-file=kubernetes/configmap.yaml
```

### Via Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AEGIS_HOME` | Aegis home directory | `/home/aegis/.aegis` |
| `RUST_LOG` | Logging level | `info` |
| `AEGIS_DAEMON_PORT` | Daemon port | `8080` |

### Via CLI Arguments

```yaml
args:
  - daemon
  - --host
  - "0.0.0.0"
  - --port
  - "8080"
  - --config
  - /etc/aegis/aegis.yaml
```

## Scaling

```bash
# Manual scaling
kubectl scale deployment aegis-daemon --replicas=5

# Enable HPA
kubectl autoscale deployment aegis-daemon \
  --cpu-percent=70 \
  --min=2 \
  --max=10
```

## Monitoring

The daemon exposes Prometheus metrics at `/metrics`:
- `aegis_scans_total` - Total scans
- `aegis_scan_duration_seconds` - Scan duration histogram
- `aegis_findings_total` - Total findings by severity

Grafana dashboard available in `/kubernetes/grafana-dashboard.json`.

## Troubleshooting

```bash
# Check logs
kubectl logs -l app=aegis -f

# Check events
kubectl get events --sort-by='.lastTimestamp'

# Exec into pod
kubectl exec -it deploy/aegis-daemon -- /bin/bash
```

## Production Considerations

1. **Security**: Use read-only root filesystem and non-root user
2. **Storage**: Use PVC for scan results persistence
3. **Networking**: Configure TLS via ingress
4. **Secrets**: Mount API keys via Kubernetes secrets
5. **Monitoring**: Enable Prometheus scraping via ServiceMonitor
