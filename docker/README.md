# Aegis Docker Support

This directory contains Docker configuration for running Aegis in containers.

## Quick Start

### Build the Docker image

```bash
docker build -t aegis:latest -f docker/Dockerfile .
```

### Run a basic scan

```bash
docker run --rm -v $(pwd):/workspace aegis scan /workspace
```

## Using Docker Compose

Docker Compose provides convenient profiles for different use cases:

### Default scan

```bash
docker compose --profile default run --rm aegis scan /workspace
```

### CI/CD mode (exits with SARIF output)

```bash
docker compose --profile ci up
```

### Run tests

```bash
docker compose --profile test up
```

### Interactive shell

```bash
docker compose run --rm -it aegis /bin/bash
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AEGIS_HOME` | Aegis home directory | `/home/aegis/.aegis` |
| `RUST_LOG` | Logging level | `info` |
| `AEGIS_SEVERITY_THRESHOLD` | Minimum severity to report | `medium` |
| `AEGIS_EXIT_ON_FINDINGS` | Exit with non-zero on findings (CI mode) | `false` |
| `AEGIS_FORMAT` | Output format (human, json, sarif) | `human` |

## Examples

### Scan with JSON output

```bash
docker run --rm -v $(pwd):/workspace \
  -e AEGIS_FORMAT=json \
  aegis scan /workspace --format json > results.json
```

### SARIF output for GitHub Security

```bash
docker run --rm -v $(pwd):/workspace \
  -e AEGIS_FORMAT=sarif \
  -e AEGIS_EXIT_ON_FINDINGS=true \
  aegis scan /workspace --format sarif --output results.sarif
```

### Scan with pipeline preset (strict mode)

```bash
docker run --rm -v $(pwd):/workspace \
  aegis scan /workspace --preset pipeline
```

## Multi-platform Build

To build for multiple platforms:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t aegis:latest -f docker/Dockerfile . --push
```

## Security Considerations

- The Docker image runs as non-root user `aegis`
- File volumes are mounted read-only by default
- No secrets are stored in the image
- Minimal attack surface with distroless/slim base images

## Image Size Optimization

The multi-stage build produces a minimal image:
- Builder stage: includes Rust toolchain (~1.5GB)
- Runtime stage: minimal Debian with Aegis binary (~100MB)
