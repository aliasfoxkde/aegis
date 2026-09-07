# Installation

## Quick Install (Recommended for Users)

Install the latest binary release for your platform. Every archive
bundles `aegis`, `aegis-mcp`, `aegis-daemon`, and `aegis-bundler`.

### Linux

```bash
# Download the latest release
curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-linux-x86_64.tar.gz

# Extract
tar -xzf aegis-linux-x86_64.tar.gz

# Move to PATH
sudo mv aegis /usr/local/bin/
```

For ARM64 Linux, use `aegis-linux-arm64.tar.gz` instead.

### macOS

```bash
# Intel
curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-darwin-x86_64.tar.gz
tar -xzf aegis-darwin-x86_64.tar.gz
sudo mv aegis /usr/local/bin/

# Apple Silicon
curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-darwin-arm64.tar.gz
tar -xzf aegis-darwin-arm64.tar.gz
sudo mv aegis /usr/local/bin/
```

### Windows

Download `aegis-windows-x86_64.tar.gz` from the
[GitHub Releases](https://github.com/aliasfoxkde/aegis/releases/latest)
page, extract it, and add `aegis.exe` to your PATH.

## Verify Installation

```bash
aegis --version
aegis list
```

## Docker

No image is published to a registry, so build one locally from
[`docker/Dockerfile`](../../docker/Dockerfile):

```bash
docker build -t aegis:latest -f docker/Dockerfile .
docker run --rm -v $(pwd):/workspace aegis:latest scan /workspace
```

See [`docker/README.md`](../../docker/README.md) for Docker Compose
profiles.

## Building from Source

```bash
cargo build --release -p aegis-cli
```

The binary lands at `target/release/aegis`. See
[Building from Source](BUILDING.md) for the full contributor setup.

## Requirements

- **No runtime dependencies** - Binary releases are self-contained
- **Linux/macOS/Windows** - Supported on x86_64 and ARM64

## Directory Installation

For multi-user environments or custom setups:

```bash
# Create installation directory
sudo mkdir -p /opt/aegis

# Extract there
sudo tar -xzf aegis-*.tar.gz -C /opt/aegis

# Create symlinks
sudo ln -s /opt/aegis/aegis /usr/local/bin/aegis
```

## Next Steps

- [Quick Start](QUICK_START.md) - Get started with basic scans
- [CLI Reference](CLI.md) - Full command documentation
- [CI/CD Integration](CICD_INTEGRATION.md) - Add to your pipelines
