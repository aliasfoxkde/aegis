# Installation

## Quick Install (Recommended for Users)

Install the latest binary release for your platform:

### Linux

```bash
curl -sSL https://get.aegis.dev | sh
```

Or download manually:

```bash
# Download the latest release
curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-linux-x86_64.tar.gz

# Extract
tar -xzf aegis-linux-x86_64.tar.gz

# Move to PATH
sudo mv aegis /usr/local/bin/
```

### macOS

```bash
# Download the latest release
curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-macos.tar.gz

# Extract
tar -xzf aegis-macos.tar.gz

# Move to PATH
sudo mv aegis /usr/local/bin/
```

### Windows

Download the latest release from the [GitHub Releases](https://github.com/aliasfoxkde/aegis/releases/latest) page and add to your PATH.

## Verify Installation

```bash
aegis --version
aegis list
```

## Docker

```bash
docker run --rm -v $(pwd):/scan ghcr.io/aliasfoxkde/aegis scan /scan
```

## Package Managers

### Homebrew (macOS/Linux)

```bash
brew install aliasfoxkde/tap/aegis
```

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
