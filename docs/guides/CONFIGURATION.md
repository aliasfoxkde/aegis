# Configuration

## Configuration Files

Aegis uses configuration files in the following order (first found wins):

1. `./.aegis.toml` (project directory)
2. `~/.aegis/config.toml` (user home)
3. `/etc/aegis/config.toml` (system-wide)

## Profile Configuration

Aegis includes preset profiles for different use cases.

### Production Profile

High-security settings for production environments.

```toml
[profile]
name = "production"

[scanning]
severity_threshold = "medium"
confidence_threshold = "medium"
scan_binaries = true
scan_hidden = false

[performance]
workers = 8
batch_size = 1000

[risk]
enabled = true
thresholds.critical = 80
thresholds.high = 60
thresholds.medium = 40
```

### Pipeline Profile

Optimized for CI/CD pipelines.

```toml
[profile]
name = "pipeline"

[scanning]
severity_threshold = "high"
confidence_threshold = "high"
scan_binaries = false
scan_hidden = false

[output]
format = "sarif"
fail_on = "high"

[performance]
workers = 4
batch_size = 500
```

### Development Profile

Relaxed settings for local development.

```toml
[profile]
name = "development"

[scanning]
severity_threshold = "low"
confidence_threshold = "low"
scan_binaries = true
scan_hidden = true

[output]
format = "text"
verbose = true

[performance]
workers = 2
batch_size = 100
```

### MCP Integration Profile

Settings for MCP server mode.

```toml
[profile]
name = "mcp-integration"

[scanning]
severity_threshold = "low"
confidence_threshold = "low"
scan_binaries = false
scan_hidden = false

[output]
format = "json"
verbose = false

[mcp]
port = 8765
timeout = 30
```

## Ignoring Files

Create `.aegisignore` in your project root:

```
# Patterns (glob)
node_modules/
dist/
build/
*.min.js

# Directories
.git/
target/
vendor/

# File types
**/*.png
**/*.jpg
**/*.lock

# Specific findings
ignore: aws-access-key
ignore: commented-secret
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AEGIS_CONFIG` | Config file path | - |
| `AEGIS_PROFILE` | Profile to use | `development` |
| `AEGIS_BUNDLE_URL` | Pattern bundle URL | official |
| `AEGIS_WORKERS` | Worker threads | auto |
| `AEGIS_LOG_LEVEL` | Log level | `info` |

## Risk Scoring Configuration

```toml
[risk]
enabled = true

[risk.severity_weights]
critical = 40
high = 25
medium = 10
low = 3

[risk.confidence_weights]
high = 1.0
medium = 0.7
low = 0.4

[risk.density_threshold]
high = 10    # findings per 1000 lines
medium = 5
low = 2
```

## Pattern Categories

Categories can be individually enabled/disabled:

```toml
[categories.secrets]
enabled = true
severity_override = "high"

[categories.pii]
enabled = true
severity_override = null  # use pattern default

[categories.ai_detection]
enabled = false
```
