# MCP Server

Aegis provides a Model Context Protocol (MCP) server for integration with AI tools.

## Starting the Server

```bash
# Start with default settings
aegis-mcp

# Start on custom port
aegis-mcp --port 8765

# Start with verbose logging
aegis-mcp --verbose
```

## Available Tools

### scan_string

Scan in-memory content for security issues.

```json
{
  "tool": "scan_string",
  "args": {
    "content": "const apiKey = 'AKIAIOSFODNN7EXAMPLE';",
    "category": "secrets"
  }
}
```

### scan_file

Scan a single file.

```json
{
  "tool": "scan_file",
  "args": {
    "path": "/path/to/config.json"
  }
}
```

### scan_dir

Scan a directory recursively.

```json
{
  "tool": "scan_dir",
  "args": {
    "path": "/path/to/project",
    "severity_threshold": "high"
  }
}
```

### scan_env

Scan environment variables.

```json
{
  "tool": "scan_env",
  "args": {}
}
```

### list_patterns

List available patterns.

```json
{
  "tool": "list_patterns",
  "args": {
    "category": "secrets"
  }
}
```

### list_categories

List all pattern categories.

```json
{
  "tool": "list_categories",
  "args": {}
}
```

## MCP Client Integration

### Claude Desktop

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "aegis-mcp",
      "args": ["--port", "8765"]
    }
  }
}
```

### Cursor / Other AI IDEs

Consult your IDE's documentation for MCP server configuration.

## Response Format

```json
{
  "findings": [
    {
      "pattern": "aws-access-key",
      "severity": "critical",
      "confidence": "high",
      "line": 1,
      "content": "const apiKey = 'AKIAIOSFODNN7EXAMPLE';",
      "description": "AWS access key ID detected"
    }
  ],
  "summary": {
    "total": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0
  }
}
```
