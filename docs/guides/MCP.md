# MCP Server

Aegis provides a Model Context Protocol (MCP) server for integration with AI tools.

## Starting the Server

The MCP server communicates over stdio (standard input/output):

```bash
# Start the MCP server (listens on stdin/stdout)
aegis-mcp
```

## Available Tools

The server accepts JSON-RPC requests over stdin and responds on stdout.

### scan_string

Scan in-memory content for security issues.

```json
{
  "jsonrpc": "2.0",
  "method": "scan_string",
  "params": ["const apiKey = 'AKIAIOSFODNN7EXAMPLE';", "config.js"],
  "id": 1
}
```

### scan_file

Scan a single file.

```json
{
  "jsonrpc": "2.0",
  "method": "scan_file",
  "params": ["/path/to/config.json"],
  "id": 2
}
```

### scan_dir

Scan a directory recursively.

```json
{
  "jsonrpc": "2.0",
  "method": "scan_dir",
  "params": ["/path/to/project"],
  "id": 3
}
```

### scan_env

Scan environment variables.

```json
{
  "jsonrpc": "2.0",
  "method": "scan_env",
  "params": [],
  "id": 4
}
```

### list_patterns

List available patterns.

```json
{
  "jsonrpc": "2.0",
  "method": "list_patterns",
  "params": ["secrets"],
  "id": 5
}
```

### list_categories

List all pattern categories.

```json
{
  "jsonrpc": "2.0",
  "method": "list_categories",
  "params": [],
  "id": 6
}
```

### update_bundle

Update pattern bundle (checks if updates are available).

```json
{
  "jsonrpc": "2.0",
  "method": "update_bundle",
  "params": [false],
  "id": 7
}
```

## MCP Client Integration

### Claude Desktop

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "aegis-mcp"
    }
  }
}
```

### Cursor / Other AI IDEs

Consult your IDE's documentation for MCP server configuration. The server uses the standard MCP protocol over stdio.

## Response Format

Responses are JSON-RPC 2.0:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "findings": [
      {
        "pattern": "aws-access-key",
        "severity": "critical",
        "confidence": "high",
        "location": {
          "file": "config.js",
          "line": 1,
          "column": 20
        },
        "matched_content": "AKIAIOSFODNN7EXAMPLE",
        "description": "AWS access key ID detected"
      }
    ],
    "finding_count": 1,
    "risk_level": "high",
    "risk_score": 85
  },
  "id": 1
}
```

## Error Responses

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32602,
    "message": "Invalid params: path is outside allowed directory"
  },
  "id": 2
}
```
