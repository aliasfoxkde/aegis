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

Update pattern bundle. Takes a two-element array: an optional bundle path
(`null` for the default) and a `force` flag.

```json
{
  "jsonrpc": "2.0",
  "method": "update_bundle",
  "params": [null, false],
  "id": 7
}
```

## Parameter Shapes

| Method | `params` |
|--------|----------|
| `scan_string` | `["<content>", "<source label>"]` — two strings |
| `scan_file` | `["/path/to/file"]` — exactly one string |
| `scan_dir` | `["/path/to/dir"]` — exactly one string |
| `scan_env` | `[]` or omitted |
| `list_patterns` | `[]` or `["<category>"]` |
| `list_categories` | `[]` or omitted |
| `update_bundle` | `[<path or null>, <bool>]` |

`scan_file` and `scan_dir` are sandboxed to the server's working
directory: a path that escapes it is rejected.

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

Responses are JSON-RPC 2.0. Scan results carry `finding_count`,
`findings`, `risk_level`, `risk_score`, `stats`, and a `receipt`:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "finding_count": 1,
    "findings": [
      {
        "pattern": "aws-access-key",
        "category": "pii",
        "kind": "pattern",
        "severity": "critical",
        "confidence": "high",
        "location": {
          "file": "config.js",
          "line": 1,
          "column": 18
        },
        "description": "AWS Access Key ID detected",
        "reference": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
        "tags": [],
        "id": "000000000000000018d31755598f11f4",
        "fingerprint": "aws-access-key:config.js:1:1a5d44a2…",
        "stable_id": "aegis-84f7dbec95cecf248f…"
      }
    ],
    "risk_level": "critical",
    "risk_score": 215,
    "stats": {"files_scanned": 1},
    "receipt": {"receipt_id": "aegis-receipt-…"}
  },
  "id": 1
}
```

`list_patterns` returns `{"patterns": [...], "total": N}`;
`list_categories` returns a plain array of category names;
`update_bundle` returns `{"success": true, "message": "...", "pattern_count": 0}`.

## Error Responses

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32602,
    "message": "Path is outside allowed directory"
  },
  "id": 2
}
```

Malformed parameters also return `-32602`, e.g. calling `scan_file` with
the wrong number of arguments yields
`Invalid params: expected exactly one string parameter: ["/path/to/scan/target"]`.
