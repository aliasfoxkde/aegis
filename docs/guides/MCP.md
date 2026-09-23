# MCP Server (`aegis-mcp`)

Aegis ships a JSON-RPC 2.0 server over stdio for integration with AI
tools and scripts.

**Protocol surface (since 0.6.2):** the server speaks the Model Context
Protocol lifecycle and discovery methods — `initialize`,
`notifications/initialized`, `tools/list`, `tools/call`, and `ping` —
across protocol revisions `2024-11-05`, `2025-03-26`, and `2025-06-18`
(the client-requested version is echoed when supported, otherwise the
server answers with `2025-06-18`). Only the `tools` capability is
advertised: `resources/*` and `prompts/*` remain `-32601 Method not
found`. The seven scanning tools are also reachable directly through
their original custom JSON-RPC method names, with positional parameters
(documented below); both surfaces dispatch to the same implementations.

Wire behaviour is pinned by a conformance suite
(`crates/aegis-mcp/tests/fixtures/mcp_wire_conformance.json`, replayed
in CI), so request/response shapes documented here are tested
contract, not prose.

**Frame size:** one request frame (a JSON line) may be at most
10 MiB. A longer line is answered with a JSON-RPC `-32600` error
(`request frame exceeds maximum size`) and the session ends — framing
cannot resume inside an oversized line. `scan_string` is for snippets;
use `scan_file`/`scan_dir` for anything on disk.

## Starting the Server

The server communicates over stdio (standard input/output); diagnostics
go to stderr so stdout carries only JSON responses:

```bash
# Start the server (listens on stdin/stdout)
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

## Model Context Protocol Surface

The standard MCP flow, one JSON-RPC frame per line:

```json
{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"my-client","version":"1.0"}},"id":1}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","method":"tools/list","params":{},"id":2}
{"jsonrpc":"2.0","method":"tools/call","params":{"name":"scan_string","arguments":{"content":"TOKEN = \"...\"","source":"clip"}},"id":3}
```

`initialize` answers with the negotiated `protocolVersion`,
`serverInfo` (`aegis-mcp` / crate version), a `tools` capability, and
`instructions` describing the sandbox. `notifications/initialized`
produces no response. `tools/call` names a tool and takes an
`arguments` object matching that tool's schema (`content`/`source`,
`path`, `category`, `bundlePath`/`force` — the same parameters as the
positional custom methods). `ping` answers `{}`.

## Client Integration

### Claude Desktop / MCP clients

The server passes standard MCP discovery. Point an MCP client at the
binary:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "aegis-mcp",
      "args": []
    }
  }
}
```

Discovery exposes the seven tools (`scan_string`, `scan_file`,
`scan_dir`, `scan_env`, `list_patterns`, `list_categories`,
`update_bundle`) with JSON-Schema `inputSchema` objects. Tool results
arrive as one text block containing the same JSON payload the custom
methods return. Tool failures — including sandbox rejections — come
back as `isError: true` results (so the client can show them to the
model), while malformed `tools/call` parameters are JSON-RPC `-32602`.

The sandbox rule applies on every surface: `scan_file`, `scan_dir`, and
`update_bundle` paths must stay under the server process's working
directory. Configure the client's working directory accordingly, or the
tools will refuse paths outside it.

### Scripts and AI IDE terminals

Any process-spawning environment that can write a line and read a line
can drive the server; examples in this guide are copy-pasteable with
`echo ... | aegis-mcp`.

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
