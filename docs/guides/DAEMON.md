# Aegis daemon protocol

The daemon is a long-lived scanner that serves one machine's worth of
clients over a Unix domain socket. It exists so that a client — an IDE, an
agent, a CI job on the same host — can scan without paying the cost of
loading the rule set and walking the tree itself, and so that the operator
can decide once, in one place, what the daemon is allowed to look at.

This guide is the protocol: how to talk to the daemon, what each method
accepts, what comes back, and what the daemon refuses to do. The boundary
configuration — socket path, scan root, peer allowlists, profile file — is
in [`crates/aegis-daemon/README.md`](../../crates/aegis-daemon/README.md);
the profile fields themselves are in
[`CONFIGURATION.md`](CONFIGURATION.md).

## Transport

- **Socket**: a Unix domain socket. The path comes from
  `AEGIS_DAEMON_SOCKET_PATH`; the daemon does not choose a default that
  clients have to guess.
- **Framing**: newline-delimited JSON. One request object per line, one
  response object per line. The framing is the delimiter, so a request
  never contains a raw newline.
- **Frame limit**: 10 MiB per request. A larger frame is answered once
  with an error and the connection is closed — the rest of the oversized
  line cannot be located, so framing cannot resume.
- **Connection lifetime**: a connection serves any number of requests
  until the client closes it. A blank line is ignored rather than
  answered, and a line that is not JSON is answered with a parse error
  and the connection continues.
- **Authorization**: Unix peer credentials. The socket owner is always
  authorized; additional UIDs and GIDs may be allowed through
  `AEGIS_DAEMON_ALLOWED_UIDS` and `AEGIS_DAEMON_ALLOWED_GIDS`. The
  filesystem mode on the socket is defense in depth, not the mechanism:
  an unauthorized peer is dropped even when the socket was readable.

## Request

```json
{"method": "scan_string", "params": ["fn main() {}", "main.rs"], "id": 1}
```

| Field | Required | Meaning |
| --- | --- | --- |
| `method` | yes | The method name. A request without one is refused. |
| `params` | depends on the method | The method's parameters; see the table. |
| `id` | no | Ignored. The daemon answers in order, one response per request, and does not echo the id. |

The daemon reads `method` and `params`. It does not echo `id` back, so a
client correlates responses by the order it sent them — which is what the
one-request-one-response framing guarantees.

## Methods

| Method | Parameters | What it does |
| --- | --- | --- |
| `ping` | none | Liveness check. Answers with a successful, empty response. |
| `scan_string` | `[content, source]` | Scans in-memory content. `source` is the label the finding and the receipt carry — a filename, a URL, a description. |
| `scan_file` | `"path"` | Scans one file. The path is resolved beneath the daemon's scan root. |
| `scan_dir` | `"path"` | Scans a directory tree. The path is resolved beneath the daemon's scan root. |
| `scan_env` | none | Scans the daemon process's own environment variables. |
| `list_patterns` | none | Reports how many rules the registry holds. The rules themselves are not returned: pattern metadata belongs to the MCP server, whose response shape has room for it. |
| `list_categories` | none | Lists the categories the registry holds, and how many there are. |

### `scan_string`

```json
{"method": "scan_string", "params": ["AKIA...", "deploy.sh"], "id": 2}
```

`params` is an array of exactly two strings: the content to scan and the
label to report it under. A missing content or source is refused with
`Missing content param` or `Missing source param`.

The receipt records the source as `string:<source>`, so an in-memory scan
stays distinguishable from a filesystem scan in audit output.

### `scan_file` and `scan_dir`

```json
{"method": "scan_file", "params": "src/config.rs", "id": 3}
```

The path is relative to the daemon's scan root, or absolute and inside it.
Absolute paths outside the root, `..` traversal, and symlinks whose
canonical target leaves the root are refused before the scanner runs. A
path that cannot be resolved at all — because it does not exist, or the
daemon cannot read its parents — is refused too. A path that resolves but
cannot be scanned is reported as `Scan error: <reason>`.

### `scan_env`

The daemon scans its own environment — the variables the daemon's service
account was given — not the client's. The client cannot send variables to
scan.

## Response

Every answer uses the same envelope, so a client parses one shape:

```json
{
  "success": true,
  "findings": [],
  "finding_count": 0,
  "risk_level": "none",
  "risk_score": 0,
  "stats": {"files_scanned": 0, "bytes_scanned": 0, "finding_count": 0, "...": "..."},
  "receipt": {"schema_version": 1, "receipt_id": "aegis-receipt-...", "...": "..."},
  "categories": [],
  "error": null
}
```

| Field | Meaning |
| --- | --- |
| `success` | Whether the request was served. `false` is always paired with a non-empty `error` and never with findings. |
| `findings` | The findings, already stripped of the matched source text. Empty on failure. |
| `finding_count` | How many findings came back. `list_patterns` and `list_categories` reuse it to report the number of rules or categories. |
| `risk_level` | Aggregate severity label: `none`, `low`, `medium`, `high`, `critical`, or `unknown` for a failed request. |
| `risk_score` | The integer behind `risk_level`; `0` for an empty or failed scan. |
| `stats` | The coverage and timing ledger — files read, files skipped, files that failed, bytes, patterns matched, timings, per-extension and per-severity breakdowns. |
| `receipt` | The audit record: the source, the scope, the profile digest, the redacted findings, and what the scan did and did not inspect. Absent for errors and for the two listing methods. |
| `categories` | The category list, returned only by `list_categories`; empty otherwise. |
| `error` | The reason the request was refused, or `null` on success. |

A failed request answers with `success: false`, an `error` message, no
findings, and `risk_level: "unknown"`. A failed request can therefore
never be mistaken for a clean scan.

## Error model

Errors are reported in the envelope, never as a dropped connection. The
messages a client can match on:

| Message | Cause |
| --- | --- |
| `Missing method` | The request had no `method` field. |
| `Unknown method: <name>` | No such method. |
| `Parse error: <detail>` | The line was not JSON. |
| `scan_string requires [content, source] params` | `scan_string` was called without an array of two strings. |
| `Missing content param` / `Missing source param` | `scan_string` was called with the wrong parameters. |
| `Missing path param` | `scan_file` or `scan_dir` was called with no path. |
| `scan path is outside approved root <root>: <requested>` | The path resolved outside the approved tree. |
| `scan path cannot be resolved within approved root: <path> (<reason>)` | The path could not be resolved at all. |
| `Scan error: <reason>` | The path could not be scanned. |
| `scanner unavailable: <reason>` | The rule set could not be loaded. |
| `request frame exceeds maximum size (10485760 bytes)` | The request was larger than the frame limit; the connection is then closed. |

## What the daemon does not do

These are deliberate, not gaps:

- **No configuration over the wire.** The profile is read from
  `AEGIS_DAEMON_CONFIG` at startup and applied before the socket is
  bound. A client cannot change it; changing it means editing the file
  and restarting the daemon.
- **No rule-set replacement.** There is no `update_bundle` method, and
  `Config::bundle` is skipped on deserialization, so a client can never
  name a rule set. The daemon serves the corpus shipped with the binary.
  The MCP server's `update_bundle` swaps the bundle that server itself
  serves, which is an operator's decision made at the operator's console;
  a client of a shared daemon has no such standing.
- **No unrestricted paths.** `scan_file` and `scan_dir` are confined to
  the scan root. There is no compatibility mode that scans arbitrary
  absolute paths.

## Talking to the daemon

The socket is a Unix socket, so any client that can write a line to it
works. A minimal client in Python:

```python
import json, socket

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect("/run/aegis/aegis-daemon.sock")
sock.sendall(json.dumps({
    "method": "scan_string",
    "params": ["AKIA...", "deploy.sh"],
    "id": 1,
}).encode() + b"\n")

line = b""
while not line.endswith(b"\n"):
    line += sock.recv(4096)
print(json.loads(line))
```

The wire-conformance suite in
`crates/aegis-daemon/tests/daemon_wire_conformance.rs` is the executable
version of this document: it drives a real daemon over a real socket and
replays the cases above.
