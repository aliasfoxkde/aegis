//! Model Context Protocol (MCP) lifecycle and discovery layer.
//!
//! The server's scanning surface is the custom method set registered in
//! [`crate::main`] (`scan_string`, `scan_file`, …). This module adds the
//! standard MCP methods a generic client needs before it can use any of
//! that: the `initialize` handshake, `notifications/initialized`,
//! `tools/list` discovery, `tools/call` dispatch, and `ping`.
//!
//! Version negotiation follows the MCP revision of 2025-06-18: the server
//! echoes a client-requested protocol version it supports, otherwise it
//! answers with its own latest supported version and lets the client
//! decide whether that is compatible.
//!
//! Tool failures are reported inside the `tools/call` result with
//! `isError: true` (sandbox rejections, unreadable files, unknown tools),
//! not as JSON-RPC protocol errors — that distinction is what lets an MCP
//! client show the failure to the model instead of treating it as a
//! broken transport.

use crate::AegisRpcImpl;
use jsonrpc_core::{IoHandler, Params, Result, Value};
use serde::Deserialize;
use serde_json::json;

/// Protocol versions this server can speak, newest last.
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 3] = ["2024-11-05", "2025-03-26", "2025-06-18"];

/// The version answered when the client requests nothing we support.
pub const LATEST_PROTOCOL_VERSION: &str = "2025-06-18";

/// `initialize` request parameters, parsed liberally: unknown fields are
/// ignored and missing optional fields fall back to descriptive
/// placeholders, because the server must stay usable with clients across
/// MCP revisions.
#[derive(Debug, Deserialize)]
pub struct InitializeParams {
    #[serde(default, rename = "protocolVersion")]
    pub protocol_version: Option<String>,
    /// Client capability set. Parsed and ignored: this server only
    /// advertises `tools`, and no client capability changes our answers.
    #[serde(default)]
    #[allow(dead_code)]
    pub capabilities: Value,
    // `clientInfo` is deliberately not captured — serde ignores unknown
    // fields, and the server never needs the client's identity.
}

/// Negotiate the protocol version: echo the client's request when we
/// support it, otherwise answer with our latest.
#[must_use]
pub fn negotiate_protocol_version(requested: Option<&str>) -> &'static str {
    match requested {
        Some(version) if SUPPORTED_PROTOCOL_VERSIONS.contains(&version) => {
            SUPPORTED_PROTOCOL_VERSIONS
                .iter()
                .find(|supported| **supported == version)
                .expect("version matched the supported list")
        }
        _ => LATEST_PROTOCOL_VERSION,
    }
}

/// The `initialize` result: negotiated version, the `tools` capability,
/// server identity, and the sandbox rule every caller needs to know.
#[must_use]
pub fn initialize_result(params: &InitializeParams) -> Value {
    let version = negotiate_protocol_version(params.protocol_version.as_deref());
    json!({
        "protocolVersion": version,
        "capabilities": {
            "tools": { "listChanged": false },
        },
        "serverInfo": {
            "name": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
        },
        "instructions": format!(
            "Aegis security scanner. {} Scan paths must stay under the server's working directory; \
             anything else is rejected as a sandbox violation.",
            server_description()
        ),
    })
}

fn server_description() -> &'static str {
    "Every scan returns findings (with the matched secret text redacted), a risk score, coverage stats, and a receipt."
}

/// One entry of `tools/list`: the name an MCP client selects, the
/// description the model reads, and the JSON Schema its arguments must
/// satisfy.
#[must_use]
pub fn tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "scan_string",
            "Scan in-memory source text for security issues (secrets, PII, injection, and more).",
            json!({
                "type": "object",
                "properties": {
                    "content": { "type": "string", "description": "Text to scan" },
                    "source": { "type": "string", "description": "Label recorded in the scan receipt" },
                },
                "required": ["content"],
                "additionalProperties": false,
            }),
        ),
        tool(
            "scan_file",
            "Scan one file under the server's working directory.",
            path_schema("File to scan; must stay under the server's working directory"),
        ),
        tool(
            "scan_dir",
            "Scan a directory recursively, honouring .gitignore and .aegisignore.",
            path_schema("Directory to scan; must stay under the server's working directory"),
        ),
        tool(
            "scan_env",
            "Scan the server process's environment variables for leaked credentials.",
            json!({ "type": "object", "properties": {}, "additionalProperties": false }),
        ),
        tool(
            "list_patterns",
            "List detection rules, optionally filtered by category.",
            json!({
                "type": "object",
                "properties": {
                    "category": { "type": "string", "description": "Only return rules in this category" },
                },
                "additionalProperties": false,
            }),
        ),
        tool(
            "list_categories",
            "List the detection rule categories the server can report.",
            json!({ "type": "object", "properties": {}, "additionalProperties": false }),
        ),
        tool(
            "update_bundle",
            "Replace the detection rule set. Without arguments, reinstalls the rules compiled into the server.",
            json!({
                "type": "object",
                "properties": {
                    "bundlePath": { "type": "string", "description": "Path to a signed bundle; omitted means the built-in rules" },
                    "force": { "type": "boolean", "description": "Reserved for compatibility; has no effect" },
                },
                "additionalProperties": false,
            }),
        ),
    ]
}

fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    // scan/list tools only read; `update_bundle` replaces the rule set.
    let read_only = name != "update_bundle";
    let mut tool = json!({
        "name": name,
        "description": description,
        "annotations": { "readOnlyHint": read_only, "openWorldHint": false },
    });
    tool["inputSchema"] = input_schema;
    tool
}

fn path_schema(description: &str) -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": description },
        },
        "required": ["path"],
        "additionalProperties": false,
    })
}

/// `tools/call` parameters. `arguments` is optional because the schema of
/// several tools allows `{}`; a missing `name` is a protocol-level
/// invalid-params error.
#[derive(Debug, Deserialize)]
pub struct CallToolParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Option<Value>,
}

/// The `tools/call` result envelope demanded by the MCP spec: tool output
/// is text content, and tool failures are flagged with `isError` instead
/// of failing the JSON-RPC call.
#[must_use]
pub fn call_tool_result(text: &str, is_error: bool) -> Value {
    json!({
        "content": [ { "type": "text", "text": text } ],
        "isError": is_error,
    })
}

/// Compact JSON serialization for embedding a scan/list result as the
/// text content of a `tools/call` response.
fn to_text<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|error| format!("{{\"serialization_error\":\"{error}\"}}"))
}

/// Tool execution as the shared internal implementations see it: either a
/// serialized result, or a message that becomes `isError: true` content.
type ToolOutcome = std::result::Result<String, String>;

/// Dispatch one `tools/call` to the matching internal implementation.
///
/// The argument shapes mirror the legacy custom methods (which stay
/// registered), so both surfaces stay behaviourally identical.
async fn dispatch_tool(rpc: &AegisRpcImpl, name: &str, arguments: Option<Value>) -> ToolOutcome {
    #[derive(Deserialize)]
    struct ScanStringArgs {
        content: String,
        #[serde(default)]
        source: Option<String>,
    }
    #[derive(Deserialize)]
    struct PathArgs {
        path: String,
    }
    #[derive(Deserialize)]
    struct CategoryArgs {
        #[serde(default)]
        category: Option<String>,
    }
    #[derive(Deserialize)]
    struct UpdateBundleArgs {
        #[serde(default, rename = "bundlePath")]
        bundle_path: Option<String>,
        #[serde(default)]
        force: Option<bool>,
    }

    fn parse_args<T: serde::de::DeserializeOwned>(
        arguments: Option<Value>,
        tool_name: &str,
    ) -> std::result::Result<T, String> {
        let arguments = arguments.unwrap_or(Value::Null);
        serde_json::from_value(arguments)
            .map_err(|error| format!("invalid arguments for tool {tool_name}: {error}"))
    }

    let error_to_message = |error: jsonrpc_core::Error| error.message;

    match name {
        "scan_string" => {
            let args: ScanStringArgs = parse_args(arguments, name)?;
            let source = args.source.unwrap_or_else(|| String::from("<input>"));
            rpc.scan_string(args.content, source)
                .await
                .map(|response| to_text(&response))
                .map_err(error_to_message)
        }
        "scan_file" => {
            let args: PathArgs = parse_args(arguments, name)?;
            rpc.scan_file(args.path)
                .await
                .map(|response| to_text(&response))
                .map_err(error_to_message)
        }
        "scan_dir" => {
            let args: PathArgs = parse_args(arguments, name)?;
            rpc.scan_dir(args.path)
                .await
                .map(|response| to_text(&response))
                .map_err(error_to_message)
        }
        "scan_env" => rpc
            .scan_env()
            .await
            .map(|response| to_text(&response))
            .map_err(error_to_message),
        "list_patterns" => {
            let args: CategoryArgs = parse_args(arguments, name)?;
            rpc.list_patterns(args.category)
                .await
                .map(|response| to_text(&response))
                .map_err(error_to_message)
        }
        "list_categories" => rpc
            .list_categories()
            .await
            .map(|categories| to_text(&categories))
            .map_err(error_to_message),
        "update_bundle" => {
            let args: UpdateBundleArgs = parse_args(arguments, name)?;
            rpc.update_bundle(args.bundle_path, args.force.unwrap_or(false))
                .await
                .map(|response| to_text(&response))
                .map_err(error_to_message)
        }
        other => Err(format!("unknown tool: {other}")),
    }
}

/// Register the MCP lifecycle and discovery methods on `io`.
///
/// The custom method set stays registered separately (legacy surface);
/// the two share the same [`AegisRpcImpl`], so results never diverge.
pub fn register(io: &mut IoHandler, rpc: std::sync::Arc<AegisRpcImpl>) {
    io.add_method("initialize", |params: Params| {
        Box::pin(async move {
            let params: InitializeParams = parse_params(params)?;
            Ok(initialize_result(&params))
        })
    });

    // The client's "I know who you are" notification: nothing to do and
    // nothing to answer — jsonrpc-core runs notification handlers to
    // completion synchronously and emits no response frame.
    io.add_notification("notifications/initialized", |_params: Params| {});

    io.add_method("tools/list", |_params: Params| {
        Box::pin(async move { Ok(json!({ "tools": tool_definitions() })) })
    });

    io.add_method("tools/call", move |params: Params| {
        let handler = rpc.clone();
        Box::pin(async move {
            let params: CallToolParams = parse_params(params)?;
            match dispatch_tool(&handler, &params.name, params.arguments).await {
                Ok(text) => Ok(call_tool_result(&text, false)),
                Err(message) => Ok(call_tool_result(&message, true)),
            }
        })
    });

    io.add_method("ping", |_params: Params| {
        Box::pin(async move { Ok(json!({})) })
    });
}

fn parse_params<T: serde::de::DeserializeOwned>(params: Params) -> Result<T> {
    params.parse().map_err(|error| jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::InvalidParams,
        message: error.to_string(),
        data: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params_from(value: Value) -> InitializeParams {
        serde_json::from_value(value).expect("initialize params parse")
    }

    #[test]
    fn initialize_negotiates_supported_client_version() {
        for version in SUPPORTED_PROTOCOL_VERSIONS {
            let params = params_from(json!({
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": { "name": "test-client", "version": "1.0" },
            }));
            let result = initialize_result(&params);
            assert_eq!(result["protocolVersion"], version);
        }
    }

    #[test]
    fn initialize_falls_back_to_latest_for_unknown_version() {
        let params = params_from(json!({
            "protocolVersion": "1999-01-01",
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "1.0" },
        }));
        let result = initialize_result(&params);
        assert_eq!(result["protocolVersion"], LATEST_PROTOCOL_VERSION);
    }

    #[test]
    fn initialize_survives_missing_optional_fields() {
        let params = params_from(json!({}));
        let result = initialize_result(&params);
        assert_eq!(result["protocolVersion"], LATEST_PROTOCOL_VERSION);
        assert_eq!(result["serverInfo"]["name"], "aegis-mcp");
        assert!(result["capabilities"]["tools"].is_object());
        assert!(result["instructions"]
            .as_str()
            .unwrap_or_default()
            .contains("working directory"));
    }

    #[test]
    fn tools_list_has_input_schemas_for_every_tool() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 7);
        for tool in &tools {
            assert!(tool["name"].is_string(), "tool needs a name: {tool}");
            assert!(
                !tool["description"].as_str().unwrap_or_default().is_empty(),
                "tool needs a description: {tool}"
            );
            assert_eq!(
                tool["inputSchema"]["type"], "object",
                "inputSchema must be an object schema: {tool}"
            );
        }
        let names: Vec<_> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        for expected in [
            "scan_string",
            "scan_file",
            "scan_dir",
            "scan_env",
            "list_patterns",
            "list_categories",
            "update_bundle",
        ] {
            assert!(
                names.contains(&expected),
                "missing tool {expected}: {names:?}"
            );
        }
    }

    #[test]
    fn scan_string_schema_requires_content_only() {
        let tools = tool_definitions();
        let scan_string = tools
            .iter()
            .find(|t| t["name"] == "scan_string")
            .expect("scan_string tool exists");
        let required: Vec<_> = scan_string["inputSchema"]["required"]
            .as_array()
            .expect("required array")
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(required, vec!["content"]);
    }

    #[test]
    fn call_tool_result_marks_errors_without_protocol_errors() {
        let ok = call_tool_result("{}", false);
        assert_eq!(ok["isError"], false);
        assert_eq!(ok["content"][0]["type"], "text");
        let failed = call_tool_result("path outside sandbox", true);
        assert_eq!(failed["isError"], true);
    }

    #[tokio::test]
    async fn dispatch_unknown_tool_is_an_error_message() {
        let state = std::sync::Arc::new(crate::ServerState::new());
        let rpc = AegisRpcImpl::new(state);
        let outcome = dispatch_tool(&rpc, "no_such_tool", None).await;
        let message = outcome.expect_err("unknown tool must fail");
        assert!(message.contains("unknown tool"), "{message}");
    }

    #[tokio::test]
    async fn dispatch_scan_string_rejects_missing_content() {
        let state = std::sync::Arc::new(crate::ServerState::new());
        let rpc = AegisRpcImpl::new(state);
        let outcome = dispatch_tool(&rpc, "scan_string", Some(json!({}))).await;
        let message = outcome.expect_err("missing content must fail");
        assert!(message.contains("invalid arguments"), "{message}");
    }

    #[tokio::test]
    async fn dispatch_scan_string_reports_findings() {
        let state = std::sync::Arc::new(crate::ServerState::new());
        let rpc = AegisRpcImpl::new(state);
        // Credential-assignment form: the bare token alone does not clear
        // the string-mode entropy/assignment gates (verified e2e).
        let outcome = dispatch_tool(
            &rpc,
            "scan_string",
            Some(json!({
                "content": "OPENAI_KEY = \"sk-U6JX9JE2SMfjqS8iK9uj9Q\"",
                "source": "fixture",
            })),
        )
        .await;
        let text = outcome.expect("scan_string must succeed");
        let value: Value = serde_json::from_str(&text).expect("text is JSON");
        assert!(
            value["finding_count"].as_u64().unwrap_or(0) > 0,
            "secret fixture must produce findings: {text}"
        );
    }
}
