//! Aegis MCP Server
//!
//! Model Context Protocol server for Aegis security scanning.

mod protocol;
mod sandbox;

use aegis_core::transport::{read_bounded_line, FrameRead, MAX_FRAME_BYTES};
use aegis_core::{Bundle, Config, ScanOptions, ScanReceipt, ScanStats, Scanner};
use jsonrpc_core::{BoxFuture, IoHandler, Result, Value};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::BufReader;
use tokio::sync::RwLock;

/// Maximum concurrently executing JSON-RPC request handlers. Slow or
/// cancelled blocking scans keep their permit until the blocking task exits.
const MAX_IN_FLIGHT_REQUESTS: usize = 32;

/// MCP server state
pub struct ServerState {
    /// Scanner served to every tool call; installed by the lazy pattern
    /// initialization and replaced wholesale by `update_bundle`. Held as
    /// `Arc` so blocking work (synchronous filesystem scans, regex
    /// compilation) can be moved off the async runtime with
    /// `spawn_blocking` while scans still see a consistent snapshot.
    pub scanner: RwLock<Arc<Scanner>>,
    /// Configuration in force for the session, seeded with defaults at
    /// startup.
    ///
    /// The configuration is not merely recorded: the categories, severity
    /// threshold, anomaly detectors, and path classes it names are in
    /// force for the scans that follow. It is written only through
    /// [`ServerState::set_config`], which rebuilds the scanner around it,
    /// so the two are replaced together.
    config: RwLock<Config>,
    /// The bundle installed by `update_bundle`, kept so a configuration
    /// applied later can be built around the same rules instead of
    /// silently falling back to the shipped corpus.
    installed_bundle: RwLock<Option<Bundle>>,
    /// Version of the bundle currently serving scans, `"0.0.0"` until one is
    /// installed.
    pub bundle_version: RwLock<String>,
    /// Checksum of the installed bundle, empty until a bundle is installed.
    pub bundle_checksum: RwLock<String>,
    /// Guards the one-time lazy compilation of the bundled patterns. The
    /// JSON-RPC handshake and tool listing never wait on it; the first
    /// request that needs the scanner does. The memoized outcome keeps a
    /// failed compilation sticky — a scanner that silently holds zero
    /// patterns would approve everything, so requests must keep failing.
    patterns_init: tokio::sync::OnceCell<std::result::Result<(), String>>,
    /// Set by `update_bundle` after it installs a compiled scanner, so the
    /// lazy init is skipped entirely (and cannot clobber the bundle) even
    /// if a previous lazy compilation failed.
    bundle_swapped: AtomicBool,
    /// Serializes the paths that build and install a scanner: the lazy
    /// compilation on first use, `update_bundle`, and
    /// [`ServerState::set_config`]. Without it, a compilation that began
    /// before a configuration was applied would install its scanner
    /// afterwards, silently undoing the change. It is always the outermost
    /// lock, so the paths cannot deadlock.
    apply_lock: tokio::sync::Mutex<()>,
}

impl ServerState {
    /// Build a state with an empty scanner, default configuration, and
    /// placeholder bundle metadata; patterns compile on the first request
    /// that needs them, not here.
    #[must_use]
    pub fn new() -> Self {
        let config = Config::default();
        Self {
            scanner: RwLock::new(Arc::new(Scanner::new())),
            config: RwLock::new(config),
            installed_bundle: RwLock::new(None),
            bundle_version: RwLock::new(String::from("0.0.0")),
            bundle_checksum: RwLock::new(String::new()),
            patterns_init: tokio::sync::OnceCell::const_new(),
            bundle_swapped: AtomicBool::new(false),
            apply_lock: tokio::sync::Mutex::const_new(()),
        }
    }

    /// The configuration in force.
    ///
    /// The configuration that is returned is the one the scanner was built
    /// from, so a caller that reads it after [`Self::set_config`] returns
    /// learns what the server is actually applying.
    #[must_use]
    pub async fn config(&self) -> Config {
        self.config.read().await.clone()
    }

    /// Apply a configuration and rebuild the scanner around it.
    ///
    /// The categories, severity threshold, anomaly detectors, and path
    /// classes the configuration names are in force for the scans that
    /// follow. The rule set stays in force: a configuration says what to
    /// look for, not which rules to ship, so an installed bundle keeps
    /// serving and the shipped corpus is used when no bundle is installed.
    ///
    /// # Errors
    /// Returns a message naming the reason the configuration was rejected
    /// — an unknown category, a path-class rule whose glob does not
    /// compile, a severity threshold no severity name matches, or an
    /// unknown anomaly detector — and leaves the previous configuration and
    /// scanner in place, so a rejected configuration never leaves the
    /// server half-configured.
    pub async fn set_config(&self, config: Config) -> std::result::Result<(), String> {
        // The lock keeps a lazy compilation that is already running from
        // installing its scanner after this one; the configuration that is
        // in force afterwards is the one that was applied here.
        let _guard = self.apply_lock.lock().await;
        let bundle = self.current_bundle().await;
        // Rebuilding the scanner compiles the whole rule set, which is
        // CPU-bound; `spawn_blocking` keeps it off the reactor so other
        // tool calls keep being served while the configuration changes.
        let applied = config.clone();
        let rebuilt = tokio::task::spawn_blocking(move || scanner_for(&bundle, &applied))
            .await
            .map_err(|error| format!("scanner rebuild task failed: {error}"))?;
        let scanner = rebuilt?;
        *self.scanner.write().await = Arc::new(scanner);
        *self.config.write().await = config;
        // The scanner in force is already built from this configuration, so
        // the lazy compilation is marked as done. Without this the first
        // request would compile the whole rule set a second time.
        let _marked = self.patterns_init.set(Ok(()));
        Ok(())
    }

    /// The rule set the server is serving: the installed bundle when one
    /// was installed, the shipped corpus otherwise.
    async fn current_bundle(&self) -> Bundle {
        if let Some(bundle) = self.installed_bundle.read().await.clone() {
            return bundle;
        }
        shipped_bundle()
    }

    /// Compile the bundled patterns on first use instead of at startup.
    ///
    /// Compiling 600+ regexes is CPU-bound; `spawn_blocking` keeps it off
    /// the reactor, and the `OnceCell` makes concurrent first requests
    /// share one compilation. Fails closed: a compilation error surfaces on
    /// every request instead of degrading to a scanner with no patterns.
    ///
    /// The configuration in force when the patterns are compiled is the one
    /// the scanner is built from, and a configuration applied while that
    /// compilation runs waits for it, so the configuration in force is
    /// never overwritten by a scanner built from an earlier one.
    ///
    /// # Errors
    /// Returns `InternalError` when the pattern compilation task fails or
    /// panics, and keeps returning that same error for later requests.
    pub async fn ensure_patterns_loaded(&self) -> Result<()> {
        if self.bundle_swapped.load(Ordering::Acquire) {
            return Ok(());
        }
        self.patterns_init
            .get_or_init(|| async {
                // The lock keeps a configuration applied while this
                // compilation runs from being overwritten by it.
                let _guard = self.apply_lock.lock().await;
                let bundle = self.current_bundle().await;
                let config = self.config.read().await.clone();
                let compiled: std::result::Result<Scanner, String> =
                    match tokio::task::spawn_blocking(move || scanner_for(&bundle, &config)).await {
                        Ok(result) => result,
                        Err(error) => Err(format!("pattern compilation task failed: {error}")),
                    };
                match compiled {
                    Ok(scanner) => {
                        *self.scanner.write().await = Arc::new(scanner);
                        Ok(())
                    }
                    Err(message) => Err(message),
                }
            })
            .await
            .clone()
            .map_err(|message| jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::InternalError,
                message: format!("scanner patterns are unavailable: {message}"),
                data: None,
            })
    }
}

/// The rule set shipped with the binary.
///
/// A configuration says what to look for, not which rules to ship, so the
/// shipped corpus is the rule set unless a bundle is installed on top.
fn shipped_bundle() -> Bundle {
    Bundle::new(
        aegis_patterns::all_patterns()
            .into_iter()
            .map(Into::into)
            .collect(),
    )
}

/// Build a scanner over a rule set with a configuration in force.
///
/// The configuration names the categories to scan, the severity threshold,
/// the anomaly detectors, and the path classes; the bundle stays the rule
/// set, because a configuration says what to look for, not which rules to
/// ship.
///
/// # Errors
///
/// Returns a message naming the reason the configuration was rejected —
/// an unknown category, a path-class rule whose glob does not compile, a
/// severity threshold no severity name matches, or an unknown anomaly
/// detector. The scanner is not built, so a rejected configuration leaves
/// the server serving the configuration it already had.
fn scanner_for(bundle: &Bundle, config: &Config) -> std::result::Result<Scanner, String> {
    // A rule whose glob does not compile classifies nothing, so the
    // configuration is rejected here instead of being applied as a silent
    // no-op: the caller learns that its path class never fired.
    for rule in &config.path_classes {
        rule.validate()?;
    }

    let mut configured = config.clone();
    configured.bundle = bundle.clone();

    let scanner = Scanner::from_config(&configured).map_err(|error| error.to_string())?;

    // `from_config` applies the categories and the path classes; the
    // threshold and the detector selection are scan options, so they are
    // applied here — with the path classes carried over, because the
    // options replace the ones the scanner was built with.
    let options = ScanOptions {
        path_classes: configured.path_classes.clone(),
        severity_threshold: configured.severity_threshold.clone(),
        anomaly_detectors: configured.anomaly_detectors.clone(),
        ..ScanOptions::default()
    };
    // A threshold or a detector name that cannot be honoured would quiet
    // the scan without saying so, so the configuration is rejected instead.
    options.validate()?;
    if let Some(detectors) = &options.anomaly_detectors {
        aegis_core::anomalies::validate_detector_names(detectors)?;
    }

    Ok(scanner.with_options(options))
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}

/// Scan response
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResponse {
    /// Findings that survived the configured filters. Matched source text is
    /// skipped during serialization, so the payload never carries the secret
    /// a rule fired on.
    pub findings: Vec<aegis_core::Finding>,
    /// Count mirroring `findings`, for clients that never inspect the array.
    pub finding_count: usize,
    /// Human-readable risk band derived from the finding set.
    pub risk_level: String,
    /// Numeric score backing `risk_level`.
    pub risk_score: i32,
    /// Coverage and completeness evidence for the scan.
    pub stats: ScanStats,
    /// Redacted provenance receipt for the scan.
    pub receipt: ScanReceipt,
}

impl ScanResponse {
    fn from_parts(
        findings: Vec<aegis_core::Finding>,
        stats: ScanStats,
        source: impl Into<String>,
    ) -> Self {
        let risk_score =
            aegis_core::RiskScore::new(&findings, &HashMap::default(), &HashMap::default());
        let profile = "mcp-default";
        let receipt = ScanReceipt::from_scan(
            source,
            "mcp_scan",
            profile,
            Some(ScanReceipt::digest_text(profile)),
            &findings,
            stats.clone(),
        )
        .with_source_revision(std::env::var("AEGIS_SOURCE_REVISION").ok());
        Self {
            finding_count: findings.len(),
            risk_level: risk_score.level.to_string(),
            risk_score: risk_score.score,
            findings,
            stats,
            receipt,
        }
    }

    fn for_string(findings: Vec<aegis_core::Finding>, source: &str, bytes: usize) -> Self {
        Self::from_parts(
            findings,
            ScanStats::for_content(format!("string:{source}"), bytes),
            format!("string:{source}"),
        )
    }

    fn for_environment(findings: Vec<aegis_core::Finding>) -> Self {
        Self::from_parts(findings, ScanStats::for_environment(), "environment")
    }
}

/// List patterns response
#[derive(Debug, Serialize, Deserialize)]
pub struct ListPatternsResponse {
    /// Patterns matching the requested category filter, if one was given.
    pub patterns: Vec<PatternInfo>,
    /// Number of entries returned, mirroring `patterns`.
    pub total: usize,
}

/// Pattern info
#[derive(Debug, Serialize, Deserialize)]
pub struct PatternInfo {
    /// Registry identifier clients pass to `enable` or `disable`.
    pub name: String,
    /// Category bucket the pattern belongs to.
    pub category: String,
    /// Severity label, from `critical` down to `low`.
    pub severity: String,
    /// How strongly the pattern is trusted to be a true positive.
    pub confidence: String,
    /// One-line explanation surfaced to the end user.
    pub description: String,
}

/// Update response
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateResponse {
    /// Whether the newly installed bundle is now serving scans.
    pub success: bool,
    /// Human-readable summary for the caller's logs.
    pub message: String,
    /// Number of patterns the installed bundle carries.
    pub pattern_count: usize,
}

/// Aegis RPC implementation
pub struct AegisRpcImpl {
    state: Arc<ServerState>,
}

impl AegisRpcImpl {
    /// Bind the JSON-RPC dispatcher to the shared server state.
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

impl AegisRpcImpl {
    fn scan_string(&self, content: String, source: String) -> BoxFuture<Result<ScanResponse>> {
        let state = self.state.clone();
        Box::pin(async move {
            state.ensure_patterns_loaded().await?;
            let scanner = Arc::clone(&state.scanner.read().await);
            let bytes = content.len();
            let spawned = tokio::task::spawn_blocking(move || {
                let findings = scanner.scan_string(&content, &source);
                ScanResponse::for_string(findings, &source, bytes)
            })
            .await;
            spawn_blocking_result(spawned, "string scan failed")
        })
    }

    fn scan_file(&self, path: String) -> BoxFuture<Result<ScanResponse>> {
        let state = self.state.clone();
        Box::pin(async move {
            let path = PathBuf::from(&path);

            // Security: validate path
            if !sandbox::is_path_safe(&path) {
                return Err(jsonrpc_core::Error {
                    code: jsonrpc_core::ErrorCode::InvalidParams,
                    message: "Path is outside allowed directory".to_string(),
                    data: None,
                });
            }

            state.ensure_patterns_loaded().await?;
            // The scanner does synchronous filesystem IO and regex work
            // over every file; run it off the async runtime so one heavy
            // scan cannot stall request handling or the transport loop.
            let scanner = Arc::clone(&*state.scanner.read().await);
            let path_display = path.to_string_lossy().to_string();
            let spawned = tokio::task::spawn_blocking(move || scanner.scan_file(&path)).await;
            let (findings, scan_stats) = spawn_blocking_result(spawned, "file scan failed")?;

            Ok(ScanResponse::from_parts(findings, scan_stats, path_display))
        })
    }

    fn scan_dir(&self, path: String) -> BoxFuture<Result<ScanResponse>> {
        let state = self.state.clone();
        Box::pin(async move {
            let path = PathBuf::from(&path);

            // Security: validate path
            if !sandbox::is_path_safe(&path) {
                return Err(jsonrpc_core::Error {
                    code: jsonrpc_core::ErrorCode::InvalidParams,
                    message: "Path is outside allowed directory".to_string(),
                    data: None,
                });
            }

            state.ensure_patterns_loaded().await?;
            // See scan_file: directory scans walk the filesystem
            // synchronously (plus a rayon parallel pass), so they must
            // not run on the async reactor.
            let scanner = Arc::clone(&*state.scanner.read().await);
            let path_display = path.to_string_lossy().to_string();
            let spawned = tokio::task::spawn_blocking(move || scanner.scan_dir(&path)).await;
            let (findings, scan_stats) = spawn_blocking_result(spawned, "directory scan failed")?;

            Ok(ScanResponse::from_parts(findings, scan_stats, path_display))
        })
    }

    fn scan_env(&self) -> BoxFuture<Result<ScanResponse>> {
        let state = self.state.clone();
        Box::pin(async move {
            state.ensure_patterns_loaded().await?;
            let scanner = Arc::clone(&state.scanner.read().await);
            let spawned = tokio::task::spawn_blocking(move || {
                let findings = scanner.scan_env();
                ScanResponse::for_environment(findings)
            })
            .await;
            spawn_blocking_result(spawned, "environment scan failed")
        })
    }

    fn list_patterns(&self, category: Option<String>) -> BoxFuture<Result<ListPatternsResponse>> {
        let state = self.state.clone();
        Box::pin(async move {
            state.ensure_patterns_loaded().await?;
            let scanner = state.scanner.read().await;
            let registry = scanner.registry();

            let patterns = if let Some(cat) = category {
                registry.by_category(&cat)
            } else {
                registry.all()
            };

            let pattern_infos: Vec<PatternInfo> = patterns
                .iter()
                .map(|p| PatternInfo {
                    name: p.name().to_string(),
                    category: p.category().to_string(),
                    severity: p.severity().to_string(),
                    confidence: p.confidence().to_string(),
                    description: p.description().to_string(),
                })
                .collect();

            Ok(ListPatternsResponse {
                total: pattern_infos.len(),
                patterns: pattern_infos,
            })
        })
    }

    fn list_categories(&self) -> BoxFuture<Result<Vec<String>>> {
        let state = self.state.clone();
        Box::pin(async move {
            state.ensure_patterns_loaded().await?;
            let scanner = state.scanner.read().await;
            let registry = scanner.registry();
            Ok(registry.categories())
        })
    }

    fn update_bundle(
        &self,
        bundle_path: Option<String>,
        _force: bool,
    ) -> BoxFuture<Result<UpdateResponse>> {
        let state = self.state.clone();
        Box::pin(async move {
            // Sandbox-validate the requested path before deferring to a
            // blocking task; rejections must stay `InvalidParams`.
            let validated = match &bundle_path {
                Some(path) => {
                    let path = PathBuf::from(path);
                    if !sandbox::is_path_safe(&path) {
                        return Err(invalid_params("Path is outside allowed directory"));
                    }
                    Some(path)
                }
                None => None,
            };
            // Keep scanner builds serialized with configuration changes and
            // first-use initialization, but do I/O and regex compilation on
            // a blocking worker so this request cannot stall the reactor.
            let _guard = state.apply_lock.lock().await;
            let config = state.config.read().await.clone();
            let prepared =
                tokio::task::spawn_blocking(move || prepare_bundle(validated, config)).await;
            let bundle = spawn_blocking_result(prepared, "bundle update failed")?;

            // Update state. The swap flag makes later `ensure_patterns_loaded`
            // calls no-ops so they cannot overwrite this bundle, and it also
            // clears a previously failed lazy compilation.
            {
                let mut scanner = state.scanner.write().await;
                *scanner = Arc::new(bundle.scanner);
            }
            // Keep the installed bundle, so a configuration applied later
            // is built around the same rules instead of silently falling
            // back to the shipped corpus.
            {
                let mut installed = state.installed_bundle.write().await;
                *installed = Some(bundle.bundle.clone());
            }
            state.bundle_swapped.store(true, Ordering::Release);
            {
                let mut version = state.bundle_version.write().await;
                *version = bundle.version;
            }
            {
                let mut checksum = state.bundle_checksum.write().await;
                *checksum = bundle.checksum;
            }

            Ok(UpdateResponse {
                success: true,
                message: format!("Bundle updated with {} patterns", bundle.pattern_count),
                pattern_count: bundle.pattern_count,
            })
        })
    }
}

/// The operator configuration file the server applies at startup.
///
/// The configuration is operator-side on purpose: a client of the server
/// must not be able to change it, because a client that could set the
/// severity threshold or the category list could weaken the scan it was
/// asked for.
const CONFIG_ENV: &str = "AEGIS_MCP_CONFIG";

/// The operator configuration file to apply, when one is named.
///
/// An empty value is refused rather than treated as "no configuration": a
/// deployment that meant to configure the server and named nothing would
/// otherwise run with the default configuration and say nothing.
fn operator_config_path() -> anyhow::Result<Option<PathBuf>> {
    match std::env::var_os(CONFIG_ENV) {
        Some(value) if !value.is_empty() => Ok(Some(PathBuf::from(value))),
        Some(_) => Err(anyhow::anyhow!("{CONFIG_ENV} cannot be empty")),
        None => Ok(None),
    }
}

/// Outcome of building and compiling a bundle on a blocking task.
struct PreparedBundle {
    bundle: Bundle,
    scanner: Scanner,
    version: String,
    checksum: String,
    pattern_count: usize,
}

/// Load (or rebuild from embedded patterns), validate, and compile a
/// bundle. All resource-heavy steps stay on the caller's blocking task.
fn prepare_bundle(
    path: Option<PathBuf>,
    config: Config,
) -> std::result::Result<PreparedBundle, String> {
    let bundle = if let Some(path) = path {
        Bundle::load(&path).map_err(|e| format!("Failed to load bundle: {e}"))?
    } else {
        // Use embedded patterns from the aegis-patterns crate.
        let patterns = aegis_patterns::all_patterns()
            .into_iter()
            .map(Into::into)
            .collect();
        Bundle::new(patterns)
    };
    bundle
        .validate()
        .map_err(|e| format!("Invalid bundle: {e}"))?;
    let scanner = scanner_for(&bundle, &config)?;
    let pattern_count = bundle.len();
    let version = bundle.metadata().version.to_string();
    let checksum = bundle.metadata().checksum;
    Ok(PreparedBundle {
        bundle,
        pattern_count,
        version,
        checksum,
        scanner,
    })
}

/// Initialize scanner with patterns from aegis-patterns
///
/// The server builds its scanner through [`scanner_for`], so this shortcut
/// exists for the tests that need a scanner without a configuration.
#[cfg(test)]
fn init_scanner() -> anyhow::Result<Scanner> {
    scanner_for(&shipped_bundle(), &Config::default()).map_err(anyhow::Error::msg)
}

fn invalid_params<T: std::fmt::Display>(error: T) -> jsonrpc_core::Error {
    jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::InvalidParams,
        message: error.to_string(),
        data: None,
    }
}

fn internal_error<T: std::fmt::Display>(message: T) -> jsonrpc_core::Error {
    jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::InternalError,
        message: message.to_string(),
        data: None,
    }
}

/// Resolve a `spawn_blocking` task result into the JSON-RPC result or an
/// `InternalError`; a panicked blocking task is reported like any other
/// failure instead of unwinding into the transport.
fn spawn_blocking_result<T, E: std::fmt::Display>(
    spawned: std::result::Result<std::result::Result<T, E>, tokio::task::JoinError>,
    context: &str,
) -> Result<T> {
    match spawned {
        Ok(value) => value.map_err(|error| internal_error(format!("{context}: {error}"))),
        Err(join) => Err(internal_error(format!("{context}: task failed: {join}"))),
    }
}

fn serialize_result<T: Serialize>(value: T) -> Result<Value> {
    serde_json::to_value(value).map_err(|error| jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::InternalError,
        message: format!("Failed to serialize response: {error}"),
        data: None,
    })
}

fn parse_params<T: DeserializeOwned>(params: jsonrpc_core::Params) -> Result<T> {
    params.parse().map_err(invalid_params)
}

fn parse_no_params(params: jsonrpc_core::Params) -> Result<()> {
    match params {
        jsonrpc_core::Params::None => Ok(()),
        jsonrpc_core::Params::Array(values) if values.is_empty() => Ok(()),
        _ => Err(invalid_params("expected no parameters")),
    }
}

fn parse_required_string_param(params: jsonrpc_core::Params) -> Result<String> {
    match params {
        jsonrpc_core::Params::Array(mut values) if values.len() == 1 => {
            let value = values
                .pop()
                .ok_or_else(|| invalid_params("expected exactly one parameter"))?;
            serde_json::from_value(value).map_err(invalid_params)
        }
        _ => Err(invalid_params(
            "expected exactly one string parameter: [\"/path/to/scan/target\"]",
        )),
    }
}

fn parse_optional_string_param(params: jsonrpc_core::Params) -> Result<Option<String>> {
    match params {
        jsonrpc_core::Params::None => Ok(None),
        jsonrpc_core::Params::Array(mut values) if values.len() <= 1 => values
            .pop()
            .map(|value| serde_json::from_value(value).map_err(invalid_params))
            .transpose(),
        _ => Err(invalid_params("expected zero or one string parameter")),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Route tracing output to stderr so it cannot corrupt the stdout JSON-RPC stream.
    // use try_init: multiple initializations in tests are silent no-ops.
    let _log_init = tracing_subscriber::fmt()
        .with_env_filter("aegis=info")
        .with_writer(std::io::stderr)
        .try_init();

    // `--version` exists so clients (and people) can detect a stale
    // install of this binary, which is how mixed-method MCP servers
    // surface as `-32601` storms from real clients.
    if let Some(arg) = std::env::args().nth(1) {
        if arg == "--version" || arg == "-V" {
            println!("aegis-mcp {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        anyhow::bail!(
            "aegis-mcp takes no arguments (it serves MCP over stdio); --version prints the build"
        );
    }

    serve().await
}

/// Frames flowing to the writer task: either a response produced before
/// any task had to run (parse/protocol errors), or the spawned task whose
/// completion yields the response.
enum Incoming {
    Ready(String),
    Task(tokio::task::JoinHandle<Option<String>>),
}

/// Wire up the JSON-RPC surface and run the stdio transport until EOF or
/// transport failure.
async fn serve() -> anyhow::Result<()> {
    let state = Arc::new(ServerState::new());

    // An operator configuration is applied before the server answers, so a
    // configuration that cannot be applied stops the server instead of
    // leaving it serving scans it was not configured for.
    if let Some(path) = operator_config_path()? {
        let config = Config::load(&path)?;
        state.set_config(config).await.map_err(anyhow::Error::msg)?;
    }

    // Patterns compile lazily on the first request that needs them (see
    // `ServerState::ensure_patterns_loaded`); startup only wires the
    // JSON-RPC machinery so the handshake answers immediately.

    let rpc = Arc::new(AegisRpcImpl::new(state.clone()));
    let mut io = IoHandler::new();

    let handler = rpc.clone();
    io.add_method("scan_string", move |params| {
        let handler = handler.clone();
        async move {
            let (content, source) = parse_params(params)?;
            serialize_result(handler.scan_string(content, source).await?)
        }
    });
    let handler = rpc.clone();
    io.add_method("scan_file", move |params| {
        let handler = handler.clone();
        async move {
            let path = parse_required_string_param(params)?;
            serialize_result(handler.scan_file(path).await?)
        }
    });
    let handler = rpc.clone();
    io.add_method("scan_dir", move |params| {
        let handler = handler.clone();
        async move {
            let path = parse_required_string_param(params)?;
            serialize_result(handler.scan_dir(path).await?)
        }
    });
    let handler = rpc.clone();
    io.add_method("scan_env", move |params| {
        let handler = handler.clone();
        async move {
            parse_no_params(params)?;
            serialize_result(handler.scan_env().await?)
        }
    });
    let handler = rpc.clone();
    io.add_method("list_patterns", move |params| {
        let handler = handler.clone();
        async move {
            let category = parse_optional_string_param(params)?;
            serialize_result(handler.list_patterns(category).await?)
        }
    });
    let handler = rpc.clone();
    io.add_method("list_categories", move |params| {
        let handler = handler.clone();
        async move {
            parse_no_params(params)?;
            serialize_result(handler.list_categories().await?)
        }
    });
    let handler = rpc.clone();
    io.add_method("update_bundle", move |params| {
        let handler = handler.clone();
        async move {
            let (bundle_path, force) = parse_params(params)?;
            serialize_result(handler.update_bundle(bundle_path, force).await?)
        }
    });

    // MCP lifecycle and discovery (`initialize`, `tools/list`,
    // `tools/call`, `ping`) so generic MCP clients can negotiate a
    // session and find the tools; `tools/call` dispatches to the same
    // implementations as the custom methods above, so the two surfaces
    // stay behaviourally identical.
    let cancellations = protocol::new_cancellation_registry();
    protocol::register(&mut io, rpc.clone(), cancellations.clone());

    // stdout is the JSON-RPC transport; startup diagnostics must not corrupt
    // the protocol stream consumed by MCP clients.
    eprintln!(
        "Aegis MCP Server {} starting (protocol versions: {})",
        env!("CARGO_PKG_VERSION"),
        protocol::SUPPORTED_PROTOCOL_VERSIONS.join(", ")
    );
    eprintln!("Listening on stdin/stdout");

    let tool_timeout = protocol::tool_timeout();
    let io = Arc::new(io);

    let reader = BufReader::new(tokio::io::stdin());
    let writer = tokio::io::BufWriter::new(tokio::io::stdout());
    let (tx, rx) = tokio::sync::mpsc::channel::<Incoming>(MAX_IN_FLIGHT_REQUESTS * 2);

    // One task reads and dispatches; one writes responses. Requests are
    // processed by spawned tasks, so a long scan cannot stall another
    // request (e.g. `ping`) the way sequential handlers did.
    let mut reader_task = tokio::spawn(read_frames(
        reader,
        io,
        cancellations,
        tool_timeout,
        Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT_REQUESTS)),
        tx,
    ));
    let mut writer_task = tokio::spawn(write_frames(writer, rx));

    // Normal flow: stdin hits EOF, the reader drops its sender, the writer
    // drains the remaining responses and ends. If either side dies early
    // (broken stdout, decode failure, panic), the other is stopped.
    // Whoever ends first decides the outcome: the reader finishing (EOF)
    // lets the writer drain and exit on its own; a writer failure means
    // the transport is dead, so the reader must not keep waiting on a
    // client stdin that may never close.
    let outcome = tokio::select! {
        // Polling through `&mut` keeps both handles owned here so the
        // non-selected side can still be drained or aborted below.
        reader = &mut reader_task => {
            let reader_result = reader
                .map_err(|join| anyhow::anyhow!("reader task failed: {join}"))
                .and_then(std::convert::identity);
            // Normal flow: the writer drains remaining responses and ends.
            let writer_result = writer_task
                .await
                .map_err(|join| anyhow::anyhow!("writer task failed: {join}"))
                .and_then(std::convert::identity);
            writer_result.and(reader_result)
        }
        writer = &mut writer_task => {
            reader_task.abort();
            writer
                .map_err(|join| anyhow::anyhow!("writer task failed: {join}"))
                .and_then(std::convert::identity)
        }
    };
    outcome
}

async fn read_frames<R>(
    mut reader: R,
    io: Arc<IoHandler>,
    cancellations: protocol::CancelRegistry,
    tool_timeout: Option<std::time::Duration>,
    requests: Arc<tokio::sync::Semaphore>,
    tx: tokio::sync::mpsc::Sender<Incoming>,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut line = String::new();
    loop {
        match read_bounded_line(&mut reader, MAX_FRAME_BYTES, &mut line).await {
            Ok(FrameRead::Line) => {}
            Ok(FrameRead::Eof) | Err(_) => return Ok(()),
            Ok(FrameRead::Oversize) => {
                // The rest of the oversized line is still unread and
                // unknowable, so framing cannot resume: answer once with a
                // request error, then end the session.
                return send_frame(
                    &tx,
                    Incoming::Ready(protocol_error_frame(
                        &Value::Null,
                        -32600,
                        format!("request frame exceeds maximum size ({MAX_FRAME_BYTES} bytes)")
                            .as_str(),
                    )),
                )
                .await;
            }
        }

        if line.trim().is_empty() {
            continue;
        }

        // Parse request
        let request: Value = match serde_json::from_str(line.trim()) {
            Ok(request) => request,
            Err(error) => {
                let response = protocol_error_frame(
                    &Value::Null,
                    -32700,
                    format!("Parse error: {error}").as_str(),
                );
                send_frame(&tx, Incoming::Ready(response)).await?;
                continue;
            }
        };

        // MCP stdio carries one message per line; JSON-RPC batch arrays
        // are not part of MCP 2025-03-26+ and can only confuse clients
        // that never asked for them.
        if request.is_array() {
            send_frame(
                &tx,
                Incoming::Ready(protocol_error_frame(
                    &Value::Null,
                    -32600,
                    "batched JSON-RPC requests are not supported: one message per line",
                )),
            )
            .await?;
            continue;
        }

        let is_cancel_notification =
            request.get("method").and_then(Value::as_str) == Some("notifications/cancelled");
        let permit = if is_cancel_notification {
            // Cancellation must remain serviceable when the scan slots are
            // saturated; its handler only wakes a waiter and does no scan.
            None
        } else {
            match requests.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    if let Some(id) = request.get("id") {
                        send_frame(
                            &tx,
                            Incoming::Ready(protocol_error_frame(
                                id,
                                -32001,
                                "server is at its concurrent request limit; retry later",
                            )),
                        )
                        .await?;
                    }
                    continue;
                }
            }
        };

        // Track cancellation by the serialized id. Notifications carry no
        // id and therefore nothing to cancel; `initialize` is tracked too
        // (the spec forbids clients from cancelling it, which is the
        // client side of the contract — a stray cancel is simply ignored
        // server-side).
        let cancel_state = request
            .get("id")
            .map(|id| protocol::track_request(&cancellations, id));

        let io = io.clone();
        let cancellations = cancellations.clone();
        let request_id = request.get("id").cloned();
        let line = line.trim().to_owned();
        // The worker owns the admission permit. If the client cancels or
        // times out, dropping its JoinHandle detaches this worker, so the
        // permit still bounds blocking work until that work actually ends.
        let work = tokio::spawn(async move {
            let _permit = permit;
            io.handle_request(&line).await
        });
        let handle = tokio::spawn(async move {
            // Notifications carry no id: they get no cancellation handle
            // (nothing to cancel) and no timeout frame (their handlers
            // run to completion synchronously inside jsonrpc-core).
            let outcome = run_request(work, cancel_state, request_id.clone(), tool_timeout).await;
            if let Some(request_id) = &request_id {
                protocol::untrack_request(&cancellations, request_id);
            }
            outcome
        });

        send_frame(&tx, Incoming::Task(handle)).await?;
    }
}

/// Execute one request or notification. Cancellation and timeout stop
/// waiting for the response; already-running blocking work continues under
/// its admission permit until it finishes. Cancelled requests emit no
/// response, and every request is walled by [`protocol::tool_timeout`].
async fn run_request(
    mut work: tokio::task::JoinHandle<Option<String>>,
    cancel_state: Option<Arc<protocol::CancelState>>,
    request_id: Option<Value>,
    tool_timeout: Option<std::time::Duration>,
) -> Option<String> {
    let raced = async {
        match &cancel_state {
            Some(cancel_state) => {
                tokio::select! {
                    response = &mut work => Some(response),
                    // Cancellation wins the race against the work; the
                    // client was told to ignore a late response anyway.
                    () = cancel_state.cancelled() => None,
                }
            }
            None => Some(work.await),
        }
    };
    let completed = match tool_timeout {
        Some(duration) => match tokio::time::timeout(duration, raced).await {
            Ok(response) => response,
            Err(_elapsed) => {
                return request_id.as_ref().map(|request_id| {
                    timeout_frame(request_id, duration.as_millis().to_string().as_str())
                });
            }
        },
        None => raced.await,
    };
    match completed {
        Some(Ok(response)) => response,
        Some(Err(_join)) => request_id
            .as_ref()
            .map(|id| protocol_error_frame(id, -32603, "request handler failed")),
        None => None,
    }
}

/// Build one JSON-RPC error frame with an explicit numeric code; used for
/// the transport-level rejections that never reach jsonrpc-core.
fn protocol_error_frame(id: &Value, code: i64, message: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "error": { "code": code, "message": message },
        "id": id
    })
    .to_string()
}

/// Frame for a request that outlived [`protocol::tool_timeout`]. The
/// request id is echoed so the client can correlate it.
fn timeout_frame(request_id: &Value, timeout: &str) -> String {
    protocol_error_frame(
        request_id,
        -32000,
        format!(
            "request took longer than the tool timeout ({timeout}); set \
             AEGIS_MCP_TOOL_TIMEOUT_MS=0 or a higher value for longer scans"
        )
        .as_str(),
    )
}

/// Deliver frames to the writer as request tasks complete, in completion
/// order — the same behaviour as the reference MCP server SDK. Clients
/// correlate responses by request id, and the 2025-06-18 stdio transport
/// imposes no ordering requirement, so a slow scan never delays an
/// in-flight `ping`.
async fn write_frames<W>(
    mut writer: W,
    mut rx: tokio::sync::mpsc::Receiver<Incoming>,
) -> anyhow::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use jsonrpc_core::futures::stream::{FuturesUnordered, StreamExt};

    let mut pending: FuturesUnordered<tokio::task::JoinHandle<Option<String>>> =
        FuturesUnordered::new();
    loop {
        tokio::select! {
            done = pending.next(), if !pending.is_empty() => match done {
                Some(Ok(Some(response))) => write_response(&mut writer, &response).await?,
                // Cancelled or otherwise silent request: no frame.
                Some(Ok(None)) => {}
                Some(Err(join)) => return Err(anyhow::anyhow!("request task failed: {join}")),
                // Unreachable while the guard keeps this arm off an empty
                // stream, but the match must know it ends.
                None => return Ok(()),
            },
            incoming = rx.recv() => match incoming {
                Some(Incoming::Ready(response)) => write_response(&mut writer, &response).await?,
                Some(Incoming::Task(handle)) => pending.push(handle),
                // Reader ended (stdin EOF); drain responses still queued.
                None => {
                    while let Some(done) = pending.next().await {
                        match done {
                            Ok(Some(response)) => write_response(&mut writer, &response).await?,
                            Ok(None) => {}
                            Err(join) => {
                                return Err(anyhow::anyhow!("request task failed: {join}"))
                            }
                        }
                    }
                    return Ok(());
                }
            },
        }
    }
}

async fn send_frame(
    tx: &tokio::sync::mpsc::Sender<Incoming>,
    frame: Incoming,
) -> anyhow::Result<()> {
    tx.send(frame)
        .await
        .map_err(|_| anyhow::anyhow!("writer has ended; session over"))
}

/// Write one newline-terminated JSON-RPC frame and flush.
///
/// # Errors
/// Returns an error when the transport write or flush fails (client
/// disconnected); callers end the session rather than loop on a dead pipe.
async fn write_response<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    response: &str,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    writer.write_all(response.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_scanner_has_patterns() {
        let scanner = init_scanner().expect("bundled patterns compile");
        let registry = scanner.registry();
        let patterns = registry.all();
        assert!(!patterns.is_empty(), "Scanner should have patterns loaded");
    }

    #[test]
    fn test_server_state_new() {
        let state = ServerState::new();
        assert!(state.scanner.try_read().is_ok());
        assert!(state.config.try_read().is_ok());
    }

    #[test]
    fn test_server_state_default() {
        let state = ServerState::default();
        assert!(state.scanner.try_read().is_ok());
    }

    #[tokio::test]
    async fn test_server_state_with_scanner() {
        let state = Arc::new(ServerState::new());
        {
            let mut scanner = state.scanner.write().await;
            *scanner = Arc::new(init_scanner().expect("bundled patterns compile"));
        }
        let scanner = state.scanner.read().await;
        let registry = scanner.registry();
        assert!(!registry.all().is_empty());
    }

    #[test]
    fn test_scan_response_serialization() {
        let response = ScanResponse {
            findings: vec![],
            finding_count: 0,
            risk_level: "none".to_string(),
            risk_score: 0,
            stats: ScanStats::default(),
            receipt: ScanReceipt::from_scan(
                "test",
                "test",
                "test",
                None,
                &[],
                ScanStats::default(),
            ),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("finding_count"));
        assert!(json.contains("risk_level"));
        assert!(json.contains("inspection_ledger"));
        assert!(json.contains("receipt_id"));
    }

    #[test]
    fn test_scan_response_records_string_coverage() {
        let response = ScanResponse::for_string(vec![], "fixture.rs", 12);
        assert_eq!(response.stats.files_scanned, 1);
        assert_eq!(response.stats.bytes_scanned, 12);
        assert!(response.stats.inspection_ledger.allows_safe());
        assert_eq!(
            response.stats.inspection_ledger.units[0].status,
            aegis_core::InspectionStatus::Analyzed
        );
    }

    #[test]
    fn test_list_patterns_response_serialization() {
        let response = ListPatternsResponse {
            patterns: vec![PatternInfo {
                name: "test".to_string(),
                category: "secrets".to_string(),
                severity: "high".to_string(),
                confidence: "high".to_string(),
                description: "Test pattern".to_string(),
            }],
            total: 1,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("total"));
        assert!(json.contains("patterns"));
    }

    #[test]
    fn test_update_response_serialization() {
        let response = UpdateResponse {
            success: true,
            message: "Updated".to_string(),
            pattern_count: 100,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("success"));
        assert!(json.contains("pattern_count"));
    }

    #[test]
    fn test_aegis_rpc_impl_new() {
        let state = Arc::new(ServerState::new());
        let _rpc = AegisRpcImpl::new(state);
    }

    #[tokio::test]
    async fn test_scan_string_empty() {
        let state = Arc::new(ServerState::new());
        {
            let mut scanner = state.scanner.write().await;
            *scanner = Arc::new(init_scanner().expect("bundled patterns compile"));
        }
        let rpc = AegisRpcImpl::new(state);
        let result = rpc.scan_string(String::new(), "test.txt".to_string()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.finding_count, 0);
    }

    #[tokio::test]
    async fn test_scan_string_with_secret() {
        let state = Arc::new(ServerState::new());
        {
            let mut scanner = state.scanner.write().await;
            *scanner = Arc::new(init_scanner().expect("bundled patterns compile"));
        }
        let rpc = AegisRpcImpl::new(state);
        let result = rpc
            // AWS docs example key; directive shares the flagged line.
            .scan_string("AKIAIOSFODNN7EXAMPLE".to_string(), "test.txt".to_string()) // aegis:ignore:aws-access-key
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.finding_count > 0, "Should detect AWS key");
    }

    #[tokio::test]
    async fn test_scan_env() {
        let state = Arc::new(ServerState::new());
        {
            let mut scanner = state.scanner.write().await;
            *scanner = Arc::new(init_scanner().expect("bundled patterns compile"));
        }
        let rpc = AegisRpcImpl::new(state);
        let result = rpc.scan_env().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_patterns() {
        let state = Arc::new(ServerState::new());
        {
            let mut scanner = state.scanner.write().await;
            *scanner = Arc::new(init_scanner().expect("bundled patterns compile"));
        }
        let rpc = AegisRpcImpl::new(state);
        let result = rpc.list_patterns(None).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.total > 0);
    }

    #[tokio::test]
    async fn test_list_patterns_by_category() {
        let state = Arc::new(ServerState::new());
        {
            let mut scanner = state.scanner.write().await;
            *scanner = Arc::new(init_scanner().expect("bundled patterns compile"));
        }
        let rpc = AegisRpcImpl::new(state);
        let result = rpc.list_patterns(Some("secrets".to_string())).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.total > 0);
    }

    #[tokio::test]
    async fn test_list_categories() {
        let state = Arc::new(ServerState::new());
        {
            let mut scanner = state.scanner.write().await;
            *scanner = Arc::new(init_scanner().expect("bundled patterns compile"));
        }
        let rpc = AegisRpcImpl::new(state);
        let result = rpc.list_categories().await;
        assert!(result.is_ok());
        let categories = result.unwrap();
        assert_ne!(categories, [] as [String; 0]);
    }

    async fn ready_state() -> Arc<ServerState> {
        let state = Arc::new(ServerState::new());
        {
            let mut scanner = state.scanner.write().await;
            *scanner = Arc::new(init_scanner().expect("bundled patterns compile"));
        }
        state
    }

    #[tokio::test]
    async fn scan_file_outside_sandbox_is_rejected() {
        let rpc = AegisRpcImpl::new(ready_state().await);
        // /etc/passwd is outside the sandbox cwd.
        let error = rpc
            .scan_file("/etc/passwd".to_string())
            .await
            .expect_err("sandbox must refuse absolute paths outside cwd");
        assert_eq!(error.code, jsonrpc_core::ErrorCode::InvalidParams);
    }

    #[tokio::test]
    async fn scan_dir_outside_sandbox_is_rejected() {
        let rpc = AegisRpcImpl::new(ready_state().await);
        let error = rpc
            .scan_dir("/etc".to_string())
            .await
            .expect_err("sandbox must refuse directories outside cwd");
        assert_eq!(error.code, jsonrpc_core::ErrorCode::InvalidParams);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn scan_file_via_symlink_escape_is_rejected() {
        // A symlink inside the sandbox cwd pointing at an existing file
        // outside it: the guard canonicalizes the resolved target, so the
        // call must fail as a sandbox violation (InvalidParams), not as an
        // ordinary scan error.
        // TempDir-owned fixtures, uniquely named per run: the link lives
        // inside cwd so containment applies, the probed target lives
        // outside it (the parent of cwd). RAII removes both.
        let cwd = std::env::current_dir()
            .expect("read cwd")
            .canonicalize()
            .expect("canonicalize cwd");
        let outside = tempfile::tempdir_in(cwd.parent().expect("cwd has a parent"))
            .expect("create outside temp dir");
        let target = outside.path().join("target.txt");
        std::fs::write(&target, "probe fixture").expect("write target");

        let fixture_dir = tempfile::tempdir_in(&cwd).expect("create fixture temp dir");
        let link = fixture_dir.path().join("leak-link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink target");

        let rpc = AegisRpcImpl::new(ready_state().await);
        let error = rpc.scan_file(link.to_string_lossy().into_owned()).await;

        let error = error.expect_err("sandbox must refuse symlinked targets outside cwd");
        assert_eq!(error.code, jsonrpc_core::ErrorCode::InvalidParams);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn scan_dir_via_symlink_escape_is_rejected() {
        // Same invariant for directory scans: a symlinked directory inside
        // cwd that resolves outside must be refused before any walking.
        let cwd = std::env::current_dir()
            .expect("read cwd")
            .canonicalize()
            .expect("canonicalize cwd");
        let outside = tempfile::tempdir_in(cwd.parent().expect("cwd has a parent"))
            .expect("create outside temp dir");
        std::fs::write(outside.path().join("target.txt"), "probe fixture").expect("write target");

        let fixture_dir = tempfile::tempdir_in(&cwd).expect("create fixture temp dir");
        let link = fixture_dir.path().join("leak-dir");
        std::os::unix::fs::symlink(outside.path(), &link).expect("symlink dir");

        let rpc = AegisRpcImpl::new(ready_state().await);
        let error = rpc
            .scan_dir(link.to_string_lossy().into_owned())
            .await
            .expect_err("sandbox must refuse symlinked directories outside cwd");

        assert_eq!(error.code, jsonrpc_core::ErrorCode::InvalidParams);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn update_bundle_via_symlink_escape_is_rejected() {
        // Same invariant for bundle updates: a symlink inside cwd that
        // resolves to an existing file outside must be refused by the guard
        // before `Bundle::load` is ever reached — InvalidParams (sandbox),
        // not InternalError (load failure). The target deliberately is not
        // a valid bundle, so dropping the guard would flip this test's
        // error code.
        // TempDir-owned fixtures, uniquely named per run: the link lives
        // inside cwd so containment applies, the probed target lives
        // outside it (the parent of cwd). RAII removes both.
        let cwd = std::env::current_dir()
            .expect("read cwd")
            .canonicalize()
            .expect("canonicalize cwd");
        let outside = tempfile::tempdir_in(cwd.parent().expect("cwd has a parent"))
            .expect("create outside temp dir");
        let target = outside.path().join("target-bundle.txt");
        std::fs::write(&target, "probe fixture").expect("write target");

        let fixture_dir = tempfile::tempdir_in(&cwd).expect("create fixture temp dir");
        let link = fixture_dir.path().join("leak-bundle-link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink target");

        let rpc = AegisRpcImpl::new(ready_state().await);
        let error = rpc
            .update_bundle(Some(link.to_string_lossy().into_owned()), false)
            .await
            .expect_err("sandbox must refuse symlinked bundle paths outside cwd");

        assert_eq!(error.code, jsonrpc_core::ErrorCode::InvalidParams);
    }

    #[tokio::test]
    async fn scan_file_inside_cwd_reports_findings_and_stats() {
        let rpc = AegisRpcImpl::new(ready_state().await);

        // `temp/` is inside the sandbox cwd and gitignored.
        let fixture_dir = PathBuf::from("temp/mcp-fixtures");
        std::fs::create_dir_all(&fixture_dir).expect("create fixture dir");
        std::fs::write(
            fixture_dir.join("leak.txt"),
            concat!("token = \"ghp_", "0123456789abcdefghijklmnopqrstuvwxyzAB\""),
        )
        .expect("write fixture");

        let result = rpc
            .scan_file("temp/mcp-fixtures/leak.txt".to_string())
            .await;
        let _removed = std::fs::remove_dir_all(&fixture_dir);

        let response = result.expect("scan_file inside cwd must succeed");
        assert!(response.finding_count > 0, "leaked token must be detected");
    }

    #[tokio::test]
    async fn scan_file_missing_file_maps_to_internal_error() {
        let rpc = AegisRpcImpl::new(ready_state().await);

        // Nonexistent but inside cwd: the sandbox allows it, the scan fails.
        let error = rpc
            .scan_file("temp/absent-file.txt".to_string())
            .await
            .expect_err("missing file must surface an error");
        assert_eq!(error.code, jsonrpc_core::ErrorCode::InternalError);
    }

    #[tokio::test]
    async fn scan_dir_inside_cwd_reports_findings() {
        let rpc = AegisRpcImpl::new(ready_state().await);

        let fixture_dir = PathBuf::from("temp/mcp-dir-fixture");
        std::fs::create_dir_all(&fixture_dir).expect("create fixture dir");
        // The console.log line gives the test a finding to assert on; the
        // credential line is a synthetic fixture, suppressed on its own line.
        std::fs::write(
            fixture_dir.join("creds.txt"),
            "console.log(\"debug\");\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI\n", // aegis:ignore:aws-secret-key,env-credential-assignment -- synthetic fixtures
        )
        .expect("write fixture");

        let result = rpc.scan_dir("temp/mcp-dir-fixture".to_string()).await;
        let _removed = std::fs::remove_dir_all(&fixture_dir);

        let response = result.expect("scan_dir inside cwd must succeed");
        assert!(
            response.finding_count > 0,
            "finding in nested fixture must be reported"
        );
    }

    /// Content that trips one secret rule and one non-secret rule. The
    /// pieces are assembled at run time so the repository's own scan does
    /// not flag this fixture as a leak.
    fn mixed_category_fixture() -> String {
        let token = format!("glpat-{}", "ABCDEFGHIJKLMNOPQRST");
        let weak_hash = format!("md{}(password)", "5");
        format!("{token}\n{weak_hash}")
    }

    #[tokio::test]
    async fn a_configured_category_is_in_force_for_the_next_scan() {
        let state = Arc::new(ServerState::new());
        let rpc = AegisRpcImpl::new(state.clone());
        let content = mixed_category_fixture();

        let unconfigured = rpc
            .scan_string(content.clone(), "test.txt".to_string())
            .await
            .expect("scan_string must succeed");
        assert!(
            unconfigured
                .findings
                .iter()
                .any(|finding| finding.category == "secrets"),
            "the fixture must trip a secret rule"
        );
        assert!(
            unconfigured
                .findings
                .iter()
                .any(|finding| finding.category != "secrets"),
            "the fixture must trip a rule outside the secrets category"
        );

        let config = Config {
            enabled_categories: Some(vec!["secrets".to_string()]),
            ..Config::default()
        };
        state
            .set_config(config)
            .await
            .expect("configuration applies");

        let configured = rpc
            .scan_string(content, "test.txt".to_string())
            .await
            .expect("scan_string must succeed");
        assert!(
            configured
                .findings
                .iter()
                .any(|finding| finding.category == "secrets"),
            "the configured category must still report"
        );
        assert!(
            configured
                .findings
                .iter()
                .all(|finding| finding.category == "secrets"),
            "only the configured category may report: {:?}",
            configured
                .findings
                .iter()
                .map(|finding| finding.category.as_str())
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn a_configuration_applied_while_the_rule_set_compiles_stays_in_force() {
        // The lazy compilation and the configuration change each install a
        // scanner. Whichever runs last, the configuration that was applied
        // is the one in force afterwards: a compilation that began before
        // the change must not install its scanner over it.
        for order in [0_u8, 1] {
            let state = Arc::new(ServerState::new());
            let config = Config {
                enabled_categories: Some(vec!["secrets".to_string()]),
                ..Config::default()
            };
            let apply = state.set_config(config);
            let load = state.ensure_patterns_loaded();
            let (applied, loaded) = if order == 0 {
                tokio::join!(apply, load)
            } else {
                let (loaded, applied) = tokio::join!(load, apply);
                (applied, loaded)
            };
            applied.expect("configuration applies");
            loaded.expect("the rule set compiles");

            let rpc = AegisRpcImpl::new(state.clone());
            let scanned = rpc
                .scan_string(mixed_category_fixture(), "test.txt".to_string())
                .await
                .expect("scan_string must succeed");
            assert!(
                scanned
                    .findings
                    .iter()
                    .all(|finding| finding.category == "secrets"),
                "the configuration in force is the one that was applied: {:?}",
                scanned
                    .findings
                    .iter()
                    .map(|finding| finding.category.as_str())
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn the_operator_configuration_is_read_from_the_environment() {
        // Env vars are process-global; the name is exercised in this one
        // serialized test so parallel tests cannot race the mutation.
        std::env::remove_var(CONFIG_ENV);
        assert!(
            operator_config_path()
                .expect("unset is not an error")
                .is_none(),
            "no configuration is named when the variable is unset"
        );

        std::env::set_var(CONFIG_ENV, "/tmp/aegis-operator.json");
        assert_eq!(
            operator_config_path().expect("a named file is read"),
            Some(PathBuf::from("/tmp/aegis-operator.json"))
        );

        std::env::set_var(CONFIG_ENV, "");
        let error = operator_config_path().expect_err("an empty value must be rejected");
        assert!(
            error.to_string().contains(CONFIG_ENV),
            "the rejection names the variable: {error}"
        );

        std::env::remove_var(CONFIG_ENV);
    }

    #[tokio::test]
    async fn a_configuration_with_an_uncompilable_path_class_is_rejected() {
        let state = Arc::new(ServerState::new());
        let config = Config {
            path_classes: vec![aegis_core::PathClassRule {
                glob: "docs/[".to_string(),
                class: aegis_core::PathClass::Docs,
            }],
            ..Config::default()
        };

        let error = state
            .set_config(config)
            .await
            .expect_err("a glob that cannot compile must be rejected");
        assert!(
            error.contains("docs/["),
            "the rejection names the broken glob: {error}"
        );
    }

    #[tokio::test]
    async fn a_configuration_with_an_unusable_severity_threshold_is_rejected() {
        let state = Arc::new(ServerState::new());
        let config = Config {
            severity_threshold: Some("severe".to_string()),
            ..Config::default()
        };

        let error = state
            .set_config(config)
            .await
            .expect_err("a threshold that matches no severity must be rejected");
        assert!(
            error.contains("severe"),
            "the rejection names the threshold: {error}"
        );
    }
}
