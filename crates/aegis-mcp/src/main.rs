//! Aegis MCP Server
//!
//! Model Context Protocol server for Aegis security scanning.

mod protocol;
mod sandbox;

use aegis_core::transport::{read_bounded_line, FrameRead, MAX_FRAME_BYTES};
use aegis_core::{Bundle, Config, ScanOptions, ScanReceipt, ScanStats, Scanner};
use jsonrpc_core::{BoxFuture, IoHandler, Result, Value};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::BufReader;
use tokio::sync::RwLock;

/// MCP server state
pub struct ServerState {
    /// Scanner served to every tool call; installed by the lazy pattern
    /// initialization and replaced wholesale by `update_bundle`.
    pub scanner: RwLock<Scanner>,
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
    /// The persisted pattern state this server honors, when it was pointed
    /// at a file. The file is re-read for every tool call, so a pattern the
    /// operator disabled after startup stops firing without a restart.
    pattern_state_path: Option<PathBuf>,
    /// The pattern disablements the scanner in force was built with, so a
    /// state file that did not change does not rebuild the rule set.
    applied_pattern_state: RwLock<BTreeSet<String>>,
}

impl ServerState {
    /// Build a state with an empty scanner, default configuration, and
    /// placeholder bundle metadata; patterns compile on the first request
    /// that needs them, not here.
    #[must_use]
    pub fn new() -> Self {
        let config = Config::default();
        Self {
            scanner: RwLock::new(Scanner::new()),
            config: RwLock::new(config),
            installed_bundle: RwLock::new(None),
            bundle_version: RwLock::new(String::from("0.0.0")),
            bundle_checksum: RwLock::new(String::new()),
            patterns_init: tokio::sync::OnceCell::const_new(),
            bundle_swapped: AtomicBool::new(false),
            apply_lock: tokio::sync::Mutex::const_new(()),
            pattern_state_path: None,
            applied_pattern_state: RwLock::new(BTreeSet::new()),
        }
    }

    /// Point the server at a persisted pattern state file.
    ///
    /// The server reads the file for every tool call, so a pattern the
    /// operator disabled after startup stops firing without a restart. A
    /// server that is not pointed at a file honors no persisted state: the
    /// rule set in force is what it scans with.
    #[must_use]
    pub fn with_pattern_state(mut self, path: PathBuf) -> Self {
        self.pattern_state_path = Some(path);
        self
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
        let state = load_pattern_state(self.pattern_state_path.as_deref())?;
        let disabled = state.disabled_patterns.clone();
        let rebuilt =
            tokio::task::spawn_blocking(move || scanner_for_with_state(&bundle, &applied, &state))
                .await
                .map_err(|error| format!("scanner rebuild task failed: {error}"))?;
        let scanner = rebuilt?;
        *self.scanner.write().await = scanner;
        *self.config.write().await = config;
        *self.applied_pattern_state.write().await = disabled;
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
                let state = load_pattern_state(self.pattern_state_path.as_deref())
                    .map_err(|message| format!("pattern state is unavailable: {message}"))?;
                let disabled = state.disabled_patterns.clone();
                let compiled: std::result::Result<Scanner, String> =
                    match tokio::task::spawn_blocking(move || {
                        scanner_for_with_state(&bundle, &config, &state)
                    })
                    .await
                    {
                        Ok(result) => result,
                        Err(error) => Err(format!("pattern compilation task failed: {error}")),
                    };
                match compiled {
                    Ok(scanner) => {
                        *self.scanner.write().await = scanner;
                        *self.applied_pattern_state.write().await = disabled;
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

    /// Make the scanner in force match the persisted pattern state.
    ///
    /// The state file is read for every tool call, so a pattern the
    /// operator disabled after the server started stops firing without a
    /// restart. A state file that did not change does not rebuild the rule
    /// set.
    ///
    /// # Errors
    /// Returns `InternalError` when the state cannot be read or parsed, and
    /// when the rule set cannot be rebuilt around it.
    pub async fn refresh_pattern_state(&self) -> Result<()> {
        let state = load_pattern_state(self.pattern_state_path.as_deref()).map_err(|message| {
            jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::InternalError,
                message: format!("pattern state is unavailable: {message}"),
                data: None,
            }
        })?;
        if *self.applied_pattern_state.read().await == state.disabled_patterns {
            return Ok(());
        }
        // The lock keeps a configuration applied while this rebuild runs
        // from being overwritten by it.
        let _guard = self.apply_lock.lock().await;
        if *self.applied_pattern_state.read().await == state.disabled_patterns {
            return Ok(());
        }
        let bundle = self.current_bundle().await;
        let config = self.config.read().await.clone();
        let disabled = state.disabled_patterns.clone();
        let rebuilt = match tokio::task::spawn_blocking(move || {
            scanner_for_with_state(&bundle, &config, &state)
        })
        .await
        {
            Ok(Ok(scanner)) => scanner,
            Ok(Err(message)) => {
                return Err(jsonrpc_core::Error {
                    code: jsonrpc_core::ErrorCode::InternalError,
                    message: format!("scanner rebuild failed: {message}"),
                    data: None,
                });
            }
            Err(error) => {
                return Err(jsonrpc_core::Error {
                    code: jsonrpc_core::ErrorCode::InternalError,
                    message: format!("scanner rebuild task failed: {error}"),
                    data: None,
                });
            }
        };
        *self.scanner.write().await = rebuilt;
        *self.applied_pattern_state.write().await = disabled;
        Ok(())
    }

    /// The scanner every tool call scans with.
    ///
    /// The rule set is compiled on first use, and the persisted pattern
    /// state is applied before the first scan and refreshed afterwards, so
    /// the rule set in force is the one the operator configured.
    ///
    /// # Errors
    /// Returns `InternalError` when the rule set cannot be compiled, when
    /// the persisted pattern state cannot be read, or when the rule set
    /// cannot be rebuilt around it.
    pub async fn prepare_scanner(&self) -> Result<()> {
        self.ensure_patterns_loaded().await?;
        self.refresh_pattern_state().await
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

/// Build a scanner over a rule set with a configuration in force and a
/// persisted pattern state applied.
///
/// The state narrows the registry before any scan, the same way it does on
/// the command line, so a pattern the operator disabled does not fire here
/// either.
///
/// # Errors
///
/// Returns a message naming the reason the configuration was rejected —
/// an unknown category, a path-class rule whose glob does not compile, a
/// severity threshold no severity name matches, or an unknown anomaly
/// detector. The scanner is not built, so a rejected configuration leaves
/// the server serving the configuration it already had.
fn scanner_for_with_state(
    bundle: &Bundle,
    config: &Config,
    state: &aegis_core::pattern_state::PatternState,
) -> std::result::Result<Scanner, String> {
    // A rule whose glob does not compile classifies nothing, so the
    // configuration is rejected here instead of being applied as a silent
    // no-op: the caller learns that its path class never fired.
    for rule in &config.path_classes {
        rule.validate()?;
    }

    // A baseline must name an existing, readable file, and it must sit
    // inside the sandbox: a baseline is content the scan reads, so an
    // operator profile cannot smuggle reads outside the allowed directory.
    if let Some(baseline) = &config.baseline {
        if !sandbox::is_path_safe(baseline) {
            return Err(format!(
                "baseline path {} is outside the allowed directory",
                baseline.display()
            ));
        }
        aegis_core::scanner::load_baseline_fingerprints(baseline)
            .map_err(|error| error.to_string())?;
    }

    let mut configured = config.clone();
    configured.bundle = bundle.clone();

    let scanner = Scanner::from_config(&configured).map_err(|error| error.to_string())?;

    // `from_config` applies the categories and the path classes; the
    // threshold and the detector selection are scan options, so they are
    // applied here — with the path classes carried over, because the
    // options replace the ones the scanner was built with. The baseline
    // and the walk options come from the configuration the same way.
    let options = ScanOptions {
        path_classes: configured.path_classes.clone(),
        severity_threshold: configured.severity_threshold.clone(),
        anomaly_detectors: configured.anomaly_detectors.clone(),
        baseline: configured.baseline.clone(),
        follow_symlinks: configured.follow_symlinks,
        detect_clones: configured.detect_clones,
        ..ScanOptions::default()
    };
    // A threshold or a detector name that cannot be honoured would quiet
    // the scan without saying so, so the configuration is rejected instead.
    options.validate()?;
    if let Some(detectors) = &options.anomaly_detectors {
        aegis_core::anomalies::validate_detector_names(detectors)?;
    }

    let scanner = scanner.with_options(options);
    // The state is applied before the first scan, so the extension scanners
    // the scanner caches are built from the narrowed registry.
    aegis_core::pattern_state::apply_to_registry(state, scanner.registry());
    Ok(scanner)
}

/// Read the persisted pattern state a server honors.
///
/// `path` is the file the server was pointed at; without one the server
/// honors no persisted state and scans with the rule set in force.
///
/// # Errors
///
/// Returns a message naming the file when the state cannot be read or
/// parsed. A malformed state file is an error, never a silent fallback: an
/// ignored preference silently changes scan results.
fn load_pattern_state(
    path: Option<&std::path::Path>,
) -> std::result::Result<aegis_core::pattern_state::PatternState, String> {
    let Some(path) = path else {
        return Ok(aegis_core::pattern_state::PatternState::empty());
    };
    aegis_core::pattern_state::load(path).map_err(|error| error.to_string())
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
            state.prepare_scanner().await?;
            let scanner = state.scanner.read().await;
            let findings = scanner.scan_string(&content, &source);

            Ok(ScanResponse::for_string(findings, &source, content.len()))
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

            state.prepare_scanner().await?;
            let scanner = state.scanner.read().await;
            let (findings, scan_stats) =
                scanner.scan_file(&path).map_err(|e| jsonrpc_core::Error {
                    code: jsonrpc_core::ErrorCode::InternalError,
                    message: e.to_string(),
                    data: None,
                })?;

            Ok(ScanResponse::from_parts(
                findings,
                scan_stats,
                path.to_string_lossy().to_string(),
            ))
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

            state.prepare_scanner().await?;
            let scanner = state.scanner.read().await;
            let (findings, scan_stats) =
                scanner.scan_dir(&path).map_err(|e| jsonrpc_core::Error {
                    code: jsonrpc_core::ErrorCode::InternalError,
                    message: e.to_string(),
                    data: None,
                })?;

            Ok(ScanResponse::from_parts(
                findings,
                scan_stats,
                path.to_string_lossy().to_string(),
            ))
        })
    }

    fn scan_env(&self) -> BoxFuture<Result<ScanResponse>> {
        let state = self.state.clone();
        Box::pin(async move {
            state.prepare_scanner().await?;
            let scanner = state.scanner.read().await;
            let findings = scanner.scan_env();

            Ok(ScanResponse::for_environment(findings))
        })
    }

    fn list_patterns(&self, category: Option<String>) -> BoxFuture<Result<ListPatternsResponse>> {
        let state = self.state.clone();
        Box::pin(async move {
            state.prepare_scanner().await?;
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
            state.prepare_scanner().await?;
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
            // If no path provided, use embedded patterns
            let bundle = if let Some(path) = bundle_path {
                let path = PathBuf::from(&path);

                // Security: validate path
                if !sandbox::is_path_safe(&path) {
                    return Err(jsonrpc_core::Error {
                        code: jsonrpc_core::ErrorCode::InvalidParams,
                        message: "Path is outside allowed directory".to_string(),
                        data: None,
                    });
                }

                // Load bundle from file
                Bundle::load(&path).map_err(|e| jsonrpc_core::Error {
                    code: jsonrpc_core::ErrorCode::InternalError,
                    message: format!("Failed to load bundle: {e}"),
                    data: None,
                })?
            } else {
                // Use the patterns shipped with the binary
                shipped_bundle()
            };

            // Validate bundle
            bundle.validate().map_err(|e| jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::InternalError,
                message: format!("Invalid bundle: {e}"),
                data: None,
            })?;

            // Create the scanner from the bundle with the configuration in
            // force: an installed rule set answers what to scan, not how
            // to treat what is found.
            //
            // The lock keeps a lazy compilation that is already running
            // from installing its scanner after this one.
            let _guard = state.apply_lock.lock().await;
            let config = state.config.read().await.clone();
            let pattern_state =
                load_pattern_state(state.pattern_state_path.as_deref()).map_err(|e| {
                    jsonrpc_core::Error {
                        code: jsonrpc_core::ErrorCode::InternalError,
                        message: format!("Failed to read the pattern state: {e}"),
                        data: None,
                    }
                })?;
            let disabled = pattern_state.disabled_patterns.clone();
            let new_scanner =
                scanner_for_with_state(&bundle, &config, &pattern_state).map_err(|e| {
                    jsonrpc_core::Error {
                        code: jsonrpc_core::ErrorCode::InternalError,
                        message: format!("Failed to create scanner: {e}"),
                        data: None,
                    }
                })?;

            // Update state. The swap flag makes later `ensure_patterns_loaded`
            // calls no-ops so they cannot overwrite this bundle, and it also
            // clears a previously failed lazy compilation.
            {
                let mut scanner = state.scanner.write().await;
                *scanner = new_scanner;
            }
            // The scanner in force was built around this state, so a later
            // refresh does not rebuild the rule set for nothing.
            {
                let mut applied = state.applied_pattern_state.write().await;
                *applied = disabled;
            }
            // Keep the installed bundle, so a configuration applied later
            // is built around the same rules instead of silently falling
            // back to the shipped corpus.
            {
                let mut installed = state.installed_bundle.write().await;
                *installed = Some(bundle.clone());
            }
            state.bundle_swapped.store(true, Ordering::Release);
            {
                let mut version = state.bundle_version.write().await;
                *version = bundle.metadata().version.to_string();
            }
            {
                let mut checksum = state.bundle_checksum.write().await;
                *checksum = bundle.metadata().checksum;
            }

            let pattern_count = bundle.len();
            Ok(UpdateResponse {
                success: true,
                message: format!("Bundle updated with {pattern_count} patterns"),
                pattern_count,
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

/// The persisted pattern state the server honors.
///
/// The environment is read here, at the edge: `AEGIS_PATTERN_STATE` names
/// the file, and the default is this account's own configuration
/// directory. A server running under a service account therefore needs the
/// environment variable to honor the file the operator's `aegis disable`
/// writes.
fn pattern_state_path() -> Option<PathBuf> {
    let explicit = std::env::var_os(aegis_core::pattern_state::STATE_PATH_ENV).map(PathBuf::from);
    aegis_core::pattern_state::resolve_state_file(explicit.as_deref()).ok()
}

/// Initialize scanner with patterns from aegis-patterns
///
/// The server builds its scanner through [`scanner_for_with_state`], so this
/// shortcut exists for the tests that need a scanner without a
/// configuration. It applies an empty pattern state: a test must not depend
/// on the pattern state file the operator's own `aegis disable` writes.
#[cfg(test)]
fn init_scanner() -> anyhow::Result<Scanner> {
    let state = aegis_core::pattern_state::PatternState::empty();
    scanner_for_with_state(&shipped_bundle(), &Config::default(), &state)
        .map_err(anyhow::Error::msg)
}

fn invalid_params<T: std::fmt::Display>(error: T) -> jsonrpc_core::Error {
    jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::InvalidParams,
        message: error.to_string(),
        data: None,
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

    let server_state = ServerState::new();
    let server_state = match pattern_state_path() {
        Some(path) => server_state.with_pattern_state(path),
        None => server_state,
    };
    let state = Arc::new(server_state);

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
    protocol::register(&mut io, rpc.clone());

    // stdout is the JSON-RPC transport; startup diagnostics must not corrupt
    // the protocol stream consumed by MCP clients.
    eprintln!("Aegis MCP Server starting...");
    eprintln!("Listening on stdin/stdout");

    // JSON-RPC over stdio
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let stdout = tokio::io::stdout();
    let mut writer = tokio::io::BufWriter::new(stdout);

    let mut line = String::new();
    loop {
        match read_bounded_line(&mut reader, MAX_FRAME_BYTES, &mut line).await {
            Ok(FrameRead::Line) => {}
            Ok(FrameRead::Eof) | Err(_) => break,
            Ok(FrameRead::Oversize) => {
                // The rest of the oversized line is still unread and
                // unknowable, so framing cannot resume: answer once with a
                // request error, then end the session.
                let response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32600,
                        "message": format!(
                            "request frame exceeds maximum size ({MAX_FRAME_BYTES} bytes)"
                        )
                    },
                    "id": Value::Null
                });
                write_response(&mut writer, &response.to_string())
                    .await
                    .map_err(anyhow::Error::from)?;
                break;
            }
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Parse request
        let _request: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                let response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32700,
                        "message": format!("Parse error: {}", e)
                    },
                    "id": Value::Null
                });
                // A dead stdout means the client is gone; serving on would
                // spin silently, so the failure terminates the session.
                write_response(&mut writer, &response.to_string())
                    .await
                    .map_err(anyhow::Error::from)?;
                continue;
            }
        };

        // Handle JSON-RPC request
        let response = io.handle_request(line).await;
        if let Some(resp) = response {
            write_response(&mut writer, &resp)
                .await
                .map_err(anyhow::Error::from)?;
        }
    }

    Ok(())
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
    fn a_config_with_a_baseline_inside_the_sandbox_carries_it_into_the_options() {
        // The server can offer the "what is new since last time" mode: the
        // profile's baseline reaches the scan options and the scanner is
        // built with it.
        // The sandbox admits only paths inside the working directory, so
        // the fixture lives under the process cwd, spelled absolutely so
        // the test does not depend on how the runner resolves relatives.
        let dir = std::env::current_dir()
            .expect("test cwd")
            .join(format!("target/aegis-mcp-baseline-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create fixture dir");
        let baseline = dir.join("baseline.json");
        std::fs::write(&baseline, r#"[{"fingerprint":"fp-1"}]"#).expect("write baseline");

        let config = Config {
            baseline: Some(baseline.clone()),
            ..Config::default()
        };
        let state = aegis_core::pattern_state::PatternState::default();

        let scanner =
            scanner_for_with_state(&shipped_bundle(), &config, &state).expect("scanner builds");
        assert_eq!(scanner.scan_options().baseline.as_ref(), Some(&baseline));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_config_with_a_baseline_outside_the_sandbox_is_refused() {
        // A baseline is content the scan reads, so an operator profile
        // cannot point it outside the allowed directory.
        let config = Config {
            baseline: Some(PathBuf::from("/etc/aegis-never-here-baseline.json")),
            ..Config::default()
        };
        let state = aegis_core::pattern_state::PatternState::default();

        let Err(error) = scanner_for_with_state(&shipped_bundle(), &config, &state) else {
            panic!("a baseline outside the sandbox must be refused");
        };
        assert!(
            error.contains("outside the allowed directory"),
            "got: {error}"
        );
    }

    #[test]
    fn a_config_with_walk_options_carries_them_into_the_options() {
        let config = Config {
            follow_symlinks: true,
            detect_clones: true,
            ..Config::default()
        };
        let state = aegis_core::pattern_state::PatternState::default();

        let scanner =
            scanner_for_with_state(&shipped_bundle(), &config, &state).expect("scanner builds");
        let options = scanner.scan_options();
        assert!(options.follow_symlinks);
        assert!(options.detect_clones);
    }

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
            *scanner = init_scanner().expect("bundled patterns compile");
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
            *scanner = init_scanner().expect("bundled patterns compile");
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
            *scanner = init_scanner().expect("bundled patterns compile");
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
            *scanner = init_scanner().expect("bundled patterns compile");
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
            *scanner = init_scanner().expect("bundled patterns compile");
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
            *scanner = init_scanner().expect("bundled patterns compile");
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
            *scanner = init_scanner().expect("bundled patterns compile");
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
            *scanner = init_scanner().expect("bundled patterns compile");
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

    #[tokio::test]
    async fn a_disabled_pattern_stops_firing_on_the_next_tool_call() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_file = dir.path().join("pattern-state.json");
        let state = Arc::new(ServerState::new().with_pattern_state(state_file.clone()));
        let rpc = AegisRpcImpl::new(state.clone());
        let content = mixed_category_fixture();

        let before = rpc
            .scan_string(content.clone(), "test.txt".to_string())
            .await
            .expect("scan_string must succeed");
        assert!(
            before
                .findings
                .iter()
                .any(|finding| finding.pattern == "gitlab-token"),
            "the fixture must trip the gitlab rule: {:?}",
            before
                .findings
                .iter()
                .map(|finding| finding.pattern.as_str())
                .collect::<Vec<_>>()
        );

        let mut document = aegis_core::pattern_state::PatternState::empty();
        document
            .disabled_patterns
            .insert("gitlab-token".to_string());
        aegis_core::pattern_state::save(&state_file, &document).expect("the state is written");

        let after = rpc
            .scan_string(content, "test.txt".to_string())
            .await
            .expect("scan_string must succeed");
        assert!(
            !after
                .findings
                .iter()
                .any(|finding| finding.pattern == "gitlab-token"),
            "the disabled rule must not fire: {:?}",
            after
                .findings
                .iter()
                .map(|finding| finding.pattern.as_str())
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn a_malformed_state_file_is_refused_rather_than_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_file = dir.path().join("pattern-state.json");
        std::fs::write(&state_file, "{not json").expect("write a malformed state");
        let state = Arc::new(ServerState::new().with_pattern_state(state_file));
        let rpc = AegisRpcImpl::new(state.clone());

        let error = rpc
            .scan_string(mixed_category_fixture(), "test.txt".to_string())
            .await
            .expect_err("a malformed state must not be ignored");
        assert!(
            error.to_string().contains("pattern-state.json"),
            "the refusal names the file: {error}"
        );
    }

    #[tokio::test]
    async fn a_malformed_state_file_is_refused_when_the_state_is_refreshed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_file = dir.path().join("pattern-state.json");
        std::fs::write(&state_file, "{not json").expect("write a malformed state");
        let state = Arc::new(ServerState::new().with_pattern_state(state_file));

        let error = state
            .refresh_pattern_state()
            .await
            .expect_err("a malformed state must not be ignored");
        assert!(
            error.to_string().contains("pattern-state.json"),
            "the refusal names the file: {error}"
        );
    }

    #[tokio::test]
    async fn a_malformed_state_file_is_refused_when_the_bundle_is_replaced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_file = dir.path().join("pattern-state.json");
        std::fs::write(&state_file, "{not json").expect("write a malformed state");
        let state = Arc::new(ServerState::new().with_pattern_state(state_file));
        let rpc = AegisRpcImpl::new(state);

        let error = rpc
            .update_bundle(None, false)
            .await
            .expect_err("a malformed state must not be ignored");
        assert!(
            error.to_string().contains("pattern-state.json"),
            "the refusal names the file: {error}"
        );
    }
}
