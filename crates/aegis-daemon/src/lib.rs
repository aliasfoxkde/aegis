//! Aegis Daemon Library
//!
//! Core logic for the Aegis daemon.

use aegis_core::pattern_state::PatternState;
use aegis_core::{
    Bundle, Config, Finding, RiskScore, ScanOptions, ScanReceipt, ScanStats, Scanner,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

const ALLOWED_UIDS_ENV: &str = "AEGIS_DAEMON_ALLOWED_UIDS";
const ALLOWED_GIDS_ENV: &str = "AEGIS_DAEMON_ALLOWED_GIDS";

/// Peer credentials allowed to use the daemon socket.
///
/// The socket owner is always allowed. Additional UIDs or primary GIDs can be
/// supplied through the corresponding environment variables. A peer matching
/// either an allowed UID or GID is authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonPeerPolicy {
    allowed_uids: BTreeSet<u32>,
    allowed_gids: BTreeSet<u32>,
}

impl DaemonPeerPolicy {
    /// Build the policy from the socket owner and process environment.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidInput` I/O error when `AEGIS_DAEMON_ALLOWED_UIDS` or
    /// `AEGIS_DAEMON_ALLOWED_GIDS` is set but holds an empty or non-numeric
    /// entry.
    pub fn from_env(socket_owner_uid: u32) -> io::Result<Self> {
        let user_id_allowlist = env::var(ALLOWED_UIDS_ENV).ok();
        let group_id_allowlist = env::var(ALLOWED_GIDS_ENV).ok();
        Self::from_allowlists(
            socket_owner_uid,
            user_id_allowlist.as_deref(),
            group_id_allowlist.as_deref(),
        )
    }

    /// Build a policy from explicit comma-separated numeric UID/GID lists.
    ///
    /// The socket owner is always included. This is public so service
    /// managers and embedding applications can construct the same policy
    /// without mutating process-global environment variables.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidInput` I/O error when either list contains an empty
    /// entry or a value that is not a valid numeric ID.
    pub fn from_allowlists(
        socket_owner_uid: u32,
        allowed_user_ids: Option<&str>,
        allowed_group_ids: Option<&str>,
    ) -> io::Result<Self> {
        let mut policy = Self {
            allowed_uids: BTreeSet::from([socket_owner_uid]),
            allowed_gids: BTreeSet::new(),
        };

        if let Some(value) = allowed_user_ids {
            policy
                .allowed_uids
                .extend(parse_allowlist(ALLOWED_UIDS_ENV, value)?);
        }
        if let Some(value) = allowed_group_ids {
            policy
                .allowed_gids
                .extend(parse_allowlist(ALLOWED_GIDS_ENV, value)?);
        }

        Ok(policy)
    }

    /// Policy that trusts the socket owner and nobody else.
    ///
    /// Matches the posture the daemon gets when neither allowlist variable is
    /// set, without reading process-global environment state.
    #[must_use]
    pub fn owner_only(socket_owner_uid: u32) -> Self {
        Self {
            allowed_uids: BTreeSet::from([socket_owner_uid]),
            allowed_gids: BTreeSet::new(),
        }
    }

    /// Return true when a peer's effective credentials match the policy.
    #[must_use]
    pub fn allows_credentials(&self, uid: u32, gid: u32) -> bool {
        self.allowed_uids.contains(&uid) || self.allowed_gids.contains(&gid)
    }

    /// Socket mode appropriate for this policy.
    ///
    /// Group access is exposed only when a group allowlist is explicitly
    /// configured; the application-level peer check remains authoritative.
    #[must_use]
    pub fn socket_mode(&self) -> u32 {
        if self.allowed_gids.is_empty() {
            0o600
        } else {
            0o660
        }
    }

    /// Apply the UID/GID check to the credentials the kernel reported for a
    /// connected peer; the connection handler runs this before parsing a
    /// single request byte, so an untrusted local account gets no response.
    #[cfg(unix)]
    #[must_use]
    pub fn allows(&self, credentials: &tokio::net::unix::UCred) -> bool {
        self.allows_credentials(credentials.uid(), credentials.gid())
    }
}

fn parse_allowlist(name: &str, value: &str) -> io::Result<BTreeSet<u32>> {
    let mut values = BTreeSet::new();
    for item in value.split(',').map(str::trim) {
        if item.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} contains an empty entry"),
            ));
        }
        let parsed = item.parse::<u32>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} contains invalid numeric ID {item:?}"),
            )
        })?;
        values.insert(parsed);
    }
    Ok(values)
}

/// Daemon state
pub struct DaemonState {
    /// Scanner shared by concurrent requests; reads take a read lock and the
    /// lazy pattern load swaps in a fully compiled instance on first use.
    pub scanner: RwLock<Scanner>,
    /// Live configuration, published behind a lock so a host process can
    /// retune scanning without rebuilding the state.
    ///
    /// The configuration is not merely recorded: the categories, severity
    /// threshold, anomaly detectors, and path classes it names are in
    /// force for the scans that follow. It is written only through
    /// [`Self::set_config`], which rebuilds the scanner around it, so the
    /// two are replaced together.
    config: RwLock<Config>,
    /// Where the Unix socket is (or will be) bound; lets an embedding process
    /// or test discover the endpoint it needs to connect to.
    pub socket_path: PathBuf,
    scan_root: PathBuf,
    /// Guards the one-time lazy compilation of the bundled patterns; the
    /// first scan request pays for it, startup does not. The memoized
    /// outcome keeps a failed compilation sticky — a scanner that silently
    /// holds zero patterns would approve everything, so requests must keep
    /// failing closed.
    patterns_init: tokio::sync::OnceCell<Result<(), String>>,
    /// Serializes the two paths that build and install a scanner: the lazy
    /// compilation on first use and [`Self::set_config`]. Without it, a
    /// compilation that began before a configuration was applied would
    /// install its scanner afterwards, silently undoing the change. It is
    /// always the outermost lock, so the two paths cannot deadlock.
    apply_lock: tokio::sync::Mutex<()>,
    /// The persisted pattern state this daemon honors, when it was pointed
    /// at a file. The daemon is a long-running service, so the file is
    /// re-read for every request: a pattern the operator disabled after
    /// startup stops firing without a restart.
    pattern_state_path: Option<PathBuf>,
    /// The pattern disablements the scanner in force was built with, so a
    /// state file that did not change does not rebuild the rule set.
    applied_pattern_state: RwLock<BTreeSet<String>>,
}

impl DaemonState {
    /// Build state using the process's current working directory as the
    /// approved scan root, falling back to `.` when that cannot be read.
    ///
    /// # Panics
    ///
    /// Panics when the chosen root is not an existing directory, exactly as
    /// [`Self::with_scan_root`] does; prefer [`Self::try_with_scan_root`] in
    /// code that must report the failure instead.
    #[must_use]
    pub fn new(socket_path: PathBuf) -> Self {
        let scan_root = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self::with_scan_root(socket_path, &scan_root)
    }

    /// Construct state with an approved scan root.
    ///
    /// This convenience constructor is intended for callers that already
    /// know the root exists. The daemon entry point uses the fallible form so
    /// configuration errors are reported instead of panicking.
    ///
    /// # Panics
    ///
    /// Panics when the scan root cannot be canonicalized or resolves to a path
    /// that is not an existing directory; the `expect` message states the
    /// requirement.
    #[must_use]
    #[allow(clippy::expect_used)] // aegis-allow: documented panicking convenience wrapper; try_with_scan_root is the fallible form | expires=2027-12-31 | approver=maintainers
    pub fn with_scan_root(socket_path: PathBuf, scan_root: &Path) -> Self {
        Self::try_with_scan_root(socket_path, scan_root)
            .expect("Aegis daemon scan root must be an existing directory")
    }

    /// Construct state after canonicalizing and validating the approved root.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error when the root cannot be canonicalized,
    /// or an `InvalidInput` I/O error when the resolved path is not an existing
    /// directory.
    pub fn try_with_scan_root(socket_path: PathBuf, scan_root: &Path) -> io::Result<Self> {
        let scan_root = fs::canonicalize(scan_root)?;
        if !scan_root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "approved scan root is not a directory: {}",
                    scan_root.display()
                ),
            ));
        }

        Ok(Self {
            scanner: RwLock::new(Scanner::new()),
            config: RwLock::new(Config::default()),
            socket_path,
            scan_root,
            patterns_init: tokio::sync::OnceCell::const_new(),
            apply_lock: tokio::sync::Mutex::const_new(()),
            pattern_state_path: None,
            applied_pattern_state: RwLock::new(BTreeSet::new()),
        })
    }

    /// Point the daemon at a persisted pattern state file.
    ///
    /// The daemon reads the file for every request, so a pattern the
    /// operator disabled after startup stops firing without a restart. A
    /// daemon that is not pointed at a file honors no persisted state: the
    /// shipped rule set is what it scans with.
    #[must_use]
    pub fn with_pattern_state(mut self, path: PathBuf) -> Self {
        self.pattern_state_path = Some(path);
        self
    }

    /// The canonicalized boundary every client-supplied path is confined to.
    ///
    /// Requests that resolve outside it — including through symlinks — are
    /// refused, so this value is the effective trust boundary of the daemon.
    pub fn scan_root(&self) -> &Path {
        &self.scan_root
    }

    /// The configuration in force.
    ///
    /// The configuration that is returned is the one the scanner was built
    /// from, so a caller that reads it after [`Self::set_config`] returns
    /// learns what the daemon is actually applying.
    #[must_use]
    pub async fn config(&self) -> Config {
        self.config.read().await.clone()
    }

    /// Apply a configuration and rebuild the scanner around it.
    ///
    /// The categories, severity threshold, anomaly detectors, and path
    /// classes the configuration names are in force for the scans that
    /// follow. The shipped pattern corpus stays in force: a configuration
    /// says what to look for, not which rules to ship.
    ///
    /// # Errors
    ///
    /// Returns the reason the configuration was rejected — an unknown
    /// category, a path-class rule whose glob does not compile, a severity
    /// threshold no severity name matches, or an unknown anomaly detector —
    /// and leaves the previous configuration and scanner in place, so a
    /// rejected configuration never leaves the daemon half-configured.
    pub async fn set_config(&self, config: Config) -> Result<(), String> {
        // The lock keeps a lazy compilation that is already running from
        // installing its scanner after this one; the configuration that is
        // in force afterwards is the one that was applied here.
        let _guard = self.apply_lock.lock().await;
        // Rebuilding the scanner compiles the whole rule set, which is
        // CPU-bound; `spawn_blocking` keeps it off the reactor so other
        // requests keep being served while the configuration changes.
        let applied = config.clone();
        let state = load_pattern_state(self.pattern_state_path.as_deref())?;
        let disabled = state.disabled_patterns.clone();
        let rebuilt = tokio::task::spawn_blocking(move || scanner_for_with_state(&applied, &state))
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

    /// Compile the bundled patterns on first use instead of at startup.
    ///
    /// Compiling 600+ regexes is CPU-bound; `spawn_blocking` keeps it off
    /// the reactor, and the `OnceCell` makes concurrent first requests
    /// share one compilation. Fails closed: a compilation error is returned
    /// to every caller instead of degrading to a scanner with no patterns.
    ///
    /// The configuration in force when the patterns are compiled is the one
    /// the scanner is built from, and a configuration applied while that
    /// compilation runs waits for it, so the configuration in force is
    /// never overwritten by a scanner built from an earlier one.
    ///
    /// # Errors
    ///
    /// Returns the failure message when the bundled patterns cannot be
    /// compiled, when the configuration in force cannot be applied, or
    /// when the compiling task panics or is cancelled before finishing.
    /// The outcome is memoized, so every later call observes the same
    /// error instead of retrying.
    pub async fn ensure_patterns_loaded(&self) -> Result<(), String> {
        self.patterns_init
            .get_or_init(|| async {
                // The lock keeps a configuration applied while this
                // compilation runs from being overwritten by it.
                let _guard = self.apply_lock.lock().await;
                let config = self.config.read().await.clone();
                let state = load_pattern_state(self.pattern_state_path.as_deref())?;
                let disabled = state.disabled_patterns.clone();
                let compiled: Result<Scanner, String> =
                    match tokio::task::spawn_blocking(move || {
                        scanner_for_with_state(&config, &state)
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
    }

    /// Make the scanner in force match the persisted pattern state.
    ///
    /// The state file is read for every request, so a pattern the operator
    /// disabled after the daemon started stops firing without a restart. A
    /// state file that did not change does not rebuild the rule set.
    ///
    /// # Errors
    ///
    /// Returns a message naming the file when the state cannot be read or
    /// parsed, and the rebuild failure when the rule set cannot be
    /// compiled around it.
    pub async fn refresh_pattern_state(&self) -> Result<(), String> {
        let state = load_pattern_state(self.pattern_state_path.as_deref())?;
        if *self.applied_pattern_state.read().await == state.disabled_patterns {
            return Ok(());
        }
        // The lock keeps a configuration applied while this rebuild runs
        // from being overwritten by it.
        let _guard = self.apply_lock.lock().await;
        if *self.applied_pattern_state.read().await == state.disabled_patterns {
            return Ok(());
        }
        let config = self.config.read().await.clone();
        let disabled = state.disabled_patterns.clone();
        let rebuilt = tokio::task::spawn_blocking(move || scanner_for_with_state(&config, &state))
            .await
            .map_err(|error| format!("scanner rebuild task failed: {error}"))?;
        let scanner = rebuilt?;
        *self.scanner.write().await = scanner;
        *self.applied_pattern_state.write().await = disabled;
        Ok(())
    }

    /// The scanner every request scans with.
    ///
    /// The bundled patterns are compiled on first use, and the persisted
    /// pattern state is applied before the first scan and refreshed
    /// afterwards, so the rule set in force is the one the operator
    /// configured.
    ///
    /// # Errors
    ///
    /// Returns the failure message when the bundled patterns cannot be
    /// compiled, when the persisted pattern state cannot be read, or when
    /// the rule set cannot be rebuilt around it.
    pub async fn prepare_scanner(&self) -> Result<(), String> {
        self.ensure_patterns_loaded().await?;
        self.refresh_pattern_state().await
    }

    fn resolve_scan_path(&self, requested: &str) -> Result<PathBuf, String> {
        let requested_path = Path::new(requested);
        let candidate = if requested_path.is_absolute() {
            requested_path.to_path_buf()
        } else {
            self.scan_root.join(requested_path)
        };
        let canonical = fs::canonicalize(&candidate).map_err(|e| {
            format!(
                "scan path cannot be resolved within approved root: {} ({e})",
                candidate.display()
            )
        })?;

        if canonical == self.scan_root || canonical.starts_with(&self.scan_root) {
            Ok(canonical)
        } else {
            Err(format!(
                "scan path is outside approved root {}: {}",
                self.scan_root.display(),
                requested
            ))
        }
    }
}

/// Initialize scanner with patterns from aegis-patterns
///
/// Fails closed: a pattern that cannot compile aborts initialization rather
/// than returning a scanner that would silently approve everything.
///
/// # Errors
///
/// Returns an error when a bundled pattern definition cannot be converted into
/// a scanner pattern or cannot be compiled.
pub fn init_scanner() -> anyhow::Result<Scanner> {
    scanner_for(&Config::default()).map_err(anyhow::Error::msg)
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

/// Build a scanner over the shipped patterns with a configuration in force.
///
/// The configuration names the categories to scan, the severity threshold,
/// the anomaly detectors, and the path classes; the shipped pattern
/// corpus is always the rule set, because a configuration says what to
/// look for, not which rules to ship.
///
/// # Errors
///
/// Returns a message naming the reason the configuration was rejected —
/// an unknown category, a path-class rule whose glob does not compile, a
/// severity threshold no severity name matches, or an unknown anomaly
/// detector. The scanner is not built, so a rejected configuration leaves
/// the daemon serving the configuration it already had.
fn scanner_for(config: &Config) -> Result<Scanner, String> {
    let state = load_pattern_state(None)?;
    scanner_for_with_state(config, &state)
}

/// Build a scanner over the shipped patterns with a configuration in force
/// and a persisted pattern state applied.
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
/// the daemon serving the configuration it already had.
fn scanner_for_with_state(config: &Config, state: &PatternState) -> Result<Scanner, String> {
    // A rule whose glob does not compile classifies nothing, so the
    // configuration is rejected here instead of being applied as a silent
    // no-op: the caller learns that its path class never fired.
    for rule in &config.path_classes {
        rule.validate()?;
    }

    let mut configured = config.clone();
    configured.bundle = shipped_bundle();

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

    let scanner = scanner.with_options(options);
    // The state is applied before the first scan, so the extension scanners
    // the scanner caches are built from the narrowed registry.
    aegis_core::pattern_state::apply_to_registry(state, scanner.registry());
    Ok(scanner)
}

/// Read the persisted pattern state a daemon honors.
///
/// `path` is the file the daemon was pointed at; without one the daemon
/// honors no persisted state and scans with the shipped rule set.
///
/// # Errors
///
/// Returns a message naming the file when the state cannot be read or
/// parsed. A malformed state file is an error, never a silent fallback: an
/// ignored preference silently changes scan results.
fn load_pattern_state(path: Option<&Path>) -> Result<PatternState, String> {
    let Some(path) = path else {
        return Ok(PatternState::empty());
    };
    aegis_core::pattern_state::load(path).map_err(|error| error.to_string())
}

/// Daemon response
#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonResponse {
    /// Whether the request was served at all; `false` is always paired with a
    /// non-empty [`Self::error`] and never with findings.
    pub success: bool,
    /// Findings produced by the scan, already redacted of matched source text
    /// before they reach the socket; empty on failure.
    pub findings: Vec<Finding>,
    /// How many findings came back, reused by `list_patterns` to report the
    /// number of rules in the registry.
    pub finding_count: usize,
    /// Aggregated severity label computed over the findings, `"unknown"` when
    /// the request failed and `"none"` when nothing was inspected.
    pub risk_level: String,
    /// Numeric rollup of finding severities, `0` for an empty or failed scan.
    pub risk_score: i32,
    /// Coverage and timing ledger for the inspection; defaults when no files
    /// or content were actually read.
    pub stats: ScanStats,
    /// Signed-ish audit record tying the answer to a source, profile digest,
    /// and optional source revision; absent for errors and `list_patterns`.
    pub receipt: Option<ScanReceipt>,
    /// Human-readable reason the request was refused or failed, `None` on
    /// success.
    pub error: Option<String>,
}

impl DaemonResponse {
    /// Package a completed scan whose origin is the daemon itself, which is
    /// the attribution used when no more specific label applies.
    #[must_use]
    pub fn from_findings(findings: Vec<Finding>, stats: ScanStats) -> Self {
        Self::from_findings_with_source(findings, stats, "daemon")
    }

    /// Package a completed scan and record `source` in its receipt, so a
    /// `string:<label>` in-memory scan and a resolved filesystem path stay
    /// distinguishable in audit output. Risk is derived from the findings.
    pub fn from_findings_with_source(
        findings: Vec<Finding>,
        stats: ScanStats,
        source: impl Into<String>,
    ) -> Self {
        let risk = RiskScore::new(&findings, &HashMap::default(), &HashMap::default());
        let profile = "daemon-default";
        let receipt = ScanReceipt::from_scan(
            source,
            "daemon_scan",
            profile,
            Some(ScanReceipt::digest_text(profile)),
            &findings,
            stats.clone(),
        )
        .with_source_revision(env::var("AEGIS_SOURCE_REVISION").ok());
        Self {
            success: true,
            finding_count: findings.len(),
            findings,
            risk_level: risk.level.to_string(),
            risk_score: risk.score,
            stats,
            receipt: Some(receipt),
            error: None,
        }
    }

    /// Build the response sent when a request cannot be honored: no findings,
    /// no stats, no receipt, and an `"unknown"` risk level so a rejected
    /// request can never be mistaken for a clean scan.
    #[must_use]
    pub fn error(msg: String) -> Self {
        Self {
            success: false,
            findings: vec![],
            finding_count: 0,
            risk_level: "unknown".to_string(),
            risk_score: 0,
            stats: ScanStats::default(),
            receipt: None,
            error: Some(msg),
        }
    }
}

/// Handle a JSON-RPC style request
pub async fn handle_request(
    request: &serde_json::Value,
    state: &Arc<DaemonState>,
) -> DaemonResponse {
    let Some(method) = request.get("method").and_then(|v| v.as_str()) else {
        return DaemonResponse::error("Missing method".to_string());
    };

    let params = request.get("params");

    match method {
        "scan_string" => {
            if let Err(error) = state.prepare_scanner().await {
                return DaemonResponse::error(format!("scanner unavailable: {error}"));
            }
            let Some(serde_json::Value::Array(arr)) = params else {
                return DaemonResponse::error(
                    "scan_string requires [content, source] params".to_string(),
                );
            };
            let Some(content) = arr.first().and_then(|v| v.as_str()) else {
                return DaemonResponse::error("Missing content param".to_string());
            };
            let Some(source) = arr.get(1).and_then(|v| v.as_str()) else {
                return DaemonResponse::error("Missing source param".to_string());
            };

            let scanner = state.scanner.read().await;
            let findings = scanner.scan_string(content, source);
            let scan_stats = ScanStats::for_content(format!("string:{source}"), content.len());
            DaemonResponse::from_findings_with_source(
                findings,
                scan_stats,
                format!("string:{source}"),
            )
        }
        "scan_file" => {
            if let Err(error) = state.prepare_scanner().await {
                return DaemonResponse::error(format!("scanner unavailable: {error}"));
            }
            let Some(requested_path) = params.and_then(|v| v.as_str()) else {
                return DaemonResponse::error("Missing path param".to_string());
            };
            let path = match state.resolve_scan_path(requested_path) {
                Ok(path) => path,
                Err(error) => return DaemonResponse::error(error),
            };

            let scanner = state.scanner.read().await;
            match scanner.scan_file(&path) {
                Ok((findings, scan_stats)) => DaemonResponse::from_findings_with_source(
                    findings,
                    scan_stats,
                    path.to_string_lossy().to_string(),
                ),
                Err(e) => DaemonResponse::error(format!("Scan error: {e}")),
            }
        }
        "scan_dir" => {
            if let Err(error) = state.prepare_scanner().await {
                return DaemonResponse::error(format!("scanner unavailable: {error}"));
            }
            let Some(requested_path) = params.and_then(|v| v.as_str()) else {
                return DaemonResponse::error("Missing path param".to_string());
            };
            let path = match state.resolve_scan_path(requested_path) {
                Ok(path) => path,
                Err(error) => return DaemonResponse::error(error),
            };

            let scanner = state.scanner.read().await;
            match scanner.scan_dir(&path) {
                Ok((findings, scan_stats)) => DaemonResponse::from_findings(findings, scan_stats),
                Err(e) => DaemonResponse::error(format!("Scan error: {e}")),
            }
        }
        "scan_env" => {
            if let Err(error) = state.prepare_scanner().await {
                return DaemonResponse::error(format!("scanner unavailable: {error}"));
            }
            let scanner = state.scanner.read().await;
            let findings = scanner.scan_env();
            let scan_stats = ScanStats::for_environment();
            DaemonResponse::from_findings_with_source(findings, scan_stats, "environment")
        }
        "list_patterns" => {
            if let Err(error) = state.prepare_scanner().await {
                return DaemonResponse::error(format!("scanner unavailable: {error}"));
            }
            let scanner = state.scanner.read().await;
            // Count-only by contract: pattern metadata belongs to the MCP
            // server's `list_patterns`, which has a response shape for it.
            let pattern_count = scanner.registry().all().len();
            DaemonResponse {
                success: true,
                findings: vec![],
                finding_count: pattern_count,
                risk_level: "none".to_string(),
                risk_score: 0,
                stats: ScanStats::default(),
                receipt: None,
                error: None,
            }
        }
        "ping" => DaemonResponse::from_findings(vec![], ScanStats::default()),
        _ => DaemonResponse::error(format!("Unknown method: {method}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Arc;

    #[test]
    fn test_peer_policy_matches_owner_uid_and_explicit_lists() {
        let policy = DaemonPeerPolicy::from_allowlists(1000, Some("1001,1002"), Some("2000"))
            .expect("valid allowlists");
        assert!(policy.allows_credentials(1000, 9999));
        assert!(policy.allows_credentials(1001, 9999));
        assert!(policy.allows_credentials(9999, 2000));
        assert!(!policy.allows_credentials(1003, 2001));
        assert_eq!(policy.socket_mode(), 0o660);
    }

    #[test]
    fn test_peer_policy_rejects_invalid_allowlist() {
        let error = DaemonPeerPolicy::from_allowlists(1000, Some("1001,nope"), None)
            .expect_err("invalid UID must fail");
        assert!(error.to_string().contains("AEGIS_DAEMON_ALLOWED_UIDS"));
    }

    #[cfg(unix)]
    #[test]
    fn test_scan_root_rejects_traversal_and_external_symlink() {
        use std::os::unix::fs::symlink;

        let base = env::temp_dir().join(format!("aegis-daemon-boundary-{}", std::process::id()));
        let root = base.join("root");
        let outside = base.join("outside");
        fs::create_dir_all(&root).expect("create root");
        fs::create_dir_all(&outside).expect("create outside");
        fs::write(root.join("inside.txt"), b"safe").expect("create inside file");
        fs::write(outside.join("secret.txt"), b"outside").expect("create outside file");
        symlink(outside.join("secret.txt"), root.join("external-link.txt"))
            .expect("create external symlink");

        let state = DaemonState::with_scan_root(PathBuf::from("/tmp/test.sock"), &root);
        assert_eq!(
            state.resolve_scan_path("inside.txt").expect("inside path"),
            fs::canonicalize(root.join("inside.txt")).expect("canonical inside")
        );
        assert!(state.resolve_scan_path("../outside/secret.txt").is_err());
        assert!(state.resolve_scan_path("external-link.txt").is_err());

        fs::remove_dir_all(base).expect("cleanup boundary fixture");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_scan_request_rejects_path_outside_approved_root() {
        let base = env::temp_dir().join(format!(
            "aegis-daemon-boundary-request-{}",
            std::process::id()
        ));
        let root = base.join("root");
        fs::create_dir_all(&root).expect("create root");
        fs::write(base.join("outside.txt"), b"outside").expect("create outside file");
        let state = Arc::new(DaemonState::with_scan_root(
            PathBuf::from("/tmp/test.sock"),
            &root,
        ));
        let request = serde_json::json!({
            "method": "scan_file",
            "params": "../outside.txt",
            "id": 12
        });

        let response = handle_request(&request, &state).await;
        assert!(!response.success);
        assert!(response.error.unwrap().contains("outside approved root"));

        fs::remove_dir_all(base).expect("cleanup boundary fixture");
    }

    #[tokio::test]
    async fn test_ping() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        // Initialize scanner
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner().expect("bundled patterns compile");
        }

        let request = serde_json::json!({
            "method": "ping",
            "params": [],
            "id": 1
        });

        let response = handle_request(&request, &state).await;
        assert!(response.success);
        assert_eq!(response.finding_count, 0);
    }

    #[tokio::test]
    async fn test_scan_string() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        // Initialize scanner
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner().expect("bundled patterns compile");
        }

        let request = serde_json::json!({
            "method": "scan_string",
            "params": ["aws_key: AKIAIOSFODNN7EXAMPLE", "test.txt"], // aegis:ignore:aws-access-key
            "id": 2
        });

        let response = handle_request(&request, &state).await;
        assert!(response.success);
        assert!(response.finding_count > 0, "Should detect AWS key");
    }

    #[tokio::test]
    async fn test_scan_string_no_findings() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner().expect("bundled patterns compile");
        }

        let request = serde_json::json!({
            "method": "scan_string",
            "params": ["fn main() { println!(\"hello\"); }", "test.rs"],
            "id": 3
        });

        let response = handle_request(&request, &state).await;
        assert!(response.success);
        assert_eq!(response.finding_count, 0);
    }

    #[tokio::test]
    async fn test_missing_method() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner().expect("bundled patterns compile");
        }

        let request = serde_json::json!({
            "params": [],
            "id": 4
        });

        let response = handle_request(&request, &state).await;
        assert!(!response.success);
        assert!(response.error.is_some());
    }

    #[tokio::test]
    async fn test_unknown_method() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner().expect("bundled patterns compile");
        }

        let request = serde_json::json!({
            "method": "unknown_method",
            "params": [],
            "id": 5
        });

        let response = handle_request(&request, &state).await;
        assert!(!response.success);
        assert!(response.error.unwrap().contains("Unknown method"));
    }

    #[tokio::test]
    async fn test_list_patterns() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner().expect("bundled patterns compile");
        }

        let request = serde_json::json!({
            "method": "list_patterns",
            "params": null,
            "id": 6
        });

        let response = handle_request(&request, &state).await;
        assert!(response.success);
        assert!(response.finding_count > 0, "Should have patterns");
    }

    #[test]
    fn test_daemon_response_error() {
        let response = DaemonResponse::error("test error".to_string());
        assert!(!response.success);
        assert_eq!(response.error, Some("test error".to_string()));
    }

    #[test]
    fn test_daemon_response_from_findings() {
        let findings = vec![];
        let stats = ScanStats::default();
        let response = DaemonResponse::from_findings(findings, stats);
        assert!(response.success);
        assert_eq!(response.finding_count, 0);
        assert!(response.receipt.is_some());
    }

    #[test]
    fn test_daemon_response_error_message() {
        let response = DaemonResponse::error("Connection refused".to_string());
        assert!(!response.success);
        assert!(response.error.unwrap().contains("Connection refused"));
    }

    #[test]
    fn test_daemon_state_new() {
        let state = DaemonState::new(PathBuf::from("/tmp/test.sock"));
        assert_eq!(state.socket_path, PathBuf::from("/tmp/test.sock"));
    }

    #[test]
    fn test_init_scanner() {
        let scanner = init_scanner().expect("bundled patterns compile");
        let registry = scanner.registry();
        let patterns = registry.all();
        assert!(!patterns.is_empty(), "Scanner should have patterns loaded");
    }

    #[tokio::test]
    async fn test_handle_request_scan_env() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner().expect("bundled patterns compile");
        }

        let request = serde_json::json!({
            "method": "scan_env",
            "params": null,
            "id": 7
        });

        let response = handle_request(&request, &state).await;
        assert!(response.success);
    }

    #[tokio::test]
    async fn test_handle_request_missing_content() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner().expect("bundled patterns compile");
        }

        // scan_string with no content param
        let request = serde_json::json!({
            "method": "scan_string",
            "params": [],
            "id": 8
        });

        let response = handle_request(&request, &state).await;
        assert!(!response.success);
        assert!(response.error.unwrap().contains("Missing content"));
    }

    #[tokio::test]
    async fn test_handle_request_missing_source() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner().expect("bundled patterns compile");
        }

        // scan_string with content but no source
        let request = serde_json::json!({
            "method": "scan_string",
            "params": ["some content"],
            "id": 9
        });

        let response = handle_request(&request, &state).await;
        assert!(!response.success);
        assert!(response.error.unwrap().contains("Missing source"));
    }

    #[tokio::test]
    async fn test_handle_request_scan_file_invalid_params() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner().expect("bundled patterns compile");
        }

        let request = serde_json::json!({
            "method": "scan_file",
            "params": null,
            "id": 10
        });

        let response = handle_request(&request, &state).await;
        assert!(!response.success);
    }

    #[tokio::test]
    async fn test_handle_request_scan_dir_invalid_params() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_scanner().expect("bundled patterns compile");
        }

        let request = serde_json::json!({
            "method": "scan_dir",
            "params": 123, // Should be string
            "id": 11
        });

        let response = handle_request(&request, &state).await;
        assert!(!response.success);
    }

    /// Requests that rely on lazy pattern compilation: none of these tests
    /// pre-seed the scanner, so `ensure_patterns_loaded` is what populates
    /// the registry.
    #[tokio::test]
    async fn lazy_patterns_load_on_first_request() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        let request = serde_json::json!({ "method": "scan_env", "params": [], "id": 20 });

        let response = handle_request(&request, &state).await;
        assert!(response.success, "scan_env: {:?}", response.error);
        // The registry loaded lazily, so the environment was actually
        // scanned against the full corpus (the test process env itself may
        // legitimately contain matches, so only the shape is asserted).
    }

    #[tokio::test]
    async fn scan_file_within_root_reports_findings() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("leak.txt"),
            concat!("token = \"ghp_", "0123456789abcdefghijklmnopqrstuvwxyzAB\""),
        )
        .expect("write fixture");

        let state = Arc::new(DaemonState::with_scan_root(
            PathBuf::from("/tmp/test.sock"),
            dir.path(),
        ));
        let request = serde_json::json!({
            "method": "scan_file",
            "params": "leak.txt",
            "id": 21
        });

        let response = handle_request(&request, &state).await;
        assert!(response.success, "scan_file: {:?}", response.error);
        assert!(response.finding_count > 0, "leaked token must be detected");
    }

    #[tokio::test]
    async fn scan_file_against_a_directory_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = Arc::new(DaemonState::with_scan_root(
            PathBuf::from("/tmp/test.sock"),
            dir.path(),
        ));
        let request = serde_json::json!({
            "method": "scan_file",
            "params": ".",
            "id": 22
        });

        let response = handle_request(&request, &state).await;
        assert!(!response.success);
        assert!(response.error.unwrap().contains("Scan error"));
    }

    #[tokio::test]
    async fn scan_dir_within_root_reports_findings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).expect("mkdir");
        // The console.log line gives the test a finding to assert on; the
        // credential line is a synthetic fixture, suppressed on its own line.
        fs::write(
            nested.join("leak.txt"),
            "console.log(\"debug\");\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI\n", // aegis:ignore:aws-secret-key,env-credential-assignment -- synthetic fixtures
        )
        .expect("write");

        let state = Arc::new(DaemonState::with_scan_root(
            PathBuf::from("/tmp/test.sock"),
            dir.path(),
        ));
        let request = serde_json::json!({ "method": "scan_dir", "params": ".", "id": 23 });

        let response = handle_request(&request, &state).await;
        assert!(response.success, "scan_dir: {:?}", response.error);
        assert!(
            response.finding_count > 0,
            "finding in nested fixture must be reported"
        );
    }

    #[tokio::test]
    async fn scan_string_rejects_malformed_params() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));

        // params is not an array
        let not_array = serde_json::json!({ "method": "scan_string", "params": "text" });
        let response = handle_request(&not_array, &state).await;
        assert!(response
            .error
            .unwrap()
            .contains("requires [content, source]"));

        // array without a string content element
        let no_content = serde_json::json!({ "method": "scan_string", "params": [42, "src"] });
        let response = handle_request(&no_content, &state).await;
        assert!(response.error.unwrap().contains("Missing content"));

        // array without a source element
        let no_source = serde_json::json!({ "method": "scan_string", "params": ["text"] });
        let response = handle_request(&no_source, &state).await;
        assert!(response.error.unwrap().contains("Missing source"));
    }

    #[tokio::test]
    async fn requests_without_a_method_string_are_rejected() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));

        let no_method = serde_json::json!({ "params": [] });
        let response = handle_request(&no_method, &state).await;
        assert!(!response.success);
        assert_eq!(response.error.as_deref(), Some("Missing method"));

        let method_not_string = serde_json::json!({ "method": 7 });
        let response = handle_request(&method_not_string, &state).await;
        assert_eq!(response.error.as_deref(), Some("Missing method"));
    }

    #[tokio::test]
    async fn error_responses_carry_the_message_and_defaults() {
        let response = DaemonResponse::error("boom".to_string());
        assert!(!response.success);
        assert_eq!(response.error.as_deref(), Some("boom"));
        assert_eq!(response.finding_count, 0);
        assert_eq!(response.risk_level, "unknown");
        assert_eq!(response.risk_score, 0);

        let from_findings =
            DaemonResponse::from_findings_with_source(vec![], ScanStats::default(), "unit-test");
        assert!(from_findings.success);
    }

    #[cfg(unix)]
    #[test]
    fn allowlist_policy_honors_uid_and_gid_entries() {
        let policy =
            DaemonPeerPolicy::from_allowlists(42, None, Some("7,8")).expect("valid allowlists");
        assert!(policy.allows_credentials(42, 1_000));
        assert!(policy.allows_credentials(43, 7));
        assert!(!policy.allows_credentials(43, 9));
        assert_eq!(policy.socket_mode(), 0o660);
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
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
        let request = serde_json::json!({
            "method": "scan_string",
            "params": [mixed_category_fixture(), "test.txt"],
            "id": 30
        });

        let unconfigured = handle_request(&request, &state).await;
        assert!(
            unconfigured.success,
            "scan_string: {:?}",
            unconfigured.error
        );
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

        let configured = handle_request(&request, &state).await;
        assert!(configured.success, "scan_string: {:?}", configured.error);
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
            let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
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

            let request = serde_json::json!({
                "method": "scan_string",
                "params": [mixed_category_fixture(), "test.txt"],
                "id": 32
            });
            let response = handle_request(&request, &state).await;
            assert!(response.success, "scan_string: {:?}", response.error);
            assert!(
                response
                    .findings
                    .iter()
                    .all(|finding| finding.category == "secrets"),
                "the configuration in force is the one that was applied: {:?}",
                response
                    .findings
                    .iter()
                    .map(|finding| finding.category.as_str())
                    .collect::<Vec<_>>()
            );
        }
    }

    #[tokio::test]
    async fn a_configured_path_class_lowers_a_documentation_finding() {
        let dir = tempfile::tempdir().expect("tempdir");
        let docs = dir.path().join("docs");
        fs::create_dir(&docs).expect("mkdir");
        fs::write(docs.join("example.md"), mixed_category_fixture()).expect("write fixture");

        let state = Arc::new(DaemonState::with_scan_root(
            PathBuf::from("/tmp/test.sock"),
            dir.path(),
        ));
        let config = Config {
            path_classes: vec![
                aegis_core::PathClassRule::new("docs/**", "docs").expect("valid rule")
            ],
            ..Config::default()
        };
        state
            .set_config(config)
            .await
            .expect("configuration applies");

        let request = serde_json::json!({
            "method": "scan_file",
            "params": "docs/example.md",
            "id": 31
        });
        let response = handle_request(&request, &state).await;
        assert!(response.success, "scan_file: {:?}", response.error);

        let finding = response
            .findings
            .iter()
            .find(|finding| finding.category == "web-security")
            .expect("the documentation file must still report the finding");
        assert_eq!(finding.severity, "low", "a classed path reports as low");
        assert!(
            finding.tags.iter().any(|tag| tag == "docs"),
            "the class is recorded on the finding: {:?}",
            finding.tags
        );
    }

    #[tokio::test]
    async fn a_configuration_with_an_uncompilable_path_class_is_rejected() {
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
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
        let state = Arc::new(DaemonState::new(PathBuf::from("/tmp/test.sock")));
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
    async fn a_disabled_pattern_stops_firing_on_the_next_request() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_file = dir.path().join("pattern-state.json");
        let state = Arc::new(
            DaemonState::new(PathBuf::from("/tmp/test.sock"))
                .with_pattern_state(state_file.clone()),
        );
        let request = serde_json::json!({
            "method": "scan_string",
            "params": [mixed_category_fixture(), "test.txt"],
            "id": 40
        });

        let before = handle_request(&request, &state).await;
        assert!(before.success, "scan_string: {:?}", before.error);
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

        let mut document = PatternState::empty();
        document
            .disabled_patterns
            .insert("gitlab-token".to_string());
        aegis_core::pattern_state::save(&state_file, &document).expect("the state is written");

        let after = handle_request(&request, &state).await;
        assert!(after.success, "scan_string: {:?}", after.error);
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
        fs::write(&state_file, "{not json").expect("write a malformed state");
        let state = Arc::new(
            DaemonState::new(PathBuf::from("/tmp/test.sock")).with_pattern_state(state_file),
        );
        let request = serde_json::json!({
            "method": "scan_string",
            "params": [mixed_category_fixture(), "test.txt"],
            "id": 41
        });

        let response = handle_request(&request, &state).await;
        assert!(!response.success, "a malformed state must not be ignored");
        assert!(
            response
                .error
                .as_deref()
                .is_some_and(|message| message.contains("pattern-state.json")),
            "the refusal names the file: {:?}",
            response.error
        );
    }
}
