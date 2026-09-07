//! Aegis Daemon Library
//!
//! Core logic for the Aegis daemon.

use aegis_core::{Config, Finding, PatternDefinition, RiskScore, ScanReceipt, ScanStats, Scanner};
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
    pub scanner: RwLock<Scanner>,
    pub config: RwLock<Config>,
    pub socket_path: PathBuf,
    scan_root: PathBuf,
    /// Guards the one-time lazy compilation of the bundled patterns; the
    /// first scan request pays for it, startup does not. The memoized
    /// outcome keeps a failed compilation sticky — a scanner that silently
    /// holds zero patterns would approve everything, so requests must keep
    /// failing closed.
    patterns_init: tokio::sync::OnceCell<Result<(), String>>,
}

impl DaemonState {
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
        })
    }

    pub fn scan_root(&self) -> &Path {
        &self.scan_root
    }

    /// Compile the bundled patterns on first use instead of at startup.
    ///
    /// Compiling 600+ regexes is CPU-bound; `spawn_blocking` keeps it off
    /// the reactor, and the `OnceCell` makes concurrent first requests
    /// share one compilation. Fails closed: a compilation error is returned
    /// to every caller instead of degrading to a scanner with no patterns.
    ///
    /// # Errors
    ///
    /// Returns the failure message when the bundled patterns cannot be
    /// compiled, or when the compiling task panics or is cancelled before
    /// finishing. The outcome is memoized, so every later call observes the
    /// same error instead of retrying.
    pub async fn ensure_patterns_loaded(&self) -> Result<(), String> {
        self.patterns_init
            .get_or_init(|| async {
                let compiled: Result<Scanner, String> = tokio::task::spawn_blocking(init_scanner)
                    .await
                    .map_err(|error| format!("pattern compilation task failed: {error}"))
                    .and_then(|result| result.map_err(|error| error.to_string()));
                match compiled {
                    Ok(scanner) => {
                        *self.scanner.write().await = scanner;
                        Ok(())
                    }
                    Err(message) => Err(message),
                }
            })
            .await
            .clone()
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
    let definitions: Vec<PatternDefinition> = aegis_patterns::all_patterns()
        .into_iter()
        .map(Into::into)
        .collect();

    Scanner::from_definitions(definitions).map_err(anyhow::Error::from)
}

/// Daemon response
#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonResponse {
    pub success: bool,
    pub findings: Vec<Finding>,
    pub finding_count: usize,
    pub risk_level: String,
    pub risk_score: i32,
    pub stats: ScanStats,
    pub receipt: Option<ScanReceipt>,
    pub error: Option<String>,
}

impl DaemonResponse {
    #[must_use]
    pub fn from_findings(findings: Vec<Finding>, stats: ScanStats) -> Self {
        Self::from_findings_with_source(findings, stats, "daemon")
    }

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
            if let Err(error) = state.ensure_patterns_loaded().await {
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
            if let Err(error) = state.ensure_patterns_loaded().await {
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
            if let Err(error) = state.ensure_patterns_loaded().await {
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
            if let Err(error) = state.ensure_patterns_loaded().await {
                return DaemonResponse::error(format!("scanner unavailable: {error}"));
            }
            let scanner = state.scanner.read().await;
            let findings = scanner.scan_env();
            let scan_stats = ScanStats::for_environment();
            DaemonResponse::from_findings_with_source(findings, scan_stats, "environment")
        }
        "list_patterns" => {
            if let Err(error) = state.ensure_patterns_loaded().await {
                return DaemonResponse::error(format!("scanner unavailable: {error}"));
            }
            let scanner = state.scanner.read().await;
            let registry = scanner.registry();
            let patterns = registry.all();
            let _pattern_infos: Vec<_> = patterns
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "name": p.name(),
                        "category": p.category(),
                        "severity": p.severity().to_string(),
                        "confidence": p.confidence().to_string(),
                        "description": p.description()
                    })
                })
                .collect();
            DaemonResponse {
                success: true,
                findings: vec![],
                finding_count: patterns.len(),
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
        fs::write(
            nested.join("leak.txt"),
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI\n",
        )
        .expect("write");
        // aegis:ignore:aws-secret-key

        let state = Arc::new(DaemonState::with_scan_root(
            PathBuf::from("/tmp/test.sock"),
            dir.path(),
        ));
        let request = serde_json::json!({ "method": "scan_dir", "params": ".", "id": 23 });

        let response = handle_request(&request, &state).await;
        assert!(response.success, "scan_dir: {:?}", response.error);
        assert!(response.finding_count > 0, "nested leak must be found");
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
}
