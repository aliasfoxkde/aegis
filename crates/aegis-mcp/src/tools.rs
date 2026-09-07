//! MCP tools implementation

use super::{
    sandbox, ListPatternsResponse, PathBuf, PatternInfo, Result, ScanResponse, ServerState,
    UpdateResponse,
};

#[allow(dead_code)]
pub struct AegisTools;

impl AegisTools {
    /// Execute scan_string tool
    ///
    /// # Errors
    /// Never fails: string scanning is in-memory and infallible, so every
    /// finding is reported in the returned response.
    pub async fn scan_string(
        state: &ServerState,
        content: String,
        source: String,
    ) -> Result<ScanResponse> {
        let scanner = state.scanner.read().await;
        let findings = scanner.scan_string(&content, &source);

        Ok(ScanResponse::for_string(findings, &source, content.len()))
    }

    /// Execute scan_file tool
    ///
    /// # Errors
    /// Returns `InvalidParams` when `path` falls outside the sandbox, and
    /// `InternalError` when the file cannot be read or scanned (missing
    /// file, permission denied, malformed content).
    pub async fn scan_file(state: &ServerState, path: String) -> Result<ScanResponse> {
        let path = PathBuf::from(&path);

        // Security: validate path
        if !sandbox::is_path_safe(&path) {
            return Err(jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::InvalidParams,
                message: "Path is outside allowed directory".to_string(),
                data: None,
            });
        }

        let scanner = state.scanner.read().await;
        let (findings, scan_stats) = scanner.scan_file(&path).map_err(|e| jsonrpc_core::Error {
            code: jsonrpc_core::ErrorCode::InternalError,
            message: e.to_string(),
            data: None,
        })?;

        Ok(ScanResponse::from_parts(
            findings,
            scan_stats,
            path.to_string_lossy().to_string(),
        ))
    }

    /// Execute scan_dir tool
    ///
    /// # Errors
    /// Returns `InvalidParams` when `path` falls outside the sandbox, and
    /// `InternalError` when the directory walk fails (missing directory,
    /// permission denied while descending into it).
    pub async fn scan_dir(state: &ServerState, path: String) -> Result<ScanResponse> {
        let path = PathBuf::from(&path);

        // Security: validate path
        if !sandbox::is_path_safe(&path) {
            return Err(jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::InvalidParams,
                message: "Path is outside allowed directory".to_string(),
                data: None,
            });
        }

        let scanner = state.scanner.read().await;
        let (findings, scan_stats) = scanner.scan_dir(&path).map_err(|e| jsonrpc_core::Error {
            code: jsonrpc_core::ErrorCode::InternalError,
            message: e.to_string(),
            data: None,
        })?;

        Ok(ScanResponse::from_parts(
            findings,
            scan_stats,
            path.to_string_lossy().to_string(),
        ))
    }

    /// Execute scan_env tool
    ///
    /// # Errors
    /// Never fails: the environment scan only reads process variables, so
    /// every finding is reported in the returned response.
    pub async fn scan_env(state: &ServerState) -> Result<ScanResponse> {
        let scanner = state.scanner.read().await;
        let findings = scanner.scan_env();

        Ok(ScanResponse::for_environment(findings))
    }

    /// List patterns
    ///
    /// # Errors
    /// Never fails: an unknown category simply yields an empty pattern list.
    pub async fn list_patterns(
        state: &ServerState,
        category: Option<String>,
    ) -> Result<ListPatternsResponse> {
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
    }

    /// List categories
    ///
    /// # Errors
    /// Never fails: categories are derived from the in-memory registry.
    pub async fn list_categories(state: &ServerState) -> Result<Vec<String>> {
        let scanner = state.scanner.read().await;
        let registry = scanner.registry();
        Ok(registry.categories())
    }

    /// Update bundle
    ///
    /// # Errors
    /// Never fails: bundle updates run through the RPC method, so this
    /// stub always answers with a pointer to that implementation.
    #[allow(dead_code)]
    pub async fn update_bundle(
        state: &ServerState,
        _bundle_path: Option<String>,
        _force: bool,
    ) -> Result<UpdateResponse> {
        // Note: The actual update_bundle implementation is in main.rs
        // This tool exists for potential future direct tool calls
        // Take the scanner lock like the real tools do; the swap itself
        // lives in the RPC method.
        let _scanner_guard = state.scanner.read().await;
        Ok(UpdateResponse {
            success: true,
            message: "Use RPC update_bundle method".to_string(),
            pattern_count: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::{PatternDefinition, Scanner};
    use std::sync::Arc;

    fn init_test_scanner() -> Scanner {
        // The canonical `From<Pattern>` conversion keeps this harness in
        // lockstep with the production scanners.
        let definitions: Vec<PatternDefinition> = aegis_patterns::all_patterns()
            .into_iter()
            .map(Into::into)
            .collect();
        Scanner::from_definitions(definitions).unwrap_or_else(|_| Scanner::new())
    }

    fn create_test_state() -> Arc<ServerState> {
        Arc::new(ServerState::new())
    }

    #[tokio::test]
    async fn test_tools_scan_string() {
        let state = create_test_state();
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_test_scanner();
        }
        let result =
            AegisTools::scan_string(&state, "test content".to_string(), "test.txt".to_string())
                .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_tools_scan_string_with_secret() {
        let state = create_test_state();
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_test_scanner();
        }
        let result = AegisTools::scan_string(
            &state,
            "AWS_SECRET_KEY=abcdefghijk".to_string(), // aegis:ignore:env-credential-assignment
            "test.txt".to_string(),
        )
        .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.finding_count > 0);
    }

    #[tokio::test]
    async fn test_tools_scan_file_unsafe_path() {
        let state = create_test_state();
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_test_scanner();
        }
        // /etc/passwd should be blocked by sandbox
        let result = AegisTools::scan_file(&state, "/etc/passwd".to_string()).await;
        assert!(result.is_err()); // Should return error for unsafe path
    }

    #[tokio::test]
    async fn test_tools_scan_dir_unsafe_path() {
        let state = create_test_state();
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_test_scanner();
        }
        let result = AegisTools::scan_dir(&state, "/etc".to_string()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tools_scan_env() {
        let state = create_test_state();
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_test_scanner();
        }
        let result = AegisTools::scan_env(&state).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_tools_list_patterns() {
        let state = create_test_state();
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_test_scanner();
        }
        let result = AegisTools::list_patterns(&state, None).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.total > 0);
    }

    #[tokio::test]
    async fn test_tools_list_patterns_by_category() {
        let state = create_test_state();
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_test_scanner();
        }
        let result = AegisTools::list_patterns(&state, Some("secrets".to_string())).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.total > 0);
    }

    #[tokio::test]
    async fn test_tools_list_categories() {
        let state = create_test_state();
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_test_scanner();
        }
        let result = AegisTools::list_categories(&state).await;
        assert!(result.is_ok());
        let categories = result.unwrap();
        assert!(!categories.is_empty());
    }

    #[tokio::test]
    async fn test_tools_update_bundle() {
        let state = create_test_state();
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_test_scanner();
        }
        let result = AegisTools::update_bundle(&state, None, false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_tools_scan_string_empty() {
        let state = create_test_state();
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_test_scanner();
        }
        let result = AegisTools::scan_string(&state, String::new(), "empty.txt".to_string()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.finding_count, 0);
    }

    #[tokio::test]
    async fn scan_file_inside_cwd_reports_findings_and_stats() {
        let state = create_test_state();
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_test_scanner();
        }

        // `temp/` is inside the sandbox cwd and gitignored.
        let fixture_dir = PathBuf::from("temp/mcp-fixtures");
        std::fs::create_dir_all(&fixture_dir).expect("create fixture dir");
        std::fs::write(
            fixture_dir.join("leak.txt"),
            concat!("token = \"ghp_", "0123456789abcdefghijklmnopqrstuvwxyzAB\""),
        )
        .expect("write fixture");

        let result = AegisTools::scan_file(&state, "temp/mcp-fixtures/leak.txt".to_string()).await;
        let _removed = std::fs::remove_dir_all(&fixture_dir);

        let response = result.expect("scan_file inside cwd must succeed");
        assert!(response.finding_count > 0, "leaked token must be detected");
    }

    #[tokio::test]
    async fn scan_file_missing_file_maps_to_internal_error() {
        let state = create_test_state();
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_test_scanner();
        }

        // Nonexistent but inside cwd: the sandbox allows it, the scan fails.
        let result = AegisTools::scan_file(&state, "temp/absent-file.txt".to_string()).await;
        let error = result.expect_err("missing file must surface an error");
        assert_eq!(error.code, jsonrpc_core::ErrorCode::InternalError);
    }

    #[tokio::test]
    async fn scan_dir_inside_cwd_reports_findings() {
        let state = create_test_state();
        {
            let mut scanner = state.scanner.write().await;
            *scanner = init_test_scanner();
        }

        let fixture_dir = PathBuf::from("temp/mcp-dir-fixture");
        std::fs::create_dir_all(&fixture_dir).expect("create fixture dir");
        std::fs::write(
            fixture_dir.join("creds.txt"),
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI\n",
        )
        .expect("write fixture"); // aegis:ignore:aws-secret-key

        let result = AegisTools::scan_dir(&state, "temp/mcp-dir-fixture".to_string()).await;
        let _removed = std::fs::remove_dir_all(&fixture_dir);

        let response = result.expect("scan_dir inside cwd must succeed");
        assert!(response.finding_count > 0, "nested leak must be found");
    }
}
