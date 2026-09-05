//! MCP tools implementation

use super::*;

#[allow(dead_code)]
pub struct AegisTools;

impl AegisTools {
    /// Execute scan_string tool
    pub async fn scan_string(
        state: &ServerState,
        content: String,
        source: String,
    ) -> jsonrpc_core::Result<ScanResponse> {
        let scanner = state.scanner.read().await;
        let findings = scanner.scan_string(&content, &source);

        Ok(ScanResponse::for_string(findings, &source, content.len()))
    }

    /// Execute scan_file tool
    pub async fn scan_file(
        state: &ServerState,
        path: String,
    ) -> jsonrpc_core::Result<ScanResponse> {
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
        let (findings, stats) = scanner.scan_file(&path).map_err(|e| jsonrpc_core::Error {
            code: jsonrpc_core::ErrorCode::InternalError,
            message: e.to_string(),
            data: None,
        })?;

        Ok(ScanResponse::from_parts(
            findings,
            stats,
            path.to_string_lossy().to_string(),
        ))
    }

    /// Execute scan_dir tool
    pub async fn scan_dir(state: &ServerState, path: String) -> jsonrpc_core::Result<ScanResponse> {
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
        let (findings, stats) = scanner.scan_dir(&path).map_err(|e| jsonrpc_core::Error {
            code: jsonrpc_core::ErrorCode::InternalError,
            message: e.to_string(),
            data: None,
        })?;

        Ok(ScanResponse::from_parts(
            findings,
            stats,
            path.to_string_lossy().to_string(),
        ))
    }

    /// Execute scan_env tool
    pub async fn scan_env(state: &ServerState) -> jsonrpc_core::Result<ScanResponse> {
        let scanner = state.scanner.read().await;
        let findings = scanner.scan_env();

        Ok(ScanResponse::for_environment(findings))
    }

    /// List patterns
    pub async fn list_patterns(
        state: &ServerState,
        category: Option<String>,
    ) -> jsonrpc_core::Result<ListPatternsResponse> {
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
    pub async fn list_categories(state: &ServerState) -> jsonrpc_core::Result<Vec<String>> {
        let scanner = state.scanner.read().await;
        let registry = scanner.registry();
        Ok(registry.categories())
    }

    /// Update bundle
    #[allow(dead_code)]
    pub async fn update_bundle(
        state: &ServerState,
        _bundle_path: Option<String>,
        _force: bool,
    ) -> jsonrpc_core::Result<UpdateResponse> {
        // Note: The actual update_bundle implementation is in main.rs
        // This tool exists for potential future direct tool calls
        let scanner = state.scanner.read().await;
        let _ = scanner;
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

    fn init_test_scanner() -> Scanner {
        let patterns = aegis_patterns::all_patterns();
        let definitions: Vec<PatternDefinition> = patterns
            .into_iter()
            .map(|p| PatternDefinition {
                name: p.name,
                category: p.category,
                match_pattern: p.match_pattern,
                enabled: p.enabled,
                severity: aegis_core::Severity::parse(&p.severity)
                    .unwrap_or(aegis_core::Severity::Medium),
                confidence: aegis_core::Confidence::parse(&p.confidence)
                    .unwrap_or(aegis_core::Confidence::Medium),
                min_entropy: p.min_entropy,
                description: p.description,
                reference: p.reference,
                tags: p.tags,
                env_var: p.env_var,
                binary: p.binary,
            })
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
            "AWS_SECRET_KEY=abcdefghijk".to_string(),
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
        let result = AegisTools::scan_string(&state, "".to_string(), "empty.txt".to_string()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.finding_count, 0);
    }
}
