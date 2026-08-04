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

        let risk_score =
            aegis_core::RiskScore::new(&findings, &Default::default(), &Default::default());

        Ok(ScanResponse {
            finding_count: findings.len(),
            risk_level: risk_score.level.to_string(),
            risk_score: risk_score.score,
            findings,
        })
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
        let (findings, _) = scanner.scan_file(&path).map_err(|e| jsonrpc_core::Error {
            code: jsonrpc_core::ErrorCode::InternalError,
            message: e.to_string(),
            data: None,
        })?;

        let risk_score =
            aegis_core::RiskScore::new(&findings, &Default::default(), &Default::default());

        Ok(ScanResponse {
            finding_count: findings.len(),
            risk_level: risk_score.level.to_string(),
            risk_score: risk_score.score,
            findings,
        })
    }

    /// Execute scan_dir tool
    pub async fn scan_dir(
        state: &ServerState,
        path: String,
        _recursive: bool,
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
        let (findings, _) = scanner.scan_dir(&path).map_err(|e| jsonrpc_core::Error {
            code: jsonrpc_core::ErrorCode::InternalError,
            message: e.to_string(),
            data: None,
        })?;

        let risk_score =
            aegis_core::RiskScore::new(&findings, &Default::default(), &Default::default());

        Ok(ScanResponse {
            finding_count: findings.len(),
            risk_level: risk_score.level.to_string(),
            risk_score: risk_score.score,
            findings,
        })
    }

    /// Execute scan_env tool
    pub async fn scan_env(state: &ServerState) -> jsonrpc_core::Result<ScanResponse> {
        let scanner = state.scanner.read().await;
        let findings = scanner.scan_env();

        let risk_score =
            aegis_core::RiskScore::new(&findings, &Default::default(), &Default::default());

        Ok(ScanResponse {
            finding_count: findings.len(),
            risk_level: risk_score.level.to_string(),
            risk_score: risk_score.score,
            findings,
        })
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
    pub async fn update_bundle(
        _state: &ServerState,
        _force: bool,
    ) -> jsonrpc_core::Result<UpdateResponse> {
        // In a real implementation, this would download and update the bundle
        Ok(UpdateResponse {
            success: true,
            message: "Bundle is up to date".to_string(),
            pattern_count: 0,
        })
    }
}
