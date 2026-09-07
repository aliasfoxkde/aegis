//! Aegis WASM Library
//!
//! Provides WASM bindings for Aegis security scanning.
//! This allows running Aegis pattern matching in browser environments.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Location of a finding
#[derive(Serialize, Deserialize)]
pub struct WasmLocation {
    pub file: String,
    pub line: usize,
    pub column: usize,
}

/// A finding from the scanner
#[derive(Serialize, Deserialize)]
pub struct WasmFinding {
    pub pattern: String,
    pub category: String,
    pub severity: String,
    pub confidence: String,
    pub description: String,
    pub matched_text: String,
    pub location: WasmLocation,
}

/// Initialize the WASM module
#[wasm_bindgen(start)]
pub fn init() {
    // Set up panic hook for better error messages
    console_error_panic_hook::set_once();
}

/// The shared scanner over the full bundled pattern set.
///
/// Compilation is lazy (first call pays for it) and the result is reused
/// for every subsequent scan. On `wasm32` there is a single thread, so a
/// `OnceLock` is all the synchronization needed.
fn bundled_scanner() -> Result<&'static aegis_core::Scanner, JsError> {
    static SCANNER: OnceLock<Result<aegis_core::Scanner, String>> = OnceLock::new();

    match SCANNER.get_or_init(|| {
        let definitions: Vec<aegis_core::pattern::PatternDefinition> =
            aegis_patterns::all_patterns()
                .into_iter()
                .map(Into::into)
                .collect();
        aegis_core::Scanner::from_definitions(definitions).map_err(|e| e.to_string())
    }) {
        Ok(scanner) => Ok(scanner),
        Err(message) => Err(JsError::new(&format!(
            "bundled pattern compilation failed: {message}"
        ))),
    }
}

/// Scan content for patterns
///
/// # Arguments
/// * `content` - The text content to scan
/// * `source` - The source name/identifier for findings
///
/// # Returns
/// JSON string containing an array of findings. Throws a `JsError` if the
/// bundled patterns cannot be compiled — a broken bundle is a setup error,
/// not an empty result.
#[wasm_bindgen]
pub fn scan_content(content: &str, source: &str) -> Result<String, JsError> {
    let scanner = bundled_scanner()?;

    let findings = scanner.scan_string(content, source);

    let wasm_findings: Vec<WasmFinding> = findings
        .into_iter()
        .map(|f| WasmFinding {
            pattern: f.pattern,
            category: f.category,
            severity: f.severity,
            confidence: f.confidence,
            description: f.description,
            matched_text: f.matched_content,
            location: WasmLocation {
                file: f.location.file,
                line: f.location.line,
                column: f.location.column,
            },
        })
        .collect();

    serde_json::to_string(&wasm_findings)
        .map_err(|e| JsError::new(&format!("finding serialization failed: {e}")))
}

/// Get the number of available patterns
///
/// Throws a `JsError` if the bundled patterns cannot be compiled.
#[wasm_bindgen]
pub fn get_pattern_count() -> Result<usize, JsError> {
    let scanner = bundled_scanner()?;
    Ok(scanner.registry().len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The crate builds as an `rlib` too, so the bindings are exercised on
    /// the host: the same code path the browser calls, no wasm runtime
    /// required. Real `wasm32` coverage stays with the release build job.
    #[test]
    fn bundled_scanner_compiles_full_pattern_set() {
        let count = get_pattern_count().expect("bundled patterns must compile");
        assert!(count > 600, "unexpectedly small bundled registry: {count}");
    }

    #[test]
    fn scan_content_finds_a_leaked_credential() {
        let json =
            scan_content("key = \"AKIAIOSFODNN7EXAMPLE\"", "demo.js").expect("scan must succeed");
        let findings: Vec<WasmFinding> =
            serde_json::from_str(&json).expect("scan_content emits a finding array");
        assert!(
            findings
                .iter()
                .any(|f| f.pattern == "aws-access-key" && f.location.file == "demo.js"),
            "aws-access-key missing from {json}"
        );
    }

    #[test]
    fn scan_content_reports_nothing_for_benign_content() {
        let json = scan_content("fn main() { println!(\"Hello, World!\"); }", "main.rs")
            .expect("scan must succeed");
        let findings: Vec<WasmFinding> =
            serde_json::from_str(&json).expect("scan_content emits a finding array");
        assert!(findings.is_empty(), "unexpected findings: {json}");
    }

    #[test]
    fn finding_shape_survives_the_json_round_trip() {
        let json =
            scan_content("key = \"AKIAIOSFODNN7EXAMPLE\"", "demo.js").expect("scan must succeed");
        let findings: Vec<WasmFinding> =
            serde_json::from_str(&json).expect("scan_content emits a finding array");
        let f = &findings[0];
        assert!(!f.pattern.is_empty());
        assert!(!f.category.is_empty());
        assert!(!f.severity.is_empty());
        assert!(!f.description.is_empty());
        assert_eq!(f.location.line, 1);
    }
}
