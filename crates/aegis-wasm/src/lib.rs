//! Aegis WASM Library
//!
//! Provides WASM bindings for Aegis security scanning.
//! This allows running Aegis pattern matching in browser environments.

use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};

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

/// Scan content for patterns
///
/// # Arguments
/// * `content` - The text content to scan
/// * `source` - The source name/identifier for findings
///
/// # Returns
/// JSON string containing an array of findings
#[wasm_bindgen]
pub fn scan_content(content: &str, source: &str) -> String {
    let scanner = aegis_core::Scanner::new();

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

    serde_json::to_string(&wasm_findings).unwrap_or_else(|_| "[]".to_string())
}

/// Get the number of available patterns
#[wasm_bindgen]
pub fn get_pattern_count() -> usize {
    let scanner = aegis_core::Scanner::new();
    scanner.registry().len()
}
