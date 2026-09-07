//! Aegis CLI Library
//!
//! This library exposes internal components for testing.

pub mod benchmark;
pub mod config;
pub mod output;
pub mod scanner;

pub use benchmark::{run_benchmark, BenchmarkOptions};
pub use config::{
    disable_pattern, disable_pattern_message, enable_pattern, enable_pattern_message, load_config,
    resolve_profile, save_config,
};
pub use output::Output;
pub use scanner::{
    execute_scan, execute_scan_with_stdin, run_scan_and_get_exit_code, update_bundle, ScanOptions,
};

use clap::ValueEnum;

/// Output format options
#[derive(Clone, Debug, ValueEnum)]
pub enum OutputFormat {
    /// Colorized console report with the risk summary, per-finding lines, and
    /// stats footer.
    Human,
    /// Machine-readable document holding findings plus scan stats; the same
    /// shape a `--baseline` file is expected to carry.
    Json,
    /// SARIF 2.1.0 run for code-scanning platforms, carrying the inspection
    /// ledger as run properties.
    Sarif,
}

/// Adopt a profile's output format; both enums name the same three renders.
impl From<aegis_core::config::OutputFormat> for OutputFormat {
    fn from(format: aegis_core::config::OutputFormat) -> Self {
        match format {
            aegis_core::config::OutputFormat::Human => Self::Human,
            aegis_core::config::OutputFormat::Json => Self::Json,
            aegis_core::config::OutputFormat::Sarif => Self::Sarif,
        }
    }
}
