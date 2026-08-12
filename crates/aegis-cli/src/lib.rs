//! Aegis CLI Library
//!
//! This library exposes internal components for testing.

pub mod config;
pub mod output;
pub mod scanner;

pub use config::{
    disable_pattern, disable_pattern_message, enable_pattern, enable_pattern_message, load_config,
    save_config,
};
pub use output::Output;
pub use scanner::{
    convert_pattern, execute_scan, execute_scan_with_stdin, run_scan_and_get_exit_code,
    update_bundle, ScanOptions,
};

use clap::ValueEnum;

/// Output format options
#[derive(Clone, Debug, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
    Sarif,
}
