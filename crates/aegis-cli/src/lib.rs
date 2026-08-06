//! Aegis CLI Library
//!
//! This library exposes internal components for testing.

pub mod config;
pub mod output;
pub mod scanner;

pub use config::{disable_pattern, enable_pattern, load_config, save_config};
pub use output::Output;
pub use scanner::{convert_pattern, update_bundle, ScanOptions};

use clap::ValueEnum;

/// Output format options
#[derive(Clone, Debug, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
    Sarif,
}
