//! Aegis CLI
//!
//! Command-line interface for Aegis security scanning.

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

mod config;
pub mod output;
mod scanner;

#[derive(Parser)]
#[command(name = "aegis")]
#[command(version = "0.1.0")]
#[command(about = "Aegis - Security scanning for DevOps and CI/CD", long_about = None)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output format
    #[arg(short, long, value_enum, default_value = "human")]
    format: OutputFormat,

    /// Configuration profile
    #[arg(short, long)]
    config: Option<String>,

    /// Suppress output except findings
    #[arg(short, long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
    Sarif,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan files or directories
    Scan {
        /// Path to scan
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Scan a single file
        #[arg(short, long)]
        file: bool,

        /// Scan environment variables
        #[arg(short, long)]
        env: bool,

        /// Scan from stdin
        #[arg(short, long)]
        stdin: bool,

        /// Follow symbolic links
        #[arg(long)]
        follow_symlinks: bool,

        /// Categories to include
        #[arg(long)]
        categories: Option<String>,

        /// Severity threshold
        #[arg(long)]
        severity_threshold: Option<String>,

        /// Output file
        #[arg(long)]
        output_file: Option<PathBuf>,

        /// Baseline file for diff
        #[arg(long)]
        baseline: Option<PathBuf>,
    },

    /// List patterns
    List {
        /// List only enabled patterns
        #[arg(long)]
        enabled: bool,

        /// List only disabled patterns
        #[arg(long)]
        disabled: bool,

        /// Filter by category
        #[arg(long)]
        category: Option<String>,
    },

    /// Enable a pattern
    Enable {
        /// Pattern name
        pattern: String,
    },

    /// Disable a pattern
    Disable {
        /// Pattern name
        pattern: String,
    },

    /// Update pattern bundle
    Update {
        /// Force update even if cached
        #[arg(short, long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("aegis=debug")
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter("aegis=info")
            .init();
    }

    match cli.command {
        Commands::Scan {
            path,
            file,
            env,
            stdin,
            follow_symlinks,
            categories,
            severity_threshold,
            output_file,
            baseline,
        } => {
            scanner::run_scan(scanner::ScanOptions {
                path,
                scan_file: file,
                scan_env: env,
                scan_stdin: stdin,
                follow_symlinks,
                categories,
                severity_threshold,
                output_file,
                baseline,
                format: cli.format,
                quiet: cli.quiet,
            })
            .await?;
        }
        Commands::List {
            enabled,
            disabled,
            category,
        } => {
            output::list_patterns(enabled, disabled, category)?;
        }
        Commands::Enable { pattern } => {
            config::enable_pattern(&pattern)?;
            println!("Enabled pattern: {}", pattern);
        }
        Commands::Disable { pattern } => {
            config::disable_pattern(&pattern)?;
            println!("Disabled pattern: {}", pattern);
        }
        Commands::Update { force } => {
            scanner::update_bundle(force).await?;
        }
    }

    Ok(())
}
