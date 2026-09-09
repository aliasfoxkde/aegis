//! Aegis CLI
//!
//! Command-line interface for Aegis security scanning.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use aegis_cli::{
    benchmark, config, disable_pattern_message, enable_pattern_message, output, scanner,
    OutputFormat,
};

#[derive(Parser)]
#[command(name = "aegis")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Aegis - Security scanning for DevOps and CI/CD", long_about = None)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output format
    #[arg(short, long, value_enum)]
    format: Option<OutputFormat>,

    /// Configuration profile: a built-in preset name (production, pipeline,
    /// development, mcp-integration) or a path to a JSON profile file.
    /// Flags given explicitly on the command line win over profile values.
    #[arg(short, long, global = true)]
    config: Option<String>,

    /// Suppress output except findings
    #[arg(short, long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
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

        /// Filter out findings recorded in this baseline (JSON output from
        /// a previous --format json scan); exit code reflects new findings only
        #[arg(long)]
        baseline: Option<PathBuf>,

        /// Include disabled patterns in scan
        #[arg(long)]
        all: bool,

        /// Diff file to scan (only changed lines)
        #[arg(long)]
        diff: Option<PathBuf>,

        /// Scan the staged (index) content of the git repository instead
        /// of files on disk — pre-commit mode; `[path]` selects the
        /// repository and defaults to the current directory
        #[arg(long)]
        staged: bool,

        /// Comma-separated statistical anomaly detectors to run
        /// (comment-ratio-outlier, comment-concentration,
        /// identifier-diversity-outlier, file-size-outlier)
        #[arg(long)]
        anomaly_detectors: Option<String>,

        /// Disable the statistical anomaly layer entirely
        #[arg(long)]
        no_anomalies: bool,
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

    /// Run benchmark comparison
    Benchmark {
        /// Path to scan
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Number of warmup runs
        #[arg(long, default_value = "1")]
        warmup: usize,

        /// Number of benchmark runs to average
        #[arg(long, default_value = "3")]
        runs: usize,

        /// Compare with Atheon-Enhanced if available
        #[arg(long)]
        compare: bool,
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
            all,
            diff,
            staged,
            anomaly_detectors,
            no_anomalies,
        } => {
            // A `-c/--config` profile supplies defaults for flags the
            // operator did not set; explicit flags always win.
            let profile = cli
                .config
                .as_deref()
                .map(config::resolve_profile)
                .transpose()?;
            let format = cli
                .format
                .or_else(|| {
                    profile
                        .as_ref()
                        .map(|profile| OutputFormat::from(profile.output_format))
                })
                .unwrap_or(OutputFormat::Human);
            let categories = categories.or_else(|| {
                profile
                    .as_ref()
                    .and_then(|profile| profile.enabled_categories.as_ref())
                    .filter(|enabled| !enabled.is_empty())
                    .map(|enabled| enabled.join(","))
            });
            let severity_threshold = severity_threshold.or_else(|| {
                profile
                    .as_ref()
                    .and_then(|profile| profile.severity_threshold.clone())
            });
            // --no-anomalies wins over --anomaly-detectors; both fall back
            // to the profile's `anomaly_detectors` list when unset.
            let anomaly_detectors = if no_anomalies {
                if anomaly_detectors.is_some() {
                    anyhow::bail!("--no-anomalies conflicts with --anomaly-detectors");
                }
                Some(String::new())
            } else {
                anomaly_detectors.or_else(|| {
                    profile
                        .as_ref()
                        .and_then(|profile| profile.anomaly_detectors.as_ref())
                        .map(|detectors| detectors.join(","))
                })
            };
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
                all,
                diff,
                staged,
                anomaly_detectors,
                format,
                quiet: cli.quiet,
            })
            .await?;
        }
        Commands::List {
            enabled,
            disabled,
            category,
        } => {
            println!(
                "{}",
                output::list_patterns(enabled, disabled, category.as_deref())?
            );
        }
        Commands::Enable { pattern } => {
            config::enable_pattern(&pattern)?;
            println!("{}", enable_pattern_message(&pattern));
        }
        Commands::Disable { pattern } => {
            config::disable_pattern(&pattern)?;
            println!("{}", disable_pattern_message(&pattern));
        }
        Commands::Update { force } => {
            scanner::update_bundle(force).await?;
        }
        Commands::Benchmark {
            path,
            warmup,
            runs,
            compare,
        } => {
            benchmark::run_benchmark(&benchmark::BenchmarkOptions {
                path,
                warmup,
                runs,
                compare,
            })?;
        }
    }

    Ok(())
}
