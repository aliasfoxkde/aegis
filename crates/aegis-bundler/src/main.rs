//! Aegis Bundler
//!
//! Tool to create pattern bundles from YAML definitions.

use anyhow::Result;
use std::path::PathBuf;

pub use aegis_bundler::{create_bundle_from_dir, read_patterns_from_dir, Bundle, Pattern};

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("aegis=info")
        .init();

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        println!("Usage: aegis-bundler <input_dir> <output_file>");
        return Ok(());
    }

    let input_dir = PathBuf::from(&args[1]);
    let output_file = PathBuf::from(&args[2]);

    println!("Building bundle from {:?}...", input_dir);

    let patterns = read_patterns_from_dir(&input_dir)?;
    println!("  Found {} valid patterns", patterns.len());

    let bundle = aegis_bundler::create_bundle(patterns);
    let compressed = aegis_bundler::serialize_bundle(&bundle)?;

    std::fs::write(&output_file, &compressed)?;

    println!(
        "Bundle written to {:?} ({} bytes)",
        output_file,
        compressed.len()
    );

    Ok(())
}
