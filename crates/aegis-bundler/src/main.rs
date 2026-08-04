//! Aegis Bundler
//!
//! Tool to create pattern bundles from YAML definitions.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use walkdir::WalkDir;

#[derive(Debug, Serialize, Deserialize)]
struct Pattern {
    name: String,
    category: String,
    #[serde(rename = "match")]
    match_pattern: String,
    enabled: bool,
    severity: String,
    confidence: String,
    #[serde(default)]
    min_entropy: Option<f64>,
    description: String,
    #[serde(default)]
    reference: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    env_var: bool,
    #[serde(default)]
    binary: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Bundle {
    schema_version: u32,
    created_at: String,
    patterns: Vec<Pattern>,
}

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

    let mut patterns = Vec::new();

    // Walk the input directory
    for entry in WalkDir::new(&input_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }

        println!("  Processing {:?}", path);

        let content = std::fs::read_to_string(path)?;
        let yaml_patterns: Vec<Pattern> = serde_yaml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse {:?}: {}", path, e))?;

        for yaml_pat in yaml_patterns {
            // Validate regex
            if regex::Regex::new(&yaml_pat.match_pattern).is_err() {
                eprintln!("  Warning: Invalid regex in pattern '{}'", yaml_pat.name);
                continue;
            }

            patterns.push(yaml_pat);
        }
    }

    // Create bundle
    let bundle = Bundle {
        schema_version: 2,
        created_at: format!(
            "{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ),
        patterns,
    };

    // Serialize to JSON
    let json = serde_json::to_string(&bundle)?;

    // Compress with gzip using flate2
    use flate2::write::GzEncoder;
    use flate2::Compression;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    use std::io::Write;
    encoder.write_all(json.as_bytes())?;
    let compressed = encoder.finish()?;

    // Write to output
    std::fs::write(&output_file, &compressed)?;

    println!(
        "Bundle written to {:?} ({} bytes)",
        output_file,
        compressed.len()
    );

    Ok(())
}
