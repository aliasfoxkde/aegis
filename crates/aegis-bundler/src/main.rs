//! Aegis Bundler
//!
//! Tool to create pattern bundles from YAML definitions.

use anyhow::Result;
use std::path::Path;

pub use aegis_bundler::{create_bundle_from_dir, read_patterns_from_dir, Bundle, Pattern};

/// Build a bundle from `input_dir` and write the compressed artifact to
/// `output_file`. Split out of `main` so the argument handling is testable.
fn run(input_dir: &Path, output_file: &Path) -> Result<()> {
    println!("Building bundle from {}...", input_dir.display());

    let patterns = read_patterns_from_dir(input_dir)?;
    println!("  Found {} valid patterns", patterns.len());

    let bundle = aegis_bundler::create_bundle(patterns);
    let compressed = aegis_bundler::serialize_bundle(&bundle)?;

    std::fs::write(output_file, &compressed)?;

    println!(
        "Bundle written to {} ({} bytes)",
        output_file.display(),
        compressed.len()
    );

    Ok(())
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

    run(Path::new(&args[1]), Path::new(&args[2]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but valid pattern YAML, matching the bundler's schema: a
    /// top-level sequence of pattern definitions.
    const SAMPLE_PATTERN: &str = r#"
- name: sample-rule
  category: secrets
  match: "sample-secret-[a-z0-9]+"
  enabled: true
  severity: high
  confidence: high
  description: Bundler fixture rule for the CLI smoke test
"#;

    #[test]
    fn builds_and_writes_a_bundle_from_a_pattern_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("sample.yaml"), SAMPLE_PATTERN).expect("write pattern");
        let output = dir.path().join("sample.bundle");

        run(dir.path(), &output).expect("bundle build");
        let bytes = std::fs::read(&output).expect("bundle bytes");
        assert!(!bytes.is_empty(), "bundle artifact must not be empty");
    }

    #[test]
    fn refuses_to_bundle_a_missing_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = run(&dir.path().join("absent"), &dir.path().join("out.bundle"))
            .expect_err("missing input directory must error");
        assert!(!error.to_string().is_empty());
    }
}
