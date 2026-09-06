//! Regenerate `docs/patterns/README.md` from the shipped pattern corpus.
//!
//! Run from the repository root:
//!
//! ```bash
//! cargo run -p aegis-patterns --example generate_docs
//! ```

use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // crates/aegis-patterns -> repo root -> docs/patterns
    let docs_dir = manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|root| root.join("docs").join("patterns"))
        .expect("crate must live inside the repository");

    std::fs::create_dir_all(&docs_dir)?;
    let target = docs_dir.join("README.md");
    std::fs::write(&target, aegis_patterns::docs::generate_pattern_docs())?;
    println!("wrote {}", target.display());
    Ok(())
}
