//! Regenerate the pattern documentation under `docs/patterns/` from the
//! shipped pattern corpus: the high-level `README.md` index plus one
//! detail page per category in `categories/`. Category pages that no
//! longer correspond to a shipped category are removed, so the directory
//! never accumulates stale pages.
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
    let categories_dir = docs_dir.join("categories");

    std::fs::create_dir_all(&categories_dir)?;

    let index = docs_dir.join("README.md");
    std::fs::write(&index, aegis_patterns::docs::generate_pattern_index())?;
    println!("wrote {}", index.display());

    let pages = aegis_patterns::docs::generate_category_docs();
    for (category, document) in &pages {
        let target = categories_dir.join(format!("{category}.md"));
        std::fs::write(&target, document)?;
        println!("wrote {}", target.display());
    }

    // Drop pages for categories that no longer exist so the committed
    // tree matches the generated set exactly (the freshness test
    // enforces the same invariant).
    for entry in std::fs::read_dir(&categories_dir)? {
        let entry = entry?;
        let path = entry.path();
        let is_stale_page = path.extension().is_some_and(|ext| ext == "md")
            && !pages.contains_key(
                path.file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or_default(),
            );
        if is_stale_page {
            println!("removing stale {}", path.display());
            std::fs::remove_file(&path)?;
        }
    }

    Ok(())
}
