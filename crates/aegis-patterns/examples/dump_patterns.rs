//! Dump every bundled pattern as JSON for offline tooling.
//!
//! ```bash
//! cargo run -p aegis-patterns --example dump_patterns > /tmp/patterns.json
//! ```

fn main() {
    let patterns = aegis_patterns::all_patterns();
    if let Err(error) = serde_json::to_writer_pretty(std::io::stdout(), &patterns) {
        eprintln!("failed to serialize patterns: {error}");
        std::process::exit(1);
    }
    println!();
}
