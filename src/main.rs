//! Aegis - Security scanning tool
//!
//! This is the root package that serves as a workspace aggregator.

/// Point users at the real CLI entry point; the workspace root itself only
/// exists to hold shared profile/dependency configuration.
fn print_hint() {
    println!("Aegis - Use 'cargo run --package aegis-cli --bin aegis -- --help' to run");
}

fn main() {
    print_hint();
}

#[cfg(test)]
mod tests {
    #[test]
    fn aggregator_prints_the_cli_hint() {
        // Runs the extracted body so the aggregator bin stays covered and
        // honest about where the real entry point lives.
        super::print_hint();
    }
}
