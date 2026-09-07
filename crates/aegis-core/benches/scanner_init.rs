//! Criterion benchmarks for scanner construction and first-scan latency.
//!
//! The bundled registry compiles 600+ regexes; extension-narrowed category
//! scanners are compiled lazily on the first scan of each file type. These
//! benchmarks pin both costs so a regression shows up in `cargo bench`.
//!
//! Run with `cargo bench -p aegis-core --bench scanner_init`.

use aegis_core::pattern::PatternDefinition;
use aegis_core::Scanner;
use aegis_patterns::Pattern;
use criterion::{criterion_group, criterion_main, Criterion};

/// criterion's own `black_box` is deprecated in favor of the std hint.
use std::hint::black_box;

fn convert(p: Pattern) -> PatternDefinition {
    PatternDefinition {
        name: p.name,
        category: p.category,
        match_pattern: p.match_pattern,
        enabled: p.enabled,
        severity: aegis_core::Severity::parse(&p.severity).unwrap_or(aegis_core::Severity::Medium),
        confidence: aegis_core::Confidence::parse(&p.confidence)
            .unwrap_or(aegis_core::Confidence::Medium),
        min_entropy: p.min_entropy,
        description: p.description,
        reference: p.reference,
        tags: p.tags,
        env_var: p.env_var,
        binary: p.binary,
        exclude_pattern: p.exclude,
        file_extensions: p.file_extensions,
        ..Default::default()
    }
}

fn bundled_definitions() -> Vec<PatternDefinition> {
    aegis_patterns::all_patterns()
        .into_iter()
        .map(convert)
        .collect()
}

/// A small universal-pattern source (no bundled rule is extension-scoped
/// for `txt`, so this exercises the full narrowed set).
fn sample_source() -> String {
    "let config = load_config();\nfn handle(req: Request) -> Response { todo!() }\n".repeat(20)
}

fn bench_registry_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("scanner_init");
    group.bench_function("from_definitions", |b| {
        b.iter(|| {
            let definitions = black_box(bundled_definitions());
            // Bench setup may expect; the directive must share the flagged line.
            Scanner::from_definitions(definitions).expect("patterns compile") // aegis:ignore:rust-expect-usage
        })
    });

    // First scan of a file type pays the per-extension scanner compile.
    group.bench_function("first_scan_extension_rs", |b| {
        b.iter_batched(
            || Scanner::from_definitions(bundled_definitions()).expect("patterns compile"), // aegis:ignore:rust-expect-usage
            |scanner| {
                scanner
                    .scan_string(black_box(&sample_source()), "src/main.rs")
                    .len()
            },
            criterion::BatchSize::PerIteration,
        )
    });

    // Steady state: scanners for the extension are already compiled.
    group.bench_function("cached_scan_extension_rs", |b| {
        // Bench setup may expect; the directive must share the flagged line.
        let scanner = Scanner::from_definitions(bundled_definitions()).expect("patterns compile"); // aegis:ignore:rust-expect-usage
                                                                                                   // Warm the extension cache outside the timed section.
        let _ = scanner.scan_string(&sample_source(), "src/main.rs");
        b.iter(|| {
            scanner
                .scan_string(black_box(&sample_source()), "src/main.rs")
                .len()
        })
    });

    group.finish();
}

criterion_group!(scanner_init, bench_registry_build);
criterion_main!(scanner_init);
