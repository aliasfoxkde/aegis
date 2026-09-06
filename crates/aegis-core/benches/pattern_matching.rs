//! Criterion benchmarks for the pattern-matching hot path.
//!
//! Run with `cargo bench -p aegis-core`.

use aegis_core::pattern::PatternDefinition;
use aegis_core::Scanner;
use aegis_patterns::Pattern;
use criterion::{criterion_group, criterion_main, Criterion};

/// criterion's own `black_box` is deprecated in favor of the std hint.
use std::hint::black_box;

/// Build a synthetic-but-realistic source: repetitive code lines (the
/// common case for the combined-regex pre-filter) interspersed with a few
/// lines that match bundled patterns.
fn synthetic_source(lines: usize) -> String {
    let filler = [
        "let total = subtotal + tax_amount;",
        "if user.is_active() {",
        "    logger.debug(\"processing request\");",
        "}",
        "return Ok(Response::json(payload));",
        "# TODO: extract to config",
        "const DEFAULT_TIMEOUT_MS: u64 = 5_000;",
        "self.entries.retain(|e| e.active);",
    ];
    let hot = [
        "let aws_key = \"AKIAIOSFODNN7EXAMPLE\";",
        "eval(user_input);",
        "<img src=\"chart.png\">",
        "password = \"hunter2hunter2\";",
    ];
    let mut out = String::with_capacity(lines * 40);
    for i in 0..lines {
        if i % 32 == 0 {
            out.push_str(hot[i % hot.len()]);
        } else {
            out.push_str(filler[i % filler.len()]);
        }
        out.push('\n');
    }
    out
}

fn bundled_scanner() -> Scanner {
    let definitions: Vec<PatternDefinition> = aegis_patterns::all_patterns()
        .into_iter()
        .map(convert)
        .collect();
    Scanner::from_definitions(definitions).expect("bundled patterns must compile")
}

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

fn bench_scan_string(c: &mut Criterion) {
    let scanner = bundled_scanner();
    let source = synthetic_source(1_024);
    let mut group = c.benchmark_group("scan_string");
    group.throughput(criterion::Throughput::Bytes(source.len() as u64));
    group.bench_function("bundled_registry_1k_lines", |b| {
        b.iter(|| scanner.scan_string(black_box(&source), "bench.rs"))
    });
    group.finish();
}

fn bench_extension_dispatch(c: &mut Criterion) {
    let scanner = bundled_scanner();
    let source = synthetic_source(1_024);
    // Warm the per-extension caches once so the benchmark measures the
    // cached dispatch path (the steady state of a real scan), not cache
    // construction.
    for ext in ["rs", "py", "html", "yaml"] {
        let _ = scanner.scan_string(&source, &format!("warm.{ext}"));
    }

    let mut group = c.benchmark_group("extension_dispatch");
    for ext in ["rs", "py", "html", "yaml"] {
        group.bench_function(ext, |b| {
            b.iter(|| scanner.scan_string(black_box(&source), &format!("bench.{ext}")))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_scan_string, bench_extension_dispatch);
criterion_main!(benches);
