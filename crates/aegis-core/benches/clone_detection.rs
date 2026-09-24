//! Criterion benchmarks for the code-clone detector.
//!
//! `aegis scan --detect-clones` runs [`CloneDetector::detect_content`] once
//! per analyzed file, inside the measured scan window, so its per-file cost
//! belongs in the weekly trend next to the pattern pipeline. The corpus
//! mixes four identical regions (clone pairs flow) with four structurally
//! distinct ones (pairing work with mostly nothing to report), which is the
//! shape a real opt-in scan pays for.
//!
//! Run with `cargo bench -p aegis-core --bench clone_detection`.

// Benchmark binary: panicking on a broken fixture is the harness's
// failure mechanism, and bench targets do not get clippy.toml's
// test exemptions (they are not `#[test]` code).
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use aegis_core::clone::CloneDetector;
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

/// One ~45-token region: long enough to clear the detector's 40-token
/// block size, ordinary enough to read like real code. `seed` only varies
/// the fixture's arithmetic; `salt` as a name would trip CodeQL's
/// hard-coded-cryptographic-value heuristic (it did, alert 6860).
fn loop_region(name: &str, seed: usize) -> String {
    format!(
        "fn {name}(input: i64) -> i64 {{\n\
         \x20   let mut total = {seed};\n\
         \x20   for step in 0..input {{\n\
         \x20       total += step * 3;\n\
         \x20       total -= step / 7;\n\
         \x20       total += input % 13;\n\
         \x20   }}\n\
         \x20   let shifted = total - input;\n\
         \x20   let scaled = shifted * 5 + total / 2;\n\
         \x20   scaled - shifted + total\n\
         }}\n"
    )
}

/// Four regions with genuinely different shapes, so the corpus is not one
/// function repeated: the detector still scores every window pair across
/// them, which is the cost being measured.
fn distinct_regions() -> Vec<String> {
    vec![
        "fn branchy(flag: bool, left: i64, right: i64) -> i64 {
    if flag { left - 1 } else { right + 2 }
}
"
        .to_string(),
        "fn picker(code: u8) -> &'static str {
    match code {
        0 => \"ok\",
        1 => \"retry\",
        _ => \"fail\",
    }
}
"
        .to_string(),
        "fn accumulate(values: &[i64]) -> i64 {
    let mut sum = 0;
    let mut product = 1;
    for value in values {
        sum += value;
        product *= value.max(1);
    }
    sum | product
}
"
        .to_string(),
        "fn greet(person: &str, times: usize) -> String {
    let mut message = String::new();
    for _ in 0..times {
        message.push_str(\"hello \");
        message.push_str(person);
    }
    message
}
"
        .to_string(),
    ]
}

fn bench_clone_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("clone_detection");

    let mut corpus: Vec<String> = (0..4)
        .map(|index| loop_region(&format!("copy_{index}"), 0))
        .collect();
    corpus.extend(distinct_regions());
    let corpus = corpus.join("\n");

    group.bench_function("detect_content_mixed_regions", |b| {
        b.iter(|| {
            CloneDetector::new()
                .detect_content(black_box(&corpus), "bench_corpus.rs")
                .map_or(0, |clones| clones.len())
        });
    });

    group.finish();
}

criterion_group!(clone_detection, bench_clone_detection);
criterion_main!(clone_detection);
