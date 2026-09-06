# Aegis fuzz targets

Run with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (requires
nightly):

```sh
cargo fuzz run fuzz_suppression_parse -- -max_total_time=60
cargo fuzz run fuzz_ignore_rules_compile -- -max_total_time=60
cargo fuzz run fuzz_baseline_parse -- -max_total_time=60
```

The `fuzz/` directory is excluded from the workspace so nightly-only
dependencies never leak into release builds.
