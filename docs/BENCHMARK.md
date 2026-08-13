# Aegis Benchmark Results

## Benchmark Methodology

**Apples-to-apples comparison** on same codebase: `/nas/Temp/repos/aegis/crates/aegis-core/src/`
- 32 files, 0.24 MB total
- Resource limit: 30s timeout per tool

## Results Summary

| Tool | Time | Files/s | MB/s | Findings |
|------|------|---------|------|----------|
| **Aegis** | 0.19s | 164 | 1.25 | 1711 |
| **Atheon-Enhanced** | 4.69s | ~7 | ~0.05 | 1930 |

**Aegis is ~25x faster** on this dataset.

## Detailed Metrics

### Aegis
```
Files scanned: 32
Bytes scanned: 0.24 MB
Findings: 1711
Scan time: 0.19s
Throughput: 164.10 files/s, 1.25 MB/s
```

### Atheon-Enhanced
```
Files scanned: 32 (estimated from timing)
Findings: 1930
Scan time: 4.69s
Throughput: ~7 files/s, ~0.05 MB/s
```

## Key Observations

1. **Aegis is significantly faster** (~25x) for this Rust codebase scan
2. **Aegis found fewer findings** (1711 vs 1930) - different pattern sets
3. **Throughput difference**: Aegis processes ~164 files/s vs ~7 files/s for Atheon
4. **CPU utilization**: Aegis uses ~2.5s user time (parallel), Atheon ~4.7s (single-threaded)

## Running Benchmarks

```bash
# Full benchmark with both tools
./benchmark.sh

# Quick Aegis benchmark
./target/release/aegis scan crates/aegis-core/src/

# Quick Atheon benchmark
cd /nas/Temp/repos/Atheon-Enhanced && ./atheon /nas/Temp/repos/aegis/crates/aegis-core/src/
```

## Historical Tracking

Results are tracked in `benchmark_history.jsonl` for regression detection.
