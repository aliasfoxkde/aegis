#!/bin/bash
# Aegis vs Atheon-Enhanced Benchmark Script
# Compares both tools on a small, normalized dataset
# Resource limits: 30s timeout, focused test set

set -e

echo "=============================================="
echo "Aegis vs Atheon-Enhanced Benchmark"
echo "=============================================="
echo ""

# Resource limits
TIMEOUT_SECS=30
# Use just the core source files for focused benchmark
TEST_FILES=("crates/aegis-core/src/scanner.rs" "crates/aegis-core/src/lib.rs" "crates/aegis-core/src/finding.rs" "crates/aegis-core/src/pattern.rs")

# Build both tools
echo "[1/4] Building Aegis..."
cd /nas/Temp/repos/aegis
cargo build --release -p aegis-cli 2>/dev/null
AEGIS_BIN="./target/release/aegis"

echo "[2/4] Building Atheon-Enhanced..."
cd /nas/Temp/repos/Atheon-Enhanced
if [ ! -f atheon ]; then
    go build -o atheon . 2>/dev/null
fi
ATHEON_BIN="./atheon"

echo "[3/4] Preparing test data..."
cd /nas/Temp/repos/aegis
echo "Test files: ${TEST_FILES[*]}"
echo ""

echo "[4/4] Running benchmarks (timeout: ${TIMEOUT_SECS}s)..."
echo "=============================================="
echo ""

# Benchmark Aegis with timeout
echo ">>> AEGIS <<<"
echo "----------------------------------------------"
START=$(date +%s.%N)
timeout ${TIMEOUT_SECS}s $AEGIS_BIN scan "${TEST_FILES[@]}" 2>&1 | grep -E "^(Scan Statistics:|Files scanned:|Findings:|Scan time:|Throughput:)" || echo "TIMEOUT or ERROR"
END=$(date +%s.%N)
AEGIS_TIME=$(echo "$END - $START" | bc)

echo ""
echo ">>> ATHEON-ENHANCED <<<"
echo "----------------------------------------------"
START=$(date +%s.%N)
timeout ${TIMEOUT_SECS}s $ATHEON_BIN "${TEST_FILES[@]}" -q 2>&1 | head -5 || echo "TIMEOUT or ERROR"
END=$(date +%s.%N)
ATHEON_TIME=$(echo "$END - $START" | bc)

echo ""
echo "=============================================="
echo "RESULTS SUMMARY"
echo "=============================================="
echo ""
printf "Aegis time:   %s seconds\n" "$AEGIS_TIME"
printf "Atheon time: %s seconds\n" "$ATHEON_TIME"
echo ""

# Calculate speedup/slowdown
if [ "$AEGIS_TIME" != "0" ] && [ "$AEGIS_TIME" != "0.0" ]; then
    RATIO=$(echo "scale=2; $ATHEON_TIME / $AEGIS_TIME" | bc)
    echo "Speed ratio (Atheon/Aegis): ${RATIO}x"
    if (( $(echo "$RATIO > 1" | bc -l) )); then
        echo "Aegis is ${RATIO}x faster"
    else
        echo "Atheon is $(echo "scale=2; 1 / $RATIO" | bc)x faster"
    fi
else
    echo "Could not calculate ratio (Aegis too fast or error)"
fi
