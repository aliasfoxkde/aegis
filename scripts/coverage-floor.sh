#!/usr/bin/env bash
# Enforce the workspace line-coverage floor directly from an lcov report.
#
# Why this exists: the Codecov upload silently fails on every run ("Token
# required - not valid tokenless upload") because no CODECOV_TOKEN secret
# is configured for this repository, so the percentages in codecov.yml are
# never evaluated by anything. This script is the gate that actually runs:
# it sums LH/LF records over the same files Codecov would count (the
# codecov.yml `ignore` list mirrored below) and fails below the floor.
#
# Usage: scripts/coverage-floor.sh <lcov.info> [floor_percent]
# The floor sits just below measured reality and is ratcheted up — never
# lowered to pass (see docs/PLAN.md, "Measure, then pin").
set -euo pipefail

LCOV="${1:?usage: coverage-floor.sh <lcov.info> [floor_percent]}"
FLOOR="${2:-89.0}"

if [[ ! -f "$LCOV" ]]; then
    echo "coverage-floor: report not found: $LCOV" >&2
    exit 2
fi

# Mirrors codecov.yml `ignore`.
readarray -t IGNORED <<'EOF'
^SF:crates/aegis-wasm/
^SF:src/main.rs
EOF

is_ignored() {
    local path="$1" pattern
    for pattern in "${IGNORED[@]}"; do
        if [[ "$path" =~ $pattern ]]; then
            return 0
        fi
    done
    return 1
}

hit=0
total=0
in_record=0
skip_record=0
while IFS= read -r line; do
    case "$line" in
        SF:*)
            in_record=1
            if is_ignored "$line"; then skip_record=1; fi
            ;;
        LH:*)
            if ((in_record && !skip_record)); then hit=$((hit + ${line#LH:})); fi
            ;;
        LF:*)
            if ((in_record && !skip_record)); then total=$((total + ${line#LF:})); fi
            ;;
        end_of_record)
            in_record=0
            skip_record=0
            ;;
    esac
done <"$LCOV"

if ((total == 0)); then
    echo "coverage-floor: no line records found in $LCOV (wrong format?)" >&2
    exit 2
fi

percent=$(awk -v h="$hit" -v t="$total" 'BEGIN {printf "%.2f", 100 * h / t}')
printf 'coverage-floor: %s%% lines covered (%d/%d, floor %s%%)\n' \
    "$percent" "$hit" "$total" "$FLOOR"

if awk -v p="$percent" -v f="$FLOOR" 'BEGIN {exit !(p + 0 < f + 0)}'; then
    echo "coverage-floor: BELOW floor — add tests or fix dead code; do not lower the floor" >&2
    exit 1
fi
