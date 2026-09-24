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

# Bucket each record by crate so the log shows what the floor is computed
# over. SF paths are absolute in some environments and relative in others,
# so buckets are matched by substring, not prefix.
declare -A B_HIT B_LF
bucket_of() {
    local path="$1"
    if [[ "$path" == *crates/* ]]; then
        local rest="${path#*crates/}"
        printf 'crates/%s' "${rest%%/*}"
    elif [[ "$path" == *src/main.rs ]]; then
        printf 'src (root aggregator)'
    else
        printf 'other'
    fi
}

hit=0
total=0
skipped=0
counted=0
in_record=0
skip_record=0
CURRENT_PATH=""
while IFS= read -r line; do
    case "$line" in
        SF:*)
            in_record=1
            CURRENT_PATH="${line#SF:}"
            if is_ignored "$line"; then skip_record=1; fi
            ;;
        LH:*)
            if ((in_record && !skip_record)); then
                hit=$((hit + ${line#LH:}))
                bucket=$(bucket_of "$CURRENT_PATH")
                B_HIT[$bucket]=$(( ${B_HIT[$bucket]:-0} + ${line#LH:} ))
            fi
            ;;
        LF:*)
            if ((in_record && !skip_record)); then
                total=$((total + ${line#LF:}))
                bucket=$(bucket_of "$CURRENT_PATH")
                B_LF[$bucket]=$(( ${B_LF[$bucket]:-0} + ${line#LF:} ))
            fi
            ;;
        end_of_record)
            if ((in_record)); then
                if ((skip_record)); then
                    skipped=$((skipped + 1))
                else
                    counted=$((counted + 1))
                fi
            fi
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

printf 'coverage-floor: counted %d records, ignored %d (per codecov.yml ignore):\n' \
    "$counted" "$skipped"
for bucket in "${!B_LF[@]}"; do
    b_pct=$(awk -v h="${B_HIT[$bucket]}" -v t="${B_LF[$bucket]}" \
        'BEGIN {printf "%.2f", 100 * h / t}')
    printf 'coverage-floor:   %-24s %6d/%-6d %s%%\n' \
        "$bucket" "${B_HIT[$bucket]}" "${B_LF[$bucket]}" "$b_pct"
done | sort

if awk -v p="$percent" -v f="$FLOOR" 'BEGIN {exit !(p + 0 < f + 0)}'; then
    echo "coverage-floor: BELOW floor — add tests or fix dead code; do not lower the floor" >&2
    exit 1
fi
