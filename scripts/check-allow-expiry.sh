#!/usr/bin/env bash
# Fail when a lint suppression's recorded expiry has passed, or is about to.
#
# Every `#[allow(...)]` in `crates/*/src` carries an `aegis-allow:` annotation
# with an `expires=YYYY-MM-DD` date (see crates/aegis-core/tests/lint_policy.rs,
# which enforces that the annotation exists and is well formed). This script
# enforces the second half of the promise: that the date means something.
#
# A suppression is a decision, and a decision has an owner and a shelf life.
# When one expires, the choice is re-made — the code is fixed, or the
# annotation is renewed with a new date and, if the reason changed, a new
# reason.
#
# Usage: scripts/check-allow-expiry.sh [renewal_window_days]
set -euo pipefail
cd "$(dirname "$0")/.."

WINDOW="${1:-45}"
today="$(date -u +%F)"
horizon="$(date -u -d "+${WINDOW} days" +%F)"

expired=0
expiring=0
total=0

while IFS= read -r entry; do
    file="${entry%%:*}"
    rest="${entry#*:}"
    line="${rest%%:*}"
    expiry="${rest##*:}"
    total=$((total + 1))
    if [[ "$expiry" < "$today" ]]; then
        printf 'expired  %s:%s (expired %s)\n' "$file" "$line" "$expiry" >&2
        expired=$((expired + 1))
    elif [[ "$expiry" < "$horizon" ]]; then
        printf 'expiring %s:%s (expires %s, within %s days)\n' \
            "$file" "$line" "$expiry" "$WINDOW" >&2
        expiring=$((expiring + 1))
    fi
done < <(grep -rn 'aegis-allow:' crates/*/src --include='*.rs' |
    sed -E 's#^([^:]+):([0-9]+):.*expires=([0-9]{4}-[0-9]{2}-[0-9]{2}).*#\1:\2:\3#' |
    sort)

if ((expired > 0)); then
    printf 'allow-expiry: %d suppression(s) expired — fix the code or renew the annotation\n' \
        "$expired" >&2
    exit 1
fi
if ((expiring > 0)); then
    printf 'allow-expiry: %d suppression(s) expire within %s days — renew them now\n' \
        "$expiring" "$WINDOW" >&2
    exit 1
fi

printf 'allow-expiry: %d suppression(s), none expired or expiring within %s days\n' \
    "$total" "$WINDOW"
