#!/usr/bin/env bash
# Fail unless deny.toml's [licenses] allow list and about.toml's accepted
# list are identical. One license policy, two consumers: cargo-deny gates
# the dependency tree, cargo-about generates THIRD-PARTY-NOTICES.md. The
# lists must move together or the two gates disagree about what is allowed.
set -euo pipefail
cd "$(dirname "$0")/.."

deny_list="$(sed -n '/^allow = \[/,/^\]/p' deny.toml | grep -oE '"[^"]+"' | tr -d '"' | sort)"
about_list="$(sed -n '/^accepted = \[/,/^\]/p' about.toml | grep -oE '"[^"]+"' | tr -d '"' | sort)"

if [[ "$deny_list" != "$about_list" ]]; then
    printf 'deny.toml [licenses] allow and about.toml accepted diverge:\n' >&2
    diff <(printf '%s\n' "$deny_list") <(printf '%s\n' "$about_list") >&2 || true
    printf 'update both lists together — one policy, two consumers\n' >&2
    exit 1
fi
printf 'license policies identical (%s entries)\n' "$(printf '%s\n' "$deny_list" | grep -c .)"
