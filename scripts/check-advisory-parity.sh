#!/usr/bin/env bash
# Fail unless the advisory ignores used by cargo-audit and the advisory
# ignores listed in deny.toml are identical.
#
# Two consumers, one policy: `cargo audit` (CI, "Security Audit" job) and
# `cargo deny check` (CI, "Dependency Policy" job) must waive the same
# advisories. A waiver added to one file only is a silent hole in the
# other gate — the comment in deny.toml claims they are kept in lockstep,
# and this script is what makes that claim true.
set -euo pipefail
cd "$(dirname "$0")/.."

audit_ignores() {
    # `--ignore RUSTSEC-XXXX-YYYY` occurrences in the audit command.
    sed -n '/cargo audit/,/^$/p' .github/workflows/ci.yml |
        grep -oE -- '--ignore +RUSTSEC-[0-9]{4}-[0-9]{4}' |
        grep -oE 'RUSTSEC-[0-9]{4}-[0-9]{4}' |
        sort -u
}

deny_ignores() {
    # The `[advisories] ignore = [...]` list.
    sed -n '/^\[advisories\]/,/^\[/p' deny.toml |
        grep -oE 'RUSTSEC-[0-9]{4}-[0-9]{4}' |
        sort -u
}

audit="$(audit_ignores)"
deny="$(deny_ignores)"

if [[ "$audit" != "$deny" ]]; then
    printf 'cargo-audit ignores and deny.toml advisory ignores diverge:\n' >&2
    diff <(printf '%s\n' "$audit") <(printf '%s\n' "$deny") >&2 || true
    printf 'update both lists together — one policy, two consumers\n' >&2
    exit 1
fi

printf 'advisory policies identical (%s waivers)\n' "$(printf '%s\n' "$audit" | grep -c . || true)"
