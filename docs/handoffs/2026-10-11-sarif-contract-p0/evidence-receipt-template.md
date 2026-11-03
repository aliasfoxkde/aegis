# Aegis SARIF P0 evidence receipt (template — nothing measured yet)

Dated receipt required by the parent handoff (`docs/handoffs/2026-10-11-sarif-github-consumer-parity.md`, section 5 P0 "Validation"). Fill one row per upload; leave UNMEASURED until observed. Never paste source lines containing real secrets here, and never paste tokens.

## Run metadata (fill once per probe repository)

| Field | Value |
|---|---|
| Upload date(s) | UNMEASURED |
| Probe repository (disposable) | UNMEASURED |
| Code scanning enabled by / when | UNMEASURED |
| `upload-sarif` action version | UNMEASURED |
| API route and path used | UNMEASURED |
| Executor | UNMEASURED (infra-operator) |

## P0-1 / P0-2 single-upload probes

| Fixture | Route | Commit | Upload ID | Observed severity display | Observed CWE display | Unknowns preserved |
|---|---|---|---|---|---|---|
| `p0-1a-security-severity-only` | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | n/a | parent 7.2-2 |
| `p0-1b-security-severity-plus-security-tag` | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | n/a | parent 7.2-2 |
| `p0-2-cwe-taxonomies` | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED (record unknown/unavailable if the UI shows nothing) | parent 7.2-1 |

## P0-3 fingerprint probes (commit A then commit B, per route)

| Variant | Route | Commit A sha | Upload ID (A) | Alerts after A | Commit B sha | Upload ID (B) | Alerts after B | One alert or duplicate |
|---|---|---|---|---|---|---|---|---|
| `p0-3a-no-partialfingerprints` | action | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| `p0-3a-no-partialfingerprints` | API | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| `p0-3b-aegis-stable-id-only` | action | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| `p0-3b-aegis-stable-id-only` | API | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| `p0-3c-primary-location-line-hash-only` | action | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| `p0-3c-primary-location-line-hash-only` | API | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |

## Interpretation limits (carry into any filled receipt)

- P0-3b: record only the observed outcome for this exact fixture, route, and tool version; do not infer that a consumer recognizes `aegisStableId/v1` or guarantees alert lineage (parent 3.4-4, DEC-5).
- P0-3c: the hash value is a fixture-local derivation (README section 2); any consumer-side derivation or comparison behavior is UNMEASURED, not assumed.
- P0-2: absence of CWE display is recorded as unknown/unavailable for this probe; it does not generalize beyond this repository and tool version (parent 7.2-1).
- No DEC clause flips to DECIDED without the operator reading this receipt (parent section 5 P0 acceptance). DEC-5(c) (never emit the content-derived `fingerprint`) is not negotiable without operator sign-off.

## Decision-record effects once measured

- DEC-1: severity display observation, 1a vs 1b.
- DEC-2: whether adding the `security` tag changed any observed behavior (1a vs 1b delta).
- DEC-4: CWE acceptance/display outcome from `p0-2`.
- DEC-5: fingerprint probe outcomes from P0-3; production emission policy unchanged by fixtures.
