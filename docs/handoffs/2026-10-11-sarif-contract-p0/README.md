# Aegis SARIF P0 contract fixtures (offline)

Date: 2026-10-11. Parent handoff: `docs/handoffs/2026-10-11-sarif-github-consumer-parity.md` (section 5 P0, DEC-1 through DEC-6). This directory is the evidence location that handoff's P0 "Validation" row requires.

**Status: fixtures only. Every action/API result is UNMEASURED. Nothing here was uploaded anywhere, and nothing here states or implies GitHub behavior; each probe exists to measure behavior that is currently UNKNOWN (parent sections 3.4-2, 3.4-3, 7.2). No product code was changed, no build was run, and no network access was used.**

## 1. Inventory

| File | Purpose |
|---|---|
| `fixtures/p0-1a-security-severity-only.sarif.json` | P0-1 variant (i): rule carries `properties.security-severity`, no `security` tag |
| `fixtures/p0-1b-security-severity-plus-security-tag.sarif.json` | P0-1 variant (ii): identical to 1a plus `security` in rule tags |
| `fixtures/p0-2-cwe-taxonomies.sarif.json` | P0-2: identical to 1b plus run-level `taxonomies` (one CWE taxon) and a rule `relationships` entry |
| `fixtures/p0-3a-no-partialfingerprints.sarif.json` | P0-3 baseline: current emitter shape; result has no `partialFingerprints` key |
| `fixtures/p0-3b-aegis-stable-id-only.sarif.json` | P0-3: 3a plus only the proposed supplemental key `aegisStableId/v1` |
| `fixtures/p0-3c-primary-location-line-hash-only.sarif.json` | P0-3: 3a plus only `primaryLocationLineHash` |
| `fixtures/p0-synthetic-source-v1.txt`, `fixtures/p0-synthetic-source-v2.txt` | Harmless synthetic source; line 1 (the anchor) is byte-identical in both |
| `evidence-receipt-template.md` | Dated receipt skeleton; every observation cell starts UNMEASURED |

## 2. Shared synthetic identity (all six SARIF files)

One identity is shared so each variant differs from its sibling in exactly one variable.

| Field | Value | Shape source |
|---|---|---|
| SARIF version | `2.1.0` | `crates/aegis-cli/src/output.rs:289` |
| driver | `name: "Aegis"`, `version: "0.6.4"` | `output.rs:293-294` (`CARGO_PKG_VERSION`; workspace `Cargo.toml` `[workspace.package]`) |
| rule `id` | `aegis-8df48180634c583c1bd7d2f67cd63843faba1b90ffe640b16f54c378d3126a55` | emitter sets `rules[].id` to `stable_id` (`output.rs:258-264`) |
| rule `name` | `p0_synthetic_finding` | emitter sets `rules[].name` to the pattern name |
| result `level` | `error` | `severity_to_sarif_level`: high maps to error (`output.rs:317-324`; frozen by DEC-6) |
| location | `uri: "p0-synthetic-source.txt"`, `startLine: 1`, `startColumn: 1` | `output.rs:274-284` |
| `inspectionLedger` | one unit, `status: "analyzed"`, `required: true` | serde shape at `crates/aegis-core/src/finding.rs:223,241-261,270-277` |

All fixture content is synthetic. The content-derived `fingerprint` field (`finding.rs:123-127,147-150`) and `matched_text` appear nowhere, per DEC-5(c).

**`stable_id` derivation** (formula VERIFIED at `finding.rs:152-159`: `"aegis-" + sha256("pattern|category|file|line|column")`):

```bash
printf '%s' 'p0_synthetic_finding|synthetic|p0-synthetic-source.txt|1|1' | sha256sum
# 8df48180634c583c1bd7d2f67cd63843faba1b90ffe640b16f54c378d3126a55
# rule id and aegisStableId/v1 value: aegis-8df48180634c583c1bd7d2f67cd63843faba1b90ffe640b16f54c378d3126a55
```

The material is locator-only (pattern name, category, path, line, column); no source content contributes, so the value is content-safe to upload and reproducible offline.

**`primaryLocationLineHash` derivation** (P0-3c only). SARIF 2.1.0 treats this string as opaque; this fixture defines it as the first 16 hex characters of the SHA-256 of the exact anchor-line bytes (UTF-8, no trailing newline):

```bash
printf '%s' 'aegis-p0 fixture anchor line one (synthetic, harmless, contains no credentials)' | sha256sum | cut -c1-16
# ab2bb0e172f8bab3
```

The hashed line contains no credential material, so hashing it is harmless. Whether any consumer derives or compares this value the same way is precisely what P0-3 measures; **UNMEASURED**, and no behavior is claimed.

## 3. Exact variant differences

Base = the current emitter shape (`output.rs:166-308`) plus one finding. Each row is the complete delta from the named base; the files are otherwise byte-identical in structure.

| Variant | Base | Delta |
|---|---|---|
| P0-1a | emitter shape | rule gains `properties`: `tags: ["synthetic"]`, `security-severity: "8.5"` (DEC-1 PROPOSED high-band value) |
| P0-1b | P0-1a | rule tags become `["security", "synthetic"]` |
| P0-2 | P0-1b | run gains `taxonomies` (MITRE CWE toolComponent, `taxa: [CWE-532]`, `isComprehensive: false`); rule gains `relationships: [{target: {id: "CWE-532", index: 0, toolComponent: {name: "CWE", index: 0}}}]` |
| P0-3a | emitter shape | none (baseline; result carries no `partialFingerprints` at all) |
| P0-3b | P0-3a | result gains `partialFingerprints: {"aegisStableId/v1": "aegis-8df4...a55"}` (DEC-5(b) supplemental key; value equals the rule id) |
| P0-3c | P0-3a | result gains `partialFingerprints: {"primaryLocationLineHash": "ab2bb0e172f8bab3"}` |

P0-3 rules deliberately carry no metadata properties: the fingerprint probes must not share variables with the P0-1/P0-2 metadata probes. CWE-532 is used because it is one of the four CWE ids already attested in the registry (parent section 3.3). If P0-2 shows display behavior and attribution between encodings is needed, clone this fixture offline (see section 5 tooling) into single-encoding sub-variants before uploading again.

## 4. Synthetic source lines (commit A / commit B)

| File | Line 1 (anchor; identical bytes in both) | Line 2 |
|---|---|---|
| `fixtures/p0-synthetic-source-v1.txt` | `aegis-p0 fixture anchor line one (synthetic, harmless, contains no credentials)` | `aegis-p0 commit-a filler, baseline content for the first upload` |
| `fixtures/p0-synthetic-source-v2.txt` | (same) | `aegis-p0 commit-b filler, changed content for the re-upload probe` |

Operator prep in the disposable probe repo (offline step, not performed here): commit A adds the anchor file at the repo root as `p0-synthetic-source.txt` with the v1 bytes; commit B replaces that file with the v2 bytes (line 1 unchanged, so the finding location is stable across the commit pair). Every SARIF `uri` is probe-repo-relative; if a different path is used, update `artifactLocation.uri` in all six files and re-derive `stable_id` with the formula above.

## 5. Offline validation commands (no downloads)

JSON parse check, from this directory:

```bash
for f in fixtures/*.sarif.json; do jq empty "$f" && python3 -m json.tool "$f" > /dev/null && echo "OK $f"; done
```

Structural self-check (asserts SARIF version, emitter shape, each variant's documented delta, and that no content-derived `fingerprint` key exists anywhere, per DEC-5(c)):

```bash
python3 - <<'PY'
import json
sid = "aegis-8df48180634c583c1bd7d2f67cd63843faba1b90ffe640b16f54c378d3126a55"
want = {
    "p0-1a-security-severity-only.sarif.json": (["synthetic"], False, None),
    "p0-1b-security-severity-plus-security-tag.sarif.json": (["security", "synthetic"], False, None),
    "p0-2-cwe-taxonomies.sarif.json": (["security", "synthetic"], True, None),
    "p0-3a-no-partialfingerprints.sarif.json": (None, False, set()),
    "p0-3b-aegis-stable-id-only.sarif.json": (None, False, {"aegisStableId/v1"}),
    "p0-3c-primary-location-line-hash-only.sarif.json": (None, False, {"primaryLocationLineHash"}),
}
for name, (tags, taxo, fpkeys) in want.items():
    doc = json.load(open("fixtures/" + name))
    assert doc["version"] == "2.1.0" and len(doc["runs"]) == 1
    run = doc["runs"][0]
    drv = run["tool"]["driver"]
    assert drv["name"] == "Aegis" and drv["version"] == "0.6.4"
    rule, res = drv["rules"][0], run["results"][0]
    assert rule["id"] == sid == res["ruleId"] and res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["region"] == {"startLine": 1, "startColumn": 1}
    assert run["properties"]["inspectionLedger"]["schema_version"] == 1
    if tags is None:
        assert "properties" not in rule
    else:
        assert rule["properties"]["tags"] == tags
        assert rule["properties"]["security-severity"] == "8.5"
    assert ("taxonomies" in run) == taxo
    assert set(res.get("partialFingerprints", {})) == (fpkeys or set())
    if fpkeys and "aegisStableId/v1" in fpkeys:
        assert res["partialFingerprints"]["aegisStableId/v1"] == sid
    if fpkeys and "primaryLocationLineHash" in fpkeys:
        assert res["partialFingerprints"]["primaryLocationLineHash"] == "ab2bb0e172f8bab3"
    assert "fingerprint" not in res
print("all 6 fixtures: shape OK")
PY
```

SARIF 2.1.0 schema validation: the `jsonschema` Python package (4.26.0) is available in this environment, but no SARIF schema file exists in this repository or its local cargo registry, and fetching one is out of scope for this task. When the operator supplies a schema file locally (any trusted copy, e.g. saved as `sarif-schema-2.1.0.json` beside this README), validate with:

```bash
python3 -c 'import json,sys,jsonschema; jsonschema.validate(json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))); print("schema OK")' fixtures/p0-1a-security-severity-only.sarif.json sarif-schema-2.1.0.json
```

(repeat per fixture). Until then, conformance rests on the structural check above plus the member-by-member SARIF citations in the parent handoff.

## 6. Upload plan (operator/infra work — NOT executed here)

No upload was performed. `evidence-receipt-template.md` has one row per planned run; every observation cell is UNMEASURED until the infra-operator fills it. Routes per parent section 5 P0: the code-scanning `upload-sarif` action and the code-scanning SARIF API, against a disposable repository; for each P0-3 variant, commit A then commit B, per route. Record per run: action version or API path, commit, upload id, alert count, and the one-alert-or-duplicate outcome. Interpretation limits from the parent hold: a P0-3b observation cannot establish that GitHub recognizes the supplemental key or guarantees lineage (parent section 3.4-4, DEC-5), and P0-2 CWE display may be recorded as unknown/unavailable UI behavior (parent section 7.2-1).

## 7. Missing operator/infra inputs (blocking measurement)

- a disposable probe repository with code scanning enabled, and permission to enable it
- the pinned `upload-sarif` action version, and the API endpoint/path plus a token authorized for that repo (never stored in this directory)
- commit SHAs for commit A and commit B (the fixtures are commit-agnostic; SARIF files carry no commit field — the route supplies it)
- operator ratification of the DEC-1 score value baked into the fixtures (`"8.5"` PROPOSED), or substitution of the Atheon-transcribed alternative before upload
- a locally supplied SARIF 2.1.0 schema file for the optional schema-validation step
- the observed results themselves; until the receipt is filled, every DEC clause gated on P0 (DEC-1/DEC-2/DEC-4, parent section 5 P0 acceptance) remains PROPOSED/UNMEASURED

## 8. Provenance

Shapes transcribed by hand from `crates/aegis-cli/src/output.rs:166-324` and `crates/aegis-core/src/finding.rs:88-159,223,241-277` in this tree (branch `codex/aegis-sarif-p0-fixtures-20261011`). Hash values are reproducible with the commands in section 2. This directory adds no product code, no builds, no scans, no uploads, and no dependency changes.
