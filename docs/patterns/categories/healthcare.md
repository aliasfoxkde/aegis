# healthcare patterns

Clinical data and HIPAA-adjacent rules

**7 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`clinical-trial-id`](#clinical-trial-id) | medium | high | Clinical trial identifier detected |
| [`healthcare-code`](#healthcare-code) | medium | high | Healthcare code detected (CPT, HCPCS, ICD-10) |
| [`healthcare-medical-record-number`](#healthcare-medical-record-number) | medium | high | Medical record number detected |
| [`healthcare-prescription-number`](#healthcare-prescription-number) | medium | high | Prescription number detected |
| [`insurance-number`](#insurance-number) | medium | high | Insurance number detected |
| [`medical-license-number`](#medical-license-number) | medium | high | Medical license number detected |
| [`patient-id`](#patient-id) | medium | high | Patient identifier detected |

## Pattern details

### clinical-trial-id

Clinical trial identifier detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `healthcare`, `clinical-trial` |

**Match pattern** (Rust `regex` syntax):

```regex
\bNCT[0-9]{8}\b
```

**Input that fires** (verified by the liveness test):

```text
NCT99358458
```

### healthcare-code

Healthcare code detected (CPT, HCPCS, ICD-10)

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `healthcare`, `medical-code` |

**Match pattern** (Rust `regex` syntax):

```regex
\b(?:CPT|HCPCS|ICD-10)[A-Z0-9]{5,8}\b
```

**Input that fires** (verified by the liveness test):

```text
CPTRY885UTE
```

### healthcare-medical-record-number

Medical record number detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `healthcare`, `medical-record` |

**Match pattern** (Rust `regex` syntax):

```regex
\bMRN[0-9]{8,12}\b
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
MRN96883…24
```

### healthcare-prescription-number

Prescription number detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `healthcare`, `prescription` |

**Match pattern** (Rust `regex` syntax):

```regex
\bRX[0-9]{7,10}\b
```

**Input that fires** (verified by the liveness test):

```text
RX4545679975
```

### insurance-number

Insurance number detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `healthcare`, `insurance` |

**Match pattern** (Rust `regex` syntax):

```regex
\b(?:INS|INSURANCE)[0-9]{9,11}\b
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
INS72363…97
```

### medical-license-number

Medical license number detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `healthcare`, `license` |

**Match pattern** (Rust `regex` syntax):

```regex
\b(?:MD|DO|RN|LPN|PA|NP)[0-9]{8,12}\b
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
MD957678…68
```

### patient-id

Patient identifier detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `healthcare`, `patient` |

**Match pattern** (Rust `regex` syntax):

```regex
\b(?:PATIENT|PT)[0-9]{8,12}\b
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
PATIENT8…29
```
