# healthcare patterns

Clinical data and HIPAA-adjacent rules

**17 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`clinical-trial-id`](#clinical-trial-id) | medium | high | Clinical trial identifier detected |
| [`dea-number`](#dea-number) | medium | high | DEA prescriber registration number detected |
| [`healthcare-code`](#healthcare-code) | medium | high | Healthcare code detected (CPT, HCPCS, ICD-10) |
| [`healthcare-encryption-disabled`](#healthcare-encryption-disabled) | medium | low | Encryption explicitly disabled near patient or PHI data; addressable encryption is expected at rest |
| [`healthcare-medical-record-number`](#healthcare-medical-record-number) | medium | high | Medical record number detected |
| [`healthcare-phi-emailed`](#healthcare-phi-emailed) | high | medium | PHI routed through email; unsecured email is a leading cause of reported healthcare breaches |
| [`healthcare-phi-hardcoded`](#healthcare-phi-hardcoded) | high | medium | Hard-coded patient identifier literal; PHI belongs in systems of record, not source control |
| [`healthcare-phi-in-url-query`](#healthcare-phi-in-url-query) | medium | medium | Patient identifier in a URL query string; URLs persist in history, referrers, and access logs |
| [`healthcare-phi-logged`](#healthcare-phi-logged) | high | medium | PHI appears in a log or print statement; protected health information must not reach application logs |
| [`healthcare-phi-plaintext-endpoint`](#healthcare-phi-plaintext-endpoint) | high | medium | Patient or clinical resource referenced over plaintext HTTP; PHI in transit requires encryption |
| [`healthcare-prescription-number`](#healthcare-prescription-number) | medium | high | Prescription number detected |
| [`healthcare-select-star-phi-table`](#healthcare-select-star-phi-table) | medium | high | SELECT * over a PHI table; the minimum-necessary standard calls for selecting only required columns |
| [`insurance-number`](#insurance-number) | medium | high | Insurance number detected |
| [`medical-license-number`](#medical-license-number) | medium | high | Medical license number detected |
| [`medicare-beneficiary-identifier`](#medicare-beneficiary-identifier) | medium | high | Medicare beneficiary identifier (MBI/HICN) detected |
| [`national-provider-identifier`](#national-provider-identifier) | medium | high | National Provider Identifier detected |
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

### dea-number

DEA prescriber registration number detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `healthcare`, `prescriber` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\bDEA[:\s#=-]*[A-Z]{2}[0-9]{7}\b
```

**Input that fires** (verified by the liveness test):

```text
DEA: BJ1234563
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

### healthcare-encryption-disabled

Encryption explicitly disabled near patient or PHI data; addressable encryption is expected at rest

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `healthcare`, `phi`, `encryption` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(?:\bphi\b|patient|medical)[\w\s,()\[\].-]{0,40}\bencrypt\w*\s*[:=]{1,2}\s*(?:false|0|no|none)\b|encrypt\w*\s*[:=]{1,2}\s*(?:false|0|no|none)\b[\w\s,()\[\].-]{0,40}(?:\bphi\b|patient|medical)
```

**Reference**: <https://www.hhs.gov/hipaa/for-professionals/security/guidance/encryption/index.html>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
patient_…ve, encryption = false
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

### healthcare-phi-emailed

PHI routed through email; unsecured email is a leading cause of reported healthcare breaches

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `healthcare`, `phi`, `email` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(?:(?:mailto:[^\s"\x27]*(?:patient|mrn|medical))|(?:send_?mail\s*\([^)]{0,80}(?:\bpatient|\bmrn|\bdiagnos|\bmedical))).*
```

**Input that fires** (verified by the liveness test):

```text
mailto:patient@clinic.example
```

### healthcare-phi-hardcoded

Hard-coded patient identifier literal; PHI belongs in systems of record, not source control

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `healthcare`, `phi`, `hardcoded` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:patient[_ ]?(?:name|id|address|phone|dob|email)|medical[_ ]?record|mrn|diagnosis)\w*\s*[:=]{1,2}\s*["\x27][^"\x27]{3,}["\x27]
```

**Input that fires** (verified by the liveness test):

```text
patient_name = "Jane Doe"
```

### healthcare-phi-in-url-query

Patient identifier in a URL query string; URLs persist in history, referrers, and access logs

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `healthcare`, `phi`, `url` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i).*[?&](?:patient(?:_id)?|mrn|ssn|dob|medical[_ ]?record)[a-z_]*=[^&"\x27\s]+
```

**Input that fires** (verified by the liveness test):

```text
/search?patient_id=483920114
```

### healthcare-phi-logged

PHI appears in a log or print statement; protected health information must not reach application logs

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `healthcare`, `phi`, `logging` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(?:\blog(?:ger|ging)?\s*[\.\(:_]|print(?:ln|f)?\s*\(|console\.(?:log|info|warn|error)\s*\(|dbg!|echo\s)[^\n;]{0,80}(?:\bpatient|\bmrn\b|\bdiagnos|\bmedical[_ ]?record|\bphi\b).*
```

**Reference**: <https://www.hhs.gov/hipaa/for-professionals/security/guidance/security-rule-guidance/index.html>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
logger.info("patient MRN96883…24")
```

### healthcare-phi-plaintext-endpoint

Patient or clinical resource referenced over plaintext HTTP; PHI in transit requires encryption

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `healthcare`, `phi`, `transport` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)["\x27]http://[^"\x27\s]*(?:patient|medical|clinical|phi|health)[^"\x27\s]*["\x27]
```

**Reference**: <https://www.hhs.gov/hipaa/for-professionals/security/guidance/cybersecurity/index.html>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
"http://api.clinic.local/patient-…ds"
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

### healthcare-select-star-phi-table

SELECT * over a PHI table; the minimum-necessary standard calls for selecting only required columns

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `healthcare`, `phi`, `minimum-necessary` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)select\s+\*\s+from\s+(?:patients?|medical_\w+|health_?\w+|clinical_\w+|encounters?|diagnos\w+|prescriptions?|medications?|claims)\b
```

**Input that fires** (verified by the liveness test):

```text
SELECT * FROM patients
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

### medicare-beneficiary-identifier

Medicare beneficiary identifier (MBI/HICN) detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `healthcare`, `medicare` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:MBI|HICN|MCR)[:\s#=-]*[0-9][A-Z0-9]{9,10}\b
```

**Input that fires** (verified by the liveness test):

```text
MBI: 1EG4TE5MK73
```

### national-provider-identifier

National Provider Identifier detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `healthcare`, `provider` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\bNPI[:\s#=-]*[0-9]{10}\b
```

**Input that fires** (verified by the liveness test):

```text
NPI: 1234567893
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
