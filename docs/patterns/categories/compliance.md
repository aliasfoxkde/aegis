# compliance patterns

Regulatory frameworks: GDPR, HIPAA, PCI-DSS, SOC 2

**33 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`ccpa-consumer-rights`](#ccpa-consumer-rights) | low | high | CCPA consumer rights reference detected |
| [`ccpa-reference`](#ccpa-reference) | low | medium | CCPA reference detected |
| [`cobit`](#cobit) | low | medium | COBIT reference detected |
| [`coppa`](#coppa) | high | high | COPPA reference detected |
| [`coso`](#coso) | low | medium | COSO framework reference detected |
| [`data-residency`](#data-residency) | medium | high | Data residency requirement reference detected |
| [`data-retention`](#data-retention) | medium | high | Data retention policy reference detected |
| [`fedramp`](#fedramp) | medium | high | FedRAMP reference detected |
| [`ferpa`](#ferpa) | medium | high | FERPA reference detected |
| [`gdpr-article-17`](#gdpr-article-17) | low | high | GDPR Article 17 (Right to Erasure) reference detected |
| [`gdpr-article-25`](#gdpr-article-25) | low | high | GDPR Article 25 (Data Protection by Design) reference detected |
| [`gdpr-article-32`](#gdpr-article-32) | medium | high | GDPR Article 32 (Security of Processing) reference detected |
| [`gdpr-reference`](#gdpr-reference) | low | medium | GDPR reference detected |
| [`glba`](#glba) | medium | high | GLBA (Gramm-Leach-Bliley Act) reference detected |
| [`hipaa-phi`](#hipaa-phi) | high | high | HIPAA Protected Health Information (PHI) reference detected |
| [`hipaa-reference`](#hipaa-reference) | low | medium | HIPAA reference detected |
| [`hipaa-safeguards`](#hipaa-safeguards) | medium | high | HIPAA safeguards reference detected |
| [`hitrust`](#hitrust) | medium | high | HITRUST reference detected |
| [`iso-27001`](#iso-27001) | low | high | ISO 27001 reference detected |
| [`iso-27002`](#iso-27002) | low | high | ISO 27002 reference detected |
| [`iso-9001`](#iso-9001) | low | medium | ISO 9001 reference detected |
| [`lgpd`](#lgpd) | low | medium | LGPD (Brazilian GDPR) reference detected |
| [`nist-800-190`](#nist-800-190) | medium | high | NIST SP 800-190 (Container Security) reference detected |
| [`nist-800-53`](#nist-800-53) | medium | high | NIST SP 800-53 reference detected |
| [`nist-framework`](#nist-framework) | low | medium | NIST Cybersecurity Framework reference detected |
| [`pa-dss`](#pa-dss) | high | high | PA-DSS reference detected |
| [`pci-cardholder-data`](#pci-cardholder-data) | high | high | PCI cardholder data reference detected |
| [`pci-dss`](#pci-dss) | medium | high | PCI DSS reference detected |
| [`pipl`](#pipl) | low | medium | PIPL (China Personal Information Protection Law) reference detected |
| [`popia`](#popia) | low | medium | POPIA (South Africa) reference detected |
| [`soc2-reference`](#soc2-reference) | low | medium | SOC 2 reference detected |
| [`soc2-trust-criteria`](#soc2-trust-criteria) | medium | high | SOC 2 trust service criteria detected |
| [`sox-compliance`](#sox-compliance) | low | medium | SOX compliance reference detected |

## Pattern details

### ccpa-consumer-rights

CCPA consumer rights reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `ccpa`, `privacy` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(right\s*to\s*know|right\s*to\s*delete|right\s*to\s*opt[-_]?out)
```

**Reference**: <https://oag.ca.gov/privacy/ccpa>

**Input that fires** (verified by the liveness test):

```text
right to know
```

### ccpa-reference

CCPA reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `ccpa`, `privacy` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)ccpa|california\s+consumer\s+privacy
```

**Reference**: <https://oag.ca.gov/privacy/ccpa>

**Input that fires** (verified by the liveness test):

```text
ccpa
```

### cobit

COBIT reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `cobit`, `governance` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)cobit|control\s*objectives\s*for\s*information
```

**Reference**: <https://www.isaca.org/resources/cobit>

**Input that fires** (verified by the liveness test):

```text
cobit
```

### coppa

COPPA reference detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `coppa`, `children` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)coppa|children['\s]+online\s*privacy\s*protection
```

**Reference**: <https://www.ftc.gov/legal-library/browse/rules/childrens-online-privacy-protection-rule-coppa>

**Input that fires** (verified by the liveness test):

```text
coppa
```

### coso

COSO framework reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `coso`, `governance` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)coso|committee\s*of\s*sponsoring\s*organizations
```

**Reference**: <https://www.coso.org/>

**Input that fires** (verified by the liveness test):

```text
coso
```

### data-residency

Data residency requirement reference detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `data-residency`, `privacy` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)data\s*residency|data\s*sovereignty|data\s*localization
```

**Input that fires** (verified by the liveness test):

```text
data residency
```

### data-retention

Data retention policy reference detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `data-retention`, `records` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)data\s*retention|record\s*retention|document\s*retention
```

**Input that fires** (verified by the liveness test):

```text
data retention
```

### fedramp

FedRAMP reference detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `fedramp`, `government` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)fedramp|federal\s*risk\s*and\s*authorization
```

**Reference**: <https://www.fedramp.gov/>

**Input that fires** (verified by the liveness test):

```text
fedramp
```

### ferpa

FERPA reference detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `ferpa`, `education` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)ferpa|family\s*educational\s*rights
```

**Reference**: <https://www2.ed.gov/policy/gen/guid/fpco/ferpa/index.html>

**Input that fires** (verified by the liveness test):

```text
ferpa
```

### gdpr-article-17

GDPR Article 17 (Right to Erasure) reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `gdpr`, `privacy` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)article\s*17|right\s*to\s*erasure
```

**Reference**: <https://gdpr.eu/article-17-right-to-erasure/>

**Input that fires** (verified by the liveness test):

```text
article 17
```

### gdpr-article-25

GDPR Article 25 (Data Protection by Design) reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `gdpr`, `privacy` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)article\s*25|data\s*by\s*design|privacy\s*by\s*design
```

**Reference**: <https://gdpr.eu/article-25-data-protection-by-design/>

**Input that fires** (verified by the liveness test):

```text
article 25
```

### gdpr-article-32

GDPR Article 32 (Security of Processing) reference detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `gdpr`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)article\s*32|security\s*of\s*processing
```

**Reference**: <https://gdpr.eu/article-32-security-of-processing/>

**Input that fires** (verified by the liveness test):

```text
article 32
```

### gdpr-reference

GDPR reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `gdpr`, `privacy` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)gdpr|general\s+data\s+protection
```

**Reference**: <https://gdpr.eu/>

**Input that fires** (verified by the liveness test):

```text
gdpr
```

### glba

GLBA (Gramm-Leach-Bliley Act) reference detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `glba`, `finance` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)glba|gramm[-_]?leach[-_]?bliley
```

**Reference**: <https://www.ftc.gov/privacy/privacyinitiatives/glbact>

**Input that fires** (verified by the liveness test):

```text
glba
```

### hipaa-phi

HIPAA Protected Health Information (PHI) reference detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `hipaa`, `phi` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)phi|protected\s*health\s*information
```

**Reference**: <https://www.hhs.gov/hipaa/for-professionals/special-topics/health-information-privacy/>

**Input that fires** (verified by the liveness test):

```text
phi
```

### hipaa-reference

HIPAA reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `hipaa`, `healthcare` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)hipaa|health\s+insurance\s+portability
```

**Reference**: <https://www.hhs.gov/hipaa/>

**Input that fires** (verified by the liveness test):

```text
hipaa
```

### hipaa-safeguards

HIPAA safeguards reference detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `hipaa`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)hipaa\s*safeguards|administrative\s*safeguards|physical\s*safeguards|technical\s*safeguards
```

**Reference**: <https://www.hhs.gov/hipaa/for-professionals/security/>

**Input that fires** (verified by the liveness test):

```text
hipaa safeguards
```

### hitrust

HITRUST reference detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `hitrust`, `healthcare` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)hitrust|health\s*information\s*trust
```

**Reference**: <https://hitrustalliance.net/>

**Input that fires** (verified by the liveness test):

```text
hitrust
```

### iso-27001

ISO 27001 reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `iso27001`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)iso\s*27001|iso\s*iec\s*27001
```

**Reference**: <https://www.iso.org/isoiec-27001-information-security.html>

**Input that fires** (verified by the liveness test):

```text
iso 27001
```

### iso-27002

ISO 27002 reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `iso27002`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)iso\s*27002|information\s*security\s*controls
```

**Reference**: <https://www.iso.org/standard/75652.html>

**Input that fires** (verified by the liveness test):

```text
iso 27002
```

### iso-9001

ISO 9001 reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `iso9001`, `quality` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)iso\s*9001|quality\s*management
```

**Reference**: <https://www.iso.org/iso-9001-quality-management.html>

**Input that fires** (verified by the liveness test):

```text
iso 9001
```

### lgpd

LGPD (Brazilian GDPR) reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `lgpd`, `privacy` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)lgpd|lei\s*geral\s*de\s*proteção
```

**Reference**: <https://www.gov.br/cidadania/pt-br/acesso-a-informacao/lgpd>

**Input that fires** (verified by the liveness test):

```text
lgpd
```

### nist-800-190

NIST SP 800-190 (Container Security) reference detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `nist`, `container` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)nist\s*800[-_]?190|container\s*security\s*guide
```

**Reference**: <https://csrc.nist.gov/publications/detail/sp/800-190/final>

**Input that fires** (verified by the liveness test):

```text
nist 800_190
```

### nist-800-53

NIST SP 800-53 reference detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `nist`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)nist\s*800[-_]?53|sp\s*800[-_]?53
```

**Reference**: <https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final>

**Input that fires** (verified by the liveness test):

```text
nist 800-53
```

### nist-framework

NIST Cybersecurity Framework reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `nist`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)nist\s*framework|csf|cybersecurity\s*framework
```

**Reference**: <https://www.nist.gov/cyberframework>

**Input that fires** (verified by the liveness test):

```text
nist framework
```

### pa-dss

PA-DSS reference detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `pa-dss`, `payment` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)pa[-_]?dss|payment\s*application\s*data\s*security
```

**Reference**: <https://www.pcisecuritystandards.org/>

**Input that fires** (verified by the liveness test):

```text
pa-dss
```

### pci-cardholder-data

PCI cardholder data reference detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `pci-dss`, `card-data` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\bcardholder(?:'s)?\s+data\b|\bPAN\b|\bprimary\s+account\s+number\b
```

**Reference**: <https://www.pcisecuritystandards.org/pci_security/>

**Input that fires** (verified by the liveness test):

```text
cardholder's data
```

### pci-dss

PCI DSS reference detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `pci-dss`, `payment` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)pci\s*dss|payment\s*card\s*industry
```

**Reference**: <https://www.pcisecuritystandards.org/>

**Input that fires** (verified by the liveness test):

```text
pci dss
```

### pipl

PIPL (China Personal Information Protection Law) reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `pipl`, `privacy` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)pipl|china\s*personal\s*information\s*protection
```

**Reference**: <https://www.cac.gov.cn/2021-08/20/c_1631050028355286.htm>

**Input that fires** (verified by the liveness test):

```text
pipl
```

### popia

POPIA (South Africa) reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `popia`, `privacy` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)popia|protection\s*of\s*personal\s*information
```

**Reference**: <https://popia.co.za/>

**Input that fires** (verified by the liveness test):

```text
popia
```

### soc2-reference

SOC 2 reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `soc2`, `audit` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)soc\s*2|service\s*organization\s*control
```

**Reference**: <https://www.aicpa.org/soc2>

**Input that fires** (verified by the liveness test):

```text
soc 2
```

### soc2-trust-criteria

SOC 2 trust service criteria detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `soc2`, `trust-services` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(security|availability|processing\s*integrity|confidentiality|privacy)\s*(criteria|principle)
```

**Reference**: <https://www.aicpa.org/soc2>

**Input that fires** (verified by the liveness test):

```text
security criteria
```

### sox-compliance

SOX compliance reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `compliance`, `sox`, `finance` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)sox|sarbanes[-_]?oxley
```

**Reference**: <https://www.soxlaw.com/>

**Input that fires** (verified by the liveness test):

```text
sox
```
