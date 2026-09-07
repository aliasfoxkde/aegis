# pii patterns

Personal data: emails, phones, national IDs

**39 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`api-key-field`](#api-key-field) | high | high | API key field with value detected |
| [`australian-tfn`](#australian-tfn) | high | medium | Australian Tax File Number (TFN) detected |
| [`aws-access-key`](#aws-access-key) | critical | high | AWS Access Key ID detected |
| [`bank-routing-number`](#bank-routing-number) | high | medium | Bank routing number (ABA) detected |
| [`bitcoin-address`](#bitcoin-address) | medium | high | Bitcoin address detected |
| [`canadian-sin`](#canadian-sin) | high | high | Canadian Social Insurance Number (SIN) detected |
| [`consent-record`](#consent-record) | low | high | User consent record detected |
| [`credit-card-amex`](#credit-card-amex) | critical | high | American Express credit card number detected |
| [`credit-card-discover`](#credit-card-discover) | critical | high | Discover credit card number detected |
| [`credit-card-mastercard`](#credit-card-mastercard) | critical | high | Mastercard credit card number detected |
| [`credit-card-number-generic`](#credit-card-number-generic) | critical | high | Generic credit card number detected |
| [`credit-card-visa`](#credit-card-visa) | critical | high | Visa credit card number detected |
| [`cvv`](#cvv) | critical | high | Card verification value (CVV/CVC) detected |
| [`data-processing`](#data-processing) | low | high | Data processing agreement reference detected |
| [`date-of-birth`](#date-of-birth) | medium | medium | Date of birth field detected |
| [`drivers-license`](#drivers-license) | high | medium | Driver's license number detected |
| [`ein`](#ein) | medium | high | Employer Identification Number (EIN) detected |
| [`email-address`](#email-address) | low | high | Email address detected |
| [`full-name`](#full-name) | low | medium | Full name field detected |
| [`gdpr-personal-data`](#gdpr-personal-data) | low | high | Reference to personal data detected |
| [`health-insurance-number`](#health-insurance-number) | high | medium | Health insurance number detected |
| [`iban`](#iban) | high | high | International Bank Account Number (IBAN) detected |
| [`indian-aadhaar`](#indian-aadhaar) | high | high | Indian Aadhaar number detected |
| [`international-phone`](#international-phone) | low | medium | International phone number detected |
| [`itin`](#itin) | high | high | Individual Taxpayer Identification Number (ITIN) detected |
| [`medical-record-number`](#medical-record-number) | high | medium | Medical Record Number (MRN) detected |
| [`military-id`](#military-id) | high | medium | Military ID detected |
| [`national-id`](#national-id) | high | medium | National ID number detected |
| [`passport-number`](#passport-number) | high | medium | Passport number detected |
| [`password-field`](#password-field) | high | high | Password field with value detected |
| [`phone-number`](#phone-number) | low | medium | Phone number detected |
| [`prescription-number`](#prescription-number) | medium | medium | Prescription number detected |
| [`right-to-erasure`](#right-to-erasure) | low | high | Right to erasure request detected |
| [`ssn`](#ssn) | high | high | Social Security Number (SSN) detected |
| [`ssn-no-dashes`](#ssn-no-dashes) | high | medium | Possible SSN without dashes detected |
| [`street-address`](#street-address) | medium | medium | Street address detected |
| [`uk-national-insurance`](#uk-national-insurance) | high | high | UK National Insurance number detected |
| [`username-field`](#username-field) | low | medium | Username field with value detected |
| [`zip-code`](#zip-code) | low | high | US ZIP code detected |

## Pattern details

### api-key-field

API key field with value detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `api-key`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(api\s*key|apikey|api\s*token)\s*[:=]\s*['\"][^'\"]{10,}
```

**Input that fires** (verified by the liveness test):

```text
api key : "6fVs2J xm=bsJrWZBMa
```

### australian-tfn

Australian Tax File Number (TFN) detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `australia`, `tax` |

**Match pattern** (Rust `regex` syntax):

```regex
\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b
```

**Reference**: <https://www.ato.gov.au/individual/tax-file-number>

**Input that fires** (verified by the liveness test):

```text
227-927 472
```

### aws-access-key

AWS Access Key ID detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `aws`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
AKIA[0-9A-Z]{16}
```

**Reference**: <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
AKIAAV8J…LR
```

### bank-routing-number

Bank routing number (ABA) detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `banking`, `financial` |

**Match pattern** (Rust `regex` syntax):

```regex
\b\d{9}\b
```

**Reference**: <https://en.wikipedia.org/wiki/ABA_routing_transit_number>

**Input that fires** (verified by the liveness test):

```text
378772374
```

### bitcoin-address

Bitcoin address detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `cryptocurrency`, `financial` |

**Match pattern** (Rust `regex` syntax):

```regex
\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b
```

**Reference**: <https://en.wikipedia.org/wiki/Bitcoin>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
35SRMX4E…LZ
```

### canadian-sin

Canadian Social Insurance Number (SIN) detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `canada`, `sin` |

**Match pattern** (Rust `regex` syntax):

```regex
\b\d{3}-\d{3}-\d{3}\b
```

**Reference**: <https://www.canada.ca/en/employment-social-development/services/sin.html>

**Input that fires** (verified by the liveness test):

```text
697-237-879
```

### consent-record

User consent record detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `consent`, `privacy` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)consent\s*(record|management|given)
```

**Reference**: <https://gdpr.eu/article-7-conditions-for-consent/>

**Input that fires** (verified by the liveness test):

```text
consent record
```

### credit-card-amex

American Express credit card number detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `payment`, `financial` |

**Match pattern** (Rust `regex` syntax):

```regex
\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b
```

**Reference**: <https://en.wikipedia.org/wiki/Payment_card_number>

**Input that fires** (verified by the liveness test):

```text
3486 977666-72395
```

### credit-card-discover

Discover credit card number detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `payment`, `financial` |

**Match pattern** (Rust `regex` syntax):

```regex
\b6(?:011|5[0-9]{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b
```

**Reference**: <https://en.wikipedia.org/wiki/Payment_card_number>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
6011 8422-922…32
```

### credit-card-mastercard

Mastercard credit card number detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `payment`, `financial` |

**Match pattern** (Rust `regex` syntax):

```regex
\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b
```

**Reference**: <https://en.wikipedia.org/wiki/Payment_card_number>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
5198-265…79 7674
```

### credit-card-number-generic

Generic credit card number detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `payment`, `financial` |

**Match pattern** (Rust `regex` syntax):

```regex
\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b
```

**Reference**: <https://en.wikipedia.org/wiki/Payment_card_number>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
42877729…43
```

### credit-card-visa

Visa credit card number detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `payment`, `financial` |

**Match pattern** (Rust `regex` syntax):

```regex
\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b
```

**Reference**: <https://en.wikipedia.org/wiki/Payment_card_number>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
4427-849…35 8469
```

### cvv

Card verification value (CVV/CVC) detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `payment`, `cvv` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:cvv|cvc|security\s*code)\s*[:=]\s*\d{3,4}\b
```

**Reference**: <https://en.wikipedia.org/wiki/Card_security_code>

**Input that fires** (verified by the liveness test):

```text
cvv = 5592
```

### data-processing

Data processing agreement reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `gdpr`, `privacy` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)data\s*processing\s*agreement
```

**Reference**: <https://gdpr.eu/article-28-processors/>

**Input that fires** (verified by the liveness test):

```text
data processing agreement
```

### date-of-birth

Date of birth field detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `dob`, `personal` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(dob|date\s*of\s*birth|birth\s*date|birthday)\s*[:=]\s*['\"]?\d{1,2}[/-]\d{1,2}[/-]\d{2,4}
```

**Input that fires** (verified by the liveness test):

```text
dob : '33-88/3737
```

### drivers-license

Driver's license number detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `license`, `personal` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(drivers?\s*license|dl\s*#|license\s*#)\s*[:=]\s*['\"]?[A-Z0-9]{5,20}
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
drivers license = 'JPS92ZKL…W8
```

### ein

Employer Identification Number (EIN) detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `ein`, `business` |

**Match pattern** (Rust `regex` syntax):

```regex
\b\d{2}-\d{7}\b
```

**Reference**: <https://www.irs.gov/employers/taxpayer-identification-numbers>

**Input that fires** (verified by the liveness test):

```text
29-8586847
```

### email-address

Email address detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `email`, `personal` |

**Match pattern** (Rust `regex` syntax):

```regex
\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)@example\.(?:com|org|net)\z
```
**Reference**: <https://tools.ietf.org/html/rfc5322>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
e5xD+LQW.LKiKf@kGb.xGfKzQfX…Hq
```

### full-name

Full name field detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `name`, `personal` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(first\s+name|last\s+name|full\s+name|surname|given\s+name)\s*[:=]\s*['\"][A-Za-z\s]+['\"]
```

**Input that fires** (verified by the liveness test):

```text
first name = "oiBEWSm'
```

### gdpr-personal-data

Reference to personal data detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `gdpr`, `privacy` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)personal\s*data
```

**Reference**: <https://gdpr.eu/article-4-definitions/>

**Input that fires** (verified by the liveness test):

```text
personal data
```

### health-insurance-number

Health insurance number detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `insurance`, `health` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(health\s*insurance|insurance\s*id|member\s*id)\s*[:=]\s*['\"]?[A-Z0-9]{6,15}
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
health insurance = "W5Y5NTFS…MJ
```

### iban

International Bank Account Number (IBAN) detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `banking`, `international` |

**Match pattern** (Rust `regex` syntax):

```regex
\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b
```

**Reference**: <https://en.wikipedia.org/wiki/International_Bank_Account_Number>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
WY93MAKT…WJ
```

### indian-aadhaar

Indian Aadhaar number detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `india`, `aadhaar` |

**Match pattern** (Rust `regex` syntax):

```regex
\b[2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4}\b
```

**Reference**: <https://uidai.gov.in/>

**Input that fires** (verified by the liveness test):

```text
6662 4977 6934
```

### international-phone

International phone number detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `phone`, `international` |

**Match pattern** (Rust `regex` syntax):

```regex
\+\d{1,3}[-.\s]?(?:\(\d{1,4}\)|\d{1,4})[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b
```

**Input that fires** (verified by the liveness test):

```text
+686 (5377) 9473.7756
```

### itin

Individual Taxpayer Identification Number (ITIN) detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `itin`, `tax` |

**Match pattern** (Rust `regex` syntax):

```regex
\b9\d{2}-\d{2}-\d{4}\b
```

**Reference**: <https://www.irs.gov/individuals/itin>

**Input that fires** (verified by the liveness test):

```text
933-38-4349
```

### medical-record-number

Medical Record Number (MRN) detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `medical`, `health` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(mrn|medical\s*record|patient\s*id)\s*[:=]\s*['\"]?\d{5,10}
```

**Input that fires** (verified by the liveness test):

```text
mrn = '2473463923
```

### military-id

Military ID detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `military`, `government` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(military\s*id|service\s*number|us\s*military)\s*[:=]\s*['\"]?[A-Z0-9]{6,10}
```

**Input that fires** (verified by the liveness test):

```text
military id = "FZUWH4GUEB
```

### national-id

National ID number detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `national-id`, `personal` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(national\s*id|identity\s*card|id\s*number)\s*[:=]\s*['\"]?[A-Z0-9]{5,20}
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
national id : '4CZCXNA4…84
```

### passport-number

Passport number detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `passport`, `travel` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(passport|passport\s*#|passport\s*number)\s*[:=]\s*['\"]?[A-Z0-9]{6,9}
```

**Input that fires** (verified by the liveness test):

```text
passport : 'C6FBGJEEM
```

### password-field

Password field with value detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `password`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(password|passwd|pwd|secret)\s*[:=]\s*['\"][^'\"]{3,}
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)['\"](example|placeholder|changeme|change-me|dummy|sample|test|testing|redacted|password|not-a-real-?password|\$\{[^}]*\}|<[^>]*>|\*\*\*)['\"]
```
**Input that fires** (verified by the liveness test):

```text
password : 'j4zRQT
```

### phone-number

Phone number detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `phone`, `personal` |

**Match pattern** (Rust `regex` syntax):

```regex
\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b
```

**Input that fires** (verified by the liveness test):

```text
1 (258)-339 7384
```

### prescription-number

Prescription number detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `medical`, `prescription` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(prescription|rx\s*#)\s*[:=]\s*['\"]?\d{5,10}
```

**Input that fires** (verified by the liveness test):

```text
prescription : "5497743544
```

### right-to-erasure

Right to erasure request detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `gdpr`, `privacy` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(right\s*to\s*erasure|right\s*to\s*be\s*forgotten|delete\s*request)
```

**Reference**: <https://gdpr.eu/article-17-right-to-erasure/>

**Input that fires** (verified by the liveness test):

```text
right to erasure
```

### ssn

Social Security Number (SSN) detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `ssn`, `personal` |

**Match pattern** (Rust `regex` syntax):

```regex
\b\d{3}-\d{2}-\d{4}\b
```

**Reference**: <https://www.ssa.gov/history/ssn.html>

**Input that fires** (verified by the liveness test):

```text
845-79-5546
```

### ssn-no-dashes

Possible SSN without dashes detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `ssn`, `personal` |

**Match pattern** (Rust `regex` syntax):

```regex
\b\d{3}\d{2}\d{4}\b
```

**Reference**: <https://www.ssa.gov/history/ssn.html>

**Input that fires** (verified by the liveness test):

```text
292258736
```

### street-address

Street address detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `address`, `location` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(address|street|street\s*address)\s*[:=]\s*['\"]?\d+\s+[A-Za-z\s]+
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
address : '2667657 cgvLjZRp…em
```

### uk-national-insurance

UK National Insurance number detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `uk`, `government` |

**Match pattern** (Rust `regex` syntax):

```regex
\b[A-Z]{2}\d{6}[A-Z]\b
```

**Reference**: <https://www.gov.uk/national-insurance>

**Input that fires** (verified by the liveness test):

```text
QM265944S
```

### username-field

Username field with value detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `username`, `auth` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(username|user\s*name|login)\s*[:=]\s*['\"][^'\"]{3,}
```

**Input that fires** (verified by the liveness test):

```text
username : 'PAefNJre.b-Zbi.9ijN
```

### zip-code

US ZIP code detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pii`, `zip`, `location` |

**Match pattern** (Rust `regex` syntax):

```regex
\b\d{5}(?:[-\s]\d{4})?\b
```

**Input that fires** (verified by the liveness test):

```text
76282-5895
```
