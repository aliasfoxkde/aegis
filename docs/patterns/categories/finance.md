# finance patterns

Financial data handling rules

**13 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`aba-routing-number`](#aba-routing-number) | medium | high | ABA routing number detected |
| [`ethereum-address`](#ethereum-address) | medium | high | Ethereum address detected |
| [`finance-balance-read-modify-write`](#finance-balance-read-modify-write) | high | medium | Balance updated by read-modify-write; concurrent updates can lose money without locking |
| [`finance-bitcoin-address`](#finance-bitcoin-address) | medium | high | Bitcoin address detected |
| [`finance-float-equality`](#finance-float-equality) | medium | high | Money compared for exact equality; float residue makes this unreliable |
| [`finance-float-money-field`](#finance-float-money-field) | high | medium | Money held in a binary floating-point field; IEEE 754 cannot represent decimal currency exactly |
| [`finance-iban`](#finance-iban) | medium | high | IBAN (International Bank Account Number) detected |
| [`finance-math-round-money`](#finance-math-round-money) | medium | low | Math.round applied to a money value; banker's-rounding expectations differ |
| [`finance-naive-settlement-now`](#finance-naive-settlement-now) | medium | low | Settlement or expiry timestamp taken from wall-clock now(); timezone and reproducibility hazard |
| [`finance-parsefloat-money`](#finance-parsefloat-money) | medium | low | Money parsed through parseFloat, inheriting binary float error |
| [`finance-tofixed-currency`](#finance-tofixed-currency) | medium | high | toFixed used for currency rounding; binary rounding still applies beneath the formatting |
| [`stripe-publishable-key`](#stripe-publishable-key) | medium | high | Stripe publishable key detected |
| [`swift-bic`](#swift-bic) | medium | high | SWIFT/BIC code detected |

## Pattern details

### aba-routing-number

ABA routing number detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4` |
| Tags | `bank`, `routing`, `finance` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)routing[\s_-]*(number|num|no)?[\s:=]+\b[0-9]{9}\b
```

**Reference**: <https://en.wikipedia.org/wiki/ABA_routing_transit_number>

**Input that fires** (verified by the liveness test):

```text
routing_ -_ -- _no: =:= : = 735982468
```

### ethereum-address

Ethereum address detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `3.5` |
| Tags | `ethereum`, `cryptocurrency`, `wallet` |

**Match pattern** (Rust `regex` syntax):

```regex
\b0x[0-9a-fA-F]{40}\b
```

**Reference**: <https://ethereum.org/en/developers/docs/accounts/>

**Environment value that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
0x85Bfb4…EF
```

### finance-balance-read-modify-write

Balance updated by read-modify-write; concurrent updates can lose money without locking

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `finance`, `concurrency` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:balance|available)\s*:?=\s*(?:\w+\.)?(?:balance|available)\s*[-+*].*
```

**Input that fires** (verified by the liveness test):

```text
balance = balance - amount
```

### finance-bitcoin-address

Bitcoin address detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4.5` |
| Tags | `bitcoin`, `cryptocurrency`, `wallet` |

**Match pattern** (Rust `regex` syntax):

```regex
\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b
```

**Reference**: <https://en.bitcoin.it/wiki/Address>

**Environment value that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
bc1SGuZy…AT
```

### finance-float-equality

Money compared for exact equality; float residue makes this unreliable

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `finance`, `correctness` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:price|amount|total|balance)\w*\s*(?:===|==)\s*[-+]?\d.*
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)(?:_count|_findings|_items|_rows|_lines|_files|_records|_pages|_matches|_size|_length|_number|_num)\b
```
**Input that fires** (verified by the liveness test):

```text
balance == 0.0
```

### finance-float-money-field

Money held in a binary floating-point field; IEEE 754 cannot represent decimal currency exactly

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `finance`, `correctness` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:double|float)\s+(?:price|amount|balance|total|cost|fee|subtotal|salary|payment)s?\b|(?:price|amount|balance|total|cost|fee)s?\s*:\s*float\b
```

**Reference**: <https://martinfowler.com/articles/quantity.html>

**Input that fires** (verified by the liveness test):

```text
double prices
```

### finance-iban

IBAN (International Bank Account Number) detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4` |
| Tags | `bank`, `iban`, `finance` |

**Match pattern** (Rust `regex` syntax):

```regex
\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b
```

**Reference**: <https://en.wikipedia.org/wiki/International_Bank_Account_Number>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
WF73JAC3…84
```

### finance-math-round-money

Math.round applied to a money value; banker's-rounding expectations differ

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `finance`, `rounding` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)Math\.round\s*\([^)]*(?:price|amount|total|balance|cost|fee|cent).*
```

**Input that fires** (verified by the liveness test):

```text
Math.round(totalAmount * 100) / 100
```

### finance-naive-settlement-now

Settlement or expiry timestamp taken from wall-clock now(); timezone and reproducibility hazard

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `finance`, `time` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:settlement|maturity|expiry|expires_at|effective)\w*\s*:?=\s*(?:new\s+Date\s*\(\s*\)|datetime\.now\s*\(\s*\)|Date\.now\s*\(\s*\)|LocalDate\.now\s*\(\s*\)).*
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
settleme…te := datetime.now()
```

### finance-parsefloat-money

Money parsed through parseFloat, inheriting binary float error

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `finance`, `parsing` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)parseFloat\s*\([^)]*(?:price|amount|total|balance|cost|fee).*
```

**Input that fires** (verified by the liveness test):

```text
parseFloat(amountStr)
```

### finance-tofixed-currency

toFixed used for currency rounding; binary rounding still applies beneath the formatting

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `finance`, `correctness` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\.toFixed\s*\(\s*[0-2]\s*\)
```

**Reference**: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number/toFixed>

**Input that fires** (verified by the liveness test):

```text
.toFixed ( 1 )
```

### stripe-publishable-key

Stripe publishable key detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4.5` |
| Tags | `stripe`, `payment`, `api-key` |

**Match pattern** (Rust `regex` syntax):

```regex
\bpk_(?:live|test)_[0-9a-zA-Z]{24,}\b
```

**Reference**: <https://stripe.com/docs/keys>

**Environment value that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
pk_live_…rh
```

### swift-bic

SWIFT/BIC code detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4` |
| Tags | `bank`, `swift`, `bic`, `finance` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:swift|bic)[\s:=]+[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b
```

**Reference**: <https://en.wikipedia.org/wiki/ISO_9362>

**Input that fires** (verified by the liveness test):

```text
swift:::= FJYVFDXZL4U
```
