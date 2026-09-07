# finance patterns

Financial data handling rules

**6 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`aba-routing-number`](#aba-routing-number) | medium | high | ABA routing number detected |
| [`ethereum-address`](#ethereum-address) | medium | high | Ethereum address detected |
| [`finance-bitcoin-address`](#finance-bitcoin-address) | medium | high | Bitcoin address detected |
| [`finance-iban`](#finance-iban) | medium | high | IBAN (International Bank Account Number) detected |
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
