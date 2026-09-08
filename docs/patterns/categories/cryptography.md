# cryptography patterns

Cryptographic primitive misuse: weak hashes, broken modes, predictable key material

**10 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`crypto-ecb-mode`](#crypto-ecb-mode) | high | high | ECB mode selected; identical blocks encrypt identically and leak structure |
| [`crypto-hardcoded-salt`](#crypto-hardcoded-salt) | medium | low | Hard-coded salt string; salts should be random per credential |
| [`crypto-insecure-rsa-padding`](#crypto-insecure-rsa-padding) | high | medium | RSA encryption without OAEP padding; PKCS#1 v1.5 and no-padding are malleable |
| [`crypto-legacy-cipher`](#crypto-legacy-cipher) | high | medium | Legacy cipher (DES, 3DES, RC4, Blowfish) referenced; all are deprecated |
| [`crypto-low-pbkdf2-iterations`](#crypto-low-pbkdf2-iterations) | high | medium | PBKDF2 with fewer than 15000 iterations; below modern brute-force resistance |
| [`crypto-predictable-key-material`](#crypto-predictable-key-material) | high | high | Key, nonce, or seed derived from a non-cryptographic PRNG |
| [`crypto-timing-unsafe-compare`](#crypto-timing-unsafe-compare) | medium | low | MAC or signature compared with == instead of a constant-time compare |
| [`crypto-weak-hmac`](#crypto-weak-hmac) | high | high | HMAC built on MD5 or SHA-1; use SHA-256 or stronger |
| [`crypto-weak-password-hash`](#crypto-weak-password-hash) | high | high | MD5/SHA-1 used to hash a password; both are broken for password storage |
| [`crypto-zero-iv-or-nonce`](#crypto-zero-iv-or-nonce) | high | medium | IV or nonce allocated as all-zero bytes; fixed IVs break CBC/GCM security |

## Pattern details

### crypto-ecb-mode

ECB mode selected; identical blocks encrypt identically and leak structure

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cryptography`, `cipher-mode` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\baes[-_/]ecb\b|\bMODE_ECB\b|['\"]ECB['\"]|\bECBMode\b|NewECB(?:Encryptor|Decryptor)?\b
```

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html>

**Input that fires** (verified by the liveness test):

```text
aes-ecb
```

### crypto-hardcoded-salt

Hard-coded salt string; salts should be random per credential

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cryptography`, `salt` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\bsalt\s*[:=]\s*['\"][a-zA-Z0-9_]{6,}['\"]
```

**Input that fires** (verified by the liveness test):

```text
salt = "n6mXWP9'
```

### crypto-insecure-rsa-padding

RSA encryption without OAEP padding; PKCS#1 v1.5 and no-padding are malleable

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cryptography`, `rsa` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)RSA/(?:ECB|NONE)/(?:PKCS1|NoPadding)|PKCS1_v1_5\.new\s*\(|padding\s*[:=]\s*['\"]?(?:NoPadding|PKCS1v15)['\";\s,]
```

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html>

**Input that fires** (verified by the liveness test):

```text
RSA/ECB/PKCS1
```

### crypto-legacy-cipher

Legacy cipher (DES, 3DES, RC4, Blowfish) referenced; all are deprecated

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cryptography`, `cipher` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:des-ecb|des-cbc|des-ede3?|3des|desede|rc4|arc4|arcfour|blowfish)\b|Crypto\.Cipher\.(?:DES|ARC4|Blowfish)|Cipher\.getInstance\s*\(\s*\"(?:DES|RC4)
```

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html>

**Input that fires** (verified by the liveness test):

```text
des-ecb
```

### crypto-low-pbkdf2-iterations

PBKDF2 with fewer than 15000 iterations; below modern brute-force resistance

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cryptography`, `kdf` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)pbkdf2(?:_hmac)?\s*\([^)]*?,\s*(?:\d{1,4}|1[0-4]\d{3})\s*[,)]|\biterations\s*[:=]\s*(?:\d{1,4}|1[0-4]\d{3})\b
```

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>

**Input that fires** (verified by the liveness test):

```text
iterations = 10000
```

### crypto-predictable-key-material

Key, nonce, or seed derived from a non-cryptographic PRNG

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cryptography`, `randomness` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:key|nonce|salt|seed|secret|token)\w*\s*:?=\s*(?:Math\.random\s*\(\s*\)|random\.random\s*\(\s*\)|new\s+Random\s*\(\s*\)|rand::random\s*(?:::<[^>]*>)?\s*\(\s*\)|rand\.(?:Int|Intn|Float\d*)\s*\([^)]*\))
```

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html>

**Input that fires** (verified by the liveness test):

```text
secret = Math.random()
```

### crypto-timing-unsafe-compare

MAC or signature compared with == instead of a constant-time compare

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cryptography`, `timing` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:mac|digest|signature|hmac|checksum)\w*\s*(?:===|==)\s*[A-Za-z_$].*
```

**Reference**: <https://cwe.mitre.org/data/definitions/208.html>

**Input that fires** (verified by the liveness test):

```text
signature === expected
```

### crypto-weak-hmac

HMAC built on MD5 or SHA-1; use SHA-256 or stronger

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cryptography`, `mac` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\bHmac(?:MD5|SHA1)\b|createHmac\s*\(\s*['\"](?:md5|sha1)['\"]|hmac(?:_new)?\s*\(\s*['\"](?:md5|sha1)['\"]
```

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html>

**Input that fires** (verified by the liveness test):

```text
HmacMD5
```

### crypto-weak-password-hash

MD5/SHA-1 used to hash a password; both are broken for password storage

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cryptography`, `hashing`, `passwords` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:md5|sha1)\s*\(\s*(?:password|passwd|pwd|pass|\$_?post\.)|\b(?:md5|sha1)\.hexdigest\s*\(\s*(?:password|passwd|pass)|createHash\s*\(\s*['\"](?:md5|sha1)['\"]\s*\)\.update\s*\(\s*(?:password|passwd|pwd|pass)|hashlib\.(?:md5|sha1)\s*\(\s*(?:password|passwd|pwd|pw|pass)
```

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>

**Input that fires** (verified by the liveness test):

```text
md5 ( password
```

### crypto-zero-iv-or-nonce

IV or nonce allocated as all-zero bytes; fixed IVs break CBC/GCM security

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cryptography`, `iv` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:iv|nonce)\s*:?=[^;\n]*(?:make\s*\(\s*\[\]byte|new\s+byte\s*\[|Buffer\.alloc\s*\(|bytearray\s*\(|\[0(?:\s*,\s*0){5,}\]).*
```

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
iv :=n8iarZno…ke ( []byteP
```
