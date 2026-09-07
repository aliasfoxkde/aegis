# cloudformation patterns

AWS CloudFormation template issues

**3 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`cloudformation-iam-lambda-assume-role`](#cloudformation-iam-lambda-assume-role) | medium | high | Detects CloudFormation IAM or Lambda trust policy with wildcard principal |
| [`cloudformation-s3-no-encryption`](#cloudformation-s3-no-encryption) | high | high | Detects CloudFormation S3 bucket without server-side encryption |
| [`cloudformation-s3-public-access`](#cloudformation-s3-public-access) | critical | high | Detects CloudFormation S3 bucket with public access enabled |

## Pattern details

### cloudformation-iam-lambda-assume-role

Detects CloudFormation IAM or Lambda trust policy with wildcard principal

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cloudformation`, `aws`, `iam`, `lambda` |

**Match pattern** (Rust `regex` syntax):

```regex
(Principal\s*:\s*\*|AWS\s*:\s*["\x27]*\*["\x27]*)
```

**Input that fires** (verified by the liveness test):

```text
Principal : *
```

### cloudformation-s3-no-encryption

Detects CloudFormation S3 bucket without server-side encryption

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cloudformation`, `aws`, `s3`, `encryption` |

**Match pattern** (Rust `regex` syntax):

```regex
ServerSideEncryptionByDefault\s*:\s*(?:NOT\s*DEFINED|false|null)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
ServerSi…lt : NOT DEFINED
```

### cloudformation-s3-public-access

Detects CloudFormation S3 bucket with public access enabled

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cloudformation`, `aws`, `s3`, `public-access` |

**Match pattern** (Rust `regex` syntax):

```regex
(PublicAccessBlockConfiguration|BucketPublicAccessBlock)\s*:\s*(?:false|~\s*-\s*true)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
PublicAc…on : false
```
