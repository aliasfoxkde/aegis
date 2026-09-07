# terraform patterns

HashiCorp Terraform issues

**7 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`db-public-access`](#db-public-access) | high | high | Database instance configured with public accessibility |
| [`hardcoded-tf-secrets`](#hardcoded-tf-secrets) | critical | high | Hardcoded secrets detected in Terraform configuration |
| [`s3-public-access`](#s3-public-access) | high | high | S3 bucket configured with public access |
| [`tf-ecs-no-secrets`](#tf-ecs-no-secrets) | medium | high | ECS task definition detected - ensure secrets are not hardcoded |
| [`tf-ecs-privileged`](#tf-ecs-privileged) | critical | high | ECS task definition with privileged mode enabled |
| [`tf-s3-unencrypted`](#tf-s3-unencrypted) | high | high | S3 bucket without server-side encryption |
| [`unencrypted-storage`](#unencrypted-storage) | high | high | Storage resource configured without encryption |

## Pattern details

### db-public-access

Database instance configured with public accessibility

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `database`, `aws` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)publicly_accessible\s*=\s*true|skip_final_snapshot\s*=\s*true
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
publicly…le = true
```

### hardcoded-tf-secrets

Hardcoded secrets detected in Terraform configuration

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `secrets`, `aws`, `hardcoded` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(password\s*=\s*["'][^"']{8,}["']|secret\s*=\s*["'][^"']{8,}["']|api_key\s*=\s*["'][^"']{8,}["']|aws_access_key\s*=\s*["'][^"']{8,}["']|aws_secret_key\s*=\s*["'][^"']{8,}["'])
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
password = 'VuiRYsS2…54'
```

### s3-public-access

S3 bucket configured with public access

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `s3`, `aws`, `public-access` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)acl\s*=\s*["']public-read["']|acl\s*=\s*["']public-read-write["']|acl\s*=\s*["']aws-auth["']|block_public_acls\s*=\s*false|block_public_policy\s*=\s*false
```

**Input that fires** (verified by the liveness test):

```text
acl = "public-read"
```

### tf-ecs-no-secrets

ECS task definition detected - ensure secrets are not hardcoded

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `ecs`, `aws`, `secrets` |

**Match pattern** (Rust `regex` syntax):

```regex
aws_ecs_task_definition
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
aws_ecs_…on
```

### tf-ecs-privileged

ECS task definition with privileged mode enabled

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `ecs`, `aws`, `privilege` |

**Match pattern** (Rust `regex` syntax):

```regex
aws_ecs_task_definition[^{]*\{[^}]*privileged\s*=\s*true
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
aws_ecs_…zB{3WRpacTp…ed = true
```

### tf-s3-unencrypted

S3 bucket without server-side encryption

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `s3`, `aws`, `encryption` |

**Match pattern** (Rust `regex` syntax):

```regex
aws_s3_bucket[^{]*\{[^}]*server_side_encryption_configuration\s*=\s*null
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
aws_s3_b…jX=R{LpX-WJas…on = null
```

### unencrypted-storage

Storage resource configured without encryption

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `storage`, `aws`, `encryption` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)encrypted\s*=\s*false|encryption\s*=\s*false|server_side_encryption_configuration\s*=\s*null
```

**Input that fires** (verified by the liveness test):

```text
encrypted = false
```
