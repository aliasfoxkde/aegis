# arm patterns

Azure Resource Manager template issues

**2 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`arm-azure-sql-no-firewall`](#arm-azure-sql-no-firewall) | high | high | Detects Azure ARM template SQL server without proper firewall rules |
| [`arm-azure-storage-enable-https`](#arm-azure-storage-enable-https) | high | high | Detects Azure ARM template storage account with HTTPS traffic disabled |

## Pattern details

### arm-azure-sql-no-firewall

Detects Azure ARM template SQL server without proper firewall rules

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `arm`, `azure`, `sql` |

**Match pattern** (Rust `regex` syntax):

```regex
startIpAddress\s*[:=]\s*["\x27]0\.0\.0\.0["\x27]
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
startIpA…ss = "0.0.0.0"
```

### arm-azure-storage-enable-https

Detects Azure ARM template storage account with HTTPS traffic disabled

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `arm`, `azure`, `storage` |

**Match pattern** (Rust `regex` syntax):

```regex
enableHttpsTrafficOnly\s*[:=]\s*(?:false|0|no)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
enableHt…ly : false
```
