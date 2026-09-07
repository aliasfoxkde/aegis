# devops patterns

CI/CD pipeline and deployment checks

**15 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`ansible-vault`](#ansible-vault) | medium | high | Ansible vault encrypted content detected |
| [`ci-bypass`](#ci-bypass) | high | high | CI/CD bypass marker detected |
| [`ci-secret-hardcoded`](#ci-secret-hardcoded) | critical | high | Hardcoded CI/CD secret detected |
| [`debug-endpoint`](#debug-endpoint) | low | medium | Debug/test endpoint detected |
| [`docker-socket`](#docker-socket) | high | high | Docker socket reference detected |
| [`dockerignore-missing`](#dockerignore-missing) | low | medium | Dockerignore file reference detected |
| [`env-file-in-git`](#env-file-in-git) | high | high | .env file may be committed to git |
| [`exposed-port`](#exposed-port) | low | high | Exposed port in Dockerfile detected |
| [`hardcoded-ip`](#hardcoded-ip) | medium | medium | Hardcoded IP address detected |
| [`kubeconfig-reference`](#kubeconfig-reference) | medium | high | Kubernetes config reference detected |
| [`latest-tag`](#latest-tag) | medium | high | Using latest tag in Dockerfile |
| [`privileged-container`](#privileged-container) | high | high | Privileged container configuration detected |
| [`root-user`](#root-user) | medium | high | Root user in Dockerfile detected |
| [`secrets-in-dockerfile`](#secrets-in-dockerfile) | high | medium | Potential secret in Dockerfile detected |
| [`terraform-state`](#terraform-state) | high | high | Terraform state file detected |

## Pattern details

### ansible-vault

Ansible vault encrypted content detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ansible`, `secrets` |

**Match pattern** (Rust `regex` syntax):

```regex
\$ANSIBLE_VAULT
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
$ANSIBLE_…LT
```

### ci-bypass

CI/CD bypass marker detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ci-cd`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(bypass|skip|disable|ignore).*(ci|pipeline|check|test|lint)
```

**Input that fires** (verified by the liveness test):

```text
bypass3sq _hhz-DnVUci
```

### ci-secret-hardcoded

Hardcoded CI/CD secret detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `3.5` |
| Tags | `ci-cd`, `secrets` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(gh_token|github_token|circle_token|jenkins_api).*['"][a-zA-Z0-9]{10,}
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
gh_token…hD'j7KUu4iwZL
```

### debug-endpoint

Debug/test endpoint detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `endpoint`, `debug` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(debug|test|dev|staging).*(endpoint|api|route)
```

**Input that fires** (verified by the liveness test):

```text
debug6c 9 HxBendpoint
```

### docker-socket

Docker socket reference detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `docker`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(/var/run/docker\.sock|/run/docker\.sock)
```

**Input that fires** (verified by the liveness test):

```text
/var/run/docker.sock
```

### dockerignore-missing

Dockerignore file reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `docker`, `best-practice` |

**Match pattern** (Rust `regex` syntax):

```regex
^\.dockerignore
```

**Input that fires** (verified by the liveness test):

```text
.dockerignore
```

### env-file-in-git

.env file may be committed to git

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git`, `secrets`, `devops` |

**Match pattern** (Rust `regex` syntax):

```regex
\.env(\.\w+)?\b
```

**Input that fires** (verified by the liveness test):

```text
.env.cH5dv_bix8h
```

### exposed-port

Exposed port in Dockerfile detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `docker`, `network` |

**Match pattern** (Rust `regex` syntax):

```regex
EXPOSE\s+\d{2,5}
```

**Input that fires** (verified by the liveness test):

```text
EXPOSE 75645
```

### hardcoded-ip

Hardcoded IP address detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ip`, `hardcoded`, `devops` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b
```

**Input that fires** (verified by the liveness test):

```text
279.273.375.553
```

### kubeconfig-reference

Kubernetes config reference detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `config` |

**Match pattern** (Rust `regex` syntax):

```regex
(\.kube/config|kubeconfig)
```

**Input that fires** (verified by the liveness test):

```text
.kube/config
```

### latest-tag

Using latest tag in Dockerfile

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `docker`, `best-practice` |

**Match pattern** (Rust `regex` syntax):

```regex
:latest
```

**Input that fires** (verified by the liveness test):

```text
:latest
```

### privileged-container

Privileged container configuration detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `docker`, `security`, `container` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(privileged|--privileged)
```

**Input that fires** (verified by the liveness test):

```text
privileged
```

### root-user

Root user in Dockerfile detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `docker`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(USER\s+root|RUN\s+.*chmod.*0777)
```

**Input that fires** (verified by the liveness test):

```text
USER root
```

### secrets-in-dockerfile

Potential secret in Dockerfile detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `docker`, `secrets` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:ARG|ENV)\b[^\n]*(?:SECRET|KEY|TOKEN|PASSWORD)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
ENV-x2Cf…ET
```

### terraform-state

Terraform state file detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `infrastructure` |

**Match pattern** (Rust `regex` syntax):

```regex
terraform\.tfstate
```

**Input that fires** (verified by the liveness test):

```text
terraform.tfstate
```
