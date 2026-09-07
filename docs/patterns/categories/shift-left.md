# shift-left patterns

Early-lifecycle security practices

**20 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`azure-pipeline`](#azure-pipeline) | low | high | Azure Pipeline detected |
| [`checkov-config`](#checkov-config) | low | high | IaC security scanning tool detected |
| [`circleci-config`](#circleci-config) | low | high | CircleCI config detected |
| [`codecov-config`](#codecov-config) | low | high | Code coverage config detected |
| [`drone-ci`](#drone-ci) | low | high | Drone CI config detected |
| [`gitlab-ci-pipeline`](#gitlab-ci-pipeline) | low | high | GitLab CI pipeline detected |
| [`grype-config`](#grype-config) | low | high | Container vulnerability scanning with Grype detected |
| [`integration-test-marker`](#integration-test-marker) | low | high | Integration test marker detected |
| [`jenkinsfile`](#jenkinsfile) | low | high | Jenkinsfile detected |
| [`pr-review-marker`](#pr-review-marker) | low | medium | PR review marker detected |
| [`precommit-marker`](#precommit-marker) | low | high | Pre-commit hook marker detected |
| [`security-test-marker`](#security-test-marker) | low | high | Security test marker detected |
| [`shift-left-dependabot-config`](#shift-left-dependabot-config) | low | high | Dependabot config detected |
| [`shift-left-github-actions-workflow`](#shift-left-github-actions-workflow) | low | high | GitHub Actions workflow detected |
| [`snyk-config`](#snyk-config) | medium | high | Snyk security config detected |
| [`sonarqube-config`](#sonarqube-config) | low | high | SonarQube config detected |
| [`terraform-validate`](#terraform-validate) | low | high | Terraform validate command detected |
| [`travis-yml`](#travis-yml) | low | high | Travis CI config detected |
| [`trivy-config`](#trivy-config) | low | high | Container vulnerability scanning tool detected |
| [`unit-test-marker`](#unit-test-marker) | low | high | Unit test marker detected |

## Pattern details

### azure-pipeline

Azure Pipeline detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `shift-left`, `azure`, `ci-cd` |

**Match pattern** (Rust `regex` syntax):

```regex
azure-pipelines\.ya?ml
```

**Reference**: <https://docs.microsoft.com/en-us/azure/devops/pipelines/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
azure-pi…es.yaml
```

### checkov-config

IaC security scanning tool detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `shift-left`, `checkov`, `iac` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)checkov|terragrunt|terraform-compliance
```

**Reference**: <https://www.checkov.io/>

**Input that fires** (verified by the liveness test):

```text
checkov
```

### circleci-config

CircleCI config detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `shift-left`, `circleci`, `ci-cd` |

**Match pattern** (Rust `regex` syntax):

```regex
\.circleci/config\.yml
```

**Reference**: <https://circleci.com/docs/>

**Input that fires** (verified by the liveness test):

```text
.circleci/config.yml
```

### codecov-config

Code coverage config detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `shift-left`, `coverage`, `quality` |

**Match pattern** (Rust `regex` syntax):

```regex
codecov\.yml|codeclimate\.yml
```

**Reference**: <https://docs.codecov.io/>

**Input that fires** (verified by the liveness test):

```text
codecov.yml
```

### drone-ci

Drone CI config detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `shift-left`, `drone`, `ci-cd` |

**Match pattern** (Rust `regex` syntax):

```regex
\.drone\.yml
```

**Reference**: <https://docs.drone.io/>

**Input that fires** (verified by the liveness test):

```text
.drone.yml
```

### gitlab-ci-pipeline

GitLab CI pipeline detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `shift-left`, `gitlab`, `ci-cd` |

**Match pattern** (Rust `regex` syntax):

```regex
\.gitlab-ci\.yml
```

**Reference**: <https://docs.gitlab.com/ee/ci/yaml/>

**Input that fires** (verified by the liveness test):

```text
.gitlab-ci.yml
```

### grype-config

Container vulnerability scanning with Grype detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `shift-left`, `grype`, `container` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)grype|synthonizer
```

**Reference**: <https://github.com/anchore/grype>

**Input that fires** (verified by the liveness test):

```text
grype
```

### integration-test-marker

Integration test marker detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `shift-left`, `testing`, `integration` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)integration.*test|@IntegrationTest|e2e|e2e.*test
```

**Input that fires** (verified by the liveness test):

```text
integration-@.LXrZdxQtest
```

### jenkinsfile

Jenkinsfile detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `shift-left`, `jenkins`, `ci-cd` |

**Match pattern** (Rust `regex` syntax):

```regex
Jenkinsfile
```

**Reference**: <https://www.jenkins.io/doc/book/pipeline/>

**Input that fires** (verified by the liveness test):

```text
Jenkinsfile
```

### pr-review-marker

PR review marker detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `shift-left`, `pr`, `review` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(pull.request|code.review|review.required)
```

**Input that fires** (verified by the liveness test):

```text
pullnrequest
```

### precommit-marker

Pre-commit hook marker detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `shift-left`, `ci-cd`, `hooks` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(pre-commit|precommit|commit-msg)
```

**Reference**: <https://pre-commit.com/>

**Input that fires** (verified by the liveness test):

```text
pre-commit
```

### security-test-marker

Security test marker detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `shift-left`, `testing`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)security.*test|@SecuredTest|pen.*test|vuln.*test
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
security…st
```

### shift-left-dependabot-config

Dependabot config detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `shift-left`, `dependabot`, `dependencies` |

**Match pattern** (Rust `regex` syntax):

```regex
dependabot\.yml
```

**Reference**: <https://docs.github.com/en/code-security/dependabot>

**Input that fires** (verified by the liveness test):

```text
dependabot.yml
```

### shift-left-github-actions-workflow

GitHub Actions workflow detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `shift-left`, `github`, `ci-cd` |

**Match pattern** (Rust `regex` syntax):

```regex
\.github/workflows/[^/]+\.ya?ml
```

**Reference**: <https://docs.github.com/en/actions/learn-github-actions>

**Input that fires** (verified by the liveness test):

```text
.github/workflows/Y5.yaml
```

### snyk-config

Snyk security config detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `shift-left`, `snyk`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
\.snyk|snyk.*\.yml
```

**Reference**: <https://docs.snyk.io/>

**Input that fires** (verified by the liveness test):

```text
.snyk
```

### sonarqube-config

SonarQube config detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `shift-left`, `sonarqube`, `quality` |

**Match pattern** (Rust `regex` syntax):

```regex
sonar-project\.properties|sonar.*\.yml
```

**Reference**: <https://docs.sonarqube.org/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
sonar-pr…ct.properties
```

### terraform-validate

Terraform validate command detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `shift-left`, `terraform`, `iac` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)terraform\s+validate|terraform\s+plan
```

**Reference**: <https://www.terraform.io/docs/commands/validate.html>

**Input that fires** (verified by the liveness test):

```text
terraform validate
```

### travis-yml

Travis CI config detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `shift-left`, `travis`, `ci-cd` |

**Match pattern** (Rust `regex` syntax):

```regex
\.travis\.yml
```

**Reference**: <https://docs.travis-ci.com/>

**Input that fires** (verified by the liveness test):

```text
.travis.yml
```

### trivy-config

Container vulnerability scanning tool detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `shift-left`, `trivy`, `container` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)trivy|aqua.*security|anchore
```

**Reference**: <https://aquasecurity.github.io/trivy/>

**Input that fires** (verified by the liveness test):

```text
trivy
```

### unit-test-marker

Unit test marker detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `shift-left`, `testing`, `unit` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)@Test|@test|def\s+test_|test\s*\(\s*
```

**Input that fires** (verified by the liveness test):

```text
@Test
```
