# supply-chain patterns

Dependency and artifact supply-chain rules

**35 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`cargo-audit`](#cargo-audit) | medium | high | Cargo audit command detected |
| [`cargo-lock`](#cargo-lock) | medium | high | Rust Cargo.lock detected |
| [`cargo-toml`](#cargo-toml) | low | high | Rust Cargo.toml detected |
| [`dependabot-config`](#dependabot-config) | low | high | Dependabot configuration detected |
| [`dockerfile-base-image`](#dockerfile-base-image) | medium | high | Docker base image reference detected |
| [`dotnet-csproj`](#dotnet-csproj) | low | high | .NET project file detected |
| [`github-actions-workflow`](#github-actions-workflow) | low | high | GitHub Actions workflow detected |
| [`github-advisory`](#github-advisory) | high | high | GitHub security advisory reference detected |
| [`go-mod`](#go-mod) | low | high | Go module file detected |
| [`go-replace-directive`](#go-replace-directive) | medium | high | Go replace directive detected |
| [`go-sum`](#go-sum) | medium | high | Go checksum file detected |
| [`gradle-build`](#gradle-build) | low | high | Gradle build file detected |
| [`gradle-lockfile`](#gradle-lockfile) | medium | high | Gradle lockfile detected |
| [`gradle-wrapper`](#gradle-wrapper) | low | high | Gradle wrapper detected |
| [`helm-chart-dependency`](#helm-chart-dependency) | medium | high | Helm chart dependency detected |
| [`maven-wrapper`](#maven-wrapper) | low | high | Maven wrapper detected |
| [`npm-audit`](#npm-audit) | medium | high | NPM audit command detected |
| [`npm-shrinkwrap`](#npm-shrinkwrap) | medium | high | NPM shrinkwrap file detected |
| [`nuget-config`](#nuget-config) | low | high | NuGet config detected |
| [`package-json`](#package-json) | low | high | package.json file detected |
| [`packages-config`](#packages-config) | low | high | .NET packages.config detected |
| [`pipfile`](#pipfile) | low | high | Pipfile detected |
| [`pipfile-lock`](#pipfile-lock) | medium | high | Pipfile.lock detected |
| [`pnpm-lockfile`](#pnpm-lockfile) | low | high | PNPM lockfile detected |
| [`poetry-lock`](#poetry-lock) | medium | high | Poetry lock file detected |
| [`pom-xml`](#pom-xml) | low | high | Maven pom.xml detected |
| [`pyproject-toml`](#pyproject-toml) | low | high | Python pyproject.toml detected |
| [`renovate-config`](#renovate-config) | low | high | Renovate configuration detected |
| [`requirements-txt`](#requirements-txt) | low | high | Python requirements file detected |
| [`safety-db`](#safety-db) | medium | high | Python safety check detected |
| [`sbom-cyclonedx`](#sbom-cyclonedx) | medium | high | CycloneDX SBOM detected |
| [`sbom-spdx`](#sbom-spdx) | medium | high | SPDX SBOM detected |
| [`setup-py`](#setup-py) | low | high | Python setup.py detected |
| [`unknown-npm-package`](#unknown-npm-package) | low | low | NPM package installation detected |
| [`yarn-lockfile`](#yarn-lockfile) | low | high | Yarn lockfile detected |

## Pattern details

### cargo-audit

Cargo audit command detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `rust`, `audit`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)cargo\s+audit
```

**Reference**: <https://crates.io/crates/cargo-audit>

**Input that fires** (verified by the liveness test):

```text
cargo audit
```

### cargo-lock

Rust Cargo.lock detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `rust`, `cargo`, `lockfile` |

**Match pattern** (Rust `regex` syntax):

```regex
Cargo\.lock
```

**Reference**: <https://doc.rust-lang.org/cargo/reference/locking.html>

**Input that fires** (verified by the liveness test):

```text
Cargo.lock
```

### cargo-toml

Rust Cargo.toml detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `rust`, `cargo`, `dependencies` |

**Match pattern** (Rust `regex` syntax):

```regex
Cargo\.toml
```

**Reference**: <https://doc.rust-lang.org/cargo/reference/manifest.html>

**Input that fires** (verified by the liveness test):

```text
Cargo.toml
```

### dependabot-config

Dependabot configuration detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `github`, `dependabot`, `updates` |

**Match pattern** (Rust `regex` syntax):

```regex
dependabot\.yml
```

**Reference**: <https://docs.github.com/en/code-security/dependabot>

**Input that fires** (verified by the liveness test):

```text
dependabot.yml
```

### dockerfile-base-image

Docker base image reference detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `docker`, `container`, `base-image` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)^FROM\s+[a-z0-9._/-]+:([a-z0-9._-]+|latest)
```

**Reference**: <https://docs.docker.com/engine/reference/builder/#from>

**Input that fires** (verified by the liveness test):

```text
FROM bjjij_/hwed:fi.vih7aqtjg2
```

### dotnet-csproj

.NET project file detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `dotnet`, `project`, `msbuild` |

**Match pattern** (Rust `regex` syntax):

```regex
\.[a-z]+\.csproj
```

**Reference**: <https://docs.microsoft.com/en-us/visualstudio/msbuild/common-msbuild-project-properties>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
.tpeocptq…mh.csproj
```

### github-actions-workflow

GitHub Actions workflow detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `github`, `ci`, `actions` |

**Match pattern** (Rust `regex` syntax):

```regex
\.github/workflows/
```

**Reference**: <https://docs.github.com/en/actions/learn-github-actions>

**Input that fires** (verified by the liveness test):

```text
.github/workflows/
```

### github-advisory

GitHub security advisory reference detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `github`, `advisory`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
github\.com/advisories
```

**Reference**: <https://github.com/advisories>

**Input that fires** (verified by the liveness test):

```text
github.com/advisories
```

### go-mod

Go module file detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `go`, `module`, `dependencies` |

**Match pattern** (Rust `regex` syntax):

```regex
go\.mod
```

**Reference**: <https://go.dev/ref/mod>

**Input that fires** (verified by the liveness test):

```text
go.mod
```

### go-replace-directive

Go replace directive detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `go`, `replace`, `dependency` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)replace\s+
```

**Reference**: <https://go.dev/ref/mod#go.sum>

**Input that fires** (verified by the liveness test):

```text
replace 
```

### go-sum

Go checksum file detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `go`, `checksum`, `integrity` |

**Match pattern** (Rust `regex` syntax):

```regex
go\.sum
```

**Reference**: <https://go.dev/ref/mod#go-sum>

**Input that fires** (verified by the liveness test):

```text
go.sum
```

### gradle-build

Gradle build file detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `java`, `gradle`, `build` |

**Match pattern** (Rust `regex` syntax):

```regex
build\.gradle
```

**Reference**: <https://docs.gradle.org/current/userguide/build_file_basics.html>

**Input that fires** (verified by the liveness test):

```text
build.gradle
```

### gradle-lockfile

Gradle lockfile detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `java`, `gradle`, `lockfile` |

**Match pattern** (Rust `regex` syntax):

```regex
gradle\.lockfile
```

**Reference**: <https://docs.gradle.org/current/userguide/dependency_locking.html>

**Input that fires** (verified by the liveness test):

```text
gradle.lockfile
```

### gradle-wrapper

Gradle wrapper detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `java`, `gradle`, `wrapper` |

**Match pattern** (Rust `regex` syntax):

```regex
gradlew
```

**Reference**: <https://docs.gradle.org/current/userguide/gradle_wrapper.html>

**Input that fires** (verified by the liveness test):

```text
gradlew
```

### helm-chart-dependency

Helm chart dependency detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `helm`, `kubernetes`, `dependency` |

**Match pattern** (Rust `regex` syntax):

```regex
dependencies:.*- name:
```

**Reference**: <https://helm.sh/docs/topics/charts/#chart-dependencies>

**Input that fires** (verified by the liveness test):

```text
dependencies:sxBp- name:
```

### maven-wrapper

Maven wrapper detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `java`, `maven`, `wrapper` |

**Match pattern** (Rust `regex` syntax):

```regex
mvnw
```

**Reference**: <https://maven.apache.org/wrapper/>

**Input that fires** (verified by the liveness test):

```text
mvnw
```

### npm-audit

NPM audit command detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `npm`, `audit`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)npm\s+audit
```

**Reference**: <https://docs.npmjs.com/cli/v8/commands/npm-audit>

**Input that fires** (verified by the liveness test):

```text
npm audit
```

### npm-shrinkwrap

NPM shrinkwrap file detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `npm`, `lockfile`, `reproducible` |

**Match pattern** (Rust `regex` syntax):

```regex
npm-shrinkwrap\.json
```

**Reference**: <https://docs.npmjs.com/cli/v8/commands/npm-shrinkwrap>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
npm-shri…ap.json
```

### nuget-config

NuGet config detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `dotnet`, `nuget`, `package-manager` |

**Match pattern** (Rust `regex` syntax):

```regex
nuget\.config
```

**Reference**: <https://docs.microsoft.com/en-us/nuget/consume-packages/configuring-nuget-behavior>

**Input that fires** (verified by the liveness test):

```text
nuget.config
```

### package-json

package.json file detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `npm`, `package`, `manifest` |

**Match pattern** (Rust `regex` syntax):

```regex
package\.json
```

**Reference**: <https://docs.npmjs.com/creating-a-package-json-file>

**Input that fires** (verified by the liveness test):

```text
package.json
```

### packages-config

.NET packages.config detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `dotnet`, `packages`, `dependencies` |

**Match pattern** (Rust `regex` syntax):

```regex
packages\.config
```

**Reference**: <https://docs.microsoft.com/en-us/nuget/reference/packages-config>

**Input that fires** (verified by the liveness test):

```text
packages.config
```

### pipfile

Pipfile detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `python`, `pipenv`, `dependencies` |

**Match pattern** (Rust `regex` syntax):

```regex
Pipfile
```

**Reference**: <https://pipenv.pypa.io/en/latest/basics/>

**Input that fires** (verified by the liveness test):

```text
Pipfile
```

### pipfile-lock

Pipfile.lock detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `python`, `pipenv`, `lockfile` |

**Match pattern** (Rust `regex` syntax):

```regex
Pipfile\.lock
```

**Reference**: <https://pipenv.pypa.io/en/latest/basics/#pipfile-lock>

**Input that fires** (verified by the liveness test):

```text
Pipfile.lock
```

### pnpm-lockfile

PNPM lockfile detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pnpm`, `lockfile`, `reproducible` |

**Match pattern** (Rust `regex` syntax):

```regex
pnpm-lock\.yaml
```

**Reference**: <https://pnpm.io/motivation>

**Input that fires** (verified by the liveness test):

```text
pnpm-lock.yaml
```

### poetry-lock

Poetry lock file detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `python`, `poetry`, `lockfile` |

**Match pattern** (Rust `regex` syntax):

```regex
poetry\.lock
```

**Reference**: <https://python-poetry.org/docs/basic-usage/#locking-your-dependencies>

**Input that fires** (verified by the liveness test):

```text
poetry.lock
```

### pom-xml

Maven pom.xml detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `java`, `maven`, `build` |

**Match pattern** (Rust `regex` syntax):

```regex
pom\.xml
```

**Reference**: <https://maven.apache.org/guides/introduction/introduction-to-the-pom.html>

**Input that fires** (verified by the liveness test):

```text
pom.xml
```

### pyproject-toml

Python pyproject.toml detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `python`, `packaging`, `build` |

**Match pattern** (Rust `regex` syntax):

```regex
pyproject\.toml
```

**Reference**: <https://packaging.python.org/en/latest/specifications/pyproject-toml/>

**Input that fires** (verified by the liveness test):

```text
pyproject.toml
```

### renovate-config

Renovate configuration detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `renovate`, `updates`, `dependencies` |

**Match pattern** (Rust `regex` syntax):

```regex
renovate\.json
```

**Reference**: <https://docs.renovatebot.com/>

**Input that fires** (verified by the liveness test):

```text
renovate.json
```

### requirements-txt

Python requirements file detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `python`, `pip`, `dependencies` |

**Match pattern** (Rust `regex` syntax):

```regex
requirements.*\.txt
```

**Reference**: <https://pip.pypa.io/en/stable/user_guide/#requirements-files>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
requirem…Kk.txt
```

### safety-db

Python safety check detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `python`, `safety`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)safety\s+check
```

**Reference**: <https://pypi.org/project/safety/>

**Input that fires** (verified by the liveness test):

```text
safety check
```

### sbom-cyclonedx

CycloneDX SBOM detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `sbom`, `cyclonedx`, `software-bill-of-materials` |

**Match pattern** (Rust `regex` syntax):

```regex
<bom.*xmlns.*cyclonedx
```

**Reference**: <https://cyclonedx.org/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
<bomYm54i…dx
```

### sbom-spdx

SPDX SBOM detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `sbom`, `spdx`, `software-bill-of-materials` |

**Match pattern** (Rust `regex` syntax):

```regex
SPDXID.*DocumentName
```

**Reference**: <https://spdx.dev/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
SPDXID_B…me
```

### setup-py

Python setup.py detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `python`, `setuptools`, `packaging` |

**Match pattern** (Rust `regex` syntax):

```regex
setup\.py
```

**Reference**: <https://setuptools.pypa.io/en/latest/userguide/quickstart.html>

**Input that fires** (verified by the liveness test):

```text
setup.py
```

### unknown-npm-package

NPM package installation detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `npm`, `supply-chain`, `package` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)npm\s+(install|add)\s+([a-z0-9_-]+@[0-9]+\.[0-9]+\.[0-9]+|[a-z0-9_-]+\.[a-z0-9_-]+)
```

**Reference**: <https://docs.npmjs.com/cli/v8/commands/npm-install>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
npm install bxvyvkap@78362737…45.48874526…47.8
```

### yarn-lockfile

Yarn lockfile detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `yarn`, `lockfile`, `reproducible` |

**Match pattern** (Rust `regex` syntax):

```regex
yarn\.lock
```

**Reference**: <https://yarnpkg.com/getting-started/qa>

**Input that fires** (verified by the liveness test):

```text
yarn.lock
```
