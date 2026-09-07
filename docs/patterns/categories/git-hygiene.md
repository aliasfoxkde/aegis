# git-hygiene patterns

Repository hygiene: artifacts, debug files, history

**28 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`branch-naming-bugfix`](#branch-naming-bugfix) | low | high | Bugfix branch naming convention detected |
| [`branch-naming-feature`](#branch-naming-feature) | low | high | Feature branch naming convention detected |
| [`branch-naming-hotfix`](#branch-naming-hotfix) | low | high | Hotfix branch naming convention detected |
| [`branch-naming-release`](#branch-naming-release) | low | high | Release branch naming convention detected |
| [`commit-ampersand`](#commit-ampersand) | low | low | Commit message contains '&' instead of 'and' |
| [`commit-message-conventional`](#commit-message-conventional) | low | medium | Conventional commit message format detected |
| [`commit-sha-reference`](#commit-sha-reference) | low | high | Full commit SHA reference detected |
| [`commitizen-config`](#commitizen-config) | low | high | Commitizen configuration detected |
| [`force-push-detected`](#force-push-detected) | medium | high | Force push command detected |
| [`git-commit-signoff`](#git-commit-signoff) | low | high | Git sign-off detected (DCO) |
| [`git-commit-verify`](#git-commit-verify) | low | high | GPG commit signing enabled |
| [`git-flow-model`](#git-flow-model) | low | high | Git Flow branching model reference |
| [`git-hooks-husky`](#git-hooks-husky) | low | high | Husky git hooks directory detected |
| [`git-hygiene-dependabot-config`](#git-hygiene-dependabot-config) | low | high | Dependabot configuration detected |
| [`git-hygiene-github-actions-workflow`](#git-hygiene-github-actions-workflow) | low | high | GitHub Actions workflow detected |
| [`git-hygiene-renovate-config`](#git-hygiene-renovate-config) | low | high | Renovate configuration detected |
| [`git-lfs`](#git-lfs) | low | high | Git LFS usage detected |
| [`git-stash`](#git-stash) | low | high | Git stash command detected |
| [`git-worktree`](#git-worktree) | low | high | Git worktree command detected |
| [`gitattributes-entry`](#gitattributes-entry) | low | high | .gitattributes file detected |
| [`github-issue-reference`](#github-issue-reference) | low | high | GitHub issue reference in commit |
| [`gitignore-entry`](#gitignore-entry) | low | high | .gitignore file detected |
| [`gitmodules-entry`](#gitmodules-entry) | medium | high | .gitmodules file detected (git submodule) |
| [`merge-commit`](#merge-commit) | low | high | Merge commit message detected |
| [`merge-conflict`](#merge-conflict) | high | high | Unresolved merge conflict marker detected |
| [`pre-commit-config`](#pre-commit-config) | low | high | Pre-commit configuration detected |
| [`semantic-release-config`](#semantic-release-config) | low | high | Semantic release configuration detected |
| [`tag-reference`](#tag-reference) | low | high | Semantic version tag reference detected |

## Pattern details

### branch-naming-bugfix

Bugfix branch naming convention detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git`, `branch`, `naming` |

**Match pattern** (Rust `regex` syntax):

```regex
^bugfix/[a-z0-9-_]+$
```

**Reference**: <https://git-scm.com/book/en/v2/Git-Branching-Branching-Workflows>

**Input that fires** (verified by the liveness test):

```text
bugfix/ef
```

### branch-naming-feature

Feature branch naming convention detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git`, `branch`, `naming` |

**Match pattern** (Rust `regex` syntax):

```regex
^feature/[a-z0-9-_]+$
```

**Reference**: <https://git-scm.com/book/en/v2/Git-Branching-Branching-Workflows>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
feature/o_p63qpu…ok
```

### branch-naming-hotfix

Hotfix branch naming convention detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git`, `branch`, `naming` |

**Match pattern** (Rust `regex` syntax):

```regex
^hotfix/[a-z0-9-_]+$
```

**Reference**: <https://git-scm.com/book/en/v2/Git-Branching-Branching-Workflows>

**Input that fires** (verified by the liveness test):

```text
hotfix/wpz2rz2a-
```

### branch-naming-release

Release branch naming convention detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git`, `branch`, `naming` |

**Match pattern** (Rust `regex` syntax):

```regex
^release/[a-z0-9._-]+$
```

**Reference**: <https://git-scm.com/book/en/v2/Git-Branching-Branching-Workflows>

**Input that fires** (verified by the liveness test):

```text
release/s6jnht
```

### commit-ampersand

Commit message contains '&' instead of 'and'

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git`, `commit-message`, `style` |

**Match pattern** (Rust `regex` syntax):

```regex
\bamp\b
```

**Input that fires** (verified by the liveness test):

```text
amp
```

### commit-message-conventional

Conventional commit message format detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git`, `commit`, `conventional` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)^(feat|fix|docs|style|refactor|test|chore|perf|ci|build|revert)\([^)]+\):
```

**Reference**: <https://www.conventionalcommits.org/>

**Input that fires** (verified by the liveness test):

```text
feat(h/7jBBdB):
```

### commit-sha-reference

Full commit SHA reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.md`, `.rst`, `.adoc`, `.txt` |
| Binary files | skipped |
| Tags | `git`, `commit`, `sha` |

**Match pattern** (Rust `regex` syntax):

```regex
\b[0-9a-f]{40}\b
```

**Reference**: <https://git-scm.com/book/en/v2/Git-Tools-Revision-Selection>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
ceb8db73…5c
```

### commitizen-config

Commitizen configuration detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `commitizen`, `commit`, `convention` |

**Match pattern** (Rust `regex` syntax):

```regex
\.(czrc|cz.json|commitizen)
```

**Reference**: <https://commitizen-tools.github.io/commitizen/>

**Input that fires** (verified by the liveness test):

```text
.czrc
```

### force-push-detected

Force push command detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git`, `force-push`, `dangerous` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)git\s+push\s+--force|git\s+push\s+-f
```

**Input that fires** (verified by the liveness test):

```text
git push --force
```

### git-commit-signoff

Git sign-off detected (DCO)

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git`, `commit`, `signoff` |

**Match pattern** (Rust `regex` syntax):

```regex
Signed-off-by:
```

**Reference**: <https://developercertificate.org/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
Signed-o…by:
```

### git-commit-verify

GPG commit signing enabled

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git`, `gpg`, `signing` |

**Match pattern** (Rust `regex` syntax):

```regex
gpg.sign\s*=\s*true
```

**Reference**: <https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work>

**Input that fires** (verified by the liveness test):

```text
gpg_sign = true
```

### git-flow-model

Git Flow branching model reference

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git`, `git-flow`, `branching` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)git.flow|gitflow
```

**Reference**: <https://nvie.com/posts/a-successful-git-branching-model/>

**Input that fires** (verified by the liveness test):

```text
gitEflow
```

### git-hooks-husky

Husky git hooks directory detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `husky`, `git-hooks`, `automation` |

**Match pattern** (Rust `regex` syntax):

```regex
\.husky/
```

**Reference**: <https://typicode.github.io/husky/>

**Input that fires** (verified by the liveness test):

```text
.husky/
```

### git-hygiene-dependabot-config

Dependabot configuration detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `dependabot`, `dependencies`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
dependabot\.yml
```

**Reference**: <https://docs.github.com/en/code-security/dependabot>

**Input that fires** (verified by the liveness test):

```text
dependabot.yml
```

### git-hygiene-github-actions-workflow

GitHub Actions workflow detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `github`, `ci-cd`, `workflow` |

**Match pattern** (Rust `regex` syntax):

```regex
\.github/workflows/[^/]+\.ya?ml
```

**Reference**: <https://docs.github.com/en/actions/learn-github-actions>

**Input that fires** (verified by the liveness test):

```text
.github/workflows/6 dgt2huJthz.yaml
```

### git-hygiene-renovate-config

Renovate configuration detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `renovate`, `dependencies`, `automation` |

**Match pattern** (Rust `regex` syntax):

```regex
renovate\.json
```

**Reference**: <https://docs.renovatebot.com/>

**Input that fires** (verified by the liveness test):

```text
renovate.json
```

### git-lfs

Git LFS usage detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git`, `lfs`, `storage` |

**Match pattern** (Rust `regex` syntax):

```regex
git\s+lfs|\.gitattributes.*lfs
```

**Reference**: <https://git-lfs.github.com/>

**Input that fires** (verified by the liveness test):

```text
git lfs
```

### git-stash

Git stash command detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git`, `stash` |

**Match pattern** (Rust `regex` syntax):

```regex
git\s+stash
```

**Reference**: <https://git-scm.com/docs/git-stash>

**Input that fires** (verified by the liveness test):

```text
git stash
```

### git-worktree

Git worktree command detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git`, `worktree`, `branching` |

**Match pattern** (Rust `regex` syntax):

```regex
git\s+worktree
```

**Reference**: <https://git-scm.com/docs/git-worktree>

**Input that fires** (verified by the liveness test):

```text
git worktree
```

### gitattributes-entry

.gitattributes file detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git`, `gitattributes`, `hygiene` |

**Match pattern** (Rust `regex` syntax):

```regex
^\.gitattributes$
```

**Reference**: <https://git-scm.com/docs/gitattributes>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
.gitattri…es
```

### github-issue-reference

GitHub issue reference in commit

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `github`, `issue`, `commit` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(fixes|closes|resolves)\s+#\d+
```

**Reference**: <https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
fixes #69557752…44
```

### gitignore-entry

.gitignore file detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git`, `gitignore`, `hygiene` |

**Match pattern** (Rust `regex` syntax):

```regex
^\.gitignore$
```

**Reference**: <https://git-scm.com/docs/gitignore>

**Input that fires** (verified by the liveness test):

```text
.gitignore
```

### gitmodules-entry

.gitmodules file detected (git submodule)

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git`, `submodule`, `hygiene` |

**Match pattern** (Rust `regex` syntax):

```regex
^\.gitmodules$
```

**Reference**: <https://git-scm.com/book/en/v2/Git-Tools-Submodules>

**Input that fires** (verified by the liveness test):

```text
.gitmodules
```

### merge-commit

Merge commit message detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git`, `merge`, `commit` |

**Match pattern** (Rust `regex` syntax):

```regex
^Merge branch
```

**Reference**: <https://git-scm.com/book/en/v2/Git-Branching-Basic-Branching-and-Merging>

**Input that fires** (verified by the liveness test):

```text
Merge branch
```

### merge-conflict

Unresolved merge conflict marker detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git`, `merge-conflict`, `hygiene` |

**Match pattern** (Rust `regex` syntax):

```regex
^<{7}|^={7}|^>{7}
```

**Reference**: <https://git-scm.com/book/en/v2/Git-Branching-Basic-Branching-and-Merging>

**Input that fires** (verified by the liveness test):

```text
<<<<<<<
```

### pre-commit-config

Pre-commit configuration detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `pre-commit`, `git-hooks`, `quality` |

**Match pattern** (Rust `regex` syntax):

```regex
\.pre-commit-config\.ya?ml
```

**Reference**: <https://pre-commit.com/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
.pre-comm…ig.yaml
```

### semantic-release-config

Semantic release configuration detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `semantic-release`, `release`, `automation` |

**Match pattern** (Rust `regex` syntax):

```regex
\.releaserc|semantic-release
```

**Reference**: <https://semantic-release.gitbook.io/semantic-release/>

**Input that fires** (verified by the liveness test):

```text
.releaserc
```

### tag-reference

Semantic version tag reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `git`, `tag`, `version` |

**Match pattern** (Rust `regex` syntax):

```regex
^refs/tags/v?\d+\.\d+
```

**Reference**: <https://git-scm.com/book/en/v2/Git-Basics-Tagging>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
refs/tags/v69634658.29852268…57
```
