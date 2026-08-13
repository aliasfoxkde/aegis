# Contributing to Aegis

Aegis grows through patterns. Every pattern is one YAML file — no Rust required, no engine changes, fast to review, and immediately useful to every user once merged.

---

## 🎯 Which Project to Contribute To?

### **Official aliasfoxkde/aegis**
- **Best for**: Stable patterns, bug fixes, documentation
- **Process**: Standard PR review and testing
- **Impact**: Immediate benefit to all users
- **Repository**: [https://github.com/aliasfoxkde/aegis](https://github.com/aliasfoxkde/aegis)

---

## 👥 Contributors

All contributions are permanently credited in the [contributors graph](https://github.com/aliasfoxkde/aegis/graphs/contributors).

---

## Development Setup

### Prerequisites

- **Rust 1.70+** - Install via [rustup](https://rustup.rs/)
- **Git**

### Clone and Build

```bash
git clone https://github.com/aliasfoxkde/aegis.git
cd aegis
cargo build --workspace
```

### Run Tests

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

---

## Adding a YAML Pattern

**1. Check it doesn't already exist**

```bash
cargo run --bin aegis-cli -- list
cargo run --bin aegis-cli -- list --category secrets
```

**2. Create the YAML file**

Drop a `.yaml` file into the appropriate `community/<category>/` folder:

```yaml
name: my-service-api-key
match: '\bmsvc_[A-Za-z0-9]{32}\b'
severity: high
confidence: high
minEntropy: 3.5
description: 'Detects MyService API keys'
tags:
  - secrets
  - api-key
```

**Required Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Unique pattern name (snake_case) |
| `match` | string | Valid regex pattern |
| `severity` | string | `critical`, `high`, `medium`, or `low` |
| `confidence` | string | `high`, `medium`, or `low` |
| `description` | string | Human-readable description |

**3. Test the pattern**

```bash
cargo run --bin aegis-cli -- scan --help
```

**4. Submit**

Open a pull request. Include what the pattern detects, why it matters, and test cases.

---

## Rust Contributions

Any Rust code contributed must be clean and idiomatic:

- Standard Rust naming conventions
- No `unwrap()` in production code — use `?` or proper error handling
- No `panic!()` in library code — return `Result` instead
- No unsafe code without review
- `cargo fmt` and `cargo clippy -D warnings` must pass
- Tests in `tests/` or `#[cfg(test)]` modules

The engine is intentionally minimal and stable. If you're unsure whether a change is in scope, open an issue first.

---

## Commit Message Format

All commits follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]
```

**Types:** `feat` | `fix` | `docs` | `test` | `refactor` | `chore` | `ci` | `build` | `perf`

**Examples:**
```
feat(secrets): add new AWS pattern
fix(scanner): guard against nil bundle panic
docs: update CONTRIBUTING.md
chore: bump regex crate to v1.10
```

---

## PR & Branch Workflow

1. Branch from `main` → PR to `main`
2. Use feature branches: `feature/`, `fix/`, `docs/`, `test/`, `refactor/`
3. All CI checks must pass before merge
4. PRs require 1 code owner approval
5. Merges are **squash-only** with `--delete-branch`

---

## Project Structure

```
aegis/
├── crates/
│   ├── aegis-core/       # Core scanning engine
│   ├── aegis-cli/        # CLI application
│   ├── aegis-mcp/        # MCP server
│   ├── aegis-daemon/     # Daemon mode
│   ├── aegis-bundler/    # Pattern bundler
│   └── aegis-patterns/   # Pattern definitions (620 patterns)
├── config/profiles/       # Configuration profiles
└── docs/                 # Documentation
```
