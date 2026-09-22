# Contributing to Aegis

Aegis is a security scanner with 670 built-in patterns across 34
categories, shipped as Rust definitions in `crates/aegis-patterns/`.
Contributions fall into three buckets: patterns, engine/CLI code, and
documentation.

---

## 🎯 Which Project to Contribute To?

### **Official aliasfoxkde/aegis**

- **Best for**: Pattern additions, engine fixes, documentation
- **Process**: Standard PR review and testing
- **Impact**: Immediate benefit to all users
- **Repository**: [https://github.com/aliasfoxkde/aegis](https://github.com/aliasfoxkde/aegis)

---

## 👥 Contributors

All contributions are permanently credited in the
[contributors graph](https://github.com/aliasfoxkde/aegis/graphs/contributors).

---

## Development Setup

### Prerequisites

- **Rust 1.88+** (the workspace MSRV, driven by locked dependencies) -
  Install via [rustup](https://rustup.rs/)
- **Git**

### Clone and Build

```bash
git clone https://github.com/aliasfoxkde/aegis.git
cd aegis
cargo build --workspace
```

### Quality Gates

CI (and every merge) requires all three:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The workspace compiles with `pedantic` + `missing_docs` lints; new public
items need doc comments.

---

## Adding a Pattern

**1. Check it doesn't already exist**

```bash
cargo run --bin aegis -- list
cargo run --bin aegis -- list --category secrets
```

**2. Add the pattern to `crates/aegis-patterns/src/`**

Patterns are Rust `Pattern` values grouped by theme module. Full field
reference, naming rules (kebab-case names, enforced by the registry
hygiene tests), and the generated-catalog step live in
[docs/guides/ADDING_PATTERNS.md](../docs/guides/ADDING_PATTERNS.md).

**3. Test the pattern in both directions**

Add positive and negative fixtures to
`crates/aegis-cli/tests/pattern_fixtures.rs` — a pattern must detect its
target *and* ignore placeholder examples.

**4. Submit**

Open a pull request. Include what the pattern detects, why it matters,
and the fixtures proving both directions.

### Organization-specific rules without a code change

A `.aegis.yml` / `.aegis.yaml` at the scan root accepts custom patterns.
Validation is fail-loud: unknown fields, invalid regex, unknown severity,
or duplicate names abort the scan naming the file and the pattern.

### Distributable bundles

`aegis-bundler` packs a directory of YAML pattern files into a
versioned, checksummed bundle:

```bash
cargo run -p aegis-bundler -- my-patterns/ my.bundle
```

---

## Rust Contributions

Any Rust code contributed must be clean and idiomatic:

- Standard Rust naming conventions
- No `unwrap()` in production code — use `?` or proper error handling
- No `panic!()` in library code — return `Result` instead
- No unsafe code without review
- `cargo fmt` and `cargo clippy -D warnings` must pass
- Tests in `tests/` or `#[cfg(test)]` modules

The engine follows two standing principles: **fail loud** (never
silently degrade — an ignored error must be a logged warning at minimum)
and **no synthetic shortcuts** (tests assert real behavior, not mocks of
the thing under test). If you're unsure whether a change is in scope,
open an issue first.

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
feat(secrets): add msvc API key pattern
fix(scanner): advance clone tokenizer by UTF-8 width
docs: update CONTRIBUTING.md
chore: bump clap to 4.6.6
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
│   ├── aegis-cli/        # CLI application (binary: `aegis`)
│   ├── aegis-mcp/        # JSON-RPC server for editor/agent integration
│   ├── aegis-daemon/     # Unix-socket daemon mode
│   ├── aegis-bundler/    # Pattern bundler
│   ├── aegis-patterns/   # 670 pattern definitions
│   └── aegis-wasm/       # WebAssembly binding
├── config/profiles/      # Configuration profiles
├── docs/                 # Documentation and guides
└── scripts/release/      # GitForge-first release pipeline
```
