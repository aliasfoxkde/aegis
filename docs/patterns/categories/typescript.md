# typescript patterns

TypeScript and typed-JavaScript rules

**13 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`arguments-object-usage`](#arguments-object-usage) | low | medium | `arguments` object used; prefer rest parameters |
| [`async-promise-executor`](#async-promise-executor) | medium | high | Async Promise executor swallows rejections |
| [`double-type-assertion`](#double-type-assertion) | medium | high | Double type assertion casts through unknown/any |
| [`empty-interface`](#empty-interface) | low | high | Empty interface declared |
| [`namespace-declaration`](#namespace-declaration) | low | medium | TypeScript namespace detected; prefer ES modules |
| [`object-function-type`](#object-function-type) | low | medium | Useless broad type annotation (object/Object/Function) |
| [`prototype-builtin-call`](#prototype-builtin-call) | low | high | Object prototype method called directly; use Object.hasOwn |
| [`require-in-typescript`](#require-in-typescript) | low | high | CommonJS require() used in TypeScript; prefer ES imports |
| [`return-await`](#return-await) | low | medium | Redundant `return await` outside try/catch |
| [`ts-ignore-comment`](#ts-ignore-comment) | medium | high | @ts-ignore suppresses type errors indefinitely; use @ts-expect-error |
| [`ts-nocheck`](#ts-nocheck) | high | high | @ts-nocheck disables type checking for the whole file |
| [`typescript-any-alias`](#typescript-any-alias) | medium | high | Type alias resolves to `any` |
| [`typescript-explicit-any`](#typescript-explicit-any) | medium | high | Explicit `any` defeats TypeScript type checking |

## Pattern details

### arguments-object-usage

`arguments` object used; prefer rest parameters

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `javascript`, `best-practice`, `style` |

**Match pattern** (Rust `regex` syntax):

```regex
\barguments\b
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
\.arguments\b|arguments\[0\]\s*=\s*new
```
**Reference**: <https://eslint.org/docs/latest/rules/prefer-rest-params>

**Input that fires** (verified by the liveness test):

```text
arguments
```

### async-promise-executor

Async Promise executor swallows rejections

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `javascript`, `promises`, `correctness` |

**Match pattern** (Rust `regex` syntax):

```regex
new\s+Promise\s*(?:<[^>]*>)?\s*\(\s*async\b
```

**Reference**: <https://eslint.org/docs/latest/rules/no-async-promise-executor>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
new Promise <byqxZSKe…Mg> ( async
```

### double-type-assertion

Double type assertion casts through unknown/any

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.ts`, `.tsx`, `.mts`, `.cts`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `typescript`, `types`, `code-smell` |

**Match pattern** (Rust `regex` syntax):

```regex
\bas\s+unknown\s+as\b|\bas\s+any\s+as\b
```

**Reference**: <https://typescript-eslint.io/rules/no-unnecessary-type-assertion/>

**Input that fires** (verified by the liveness test):

```text
as unknown as
```

### empty-interface

Empty interface declared

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.ts`, `.tsx`, `.mts`, `.cts`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `typescript`, `types`, `dead-code` |

**Match pattern** (Rust `regex` syntax):

```regex
\binterface\s+[A-Za-z_$][\w$]*\s*\{\s*\}
```

**Reference**: <https://typescript-eslint.io/rules/no-empty-interface/>

**Input that fires** (verified by the liveness test):

```text
interface pe9lEf { }
```

### namespace-declaration

TypeScript namespace detected; prefer ES modules

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.ts`, `.tsx`, `.mts`, `.cts`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `typescript`, `modules`, `best-practice` |

**Match pattern** (Rust `regex` syntax):

```regex
\bnamespace\s+[A-Za-z_$][\w$]*
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
\bdeclare\s+namespace
```
**Reference**: <https://typescript-eslint.io/rules/no-namespace/>

**Input that fires** (verified by the liveness test):

```text
namespace ezx0
```

### object-function-type

Useless broad type annotation (object/Object/Function)

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.ts`, `.tsx`, `.mts`, `.cts`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `typescript`, `types`, `best-practice` |

**Match pattern** (Rust `regex` syntax):

```regex
:\s*(?:object|Object|Function)\b
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
JSON\.parse|\.isObject|typeof object
```
**Reference**: <https://typescript-eslint.io/rules/ban-types/>

**Input that fires** (verified by the liveness test):

```text
: object
```

### prototype-builtin-call

Object prototype method called directly; use Object.hasOwn

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `javascript`, `security`, `best-practice` |

**Match pattern** (Rust `regex` syntax):

```regex
\.hasOwnProperty\s*\(|\.isPrototypeOf\s*\(|\.propertyIsEnumerable\s*\(
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
Object\.prototype\.hasOwnProperty|\.call\s*\(
```
**Reference**: <https://eslint.org/docs/latest/rules/no-prototype-builtins>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
.hasOwnPr…ty (
```

### require-in-typescript

CommonJS require() used in TypeScript; prefer ES imports

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.ts`, `.tsx`, `.mts`, `.cts`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `typescript`, `modules`, `best-practice` |

**Match pattern** (Rust `regex` syntax):

```regex
\b(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*require\s*\(
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
createRequire|__non_webpack_require__
```
**Reference**: <https://typescript-eslint.io/rules/no-require-imports/>

**Input that fires** (verified by the liveness test):

```text
const QOeO3ebutbNH = require (
```

### return-await

Redundant `return await` outside try/catch

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `javascript`, `promises`, `best-practice` |

**Match pattern** (Rust `regex` syntax):

```regex
\breturn\s+await\s+[A-Za-z_$\[(]
```

**Reference**: <https://eslint.org/docs/latest/rules/no-return-await>

**Input that fires** (verified by the liveness test):

```text
return await U
```

### ts-ignore-comment

@ts-ignore suppresses type errors indefinitely; use @ts-expect-error

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.ts`, `.tsx`, `.mts`, `.cts`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `typescript`, `suppression`, `best-practice` |

**Match pattern** (Rust `regex` syntax):

```regex
@ts-ignore\b
```

**Reference**: <https://typescript-eslint.io/rules/ban-ts-comment/>

**Input that fires** (verified by the liveness test):

```text
@ts-ignore
```

### ts-nocheck

@ts-nocheck disables type checking for the whole file

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.ts`, `.tsx`, `.mts`, `.cts`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `typescript`, `suppression`, `best-practice` |

**Match pattern** (Rust `regex` syntax):

```regex
@ts-nocheck\b
```

**Reference**: <https://typescript-eslint.io/rules/ban-ts-comment/>

**Input that fires** (verified by the liveness test):

```text
@ts-nocheck
```

### typescript-any-alias

Type alias resolves to `any`

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.ts`, `.tsx`, `.mts`, `.cts`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `typescript`, `types`, `best-practice` |

**Match pattern** (Rust `regex` syntax):

```regex
\btype\s+[A-Za-z_$][\w$]*\s*=\s*any\b
```

**Reference**: <https://typescript-eslint.io/rules/no-explicit-any/>

**Input that fires** (verified by the liveness test):

```text
type _N4LNVrfcl = any
```

### typescript-explicit-any

Explicit `any` defeats TypeScript type checking

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.ts`, `.tsx`, `.mts`, `.cts`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `typescript`, `types`, `best-practice` |

**Match pattern** (Rust `regex` syntax):

```regex
\bas\s+any\b|[:<]\s*any\b|Array<any>
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
@\s*ts-expect-error|any\[\]\s*\)|unknown
```
**Reference**: <https://typescript-eslint.io/rules/no-explicit-any/>

**Input that fires** (verified by the liveness test):

```text
as any
```
