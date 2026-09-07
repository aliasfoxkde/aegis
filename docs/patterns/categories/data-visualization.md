# data-visualization patterns

Charting and visualization pitfalls

**5 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`chart-accessibility`](#chart-accessibility) | medium | high | Chart accessibility issue detected - missing ARIA attributes or disabled accessibility features |
| [`chart-config`](#chart-config) | medium | high | Chart configuration issue detected - potential performance or display problem |
| [`chart-types`](#chart-types) | medium | high | Chart type mismatch detected - inappropriate chart type for data volume |
| [`color-schemes`](#color-schemes) | medium | high | Color scheme issue detected - invalid hex color format or poor contrast |
| [`mobile-optimization`](#mobile-optimization) | medium | high | Mobile optimization issue detected - charts may not render properly on mobile devices |

## Pattern details

### chart-accessibility

Chart accessibility issue detected - missing ARIA attributes or disabled accessibility features

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `chart`, `accessibility`, `a11y` |

**Match pattern** (Rust `regex` syntax):

```regex
canvas[^>]*[^aria-]|tooltip.*enabled.*false|legend.*display.*false
```

**Reference**: <https://chartjs.org/docs/latest/general/accessibility.html>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
canvasCx…_-=zj
```

### chart-config

Chart configuration issue detected - potential performance or display problem

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `chart`, `configuration`, `performance` |

**Match pattern** (Rust `regex` syntax):

```regex
Chart\.js.*type.*bar.*data.*1000\+|options.*responsive.*false|scale.*ticks.*display.*false
```

**Reference**: <https://www.chartjs.org/docs/latest/configuration/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
Chart.jsFtypep…a-@aQ1000+
```

### chart-types

Chart type mismatch detected - inappropriate chart type for data volume

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `chart`, `type`, `data-visualization` |

**Match pattern** (Rust `regex` syntax):

```regex
type.*bar.*data.*1000\+|type.*line.*categories.*10\+|type.*pie.*slices.*20\+
```

**Reference**: <https://chartjs.org/docs/latest/charts/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
typeUDo-3G92@hbarZyMEuCy VLaxnoFo…00+
```

### color-schemes

Color scheme issue detected - invalid hex color format or poor contrast

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `chart`, `color`, `accessibility` |

**Match pattern** (Rust `regex` syntax):

```regex
backgroundColor.*#[fF]{6}|borderColor.*#[0F]{6}|color.*palette.*contrast
```

**Reference**: <https://chartjs.org/docs/latest/axes/styling.html>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
backgrou…dB#FffFff
```

### mobile-optimization

Mobile optimization issue detected - charts may not render properly on mobile devices

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `chart`, `mobile`, `responsive` |

**Match pattern** (Rust `regex` syntax):

```regex
responsive.*false|width.*100%.*height.*100%|chart.*mobile.*breakpoint
```

**Reference**: <https://chartjs.org/docs/latest/general/responsive.html>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
responsi…se
```
