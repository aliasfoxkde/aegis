# accessibility patterns

WCAG 2.x success criteria for markup, media, and styles

**28 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`accesskey-usage`](#accesskey-usage) | low | high | accesskey attribute may conflict with assistive tech shortcuts |
| [`aria-live-off`](#aria-live-off) | low | high | Live region explicitly disabled with aria-live=off |
| [`aria-role-invalid`](#aria-role-invalid) | medium | high | Invalid ARIA role value (not a defined role) |
| [`audio-missing-transcript`](#audio-missing-transcript) | low | low | Audio element present - verify a transcript is provided |
| [`autocomplete-missing`](#autocomplete-missing) | low | medium | Text input missing autocomplete attribute |
| [`autoplay-media`](#autoplay-media) | medium | medium | Media set to autoplay (must be muted or user-controlled) |
| [`blinking-content`](#blinking-content) | medium | medium | Blinking content may cause accessibility issues |
| [`click-without-keyboard`](#click-without-keyboard) | high | medium | Click handler on an element that is not keyboard focusable |
| [`empty-button`](#empty-button) | medium | high | Button has no text content or accessible name |
| [`empty-label`](#empty-label) | medium | high | Label element has no text content |
| [`empty-link-text`](#empty-link-text) | medium | high | Anchor has no link text or accessible name |
| [`font-size-below-12px`](#font-size-below-12px) | low | medium | Font size below 12px/pt detected |
| [`iframe-missing-title`](#iframe-missing-title) | medium | high | Iframe missing title attribute |
| [`invalid-heading-level`](#invalid-heading-level) | low | high | Heading level h6 or higher does not exist in HTML |
| [`marquee-element`](#marquee-element) | high | high | Deprecated marquee element used |
| [`missing-alt-text`](#missing-alt-text) | medium | high | Image missing alt attribute |
| [`missing-focus-indicator`](#missing-focus-indicator) | medium | medium | Focus outline removed without a visible replacement |
| [`missing-form-label`](#missing-form-label) | medium | medium | Form input missing an associated label |
| [`missing-lang-attribute`](#missing-lang-attribute) | medium | high | HTML element missing lang attribute |
| [`missing-main-landmark`](#missing-main-landmark) | low | medium | Page body has no main landmark |
| [`missing-meta-viewport`](#missing-meta-viewport) | medium | high | Viewport meta disables user zoom (user-scalable=no) |
| [`missing-skip-link`](#missing-skip-link) | low | medium | Page body has no skip-to-content link |
| [`missing-table-headers`](#missing-table-headers) | medium | medium | Table has no header cells (<th>) |
| [`missing-title`](#missing-title) | medium | high | Document head missing a <title> element |
| [`positive-tabindex`](#positive-tabindex) | medium | high | Positive tabindex overrides natural focus order |
| [`single-character-heading`](#single-character-heading) | low | medium | Heading contains a single character (likely decorative misuse) |
| [`target-blank-unlabeled`](#target-blank-unlabeled) | low | medium | Link opens in a new window without an accessible warning |
| [`video-missing-captions`](#video-missing-captions) | medium | medium | Video element missing a captions track |

## Pattern details

### accesskey-usage

accesskey attribute may conflict with assistive tech shortcuts

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-2.1.4`, `keyboard` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\saccesskey\s*=
```

**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/character-key-shortcuts>

**Input that fires** (verified by the liveness test):

```text
 accesskey =
```

### aria-live-off

Live region explicitly disabled with aria-live=off

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `aria`, `wcag-4.1.3`, `live-region` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)aria-live\s*=\s*["']off["']
```

**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/status-messages>

**Input that fires** (verified by the liveness test):

```text
aria-live = "off"
```

### aria-role-invalid

Invalid ARIA role value (not a defined role)

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `aria`, `wcag-4.1.2`, `role` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)role\s*=\s*["'](?:text|label|title|heading[2-6]|div|span|image)["']
```

**Reference**: <https://www.w3.org/WAI/ARIA/apg/practices/read-me-first/>

**Input that fires** (verified by the liveness test):

```text
role = 'text'
```

### audio-missing-transcript

Audio element present - verify a transcript is provided

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-1.2.3`, `media` |

**Match pattern** (Rust `regex` syntax):

```regex
(?is)<audio\b[^>]*(?:/>|>.*?</audio>)
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)<track\b[^>]*kind\s*=\s*["']?(?:captions|descriptions)
```
**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/audio-description-or-media-alternative-prerecorded>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
<audio+TkNRwmra…od/iFE-:=MJpYuQW3HxBV>2wX3HbDLmZ7</audio>
```

### autocomplete-missing

Text input missing autocomplete attribute

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-1.3.5`, `form` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)<input\b[^>]*>
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)\bautocomplete\s*=|type\s*=\s*["']?(?:hidden|submit|button|reset|checkbox|radio|file|password|search|email|tel|url|date|number)\b
```
**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/identify-input-purpose>

**Input that fires** (verified by the liveness test):

```text
<input:k>
```

### autoplay-media

Media set to autoplay (must be muted or user-controlled)

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-1.4.2`, `media` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)<(?:video|audio)\b[^>]*\bautoplay\b[^>]*>
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)\bmuted\b
```
**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/audio-control>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
<video-iV…st.7D/kH8cEUSX…ex=jrzdqogRC2J:autoplay Z>
```

### blinking-content

Blinking content may cause accessibility issues

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.css`, `.scss`, `.less`, `.html`, `.htm`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-2.3.1`, `flashing` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i:animation.*:blink|@keyframes\s+.*\s+0%\s*\{\s*[^}]*opacity\s*:\s*0)
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)prefers-reduced-motion
```
**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/three-flashes-or-below-threshold>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
animatio…Ef:blink
```

### click-without-keyboard

Click handler on an element that is not keyboard focusable

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-2.1.1`, `keyboard` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)<(?:div|span|p|img|li|ul|section)\b[^>]*\sonclick\s*=
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)\brole\s*=\s*["']?(?:button|link|tab|menuitem|checkbox|switch|option)\b|\btabindex\s*=
```
**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/keyboard>

**Input that fires** (verified by the liveness test):

```text
<div.kbJMaT:q onclick =
```

### empty-button

Button has no text content or accessible name

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-4.1.2`, `button` |

**Match pattern** (Rust `regex` syntax):

```regex
(?is)<button\b[^>]*>\s*</button>
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)\baria-label(?:ledby)?\s*=|\btitle\s*=
```
**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/name-role-value>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
<button hnWHJ=m/7RGtskaN…g8.Y9V> </button>
```

### empty-label

Label element has no text content

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-3.3.2`, `form` |

**Match pattern** (Rust `regex` syntax):

```regex
(?is)<label\b[^>]*>\s*</label>
```

**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/labels-or-instructions>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
<label-MX…xW=RumwA/7qokhzeQ…U9+acsnBSHTpj2> </label>
```

### empty-link-text

Anchor has no link text or accessible name

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-2.4.4`, `link` |

**Match pattern** (Rust `regex` syntax):

```regex
(?is)<a\b[^>]*>\s*</a>
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)\baria-label(?:ledby)?\s*=|\btitle\s*=|\baria-hidden\b
```
**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/link-purpose-in-context>

**Input that fires** (verified by the liveness test):

```text
<a+ZFv_Cc9.ajrsyK> </a>
```

### font-size-below-12px

Font size below 12px/pt detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.css`, `.scss`, `.less`, `.html`, `.htm`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-1.4.4`, `css` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)font-size\s*:\s*(?:[0-9]|1[01])(?:\.\d+)?(?:px|pt)\b
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)@media[^{]*print
```
**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/resize-text>

**Input that fires** (verified by the liveness test):

```text
font-size : 4.744px
```

### iframe-missing-title

Iframe missing title attribute

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-4.1.2`, `iframe` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)<iframe\b[^>]*>
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)\btitle\s*=|\baria-label(?:ledby)?\s*=|\baria-hidden\b
```
**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/name-role-value>

**Input that fires** (verified by the liveness test):

```text
<iframe >
```

### invalid-heading-level

Heading level h6 or higher does not exist in HTML

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-1.3.1`, `heading` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)<h(?:[6-9]|[1-9][0-9])[\s>]
```

**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/info-and-relationships>

**Input that fires** (verified by the liveness test):

```text
<h7 
```

### marquee-element

Deprecated marquee element used

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-2.2.2`, `deprecated` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)<marquee[\s>]
```

**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/pause-stop-hide>

**Input that fires** (verified by the liveness test):

```text
<marquee>
```

### missing-alt-text

Image missing alt attribute

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-1.1.1`, `image` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)<img\b[^>]*(?:/>|>)
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)\balt\s*=|\brole\s*=\s*["']?presentation\b|\baria-hidden\b
```
**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/non-text-content>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
<img=JQYitRs9…NM:b/A+Kd Gc.vzx6qwPef8/>
```

### missing-focus-indicator

Focus outline removed without a visible replacement

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.css`, `.scss`, `.less`, `.html`, `.htm`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-2.4.7`, `focus` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i):focus[^{]*\{[^}]*outline\s*:\s*(?:none|0)\b
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)box-shadow|outline-offset|border\b
```
**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/focus-visible>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
:focusfNo…hg{2PW.F +M.Jxmp5outline : none
```

### missing-form-label

Form input missing an associated label

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-3.3.2`, `form` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)<input\b[^>]*>
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)\baria-label(?:ledby)?\s*=|\btitle\s*=|type\s*=\s*["']?(?:hidden|submit|button|reset|image)\b
```
**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/labels-or-instructions>

**Input that fires** (verified by the liveness test):

```text
<input/>
```

### missing-lang-attribute

HTML element missing lang attribute

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-3.1.1`, `html` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)<html\b[^>]*>
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)\blang\s*=
```
**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/language-of-page>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
<html/ZiF=TJS+rt4Xm2eV…wp>
```

### missing-main-landmark

Page body has no main landmark

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-1.3.1`, `landmarks` |

**Match pattern** (Rust `regex` syntax):

```regex
(?is)<body\b[^>]*>.*?</body>
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)<main\b|\brole\s*=\s*["']?main\b
```
**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/info-and-relationships>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
<body+9uxeyih7…wa:RGdNBs.8LTVnC3QDX2m/v=z-46c _q5>2.FKscSgb4…CU/_HRZQ8vG…rx@7o-d</body>
```

### missing-meta-viewport

Viewport meta disables user zoom (user-scalable=no)

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-1.4.4`, `viewport` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)<meta\b[^>]*name\s*=\s*["']?viewport[^>]*user-scalable\s*=\s*["']?(?:no|0)\b[^>]*>
```

**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/resize-text>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
<meta-Jo4…y6.fHepcgqm…me = 'viewport…Xa/3AG2=:dZ+s59 FQwjmd3E-as=TJ2ceqk:iVYhnyZ4…le = "no B9HovRNw…X6>
```

### missing-skip-link

Page body has no skip-to-content link

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-2.4.1`, `navigation` |

**Match pattern** (Rust `regex` syntax):

```regex
(?is)<body\b[^>]*>.*?</body>
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)skip|href="#(?:main|content)
```
**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/bypass-blocks>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
<body._DhEW-gm…7y=RpVkKji>b.FCQmvusa…LY ehpq</body>
```

### missing-table-headers

Table has no header cells (<th>)

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-1.3.1`, `table` |

**Match pattern** (Rust `regex` syntax):

```regex
(?is)<table\b[^>]*>.*?</table>
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)<th[\s>]|scope\s*=|\brole\s*=\s*["']?(?:presentation|none)\b
```
**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/info-and-relationships>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
<table-E396+BheDjwTo…4S:mJxdcqPu…Mg>ZmHCMauc…og t8yjLV9/hp3nEPWvqDF._XzefUb@rGQ6T4_2…Xu</table>
```

### missing-title

Document head missing a <title> element

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-2.4.2`, `html` |

**Match pattern** (Rust `regex` syntax):

```regex
(?is)<head\b[^>]*>.*?</head>
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)<title[\s>]
```
**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/page-title>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
<head:jh=_aU-qPm7VeX JwAz4>4PhbA97G…nJ@2yp</head>
```

### positive-tabindex

Positive tabindex overrides natural focus order

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-2.1.1`, `keyboard`, `focus` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)tabindex\s*=\s*["']?[1-9]\d*
```

**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/keyboard>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
tabindex = '76257967…82
```

### single-character-heading

Heading contains a single character (likely decorative misuse)

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-2.4.6`, `heading` |

**Match pattern** (Rust `regex` syntax):

```regex
(?is)<h[1-6]\b[^>]*>\s*[^<\s]\s*</h[1-6]>
```

**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/headings-and-labels>

**Input that fires** (verified by the liveness test):

```text
<h5-Rn3ZTQvv.r> X </h5>
```

### target-blank-unlabeled

Link opens in a new window without an accessible warning

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-3.2.5`, `link` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)<a\b[^>]*target\s*=\s*["']?_blank
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)\baria-label\b|\btitle\s*=\s*["'][^"']*(?:new (?:window|tab)|opens? in)
```
**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/change-on-request>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
<a-/aeDEGANm…5J:KxFPiW3zd=TZ_6.n2Skjrpq8B v4oV+cUupX.m7h=AQyidqfo…et = "_blank
```

### video-missing-captions

Video element missing a captions track

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Binary files | skipped |
| Tags | `accessibility`, `wcag`, `wcag-1.2.2`, `media` |

**Match pattern** (Rust `regex` syntax):

```regex
(?is)<video\b[^>]*(?:/>|>.*?</video>)
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)<track\b[^>]*kind\s*=\s*["']?captions
```
**Reference**: <https://www.w3.org/WAI/WCAG22/Understanding/captions-prerecorded>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
<video WreCyj6p…x9+g7K5.dNPHqG2fhuSV/>
```
