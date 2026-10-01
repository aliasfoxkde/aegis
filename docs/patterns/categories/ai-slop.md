# ai-slop patterns

LLM prose style markers: em dashes, typographic punctuation, slop lexicon — informative

**7 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`slop-ai-attribution`](#slop-ai-attribution) | info | medium | AI attribution footer left in a file (Generated with …, Co-Authored-By: …) — a provenance record, not just a style signal |
| [`slop-ellipsis-character`](#slop-ellipsis-character) | info | low | Single-character ellipsis in a plain-text file — prose typed as '...' by humans; the typographic form arrives by paste |
| [`slop-em-dash`](#slop-em-dash) | info | low | Em dash / horizontal bar in a source or doc file — the punctuation LLM prose overuses and plain-text editing almost never produces |
| [`slop-hype-lexicon`](#slop-hype-lexicon) | info | low | Marketing hype register that LLM READMEs and landing pages default to (harness the power, unleash, game-changer…) |
| [`slop-prose-lexicon`](#slop-prose-lexicon) | info | low | Narrative filler from the LLM lexicon (tapestry, delve into, in the realm of, plethora of…) — individually human, statistically machine |
| [`slop-sycophancy`](#slop-sycophancy) | info | low | Chat-session opener or agreement phrase at the start of a line — a pasted assistant transcript fragment |
| [`slop-typographic-quote`](#slop-typographic-quote) | info | low | Curly single/double quote in a plain-text source file — pasted prose (word processor or LLM), since keyboards and editors emit ASCII quotes |

## Pattern details

### slop-ai-attribution

AI attribution footer left in a file (Generated with …, Co-Authored-By: …) — a provenance record, not just a style signal

| Field | Value |
|-------|-------|
| Severity | `info` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai`, `slop`, `provenance` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(?:(?:generated|built|written)\s+with\s+[^.\n]{0,60}\b(?:claude(?:\s+code)?|anthropic|openai|chatgpt|copilot|cursor|gemini|deepseek)\b|co-?authored-by:\s*[^\n]{0,60}(?:claude|anthropic|openai|copilot|cursor|gemini|noreply@anthropic\.com))
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
co-autho…by: Claude
```

### slop-ellipsis-character

Single-character ellipsis in a plain-text file — prose typed as '...' by humans; the typographic form arrives by paste

| Field | Value |
|-------|-------|
| Severity | `info` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai`, `slop`, `punctuation` |

**Match pattern** (Rust `regex` syntax):

```regex
…
```

**Input that fires** (verified by the liveness test):

```text
…
```

### slop-em-dash

Em dash / horizontal bar in a source or doc file — the punctuation LLM prose overuses and plain-text editing almost never produces

| Field | Value |
|-------|-------|
| Severity | `info` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai`, `slop`, `punctuation` |

**Match pattern** (Rust `regex` syntax):

```regex
[—―]
```

**Input that fires** (verified by the liveness test):

```text
—
```

### slop-hype-lexicon

Marketing hype register that LLM READMEs and landing pages default to (harness the power, unleash, game-changer…)

| Field | Value |
|-------|-------|
| Severity | `info` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai`, `slop`, `lexicon` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:harness(?:ing)?\s+the\s+power|unleash(?:es|ing)?|revolution(?:ize|izing|ises?)|supercharg\w+|look\s+no\s+further|whether\s+you'?re\s+(?:a|an|building)|in\s+today'?s\s+(?:fast-?paced\s+)?(?:world|digital\s+landscape)|game-?chang\w+)\b
```

**Reference**: <https://www.nature.com/articles/s41598-026-35203-3>

**Input that fires** (verified by the liveness test):

```text
harnessing the power
```

### slop-prose-lexicon

Narrative filler from the LLM lexicon (tapestry, delve into, in the realm of, plethora of…) — individually human, statistically machine

| Field | Value |
|-------|-------|
| Severity | `info` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai`, `slop`, `lexicon` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:(?:rich|vibrant|woven)\s+tapestry|testament\s+to|in\s+the\s+realm\s+of|delv(?:e|es|ed|ing)\s+into|deep\s+dive|myriad\s+of|plethora\s+of|ever-?evolving|paradigm\s+shift|fast-?paced\s+(?:world|environment)|navigat\w+\s+the\s+(?:complexities|nuances|landscape|intricacies))\b
```

**Reference**: <https://www.nature.com/articles/s41598-026-35203-3>

**Input that fires** (verified by the liveness test):

```text
rich tapestry
```

### slop-sycophancy

Chat-session opener or agreement phrase at the start of a line — a pasted assistant transcript fragment

| Field | Value |
|-------|-------|
| Severity | `info` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai`, `slop`, `transcript` |

**Match pattern** (Rust `regex` syntax):

```regex
(?im)^\s*(?:certainly!|of course!|great question|good catch|excellent point|happy to help|you(?:'re| are) (?:absolutely )?right)\b
```

**Input that fires** (verified by the liveness test):

```text
 happy to help
```

### slop-typographic-quote

Curly single/double quote in a plain-text source file — pasted prose (word processor or LLM), since keyboards and editors emit ASCII quotes

| Field | Value |
|-------|-------|
| Severity | `info` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai`, `slop`, `punctuation` |

**Match pattern** (Rust `regex` syntax):

```regex
[‘’“”]
```

**Input that fires** (verified by the liveness test):

```text
”
```
