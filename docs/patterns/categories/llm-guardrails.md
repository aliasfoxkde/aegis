# llm-guardrails patterns

Prompt-injection and LLM guardrail checks

**25 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`bias-detection`](#bias-detection) | medium | medium | Potential bias detected |
| [`code-injection-request`](#code-injection-request) | high | high | Request for malicious code guidance |
| [`copyright-material`](#copyright-material) | medium | medium | Copyright material reference detected |
| [`data-exfiltration-attempt`](#data-exfiltration-attempt) | critical | high | Data exfiltration attempt detected |
| [`financial-advice-request`](#financial-advice-request) | medium | medium | Financial advice request detected |
| [`harmful-content-marker`](#harmful-content-marker) | high | medium | Potential harmful content marker detected |
| [`hate-speech-marker`](#hate-speech-marker) | critical | high | Potential hate speech marker detected |
| [`hypothetical-malware`](#hypothetical-malware) | medium | medium | Hypothetical malware request detected |
| [`jailbreak-attempt`](#jailbreak-attempt) | high | high | Jailbreak attempt detected |
| [`legal-advice-request`](#legal-advice-request) | medium | high | Legal advice request detected |
| [`llm-guardrails-prompt-injection`](#llm-guardrails-prompt-injection) | high | high | Potential prompt injection attempt |
| [`medical-advice-request`](#medical-advice-request) | medium | high | Medical advice request detected |
| [`output-filtering-enabled`](#output-filtering-enabled) | low | high | Output filtering mechanism detected |
| [`pii-leak-risk`](#pii-leak-risk) | high | medium | Potential PII leak instruction detected |
| [`pii-output-marker`](#pii-output-marker) | high | high | PII marker detected in content |
| [`privacy-breach-request`](#privacy-breach-request) | high | high | Privacy breach request detected |
| [`profanity-detected`](#profanity-detected) | low | high | Profanity detected |
| [`role-play-override`](#role-play-override) | medium | medium | Role-play override attempt detected |
| [`self-harm-content`](#self-harm-content) | critical | high | Self-harm content detected |
| [`sql-injection-request`](#sql-injection-request) | high | high | Request for SQL injection guidance |
| [`system-prompt-override`](#system-prompt-override) | medium | high | System prompt override attempt detected |
| [`token-limit-warning`](#token-limit-warning) | low | high | Token limit configuration detected |
| [`toxicity-marker`](#toxicity-marker) | high | high | Toxicity marker detected |
| [`trademark-reference`](#trademark-reference) | low | medium | Trademark reference detected |
| [`violence-glorification`](#violence-glorification) | critical | high | Violence glorification detected |

## Pattern details

### bias-detection

Potential bias detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `bias`, `fairness` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(bias|discriminat|prejudic|stereotyp)\s+(in|against|between)
```

**Input that fires** (verified by the liveness test):

```text
bias in
```

### code-injection-request

Request for malicious code guidance

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `code-injection`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(give|writ|show|explain).*(malicious|exploit|rce|payload)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
givep6ma…us
```

### copyright-material

Copyright material reference detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `copyright`, `ip` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(copyright|©|\(c\))\s*\d{4}.*(material|work|content)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
copyright 3835ff2T…al
```

### data-exfiltration-attempt

Data exfiltration attempt detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `data-exfiltration`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(extract|reveal|share|leak)\s+(password|credential|secret|key|token)
```

**Input that fires** (verified by the liveness test):

```text
extract password
```

### financial-advice-request

Financial advice request detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `financial`, `advice` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(financial|investment|stock\s+market|crypto)\s+advice
```

**Input that fires** (verified by the liveness test):

```text
financial advice
```

### harmful-content-marker

Potential harmful content marker detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `safety`, `content-filter` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(harmful|illegal|malicious|attack|exploit)\s+(content|instruct|guide)
```

**Reference**: <https://platform.openai.com/docs/guides/moderation>

**Input that fires** (verified by the liveness test):

```text
harmful content
```

### hate-speech-marker

Potential hate speech marker detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `hate-speech`, `safety` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(hate|slur|discriminat|racist|sexist)\s+(speech|content|language)
```

**Input that fires** (verified by the liveness test):

```text
hate speech
```

### hypothetical-malware

Hypothetical malware request detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `malware`, `safety` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(hypothetical|theoretical|imagine).*(malware|virus|ransomware)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
hypothet…re
```

### jailbreak-attempt

Jailbreak attempt detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `jailbreak`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(?:jailbreak|jail_break|do\s+any\s*thing\s+now|developer\s+mode|dan\s+mode|ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions)\b
```

**Input that fires** (verified by the liveness test):

```text
jailbreak
```

### legal-advice-request

Legal advice request detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `legal`, `advice` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(legal|lawyer|law\s+advice|attorney)\s+advice
```

**Input that fires** (verified by the liveness test):

```text
legal advice
```

### llm-guardrails-prompt-injection

Potential prompt injection attempt

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `prompt-injection`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(ignore|disregard|bypass)\s+(previous|above|initial|system)
```

**Reference**: <https://www.promptguard.com/>

**Input that fires** (verified by the liveness test):

```text
ignore previous
```

### medical-advice-request

Medical advice request detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `medical`, `advice` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(medical|health|doctor|diagnosis|treatment)\s+advice
```

**Input that fires** (verified by the liveness test):

```text
medical advice
```

### output-filtering-enabled

Output filtering mechanism detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `filtering`, `safety` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(content.?filter|output.?filter|moderation.?api)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
contentz…er
```

### pii-leak-risk

Potential PII leak instruction detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `pii`, `safety` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(extract|leak|share)\s+(personal|private|confidential)\s+(data|information)
```

**Input that fires** (verified by the liveness test):

```text
extract personal data
```

### pii-output-marker

PII marker detected in content

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `pii`, `detection` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(ssn|social\s*security|credit\s*card|bank\s+account)
```

**Input that fires** (verified by the liveness test):

```text
ssn
```

### privacy-breach-request

Privacy breach request detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `privacy`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(spy|surveill|track|monitor)\s+(user|customer|employee)
```

**Input that fires** (verified by the liveness test):

```text
spy user
```

### profanity-detected

Profanity detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `content-filter`, `profanity` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)\b(fuck|shit|ass|damn|bitch)\b
```

**Input that fires** (verified by the liveness test):

```text
fuck
```

### role-play-override

Role-play override attempt detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `prompt-injection`, `jailbreak` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(you\s+are\s+now|act\s+as|pretend\s+to\s+be|imagine\s+you\s+are)
```

**Input that fires** (verified by the liveness test):

```text
you are now
```

### self-harm-content

Self-harm content detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `self-harm`, `safety` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(self.?harm|suicide|self.?injury|cut\s+yourself)
```

**Reference**: <https://988lifeline.org/>

**Input that fires** (verified by the liveness test):

```text
selfJharm
```

### sql-injection-request

Request for SQL injection guidance

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `sql-injection`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(give|writ|show|explain).*(sql\s+injection|drop\s+table|delete\s+from)
```

**Input that fires** (verified by the liveness test):

```text
giveQG4-Ysql injection
```

### system-prompt-override

System prompt override attempt detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `prompt-injection`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(system\s*prompt|initial\s*instructions)\s*[:=]\s*['"]
```

**Input that fires** (verified by the liveness test):

```text
system prompt = "
```

### token-limit-warning

Token limit configuration detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `token-limit`, `configuration` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(max.?token|token.?limit|context.?window)
```

**Input that fires** (verified by the liveness test):

```text
maxWtoken
```

### toxicity-marker

Toxicity marker detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `toxicity`, `safety` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(toxic|harmful|offensive|inappropriate)\s+(content|language|behavior)
```

**Input that fires** (verified by the liveness test):

```text
toxic content
```

### trademark-reference

Trademark reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `trademark`, `ip` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(trademark|registered\s+trademark)
```

**Input that fires** (verified by the liveness test):

```text
trademark
```

### violence-glorification

Violence glorification detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `llm-guardrails`, `violence`, `safety` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(glorif|celebrat|justif).*\b(violence|attack|murder|kill)
```

**Input that fires** (verified by the liveness test):

```text
glorifHT.violence
```
