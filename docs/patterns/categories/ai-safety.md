# ai-safety patterns

Agentic and LLM application safety checks

**25 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`adversarial-testing`](#adversarial-testing) | medium | high | Adversarial testing reference detected |
| [`ai-bias-report`](#ai-bias-report) | medium | high | AI bias or fairness assessment reference |
| [`ai-incident-response`](#ai-incident-response) | medium | high | AI incident response reference detected |
| [`attention-visualization`](#attention-visualization) | low | high | Model visualization reference detected |
| [`bias-in-training`](#bias-in-training) | medium | medium | Potential bias in training data reference |
| [`consent-for-training`](#consent-for-training) | high | high | Consent for data training reference detected |
| [`constitutional-ai`](#constitutional-ai) | low | high | Constitutional AI reference detected |
| [`data-augmentation`](#data-augmentation) | low | high | Data augmentation technique reference |
| [`evaluation-benchmark`](#evaluation-benchmark) | low | high | AI evaluation benchmark reference |
| [`hallucination-risk`](#hallucination-risk) | medium | medium | Potential hallucination risk detected |
| [`human-approval-required`](#human-approval-required) | medium | high | Human approval requirement detected |
| [`human-in-the-loop`](#human-in-the-loop) | medium | high | Human-in-the-loop reference detected |
| [`interpretability-tool`](#interpretability-tool) | low | high | Interpretability tool reference detected |
| [`mesa-optimization`](#mesa-optimization) | high | low | Potential mesa-optimization risk detected |
| [`model-card-missing`](#model-card-missing) | low | high | Model card or documentation reference |
| [`model-rollback`](#model-rollback) | medium | high | Model rollback capability detected |
| [`model-version-tracking`](#model-version-tracking) | low | high | Model version tracking reference |
| [`noise-injection`](#noise-injection) | low | high | Noise injection technique reference |
| [`prompt-injection`](#prompt-injection) | high | medium | Potential prompt injection detected |
| [`reward-hacking-risk`](#reward-hacking-risk) | high | medium | Potential reward hacking risk detected |
| [`rlhf-reference`](#rlhf-reference) | low | high | RLHF technique reference detected |
| [`rlhf-reward-model`](#rlhf-reward-model) | medium | high | Reward model training reference detected |
| [`system-prompt-leak`](#system-prompt-leak) | medium | low | Potential system prompt reference detected |
| [`training-data-audit`](#training-data-audit) | medium | high | Training data audit reference detected |
| [`unsafe-model-output`](#unsafe-model-output) | high | high | Unsafe model output detected |

## Pattern details

### adversarial-testing

Adversarial testing reference detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `adversarial`, `testing` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(adversarial|red\s+team|attack\s+testing)
```

**Input that fires** (verified by the liveness test):

```text
adversarial
```

### ai-bias-report

AI bias or fairness assessment reference

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `bias`, `fairness` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(ai\s+bias|fairness\s+report|impact\s+assessment)
```

**Input that fires** (verified by the liveness test):

```text
ai bias
```

### ai-incident-response

AI incident response reference detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `incident-response`, `safety` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(ai\s+incident|model\s+fail|incident\s+report)
```

**Input that fires** (verified by the liveness test):

```text
ai incident
```

### attention-visualization

Model visualization reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `visualization`, `interpretability` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(attention\s+map|activation\s+map|gradient\s+viz)
```

**Input that fires** (verified by the liveness test):

```text
attention map
```

### bias-in-training

Potential bias in training data reference

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `bias`, `training` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(training\s+data|bias|discriminat).*\b(contain|include|inject)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
training dataNb8Q…Ff.contain
```

### consent-for-training

Consent for data training reference detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `consent`, `privacy` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(consent|opt.?in|permission)\s.*\b(train|use\s+data)
```

**Input that fires** (verified by the liveness test):

```text
consent 3UMK-train
```

### constitutional-ai

Constitutional AI reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `constitutional-ai`, `alignment` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(constitutional\s+ai|CAI|principle.?based)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
constitu…al ai
```

### data-augmentation

Data augmentation technique reference

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `robustness`, `training` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(augment|synthesiz|generate\s+data)
```

**Input that fires** (verified by the liveness test):

```text
augment
```

### evaluation-benchmark

AI evaluation benchmark reference

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `evaluation`, `benchmark` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(MMLU|BIG-Bench|GLUE|HELM|TruthfulQA)
```

**Input that fires** (verified by the liveness test):

```text
MMLU
```

### hallucination-risk

Potential hallucination risk detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `hallucination`, `accuracy` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(hallucin|confabula|fabricat).*\b(fact|information|data)
```

**Input that fires** (verified by the liveness test):

```text
hallucinTS fact
```

### human-approval-required

Human approval requirement detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `human-approval`, `control` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(require.*human|human.*approval|human.*sign.?off)
```

**Input that fires** (verified by the liveness test):

```text
requireMzurj zc4human
```

### human-in-the-loop

Human-in-the-loop reference detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `human-oversight`, `control` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(human.?in.?the.?loop|HITL|human\s+oversight)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
human7in…op
```

### interpretability-tool

Interpretability tool reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `interpretability`, `explainability` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(SHAP|LIME|feature\s+importance|attribution)
```

**Input that fires** (verified by the liveness test):

```text
SHAP
```

### mesa-optimization

Potential mesa-optimization risk detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `mesa-optimization`, `alignment` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(mesa.?optim|inner.?optim|acquisit|power.?seek)
```

**Input that fires** (verified by the liveness test):

```text
mesa_optim
```

### model-card-missing

Model card or documentation reference

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `transparency`, `documentation` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)model\s*card|model\s*sheet|model\s*document
```

**Reference**: <https://modelcards.withgoogle.com/>

**Input that fires** (verified by the liveness test):

```text
model card
```

### model-rollback

Model rollback capability detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `rollback`, `operations` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(rollback|revert|previous\s+version)\s.*\b(model|ai)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
rollback w7eAfmaz…s3 .hCZHrNYo…Vv@Ktu_y_Fq…5M/SG4PdpXb…pE _25jn9oR…el
```

### model-version-tracking

Model version tracking reference

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `versioning`, `reproducibility` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(model\s+version|model\s+hash|snapshot)
```

**Input that fires** (verified by the liveness test):

```text
model version
```

### noise-injection

Noise injection technique reference

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `robustness`, `fuzzing` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(noise|inject|fuzz)\s.*\b(input|data|training)
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
noise GH@iEnCpgY/L4_BRAFZ…ut
```

### prompt-injection

Potential prompt injection detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `prompt-injection`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(ignore\s+(previous|above|all)|disregard\s+(previous|your)|you\s+are\s+now|forget\s+everything)
```

**Reference**: <https://www.promptguard.com/>

**Input that fires** (verified by the liveness test):

```text
ignore previous
```

### reward-hacking-risk

Potential reward hacking risk detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `alignment`, `reward` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(reward\s+hack|optimize\s+wrong|goal\s+mis-spec)
```

**Input that fires** (verified by the liveness test):

```text
reward hack
```

### rlhf-reference

RLHF technique reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `rlhf`, `alignment` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(RLHF|reinforcement\s+learning\s+from\s+human\s+feedback)
```

**Input that fires** (verified by the liveness test):

```text
RLHF
```

### rlhf-reward-model

Reward model training reference detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `reward-model`, `alignment` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(reward\s+model|train\s+reward|preference\s+model)
```

**Input that fires** (verified by the liveness test):

```text
reward model
```

### system-prompt-leak

Potential system prompt reference detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `prompt`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)system\s*prompt|instruction\s*manual|foundation\s*prompt
```

**Input that fires** (verified by the liveness test):

```text
system prompt
```

### training-data-audit

Training data audit reference detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `data-governance`, `training` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(training\s+data\s+audit|data\s+lineage|data\s+provenance)
```

**Input that fires** (verified by the liveness test):

```text
training data audit
```

### unsafe-model-output

Unsafe model output detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `ai-safety`, `output`, `content` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(unsafe|harmful|inappropriate)\s+(output|response|content)
```

**Input that fires** (verified by the liveness test):

```text
unsafe output
```
