# AI Safety & LLM Patterns (50 patterns)

Detection patterns for AI system security, LLM guardrails, and responsible AI practices.

## AI Safety (25 patterns)

| Pattern | Severity | Description |
|---------|----------|-------------|
| prompt-injection | high | Potential prompt injection detected |
| system-prompt-leak | medium | Potential system prompt reference detected |
| unsafe-model-output | high | Unsafe model output detected |
| hallucination-risk | medium | Potential hallucination risk detected |
| bias-in-training | medium | Potential bias in training data reference |
| reward-hacking-risk | high | Potential reward hacking risk detected |
| mesa-optimization | high | Potential mesa-optimization risk detected |
| model-card-missing | low | Model card or documentation reference |
| ai-bias-report | medium | AI bias or fairness assessment reference |
| model-version-tracking | low | Model version tracking reference |
| evaluation-benchmark | low | AI evaluation benchmark reference |
| adversarial-testing | medium | Adversarial testing reference detected |
| interpretability-tool | low | Interpretability tool reference detected |
| attention-visualization | low | Model visualization reference detected |
| training-data-audit | medium | Training data audit reference detected |
| consent-for-training | high | Consent for data training reference detected |
| data-augmentation | low | Data augmentation technique reference |
| noise-injection | low | Noise injection technique reference |
| human-in-the-loop | medium | Human-in-the-loop reference detected |
| human-approval-required | medium | Human approval requirement detected |
| rlhf-reference | low | RLHF technique reference detected |
| rlhf-reward-model | medium | Reward model training reference detected |
| constitutional-ai | low | Constitutional AI reference detected |
| ai-incident-response | medium | AI incident response reference detected |
| model-rollback | medium | Model rollback capability detected |

## LLM Guardrails (25 patterns)

| Pattern | Severity | Description |
|---------|----------|-------------|
| harmful-content-marker | high | Potential harmful content marker detected |
| pii-leak-risk | high | Potential PII leak instruction detected |
| llm-guardrails-prompt-injection | high | Potential prompt injection attempt |
| system-prompt-override | medium | System prompt override attempt detected |
| role-play-override | medium | Role-play override attempt detected |
| profanity-detected | low | Profanity detected |
| hate-speech-marker | critical | Potential hate speech marker detected |
| violence-glorification | critical | Violence glorification detected |
| data-exfiltration-attempt | critical | Data exfiltration attempt detected |
| sql-injection-request | high | Request for SQL injection guidance |
| code-injection-request | high | Request for malicious code guidance |
| jailbreak-attempt | high | Jailbreak attempt detected |
| hypothetical-malware | medium | Hypothetical malware request detected |
| medical-advice-request | medium | Medical advice request detected |
| legal-advice-request | medium | Legal advice request detected |
| financial-advice-request | medium | Financial advice request detected |
| toxicity-marker | high | Toxicity marker detected |
| self-harm-content | critical | Self-harm content detected |
| privacy-breach-request | high | Privacy breach request detected |
| bias-detection | medium | Potential bias detected |
| output-filtering-enabled | low | Output filtering mechanism detected |
| token-limit-warning | low | Token limit configuration detected |
| pii-output-marker | high | PII marker detected in content |
| copyright-material | medium | Copyright material reference detected |
| trademark-reference | low | Trademark reference detected |

## Related Documentation

- [AI Detection Patterns](../ai_detection.md)
- [DevOps Patterns](../devops.md)
- [Security Hardening Patterns](../security_hardening.md)
- [Main Pattern Index](../README.md)
