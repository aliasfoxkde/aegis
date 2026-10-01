//! AI-slop patterns — LLM prose conventions that leak into source trees.
//!
//! The sibling `ai-detection` category flags evidence that code was
//! machine-generated. This category is narrower and shallower: it flags the
//! *style* of LLM-written prose — typographic punctuation (the em dash above
//! all), attribution footers pasted from a chat session, and the recycled
//! lexicon ("delve into", "tapestry", "harness the power") that LLMs reach
//! for far more often than people do.
//!
//! Same honesty contract as `ai-detection`: these are triage signals, not
//! verdicts. Humans write em dashes; "deep dive" predates chatbots; the
//! literature citation on the lexical rules applies here verbatim. Every
//! rule is `info` severity — reported, but never contributing to the risk
//! score or flipping the exit code — with `low` confidence except the
//! attribution footer, which is near-proof of provenance and rates
//! `medium`.
//!
//! Treat a pile of these findings on one file as the real signal — a file
//! where five slop rules fire was almost certainly drafted by a model.

use crate::Pattern;

/// Slop rules; all info severity, one medium-confidence provenance rule.
#[must_use]
pub fn get() -> Vec<Pattern> {
    vec![
        Pattern {
            name: "slop-em-dash".to_string(),
            category: "ai-slop".to_string(),
            match_pattern: "[\u{2014}\u{2015}]".to_string(),
            enabled: true,
            severity: "info".to_string(),
            confidence: "low".to_string(),
            min_entropy: None,
            description: "Em dash / horizontal bar in a source or doc file — the punctuation LLM prose overuses and plain-text editing almost never produces".to_string(),
            reference: None,
            tags: vec!["ai".to_string(), "slop".to_string(), "punctuation".to_string()],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: Vec::new(),
        },
        Pattern {
            name: "slop-typographic-quote".to_string(),
            category: "ai-slop".to_string(),
            match_pattern: "[\u{2018}\u{2019}\u{201C}\u{201D}]".to_string(),
            enabled: true,
            severity: "info".to_string(),
            confidence: "low".to_string(),
            min_entropy: None,
            description: "Curly single/double quote in a plain-text source file — pasted prose (word processor or LLM), since keyboards and editors emit ASCII quotes".to_string(),
            reference: None,
            tags: vec!["ai".to_string(), "slop".to_string(), "punctuation".to_string()],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: Vec::new(),
        },
        Pattern {
            name: "slop-ellipsis-character".to_string(),
            category: "ai-slop".to_string(),
            match_pattern: "\u{2026}".to_string(),
            enabled: true,
            severity: "info".to_string(),
            confidence: "low".to_string(),
            min_entropy: None,
            description: "Single-character ellipsis in a plain-text file — prose typed as '...' by humans; the typographic form arrives by paste".to_string(),
            reference: None,
            tags: vec!["ai".to_string(), "slop".to_string(), "punctuation".to_string()],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: Vec::new(),
        },
        Pattern {
            name: "slop-ai-attribution".to_string(),
            category: "ai-slop".to_string(),
            match_pattern: r"(?i)(?:(?:generated|built|written)\s+with\s+[^.\n]{0,60}\b(?:claude(?:\s+code)?|anthropic|openai|chatgpt|copilot|cursor|gemini|deepseek)\b|co-?authored-by:\s*[^\n]{0,60}(?:claude|anthropic|openai|copilot|cursor|gemini|noreply@anthropic\.com))".to_string(),
            enabled: true,
            severity: "info".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "AI attribution footer left in a file (Generated with …, Co-Authored-By: …) — a provenance record, not just a style signal".to_string(),
            reference: None,
            tags: vec!["ai".to_string(), "slop".to_string(), "provenance".to_string()],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: Vec::new(),
        },
        Pattern {
            name: "slop-sycophancy".to_string(),
            category: "ai-slop".to_string(),
            match_pattern: r"(?im)^\s*(?:certainly!|of course!|great question|good catch|excellent point|happy to help|you(?:'re| are) (?:absolutely )?right)\b".to_string(),
            enabled: true,
            severity: "info".to_string(),
            confidence: "low".to_string(),
            min_entropy: None,
            description: "Chat-session opener or agreement phrase at the start of a line — a pasted assistant transcript fragment".to_string(),
            reference: None,
            tags: vec!["ai".to_string(), "slop".to_string(), "transcript".to_string()],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: Vec::new(),
        },
        Pattern {
            name: "slop-prose-lexicon".to_string(),
            category: "ai-slop".to_string(),
            match_pattern: r"(?i)\b(?:(?:rich|vibrant|woven)\s+tapestry|testament\s+to|in\s+the\s+realm\s+of|delv(?:e|es|ed|ing)\s+into|deep\s+dive|myriad\s+of|plethora\s+of|ever-?evolving|paradigm\s+shift|fast-?paced\s+(?:world|environment)|navigat\w+\s+the\s+(?:complexities|nuances|landscape|intricacies))\b".to_string(),
            enabled: true,
            severity: "info".to_string(),
            confidence: "low".to_string(),
            min_entropy: None,
            description: "Narrative filler from the LLM lexicon (tapestry, delve into, in the realm of, plethora of…) — individually human, statistically machine".to_string(),
            reference: Some("https://www.nature.com/articles/s41598-026-35203-3".to_string()),
            tags: vec!["ai".to_string(), "slop".to_string(), "lexicon".to_string()],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: Vec::new(),
        },
        Pattern {
            name: "slop-hype-lexicon".to_string(),
            category: "ai-slop".to_string(),
            match_pattern: r"(?i)\b(?:harness(?:ing)?\s+the\s+power|unleash(?:es|ing)?|revolution(?:ize|izing|ises?)|supercharg\w+|look\s+no\s+further|whether\s+you'?re\s+(?:a|an|building)|in\s+today'?s\s+(?:fast-?paced\s+)?(?:world|digital\s+landscape)|game-?chang\w+)\b".to_string(),
            enabled: true,
            severity: "info".to_string(),
            confidence: "low".to_string(),
            min_entropy: None,
            description: "Marketing hype register that LLM READMEs and landing pages default to (harness the power, unleash, game-changer…)".to_string(),
            reference: Some("https://www.nature.com/articles/s41598-026-35203-3".to_string()),
            tags: vec!["ai".to_string(), "slop".to_string(), "lexicon".to_string()],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: Vec::new(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    /// (rule name, text that must fire, text that must not) — one row per
    /// rule, so a regex edit that breaks a rule fails exactly one assertion.
    const CASES: &[(&str, &str, &str)] = &[
        (
            "slop-em-dash",
            "the parser — and its tests — live here",
            "the parser and its tests live here",
        ),
        (
            "slop-typographic-quote",
            "it\u{2019}s not a real \u{201C}fix\u{201D}",
            "it's not a real \"fix\"",
        ),
        (
            "slop-ellipsis-character",
            "waiting for the build\u{2026}",
            "waiting for the build...",
        ),
        (
            "slop-ai-attribution",
            "\u{1f916} Generated with Claude Code",
            "generated with rustc 1.88",
        ),
        (
            "slop-sycophancy",
            "You're absolutely right, the lock is needed.",
            "// you are right sometimes",
        ),
        (
            "slop-prose-lexicon",
            "This header is a testament to the module's design.",
            "the tapestry crate is not installed",
        ),
        (
            "slop-hype-lexicon",
            "Harness the power of incremental builds!",
            "we could not harness the sled",
        ),
    ];

    #[test]
    fn every_rule_compiles_and_separates_signal_from_noise() {
        let patterns = get();
        assert_eq!(patterns.len(), CASES.len(), "a rule is missing a test row");
        for (pattern, (name, positive, negative)) in patterns.iter().zip(CASES) {
            assert_eq!(pattern.name, *name, "rule order changed; fix the table");
            let re = Regex::new(&pattern.match_pattern).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(re.is_match(positive), "{name} must match {positive:?}");
            assert!(!re.is_match(negative), "{name} must not match {negative:?}");
        }
    }

    #[test]
    fn slop_rules_are_info_severity_and_scoped_to_every_text_file() {
        // `info` is load-bearing: the CLI's exit code ignores info findings,
        // so a style signal must never fail a scan on its own.
        for pattern in get() {
            assert_eq!(pattern.severity, "info", "{} must stay info", pattern.name);
            assert!(
                pattern.file_extensions.is_empty(),
                "{} must scan every text file",
                pattern.name
            );
        }
    }

    #[test]
    fn attribution_rule_is_the_only_medium_confidence_rule() {
        for pattern in get() {
            let expected = if pattern.name == "slop-ai-attribution" {
                "medium"
            } else {
                "low"
            };
            assert_eq!(pattern.confidence, expected, "{}", pattern.name);
        }
    }
}
