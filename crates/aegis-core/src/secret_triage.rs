//! Triage verdicts for secret-shaped values.
//!
//! A secret-pattern hit is a *shape*, not a proof. A vendor's published
//! example key and a live AWS key have the same shape, and only one of them
//! is worth a rotation. Triage support exists so that the set of hits a
//! human has to look at is bounded by evidence rather than by volume.
//!
//! [`triage_secret`] looks at the matched text and answers one question:
//! *does this value look like a live credential, like a placeholder, or is
//! the evidence mixed?* It combines three independent signals:
//!
//! - **Known examples.** Values that appear in vendor documentation — the
//!   example access key in AWS's own IAM guide — are placeholders by
//!   construction.
//! - **Placeholder markers.** Words like `example`, `changeme`, or
//!   `your-api-key` in the value, or a template shape such as `<token>`.
//! - **Shape.** A value that repeats one character many times, such as a
//!   token whose body is a single repeated digit, is a placeholder too.
//!
//! Entropy separates the remaining values: random credentials have high
//! entropy, `hunter2` does not.
//!
//! The verdict never repeats the value it judged. The reasons name the
//! *signal* (`"entropy 4.21 over 24 bytes is consistent with a random
//! credential"`), never a fragment of the credential, because a report that
//! says "the secret contains `example`" is itself a disclosure.

use serde::{Deserialize, Serialize};

use crate::entropy::shannon_entropy;

/// The category whose findings carry a triage verdict.
pub const SECRET_CATEGORY: &str = "secrets";

/// A value shorter than this cannot be a credential worth rotating.
const MIN_CREDENTIAL_LENGTH: usize = 12;

/// Entropy below this is characteristic of a hand-written placeholder.
const PLACEHOLDER_ENTROPY: f64 = 2.5;

/// Entropy at or above this is characteristic of a random credential.
const RANDOM_ENTROPY: f64 = 3.5;

/// Values published by vendors as documentation examples.
///
/// These are not secrets and never were; a scanner that flags them is
/// correct about the shape and wrong about the risk. Tokens whose body is a
/// single repeated character — GitHub's documentation token is a run of
/// identical digits — are caught by the repetition rule instead, so they
/// are deliberately absent from this list.
const KNOWN_EXAMPLES: &[&str] = &[
    // AWS documentation examples.
    "AKIAIOSFODNN7EXAMPLE", // aegis:ignore:aws-access-key -- synthetic fixtures
    "AKIAI44QH8DHBEXAMPLE", // aegis:ignore:aws-access-key -- synthetic fixtures
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
];

/// Words that mark a value as a placeholder rather than a credential.
///
/// The list is deliberately narrow: a word like `test` appears inside real
/// values often enough that treating it as decisive would hide findings.
const PLACEHOLDER_WORDS: &[&str] = &[
    "example",
    "dummy",
    "placeholder",
    "changeme",
    "change-me",
    "change_me",
    "redacted",
    "yourkey",
    "your-key",
    "your_key",
    "your-api-key",
    "your-api-token",
    "your-token",
    "yoursecret",
    "your-secret",
    "your_secret",
    "fake",
    "sample",
    "notreal",
    "not-real",
    "not_real",
    "invalid",
    "sk_test",
    "test_key",
    "test-key",
    "testkey",
    "insert",
];

/// How a secret-shaped value was assessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageOutcome {
    /// The value has the shape of a live credential and should be treated as
    /// exposed until it is proved otherwise.
    LikelyReal,
    /// The value is a placeholder, a documentation example, or a test
    /// double, and needs no rotation.
    LikelyPlaceholder,
    /// The signals disagree or are too weak to decide; a human has to look.
    Uncertain,
}

impl TriageOutcome {
    /// The label used in reports and in serialized output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LikelyReal => "likely_real",
            Self::LikelyPlaceholder => "likely_placeholder",
            Self::Uncertain => "uncertain",
        }
    }

    /// Whether the outcome means the value needs no further attention.
    #[must_use]
    pub fn is_placeholder(self) -> bool {
        matches!(self, Self::LikelyPlaceholder)
    }
}

impl std::fmt::Display for TriageOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The verdict for one secret-shaped value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretTriage {
    /// The verdict.
    pub outcome: TriageOutcome,
    /// How much weight the verdict carries: `high`, `medium`, or `low`.
    pub confidence: String,
    /// Why the verdict was reached, one line per signal.
    ///
    /// The lines never quote the value; they name the signal only.
    pub reasons: Vec<String>,
}

impl SecretTriage {
    /// Whether the verdict says the value needs no further attention.
    #[must_use]
    pub fn is_placeholder(&self) -> bool {
        self.outcome.is_placeholder()
    }
}

/// Assess a secret-shaped value.
///
/// The verdict is a triage aid, never a clearance: [`TriageOutcome::LikelyReal`]
/// means "look at this first", and [`TriageOutcome::LikelyPlaceholder`] means
/// "the shape is right but the evidence says this is an example".
#[must_use]
pub fn triage_secret(value: &str) -> SecretTriage {
    let lowered = value.to_ascii_lowercase();
    let mut reasons = Vec::new();
    let mut placeholder = false;
    let mut confident_placeholder = false;

    if KNOWN_EXAMPLES.iter().any(|example| value.contains(example)) {
        placeholder = true;
        confident_placeholder = true;
        reasons.push("matches a published documentation example".to_string());
    }

    if let Some(word) = PLACEHOLDER_WORDS
        .iter()
        .find(|word| lowered.contains(**word))
    {
        placeholder = true;
        reasons.push(format!("contains the placeholder marker `{word}`"));
    }

    if has_template_shape(value) {
        placeholder = true;
        confident_placeholder = true;
        reasons.push("contains a template placeholder".to_string());
    }

    if has_long_repetition(value) {
        placeholder = true;
        reasons.push("repeats one character many times".to_string());
    }

    let entropy = shannon_entropy(value);
    if entropy < PLACEHOLDER_ENTROPY {
        placeholder = true;
        reasons.push(format!(
            "entropy {entropy:.2} is below the {PLACEHOLDER_ENTROPY:.2} placeholder threshold"
        ));
    }

    if value.len() < MIN_CREDENTIAL_LENGTH {
        reasons.push(format!(
            "value is {} bytes, shorter than the {MIN_CREDENTIAL_LENGTH}-byte minimum",
            value.len()
        ));
    }

    if placeholder {
        let confidence = if confident_placeholder {
            "high"
        } else {
            "medium"
        };
        return SecretTriage {
            outcome: TriageOutcome::LikelyPlaceholder,
            confidence: confidence.to_string(),
            reasons,
        };
    }

    if value.len() >= MIN_CREDENTIAL_LENGTH && entropy >= RANDOM_ENTROPY {
        reasons.push(format!(
            "entropy {entropy:.2} over {} bytes is consistent with a random credential",
            value.len()
        ));
        return SecretTriage {
            outcome: TriageOutcome::LikelyReal,
            confidence: "medium".to_string(),
            reasons,
        };
    }

    reasons.push(format!(
        "entropy {entropy:.2} over {} bytes is not decisive",
        value.len()
    ));
    SecretTriage {
        outcome: TriageOutcome::Uncertain,
        confidence: "low".to_string(),
        reasons,
    }
}

/// Whether the value contains a template placeholder such as `<token>`.
fn has_template_shape(value: &str) -> bool {
    value.contains('<') || value.contains('>') || value.contains("{{") || value.contains("}}")
}

/// Whether the value repeats one character six or more times in a row.
fn has_long_repetition(value: &str) -> bool {
    let mut run = 0usize;
    let mut previous: Option<char> = None;
    for character in value.chars() {
        if Some(character) == previous {
            run += 1;
            if run >= 6 {
                return true;
            }
        } else {
            run = 1;
            previous = Some(character);
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_documentation_example_is_a_placeholder() {
        let verdict = triage_secret("AKIAIOSFODNN7EXAMPLE"); // aegis:ignore:aws-access-key -- synthetic fixtures
        assert_eq!(verdict.outcome, TriageOutcome::LikelyPlaceholder);
        assert_eq!(verdict.confidence, "high");
        assert!(verdict.is_placeholder());
    }

    #[test]
    fn a_placeholder_word_marks_a_placeholder() {
        let verdict = triage_secret("your-api-key-here");
        assert_eq!(verdict.outcome, TriageOutcome::LikelyPlaceholder);
        assert!(verdict
            .reasons
            .iter()
            .any(|reason| reason.contains("placeholder marker")));
    }

    #[test]
    fn a_template_shape_marks_a_placeholder() {
        let verdict = triage_secret("<your-token-here>");
        assert_eq!(verdict.outcome, TriageOutcome::LikelyPlaceholder);
    }

    #[test]
    fn a_repeated_character_marks_a_placeholder() {
        let verdict = triage_secret("aaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(verdict.outcome, TriageOutcome::LikelyPlaceholder);
    }

    #[test]
    fn a_token_whose_body_repeats_one_digit_is_a_placeholder() {
        // The shape GitHub's documentation token has, without repeating
        // the token itself in this file.
        let verdict = triage_secret("ghp_2222222222222222222222222222222222");
        assert_eq!(verdict.outcome, TriageOutcome::LikelyPlaceholder);
    }

    #[test]
    fn a_random_looking_value_looks_real() {
        let verdict = triage_secret("9fK2mQ7xL4nR8vT1yW6zB3cD5");
        assert_eq!(verdict.outcome, TriageOutcome::LikelyReal);
        assert_eq!(verdict.confidence, "medium");
    }

    #[test]
    fn a_short_value_is_uncertain() {
        let verdict = triage_secret("hunter2");
        assert_eq!(verdict.outcome, TriageOutcome::Uncertain);
        assert!(verdict
            .reasons
            .iter()
            .any(|reason| reason.contains("shorter than")));
    }

    #[test]
    fn the_reasons_never_quote_the_value() {
        let secret = "s3cr3t-v4lu3-with-a-marker";
        let verdict = triage_secret(secret);
        for reason in &verdict.reasons {
            assert!(
                !reason.contains(secret),
                "a reason must not repeat the value: {reason}"
            );
        }
    }

    #[test]
    fn the_outcome_serializes_as_a_stable_label() {
        let json = serde_json::to_string(&TriageOutcome::LikelyReal).expect("serializable");
        assert_eq!(json, "\"likely_real\"");
    }
}
