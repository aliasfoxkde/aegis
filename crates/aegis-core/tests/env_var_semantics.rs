//! Env-var semantics guardrails.
//!
//! `env_var: true` marks a rule as env-scan-only (`PatternDefinition::
//! is_env_var_only`): it never runs against file contents. The flag is
//! reserved for credential shapes that are only precise with an env-var
//! key name for context — bare `[A-Za-z0-9]{25,}` blobs, UUIDs, crypto
//! addresses. Vendor-prefixed credentials (`glpat-`, `sk-ant-`, `npm_`,
//! ...) are precise in source files and must stay file-active: before
//! the Phase 5 audit a dozen flagship rules (GitLab, OpenAI, Anthropic,
//! HuggingFace, npm, JWTs, Google, Facebook, Discord, Mailchimp) were
//! env-scan-only and undetectable in leaked files.
//!
//! `scan_env` matches every rule in the `secrets` category regardless of
//! the flag, so clearing the flag never weakens env coverage.

use aegis_core::pattern::PatternDefinition;
use aegis_core::Scanner;
use aegis_patterns::Pattern;

fn convert(p: &Pattern) -> PatternDefinition {
    PatternDefinition {
        name: p.name.clone(),
        category: p.category.clone(),
        match_pattern: p.match_pattern.clone(),
        enabled: p.enabled,
        severity: aegis_core::Severity::parse(&p.severity).unwrap_or(aegis_core::Severity::Medium),
        confidence: aegis_core::Confidence::parse(&p.confidence)
            .unwrap_or(aegis_core::Confidence::Medium),
        min_entropy: p.min_entropy,
        description: p.description.clone(),
        reference: p.reference.clone(),
        tags: p.tags.clone(),
        env_var: p.env_var,
        binary: p.binary,
        exclude_pattern: p.exclude.clone(),
        file_extensions: p.file_extensions.clone(),
        ..Default::default()
    }
}

/// The complete env-scan-only set. Extending it means accepting that the
/// rule stops detecting its payload in leaked files — do that only for
/// shapes that would otherwise flood file scans with false positives.
const ENV_ONLY_RULES: &[&str] = &[
    "azure-api-key",
    "bearer-token",
    "database-connection-string",
    "dropbox-api-key",
    "ethereum-address",
    "finance-bitcoin-address",
    "firebase-api-key",
    "generic-api-key",
    "generic-secret",
    "github-oauth-token",
    "heroku-api-key",
    "secrets-aws-access-key",
    "secrets-aws-secret-key",
    "secrets-github-token",
    "secrets-sendgrid-api-key",
    "secrets-slack-token",
    "secrets-stripe-api-key",
    "secrets-stripe-publishable-key",
    "secrets-twilio-api-key",
    "stripe-publishable-key",
    "twitter-api-key",
];

/// Rule -> a file-mode payload every one of which must produce a finding.
/// Each payload clears the rule's own entropy gate; the value shapes are
/// realistic leaked credentials, not minimal regex satisfactions. The
/// literals are split with `concat!` (as in `aegis_patterns::examples`)
/// so no full credential-shaped literal appears in this source file —
/// GitHub push protection otherwise blocks the branch — while the
/// compiled strings are byte-identical.
const FILE_MODE_REQUIREMENTS: &[(&str, &str)] = &[
    // Vendor-prefixed rules that are file-active as of the Phase 5 audit.
    (
        "gitlab-token",
        concat!("deploy_token = \"glpat-", "YH6PpZhgTWozFM4DBYqA\""),
    ),
    (
        "jwt-token",
        concat!(
            "session = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
            "eyJzdWIiOiIxMjM0NTY3ODkwfQ.9f3KqZw7vR2mXn8JbT5cLy1dHa4Eu6Ws0PgNe2VkQrT\""
        ),
    ),
    (
        "google-api-key",
        concat!("gcp = \"AIza", "9f3KqZw7vR2mXn8JbT5cLy1dHa4Eu6Ws0PgNe2\""),
    ),
    (
        "google-oauth-token",
        concat!(
            "tok = \"ya29.",
            "9f3KqZw7vR2mXn8JbT5cLy1dHa4Eu6Ws0PgNe2VkQrTMxUAoiSdHa4Eu6Ws0PgNe2VkQrTMxUAoiS\""
        ),
    ),
    (
        "npm-token",
        concat!(
            "//registry.npmjs.org/:_authToken=npm_",
            "9f3KqZw7vR2mXn8JbT5cLy1dHa4Eu6Ws0PgN"
        ),
    ),
    (
        "openai-api-key",
        concat!(
            "openai = \"sk-",
            "9f3KqZw7vR2mXn8JbT5cLy1dHa4Eu6Ws0PgNe2VkQrTMxUAoiS\""
        ),
    ),
    (
        "anthropic-api-key",
        concat!(
            "anthropic = \"sk-ant-",
            "9f3KqZw7vR2mXn8JbT5cLy1dHa4Eu6Ws0PgNe2VkQrTMxUAoiSdHa4\""
        ),
    ),
    (
        "huggingface-api-key",
        concat!("hf = \"hf_", "9f3KqZw7vR2mXn8JbT5cLy1dHa4Eu6Ws0PgNe2V\""),
    ),
    (
        "facebook-access-token",
        concat!(
            "fb = \"EAACEdEose0cBA",
            "9f3KqZw7vR2mXn8JbT5cLy1dHa4Eu6Ws0PgNe2VkQrTMxUAoiSdHa4Eu6Ws0PgNe2VkQrTMxUAoiS\""
        ),
    ),
    (
        "discord-api-key",
        concat!(
            "bot = \"9f3KqZw7vR2mXn8JbT5cLy1dHa4Eu6Ws.",
            "9f3KqZ.9f3KqZw7vR2mXn8JbT5cLy1dHa4Eu6Ws0Pg\""
        ),
    ),
    (
        "mailchimp-api-key",
        concat!("chimp = \"e9f31b7c5a2d4806fa3c9104be57d268", "-us98\""),
    ),
    (
        "connection-string-with-password",
        "SqlCon = \"Server=db.internal;Password=9f3KqZw7vR2mXn8JbT5cLy1;\"",
    ),
    (
        "basic-auth-credentials",
        concat!("auth = \"basic ", "OTMzS3Fadzd2UjJtWG44SmJUNWNMeTFkSEE9\""),
    ),
    // Pre-existing file-active counterparts: env-only siblings rely on
    // these for file-mode coverage of the same credential families.
    ("aws-access-key", "key = \"AKIAIOSFODNN7EXAMPLE\""),
    (
        "aws-secret-key",
        concat!(
            "aws_secret_access_key = \"9f3KqZw7vR2mXn8JbT5cLy1dHa4Eu6Ws0PgNe2VkQ",
            "rT\""
        ),
    ),
    (
        "github-token",
        concat!(
            "gh = \"ghp_",
            "9f3KqZw7vR2mXn8JbT5cLy1dHa4Eu6Ws0PgNe2VkQrTMxUAoiS\""
        ),
    ),
    (
        "slack-token",
        concat!(
            "slack = \"xoxb-",
            "123456789012-123456789012-9f3KqZw7vR2mXn8JbT5cLy1dHa4Eu6Ws0PgNe2V\""
        ),
    ),
    (
        "stripe-api-key",
        concat!(
            "stripe = \"sk_live_",
            "9f3KqZw7vR2mXn8JbT5cLy1dHa4Eu6Ws0PgNe2V\""
        ),
    ),
    (
        "sendgrid-api-key",
        concat!(
            "sg = \"SG.",
            "9f3KqZw7vR2mXn8JbT5cLy.9f3KqZw7vR2mXn8JbT5cLy1dHa4Eu6Ws0PgNe2VkQrTMxUAoiSdHa\""
        ),
    ),
    (
        "twilio-api-key",
        concat!("tw = \"SK", "9f3KqZw7vR2mXn8JbT5cLy1dHa4Eu6Ws0PgNe2V\""),
    ),
    (
        "bearer-token-url",
        concat!(
            "Authorization: Bearer 9f3KqZw7vR2mXn8",
            "JbT5cLy1dHa4Eu6Ws0PgNe2VkQrTMxUAoiS"
        ),
    ),
];

#[test]
fn env_scan_only_rules_are_exactly_the_documented_set() {
    let actual: Vec<String> = aegis_patterns::all_patterns()
        .into_iter()
        .filter(|p| p.env_var)
        .map(|p| p.name)
        .collect();
    let mut actual = actual;
    actual.sort_unstable();
    let mut expected: Vec<String> = ENV_ONLY_RULES.iter().map(|s| s.to_string()).collect();
    expected.sort_unstable();
    assert_eq!(
        actual, expected,
        "the env-scan-only rule set changed; update ENV_ONLY_RULES and \
         docs/PATTERNS.md deliberately"
    );
}

#[test]
fn vendor_prefixed_secrets_are_detected_in_files() {
    let all: Vec<Pattern> = aegis_patterns::all_patterns()
        .into_iter()
        .filter(|p| p.enabled)
        .collect();
    let file_active: Vec<Pattern> = all.iter().filter(|p| !p.env_var).cloned().collect();
    assert!(file_active.len() > 600, "unexpectedly small pattern corpus");
    let scanner = Scanner::from_definitions(file_active.iter().map(convert).collect())
        .expect("file-active patterns must compile");

    let mut failures: Vec<String> = Vec::new();
    for (rule, payload) in FILE_MODE_REQUIREMENTS {
        let fired = scanner
            .scan_string(payload, "leaked.rs")
            .iter()
            .any(|f| f.pattern == *rule);
        if !fired {
            failures.push(format!("{rule} did not fire in file mode on {payload:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "secret families lost file-mode coverage ({}):\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// Behavioral backstop for the exclusion mechanism itself: env-scan-only
/// rules never appear among file-mode findings, whatever the content.
#[test]
fn env_scan_only_rules_never_fire_in_file_mode() {
    let all: Vec<Pattern> = aegis_patterns::all_patterns()
        .into_iter()
        .filter(|p| p.enabled)
        .collect();
    let scanner = Scanner::from_definitions(all.iter().map(convert).collect())
        .expect("bundled patterns must compile");

    // A bare 25+ alphanumeric blob would match `twitter-api-key` and the
    // other shape-generic env-only rules if they leaked into file mode.
    let findings = scanner.scan_string(
        "AZURE_BLOB_KEY = \"9f3KqZw7vR2mXn8JbT5cLy1dHa4Eu6Ws0PgNe2VkQrTMxUAoiSdHa4\"",
        "blob.rs",
    );
    let offenders: Vec<&str> = findings
        .iter()
        .map(|f| f.pattern.as_str())
        .filter(|name| ENV_ONLY_RULES.contains(name))
        .collect();
    assert!(
        offenders.is_empty(),
        "env-scan-only rules fired in file mode: {offenders:?}"
    );
}
