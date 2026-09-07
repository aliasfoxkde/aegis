//! API integration patterns
//!
//! Detects mistakes specific to client/service API integrations: secrets in
//! query strings, auth tokens reaching logs, disabled certificate
//! validation, unsigned webhooks, and timeout-less HTTP clients. The
//! original pack was a set of presence detectors that flagged *correct*
//! usage (an `Authorization: Bearer` header, a `try/catch` around `fetch`)
//! as findings, each with a copy-pasted "API key leaked" description.

use crate::Pattern;

/// JavaScript-family extensions where client-side API calls appear.
fn js_extensions() -> Vec<String> {
    vec![
        "js".to_string(),
        "mjs".to_string(),
        "cjs".to_string(),
        "jsx".to_string(),
        "ts".to_string(),
        "tsx".to_string(),
    ]
}

/// Broader set including server-side integration languages.
fn service_extensions() -> Vec<String> {
    vec![
        "js".to_string(),
        "mjs".to_string(),
        "cjs".to_string(),
        "jsx".to_string(),
        "ts".to_string(),
        "tsx".to_string(),
        "py".to_string(),
        "rb".to_string(),
        "php".to_string(),
        "go".to_string(),
    ]
}

/// Client/service integration mistakes, scoped to JS/TS plus server-side extensions.
#[must_use]
pub fn get() -> Vec<Pattern> {
    vec![
        // Credentials in query strings end up in access logs, browser
        // history, and Referer headers.
        Pattern {
            name: "api-key-in-query-param".to_string(),
            category: "api-integration".to_string(),
            match_pattern: r#"(?i)[?&](?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|api[_-]?token)=['"]?[A-Za-z0-9_\-]{4,}"#.to_string(),
            enabled: true,
            severity: "high".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Credential passed in a URL query string; use an Authorization header instead".to_string(),
            reference: Some("https://cwe.mitre.org/data/definitions/598.html".to_string()),
            tags: vec![
                "api-integration".to_string(),
                "secrets".to_string(),
                "security".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(
                r"(?i)example\.(?:com|org|net)|your[-_]|placeholder|<[^>]*>|\$\{|insert[-_]?key|xxx".to_string(),
            ),
            file_extensions: service_extensions(),
        },
        // Auth material written to logs breaks out of the request lifecycle
        // and lands in log aggregation systems.
        Pattern {
            name: "bearer-token-logged".to_string(),
            category: "api-integration".to_string(),
            match_pattern: r"(?i)\b(?:console|logger|logging|log)\s*\.\s*(?:log|debug|info|warn|error|trace)\s*\([^)\n]*(?:authorization|bearer|auth[_-]?token|access[_-]?token)".to_string(),
            enabled: true,
            severity: "high".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Authorization token passed to a logging call".to_string(),
            reference: Some("https://cwe.mitre.org/data/definitions/532.html".to_string()),
            tags: vec![
                "api-integration".to_string(),
                "logging".to_string(),
                "security".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r"(?i)redact|scrub|mask|placeholder|your[-_]?token".to_string()),
            file_extensions: js_extensions(),
        },
        // Disabling certificate validation re-enables interception of every
        // request the client makes.
        Pattern {
            name: "ssl-verification-disabled".to_string(),
            category: "api-integration".to_string(),
            match_pattern: r#"(?i)rejectUnauthorized\s*[:=]\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0\b|verify\s*[:=]\s*False\b|ssl[_-]?verify\s*[:=]\s*false|check_hostname\s*[:=]\s*False\b|InsecureSkipVerify\s*:\s*true\b|CURLOPT_SSL_VERIFYPEER\s*,\s*false\b"#.to_string(),
            enabled: true,
            severity: "high".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "TLS certificate verification disabled for an API client".to_string(),
            reference: Some("https://cwe.mitre.org/data/definitions/295.html".to_string()),
            tags: vec![
                "api-integration".to_string(),
                "tls".to_string(),
                "security".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r"(?i)\b(?:example|test|spec|dummy|mock)\b".to_string()),
            file_extensions: service_extensions(),
        },
        // Webhook endpoints that never verify a signature accept forged
        // deliveries from anyone who finds the URL.
        Pattern {
            name: "webhook-signature-unchecked".to_string(),
            category: "api-integration".to_string(),
            match_pattern: r#"(?i)\b(?:post|put)\s*\(\s*['"][^'"]*webhooks?[^'"]*['"][^\n]{0,200}"#.to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Webhook route registered without a visible signature check".to_string(),
            reference: Some(
                "https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries"
                    .to_string(),
            ),
            tags: vec![
                "api-integration".to_string(),
                "webhooks".to_string(),
                "security".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(
                r"(?i)signature|signing[_-]?secret|hmac|\bverify|raw[_-]?body|x-hub|x-signature".to_string(),
            ),
            file_extensions: vec![
                "js".to_string(),
                "ts".to_string(),
                "py".to_string(),
                "rb".to_string(),
            ],
        },
        // A client without a timeout can hang forever on a stalled response,
        // pinning connections and threads.
        Pattern {
            name: "api-client-no-timeout".to_string(),
            category: "api-integration".to_string(),
            match_pattern: r"(?i)\baxios\.create\s*\(\s*\{[^}\n]*\}".to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "HTTP client created without a timeout".to_string(),
            reference: Some("https://axios.rest/pages/advanced/request-config".to_string()),
            tags: vec![
                "api-integration".to_string(),
                "reliability".to_string(),
                "timeout".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r"(?i)\btimeout\b".to_string()),
            file_extensions: js_extensions(),
        },
        // Parsing the body before checking `response.ok` turns 4xx/5xx
        // payloads into silent data errors. Only the chained form is
        // detectable on a single line: `(await fetch(url)).json()`.
        Pattern {
            name: "api-response-status-unchecked".to_string(),
            category: "api-integration".to_string(),
            match_pattern: r"(?i)await\s+[^;\n]{0,60}\bfetch\b[^;\n]{0,40}\.json\s*\(\s*\)".to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Fetch response body parsed without a visible status check".to_string(),
            reference: Some(
                "https://developer.mozilla.org/en-US/docs/Web/API/Window/fetch".to_string(),
            ),
            tags: vec![
                "api-integration".to_string(),
                "error-handling".to_string(),
                "reliability".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r"(?i)\.ok\b|\.status\b|checkStatus|assert".to_string()),
            file_extensions: js_extensions(),
        },
        // Fixed-interval polling hammers the API and hides failures behind
        // the next tick.
        Pattern {
            name: "api-polling-loop".to_string(),
            category: "api-integration".to_string(),
            match_pattern: r"\bsetInterval\s*\([^)\n]{0,120}\bfetch\b".to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Fixed-interval polling loop with fetch; prefer event-driven updates or exponential backoff".to_string(),
            reference: Some(
                "https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/"
                    .to_string(),
            ),
            tags: vec![
                "api-integration".to_string(),
                "rate-limiting".to_string(),
                "performance".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r"\bbackoff\b|\bjitter\b|\bretry\b".to_string()),
            file_extensions: js_extensions(),
        },
        // Wildcard origin plus credentials lets any site make authenticated
        // requests as the victim.
        Pattern {
            name: "cors-credentials-wildcard".to_string(),
            category: "api-integration".to_string(),
            match_pattern: r#"(?i)Access-Control-Allow-Credentials['"\s:,]+true\b[^;\n]{0,120}Access-Control-Allow-Origin['"\s:]+\*|Access-Control-Allow-Origin['"\s:]+\*[^;\n]{0,120}Access-Control-Allow-Credentials['"\s:,]+true\b"#.to_string(),
            enabled: true,
            severity: "high".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "CORS configured with wildcard origin and credentials together".to_string(),
            reference: Some(
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS".to_string(),
            ),
            tags: vec![
                "api-integration".to_string(),
                "cors".to_string(),
                "security".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: service_extensions(),
        },
        // Environment-specific hosts baked into source break deploys and can
        // route production traffic to a developer machine.
        Pattern {
            name: "hardcoded-internal-endpoint".to_string(),
            category: "api-integration".to_string(),
            match_pattern: r#"(?i)['"]https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|(?:[a-z0-9-]+\.)*(?:internal|local|lan))(?::\d+)?(?:/[^'"]*)?['"]"#.to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Hardcoded localhost/internal endpoint; move base URLs to configuration".to_string(),
            reference: Some("https://12factor.net/config".to_string()),
            tags: vec![
                "api-integration".to_string(),
                "configuration".to_string(),
                "portability".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(
                r"(?i)\btest\b|\bspec\b|\bmock\b|allow[_-]?origin|proxy|redirect".to_string(),
            ),
            file_extensions: service_extensions(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_are_unique_and_well_formed() {
        let patterns = get();
        assert_eq!(patterns.len(), 9);
        let mut names: Vec<_> = patterns.iter().map(|p| p.name.as_str()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(
            names.len(),
            count,
            "duplicate names in api-integration pack"
        );
    }
}
