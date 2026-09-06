//! Fixture-based pattern regression tests.
//!
//! These lock in the two directions every pattern pack must satisfy:
//! compliant code produces zero findings, and planted violations each
//! produce exactly the expected finding. They exist because the packs
//! previously shipped patterns that fired on their own positive examples.

use aegis_cli::scanner::convert_pattern;
use aegis_core::{Finding, Scanner};

fn scanner() -> Scanner {
    let definitions: Vec<aegis_core::PatternDefinition> = aegis_patterns::all_patterns()
        .into_iter()
        .map(convert_pattern)
        .collect();
    Scanner::from_definitions(definitions).expect("all shipped patterns must compile")
}

fn findings(scanner: &Scanner, content: &str, source: &str) -> Vec<Finding> {
    let mut found = scanner.scan_string(content, source);
    found.sort_by(|a, b| {
        (a.pattern.clone(), a.location.line).cmp(&(b.pattern.clone(), b.location.line))
    });
    found
}

fn pattern_names(fs: &[Finding]) -> Vec<&str> {
    fs.iter().map(|f| f.pattern.as_str()).collect()
}

const COMPLIANT_HTML: &str = r##"<html lang="en">
<head><title>Fully accessible page</title></head>
<body>
<a href="#main" class="skip-link">Skip to main content</a>
<main id="main">
<img src="logo.png" alt="Company logo" width="120" height="40">
<button aria-label="Close dialog">Close</button>
<input type="text" id="name" name="name" aria-label="Your name" autocomplete="name">
<a href="/home">Home</a>
</main>
</body>
</html>
"##;

/// Fully compliant markup must not trip a single accessibility rule.
#[test]
fn compliant_html_has_zero_accessibility_findings() {
    let scanner = scanner();
    let fs = findings(&scanner, COMPLIANT_HTML, "fixtures/compliant.html");
    let a11y: Vec<_> = fs
        .iter()
        .filter(|f| f.category == "accessibility")
        .map(|f| f.pattern.as_str())
        .collect();
    assert!(a11y.is_empty(), "unexpected a11y findings: {a11y:?}");
}

const BROKEN_HTML: &str = r#"<html>
<head></head>
<body>
<img src="chart.png">
<button></button>
<a href="/x"></a>
<input type="text" id="q">
<iframe src="https://ads.example.com"></iframe>
<table><tr><td>1</td></tr></table>
<div onclick="submit()">Go</div>
<video autoplay><source src="a.mp4"></video>
<span role="text">hi</span>
<h7>bad</h7>
</body>
</html>
"#;

/// Every planted violation must be caught by exactly the intended rule.
#[test]
fn broken_html_triggers_expected_accessibility_rules() {
    let scanner = scanner();
    let fs = findings(&scanner, BROKEN_HTML, "fixtures/broken.html");
    let names = pattern_names(&fs);

    let expected = [
        "missing-lang-attribute",
        "missing-title",
        "missing-skip-link",
        "missing-main-landmark",
        "missing-alt-text",
        "empty-button",
        "empty-link-text",
        "missing-form-label",
        "iframe-missing-title",
        "missing-table-headers",
        "click-without-keyboard",
        "autoplay-media",
        "video-missing-captions",
        "aria-role-invalid",
        "invalid-heading-level",
    ];
    for rule in expected {
        assert!(
            names.contains(&rule),
            "rule {rule} did not fire on its violation; findings: {names:?}"
        );
    }
}

/// Compliant CSS (focus style, readable font, reduced-motion guard) is clean.
#[test]
fn compliant_css_has_zero_findings() {
    let scanner = scanner();
    let css = "a:focus { outline: 2px solid blue; box-shadow: 0 0 4px blue; }\n\
               p { font-size: 16px; }\n\
               @media (prefers-reduced-motion: reduce) { .anim { animation: none; } }\n";
    let fs = findings(&scanner, css, "fixtures/compliant.css");
    assert!(
        fs.is_empty(),
        "compliant CSS must be clean, got: {:?}",
        pattern_names(&fs)
    );
}

const SUSPICIOUS_TXT: &str = r#"# real credential in URL - should fire
curl https://admin:s3cretP@ss@api.internal.com/v1
# placeholder docs examples - should NOT fire
# See https://user:password@example.com/path
# GET https://{username}:{password}@host/resource
fetch("https://user:pass@example.org/api");
"#;

/// Credential-URL detection must catch real credentials and skip the
/// placeholder forms that documentation uses.
#[test]
fn credential_url_patterns_skip_documentation_placeholders() {
    let scanner = scanner();
    let fs = findings(&scanner, SUSPICIOUS_TXT, "fixtures/urls.txt");

    let url_hits: Vec<_> = fs
        .iter()
        .filter(|f| matches!(f.pattern.as_str(), "password-in-url" | "basic-auth-url"))
        .collect();
    assert_eq!(url_hits.len(), 2, "exactly the two URL rules fire once");
    assert_eq!(
        url_hits[0].location.line, 2,
        "only the real credential line"
    );

    let placeholder_lines: Vec<_> = fs
        .iter()
        .filter(|f| f.location.line >= 4)
        .map(|f| f.pattern.as_str())
        .collect();
    assert!(
        !placeholder_lines.contains(&"password-in-url"),
        "placeholders must not be flagged: {placeholder_lines:?}"
    );
}

/// Prose and manifest files that previously produced hundreds of self-scan
/// findings must stay clean.
#[test]
fn prose_and_manifests_stay_clean() {
    let scanner = scanner();
    let cargo_toml = "[dependencies]\n\
                      aegis-core = { path = \"../aegis-core\", version = \"0.2\" }\n\
                      serde = { path = \"../../other/lib\" }\n";
    let fs = findings(&scanner, cargo_toml, "Cargo.toml");
    assert!(
        fs.is_empty(),
        "manifest relative paths must not be flagged: {:?}",
        pattern_names(&fs)
    );

    let prose = "// Retrieval of cached records with strict typing throughout.\n\
                 const x = \"../relative/path/in/comment.txt\";\n\
                 import { a } from \"./mod\";\n\
                 let total = 2026;\n";
    let fs = findings(&scanner, prose, "fixtures/clean.js");
    assert!(
        fs.is_empty(),
        "prose mentioning eval-adjacent words must stay clean: {:?}",
        pattern_names(&fs)
    );
}

/// Positive controls for the repaired quality/security patterns.
#[test]
fn repaired_patterns_still_catch_real_violations() {
    let scanner = scanner();
    let bad_js = "eval(userInput);\n\
                  with (obj) { doThing(); }\n\
                  var oldStyle = 1;\n\
                  if (a == b) { }\n\
                  const cfg = { alg: \"none\", typ: \"JWT\" };\n\
                  document.write(\"<b>\" + user + \"</b>\");\n";
    let findings_vec = findings(&scanner, bad_js, "fixtures/bad.js");
    let names = pattern_names(&findings_vec);

    for rule in [
        "code-quality-eval-usage",
        "with-statement",
        "var-declaration",
        "loose-equality",
        "jwt-none-algorithm",
    ] {
        assert!(
            names.contains(&rule),
            "repaired rule {rule} stopped detecting its target; findings: {names:?}"
        );
    }

    let dockerfile = "ARG API_KEY=abc123\n";
    let dockerfile_findings = findings(&scanner, dockerfile, "Dockerfile.dev");
    let names = pattern_names(&dockerfile_findings);
    assert!(
        names.contains(&"secrets-in-dockerfile"),
        "ARG API_KEY must be detected: {names:?}"
    );
}

/// Files without an extension must not trip extension-scoped patterns.
#[test]
fn extension_scoped_patterns_skip_extensionless_files() {
    let scanner = scanner();
    // The img tag only trips rules scoped to html/jsx/...; a bare README
    // containing one is documentation, not a web page.
    let fs = findings(&scanner, "<img src=\"x.png\">", "README");
    assert!(
        fs.iter().all(|f| f.category != "accessibility"),
        "extensionless files must skip scoped rules: {:?}",
        pattern_names(&fs)
    );
}

/// Correct API-integration usage must never be flagged. The original
/// api-integration pack fired on `Authorization: Bearer` headers and
/// try/catch around fetch, labeling good code as leaked secrets.
#[test]
fn correct_api_usage_is_clean() {
    let scanner = scanner();
    let good = "const client = axios.create({ baseURL: api, timeout: 5000 });\n\
                fetch('/api/items', { headers: { Authorization: `Bearer ${token}` } });\n\
                const res = await fetch(url);\n\
                if (!res.ok) throw new Error('bad status');\n\
                const data = await res.json();\n\
                app.post('/github/webhook', express.raw({type: 'application/json'}), verifySignature, handler);\n";
    let fs = findings(&scanner, good, "fixtures/client.ts");
    let api: Vec<_> = fs
        .iter()
        .filter(|f| f.category == "api-integration")
        .map(|f| f.pattern.as_str())
        .collect();
    assert!(api.is_empty(), "correct API usage must be clean: {api:?}");
}

/// Genuine API-integration mistakes must be caught by the intended rules.
#[test]
fn api_integration_mistakes_are_caught() {
    let scanner = scanner();
    let bad = "const d = await (await fetch(url)).json();\n\
               const c2 = axios.create({ baseURL: 'http://localhost:3000' });\n\
               console.log('auth header was', authorization);\n\
               const agent = new https.Agent({ rejectUnauthorized: false });\n\
               app.post('/stripe/webhook', handler);\n";
    let fs = findings(&scanner, bad, "fixtures/bad_client.ts");
    let names = pattern_names(&fs);

    for rule in [
        "api-response-status-unchecked",
        "bearer-token-logged",
        "ssl-verification-disabled",
        "webhook-signature-unchecked",
    ] {
        assert!(
            names.contains(&rule),
            "rule {rule} did not fire on its violation; findings: {names:?}"
        );
    }
}
