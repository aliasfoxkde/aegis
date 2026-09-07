//! Accessibility patterns - WCAG compliance, screen reader support
//!
//! Every "missing X" rule here is expressed as a *presence* match plus an
//! `exclude` regex: the finding fires only when the matched element (or
//! subtree) does NOT also contain the accessible alternative. This is how
//! negative checks are written without lookarounds, which the `regex` crate
//! does not support. Patterns are scoped to web file types via
//! `file_extensions` so they never run against unrelated sources.

use crate::Pattern;

/// File extensions shared by all HTML/JSX-flavored accessibility patterns.
fn web_extensions() -> Vec<String> {
    vec![
        "html".to_string(),
        "htm".to_string(),
        "jsx".to_string(),
        "tsx".to_string(),
        "vue".to_string(),
        "svelte".to_string(),
    ]
}

/// Extensions for stylesheet-bearing patterns (inline styles included).
fn style_extensions() -> Vec<String> {
    vec![
        "css".to_string(),
        "scss".to_string(),
        "less".to_string(),
        "html".to_string(),
        "htm".to_string(),
        "vue".to_string(),
        "svelte".to_string(),
    ]
}

/// WCAG rules for HTML, JSX, and stylesheet files; every rule is extension-scoped.
#[must_use]
pub fn get() -> Vec<Pattern> {
    vec![
        // WCAG 1.1.1 Non-text Content
        Pattern {
            name: "missing-alt-text".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?i)<img\b[^>]*(?:/>|>)".to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Image missing alt attribute".to_string(),
            reference: Some(
                "https://www.w3.org/WAI/WCAG22/Understanding/non-text-content".to_string(),
            ),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-1.1.1".to_string(),
                "image".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(
                r#"(?i)\balt\s*=|\brole\s*=\s*["']?presentation\b|\baria-hidden\b"#.to_string(),
            ),
            file_extensions: web_extensions(),
        },
        // WCAG 4.1.2 Name, Role, Value - empty <button> has no accessible name
        Pattern {
            name: "empty-button".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?is)<button\b[^>]*>\s*</button>".to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Button has no text content or accessible name".to_string(),
            reference: Some(
                "https://www.w3.org/WAI/WCAG22/Understanding/name-role-value".to_string(),
            ),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-4.1.2".to_string(),
                "button".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r"(?i)\baria-label(?:ledby)?\s*=|\btitle\s*=".to_string()),
            file_extensions: web_extensions(),
        },
        // WCAG 3.1.1 Language of Page
        Pattern {
            name: "missing-lang-attribute".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?i)<html\b[^>]*>".to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "HTML element missing lang attribute".to_string(),
            reference: Some(
                "https://www.w3.org/WAI/WCAG22/Understanding/language-of-page".to_string(),
            ),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-3.1.1".to_string(),
                "html".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r"(?i)\blang\s*=".to_string()),
            file_extensions: web_extensions(),
        },
        // WCAG 2.4.4 Link Purpose - empty anchors have no link text
        Pattern {
            name: "empty-link-text".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?is)<a\b[^>]*>\s*</a>".to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Anchor has no link text or accessible name".to_string(),
            reference: Some(
                "https://www.w3.org/WAI/WCAG22/Understanding/link-purpose-in-context".to_string(),
            ),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-2.4.4".to_string(),
                "link".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(
                r"(?i)\baria-label(?:ledby)?\s*=|\btitle\s*=|\baria-hidden\b".to_string(),
            ),
            file_extensions: web_extensions(),
        },
        // WCAG 3.3.2 Labels or Instructions / 1.3.1 Info and Relationships
        Pattern {
            name: "missing-form-label".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?i)<input\b[^>]*>".to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Form input missing an associated label".to_string(),
            reference: Some(
                "https://www.w3.org/WAI/WCAG22/Understanding/labels-or-instructions".to_string(),
            ),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-3.3.2".to_string(),
                "form".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(
                r#"(?i)\baria-label(?:ledby)?\s*=|\btitle\s*=|type\s*=\s*["']?(?:hidden|submit|button|reset|image)\b"#
                    .to_string(),
            ),
            file_extensions: web_extensions(),
        },
        // WCAG 2.4.2 Page Title
        Pattern {
            name: "missing-title".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?is)<head\b[^>]*>.*?</head>".to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Document head missing a <title> element".to_string(),
            reference: Some("https://www.w3.org/WAI/WCAG22/Understanding/page-title".to_string()),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-2.4.2".to_string(),
                "html".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r"(?i)<title[\s>]".to_string()),
            file_extensions: web_extensions(),
        },
        // WCAG 1.4.4 Resize Text - viewport meta that disables zoom
        Pattern {
            name: "missing-meta-viewport".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r#"(?i)<meta\b[^>]*name\s*=\s*["']?viewport[^>]*user-scalable\s*=\s*["']?(?:no|0)\b[^>]*>"#.to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Viewport meta disables user zoom (user-scalable=no)".to_string(),
            reference: Some("https://www.w3.org/WAI/WCAG22/Understanding/resize-text".to_string()),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-1.4.4".to_string(),
                "viewport".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: web_extensions(),
        },
        // WCAG 1.4.4 Resize Text - sub-12px text is a common a11y defect
        Pattern {
            name: "font-size-below-12px".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?i)font-size\s*:\s*(?:[0-9]|1[01])(?:\.\d+)?(?:px|pt)\b".to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Font size below 12px/pt detected".to_string(),
            reference: Some("https://www.w3.org/WAI/WCAG22/Understanding/resize-text".to_string()),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-1.4.4".to_string(),
                "css".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r"(?i)@media[^{]*print".to_string()),
            file_extensions: style_extensions(),
        },
        // WCAG 2.4.1 Bypass Blocks
        Pattern {
            name: "missing-skip-link".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?is)<body\b[^>]*>.*?</body>".to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Page body has no skip-to-content link".to_string(),
            reference: Some("https://www.w3.org/WAI/WCAG22/Understanding/bypass-blocks".to_string()),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-2.4.1".to_string(),
                "navigation".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r##"(?i)skip|href="#(?:main|content)"##.to_string()),
            file_extensions: web_extensions(),
        },
        // WCAG 1.3.1 Info and Relationships - landmarks
        Pattern {
            name: "missing-main-landmark".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?is)<body\b[^>]*>.*?</body>".to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Page body has no main landmark".to_string(),
            reference: Some(
                "https://www.w3.org/WAI/WCAG22/Understanding/info-and-relationships".to_string(),
            ),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-1.3.1".to_string(),
                "landmarks".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r#"(?i)<main\b|\brole\s*=\s*["']?main\b"#.to_string()),
            file_extensions: web_extensions(),
        },
        // WCAG 1.3.1 - h7+ is not a valid heading level
        Pattern {
            name: "invalid-heading-level".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?i)<h(?:[6-9]|[1-9][0-9])[\s>]".to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Heading level h6 or higher does not exist in HTML".to_string(),
            reference: Some(
                "https://www.w3.org/WAI/WCAG22/Understanding/info-and-relationships".to_string(),
            ),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-1.3.1".to_string(),
                "heading".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: web_extensions(),
        },
        // WCAG 1.3.5 Identify Input Purpose
        Pattern {
            name: "autocomplete-missing".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?i)<input\b[^>]*>".to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Text input missing autocomplete attribute".to_string(),
            reference: Some(
                "https://www.w3.org/WAI/WCAG22/Understanding/identify-input-purpose".to_string(),
            ),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-1.3.5".to_string(),
                "form".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(
                r#"(?i)\bautocomplete\s*=|type\s*=\s*["']?(?:hidden|submit|button|reset|checkbox|radio|file|password|search|email|tel|url|date|number)\b"#
                    .to_string(),
            ),
            file_extensions: web_extensions(),
        },
        // WCAG 2.4.7 Focus Visible - focus outline suppressed without replacement
        Pattern {
            name: "missing-focus-indicator".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?i):focus[^{]*\{[^}]*outline\s*:\s*(?:none|0)\b".to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Focus outline removed without a visible replacement".to_string(),
            reference: Some("https://www.w3.org/WAI/WCAG22/Understanding/focus-visible".to_string()),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-2.4.7".to_string(),
                "focus".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r"(?i)box-shadow|outline-offset|border\b".to_string()),
            file_extensions: style_extensions(),
        },
        // WCAG 1.3.1 - data tables need header cells
        Pattern {
            name: "missing-table-headers".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?is)<table\b[^>]*>.*?</table>".to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Table has no header cells (<th>)".to_string(),
            reference: Some(
                "https://www.w3.org/WAI/WCAG22/Understanding/info-and-relationships".to_string(),
            ),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-1.3.1".to_string(),
                "table".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(
                r#"(?i)<th[\s>]|scope\s*=|\brole\s*=\s*["']?(?:presentation|none)\b"#.to_string(),
            ),
            file_extensions: web_extensions(),
        },
        // WCAG 1.2.2 Captions (Prerecorded)
        Pattern {
            name: "video-missing-captions".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?is)<video\b[^>]*(?:/>|>.*?</video>)".to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Video element missing a captions track".to_string(),
            reference: Some(
                "https://www.w3.org/WAI/WCAG22/Understanding/captions-prerecorded".to_string(),
            ),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-1.2.2".to_string(),
                "media".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r#"(?i)<track\b[^>]*kind\s*=\s*["']?captions"#.to_string()),
            file_extensions: web_extensions(),
        },
        // WCAG 1.2.3 Audio Description or Media Alternative - advisory
        Pattern {
            name: "audio-missing-transcript".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?is)<audio\b[^>]*(?:/>|>.*?</audio>)".to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "low".to_string(),
            min_entropy: None,
            description: "Audio element present - verify a transcript is provided".to_string(),
            reference: Some(
                "https://www.w3.org/WAI/WCAG22/Understanding/audio-description-or-media-alternative-prerecorded"
                    .to_string(),
            ),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-1.2.3".to_string(),
                "media".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(
                r#"(?i)<track\b[^>]*kind\s*=\s*["']?(?:captions|descriptions)"#.to_string(),
            ),
            file_extensions: web_extensions(),
        },
        // WCAG 4.1.2 Name, Role, Value
        Pattern {
            name: "iframe-missing-title".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?i)<iframe\b[^>]*>".to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Iframe missing title attribute".to_string(),
            reference: Some(
                "https://www.w3.org/WAI/WCAG22/Understanding/name-role-value".to_string(),
            ),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-4.1.2".to_string(),
                "iframe".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(
                r"(?i)\btitle\s*=|\baria-label(?:ledby)?\s*=|\baria-hidden\b".to_string(),
            ),
            file_extensions: web_extensions(),
        },
        // WCAG 2.2.2 Pause, Stop, Hide - deprecated movement element
        Pattern {
            name: "marquee-element".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?i)<marquee[\s>]".to_string(),
            enabled: true,
            severity: "high".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Deprecated marquee element used".to_string(),
            reference: Some("https://www.w3.org/WAI/WCAG22/Understanding/pause-stop-hide".to_string()),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-2.2.2".to_string(),
                "deprecated".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: web_extensions(),
        },
        // WCAG 2.3.1 Three Flashes or Below Threshold
        Pattern {
            name: "blinking-content".to_string(),
            category: "accessibility".to_string(),
            match_pattern:
                r"(?i:animation.*:blink|@keyframes\s+.*\s+0%\s*\{\s*[^}]*opacity\s*:\s*0)"
                    .to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Blinking content may cause accessibility issues".to_string(),
            reference: Some(
                "https://www.w3.org/WAI/WCAG22/Understanding/three-flashes-or-below-threshold"
                    .to_string(),
            ),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-2.3.1".to_string(),
                "flashing".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r"(?i)prefers-reduced-motion".to_string()),
            file_extensions: style_extensions(),
        },
        // Invalid ARIA roles commonly seen in the wild (correct is img, button, ...)
        Pattern {
            name: "aria-role-invalid".to_string(),
            category: "accessibility".to_string(),
            match_pattern:
                r#"(?i)role\s*=\s*["'](?:text|label|title|heading[2-6]|div|span|image)["']"#
                    .to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Invalid ARIA role value (not a defined role)".to_string(),
            reference: Some("https://www.w3.org/WAI/ARIA/apg/practices/read-me-first/".to_string()),
            tags: vec![
                "accessibility".to_string(),
                "aria".to_string(),
                "wcag-4.1.2".to_string(),
                "role".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: web_extensions(),
        },
        // WCAG 4.1.3 Status Messages - aria-live="off" suppresses announcements
        Pattern {
            name: "aria-live-off".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r#"(?i)aria-live\s*=\s*["']off["']"#.to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Live region explicitly disabled with aria-live=off".to_string(),
            reference: Some(
                "https://www.w3.org/WAI/WCAG22/Understanding/status-messages".to_string(),
            ),
            tags: vec![
                "accessibility".to_string(),
                "aria".to_string(),
                "wcag-4.1.3".to_string(),
                "live-region".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: web_extensions(),
        },
        // WCAG 2.1.1 Keyboard - positive tabindex breaks natural focus order
        Pattern {
            name: "positive-tabindex".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r#"(?i)tabindex\s*=\s*["']?[1-9]\d*"#.to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Positive tabindex overrides natural focus order".to_string(),
            reference: Some("https://www.w3.org/WAI/WCAG22/Understanding/keyboard".to_string()),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-2.1.1".to_string(),
                "keyboard".to_string(),
                "focus".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: web_extensions(),
        },
        // WCAG 2.1.1 Keyboard - click handler on a non-focusable element
        Pattern {
            name: "click-without-keyboard".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?i)<(?:div|span|p|img|li|ul|section)\b[^>]*\sonclick\s*=".to_string(),
            enabled: true,
            severity: "high".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Click handler on an element that is not keyboard focusable".to_string(),
            reference: Some("https://www.w3.org/WAI/WCAG22/Understanding/keyboard".to_string()),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-2.1.1".to_string(),
                "keyboard".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(
                r#"(?i)\brole\s*=\s*["']?(?:button|link|tab|menuitem|checkbox|switch|option)\b|\btabindex\s*="#
                    .to_string(),
            ),
            file_extensions: web_extensions(),
        },
        // WCAG 2.2.2 - media autoplaying with sound
        Pattern {
            name: "autoplay-media".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?i)<(?:video|audio)\b[^>]*\bautoplay\b[^>]*>".to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Media set to autoplay (must be muted or user-controlled)".to_string(),
            reference: Some("https://www.w3.org/WAI/WCAG22/Understanding/audio-control".to_string()),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-1.4.2".to_string(),
                "media".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r"(?i)\bmuted\b".to_string()),
            file_extensions: web_extensions(),
        },
        // WCAG 3.3.2 - empty <label> provides no label text
        Pattern {
            name: "empty-label".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?is)<label\b[^>]*>\s*</label>".to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Label element has no text content".to_string(),
            reference: Some(
                "https://www.w3.org/WAI/WCAG22/Understanding/labels-or-instructions".to_string(),
            ),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-3.3.2".to_string(),
                "form".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: web_extensions(),
        },
        // Advisory - accesskey frequently conflicts with AT/browser shortcuts
        Pattern {
            name: "accesskey-usage".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?i)\saccesskey\s*=".to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "accesskey attribute may conflict with assistive tech shortcuts".to_string(),
            reference: Some(
                "https://www.w3.org/WAI/WCAG22/Understanding/character-key-shortcuts".to_string(),
            ),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-2.1.4".to_string(),
                "keyboard".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: web_extensions(),
        },
        // WCAG 3.2.5 Change on Request - unlabeled new-window links
        Pattern {
            name: "target-blank-unlabeled".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r#"(?i)<a\b[^>]*target\s*=\s*["']?_blank"#.to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Link opens in a new window without an accessible warning".to_string(),
            reference: Some("https://www.w3.org/WAI/WCAG22/Understanding/change-on-request".to_string()),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-3.2.5".to_string(),
                "link".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(
                r#"(?i)\baria-label\b|\btitle\s*=\s*["'][^"']*(?:new (?:window|tab)|opens? in)"#
                    .to_string(),
            ),
            file_extensions: web_extensions(),
        },
        // WCAG 2.4.6 Headings and Labels - single-character headings
        Pattern {
            name: "single-character-heading".to_string(),
            category: "accessibility".to_string(),
            match_pattern: r"(?is)<h[1-6]\b[^>]*>\s*[^<\s]\s*</h[1-6]>".to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Heading contains a single character (likely decorative misuse)".to_string(),
            reference: Some(
                "https://www.w3.org/WAI/WCAG22/Understanding/headings-and-labels".to_string(),
            ),
            tags: vec![
                "accessibility".to_string(),
                "wcag".to_string(),
                "wcag-2.4.6".to_string(),
                "heading".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: web_extensions(),
        },
    ]
}
