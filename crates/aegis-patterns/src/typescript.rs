//! TypeScript / modern JavaScript patterns
//!
//! Rules the TypeScript compiler and typescript-eslint flag but that are
//! reliably detectable with plain regexes. Every pattern is scoped with
//! `file_extensions`; TypeScript-only rules list only `ts`/`tsx` (plus the
//! framework blends that embed TS) so they never run against plain
//! JavaScript or other languages.

use crate::Pattern;

/// JavaScript-family extensions (plain JS included).
fn js_extensions() -> Vec<String> {
    vec![
        "js".to_string(),
        "mjs".to_string(),
        "cjs".to_string(),
        "jsx".to_string(),
        "ts".to_string(),
        "tsx".to_string(),
        "vue".to_string(),
        "svelte".to_string(),
    ]
}

/// TypeScript-only extensions (framework blends included).
fn ts_extensions() -> Vec<String> {
    vec![
        "ts".to_string(),
        "tsx".to_string(),
        "mts".to_string(),
        "cts".to_string(),
        "vue".to_string(),
        "svelte".to_string(),
    ]
}

#[must_use]
pub fn get() -> Vec<Pattern> {
    vec![
        // `any` disables type checking at the use site
        Pattern {
            name: "typescript-explicit-any".to_string(),
            category: "typescript".to_string(),
            match_pattern: r"\bas\s+any\b|[:<]\s*any\b|Array<any>".to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Explicit `any` defeats TypeScript type checking".to_string(),
            reference: Some("https://typescript-eslint.io/rules/no-explicit-any/".to_string()),
            tags: vec![
                "typescript".to_string(),
                "types".to_string(),
                "best-practice".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r"@\s*ts-expect-error|any\[\]\s*\)|unknown".to_string()),
            file_extensions: ts_extensions(),
        },
        // Type aliases built on `any` silently widen every use site
        Pattern {
            name: "typescript-any-alias".to_string(),
            category: "typescript".to_string(),
            match_pattern: r"\btype\s+[A-Za-z_$][\w$]*\s*=\s*any\b".to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Type alias resolves to `any`".to_string(),
            reference: Some("https://typescript-eslint.io/rules/no-explicit-any/".to_string()),
            tags: vec![
                "typescript".to_string(),
                "types".to_string(),
                "best-practice".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: ts_extensions(),
        },
        // @ts-ignore suppresses forever; @ts-expect-error at least expires
        Pattern {
            name: "ts-ignore-comment".to_string(),
            category: "typescript".to_string(),
            match_pattern: r"@ts-ignore\b".to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "@ts-ignore suppresses type errors indefinitely; use @ts-expect-error"
                .to_string(),
            reference: Some("https://typescript-eslint.io/rules/ban-ts-comment/".to_string()),
            tags: vec![
                "typescript".to_string(),
                "suppression".to_string(),
                "best-practice".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: ts_extensions(),
        },
        // File-wide type-check opt-out
        Pattern {
            name: "ts-nocheck".to_string(),
            category: "typescript".to_string(),
            match_pattern: r"@ts-nocheck\b".to_string(),
            enabled: true,
            severity: "high".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "@ts-nocheck disables type checking for the whole file".to_string(),
            reference: Some("https://typescript-eslint.io/rules/ban-ts-comment/".to_string()),
            tags: vec![
                "typescript".to_string(),
                "suppression".to_string(),
                "best-practice".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: ts_extensions(),
        },
        // `as unknown as T` is a forced cast through the type system
        Pattern {
            name: "double-type-assertion".to_string(),
            category: "typescript".to_string(),
            match_pattern: r"\bas\s+unknown\s+as\b|\bas\s+any\s+as\b".to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Double type assertion casts through unknown/any".to_string(),
            reference: Some(
                "https://typescript-eslint.io/rules/no-unnecessary-type-assertion/".to_string(),
            ),
            tags: vec![
                "typescript".to_string(),
                "types".to_string(),
                "code-smell".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: ts_extensions(),
        },
        // CommonJS require() inside TypeScript sources
        Pattern {
            name: "require-in-typescript".to_string(),
            category: "typescript".to_string(),
            match_pattern: r"\b(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*require\s*\(".to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "CommonJS require() used in TypeScript; prefer ES imports".to_string(),
            reference: Some("https://typescript-eslint.io/rules/no-require-imports/".to_string()),
            tags: vec![
                "typescript".to_string(),
                "modules".to_string(),
                "best-practice".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r"createRequire|__non_webpack_require__".to_string()),
            file_extensions: ts_extensions(),
        },
        // `interface Foo {}` is always a mistake or dead code
        Pattern {
            name: "empty-interface".to_string(),
            category: "typescript".to_string(),
            match_pattern: r"\binterface\s+[A-Za-z_$][\w$]*\s*\{\s*\}".to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Empty interface declared".to_string(),
            reference: Some("https://typescript-eslint.io/rules/no-empty-interface/".to_string()),
            tags: vec![
                "typescript".to_string(),
                "types".to_string(),
                "dead-code".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: ts_extensions(),
        },
        // Namespaces predate ES modules; prefer modules or `declare`
        Pattern {
            name: "namespace-declaration".to_string(),
            category: "typescript".to_string(),
            match_pattern: r"\bnamespace\s+[A-Za-z_$][\w$]*".to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "TypeScript namespace detected; prefer ES modules".to_string(),
            reference: Some("https://typescript-eslint.io/rules/no-namespace/".to_string()),
            tags: vec![
                "typescript".to_string(),
                "modules".to_string(),
                "best-practice".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r"\bdeclare\s+namespace".to_string()),
            file_extensions: ts_extensions(),
        },
        // `: object` / `: Function` are near-useless types (ban-types)
        Pattern {
            name: "object-function-type".to_string(),
            category: "typescript".to_string(),
            match_pattern: r":\s*(?:object|Object|Function)\b".to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Useless broad type annotation (object/Object/Function)".to_string(),
            reference: Some("https://typescript-eslint.io/rules/ban-types/".to_string()),
            tags: vec![
                "typescript".to_string(),
                "types".to_string(),
                "best-practice".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r"JSON\.parse|\.isObject|typeof object".to_string()),
            file_extensions: ts_extensions(),
        },
        // eslint no-async-promise-executor: rejections are swallowed
        Pattern {
            name: "async-promise-executor".to_string(),
            category: "typescript".to_string(),
            match_pattern: r"new\s+Promise\s*(?:<[^>]*>)?\s*\(\s*async\b".to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Async Promise executor swallows rejections".to_string(),
            reference: Some(
                "https://eslint.org/docs/latest/rules/no-async-promise-executor".to_string(),
            ),
            tags: vec![
                "javascript".to_string(),
                "promises".to_string(),
                "correctness".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: js_extensions(),
        },
        // eslint no-return-await: adds a needless microtask hop
        Pattern {
            name: "return-await".to_string(),
            category: "typescript".to_string(),
            match_pattern: r"\breturn\s+await\s+[A-Za-z_$\[(]".to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "Redundant `return await` outside try/catch".to_string(),
            reference: Some("https://eslint.org/docs/latest/rules/no-return-await".to_string()),
            tags: vec![
                "javascript".to_string(),
                "promises".to_string(),
                "best-practice".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: None,
            file_extensions: js_extensions(),
        },
        // eslint no-prototype-builtins: objects can shadow hasOwnProperty
        Pattern {
            name: "prototype-builtin-call".to_string(),
            category: "typescript".to_string(),
            match_pattern:
                r"\.hasOwnProperty\s*\(|\.isPrototypeOf\s*\(|\.propertyIsEnumerable\s*\("
                    .to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Object prototype method called directly; use Object.hasOwn".to_string(),
            reference: Some(
                "https://eslint.org/docs/latest/rules/no-prototype-builtins".to_string(),
            ),
            tags: vec![
                "javascript".to_string(),
                "security".to_string(),
                "best-practice".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r"Object\.prototype\.hasOwnProperty|\.call\s*\(".to_string()),
            file_extensions: js_extensions(),
        },
        // eslint prefer-rest-params: `arguments` is not array-like in
        // arrow functions and blocks optimization
        Pattern {
            name: "arguments-object-usage".to_string(),
            category: "typescript".to_string(),
            match_pattern: r"\barguments\b".to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "medium".to_string(),
            min_entropy: None,
            description: "`arguments` object used; prefer rest parameters".to_string(),
            reference: Some("https://eslint.org/docs/latest/rules/prefer-rest-params".to_string()),
            tags: vec![
                "javascript".to_string(),
                "best-practice".to_string(),
                "style".to_string(),
            ],
            env_var: false,
            binary: false,
            exclude: Some(r"\.arguments\b|arguments\[0\]\s*=\s*new".to_string()),
            file_extensions: js_extensions(),
        },
    ]
}
