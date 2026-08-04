//! GraphQL patterns

use crate::Pattern;

pub fn get() -> Vec<Pattern> {
    vec![
        Pattern {
            name: "graphql-debug-mode".to_string(),
            category: "graphql".to_string(),
            match_pattern: r#"(?:debug|DEBUG|debugMode)\s*[:=]\s*(?:true|True|TRUE)"#.to_string(),
            enabled: true,
            severity: "high".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Detects GraphQL with debug mode enabled".to_string(),
            reference: None,
            tags: vec!["graphql".to_string(), "debug".to_string()],
            env_var: false,
            binary: false,
        },
        Pattern {
            name: "graphql-field-cost-undefined".to_string(),
            category: "graphql".to_string(),
            match_pattern:
                r#"(?:complexity|fieldCost|costAnalysis)\s*[:=]\s*(?:false|disabled|none)"#
                    .to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Detects GraphQL without field cost analysis enabled".to_string(),
            reference: None,
            tags: vec!["graphql".to_string(), "performance".to_string()],
            env_var: false,
            binary: false,
        },
        Pattern {
            name: "graphql-introspection-enabled".to_string(),
            category: "graphql".to_string(),
            match_pattern: r#"introspection\s*[:=]\s*(?:true|True|TRUE)"#.to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Detects GraphQL with introspection enabled in production".to_string(),
            reference: None,
            tags: vec!["graphql".to_string(), "security".to_string()],
            env_var: false,
            binary: false,
        },
        Pattern {
            name: "graphql-query-depth-unlimited".to_string(),
            category: "graphql".to_string(),
            match_pattern:
                r#"(?:maxDepth|defaultMaxDepth|queryDepth)\s*[:=]\s*(?:0|null|undefined|false)"#
                    .to_string(),
            enabled: true,
            severity: "high".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Detects GraphQL with unlimited query depth".to_string(),
            reference: None,
            tags: vec!["graphql".to_string(), "dos".to_string()],
            env_var: false,
            binary: false,
        },
    ]
}
