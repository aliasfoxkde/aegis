//! GitOps patterns - git operations security and safety

use crate::Pattern;

pub fn get() -> Vec<Pattern> {
    vec![
        Pattern {
            name: "force-push-detected".to_string(),
            category: "git-ops".to_string(),
            match_pattern: r#"(?i)(git\s+push\s+--force|git\s+push\s+-f\s+origin|push\s+--force-with-lease|--force-with-lease)"#.to_string(),
            enabled: true,
            severity: "high".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Detects force push commands which can overwrite remote history".to_string(),
            reference: Some("https://git-scm.com/docs/git-push".to_string()),
            tags: vec!["git_ops".to_string(), "git".to_string(), "force-push".to_string()],
            env_var: false,
            binary: false,
        },
        Pattern {
            name: "git-credential-leak".to_string(),
            category: "git-ops".to_string(),
            match_pattern: r#"(?i)(git\s+config\s+--local\s+credential\.helper|git\s+clone\s+https?://[^@]+@|url\s*=\s*https?://[^:]+:[^@]+@)"#.to_string(),
            enabled: true,
            severity: "critical".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Detects potential git credential leakage in configuration or URLs".to_string(),
            reference: Some("https://git-scm.com/docs/git-credential".to_string()),
            tags: vec!["git_ops".to_string(), "git".to_string(), "credentials".to_string(), "leak".to_string()],
            env_var: false,
            binary: false,
        },
        Pattern {
            name: "protected-branch-delete".to_string(),
            category: "git-ops".to_string(),
            match_pattern: r#"(?i)(git\s+push\s+origin\s+--delete\s+(main|master|develop|release|prod)|git\s+branch\s+-D\s+(main|master|develop|release|prod)|branch\s*=\s*["']?(main|master|develop|release|prod)["']?\s*\n\s*protection\s*:\s*false)"#.to_string(),
            enabled: true,
            severity: "critical".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Detects commands that delete or modify protected branches".to_string(),
            reference: Some("https://git-scm.com/docs/git-push".to_string()),
            tags: vec!["git_ops".to_string(), "git".to_string(), "protected-branch".to_string(), "destructive".to_string()],
            env_var: false,
            binary: false,
        },
    ]
}
