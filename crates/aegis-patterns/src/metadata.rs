//! Metadata patterns

use crate::Pattern;

pub fn get() -> Vec<Pattern> {
    vec![
        Pattern {
            name: "backup-file".to_string(),
            category: "metadata".to_string(),
            match_pattern: r#"\.(bak|old|backup|orig|rpmorig|dpkg-(?:old|dist)|~\")$"#.to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Detects backup files that may contain sensitive data".to_string(),
            reference: None,
            tags: vec!["metadata".to_string(), "backup".to_string()],
            env_var: false,
            binary: false,
        },
        Pattern {
            name: "IDE-config-leak".to_string(),
            category: "metadata".to_string(),
            match_pattern: r#"\.(idea|vscode|vscodium|settings\.json|workspace\.json)$"#
                .to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Detects IDE configuration files that may contain sensitive settings"
                .to_string(),
            reference: None,
            tags: vec!["metadata".to_string(), "IDE".to_string()],
            env_var: false,
            binary: false,
        },
        Pattern {
            name: "os-cache-file".to_string(),
            category: "metadata".to_string(),
            match_pattern: r#"\.(DS_Store|Thumbs\.db|desktop\.ini|\.AppleDouble|\.LSOverride)$"#
                .to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Detects operating system cache files that may contain metadata"
                .to_string(),
            reference: None,
            tags: vec!["metadata".to_string(), "os-cache".to_string()],
            env_var: false,
            binary: false,
        },
        Pattern {
            name: "temporary-file".to_string(),
            category: "metadata".to_string(),
            match_pattern: r#"\.(tmp|temp|cache|swp|swo)$"#.to_string(),
            enabled: true,
            severity: "low".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Detects temporary files that may contain sensitive data".to_string(),
            reference: None,
            tags: vec!["metadata".to_string(), "temporary".to_string()],
            env_var: false,
            binary: false,
        },
    ]
}
