//! Container security patterns

use crate::Pattern;

pub fn get() -> Vec<Pattern> {
    vec![
        Pattern {
            name: "dockerfile-cap-add-all".to_string(),
            category: "container".to_string(),
            match_pattern: r#"(--cap-add\s*=\s*ALL|cap_add:\s*-\s*ALL)"#.to_string(),
            enabled: true,
            severity: "high".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Detects Docker run or Dockerfile with --cap-add=ALL or cap_add: - ALL".to_string(),
            reference: None,
            tags: vec!["container".to_string(), "dockerfile".to_string(), "capabilities".to_string()],
            env_var: false,
            binary: false,
        },
        Pattern {
            name: "dockerfile-exposed-socket".to_string(),
            category: "container".to_string(),
            match_pattern: r#"(-v|--mount)(?:=|\s+)(?:/var/run/docker\.sock|var/run/docker\.sock)"#.to_string(),
            enabled: true,
            severity: "critical".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Detects Docker socket mount which can give container full Docker access".to_string(),
            reference: None,
            tags: vec!["container".to_string(), "dockerfile".to_string(), "docker-socket".to_string()],
            env_var: false,
            binary: false,
        },
        Pattern {
            name: "dockerfile-privileged-mode".to_string(),
            category: "container".to_string(),
            match_pattern: r#"(--privileged|privileged:\s*true)"#.to_string(),
            enabled: true,
            severity: "critical".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Detects Docker container running in privileged mode with full host access".to_string(),
            reference: None,
            tags: vec!["container".to_string(), "dockerfile".to_string(), "privileged".to_string()],
            env_var: false,
            binary: false,
        },
        Pattern {
            name: "dockerfile-running-as-root".to_string(),
            category: "container".to_string(),
            match_pattern: r#"(?i)^(?:USER|user)\s*(?::\s*|=|\s+)(?:root|0)$"#.to_string(),
            enabled: true,
            severity: "high".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Detects Dockerfile or Docker run with user set to root or UID 0".to_string(),
            reference: None,
            tags: vec!["container".to_string(), "dockerfile".to_string(), "root".to_string()],
            env_var: false,
            binary: false,
        },
    ]
}
