//! ARM/Azure patterns

use crate::Pattern;

pub fn get() -> Vec<Pattern> {
    vec![
        Pattern {
            name: "arm-azure-sql-no-firewall".to_string(),
            category: "arm".to_string(),
            match_pattern: r#"startIpAddress\s*[:=]\s*["\x27]0\.0\.0\.0["\x27]"#.to_string(),
            enabled: true,
            severity: "high".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Detects Azure ARM template SQL server without proper firewall rules"
                .to_string(),
            reference: None,
            tags: vec!["arm".to_string(), "azure".to_string(), "sql".to_string()],
            env_var: false,
            binary: false,
        },
        Pattern {
            name: "arm-azure-storage-enable-https".to_string(),
            category: "arm".to_string(),
            match_pattern: r#"enableHttpsTrafficOnly\s*[:=]\s*(?:false|0|no)"#.to_string(),
            enabled: true,
            severity: "high".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Detects Azure ARM template storage account with HTTPS traffic disabled"
                .to_string(),
            reference: None,
            tags: vec![
                "arm".to_string(),
                "azure".to_string(),
                "storage".to_string(),
            ],
            env_var: false,
            binary: false,
        },
    ]
}
