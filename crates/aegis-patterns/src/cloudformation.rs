//! CloudFormation/AWS patterns

use crate::Pattern;

pub fn get() -> Vec<Pattern> {
    vec![
        Pattern {
            name: "cloudformation-iam-lambda-assume-role".to_string(),
            category: "cloudformation".to_string(),
            match_pattern: r#"(Principal\s*:\s*\*|AWS\s*:\s*["\x27]*\*["\x27]*)"#.to_string(),
            enabled: true,
            severity: "medium".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Detects CloudFormation IAM or Lambda trust policy with wildcard principal".to_string(),
            reference: None,
            tags: vec!["cloudformation".to_string(), "aws".to_string(), "iam".to_string(), "lambda".to_string()],
            env_var: false,
            binary: false,
        },
        Pattern {
            name: "cloudformation-s3-no-encryption".to_string(),
            category: "cloudformation".to_string(),
            match_pattern: r#"ServerSideEncryptionByDefault\s*:\s*(?:NOT\s*DEFINED|false|null)"#.to_string(),
            enabled: true,
            severity: "high".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Detects CloudFormation S3 bucket without server-side encryption".to_string(),
            reference: None,
            tags: vec!["cloudformation".to_string(), "aws".to_string(), "s3".to_string(), "encryption".to_string()],
            env_var: false,
            binary: false,
        },
        Pattern {
            name: "cloudformation-s3-public-access".to_string(),
            category: "cloudformation".to_string(),
            match_pattern: r#"(PublicAccessBlockConfiguration|BucketPublicAccessBlock)\s*:\s*(?:false|~\s*-\s*true)"#.to_string(),
            enabled: true,
            severity: "critical".to_string(),
            confidence: "high".to_string(),
            min_entropy: None,
            description: "Detects CloudFormation S3 bucket with public access enabled".to_string(),
            reference: None,
            tags: vec!["cloudformation".to_string(), "aws".to_string(), "s3".to_string(), "public-access".to_string()],
            env_var: false,
            binary: false,
        },
    ]
}
