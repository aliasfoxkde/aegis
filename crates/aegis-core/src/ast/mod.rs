//! AST-based pattern analysis
//!
//! Provides AST analysis for Go and Rust code.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// AST analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstAnalysis {
    /// Findings from AST analysis
    pub findings: Vec<AstFinding>,
    /// Complexity metrics
    pub complexity: ComplexityMetrics,
}

/// Outcome of attempting structural analysis for one source unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AstInspectionStatus {
    /// The source extension is not recognized by Aegis.
    NotApplicable,
    /// A tree-sitter parse completed successfully.
    Parsed,
    /// The parser feature is unavailable; line-based AST rules were used.
    Fallback,
    /// A supported parser reported a syntax error.
    ParseError,
    /// The language is known, but no parser grammar is available.
    Unsupported,
}

/// Bounded AST inspection result used by scanner and ledger integrations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstInspection {
    pub status: AstInspectionStatus,
    pub language: Option<String>,
    pub required: bool,
    pub reason: Option<String>,
    pub findings: Vec<AstFinding>,
}

/// An AST-based finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstFinding {
    /// Pattern that triggered
    pub pattern: String,
    /// File location
    pub file: String,
    /// Line number
    pub line: usize,
    /// Description
    pub description: String,
    /// Severity
    pub severity: String,
    /// Confidence
    pub confidence: String,
}

/// Complexity metrics for a file or function
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComplexityMetrics {
    /// Cyclomatic complexity
    pub cyclomatic: usize,
    /// Cognitive complexity
    pub cognitive: usize,
    /// Lines of code
    pub loc: usize,
    /// Parameter count
    pub param_count: usize,
    /// Nesting depth
    pub max_nesting: usize,
    /// Has early return
    pub has_early_return: bool,
    /// Has TODO/FIXME
    pub has_todo: bool,
}

/// AST analyzer
#[derive(Debug, PartialEq)]
pub struct AstAnalyzer {
    /// Language to analyze
    language: Language,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Go,
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Java,
    C,
    Cpp,
}

impl AstAnalyzer {
    /// Create a new analyzer
    pub fn new(language: Language) -> Self {
        Self { language }
    }

    /// Detect language from file extension
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "go" => Some(Self {
                language: Language::Go,
            }),
            "rs" => Some(Self {
                language: Language::Rust,
            }),
            "py" => Some(Self {
                language: Language::Python,
            }),
            "js" | "mjs" | "cjs" => Some(Self {
                language: Language::JavaScript,
            }),
            "ts" | "mts" | "cts" => Some(Self {
                language: Language::TypeScript,
            }),
            "java" => Some(Self {
                language: Language::Java,
            }),
            "c" | "h" => Some(Self {
                language: Language::C,
            }),
            "cpp" | "cc" | "cxx" | "hpp" | "hxx" => Some(Self {
                language: Language::Cpp,
            }),
            _ => None,
        }
    }

    /// Analyze a file
    pub fn analyze_file(&self, path: &Path) -> Result<AstAnalysis, AstError> {
        let content = std::fs::read_to_string(path)?;
        self.analyze_content(&content, path.to_str().unwrap_or("unknown"))
    }

    /// Analyze content
    pub fn analyze_content(&self, content: &str, source: &str) -> Result<AstAnalysis, AstError> {
        match self.language {
            Language::Go => self.analyze_go(content, source),
            Language::Rust => self.analyze_rust(content, source),
            Language::Python => self.analyze_python(content, source),
            Language::JavaScript | Language::TypeScript => self.analyze_javascript(content, source),
            _ => Ok(AstAnalysis {
                findings: Vec::new(),
                complexity: ComplexityMetrics::default(),
            }),
        }
    }

    /// Run the configured AST rules and report whether parser-backed coverage
    /// was actually available. This keeps fallback analysis useful without
    /// allowing a scan receipt to claim parser coverage it did not perform.
    pub fn inspect_source(content: &str, source: &str) -> AstInspection {
        let extension = Path::new(source)
            .extension()
            .and_then(|extension| extension.to_str());
        let Some(extension) = extension else {
            return AstInspection {
                status: AstInspectionStatus::NotApplicable,
                language: None,
                required: false,
                reason: Some("source_has_no_extension".to_string()),
                findings: Vec::new(),
            };
        };
        let Some(analyzer) = Self::from_extension(extension) else {
            return AstInspection {
                status: AstInspectionStatus::NotApplicable,
                language: None,
                required: false,
                reason: Some("unsupported_extension".to_string()),
                findings: Vec::new(),
            };
        };

        let language = extension.to_string();
        let analysis = analyzer
            .analyze_content(content, source)
            .unwrap_or(AstAnalysis {
                findings: Vec::new(),
                complexity: ComplexityMetrics::default(),
            });

        #[cfg(feature = "tree-sitter")]
        {
            match tree_sitter_analysis::parse_source_checked(content, analyzer.language) {
                Ok(_) => AstInspection {
                    status: AstInspectionStatus::Parsed,
                    language: Some(language),
                    required: true,
                    reason: None,
                    findings: analysis.findings,
                },
                Err(error) => AstInspection {
                    status: AstInspectionStatus::ParseError,
                    language: Some(language),
                    required: true,
                    reason: Some(error.to_string()),
                    findings: analysis.findings,
                },
            }
        }

        #[cfg(not(feature = "tree-sitter"))]
        AstInspection {
            status: AstInspectionStatus::Fallback,
            language: Some(language),
            required: false,
            reason: Some("tree_sitter_feature_disabled".to_string()),
            findings: analysis.findings,
        }
    }

    /// Analyze Python code
    fn analyze_python(&self, content: &str, source: &str) -> Result<AstAnalysis, AstError> {
        let mut findings = Vec::new();
        let mut complexity = ComplexityMetrics::default();

        for (i, line) in content.lines().enumerate() {
            let line_num = i + 1;
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with('#') || trimmed.starts_with("\"\"\"") {
                continue;
            }

            // Check for SQL injection (format with % or f-string concatenation)
            if (trimmed.contains("format(") || trimmed.contains("'%'"))
                && (trimmed.contains("SELECT")
                    || trimmed.contains("INSERT")
                    || trimmed.contains("UPDATE"))
            {
                findings.push(AstFinding {
                    pattern: "sql-injection".to_string(),
                    file: source.to_string(),
                    line: line_num,
                    description: "Potential SQL injection - string formatting in query".to_string(),
                    severity: "high".to_string(),
                    confidence: "medium".to_string(),
                });
            }

            // Check for pickle deserialization
            if trimmed.contains("pickle.load") || trimmed.contains("pickle.loads") {
                findings.push(AstFinding {
                    pattern: "insecure-deserialization".to_string(),
                    file: source.to_string(),
                    line: line_num,
                    description: "Use of insecure pickle deserialization".to_string(),
                    severity: "high".to_string(),
                    confidence: "high".to_string(),
                });
            }

            // Check for hardcoded secrets
            if (trimmed.contains("password")
                || trimmed.contains("secret")
                || trimmed.contains("api_key"))
                && trimmed.contains('=')
                && !trimmed.starts_with('#')
            {
                if trimmed.contains("os.environ") || trimmed.contains("getenv") {
                    // Environment variable access - likely checking, not hardcoding
                } else if trimmed.contains('"') || trimmed.contains('\'') {
                    findings.push(AstFinding {
                        pattern: "hardcoded-credential".to_string(),
                        file: source.to_string(),
                        line: line_num,
                        description: "Potential hardcoded credential or secret".to_string(),
                        severity: "high".to_string(),
                        confidence: "medium".to_string(),
                    });
                }
            }

            // Check for eval usage
            if trimmed.contains("eval(") {
                findings.push(AstFinding {
                    pattern: "dangerous-execution".to_string(),
                    file: source.to_string(),
                    line: line_num,
                    description: "Use of eval() - dynamic code execution".to_string(),
                    severity: "high".to_string(),
                    confidence: "high".to_string(),
                });
            }

            // Check for exec usage
            if trimmed.contains("exec(") {
                findings.push(AstFinding {
                    pattern: "command-injection".to_string(),
                    file: source.to_string(),
                    line: line_num,
                    description: "Use of exec() - command injection risk".to_string(),
                    severity: "high".to_string(),
                    confidence: "high".to_string(),
                });
            }

            // Check for subprocess with shell=True
            if trimmed.contains("subprocess") && trimmed.contains("shell=True") {
                findings.push(AstFinding {
                    pattern: "command-injection".to_string(),
                    file: source.to_string(),
                    line: line_num,
                    description: "subprocess with shell=True is a command injection risk"
                        .to_string(),
                    severity: "high".to_string(),
                    confidence: "high".to_string(),
                });
            }

            // Check for input without sanitization
            if trimmed.contains("input(") && !trimmed.contains("int(") {
                // raw input without type conversion might be risky
            }

            // Check for yaml.load without Loader
            if trimmed.contains("yaml.load") && !trimmed.contains("Loader=yaml.SafeLoader") {
                findings.push(AstFinding {
                    pattern: "insecure-deserialization".to_string(),
                    file: source.to_string(),
                    line: line_num,
                    description: "yaml.load without SafeLoader is insecure".to_string(),
                    severity: "medium".to_string(),
                    confidence: "high".to_string(),
                });
            }

            // Check for MD5 usage
            if trimmed.contains("hashlib.md5") {
                findings.push(AstFinding {
                    pattern: "weak-crypto".to_string(),
                    file: source.to_string(),
                    line: line_num,
                    description: "Use of MD5 for security purposes is insecure".to_string(),
                    severity: "medium".to_string(),
                    confidence: "high".to_string(),
                });
            }

            // Check for SHA1 usage
            if trimmed.contains("hashlib.sha1") {
                findings.push(AstFinding {
                    pattern: "weak-crypto".to_string(),
                    file: source.to_string(),
                    line: line_num,
                    description: "Use of SHA1 for security purposes is insecure".to_string(),
                    severity: "medium".to_string(),
                    confidence: "high".to_string(),
                });
            }

            // Check for TODO/FIXME
            if trimmed.contains("TODO") || trimmed.contains("FIXME") || trimmed.contains("HACK") {
                complexity.has_todo = true;
            }

            // Count complexity
            complexity.cyclomatic += line.matches("if ").count();
            complexity.cyclomatic += line.matches("elif ").count();
            complexity.cyclomatic += line.matches("for ").count();
            complexity.cyclomatic += line.matches("while ").count();
            complexity.cyclomatic += line.matches("and ").count();
            complexity.cyclomatic += line.matches("or ").count();
            complexity.cyclomatic += line.matches(" try:").count();
            complexity.cyclomatic += line.matches("except").count();
        }

        complexity.loc = content.lines().count();

        Ok(AstAnalysis {
            findings,
            complexity,
        })
    }

    /// Analyze JavaScript/TypeScript code
    fn analyze_javascript(&self, content: &str, source: &str) -> Result<AstAnalysis, AstError> {
        let mut findings = Vec::new();
        let mut complexity = ComplexityMetrics::default();

        for (i, line) in content.lines().enumerate() {
            let line_num = i + 1;
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with("*/") {
                continue;
            }

            // Check for eval usage
            if trimmed.contains("eval(") {
                findings.push(AstFinding {
                    pattern: "dangerous-execution".to_string(),
                    file: source.to_string(),
                    line: line_num,
                    description: "Use of eval() - dynamic code execution".to_string(),
                    severity: "high".to_string(),
                    confidence: "high".to_string(),
                });
            }

            // Check for document.domain
            if trimmed.contains("document.domain") {
                findings.push(AstFinding {
                    pattern: "xss".to_string(),
                    file: source.to_string(),
                    line: line_num,
                    description: "document.domain manipulation can cause XSS".to_string(),
                    severity: "medium".to_string(),
                    confidence: "medium".to_string(),
                });
            }

            // Check for innerHTML without sanitization
            if trimmed.contains("innerHTML") && !trimmed.contains("textContent") {
                findings.push(AstFinding {
                    pattern: "xss".to_string(),
                    file: source.to_string(),
                    line: line_num,
                    description: "Use of innerHTML without sanitization can cause XSS".to_string(),
                    severity: "high".to_string(),
                    confidence: "medium".to_string(),
                });
            }

            // Check for eval in setTimeout/setInterval
            if (trimmed.contains("setTimeout(") || trimmed.contains("setInterval("))
                && trimmed.contains("eval")
            {
                findings.push(AstFinding {
                    pattern: "dangerous-execution".to_string(),
                    file: source.to_string(),
                    line: line_num,
                    description: "eval in setTimeout/setInterval is dangerous".to_string(),
                    severity: "high".to_string(),
                    confidence: "high".to_string(),
                });
            }

            // Check for hardcoded credentials
            if (trimmed.contains("password")
                || trimmed.contains("secret")
                || trimmed.contains("apiKey"))
                && trimmed.contains('=')
                && !trimmed.starts_with("//")
                && (trimmed.contains('"') || trimmed.contains('\''))
            {
                findings.push(AstFinding {
                    pattern: "hardcoded-credential".to_string(),
                    file: source.to_string(),
                    line: line_num,
                    description: "Potential hardcoded credential".to_string(),
                    severity: "high".to_string(),
                    confidence: "medium".to_string(),
                });
            }

            // Check for crypto.createCipher (deprecated)
            if trimmed.contains("crypto.createCipher") {
                findings.push(AstFinding {
                    pattern: "weak-crypto".to_string(),
                    file: source.to_string(),
                    line: line_num,
                    description: "crypto.createCipher is deprecated, use crypto.createCipheriv"
                        .to_string(),
                    severity: "medium".to_string(),
                    confidence: "high".to_string(),
                });
            }

            // Check for process.env without validation
            if trimmed.contains("process.env")
                && !trimmed.contains("=== \"\"")
                && !trimmed.contains("|| \"\"")
            {
                // Accessing env vars without defaults might cause issues
            }

            // Check for TODO/FIXME
            if trimmed.contains("TODO") || trimmed.contains("FIXME") || trimmed.contains("HACK") {
                complexity.has_todo = true;
            }

            // Count complexity
            complexity.cyclomatic += line.matches("if ").count();
            complexity.cyclomatic += line.matches("else if").count();
            complexity.cyclomatic += line.matches("for ").count();
            complexity.cyclomatic += line.matches("while ").count();
            complexity.cyclomatic += line.matches("&&").count();
            complexity.cyclomatic += line.matches("||").count();
            complexity.cyclomatic += line.matches("?").count();
        }

        complexity.loc = content.lines().count();

        Ok(AstAnalysis {
            findings,
            complexity,
        })
    }

    /// Analyze Go code
    fn analyze_go(&self, content: &str, source: &str) -> Result<AstAnalysis, AstError> {
        let mut findings = Vec::new();
        let mut complexity = ComplexityMetrics::default();

        // Simple line-based analysis (full AST parsing would require go_parser crate)
        for (i, line) in content.lines().enumerate() {
            let line_num = i + 1;

            // Check for dangerous patterns
            if line.contains("exec.Command") && !line.starts_with("//") {
                let trimmed = line.trim();
                if !trimmed.starts_with("//") && !trimmed.starts_with("/*") {
                    findings.push(AstFinding {
                        pattern: "command-injection".to_string(),
                        file: source.to_string(),
                        line: line_num,
                        description:
                            "Potential command injection: exec.Command with string concatenation"
                                .to_string(),
                        severity: "high".to_string(),
                        confidence: "medium".to_string(),
                    });
                }
            }

            // Check for hardcoded credentials
            if line.contains(":=")
                && (line.contains("password")
                    || line.contains("secret")
                    || line.contains("api_key"))
            {
                findings.push(AstFinding {
                    pattern: "hardcoded-credentials".to_string(),
                    file: source.to_string(),
                    line: line_num,
                    description: "Potential hardcoded credentials".to_string(),
                    severity: "high".to_string(),
                    confidence: "low".to_string(),
                });
            }

            // Check for unchecked errors
            if line.contains("_") && line.contains("=") && !line.contains("_ =") {
                // '_' as left-hand side of assignment might be unchecked error
            }

            // Check for TODO
            if line.contains("TODO") || line.contains("FIXME") || line.contains("HACK") {
                complexity.has_todo = true;
            }

            // Count braces for complexity estimation
            complexity.cyclomatic += line.matches("if").count();
            complexity.cyclomatic += line.matches("for").count();
            complexity.cyclomatic += line.matches("case").count();
            complexity.cyclomatic += line.matches("&&").count();
            complexity.cyclomatic += line.matches("||").count();
        }

        complexity.loc = content.lines().count();

        Ok(AstAnalysis {
            findings,
            complexity,
        })
    }

    /// Analyze Rust code
    fn analyze_rust(&self, content: &str, source: &str) -> Result<AstAnalysis, AstError> {
        let mut findings = Vec::new();
        let mut complexity = ComplexityMetrics::default();

        for (i, line) in content.lines().enumerate() {
            let line_num = i + 1;
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with("*/") {
                continue;
            }

            // Check for unsafe blocks
            if trimmed.contains("unsafe ") && !trimmed.starts_with("//") {
                findings.push(AstFinding {
                    pattern: "unsafe-code".to_string(),
                    file: source.to_string(),
                    line: line_num,
                    description: "Use of unsafe code block".to_string(),
                    severity: "medium".to_string(),
                    confidence: "high".to_string(),
                });
            }

            // Check for unwrap() usage
            if trimmed.contains(".unwrap()") || trimmed.contains(".expect(") {
                findings.push(AstFinding {
                    pattern: "panic-possible".to_string(),
                    file: source.to_string(),
                    line: line_num,
                    description: "Use of unwrap() or expect() can cause panics".to_string(),
                    severity: "medium".to_string(),
                    confidence: "high".to_string(),
                });
            }

            // Check for TODO
            if trimmed.contains("TODO") || trimmed.contains("FIXME") || trimmed.contains("HACK") {
                complexity.has_todo = true;
            }

            // Count complexity
            complexity.cyclomatic += line.matches("if").count();
            complexity.cyclomatic += line.matches("match").count();
            complexity.cyclomatic += line.matches("for").count();
            complexity.cyclomatic += line.matches("while").count();
            complexity.cyclomatic += line.matches("||").count();
            complexity.cyclomatic += line.matches("&&").count();

            // Count function definitions
            if line.contains("fn ") && !line.contains("//") {
                // Estimate parameter count
                if let Some(paren_start) = line.find('(') {
                    if let Some(paren_end) = line.find(')') {
                        let params = &line[paren_start..paren_end];
                        if params.len() > 1 {
                            complexity.param_count = complexity
                                .param_count
                                .max(params.chars().filter(|&c| c == ',').count() + 1);
                        }
                    }
                }
            }
        }

        complexity.loc = content.lines().count();

        Ok(AstAnalysis {
            findings,
            complexity,
        })
    }

    /// Check for common patterns across languages
    pub fn check_common_patterns(&self, content: &str, source: &str) -> Vec<AstFinding> {
        let mut findings = Vec::new();

        for (i, line) in content.lines().enumerate() {
            let line_num = i + 1;
            let trimmed = line.trim();

            // Console.log/print statements
            if trimmed.contains("console.log")
                || trimmed.contains("console.error")
                || trimmed.contains("System.out.println")
                || trimmed.contains("print(")
            {
                findings.push(AstFinding {
                    pattern: "debug-artifact".to_string(),
                    file: source.to_string(),
                    line: line_num,
                    description: "Debug output statement found".to_string(),
                    severity: "low".to_string(),
                    confidence: "high".to_string(),
                });
            }

            // Hardcoded IP addresses
            if trimmed.contains("localhost") || trimmed.contains("127.0.0.1") {
                // Only flag if not in comments and part of actual code
                if !trimmed.starts_with("//")
                    && !trimmed.starts_with("#")
                    && !trimmed.starts_with("/*")
                    && trimmed.len() > 5
                {
                    findings.push(AstFinding {
                        pattern: "hardcoded-host".to_string(),
                        file: source.to_string(),
                        line: line_num,
                        description: "Hardcoded localhost or IP address".to_string(),
                        severity: "low".to_string(),
                        confidence: "medium".to_string(),
                    });
                }
            }

            // Eval/exec usage
            if trimmed.contains("eval(")
                || trimmed.contains("exec(")
                || trimmed.contains("Runtime.getRuntime().exec")
            {
                findings.push(AstFinding {
                    pattern: "dangerous-execution".to_string(),
                    file: source.to_string(),
                    line: line_num,
                    description: "Use of dynamic code execution".to_string(),
                    severity: "high".to_string(),
                    confidence: "high".to_string(),
                });
            }
        }

        findings
    }
}

/// AST error types
#[derive(Debug, thiserror::Error)]
pub enum AstError {
    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_detection() {
        assert_eq!(
            AstAnalyzer::from_extension("go"),
            Some(AstAnalyzer {
                language: Language::Go
            })
        );
        assert_eq!(
            AstAnalyzer::from_extension("rs"),
            Some(AstAnalyzer {
                language: Language::Rust
            })
        );
        assert_eq!(
            AstAnalyzer::from_extension("py"),
            Some(AstAnalyzer {
                language: Language::Python
            })
        );
        assert_eq!(AstAnalyzer::from_extension("unknown"), None);
    }

    #[test]
    fn test_go_analysis() {
        let analyzer = AstAnalyzer::new(Language::Go);
        let content = r#"
package main

import "os/exec"

func main() {
    cmd := exec.Command("ls", "-la")
}
"#;
        let result = analyzer.analyze_content(content, "test.go").unwrap();
        assert!(!result.findings.is_empty());
        assert!(result
            .findings
            .iter()
            .any(|f| f.pattern == "command-injection"));
    }

    #[test]
    fn test_rust_analysis() {
        let analyzer = AstAnalyzer::new(Language::Rust);
        let content = r#"
fn main() {
    let x = Some(1);
    println!("{:?}", x.unwrap());
}
"#;
        let result = analyzer.analyze_content(content, "test.rs").unwrap();
        assert!(result
            .findings
            .iter()
            .any(|f| f.pattern == "panic-possible"));
    }

    #[test]
    fn test_common_patterns() {
        let analyzer = AstAnalyzer::new(Language::JavaScript);
        let content = r#"
function test() {
    console.log("debug");
    eval("dynamic code");
}
"#;
        let findings = analyzer.check_common_patterns(content, "test.js");
        assert!(findings.iter().any(|f| f.pattern == "debug-artifact"));
        assert!(findings.iter().any(|f| f.pattern == "dangerous-execution"));
    }

    #[test]
    fn test_complexity_counting() {
        let analyzer = AstAnalyzer::new(Language::Rust);
        let content = r#"
fn complex(a: bool, b: bool, c: bool) {
    if a && b {
        if c {
            match x {
                1 => println!("one"),
                2 => println!("two"),
                _ => {},
            }
        }
    }
}
"#;
        let result = analyzer.analyze_content(content, "test.rs").unwrap();
        assert!(result.complexity.cyclomatic >= 4);
    }

    #[test]
    fn test_rust_unsafe_detection() {
        let analyzer = AstAnalyzer::new(Language::Rust);
        let content = r#"
fn main() {
    unsafe {
        do_thing();
    }
}
"#;
        let result = analyzer.analyze_content(content, "test.rs").unwrap();
        assert!(result.findings.iter().any(|f| f.pattern == "unsafe-code"));
    }

    #[test]
    fn test_go_hardcoded_credentials() {
        let analyzer = AstAnalyzer::new(Language::Go);
        let content = r#"
package main

func main() {
    password := "secret123"
    api_key := "key-12345"
}
"#;
        let result = analyzer.analyze_content(content, "test.go").unwrap();
        assert!(result
            .findings
            .iter()
            .any(|f| f.pattern == "hardcoded-credentials"));
    }

    #[test]
    fn test_go_todo_detection() {
        let analyzer = AstAnalyzer::new(Language::Go);
        let content = r#"
package main
// TODO: fix this
func main() {}
"#;
        let result = analyzer.analyze_content(content, "test.go").unwrap();
        assert!(result.complexity.has_todo);
    }

    #[test]
    fn test_go_fixme_detection() {
        let analyzer = AstAnalyzer::new(Language::Go);
        let content = r#"
package main
// FIXME: fix this
func main() {}
"#;
        let result = analyzer.analyze_content(content, "test.go").unwrap();
        assert!(result.complexity.has_todo);
    }

    #[test]
    fn test_rust_hack_detection() {
        let analyzer = AstAnalyzer::new(Language::Rust);
        // HACK must be on a non-comment line to be detected
        let content = "fn main() { let x = 1; /* HACK: temporary */ }\n";
        let result = analyzer.analyze_content(content, "test.rs").unwrap();
        assert!(result.complexity.has_todo);
    }

    #[test]
    fn test_go_analysis_loc() {
        let analyzer = AstAnalyzer::new(Language::Go);
        let content = "line1\nline2\nline3\n";
        let result = analyzer.analyze_content(content, "test.go").unwrap();
        assert_eq!(result.complexity.loc, 3);
    }

    #[test]
    fn test_rust_analysis_loc() {
        let analyzer = AstAnalyzer::new(Language::Rust);
        let content = "line1\nline2\nline3\n";
        let result = analyzer.analyze_content(content, "test.rs").unwrap();
        assert_eq!(result.complexity.loc, 3);
    }

    #[test]
    fn test_language_detection_java() {
        assert_eq!(
            AstAnalyzer::from_extension("java"),
            Some(AstAnalyzer {
                language: Language::Java
            })
        );
    }

    #[test]
    fn test_language_detection_c() {
        assert_eq!(
            AstAnalyzer::from_extension("c"),
            Some(AstAnalyzer {
                language: Language::C
            })
        );
        assert_eq!(
            AstAnalyzer::from_extension("h"),
            Some(AstAnalyzer {
                language: Language::C
            })
        );
    }

    #[test]
    fn test_language_detection_cpp() {
        assert_eq!(
            AstAnalyzer::from_extension("cpp"),
            Some(AstAnalyzer {
                language: Language::Cpp
            })
        );
        assert_eq!(
            AstAnalyzer::from_extension("hpp"),
            Some(AstAnalyzer {
                language: Language::Cpp
            })
        );
        assert_eq!(
            AstAnalyzer::from_extension("cxx"),
            Some(AstAnalyzer {
                language: Language::Cpp
            })
        );
    }

    #[test]
    fn test_language_detection_js() {
        assert_eq!(
            AstAnalyzer::from_extension("js"),
            Some(AstAnalyzer {
                language: Language::JavaScript
            })
        );
        assert_eq!(
            AstAnalyzer::from_extension("mjs"),
            Some(AstAnalyzer {
                language: Language::JavaScript
            })
        );
        assert_eq!(
            AstAnalyzer::from_extension("cjs"),
            Some(AstAnalyzer {
                language: Language::JavaScript
            })
        );
    }

    #[test]
    fn test_language_detection_ts() {
        assert_eq!(
            AstAnalyzer::from_extension("ts"),
            Some(AstAnalyzer {
                language: Language::TypeScript
            })
        );
        assert_eq!(
            AstAnalyzer::from_extension("mts"),
            Some(AstAnalyzer {
                language: Language::TypeScript
            })
        );
        assert_eq!(
            AstAnalyzer::from_extension("cts"),
            Some(AstAnalyzer {
                language: Language::TypeScript
            })
        );
    }

    #[test]
    fn test_check_common_patterns_localhost() {
        let analyzer = AstAnalyzer::new(Language::Python);
        let content = "server = '127.0.0.1'\n";
        let findings = analyzer.check_common_patterns(content, "test.py");
        assert!(findings.iter().any(|f| f.pattern == "hardcoded-host"));
    }

    #[test]
    fn test_check_common_patterns_print() {
        let analyzer = AstAnalyzer::new(Language::Python);
        let content = "print('debug')\n";
        let findings = analyzer.check_common_patterns(content, "test.py");
        assert!(findings.iter().any(|f| f.pattern == "debug-artifact"));
    }

    #[test]
    fn test_check_common_patterns_system_out() {
        let analyzer = AstAnalyzer::new(Language::Java);
        let content = "System.out.println('debug');\n";
        let findings = analyzer.check_common_patterns(content, "test.java");
        assert!(findings.iter().any(|f| f.pattern == "debug-artifact"));
    }

    #[test]
    fn test_check_common_patterns_exec() {
        let analyzer = AstAnalyzer::new(Language::JavaScript);
        let content = "eval('code');\n";
        let findings = analyzer.check_common_patterns(content, "test.js");
        assert!(findings.iter().any(|f| f.pattern == "dangerous-execution"));
    }

    #[test]
    fn test_check_common_patterns_runtime_exec() {
        let analyzer = AstAnalyzer::new(Language::Java);
        let content = "Runtime.getRuntime().exec('cmd');\n";
        let findings = analyzer.check_common_patterns(content, "test.java");
        assert!(findings.iter().any(|f| f.pattern == "dangerous-execution"));
    }

    #[test]
    fn test_analyze_unsupported_language() {
        let analyzer = AstAnalyzer::new(Language::Python);
        let content = "x = 1\n";
        let result = analyzer.analyze_content(content, "test.py").unwrap();
        // Python is now supported, should return complexity
        assert_eq!(result.complexity.loc, 1); // 1 line of code
    }

    #[test]
    fn test_inspect_source_reports_parser_coverage() {
        let inspection = AstAnalyzer::inspect_source("eval('x')\n", "fixture.py");
        assert_eq!(inspection.language.as_deref(), Some("py"));
        assert!(!inspection.findings.is_empty());
        #[cfg(feature = "tree-sitter")]
        assert_eq!(inspection.status, AstInspectionStatus::Parsed);
        #[cfg(not(feature = "tree-sitter"))]
        assert_eq!(inspection.status, AstInspectionStatus::Fallback);
    }

    #[test]
    fn test_complexity_with_while_loop() {
        let analyzer = AstAnalyzer::new(Language::Rust);
        let content = "while condition {\n    do_something();\n}\n";
        let result = analyzer.analyze_content(content, "test.rs").unwrap();
        assert!(result.complexity.cyclomatic >= 1);
    }

    #[test]
    fn test_complexity_function_params() {
        let analyzer = AstAnalyzer::new(Language::Rust);
        let content = "fn foo(a: i32, b: i32, c: i32) {}\n";
        let result = analyzer.analyze_content(content, "test.rs").unwrap();
        assert_eq!(result.complexity.param_count, 3);
    }

    #[test]
    fn test_analyze_file_nonexistent() {
        let analyzer = AstAnalyzer::new(Language::Rust);
        let result = analyzer.analyze_file(std::path::Path::new("/nonexistent/file.rs"));
        assert!(result.is_err());
    }
}

// =============================================================================
// Enhanced AST Analysis with Tree-sitter Integration
// =============================================================================

use std::collections::HashSet;

/// Represents a node in the AST during traversal
#[derive(Debug, Clone)]
pub struct AstNode {
    /// Node type
    pub node_type: String,
    /// Source text
    pub text: String,
    /// Start byte offset
    pub start_byte: usize,
    /// End byte offset
    pub end_byte: usize,
    /// Children
    pub children: Vec<AstNode>,
}

impl AstNode {
    /// Check if this node matches a type pattern
    pub fn is_type(&self, node_type: &str) -> bool {
        self.node_type == node_type
    }

    /// Get all descendant nodes of a specific type
    pub fn descendants_of_type(&self, node_type: &str) -> Vec<&AstNode> {
        let mut results = Vec::new();
        self.collect_descendants_of_type(node_type, &mut results);
        results
    }

    fn collect_descendants_of_type<'a>(&'a self, node_type: &str, results: &mut Vec<&'a AstNode>) {
        for child in &self.children {
            if child.node_type == node_type {
                results.push(child);
            }
            child.collect_descendants_of_type(node_type, results);
        }
    }
}

/// Security pattern to detect in code
#[derive(Debug, Clone)]
pub struct SecurityPattern {
    /// Pattern name
    pub name: String,
    /// AST node types to look for
    pub node_types: Vec<String>,
    /// Dangerous parent types
    pub dangerous_parents: Vec<String>,
    /// Description
    pub description: String,
    /// Severity
    pub severity: &'static str,
    /// Confidence
    pub confidence: &'static str,
}

/// Data flow tracker for taint analysis
#[derive(Debug, Clone, Default)]
pub struct TaintTracker {
    /// Variables that contain tainted (user-controlled) data
    pub tainted_vars: HashSet<String>,
    /// Sanitized variables
    pub sanitized_vars: HashSet<String>,
}

impl TaintTracker {
    /// Create a new taint tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a variable as tainted
    pub fn taint(&mut self, var: &str) {
        self.tainted_vars.insert(var.to_string());
    }

    /// Mark a variable as sanitized
    pub fn sanitize(&mut self, var: &str) {
        self.sanitized_vars.insert(var.to_string());
    }

    /// Check if a variable is tainted
    pub fn is_tainted(&self, var: &str) -> bool {
        self.tainted_vars.contains(var) && !self.sanitized_vars.contains(var)
    }
}

/// Enhanced AST analyzer with tree-sitter support
#[cfg(feature = "tree-sitter")]
pub mod tree_sitter_analysis {
    use super::*;
    use tree_sitter::{Language as TsLanguage, Parser};

    fn grammar(language: super::Language) -> Option<TsLanguage> {
        Some(match language {
            super::Language::Go => tree_sitter_go::LANGUAGE.into(),
            super::Language::Rust => tree_sitter_rust::LANGUAGE.into(),
            super::Language::Python => tree_sitter_python::LANGUAGE.into(),
            super::Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            super::Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            _ => return None,
        })
    }

    fn convert_node(node: tree_sitter::Node<'_>, content: &str) -> AstNode {
        let mut cursor = node.walk();
        let children = node
            .children(&mut cursor)
            .map(|child| convert_node(child, content))
            .collect();
        let text = content
            .get(node.byte_range())
            .unwrap_or_default()
            .to_string();

        AstNode {
            node_type: node.kind().to_string(),
            text,
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            children,
        }
    }

    /// Parse source code and preserve parser failures for callers that need a
    /// fail-closed quality/security decision.
    pub fn parse_source_checked(
        content: &str,
        language: super::Language,
    ) -> Result<AstNode, AstError> {
        let grammar = grammar(language).ok_or_else(|| {
            AstError::ParseError(format!("tree-sitter grammar unavailable for {language:?}"))
        })?;
        let mut parser = Parser::new();
        parser
            .set_language(&grammar)
            .map_err(|error| AstError::ParseError(error.to_string()))?;
        let tree = parser
            .parse(content, None)
            .ok_or_else(|| AstError::ParseError("parser returned no tree".to_string()))?;
        let root = tree.root_node();
        if root.has_error() {
            return Err(AstError::ParseError(format!(
                "tree-sitter reported a syntax error for {language:?}"
            )));
        }
        Ok(convert_node(root, content))
    }

    /// Parse source code using tree-sitter
    pub fn parse_source(content: &str, language: super::Language) -> Option<AstNode> {
        parse_source_checked(content, language).ok()
    }
}

#[cfg(all(test, feature = "tree-sitter"))]
mod tree_sitter_tests {
    use super::{tree_sitter_analysis, Language};

    #[test]
    fn parses_supported_source_into_a_real_tree() {
        let root = tree_sitter_analysis::parse_source_checked(
            "fn main() { let value = 1; }",
            Language::Rust,
        )
        .expect("valid Rust should parse");

        assert_eq!(root.node_type, "source_file");
        assert!(!root.children.is_empty());
        assert!(root.descendants_of_type("function_item").len() == 1);
    }

    #[test]
    fn reports_syntax_errors_and_unsupported_grammars() {
        let syntax_error = tree_sitter_analysis::parse_source_checked("fn main( {", Language::Rust);
        assert!(syntax_error.is_err());

        let unsupported = tree_sitter_analysis::parse_source_checked("class X {}", Language::Java);
        assert!(unsupported.is_err());
    }
}

/// Built-in security patterns
pub fn get_security_patterns() -> Vec<SecurityPattern> {
    vec![
        SecurityPattern {
            name: "sql-injection".to_string(),
            node_types: vec!["string".to_string()],
            dangerous_parents: vec!["call".to_string()],
            description: "Potential SQL injection - string concatenated to query".to_string(),
            severity: "high",
            confidence: "medium",
        },
        SecurityPattern {
            name: "command-injection".to_string(),
            node_types: vec!["string".to_string()],
            dangerous_parents: vec!["call".to_string()],
            description: "Potential command injection - string passed to exec".to_string(),
            severity: "high",
            confidence: "medium",
        },
        SecurityPattern {
            name: "path-traversal".to_string(),
            node_types: vec!["string".to_string()],
            dangerous_parents: vec!["call".to_string()],
            description: "Potential path traversal - unsanitized path input".to_string(),
            severity: "medium",
            confidence: "low",
        },
        SecurityPattern {
            name: "xss".to_string(),
            node_types: vec!["string".to_string()],
            dangerous_parents: vec!["call".to_string()],
            description: "Potential XSS - HTML output without encoding".to_string(),
            severity: "high",
            confidence: "medium",
        },
        SecurityPattern {
            name: "hardcoded-secret".to_string(),
            node_types: vec!["string".to_string()],
            dangerous_parents: vec!["declaration".to_string()],
            description: "Hardcoded secret or credential".to_string(),
            severity: "high",
            confidence: "high",
        },
        SecurityPattern {
            name: "insecure-random".to_string(),
            node_types: vec!["call".to_string()],
            dangerous_parents: vec![],
            description: "Use of cryptographically insecure random".to_string(),
            severity: "medium",
            confidence: "high",
        },
        SecurityPattern {
            name: "eval-usage".to_string(),
            node_types: vec!["call".to_string()],
            dangerous_parents: vec![],
            description: "Use of eval() - dynamic code execution".to_string(),
            severity: "high",
            confidence: "high",
        },
        SecurityPattern {
            name: "xml-external-entity".to_string(),
            node_types: vec!["call".to_string()],
            dangerous_parents: vec![],
            description: "Potential XML external entity (XXE) attack".to_string(),
            severity: "high",
            confidence: "medium",
        },
        SecurityPattern {
            name: "deserialization".to_string(),
            node_types: vec!["call".to_string()],
            dangerous_parents: vec![],
            description: "Use of insecure deserialization".to_string(),
            severity: "critical",
            confidence: "medium",
        },
        SecurityPattern {
            name: "weak-crypto".to_string(),
            node_types: vec!["call".to_string()],
            dangerous_parents: vec![],
            description: "Use of weak cryptographic algorithm".to_string(),
            severity: "medium",
            confidence: "high",
        },
    ]
}
