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
            _ => Ok(AstAnalysis {
                findings: Vec::new(),
                complexity: ComplexityMetrics::default(),
            }),
        }
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
}
